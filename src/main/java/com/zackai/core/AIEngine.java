package com.zackai.core;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import com.zackai.model.ScanTask;
import com.zackai.model.VulnResult;
import com.zackai.ui.LogPanel;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class AIEngine {
    public interface VulnDiscoveryListener {
        void onVulnerabilityFound(ScanTask task, VulnResult vuln);
    }

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private LogPanel logPanel;
    private OkHttpClient httpClient;
    private Gson gson;
    private VulnDiscoveryListener vulnListener;
    private static final MediaType JSON_TYPE = MediaType.parse("application/json; charset=utf-8");
    private static final int PAYLOAD_COUNT_PER_PARAM = 10;
    private static final int WAF_BYPASS_RATIO = 50;

    private JsonArray filterAndDedupPayloads(JsonArray payloads, ScanTask task, List<String> validParamNames) {
        JsonArray filtered = new JsonArray();
        Set<String> seenPayloads = new HashSet<>();
        for (int i = 0; i < payloads.size(); i++) {
            JsonObject payload = payloads.get(i).getAsJsonObject();
            if (payload == null) continue;
            if (!payload.has("payload") || !payload.has("type")) continue;
            String payloadStr = payload.get("payload").getAsString();
            if (payloadStr == null || payloadStr.trim().isEmpty()) continue;
            String position = payload.has("position") && !payload.get("position").isJsonNull() ? payload.get("position").getAsString() : null;
            if (position == null || position.equals("auto")) continue;
            String type = payload.has("type") ? payload.get("type").getAsString() : "UNKNOWN";
            if (isHeaderParameter(position)) continue;
            if (!isValidPosition(position, validParamNames)) continue;
            String normalized = payloadStr.trim().toLowerCase();
            String dedupKey = position + ":" + type + ":" + normalized;
            if (seenPayloads.contains(dedupKey)) continue;
            seenPayloads.add(dedupKey);
            JsonObject filteredPayload = new JsonObject();
            filteredPayload.addProperty("type", type);
            filteredPayload.addProperty("payload", payloadStr);
            filteredPayload.addProperty("position", position);
            if (payload.has("wafBypass") && !payload.get("wafBypass").isJsonNull()) {
                if (payload.get("wafBypass").isJsonPrimitive()) {
                    String wafBypass = payload.get("wafBypass").getAsString();
                    if (wafBypass != null && !wafBypass.trim().isEmpty()) {
                        filteredPayload.addProperty("wafBypass", wafBypass);
                    }
                }
            }
            filtered.add(filteredPayload);
        }
        return filtered;
    }

    private boolean isValidPosition(String position, List<String> validParamNames) {
        if (position == null || position.isEmpty()) return false;
        if (position.equals("auto") || position.equals("URL_PATH") || position.equals("URL") || position.startsWith("/")) {
            return false;
        }
        if (isHeaderParameter(position)) {
            return false;
        }
        if (validParamNames == null) return false;
        for (String validName : validParamNames) {
            if (validName != null && validName.equalsIgnoreCase(position)) {
                return true;
            }
        }
        return false;
    }

    private boolean isHeaderParameter(String position) {
        if (position == null) return false;
        String lower = position.toLowerCase();
        return lower.equals("host") || lower.equals("user-agent") || lower.equals("accept") ||
               lower.equals("content-type") || lower.equals("content-length") || lower.equals("connection") ||
               lower.equals("cookie") || lower.equals("referer") || lower.equals("origin") ||
               lower.equals("authorization") || lower.equals("x-forwarded-for") || lower.equals("x-real-ip") ||
               lower.equals("cache-control") || lower.equals("accept-language") || lower.equals("accept-encoding") ||
               lower.equals("upgrade-insecure-requests") || lower.equals("if-none-match") || lower.equals("if-modified-since") ||
               lower.equals("etag") || lower.equals("last-modified") || lower.equals("server") ||
               lower.equals("date") || lower.equals("age") || lower.equals("content-encoding") ||
               lower.equals("transfer-encoding") || lower.equals("www-authenticate") ||
               lower.startsWith("x-") || lower.startsWith("sec-") ||
               lower.contains("-token") || lower.contains("_token") ||
               lower.equals("token") || lower.equals("session") || lower.equals("xsrf-token") ||
               lower.equals("csrf-token") || lower.equals("csrf") || lower.equals("xsrf");
    }

    private List<String> getValidParamNames(byte[] requestBytes) {
        List<String> validParamNames = new ArrayList<>();
        try {
            IRequestInfo requestInfo = this.helpers.analyzeRequest(requestBytes);
            List<IParameter> parameters = requestInfo.getParameters();
            if (parameters != null) {
                for (IParameter param : parameters) {
                    if (param == null || param.getName() == null) continue;
                    String name = param.getName().toLowerCase();
                    if (name.equals("csrf") || name.equals("token") || name.equals("timestamp") || name.equals("nonce")) continue;
                    validParamNames.add(param.getName());
                }
            }
        } catch (Exception e) {
            this.callbacks.printError("[AI] getValidParamNames: " + e.getMessage());
        }
        return validParamNames;
    }

    public AIEngine(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, LogPanel logPanel, VulnDiscoveryListener listener) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.logPanel = logPanel;
        this.vulnListener = listener;
        this.gson = new Gson();
        this.httpClient = new OkHttpClient.Builder().connectTimeout(30L, TimeUnit.SECONDS).writeTimeout(30L, TimeUnit.SECONDS).readTimeout(120L, TimeUnit.SECONDS).build();
    }

    public void setVulnListener(VulnDiscoveryListener listener) {
        this.vulnListener = listener;
    }

    public void scanRequest(ScanTask task) {
        try {
            this.logPanel.log("\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501");
            this.logPanel.logAI("\u4efb\u52a1 #" + task.getId() + " | " + task.getMethod() + " " + task.getUrl());
            this.logPanel.log("\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501");
            task.clearProbeRecords();
            task.setStatus(ScanTask.TaskStatus.SCANNING);
            task.setAiTag("\u5206\u6790\u4e2d");
            this.logPanel.logAI("[\u5206\u6790] AI\u5206\u6790\u8bf7\u6c42\u7279\u5f81...");
            String requestInfo = this.buildRequestInfo(task.getOriginalRequest());
            JsonObject analysis = this.analyzeRequest(task, requestInfo);
            if (analysis == null) {
                task.setStatus(ScanTask.TaskStatus.FINISHED);
                task.setAiTag("\u5206\u6790\u5931\u8d25");
                this.callbacks.printError("[AI] AI分析失败");
                return;
            }
            String analysisText = this.safeGetString(analysis, "analysis", "\u5206\u6790\u5b8c\u6210");
            this.logPanel.logSuccess("[\u5b8c\u6210] " + analysisText);
            JsonArray testPayloads = analysis.getAsJsonArray("testPayloads");
            if (testPayloads == null || testPayloads.size() == 0) {
                task.setStatus(ScanTask.TaskStatus.FINISHED);
                task.setVulnLevel(ScanTask.VulnLevel.NONE);
                task.setAiTag("\u5b89\u5168");
                return;
            }
            ScanTask.ScanMode mode = task.getScanMode();
            List<String> validParamNames = this.getValidParamNames(task.getOriginalRequest().getRequest());
            task.setTestParams(String.join(", ", validParamNames));
            int validParamCount = Math.max(validParamNames.size(), 1);
            int targetPayloadsPerTypePerParam;
            if (mode != null && mode.isCustom()) {
                JsonArray vulnTypesArray = analysis.getAsJsonArray("vulnTypes");
                int vulnTypeCount = (vulnTypesArray != null && vulnTypesArray.size() > 0) ? vulnTypesArray.size() : 5;
                String vulnTypesList = "";
                if (vulnTypesArray != null) {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < vulnTypesArray.size(); i++) {
                        if (i > 0) sb.append("、");
                        sb.append(this.formatVulnName(vulnTypesArray.get(i).getAsString()));
                    }
                    vulnTypesList = sb.toString();
                }
            }
            targetPayloadsPerTypePerParam = PAYLOAD_COUNT_PER_PARAM;
            JsonArray filteredPayloads = this.filterAndDedupPayloads(testPayloads, task, validParamNames);
            this.logPanel.logAI("[\u8fc7\u6ee4\u540e\u4e2a\u6570: " + filteredPayloads.size() + "\u4e2a (after deduplication)");
            if (filteredPayloads.size() == 0) {
                task.setStatus(ScanTask.TaskStatus.FINISHED);
                task.setVulnLevel(ScanTask.VulnLevel.NONE);
                task.setAiTag("\u5b89\u5168");
                return;
            }
            task.setAiTag("\u6e17\u900f\u6d4b\u8bd5\u4e2d");
            int testCount = 0;
            this.logPanel.logAI("[\u6d4b\u8bd5] \u5171 " + filteredPayloads.size() + " \u4e2a\u8f7d\u8377");
            Set<String> allTestedParams = new HashSet<>();
            for (String pname : validParamNames) {
                allTestedParams.add(pname.toLowerCase());
            }
            List<String> testedPositions = new ArrayList<>();
            for (int i = 0; i < filteredPayloads.size(); ++i) {
                JsonObject payload = filteredPayloads.get(i).getAsJsonObject();
                if (!payload.has("type") || !payload.has("payload")) {
                    continue;
                }
                String vulnType = this.safeGetString(payload, "type", "UNKNOWN");
                String testData = this.safeGetString(payload, "payload", "");
                String position = this.safeGetString(payload, "position", null);
                if (testData.isEmpty() || position == null || position.equals("auto")) {
                    continue;
                }
                this.logPanel.logAI("[\u8f7d\u8377" + (i + 1) + "/" + filteredPayloads.size() + "] " + vulnType + " \u2192 " + testData + " [\u6ce8\u5165\u4f4d: " + position + "]");
                IHttpRequestResponse testResponse = this.sendTestRequest(task.getOriginalRequest(), testData, position);
                if (!testedPositions.contains(position.toLowerCase())) {
                    testedPositions.add(position.toLowerCase());
                }
                if (testResponse != null) {
                    task.addProbeRecord(new ScanTask.ProbeRecord(testCount, vulnType, testData, position, testResponse));
                    this.processTestResult(task, testResponse, testCount, vulnType, testData, position, requestInfo);
                    ++testCount;
                }
            }
            Set<String> uncoveredParams = new HashSet<>(allTestedParams);
            uncoveredParams.removeAll(testedPositions);
            if (!uncoveredParams.isEmpty()) {
                for (String uncovered : uncoveredParams) {
                    for (int i = 0; i < filteredPayloads.size() && i < 3; ++i) {
                        JsonObject payload = filteredPayloads.get(i).getAsJsonObject();
                        String vulnType = this.safeGetString(payload, "type", "UNKNOWN");
                        String testData = this.safeGetString(payload, "payload", "");
                        IHttpRequestResponse testResponse = this.sendTestRequest(task.getOriginalRequest(), testData, uncovered);
                        if (!testedPositions.contains(uncovered.toLowerCase())) {
                            testedPositions.add(uncovered.toLowerCase());
                        }
                        if (testResponse != null) {
                            task.addProbeRecord(new ScanTask.ProbeRecord(testCount, vulnType, testData, uncovered, testResponse));
                            this.processTestResult(task, testResponse, testCount, vulnType, testData, uncovered, requestInfo);
                            ++testCount;
                        }
                    }
                }
            }
            task.setStatus(ScanTask.TaskStatus.FINISHED);
            List<VulnResult> vulns = task.getVulnerabilities();
            if (vulns == null || vulns.isEmpty()) {
                task.setVulnLevel(ScanTask.VulnLevel.NONE);
                task.setAiTag("\u5b89\u5168");
                this.logPanel.logSuccess("[\u5b8c\u6210] \u672a\u53d1\u73b0\u6f0f\u6d1e | \u53d1\u5305: " + testCount);
            } else {
                task.setAiTag(this.getHighestVulnTag(task.getVulnerabilities()));
                this.logPanel.logSuccess("[\u5b8c\u6210] \u53d1\u73b0 " + task.getVulnerabilities().size() + " \u4e2a\u6f0f\u6d1e | \u53d1\u5305: " + testCount + " | \u7b49\u7ea7: " + task.getVulnLevel().getDisplayName());
            }
            this.logPanel.log("\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501");
        }
        catch (Exception e) {
            task.setStatus(ScanTask.TaskStatus.FINISHED);
            task.setAiTag("\u5f02\u5e38");
            task.setErrorMessage(e.getMessage());
            this.callbacks.printError("[扫描] 异常: " + e.getMessage());
            this.logPanel.log("\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501");
        }
    }

    private String buildRequestInfo(IHttpRequestResponse request) {
        int i;
        byte[] requestBytes = request.getRequest();
        if (requestBytes == null || requestBytes.length == 0) {
            return "无法解析请求信息：请求体为空";
        }
        String requestStr = new String(requestBytes, StandardCharsets.UTF_8);
        StringBuilder info = new StringBuilder();
        info.append("\u8bf7\u6c42\u65b9\u6cd5\u548cURL\uff1a\n");
        String[] lines = requestStr.split("\r?\n");
        if (lines.length > 0) {
            info.append(lines[0]).append("\n\n");
        }
        info.append("\u8bf7\u6c42\u5934\uff1a\n");
        boolean bodyStart = false;
        for (i = 1; i < lines.length; ++i) {
            if (lines[i].trim().isEmpty()) {
                bodyStart = true;
                break;
            }
            info.append(lines[i]).append("\n");
        }
        if (bodyStart && lines.length > 0) {
            info.append("\n\u8bf7\u6c42\u4f53\uff1a\n");
            for (i = 0; i < lines.length; ++i) {
                if (!lines[i].trim().isEmpty() || i + 1 >= lines.length) continue;
                StringBuilder body = new StringBuilder();
                for (int j = i + 1; j < lines.length && body.length() < 2000; ++j) {
                    body.append(lines[j]).append("\n");
                }
                info.append(body.toString());
                if (body.length() < 2000) break;
                info.append("...(\u5df2\u622a\u65ad)");
                break;
            }
        }
        return info.toString();
    }

    private JsonObject analyzeRequest(ScanTask task, String requestInfo) {
        try {
            block14: {
                int start;
                int end;
                ConfigManager.Config config = ConfigManager.getInstance().getConfig();
                String systemPrompt = this.resolveSystemPrompt(task, config);
                String userPrompt = this.buildAnalyzeUserPrompt(task, requestInfo);
                JsonObject requestBody = this.buildAIRequest(systemPrompt, userPrompt);
                String responseBody = this.callAI(requestBody);
                if (responseBody == null) {
                    return null;
                }
                JsonObject result = this.gson.fromJson(responseBody, JsonObject.class);
                String content = this.extractAIContent(result);
                if (content == null) {
                    return null;
                }
                if (content.contains("{") && (end = this.findClosingBrace(content, start = content.indexOf("{"))) > start) {
                    String jsonStr = content.substring(start, end);
                    try {
                        JsonObject analysisResult = this.gson.fromJson(jsonStr, JsonObject.class);
                        if (!analysisResult.has("testPayloads")) {
                            analysisResult.add("testPayloads", new JsonArray());
                        }
                        if (!analysisResult.has("analysis")) {
                            analysisResult.addProperty("analysis", "AI\u5206\u6790\u5b8c\u6210");
                        }
                        this.logInitialAnalysis(analysisResult);
                        return analysisResult;
                    }
                    catch (JsonSyntaxException jsonEx) {
                        String fixedJson = this.fixIncompleteJson(jsonStr);
                        if (fixedJson != null) {
                            try {
                                JsonObject analysisResult = this.gson.fromJson(fixedJson, JsonObject.class);
                                if (!analysisResult.has("testPayloads")) {
                                    analysisResult.add("testPayloads", new JsonArray());
                                }
                                if (!analysisResult.has("analysis")) {
                                    analysisResult.addProperty("analysis", "AI\u5206\u6790\u5b8c\u6210\uff08\u5df2\u4fee\u590d\u4e0d\u5b8c\u6574JSON\uff09");
                                }
                                this.logInitialAnalysis(analysisResult);
                                return analysisResult;
                            }
                            catch (Exception fixEx) {
                                this.callbacks.printError("[AI] JSON修复失败: " + fixEx.getMessage());
                            }
                        }
                    }
                }
            }
            return null;
        }
        catch (Exception e) {
            this.callbacks.printError("[AI] analyzeRequest异常: " + e.getMessage());
            return null;
        }
    }

    private String resolveSystemPrompt(ScanTask task, ConfigManager.Config config) {
        ScanTask.ScanMode mode = task != null ? task.getScanMode() : ScanTask.ScanMode.CUSTOM;
        if (mode == null || mode.isCustom()) {
            boolean useCustomPrompt = config.getSystemPrompt() != null && !config.getSystemPrompt().trim().isEmpty();
            return useCustomPrompt ? config.getSystemPrompt() : this.getDefaultAnalyzePrompt();
        }
        return this.buildSingleVulnPrompt(mode);
    }

    private String buildAnalyzeUserPrompt(ScanTask task, String requestInfo) {
        ScanTask.ScanMode mode = task != null ? task.getScanMode() : ScanTask.ScanMode.CUSTOM;
        if (mode == null || mode.isCustom()) {
            return "分析以下HTTP请求并制定测试策略：\n\n" + requestInfo;
        }
        return "仅对以下HTTP请求进行“" + mode.getDisplayName() + "”检测，不要扩展到其他漏洞类型。\n\n" + requestInfo;
    }

    private String buildSingleVulnPrompt(ScanTask.ScanMode mode) {
        String typeKey = mode.getTypeKey();
        String payloadGuide;
        String wafBypassGuide;
        switch (mode) {
            case FILE_UPLOAD: {
                payloadGuide = "只生成文件上传相关payload：后缀绕过(.php/.asp/.jsp/.aspx)、MIME绕过、内容绕过、双扩展名(.php.jpg)、空字节截断(.php%00)、.htaccess绕过、竞争上传。" +
                    "\n无害文件：test.txt(内容test)、info.php(<?php echo 123;?>)、test.jsp(<% out.print(123); %>)。";
                wafBypassGuide = "WAF绕过技巧(必须占payload总数50%)：大小写混合(PhP/PhP3/PhP4/PhP5)、多重后缀(.php.jpg/.php.jpeg)、特殊字符填充(垃圾数据混淆)、修改Content-Type(image/gif)、0x00截断、::DATA流、.user.ini绕过、Apache配置文件绕过。";
                break;
            }
            case COMMAND_INJECTION: {
                payloadGuide = "只生成命令注入payload，命令仅允许whoami、id、echo、ping -c 1 127.0.0.1、sleep 1、curl dnslog.cn。" +
                    "\n基础载荷：;whoami、|whoami、&whoami&、&&whoami、||whoami、`whoami`、$(whoami)。";
                wafBypassGuide = "WAF绕过技巧(必须占payload总数50%)：管道符组合(whoami|cat)、分号分隔(;whoami)、&&和||、反引号$(whoami)、URL编码(%20;whoami)、大小写混合(WhoAmI/whoamI)、制表符/换行符分隔(\nwhoami)、环境变量拼接($HOME)、空字符截断(whoam%00i)、多行注入、Base64编码(echoYmFzZTY0|base64 -d|bash)。";
                break;
            }
            case SSTI: {
                payloadGuide = "只生成SSTI模板注入payload，覆盖Jinja2/Twig/Freemarker/Velocity/Handlebars/Django表达式。" +
                    "\n基础载荷：{{7*7}}、${7*7}、<%= 7*7 %>、#{7*7}、*T{{7*7}}*。";
                wafBypassGuide = "WAF绕过技巧(必须占payload总数50%)：模板语法变形({{7*'7'}}、{{config}}、{{request.application}})、URL编码({{''|join}})、HTML实体编码(&#123;&#123;7*7&#125;&#125;)、注释混淆(/*{{7*7}}*/)、嵌套花括号({{{{}}}})、特殊字符插入(${_{7*7}})、空格替代(_)、数字与字符串转换、polyglot payload。";
                break;
            }
            case SQL_INJECTION: {
                payloadGuide = "只生成SQL注入payload，覆盖联合注入、布尔盲注、时间盲注、报错注入、堆叠查询、宽字节注入。" +
                    "\n基础载荷：' OR '1'='1、AND 1=1、AND 1=2、SLEEP(1)、' XOR 1=1#、1' ORDER BY 10#。";
                wafBypassGuide = "WAF绕过技巧(必须占payload总数50%)：注释替代空格(--%0a/**/)、UNION SELECT/**/ALL、大小写混合(UniOn SeLeCt)、URL编码(%27%20OR%20%271%27%3D%271)、宽字节绕过(%df' OR 1=1--)、HPP参数污染(_parameter=value)、双重URL编码(%2527)、Unicode编码(\\u0027)、二阶注入、脏数据填充(OOB通道)。";
                break;
            }
            case XSS: {
                payloadGuide = "只生成XSS payload，覆盖反射型、存储型、DOM型与通用场景。" +
                    "\n基础载荷：alert(1)、console.log('xss')、prompt(1)、confirm(1)。";
                wafBypassGuide = "WAF绕过技巧(必须占payload总数50%)：大小写混合(<ScRiPt>alert(1)</ScRiPt>)、事件处理器混淆(onerror=、onload=、onmouseover=)、HTML实体编码(&lt;script&gt;alert(1)&lt;/script&gt;)、SVG标签(<svg onload=alert(1)>)、JavaScript伪协议(javascript:alert(1))、数据URI(data:text/html,<script>alert(1)</script>)、DOMPurify绕过、双重编码、注释混淆、img/src标签利用、空属性触发。";
                break;
            }
            case SSRF: {
                payloadGuide = "只生成SSRF payload，使用公共测试DNS或可控服务器(interact.sh/burpcollaborator.net)。" +
                    "\n基础载荷：http://127.0.0.1、http://localhost、http://169.254.169.254。";
                wafBypassGuide = "WAF绕过技巧(必须占payload总数50%)：localhost替代127.0.0.1(xxx.127.0.0.1.xxx)、IP地址十进制转换(2130706433)、IPv6地址(::1)、URL跳转重定向(302跳转到内网)、DNS重绑定、@符绕过(https://google.com@127.0.0.1)、xip.io域名(127.0.0.1.xip.io)、绕过localhost限制(0x7f000001)、私有IP编码。";
                break;
            }
            case XXE: {
                payloadGuide = "只生成XXE payload，使用外部测试实体指向webhook.site或本地回环地址。" +
                    "\n基础载荷：<!DOCTYPE foo[<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>。";
                wafBypassGuide = "WAF绕过技巧(必须占payload总数50%)：XML实体编码、CDATA节包裹(<![CDATA[...]]>)、参数实体使用(%xx;)、无回显XXE(Blind XXE通过外部DTD)、Base64编码外部实体、SOAP XML注入、XInclude注入、XMLDecoder绕过、JSON XML注入、嵌套实体。";
                break;
            }
            case FILE_INCLUDE: {
                payloadGuide = "只生成文件包含payload，覆盖LFI/RFI，验证目标仅使用/etc/passwd或windows/win.ini。" +
                    "\n基础载荷：../../../../etc/passwd、/etc/passwd、../etc/passwd。";
                wafBypassGuide = "WAF绕过技巧(必须占payload总数50%)：路径遍历多重编码(%2e%2e%2f%2e%2e%2f%2e%2e%2f)、null字节截断(%00)、double URL编码(%252e%252e%252f)、问号截断(?file=/etc/passwd%00)、Linux/proc/self/environ、php://filter/read=convert.base64-encode/resource=、zip://和phar://伪协议、字符串拼接(w嘿嘿/etc/passwd)、UTF-8编码(%c0%ae)。";
                break;
            }
            case CSRF: {
                payloadGuide = "只生成CSRF检测payload，生成无敏感操作POC，重点检查Token、Referer、SameSite。" +
                    "\n基础载荷：自动提交的HTML表单、无Token的POST请求。";
                wafBypassGuide = "WAF绕过技巧(必须占payload总数50%)：绕过Referer检查(空Referer、伪协议javascript:、数据URI作为Referer:data:text/html,<script>alert(1)</script>;base64,..)、利用同域漏洞绕过、CORS跨域利用(JSONP劫持)、Flash跨域(.crossdomain.xml)、CSRF Token预测、固定Token利用。";
                break;
            }
            case DESERIALIZATION: {
                payloadGuide = "只生成反序列化检测payload，使用无害DNS外带探测，不进行破坏性利用。" +
                    "\n基础载荷：Python pickle.loads()、Ruby YAML.load()、PHP unserialize()触发点。";
                wafBypassGuide = "WAF绕过技巧(必须占payload总数50%)：Python pickle绕过(RCE gadget chain)、Ruby YAML注入(<%yaml%>)、PHP序列化Payload变形(O:8:\"stdClass\":2:{s:4:\"foo\";s:3:\"bar\";})、Javaysafe-alternatives绕过、修改__proto__属性、Content-Type绕过(application/json)、JSON反序列化绕过、XMLDecoder绕过。";
                break;
            }
            case AUTH_BYPASS: {
                payloadGuide = "只生成越权检测payload，覆盖水平越权、垂直越权、IDOR，不做其他漏洞测试。" +
                    "\n基础载荷：修改用户ID参数值、访问其他用户资源。";
                wafBypassGuide = "WAF绕过技巧(必须占payload总数50%)：修改用户ID参数值(id=123→id=124)、JWT Token伪造/篡改(修改alg为none/HS256→RS256)、OAuth 2.0 Token劫持、SessionID预测、会话固定攻击、密码重置Token预测、IDOR绕过(修改resource_id)、越权枚举。";
                break;
            }
            case PATH_TRAVERSAL: {
                payloadGuide = "只生成路径遍历payload，验证目标仅使用/etc/passwd或windows/win.ini。" +
                    "\n基础载荷：../../../../etc/passwd、../etc/passwd、/etc/passwd、..\\..\\..\\windows\\win.ini。";
                wafBypassGuide = "WAF绕过技巧(必须占payload总数50%)：多重URL编码(%2e%2e%2f%2e%2e%2f%2e%2e%2f)、double URL编码(%252e%252e%252f)、null字节截断(%00)、问号截断(?file=/etc/passwd%00)、双斜杠替代(//etc//passwd)、反斜杠替代(..\\..\\win.ini)、Unicode编码(%c0%ae)、路径规范化绕过(/././etc/passwd)、Base64编码、零字节填充。";
                break;
            }
            case DIRECTORY_TRAVERSAL: {
                payloadGuide = "只生成目录穿越payload，验证目标仅使用/etc/passwd或windows/win.ini。" +
                    "\n基础载荷：../../../../etc/passwd、../etc/passwd、/etc/passwd、..\\..\\..\\windows\\win.ini。";
                wafBypassGuide = "WAF绕过技巧(必须占payload总数50%)：多重URL编码(%2e%2e%2f%2e%2e%2f%2e%2e%2f)、double URL编码(%252e%252e%252f)、null字节截断(%00)、问号截断(?file=/etc/passwd%00)、双斜杠替代(//etc//passwd)、反斜杠替代(..\\..\\win.ini)、Unicode编码(%c0%ae)、路径规范化绕过(/././etc/passwd)、Base64编码、零字节填充。";
                break;
            }
            case SENSITIVE_DATA_EXPOSURE: {
                payloadGuide = "只生成敏感信息泄露检测payload，检查URL路径、请求头、响应头中的敏感信息泄露。" +
                    "\n【重要】这些payload必须作为URL路径参数(position=URL_PATH)，不能作为参数值！例如：/api/debug、/actuator/env、/.git/config等。" +
                    "\n基础载荷：/api/debug、/actuator/env、/.git/config、/.env、/config.php、/database.yml、/backup.sql。";
                wafBypassGuide = "WAF绕过技巧(必须占payload总数50%)：路径遍历绕过(../.git/config)、403绕过(使用HEAD方法、修改Accept头)、信息枚举(猜测常见路径)、HTTP参数污染(_=debug)、编码绕过(Base64/Unicode)、元数据泄露(.DS_Store、.swp文件)、Git/SVN索引文件访问、Spring Boot actuator端点探测。";
                break;
            }
            case LOGIC_FLAW: {
                payloadGuide = "只生成逻辑漏洞检测payload，检查验证码绕过、暴力破解、频率限制绕过、业务逻辑漏洞。" +
                    "\n【重要】payload必须作为参数值注入到实际参数(position=实际参数名)。" +
                    "\n基础载荷：验证码重放(同一验证码多次使用)、密码暴力破解、无限循环下单、负数量购买、越权操作。";
                wafBypassGuide = "WAF绕过技巧(必须占payload总数50%)：暴力破解IP代理池、BurpSuite Intruder多线程、验证码识别(OCR)、绕过频率限制(时间随机化、IP轮换)、Session固定攻击、Cookie篡改、Token重放、绕过图形验证码(复用已验证验证码)、业务逻辑参数篡改(price=-1、quantity=0)。";
                break;
            }
            case RACE_CONDITION: {
                payloadGuide = "只生成条件竞争漏洞检测payload，检查并发场景下的时序问题。" +
                    "\n【重要】payload必须作为参数值(position=实际参数名)，发送到目标参数后进行并发测试。" +
                    "\n基础载荷：并发抢购(同一商品同时下单)、并发积分兑换、多次领取优惠券。";
                wafBypassGuide = "WAF绕过技巧(必须占payload总数50%)：多线程并发(BurpSuite Turbo Intruder)、请求间隔极短(0.001秒)、HPP参数污染发送同一参数多次、HTTP/2多路复用、TCP并发连接、Race condition专用工具(如 Burp Collaborator, Intruder耿迟攻击)、边界条件竞争(时间窗口极窄的转账)、并发文件上传覆盖。";
                break;
            }
            case TYPE_CONFUSION: {
                payloadGuide = "只生成类型混淆漏洞检测payload，检查不同类型参数处理错误。" +
                    "\n【重要】payload必须作为参数值(position=实际参数名)，测试类型转换是否安全。" +
                    "\n基础载荷：数字类型参数注入字符串、数组参数注入、JSON类型混淆、类型转换错误。";
                wafBypassGuide = "WAF绕过技巧(必须占payload总数50%)：类型转换函数差异(Array, Object混淆)、JSON参数污染({}替代[])、PHP类型 juggling(字符串与数字)、弱类型比较绕过(== vs ===)、序列化类型混淆(String vs Array)、UTF-7/UTF-16 BOM注入、XML类型混淆、参数类型篡改(id[]=1 vs id=1)。";
                break;
            }
            default: {
                payloadGuide = "只生成对应漏洞类型的无害化payload，并提供WAF绕过技巧。";
                wafBypassGuide = "提供50%的WAF绕过payload，使用编码、混淆、分块传输等技术。";
            }
        }
        return "你是顶级渗透测试专家。分析HTTP请求并制定" + mode.getDisplayName() + "测试策略。\n\n"
                + "核心原则：只生成最有可能存在漏洞的payload，而非罗列多样化示例。\n\n"
                + "【最重要】position字段填写规则（必须严格遵守）：\n"
                + "1. position必须是实际存在的参数名！包括：查询参数(?id=1中的id)、JSON参数(username、ip_address等)、Form参数、RESTful路径参数(/user/{id}中的id)。\n"
                + "2. 【绝对禁止】position绝对不能是HTTP请求头！包括但不限于：Host、User-Agent、Referer、Cookie、Content-Type、Authorization、X-Forwarded-For、Origin、Token、Session、csrf_token、xsrf-token等所有请求头及其变体！\n"
                + "3. 【禁止】position不能是URL_PATH、URL、PATH等抽象名词，必须用实际参数名！\n"
                + "4. 【强制】识别出的每个参数（不含请求头）都必须作为position生成对应payload，一个都不能遗漏！\n"
                + "5. 【绝对禁止】position禁止为空、null、auto或任何无效值！如果payload没有指定position或position无效，该payload将被直接过滤！\n\n"
                + "硬性要求（必须严格遵守，禁止超出）：\n"
                + "1. 【强制】payload总数绝对不能超过：有效参数个数 × 10\n"
                + "   - 例如：3个参数 × 10 = 30个（不允许超过30个！）\n"
                + "2. 【强制】每个参数必须精确生成10个payload，不多不少！\n"
                + "   - 例如：3个参数 = 3组，每组恰好10个payload，总计30个\n"
                + "3. 【强制】50%的payload必须是WAF绕过技术，每个参数都要精确50%！\n"
                + "   - 例如：每组10个payload中，5个普通+5个绕过，不能多也不能少！\n"
                + "4. 【绝对禁止】生成超出上述计算结果的payload，哪怕只多1个也不行！\n"
                + "5. 【禁止】payload之间必须有实际区别，不能是微小变体\n"
                + "6. 【禁止】不能重复，不能为空\n\n"
                + "无害化测试要求（所有payload必须严格遵守，禁止生成任何可能对目标造成破坏的payload）：\n"
                + "- 文件上传：test.txt(内容test)、info.php(<?php echo 123;?>)、test.jsp(<% out.print(123); %>)\n"
                + "- 命令注入：whoami/id/echo/ping -c 1 127.0.0.1/sleep 1/curl dnslog.cn\n"
                + "- SQL注入：' OR '1'='1/AND 1=1/SLEEP(1)/' XOR 1=1#\n"
                + "- XSS：alert(1)/console.log('xss')/prompt(1)/confirm(1)\n"
                + "- SSRF：interact.sh或burpcollaborator.net或dnslog.cn或127.0.0.1\n"
                + "- XXE：外部实体指向webhook.site/dnslog.cn，禁止读取敏感文件\n"
                + "- 文件包含：/etc/passwd或windows/win.ini\n"
                + "- SSTI：{{7*7}}/${7*7}/<%= 7*7 %>，只做数学运算验证\n"
                + "- CSRF：自动提交的HTML表单(无敏感操作)\n"
                + "- 反序列化：使用无害DNS外带探测(OOB)，不进行RCE利用\n"
                + "- 越权检测：使用自己的测试账号数据，不访问其他真实用户数据\n"
                + "- 路径遍历：../../../../etc/passwd、..\\..\\..\\windows\\win.ini\n"
                + "- 敏感信息泄露：/api/debug、/actuator/env、/.git/config\n"
                + "- 逻辑漏洞：验证码重放、负数量购买(price=-1)\n"
                + "- 条件竞争：同一商品并发抢购\n"
                + "- 类型混淆：数字参数注入字符串(id=abc)\n\n"
                + "分析要点：\n"
                + "1. 识别请求组件：查询参数(?id=1中的id)、JSON参数(username、ip_address等)、Form参数、RESTful路径参数(/user/{id}中的id)。\n"
                + "2. 本次只检测一种漏洞类型：" + mode.getDisplayName() + "。\n"
                + "3. " + payloadGuide + "\n"
                + "4. " + wafBypassGuide + "\n"
                + "5. WAF指纹识别：识别Cloudflare/AWS WAF/ModSecurity/安全狗/云锁/宝塔/360WebScan/Imperva/F5/Nginx/apache。\n"
                + "6. 基于参数特征智能选择最可能成功的攻击向量。\n\n"
                + "输出要求：返回纯JSON，不要markdown代码块。\n"
                + "JSON格式：{\"analysis\":\"分析发现登录接口存在SQL注入风险，WAF类型为安全狗\",\"vulnTypes\":[\"" + typeKey + "\"],\"testPayloads\":[{\"type\":\"" + typeKey + "\",\"payload\":\"基础payload\",\"position\":\"username\",\"wafBypass\":false},{\"type\":\"" + typeKey + "\",\"payload\":\"WAF绕过payload\",\"position\":\"username\",\"wafBypass\":true}]}";
    }

    private String getDefaultAnalyzePrompt() {
        return "你是顶级渗透测试专家。分析HTTP请求并制定测试策略。\n\n"
                + "核心原则：只生成最有可能存在漏洞的payload，而非罗列多样化示例。\n\n"
                + "【最重要】position字段填写规则（必须严格遵守）：\n"
                + "1. position必须是实际存在的参数名！包括：查询参数(?id=1中的id)、JSON参数(username、ip_address等)、Form参数、RESTful路径参数(/user/{id}中的id)。\n"
                + "2. 【绝对禁止】position绝对不能是HTTP请求头！包括但不限于：Host、User-Agent、Referer、Cookie、Content-Type、Authorization、X-Forwarded-For、Origin、Token、Session、csrf_token、xsrf-token等所有请求头及其变体！\n"
                + "3. 【禁止】position不能是URL_PATH、URL、PATH等抽象名词，必须用实际参数名！\n"
                + "4. 【强制】识别出的每个参数（不含请求头）都必须作为position生成对应payload，一个都不能遗漏！\n"
                + "5. 【绝对禁止】position禁止为空、null、auto或任何无效值！如果payload没有指定position或position无效，该payload将被直接过滤！\n\n"
                + "硬性要求（必须严格遵守，禁止超出）：\n"
                + "1. 【强制】payload总数绝对不能超过：漏洞类型数(最多5种) × 有效参数个数 × 10\n"
                + "   - 例如：3种漏洞类型 × 2个参数 × 10 = 60个（不允许超过60个！）\n"
                + "2. 【强制】每个漏洞类型对每个有效参数必须精确生成10个payload，不多不少！\n"
                + "   - 例如：3种漏洞类型 × 2个参数 = 6组，每组恰好10个payload，总计60个\n"
                + "3. 【强制】50%的payload必须是WAF绕过技术，每个参数、每种漏洞类型都要精确50%！\n"
                + "   - 例如：每组10个payload中，5个普通+5个绕过，不能多也不能少！\n"
                + "4. 【绝对禁止】生成超出上述计算结果的payload，哪怕只多1个也不行！\n"
                + "5. 【禁止】payload之间必须有实际区别，不能是微小变体\n"
                + "6. 【禁止】不能重复，不能为空\n\n"
                + "分析要点：\n"
                + "1. 全面识别请求组件：查询参数(?id=1中的id)、JSON参数(username、ip_address等)、Form参数、RESTful路径参数(/user/{id}中的id)、文件上传点。\n"
                + "【重要】识别出的每个参数（不含请求头）都要作为position生成对应payload，不能遗漏！\n"
                + "2. 【关键】只选择最可能存在的5种漏洞类型（根据请求特征判断最可能存在的漏洞）：\n"
                + "   - SQL_INJECTION：SQL注入\n"
                + "   - XSS：XSS跨站脚本\n"
                + "   - COMMAND_INJECTION：命令注入\n"
                + "   - FILE_UPLOAD：文件上传\n"
                + "   - SSRF：服务端请求伪造\n"
                + "   - XXE：XML外部实体注入\n"
                + "   - FILE_INCLUDE：文件包含\n"
                + "   - SSTI：模板注入\n"
                + "   - CSRF：跨站请求伪造\n"
                + "   - DESERIALIZATION：反序列化漏洞\n"
                + "   - AUTH_BYPASS：越权/认证绕过\n"
                + "   - PATH_TRAVERSAL：路径遍历\n"
                + "   - DIRECTORY_TRAVERSAL：目录穿越\n"
                + "   - SENSITIVE_DATA_EXPOSURE：敏感信息泄露\n"
                + "   - LOGIC_FLAW：逻辑漏洞\n"
                + "   - RACE_CONDITION：条件竞争\n"
                + "   - TYPE_CONFUSION：类型混淆\n\n"
                + "WAF指纹识别与绕过技术（50% payload必须使用绕过技术）：\n"
                + "- WAF识别：Cloudflare/AWS WAF/ModSecurity/安全狗/云锁/宝塔/360WebScan/Imperva/F5/Nginx/apache\n"
                + "- SQL注入绕过：注释替代空格(--%0a/**/)、UNION SELECT/**/ALL、大小写混合(UniOn SeLeCt)、URL编码(%27)、宽字节(%df')、HPP参数污染(_parameter=value)、双重URL编码(%2527)、二阶注入\n"
                + "- XSS绕过：大小写混合(<ScRiPt>)、事件处理器(onerror/onload)、HTML实体编码(&lt;script&gt;)、SVG标签(<svg>)、JavaScript伪协议(javascript:alert(1))、数据URI、DOMPurify绕过、注释混淆\n"
                + "- 命令注入绕过：管道符(whoami|cat)、分号(;whoami)、&&和||、反引号$(whoami)、URL编码(%20;)、空字符截断(%00)、多行注入、Base64编码\n"
                + "- 文件上传绕过：大小写混合(PhP/PhP3/PhP4)、多重后缀(.php.jpg)、0x00截断、Content-Type伪造、.htaccess、.user.ini\n"
                + "- SSRF绕过：IP十进制(2130706433)、localhost变种、IPv6(::1)、@符绕过、DNS重绑定、xip.io、302重定向\n"
                + "- XXE绕过：CDATA节、参数实体、Blind XXE、Base64编码、SOAP注入、XInclude\n"
                + "- 文件包含绕过：路径遍历多重编码(%2e%2e%2f)、null字节(%00)、double URL编码(%252e)、php://filter、zip://、phar://\n"
                + "- SSTI绕过：模板语法变形({{7*'7'}})、URL编码、HTML实体编码、注释混淆、嵌套花括号\n"
                + "- CSRF绕过：空Referer、javascript:伪协议、数据URI作为Referer、JSONP劫持\n"
                + "- 反序列化绕过：修改__proto__、Content-Type绕过(application/json)、JSON反序列化\n"
                + "- 越权绕过：修改用户ID(id=123→id=124)、JWT Token伪造(alg=none)、SessionID预测\n"
                + "- 路径遍历绕过：多重编码(%2e%2e%2f)、null字节(%00)、double URL编码(%252e)、UTF-8编码(%c0%ae)\n"
                + "- 敏感信息泄露绕过：路径遍历(../.git/config)、403绕过(HEAD方法)、信息枚举、Spring Boot actuator端点\n"
                + "- 逻辑漏洞绕过：验证码重放、负数量(price=-1)、Session固定、Token重放\n"
                + "- 条件竞争绕过：多线程并发(0.001秒间隔)、HPP参数污染、HTTP/2多路复用\n"
                + "- 类型混淆绕过：数组替代([]替代{})、弱类型比较(== vs ===)、参数类型篡改(id[]=1)\n\n"
                + "无害化测试要求（所有payload必须遵守）：\n"
                + "- SQL注入：' OR '1'='1/AND 1=1/SLEEP(1)/' XOR 1=1#\n"
                + "- XSS：alert(1)/console.log('xss')/prompt(1)/confirm(1)\n"
                + "- 命令注入：whoami/id/echo/ping -c 1 127.0.0.1/sleep 1/curl dnslog.cn\n"
                + "- 文件上传：test.txt(内容test)、info.php(<?php echo 123;?>)、test.jsp(<% out.print(123); %>)\n"
                + "- SSRF：interact.sh或burpcollaborator.net或dnslog.cn或127.0.0.1\n"
                + "- XXE：外部实体指向webhook.site/dnslog.cn，禁止读取敏感文件\n"
                + "- 文件包含：/etc/passwd或windows/win.ini\n"
                + "- SSTI：{{7*7}}/${7*7}/<%= 7*7 %>，只做数学运算验证\n"
                + "- CSRF：自动提交的HTML表单(无敏感操作)\n"
                + "- 反序列化：使用无害DNS外带探测(OOB)，不进行RCE利用\n"
                + "- 越权检测：使用自己的测试账号数据，不访问其他真实用户数据\n"
                + "- 路径遍历：../../../../etc/passwd、..\\..\\..\\windows\\win.ini\n"
                + "- 敏感信息泄露：/api/debug、/actuator/env、/.git/config\n"
                + "- 逻辑漏洞：验证码重放、负数量购买(price=-1)\n"
                + "- 条件竞争：同一商品并发抢购\n"
                + "- 类型混淆：数字参数注入字符串(id=abc)\n\n"
                + "输出要求：必须返回纯JSON格式，不要markdown代码块，不要额外说明。vulnTypes数组最多5个元素，只包含最可能的漏洞类型！\n"
                + "JSON格式：{\"analysis\":\"发现登录接口存在SQL注入风险，WAF类型为安全狗\",\"vulnTypes\":[\"SQL_INJECTION\",\"XSS\"],\"testPayloads\":[{\"type\":\"SQL_INJECTION\",\"payload\":\"' OR '1'='1\",\"position\":\"username\",\"wafBypass\":false},{\"type\":\"SQL_INJECTION\",\"payload\":\"%df' OR 1=1--\",\"position\":\"username\",\"wafBypass\":true},{\"type\":\"XSS\",\"payload\":\"<script>alert(1)</script>\",\"position\":\"username\",\"wafBypass\":false}]}";
    }

    private String getDefaultVerifyPrompt() {
        return "作为渗透测试专家，仔细分析测试结果，判断漏洞是否真实存在。\n\n"
                + "验证要求：\n"
                + "1. 深入分析响应内容，不能只看响应长度或状态码。\n"
                + "2. 查找响应中的具体特征：\n\n"
                + "SQL注入特征：数据库错误信息(MySQL/PostgreSQL/Oracle/SQL Server/MariaDB)、联合查询数据回显、布尔差异(AND 1=1 vs AND 1=2响应不同)、时间延迟(>=5秒)、DNS外带请求、堆叠查询效果、错误的SQL语法\n\n"
                + "XSS特征：JavaScript代码未编码直接输出、alert/confirm/prompt弹窗、DOM元素注入成功(img onerror/svg onload)、HTML标签被解析(<script>、<img>、<svg>)、存储型XSS持久化、反射型XSS URL回显\n\n"
                + "命令执行特征：系统命令输出(id/uid/whoami/echo test/hostname)、文件列表(/bin/ls /tmp)、延迟显著(sleep>=5秒)、DNS/HTTP外带请求、管道符执行结果\n\n"
                + "文件上传特征：文件路径泄露(/uploads/xxx、/upload/xxx.php)、访问上传文件返回200、上传文件可执行(返回源代码)、MIME类型正确\n\n"
                + "文件包含特征：/etc/passwd内容出现、php://filter读取源码成功、日志文件内容(/var/log/apache2/access.log)、远程文件包含(RFI)成功获取远程内容\n\n"
                + "SSRF特征：内网IP响应(127.0.0.1/192.168.x.x/10.x.x.x)、云元数据泄露(169.254.169.254/aws)、端口扫描结果开放、file://协议读取本地文件成功\n\n"
                + "XXE特征：文件读取(/etc/passwd、/etc/shadow)、DNS外带请求成功、外部实体解析结果、blind XXE外部DTD请求\n\n"
                + "SSTI模板注入特征：数学运算结果回显(7*7=49/{{7*7}}/{{config}})、模板引擎语法被解析、payload执行后的输出与预期数学结果一致\n\n"
                + "CSRF特征：请求成功执行但无CSRF Token验证、无Referer检查、无SameSite Cookie限制、跨域请求被成功执行(需结合同源策略判断)\n\n"
                + "反序列化特征：成功的DNS/HTTP外带请求、Python/Ruby/Java反序列化成功执行代码、pickle.loads()或yaml.load()执行结果\n\n"
                + "越权/IDOR特征：修改ID参数(id=123→id=124)后访问到其他用户数据、低权限用户执行高权限操作成功、响应返回未授权访问的数据\n\n"
                + "路径遍历特征：/etc/passwd或windows/win.ini内容出现、敏感文件读取成功(/.git/config、/.env)、目录列表显示\n\n"
                + "目录穿越特征：../或..\\穿越目录边界、UTF-8编码目录遍历(%c0%ae%c0%ae)、null字节截断绕过(%00)、双URL编码(%252e%252e)、路径规范化绕过(/././)、成功读取目标目录外文件\n\n"
                + "敏感信息泄露特征：.git/config、.env、database.yml、backup.sql、/api/debug、/actuator/env、/health端点、堆栈跟踪信息、源码泄露\n\n"
                + "逻辑漏洞特征：验证码可重复使用、负数值购买成功(price=-1)、超额兑换优惠券、次数限制绕过、时间戳绕过、 Session固定\n\n"
                + "条件竞争特征：并发请求后获得不当利益(重复领取、多次兑换)、时序问题导致数据不一致、race condition专用检测工具结果\n\n"
                + "类型混淆特征：数字参数收到字符串但未报错、类型转换后结果异常(1 vs '1' vs [1])、弱类型比较结果(0=='0'/[]=='')、JSON/XML类型混淆成功\n\n"
                + "3. 排除误判：参数验证失败统一错误、WAF拦截页面(403/406/445)、重定向到登录页、HTML实体编码转义、CSP阻止、业务逻辑正常返回、静态资源缓存\n\n"
                + "4. 证据充分：必须有明确技术特征证明漏洞存在，证据链完整\n\n"
                + "5. 置信度评分：只有>=95%才报告漏洞\n\n"
                + "输出要求：必须返回纯JSON格式，不要markdown代码块，不要额外说明。\n"
                + "JSON格式：{\"vulnerable\":true,\"confidence\":95,\"vulnType\":\"SQL_INJECTION\",\"level\":\"CRITICAL\",\"description\":\"响应包含MySQL错误：You have an error in your SQL syntax，证明存在SQL注入\",\"tag\":\"SQL注入\"}";
    }

    private JsonObject verifyVulnerability(String requestInfo, String payload, String response, String vulnType) {
        try {
            ConfigManager.Config config = ConfigManager.getInstance().getConfig();
            boolean useCustomPrompt = config.getVerifyPrompt() != null && !config.getVerifyPrompt().isEmpty();
            String verifyPrompt = useCustomPrompt ? config.getVerifyPrompt() : this.getDefaultVerifyPrompt();
            String prompt = String.format("\u539f\u59cb\u8bf7\u6c42\uff1a\n%s\n\n\u6d4b\u8bd5\u8f7d\u8377\uff1a%s\n\n\u6f0f\u6d1e\u7c7b\u578b\uff1a%s\n\n\u5b8c\u6574HTTP\u54cd\u5e94\uff08\u5305\u542b\u72b6\u6001\u884c\u3001\u54cd\u5e94\u5934\u3001\u54cd\u5e94\u4f53\uff09\uff1a\n%s\n\n\u8bf7\u5206\u6790\u8fd9\u4e2a\u5b8c\u6574\u7684HTTP\u54cd\u5e94\uff0c\u5224\u65ad\u6d4b\u8bd5\u8f7d\u8377\u662f\u5426\u6210\u529f\u5229\u7528\u4e86\u6f0f\u6d1e\u3002", requestInfo, payload, vulnType, response);
            JsonObject requestBody = this.buildAIRequest(verifyPrompt, prompt);
            String responseBody = this.callAI(requestBody);
            if (responseBody == null) {
                return null;
            }
            JsonObject result = this.gson.fromJson(responseBody, JsonObject.class);
            String content = this.extractAIContent(result);
            if (content == null) {
                return null;
            }
            if (content.contains("{")) {
                int start = content.indexOf("{");
                int end = content.lastIndexOf("}") + 1;
                if (end > start) {
                    String jsonStr = content.substring(start, end);
                    JsonObject verifyResult = this.gson.fromJson(jsonStr, JsonObject.class);
                    if (!verifyResult.has("vulnerable")) {
                        verifyResult.addProperty("vulnerable", false);
                    }
                    if (!verifyResult.has("confidence")) {
                        verifyResult.addProperty("confidence", 0);
                    }
                    if (!verifyResult.has("vulnType")) {
                        verifyResult.addProperty("vulnType", vulnType);
                    }
                    if (!verifyResult.has("level")) {
                        verifyResult.addProperty("level", "LOW");
                    }
                    if (!verifyResult.has("description")) {
                        verifyResult.addProperty("description", "AI\u672a\u63d0\u4f9b\u8be6\u7ec6\u63cf\u8ff0");
                    }
                    if (!verifyResult.has("tag")) {
                        verifyResult.addProperty("tag", vulnType);
                    }
                    return verifyResult;
                }
            }
            return null;
        }
        catch (Exception e) {
            this.callbacks.printError("[AI] verifyVulnerability: " + e.getMessage());
            return null;
        }
    }

    private IHttpRequestResponse sendTestRequest(IHttpRequestResponse original, String payload, String position) {
        try {
            String processedPayload = payload;
            IRequestInfo reqInfo = this.helpers.analyzeRequest(original.getRequest());
            if ("GET".equalsIgnoreCase(reqInfo.getMethod())) {
                processedPayload = payload.replace(" ", "+");
            }
            byte[] modifiedRequest = this.modifyRequest(original.getRequest(), processedPayload, position);
            IHttpService httpService = original.getHttpService();
            if (httpService == null) {
                this.callbacks.printError("[发送] HTTP服务为null");
                return null;
            }
            return this.callbacks.makeHttpRequest(httpService, modifiedRequest);
        }
        catch (Exception e) {
            this.callbacks.printError("[发送] 发送测试请求失败: " + e.getMessage());
            return null;
        }
    }

    private byte[] modifyRequest(byte[] originalRequest, String payload, String position) {
        try {
            IRequestInfo requestInfo = this.helpers.analyzeRequest(originalRequest);
            List<IParameter> parameters = requestInfo.getParameters();
            if (parameters == null || parameters.isEmpty()) {
                return originalRequest;
            }
            String contentType = this.getContentType(requestInfo);
            if (contentType != null && contentType.toLowerCase().contains("application/json")) {
                return this.modifyJsonRequest(originalRequest, payload, position, requestInfo);
            }
            if (contentType != null && contentType.toLowerCase().contains("multipart/form-data")) {
                return this.modifyMultipartRequest(originalRequest, payload, position, requestInfo, contentType);
            }
            if (position != null && !position.equals("auto")) {
                if (position.equals("URL_PATH") || position.equals("URL") || (position.startsWith("/") && !position.contains("="))) {
                    try {
                        String requestStr = new String(originalRequest, StandardCharsets.UTF_8);
                        int bodyOffset = requestInfo.getBodyOffset();
                        String requestLineAndHeaders = requestStr.substring(0, bodyOffset);
                        String body = bodyOffset < requestStr.length() ? requestStr.substring(bodyOffset) : "";
                        String firstLine = requestLineAndHeaders.split("\r?\n")[0];
                        String method = firstLine.split(" ")[0];
                        String originalPath = firstLine.split(" ")[1];
                        int queryIndex = originalPath.indexOf('?');
                        String originalBasePath = queryIndex > 0 ? originalPath.substring(0, queryIndex) : originalPath;
                        int lastSlash = originalBasePath.lastIndexOf('/');
                        String newPath = lastSlash > 0 ? originalBasePath.substring(0, lastSlash) + "/" + payload : "/" + payload;
                        String newFirstLine = method + " " + newPath + (queryIndex > 0 ? originalPath.substring(queryIndex) : "") + " HTTP/1.1";
                        String newRequestStr = requestLineAndHeaders.replace(firstLine, newFirstLine) + body;
                    return newRequestStr.getBytes(StandardCharsets.UTF_8);
                } catch (Exception urlEx) {
                    this.callbacks.printError("[AI] URL路径修改失败: " + urlEx.getMessage());
                }
                }
                boolean positionMatched = false;
                for (IParameter param : parameters) {
                    if (!param.getName().equals(position)) continue;
                    positionMatched = true;
                    byte paramType = param.getType();
                    try {
                        byte[] modifiedRequest = this.helpers.updateParameter(originalRequest, this.helpers.buildParameter(param.getName(), payload, paramType));
                        return modifiedRequest;
                    }
                    catch (Exception paramEx) {
                        this.callbacks.printError("[AI] 参数更新失败: " + paramEx.getMessage());
                    }
                }
                if (positionMatched) {
                    return originalRequest;
                }
            }
            for (IParameter param : parameters) {
                String paramName = param.getName().toLowerCase();
                if (paramName.equals("csrf") || paramName.equals("token") || paramName.equals("timestamp") || paramName.equals("nonce")) continue;
                byte paramType = param.getType();
                try {
                    byte[] modifiedRequest = this.helpers.updateParameter(originalRequest, this.helpers.buildParameter(param.getName(), payload, paramType));
                    return modifiedRequest;
                }
                catch (Exception paramEx) {
                }
            }
            return originalRequest;
        }
        catch (Exception e) {
            return originalRequest;
        }
    }

    private void processTestResult(ScanTask task, IHttpRequestResponse testResponse, int testCount, String vulnType, String testData, String position, String requestInfo) {
        if (testResponse == null) {
            return;
        }
        String responseStr = testResponse.getResponse() != null ? new String(testResponse.getResponse(), StandardCharsets.UTF_8) : "";
        if (responseStr.isEmpty()) {
            return;
        }
        JsonObject verification = this.verifyVulnerability(requestInfo, testData, responseStr, vulnType);
        if (verification == null) {
            this.callbacks.printError("[AI] 负载" + testCount + " AI验证失败");
            return;
        }
        boolean isVulnerable = verification.has("vulnerable") && verification.get("vulnerable") != null ? verification.get("vulnerable").getAsBoolean() : false;
        int confidence = verification.has("confidence") && verification.get("confidence") != null ? verification.get("confidence").getAsInt() : 0;
        String tag = this.safeGetString(verification, "tag", "");
        if (!isVulnerable || confidence < 95) return;
        this.logPanel.logSuccess("[\u6f0f\u6d1e] " + vulnType + " | \u7f6e\u4fe1\u5ea6: " + confidence + "%");
        VulnResult vuln = this.createVulnResult(verification, testResponse);
        vuln.setPayload(testData);
        String aiReport = this.generateSimpleReport(requestInfo, testData, responseStr, vulnType, verification);
        vuln.setAiReport(aiReport);
        task.addVulnerability(vuln);
        if (this.vulnListener != null) {
            this.vulnListener.onVulnerabilityFound(task, vuln);
        }
        if (task.getVulnName() == null || task.getVulnName().isEmpty()) {
            task.setVulnName(this.formatVulnName(vulnType));
        }
    }

    private VulnResult createVulnResult(JsonObject verification, IHttpRequestResponse proofRequest) {
        String tag;
        ScanTask.VulnLevel vulnLevel;
        String vulnType = this.safeGetString(verification, "vulnType", "UNKNOWN");
        String level = this.safeGetString(verification, "level", "MEDIUM");
        try {
            vulnLevel = ScanTask.VulnLevel.valueOf(level.toUpperCase());
        }
        catch (Exception e) {
            vulnLevel = ScanTask.VulnLevel.MEDIUM;
        }
        VulnResult vuln = new VulnResult(vulnType, this.formatVulnName(vulnType), vulnLevel);
        String description = this.safeGetString(verification, "description", "AI\u672a\u63d0\u4f9b\u8be6\u7ec6\u63cf\u8ff0");
        vuln.setDescription(description);
        vuln.setProofRequest(proofRequest);
        String string = tag = this.safeGetString(verification, "tag", null);
        if (tag != null && !tag.isEmpty()) {
            vuln.setTag(tag);
        } else {
            vuln.setTag(this.formatVulnName(vulnType));
        }
        if (proofRequest != null) {
            if (proofRequest.getRequest() != null) {
                vuln.setRequestData(new String(proofRequest.getRequest(), StandardCharsets.UTF_8));
            }
            if (proofRequest.getResponse() != null) {
                vuln.setResponseData(new String(proofRequest.getResponse(), StandardCharsets.UTF_8));
            }
        }
        vuln.setAiAnalysis(verification.toString());
        return vuln;
    }

    private String getHighestVulnTag(List<VulnResult> vulnerabilities) {
        if (vulnerabilities.isEmpty()) {
            return "\u5b89\u5168";
        }
        ScanTask.VulnLevel highest = ScanTask.VulnLevel.NONE;
        String tag = "";
        VulnResult highestVuln = null;
        for (VulnResult vuln : vulnerabilities) {
            if (vuln == null || vuln.getLevel() == null || vuln.getLevel().ordinal() <= highest.ordinal()) continue;
            highest = vuln.getLevel();
            highestVuln = vuln;
        }
        if (highestVuln != null) {
            tag = highestVuln.getTag() != null && !highestVuln.getTag().isEmpty() && !highestVuln.getTag().equals(highestVuln.getVulnType()) ? highestVuln.getTag() : this.formatVulnName(highestVuln.getVulnType());
        }
        return tag;
    }

    private String formatVulnName(String vulnType) {
        switch (vulnType) {
            case "SQL_INJECTION": {
                return "SQL\u6ce8\u5165";
            }
            case "XSS": 
            case "STORED_XSS": 
            case "REFLECTED_XSS": {
                return "XSS\u8de8\u7ad9\u811a\u672c";
            }
            case "COMMAND_INJECTION": 
            case "RCE": {
                return "\u547d\u4ee4\u6267\u884c";
            }
            case "XXE": {
                return "XXE\u5916\u90e8\u5b9e\u4f53\u6ce8\u5165";
            }
            case "SSRF": {
                return "SSRF\u670d\u52a1\u7aef\u8bf7\u6c42\u4f2a\u9020";
            }
            case "CSRF": {
                return "CSRF\u8de8\u7ad9\u8bf7\u6c42\u4f2a\u9020";
            }
            case "IDOR": {
                return "IDOR\u8d8a\u6743\u8bbf\u95ee";
            }
            case "LFI": {
                return "\u672c\u5730\u6587\u4ef6\u5305\u542b";
            }
            case "RFI": {
                return "\u8fdc\u7a0b\u6587\u4ef6\u5305\u542b";
            }
            case "SSTI": {
                return "\u6a21\u677f\u6ce8\u5165";
            }
            case "DESERIALIZATION": {
                return "\u53cd\u5e8f\u5217\u5316\u6f0f\u6d1e";
            }
            case "FILE_UPLOAD": {
                return "\u6587\u4ef6\u4e0a\u4f20\u6f0f\u6d1e";
            }
            case "FILE_UPLOAD_PHP_EXTENSION": 
            case "FILE_UPLOAD_PHP": {
                return "PHP\u6587\u4ef6\u4e0a\u4f20";
            }
            case "FILE_UPLOAD_DOUBLE_EXT": {
                return "\u53cc\u6269\u5c55\u540d\u7ed5\u8fc7";
            }
            case "FILE_UPLOAD_NULL_BYTE": {
                return "\u7a7a\u5b57\u8282\u622a\u65ad";
            }
            case "FILE_UPLOAD_CASE_BYPASS": {
                return "\u5927\u5c0f\u5199\u7ed5\u8fc7";
            }
            case "FILE_UPLOAD_PHTML": {
                return "PHTML\u540e\u7f00\u7ed5\u8fc7";
            }
            case "FILE_UPLOAD_HTACCESS": {
                return ".htaccess\u4e0a\u4f20";
            }
            case "FILE_UPLOAD_JSP": {
                return "JSP\u6587\u4ef6\u4e0a\u4f20";
            }
            case "FILE_UPLOAD_ASPX": {
                return "ASPX\u6587\u4ef6\u4e0a\u4f20";
            }
            case "FILE_UPLOAD_SVG_XSS": {
                return "SVG-XSS";
            }
            case "PATH_TRAVERSAL": {
                return "\u8def\u5f84\u7a7f\u8d8a";
            }
            case "DIRECTORY_TRAVERSAL": {
                return "\u76ee\u5f55\u904d\u5386";
            }
            case "AUTH_BYPASS": {
                return "\u8ba4\u8bc1\u7ed5\u8fc7";
            }
            case "WEAK_PASSWORD": {
                return "\u5f31\u53e3\u4ee4";
            }
            case "INFO_DISCLOSURE": {
                return "\u4fe1\u606f\u6cc4\u9732";
            }
            case "SENSITIVE_DATA_EXPOSURE": {
                return "\u654f\u611f\u4fe1\u606f\u66b4\u9732";
            }
            case "LOGIC_FLAW": {
                return "\u903b\u8f91\u6f0f\u6d1e";
            }
            case "TYPE_CONFUSION": {
                return "\u7c7b\u578b\u6df7\u6dc6";
            }
            case "RACE_CONDITION": {
                return "\u6761\u4ef6\u7ade\u4e89";
            }
        }
        return vulnType.replace("_", " ").toLowerCase();
    }

    private JsonObject buildAIRequest(String systemPrompt, String userPrompt) {
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        String endpoint = config.getApiEndpoint().toLowerCase();
        JsonObject request = new JsonObject();
        request.addProperty("model", config.getSelectedAgent());
        JsonArray messages = new JsonArray();
        if (endpoint.contains("anthropic.com")) {
            request.addProperty("system", systemPrompt);
            JsonObject userMsg = new JsonObject();
            userMsg.addProperty("role", "user");
            userMsg.addProperty("content", userPrompt);
            messages.add(userMsg);
            request.add("messages", messages);
            request.addProperty("max_tokens", 4096);
            request.addProperty("temperature", 0.3);
        } else {
            JsonObject systemMsg = new JsonObject();
            systemMsg.addProperty("role", "system");
            systemMsg.addProperty("content", systemPrompt);
            messages.add(systemMsg);
            JsonObject userMsg = new JsonObject();
            userMsg.addProperty("role", "user");
            userMsg.addProperty("content", userPrompt);
            messages.add(userMsg);
            request.add("messages", messages);
            request.addProperty("temperature", 0.3);
            request.addProperty("max_tokens", 8192);
        }
        return request;
    }

    private String callAI(JsonObject requestBody) throws IOException {
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        if (config.getApiKey() == null || config.getApiKey().trim().isEmpty()) {
            return null;
        }
        String endpoint = config.getApiEndpoint();
        String apiKey = config.getApiKey();
        RequestBody body = RequestBody.create(JSON_TYPE, this.gson.toJson(requestBody));
        Request.Builder requestBuilder = new Request.Builder().url(endpoint).addHeader("Content-Type", "application/json").post(body);
        this.setupAuthHeader(requestBuilder, endpoint, apiKey);
        try (Response response = this.httpClient.newCall(requestBuilder.build()).execute()) {
            if (response == null || !response.isSuccessful()) {
                return null;
            }
            return response.body() != null ? response.body().string() : null;
        }
    }

    private void setupAuthHeader(Request.Builder requestBuilder, String endpoint, String apiKey) {
        String lowerEndpoint = endpoint.toLowerCase();
        if (lowerEndpoint.contains("anthropic.com")) {
            requestBuilder.addHeader("x-api-key", apiKey);
            requestBuilder.addHeader("anthropic-version", "2023-06-01");
            return;
        }
        if (lowerEndpoint.contains("googleapis.com") || lowerEndpoint.contains("generativelanguage.googleapis.com")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("openai.azure.com")) {
            requestBuilder.addHeader("api-key", apiKey);
            requestBuilder.addHeader("Content-Type", "application/json");
            return;
        }
        if (lowerEndpoint.contains("cohere.ai") || lowerEndpoint.contains("cohere.com")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            requestBuilder.addHeader("Cohere-Version", "2022-12-06");
            return;
        }
        if (lowerEndpoint.contains("deepseek.com") || lowerEndpoint.contains("dashscope.aliyuncs.com") ||
            lowerEndpoint.contains("qianfan") || lowerEndpoint.contains("bigmodel.cn") ||
            lowerEndpoint.contains("xfyun.cn") || lowerEndpoint.contains("spark") ||
            lowerEndpoint.contains("volcengine.com") || lowerEndpoint.contains("doubao") ||
            lowerEndpoint.contains("hunyuan") || lowerEndpoint.contains("moonshot.cn") ||
            lowerEndpoint.contains("baichuan-ai.com") || lowerEndpoint.contains("minimax") ||
            lowerEndpoint.contains("sensenova.cn") || lowerEndpoint.contains("sensetime") ||
            lowerEndpoint.contains("tiangong") || lowerEndpoint.contains("kunlun") ||
            lowerEndpoint.contains("01.ai") || lowerEndpoint.contains("lingyiwanwu") ||
            lowerEndpoint.contains("stepfun.com") || lowerEndpoint.contains("modelbest.cn") ||
            lowerEndpoint.contains("mistral.ai") || lowerEndpoint.contains("huggingface.co") ||
            lowerEndpoint.contains("hf.co") || lowerEndpoint.contains("replicate.com") ||
            lowerEndpoint.contains("together.xyz") || lowerEndpoint.contains("together.ai") ||
            lowerEndpoint.contains("perplexity.ai")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
    }

    private String generateSimpleReport(String requestInfo, String payload, String response, String vulnType, JsonObject verification) {
        StringBuilder report = new StringBuilder();
        String vulnName = this.formatVulnName(vulnType);
        String description = this.safeGetString(verification, "description", "");
        int confidence = this.safeGetInt(verification, "confidence", 0);
        String level = this.safeGetString(verification, "level", "MEDIUM");
        report.append("## ").append(vulnName).append("\n\n");
        report.append("**\u6f0f\u6d1e\u7c7b\u578b\uff1a** ").append(vulnName).append("\n\n");
        report.append("**\u7f6e\u4fe1\u5ea6\uff1a** ").append(confidence).append("%\n\n");
        report.append("**\u98ce\u9669\u7b49\u7ea7\uff1a** ").append(level).append("\n\n");
        if (!description.isEmpty()) {
            report.append("### \u6f0f\u6d1e\u5206\u6790\n\n");
            report.append(description).append("\n\n");
        }
        report.append("### \u6d4b\u8bd5\u8f7d\u8377\n\n");
        report.append("```\n");
        report.append((String)(payload.length() > 500 ? payload.substring(0, 500) + "\n...(\u5df2\u622a\u65ad)" : payload));
        report.append("\n```\n\n");
        report.append("### \u54cd\u5e94\u7279\u5f81\n\n");
        Object responsePreview = this.extractResponseBody(response);
        if (((String)responsePreview).length() > 300) {
            responsePreview = ((String)responsePreview).substring(0, 300) + "...(\u5df2\u622a\u65ad)";
        }
        report.append("```\n");
        report.append((String)responsePreview);
        report.append("\n```\n\n");
        report.append("### \u590d\u73b0\u8bf4\u660e\n\n");
        report.append("\u4f7f\u7528Burp Suite\u6216\u7c7b\u4f3c\u5de5\u5177\uff0c\u5c06\u4e0a\u8ff0\u8f7d\u8377\u6ce8\u5165\u5230\u76ee\u6807\u53c2\u6570\u4e2d\u5373\u53ef\u590d\u73b0\u3002\n");
        return report.toString();
    }

    private String extractResponseBody(String response) {
        if (response == null || response.isEmpty()) {
            return "";
        }
        int bodyStart = response.indexOf("\r\n\r\n");
        if (bodyStart == -1) {
            bodyStart = response.indexOf("\n\n");
            if (bodyStart == -1) {
                return response;
            }
            bodyStart += 2;
        } else {
            bodyStart += 4;
        }
        if (bodyStart >= response.length()) {
            return "";
        }
        return response.substring(bodyStart);
    }

    private void logInitialAnalysis(JsonObject result) {
        try {
            if (result.has("testPayloads")) {
                JsonArray payloads = result.getAsJsonArray("testPayloads");
                this.logPanel.logAI("[生成payload] " + payloads.size() + " 个");
            }
        }
        catch (Exception e) {
            this.callbacks.printError("[AI] logInitialAnalysis: " + e.getMessage());
        }
    }

    private String safeGetString(JsonObject obj, String key, String defaultValue) {
        if (obj == null || key == null || !obj.has(key) || obj.get(key) == null || obj.get(key).isJsonNull()) {
            return defaultValue;
        }
        try {
            return obj.get(key).getAsString();
        }
        catch (Exception e) {
            return defaultValue;
        }
    }

    private int safeGetInt(JsonObject obj, String key, int defaultValue) {
        if (obj == null || key == null || !obj.has(key) || obj.get(key) == null || obj.get(key).isJsonNull()) {
            return defaultValue;
        }
        try {
            return obj.get(key).getAsInt();
        }
        catch (Exception e) {
            return defaultValue;
        }
    }

    private String getContentType(IRequestInfo requestInfo) {
        List<String> headers = requestInfo.getHeaders();
        for (String header : headers) {
            if (!header.toLowerCase().startsWith("content-type:")) continue;
            return header.substring(header.indexOf(":") + 1).trim();
        }
        return null;
    }

    private byte[] modifyJsonRequest(byte[] originalRequest, String payload, String position, IRequestInfo requestInfo) {
        try {
            String modifiedBody;
            JsonObject jsonBody;
            int bodyOffset = requestInfo.getBodyOffset();
            String body = new String(originalRequest, bodyOffset, originalRequest.length - bodyOffset, StandardCharsets.UTF_8);
            try {
                jsonBody = this.gson.fromJson(body, JsonObject.class);
            }
            catch (Exception e) {
                return originalRequest;
            }
            try {
                JsonObject payloadJson = this.gson.fromJson(payload, JsonObject.class);
                if (position != null && !position.equals("auto")) {
                    if (payloadJson.has(position)) {
                        jsonBody.add(position, payloadJson.get(position));
                    }
                } else {
                    for (String key : payloadJson.keySet()) {
                        jsonBody.add(key, payloadJson.get(key));
                    }
                }
                modifiedBody = jsonBody.toString();
            }
            catch (Exception e) {
                boolean injected = false;
                if (position != null && !position.equals("auto") && jsonBody.has(position)) {
                    jsonBody.addProperty(position, payload);
                    injected = true;
                }
                if (!injected) {
                    for (String key : jsonBody.keySet()) {
                        if (!jsonBody.get(key).isJsonPrimitive()) continue;
                        jsonBody.addProperty(key, payload);
                        break;
                    }
                }
                modifiedBody = jsonBody.toString();
            }
            byte[] newBody = modifiedBody.getBytes();
            byte[] headers = new byte[bodyOffset];
            System.arraycopy(originalRequest, 0, headers, 0, bodyOffset);
            byte[] newRequest = new byte[headers.length + newBody.length];
            System.arraycopy(headers, 0, newRequest, 0, headers.length);
            System.arraycopy(newBody, 0, newRequest, headers.length, newBody.length);
            return this.helpers.updateParameter(newRequest, this.helpers.buildParameter("Content-Length", String.valueOf(newBody.length), (byte)1));
        }
        catch (Exception e) {
            this.callbacks.printError("[AI] updateJsonRequest失败: " + e.getMessage());
            return originalRequest;
        }
    }

    private byte[] modifyMultipartRequest(byte[] originalRequest, String payload, String position, IRequestInfo requestInfo, String contentType) {
        try {
            String boundary = this.extractBoundary(contentType);
            if (boundary == null) {
                return originalRequest;
            }
            int bodyOffset = requestInfo.getBodyOffset();
            String body = new String(originalRequest, bodyOffset, originalRequest.length - bodyOffset, StandardCharsets.UTF_8);
            if (payload.contains("Content-Disposition:")) {
                String payloadBoundary = this.extractPayloadBoundary(payload);
                String modifiedBody = this.mergeMultipartContent(body, payload, boundary, payloadBoundary);
                byte[] headers = new byte[bodyOffset];
                System.arraycopy(originalRequest, 0, headers, 0, bodyOffset);
                byte[] newBody = modifiedBody.getBytes();
                byte[] newRequest = new byte[headers.length + newBody.length];
                System.arraycopy(headers, 0, newRequest, 0, headers.length);
                System.arraycopy(newBody, 0, newRequest, headers.length, newBody.length);
                newRequest = this.updateContentLength(newRequest, newBody.length);
                return newRequest;
            }
            String modifiedBody = this.modifyMultipartParts(body, payload, position, boundary);
            if (modifiedBody.equals(body)) {
                return originalRequest;
            }
            byte[] headers = new byte[bodyOffset];
            System.arraycopy(originalRequest, 0, headers, 0, bodyOffset);
            byte[] newBody = modifiedBody.getBytes();
            byte[] newRequest = new byte[headers.length + newBody.length];
            System.arraycopy(headers, 0, newRequest, 0, headers.length);
            System.arraycopy(newBody, 0, newRequest, headers.length, newBody.length);
            return newRequest;
        }
        catch (Exception e) {
            this.callbacks.printError("[AI] modifyMultipartRequest失败: " + e.getMessage());
            return originalRequest;
        }
    }

    private String extractPayloadBoundary(String payload) {
        int boundaryStart = payload.indexOf("------WebKitFormBoundary");
        if (boundaryStart == -1) {
            boundaryStart = payload.indexOf("----WebKitFormBoundary");
        }
        if (boundaryStart == -1) {
            return null;
        }
        int boundaryEnd = payload.indexOf("\r\n", boundaryStart);
        if (boundaryEnd == -1) {
            boundaryEnd = payload.indexOf("\n", boundaryStart);
        }
        if (boundaryEnd == -1) {
            return null;
        }
        String fullBoundary = payload.substring(boundaryStart, boundaryEnd);
        if (fullBoundary.startsWith("------")) {
            return fullBoundary.substring(6);
        }
        if (fullBoundary.startsWith("----")) {
            return fullBoundary.substring(4);
        }
        return fullBoundary;
    }

    private String mergeMultipartContent(String originalBody, String payload, String originalBoundary, String payloadBoundary) {
        try {
            int nextDelimiter;
            String newFilename = this.extractFilename(payload);
            String newContentType = this.extractContentTypeFromPayload(payload);
            String newFileContent = this.extractFileContent(payload);
            String delimiter = "--" + originalBoundary;
            StringBuilder newBody = new StringBuilder();
            int pos = 0;
            boolean filePartReplaced = false;
            while (pos < originalBody.length() && (nextDelimiter = originalBody.indexOf(delimiter, pos)) != -1) {
                String part;
                int partEnd = originalBody.indexOf(delimiter, nextDelimiter + delimiter.length());
                if (partEnd == -1) {
                    partEnd = originalBody.length();
                }
                if ((part = originalBody.substring(nextDelimiter, partEnd)).contains("filename=") && !filePartReplaced) {
                    newBody.append(delimiter).append("\r\n");
                    newBody.append("Content-Disposition: form-data; name=\"");
                    String originalName = this.extractMultipartName(part);
                    newBody.append(originalName).append("\"; filename=\"");
                    newBody.append(newFilename != null ? newFilename : "test.php").append("\"\r\n");
                    if (newContentType != null && !newContentType.isEmpty()) {
                        newBody.append("Content-Type: ").append(newContentType).append("\r\n");
                    } else if (part.contains("Content-Type:")) {
                        int ctStart = part.indexOf("Content-Type:");
                        int ctEnd = part.indexOf("\r\n", ctStart);
                        if (ctEnd == -1) {
                            ctEnd = part.indexOf("\n", ctStart);
                        }
                        if (ctEnd != -1) {
                            newBody.append(part.substring(ctStart, ctEnd)).append("\r\n");
                        }
                    }
                    newBody.append("\r\n");
                    newBody.append(newFileContent != null ? newFileContent : "test").append("\r\n");
                    filePartReplaced = true;
                } else {
                    newBody.append(part);
                }
                pos = partEnd;
            }
            if (!originalBody.endsWith("--")) {
                newBody.append(delimiter).append("--");
            }
            String result = newBody.toString();
            return result;
        }
        catch (Exception e) {
            this.callbacks.printError("[AI] mergeMultipartContent失败: " + e.getMessage());
            return payload.replace(payloadBoundary != null ? payloadBoundary : "", originalBoundary);
        }
    }

    private byte[] updateContentLength(byte[] request, int newContentLength) {
        try {
            String requestStr = new String(request, StandardCharsets.UTF_8);
            int clStart = requestStr.indexOf("Content-Length:");
            if (clStart == -1) {
                clStart = requestStr.indexOf("Content-length:");
            }
            if (clStart == -1) {
                clStart = requestStr.indexOf("content-length:");
            }
            if (clStart != -1) {
                int lineEnd = requestStr.indexOf("\r\n", clStart);
                if (lineEnd == -1) {
                    lineEnd = requestStr.indexOf("\n", clStart);
                }
                if (lineEnd != -1) {
                    String before = requestStr.substring(0, clStart);
                    String after = requestStr.substring(lineEnd);
                    String newRequest = before + "Content-Length: " + newContentLength + after;
                    return newRequest.getBytes();
                }
            }
            return request;
        }
        catch (Exception e) {
            return request;
        }
    }

    private String extractBoundary(String contentType) {
        int boundaryIndex = contentType.toLowerCase().indexOf("boundary=");
        if (boundaryIndex == -1) {
            return null;
        }
        String boundary = contentType.substring(boundaryIndex + 9).trim();
        int semicolonIndex = (boundary = boundary.replace("\"", "").replace("'", "")).indexOf(";");
        if (semicolonIndex != -1) {
            boundary = boundary.substring(0, semicolonIndex);
        }
        return boundary;
    }

    private String modifyMultipartParts(String body, String payload, String position, String boundary) {
        try {
            String delimiter = "--" + boundary;
            String[] parts = body.split(delimiter);
            StringBuilder modifiedBody = new StringBuilder();
            boolean modified = false;
            for (int i = 0; i < parts.length; ++i) {
                String part = parts[i];
                if (part.trim().isEmpty() || part.trim().equals("--")) {
                    modifiedBody.append(delimiter).append(part);
                    continue;
                }
                if (part.contains("Content-Disposition:")) {
                    String newContent;
                    String newContentType;
                    String newFilename;
                    String name = this.extractMultipartName(part);
                    if (position != null && !position.equals("auto") && !name.equals(position)) {
                        modifiedBody.append(delimiter).append(part);
                        continue;
                    }
                    if (part.contains("filename=") && payload.contains("filename=") && (newFilename = this.extractFilename(payload)) != null) {
                        part = this.replaceFilename(part, newFilename);
                        modified = true;
                    }
                    if (part.contains("Content-Type:") && payload.contains("Content-Type:") && (newContentType = this.extractContentTypeFromPayload(payload)) != null) {
                        part = this.replaceContentType(part, newContentType);
                        modified = true;
                    }
                    if ((name.equals("file") || name.equals("upload") || position != null && name.equals(position)) && (newContent = this.extractFileContent(payload)) != null && !newContent.isEmpty()) {
                        part = this.replacePartContent(part, newContent);
                        modified = true;
                    }
                }
                modifiedBody.append(delimiter).append(part);
            }
            return modified ? modifiedBody.toString() : body;
        }
        catch (Exception e) {
            return body;
        }
    }

    private String extractMultipartName(String part) {
        int nameIndex = part.indexOf("name=\"");
        if (nameIndex == -1) {
            return "";
        }
        int endIndex = part.indexOf("\"", nameIndex + 6);
        if (endIndex == -1) {
            return "";
        }
        return part.substring(nameIndex + 6, endIndex);
    }

    private String extractFilename(String payload) {
        int filenameIndex = payload.indexOf("filename=\"");
        if (filenameIndex == -1) {
            return null;
        }
        int endIndex = payload.indexOf("\"", filenameIndex + 10);
        if (endIndex == -1) {
            return null;
        }
        return payload.substring(filenameIndex + 10, endIndex);
    }

    private String replaceFilename(String part, String newFilename) {
        int filenameIndex = part.indexOf("filename=\"");
        if (filenameIndex == -1) {
            return part;
        }
        int endIndex = part.indexOf("\"", filenameIndex + 10);
        if (endIndex == -1) {
            return part;
        }
        return part.substring(0, filenameIndex + 10) + newFilename + part.substring(endIndex);
    }

    private String extractContentTypeFromPayload(String payload) {
        int ctIndex = payload.indexOf("Content-Type:");
        if (ctIndex == -1) {
            return null;
        }
        int endIndex = payload.indexOf("\n", ctIndex);
        if (endIndex == -1) {
            return null;
        }
        return payload.substring(ctIndex + 13, endIndex).trim();
    }

    private String replaceContentType(String part, String newContentType) {
        int ctIndex = part.indexOf("Content-Type:");
        if (ctIndex == -1) {
            return part;
        }
        int endIndex = part.indexOf("\n", ctIndex);
        if (endIndex == -1) {
            return part;
        }
        return part.substring(0, ctIndex + 13) + " " + newContentType + part.substring(endIndex);
    }

    private String extractFileContent(String payload) {
        if (payload.contains("Content-Disposition:")) {
            int contentEnd;
            int contentStart = payload.indexOf("\n\n");
            if (contentStart == -1) {
                contentStart = payload.indexOf("\r\n\r\n");
            }
            if (contentStart != -1 && (contentEnd = payload.lastIndexOf("--")) > contentStart) {
                return payload.substring(contentStart + 2, contentEnd).trim();
            }
        }
        return payload;
    }

    private String replacePartContent(String part, String newContent) {
        int contentStart = part.indexOf("\n\n");
        if (contentStart == -1) {
            contentStart = part.indexOf("\r\n\r\n");
            if (contentStart != -1) {
                contentStart += 4;
            }
        } else {
            contentStart += 2;
        }
        if (contentStart == -1) {
            return part;
        }
        String header = part.substring(0, contentStart);
        return header + newContent + "\r\n";
    }

    private int findClosingBrace(String content, int startPos) {
        int braceCount = 0;
        boolean inString = false;
        boolean escaped = false;
        for (int i = startPos; i < content.length(); ++i) {
            char c = content.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '\"') {
                inString = !inString;
                continue;
            }
            if (inString) continue;
            if (c == '{') {
                ++braceCount;
                continue;
            }
            if (c != '}' || --braceCount != 0) continue;
            return i + 1;
        }
        int lastBrace = content.lastIndexOf("}");
        return lastBrace > startPos ? lastBrace + 1 : startPos;
    }

    private String fixIncompleteJson(String jsonStr) {
        try {
            if (jsonStr == null || jsonStr.trim().isEmpty()) {
                return null;
            }
            StringBuilder fixed = new StringBuilder(jsonStr);
            int braceCount = 0;
            int bracketCount = 0;
            boolean inString = false;
            boolean escaped = false;
            for (int i = 0; i < fixed.length(); ++i) {
                char c = fixed.charAt(i);
                if (escaped) {
                    escaped = false;
                    continue;
                }
                if (c == '\\') {
                    escaped = true;
                    continue;
                }
                if (c == '\"') {
                    inString = !inString;
                    continue;
                }
                if (inString) continue;
                if (c == '{') {
                    ++braceCount;
                    continue;
                }
                if (c == '}') {
                    --braceCount;
                    continue;
                }
                if (c == '[') {
                    ++bracketCount;
                    continue;
                }
                if (c != ']') continue;
                --bracketCount;
            }
            if (inString || bracketCount > 0 || braceCount > 0) {
                if (jsonStr.contains("\"testPayloads\"") && jsonStr.contains("\"payload\":")) {
                    int lastPayloadStart = jsonStr.lastIndexOf("{\"type\":\"");
                    int lastPositionStart = jsonStr.lastIndexOf("\",\"position\":");
                    if (lastPayloadStart > 0 && lastPositionStart > lastPayloadStart) {
                        int cutPoint = lastPayloadStart;
                        String truncated = jsonStr.substring(0, cutPoint);
                        if (truncated.endsWith(",")) {
                            truncated = truncated.substring(0, truncated.length() - 1);
                        }
                        truncated += "]}";
                        try {
                            this.gson.fromJson(truncated, JsonObject.class);
                            return truncated;
                        }
                        catch (Exception e2) {
                        }
                    }
                }
            }
            if (inString) {
                fixed.append('\"');
            }
            while (bracketCount > 0) {
                fixed.append(']');
                --bracketCount;
            }
            while (braceCount > 0) {
                fixed.append('}');
                --braceCount;
            }
            return fixed.toString();
        }
        catch (Exception e) {
            return null;
        }
    }

    private String extractAIContent(JsonObject response) {
        try {
            JsonObject firstContent;
            JsonArray content;
            JsonObject message;
            JsonObject firstChoice;
            JsonArray choices;
            if (response.has("choices") && response.get("choices") != null && !response.get("choices").isJsonNull() && (choices = response.getAsJsonArray("choices")).size() > 0 && choices.get(0) != null && !choices.get(0).isJsonNull() && (firstChoice = choices.get(0).getAsJsonObject()).has("message") && firstChoice.get("message") != null && !firstChoice.get("message").isJsonNull() && (message = firstChoice.getAsJsonObject("message")).has("content") && message.get("content") != null && !message.get("content").isJsonNull()) {
                return message.get("content").getAsString();
            }
            if (response.has("content") && response.get("content") != null && !response.get("content").isJsonNull() && (content = response.getAsJsonArray("content")).size() > 0 && content.get(0) != null && !content.get(0).isJsonNull() && (firstContent = content.get(0).getAsJsonObject()).has("text") && firstContent.get("text") != null && !firstContent.get("text").isJsonNull()) {
                return firstContent.get("text").getAsString();
            }
            if (response.has("output") && response.get("output") != null && !response.get("output").isJsonNull()) {
                return response.get("output").getAsString();
            }
            if (response.has("result") && response.get("result") != null && !response.get("result").isJsonNull()) {
                return response.get("result").getAsString();
            }
        }
        catch (Exception e) {
        }
        return null;
    }

}
