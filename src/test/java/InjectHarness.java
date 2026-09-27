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
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IParameter;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IHttpRequestResponse;
import com.google.gson.JsonObject;
import com.zackai.core.AIEngine;
import com.zackai.ui.LogPanel;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 一次性的注入层离线验证程序（不入库）。
 * 用 Proxy 桩实现 Burp 接口，直接调用 AIEngine.modifyRequest，
 * 断言「注入位置是否正确 / Content-Length 是否正确 / 失败是否可识别」。
 */
public class InjectHarness {

    static int passed = 0;
    static final List<String> failures = new ArrayList<>();

    // ---------------------------------------------------------------- 参数实现
    static class P implements IParameter {
        final String name, value;
        final byte type;
        final int nameStart, nameEnd, valueStart, valueEnd;
        P(String n, String v, byte t, int ns, int ne, int vs, int ve) {
            name = n; value = v; type = t;
            nameStart = ns; nameEnd = ne; valueStart = vs; valueEnd = ve;
        }
        public byte getType() { return type; }
        public String getName() { return name; }
        public String getValue() { return value; }
        public int getNameStart() { return nameStart; }
        public int getNameEnd() { return nameEnd; }
        public int getValueStart() { return valueStart; }
        public int getValueEnd() { return valueEnd; }
    }

    // ---------------------------------------------------------------- 极简请求解析
    static class Parsed {
        int bodyOffset;
        String method;
        String requestLine;
        String contentType;
        List<IParameter> params = new ArrayList<>();
    }

    static Parsed parse(String req) {
        Parsed p = new Parsed();
        int hdrEnd = req.indexOf("\r\n\r\n");
        p.bodyOffset = hdrEnd < 0 ? req.length() : hdrEnd + 4;
        String head = hdrEnd < 0 ? req : req.substring(0, hdrEnd);
        String[] lines = head.split("\r\n", -1);
        p.requestLine = lines.length > 0 ? lines[0] : "";
        int sp = p.requestLine.indexOf(' ');
        p.method = sp > 0 ? p.requestLine.substring(0, sp) : "GET";
        String path = sp > 0 ? p.requestLine.substring(sp + 1) : p.requestLine;
        int sp2 = path.lastIndexOf(' ');
        if (sp2 > 0) path = path.substring(0, sp2);
        String body = hdrEnd < 0 ? "" : req.substring(p.bodyOffset);

        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            int c = line.indexOf(':');
            if (c > 0 && line.substring(0, c).trim().equalsIgnoreCase("Content-Type")) {
                p.contentType = line.substring(c + 1).trim();
            }
            if (c > 0 && line.substring(0, c).trim().equalsIgnoreCase("Cookie")) {
                int base = req.indexOf(line) + c + 1;
                scanPairs(line.substring(c + 1), base, IParameter.PARAM_COOKIE, ";", p.params);
            }
        }
        int q = path.indexOf('?');
        if (q >= 0) {
            int base = p.requestLine.indexOf('?') + 1;
            scanPairs(path.substring(q + 1), base, IParameter.PARAM_URL, "&", p.params);
        }
        String ct = p.contentType == null ? "" : p.contentType.toLowerCase();
        if (ct.contains("urlencoded")) {
            scanPairs(body, p.bodyOffset, IParameter.PARAM_BODY, "&", p.params);
        } else if (ct.contains("xml")) {
            scanXmlElements(body, p.bodyOffset, p.params);
        } else if (ct.contains("multipart/form-data")) {
            scanMultipartParts(body, p.bodyOffset, p.params);
        }
        return p;
    }

    /**
     * multipart 的 part 名按 {@code PARAM_BODY} 上报 —— 与**真实 Burp** 一致。
     *
     * <p>这条不是随手加的：桩原先只认 urlencoded/xml，于是 sendTestRequest 里
     * {@code isFormBodyPosition} 对 multipart 位置恒为 false，把「multipart 值被当表单值
     * URL 编码」这个真 bug 整条藏住了（真扫描里 Burp 报 PARAM_BODY → 载荷被编成
     * {@code %25%7B100*100%7D} → S2-059 靶场原样回显字面量、永不求值）。
     * 桩对真实环境的偏离会让离线断言全部失去意义，所以这里必须跟真的一致。
     */
    static void scanMultipartParts(String body, int base, List<IParameter> out) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("name=\"([^\"]*)\"", java.util.regex.Pattern.DOTALL).matcher(body);
        while (m.find()) {
            String name = m.group(1);
            if (name.isEmpty()) continue;
            int nameStart = base + m.start(1);
            int afterName = m.end();
            // 文件部件：Burp 报**两个**参数 —— part 名（值区间从 name="x" 之后一直盖到 part 内容结束，
            // 所以对它做 updateParameter 会把 `; filename="a.png"` 和 `Content-Type:` 一起吃掉，
            // 请求就从文件上传变成普通表单字段）和 filename 属性（PARAM_MULTIPART_ATTR）。
            // 这条以前没建模，于是「部件被通用参数替换改写」这个真 bug 在离线断言里完全看不见
            // （桩根本不报那个参数，断言空转）。用户实测的那条坏请求就是这么发出去的。
            if (body.startsWith("; filename=\"", afterName)) {
                int headerEnd = body.indexOf("\r\n\r\n", afterName);
                int partEnd = body.indexOf("\r\n--", afterName);   // 下一个分隔符前的那对 CRLF
                if (headerEnd < 0) continue;
                if (partEnd < 0) partEnd = body.length();
                // 偏移必须一律加 base（body 是相对的，P 里的偏移是相对整个请求的）
                out.add(new P(name, "", IParameter.PARAM_BODY, nameStart, nameStart + name.length(),
                        base + afterName, base + partEnd));
                int fIdx = body.indexOf("filename=\"", afterName);
                if (fIdx > 0 && fIdx < headerEnd) {
                    int vStart = fIdx + 10;
                    int vEnd = body.indexOf('"', vStart);
                    if (vEnd > vStart) {
                        out.add(new P("filename", body.substring(vStart, vEnd), IParameter.PARAM_MULTIPART_ATTR,
                                base + fIdx, base + fIdx + 8, base + vStart, base + vEnd));
                    }
                }
                continue;
            }
            // 普通字段：name="x" 后面直接就是空行
            if (!body.startsWith("\r\n\r\n", afterName)) continue;
            out.add(new P(name, "", IParameter.PARAM_BODY, nameStart, nameStart + name.length(),
                    base + afterName + 4, base + afterName + 4));
        }
    }

    static void scanPairs(String s, int base, byte type, String sep, List<IParameter> out) {
        int cursor = 0;
        while (cursor <= s.length()) {
            int next = s.indexOf(sep, cursor);
            String pair = next < 0 ? s.substring(cursor) : s.substring(cursor, next);
            int eq = pair.indexOf('=');
            if (eq >= 0) {
                String name = pair.substring(0, eq).trim();
                String rawValue = pair.substring(eq + 1);
                if (!name.isEmpty()) {
                    int absNameStart = base + cursor + (pair.indexOf(name));
                    int absValueStart = base + cursor + eq + 1;
                    out.add(new P(decode(name), decode(rawValue), type,
                            absNameStart, absNameStart + name.length(),
                            absValueStart, absValueStart + rawValue.length()));
                }
            }
            if (next < 0) break;
            cursor = next + sep.length();
        }
    }

    static void scanXmlElements(String body, int base, List<IParameter> out) {
        int i = 0;
        while ((i = body.indexOf('<', i)) >= 0) {
            if (i + 1 < body.length() && (body.charAt(i + 1) == '?' || body.charAt(i + 1) == '!')) { i++; continue; }
            int gt = body.indexOf('>', i);
            if (gt < 0) break;
            String tag = body.substring(i + 1, gt).trim();
            if (tag.contains(" ") || tag.contains("/")) { i = gt + 1; continue; }
            int close = body.indexOf("</" + tag + ">", gt);
            if (close >= 0) {
                out.add(new P(tag, body.substring(gt + 1, close), IParameter.PARAM_XML,
                        base + i + 1, base + gt, base + gt + 1, base + close));
                i = close + 1;
            } else {
                i = gt + 1;
            }
        }
    }

    static String decode(String s) {
        try { return URLDecoder.decode(s, StandardCharsets.UTF_8.name()); } catch (Exception e) { return s; }
    }

    /** Burp 的 getHeaders() 含请求行 */
    static String[] headLines(String req) {
        int i = req.indexOf("\r\n\r\n");
        String head = i < 0 ? req : req.substring(0, i);
        return head.split("\r\n", -1);
    }

    // ---------------------------------------------------------------- Burp 桩
    static byte[] updateParameter(byte[] req, IParameter newParam) {
        String s = new String(req, StandardCharsets.UTF_8);
        Parsed p = parse(s);
        for (IParameter existing : p.params) {
            if (existing.getName().equalsIgnoreCase(newParam.getName())
                    && existing.getType() == newParam.getType()) {
                byte[] value = newParam.getValue().getBytes(StandardCharsets.UTF_8);
                byte[] result = new byte[existing.getValueStart() + value.length + (req.length - existing.getValueEnd())];
                System.arraycopy(req, 0, result, 0, existing.getValueStart());
                System.arraycopy(value, 0, result, existing.getValueStart(), value.length);
                System.arraycopy(req, existing.getValueEnd(), result,
                        existing.getValueStart() + value.length, req.length - existing.getValueEnd());
                // 真实 Burp 在改 body 参数时会自动修正 Content-Length，桩必须同样处理，
                // 否则测的是桩的缺陷而不是被测代码
                if (existing.getType() == IParameter.PARAM_BODY || existing.getType() == IParameter.PARAM_XML) {
                    result = fixContentLength(result);
                }
                return result;
            }
        }
        throw new IllegalStateException("stub: 参数不存在 " + newParam.getName() + " type=" + newParam.getType());
    }

    static byte[] fixContentLength(byte[] req) {
        String s = new String(req, StandardCharsets.UTF_8);
        int i = s.indexOf("\r\n\r\n");
        if (i < 0) return req;
        int bodyLen = req.length - (i + 4);
        String header = s.substring(0, i);
        String bodyStr = s.substring(i + 4);
        if (java.util.regex.Pattern.compile("(?im)^content-length:").matcher(header).find()) {
            header = header.replaceAll("(?im)^content-length:\\s*\\d+", "Content-Length: " + bodyLen);
        } else {
            header = header + "\r\nContent-Length: " + bodyLen;
        }
        return (header + "\r\n\r\n" + bodyStr).getBytes(StandardCharsets.UTF_8);
    }

    static IExtensionHelpers helpers() {
        InvocationHandler h = (proxy, method, args) -> {
            switch (method.getName()) {
                case "analyzeRequest": {
                    byte[] req = (byte[]) args[args.length - 1];
                    String s = new String(req, StandardCharsets.UTF_8);
                    Parsed p = parse(s);
                    return Proxy.newProxyInstance(InjectHarness.class.getClassLoader(),
                            new Class[]{IRequestInfo.class}, (pr, m2, a2) -> {
                                switch (m2.getName()) {
                                    case "getMethod": return p.method;
                                    case "getBodyOffset": return p.bodyOffset;
                                    case "getParameters": return p.params;
                                    case "getUrl": return new URL("http://stub.local/");
                                    case "getHeaders": return new ArrayList<String>(Arrays.asList(headLines(s)));
                                    case "getContentType": return (byte) 0;
                                    default: throw new UnsupportedOperationException(m2.getName());
                                }
                            });
                }
                case "buildParameter":
                    return new P((String) args[0], (String) args[1], (Byte) args[2], 0, 0, 0, 0);
                case "updateParameter":
                    return updateParameter((byte[]) args[0], (IParameter) args[1]);
                default:
                    throw new UnsupportedOperationException(method.getName());
            }
        };
        return (IExtensionHelpers) Proxy.newProxyInstance(InjectHarness.class.getClassLoader(),
                new Class[]{IExtensionHelpers.class}, h);
    }

    /**
     * 模拟「Burp 收下参数更新、但没有把载荷写进请求」（类型不被支持时可能只接受不写，
     * 也可能按自己的规则转义）。注入层必须自己验一遍：没写进去就按注入失败处理，
     * 绝不能把原始请求当测试包发出去。
     */
    static IExtensionHelpers swallowingHelpers() {
        IExtensionHelpers real = helpers();
        return (IExtensionHelpers) Proxy.newProxyInstance(InjectHarness.class.getClassLoader(),
                new Class[]{IExtensionHelpers.class},
                (p, m, a) -> "updateParameter".equals(m.getName()) ? a[0] : m.invoke(real, a));
    }

    static AIEngine engine() throws Exception {
        AIEngine e = new AIEngine((IBurpExtenderCallbacks) Proxy.newProxyInstance(
                        InjectHarness.class.getClassLoader(), new Class[]{IBurpExtenderCallbacks.class},
                        (p, m, a) -> { throw new UnsupportedOperationException(m.getName()); }),
                helpers(), new LogPanel(), null);
        return e;
    }

    static byte[] modify(AIEngine engine, String request, String payload, String position) throws Exception {
        Method m = AIEngine.class.getDeclaredMethod("modifyRequest", byte[].class, String.class, String.class);
        m.setAccessible(true);
        return (byte[]) m.invoke(engine, request.getBytes(StandardCharsets.UTF_8), payload, position);
    }

    // ---------------------------------------------------------------- 发包截获
    /** sendTestRequest 真正交给 Burp 的请求字节（由 makeHttpRequest 桩留存） */
    static byte[] captured;

    /**
     * 一个会「收下」请求的 callbacks 桩：makeHttpRequest 把请求字节记进 captured 并回一个空响应。
     * 用于断言发包前的处理（编码、路径替换）——这些逻辑在 sendTestRequest 里，只测 modifyRequest 看不到。
     */
    static AIEngine captureEngine() throws Exception {
        captured = null;
        IBurpExtenderCallbacks cb = (IBurpExtenderCallbacks) Proxy.newProxyInstance(
                InjectHarness.class.getClassLoader(), new Class[]{IBurpExtenderCallbacks.class},
                (p, m, a) -> {
                    if ("makeHttpRequest".equals(m.getName())) {
                        captured = (byte[]) a[a.length - 1];
                        return Proxy.newProxyInstance(InjectHarness.class.getClassLoader(),
                                new Class[]{IHttpRequestResponse.class},
                                (p2, m2, a2) -> {
                                    if ("getResponse".equals(m2.getName())) {
                                        return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".getBytes(StandardCharsets.UTF_8);
                                    }
                                    if ("getRequest".equals(m2.getName())) return captured;
                                    throw new UnsupportedOperationException(m2.getName());
                                });
                    }
                    if ("printError".equals(m.getName())) return null;
                    throw new UnsupportedOperationException(m.getName());
                });
        return new AIEngine(cb, helpers(), new LogPanel(), null);
    }

    /** 走真实的 sendTestRequest（含看门狗线程与超时等待），结果只关心 captured */
    static void sendWith(AIEngine engine, String request, String payload, String position) throws Exception {
        sendAndGet(engine, request.getBytes(StandardCharsets.UTF_8), payload, position);
    }

    /** 同上，但把 sendTestRequest 的返回值交给调用方（超时/无响应那几条路径要断言它） */
    static Object sendAndGet(AIEngine engine, byte[] reqBytes, String payload, String position) throws Exception {
        IHttpRequestResponse orig = (IHttpRequestResponse) Proxy.newProxyInstance(
                InjectHarness.class.getClassLoader(), new Class[]{IHttpRequestResponse.class},
                (p, m, a) -> {
                    if ("getRequest".equals(m.getName())) return reqBytes;
                    if ("getHttpService".equals(m.getName())) {
                        return Proxy.newProxyInstance(InjectHarness.class.getClassLoader(),
                                new Class[]{IHttpService.class}, (p2, m2, a2) -> {
                                    throw new UnsupportedOperationException(m2.getName());
                                });
                    }
                    throw new UnsupportedOperationException(m.getName());
                });
        Method m = AIEngine.class.getDeclaredMethod("sendTestRequest",
                IHttpRequestResponse.class, String.class, String.class);
        m.setAccessible(true);
        return m.invoke(engine, orig, payload, position);
    }

    /** TestSendResult.response 字段（私有类型，反射读） */
    static IHttpRequestResponse responseOf(Object sendResult) throws Exception {
        if (sendResult == null) return null;
        java.lang.reflect.Field f = sendResult.getClass().getDeclaredField("response");
        f.setAccessible(true);
        return (IHttpRequestResponse) f.get(sendResult);
    }

    /** 发送行为可定制的 callbacks 桩：用于「发出去了但没拿到响应」的三条路径 */
    static AIEngine engineWithSend(java.util.function.Function<byte[], IHttpRequestResponse> send) throws Exception {
        IBurpExtenderCallbacks cb = (IBurpExtenderCallbacks) Proxy.newProxyInstance(
                InjectHarness.class.getClassLoader(), new Class[]{IBurpExtenderCallbacks.class},
                (p, m, a) -> {
                    if ("makeHttpRequest".equals(m.getName())) {
                        return send.apply((byte[]) a[a.length - 1]);
                    }
                    if ("printError".equals(m.getName())) return null;
                    throw new UnsupportedOperationException(m.getName());
                });
        return new AIEngine(cb, helpers(), new LogPanel(), null);
    }

    /**
     * 「包发出去了，但没拿到响应」的三条路径 —— 超时 / Burp 返回 null / makeHttpRequest 抛异常。
     *
     * <p>用户反馈（2026-09-24）：日志里有 [超时告警]，但「请求与响应详情」里连包都看不到。
     * 根因是这三条路径都返回 null，调用方按「压根没发出去」处理，于是**连探针记录都不建** ——
     * 而超时那条恰恰是最需要人眼看一眼的：得能对着发出去的包判断是目标挂了还是被拦了。
     * 现在一律返回一个只带请求的结果，响应恒为 null。
     *
     * <p>这条要真等满看门狗（{@code TEST_REQUEST_TIMEOUT_SECONDS} = 10 秒），所以慢 ——
     * 慢也得测：超时分支是这次修复的主角，用假时钟测不到它。
     */
    static void checkSentButNoResponse() throws Exception {
        byte[] req = "GET /a?cmd=1 HTTP/1.1\r\nHost: x\r\n\r\n".getBytes(StandardCharsets.UTF_8);

        AIEngine hanging = engineWithSend(b -> {
            try {
                Thread.sleep(30000L);            // 目标不响应；看门狗 10 秒后放弃并打断它
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return null;
        });
        long t0 = System.currentTimeMillis();
        Object timedOut = sendAndGet(hanging, req, "x; id", "cmd");
        long took = System.currentTimeMillis() - t0;
        check("超时的载荷不再返回 null（返回 null 就等于不建探针记录 = 详情里没有包）",
                timedOut != null, "返回了 null");
        IHttpRequestResponse timeoutMsg = responseOf(timedOut);
        // 存的是**实际发出去的那份**（GET 查询参数里的空格已按既有规则编成 +），不是原始请求
        check("超时结果里带着发出去的那份请求（详情面板据此显示包）",
                timeoutMsg != null && timeoutMsg.getResponse() == null && timeoutMsg.getRequest() != null
                        && new String(timeoutMsg.getRequest(), StandardCharsets.UTF_8).contains("cmd=x;+id"),
                timeoutMsg == null ? "没有请求"
                        : new String(timeoutMsg.getRequest(), StandardCharsets.UTF_8).split("\r\n")[0]);
        check("超时确实走满了看门狗（≥10 秒）", took >= 10000L, "只用了 " + took + " ms");
        if (timeoutMsg != null) {
            boolean threw = false;
            try {
                timeoutMsg.setRequest(req);
            } catch (UnsupportedOperationException e) {
                threw = true;
            }
            check("这份请求不可修改（存的是已发出去的字节，改了日志/报告/详情就会各说各话）",
                    threw, "setter 没抛异常");
        }

        Object nullResult = sendAndGet(engineWithSend(b -> null), req, "x; id", "cmd");
        IHttpRequestResponse nullMsg = responseOf(nullResult);
        check("Burp 返回 null（目标不可达/被拦截）时同样留下带请求的记录",
                nullMsg != null && nullMsg.getRequest() != null && nullMsg.getResponse() == null,
                nullResult == null ? "返回了 null" : String.valueOf(nullMsg));

        Object errResult = sendAndGet(engineWithSend(b -> {
            throw new IllegalStateException("模拟发送失败");
        }), req, "x; id", "cmd");
        IHttpRequestResponse errMsg = responseOf(errResult);
        check("makeHttpRequest 抛异常时同样留下带请求的记录",
                errMsg != null && errMsg.getRequest() != null && errMsg.getResponse() == null,
                errResult == null ? "返回了 null" : String.valueOf(errMsg));

        // 反向：真的拿到响应时必须原样返回 Burp 给的那个对象，不能也被换成自造件
        Object okResult = sendAndGet(captureEngine(), req, "x; id", "cmd");
        IHttpRequestResponse okMsg = responseOf(okResult);
        // 失败说明里**不能** String.valueOf(okMsg)：那是 Proxy 桩，没实现 toString，
        // 求值 detail 时会抛 UnsupportedOperationException 把整个 harness 带走（第一版就这么死的）
        check("正常拿到响应时返回的是 Burp 给的对象（不是自造的占位件）",
                okMsg != null && okMsg.getResponse() != null,
                okMsg == null ? "返回了 null" : "有对象但响应为 null");
    }

    // ---------------------------------------------------------------- 断言
    static void check(String name, boolean ok, String detail) {
        if (ok) { passed++; System.out.println("  ✅ " + name); }
        else { failures.add(name + "  <- " + detail); System.out.println("  ❌ " + name + "  <- " + detail); }
    }

    /** step2 结果里的映射位置（按顺序），用于断言映射层去重后的结果 */
    static List<String> paramsOf(JsonObject step2Result) {
        List<String> params = new ArrayList<>();
        if (step2Result == null || !step2Result.has("paramVulnMap")) return params;
        for (com.google.gson.JsonElement elem : step2Result.getAsJsonArray("paramVulnMap")) {
            if (elem != null && elem.isJsonObject()) {
                params.add(elem.getAsJsonObject().get("param").getAsString());
            }
        }
        return params;
    }

    static String body(byte[] req) {
        String s = new String(req, StandardCharsets.UTF_8);
        int i = s.indexOf("\r\n\r\n");
        return i < 0 ? "" : s.substring(i + 4);
    }

    static int declaredContentLength(byte[] req) {
        String s = new String(req, StandardCharsets.UTF_8);
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("(?im)^content-length:\\s*(\\d+)").matcher(s);
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }

    static int actualBodyLength(byte[] req) {
        String s = new String(req, StandardCharsets.UTF_8);
        int i = s.indexOf("\r\n\r\n");
        return i < 0 ? 0 : req.length - (i + 4);
    }

    static void checkCL(String name, byte[] req) {
        check(name + " | Content-Length 与实际字节数一致",
                declaredContentLength(req) == actualBodyLength(req),
                "声明 " + declaredContentLength(req) + " vs 实际 " + actualBodyLength(req));
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("java.awt.headless", "true");
        AIEngine engine = engine();

        System.out.println("\n--- 通用参数注入 ---");
        String form = "POST /a HTTP/1.1\r\nHost: t\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\nid=1&name=x";
        byte[] r = modify(engine, form, "1' OR '1'='1", "id");
        check("urlencoded: id 被注入", r != null && body(r).startsWith("id=1' OR '1'='1"), r == null ? "null" : body(r));
        check("urlencoded: name 未被改动", r != null && body(r).endsWith("&name=x"), r == null ? "null" : body(r));
        checkCL("urlencoded", r);

        r = modify(engine, form, "ZZZ", "ID");
        check("大小写不匹配的 position 注入到真实参数", r != null && body(r).startsWith("id=ZZZ"), r == null ? "null" : body(r));

        r = modify(engine, form, "ZZZ", "nope");
        check("位置不存在 → 返回 null（不再兜底注入第一个参数）", r == null, r == null ? "ok" : body(r));

        r = modify(engine, form, "ZZZ", "Auto");
        check("Auto（大小写变体）被拒绝", r == null, r == null ? "ok" : body(r));

        System.out.println("\n--- header 位置 ---");
        String get = "GET /a?id=1 HTTP/1.1\r\nHost: t\r\nUser-Agent: ua\r\n\r\n";
        r = modify(engine, get, "127.0.0.1", "x-forwarded-for");
        check("裸名 x-forwarded-for 路由到 header（此前会兜底注入 id）",
                r != null && new String(r, StandardCharsets.UTF_8).toLowerCase().contains("x-forwarded-for: 127.0.0.1"),
                r == null ? "null" : new String(r, StandardCharsets.UTF_8));
        check("注入的 header 位于 header 区（blank line 之前）",
                r != null && new String(r, StandardCharsets.UTF_8).matches("(?s).*User-Agent: ua\\r\\nx-forwarded-for: 127\\.0\\.0\\.1\\r\\n\\r\\n"),
                r == null ? "null" : new String(r, StandardCharsets.UTF_8).replace("\r", "\\r").replace("\n", "\\n"));
        check("header 注入保留 header/body 分隔空行",
                r != null && new String(r, StandardCharsets.UTF_8).contains("\r\n\r\n"), "缺空行");
        check("header 注入未改动 id 参数", r != null && new String(r, StandardCharsets.UTF_8).contains("id=1"), "id 被改");

        r = modify(engine, get, "1.2.3.4", "header:Referer");
        check("header:Referer 显式语法", r != null && new String(r, StandardCharsets.UTF_8).contains("Referer: 1.2.3.4"), r == null ? "null" : "未注入");

        r = modify(engine, get, "evil", "header:host");
        check("header:host 被黑名单拦下（此前可绕过）", r == null, r == null ? "ok" : "被注入");

        r = modify(engine, get, "a\r\nX-Evil: 1", "x-forwarded-for");
        check("载荷中的 CRLF 被剔除（未伪造出新 header 行）",
                r != null && !new String(r, StandardCharsets.UTF_8).contains("\r\nX-Evil"),
                r == null ? "null" : "存在 CRLF 注入");

        System.out.println("\n--- header 注入时 body 字节不被腐蚀 ---");
        byte[] binBody = new byte[]{(byte) 0x89, 'P', 'N', 'G', 0x00, (byte) 0xff, (byte) 0xfe, 0x01};
        byte[] binReq = concat("POST /u HTTP/1.1\r\nHost: t\r\nContent-Length: 8\r\n\r\n".getBytes(StandardCharsets.UTF_8), binBody);
        Method m = AIEngine.class.getDeclaredMethod("modifyRequest", byte[].class, String.class, String.class);
        m.setAccessible(true);
        byte[] rb = (byte[]) m.invoke(engine, binReq, "1.1.1.1", "x-forwarded-for");
        check("header 注入后二进制 body 字节完全一致",
                rb != null && contains(rb, binBody), rb == null ? "null" : "body 被腐蚀");

        System.out.println("\n--- JSON ---");
        String json = "POST /a HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: 25\r\n\r\n{\"id\":1,\"name\":\"x\",\"z\":2}";
        r = modify(engine, json, "1' OR '1'='1", "id");
        check("JSON 顶层键被替换", r != null && body(r).contains("\"id\":\"1' OR '1'='1\""), r == null ? "null" : body(r));
        check("JSON 其余键保留", r != null && body(r).contains("\"name\":\"x\"") && body(r).contains("\"z\":2"), r == null ? "null" : body(r));
        checkCL("JSON 顶层", r);
        check("JSON 载荷未被 \\uXXXX 转义", r != null && !body(r).contains("\\u003c"), "出现转义");

        String nested = "POST /a HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: 34\r\n\r\n{\"user\":{\"id\":1,\"n\":\"x\"},\"k\":\"v\"}";
        r = modify(engine, nested, "PWN", "user.id");
        check("JSON 嵌套路径 user.id 被替换",
                r != null && body(r).contains("\"id\":\"PWN\"") && body(r).contains("\"n\":\"x\""), r == null ? "null" : body(r));
        check("JSON 嵌套注入不影响顶层 k", r != null && body(r).contains("\"k\":\"v\""), r == null ? "null" : body(r));
        checkCL("JSON 嵌套", r);

        String arr = "POST /a HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: 45\r\n\r\n{\"items\":[{\"name\":\"a\"},{\"name\":\"b\"}],\"t\":1}";
        r = modify(engine, arr, "PWN", "items[1].name");
        check("JSON 数组路径 items[1].name 只改第二个元素",
                r != null && body(r).contains("[{\"name\":\"a\"},{\"name\":\"PWN\"}]"), r == null ? "null" : body(r));

        String obj = "POST /a HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: 21\r\n\r\n{\"user\":{\"id\":1,\"r\":\"u\"}}";
        r = modify(engine, obj, "{\"role\":\"admin\"}", "user");
        check("payload 为 JSON 对象 → 按键合并、保留其余键",
                r != null && body(r).contains("\"id\":1") && body(r).contains("\"role\":\"admin\""), r == null ? "null" : body(r));

        r = modify(engine, json, "PWN", "nonexistent");
        check("JSON 路径不存在 → null（不再改写第一个原始值键）", r == null, r == null ? "ok" : body(r));

        String vendorJson = "POST /a HTTP/1.1\r\nHost: t\r\nContent-Type: application/vnd.api+json\r\nContent-Length: 9\r\n\r\n{\"id\":1,\"z\":2}";
        r = modify(engine, vendorJson, "PWN", "z");
        check("application/vnd.api+json 走 JSON 路径", r != null && body(r).contains("\"z\":\"PWN\""), r == null ? "null" : body(r));

        System.out.println("\n--- XML ---");
        String xml = "POST /a HTTP/1.1\r\nHost: t\r\nContent-Type: text/xml\r\nContent-Length: 30\r\n\r\n<r><id>1</id><n>x</n></r>";
        r = modify(engine, xml, "PWN", "id");
        check("XML 元素文本值被替换", r != null && body(r).contains("<id>PWN</id>"), r == null ? "null" : body(r));
        check("XML 其它元素保留", r != null && body(r).contains("<n>x</n>"), r == null ? "null" : body(r));

        String xxe = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>";
        r = modify(engine, xml, xxe, "id");
        check("XML 完整文档（含 DOCTYPE）→ 整段 body 替换",
                r != null && body(r).contains("<!DOCTYPE") && body(r).contains("<!ENTITY"), r == null ? "null" : body(r));
        checkCL("XML 整段替换", r);

        byte[] rEntity = modify(engine, xml, "&xxe;", "id");
        check("XML 元素里的实体引用原样写入（被转义成 &amp;xxe; 的话 XXE 永远打不出来）",
                rEntity != null && body(rEntity).contains("<id>&xxe;</id>"),
                rEntity == null ? "null" : body(rEntity));

        AIEngine swallowEngine = new AIEngine((IBurpExtenderCallbacks) Proxy.newProxyInstance(
                        InjectHarness.class.getClassLoader(), new Class[]{IBurpExtenderCallbacks.class},
                        (p, mm, a) -> { throw new UnsupportedOperationException(mm.getName()); }),
                swallowingHelpers(), new LogPanel(), null);
        byte[] rSwallowed = modify(swallowEngine, "GET /a?id=1 HTTP/1.1\r\nHost: t\r\n\r\n", "PWN", "id");
        check("Burp 只收不写时判为注入失败（绝不把原始请求当测试包发出去）",
                rSwallowed == null, rSwallowed == null ? "null" : body(rSwallowed));

        // 原请求**没有 Content-Length** 时的补头分支：只该切掉末尾空行的那一个 CRLF。
        // 切 4 个字符会把上一行请求头自己的终结符也切掉，两个头粘成一行
        // （Content-Type: application/xmlContent-Length: 25）—— Content-Length 头于是**根本不存在**、
        // 上一个头的值也被污染，而载荷确实在字节里，注入层的自检抓不到 → 静默漏报。
        // Repeater 里手搓的原始请求、GET 带 body、chunked 上传都没有 CL 头。
        //（LF 换行的同类分支没有夹具：离线桩的 analyzeRequest 只认 CRLF，加了等于测桩。）
        System.out.println("\n--- 原请求没有 Content-Length 时补头 ---");
        String noCl = "POST /a HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\n\r\n{\"id\":1}";
        byte[] rNoCl = modify(engine, noCl, "{\"id\":2}", "id");
        String rNoClStr = rNoCl == null ? "" : new String(rNoCl, StandardCharsets.UTF_8);
        checkCL("无 Content-Length 的请求（CRLF）", rNoCl);
        check("补出来的 Content-Length 是独立的一行，不与上一个头粘连",
                rNoClStr.contains("Content-Type: application/json\r\nContent-Length: "),
                rNoClStr.replace("\r\n", "\\r\\n"));
        check("载荷照旧写进去了", rNoClStr.endsWith("{\"id\":2}"), rNoClStr.replace("\r\n", "\\r\\n"));

        System.out.println("\n--- 整段 body（text/plain、GraphQL）---");        String plain = "POST /a HTTP/1.1\r\nHost: t\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nabc";
        r = modify(engine, plain, "PAYLOAD", "BODY");
        check("text/plain + BODY → 整段替换", r != null && body(r).equals("PAYLOAD"), r == null ? "null" : body(r));
        checkCL("text/plain 整段替换", r);

        String graphql = "POST /g HTTP/1.1\r\nHost: t\r\nContent-Type: application/graphql\r\nContent-Length: 20\r\n\r\n{ user(id: 1) { n } }";
        r = modify(engine, graphql, "PAYLOAD", "BODY");
        check("application/graphql + BODY → 整段替换", r != null && body(r).equals("PAYLOAD"), r == null ? "null" : body(r));

        // 靶场实测（fastjson 1.2.45）：抓到的请求「头是表单、体是 JSON」→ 框架按表单解析后
        // JSON 解析器拿到空串（400: syntax error, expect {, actual error, pos 0），
        // 9 条载荷一条都没进到解析器。发整段文档时必须把 Content-Type 对齐。
        System.out.println("\n--- 整段 body 的 Content-Type 对齐 ---");
        String formHead = "POST /j HTTP/1.1\r\nHost: t\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 21\r\n\r\n{\"age\":25,\"name\":\"Bo\"}";
        byte[] rJsonBody = modify(engine, formHead,
                "{\"age\":25,\"name\":\"Bo\",\"data\":{\"@type\":\"java.net.Inet4Address\",\"val\":\"oob.invalid\"}}", "BODY");
        String rJsonStr = rJsonBody == null ? "" : new String(rJsonBody, StandardCharsets.UTF_8);
        check("表单头 + JSON 文档 → 本条改用 application/json（否则服务端解析不到 body，载荷等于没发）",
                rJsonBody != null && rJsonStr.contains("Content-Type: application/json")
                        && !rJsonStr.contains("x-www-form-urlencoded"), rJsonStr.split("\r\n").length > 2
                        ? rJsonStr.split("\r\n")[2] : rJsonStr);
        check("JSON 文档整段替换后 body 原样（没有被编码或改动）",
                rJsonBody != null && body(rJsonBody).startsWith("{\"age\":25"), body(rJsonBody));
        checkCL("JSON 文档改头后 Content-Length", rJsonBody);

        byte[] rXmlBody = modify(engine, "POST /x HTTP/1.1\r\nHost: t\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nabc",
                "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"http://oob.invalid/x\">]><r>&x;</r>", "BODY");
        check("text/plain + XML 文档 → 改用 application/xml",
                rXmlBody != null && new String(rXmlBody, StandardCharsets.UTF_8).contains("Content-Type: application/xml"),
                rXmlBody == null ? "null" : new String(rXmlBody, StandardCharsets.UTF_8).split("\r\n")[2]);

        String alreadyJson = "POST /j HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}";
        byte[] rKeep = modify(engine, alreadyJson, "{\"@type\":\"java.net.URL\",\"val\":\"http://oob.invalid/\"}", "BODY");
        String rKeepStr = rKeep == null ? "" : new String(rKeep, StandardCharsets.UTF_8);
        int ctCount = rKeepStr.split("(?i)content-type:", -1).length - 1;
        check("本来就是 application/json → 一个字都不动（不会多插一行 Content-Type）", ctCount == 1, "Content-Type 出现 " + ctCount + " 次");

        byte[] rGql = modify(engine, "POST /g HTTP/1.1\r\nHost: t\r\nContent-Type: text/plain\r\nContent-Length: 20\r\n\r\n{ user(id: 1) { n } }",
                "{ user(id: 1) { n } }", "BODY");
        check("GraphQL（长得像 JSON 但不是 JSON）不被误标成 application/json",
                rGql != null && new String(rGql, StandardCharsets.UTF_8).contains("Content-Type: text/plain"),
                rGql == null ? "null" : new String(rGql, StandardCharsets.UTF_8).split("\r\n")[2]);

        String bodyParam = "POST /a HTTP/1.1\r\nHost: t\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 8\r\n\r\nbody=abc";
        r = modify(engine, bodyParam, "PWN", "BODY");
        check("请求里真有名为 body 的参数时优先按参数注入",
                r != null && body(r).equals("body=PWN"), r == null ? "null" : body(r));

        System.out.println("\n--- multipart ---");
        String mp = "POST /u HTTP/1.1\r\nHost: t\r\nContent-Type: multipart/form-data; boundary=----B.+()[]\r\nContent-Length: 100\r\n\r\n"
                + "------B.+()[]\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n------B.+()[]--\r\n";
        r = modify(engine, mp, "PWN", "file");
        check("boundary 含正则元字符时仍能注入（此前 split 当正则）",
                r != null && body(r).contains("PWN"), r == null ? "null" : body(r));
        check("multipart 未注入的 part 保持原样", r != null && body(r).contains("filename=\"a.txt\""), r == null ? "null" : body(r));
        checkCL("multipart 普通 part（此前完全不更新 CL）", r);

        r = modify(engine, mp, "PWN", "nope");
        check("multipart 位置不匹配 → null（此前发原包）", r == null, r == null ? "ok" : body(r));

        // 值编码按 Content-Type 判，不信参数类型：真实 Burp 把 multipart 的 part 名报成 PARAM_BODY
        // （桩现在也这么报，见 scanMultipartParts），只信类型就会把 part 值当表单值去编码 ——
        // 而 multipart 的链路上没有任何一方会解码回来，载荷直接变成字面量。
        // 实测 S2-059 靶场：%{100*100} 被发成 %25%7B100*100%7D，靶场原样回显，OGNL 永远拿不到表达式。
        String mpPlain = "POST /a HTTP/1.1\r\nHost: t\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: 100\r\n\r\n"
                + "--B\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\ntest\r\n--B--\r\n";
        String formPlain = "POST /a HTTP/1.1\r\nHost: t\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\nid=test";
        AIEngine encEngine = captureEngine();
        sendWith(encEngine, mpPlain, "%{100*100}", "id");
        String mpSent = captured == null ? "" : body(captured);
        check("multipart 的 part 值不做 URL 编码（编了容器也不会解码 → OGNL/SQLi 载荷全成字面量）",
                mpSent.contains("%{100*100}") && !mpSent.contains("%25%7B"), mpSent.replace("\r", "\\r"));
        sendWith(encEngine, mpPlain, "a&b c", "id");
        check("multipart 值里的 & 与空格保持原样（& 在 part 内是普通字符，不是分隔符）",
                captured != null && body(captured).contains("a&b c"),
                captured == null ? "没截到" : body(captured));
        sendWith(encEngine, formPlain, "%{100*100}", "id");
        check("同名的 urlencoded body 参数仍然编码（本次修复只针对 multipart，别把表单值也放行）",
                captured != null && body(captured).contains("%25%7B100*100%7D"),
                captured == null ? "没截到" : body(captured));

        String mpFile = "POST /u HTTP/1.1\r\nHost: t\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: 200\r\n\r\n"
                + "--B\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhi\r\n"
                + "--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"old.php\"\r\nContent-Type: application/octet-stream\r\n\r\nOLD\r\n--B--\r\n";
        String partPayload = "Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\nContent-Type: image/png\r\n\r\n<?php echo 1;?>";
        r = modify(engine, mpFile, partPayload, "file");
        String mpBody = r == null ? "" : body(r);
        check("整段替换：filename 引号闭合且无杂字符（此前拼出 \"shell.php...\"）",
                mpBody.contains("filename=\"shell.php\"\r\n"), mpBody.replace("\r", "\\r"));
        check("整段替换：Content-Disposition 行正确结束（此前与 Content-Type 粘连成一行）",
                mpBody.contains("name=\"file\"; filename=\"shell.php\"\r\nContent-Type: image/png"), mpBody.replace("\r", "\\r"));
        check("整段替换：文件内容写入", mpBody.contains("<?php echo 1;?>"), mpBody.replace("\r", "\\r"));
        check("整段替换：非文件 part 保持原样", mpBody.contains("name=\"note\"") && mpBody.contains("\r\n\r\nhi\r\n"), mpBody.replace("\r", "\\r"));
        check("整段替换：结尾只有一个 --B--", mpBody.split(java.util.regex.Pattern.quote("--B--"), -1).length - 1 == 1, mpBody.replace("\r", "\\r"));
        checkCL("multipart 整段替换", r);

        // 纯内容载荷（无 Content-Disposition）→ 只替换字段内容，不重建 part
        r = modify(engine, mpFile, "<?php echo 2;?>", "file");
        String plainBody = r == null ? "" : body(r);
        check("纯内容载荷：只替换 part 内容", plainBody.contains("<?php echo 2;?>"), plainBody.replace("\r", "\\r"));
        check("纯内容载荷：filename 保持不变", plainBody.contains("filename=\"old.php\""), plainBody.replace("\r", "\\r"));
        check("纯内容载荷：part 结构完好（header/内容分隔符仍在）",
                plainBody.contains("application/octet-stream\r\n\r\n<?php echo 2;?>"), plainBody.replace("\r", "\\r"));
        checkCL("multipart 纯内容载荷", r);

        System.out.println("\n--- Content-Length 边界 ---");
        String trap = "POST /a HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: 43\r\n\r\n{\"q\":\"Content-Length: 999\",\"id\":1}";
        r = modify(engine, trap, "PWN", "id");
        check("body 里的 Content-Length 字样不被误改（只改 header 区）",
                r != null && body(r).contains("Content-Length: 999"), r == null ? "null" : body(r));
        checkCL("body 含同名字符串时的 CL", r);

        System.out.println("\n--- 二进制 multipart body（字节级整段替换）---");
        byte[] png = new byte[]{(byte) 0x89, 'P', 'N', 'G', (byte) 0xff, (byte) 0xfe, 0x00, 0x01};
        byte[] mpBin = concat(("POST /u HTTP/1.1\r\nHost: t\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: 300\r\n\r\n"
                + "--B\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhi\r\n"
                + "--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n").getBytes(StandardCharsets.UTF_8),
                concat(png, "\r\n--B--\r\n".getBytes(StandardCharsets.UTF_8)));
        String binPart = "Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n"
                + "Content-Type: image/png\r\n\r\n<?php echo 123;?>";
        byte[] rbin = (byte[]) m.invoke(engine, mpBin, binPart, "file");
        check("含二进制 part 的请求现在可注入（不再整条跳过）", rbin != null, "返回 null（仍被跳过）");
        if (rbin != null) {
            String s = new String(rbin, StandardCharsets.UTF_8);
            check("二进制 part 被整段替换", s.contains("filename=\"shell.php\"") && s.contains("<?php echo 123;?>"), "未替换");
            check("原 part 头未残留（整段替换而非叠加）", !s.contains("filename=\"a.png\""), "旧 part 仍在");
            check("非目标 part 保持原样", s.contains("name=\"note\"") && s.contains("\r\n\r\nhi\r\n"), "note part 被破坏");
            check("原二进制字节未被 UTF-8 往返腐蚀", !s.contains("�"), "出现了替换字符 U+FFFD");
            checkCL("二进制 multipart 整段替换", rbin);
        }

        // 纯值形态的载荷对二进制 body 现在也能注入：内容替换不需要解码整个 body，
        // 只需要 part 头（ASCII）与算出来的正文区间。以前这里整条跳过，然后落到通用参数替换，
        // 把 part 头写坏却照样发包 —— 报告里的「未发现漏洞」其实一个有效请求都没发出去。
        byte[] rbinPlain = (byte[]) m.invoke(engine, mpBin, "PWN", "file");
        String plainStr = rbinPlain == null ? "" : new String(rbinPlain, StandardCharsets.UTF_8);
        check("二进制 body + 纯值载荷 → part 内容被替换（不再整条跳过）",
                rbinPlain != null && plainStr.contains("\r\n\r\nPWN\r\n"), rbinPlain == null ? "null" : plainStr);
        check("…part 头里的 filename 与 Content-Type 保持原样",
                plainStr.contains("filename=\"a.png\"") && plainStr.contains("Content-Type: image/png"),
                plainStr);
        check("…原二进制内容确实被换掉了（目标就是这个 part）", rbinPlain != null && !contains(rbinPlain, png),
                "原 png 字节仍在");
        check("…旁边的文本 part 保持原样", plainStr.contains("\r\n\r\nhi\r\n"), plainStr);
        check("…结束分隔符 --B-- 还在（拼装时不能丢尾部）", plainStr.contains("\r\n--B--\r\n"), plainStr);
        checkCL("二进制 body + 纯值载荷", rbinPlain);

        // 用户实测报回来的形态：filename="x.php" + 空行 + 正文。这是文件上传载荷最常见的写法，
        // 而含二进制的 body 原来会把它整条丢掉（再落到参数替换，把 part 头写成普通表单字段，
        // 服务端 request.files 直接为空 —— 那一串包谁也证明不了）
        String phpPayload = "filename=\"shell.php\"\n\n<?php echo 123;?>";
        byte[] rPhp = (byte[]) m.invoke(engine, mpBin, phpPayload, "file");
        String phpStr = rPhp == null ? "" : new String(rPhp, StandardCharsets.UTF_8);
        check("二进制 body + filename=… + 正文 → part 的 filename 真的被换掉",
                rPhp != null && phpStr.contains("filename=\"shell.php\""), rPhp == null ? "null" : phpStr);
        check("…正文写进了 part 内容", phpStr.contains("<?php echo 123;?>"), phpStr);
        check("…part 头结构完整（Content-Disposition 与 Content-Type 都还在，没被写成普通表单字段）",
                phpStr.contains("Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"")
                        && phpStr.contains("Content-Type: image/png"), phpStr);
        check("…旧文件名不残留", !phpStr.contains("filename=\"a.png\""), phpStr);
        check("…旁边的文本 part 没被动", phpStr.contains("\r\n\r\nhi\r\n"), "note part 被改动");
        check("…没有多出或少掉字节（尾部结束分隔符完整）",
                phpStr.endsWith("--B--\r\n"), phpStr.substring(Math.max(0, phpStr.length() - 40)));
        checkCL("二进制 body + filename/正文形态", rPhp);
        check("…正文紧贴下一个分隔符的情况不存在（换正文时补回了尾部 CRLF）",
                rPhp != null && phpStr.contains("<?php echo 123;?>\r\n--B"), phpStr);

        // 只声明 filename=、空行之后没有正文时，原文件内容必须原样保留 ——
        // 「后缀改成 .php、内容还是原图」是最有说服力的上传证据
        byte[] rHeaderOnly = (byte[]) m.invoke(engine, mpBin, "filename=\"shell.php\"", "file");
        String headerOnlyStr = rHeaderOnly == null ? "" : new String(rHeaderOnly, StandardCharsets.UTF_8);
        check("只改 filename、不给正文 → 原文件的二进制字节原样保留",
                rHeaderOnly != null && contains(rHeaderOnly, png)
                        && headerOnlyStr.contains("filename=\"shell.php\"")
                        && headerOnlyStr.endsWith("--B--\r\n"), headerOnlyStr);

        // position 匹配不上任何 part 时不能改靶：旧版那种「退到第一个部件」的兜底已经移除
        byte[] rPlainMiss = (byte[]) m.invoke(engine, mpBin, "PWN", "nonexistent");
        check("二进制 body + 纯值载荷 + 位置不存在 → null（不改靶打到文件部件上）",
                rPlainMiss == null, rPlainMiss == null ? "ok" : new String(rPlainMiss, StandardCharsets.UTF_8));

        // 反向：multipart 请求里的 **URL 查询参数**是普通参数，不能因为「请求是 multipart」
        // 就被一起挡掉（挡多了就是漏扫）
        byte[] mpQuery = InjectHarness.concat(("POST /u?q=1 HTTP/1.1\r\nHost: t\r\n"
                + "Content-Type: multipart/form-data; boundary=B\r\nContent-Length: 200\r\n\r\n"
                + "--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\n"
                + "Content-Type: image/png\r\n\r\n").getBytes(StandardCharsets.UTF_8),
                InjectHarness.concat(png, "\r\n--B--\r\n".getBytes(StandardCharsets.UTF_8)));
        byte[] rQuery = (byte[]) m.invoke(engine, mpQuery, "PWN", "q");
        // 通用参数替换绝不能碰 multipart 部件：Burp 的 updateParameter 会重写整个 part 值区间，
        // 连 Content-Disposition 里的 filename= 一起吃 —— 请求就从「文件上传」变成「普通表单字段」，
        // 而载荷**确实原样写进去了**，所以注入层那道「有没有写进去」的自检也拦不住它。
        // 这条以前是真会发出去的（用户实测的请求就是它改出来的），专门钉住。
        java.lang.reflect.Method modParam = AIEngine.class.getDeclaredMethod("modifyParameter",
                byte[].class, String.class, String.class, IRequestInfo.class);
        modParam.setAccessible(true);
        byte[] viaParam = (byte[]) modParam.invoke(engine, mpBin, "PWN", "file", helpers().analyzeRequest(mpBin));
        check("multipart 部件不会被通用参数替换改写（那条路会丢掉 part 的 filename 属性）",
                viaParam == null, viaParam == null ? "ok"
                        : "被改写成: " + new String(viaParam, StandardCharsets.UTF_8).replace("\r\n", "|"));

        check("multipart 请求里的 URL 查询参数照常注入（守卫只挡部件，不挡整条请求）",
                rQuery != null && new String(rQuery, StandardCharsets.UTF_8).contains("?q=PWN"),
                rQuery == null ? "null（误伤）" : new String(rQuery, StandardCharsets.UTF_8).split("\r\n")[0]);

        // Burp 把文件部件报成两个参数（part 名 + filename 属性），它们是同一个上传面。
        // 两个都留在参数表里的代价：step2 映射两个 → step3 为同一个 part 各生成 9 条载荷
        // （用户实测 18 条：1-9 打 file、10-18 打 filename），报告里还出两条只是参数名不同的同一条洞。
        java.lang.reflect.Method validNames = AIEngine.class.getDeclaredMethod("getValidParamNames",
                byte[].class, com.zackai.model.ScanTask.class);
        validNames.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<String> mpNames = (List<String>) validNames.invoke(engine, mpBin, null);
        check("文件部件的 filename 属性不再被当成独立参数（同一个上传面只留 part 名）",
                mpNames.equals(Arrays.asList("note", "file")), String.valueOf(mpNames));

        // 安全兜底：万一某个 Burp 版本只报 filename 属性、不报 part 名，绝不能把整个上传点丢掉
        java.lang.reflect.Method dupAttr = AIEngine.class.getDeclaredMethod("isDuplicateMultipartAttribute",
                byte[].class, IParameter.class, List.class);
        dupAttr.setAccessible(true);
        int fnStart = new String(mpBin, StandardCharsets.UTF_8).indexOf("filename=\"");
        IParameter fnOnly = new P("filename", "a.png", IParameter.PARAM_MULTIPART_ATTR,
                fnStart, fnStart + 8, fnStart + 10, fnStart + 15);
        check("参数表里只有 filename 属性、没有 part 名时保留它（不把上传点丢掉）",
                Boolean.FALSE.equals(dupAttr.invoke(null, mpBin, fnOnly, Arrays.asList(fnOnly))),
                "被当成重复丢掉了");
        check("同一 part 的普通文本字段不受影响（note 仍在参数表里）",
                mpNames.contains("note"), String.valueOf(mpNames));

        // 参数表去重只是前半段：模型照样会为同一个上传面写两条 —— 步骤 2 的注入点提示允许
        // 「part 名或它的 filename 属性」，而这两条映射在 isValidPosition 的兜底判据里都算
        // 「请求里真实存在的位置」，于是双双活下来。用户实测到的 18 条载荷（1-9 打 file、
        // 10-18 打 filename，报告里两条同源漏洞）就是这么来的。
        // 去重因此必须落在**映射层**，不能去改 isValidPosition —— 那个判据 step3 也用来验载荷位置。
        java.lang.reflect.Method validPos = AIEngine.class.getDeclaredMethod("isValidPosition",
                String.class, List.class, byte[].class);
        validPos.setAccessible(true);
        check("filename 属性仍是合法位置（步骤3 的载荷两种写法都发得出去）",
                Boolean.TRUE.equals(validPos.invoke(engine, "filename", mpNames, mpBin)),
                "被当成非法位置 —— position 写 filename 的载荷会被静默丢掉");

        java.lang.reflect.Method norm2 = AIEngine.class.getDeclaredMethod("normalizeStep2Response",
                String.class, List.class, byte[].class);
        norm2.setAccessible(true);
        JsonObject bothMapped = (JsonObject) norm2.invoke(engine, "{\"analysis\":\"a\",\"paramVulnMap\":["
                        + "{\"param\":\"file\",\"vulnTypes\":[\"文件上传\"],\"reason\":\"r\"},"
                        + "{\"param\":\"filename\",\"vulnTypes\":[\"文件上传\"],\"reason\":\"r\"}]}",
                mpNames, mpBin);
        check("part 名与 filename 属性都映射时只留 part 名（否则步骤3 出 18 条载荷）",
                paramsOf(bothMapped).equals(Arrays.asList("file")), String.valueOf(paramsOf(bothMapped)));

        JsonObject attrOnly = (JsonObject) norm2.invoke(engine, "{\"analysis\":\"a\",\"paramVulnMap\":["
                        + "{\"param\":\"filename\",\"vulnTypes\":[\"文件上传\"],\"reason\":\"r\"}]}",
                mpNames, mpBin);
        check("只映射了 filename 属性时保留它（Burp 只报属性不报部件名时不漏扫）",
                paramsOf(attrOnly).equals(Arrays.asList("filename")), String.valueOf(paramsOf(attrOnly)));

        // 非 multipart 请求里的同名字段不受影响：body 里没有部件名，partNames 为空
        byte[] formReq = "POST /a HTTP/1.1\r\nHost: t\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                .concat("Content-Length: 15\r\n\r\nfilename=abc&id=1").getBytes(StandardCharsets.UTF_8);
        JsonObject formMapped = (JsonObject) norm2.invoke(engine, "{\"analysis\":\"a\",\"paramVulnMap\":["
                        + "{\"param\":\"filename\",\"vulnTypes\":[\"XSS跨站脚本\"],\"reason\":\"r\"}]}",
                Arrays.asList("filename", "id"), formReq);
        check("普通表单里名叫 filename 的参数不会被当成部件属性删掉",
                paramsOf(formMapped).equals(Arrays.asList("filename")), String.valueOf(paramsOf(formMapped)));

        System.out.println("\n--- 整段替换的目标选择 ---");
        String notePayload = "Content-Disposition: form-data; name=\"note\"\r\n\r\nREPLACED";
        byte[] rbyName = (byte[]) m.invoke(engine, mpBin, notePayload, "note");
        check("position 指向非文件 part 时替换那个 part",
                rbyName != null && new String(rbyName, StandardCharsets.UTF_8).contains("REPLACED"),
                rbyName == null ? "null" : "未替换目标 part");
        check("换掉文本 part 后，旁边的二进制 part 逐字节不变",
                rbyName != null && contains(rbyName, png), "二进制 part 被改动");
        check("换掉文本 part 后，文件 part 头未被动",
                rbyName != null && new String(rbyName, StandardCharsets.UTF_8).contains("filename=\"a.png\""),
                "文件 part 被改动");

        byte[] rMiss = (byte[]) m.invoke(engine, mpBin, binPart, "nonexistent");
        check("没有可替换的 part 时退回第一个文件 part（与上传点直觉一致）",
                rMiss != null && new String(rMiss, StandardCharsets.UTF_8).contains("filename=\"shell.php\""),
                rMiss == null ? "null" : "未替换");

        String withTrailing = binPart + "\r\n";
        byte[] rTrail = (byte[]) m.invoke(engine, mpBin, withTrailing, "file");
        check("载荷尾部多一个 CRLF 不会产生多余空行",
                rTrail != null && !new String(rTrail, StandardCharsets.UTF_8).contains("\r\n\r\n\r\n--B"),
                rTrail == null ? "null" : "出现多余空行");
        checkCL("尾部带 CRLF 的载荷", rTrail);

        System.out.println("\n=== multipart 改后缀的形态（改后缀 = 改 filename）===");
        String mpUpload = "POST /up HTTP/1.1\r\nHost: x\r\n"
                + "Content-Type: multipart/form-data; boundary=B\r\n\r\n"
                + "--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\n"
                + "Content-Type: image/png\r\n\r\nPNGDATA\r\n--B--\r\n";
        byte[] f1 = (byte[]) m.invoke(engine, mpUpload.getBytes(StandardCharsets.UTF_8), "shell.php", "filename");
        String s1 = f1 == null ? "null" : new String(f1, StandardCharsets.UTF_8);
        check("position=filename + 裸文件名 → 文件名被改",
                f1 != null && s1.contains("filename=\"shell.php\""), s1.replace("\r", "\\r"));
        check("position=filename + 裸文件名 → 原文件内容不被覆盖",
                f1 != null && s1.contains("PNGDATA"), "内容被写成了文件名");
        byte[] f2 = (byte[]) m.invoke(engine, mpUpload.getBytes(StandardCharsets.UTF_8), "filename=\"shell.php\"", "file");
        String s2 = f2 == null ? "null" : new String(f2, StandardCharsets.UTF_8);
        check("position=文件字段 + filename= 声明 → 文件名被改", f2 != null && s2.contains("filename=\"shell.php\""), s2.replace("\r", "\\r"));
        check("只声明 filename= 时不动文件内容（否则打上去的是一堆垃圾）",
                f2 != null && s2.contains("PNGDATA") && !s2.contains("filename=\\\"shell.php\\\"\r\n\r\nfilename"), "内容被声明覆盖了");
        byte[] f3 = (byte[]) m.invoke(engine, mpUpload.getBytes(StandardCharsets.UTF_8),
                "filename=\"shell.php\"\r\n\r\n<?php echo 1;?>", "file");
        String s3 = f3 == null ? "null" : new String(f3, StandardCharsets.UTF_8);
        check("filename= 声明 + 空行 + 正文 → 文件名与内容都改",
                f3 != null && s3.contains("filename=\"shell.php\"") && s3.contains("<?php echo 1;?>"), s3.replace("\r", "\\r"));
        check("纯内容形态（position=文件字段 + 脚本）仍只改内容、不改名",
                ((byte[]) m.invoke(engine, mpUpload.getBytes(StandardCharsets.UTF_8), "<?php echo 2;?>", "file")) != null,
                "被拒绝");

        System.out.println("\n=== URL 路径段（URL_PATH / URL_PATH[下标]）===");
        String pathReq = "GET /api/user/123/profile?tab=info HTTP/1.1\r\nHost: x\r\n\r\n";
        Method path = AIEngine.class.getDeclaredMethod("modifyRequest", byte[].class, String.class, String.class);
        path.setAccessible(true);
        byte[] pLast = (byte[]) path.invoke(engine, pathReq.getBytes(StandardCharsets.UTF_8), "PWN", "URL_PATH");
        check("URL_PATH 替换最后一段、查询串不动",
                pLast != null && new String(pLast, StandardCharsets.UTF_8).startsWith("GET /api/user/123/PWN?tab=info "),
                pLast == null ? "null" : new String(pLast, StandardCharsets.UTF_8).split("\r\n")[0]);
        byte[] pIdx = (byte[]) path.invoke(engine, pathReq.getBytes(StandardCharsets.UTF_8), "PWN", "URL_PATH[2]");
        check("URL_PATH[2] 替换第 3 段（下标从 0 起）",
                pIdx != null && new String(pIdx, StandardCharsets.UTF_8).startsWith("GET /api/user/PWN/profile?"),
                pIdx == null ? "null" : new String(pIdx, StandardCharsets.UTF_8).split("\r\n")[0]);
        byte[] pLow = (byte[]) path.invoke(engine, pathReq.getBytes(StandardCharsets.UTF_8), "PWN", "url_path[0]");
        check("小写 url_path[0] 同样识别",
                pLow != null && new String(pLow, StandardCharsets.UTF_8).startsWith("GET /PWN/user/123/profile?"),
                pLow == null ? "null" : "未替换");
        check("越界的 URL_PATH[9] → null（不猜、不改别的段）",
                path.invoke(engine, pathReq.getBytes(StandardCharsets.UTF_8), "PWN", "URL_PATH[9]") == null, "被注入了");
        check("写法残缺的 URL_PATH[x] → null",
                path.invoke(engine, pathReq.getBytes(StandardCharsets.UTF_8), "PWN", "URL_PATH[x]") == null, "被注入了");
        byte[] pTrav = (byte[]) path.invoke(engine, pathReq.getBytes(StandardCharsets.UTF_8), "../../etc/passwd", "URL_PATH[2]");
        check("路径穿越载荷里的 / 与 . 原样保留",
                pTrav != null && new String(pTrav, StandardCharsets.UTF_8).startsWith("GET /api/user/../../etc/passwd/profile?"),
                pTrav == null ? "null" : new String(pTrav, StandardCharsets.UTF_8).split("\r\n")[0]);
        // URL_PATH 是**唯一**不再经其它净化的注入路径（请求头剔 CR/LF、cookie 值剔 CR/LF、
        // 参数值由 needsUrlEncoding 编掉控制字符）。载荷里一个真换行就能把请求行劈开，
        // 后面的内容直接变成伪造的请求头 —— 就地百分号编码。
        byte[] pCrlf = (byte[]) path.invoke(engine, pathReq.getBytes(StandardCharsets.UTF_8),
                "x\r\nX-Injected: 1", "URL_PATH[2]");
        String pCrlfStr = pCrlf == null ? "" : new String(pCrlf, StandardCharsets.UTF_8);
        check("路径段里的 CR/LF 编码成 %0D%0A（否则会伪造出请求头）",
                pCrlf != null && pCrlfStr.startsWith("GET /api/user/x%0D%0AX-Injected:%201/profile?")
                        && pCrlfStr.split("\r\n", -1).length == 4,
                pCrlf == null ? "null" : pCrlfStr.split("\r\n")[0]);
        byte[] pTab = (byte[]) path.invoke(engine, pathReq.getBytes(StandardCharsets.UTF_8), "a\tb", "URL_PATH[2]");
        check("其它控制字符（TAB）同样被编码",
                pTab != null && new String(pTab, StandardCharsets.UTF_8).contains("/a%09b/"),
                pTab == null ? "null" : new String(pTab, StandardCharsets.UTF_8).split("\r\n")[0]);
        byte[] pSpace = (byte[]) path.invoke(engine, pathReq.getBytes(StandardCharsets.UTF_8), "1' OR '1'='1", "URL_PATH[2]");
        check("路径段载荷里的空格编码成 %20（否则请求行会被截断）",
                pSpace != null && new String(pSpace, StandardCharsets.UTF_8).contains("/1'%20OR%20'1'='1/"),
                pSpace == null ? "null" : new String(pSpace, StandardCharsets.UTF_8).split("\r\n")[0]);
        byte[] pQ = (byte[]) path.invoke(engine, pathReq.getBytes(StandardCharsets.UTF_8), "a?b", "URL_PATH[2]");
        check("路径段载荷里的 ? 编码成 %3F（否则会伪造出查询串）",
                pQ != null && new String(pQ, StandardCharsets.UTF_8).contains("/a%3Fb/"),
                pQ == null ? "null" : new String(pQ, StandardCharsets.UTF_8).split("\r\n")[0]);

        System.out.println("\n=== 参数值里的结构字符编码 ===");
        Method enc = AIEngine.class.getDeclaredMethod("encodeParamValue", String.class);
        enc.setAccessible(true);
        String encOut = (String) enc.invoke(null, "x&ls&");
        check("& 编码成 %26（命令注入的 &ls& 不会再被拆成新参数）", "x%26ls%26".equals(encOut), encOut);
        String encOut2 = (String) enc.invoke(null, "a#b+c");
        check("# → %23、+ → %2B（+ 否则会被表单规则解成空格）", "a%23b%2Bc".equals(encOut2), encOut2);
        String encKeep = (String) enc.invoke(null, "%27 OR %271%27=%271");
        check("已有的合法转义与 = 保持原样（否则 %27 会被二次编码成无意义字面量）",
                "%27 OR %271%27=%271".equals(encKeep), encKeep);
        // 裸 %（不是合法转义）必须编成 %25：服务端把它当转义起点，非法时整个参数作废
        // （实测 Tomcat：name=%%7B100*100%7D → 参数值解成空；%25%7B100*100%7D → 正确得到 %{100*100}）
        String encOgnl = (String) enc.invoke(null, "%{100*100}");
        check("OGNL 的 %{...} 里那个裸 % 被编成 %25（否则服务端丢参数，Struts2 载荷全废）",
                "%25%7B100*100%7D".equals(encOgnl), encOgnl);
        String encLike = (String) enc.invoke(null, "1' AND name LIKE '%a%'-- -");
        check("SQL LIKE 里的裸 % 同样被编、引号原样",
                encLike.equals("1' AND name LIKE '%25a%25'-- -"), encLike);
        String encDouble = (String) enc.invoke(null, "a%%7Bb");
        check("裸 % 与合法转义混排：只编裸的那个（a%%7Bb → a%25%7Bb）",
                "a%25%7Bb".equals(encDouble), encDouble);
        String encHex = (String) enc.invoke(null, "%00%2e%252F");
        check("连续合法转义一个都不动（%00 %2e %252F 全部原样）",
                "%00%2e%252F".equals(encHex), encHex);
        // Tomcat 这类容器对请求行里的 " { } [ ] < > \ ^ ` | 直接 400：
        // GET 查询参数里的 JSON 载荷（Fastjson 的 {"@type":…}、数组形态）不编码根本到不了应用
        String encJson = (String) enc.invoke(null, "{\"@type\":\"java.net.Inet4Address\",\"val\":\"oob.invalid\"}");
        check("JSON 载荷里的 { } \" 被编码（Tomcat 否则直接 400，GET 里的 Fastjson 打不进去）",
                encJson.startsWith("%7B%22@type%22") && encJson.endsWith("%7D")
                        && encJson.indexOf('{') < 0 && encJson.indexOf('"') < 0, encJson);
        String encArr = (String) enc.invoke(null, "[{\"a\":1}]");
        check("数组形态的 [ ] 同样被编码", "%5B%7B%22a%22:1%7D%5D".equals(encArr), encArr);
        String encTag = (String) enc.invoke(null, "<img src=x onerror=alert(1)>");
        check("尖括号被编码、其余合法字符保持原样（空格留给调用方转 +）",
                encTag.indexOf('<') < 0 && encTag.indexOf('>') < 0
                        && encTag.contains("%3C") && encTag.contains("%3E") && encTag.contains(" src=x "), encTag);
        String encCn = (String) enc.invoke(null, "中文");
        check("非 ASCII 按 UTF-8 逐字节编码", "%E4%B8%AD%E6%96%87".equals(encCn), encCn);
        String encLegal = (String) enc.invoke(null, "1' OR '1'='1-- -");
        check("合法字符（引号/空格/逗号/冒号/分号/括号）保持原样，只编结构字符",
                encLegal.equals("1' OR '1'='1-- -"), encLegal);

        // 端到端：截获 sendTestRequest 真正发出去的请求字节
        System.out.println("\n=== 发包前的处理（截获 makeHttpRequest 的实参）===");
        AIEngine capEngine = captureEngine();
        sendWith(capEngine, "GET /a?cmd=1 HTTP/1.1\r\nHost: x\r\n\r\n", "x&ls&", "cmd");
        check("GET 查询参数：载荷里的 & 已编码，请求行只有一个参数",
                captured != null && new String(captured, StandardCharsets.UTF_8).startsWith("GET /a?cmd=x%26ls%26 "),
                captured == null ? "没截到" : new String(captured, StandardCharsets.UTF_8).split("\r\n")[0]);
        sendWith(capEngine, "POST /a HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 5\r\n\r\ncmd=1", "x&ls&", "cmd");
        check("表单 body：载荷里的 & 同样编码",
                captured != null && new String(captured, StandardCharsets.UTF_8).endsWith("cmd=x%26ls%26"),
                captured == null ? "没截到" : new String(captured, StandardCharsets.UTF_8));
        sendWith(capEngine, "POST /a HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 5\r\n\r\ncmd=1", "1' AND 1=1", "cmd");
        check("表单 body：空格也转成 +（与 URL 查询串同一套规则；裸空格严格解析器会拒）",
                captured != null && new String(captured, StandardCharsets.UTF_8).endsWith("cmd=1'+AND+1=1"),
                captured == null ? "没截到" : new String(captured, StandardCharsets.UTF_8));
        sendWith(capEngine, "GET /api/user/123 HTTP/1.1\r\nHost: x\r\n\r\n", "1' OR '1'='1", "URL_PATH");
        check("URL 路径段：空格编码成 %20 且不走 & 编码",
                captured != null && new String(captured, StandardCharsets.UTF_8).startsWith("GET /api/user/1'%20OR%20'1'='1 "),
                captured == null ? "没截到" : new String(captured, StandardCharsets.UTF_8).split("\r\n")[0]);
        sendWith(capEngine, "GET /a?q=1 HTTP/1.1\r\nHost: x\r\n\r\n", "1' UNION SELECT NULL-- -", "q");
        check("查询参数：空格仍按原逻辑换成 +（不影响既有手法）",
                captured != null && new String(captured, StandardCharsets.UTF_8).startsWith("GET /a?q=1'+UNION+SELECT+NULL--+- "),
                captured == null ? "没截到" : new String(captured, StandardCharsets.UTF_8).split("\r\n")[0]);
        sendWith(capEngine, "POST /a?q=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n", "a&b c", "q");
        check("POST 的 URL 查询参数同样编码并转空格（以前只处理 GET，这类位置两个都不做）",
                captured != null && new String(captured, StandardCharsets.UTF_8).startsWith("POST /a?q=a%26b+c "),
                captured == null ? "没截到" : new String(captured, StandardCharsets.UTF_8).split("\r\n")[0]);
        // 用户实测场景：Fastjson 靶场的参数在 GET 查询串里，JSON 载荷不编码的话容器直接 400
        sendWith(capEngine, "GET /api?json=1 HTTP/1.1\r\nHost: x\r\n\r\n",
                "{\"@type\":\"java.net.Inet4Address\",\"val\":\"oob.invalid\"}", "json");
        String jsonLine = captured == null ? "没截到" : new String(captured, StandardCharsets.UTF_8).split("\r\n")[0];
        // : 与 , 是 URL 里的合法字符，保持原样（容器不会拒绝，应用解码后 JSON 完全一致）
        check("GET 查询串里的 Fastjson JSON 载荷整条被编码发出（请求行里不再有 { \" }，容器不会 400）",
                captured != null && jsonLine.startsWith("GET /api?json=%7B%22@type%22:%22java.net.Inet4Address%22")
                        && jsonLine.indexOf('{') < 0 && jsonLine.indexOf('"') < 0, jsonLine);

        System.out.println("\n=== cookie 值位置（唯一「住在请求头里却走参数注入」的位置）===");
        sendWith(capEngine, "GET /a HTTP/1.1\r\nHost: x\r\nCookie: SESSION=1\r\n\r\n",
                "1' AND '1'='1", "SESSION");
        String cookieLine = captured == null ? "没截到" : new String(captured, StandardCharsets.UTF_8);
        check("cookie 值里的空格编成 %20（RFC 6265 不允许空格，Tomcat 会把整个 cookie 丢掉 → 载荷等于没发）",
                captured != null && cookieLine.contains("SESSION=1'%20AND%20'1'='1")
                        && !cookieLine.contains("SESSION=1' AND"), cookieLine.split("\r\n").length > 2
                        ? cookieLine.split("\r\n")[2] : cookieLine);
        sendWith(capEngine, "GET /a HTTP/1.1\r\nHost: x\r\nCookie: SESSION=1\r\n\r\n",
                "x\r\nX-Injected: 1", "SESSION");
        // 剔除换行后，剩下的字面量会并进 cookie 值（无害）；判据是「没有多出一条新头行」
        String sent = captured == null ? "" : new String(captured, StandardCharsets.UTF_8);
        boolean injectedHeader = false;
        String[] sentLines = sent.split("\r\n");
        for (int i = 1; i < sentLines.length; i++) {         // 0 是请求行
            if (sentLines[i].toLowerCase().startsWith("x-injected")) injectedHeader = true;
        }
        // split 会丢掉尾部空串：请求行 + Host + Cookie = 3 行（注入成功的话会多出一条）
        check("cookie 值里的 CR/LF 被剔除（否则会伪造出新的请求头）",
                captured != null && !injectedHeader && sentLines.length == 3 && sent.contains("SESSION=xX-Injected:"),
                sent.replace("\r\n", "\\r\\n") + "  头行数=" + sentLines.length);
        sendWith(capEngine, "GET /a HTTP/1.1\r\nHost: x\r\nCookie: SESSION=1\r\n\r\n",
                "AAA+BBB== CCC", "SESSION");
        check("cookie 值里的 + 与 = 保持原样（Shiro 的 base64 就靠它们，编成 %2B 会直接解不开）",
                captured != null && new String(captured, StandardCharsets.UTF_8).contains("AAA+BBB==%20CCC"),
                captured == null ? "没截到" : new String(captured, StandardCharsets.UTF_8));
        // header:Cookie 是「整段替换」，里面的空格是 cookie 之间的分隔符 —— 编了就毁掉 rememberMe
        sendWith(capEngine, "GET /a HTTP/1.1\r\nHost: x\r\nCookie: JSESSIONID=1\r\n\r\n",
                "JSESSIONID=1; rememberMe=AAA+BBB==", "header:Cookie");
        check("header:Cookie 整段替换时空格保持原样（是分隔符，不是值里的空格）",
                captured != null && new String(captured, StandardCharsets.UTF_8)
                        .contains("Cookie: JSESSIONID=1; rememberMe=AAA+BBB=="),
                captured == null ? "没截到" : new String(captured, StandardCharsets.UTF_8));

        System.out.println("\n=== 发出去了但没拿到响应（超时 / Burp 返回 null / 发送异常）===");
        System.out.println("（超时那条要真等满看门狗 10 秒，慢是应该的）");
        checkSentButNoResponse();

        System.out.println("\n========================================");
        System.out.println("通过 " + passed + " 项，失败 " + failures.size() + " 项");
        for (String f : failures) System.out.println("  ❌ " + f);
        System.exit(failures.isEmpty() ? 0 : 1);
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return true;
        }
        return false;
    }
}
