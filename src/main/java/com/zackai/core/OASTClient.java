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
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * 外带（OOB / Out-of-Band）回连检测，后端为 dnslog.org。
 *
 * <p>为什么需要它：命令注入的无回显外带、XXE 的外部 DTD、SSRF 的出网请求这类漏洞，
 * 证据不在目标响应里，只在「目标是否向外发起了请求」这一个事实上。没有回连服务时，
 * 这类载荷发出去也永远无法确认（早期版本的验证提示词里就写着「dnslog.cn 有记录」，
 * 而程序根本没有查询能力）。
 *
 * <p>工作方式：
 * <ol>
 *   <li><b>插件加载时申请一次专属域名</b>（{@link #shared()} + {@link #ensureSession()}），
 *       形如 {@code 7f917734.log.nat.cloudns.ph}，Burp 存活期间所有扫描任务共用它；</li>
 *   <li><b>每个 OOB 请求包带一个随机前缀</b>（{@link #randomLabel()}），实际让目标解析的是
 *       {@code 3f9ac1d2.7f917734.log.nat.cloudns.ph}。标签只负责把回连归属到具体那一次请求，
 *       不承载命令输出 —— 判据是「解析发生了」，所以载荷里不必拼接 whoami/hostname；</li>
 *   <li><b>每条载荷发出后立刻轮询一次</b>（{@link #pollInteractions}），只认带本次随机前缀的记录
 *       （前缀出现在子域的任意一段标签上都算，见 {@link #labelMatches}）：那一条记录就证明这个载荷
 *       确实被执行了。按标签归属而不是按「新增记录」归属，因此 10 个并发任务的回连不会互相串味，
 *       也不需要跨轮询记忆。</li>
 * </ol>
 *
 * <p>协议（见项目根目录 dig.pm域名获取.txt）：
 * <pre>
 *   POST /new_gen            body: domain=&lt;基础域名&gt;
 *        → {"domain":"7f917734.log.nat.cloudns.ph.","key":"7f917734","token":"ytbhsfybulyo"}
 *   POST /&lt;token&gt;           body: domain=&lt;基础域名&gt;
 *        → {"0":{"ip":"219.128.128.102:64037",
 *                "subdomain":"probe.7f917734.log.nat.cloudns.ph.","time":"2026-09-21 16:50:59"}, ...}
 *        无记录时返回 null
 * </pre>
 *
 * <p>三点必须注意：
 * <ol>
 *   <li><b>按 key 过滤是强制的</b>：轮询返回的是整个基础域名下的记录，而这是个公共平台，
 *       不按自己的 key 过滤就会把别人的回连当成自己的发现。</li>
 *   <li><b>一次回连会返回多条记录</b>：每个递归解析器各记一条（实测一次查询 4 条，
 *       仅解析器 IP 不同），所以一次响应内按 subdomain 去重，否则一次回连会被算成多次。</li>
 *   <li><b>一个 Burp 会话只有一个域名</b>：服务端的记录会随时间累积，轮询响应会越来越大
 *       （按标签过滤保证正确性，只是要扫更多记录）。若以后嫌记录太长，可以让域名每隔若干
 *       任务轮换一次 {@link #refreshSession()}。</li>
 * </ol>
 */
public class OASTClient {

    /** 默认服务端与基础域名；会话与轮询都用这两个值 */
    public static final String DEFAULT_SERVER = "https://dnslog.org";
    public static final String DEFAULT_BASE_DOMAIN = "log.nat.cloudns.ph.";

    /** 外带载荷指南里给域名留的占位符（RFC 2606 保留域名，永不解析）；与 AIEngine 指南文本同一个字面量 */
    public static final String PLACEHOLDER = "oob.invalid";

    private static final String NEW_SESSION_PATH = "/new_gen";
    private static final int API_TIMEOUT_SECONDS = 10;
    private static final int MAX_DESCRIPTION_LENGTH = 300;
    /** 连续失败这么多次就丢弃当前会话、下次扫描重新申请（服务端会话可能过期） */
    private static final int REFRESH_AFTER_FAILURES = 3;
    private static final MediaType FORM =
            MediaType.parse("application/x-www-form-urlencoded");

    /** 插件级唯一实例：域名在加载时申请一次，之后所有任务共用 */
    private static volatile OASTClient shared;

    private final String server;
    private final String baseDomain;
    private final OkHttpClient httpClient;
    private final Gson gson = new Gson();

    private volatile Session session;
    private volatile String lastError;
    private volatile int pollFailures;

    public OASTClient(String server, String baseDomain) {
        this.server = (server == null || server.trim().isEmpty()) ? DEFAULT_SERVER : server.trim();
        this.baseDomain = (baseDomain == null || baseDomain.trim().isEmpty())
                ? DEFAULT_BASE_DOMAIN : baseDomain.trim();
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout((long) API_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .writeTimeout((long) API_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .readTimeout((long) API_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .build();
    }

    /**
     * 插件级实例：服务不需要账号。是否**使用**它由配置开关决定（{@code Config.isOobEnabled}）——
     * 调用方（scanRequest / 插件加载 / 配置界面）在关闭时不应该碰它，也就不该去申请域名或发载荷。
     */
    public static OASTClient shared() {
        if (shared == null) {
            synchronized (OASTClient.class) {
                if (shared == null) {
                    shared = new OASTClient(DEFAULT_SERVER, DEFAULT_BASE_DOMAIN);
                }
            }
        }
        return shared;
    }

    /**
     * 一次回连会话：专属域名 + 轮询凭据。
     *
     * <p>不可变，可以安全地跨线程传递 —— 任务池有 10 个线程在跑，会话被换掉（重新申请）时，
     * 已经拿到旧会话的任务照旧用自己的那份，不会突然改到别人的域名上。
     */
    public static final class Session {

        private final String baseDomain;
        private final String key;
        private final String token;

        Session(String baseDomain, String key, String token) {
            this.baseDomain = baseDomain;
            this.key = key;
            this.token = token;
        }

        /** 载荷里用的回连域名，形如 7f917734.log.nat.cloudns.ph（无尾点） */
        public String getDomain() {
            return this.key + "." + stripTrailingDot(this.baseDomain);
        }

        /** 轮询时提交给服务端的基础域名 */
        String getBaseDomain() {
            return this.baseDomain;
        }

        String getToken() {
            return this.token;
        }

        String getKey() {
            return this.key;
        }
    }

    /** 仅供离线验证：直接造一个会话，让解析逻辑的测试不依赖网络 */
    static Session testSession(String key, String token, String baseDomain) {
        return new Session(baseDomain, key, token);
    }

    /**
     * 取当前会话；没有（或已被丢弃）时申请一个。插件加载与每次扫描前都会调用，通常直接命中缓存。
     * 失败返回 null 并把原因记在 {@link #getLastError()}
     */
    public synchronized Session ensureSession() {
        if (this.session == null) {
            this.session = this.acquireSession();
        }
        return this.session;
    }

    /**
     * 强制重新申请一个会话（配置界面的「测试回连」，以及会话疑似失效时的恢复手段）。
     * 申请失败时**保留原会话**：一次超时就丢掉一个还能用的域名，只会让正在跑的任务白跑一轮；
     * 连续失败自然会被 {@link #notePollFailure()} 按阈值丢弃。
     */
    public synchronized Session refreshSession() {
        Session fresh = this.acquireSession();
        if (fresh != null) {
            this.session = fresh;
            this.pollFailures = 0;
        }
        return this.session;
    }

    /** 申请会话；失败返回 null 并设置 lastError */
    private Session acquireSession() {
        String responseBody = this.post(this.server + NEW_SESSION_PATH, "domain=" + this.baseDomain);
        if (responseBody == null) return null;
        JsonObject root;
        try {
            root = this.gson.fromJson(responseBody, JsonObject.class);
        }
        catch (Exception e) {
            this.lastError = Msg.t("oob.notJson");
            return null;
        }
        if (root == null) {
            this.lastError = Msg.t("oob.emptySession");
            return null;
        }
        String key = this.stringField(root, "key");
        String token = this.stringField(root, "token");
        if (key == null || key.isEmpty() || token == null || token.isEmpty()) {
            this.lastError = Msg.t("oob.noKeyToken");
            return null;
        }
        this.lastError = null;
        return new Session(this.baseDomain, key, token);
    }

    public String getLastError() {
        return this.lastError;
    }

    /**
     * 本次请求专用的随机前缀，拼在专属域名最左侧（{@code 3f9ac1d2.7f917734.log.nat.cloudns.ph}）。
     *
     * <p>8 位十六进制 ≈ 43 亿种取值，同一会话内几乎不可能撞车：撞车会让两条载荷共用同一个
     * 子域，后一条的回连被算到前一条头上。
     */
    public static String randomLabel() {
        return String.format("%08x", ThreadLocalRandom.current().nextInt());
    }

    /**
     * 把载荷里的回连域名占位符换成本次回连域名，并把域名最左侧统一成本次请求的随机前缀。
     *
     * <p>为什么不能只靠提示词要求模型替换：
     * <ol>
     *   <li>模型漏改占位符时，载荷解析的是 {@code oob.invalid} —— 永远不会有回连，而验证阶段会把
     *       「无回连记录」当成「目标确实没有外带行为」的有效反向证据，真漏洞就这么被静默漏掉；</li>
     *   <li>模型自己写的标签（照抄示例里的 p1、或重复写成同一个）不是本次请求的随机前缀，
     *       回连记录会因为对不上标签而被丢掉。</li>
     * </ol>
     *
     * <p>前缀只用于区分是哪一次请求触发的回连，不承载数据 —— 模型若仍把 whoami 之类的输出拼在
     * 标签位置，那份输出会被这里覆盖掉，这不影响判定（判定只看解析有没有发生）。
     *
     * @param payload 模型生成的载荷原文
     * @param host    本次会话的回连域名；为空时原样返回
     * @param label   本次请求的随机前缀，见 {@link #randomLabel()}
     */
    public static String applyCallbackHost(String payload, String host, String label) {
        if (payload == null || payload.isEmpty() || host == null || host.isEmpty()) return payload;
        String text = replacePlaceholders(payload, host);
        // 载荷里根本没有本次域名（非外带类载荷）：一个字都不动。
        // 域名按 ASCII 大小写不敏感查找（模型可能写成 7F917734.LOG...），并且**不能**靠
        // 「折叠大小写后的下标」——遇到大小写折叠会变长的字符（İ 等）那个下标就错位了：
        // 以前整体 return 掉，占位符于是永远不被改写；现在统一走 indexOfIgnoreCase。
        if (indexOfIgnoreCase(text, host, 0) < 0) return payload;
        StringBuilder sb = new StringBuilder(text.length() + 16);
        int from = 0;
        int at;
        while ((at = indexOfIgnoreCase(text, host, from)) >= 0) {
            // 域名前若已有「标签.」（模型自带的、或照抄示例的 p1）就把这个标签换掉。
            // 回退不能越过 from：越过之后 sb.append(text, from, labelStart) 的 start 会大于 end，
            // 直接抛 IndexOutOfBoundsException —— 载荷里出现「oob.invalid.oob.invalid」这类
            // 相邻重复域名（域名和占位符挨着写、或两个域名只隔一个点）就会踩到，
            // 异常逃出载荷循环后整个任务以「扫描异常」中止，剩下的载荷全丢。
            int labelStart = at;
            if (at > 0 && text.charAt(at - 1) == '.') {
                labelStart = at - 1;
                while (labelStart > from && isLabelChar(text.charAt(labelStart - 1))) {
                    --labelStart;
                }
                // 点前面没有可替换的标签（或已经退到 from，比如前一个域名就是我们刚补的）：
                // 保留这个分隔点 —— 否则两个相邻域名会被粘成一个（…ph3f9ac1d2…ph）
                if (labelStart == at - 1) {
                    labelStart = at;
                }
            }
            sb.append(text, from, labelStart);
            boolean startsMidWord = labelStart == at && at > 0 && isLabelChar(text.charAt(at - 1))
                    && !afterPercentEscape(text, at);
            if (!startsMidWord) {
                // 前面不是字母数字（URL 的 //、命令的分隔符、引号等）就补一个前缀
                sb.append(label).append('.');
            }
            sb.append(host);
            from = at + host.length();
        }
        sb.append(text, from, text.length());
        return sb.toString();
    }

    /**
     * 占位符的三种写法：原样、点被编码一次、点被编码两次。
     * 只认 {@code oob.invalid} 的话，{@code oob%2Einvalid} 这类载荷既不会被改写、也不会触发轮询 ——
     * 目标解析的是保留域名，回连记录永远不会出现（而且验证阶段还会被告知「这条载荷不依赖外带」）。
     * 双重编码形态同样来自 WAF 绕过指南，一样要认。
     */
    private static final String[] PLACEHOLDER_FORMS = {PLACEHOLDER, "oob%2einvalid", "oob%252einvalid"};

    /** 占位符在载荷里的位置（大小写不敏感，三种写法都认）；找不到返回 -1 */
    private static int indexOfPlaceholder(String payload, int from) {
        int best = -1;
        for (String form : PLACEHOLDER_FORMS) {
            int at = indexOfIgnoreCase(payload, form, from);
            if (at >= 0 && (best < 0 || at < best)) {
                best = at;
            }
        }
        return best;
    }

    /**
     * 大小写不敏感查找。
     * 折叠大小写会改变长度的字符（U+0130 等）存在时改走 regionMatches —— 拿小写副本里的偏移
     * 到原文上切片会错位甚至越界（实测 {@code İoob.invalid} 抛 StringIndexOutOfBoundsException，
     * 然后整个任务以「扫描异常」中止）。
     */
    private static int indexOfIgnoreCase(String text, String needle, int from) {
        String lower = text.toLowerCase(Locale.ROOT);
        if (lower.length() == text.length()) {
            return lower.indexOf(needle, from);
        }
        for (int i = Math.max(0, from); i < text.length(); ++i) {
            if (text.regionMatches(true, i, needle, 0, needle.length())) {
                return i;
            }
        }
        return -1;
    }

    /** at 处命中的是哪个写法（取最长，避免短形态截断长形态） */
    private static String matchingPlaceholder(String text, int at) {
        String best = null;
        for (String form : PLACEHOLDER_FORMS) {
            if (text.regionMatches(true, at, form, 0, form.length())
                    && (best == null || form.length() > best.length())) {
                best = form;
            }
        }
        return best;
    }

    /** 把载荷里的占位符（含编码写法）全部换成本次回连域名 */
    private static String replacePlaceholders(String payload, String host) {
        String text = payload;
        int at;
        while ((at = indexOfPlaceholder(text, 0)) >= 0) {
            String form = matchingPlaceholder(text, at);
            if (form == null) break;      // 理论上不会发生；防死循环
            text = text.substring(0, at) + host + text.substring(at + form.length());
        }
        return text;
    }

    /** 载荷里是否用到了本次会话的回连域名（含占位符）—— 只有这类载荷才需要轮询 */
    public static boolean isOobPayload(String payload, String host) {
        if (payload == null || payload.isEmpty()) return false;
        if (indexOfPlaceholder(payload, 0) >= 0) return true;
        if (host == null || host.isEmpty()) return false;
        // 同样不用「折叠大小写后 contains」：遇到大小写折叠会变长的字符会漏判
        return indexOfIgnoreCase(payload, host, 0) >= 0;
    }

    private static boolean isLabelChar(char c) {
        return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
                || c == '-' || c == '_';
    }

    /**
     * 域名前面是不是「%XX」百分号编码的数据（{@code %2F}、双写的 {@code %252F} 都算）。
     *
     * <p>没有这个判断时，{@code %24%7Bjndi%3Adns%3A%2F%2Foob.invalid...} 这类载荷会因为
     * 「%2F 的 F 是字母数字」被判成词中出现，于是**不补随机前缀** —— 载荷解析的是裸域名，
     * 按前缀过滤的轮询查不到这条回连，而验证阶段会把「无记录」当成有效的反向证据，
     * 于是真漏洞静默漏掉。而这类整体 URL 编码的载荷正是 WAF 绕过指南里明确要求的手法。
     */
    private static boolean afterPercentEscape(String text, int hostStart) {
        int i = hostStart - 1;
        int hexRun = 0;
        while (i >= 0 && isHexDigit(text.charAt(i))) {
            --i;
            ++hexRun;
        }
        // %2F → 域名前是 2 个十六进制字符，再往前是 %（%252F 则是 4 个）
        return i >= 0 && text.charAt(i) == '%' && hexRun > 0 && hexRun % 2 == 0;
    }

    private static boolean isHexDigit(char c) {
        return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F';
    }

    /**
     * 一次轮询的结果：记录 + **本次调用自己的**失败原因（null 表示正常）。
     *
     * <p>失败原因必须随结果一起返回，不能再去读共享的 {@link #getLastError()}：
     * 那是插件级单例上的一个字段，10 个扫描线程 + 每个任务一个外带验证线程都会写它。
     * A 查到记录、还没来得及读 lastError，B 的一次失败就把它设上 —— 于是 A 这次**成功**的
     * 回连记录被判成「通道不可用」直接丢掉；反过来 B 的成功会把 A 的失败洗成「无记录」，
     * 而验证阶段把「无记录」当成目标没有回连的有效反向证据。两个方向都会让外带类漏洞静默漏掉。
     */
    public static final class PollResult {
        public final List<String> records;
        public final String error;
        PollResult(List<String> records, String error) {
            this.records = records;
            this.error = error;
        }
    }

    /**
     * 查询本次请求的回连记录（人类可读描述）：只认最左侧标签等于 {@code label} 的记录。
     *
     * <p>回连服务不可用不该中断扫描：失败返回空列表并记 {@link #getLastError()}；
     * 连续失败到一定次数会丢弃当前会话，下次扫描重新申请。
     * 判定「这次查询到底成功没有」请用 {@link #pollInteractionsWithError}。
     */
    public List<String> pollInteractions(Session session, String label) {
        return this.pollInteractionsWithError(session, label).records;
    }

    /**
     * 轮询一次并把本次调用的失败原因一起返回（扫描流程走 {@link #pollInteractionsWithError(Session, String, int, long)}，
     * 原因只认这一次调用，不受并发任务影响）。
     */
    public PollResult pollInteractionsWithError(Session session, String label) {
        return this.pollOnce(session, label);
    }

    /**
     * 轮询，最多 {@code attempts} 次：只要这一次没查到记录就再查一次（失败也重查）。
     *
     * <p>**扫描路径已不用这个重载**（2026-09-27 定稿：每条外带载荷只查一次，见
     * {@code AIEngine.OOB_POLL_DELAY_SECONDS}），它现在只服务**自检** {@code roundTrip} ——
     * 那里需要多次尝试来区分「服务慢」与「服务不可用」，8 次尝试是有意义的。
     * 也就是说：下面这套语义（补查、失败重查）是**诊断目的**的，不要当成扫描策略读。
     *
     * <p>返回值含义：一次都没成功 → {@code error != null}；只要有一次成功（哪怕查到空）
     * → {@code error == null}，此时「没有记录」才是可信的反向证据。
     */
    public PollResult pollInteractionsWithError(Session session, String label, int attempts, long gapMillis) {
        PollResult result = this.pollOnce(session, label);
        for (int i = 1; i < attempts && result.records.isEmpty(); ++i) {
            if (result.error == null && gapMillis > 0) {
                try {
                    Thread.sleep(gapMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            result = this.pollOnce(session, label);
        }
        return result;
    }

    private PollResult pollOnce(Session session, String label) {
        if (session == null || session.getToken() == null || label == null) {
            this.lastError = Msg.t("oob.noSessionForPoll");
            return new PollResult(Collections.<String>emptyList(), this.lastError);
        }
        String responseBody = this.post(this.server + "/" + session.getToken(),
                "domain=" + session.getBaseDomain());
        if (responseBody == null) {
            this.notePollFailure();
            String error = this.lastError != null ? this.lastError : Msg.t("oob.pollFailedShort");
            return new PollResult(Collections.<String>emptyList(), error);
        }
        this.pollFailures = 0;
        List<String> records = new ArrayList<String>();
        String error = this.parseRecordsInto(responseBody, session, label, records);
        return new PollResult(records, error);
    }

    /** 自检时每秒查一次，最多查这么久（解析传播通常 1~3 秒；扫描里用的是固定 5 秒窗口） */
    private static final int SELF_TEST_POLL_ATTEMPTS = 8;
    private static final long SELF_TEST_POLL_INTERVAL_MILLIS = 1000L;
    /** 第几次轮询还没记录就补一次 HTTP 触发（约 3 秒后） */
    private static final int SELF_TEST_HTTP_TRIGGER_AFTER = 3;
    private static final int SELF_TEST_HTTP_TIMEOUT_MILLIS = 3000;

    /**
     * 真实回环自检：申请专属域名 → 让**本机**解析一次 {@code <随机前缀>.<专属域名>} → 按前缀把解析记录查回来。
     *
     * <p>这是「回连功能到底能不能用」的判据：只申请到域名说明不了什么（域名可能已过期、
     * 服务可能查不到记录），只有「自己解析一次、再把它查回来」才把整条链路走通。
     * 插件加载时与配置界面的「测试回连」按钮都调用这个方法。
     *
     * <p>第一次没查到记录时会换一个新域名再试一次，把两种失败分开报：
     * 会话/域名过期（换域名就能好）与服务本身不可用（换域名也没用）。
     *
     * <p>**注意**：本方法会发起真实的 DNS 解析（本机 → 递归解析器 → 回连服务的权威 DNS），
     * 属于「让流量出去」的动作；关闭外带回连时调用方不应调用它。
     */
    public SelfTestResult selfTest() {
        Session session = this.ensureSession();
        if (session == null) {
            return SelfTestResult.failure(Msg.t("oob.noDomain", this.lastError == null ? Msg.t("oob.unknownReason") : this.lastError));
        }
        SelfTestResult first = this.roundTrip(session);
        if (first.ok) return first;
        Session fresh = this.refreshSession();
        if (fresh == null || fresh == session) {
            return first;      // 连新域名都申请不到，第一次的失败原因就是最终原因
        }
        SelfTestResult second = this.roundTrip(fresh);
        return second.ok
                ? second.withNote(Msg.t("oob.noteFreshDomain", session.getDomain()))
                : second;
    }

    /** 一次完整回环：触发解析 → 按前缀轮询等待记录；DNS 没生效时补一次 HTTP 触发 */
    private SelfTestResult roundTrip(Session session) {
        String label = randomLabel();
        String target = label + "." + session.getDomain();
        String resolvedIp = resolveOnce(target);
        boolean httpTriggered = false;
        for (int attempt = 0; attempt < SELF_TEST_POLL_ATTEMPTS; attempt++) {
            PollResult poll;
            try {
                poll = this.pollInteractionsWithError(session, label);
            }
            catch (Exception e) {
                // 同 post()：带上 message，否则「测试回连」失败时也只剩一个类名
                String detail = e.getClass().getSimpleName();
                if (e.getMessage() != null && !e.getMessage().trim().isEmpty()) {
                    detail = detail + "：" + e.getMessage().trim();
                }
                return SelfTestResult.failure(Msg.t("oob.pollException", detail));
            }
            if (poll.error != null) {
                return SelfTestResult.failure(Msg.t("oob.pollFailed", poll.error));
            }
            if (!poll.records.isEmpty()) {
                // 消息本身不写「成功」：调用方已经用「回连自检通过：」框住了它，
                // 再叠一层就成了「回连自检通过：成功：…」（用户反馈的重复感）
                return SelfTestResult.success(Msg.t("oob.roundTripOk", target, poll.records.size(), session.getDomain()), poll.records);
            }
            // DNS 查询没到权威服务器时（代理/VPN 的 fake-IP、内网 DNS 拦截都会这样）再来一发 HTTP：
            // 真正的连接尝试会逼着链路去解析这个名字，同样能在回连服务上留下记录
            if (attempt == SELF_TEST_HTTP_TRIGGER_AFTER && !httpTriggered) {
                httpTriggered = true;
                httpTrigger(target);
            }
            try {
                Thread.sleep(SELF_TEST_POLL_INTERVAL_MILLIS);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return SelfTestResult.failure(Msg.t("oob.waitInterrupted"));
            }
        }
        StringBuilder sb = new StringBuilder(Msg.t("oob.diagPrefix", target, resolvedIp == null ? Msg.t("oob.none") : resolvedIp));
        if (httpTriggered) {
            sb.append(Msg.t("oob.diagHttpTriggered"));
        }
        sb.append(Msg.t("oob.diagNoRecord", SELF_TEST_POLL_ATTEMPTS));
        if (looksIntercepted(resolvedIp)) {
            sb.append(Msg.t("oob.diagIntercepted", resolvedIp));
        } else {
            sb.append(Msg.t("oob.diagHint"));
        }
        return SelfTestResult.failure(sb.toString());
    }

    /** 触发一次真实解析，返回解析到的地址（失败返回 null —— 解析不出来是正常的，我们要的是「查询发出去了」） */
    private static String resolveOnce(String host) {
        try {
            return InetAddress.getByName(host).getHostAddress();
        }
        catch (Exception e) {
            return null;
        }
    }

    /**
     * 这个解析结果像不像「DNS 被代理/VPN 接管」：假 IP 段（198.18.0.0/15 是 Clash/Surge 的 fake-ip）、
     * 回环与内网段（说明查询被本地应答，没有走到权威 DNS）。
     */
    static boolean looksIntercepted(String ip) {
        if (ip == null) return false;
        return ip.startsWith("198.18.") || ip.startsWith("198.19.")
                || ip.startsWith("127.") || ip.startsWith("10.")
                || ip.startsWith("192.168.") || ip.startsWith("169.254.")
                || ip.startsWith("0.");
    }

    /** 用一次 HTTP 连接尝试逼链路解析该域名（3 秒超时；有没有响应都无所谓） */
    private static void httpTrigger(String host) {
        java.net.HttpURLConnection connection = null;
        try {
            connection = (java.net.HttpURLConnection) new java.net.URL("http://" + host + "/").openConnection();
            connection.setConnectTimeout(SELF_TEST_HTTP_TIMEOUT_MILLIS);
            connection.setReadTimeout(SELF_TEST_HTTP_TIMEOUT_MILLIS);
            connection.setRequestMethod("GET");
            connection.getResponseCode();
        }
        catch (Exception ignored) {
            // 连不上、解析不了都属正常：这一步的作用只是「让链路去解析这个名字」
        }
        finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /** 回连自检结果：成功与否 + 一句人话说明（含域名与前缀）+ 查到的记录 */
    public static final class SelfTestResult {
        public final boolean ok;
        public final String message;
        public final List<String> records;

        private SelfTestResult(boolean ok, String message, List<String> records) {
            this.ok = ok;
            this.message = message;
            this.records = records == null ? Collections.<String>emptyList() : records;
        }

        static SelfTestResult success(String message, List<String> records) {
            return new SelfTestResult(true, message, records);
        }

        static SelfTestResult failure(String message) {
            return new SelfTestResult(false, message, null);
        }

        private SelfTestResult withNote(String note) {
            return new SelfTestResult(true, this.message + note, this.records);
        }
    }

    /**
     * 解析一次轮询响应，返回其中属于本次会话、且最左侧标签等于 {@code label} 的记录描述。
     *
     * <p>包内可见是为了能离线验证：喂固定 JSON 即可，不必真的连回连服务。
     * 失败原因同时写 {@link #getLastError()}（日志与旧调用方），但**并发下这个字段不可信** ——
     * 需要判断成败请用 {@link #pollInteractionsWithError}。
     *
     * @param label 本次请求的随机前缀；为 null 时返回空列表（无标签就无法归属，不能把别人的回连算成自己的）
     */
    List<String> parseRecords(String jsonBody, Session session, String label) {
        List<String> fresh = new ArrayList<String>();
        this.parseRecordsInto(jsonBody, session, label, fresh);
        return fresh;
    }

    /**
     * 解析主体，把「本次解析是否失败」直接返回（null = 正常），并写 lastError 供日志使用。
     * 拆出返回值是为了让调用方拿到**自己这次**的诊断，而不是共享字段上别人的。
     */
    private String parseRecordsInto(String jsonBody, Session session, String label, List<String> fresh) {
        if (jsonBody == null || session == null || label == null) {
            return null;
        }
        String trimmed = jsonBody.trim();
        // 没有记录时服务端返回字面量 null
        if (trimmed.isEmpty() || "null".equals(trimmed)) {
            this.lastError = null;
            return null;
        }
        JsonObject root;
        try {
            JsonElement parsed = this.gson.fromJson(trimmed, JsonElement.class);
            if (parsed == null || parsed.isJsonNull()) {
                this.lastError = null;
                return null;
            }
            if (!parsed.isJsonObject()) {
                this.lastError = Msg.t("oob.badRecordShape");
                return this.lastError;
            }
            root = parsed.getAsJsonObject();
        }
        catch (Exception e) {
            this.lastError = Msg.t("oob.notJson");
            return this.lastError;
        }
        this.lastError = null;
        // 同一次回连会被多个递归解析器各记一条（仅解析器 IP 不同），本次响应内按子域去重
        Set<String> seenHere = new HashSet<String>();
        for (String entryKey : root.keySet()) {
            JsonElement elem = root.get(entryKey);
            if (elem == null || !elem.isJsonObject()) continue;
            JsonObject record = elem.getAsJsonObject();
            String subdomain = this.stringField(record, "subdomain");
            if (subdomain == null || subdomain.isEmpty()) continue;
            // 公共平台上会有别人的记录，只认自己 key 名下的：
            // <key>.<基础域名> 或 <前缀>.<key>.<基础域名>（后者是正常形态，前缀由 applyCallbackHost 补上）
            // 大小写不敏感：DNS 不区分大小写，解析器可能把子域整个记成大写（下面那次 label 比较
            // 早就容忍了大小写，但若这一行按大小写敏感先把它挡掉，那份容忍就是死代码）
            String host = session.getDomain();
            String normalized = stripTrailingDot(subdomain);
            if (!normalized.equalsIgnoreCase(host) && !endsWithIgnoreCase(normalized, "." + host)) continue;
            // 归属只能靠本次请求的随机前缀：别的前缀（别的载荷、别的并发任务）的记录一律不算本次的
            if (!labelMatches(normalized, label)) continue;
            if (!seenHere.add(normalized)) continue;
            fresh.add(this.describe(record, subdomain, label));
        }
        return null;
    }

    /** 后缀比较，忽略大小写（DNS 记录可能整段被记成大写） */
    private static boolean endsWithIgnoreCase(String text, String suffix) {
        if (text.length() < suffix.length()) return false;
        return text.regionMatches(true, text.length() - suffix.length(), suffix, 0, suffix.length());
    }

    /**
     * 这条记录能不能归属到本次请求：**本次随机前缀出现在子域的任意一段标签上**（两段以上的形态也认）。
     *
     * <p>前缀是每次请求新生成的 8 位随机十六进制，只有我们和那一条载荷知道 —— 所以「出现在哪一段」
     * 与归属无关，而「有没有出现」才是判据。放开到任意位置**不会**削弱归属：公共平台上别人的记录
     * 不可能带上它；裸 {@code <key>.<基础域名>}（完全没有前缀）照样被拒，那种记录无法归属到某一次请求。
     *
     * <p>为什么不认死「最左标签」（2026-09-24 改）：回连名不一定以我们的前缀开头。三种实测得到的形态
     * 都会把别的东西排在前面 ——
     * <ul>
     *   <li>带路径的 JNDI lookup（{@code ${jndi:dns://<前缀>.<key>.<基础域>/x}}，指南里的例子就长这样），
     *       记录可能是 {@code x.<前缀>.<key>.<基础域>}；</li>
     *   <li>{@link #applyCallbackHost} 在「域名紧跟标识符字符」时**故意不插前缀**（免得把载荷改坏），
     *       于是最左标签成了 {@code x_7f917734} 这种「载荷自带的前缀 + 本次前缀」；</li>
     *   <li>应用自己给记日志的值加前缀。</li>
     * </ul>
     * 只认最左侧的话，一次**真的发生了**的回连会被自己的过滤器丢掉，判成「无记录 = 目标没有外带
     * 行为」—— 文件上传那次教训一样：静默漏报是这类检测最怕的错。
     */
    private static boolean labelMatches(String subdomain, String label) {
        if (label == null || label.isEmpty()) return false;
        for (String part : stripTrailingDot(subdomain).split("\\.")) {
            if (part.equalsIgnoreCase(label)) return true;
            // 「载荷自带的前缀 + 本次前缀」形态（见方法上的说明）
            if (part.length() > label.length()) {
                int at = part.length() - label.length();
                if (part.regionMatches(true, at, label, 0, label.length()) && isLabelChar(part.charAt(at - 1))) {
                    return true;
                }
            }
        }
        return false;
    }

    /** 连续失败若干次后丢弃会话，让下一次扫描重新申请（服务端会话可能已失效） */
    private void notePollFailure() {
        if (++this.pollFailures < REFRESH_AFTER_FAILURES) return;
        this.pollFailures = 0;
        synchronized (this) {
            this.session = null;
        }
        this.lastError = (this.lastError == null ? Msg.t("oob.pollFailedShort") : this.lastError)
                + Msg.t("oob.sessionDropped", REFRESH_AFTER_FAILURES);
    }

    private String describe(JsonObject record, String subdomain, String label) {
        // 前缀写**本次请求自己的那个**（不是子域最左侧那一段）：记录可能是 x.<前缀>.<key>.<基础域>，
        // 而最左侧那一段是 JNDI 路径/载荷自带的前缀，照抄上去会让用户以为是自己的前缀写错了。
        // 目标只要解析了这个域名就说明载荷被执行了，前缀本身不是命令输出。
        // 「无前缀的裸域名」这条分支去掉了：那种记录无法归属到某一次请求，已在过滤处挡掉
        // （所有任务共用一个 key，认下来会把别人的回连算成自己的）。
        StringBuilder sb = new StringBuilder(Msg.t("oob.recordPrefix", label));
        sb.append(Msg.t("oob.recordDomain", subdomain));
        String ip = this.stringField(record, "ip");
        if (ip != null && !ip.isEmpty()) {
            sb.append(Msg.t("oob.recordResolver", ip));
        }
        String time = this.stringField(record, "time");
        if (time != null && !time.isEmpty()) {
            sb.append(Msg.t("oob.recordTime", time));
        }
        String text = sb.toString();
        if (text.length() > MAX_DESCRIPTION_LENGTH) {
            text = text.substring(0, MAX_DESCRIPTION_LENGTH) + Msg.t("oob.truncated");
        }
        return text;
    }

    private String stringField(JsonObject obj, String field) {
        if (obj == null || !obj.has(field) || obj.get(field).isJsonNull()) return null;
        try {
            return obj.get(field).getAsString();
        }
        catch (Exception e) {
            return null;
        }
    }

    private static String stripTrailingDot(String domain) {
        if (domain != null && domain.endsWith(".")) {
            return domain.substring(0, domain.length() - 1);
        }
        return domain;
    }

    /** 发一次 POST 表单；成功返回响应体，失败返回 null 并记录原因 */
    private String post(String url, String formBody) {
        Response response = null;
        try {
            Request request = new Request.Builder()
                    .url(url)
                    .post(RequestBody.create(formBody, FORM))
                    .build();
            response = this.httpClient.newCall(request).execute();
            if (response.body() == null) {
                this.lastError = Msg.t("oob.emptyResponse");
                return null;
            }
            if (!response.isSuccessful()) {
                this.lastError = Msg.t("oob.httpStatus", response.code());
                return null;
            }
            return response.body().string();
        }
        catch (Exception e) {
            // **必须带上 message**：OkHttp 的 SocketTimeoutException 里，"connect timed out" 与
            // "Read timed out" 指向两个完全不同的方向（连不上 / 在走代理，vs 连上了但服务端不吐数据），
            // 只记类名的话日志里就是一句干巴巴的「SocketTimeoutException」，排查只能靠猜
            //（2026-09-27 实测踩到：三次超时，无法判断是哪一侧）
            String detail = e.getClass().getSimpleName();
            if (e.getMessage() != null && !e.getMessage().trim().isEmpty()) {
                detail = detail + "：" + e.getMessage().trim();
            }
            this.lastError = Msg.t("oob.requestFailed", detail);
            return null;
        }
        finally {
            if (response != null) {
                response.close();
            }
        }
    }
}
