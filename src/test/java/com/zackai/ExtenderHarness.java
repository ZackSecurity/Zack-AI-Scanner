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
package com.zackai;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IMessageEditor;
import burp.IHttpService;
import burp.IInterceptedProxyMessage;
import burp.IParameter;
import burp.IProxyListener;
import burp.IRequestInfo;
import burp.ITab;
import com.zackai.core.AIEngine;
import com.zackai.core.ConfigManager;
import com.zackai.ui.LogPanel;
import com.zackai.core.OASTClient;
import com.zackai.core.ProxyScanFilter;
import com.zackai.core.ProxyScanHistory;
import com.zackai.i18n.Msg;
import com.zackai.model.ScanTask;

import java.awt.Component;
import java.awt.Container;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

/**
 * 扩展在 Burp 里的「挂载面」离线自检 —— 用桩 callbacks 走一遍真实加载路径。
 *
 * <p>为什么需要：另外三个 harness 测的都是扫描逻辑，而「扩展能不能被 Burp 加载、右键菜单长什么样」
 * 这条路径没有自动化检查，偏偏它的失败方式是**静默**的 —— 初始化里抛一个异常，
 * Burp 只会在 Extender 面板里显示一段错误、套件标签不出现，而扫描、报告都还没机会跑到。
 * 这里把两件事钉住：真实的 {@code registerExtenderCallbacks} 能跑完并注册标签/菜单/卸载监听；
 * 右键菜单在 4 个请求类上下文里的 11 个类型项与 {@link ScanTask.ScanMode} 的 displayName 完全一致
 * （菜单文字是三处手写枚举之一，加/删类型时最容易漏）。
 *
 * <p>不联网：回连会话用 {@link OASTClient#testSession} 预置成假会话，初始化线程里的
 * {@code ensureSession()} 直接命中缓存。也不碰真实配置：调用方用 {@code -Duser.home=} 指向临时目录即可。
 *
 * <p>给一个参数（打包好的 jar 路径）时，额外做打包自检：包内每个 {@code com.zackai} 类都要能加载
 * （缺依赖会在这里暴露），且实现 {@code burp.IBurpExtender} 的类**恰好一个** ——
 * Burp 就是靠扫描这个接口找扩展入口的。
 */
public class ExtenderHarness {

    static int passed = 0;
    static int failed = 0;

    public static void main(String[] args) throws Exception {
        requireTempHome();
        pinChinese();
        String jarPath = args.length > 0 ? args[0] : null;

        System.out.println("--- 配置落盘（临时 home，不碰真实配置）---");
        checkConfigSwitch();

        System.out.println("\n--- AI 服务商预设（地址 / 模型接口 / 与认证代码的耦合）---");
        checkProviderPresets();

        System.out.println("\n--- 请求参数名按模型分派（推理模型要 max_completion_tokens 且不收 temperature）---");
        checkAiRequestParams();

        System.out.println("\n--- Proxy 自动扫描的白名单匹配（纯逻辑，无 Burp）---");
        checkProxyWhitelist();

        System.out.println("\n--- Proxy 自动扫描的去重键（纯逻辑，无 Burp）---");
        checkProxyDedupKey();

        System.out.println("\n--- 扩展初始化（桩 callbacks，等价于 Burp 里 Add 扩展）---");
        checkInit();

        System.out.println("\n--- 导出范围判定（勾选多个任务）---");
        checkExportScope();

        System.out.println("\n--- 右键菜单（按 InvocationContext）---");
        checkMenu();

        if (jarPath != null) {
            System.out.println("\n--- 打包自检：" + jarPath + " ---");
            checkJar(new File(jarPath));
        } else {
            System.out.println("\n（未传 jar 路径，跳过打包自检：java -cp ... com.zackai.ExtenderHarness target/Zack-AI-Scanner-v3.0.jar）");
        }

        // **放在最后**：它会真的执行卸载清理，清掉全部绑定器，后面不能再有依赖重译的检查
        System.out.println("\n--- 卸载清理（Msg.shutdown）---");
        checkMsgShutdown();

        System.out.println("\n========================================");
        System.out.println("通过 " + passed + " 项，失败 " + failed + " 项");
        System.exit(failed == 0 ? 0 : 1);
    }

    // ------------------------------------------------------------------ Proxy 自动扫描白名单

    /**
     * 白名单匹配：{@link ProxyScanFilter} 是「自动扫描往谁发包」的唯一闸门，写错了要么漏扫、
     * 要么把不该扫的也扫了，所以每种写法都在这里钉住。
     */
    static void checkProxyWhitelist() {
        check("白名单留空 = 全部 Proxy 目标放行", ProxyScanFilter.isWhitelisted("", "example.com", 80), "被拦了");
        check("白名单为 null 也按「全部」处理", ProxyScanFilter.isWhitelisted(null, "example.com", 80), "被拦了");
        check("域名白名单放行自身", ProxyScanFilter.isWhitelisted("example.com", "example.com", 443), "没放行");
        check("域名白名单放行子域", ProxyScanFilter.isWhitelisted("example.com", "a.b.example.com", 443), "子域被拦");
        check("域名白名单不误伤「后缀相同但不是子域」的域名",
                !ProxyScanFilter.isWhitelisted("example.com", "notexample.com", 443),
                "被误放行 —— 少一个点的边界判断就会把别人家的域扫了");
        check("白名单大小写不敏感", ProxyScanFilter.isWhitelisted("Example.COM", "www.example.com", 80), "");
        check("带端口的白名单匹配 host:port", ProxyScanFilter.isWhitelisted("example.com:8443", "example.com", 8443), "端口对不上");
        check("带端口的白名单不匹配别的端口",
                !ProxyScanFilter.isWhitelisted("example.com:8443", "example.com", 443), "写死了端口还放行");
        check("带端口的白名单不再按子域放行",
                !ProxyScanFilter.isWhitelisted("example.com:8443", "a.example.com", 8443), "写了端口还放子域");
        check("粘贴一整条 URL 也能认",
                ProxyScanFilter.isWhitelisted("https://a.example.com:8443/x?id=1", "a.example.com", 8443), "URL 没被归一化");
        check("*.example.com 写法可用", ProxyScanFilter.isWhitelisted("*.example.com", "x.example.com", 80), "");
        check("FQDN 结尾的点不影响匹配", ProxyScanFilter.isWhitelisted("example.com.", "example.com", 80), "");
        check("单独的 * 视为全部", ProxyScanFilter.isWhitelisted("*", "anything.test", 80), "");
        check("逗号/分号/空格/中文逗号都能当分隔符",
                ProxyScanFilter.isWhitelisted("a.test, b.test；c.test d.test", "c.test", 80), "有分隔符没被切开");
        check("多项里命中最后一项也放行", ProxyScanFilter.isWhitelisted("a.test,b.test,c.test", "c.test", 80),
                "最后一项被漏掉（分割/遍历少了一次）");
        check("一项都不命中就拦掉", !ProxyScanFilter.isWhitelisted("a.test,b.test", "c.test", 80), "被放行");
        check("没有 host 时不放行（宁可不扫）", !ProxyScanFilter.isWhitelisted("example.com", null, 80), "被放行");
        check("日志里的白名单回显做了归一化", "a.test, b.test".equals(ProxyScanFilter.describe(" https://A.test/x , *.b.test. ")),
                String.valueOf(ProxyScanFilter.describe(" https://A.test/x , *.b.test. ")));
    }

    // ------------------------------------------------------------------ Proxy 自动扫描去重

    /**
     * 去重键：**按参数名判重，参数值与请求头都不参与**（2026-09-24 从「请求体哈希」改过来）。
     *
     * <p>改的理由：轮询接口带时间戳/分页/随机 nonce、每次不同的 id，都能让同一个功能点每次访问
     * 变成一条新任务 —— 用户要的是「这个功能点扫过没有」。代价（同一个参数名的不同取值只扫先见到的
     * 那个）是明知的，所以下面既钉住「值不同 = 重复」，也钉住「名字不同 = 新请求」那一半，
     * 免得去重过头变成漏扫。
     */
    static void checkProxyDedupKey() {
        byte[] req = bytes("GET /a?id=1 HTTP/1.1\r\nHost: example.com\r\nCookie: s=1\r\nUser-Agent: A\r\n\r\n");
        byte[] sameButOtherHeaders = bytes("GET /a?id=1 HTTP/1.1\r\nHost: example.com\r\nCookie: s=2\r\n"
                + "User-Agent: B\r\nX-Request-Id: 9f2\r\nReferer: http://example.com/\r\n\r\n");
        List<String> idOnly = Arrays.asList("id");
        check("同一个请求（仅请求头不同）算重复 —— 否则 Cookie 轮换/请求ID一变去重就失效",
                ProxyScanHistory.key("example.com", 80, req, idOnly)
                        .equals(ProxyScanHistory.key("example.com", 80, sameButOtherHeaders, idOnly)),
                "被当成两个不同请求");
        check("同一个请求的键稳定（连算两次一样）",
                ProxyScanHistory.key("example.com", 80, req, idOnly)
                        .equals(ProxyScanHistory.key("example.com", 80, req, idOnly)), "");
        check("参数值不同 = 重复（轮询接口的时间戳/分页/随机 id 不该每次都建任务）",
                ProxyScanHistory.key("example.com", 80, req, idOnly)
                        .equals(ProxyScanHistory.key("example.com", 80,
                                bytes("GET /a?id=99999 HTTP/1.1\r\nHost: example.com\r\n\r\n"), idOnly)),
                "值一变就当成新请求");
        check("参数名不同 = 新请求（同一个路径多了一个参数，是另一个注入面）",
                !ProxyScanHistory.key("example.com", 80, req, idOnly)
                        .equals(ProxyScanHistory.key("example.com", 80,
                                bytes("GET /a?id=1&uid=2 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                                Arrays.asList("id", "uid"))), "");
        check("参数名顺序不同 = 重复（a=1&b=2 与 b=2&a=1 是同一个形态）",
                ProxyScanHistory.key("example.com", 80, bytes("GET /a?b=2&a=1 HTTP/1.1\r\nHost: h\r\n\r\n"),
                                Arrays.asList("b", "a"))
                        .equals(ProxyScanHistory.key("example.com", 80, bytes("GET /a?a=1&b=2 HTTP/1.1\r\nHost: h\r\n\r\n"),
                                Arrays.asList("a", "b"))), "名字顺序把同一个形态拆成了两个");
        check("同名参数出现多次只算一个（id=1&id=2 与 id=1 同键）",
                ProxyScanHistory.key("example.com", 80, bytes("GET /a?id=1&id=2 HTTP/1.1\r\nHost: h\r\n\r\n"), idOnly)
                        .equals(ProxyScanHistory.key("example.com", 80, bytes("GET /a?id=1 HTTP/1.1\r\nHost: h\r\n\r\n"), idOnly)), "");
        check("路径不同 = 不同请求",
                !ProxyScanHistory.key("example.com", 80, req, idOnly)
                        .equals(ProxyScanHistory.key("example.com", 80,
                                bytes("GET /b?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"), idOnly)), "");
        check("方法不同 = 不同请求",
                !ProxyScanHistory.key("example.com", 80, req, idOnly)
                        .equals(ProxyScanHistory.key("example.com", 80,
                                bytes("POST /a?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"), idOnly)), "");
        check("查询串里没有参数时，路径照样只看路径（/a? 与 /a 同键）",
                ProxyScanHistory.key("example.com", 80, bytes("GET /a? HTTP/1.1\r\nHost: h\r\n\r\n"), idOnly)
                        .equals(ProxyScanHistory.key("example.com", 80, bytes("GET /a HTTP/1.1\r\nHost: h\r\n\r\n"), idOnly)), "");
        check("端口/主机不同 = 不同请求",
                !ProxyScanHistory.key("example.com", 80, req, idOnly)
                        .equals(ProxyScanHistory.key("example.com", 8080, req, idOnly)), "");
        // 解析失败（names == null）时退回按请求体哈希判重：宁多扫不漏扫
        check("解析不出参数时退回按请求体判重（同一个请求仍然算重复）",
                ProxyScanHistory.key("h", 80, bytes("POST /a HTTP/1.1\r\nHost: h\r\n\r\nid=1"), null)
                        .equals(ProxyScanHistory.key("h", 80, bytes("POST /a HTTP/1.1\r\nHost: h\r\n\r\nid=1"), null)), "");
        check("解析不出参数时不同请求体算不同请求（退路不能变成漏扫）",
                !ProxyScanHistory.key("h", 80, bytes("POST /a HTTP/1.1\r\nHost: h\r\n\r\nid=1"), null)
                        .equals(ProxyScanHistory.key("h", 80, bytes("POST /a HTTP/1.1\r\nHost: h\r\n\r\nid=2"), null)), "");
        check("退回路径同样认只有 LF 的换行（\\n\\n）",
                !ProxyScanHistory.key("h", 80, bytes("POST /a HTTP/1.1\nHost: h\n\nid=1"), null)
                        .equals(ProxyScanHistory.key("h", 80, bytes("POST /a HTTP/1.1\nHost: h\n\nid=2"), null)), "请求体没被切出来");
        check("没有请求体时不会把请求头算进去",
                ProxyScanHistory.key("h", 80, bytes("GET /a HTTP/1.1\r\nHost: h\r\n\r\n"), idOnly)
                        .equals(ProxyScanHistory.key("h", 80, bytes("GET /a HTTP/1.1\r\nHost: h\r\nX: 1\r\n\r\n"), idOnly)), "");

        check("登记过的请求第二次就报重复", ProxyScanHistory.firstTime("k1") && !ProxyScanHistory.firstTime("k1"), "");
        check("没登记过的请求报第一次", ProxyScanHistory.firstTime("k2"), "");
        ProxyScanHistory.clear();
        check("clear() 之后重新算第一次（重新勾选自动扫描就是走这条路）",
                ProxyScanHistory.firstTime("k1") && ProxyScanHistory.size() == 1, "size=" + ProxyScanHistory.size());
        ProxyScanHistory.clear();
        for (int i = 0; i < ProxyScanHistory.MAX_KEYS + 100; i++) {
            ProxyScanHistory.firstTime("k" + i);
        }
        check("去重记录有上限（浏览器挂一天不能变成内存泄漏）",
                ProxyScanHistory.size() == ProxyScanHistory.MAX_KEYS, "size=" + ProxyScanHistory.size());
        ProxyScanHistory.clear();
    }

    static byte[] bytes(String s) {
        return s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------ 初始化

    static void checkInit() throws Exception {
        List<String> output = Collections.synchronizedList(new ArrayList<String>());
        List<String> errors = Collections.synchronizedList(new ArrayList<String>());
        boolean[] suiteTab = {false};
        Object[] suiteTabComponent = {null};
        Object[] proxyListener = {null};
        boolean[] menuFactory = {false};
        boolean[] stateListener = {false};
        String[] extensionName = {null};

        disableOob();
        IBurpExtenderCallbacks callbacks = stubCallbacks(output, errors, suiteTab, suiteTabComponent,
                menuFactory, stateListener, extensionName, proxyListener);
        IBurpExtender extender = (IBurpExtender) Class.forName("com.zackai.AISentryExtender")
                .getDeclaredConstructor().newInstance();
        extender.registerExtenderCallbacks(callbacks);
        Thread.sleep(1200);                       // 界面是在 invokeLater 里搭的
        SwingUtilities.invokeAndWait(() -> { });   // 等它跑完
        check("关掉外带时挂载不做任何回连动作（只写一行「已关闭」，不申请域名、不解析、不轮询）",
                output.stream().anyMatch(s -> s != null && s.contains("已关闭")),
                String.valueOf(output));

        check("扩展名就是「Zack-AI-Scanner」（Burp 拿它给右键菜单分组，带版本号菜单里就会显示 v3.0）",
                "Zack-AI-Scanner".equals(extensionName[0]), String.valueOf(extensionName[0]));
        check("套件标签已注册（失败时 Burp 里就是「没有 AI智能扫描 标签」）", suiteTab[0], "未注册");
        check("右键菜单工厂已注册", menuFactory[0], "未注册");
        check("卸载监听已注册（否则反复加载会攒下线程池与旧类加载器）", stateListener[0], "未注册");
        check("初始化过程没有向 Burp 报错（printError 为空）", errors.isEmpty(), String.valueOf(errors));
        check("加载横幅里有版本号",
                output.stream().anyMatch(s -> s != null && s.contains("Zack-AI-Scanner v3.0 已加载")),
                String.valueOf(output));

        // 配置从模态对话框搬成了套件标签里的一个页面：位置错了（或压根没加）就等于没搬。
        // 这条同时确认那条路径**能构造出来** —— 面板构造里抛异常时套件标签会整个不出现。
        Component suiteUi = suiteTabComponent[0] == null ? null : ((ITab) suiteTabComponent[0]).getUiComponent();
        JTabbedPane tabs = findTabbedPane(suiteUi);
        check("套件标签里能找标签页容器", tabs != null, "没有 JTabbedPane");
        Component configUi = null;
        if (tabs != null) {
            int logIndex = tabs.indexOfTab("日志统计");
            int configIndex = tabs.indexOfTab("配置");
            check("「配置」页面紧挨在「日志统计」右边", logIndex >= 0 && configIndex == logIndex + 1,
                    "日志统计=" + logIndex + " 配置=" + configIndex + " 全部=" + tabTitles(tabs));
            configUi = configIndex >= 0 ? tabs.getComponentAt(configIndex) : null;
            check("「配置」页面内容非空（构造成功且挂了控件）",
                    configUi instanceof Container && ((Container) configUi).getComponentCount() > 0,
                    String.valueOf(configUi));
            checkTopBarOobLabel(suiteUi, configUi);
        }
        checkAutoScanUi(configUi);
        check("Proxy 监听已注册（没注册的话「Proxy 流量自动扫描」勾了也不会有反应）",
                proxyListener[0] != null, "未注册");
        if (proxyListener[0] != null && suiteTabComponent[0] != null) {
            checkProxyAutoScanListener((IProxyListener) proxyListener[0],
                    (com.zackai.ui.MainPanel) suiteTabComponent[0], errors);
        }
        if (suiteTabComponent[0] != null) {
            checkTaskTableMultiSelect(suiteUi, (com.zackai.ui.MainPanel) suiteTabComponent[0]);
            checkTaskQueueDisplay(suiteUi, (com.zackai.ui.MainPanel) suiteTabComponent[0]);
            checkManualScanNotDeduped((com.zackai.ui.MainPanel) suiteTabComponent[0]);
            checkProbeListMarksNoResponse(suiteUi);
        }
        checkConfigPageControls(configUi);
        checkSavePersistsEverything(configUi);
        checkConfigStatusRefresh(suiteUi);
        checkLanguageUi(suiteUi, tabs);
        checkEnglishSweep(suiteUi);
    }

    /**
     * 切到英文后，套件界面里**不该再有任何中文控件文案**。
     *
     * <p>这条抓的是 {@code Msg.missingKeys()} 抓不到的那类错：**加了控件却忘了注册绑定器**。
     * key 从没被查过，自然不会记进未命中集合，而界面就一直停在中文 —— 靠人肉逐个文件扫
     * 是能覆盖，但下次加控件就又漏了。
     *
     * <p>覆盖范围：JLabel / AbstractButton 的文字、TitledBorder 标题、标签页标题、JTable 列头、
     * 以及 JComponent 的 tooltip。**不覆盖**：JTextComponent（日志面板、白名单框、API Key 框里
     * 装的是内容不是文案）、JComboBox 的项（服务商名与「自定义」是数据，本来就该是中文）、
     * 以及弹窗（不在组件树里）。
     */
    static void checkEnglishSweep(Component suiteUi) throws Exception {
        Msg.setLang("en");
        SwingUtilities.invokeAndWait(() -> { });
        List<String> leftovers = new ArrayList<>();
        collectCjkChrome(suiteUi, leftovers);
        check("切英文后界面控件里没有残留中文（漏注册绑定器的会在这里现形）",
                leftovers.isEmpty(), String.valueOf(leftovers));
        Msg.setLang("zh");
        SwingUtilities.invokeAndWait(() -> { });
        JTabbedPane pane = findTabbedPane(suiteUi);
        check("扫描后切回中文仍然正常（不能只单向生效）",
                pane != null && pane.indexOfTab("日志统计") >= 0,
                pane == null ? "没有 JTabbedPane" : tabTitles(pane));
    }

    /** 递归收集控件上的中文文案（范围见 checkEnglishSweep 的注释） */
    static void collectCjkChrome(Component c, List<String> out) {
        if (c == null) {
            return;
        }
        if (c instanceof javax.swing.text.JTextComponent) {
            return;
        }
        String text = null;
        if (c instanceof JLabel) {
            text = ((JLabel) c).getText();
        } else if (c instanceof javax.swing.AbstractButton) {
            text = ((javax.swing.AbstractButton) c).getText();
        }
        // 语言切换按钮自己那两个字是「切过去会变成什么语言」：英文模式下显示「中文」是**正确**的，
        // 不能当成漏翻。这是唯一豁免项 —— 多了就说明白名单在掩盖问题。
        if (text != null && containsCjk(text) && !"中文".equals(text) && !"EN".equals(text)) {
            out.add(text);
        }
        if (c instanceof javax.swing.JComponent) {
            javax.swing.border.Border b = ((javax.swing.JComponent) c).getBorder();
            if (b instanceof javax.swing.border.TitledBorder) {
                String title = ((javax.swing.border.TitledBorder) b).getTitle();
                if (title != null && containsCjk(title)) {
                    out.add("border:" + title);
                }
            }
            String tip = ((javax.swing.JComponent) c).getToolTipText();
            if (tip != null && containsCjk(tip)) {
                out.add("tip:" + tip);
            }
        }
        if (c instanceof JTable) {
            javax.swing.table.TableColumnModel cm = ((JTable) c).getColumnModel();
            for (int i = 0; i < cm.getColumnCount(); i++) {
                Object header = cm.getColumn(i).getHeaderValue();
                if (header != null && containsCjk(String.valueOf(header))) {
                    out.add("column:" + header);
                }
            }
        }
        if (c instanceof JTabbedPane) {
            JTabbedPane pane = (JTabbedPane) c;
            for (int i = 0; i < pane.getTabCount(); i++) {
                if (containsCjk(pane.getTitleAt(i))) {
                    out.add("tab:" + pane.getTitleAt(i));
                }
                collectCjkChrome(pane.getComponentAt(i), out);
            }
            return;                      // 标签页的子组件已在上面逐个走过，别再走一遍
        }
        if (c instanceof Container) {
            for (Component child : ((Container) c).getComponents()) {
                collectCjkChrome(child, out);
            }
        }
    }

    static boolean containsCjk(String s) {
        if (s == null) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch >= '一' && ch <= '龥') {
                return true;
            }
        }
        return false;
    }

    /** 找以某文案开头的 JLabel 的文字（扫描收尾复位后复查用） */
    static String labelTextOf(Component root, String text) {
        Component c = find(root, JLabel.class, x -> text.equals(((JLabel) x).getText()));
        return c == null ? null : ((JLabel) c).getText();
    }

    /**
     * 顶栏语言按钮：按一下切英文、再按一下切回中文，而且**切完界面真的跟着变**。
     *
     * <p>这是绑定器机制的验收点：只有「按钮在 + 点击后标签页标题变了 + 再点又变回来」
     * 才能证明重译真的落到了 Swing 组件上，而不是只改了一个布尔量。
     * 最后两条断言兜住另外两类错：加了控件忘了建 key（返回 key 本身）、key 打错字。
     */
    static void checkLanguageUi(Component suiteUi, JTabbedPane tabs) throws Exception {
        JButton langButton = (JButton) find(suiteUi, JButton.class, c -> {
            String text = ((JButton) c).getText();
            return "EN".equals(text) || "中文".equals(text);
        });
        check("顶栏有一个语言切换按钮", langButton != null, "没找到文案为 EN / 中文 的按钮");
        if (langButton == null || tabs == null) {
            return;
        }
        check("中文界面下按钮显示「EN」（按钮上的字是要切过去的那个语言）",
                "EN".equals(langButton.getText()), langButton.getText());
        // 位置：按钮要在顶栏**最右**那一组里，不能混进中间那行状态字里。
        // headless 下量不了像素（没有 layout pass），所以钉结构：它的兄弟只有一个（与标题等宽的
        // 隐形占位），而中间那组是 4 个状态格。以后谁把它挪回中间，这条会红。
        check("语言按钮在顶栏最右那组（不在中间的状态字组里）",
                langButton.getParent() != null && langButton.getParent().getComponentCount() == 2,
                langButton.getParent() == null ? "没有父容器"
                        : "兄弟数=" + (langButton.getParent().getComponentCount() - 1));

        checkButtonsFit(suiteUi, "中文");
        SwingUtilities.invokeAndWait(langButton::doClick);
        check("切到英文后标签页标题变英文",
                tabs.indexOfTab("Tasks") >= 0 && tabs.indexOfTab("Configuration") >= 0,
                "标签页=" + tabTitles(tabs));
        check("切到英文后按钮显示「中文」", "中文".equals(langButton.getText()), langButton.getText());
        check("切到英文后顶栏状态格也变（这格是派生文案，走的是钩子而不是绑定器）",
                labelStartingWith(suiteUi, "OOB: ") != null, "顶栏没有 OOB: 开头的格子");

        SwingUtilities.invokeAndWait(langButton::doClick);
        check("再点一次切回中文（语言不能只单向生效）",
                tabs.indexOfTab("日志统计") >= 0 && tabs.indexOfTab("配置") >= 0,
                "标签页=" + tabTitles(tabs));
        check("切回中文后按钮显示「EN」", "EN".equals(langButton.getText()), langButton.getText());
        checkButtonsFit(suiteUi, "英文");

        check("驱动过整个界面后没有查不到的文案 key（漏翻的会在这里现形）",
                Msg.missingKeys().isEmpty(), String.valueOf(Msg.missingKeys()));
        check("文案表里没有只写了一侧或写成空串的条目", Msg.tableProblems().isEmpty(),
                String.valueOf(Msg.tableProblems()));
    }

    /**
     * 按钮文字必须放得下 —— 两种语言都要查。
     *
     * <p>为什么需要：给按钮设固定 {@code preferredSize} 时，中文文案短、英文文案长
     * （"清空已完成" vs "Clear completed"），按中文宽度定的尺寸到了英文就会把文字截断，
     * 而截断**不会有任何报错**。这里用字体度量直接算：可用宽度 = 首选宽 − 左右内边距，
     * 小于文字实际宽度就是被截了。
     */
    static void checkButtonsFit(Component root, String lang) {
        List<String> clipped = new ArrayList<>();
        collectClippedButtons(root, clipped);
        check("[" + lang + "] 按钮文字都放得下（被截断的会列在这里）", clipped.isEmpty(), String.valueOf(clipped));
    }

    static void collectClippedButtons(Component c, List<String> out) {
        if (c == null) {
            return;
        }
        if (c instanceof javax.swing.AbstractButton) {
            javax.swing.AbstractButton button = (javax.swing.AbstractButton) c;
            String text = button.getText();
            if (text != null && !text.isEmpty() && button.getFont() != null) {
                int need = button.getFontMetrics(button.getFont()).stringWidth(text);
                java.awt.Insets insets = button.getInsets();
                int have = button.getPreferredSize().width - insets.left - insets.right;
                if (have < need) {
                    out.add(text + " 需要 " + need + "px 只有 " + have + "px");
                }
            }
        }
        if (c instanceof JTabbedPane) {
            JTabbedPane pane = (JTabbedPane) c;
            for (int i = 0; i < pane.getTabCount(); i++) {
                collectClippedButtons(pane.getComponentAt(i), out);
            }
            return;
        }
        if (c instanceof Container) {
            for (Component child : ((Container) c).getComponents()) {
                collectClippedButtons(child, out);
            }
        }
    }

    /** 找第一个以某前缀开头的 JLabel 的文案；没找到返回 null */
    static String labelStartingWith(Component root, String prefix) {
        Component c = find(root, JLabel.class, x -> {
            String text = ((JLabel) x).getText();
            return text != null && text.startsWith(prefix);
        });
        return c == null ? null : ((JLabel) c).getText();
    }

    /**
     * 配置页那两个新控件：勾选框立刻生效并落盘，白名单输入框跟着启用/禁用。
     *
     * <p>「立刻生效」这条是硬要求：勾选框代表「从现在起每个代理请求都要自动发包」，
     * 如果它要等「保存配置」（那个按钮还有验证 Key 的门槛），界面显示的和实际做的就会不一致。
     */
    static void checkAutoScanUi(Component configUi) throws Exception {
        if (configUi == null) {
            check("配置页里能找到自动扫描勾选框", false, "配置页为空");
            return;
        }
        JCheckBox autoScanBox = (JCheckBox) find(configUi, JCheckBox.class, c -> {
            String text = ((JCheckBox) c).getText();
            return text != null && text.startsWith("Proxy 流量自动扫描");
        });
        check("配置页里有「Proxy 流量自动扫描」勾选框", autoScanBox != null, "没找到");
        JTextArea whitelistField = findWhitelistArea(configUi);
        check("配置页里有白名单输入框", whitelistField != null, "没找到");
        if (autoScanBox == null || whitelistField == null) {
            return;
        }
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        check("白名单是多行输入框（一行一个 host），不是单行框",
                whitelistField instanceof JTextArea && ((JTextArea) whitelistField).getLineWrap(),
                String.valueOf(whitelistField.getClass()));
        check("白名单框套在滚动面板里（host 多了能滚轮翻）",
                whitelistField.getParent() instanceof javax.swing.JViewport
                        && whitelistField.getParent().getParent() instanceof JScrollPane,
                String.valueOf(whitelistField.getParent()));
        check("自动扫描没勾时白名单输入框是禁用的（它只在勾选后才有意义）", !whitelistField.isEnabled(), "居然是启用的");

        SwingUtilities.invokeAndWait(() -> autoScanBox.doClick());
        check("勾上自动扫描后：立刻写进配置并落盘（不等「保存配置」）", config.isAutoScanProxy(), "配置没变");
        check("勾上后白名单输入框变为可用", whitelistField.isEnabled(), "还是禁用的");

        SwingUtilities.invokeAndWait(() -> autoScanBox.doClick());
        check("取消勾选后配置也跟着改回来", !config.isAutoScanProxy(), "配置没变回去");
        check("取消勾选后白名单输入框重新禁用", !whitelistField.isEnabled(), "还是启用的");
    }

    /**
     * 自动扫描监听器的闸门与通路。
     *
     * <p>「没建任务」这种断言本身很弱（{@code addRequest} 走到一半失败也是没任务），所以每条否定断言
     * 都同时要求 {@code printError} 为空 —— {@code addRequest} 的每条失败路径都会 printError。
     */
    /**
     * 配置页剩下那几个控件的联动：换服务商要带出它的默认地址、外带开关要联动「测试回连」的可用性、
     * 「保存配置」在没存过 Key 时必须是灰的（保存按钮有验证门槛，这是最容易让人以为坏了的地方）。
     */
    static void checkConfigPageControls(Component configUi) throws Exception {
        if (configUi == null) {
            check("能拿到配置页来检查控件", false, "配置页为空");
            return;
        }
        List<JTextField> plainFields = new ArrayList<>();
        collect(configUi, JTextField.class, plainFields);
        JComboBox<?> providerCombo = (JComboBox<?>) find(configUi, JComboBox.class,
                c -> ((JComboBox<?>) c).getItemCount() > 1 && "自定义".equals(((JComboBox<?>) c).getItemAt(
                        ((JComboBox<?>) c).getItemCount() - 1)));
        check("配置页里有服务商下拉框", providerCombo != null && !plainFields.isEmpty(), "没找到");
        check("配置页的服务商下拉框列出了全部预设（含新加的 ChatGPT / Anthropic）",
                providerCombo != null
                        && providerCombo.getItemCount() == com.zackai.model.AIProvider.getDefaultProviders().size()
                        && comboHasItem(providerCombo, "ChatGPT (OpenAI)")
                        && comboHasItem(providerCombo, "Anthropic (Claude)"),
                providerCombo == null ? "没有下拉框" : "共 " + providerCombo.getItemCount() + " 项");
        if (providerCombo == null || plainFields.isEmpty()) {
            return;
        }
        JTextField apiEndpointField = plainFields.get(0);
        JTextField modelsEndpointField = plainFields.get(1);
        com.zackai.model.AIProvider preset = com.zackai.model.AIProvider.getDefaultProviders().get(0);
        if (!"自定义".equals(preset.getName())) {
            SwingUtilities.invokeAndWait(() -> providerCombo.setSelectedItem(preset.getName()));
            check("换服务商后带出该服务商的 API 地址", preset.getApiEndpoint().equals(apiEndpointField.getText()),
                    apiEndpointField.getText());
            check("换服务商后带出该服务商的模型接口", preset.getModelsEndpoint().equals(modelsEndpointField.getText()),
                    modelsEndpointField.getText());
        }
        SwingUtilities.invokeAndWait(() -> providerCombo.setSelectedItem("自定义"));
        check("切到「自定义」会清空地址，交给用户填",
                apiEndpointField.getText().isEmpty() && modelsEndpointField.getText().isEmpty(),
                apiEndpointField.getText() + " | " + modelsEndpointField.getText());

        JButton saveButton = (JButton) find(configUi, JButton.class, c -> "保存配置".equals(((JButton) c).getText()));
        check("没存过 Key 时「保存配置」是灰的（它有验证门槛，不是坏了）",
                saveButton != null && !saveButton.isEnabled(), String.valueOf(saveButton));

        JCheckBox oobBox = (JCheckBox) find(configUi, JCheckBox.class, c -> {
            String text = ((JCheckBox) c).getText();
            return text != null && text.startsWith("启用");
        });
        JButton oastTestButton = (JButton) find(configUi, JButton.class, c -> "测试回连".equals(((JButton) c).getText()));
        check("配置页里有外带开关与「测试回连」按钮", oobBox != null && oastTestButton != null, "没找到");
        if (oobBox == null || oastTestButton == null) {
            return;
        }
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        check("外带关着时「测试回连」不可点（它本身就是一次外发）",
                !config.isOobEnabled() && !oastTestButton.isEnabled(), "外带=" + config.isOobEnabled());
        SwingUtilities.invokeAndWait(oobBox::doClick);
        check("勾上外带后「测试回连」变为可点", config.isOobEnabled() && oastTestButton.isEnabled(),
                "外带=" + config.isOobEnabled());
        SwingUtilities.invokeAndWait(oobBox::doClick);
        check("取消外带后「测试回连」重新禁用", !config.isOobEnabled() && !oastTestButton.isEnabled(),
                "外带=" + config.isOobEnabled());
    }

    /**
     * 「保存配置」必须落盘**界面上所有能改的东西**。
     *
     * <p>这是用户报的具体 bug：白名单输入框的值是失焦/回车才进配置的，敲完直接点保存
     * （焦点还没离开输入框）就会漏掉它 —— 提示「保存成功」，配置文件里却还是老值。
     * 这里故意只 setText、不触发失焦，然后点保存，再看文件里到底有没有。
     *
     * <p>只在 headless 下跑：`saveConfig` 最后会弹一个成功对话框，有显示环境时会**挂住**整个自检。
     */
    static void checkSavePersistsEverything(Component configUi) throws Exception {
        if (!java.awt.GraphicsEnvironment.isHeadless()) {
            System.out.println("  （跳过：非 headless 环境，saveConfig 的成功对话框会把自检挂住）");
            return;
        }
        if (configUi == null) {
            check("能拿到配置页来做保存检查", false, "配置页为空");
            return;
        }
        JTextField apiKeyField = (JTextField) find(configUi, JTextField.class, c -> c instanceof JPasswordField);
        // 按顺序取普通输入框（已经跳过 JPasswordField）：0 = API 地址，1 = 模型接口，
        // 后面的白名单单独按 tooltip 认（它是最能说明身份的那个）
        List<JTextField> plainFields = new ArrayList<>();
        collect(configUi, JTextField.class, plainFields);
        // 普通单行输入框正好 2 个：API 地址 / 模型接口（API Key 是密码框、白名单是多行文本域）
        check("配置页里能找到地址 / 模型接口输入框", plainFields.size() >= 2, "只找到 " + plainFields.size() + " 个");
        if (plainFields.size() < 2 || apiKeyField == null) {
            return;
        }
        JTextField apiEndpointField = plainFields.get(0);
        JTextField modelsEndpointField = plainFields.get(1);
        JTextArea whitelistField = findWhitelistArea(configUi);
        @SuppressWarnings("unchecked")
        JComboBox<String> modelCombo = (JComboBox<String>) find(configUi, JComboBox.class, c -> {
            Object selected = ((JComboBox<?>) c).getSelectedItem();
            return selected != null && ("点击获取".equals(selected) || "获取失败".equals(selected));
        });
        check("配置页里能找到模型下拉框", modelCombo != null, "没找到");
        if (whitelistField == null || modelCombo == null) {
            return;
        }

        apiKeyField.setText("harness-key");
        apiEndpointField.setText("https://example.invalid/v1/chat");
        modelsEndpointField.setText("https://example.invalid/v1/models");
        modelCombo.addItem("harness-model");
        modelCombo.setSelectedItem("harness-model");
        // 关键：只 setText，**不**触发失焦/回车 —— 模拟「敲完白名单直接点保存」
        whitelistField.setText("only-this.test");

        java.lang.reflect.Method save = configUi.getClass().getDeclaredMethod("saveConfig");
        save.setAccessible(true);
        try {
            save.invoke(configUi);
        } catch (java.lang.reflect.InvocationTargetException e) {
            // 成功提示框在 headless 下必然抛 HeadlessException —— 那是保存之后的事，写盘已经完成了
            if (!(e.getCause() instanceof java.awt.HeadlessException)) {
                throw e;
            }
        }

        java.nio.file.Path file = java.nio.file.Paths.get(System.getProperty("user.home"))
                .resolve(com.zackai.core.ConfigManager.CONFIG_FILE_NAME);
        String json = new String(java.nio.file.Files.readAllBytes(file), java.nio.charset.StandardCharsets.UTF_8);
        check("点保存后，没失焦的白名单值也进了配置文件", json.contains("\"autoScanWhitelist\": \"only-this.test\""), json);
        check("点保存后，自动扫描开关状态进了配置文件", json.contains("\"autoScanProxy\":"), json);
        check("点保存后，API Key / 地址 / 模型也都进了配置文件",
                json.contains("\"apiKey\": \"harness-key\"") && json.contains("https://example.invalid/v1/chat")
                        && json.contains("\"selectedAgent\": \"harness-model\""), json);
        check("点保存后，外带回连开关状态也在文件里", json.contains("\"oobEnabled\":"), json);

        // 复位：后面还有检查（右击菜单那一段会自己再 disableOob），别留一份改了 key 的配置
        apiKeyField.setText("");
        whitelistField.setText("");
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        config.setAutoScanWhitelist("");
        config.setAutoScanProxy(false);
        config.setApiKey("");
        config.setSelectedAgent("");
        ConfigManager.getInstance().saveConfig();
    }

    /**
     * 验证成功后走的是 {@code refreshConfigStatus(false)}：只拿已存的验证状态刷顶栏，
     * **不再打一次验证请求**（那次验证就在几秒前，再打纯属浪费一次真实外发）。
     *
     * <p>判定条件刻意造成「两条路结果不同」：清空 key/模型/地址 + verified=true 时，
     * 带重验的实现会走 else 分支显示「未配置」，不带重验的显示「可用」；两种都不会联网。
     */
    static void checkConfigStatusRefresh(Component suiteUi) throws Exception {
        JLabel keyLabel = (JLabel) find(suiteUi, JLabel.class, c -> {
            String text = ((JLabel) c).getText();
            return text != null && text.startsWith("API Key");
        });
        check("顶栏有 API Key 状态格", keyLabel != null, "没找到");
        if (keyLabel == null || !(suiteUi instanceof com.zackai.ui.MainPanel)) {
            return;
        }
        com.zackai.ui.MainPanel panel = (com.zackai.ui.MainPanel) suiteUi;
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        String key = config.getApiKey();
        String model = config.getSelectedAgent();
        String endpoint = config.getApiEndpoint();
        boolean verified = config.isVerified();
        try {
            config.setApiKey("");
            config.setSelectedAgent("");
            config.setApiEndpoint("");
            config.setVerified(true);
            panel.refreshConfigStatus(false);
            drainEdt();
            check("验证成功后刷顶栏用的是已存状态（显示可用），不会再打一次验证请求",
                    keyLabel.getText().contains("可用"), keyLabel.getText());
            panel.refreshConfigStatus(true);
            drainEdt();
            check("同样状态下走「重验」分支显示未配置（证明上面那条不是因为两条路一样）",
                    keyLabel.getText().contains("未配置"), keyLabel.getText());
        } finally {
            config.setApiKey(key);
            config.setSelectedAgent(model);
            config.setApiEndpoint(endpoint);
            config.setVerified(verified);
        }
    }

    static JTextArea findWhitelistArea(Component configUi) {
        return (JTextArea) find(configUi, JTextArea.class, c -> {
            String tip = ((JTextArea) c).getToolTipText();
            return tip != null && tip.startsWith("只扫这些目标");
        });
    }

    static void collect(Component root, Class<?> type, List<JTextField> out) {
        if (root instanceof JPasswordField) {
            return;
        }
        if (type.isInstance(root)) {
            out.add((JTextField) root);
        }
        if (root instanceof Container) {
            for (Component child : ((Container) root).getComponents()) {
                collect(child, type, out);
            }
        }
    }

    static void checkProxyAutoScanListener(IProxyListener listener, com.zackai.ui.MainPanel panel,
                                           List<String> errors) throws Exception {
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        ProxyScanHistory.clear();                 // 从干净的去重记录开始（这是全局状态）

        config.setAutoScanProxy(false);
        config.setAutoScanWhitelist("");
        int before = panel.getTasks().size();
        listener.processProxyMessage(true, fakeProxyMessage("GET /off HTTP/1.1\r\nHost: example.com\r\n\r\n", "example.com", 80));
        drainEdt();
        check("自动扫描关着时，经过代理的请求不会建任务",
                panel.getTasks().size() == before && errors.isEmpty(),
                "任务数 " + before + " → " + panel.getTasks().size() + "，printError=" + errors);

        config.setAutoScanProxy(true);
        config.setAutoScanWhitelist("lab.test");
        listener.processProxyMessage(true, fakeProxyMessage("GET /not-whitelisted HTTP/1.1\r\nHost: example.com\r\n\r\n", "example.com", 80));
        drainEdt();
        check("开了自动扫描但目标不在白名单里时不建任务（白名单是唯一的闸门）",
                panel.getTasks().size() == before && errors.isEmpty(),
                "任务数 " + before + " → " + panel.getTasks().size() + "，printError=" + errors);

        config.setAutoScanWhitelist("example.com");
        listener.processProxyMessage(true, fakeProxyMessage("GET /auto?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n", "example.com", 80));
        drainEdt();
        int afterHit = panel.getTasks().size();
        check("命中白名单的代理请求会建出任务", afterHit == before + 1,
                "任务数 " + before + " → " + afterHit);
        if (afterHit == before + 1) {
            com.zackai.model.ScanTask task = panel.getTasks().get(afterHit - 1);
            check("自动建的任务用的是「AI智能扫描」模式与请求里的 URL",
                    task.getScanMode() == com.zackai.model.ScanTask.ScanMode.CUSTOM
                            && task.getUrl() != null && task.getUrl().contains("example.com")
                            && task.getUrl().contains("/auto?id=1"),
                    task.getScanMode() + " | " + task.getUrl());
            check("任务拿到的是请求快照（host/端口没丢）",
                    task.getOriginalRequest() != null
                            && "example.com".equals(task.getOriginalRequest().getHttpService().getHost())
                            && task.getOriginalRequest().getHttpService().getPort() == 80,
                    String.valueOf(task.getOriginalRequest()));
        }

        // 去重：同一个请求再来一次（哪怕请求头变了）不该再建任务
        listener.processProxyMessage(true, fakeProxyMessage("GET /auto?id=1 HTTP/1.1\r\nHost: example.com\r\n"
                + "Cookie: s=2\r\nUser-Agent: another\r\n\r\n", "example.com", 80));
        drainEdt();
        check("同一个请求再经过代理时不重复建任务（刷新页面/轮询不会翻倍）",
                panel.getTasks().size() == afterHit, "任务数 " + afterHit + " → " + panel.getTasks().size());

        // 参数值不参与判重（2026-09-24）：同一个功能点换了个值 —— 轮询时间戳、分页、随机 id ——
        // 不该再建一条任务。闸门用的是同一份「参数名」定义，所以这里同时钉住了两边一致。
        listener.processProxyMessage(true, fakeProxyMessage("GET /auto?id=987654321 HTTP/1.1\r\nHost: example.com\r\n\r\n", "example.com", 80));
        drainEdt();
        check("同一个功能点换了参数值不重复建任务（轮询/分页/随机 id 不再翻倍）",
                panel.getTasks().size() == afterHit, "任务数 " + afterHit + " → " + panel.getTasks().size());

        // 反方向：参数名变了 = 另一个注入面，**必须**建任务，否则就是漏扫
        listener.processProxyMessage(true, fakeProxyMessage("GET /auto?id=1&uid=2 HTTP/1.1\r\nHost: example.com\r\n\r\n", "example.com", 80));
        drainEdt();
        int afterNames = panel.getTasks().size();
        check("同一个路径多了一个参数名仍然建任务（去重不能变成漏扫）", afterNames == afterHit + 1,
                "任务数 " + afterHit + " → " + afterNames);
        // 方法不同也是新请求（GET /auto 与 POST /auto）
        listener.processProxyMessage(true, fakeProxyMessage("POST /auto HTTP/1.1\r\nHost: example.com\r\n\r\nid=2", "example.com", 80));
        drainEdt();
        int afterBody = panel.getTasks().size();
        check("同一个路径换个方法（POST /auto）仍然建任务", afterBody == afterNames + 1,
                "任务数 " + afterNames + " → " + afterBody);

        // 同名参数换个位置 = 另一个注入面：正好一个名字，只差在查询串还是请求体
        // （上面那条 POST /auto 是 {body:id}，这条是 {url:id} —— 名字集合一样，只有位置不同）
        String queryIdNoBody = "POST /auto?id=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";
        listener.processProxyMessage(true, fakeProxyMessage(queryIdNoBody, "example.com", 80));
        drainEdt();
        int afterPosition = panel.getTasks().size();
        check("同名参数从请求体换到查询串（POST /auto?id=1）仍然建任务 —— 位置不同是两个注入面",
                afterPosition == afterBody + 1, "任务数 " + afterBody + " → " + afterPosition);
        listener.processProxyMessage(true, fakeProxyMessage(queryIdNoBody, "example.com", 80));
        drainEdt();
        check("同一个位置组合再访问一次仍然是重复（去重本身没被位置前缀弄丢）",
                panel.getTasks().size() == afterPosition, "任务数 " + afterPosition + " → " + panel.getTasks().size());

        // 响应方向：即使命中白名单也不建任务（Burp 请求/响应各回调一次 —— 拿「当前任务数」比，
        // 别沿用上面某个中间变量：那些变量随新增用例变，比出来的就是一条假红）
        int beforeResponse = panel.getTasks().size();
        listener.processProxyMessage(false, fakeProxyMessage("GET /auto?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n", "example.com", 80));
        drainEdt();
        check("响应方向不建任务", panel.getTasks().size() == beforeResponse,
                "任务数 " + beforeResponse + " → " + panel.getTasks().size());

        // 「只收带参数的请求」：没有参数的流量（图片/CSS/JS/favicon、纯 REST 路径）一条任务都不建。
        // 判定复用的是 step2 那份参数谓词，所以这里同时钉住了「两边不会各判各的」。
        ProxyScanHistory.clear();
        int beforeParam = panel.getTasks().size();
        listener.processProxyMessage(true, fakeProxyMessage(
                "GET /assets/app.js HTTP/1.1\r\nHost: example.com\r\n\r\n", "example.com", 80));
        drainEdt();
        check("没有参数的请求（图片/CSS/JS）不建任务",
                panel.getTasks().size() == beforeParam && !reachedAddRequest(errors),
                "任务数 " + beforeParam + " → " + panel.getTasks().size() + "，printError=" + errors);

        listener.processProxyMessage(true, fakeProxyMessage(
                "GET /static/logo.png HTTP/1.1\r\nHost: example.com\r\nAccept: image/png\r\n\r\n",
                "example.com", 80));
        drainEdt();
        check("静态资源（哪怕带 Accept: image/png）也不建任务",
                panel.getTasks().size() == beforeParam && !reachedAddRequest(errors),
                "任务数变成了 " + panel.getTasks().size());

        listener.processProxyMessage(true, fakeProxyMessage(
                "GET /api/report?csrf_token=abc&timestamp=1700000000 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "example.com", 80));
        drainEdt();
        check("只有敏感参数（csrf_token / timestamp）的请求不建任务 —— 与 step2 是同一份判定",
                panel.getTasks().size() == beforeParam && !reachedAddRequest(errors),
                "任务数变成了 " + panel.getTasks().size());

        listener.processProxyMessage(true, fakeProxyMessage(
                "GET /admin HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc; theme=dark\r\n\r\n",
                "example.com", 80));
        drainEdt();
        check("只有 Cookie 的请求不建任务（Burp 把每个 cookie 都算参数，算上它登录状态下"
                        + "每张图片都是「有参数」）",
                panel.getTasks().size() == beforeParam && !reachedAddRequest(errors),
                "任务数变成了 " + panel.getTasks().size());

        // 正面用例：闸门不能变成「什么都不扫」。查询串参数照样建任务
        //（请求体参数那条通路由上面 POST /auto 的用例覆盖）
        listener.processProxyMessage(true, fakeProxyMessage(
                "GET /api/u?id=1 HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc\r\n\r\n",
                "example.com", 80));
        drainEdt();
        check("有查询串参数的请求照常建任务（Cookie 只是不单独构成「有参数」）",
                panel.getTasks().size() == beforeParam + 1,
                "任务数 " + beforeParam + " → " + panel.getTasks().size());

        // 白名单里写多个 host（英文逗号分隔）：命中第二项同样要建任务
        ProxyScanHistory.clear();
        int beforeMulti = panel.getTasks().size();
        config.setAutoScanWhitelist("lab.test\nsecond.test");          // 一行一个（用户填法）
        listener.processProxyMessage(true, fakeProxyMessage("GET /multi?q=1 HTTP/1.1\r\nHost: second.test\r\n\r\n", "second.test", 80));
        drainEdt();
        check("白名单写多个 host（换行分隔）时，命中第二个也会建任务",
                panel.getTasks().size() == beforeMulti + 1, "任务数 " + beforeMulti + " → " + panel.getTasks().size());
        config.setAutoScanWhitelist("example.com");

        // 重新开一轮（配置页取消再勾上会做这件事）
        int beforeRescan = panel.getTasks().size();
        ProxyScanHistory.clear();
        listener.processProxyMessage(true, fakeProxyMessage("GET /auto?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n", "example.com", 80));
        drainEdt();
        check("重置去重记录后，同一个请求会重新扫（「改了目标想重扫」不用重启插件）",
                panel.getTasks().size() == beforeRescan + 1, "任务数 " + beforeRescan + " → " + panel.getTasks().size());

        config.setAutoScanProxy(false);
        config.setAutoScanWhitelist("");
    }

    /**
     * 任务表格最左边的勾选列，以及「勾多个 → 右键批量操作」。
     *
     * <p>用户报的 bug：多选之后右键只操作一个。两个原因叠在一起 —— 右键那几项原先一律读
     * {@code getSelectedRow()}（单行），而 {@code setComponentPopupMenu} **不会替你选中光标下那一行**，
     * 所以「右键 A 行、菜单却操作了上次点过的 B 行」。
     *
     * <p>勾选状态刻意不存在单元格里（{@code checkedTaskIds} 才是权威来源）：搜索/筛选会
     * {@code setRowCount(0)} 重建整个模型，只存在单元格里的话用户勾完再打字搜索就全没了。
     * 这条是本节最关键的断言。
     */
    /**
     * 探针列表里「未响应」的那条要标出来（2026-09-24）。
     *
     * <p>超时的载荷现在也会留下记录（见 {@code AIEngine.SentRequest}），但它的响应框是空的 ——
     * 而「空响应框」和「一条都没选」在界面上长得一模一样。不标出来，用户会以为这条记录是空的。
     */
    static void checkProbeListMarksNoResponse(Component suiteUi) throws Exception {
        final com.zackai.ui.TaskDetailPanel detail =
                (com.zackai.ui.TaskDetailPanel) find(suiteUi, com.zackai.ui.TaskDetailPanel.class, c -> true);
        check("能拿到「请求与响应详情」面板", detail != null, "没找到");
        if (detail == null) {
            return;
        }
        // 两条记录：一条有响应，一条没有（响应对象在、响应体为 null —— 超时那条就是这个形态）
        IHttpRequestResponse withResponse = (IHttpRequestResponse) Proxy.newProxyInstance(
                ExtenderHarness.class.getClassLoader(), new Class[]{IHttpRequestResponse.class},
                (p, m, a) -> "getResponse".equals(m.getName()) ? "HTTP/1.1 200 OK\r\n\r\nok".getBytes() : null);
        IHttpRequestResponse noResponse = (IHttpRequestResponse) Proxy.newProxyInstance(
                ExtenderHarness.class.getClassLoader(), new Class[]{IHttpRequestResponse.class},
                (p, m, a) -> "getRequest".equals(m.getName()) ? "GET /a?cmd=1 HTTP/1.1\r\n\r\n".getBytes() : null);
        final ScanTask task = new ScanTask(424242, null, "GET", "http://probe.test/a?cmd=1", ScanTask.ScanMode.CUSTOM);
        task.addProbeRecord(new ScanTask.ProbeRecord(1, "命令注入", "x; id", "cmd", withResponse));
        task.addProbeRecord(new ScanTask.ProbeRecord(2, "命令注入", "x; id", "cmd", noResponse));
        SwingUtilities.invokeAndWait(() -> detail.showTask(task));
        // 全限定名：这个文件 import 了 java.util.List，JList 直接写会撞
        javax.swing.JList<?> probeList = (javax.swing.JList<?>) find(detail, javax.swing.JList.class, c -> true);
        check("探针列表拿得到", probeList != null, "没找到");
        if (probeList == null) {
            return;
        }
        check("两条记录都在列表里", probeList.getModel().getSize() == 2,
                "只有 " + probeList.getModel().getSize() + " 条");
        if (probeList.getModel().getSize() == 2) {
            check("有响应的那条按普通文案",
                    Msg.t("detail.probeItem", 1, "命令注入", "cmd").equals(probeList.getModel().getElementAt(0)),
                    String.valueOf(probeList.getModel().getElementAt(0)));
            check("没响应的那条带「未响应」标记（否则空响应框看着像没选中）",
                    Msg.t("detail.probeItemNoResponse", 2, "命令注入", "cmd").equals(probeList.getModel().getElementAt(1)),
                    String.valueOf(probeList.getModel().getElementAt(1)));
        }
        // **故意不 showTask(null)**：列表项文案是渲染器组件上贴的字，面板只在「换语言」时重算它
        //（onLangChanged → rebuildProbeList）。清空任务的话语言钩子会提前返回，渲染器上就留着一份
        // 中文旧文案 —— 后面的 checkEnglishSweep 会如实报出来（第一版就是这么红的）。
        // 留着任务，切英文时它会被重译成英文，这才是真实行为。
    }

    /**
     * 手动右键扫描**不受 Proxy 去重影响**（用户明确要求 2026-09-24）：右键选一个漏洞类型
     * =「就扫这个包这一次」。
     *
     * <p>两个方向都要钉住：
     * <ul>
     *   <li>已经进过去重记录的包（= 自动扫描扫过），手动右键照样建任务 —— 去重只属于自动扫描那条入口；</li>
     *   <li>手动扫过的包**不写**去重记录 —— 否则「我只手动扫了 SQL 注入」会让自动扫描把这个包的其余
     *       类型一起跳过，而且日志里没有任何痕迹（静默漏扫）。</li>
     * </ul>
     *
     * <p>去重记录里两种键形态都登记一遍（按参数名/位置的那种，和解析失败时退回的请求体哈希那种），
     * 这样将来无论哪条路径被接上，断言都会红。
     */
    static void checkManualScanNotDeduped(com.zackai.ui.MainPanel panel) throws Exception {
        ProxyScanHistory.clear();
        String raw = "POST /manual?id=1 HTTP/1.1\r\nHost: manual.test\r\n"
                + "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\n\r\nid=1";
        byte[] req = bytes(raw);
        ProxyScanHistory.firstTime(ProxyScanHistory.key("manual.test", 80, req, Arrays.asList("url:id", "body:id")));
        ProxyScanHistory.firstTime(ProxyScanHistory.key("manual.test", 80, req, null));
        check("去重记录里已经登记了这个包（下面那条断言才有意义）",
                ProxyScanHistory.size() == 2, "size=" + ProxyScanHistory.size());

        IHttpRequestResponse message = fakeProxyMessage(raw, "manual.test", 80).getMessageInfo();
        int before = panel.getTasks().size();
        SwingUtilities.invokeAndWait(() -> panel.addRequest(message, ScanTask.ScanMode.SQL_INJECTION));
        drainEdt();
        check("已在去重记录里的包，手动右键仍然建任务（手动扫描不受 Proxy 去重影响）",
                panel.getTasks().size() == before + 1, "任务数 " + before + " → " + panel.getTasks().size());
        check("手动扫描不往去重记录里写（手动扫过一个包，不会让自动扫描之后漏掉它）",
                ProxyScanHistory.size() == 2, "size=" + ProxyScanHistory.size());
        if (panel.getTasks().size() > before) {
            ScanTask manual = panel.getTasks().get(panel.getTasks().size() - 1);
            check("手动建的任务带的是右键选的那个漏洞类型",
                    manual.getScanMode() == ScanTask.ScanMode.SQL_INJECTION, String.valueOf(manual.getScanMode()));
        }
        ProxyScanHistory.clear();
    }

    /**
     * 队列可见性 + 「值没变就不重写模型」—— 自动扫描下这两件事决定界面卡不卡。
     *
     * <p>池子只有 10 条线程，代理流量会堆出成百上千条排队任务：「一直待处理」和「卡死」在界面上
     * 没有区别，所以状态列要显示排队位次。另一半是每秒一次的整表刷新：已结束的行值不再变化，
     * 逐行 {@code setValueAt} + {@code fireTableRowsUpdated} 全是白工，表格几千行时拖住的是 EDT。
     *
     * <p>断言方式（都用自己建的任务，不碰后台扫描线程正在改的那些，否则时灵时不灵）：
     * 位次文案直接调 {@code statusCellOf}；跳过逻辑对同一行连调两次 {@code updateRow}，
     * 用 TableModelListener 数事件 —— 第二遍必须是 0 次，改了值必须又变成非 0。
     */
    static void checkTaskQueueDisplay(Component suiteUi, com.zackai.ui.MainPanel panel) throws Exception {
        JTable table = (JTable) find(suiteUi, JTable.class, c -> true);
        com.zackai.ui.TaskTablePanel tablePanel =
                table == null ? null : (com.zackai.ui.TaskTablePanel) SwingUtilities.getAncestorOfClass(
                        com.zackai.ui.TaskTablePanel.class, table);
        check("队列检查能拿到任务表格", table != null && tablePanel != null, "没找到");
        if (table == null || tablePanel == null) {
            return;
        }
        final ScanTask probe = new ScanTask(987654, null, "GET", "http://queue-probe/", ScanTask.ScanMode.CUSTOM);
        SwingUtilities.invokeAndWait(() -> {
            try {
                Method statusCell = com.zackai.ui.TaskTablePanel.class.getDeclaredMethod(
                        "statusCellOf", ScanTask.class, Map.class, int.class);
                statusCell.setAccessible(true);
                Map<Integer, Integer> positions = new java.util.HashMap<>();
                positions.put(probe.getId(), 3);
                check("排队中的任务在状态列显示位次（等多久要看得见）",
                        Msg.t("task.queuedAt", 3, 7).equals(statusCell.invoke(tablePanel, probe, positions, 7)),
                        String.valueOf(statusCell.invoke(tablePanel, probe, positions, 7)));
                check("拿不到位次时退回不带数字的排队文案（单任务刷新路径）",
                        Msg.t("task.queued").equals(statusCell.invoke(tablePanel, probe, null, 0)),
                        String.valueOf(statusCell.invoke(tablePanel, probe, null, 0)));
                probe.setStatus(ScanTask.TaskStatus.FINISHED);
                check("已结束的任务仍按状态名显示（排队文案只盖 PENDING）",
                        Msg.statusName(ScanTask.TaskStatus.FINISHED).equals(statusCell.invoke(tablePanel, probe, positions, 7)),
                        String.valueOf(statusCell.invoke(tablePanel, probe, positions, 7)));

                // 跳过逻辑：自己插一行、自己调 updateRow，值可控
                Method addTask = com.zackai.ui.TaskTablePanel.class.getMethod("addTask", ScanTask.class);
                Method updateRow = com.zackai.ui.TaskTablePanel.class.getDeclaredMethod(
                        "updateRow", int.class, ScanTask.class);
                updateRow.setAccessible(true);
                addTask.invoke(tablePanel, probe);
                int row = -1;
                for (int i = 0; i < table.getRowCount(); ++i) {
                    if (Integer.valueOf(probe.getId()).equals(table.getValueAt(i, 1))) {
                        row = i;
                        break;
                    }
                }
                check("探针任务插进了表格（后面两条断言才有意义）", row >= 0, "没找到行");
                if (row >= 0) {
                    final int probeRow = row;
                    final int[] events = {0};
                    javax.swing.event.TableModelListener counter = e -> events[0] += Math.max(1,
                            e.getLastRow() - e.getFirstRow() + 1);
                    table.getModel().addTableModelListener(counter);
                    updateRow.invoke(tablePanel, probeRow, probe);   // 第一遍必定写（addTask 作废过签名）
                    int firstPass = events[0];
                    events[0] = 0;
                    updateRow.invoke(tablePanel, probeRow, probe);   // 第二遍值没变：一次都不该碰模型
                    int secondPass = events[0];
                    events[0] = 0;
                    probe.setAiTag("安全");                          // 值变了：必须再刷
                    updateRow.invoke(tablePanel, probeRow, probe);
                    int thirdPass = events[0];
                    table.getModel().removeTableModelListener(counter);
                    check("值没变的行第二次不再写模型（每秒整表刷新不再白干活）",
                            firstPass > 0 && secondPass == 0,
                            "第一遍 " + firstPass + " 次事件，第二遍 " + secondPass + " 次");
                    check("值变了照刷（跳过判断不是「永远不刷」）", thirdPass > 0, thirdPass + " 次事件");
                    com.zackai.ui.TaskTablePanel.class.getMethod("removeTask", ScanTask.class)
                            .invoke(tablePanel, probe);
                }
            } catch (Exception e) {
                check("队列可见性与整表刷新检查未抛异常", false, String.valueOf(e));
            }
        });
    }

    static void checkTaskTableMultiSelect(Component suiteUi, com.zackai.ui.MainPanel panel) throws Exception {
        JTable table = (JTable) find(suiteUi, JTable.class, c -> true);
        check("任务表格里能拿到 JTable", table != null, "没找到");
        if (table == null) {
            return;
        }
        // 渲染器和编辑器**必须画得一模一样**：只设了渲染器那一份的话，点下去的一瞬间画的是编辑器，
        // 框会跳到单元格左边、松开又跳回中间 —— 用户看到的就是「勾选时框左移再移回」
        javax.swing.table.TableCellRenderer selectRenderer = table.getColumnModel().getColumn(0).getCellRenderer();
        javax.swing.table.TableCellEditor selectEditor = table.getColumnModel().getColumn(0).getCellEditor();
        if (selectRenderer != null && selectEditor != null && table.getRowCount() > 0) {
            Component rendered = selectRenderer.getTableCellRendererComponent(table, Boolean.TRUE, false, false, 0, 0);
            Component editing = selectEditor.getTableCellEditorComponent(table, Boolean.TRUE, true, 0, 0);
            selectEditor.cancelCellEditing();
            boolean sameAlignment = rendered instanceof JCheckBox && editing instanceof JCheckBox
                    && ((JCheckBox) rendered).getHorizontalAlignment() == ((JCheckBox) editing).getHorizontalAlignment();
            // 只比对齐。**边框那半留不得**：我试过给编辑器单独加边框、也试过改 getInsets()，
            // 都改不出差异（DefaultCellEditor 取回组件时会自己归一化），一条永远不会红的断言
            // 比没有断言更糟 —— 它让人以为这件事被盯着。对齐这半是有牙的：把编辑器换回
            // new JCheckBox() 就是 0(CENTER) vs 10(LEADING)，正是用户看到的那个跳
            check("勾选框的渲染器与编辑器水平对齐一致（不一致时点一下框会左右跳）",
                    sameAlignment,
                    "对齐 " + (rendered instanceof JCheckBox ? ((JCheckBox) rendered).getHorizontalAlignment() : "?")
                            + " vs " + (editing instanceof JCheckBox ? ((JCheckBox) editing).getHorizontalAlignment() : "?"));
        }
        // URL 列必须是**唯一**会被拉长的列：其余列全封了 maxWidth，多余宽度只能落到 URL 上 ——
        // 用户反馈「url 列左右太短，长 URL 显示不完」（2026-09-24）。谁把封顶去掉一列，这里就红。
        final int urlColumn = 3;
        final int aiTagColumn = 7;
        javax.swing.table.TableColumnModel columns = table.getColumnModel();
        List<Integer> elastic = new ArrayList<>();
        for (int i = 0; i < columns.getColumnCount(); ++i) {
            if (columns.getColumn(i).getMaxWidth() >= Integer.MAX_VALUE) {
                elastic.add(i);
            }
        }
        check("只有 URL 列会被拉长（其余列封了最大宽度，长 URL 才有地方伸）",
                elastic.equals(Collections.singletonList(urlColumn)), "会伸缩的列 " + elastic);
        check("URL 列首选宽度最大、且给了最小宽度（窄窗口下不会被压没）",
                columns.getColumn(urlColumn).getPreferredWidth() >= 500
                        && columns.getColumn(urlColumn).getPreferredWidth()
                            > columns.getColumn(aiTagColumn).getPreferredWidth()
                        && columns.getColumn(urlColumn).getMinWidth() > 100,
                "URL 首选 " + columns.getColumn(urlColumn).getPreferredWidth()
                        + " 最小 " + columns.getColumn(urlColumn).getMinWidth()
                        + "，AI标签 " + columns.getColumn(aiTagColumn).getPreferredWidth());

        // 上面两条只查属性；这条**真的把表拉宽**再看宽度落在哪 —— JTable 不认这套写法时，
        // 只有这条会红（属性对不对和多余宽度去了哪儿是两回事）
        final int[] urlNarrow = new int[1];
        final int[] urlWide = new int[1];
        final int[] tagNarrow = new int[1];
        final int[] tagWide = new int[1];
        SwingUtilities.invokeAndWait(() -> {
            table.setSize(1100, 300);
            table.doLayout();
            urlNarrow[0] = columns.getColumn(urlColumn).getWidth();
            tagNarrow[0] = columns.getColumn(aiTagColumn).getWidth();
            table.setSize(1600, 300);
            table.doLayout();
            urlWide[0] = columns.getColumn(urlColumn).getWidth();
            tagWide[0] = columns.getColumn(aiTagColumn).getWidth();
        });
        // 其余列最多只涨回自己的上限（窄的时候它们被按比例压过，所以这里可能涨一点点），
        // 多出来的宽度绝大部分必须落到 URL 上 —— 以前是所有列平分，长 URL 就被挤掉了
        boolean othersCapped = true;
        for (int i = 0; i < columns.getColumnCount(); ++i) {
            if (columns.getColumn(i).getWidth() > columns.getColumn(i).getMaxWidth()) {
                othersCapped = false;
            }
        }
        check("窗口变宽时多出来的宽度基本都给了 URL（其余列涨不过自己的上限）",
                urlWide[0] - urlNarrow[0] > 400 && tagWide[0] - tagNarrow[0] < 40 && othersCapped,
                "URL " + urlNarrow[0] + " → " + urlWide[0] + "，AI标签 " + tagNarrow[0] + " → " + tagWide[0]);
        check("最左边一列是勾选框列（Boolean 且可编辑，别的列仍然不可编辑）",
                table.getModel().getColumnClass(0) == Boolean.class
                        && table.getModel().isCellEditable(0, 0)
                        && !table.getModel().isCellEditable(0, 1),
                table.getModel().getColumnClass(0) + " / editable(0)=" + table.getModel().isCellEditable(0, 0)
                        + " editable(1)=" + table.getModel().isCellEditable(0, 1));
        int rows = table.getRowCount();
        check("表格里至少有两行任务可供勾选（前面 Proxy 自动扫描的用例建的）", rows >= 2,
                "只有 " + rows + " 行");
        if (rows < 2) {
            return;
        }
        com.zackai.ui.TaskTablePanel tablePanel =
                (com.zackai.ui.TaskTablePanel) SwingUtilities.getAncestorOfClass(
                        com.zackai.ui.TaskTablePanel.class, table);
        check("能拿到表格所在的面板", tablePanel != null, "没找到");
        if (tablePanel == null) {
            return;
        }
        // 下面每一步都读写表格模型，必须整个放 EDT：TaskTablePanel 不做 EDT 派发（EDT 安全是调用方的
        // 契约），而 MainPanel 每秒有一次 refreshAllTasks 在 EDT 上跑 —— 主线程直接改模型会和它交错，
        // 断言就变成时灵时不灵（第一版就是这么写的，同一份代码跑两次结果不一样，才发现的）
        SwingUtilities.invokeAndWait(() -> {
            try {
                java.lang.reflect.Method targets =
                        com.zackai.ui.TaskTablePanel.class.getDeclaredMethod("actionTargets");
                targets.setAccessible(true);
                java.lang.reflect.Method filterTasks =
                        com.zackai.ui.TaskTablePanel.class.getDeclaredMethod("filterTasks");
                filterTasks.setAccessible(true);

                table.setValueAt(Boolean.TRUE, 0, 0);
                table.setValueAt(Boolean.TRUE, 1, 0);
                check("勾上两行后，批量操作的目标是两个任务（此前只会操作一个）",
                        ((List<?>) targets.invoke(tablePanel)).size() == 2,
                        "拿到 " + ((List<?>) targets.invoke(tablePanel)).size() + " 个");

                // 搜索/筛选会 setRowCount(0) 重建模型：勾选状态在集合里，所以必须原样还在
                filterTasks.invoke(tablePanel);
                check("重建模型（搜索/筛选变化）之后勾选没丢",
                        Boolean.TRUE.equals(table.getValueAt(0, 0))
                                && Boolean.TRUE.equals(table.getValueAt(1, 0)),
                        table.getValueAt(0, 0) + " / " + table.getValueAt(1, 0));
                check("重建模型之后批量目标仍然是两个",
                        ((List<?>) targets.invoke(tablePanel)).size() == 2,
                        "拿到 " + ((List<?>) targets.invoke(tablePanel)).size() + " 个");

                table.setValueAt(Boolean.FALSE, 0, 0);
                table.setValueAt(Boolean.FALSE, 1, 0);
                table.setRowSelectionInterval(1, 1);
                check("一个都没勾时退回光标/选中那一行（保留原来的单行操作习惯）",
                        ((List<?>) targets.invoke(tablePanel)).size() == 1,
                        "拿到 " + ((List<?>) targets.invoke(tablePanel)).size() + " 个");

                // 筛选下拉：装的是 TaskFilter 枚举（显示由渲染器翻），判定读枚举。
                // 这条路径以前没测过 —— 而它正是「换语言后筛选静默失效」的风险点：
                // 判定若回头去比显示文案，英文界面下会全部放行。
                JComboBox<?> filterCombo = (JComboBox<?>) find(tablePanel, JComboBox.class, c -> true);
                check("任务页有筛选下拉", filterCombo != null, "没找到");
                if (filterCombo != null) {
                    int allCount = table.getRowCount();
                    filterCombo.setSelectedIndex(5);   // WITHOUT_VULN（已在 EDT 上，别再套 invokeAndWait —— 会自锁）
                    int withoutVuln = table.getRowCount();
                    check("筛选「无漏洞」能筛出当前任务（说明判定确实跑通了）",
                            withoutVuln == allCount && allCount > 0, "全部=" + allCount + " 无漏洞=" + withoutVuln);
                    filterCombo.setSelectedIndex(4);   // WITH_VULN
                    check("筛选「有漏洞」时无漏洞的任务被滤掉",
                            table.getRowCount() == 0, "还剩 " + table.getRowCount() + " 行");
                    filterCombo.setSelectedIndex(0);   // ALL
                    check("筛回「全部」行数复原", table.getRowCount() == allCount,
                            "全部=" + allCount + " 当前=" + table.getRowCount());
                }

                // 右键点哪行就该操作哪行：setComponentPopupMenu 不会替我们选行
                table.setRowSelectionInterval(0, 0);
                int y = table.getRowHeight() + 5;                  // 第 2 行内部
                int hitRow = table.rowAtPoint(new java.awt.Point(5, y));
                if (hitRow >= 0) {
                    MouseEvent rightRelease = new MouseEvent(table, MouseEvent.MOUSE_RELEASED,
                            System.currentTimeMillis(), 0, 5, y, 1, true, MouseEvent.BUTTON3);
                    for (MouseListener listener : table.getMouseListeners()) {
                        listener.mouseReleased(rightRelease);
                    }
                    check("右键落在第 2 行时选中的就是第 2 行（不会去操作上次点过的那行）",
                            table.getSelectedRow() == hitRow,
                            "选中=" + table.getSelectedRow() + " 命中=" + hitRow);
                } else {
                    check("表格未布局时跳过「右键选中光标行」断言（离线环境限制）", true, "");
                }
                table.setValueAt(Boolean.FALSE, 0, 0);
                table.setValueAt(Boolean.FALSE, 1, 0);
            } catch (Exception e) {
                check("勾选/批量操作的断言执行失败", false, String.valueOf(e));
            }
        });
    }

    /**
     * AI 服务商预设。这份清单是**手工维护的枚举**，写错一个字符的症状是运行时一句含糊的
     * 「验证 Key 失败」，很难往回追 —— 所以这里把值和约束都钉住。
     *
     * <p>下面这些地址在 2026-09-23 逐个**实测**过：不带凭据请求时返回 401/403/400（或 MiniMax 那种
     * HTTP 200 + base_resp 错误信封）都说明路径存在，返回 404 才是地址错了。两家国际厂商的地址另外
     * 对过官方文档。**改任何一个地址都应该重新实测一遍**，而不是把断言改绿了事。
     */
    static void checkProviderPresets() {
        List<com.zackai.model.AIProvider> providers = com.zackai.model.AIProvider.getDefaultProviders();
        Map<String, String[]> expected = new LinkedHashMap<String, String[]>();
        expected.put("ChatGPT (OpenAI)", new String[]{
                "https://api.openai.com/v1/chat/completions", "https://api.openai.com/v1/models"});
        expected.put("Anthropic (Claude)", new String[]{
                "https://api.anthropic.com/v1/messages", "https://api.anthropic.com/v1/models"});
        expected.put("通义千问 (Qwen)", new String[]{
                "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
                "https://dashscope.aliyuncs.com/compatible-mode/v1/models"});
        expected.put("智谱 GLM-5", new String[]{
                "https://open.bigmodel.cn/api/paas/v4/chat/completions",
                "https://open.bigmodel.cn/api/paas/v4/models"});
        expected.put("Kimi (月之暗面)", new String[]{
                "https://api.moonshot.cn/v1/chat/completions", "https://api.moonshot.cn/v1/models"});
        expected.put("DeepSeek", new String[]{
                "https://api.deepseek.com/v1/chat/completions", "https://api.deepseek.com/v1/models"});
        expected.put("MiniMax", new String[]{
                "https://api.minimax.chat/v1/text/chatcompletion_v2", "https://api.minimax.chat/v1/models"});

        check("服务商比之前多了两家（ChatGPT / Anthropic）", providers.size() == expected.size() + 1,
                "共 " + providers.size() + " 个：" + providerNames(providers));
        check("「自定义」仍然排在最后（配置页那个下拉框靠它认位置）",
                "自定义".equals(providers.get(providers.size() - 1).getName()),
                String.valueOf(providers.get(providers.size() - 1).getName()));

        for (com.zackai.model.AIProvider provider : providers) {
            String[] want = expected.get(provider.getName());
            if (want == null) {
                continue;                                   // 「自定义」没有固定地址
            }
            check("「" + provider.getName() + "」的对话接口地址没变",
                    want[0].equals(provider.getApiEndpoint()), provider.getApiEndpoint());
            check("「" + provider.getName() + "」的模型接口地址没变",
                    want[1].equals(provider.getModelsEndpoint()), provider.getModelsEndpoint());
        }

        for (com.zackai.model.AIProvider provider : providers) {
            String api = provider.getApiEndpoint() == null ? "" : provider.getApiEndpoint();
            String models = provider.getModelsEndpoint() == null ? "" : provider.getModelsEndpoint();
            check("「" + provider.getName() + "」两个地址都是 https 且非空",
                    api.startsWith("https://") && models.startsWith("https://"),
                    api + " | " + models);
            // 模型接口必须挂在对话接口的同一个版本前缀下：抄错一家（比如把 models 指到别家）
            // 时，「获取模型」会成功但模型列表是另一家的 —— 这条能当场抓住
            String prefix = apiPrefixUpToVersion(api);
            check("「" + provider.getName() + "」的模型接口与对话接口同源同版本前缀",
                    prefix.isEmpty() || models.startsWith(prefix), "前缀 " + prefix + " vs " + models);
            // 与 AuthHeaders / buildAIRequest 的耦合：这两处都是按地址子串分派的
            if (provider.getName().startsWith("Anthropic")) {
                check("Anthropic 地址含 anthropic.com（不然发的是 Bearer 而不是 x-api-key，"
                                + "请求体也不会改成顶层 system）",
                        api.contains("anthropic.com"), api);
            } else if (!provider.getName().equals("自定义")) {
                check("「" + provider.getName() + "」地址不含 anthropic.com / openai.azure.com"
                                + "（含了就会命中另外两条认证分支）",
                        !api.contains("anthropic.com") && !api.contains("openai.azure.com"), api);
            }
        }
    }

    /**
     * 请求体里的长度/采样参数按**模型**分派，而不是按端点、更不能全局统一。
     *
     * <p>OpenAI 的推理模型（o 系列 / gpt-5）拒收 {@code max_tokens}，也拒收 {@code temperature}，
     * 少改一个照样 400；而 DeepSeek/Kimi/智谱/通义/MiniMax 和自建端点只认 {@code max_tokens}。
     * 症状都只是「AI 调用失败」，看不出是参数名的问题 —— 所以三种目标各钉一条。
     *
     * <p>这条放在 ExtenderHarness 里是因为要改配置对象（它把 user.home 指到临时目录，
     * 碰不到真实配置）；纯函数 isReasoningModel 顺带一起验。
     */
    /** 请求体里是不是带了「关思考」的 {@code thinking.type=disabled} */
    private static boolean thinkingDisabledIn(com.google.gson.JsonObject body) {
        if (!body.has("thinking") || !body.get("thinking").isJsonObject()) {
            return false;
        }
        com.google.gson.JsonObject thinking = body.getAsJsonObject("thinking");
        return thinking.has("type") && "disabled".equals(thinking.get("type").getAsString());
    }

    static void checkAiRequestParams() throws Exception {
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        String savedEndpoint = config.getApiEndpoint();
        String savedModel = config.getSelectedAgent();
        String savedProvider = config.getSelectedProvider();
        AIEngine engine = new AIEngine(null, null, new LogPanel(), null);
        java.lang.reflect.Method build = AIEngine.class.getDeclaredMethod(
                "buildAIRequest", String.class, String.class);
        build.setAccessible(true);
        try {
            config.setApiEndpoint("https://api.openai.com/v1/chat/completions");
            config.setSelectedProvider("ChatGPT (OpenAI)");
            for (String reasoning : new String[]{"o1", "o3-mini", "o4-mini", "gpt-5", "gpt-5.2-mini"}) {
                config.setSelectedAgent(reasoning);
                com.google.gson.JsonObject body = (com.google.gson.JsonObject) build.invoke(engine, "sys", "user");
                check("推理模型 " + reasoning + " → 发 max_completion_tokens，且不发 max_tokens / temperature",
                        body.has("max_completion_tokens") && !body.has("max_tokens")
                                && !body.has("temperature"),
                        body.toString());
                check("推理模型 " + reasoning + " → 额度是 16384（思维链共用这份额度，8192 会被思考吃光）"
                                + "且带 reasoning_effort=low",
                        body.get("max_completion_tokens").getAsInt() == 16384
                                && body.has("reasoning_effort")
                                && "low".equals(body.get("reasoning_effort").getAsString()),
                        body.toString());
            }
            for (String plain : new String[]{"gpt-4o", "gpt-4.1", "gpt-4o-mini"}) {
                config.setSelectedAgent(plain);
                com.google.gson.JsonObject body = (com.google.gson.JsonObject) build.invoke(engine, "sys", "user");
                check("非推理模型 " + plain + " → 仍是 max_tokens + temperature（第三方兼容端点只认它）",
                        body.has("max_tokens") && body.has("temperature")
                                && !body.has("max_completion_tokens"),
                        body.toString());
                check("非推理模型 " + plain + " → 额度仍是 8192，且不带 reasoning_effort（它不认这个参数）",
                        body.get("max_tokens").getAsInt() == 8192 && !body.has("reasoning_effort"),
                        body.toString());
            }

            // 「关思考」是一张厂商表（每家的参数名都不一样），不是常量。
            // DeepSeek 原生 / Kimi / 智谱 / MiniMax 都认 thinking.type=disabled。
            config.setApiEndpoint("https://api.deepseek.com/v1/chat/completions");
            config.setSelectedProvider("DeepSeek");
            for (String ds : new String[]{"deepseek-flash", "deepseek-chat"}) {
                config.setSelectedAgent(ds);
                com.google.gson.JsonObject dsBody = (com.google.gson.JsonObject) build.invoke(engine, "sys", "user");
                check("DeepSeek " + ds + " → 关思考用 thinking.type=disabled，保持 max_tokens"
                                + "（换成 max_completion_tokens 就是 400），且不再发 reasoning_effort"
                                + "（实测 low 在这个模型上不生效）",
                        thinkingDisabledIn(dsBody) && dsBody.has("max_tokens")
                                && !dsBody.has("max_completion_tokens") && !dsBody.has("reasoning_effort"),
                        dsBody.toString());
                check("DeepSeek " + ds + " → 额度仍是 8192（思考是「撑满额度」，抬额度只会让它想更久）",
                        dsBody.get("max_tokens").getAsInt() == 8192, dsBody.toString());
            }
            // 通义 DashScope（含阿里云上托管的 DeepSeek）：参数名不一样
            config.setApiEndpoint("https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions");
            config.setSelectedProvider("通义千问 (Qwen)");
            config.setSelectedAgent("qwen3-max");
            com.google.gson.JsonObject qwenBody = (com.google.gson.JsonObject) build.invoke(engine, "sys", "user");
            check("通义 DashScope → 用 enable_thinking=false（它不认 thinking.type）",
                    qwenBody.has("enable_thinking") && !qwenBody.get("enable_thinking").getAsBoolean()
                            && !qwenBody.has("thinking"),
                    qwenBody.toString());
            // 未知端点（自定义 / 自建）：按多数派发 thinking.type=disabled；拒收它的端点由
            // callAI 的 400 兜底去掉并记住 —— 没有那道兜底，表里任何一格填错都等于整体不可用
            config.setApiEndpoint("https://my-gateway.internal/v1/chat/completions");
            config.setSelectedProvider("自定义");
            config.setSelectedAgent("some-thinking-model");
            com.google.gson.JsonObject custom = (com.google.gson.JsonObject) build.invoke(engine, "sys", "user");
            check("自定义/未知端点也发 thinking.type=disabled（兼容端点会忽略，拒收的交给兜底）",
                    thinkingDisabledIn(custom), custom.toString());
            // 反向：OpenAI 普通模型不该收到这个字段（它可能拒收不认识的字段）
            config.setApiEndpoint("https://api.openai.com/v1/chat/completions");
            config.setSelectedProvider("ChatGPT (OpenAI)");
            config.setSelectedAgent("gpt-4o");
            com.google.gson.JsonObject openaiPlain = (com.google.gson.JsonObject) build.invoke(engine, "sys", "user");
            check("OpenAI 普通模型不带 thinking 字段",
                    !openaiPlain.has("thinking") && !openaiPlain.has("enable_thinking"),
                    openaiPlain.toString());

            // Anthropic：Claude 只认 max_tokens，哪怕模型名长得像推理模型
            config.setApiEndpoint("https://api.anthropic.com/v1/messages");
            config.setSelectedProvider("Anthropic (Claude)");
            config.setSelectedAgent("o3-mini");
            com.google.gson.JsonObject anthropicBody =
                    (com.google.gson.JsonObject) build.invoke(engine, "sys", "user");
            check("Anthropic 端点上永远用 max_tokens（Claude 不认 max_completion_tokens）",
                    anthropicBody.has("max_tokens") && !anthropicBody.has("max_completion_tokens")
                            && anthropicBody.has("system"),
                    anthropicBody.toString());
            check("Anthropic 不按推理档给额度、也不发 reasoning_effort / thinking"
                            + "（Claude 不开 thinking 就没有思维链开销，且它的非流式本来就别超 16K）",
                    anthropicBody.get("max_tokens").getAsInt() == 8192
                            && !anthropicBody.has("reasoning_effort")
                            && !anthropicBody.has("thinking"),
                    anthropicBody.toString());
            config.setApiEndpoint("https://api.openai.com/v1/chat/completions");
            config.setSelectedProvider("ChatGPT (OpenAI)");
            config.setSelectedAgent("gpt-5");
            com.google.gson.JsonObject oSeriesBody = (com.google.gson.JsonObject) build.invoke(engine, "sys", "user");
            check("OpenAI 推理模型不带 thinking 字段（gpt-5.x 拒收「关」参数），改为 reasoning_effort=low",
                    !oSeriesBody.has("thinking") && oSeriesBody.has("reasoning_effort")
                            && "low".equals(oSeriesBody.get("reasoning_effort").getAsString()),
                    oSeriesBody.toString());

            java.lang.reflect.Method reasoningOf = AIEngine.class.getDeclaredMethod("isReasoningModel", String.class);
            reasoningOf.setAccessible(true);
            check("模型名判定不会误伤 gpt-4o / omni / 空值",
                    !((Boolean) reasoningOf.invoke(null, "gpt-4o"))
                            && !((Boolean) reasoningOf.invoke(null, "gpt-4o-mini"))
                            && !((Boolean) reasoningOf.invoke(null, "omni-moderation-latest"))
                            && !((Boolean) reasoningOf.invoke(null, "claude-sonnet-5"))
                            && !((Boolean) reasoningOf.invoke(null, (String) null))
                            && !((Boolean) reasoningOf.invoke(null, "  ")),
                    "判定有误");
        } finally {
            config.setApiEndpoint(savedEndpoint);
            config.setSelectedAgent(savedModel);
            config.setSelectedProvider(savedProvider);
        }
    }

    /** 对话接口地址里到「版本段」为止的前缀，如 https://api.openai.com/v1/ ；找不到版本段返回空串 */
    static String apiPrefixUpToVersion(String url) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("^(https://[^/]+/(?:[^/]+/)*?v\\d+/)").matcher(url);
        return m.find() ? m.group(1) : "";
    }

    static String providerNames(List<com.zackai.model.AIProvider> providers) {
        StringBuilder sb = new StringBuilder();
        for (com.zackai.model.AIProvider provider : providers) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(provider.getName());
        }
        return sb.toString();
    }

    /** 下拉框里有没有这一项（按字符串比，因为 addItem 进去的就是名字） */
    static boolean comboHasItem(JComboBox<?> combo, String item) {
        for (int i = 0; i < combo.getItemCount(); ++i) {
            if (item.equals(String.valueOf(combo.getItemAt(i)))) {
                return true;
            }
        }
        return false;
    }

    static void drainEdt() throws Exception {
        SwingUtilities.invokeAndWait(() -> { });
    }

    /**
     * {@code MainPanel.addRequest} 有没有被走到 —— 它每条失败路径都会 {@code printError}
     * 一行以「[添加请求错误]」开头的消息。
     *
     * <p>「没建任务」这种断言本身分不清「被闸门挡了」和「进了 addRequest 但半路失败」，
     * 这个判断就是用来分开它们的。不能用「printError 为空」代替：早先建出来的任务此刻正在被
     * 后台线程扫，桩的 {@code makeHttpRequest} 抛异常也会打 printError，那种噪声与本次断言无关。
     */
    static boolean reachedAddRequest(List<String> errors) {
        for (String e : errors) {
            if (e.contains("[添加请求错误]")) {
                return true;
            }
        }
        return false;
    }

    /** 造一条假的代理消息（请求字节 + host/port），等价于 Burp 的 {@code IInterceptedProxyMessage}。 */
    static IInterceptedProxyMessage fakeProxyMessage(String rawRequest, String host, int port) {
        IHttpService service = (IHttpService) Proxy.newProxyInstance(
                ExtenderHarness.class.getClassLoader(), new Class[]{IHttpService.class},
                (p, m, a) -> {
                    switch (m.getName()) {
                        case "getHost": return host;
                        case "getPort": return port;
                        case "getProtocol": return port == 443 ? "https" : "http";
                        default: return null;
                    }
                });
        IHttpRequestResponse info = (IHttpRequestResponse) Proxy.newProxyInstance(
                ExtenderHarness.class.getClassLoader(), new Class[]{IHttpRequestResponse.class},
                (p, m, a) -> {
                    switch (m.getName()) {
                        case "getRequest": return rawRequest.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        case "getResponse": return null;
                        case "getHttpService": return service;
                        default: return null;
                    }
                });
        return (IInterceptedProxyMessage) Proxy.newProxyInstance(
                ExtenderHarness.class.getClassLoader(), new Class[]{IInterceptedProxyMessage.class},
                (p, m, a) -> "getMessageInfo".equals(m.getName()) ? info : null);
    }

    /**
     * {@code helpers.analyzeRequest} 的最小实现：只认请求行里的查询串、{@code Cookie:} 头、
     * 以及 urlencoded 请求体，产出带参数的 {@link IRequestInfo}。
     *
     * <p>桩的解析**刻意做得笨**（不做百分号解码、不识别 JSON/XML/multipart）—— 这里要验的是
     * 「闸门有没有去问参数表、拿到参数之后建不建任务」，不是「Burp 怎么解析 HTTP」。
     * 真按 Burp 的解析写一份桩，就变成在测桩而不是测代码了。
     *
     * <p>Cookie 会作为 {@code PARAM_COOKIE} 报出来（Burp 就是这么报的），
     * 而闸门要把它排除掉 —— 这条差异必须让桩如实呈现，否则那条断言是假的。
     */
    static IRequestInfo stubRequestInfo(byte[] request) {
        String raw = new String(request, java.nio.charset.StandardCharsets.ISO_8859_1);
        int headEnd = raw.indexOf("\r\n\r\n");
        String head = headEnd < 0 ? raw : raw.substring(0, headEnd);
        String body = headEnd < 0 ? "" : raw.substring(headEnd + 4);
        List<Object> params = new ArrayList<>();
        String[] lines = head.split("\r\n");
        if (lines.length > 0) {
            String[] parts = lines[0].split(" ");
            if (parts.length > 1) {
                int q = parts[1].indexOf('?');
                if (q >= 0) {
                    addStubParams(params, parts[1].substring(q + 1), IParameter.PARAM_URL);
                }
            }
        }
        for (int i = 1; i < lines.length; i++) {
            if (lines[i].toLowerCase().startsWith("cookie:")) {
                addStubParams(params, lines[i].substring(7).trim().replace(';', '&'), IParameter.PARAM_COOKIE);
            }
        }
        if (!body.isEmpty()) {
            addStubParams(params, body, IParameter.PARAM_BODY);
        }
        return (IRequestInfo) Proxy.newProxyInstance(
                ExtenderHarness.class.getClassLoader(), new Class[]{IRequestInfo.class},
                (p, m, a) -> {
                    if ("getParameters".equals(m.getName())) {
                        return params;
                    }
                    throw new UnsupportedOperationException(m.getName());
                });
    }

    // 注意类型是 byte 不是 int：Burp 的 IParameter.getType() 返回 byte，桩返回 Integer 的话
    // 动态代理每次读 getType() 都会 ClassCastException，而闸门是 fail-open 的 —— 异常会被吞掉、
    // 表现成「闸门没生效」，且只有当参数列表非空时才会暴露。
    private static void addStubParams(List<Object> out, String encoded, byte type) {
        for (String pair : encoded.split("&")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String name = eq < 0 ? pair : pair.substring(0, eq);
            if (name.isEmpty()) continue;
            String value = eq < 0 ? null : pair.substring(eq + 1);
            out.add(stubParameter(name, value, type));
        }
    }

    private static Object stubParameter(String name, String value, byte type) {
        return Proxy.newProxyInstance(ExtenderHarness.class.getClassLoader(),
                new Class[]{IParameter.class}, (p, m, a) -> {
                    switch (m.getName()) {
                        case "getName": return name;
                        case "getValue": return value;
                        case "getType": return type;
                        default: throw new UnsupportedOperationException(m.getName());
                    }
                });
    }

    /**
     * 顶栏「外带」那一格：显示当前用的回连服务，并且**跟着配置页里的开关走**。
     *
     * <p>后半句才是重点：开关一变而顶栏还写着 dnslog.org，等于告诉用户「正在往外发」，
     * 而实际上插件已经不发任何外带载荷了 —— 一个纯粹由新增代码引入、且不会自己报错的错误。
     *
     * <p>初始状态是关的：{@link #disableOob()} 已经把一个 {@code oobEnabled:false} 的文件
     * 写进临时 home，加载路径会把它读进来（所以这里不能假设默认是开）。
     */
    static void checkTopBarOobLabel(Component suiteUi, Component configUi) throws Exception {
        JLabel oobLabel = (JLabel) find(suiteUi, JLabel.class, c -> ((JLabel) c).getText() != null
                && ((JLabel) c).getText().startsWith("外带"));
        check("顶栏有「外带」状态格（显示当前回连服务）", oobLabel != null,
                "没找到以「外带」开头的 JLabel");
        JCheckBox oobBox = (JCheckBox) find(configUi, JCheckBox.class, c -> true);
        check("配置页里有外带回连开关", oobBox != null, String.valueOf(configUi));
        if (oobLabel == null || oobBox == null) {
            return;
        }
        String host = OASTClient.DEFAULT_SERVER.substring(OASTClient.DEFAULT_SERVER.indexOf("://") + 3);
        check("顶栏不再有「配置」按钮（配置本身是标签页）",
                find(suiteUi, JButton.class, c -> "配置".equals(((JButton) c).getText())) == null, "按钮还在");
        check("外带关着时顶栏显示「已关闭」而不是供应商名", oobLabel.getText().contains("已关闭"), oobLabel.getText());

        SwingUtilities.invokeAndWait(() -> oobBox.doClick());     // 拨到开
        check("拨开开关后顶栏立刻显示回连服务（不等「保存配置」）",
                oobLabel.getText().contains(host), oobLabel.getText());

        SwingUtilities.invokeAndWait(() -> oobBox.doClick());     // 拨回关（后面的检查别再动配置）
        check("再拨回去立刻变回「已关闭」", oobLabel.getText().contains("已关闭"), oobLabel.getText());
    }

    /** 在组件树里按类型 + 条件找第一个匹配的组件。 */
    static Component find(Component root, Class<?> type, java.util.function.Predicate<Component> match) {
        if (root == null) {
            return null;
        }
        if (type.isInstance(root) && match.test(root)) {
            return root;
        }
        if (root instanceof Container) {
            for (Component child : ((Container) root).getComponents()) {
                Component found = find(child, type, match);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    static String tabTitles(JTabbedPane tabs) {
        List<String> titles = new ArrayList<>();
        for (int i = 0; i < tabs.getTabCount(); i++) {
            titles.add(tabs.getTitleAt(i));
        }
        return titles.toString();
    }

    static JTabbedPane findTabbedPane(Component c) {
        if (c instanceof JTabbedPane) {
            return (JTabbedPane) c;
        }
        if (c instanceof Container) {
            for (Component child : ((Container) c).getComponents()) {
                JTabbedPane found = findTabbedPane(child);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    // ------------------------------------------------------------------ 配置落盘

    /**
     * 外带回连开关的持久化：默认启用、写下去能读回来、历史键 {@code oastEnabled} 不生效。
     *
     * <p>全程在临时目录里做：把 {@code user.home} 指到临时目录后 `init(null)` 重新解析路径，
     * 断言完再恢复并重新加载 —— **绝不动调用者真实的 {@code ~/.zack-ai-scanner-config}**。
     * 这条路径值得测是因为老版本在这里翻过车（配置文件里残留一个 false 就让外带静默失效）。
     */
    static void checkConfigSwitch() throws Exception {
        String realHome = System.getProperty("user.home");
        java.nio.file.Path tempHome = java.nio.file.Files.createTempDirectory("zackai-config-test");
        ConfigManager manager = ConfigManager.getInstance();
        try {
            System.setProperty("user.home", tempHome.toString());
            manager.init(null);                       // 不存在配置文件 → 默认值
            check("新装（没有配置文件）时外带回连默认启用", manager.getConfig().isOobEnabled(), "默认是关的");

            manager.getConfig().setOobEnabled(false);
            manager.saveConfig();
            java.nio.file.Path file = tempHome.resolve(com.zackai.core.ConfigManager.CONFIG_FILE_NAME);
            String json = new String(java.nio.file.Files.readAllBytes(file),
                    java.nio.charset.StandardCharsets.UTF_8);
            check("关掉后立刻写进配置文件", json.contains("\"oobEnabled\": false"), json);
            manager.loadConfig();
            check("重新读回来仍然是关的（开关确实落了盘）", !manager.getConfig().isOobEnabled(), "读回来变成开的了");

            java.nio.file.Files.write(file,
                    "{\"oastEnabled\":false,\"apiKey\":\"keep-me\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            manager.loadConfig();
            check("历史键 oastEnabled=false 不生效（老配置文件不会静默关掉外带）",
                    manager.getConfig().isOobEnabled(), "被历史键关掉了");
            check("同一次读取不会丢掉别的键", "keep-me".equals(manager.getConfig().getApiKey()),
                    String.valueOf(manager.getConfig().getApiKey()));

            // Proxy 自动扫描：默认必须是关 —— 打开意味着每个经过代理的请求都会自动向目标发包
            check("新装（没有配置文件）时 Proxy 自动扫描默认关闭", !manager.getConfig().isAutoScanProxy(),
                    "默认是开的：升级后随手开个浏览器就会自动打出去");
            manager.getConfig().setAutoScanProxy(true);
            manager.getConfig().setAutoScanWhitelist("lab.test, 10.0.0.5");
            manager.saveConfig();
            manager.loadConfig();
            check("Proxy 自动扫描与白名单都能落盘读回",
                    manager.getConfig().isAutoScanProxy() && "lab.test, 10.0.0.5".equals(manager.getConfig().getAutoScanWhitelist()),
                    manager.getConfig().getAutoScanWhitelist());
            manager.getConfig().setAutoScanProxy(false);
            manager.getConfig().setAutoScanWhitelist("");
            manager.saveConfig();

            // 界面语言。注意缺键时**不能**断言 isEn() —— 那表示「用户没选过」，
            // 语言跟随操作系统，取决于跑 harness 的机器（本项目开发机是 en_US）。
            // 只有显式值才决定语言，所以这里断言的是「值」与「显式设置后的效果」。
            java.nio.file.Files.write(file, "{\"oobEnabled\":false}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            manager.loadConfig();
            check("老配置里没有语言键 = 未选择（跟随系统，不写死语言）",
                    manager.getConfig().getUiLanguage().isEmpty(),
                    "得到「" + manager.getConfig().getUiLanguage() + "」");

            manager.getConfig().setUiLanguage("en");
            manager.saveConfig();
            manager.loadConfig();
            Msg.init(manager.getConfig().getUiLanguage());
            check("选英文后落盘、读回仍是英文", Msg.isEn() && "en".equals(manager.getConfig().getUiLanguage()),
                    "读到「" + manager.getConfig().getUiLanguage() + "」");

            java.nio.file.Files.write(file, "{\"uiLanguage\":null}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            manager.loadConfig();
            check("手改成 null 的语言值按「未选择」处理（getter 兜底，不抛 NPE）",
                    manager.getConfig().getUiLanguage().isEmpty(),
                    "得到「" + manager.getConfig().getUiLanguage() + "」");

            manager.getConfig().setUiLanguage("zh");
            manager.saveConfig();
            manager.loadConfig();
            Msg.init(manager.getConfig().getUiLanguage());
            check("切回中文后立刻生效（语言不能只单向生效）", !Msg.isEn(), "还是英文");
        } finally {
            System.setProperty("user.home", realHome);
            manager.init(null);                       // 路径还原（后面的段落可能还要用配置）
            pinChinese();                             // 语言也还原：后面各段断言的都是中文界面文案
        }
    }

    // ------------------------------------------------------------------ 导出范围

    /**
     * 「导出选中任务」必须导出**全部勾选的任务**，不是第一个。
     *
     * <p>这是一个真实报过的 bug：{@code TaskTablePanel.showExportDialog} 只把
     * {@code targets.get(0)} 交给对话框，勾三个只导出一个，导出的是哪个还取决于勾选顺序。
     * 之所以长期没被发现，是因为 {@code ExportDialog} 是模态 {@code JDialog} —— headless
     * 下构造不出来，整条路径没有自动化覆盖。判定逻辑因此抽成了静态方法，这里直接测它。
     */
    static void checkExportScope() throws Exception {
        List<ScanTask> selected = new ArrayList<>();
        for (int i = 1; i <= 3; i++) {
            selected.add(namedTask(i, ScanTask.VulnLevel.NONE, null));
        }
        List<ScanTask> all = new ArrayList<>(selected);
        all.add(namedTask(4, ScanTask.VulnLevel.HIGH, "SQL注入"));
        all.add(namedTask(5, ScanTask.VulnLevel.LOW, "XSS跨站脚本"));

        java.lang.reflect.Method collect = Class.forName("com.zackai.ui.ExportDialog")
                .getDeclaredMethod("collectTasksToExport", boolean.class, List.class, List.class,
                        String.class, String.class);
        collect.setAccessible(true);

        List<?> picked = (List<?>) collect.invoke(null, true, selected, all, "__all_levels__", "__all_types__");
        check("勾选 3 个任务导出 3 个（不是只导第一个）", picked.size() == 3, "只导出了 " + picked.size() + " 个");

        List<?> onlyOne = (List<?>) collect.invoke(null, true, java.util.Collections.singletonList(selected.get(0)),
                all, "__all_levels__", "__all_types__");
        check("只勾 1 个时导出 1 个", onlyOne.size() == 1, "导出了 " + onlyOne.size() + " 个");

        List<?> allScope = (List<?>) collect.invoke(null, false, selected, all, "__all_levels__", "__all_types__");
        check("「全部任务」不受勾选影响（导出 5 个）", allScope.size() == 5, "导出了 " + allScope.size() + " 个");

        List<?> byLevel = (List<?>) collect.invoke(null, false, selected, all, "HIGH", "__all_types__");
        check("按等级筛选只导出高危那一个", byLevel.size() == 1, "导出了 " + byLevel.size() + " 个");

        List<?> byType = (List<?>) collect.invoke(null, false, selected, all, "__all_levels__", "XSS跨站脚本");
        check("按类型筛选只导出该类型那一个", byType.size() == 1, "导出了 " + byType.size() + " 个");

        List<?> neither = (List<?>) collect.invoke(null, false, selected, all, "CRITICAL", "SQL注入");
        check("等级与类型同时筛且互相排斥时导出 0 个", neither.isEmpty(), "导出了 " + neither.size() + " 个");

        List<?> emptySel = (List<?>) collect.invoke(null, true, new ArrayList<ScanTask>(), all,
                "__all_levels__", "__all_types__");
        check("勾选集为空时退回按筛选导出全部（不会导出 0 个）", emptySel.size() == 5, "导出了 " + emptySel.size() + " 个");
    }

    static ScanTask namedTask(int id, ScanTask.VulnLevel level, String vulnName) {
        ScanTask task = new ScanTask(id, null, "POST", "http://t/" + id);
        task.setStatus(ScanTask.TaskStatus.FINISHED);
        task.setVulnLevel(level);
        if (vulnName != null) {
            com.zackai.model.VulnResult vuln = new com.zackai.model.VulnResult(vulnName, vulnName, level);
            task.addOrMergeVulnerability(vuln);
        }
        return task;
    }

    // ------------------------------------------------------------------ 右键菜单

    static void checkMenu() throws Exception {
        List<String> output = Collections.synchronizedList(new ArrayList<String>());
        List<String> errors = Collections.synchronizedList(new ArrayList<String>());
        disableOob();
        IBurpExtenderCallbacks callbacks = stubCallbacks(output, errors, new boolean[1], new Object[1],
                new boolean[1], new boolean[1], new String[1], new Object[1]);
        IBurpExtender extender = (IBurpExtender) Class.forName("com.zackai.AISentryExtender")
                .getDeclaredConstructor().newInstance();
        extender.registerExtenderCallbacks(callbacks);
        Thread.sleep(1200);
        SwingUtilities.invokeAndWait(() -> { });
        IContextMenuFactory factory = (IContextMenuFactory) extender;

        Set<String> wantedTypes = new LinkedHashSet<String>();
        for (ScanTask.ScanMode mode : ScanTask.ScanMode.values()) {
            if (!mode.isCustom()) wantedTypes.add(mode.getDisplayName());
        }

        for (int context : new int[]{0, 2, 5, 6}) {
            // 0/2 = 请求编辑器与请求查看器，5/6 = 站点地图表与 Proxy 历史。
            // 类型项是**平铺**返回的：不再自己套「Zack-AI-Scanner → 扫描漏洞类型」两层，
            // 否则叠上 Burp 按扩展名收的那一层就是三层，插件名还重复出现两次。
            List<JMenuItem> items = factory.createMenuItems(invocation(context, 1));
            Set<String> shown = new LinkedHashSet<String>();
            for (int i = 0; i < items.size() - 1; i++) {      // 末项是「AI智能扫描」（CUSTOM），不算类型项
                shown.add(items.get(i).getText());
            }
            check("context " + context + " 的 " + wantedTypes.size() + " 个类型项与枚举 displayName 完全一致",
                    shown.equals(wantedTypes), shown.toString());
            check("context " + context + " 末项是 AI智能扫描",
                    items.size() == wantedTypes.size() + 1
                            && "AI智能扫描".equals(items.get(items.size() - 1).getText()),
                    items.size() + " 项，末项 " + (items.isEmpty() ? "(空)" : items.get(items.size() - 1).getText()));
            check("context " + context + " 不再有自套的菜单层（点了就是类型）",
                    items.stream().noneMatch(i -> i instanceof JMenu),
                    "还留着 " + items.stream().filter(i -> i instanceof JMenu).count() + " 个 JMenu");
        }

        // 7 = Scanner 结果列表：没有原始请求可发，不提供
        check("context 7（扫描结果）不提供菜单",
                factory.createMenuItems(invocation(7, 1)).isEmpty(), "提供了");
        check("选中项为空时不提供菜单",
                factory.createMenuItems(invocation(0, 0)).isEmpty(), "提供了");
    }

    // ------------------------------------------------------------------ 打包自检

    static void checkJar(File jar) throws Exception {
        if (!jar.isFile()) {
            check("jar 存在", false, jar.getAbsolutePath() + " 不存在");
            return;
        }
        // 父加载器置空：只有 JDK + 这个 jar（+ Burp API）能被解析 —— 依赖没打进去时这里必然失败，
        // 用默认父加载器的话 gson/okhttp 可能从外部 classpath 里被借到，检查就是假的
        java.net.URL burpApi = IBurpExtender.class.getProtectionDomain().getCodeSource().getLocation();
        ClassLoader loader = new java.net.URLClassLoader(
                new java.net.URL[]{jar.toURI().toURL(), burpApi}, null);
        Class<?> extenderInterface = Class.forName("burp.IBurpExtender", false, loader);
        int ours = 0;
        int entries = 0;
        List<String> broken = new ArrayList<String>();
        try (JarFile jarFile = new JarFile(jar)) {
            for (Enumeration<JarEntry> e = jarFile.entries(); e.hasMoreElements(); ) {
                String name = e.nextElement().getName();
                if (!name.endsWith(".class") || name.contains("META-INF/") || name.contains("module-info")) {
                    continue;
                }
                ++entries;
                String className = name.substring(0, name.length() - 6).replace('/', '.');
                if (!className.startsWith("com.zackai")) continue;   // 第三方类由各自的 harness/运行期验证
                try {
                    Class<?> type = Class.forName(className, false, loader);
                    type.getDeclaredMethods();       // 解析方法签名：缺依赖会在这里暴露
                    type.getDeclaredFields();
                    ++ours;
                    if (extenderInterface.isAssignableFrom(type) && !type.isInterface()) {
                        check("包内有且只有一个扩展入口类，且是 " + className,
                                "com.zackai.AISentryExtender".equals(className), className);
                    }
                } catch (Throwable t) {
                    broken.add(className + " → " + t);
                }
            }
        }
        check("包内 " + ours + " 个 com.zackai 类全部可加载（缺依赖会在这里失败）",
                broken.isEmpty(), String.valueOf(broken));
        check("包内一共 " + entries + " 个类（含 gson/okhttp/okio/kotlin 依赖）", entries > 1000,
                "只装了 " + entries + " 个，依赖可能没打进去");
    }

    // ------------------------------------------------------------------ 桩

    static IBurpExtenderCallbacks stubCallbacks(List<String> output, List<String> errors, boolean[] suiteTab,
                                                Object[] suiteTabComponent, boolean[] menuFactory,
                                                boolean[] stateListener, String[] extensionName,
                                                Object[] proxyListener) {
        IExtensionHelpers helpers = (IExtensionHelpers) Proxy.newProxyInstance(
                ExtenderHarness.class.getClassLoader(), new Class[]{IExtensionHelpers.class},
                (p, m, a) -> {
                    // 只实现 analyzeRequest —— Proxy 自动扫描的「有参数才建任务」闸门要问参数表。
                    // **别的照旧一律抛异常**：那条约定是「addRequest 没有偷偷依赖 Burp 的解析」的证据，
                    // 而 addRequest 是自己拆请求行的，永远不会走到这里。
                    if ("analyzeRequest".equals(m.getName()) && a != null && a.length == 1
                            && a[0] instanceof byte[]) {
                        return stubRequestInfo((byte[]) a[0]);
                    }
                    throw new UnsupportedOperationException(m.getName());
                });
        JPanel editorView = new JPanel();
        return (IBurpExtenderCallbacks) Proxy.newProxyInstance(
                ExtenderHarness.class.getClassLoader(), new Class[]{IBurpExtenderCallbacks.class},
                (p, m, a) -> {
                    switch (m.getName()) {
                        case "setExtensionName":
                            extensionName[0] = String.valueOf(a[0]);
                            return null;
                        case "getHelpers":
                            return helpers;
                        case "printOutput":
                            output.add(String.valueOf(a[0]));
                            return null;
                        case "printError":
                            errors.add(String.valueOf(a[0]));
                            return null;
                        case "addSuiteTab":
                            suiteTab[0] = true;
                            suiteTabComponent[0] = a[0];
                            return null;
                        case "registerContextMenuFactory":
                            menuFactory[0] = true;
                            return null;
                        case "registerExtensionStateListener":
                            stateListener[0] = true;
                            return null;
                        case "registerProxyListener":
                            proxyListener[0] = a[0];
                            return null;
                        case "createMessageEditor":
                            // 详情面板构造时就要两个编辑器，并会立刻 setMessage 清空显示
                            return Proxy.newProxyInstance(ExtenderHarness.class.getClassLoader(),
                                    new Class[]{IMessageEditor.class}, (p2, m2, a2) -> {
                                        switch (m2.getName()) {
                                            case "getComponent": return editorView;
                                            case "getMessage": return null;
                                            case "isMessageModified": return false;
                                            case "getController": return null;
                                            case "setMessage": return null;
                                            default: throw new UnsupportedOperationException(m2.getName());
                                        }
                                    });
                        default:
                            throw new UnsupportedOperationException(m.getName());
                    }
                });
    }

    static IContextMenuInvocation invocation(int context, int messageCount) {
        final IHttpRequestResponse[] messages = new IHttpRequestResponse[messageCount];
        for (int i = 0; i < messageCount; i++) {
            messages[i] = (IHttpRequestResponse) Proxy.newProxyInstance(ExtenderHarness.class.getClassLoader(),
                    new Class[]{IHttpRequestResponse.class},
                    (p, m, a) -> { throw new UnsupportedOperationException(m.getName()); });
        }
        return (IContextMenuInvocation) Proxy.newProxyInstance(ExtenderHarness.class.getClassLoader(),
                new Class[]{IContextMenuInvocation.class}, (p, m, a) -> {
                    switch (m.getName()) {
                        case "getInvocationContext": return (byte) context;
                        case "getSelectedMessages": return messages;
                        case "getInputEvent": return null;
                        case "getSelectionBounds": return new int[]{0, 0};
                        case "getSelectedIssues": return null;
                        case "getToolFlag": return 0;
                        default: throw new UnsupportedOperationException(m.getName());
                    }
                });
    }

    /**
     * 本 harness 全程把外带回连关掉 —— 而且必须**落进临时 home 的配置文件**里。
     *
     * <p>为什么不能只改内存：{@code registerExtenderCallbacks} 内部会 `ConfigManager.init(...)`
     * 重新从文件加载配置，内存里改的值会被文件覆盖回去，插件加载就会走
     * {@code OASTClient.selfTest()} —— 那是**真实的**一次解析 + 轮询（本机 DNS 查询 + 访问回连服务），
     * 离线 harness 不该产生这种外发流量（预置假会话也挡不住：selfTest 会真的解析、真的轮询）。
     * 开启状态下的加载路径只在 {@code OASTHarness --live} 里验证。
     */
    static void disableOob() throws Exception {
        ConfigManager.getInstance().getConfig().setOobEnabled(false);
        java.nio.file.Path home = java.nio.file.Paths.get(System.getProperty("user.home"));
        java.nio.file.Files.createDirectories(home);
        // uiLanguage 也要写进去：registerExtenderCallbacks 会按这个值调 Msg.init，
        // 缺了它语言就变成「跟随操作系统」—— 本 harness 断言的中文界面文案会随开发机 Locale 飘
        java.nio.file.Files.write(home.resolve(com.zackai.core.ConfigManager.CONFIG_FILE_NAME),
                "{\"oobEnabled\":false,\"uiLanguage\":\"zh\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * 把界面语言按死在中文上。
     *
     * <p>语言默认是「跟随操作系统语言」，而本 harness 有 25 处断言写的是中文界面文案
     * （标签页标题、顶栏格子、配置页控件…）。不按死的话，在 en_US 的机器上（比如本项目的开发机）
     * 这些断言会成片飘红，而且结果随机器变化 —— 就是 {@code checkTaskTableMultiSelect}
     * 踩过的「两次运行答案不同」那类坑。
     */
    static void pinChinese() {
        Msg.setLang("zh");
    }

    /**
     * 只允许在临时目录下运行：本 harness 会往 {@code $user.home} 写 `.zack-ai-scanner-config.json`，
     * 漏传 {@code -Duser.home=} 就会覆盖真实配置。
     */
    static void requireTempHome() {
        String home = System.getProperty("user.home");
        String tmp = System.getProperty("java.io.tmpdir");
        if (home == null || tmp == null || !home.startsWith(tmp)) {
            throw new IllegalStateException("请用 -Duser.home=临时目录 运行（当前 user.home=" + home
                    + "）：本 harness 会写配置文件，不能碰真实 home");
        }
    }

    /** 回连会话预置成假会话：即使有代码路径碰到 ensureSession()，也只命中缓存、不发请求 */
    static void seedFakeOastSession() throws Exception {
        Method testSession = OASTClient.class.getDeclaredMethod("testSession", String.class, String.class, String.class);
        testSession.setAccessible(true);
        Field session = OASTClient.class.getDeclaredField("session");
        session.setAccessible(true);
        session.set(OASTClient.shared(), testSession.invoke(null, "7f917734", "tok", "log.nat.cloudns.ph."));
    }

    /**
     * 卸载清理：{@code Msg.shutdown()} 之后不能再往绑定器表里加东西。
     *
     * <p>为什么要测：界面是在 {@code invokeLater} 里搭的。若在「注册卸载监听」与「界面真正构造完」
     * 之间卸载，清理会先跑、随后构造的面板又把自己注册回来 —— 没有任何东西会再清它，
     * 旧组件树（连同旧 classloader）就被吊住了，和当初给线程池补卸载监听是同一类问题。
     * 这条路径此前**没有任何测试触发过**。
     */
    static void checkMsgShutdown() {
        final boolean[] ran = {false};
        Msg.shutdown();
        Msg.bind(() -> ran[0] = true);
        check("卸载后 bind 仍然立即执行一次（组件文案照贴，只是不再登记）", ran[0], "没执行");
        ran[0] = false;
        Msg.setLang("en");
        check("卸载后切语言不再重译旧界面（否则旧组件树被吊住）", !ran[0], "重译跑到了已卸载的界面");
        Msg.setLang("zh");
    }

    static void check(String name, boolean ok, String detail) {
        if (ok) {
            ++passed;
            System.out.println("  ✅ " + name);
        } else {
            ++failed;
            System.out.println("  ❌ " + name + "   [" + detail + "]");
        }
    }

    static {
        try {
            seedFakeOastSession();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }
}
