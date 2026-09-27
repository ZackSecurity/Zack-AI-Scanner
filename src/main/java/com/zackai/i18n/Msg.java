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
package com.zackai.i18n;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.zackai.model.ScanTask;

/**
 * 界面文案的中英对照表 + 当前语言状态。顶栏那个切换按钮改的就是这里的 {@link #setLang}。
 *
 * <p><b>哪些走这里、哪些不走</b>：界面控件、日志消息、导出报告走这里；<b>AI 提示词不走</b>
 * （而且 {@code Msg.*} 绝不能出现在 {@code AIEngine} 那几个拼提示词的方法里 —— 提示词要保持
 * 纯中文字面量，任何插进来的调用都会让那段文本无法整段复制核对；v3.0 之前是靠
 * {@code tools/extract_prompts.py} 按源码文本抽取快照来核对的，那个脚本已随 v3.0 移除，
 * 所以这条现在是人工纪律而不是自动校验）。
 *
 * <p><b>数据层的字符串永远保持中文</b>，只在渲染时翻译：
 * {@code ScanMode.displayName}（同时是提示词里的 {漏洞类型}、任务去重键、报告修复建议的查表键）、
 * {@code AIProvider.name}（含「自定义」哨兵，会被持久化并参与比较）、
 * {@code ScanTask.aiTag}、{@code VulnResult.vulnType/vulnName}、{@code Config.selectedProvider}。
 * 这些都是「被比较或被落盘的字符串」，翻掉就断链。渲染侧用
 * {@link #typeNameOf} / {@link #displayAiTag} / {@link #scanModeName} / {@link #levelName} / {@link #statusName}
 * 套一层映射，别去改数据。
 *
 * <p><b>重译用「绑定器」而不是重建界面</b>：{@link #bind} 注册一个「把新文案贴回组件」的动作，
 * 注册时立即执行一次（构造时就把文案贴上了，不用写两遍），切语言时统一重跑。之所以不重建：
 * {@code LogPanel} 建好后被传进 {@code AIEngine}，重建会让扫描引擎继续往旧面板写日志；
 * 而且重建会丢勾选的任务、表格选中行、配置页里没保存的 API Key。
 *
 * <p><b>绑定器持有组件强引用</b>，所以只给长期存活的面板注册：{@code ExportDialog} 这类每次
 * 点开都 new 的对话框，直接在构造时读 {@link #t} 就好，注册会让绑定器无限增长。
 * 另一个后果是静态表会跨卸载存活，所以 {@link AISentryExtender} 卸载时会调 {@link #shutdown()} 清空
 * —— 不清的话旧界面的组件（连同旧 classloader）会被一直吊着。
 *
 * <p><b>key 缺失时返回 key 本身</b>并记入 {@link #missingKeys()}，harness 断言这个集合为空。
 * 一条断言同时兜住「加了控件忘了建 key」和「key 打错字」。宁可界面上出现 {@code tab.tasks}
 * 这种字样，也不要静默退回中文 —— 那样翻译没生效也看不出来。
 */
public final class Msg {

    /** key -> {中文, 英文}；两边都必须写全（漏一边 harness 的对称性断言会拦住） */
    private static final Map<String, String[]> TABLE = new LinkedHashMap<String, String[]>();
    /** 切语言时要重跑的动作（重贴组件文案） */
    private static final List<Runnable> BINDERS = new ArrayList<Runnable>();
    /** 切语言时要重跑的动作（重算派生文案：状态格、探针列表、统计数字…） */
    private static final List<Runnable> HOOKS = new ArrayList<Runnable>();
    /** 未命中的 key。**扫描线程也会写这里**（AIEngine 里上百处 Msg.t），所以必须是并发集合 ——
     *  一个打错的 key 就会让多个扫描线程同时 add 一个非同步的 Set。 */
    private static final Set<String> MISSING = java.util.concurrent.ConcurrentHashMap.newKeySet();

    /** 扫描线程也会读它（AIEngine 里 170 多处日志），必须是 volatile */
    private static volatile boolean en = false;
    /**
     * 卸载后置位：界面是在 {@code invokeLater} 里搭的，若在「注册卸载监听」与「界面真正构造完」
     * 之间卸载，{@code shutdown()} 先清空了列表、随后构造的面板又把自己注册回来 —— 没有任何东西
     * 会再清它，旧组件树（连同旧 classloader）就吊住了。置位后 bind/onLangChanged 只执行、不登记。
     */
    private static volatile boolean closed = false;

    private Msg() {
    }

    // ------------------------------------------------------------------ 取词

    /** 当前语言的文案；key 不存在时返回 key 本身并记入 {@link #missingKeys()} */
    public static String t(String key) {
        String[] pair = TABLE.get(key);
        if (pair == null) {
            MISSING.add(key);
            return key;
        }
        return en ? pair[1] : pair[0];
    }

    /** 这个 key 在表里有没有（报告修复建议是按序号逐个查、查到缺号为止） */
    public static boolean has(String key) {
        return TABLE.containsKey(key);
    }

    /**
     * 带占位符的文案：模板里写 {@code {0}}、{@code {1}}，按位置替换。
     *
     * <p>**不用 {@code String.format}**：模板里一个裸的 {@code %} 就会让它抛异常，
     * 而载荷与响应文本里到处是 {@code %}（日志文案与它们同处一个方法）；
     * 而且 {@code String.format} 还带默认 Locale 的数字格式坑（本项目已经在别处
     * 用 {@code Locale.ROOT} 绕它了）。{@code {n}} 替换两样都没有。
     */
    public static String t(String key, Object... args) {
        return fill(t(key), args);
    }

    private static final java.util.regex.Pattern PLACEHOLDER = java.util.regex.Pattern.compile("\\{(\\d+)\\}");

    /**
     * 单趟替换 {@code {0}}、{@code {1}}…。
     *
     * <p>**必须单趟**：以前是按序号循环 {@code String.replace}，于是参数值里本来就有的 {@code {N}}
     * 会被后续那一轮再替换一次 —— 渗透载荷里带花括号太常见了（SSTI 的 {@code {{1}}}、
     * 含 {@code ${1}} 的模板载荷），日志行里的载荷会被改得认不出来。
     * 单趟扫描替换结果不再回扫，就没有这个问题。
     *
     * <p>另外 {@code appendReplacement} 会把值里的 {@code $} 当组引用（载荷里 {@code ${jndi:...}}
     * 到处都是），所以必须走 {@code quoteReplacement}。序号超出参数个数时**原样保留** ——
     * 让调用点漏传参数在界面上看得见，而不是把 {@code {3}} 悄悄吞掉。
     */
    private static String fill(String template, Object... args) {
        if (args == null || args.length == 0) {
            return template;
        }
        java.util.regex.Matcher m = PLACEHOLDER.matcher(template);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            int idx = Integer.parseInt(m.group(1));
            String value = idx < args.length && args[idx] != null
                    ? String.valueOf(args[idx]) : m.group(0);
            m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(value));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    // ------------------------------------------------------------------ 语言

    public static boolean isEn() {
        return en;
    }

    /**
     * 启动时按配置值定语言。配置值为空 = 用户没选过 → <b>跟随操作系统语言</b>：
     * {@code zh*} 用中文，<b>其它一律英文</b>（只有这两种语言，日语用户看英文比看中文有用）。
     *
     * <p>**由调用方推过来，不在这里读配置** —— 静态初始化里读 {@code ConfigManager} 会形成
     * 初始化顺序依赖（配置路径还没定）。
     *
     * @param cfgValue 配置里的 {@code uiLanguage}，空串或 null 表示「未选择」
     */
    public static void init(String cfgValue) {
        if (cfgValue == null || cfgValue.isEmpty()) {
            en = !Locale.getDefault().getLanguage().toLowerCase(Locale.ROOT).startsWith("zh");
        } else {
            en = "en".equalsIgnoreCase(cfgValue);
        }
    }

    /**
     * 显式设置语言并立即重译（不落盘，落盘由调用方做）。
     *
     * <p>重译会碰 Swing 组件，所以必须落在 EDT 上：不在就转过去。
     */
    public static void setLang(String lang) {
        en = "en".equalsIgnoreCase(lang);
        runOnEdt(new Runnable() {
            @Override
            public void run() {
                applyAll();
            }
        });
    }

    // ------------------------------------------------------------------ 绑定器

    /**
     * 注册一个「重新贴文案」的动作并立即执行一次。
     * 一行一条：{@code Msg.bind(() -> button.setText(Msg.t("k")))} 既贴了初始文案，
     * 也进了切语言时的重译列表。
     */
    public static void bind(Runnable apply) {
        if (!closed) {
            BINDERS.add(apply);
        }
        apply.run();
    }

    /**
     * 注册一个「派生文案重算」动作（状态格、探针列表、统计数字这类不是组件自己存的文本）。
     *
     * <p>与 {@link #bind} 的区别：bind 管的是「组件上贴的那句话」，
     * hook 管的是「每次都要重新算出来的那句话」。前者注册即执行一次，后者只在切语言时跑
     * （构造时调用方自己算过了）。
     */
    public static void onLangChanged(Runnable hook) {
        if (!closed) {
            HOOKS.add(hook);
        }
    }

    /** 重跑全部绑定器与钩子 */
    public static void applyAll() {
        for (Runnable r : BINDERS) {
            r.run();
        }
        for (Runnable r : HOOKS) {
            r.run();
        }
    }

    /**
     * 扩展卸载时清空绑定器/钩子。
     *
     * <p>绑定器持的是组件强引用，而 {Msg} 是静态状态：不清的话重载插件后，
     * 旧界面的整棵组件树（连同旧 classloader）会被一直吊着 —— 和当初给线程池补
     * {@code IExtensionStateListener} 是同一类问题。
     */
    public static void shutdown() {
        closed = true;
        BINDERS.clear();
        HOOKS.clear();
        MISSING.clear();
    }

    // ------------------------------------------------------------------ 自检

    /** 查不到过的 key 集合；harness 驱动完界面后断言它为空 */
    public static Set<String> missingKeys() {
        return MISSING;
    }

    /**
     * 表自身的毛病：中文键集与英文键集不一致、或某一侧为空值。
     * 这是「加了一批中文忘了补英文」的唯一自动拦截点 —— 那种错一个 key 都不会缺，
     * {@link #missingKeys()} 也看不见。
     */
    public static List<String> tableProblems() {
        List<String> bad = new ArrayList<String>();
        for (Map.Entry<String, String[]> e : TABLE.entrySet()) {
            String[] pair = e.getValue();
            if (pair == null || pair.length != 2) {
                bad.add(e.getKey() + ": 条目不是两个值");
                continue;
            }
            if (pair[0] == null || pair[0].isEmpty()) {
                bad.add(e.getKey() + ": 缺中文");
            }
            if (pair[1] == null || pair[1].isEmpty()) {
                bad.add(e.getKey() + ": 缺英文");
            }
        }
        return bad;
    }

    // ------------------------------------------------------------------ 数据层字符串的渲染映射

    /** 扫描模式的显示名（数据层仍是 {@code displayName} 的中文，只在渲染时调这里） */
    public static String scanModeName(ScanTask.ScanMode mode) {
        return mode == null ? "" : t("type." + mode.getTypeKey());
    }

    /** 漏洞等级的显示名 */
    public static String levelName(ScanTask.VulnLevel level) {
        return level == null ? "" : t("level." + level.name());
    }

    /** 任务状态的显示名 */
    public static String statusName(ScanTask.TaskStatus status) {
        return status == null ? "" : t("status." + status.name());
    }

    /**
     * 把「中文漏洞类型名」翻成当前语言。数据层永远是中文（见类注释）。
     *
     * @param chineseType {@code ScanMode.displayName} / {@code VulnResult.vulnType} 那种中文名；
     *                    认不出来（模型自造的类型名、空值）时**原样返回**，不要吞掉
     */
    public static String typeNameOf(String chineseType) {
        if (chineseType == null) {
            return "";
        }
        String key = TYPE_KEYS.get(chineseType);
        return key == null ? chineseType : t(key);
    }

    /**
     * 服务商名的显示映射。
     *
     * <p>{@code AIProvider.name} 是**数据**：它会被持久化进 {@code Config.selectedProvider}、
     * 还会跟 {@code providerCombo.getSelectedItem()} 比较 —— 所以只翻「自定义」这一个哨兵值
     * （它对用户是一句界面文案），其余（ChatGPT (OpenAI)、DeepSeek…）原样返回。
     *
     * @param fallback 没选服务商时显示的文案（调用方传 {@code Msg.t("status.notConfigured")}）
     */
    public static String providerNameOf(String providerName, String fallback) {
        if (providerName == null || providerName.isEmpty()) {
            return fallback;
        }
        return "自定义".equals(providerName) ? t("provider.custom") : providerName;
    }

    /**
     * 模型下拉项的显示文案。下拉里装着「点击获取」「获取失败」两个**哨兵值**（代码靠它们判断状态），
     * 所以只翻显示，值本身保持中文。
     */
    public static String modelItemOf(String value) {
        if ("点击获取".equals(value)) {
            return t("model.clickFetch");
        }
        if ("获取失败".equals(value)) {
            return t("model.fetchFailed");
        }
        return value;
    }

    /**
     * 表格「AI标签」列与报告里的 AI 结论：可能是一个类型名，也可能是「安全」「分析中」这类过程标签。
     * 两者都先按过程标签查，查不到再当类型名查，都不认就原样返回。
     */
    public static String displayAiTag(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "";
        }
        String key = AI_TAG_KEYS.get(raw);
        return key == null ? typeNameOf(raw) : t(key);
    }

    private static final Map<String, String> TYPE_KEYS = new LinkedHashMap<String, String>();
    private static final Map<String, String> AI_TAG_KEYS = new LinkedHashMap<String, String>();

    static {
        TYPE_KEYS.put("SQL注入", "type.SQL_INJECTION");
        TYPE_KEYS.put("XSS跨站脚本", "type.XSS");
        TYPE_KEYS.put("命令注入", "type.COMMAND_INJECTION");
        TYPE_KEYS.put("文件上传", "type.FILE_UPLOAD");
        TYPE_KEYS.put("SSRF服务端请求伪造", "type.SSRF");
        TYPE_KEYS.put("XXE外部实体注入", "type.XXE");
        TYPE_KEYS.put("SSTI服务端模板注入", "type.SSTI");
        TYPE_KEYS.put("Fastjson反序列化", "type.FASTJSON");
        TYPE_KEYS.put("Log4j2 JNDI注入", "type.LOG4J2");
        TYPE_KEYS.put("Struts2 OGNL注入", "type.STRUTS2");
        TYPE_KEYS.put("Shiro反序列化", "type.SHIRO");
        TYPE_KEYS.put("AI智能扫描", "type.CUSTOM");
        // formatVulnName 认不出类型名时的兜底返回值，会经 VulnResult.vulnName 进报告
        TYPE_KEYS.put("未知漏洞", "type.UNKNOWN");

        // AIEngine 里 setAiTag 的取值全集（少一个就会在界面上漏出中文）
        AI_TAG_KEYS.put("分析中", "aitag.analyzing");
        AI_TAG_KEYS.put("分析失败", "aitag.analysisFailed");
        AI_TAG_KEYS.put("无响应", "aitag.noResponse");
        AI_TAG_KEYS.put("渗透测试中", "aitag.testing");
        AI_TAG_KEYS.put("安全", "aitag.safe");
        AI_TAG_KEYS.put("已取消", "aitag.cancelled");
        AI_TAG_KEYS.put("异常", "aitag.error");
    }

    // ------------------------------------------------------------------ 文案表

    static {
        // ---- 顶栏 ----
        put("bar.provider", "AI服务: ", "AI Service: ");
        put("bar.model", "模型: ", "Model: ");
        put("bar.oob", "外带: ", "OOB: ");
        put("bar.oobOff", "外带: 已关闭", "OOB: Off");
        put("bar.oobTip", "回连服务 {0}（基础域名 {1}）；关闭时不申请域名、不发送任何带外带域名的载荷",
                "Callback service {0} (base domain {1}). When off, no domain is requested and no payload carrying an OOB domain is sent.");
        put("btn.lang", "EN", "中文");
        put("btn.lang.tip", "切换界面语言（界面、日志与报告；AI 提示词仍为中文）",
                "Switch UI language (interface, logs and reports; AI prompts stay Chinese)");

        // ---- 顶栏状态词 ----
        put("status.unverified", "未验证", "Not verified");
        put("status.notConfigured", "未配置", "Not configured");
        put("status.notSelected", "未选择", "Not selected");
        put("status.available", "可用", "Available");
        put("status.unavailable", "不可用", "Unavailable");
        put("status.verifying", "验证中", "Verifying");

        // ---- 服务商哨兵（数据层是「自定义」，只在显示时翻）----
        put("provider.custom", "自定义", "Custom");

        // ---- 标签页 ----
        put("tab.tasks", "任务列表", "Tasks");
        put("tab.detail", "请求与响应详情", "Request & Response");
        put("tab.log", "日志统计", "Log & Stats");
        put("tab.config", "配置", "Configuration");

        // ---- 漏洞类型（渲染用；数据层的中文名见 TYPE_KEYS）----
        put("type.SQL_INJECTION", "SQL注入", "SQL Injection");
        put("type.XSS", "XSS跨站脚本", "XSS");
        put("type.COMMAND_INJECTION", "命令注入", "Command Injection");
        put("type.FILE_UPLOAD", "文件上传", "File Upload");
        put("type.SSRF", "SSRF服务端请求伪造", "SSRF");
        put("type.XXE", "XXE外部实体注入", "XXE");
        put("type.SSTI", "SSTI服务端模板注入", "SSTI");
        put("type.FASTJSON", "Fastjson反序列化", "Fastjson Deserialization");
        put("type.LOG4J2", "Log4j2 JNDI注入", "Log4j2 JNDI Injection");
        put("type.STRUTS2", "Struts2 OGNL注入", "Struts2 OGNL Injection");
        put("type.SHIRO", "Shiro反序列化", "Shiro Deserialization");
        put("type.CUSTOM", "AI智能扫描", "AI Smart Scan");
        put("type.UNKNOWN", "未知漏洞", "Unknown");

        // ---- 漏洞等级 ----
        put("level.NONE", "无漏洞", "Clean");
        put("level.LOW", "低危", "Low");
        put("level.MEDIUM", "中危", "Medium");
        put("level.HIGH", "高危", "High");
        put("level.CRITICAL", "严重", "Critical");

        // ---- 任务状态 ----
        put("status.PENDING", "待处理", "Pending");
        put("status.SCANNING", "AI智能渗透中", "Scanning");
        put("status.PAUSED", "暂停中", "Paused");
        put("status.FINISHED", "已结束", "Finished");

        // ---- 导出报告对话框（每次点导出都新建，直接读当前语言，不注册绑定器）----
        put("export.title", "导出报告配置", "Export Report");
        put("export.heading", "配置导出选项", "Export Options");
        put("export.range", "导出范围", "Scope");
        put("export.rangeSelected", "导出选中任务", "Selected task");
        put("export.rangeSelectedN", "导出选中的 {0} 个任务", "Export {0} selected tasks");
        put("export.rangeAll", "导出全部任务", "All tasks");
        put("export.levelFilter", "危险等级筛选", "Severity filter");
        put("export.typeFilter", "漏洞类型筛选", "Vulnerability type filter");
        put("export.format", "导出格式", "Format");
        put("export.formatHtml", "HTML格式", "HTML");
        put("export.formatMd", "Markdown格式", "Markdown");
        put("btn.startExport", "开始导出", "Export");
        put("btn.cancel", "取消", "Cancel");
        put("dlg.hint", "提示", "Notice");
        put("dlg.saveReport", "保存报告", "Save report");
        put("dlg.chooseDir", "选择报告保存目录", "Choose output folder");
        put("dlg.exportSuccess", "导出成功", "Export finished");
        put("dlg.exportFailed", "导出失败", "Export failed");
        put("dlg.exportPartlyFailed", "部分导出失败", "Partly failed");
        put("msg.noTasksToExport", "没有符合筛选条件的任务可以导出", "No task matches the current filter");
        put("msg.exporting", "导出报告 {0}/{1}: {2}", "Exporting report {0}/{1}: {2}");
        put("msg.exportErrorPrint", "[导出错误] 报告导出失败 | 目标路径: {0} | 异常: {1}",
                "[EXPORT ERROR] report export failed | target: {0} | exception: {1}");
        put("msg.exportErrorLog", "[导出错误] 报告导出失败: {0}", "[EXPORT ERROR] report export failed: {0}");
        put("msg.reportExported", "报告已导出到:\n{0}", "Report exported to:\n{0}");
        put("msg.reportsExported", "成功导出 {0} 个报告到:\n{1}", "Exported {0} report(s) to:\n{1}");
        put("msg.batchExported", "批量导出成功: {0} 个报告", "Batch export finished: {0} report(s)");
        put("msg.exportPartial", "成功 {0} 个，失败 {1} 个", "{0} succeeded, {1} failed");
        put("msg.lastError", "\n最后一次失败原因：{0}", "\nLast failure: {0}");
        put("msg.targetPath", "\n目标路径: {0}", "\nTarget path: {0}");
        put("msg.exportDone", "导出结束：成功 {0} 个，失败 {1} 个", "Export done: {0} succeeded, {1} failed");

        // ---- 请求/响应详情页 ----
        put("detail.probes", "漏洞探测请求列表", "Probe Requests");
        put("detail.request", "请求包", "Request");
        put("detail.response", "响应包", "Response");
        put("detail.probeItem", "#{0} | {1} | 参数: {2}", "#{0} | {1} | param: {2}");
        put("detail.probeItemNoResponse", "#{0} | {1} | 参数: {2}（未响应）",
                "#{0} | {1} | param: {2} (no response)");

        put("cfg.oobCheck.tip", "关闭后：不申请回连域名、不发送任何带外带域名的载荷，被扫目标不会访问回连服务；"
                        + "但 Log4j2/Fastjson/Struts2/Shiro 与无回显的命令注入、XXE、SSRF 将无法判定（只能记「未判定」）",
                "When off, no callback domain is requested and no payload carrying an OOB domain is sent, so scanned targets never "
                        + "reach the callback service; but Log4j2/Fastjson/Struts2/Shiro and no-echo command injection, XXE and SSRF "
                        + "can then only be recorded as \"not judged\".");
        put("cfg.autoScanCheck.tip", "打开后，经过 Burp Proxy 的请求会被送进 AI 智能扫描（模式：AI智能扫描）："
                        + "每条任务都会重放一次请求、发送多条载荷、并逐条调用 AI 验证。"
                        + "只收带参数的请求（URL 查询串 / 请求体里的参数），图片、CSS、JS、纯 REST 路径"
                        + "这类没有参数的流量直接跳过；只有 Cookie 或只有自定义请求头可注入的请求也会被跳过"
                        + "（那两种要扫请手工右键）。"
                        + "同一个功能点（方法 + 路径 + 参数名，参数值与请求头都不看）只扫一次 —— "
                        + "换了个参数值（轮询时间戳、分页、随机 id）不会重复扫，多一个参数名才会；"
                        + "只想扫特定目标时，在下面的白名单里填 host。变更立即生效并落盘，"
                        + "重新勾选会重置去重记录（同一个请求会再扫一遍）。",
                "When on, requests passing through Burp Proxy are sent to the scanner: every task replays the request, sends several "
                        + "payloads and runs an AI verification for each. Only parameterised requests are taken (query string or body "
                        + "parameters); images, CSS, JS and bare REST paths are skipped, as are requests whose only injectable surface "
                        + "is a cookie or a custom header (right-click those manually). One endpoint (method + path + parameter names; "
                        + "neither values nor headers count) is scanned once — a new value for the same name (polling timestamp, page "
                        + "number, random id) does not re-scan it, an extra parameter name does. To narrow the scope, list hosts below. Changes apply and persist "
                        + "immediately; re-ticking the box resets the dedup history.");
        put("cfg.whitelist.tip", "只扫这些目标；留空 = 全部 Proxy 目标。"
                        + "一行一个，多个也用英文逗号写在同一行：example.com,api.test.cn,10.0.0.5:8080。"
                        + "可写 example.com（含子域）、example.com:8443、*.example.com，也可以直接粘一整条 URL；"
                        + "空格/分号/中文逗号同样能分隔。离开输入框（点到别处）即生效。",
                "Only scan these targets; empty = all proxied targets. One per line, or several comma-separated on one line: "
                        + "example.com,api.test.cn,10.0.0.5:8080. A bare domain also matches its subdomains; host:port, *.example.com "
                        + "and a pasted full URL all work. Spaces, semicolons and Chinese commas also separate. Applies when the field "
                        + "loses focus.");
        put("cfg.testOob.tipOn", "申请专属域名 → 让本机解析一次 → 把解析记录查回来，验证整条回连链路",
                "Acquire a domain, resolve it locally, then poll the record back — a full round trip of the callback chain");
        put("cfg.testOob.tipOff", "外带回连已关闭（勾选上方开关后可用）",
                "OOB callback is off (tick the switch above to enable)");
        put("model.clickFetch", "点击获取", "Click to fetch");
        put("model.fetchFailed", "获取失败", "Fetch failed");

        put("logcfg.oobOn", "[配置] 外带回连已启用：无回显类漏洞（命令注入外带、Blind XXE、SSRF 出网、"
                        + "Log4j2/Fastjson/Struts2/Shiro）靠回连记录取证",
                "[CONFIG] OOB callback enabled: no-echo bugs (OOB command injection, blind XXE, SSRF egress, "
                        + "Log4j2/Fastjson/Struts2/Shiro) are proven by callback records");
        put("logcfg.oobOff", "[配置] 外带回连已关闭：不申请回连域名、不发送任何外带载荷，"
                        + "被扫目标不会访问回连服务；依赖回连的类型将只能记「未判定」",
                "[CONFIG] OOB callback disabled: no domain is requested and no OOB payload is sent, so scanned targets never reach "
                        + "the callback service; types that rely on it can only be recorded as not judged");
        put("logcfg.autoScanOn", "[配置] Proxy 流量自动扫描已开启：{0}；相同请求只扫一次，本次已重置去重记录",
                "[CONFIG] Proxy auto-scan enabled: {0}; each request is scanned once and the dedup history was reset");
        put("logcfg.autoScanNoWhitelist", "未设白名单 → 所有经过代理的请求都会成为扫描任务（会主动向目标发包）",
                "no allowlist set, so every proxied request becomes a scan task (packets are actively sent to the target)");
        put("logcfg.autoScanWhitelistOnly", "仅对 {0} 生效", "only {0} is in scope");
        put("logcfg.autoScanOff", "[配置] Proxy 流量自动扫描已关闭：经过代理的请求不再自动建任务",
                "[CONFIG] Proxy auto-scan disabled: proxied requests no longer create tasks");

        put("msg.needModelNameShort", "请先选择或输入模型", "Pick or type a model first");
        put("logcfg.keyVerifiedSaved", "[配置] API Key 验证成功，已保存: {0} - {1}（模型接口 {2}）",
                "[CONFIG] API key verified and saved: {0} - {1} (models API {2})");
        put("logcfg.keyVerifyError", "[配置] API Key 验证异常", "[CONFIG] API key verification raised");

        // ---- 主面板与扩展生命周期日志 ----
        put("log.addReq.invalidEmpty", "[添加请求错误] 无效的请求：请求或请求内容为空",
                "[ADD ERROR] invalid request: the request or its content is empty");
        put("log.addReq.invalid", "[添加请求错误] 无效的请求", "[ADD ERROR] invalid request");
        put("log.addReq.emptyBody", "[添加请求错误] 请求体为空", "[ADD ERROR] empty request body");
        put("log.addReq.badHttp", "[添加请求错误] HTTP请求格式无效", "[ADD ERROR] malformed HTTP request");
        put("log.addReq.error", "[添加请求错误] 异常", "[ADD ERROR] exception");
        put("log.taskAdded", "[新增] 任务 #{0} | 模式: {1}", "[ADDED] task #{0} | mode: {1}");
        put("log.taskDeleted", "删除任务 #{0}", "Deleted task #{0}");
        put("log.clearedCompleted", "清空已完成任务，共 {0} 个", "Cleared {0} completed task(s)");
        put("log.apiKeyOk", "[API] API Key验证成功", "[API] API key verified");
        put("msg.noResponseBody", "无响应体", "no response body");
        put("log.apiKeyFailDetail", "[API错误] API Key验证失败 | HTTP {0} | 响应: {1}",
                "[API ERROR] API key verification failed | HTTP {0} | response: {1}");
        put("log.apiKeyFailHttp", "[API错误] API Key验证失败: HTTP {0}", "[API ERROR] API key verification failed: HTTP {0}");
        put("log.apiKeyFail", "[API错误] API Key验证失败", "[API ERROR] API key verification failed");
        put("log.execTermTimeout", "[系统错误] ExecutorService未能在5秒内终止",
                "[SYSTEM ERROR] ExecutorService did not terminate within 5 seconds");
        put("log.execShutdownInterrupted", "[系统错误] ExecutorService关闭被中断",
                "[SYSTEM ERROR] ExecutorService shutdown was interrupted");
        put("log.oob.off", "[外带检测] 已关闭（配置界面可开启）：不申请回连域名，也不发送外带载荷",
                "[OOB] disabled (enable it on the config page): no callback domain is requested and no OOB payload is sent");
        put("log.oob.ok", "[外带检测] 回连自检通过：{0}", "[OOB] callback self-test passed: {0}");
        put("log.oob.fail", "[外带检测] 回连自检失败：{0}（依赖回连的类型将无法判定；可在配置界面点「测试回连」重试）",
                "[OOB] callback self-test failed: {0} (types that rely on callbacks cannot be judged; retry with Test callback on the config page)");
        put("log.ui.error", "[UI错误] 初始化失败，Tab 未显示 | 异常: {0}",
                "[UI ERROR] initialisation failed, the tab was not shown | exception: {0}");
        put("log.ui.errorShort", "[UI错误] 初始化失败", "[UI ERROR] initialisation failed");
        put("log.menu.notReady", "[错误] 界面未初始化成功，无法提交扫描（模式: {0}）",
                "[ERROR] the UI did not initialise, cannot submit a scan (mode: {0})");
        put("log.menu.sent", "已发送 {0} 个请求到 Zack-AI-Scanner，模式: {1}",
                "Sent {0} request(s) to Zack-AI-Scanner, mode: {1}");

        // ---- Proxy 自动扫描与配置读写 ----
        put("log.autoscan.hit", "[自动扫描] Proxy 命中 {0}", "[AUTO-SCAN] proxied request matched {0}");
        put("err.snapshotImmutable", "自动扫描的请求是快照，不可修改",
                "an auto-scanned request is an immutable snapshot");
        put("logcfg.parseEmpty", "配置内容解析为空", "the config content parsed to nothing");
        put("logcfg.backedUp", "原文件已备份为 {0}", "the original file was backed up as {0}");
        put("logcfg.backupFailed", "原文件备份失败: {0}", "backing up the original file failed: {0}");
        put("logcfg.corrupt", "[配置错误] 配置文件无法解析，已重置为默认值（API Key 与服务商/模型需要重新填写）| "
                        + "配置文件: {0} | {1} | 异常: {2}",
                "[CONFIG ERROR] the config file could not be parsed and was reset to defaults (the API key and the "
                        + "provider/model selection must be re-entered) | config file: {0} | {1} | exception: {2}");
        put("logcfg.saveFailed", "[配置错误] 保存配置失败 | 配置文件: {0} | 异常: {1}",
                "[CONFIG ERROR] saving the config failed | config file: {0} | exception: {1}");
        put("logcfg.saveFailedShort", "[配置错误] 保存配置失败", "[CONFIG ERROR] saving the config failed");

        put("oob.sessionDropped", "（连续 {0} 次失败，已丢弃当前回连会话，下次扫描重新申请）",
                " ({0} consecutive failures, the current callback session was dropped and will be re-acquired on the next scan)");
        put("oob.recordPrefix", "DNS 解析回连：本次请求前缀 \"{0}\"", "DNS callback: per-request prefix \"{0}\"");
        put("oob.recordDomain", "，完整域名 {0}", ", full domain {0}");
        put("oob.recordResolver", "，经解析器 {0}", ", via resolver {0}");
        put("oob.recordTime", "，时间 {0}", ", at {0}");
        put("oob.truncated", "...(已截断)", "...(truncated)");
        put("oob.httpStatus", "回连服务返回 HTTP {0}", "the callback service returned HTTP {0}");
        put("oob.requestFailed", "请求回连服务失败：{0}", "requesting the callback service failed: {0}");

        // ---- 外带回连（自检结果直接显示在配置页与日志里，所以在产生处翻）----
        put("oob.noDomain", "无法获取专属回连域名（{0}）", "could not acquire a callback domain ({0})");
        put("oob.unknownReason", "未知原因", "unknown reason");
        put("oob.noteFreshDomain", "（首个域名 {0} 没查到记录，换新域名后成功）",
                " (no record for the first domain {0}; succeeded after acquiring a new one)");
        put("oob.pollException", "查询回连记录异常（{0}）", "polling callback records raised ({0})");
        put("oob.pollFailed", "无法查询回连记录（{0}）", "could not poll callback records ({0})");
        put("oob.roundTripOk", "本机解析 {0} 后查回 {1} 条记录（专属域名 {2}）",
                "resolved {0} locally and read back {1} record(s) (dedicated domain {2})");
        put("oob.waitInterrupted", "等待解析记录时被中断", "interrupted while waiting for the DNS record");
        put("oob.diagPrefix", "已让本机解析 {0}（解析结果 {1}）", "asked this machine to resolve {0} (result {1})");
        put("oob.none", "无", "none");
        put("oob.diagHttpTriggered", "、并用 HTTP 触发了一次", ", and fired one HTTP request to force resolution");
        put("oob.diagNoRecord", "，但 {0} 秒内没查到解析记录。", ", but no record showed up within {0} seconds.");
        put("oob.diagIntercepted", "解析到的是 {0}（代理/VPN 的假 IP 或内网地址段），"
                        + "说明本机 DNS 被接管、查询根本没到回连服务的权威 DNS —— "
                        + "**这不代表扫描不可用**：扫描时是「被扫目标」去解析该域名。",
                "it resolved to {0} (a proxy/VPN fake IP or a private range), which means this machine's DNS is intercepted and the "
                        + "query never reached the callback service's authoritative DNS — **this does not mean scanning is broken**: "
                        + "during a scan it is the *target* that resolves the domain.");
        put("oob.diagHint", "请确认本机能访问 dnslog.org，或稍后重试。",
                "Check that this machine can reach dnslog.org, or retry later.");
        put("oob.notJson", "回连服务返回的不是 JSON", "the callback service did not return JSON");
        put("oob.emptySession", "回连服务返回空会话", "the callback service returned an empty session");
        put("oob.noKeyToken", "回连服务未返回 key/token", "the callback service returned no key/token");
        put("oob.noSessionForPoll", "回连会话或本次随机前缀缺失，无法查询回连记录",
                "no callback session or per-request prefix, cannot poll callback records");
        put("oob.pollFailedShort", "轮询回连记录失败", "polling callback records failed");
        put("oob.badRecordShape", "回连服务返回的记录格式无法识别", "the callback service returned an unrecognised record shape");
        put("oob.emptyResponse", "回连服务返回空响应", "the callback service returned an empty response");

        put("sep.list", "、", ", ");
        put("log.getValidParamNamesFailed", "[AI 错误] getValidParamNames 失败", "[AI ERROR] getValidParamNames failed");
        put("log.oobOffThisScan", "[外带检测] 已关闭：本次不申请回连域名，外带类载荷也不会发送",
                "[OOB] disabled: no callback domain this scan and no OOB payload will be sent");
        put("log.step1.sending", "[步骤1] 正在发送原始请求到目标...", "[STEP1] sending the original request to the target...");
        put("log.step1.gotResponse", "[步骤1完成] 已获取响应包，长度: {0} 字节", "[STEP1 DONE] response received, {0} bytes");
        put("log.step1.noResponse", "[步骤1警告] 目标未返回响应（响应为null或空）",
                "[STEP1 WARN] the target returned no response (null or empty)");
        put("log.step1.sentNoResponse", "[步骤1完成] 请求已发送但无响应", "[STEP1 DONE] request sent but no response came back");
        put("log.step1.timeout", "[步骤1警告] 重放超过 {0} 秒未返回，放弃等待按无响应处理（不再等 Burp 自己的超时）",
                "[STEP1 WARN] the replay did not come back within {0}s — giving up and treating it as no response (instead of waiting on Burp's own timeout)");
        put("log.step2.analyzing", "[步骤2] AI 分析参数-漏洞类型映射", "[STEP2] AI is mapping parameters to vulnerability types");
        put("log.step2.done", "[步骤2完成] {0}", "[STEP2 DONE] {0}");
        put("log.step2.noParams", "[步骤2] AI 未发现值得测试的参数，本次不发包",
                "[STEP2] AI found no parameter worth testing, no packet will be sent");
        put("log.step3.types", "[步骤3] 本次涉及的漏洞类型: {0}", "[STEP3] vulnerability types in play: {0}");
        put("log.step3.generating", "[步骤3] AI 根据映射生成扫描 payload", "[STEP3] AI is generating payloads from the mapping");
        put("log.step3.params", "[步骤3] AI 可能存在漏洞的参数: {0}",
                "[STEP3] parameters the AI flagged as possibly vulnerable: {0}");
        put("log.step3.genFailed", "[步骤3] AI 生成 payload 失败（调用或解析出错，已重试），本次没能发包",
                "[STEP3] payload generation failed (call or parse error, already retried), nothing was sent");
        put("log.step3.noPayload", "[步骤3] AI 未生成有效 payload（模型没给出可测的组合，或载荷全被过滤）",
                "[STEP3] AI produced no usable payload (no testable combination, or every payload was filtered out)");
        put("log.step3.rawCount", "[步骤3] AI 生成 {0} 个payloads", "[STEP3] AI generated {0} payloads");
        put("log.step3.filtered", "[步骤3完成] 去重过滤后 payloads: {0}", "[STEP3 DONE] after dedup/filtering: {0} payloads");
        put("log.step3.dropped", "[步骤3] 丢弃 {0} 条不在 paramVulnMap 里的载荷（AI 没有点名的参数不发包）",
                "[STEP3] dropped {0} payload(s) not present in paramVulnMap (parameters the AI did not name are not sent)");

        put("log.step4.skipOob", "[步骤4] 载荷{0}/{1} → 外带回连已关闭，跳过这条外带载荷（未发送）| 位置: {2}",
                "[STEP4] payload {0}/{1} → OOB callback is off, skipping this OOB payload (not sent) | position: {2}");
        put("log.step4.payload", "[步骤4] 载荷{0}/{1} → {2} → {3} → {4}{5}", "[STEP4] payload {0}/{1} → {2} → {3} → {4}{5}");
        // 对照锚点是「每个参数-漏洞组合一条」而不是每条载荷一条：一个组合一次，用来证明这一组
        // 后面载荷的验证确实会带上那条探测载荷的响应（这段内容在提示词里，界面上看不见）
        put("log.step4.control", "[步骤4] 对照锚点已记录 → {0} [{1}]（本组合后续载荷的验证会带上它）",
                "[STEP4] control anchor recorded → {0} [{1}] (later payloads of this combo are verified against it)");
        // 对照自己判成漏洞 → 作废：它已经不可能再当「无害参照」（见 invalidateControlIfSelf）
        put("log.step4.controlVoid", "[步骤4] 对照锚点已作废 → {0} [{1}]：这条探测载荷自己判成了漏洞，不能再当无害参照，本组合其余载荷退回只与基线比对",
                "[STEP4] control anchor voided → {0} [{1}]: the probe payload itself came back vulnerable, so it cannot serve as a benign reference; later payloads of this combo fall back to baseline-only");
        put("log.oobPrefix", "（外带 前缀 {0}）", " (OOB prefix {0})");
        put("log.progress", "[进度] 已完成 {0}/{1} 个载荷测试", "[PROGRESS] {0}/{1} payloads tested");
        put("log.step4.uncovered", "[步骤4] 以下参数没有任何载荷命中（Step2 未映射或被过滤）: {0}",
                "[STEP4] no payload hit these parameters (not mapped in step 2, or filtered out): {0}");
        put("log.taskDone.noVuln", "[任务 #{0} 完成] 未发现漏洞{1}", "[TASK #{0} DONE] no vulnerability found{1}");
        put("log.taskDone.withVuln", "[任务 #{0} 完成] 发现 {1} 个漏洞{2} | 等级: {3}",
                "[TASK #{0} DONE] {1} finding(s){2} | level: {3}");
        put("log.scanError", "[扫描错误] 扫描异常", "[SCAN ERROR] the scan raised an exception");

        put("log.oob.noHost", "[外带检测] 未取得回连域名，本次不生成外带类载荷：{0}",
                "[OOB] no callback domain this scan, no OOB payload will be generated: {0}");
        put("log.oob.host", "[外带检测] 回连域名: {0}（每个外带载荷会自动加一个随机前缀）",
                "[OOB] callback domain: {0} (each OOB payload gets its own random prefix)");
        put("log.oob.tag", "[外带检测] {0}", "[OOB] {0}");
        put("oob.pollFailureNote", "回连记录查询失败（{0}），本次无法确认目标是否回连",
                "polling callback records failed ({0}), so it cannot be confirmed whether the target called back");
        put("log.oob.records", "[外带检测] 载荷{0} 收到 {1} 条回连记录（前缀 {2}）",
                "[OOB] payload {0} received {1} callback record(s) (prefix {2})");
        put("log.oob.verifyError", "[外带检测] 载荷{0} 的回连查询/验证异常 | 位置: {1}",
                "[OOB] polling/verification for payload {0} raised | position: {1}");
        put("log.oob.asyncError", "[外带检测] 一条外带验证以异常结束：{0}",
                "[OOB] a deferred OOB verification ended with an exception: {0}");

        put("log.send.noHttpService", "[发送错误] HTTP服务为null | 位置: {0} | 载荷: {1}",
                "[SEND ERROR] HTTP service is null | position: {0} | payload: {1}");
        put("log.send.noHttpServiceShort", "[发送错误] HTTP服务为null", "[SEND ERROR] HTTP service is null");
        put("log.send.timeout", "[超时告警] 请求超时 {0}秒未响应，目标不可达或存在防火墙/防御模块拦截 | 载荷序号: {1} | 载荷: {2}",
                "[TIMEOUT] no response within {0}s — the target is unreachable, or a firewall/defence module is blocking | payload #{1} | payload: {2}");
        put("log.send.failed", "[发送错误] 请求失败: {0} | 位置: {1} | 载荷: {2}",
                "[SEND ERROR] request failed: {0} | position: {1} | payload: {2}");
        put("log.send.testFailed", "[发送错误] 发送测试请求失败: {0} | 位置: {1}",
                "[SEND ERROR] sending the test request failed: {0} | position: {1}");
        put("log.send.modifyError", "[发送错误] 请求修改异常: {0}", "[SEND ERROR] modifying the request raised: {0}");

        put("log.api.noKey", "[API错误] API调用失败: API Key未配置", "[API ERROR] API call failed: no API key configured");
        put("log.api.noEndpoint", "[API错误] API调用失败: API Endpoint未配置", "[API ERROR] API call failed: no API endpoint configured");
        put("log.api.httpError", "[API错误] API调用失败: HTTP {0} {1} | 响应: {2}",
                "[API ERROR] API call failed: HTTP {0} {1} | response: {2}");
        put("log.api.httpErrorShort", "[API错误] API调用失败: HTTP {0} {1}", "[API ERROR] API call failed: HTTP {0} {1}");
        put("log.api.emptyBody", "[API错误] API调用失败: 响应体为空", "[API ERROR] API call failed: empty response body");
        put("log.api.callException", "[AI错误] API调用异常", "[AI ERROR] API call raised");
        put("log.step2.buildBodyFailed", "[AI错误] step2失败: 构建请求体失败", "[AI ERROR] step2 failed: could not build the request body");
        put("log.step2.emptyResponse", "[AI错误] step2失败: API返回空响应", "[AI ERROR] step2 failed: the API returned an empty response");
        put("log.step2.parseContentFailed", "[AI错误] step2失败: 解析响应内容失败", "[AI ERROR] step2 failed: could not parse the response content");
        put("log.step2.badJson", "[AI错误] step2失败: 无法解析JSON格式", "[AI ERROR] step2 failed: the reply is not valid JSON");
        put("log.step2.exception", "[AI错误] step2异常", "[AI ERROR] step2 raised");
        put("log.step3.exception", "[AI错误] step3异常", "[AI ERROR] step3 raised");

        put("log.send.cannotInject", "[发送错误] 该位置无法注入，已跳过本次测试 | 位置: {0} | 载荷: {1}",
                "[SEND ERROR] cannot inject at this position, skipping this test | position: {0} | payload: {1}");
        put("log.send.threadInterrupted", "[超时告警] 载荷测试线程被中断 | 位置: {0} | 载荷: {1}",
                "[TIMEOUT] the payload test thread was interrupted | position: {0} | payload: {1}");
        put("log.send.stdHeaderBlocked", "[发送错误] 该标准 header 禁止注入，已跳过 | 位置: {0}",
                "[SEND ERROR] standard headers cannot be injected, skipping | position: {0}");
        put("log.send.noSuchPathSegment", "[发送错误] URL 路径里没有这一段，已跳过 | 位置: {0}",
                "[SEND ERROR] the URL path has no such segment, skipping | position: {0}");
        put("log.send.positionMissing", "[发送错误] 位置在请求中不存在，已跳过 | 位置: {0}",
                "[SEND ERROR] the position does not exist in the request, skipping | position: {0}");
        put("log.send.xmlElementMissing", "[发送错误] XML 中未找到该元素，已跳过 | 位置: {0}",
                "[SEND ERROR] the element was not found in the XML, skipping | position: {0}");
        put("log.send.multipartBinary", "[发送错误] multipart body 含二进制数据，且载荷不属于可改写的形态"
                        + "（filename=… / Content-Type:… / 纯文件名 / 纯内容），已跳过 | 位置: {0}",
                "[SEND ERROR] the multipart body contains binary data and the payload is not in a rewritable shape "
                        + "(filename=… / Content-Type:… / bare filename / bare content), skipping | position: {0}");
        put("log.inject.multipartSkip", "[注入] 位置 {0} 落在 multipart 部件里，跳过参数替换"
                        + "（那条路会丢掉 part 的 filename 属性，请求就不再是文件上传了）",
                "[INJECT] position {0} sits in a multipart part, skipping parameter replacement "
                        + "(that path loses the part's filename attribute and the request stops being a file upload)");
        put("log.inject.caseDiffers", "[注入] 位置 {0} → 实际注入到参数 {1}（名称大小写不同）",
                "[INJECT] position {0} → actually injected into parameter {1} (the name differs in case)");
        put("log.inject.burpDidNotWrite", "[注入] Burp 没有把载荷原样写进请求（参数类型 {0}），改走专用注入路径 | 位置: {1}",
                "[INJECT] Burp did not write the payload verbatim into the request (parameter type {0}), "
                        + "falling through to the dedicated injector | position: {1}");
        put("log.inject.paramUpdateFailed", "[AI错误] 参数更新失败 | 参数: {0} | 类型: {1}",
                "[AI ERROR] updating the parameter failed | parameter: {0} | type: {1}");
        put("log.inject.contentTypeAligned", "[注入] Content-Type 与请求体不匹配（原: {0}）→ 本条按 {1} 发送"
                        + "（否则服务端解析不到这份文档，载荷等于没发）",
                "[INJECT] Content-Type does not match the body (was: {0}) → this request is sent as {1} "
                        + "(otherwise the server cannot parse the document and the payload is as good as unsent)");
        put("log.inject.xmlWholeBody", "[注入] XML 载荷按整段 body 替换 | 位置: {0}",
                "[INJECT] the XML payload replaces the whole body | position: {0}");
        put("log.inject.headerModifyFailed", "[AI错误] Header修改失败 | Header: {0} | 载荷: {1}",
                "[AI ERROR] modifying the header failed | header: {0} | payload: {1}");
        put("log.noResponse.oobOnly", "[无响应] {0} 目标未返回响应，但有外带回连记录可判定 | 位置: {1}",
                "[NO RESPONSE] {0} the target returned nothing, but a callback record settles it | position: {1}");
        put("log.noResponse.empty", "[无响应] {0} 目标无响应或超时（响应体为空）| 位置: {1}",
                "[NO RESPONSE] {0} the target returned nothing or timed out (empty body) | position: {1}");
        put("log.ai.repairedJson", "[AI解析] 返回的 JSON 不完整（可能被 max_tokens 截断），已按最后一个完整条目补全后继续",
                "[AI PARSE] the reply was incomplete JSON (likely cut off by max_tokens); repaired up to the last complete entry and continued");
        put("log.step2.dropped", "[步骤2] 丢弃 {0} 条无法注入的参数映射（既不是请求里的参数，"
                        + "也不是 header:名称 / URL_PATH[n] / BODY 这类合法位置）: {1}",
                "[STEP2] dropped {0} unmappable parameter mapping(s) (neither a real parameter of the request nor a valid "
                        + "position such as header:Name / URL_PATH[n] / BODY): {1}");
        put("log.step2.droppedDuplicate", "[步骤2] 丢弃 {0} 条重复的 multipart 映射（filename / name 属性与部件名是同一个"
                        + "上传面，只留部件名）: {1}",
                "[STEP2] dropped {0} duplicate multipart mapping(s) (a filename/name attribute is the same upload surface "
                        + "as its part name; only the part name is kept): {1}");
        put("log.json.parseFailed", "[发送错误] JSON body 解析失败，无法注入 | 位置: {0}",
                "[SEND ERROR] the JSON body could not be parsed, cannot inject | position: {0}");
        put("log.json.notObject", "[发送错误] JSON body 顶层不是对象，无法注入 | 位置: {0}",
                "[SEND ERROR] the JSON body is not a top-level object, cannot inject | position: {0}");
        put("log.json.pathMissing", "[发送错误] JSON 中不存在该路径，已跳过 | 位置: {0}",
                "[SEND ERROR] no such path in the JSON, skipping | position: {0}");
        put("log.json.writeBackFailed", "[发送错误] JSON 路径写回失败，已跳过 | 位置: {0}",
                "[SEND ERROR] writing the JSON path back failed, skipping | position: {0}");
        put("log.json.exception", "[AI错误] modifyJsonRequest 失败", "[AI ERROR] modifyJsonRequest raised");
        put("log.mp.noBoundary", "[发送错误] multipart 请求缺少 boundary，无法注入 | 位置: {0}",
                "[SEND ERROR] the multipart request has no boundary, cannot inject | position: {0}");
        put("log.mp.noReplaceableField", "[发送错误] multipart 中未找到可替换的字段，已跳过 | 位置: {0}",
                "[SEND ERROR] no replaceable field in the multipart body, skipping | position: {0}");
        put("log.mp.noInjectableField", "[发送错误] multipart 中未找到可注入的字段，已跳过 | 位置: {0}",
                "[SEND ERROR] no injectable field in the multipart body, skipping | position: {0}");
        put("log.mp.exception", "[AI错误] modifyMultipartRequest失败", "[AI ERROR] modifyMultipartRequest raised");
        put("log.mp.rewriteException", "[AI错误] rewriteMultipartPartBytes 失败", "[AI ERROR] rewriteMultipartPartBytes raised");
        put("log.mp.partsException", "[AI错误] modifyMultipartParts失败", "[AI ERROR] modifyMultipartParts raised");

        put("log.step5.oobUnjudged", "[步骤5] {0} → {1}；响应与基线也无差异 → 未判定（本条不参与结论）",
                "[STEP5] {0} → {1}; the response is also identical to the baseline → not judged (this payload does not feed the verdict)");
        // 通道不可用 + 模型也没能从响应确认：这条载荷**靠回连才能判定**，通道坏了就没判过，
        // 不能记成「未发现漏洞」（那会把「证据不足」读成「目标没问题」）。
        // 不重复写失败原因 —— 上一行 [外带检测] 已经说清楚了，这行只留结论
        put("log.step5.oobUnjudgedNoConfirm", "[步骤5] {0} → 未判定（回连通道不可用，模型也未能从响应确认；本条不参与结论）",
                "[STEP5] {0} → not judged (callback channel unavailable and the model could not confirm it from the response; this payload does not feed the verdict)");
        put("log.step5.noDiff", "[步骤5] {0} → 响应与基线逐字节一致、耗时无差、无回连记录 → 无变化即无漏洞（跳过 AI 验证）",
                "[STEP5] {0} → byte-identical response, no timing delta, no callback record → no change means no vulnerability (AI verification skipped)");
        put("log.step5.verifyFailedPrint", "[AI错误] 任务 #{0} | 载荷{1} AI验证失败 | 漏洞类型: {2} | 测试数据: {3} | 失败原因: {4}",
                "[AI ERROR] task #{0} | payload {1} AI verification failed | vuln type: {2} | test data: {3} | reason: {4}");
        // 验证失败的原因 —— 调用级失败（网络/HTTP）自己会打日志，这几条补的是**回复层面**的：
        // 拿不到内容字段、回复里没有 JSON。那一类原本静默，日志里和「网络抖动」分不开。
        put("verify.fail.unknown", "未记录", "not recorded");
        put("verify.fail.call", "AI 调用失败（HTTP 码或异常见上面的 [API错误] / [AI错误] 行）",
                "AI call failed (see the [API ERROR] / [AI ERROR] line above for the HTTP code or exception)");
        put("verify.fail.envelope", "AI 响应里没有可识别的内容字段（信封不是已知形态，常见于网关返回的 200+错误 JSON）",
                "AI response had no recognisable content field (unknown envelope, often a gateway's 200 + error JSON)");
        put("verify.fail.noJson", "AI 回复里找不到 JSON（多半是拒答或说明性文字，而非网络问题）",
                "no JSON found in the AI reply (usually a refusal or prose, not a network problem)");
        put("verify.fail.emptyContent", "AI 回复的 content 为空 —— 模型没给出可见答案（不是「回复里没有 JSON」）",
                "AI reply's content was empty — the model produced no visible answer (this is not \"no JSON in the reply\")");
        put("verify.fail.finishReason", " | finish_reason={0}", " | finish_reason={0}");
        put("verify.fail.hasReasoning",
                " | 回复含思维链 {0} 字符（思考与可见输出共用 max_tokens，容易把可见答案挤空）",
                " | reply carried {0} chars of reasoning (thinking and visible output share max_tokens, which can squeeze the answer out)");
        put("verify.fail.exception", "验证过程抛异常: {0}", "verification threw: {0}");
        put("verify.fail.snippet", " | 回复片段: {0}", " | reply excerpt: {0}");
        put("log.step5.verifyFailed", "[步骤5] {0} → AI 验证失败（已重试；本条未能判定）",
                "[STEP5] {0} → AI verification failed (already retried; this payload is not judged)");
        put("log.step5.noVuln", "[步骤5] {0} → 未发现漏洞", "[STEP5] {0} → no vulnerability found");
        put("log.step6.found", "[步骤6] {0} → 发现漏洞：{1}（置信度 {2}%）",
                "[STEP6] {0} → vulnerability found: {1} (confidence {2}%)");
        put("log.step5.dup", "[步骤5] {0} → 与已有记录重复（同参数同类型），保留置信度更高的那条（本条 {1}%）",
                "[STEP5] {0} → duplicate of an existing record (same parameter, same type); keeping the higher-confidence one (this one: {1}%)");
        put("log.step5.dupPlain", "[步骤5] {0} → 与已有记录重复（同参数同类型），保留置信度更高的那条",
                "[STEP5] {0} → duplicate of an existing record (same parameter, same type); keeping the higher-confidence one");
        put("log.send.urlPathInjectFailed", "[发送错误] URL 路径注入失败 | 位置: {0}",
                "[SEND ERROR] injecting into the URL path failed | position: {0}");
        put("log.step1.nullResponse", "[步骤1] makeHttpRequest 返回 null，本次无法继续分析",
                "[STEP1] makeHttpRequest returned null, the analysis cannot continue");
        put("log.shiro.markerFailed", "[Shiro] 密钥标记无法展开（密钥不是 16 字节的合法 Base64），这条载荷按原文发送，不会有回连",
                "[Shiro] the key marker could not be expanded (the key is not 16 bytes of valid Base64); the payload is sent verbatim and will not call back");
        put("log.verify.exception", "[AI错误] verifyVulnerability", "[AI ERROR] verifyVulnerability raised");
        put("log.taskHeader", "任务 #{0} | {1}", "Task #{0} | {1}");
        put("log.step5.typeMismatch", "[步骤5] 模型给出的类型（{0}）与本次扫描类型（{1}）不一致，已按扫描类型记录 | 载荷声明类型: {2}",
                "[STEP5] the type the model reported ({0}) differs from the scanned type ({1}); recording it as the scanned type | payload-declared type: {2}");
        put("log.ai.retry", "[AI重试] {0}，1 秒后重试（第 {1}/{2} 次）", "[AI RETRY] {0}, retrying in 1 second (attempt {1}/{2})");
        put("log.ai.thinkingRejected",
                "[AI重试] 端点+模型 {0} 不接受「关闭思考」参数（HTTP 400），已去掉该参数重试，本次加载期间不再给它发送",
                "[AI RETRY] endpoint+model {0} rejected the disable-thinking parameter (HTTP 400); retried without it and will not send it again this session");

        // ---- 扫描流水（AIEngine）----
        put("log.step6.foundArithmetic", "[步骤6] {0} → 发现漏洞：{1}（OGNL 求值证据 {2}，置信度 {3}%）",
                "[STEP6] {0} → vulnerability found: {1} (OGNL evaluation evidence {2}, confidence {3}%)");
        put("log.step6.foundOob", "[步骤6] {0} → 发现漏洞：{1}（回连记录 {2} 条，置信度 {3}%）",
                "[STEP6] {0} → vulnerability found: {1} ({2} callback record(s), confidence {3}%)");

        // ---- 漏洞描述（进报告正文；与报告一致，按扫描当时的语言定稿）----
        put("finding.strutsArithmetic", "Struts2 OGNL 求值证据：载荷 {0} 里的算术表达式被服务器求值，"
                        + "响应中出现了结果 {1}（该值在基线响应里不存在，只可能是表达式被求值算出来的）。"
                        + "\n注意：不少演示环境同时把原始输入也回显在页面上（如 your input id: {0}），"
                        + "那是回显而不是求值结果 —— 证据是求值后的值。",
                "Struts2 OGNL evaluation evidence: the arithmetic expression in payload {0} was evaluated by the server and the "
                        + "result {1} appeared in the response (that value is absent from the baseline, so it can only come from "
                        + "evaluating the expression).\nNote: many demo setups also echo the raw input on the page (e.g. "
                        + "your input id: {0}) — that is an echo, not the evaluated result; the evidence is the evaluated value.");
        put("finding.oobEvidence", "外带回连证据：目标解析了本次请求的专属域名 {0}"
                        + "（载荷在 {1} 位置被目标执行；该前缀由本次请求随机生成，只可能来自这条载荷）。\n回连记录：\n- {2}",
                "Out-of-band callback evidence: the target resolved the dedicated domain {0} for this request (the payload was "
                        + "executed at position {1}; that prefix is generated randomly per request and can only come from this "
                        + "payload).\nCallback records:\n- {2}");

        // ---- 报告里的修复建议（按类型 key，索引从 1 起；getFixSuggestions 逐个查直到缺号）----
        put("fix.SQL_INJECTION.1", "使用参数化查询（PreparedStatement）而非字符串拼接SQL语句。",
                "Use parameterised queries (PreparedStatement) instead of concatenating SQL strings.");
        put("fix.SQL_INJECTION.2", "使用ORM框架（如Hibernate、MyBatis）时避免动态SQL拼接。",
                "When using an ORM (Hibernate, MyBatis), avoid dynamic SQL concatenation.");
        put("fix.SQL_INJECTION.3", "对用户输入进行严格的白名单校验。",
                "Validate user input against a strict allowlist.");
        put("fix.SQL_INJECTION.4", "数据库账户使用最小权限原则，禁止使用DBA或管理员权限。",
                "Give the database account least privilege — no DBA or admin rights.");
        put("fix.XSS.1", "对所有用户输入进行HTML转义（ESCAPE HTML）。",
                "HTML-escape all user input.");
        put("fix.XSS.2", "使用Content-Security-Policy (CSP) 响应头限制脚本执行。",
                "Restrict script execution with a Content-Security-Policy (CSP) response header.");
        put("fix.XSS.3", "设置HttpOnly和Secure标志防止Cookie被JavaScript读取。",
                "Set the HttpOnly and Secure flags so JavaScript cannot read cookies.");
        put("fix.XSS.4", "对输出到HTML的内容进行上下文感知编码。",
                "Encode context-aware when writing into HTML.");
        put("fix.COMMAND_INJECTION.1", "避免使用用户输入直接调用系统命令。",
                "Never pass user input straight into a system command.");
        put("fix.COMMAND_INJECTION.2", "使用API替代系统命令执行，如Java的ProcessBuilder或Runtime.exec()。",
                "Prefer APIs over shelling out — e.g. Java's ProcessBuilder or Runtime.exec().");
        put("fix.COMMAND_INJECTION.3", "如果必须执行命令，对用户输入进行严格的白名单校验。",
                "Where a command is unavoidable, validate user input against a strict allowlist.");
        put("fix.COMMAND_INJECTION.4", "使用安全的沙箱环境执行动态代码。",
                "Run dynamic code in a properly sandboxed environment.");
        put("fix.FILE_UPLOAD.1", "对上传文件类型进行白名单校验，只允许已知安全类型。",
                "Validate uploaded file types against an allowlist of known-safe types.");
        put("fix.FILE_UPLOAD.2", "验证文件魔数和MIME类型，而非仅依赖文件扩展名。",
                "Check the magic bytes and MIME type, not just the file extension.");
        put("fix.FILE_UPLOAD.3", "将上传文件存储在Web根目录之外或云存储。",
                "Store uploads outside the web root, or in object storage.");
        put("fix.FILE_UPLOAD.4", "重命名上传文件，使用随机文件名，保留原始扩展名。",
                "Rename uploads to random names, keeping the original extension only for display.");
        put("fix.FILE_UPLOAD.5", "限制上传文件大小和执行权限。",
                "Cap the upload size and strip execute permissions.");
        put("fix.SSRF.1", "对用户输入的URL/主机名进行严格校验，禁止访问内网IP段（10.x.x.x、172.16.x.x、192.168.x.x、127.x.x.x）。",
                "Strictly validate user-supplied URLs/hostnames and block private ranges (10.x.x.x, 172.16.x.x, 192.168.x.x, 127.x.x.x).");
        put("fix.SSRF.2", "使用URL解析库验证URL合法性，解析后再次校验主机名是否为内网IP。",
                "Validate the URL with a parsing library and re-check the resolved hostname for private IPs.");
        put("fix.SSRF.3", "禁止将用户输入作为URL的一部分直接发起请求，限制允许的协议（http/https）和端口范围。",
                "Never request a user-supplied URL directly; restrict allowed protocols (http/https) and the port range.");
        put("fix.SSRF.4", "配置Web服务器和防火墙策略，禁止从服务器访问内部服务（数据库、Redis、Memcached等）。",
                "Configure the web server and firewall so it cannot reach internal services (databases, Redis, Memcached).");
        put("fix.SSRF.5", "使用网络隔离，为SSRF易受攻击的功能划分独立的DMZ区域。",
                "Network-isolate: put SSRF-prone functionality in its own DMZ segment.");
        put("fix.SSRF.6", "启用DNS rebinding保护，禁用DNS缓存。",
                "Enable DNS-rebinding protection and disable DNS caching.");
        put("fix.SSRF.7", "对内网资源访问实施认证和授权机制。",
                "Require authentication and authorisation for internal resources.");
        put("fix.XXE.1", "禁用XML外部实体（DTD）。",
                "Disable XML external entities (DTDs).");
        put("fix.XXE.2", "使用安全的XML解析器，禁用DTD和外部实体。",
                "Use a hardened XML parser with DTDs and external entities disabled.");
        put("fix.XXE.3", "对用户上传的XML文件进行白名单校验。",
                "Validate uploaded XML against an allowlist.");
        put("fix.XXE.4", "使用JSON替代XML进行数据传输。",
                "Use JSON instead of XML for data transfer.");
        put("fix.SSTI.1", "禁止用户输入直接插入模板。",
                "Never insert user input directly into a template.");
        put("fix.SSTI.2", "使用模板引擎的沙箱模式，禁用危险标签和函数。",
                "Use the template engine's sandbox mode and disable dangerous tags and functions.");
        put("fix.SSTI.3", "对用户输入进行严格过滤和转义。",
                "Strictly filter and escape user input.");
        put("fix.SSTI.4", "考虑使用静态模板生成替代动态渲染。",
                "Consider static template generation instead of dynamic rendering.");
        put("fix.FASTJSON.1", "升级到 Fastjson2（2.0.46 及以上），fastjson 1.x 官方仓库已归档、CVE-2026-16723 在 1.2.68~1.2.83 上默认配置即可利用且无补丁。",
                "Upgrade to Fastjson2 (2.0.46+): fastjson 1.x is archived upstream, and CVE-2026-16723 is exploitable with default settings on 1.2.68-1.2.83 with no patch.");
        put("fix.FASTJSON.2", "无法升级时开启 SafeMode（-Dfastjson.parser.safeMode=true）或换用 1.2.83_noneautotype 受限构建。",
                "If upgrading is not possible, enable SafeMode (-Dfastjson.parser.safeMode=true) or move to the restricted 1.2.83_noneautotype build.");
        put("fix.FASTJSON.3", "不要用 JSON.parse 直接解析用户可控输入；必须绑定时用 JSONObject 而不是 Object/Map 字段承载未知类型。",
                "Do not parse user-controlled input with JSON.parse directly; when binding is required, use JSONObject rather than Object/Map fields for unknown types.");
        put("fix.FASTJSON.4", "限制应用服务器出网（尤其禁止访问外部 JAR/HTTP 资源），可阻断 CVE-2026-16723 的远程 JAR 加载链。",
                "Restrict the application server's egress (especially external JAR/HTTP resources) — this breaks the remote JAR loading chain in CVE-2026-16723.");
        put("fix.FASTJSON.5", "排查日志中异常的 @type 值（含 jar:http://、ldap://、rmi://）与异常外连。",
                "Watch logs for anomalous @type values (jar:http://, ldap://, rmi://) and unexpected outbound connections.");
        put("fix.LOG4J2.1", "升级 log4j-core：2.17.1 及以上（2.0-beta9~2.14.1 为 Log4Shell 完整可利用版本，2.15.0/2.16.0 也有已被绕过的记录）。",
                "Upgrade log4j-core to 2.17.1 or later (2.0-beta9 to 2.14.1 is fully exploitable for Log4Shell, and 2.15.0/2.16.0 have documented bypasses).");
        put("fix.LOG4J2.2", "2.16.0 起 JNDI 默认关闭；确认 log4j2.enableJndiLookup 未被打开，并关闭 Message Lookups（log4j2.formatMsgNoLookups=true）。",
                "JNDI is off by default from 2.16.0; confirm log4j2.enableJndiLookup is not enabled and turn off Message Lookups (log4j2.formatMsgNoLookups=true).");
        put("fix.LOG4J2.3", "关注 2025-2026 的新披露：CVE-2026-34478/34480/34481（日志注入与格式破坏，修复于 2.25.4）、CVE-2026-49844（MapMessage 非有限浮点，修复于 2.25.5/2.26.1）、CVE-2025-68161（Socket Appender 未校验 TLS 主机名，修复于 2.25.3）。",
                "Track the 2025-2026 disclosures: CVE-2026-34478/34480/34481 (log injection and format corruption, fixed in 2.25.4), CVE-2026-49844 (MapMessage non-finite floats, fixed in 2.25.5/2.26.1), CVE-2025-68161 (Socket Appender does not verify the TLS hostname, fixed in 2.25.3).");
        put("fix.LOG4J2.4", "序列化事件接收器（SocketAppender/序列化 Log4jLogEvent）配置存在反序列化白名单绕过风险（java.rmi.MarshalledObject），建议禁用或对来源做网络隔离。",
                "Serialised event receivers (SocketAppender / serialised Log4jLogEvent) risk a deserialisation allowlist bypass (java.rmi.MarshalledObject); disable them or isolate the source on the network.");
        put("fix.LOG4J2.5", "对用户可控输入做日志前过滤（过滤 ${ 与 jndi/lower/upper 等 lookup 关键字），并限制服务器出网。",
                "Filter user-controlled input before logging (strip ${ and lookup keywords such as jndi/lower/upper) and restrict server egress.");
        put("fix.STRUTS2.1", "升级到 Struts 6.8.0 / 7.1.1 及以上（S2-068），并确认 S2-069（CVE-2025-68493，2.0.0~6.1.0）已修复到 6.1.1+。",
                "Upgrade to Struts 6.8.0 / 7.1.1 or later (S2-068) and confirm S2-069 (CVE-2025-68493, 2.0.0-6.1.0) is patched to 6.1.1+.");
        put("fix.STRUTS2.2", "关闭开发者模式（struts.devMode=false）与 OGNL 静态方法访问，升级到 2.5.30+/6.x 以启用 OGNL 沙箱。",
                "Turn off dev mode (struts.devMode=false) and static OGNL method access; upgrade to 2.5.30+/6.x to get the OGNL sandbox.");
        put("fix.STRUTS2.3", "为 XML 请求体禁用外部实体（S2-069 走的就是 XXE），并对 multipart 上传设置大小与数量上限（S2-068 靠磁盘耗尽）。",
                "Disable external entities for XML bodies (S2-069 is XXE) and cap the size and count of multipart uploads (S2-068 is disk exhaustion).");
        put("fix.STRUTS2.4", "不要用用户输入拼接 Content-Type、namespace 或 URL 路径。",
                "Never concatenate user input into Content-Type, namespace or URL paths.");
        put("fix.STRUTS2.5", "对返回页关闭详细报错（struts.devMode/Struts 报错页会泄露内部信息）。",
                "Disable detailed error pages (struts.devMode and the Struts error page leak internals).");
        put("fix.SHIRO.1", "设置随机且足够强的 rememberMe 密钥（CookieRememberMeManager.setCipherKey），绝不要使用默认或公开的硬编码密钥。",
                "Set a random, sufficiently strong rememberMe key (CookieRememberMeManager.setCipherKey); never ship a default or public hard-coded key.");
        put("fix.SHIRO.2", "升级到 Shiro 3.0.0 及以上（CVE-2026-56130 rememberMe 缺少过期校验、CVE-2026-56091 shiro-guice 认证绕过均在其中修复），并注意 CVE-2026-43828（Cookie 缺 secure 属性）。",
                "Upgrade to Shiro 3.0.0 or later (it fixes CVE-2026-56130's missing rememberMe expiry check and CVE-2026-56091's shiro-guice auth bypass) and note CVE-2026-43828 (cookies missing the Secure attribute).");
        put("fix.SHIRO.3", "如果业务用不到 rememberMe，直接关闭该功能；关闭后仍建议保留对 deleteMe 回显的监控以便发现探测行为。",
                "If rememberMe is not needed, turn it off — but keep monitoring for deleteMe responses so probing stays visible.");
        put("fix.SHIRO.4", "对 rememberMe cookie 做长度与格式校验，并对反序列化对象做白名单（Java 反序列化过滤器 / JEP 290）。",
                "Validate the length and format of the rememberMe cookie and apply a deserialisation allowlist (a Java deserialisation filter / JEP 290).");
        put("fix.SHIRO.5", "关注 CVE-2023-34478（路径穿越，1.12.0/2.0.0-alpha-3 前）等历史问题，避免只盯着反序列化。",
                "Track older issues such as CVE-2023-34478 (path traversal, before 1.12.0/2.0.0-alpha-3) rather than looking only at deserialisation.");

        // ---- 导出报告（生成时按当时的语言定稿）----
        put("report.html.title", "Zack-AI-Scanner 漏洞报告", "Zack-AI-Scanner Vulnerability Report");
        put("report.html.h1", "<h1>Zack-AI-Scanner 漏洞报告</h1>", "<h1>Zack-AI-Scanner Vulnerability Report</h1>");
        put("report.html.meta", "<p class=\"meta\">版本 v3.0 | 生成时间", "<p class=\"meta\">Version v3.0 | Generated");
        put("report.html.taskInfo", "<h2>任务信息</h2>", "<h2>Task</h2>");
        put("report.label.taskId", "任务编号", "Task ID");
        put("report.label.method", "请求方法", "Method");
        put("report.label.url", "目标 URL", "Target URL");
        put("report.label.testedParams", "测试参数", "Tested parameters");
        put("report.label.vulnCount", "漏洞数量", "Findings");
        put("report.label.risk", "综合风险", "Overall risk");
        put("report.label.aiTag", "AI 标签", "AI tag");
        put("report.label.created", "创建时间", "Created");
        put("report.label.finished", "完成时间", "Finished");
        put("report.html.noVuln", "<section class=\"card\"><h2>扫描结论</h2><p>No vulnerability was found.</p></section>",
                "<section class=\"card\"><h2>Conclusion</h2><p>No vulnerability was found.</p></section>");
        put("report.html.vulnHeading", "漏洞 #{0} - {1}", "Vulnerability #{0} - {1}");
        put("report.html.riskLine", "风险等级：{0} | 漏洞类型：{1} | 存在漏洞的参数：{2}",
                "Severity: {0} | Type: {1} | Vulnerable parameter: {2}");
        put("report.html.payload", "<h3>测试载荷</h3>", "<h3>Test payload</h3>");
        put("report.html.evidence", "<h3>响应特征分析</h3>", "<h3>Response analysis</h3>");
        put("report.html.request", "<h3>完整请求包</h3>", "<h3>Full request</h3>");
        put("report.html.response", "<h3>完整响应包</h3>", "<h3>Full response</h3>");
        put("report.html.fixes", "<h3>修复建议</h3>", "<h3>Remediation</h3>");
        put("report.clickToToggle", "点击展开/收起", "Click to expand/collapse");
        put("report.notRecorded", "未记录", "not recorded");
        put("report.none", "无", "none");
        put("report.unknown", "未知", "unknown");

        put("report.md.title", "# Zack-AI-Scanner 漏洞报告\n\n", "# Zack-AI-Scanner Vulnerability Report\n\n");
        put("report.md.version", "- 版本: v3.0\n", "- Version: v3.0\n");
        put("report.md.taskId", "- 任务编号: #", "- Task ID: #");
        put("report.md.url", "- 目标 URL: ", "- Target URL: ");
        put("report.md.method", "- 请求方法: ", "- Method: ");
        put("report.md.testedParams", "- 测试参数: ", "- Tested parameters: ");
        put("report.md.risk", "- 综合风险: ", "- Overall risk: ");
        put("report.md.generated", "- 生成时间: ", "- Generated: ");
        put("report.md.noVuln", "## 扫描结论\n\n未发现漏洞。\n\n", "## Conclusion\n\nNo vulnerability was found.\n\n");
        put("report.md.vulnHeading", "## 漏洞 #{0} - {1}", "## Vulnerability #{0} - {1}");
        put("report.md.type", "- 漏洞类型：", "- Type: ");
        put("report.md.level", "- 风险等级：", "- Severity: ");
        put("report.md.position", "- 存在漏洞的参数：", "- Vulnerable parameter: ");
        put("report.md.payload", "### 测试载荷\n\n", "### Test payload\n\n");
        put("report.md.evidence", "### 响应特征分析\n\n", "### Response analysis\n\n");
        put("report.md.request", "### 完整请求包\n\n", "### Full request\n\n");
        put("report.md.response", "### 完整响应包\n\n", "### Full response\n\n");
        put("report.md.fixes", "### 修复建议\n\n", "### Remediation\n\n");

        put("report.noPayloadsSent", "无（本次未发出任何载荷）", "none (no payload was sent in this scan)");
        put("report.fix.genericHtml", "<li>对用户输入进行严格校验和过滤。</li><li>遵循最小权限原则。</li><li>实施纵深防御策略。</li>",
                "<li>Strictly validate and filter user input.</li><li>Follow the principle of least privilege.</li><li>Apply defence in depth.</li>");
        put("report.fix.genericMd", "- 对所有用户输入进行严格校验和过滤。\n- 遵循最小权限原则。\n- 实施纵深防御策略。\n",
                "- Strictly validate and filter all user input.\n- Follow the principle of least privilege.\n- Apply defence in depth.\n");

        put("log.loadBanner", "================================\nZack-AI-Scanner v3.0 已加载"
                        + "\nGithub: https://github.com/ZackSecurity/Zack-AI-Scanner\n================================",
                "================================\nZack-AI-Scanner v3.0 loaded"
                        + "\nGithub: https://github.com/ZackSecurity/Zack-AI-Scanner\n================================");

        // GPLv3 的「How to Apply These Terms」建议交互式程序启动时打一段简短的版权 + 免责声明。
        // 单独一行而不是并进 log.loadBanner：那一行被 ExtenderHarness 按字面断言着（含版本号）。
        put("log.license", "Copyright (C) 2026 Zack AI Scanner\n"
                        + "本程序是自由软件，无任何担保（ABSOLUTELY NO WARRANTY）；"
                        + "可在 GPL-3.0-or-later 条款下再分发，详见随附的 LICENSE。",
                "Copyright (C) 2026 Zack AI Scanner\n"
                        + "This program comes with ABSOLUTELY NO WARRANTY; it is free software "
                        + "and you are welcome to redistribute it under GPL-3.0-or-later. See LICENSE.");

        put("log.counters", " | 发包 {0}{1}{2}{3} | 用时 {4} 秒", " | sent {0}{1}{2}{3} | {4}s");
        put("log.counters.skipped", "（跳过 {0}）", " (skipped {0})");
        put("log.counters.noDiff", " | 无差异跳过验证 {0}", " | {0} skipped as no-diff");
        put("log.counters.noResponse", " | 未响应（未判定）{0}", " | {0} sent with no response (not judged)");
        put("log.payloadTruncated", "…（共 {0} 字符）", "…({0} chars total)");
        put("err.sentRequestImmutable", "这份请求是已经发出去的记录，不可修改",
                "this request is the record of what was sent and cannot be modified");
        put("err.targetNoResponse", "目标未返回响应（makeHttpRequest 返回 null）",
                "the target returned no response (makeHttpRequest returned null)");
        put("log.step2.analysisDefault", "分析完成", "analysis complete");

        put("log.api.attempt", "（第 {0} 次）", " (attempt {0})");
        put("log.api.retryExhausted", "（重试后仍失败）", " (still failing after retry)");

        // ---- 配置页 ----
        put("cfg.provider", "AI 服务商:", "AI provider:");
        put("cfg.apiEndpoint", "API 地址:", "API endpoint:");
        put("cfg.modelsEndpoint", "模型接口:", "Models API:");
        put("cfg.model", "选择模型:", "Model:");
        put("cfg.verifyStatus", "验证状态:", "Status:");
        put("cfg.oob", "外带回连:", "OOB callback:");
        put("cfg.autoScan", "自动扫描:", "Auto scan:");
        put("cfg.whitelist", "白名单:", "Allowlist:");
        put("cfg.fetchModels", "获取模型", "Fetch models");
        put("cfg.save", "保存配置", "Save");
        put("cfg.verifyKey", "验证 Key", "Verify key");
        put("cfg.testOob", "测试回连", "Test callback");
        put("cfg.oobCheck", "启用（无回显漏洞取证：命令注入外带、Blind XXE、SSRF 出网、组件类反序列化）",
                "Enabled (evidence for no-echo bugs: OOB command injection, blind XXE, SSRF egress, component deserialization)");
        put("cfg.autoScanCheck", "Proxy 流量自动扫描（只收带参数的请求；同一接口按参数名只扫一次）",
                "Auto-scan proxied traffic (parameterised requests only; one scan per endpoint by parameter names)");
        put("cfg.whitelistHint", "留空 = 全部；一行一个 host（同一行用英文逗号也行），域名含子域；离开输入框生效",
                "Empty = all; one host per line (or comma-separated), a domain also matches its subdomains; applies on focus loss");
        put("status.verified", "验证成功", "Verified");
        put("status.verifyFailed", "验证失败", "Verification failed");
        put("status.verifyError", "验证异常", "Verification error");
        put("status.verifyingDots", "验证中...", "Verifying...");
        put("status.testingDots", "测试中...", "Testing...");
        put("status.oobOk", "回连可用", "Callback OK");
        put("msg.needApiKey", "请先输入 API Key", "Enter an API key first");
        put("msg.needApiKeyInput", "请输入 API Key", "Enter the API key");
        put("msg.needApiEndpoint", "请输入 API 地址", "Enter the API endpoint");
        put("msg.needModelEndpoint", "请先填写模型接口地址", "Fill in the models endpoint first");
        put("msg.needModelsEndpoint", "请输入模型接口地址", "Enter the models endpoint");
        put("msg.needModelName", "请输入或选择具体的模型名称", "Enter or pick a concrete model name");
        put("msg.fetching", "获取中...", "Fetching...");
        put("msg.fetchingList", "正在获取...", "Fetching...");
        put("msg.oobTestError", "回连测试异常：", "Callback test error: ");
        put("msg.configSaved", "配置已保存成功！", "Configuration saved.");
        put("dlg.success", "成功", "Success");
        put("dlg.oobSelfTest", "回连自检", "Callback self-test");
        put("logcfg.fetchFailed", "[配置] 获取模型列表失败", "[CONFIG] fetching the model list failed");
        put("logcfg.fetchOk", "[配置] 获取模型列表成功: {0} 个模型", "[CONFIG] model list fetched: {0} model(s)");
        put("logcfg.fetchError", "[配置] 获取模型列表异常", "[CONFIG] model list fetch raised");
        put("logcfg.saved", "[配置] 已保存: ", "[CONFIG] saved: ");
        put("logcfg.oobOk", "[配置] 回连自检通过：", "[CONFIG] callback self-test passed: ");
        put("logcfg.indent", "[配置] 　", "[CONFIG]   ");
        put("logcfg.whitelistUpdated", "[配置] 自动扫描白名单已更新: ", "[CONFIG] auto-scan allowlist updated: ");
        put("logcfg.whitelistEmpty", "（空 = 全部 Proxy 目标）", " (empty = all proxied targets)");

        // ---- 日志统计页 ----
        put("log.stat.total", "总任务数", "Tasks");
        put("log.stat.completed", "已完成", "Completed");
        put("log.stat.vulns", "发现漏洞", "Findings");
        put("log.stat.scanning", "正在扫描", "Scanning");
        put("log.title", "实时日志", "Live Log");
        put("btn.clearLog", "清空日志", "Clear log");
        put("btn.exportLog", "导出日志", "Export log");
        put("msg.logCleared", "日志已清空", "Log cleared");
        put("msg.logExported", "日志已导出到: {0}", "Log exported to: {0}");
        put("msg.exportFailed", "导出失败: {0}", "Export failed: {0}");
        put("dlg.error", "错误", "Error");

        // ---- 任务列表页 ----
        put("tasks.title", "扫描任务列表", "Scan Tasks");
        put("tasks.search", "搜索:", "Search:");
        put("tasks.filter", "筛选:", "Filter:");
        put("btn.clearCompleted", "清空已完成", "Clear completed");
        put("btn.exportReport", "导出报告", "Export report");
        put("col.select", "选择", "Sel");
        put("col.id", "编号", "ID");
        put("col.method", "方法", "Method");
        put("col.url", "URL", "URL");
        put("col.status", "AI状态", "AI Status");
        put("col.result", "结果", "Result");
        put("col.vulnCount", "漏洞数", "Findings");
        put("col.aiTag", "AI标签", "AI Tag");
        put("menu.deleteTask", "删除任务", "Delete task");
        put("menu.pauseScan", "暂停扫描", "Pause scan");
        put("menu.resumeScan", "继续扫描", "Resume scan");
        put("menu.copyUrl", "复制URL", "Copy URL");
        put("tip.tasks.header", "勾选最左边的方框可以选中多个任务，然后右键批量操作（删除 / 暂停 / 继续 / 复制URL）；"
                        + "一个都没勾时右键作用于光标下那一行",
                "Tick the leftmost boxes to select several tasks, then right-click to act on them in bulk "
                        + "(delete / pause / resume / copy URL). With nothing ticked, right-click acts on the row under the cursor.");
        put("dlg.confirmDelete", "确认删除", "Confirm delete");
        put("dlg.deleteOne", "确定要删除任务 #{0} 吗？", "Delete task #{0}?");
        put("dlg.deleteMany", "确定要删除勾选的 {0} 个任务吗？", "Delete the {0} selected tasks?");

        // ---- 任务列表的操作结果日志 ----
        put("msg.deleted", "已删除 {0} 个任务", "Deleted {0} task(s)");
        put("msg.paused", "已暂停 {0} 个任务", "Paused {0} task(s)");
        put("msg.resumed", "已继续 {0} 个任务", "Resumed {0} task(s)");
        put("msg.noScanningToPause", "没有正在扫描的任务需要暂停", "No scanning task to pause");
        put("msg.noPausedToResume", "没有已暂停的任务需要继续", "No paused task to resume");
        put("msg.copiedUrl", "已复制URL到剪贴板", "URL copied to clipboard");
        put("msg.copiedUrls", "已复制 {0} 个 URL 到剪贴板", "Copied {0} URL(s) to clipboard");

        // ---- 任务列表的筛选下拉（判定读枚举，不读这些文案）----
        put("filter.all", "全部", "All");
        put("filter.allLevels", "全部等级", "All levels");
        put("filter.allTypes", "全部类型", "All types");
        put("filter.pending", "待处理", "Pending");
        put("filter.scanning", "扫描中", "Scanning");
        put("filter.finished", "已完成", "Completed");
        // 状态列的 PENDING 文案：池子只有 10 条线程，排队要看得见（见 TaskTablePanel.statusCellOf）。
        // 筛选下拉里仍写「待处理」—— 筛选判的是枚举，不是这行文案。
        put("task.queued", "排队中", "Queued");
        put("task.queuedAt", "排队中 {0}/{1}", "Queued {0}/{1}");
        put("filter.withVuln", "有漏洞", "With findings");
        put("filter.withoutVuln", "无漏洞", "No findings");

        // ---- AI 标签 ----
        put("aitag.analyzing", "分析中", "Analyzing");
        put("aitag.analysisFailed", "分析失败", "Analysis failed");
        put("aitag.noResponse", "无响应", "No response");
        put("aitag.testing", "渗透测试中", "Testing");
        put("aitag.safe", "安全", "Clean");
        put("aitag.cancelled", "已取消", "Cancelled");
        put("aitag.error", "异常", "Error");
    }

    private static void put(String key, String zh, String enText) {
        TABLE.put(key, new String[]{zh, enText});
    }

    // ------------------------------------------------------------------ 线程

    private static void runOnEdt(Runnable r) {
        if (javax.swing.SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            javax.swing.SwingUtilities.invokeLater(r);
        }
    }
}
