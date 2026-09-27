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
package com.zackai.ui;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.ITab;
import com.zackai.core.AIEngine;
import com.zackai.core.ConfigManager;
import com.zackai.core.OASTClient;
import com.zackai.i18n.Msg;
import com.zackai.model.ScanTask;
import com.zackai.model.VulnResult;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Insets;
import java.awt.GridBagConstraints;
import java.nio.charset.StandardCharsets;
import java.awt.GridBagLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class MainPanel
extends JPanel
implements ITab, AIEngine.VulnDiscoveryListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private AIEngine aiEngine;
    private LogPanel logPanel;
    private TaskTablePanel taskTablePanel;
    private TaskDetailPanel taskDetailPanel;
    private JLabel apiKeyStatusLabel;
    private JLabel providerStatusLabel;
    private JLabel modelStatusLabel;
    private JLabel oobStatusLabel;
    /** 语言切换按钮：放顶栏最右，样式与配置页那几个按钮一致（朴素 JButton + 微软雅黑 14 + 110×38） */
    private JButton langButton;
    // 顶栏 API Key 格存的是**状态**而不是文本：切语言时要用新语言重贴，存文本就没法重贴了。
    // 也正因为存了状态，切语言的钩子不必去调 refreshConfigStatus(true)（那会真的打一次 HTTP 验证请求）
    private String apiKeyStatusKey = "status.unverified";
    private Color apiKeyStatusColor = new Color(200, 100, 100);
    private List<ScanTask> tasks;
    private int taskIdCounter = 1;
    private ExecutorService executorService;
    /** 扫描期间的就地刷新：任务行与统计以前只在「开始前 / 结束 / 首个漏洞」时更新，整场扫描都显示旧值 */
    private javax.swing.Timer refreshTimer;
    private static final Color BG_WHITE = Color.WHITE;
    private static final Color TEXT_DARK = new Color(33, 37, 41);
    private static final Color BORDER_GRAY = new Color(210, 214, 220);
    /** 顶栏显示的 OOB 供应商名：从服务地址里取主机名，免得同一个地址在界面和代码里各写一份 */
    private static final String OOB_PROVIDER = OASTClient.DEFAULT_SERVER.replaceFirst("^[a-zA-Z]+://", "");

    public MainPanel(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, LogPanel logPanel) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.logPanel = logPanel;
        this.aiEngine = new AIEngine(callbacks, helpers, logPanel, this);
        this.tasks = new ArrayList<ScanTask>();
        this.executorService = Executors.newFixedThreadPool(10);
        this.initUI();
        // 每秒把任务行与统计刷新一遍（EDT 上跑）：状态列/AI标签/漏洞数要能跟着扫描进度走。
        // 就地更新已有行，不重建模型，选中行不受影响。
        this.refreshTimer = new javax.swing.Timer(1000, e -> {
            this.updateStats();
            if (this.taskTablePanel != null) {
                this.taskTablePanel.refreshAllTasks();
            }
        });
        this.refreshTimer.start();
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return this.callbacks;
    }

    private void initUI() {
        this.setLayout(new BorderLayout(10, 10));
        this.setBackground(BG_WHITE);
        this.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        JPanel topPanel = this.createTopPanel();
        this.add((Component)topPanel, "North");
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setBackground(BG_WHITE);
        tabbedPane.setForeground(TEXT_DARK);
        tabbedPane.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 14));
        this.taskTablePanel = new TaskTablePanel(this, this.logPanel);
        tabbedPane.addTab(Msg.t("tab.tasks"), this.taskTablePanel);
        // \u6807\u9898\u8d70\u7ed1\u5b9a\u5668\uff1a\u5207\u8bed\u8a00\u65f6\u6309 index \u91cd\u8d34\u3002tabbedPane \u662f\u5c40\u90e8\u53d8\u91cf\uff0c
        // \u4f46 lambda \u6355\u83b7\u5b83\u5c31\u591f \u2014\u2014 \u4e0d\u5fc5\u4e3a\u4e86\u5207\u8bed\u8a00\u628a\u5b83\u63d0\u5347\u6210\u6210\u5458
        Msg.bind(() -> tabbedPane.setTitleAt(0, Msg.t("tab.tasks")));
        this.taskDetailPanel = new TaskDetailPanel(this.callbacks, this.helpers, this);
        tabbedPane.addTab(Msg.t("tab.detail"), this.taskDetailPanel);
        Msg.bind(() -> tabbedPane.setTitleAt(1, Msg.t("tab.detail")));
        tabbedPane.addTab(Msg.t("tab.log"), this.logPanel.getUiComponent());
        Msg.bind(() -> tabbedPane.setTitleAt(2, Msg.t("tab.log")));
        // \u914d\u7f6e\u653e\u5728\u300c\u65e5\u5fd7\u7edf\u8ba1\u300d\u53f3\u8fb9\uff1a\u5b83\u4ee5\u524d\u662f\u6a21\u6001\u5bf9\u8bdd\u6846\uff0c\u5f39\u7a97\u4e00\u5f00\u6574\u4e2a Burp \u90fd\u88ab\u6321\u4f4f\uff1b
        // \u505a\u6210\u6807\u7b7e\u9875\u540e\u914d\u7f6e\u5185\u5bb9\u548c\u65e5\u5fd7/\u4efb\u52a1\u5e76\u6392\uff0c\u5207\u8fc7\u53bb\u5c31\u80fd\u6539\u3002
        ConfigPanel configPanel = new ConfigPanel(this, this.logPanel);
        tabbedPane.addTab(Msg.t("tab.config"), configPanel);
        Msg.bind(() -> tabbedPane.setTitleAt(3, Msg.t("tab.config")));
        this.add((Component)tabbedPane, "Center");
    }

    private JPanel createTopPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 0));
        panel.setBackground(BG_WHITE);
        panel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER_GRAY, 1), BorderFactory.createEmptyBorder(8, 10, 8, 10)));
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        this.apiKeyStatusLabel = new JLabel("API Key: " + Msg.t("status.unverified"));
        this.apiKeyStatusLabel.setForeground(TEXT_DARK);
        this.apiKeyStatusLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        this.providerStatusLabel = new JLabel(Msg.t("bar.provider") + Msg.providerNameOf(config.getSelectedProvider(), Msg.t("status.notConfigured")));
        this.providerStatusLabel.setForeground(TEXT_DARK);
        this.providerStatusLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        this.modelStatusLabel = new JLabel(Msg.t("bar.model") + (config.getSelectedAgent() != null && !config.getSelectedAgent().isEmpty() ? config.getSelectedAgent() : Msg.t("status.notSelected")));
        this.modelStatusLabel.setForeground(TEXT_DARK);
        this.modelStatusLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        // \u5916\u5e26\u4f9b\u5e94\u5546\u5c31\u5199\u5728\u300c\u6a21\u578b\u300d\u53f3\u8fb9\uff1a\u7528\u7684\u662f\u54ea\u5bb6\u56de\u8fde\u670d\u52a1\uff0c\u4e00\u773c\u53ef\u89c1
        this.oobStatusLabel = new JLabel();
        this.oobStatusLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        Msg.bind(() -> this.oobStatusLabel.setToolTipText(
                Msg.t("bar.oobTip", OASTClient.DEFAULT_SERVER, OASTClient.DEFAULT_BASE_DOMAIN)));
        JPanel centerPanel = new JPanel(new GridBagLayout());
        centerPanel.setBackground(BG_WHITE);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(0, 15, 0, 15);
        gbc.anchor = GridBagConstraints.CENTER;
        centerPanel.add(this.apiKeyStatusLabel, gbc);
        gbc.gridx = 1;
        centerPanel.add(this.providerStatusLabel, gbc);
        gbc.gridx = 2;
        centerPanel.add(this.modelStatusLabel, gbc);
        gbc.gridx = 3;
        centerPanel.add(this.oobStatusLabel, gbc);
        // 语言切换按钮放在**最右边**，样式与配置页那几个按钮完全一致（朴素 JButton、微软雅黑 14、
        // 110×38）—— 以前用的是 UiKit 那套 12 号带悬停效果的，摆在顶栏里和配置页对不上。
        this.langButton = new JButton();
        Msg.bind(() -> {
            this.langButton.setText(Msg.t("btn.lang"));
            this.langButton.setToolTipText(Msg.t("btn.lang.tip"));
        });
        this.langButton.setFont(new Font("微软雅黑", 0, 14));
        // 字号与配置页一致（14 号朴素体），但**尺寸要按顶栏来**：配置页那个 110×38 会把整条顶栏
        // 撑高十几像素（BorderLayout 取各区的最大首选高度），而顶栏那几格状态字只有 13 号
        this.langButton.setPreferredSize(new Dimension(80, 26));
        // 去掉获得焦点时那圈蓝边：顶栏里只有它可获得焦点，一点上去就是蓝的，和配置页按钮看着不像
        this.langButton.setFocusPainted(false);
        this.langButton.addActionListener(e -> this.toggleLanguage());
        this.refreshOobStatus();
        // 顶栏那几格是**派生**文案（每次都要按配置重新算），不是组件自己存的一句话，
        // 所以进钩子而不是绑定器；不注册的话切语言后它们会一直停在旧语言
        Msg.onLangChanged(this::refreshTopBarTexts);
        panel.add((Component)centerPanel, "Center");
        JLabel titleLabel = new JLabel("Zack-AI-Scanner v3.0");
        titleLabel.setForeground(TEXT_DARK);
        titleLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 15));
        // 两侧的间距必须一致：东侧是「占位 + 间距 + 按钮」，西侧不给同样的间距就差一个 gap，整组会偏 5px
        JPanel westPanel = new JPanel(new BorderLayout(10, 0));
        westPanel.setBackground(BG_WHITE);
        westPanel.add((Component)titleLabel, "West");
        JPanel eastPanel = new JPanel(new BorderLayout(10, 0));
        eastPanel.setBackground(BG_WHITE);
        JLabel titleSpacer = new JLabel();
        titleSpacer.setPreferredSize(titleLabel.getPreferredSize());
        eastPanel.add((Component)titleSpacer, "West");
        eastPanel.add((Component)this.langButton, "East");
        // 布局配平：标题靠左、语言按钮靠**最右**，而中间那行状态字仍然居中。
        // BorderLayout 的 Center 从西侧组件右边算起，所以「居中」等价于两侧总宽相等：
        //   西侧 = 标题 + 与按钮等宽的隐形占位
        //   东侧 = 与标题等宽的隐形占位 + 按钮
        // 两边相消。只补一边（只放 titleSpacer，或把按钮单独挂 East）都会让整组偏半个差值。
        JLabel westBalance = new JLabel();
        westBalance.setPreferredSize(this.langButton.getPreferredSize());
        westPanel.add((Component)westBalance, "East");
        panel.add((Component)westPanel, "West");
        panel.add((Component)eastPanel, "East");
        if (config.getApiKey() != null && !config.getApiKey().isEmpty() && config.getSelectedAgent() != null && !config.getSelectedAgent().isEmpty() && config.getApiEndpoint() != null && !config.getApiEndpoint().isEmpty()) {
            this.autoVerifyApiKey();
        }
        return panel;
    }

    public void addRequest(IHttpRequestResponse request, ScanTask.ScanMode scanMode) {
        try {
            if (request == null || request.getRequest() == null || request.getHttpService() == null) {
                this.callbacks.printError(Msg.t("log.addReq.invalidEmpty"));
                this.logPanel.logError(Msg.t("log.addReq.invalid"));
                return;
            }
            byte[] requestBytes = request.getRequest();
            if (requestBytes == null || requestBytes.length == 0) {
                this.callbacks.printError(Msg.t("log.addReq.emptyBody"));
                this.logPanel.logError(Msg.t("log.addReq.emptyBody"));
                return;
            }
            String requestStr = new String(requestBytes, StandardCharsets.UTF_8);
            String[] firstLine = requestStr.split("\r?\n")[0].split(" ");
            if (firstLine.length < 2) {
                this.callbacks.printError(Msg.t("log.addReq.badHttp"));
                this.logPanel.logError(Msg.t("log.addReq.badHttp"));
                return;
            }
            // 上面已经拦掉 length < 2 的情况，这里直接取（原来的三元判断不可达）
            String method = firstLine[0];
            String pathOrUrl = firstLine[1];
            int port = request.getHttpService().getPort();
            String portSuffix = (port == 80 || port == 443) ? "" : (":" + port);
            String url;
            if (pathOrUrl.startsWith("/")) {
                url = request.getHttpService().getProtocol() + "://" + request.getHttpService().getHost() + portSuffix + pathOrUrl;
            } else if (pathOrUrl.startsWith("http")) {
                url = pathOrUrl;
            } else {
                url = request.getHttpService().getProtocol() + "://" + request.getHttpService().getHost() + portSuffix + "/" + pathOrUrl;
            }
            ScanTask task = new ScanTask(this.taskIdCounter++, request, method, url, scanMode);
            this.tasks.add(task);
            this.logPanel.logInfo(Msg.t("log.taskAdded", task.getId(), Msg.scanModeName(task.getScanMode())));
            SwingUtilities.invokeLater(() -> {
                this.taskTablePanel.addTask(task);
                this.updateStats();
            });
            this.executorService.submit(() -> {
                // updateStats 会遍历 this.tasks，而 EDT 上的增删也在改这个列表 ——
                // 以前这里直接调用，抛出的 ConcurrentModificationException 被 submit() 的 Future 吞掉，
                // 任务就这么无声无息地不再扫描（行一直停在「待处理」）。统一回 EDT 读。
                SwingUtilities.invokeLater(() -> {
                    this.taskTablePanel.refreshTask(task);
                    this.updateStats();
                });
                this.aiEngine.scanRequest(task);
                SwingUtilities.invokeLater(() -> {
                    this.taskTablePanel.refreshTask(task);
                    this.updateStats();
                });
            });
        }
        catch (Exception e) {
            this.logPanel.logError(Msg.t("log.addReq.error"), e);
        }
    }

    public void deleteTask(ScanTask task) {
        task.cancel();
        this.tasks.remove(task);
        this.taskTablePanel.removeTask(task);
        if (this.taskDetailPanel != null) {
            this.taskDetailPanel.showTask(null);
        }
        this.updateStats();
        this.logPanel.logInfo(Msg.t("log.taskDeleted", task.getId()));
    }

    public void clearCompletedTasks() {
        ArrayList<ScanTask> toRemove = new ArrayList<ScanTask>();
        for (ScanTask task : this.tasks) {
            if (task.getStatus() != ScanTask.TaskStatus.FINISHED) continue;
            toRemove.add(task);
        }
        this.tasks.removeAll(toRemove);
        for (ScanTask task : toRemove) {
            this.taskTablePanel.removeTask(task);
        }
        // \u8be6\u60c5\u9762\u677f\u4e5f\u8981\u8ddf\u7740\u6e05\uff1a\u88ab\u5220\u6389\u7684\u4efb\u52a1\u5982\u679c\u8fd8\u663e\u793a\u5728\u300c\u8bf7\u6c42\u4e0e\u54cd\u5e94\u8be6\u60c5\u300d\u91cc\uff0c
        // \u7528\u6237\u770b\u5230\u7684\u662f\u4e00\u6761\u8868\u683c\u548c getTasks() \u91cc\u90fd\u5df2\u7ecf\u4e0d\u5b58\u5728\u7684\u4efb\u52a1\u7684\u63a2\u9488\u8bb0\u5f55
        if (this.taskDetailPanel != null && this.taskDetailPanel.getCurrentTask() != null
                && toRemove.contains(this.taskDetailPanel.getCurrentTask())) {
            this.taskDetailPanel.showTask(null);
        }
        this.updateStats();
        this.logPanel.logInfo(Msg.t("log.clearedCompleted", toRemove.size()));
    }

    private void updateStats() {
        int total = this.tasks.size();
        int completed = 0;
        int totalVulns = 0;
        int scanning = 0;
        for (ScanTask task : this.tasks) {
            if (task.getStatus() == ScanTask.TaskStatus.FINISHED) {
                ++completed;
            }
            List<VulnResult> vulns = task.getVulnerabilities();
                totalVulns += vulns != null ? vulns.size() : 0;
            if (task.getStatus() == ScanTask.TaskStatus.SCANNING) {
                ++scanning;
            }
        }
        this.logPanel.updateStats(total, completed, totalVulns, scanning);
    }

    public void showTaskDetail(ScanTask task) {
        this.taskDetailPanel.showTask(task);
    }

    public List<ScanTask> getTasks() {
        return this.tasks;
    }

    public void refreshConfigStatus() {
        this.refreshConfigStatus(true);
    }

    /**
     * @param recheckKey 是否顺手打一次「验证 Key」。配置页刚手动验证成功时传 false ——
     *                   那次验证就在几秒前、结果已知，再打一次纯属浪费（而且它是真的外发请求）。
     */
    public void refreshConfigStatus(boolean recheckKey) {
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        if (!recheckKey) {
            if (config.isVerified()) {
                this.updateApiKeyStatus("status.available", TEXT_DARK);
            } else {
                this.updateApiKeyStatus("status.unverified", new Color(200, 100, 100));
            }
            this.refreshTopBarTexts();
            return;
        }
        if (config.getApiKey() != null && !config.getApiKey().isEmpty() && config.getSelectedAgent() != null && !config.getSelectedAgent().isEmpty() && config.getApiEndpoint() != null && !config.getApiEndpoint().isEmpty()) {
            this.refreshTopBarTexts();
            this.autoVerifyApiKey();
        } else {
            this.updateApiKeyStatus("status.notConfigured", new Color(200, 100, 100));
            this.refreshTopBarTexts();
        }
        this.refreshOobStatus();
    }

    /**
     * \u91cd\u8d34\u9876\u680f\u90a3\u51e0\u683c\u7684**\u6d3e\u751f**\u6587\u6848\uff08\u670d\u52a1\u5546 / \u6a21\u578b / API Key / \u5916\u5e26\uff09\u3002
     *
     * <p>\u4e3a\u4ec0\u4e48\u4e0d\u8d70 {@code Msg.bind}\uff1a\u8fd9\u51e0\u683c\u7684\u5185\u5bb9\u8981\u6309\u914d\u7f6e\u73b0\u7b97\uff0c\u4e0d\u662f\u7ec4\u4ef6\u81ea\u5df1\u5b58\u7740\u7684\u4e00\u53e5\u8bdd\u3002
     * \u5207\u8bed\u8a00\u65f6\u7531 {@code Msg.onLangChanged} \u94a9\u5b50\u8c03\u8fd9\u91cc\u91cd\u7b97 \u2014\u2014 \u6ce8\u610f**\u4e0d\u8981**\u6539\u6210\u8c03
     * {@link #refreshConfigStatus(boolean) refreshConfigStatus(true)}\uff1a\u90a3\u4f1a\u771f\u7684\u5916\u53d1\u4e00\u6b21 AI \u63a5\u53e3\u9a8c\u8bc1\u8bf7\u6c42\uff0c
     * \u62e8\u4e00\u4e0b\u8bed\u8a00\u4e0d\u8be5\u987a\u624b\u6253\u4eba\u5bb6\u63a5\u53e3\u3002
     */
    private void refreshTopBarTexts() {
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        if (this.providerStatusLabel != null) {
            this.providerStatusLabel.setText(Msg.t("bar.provider")
                    + Msg.providerNameOf(config.getSelectedProvider(), Msg.t("status.notConfigured")));
        }
        if (this.modelStatusLabel != null) {
            this.modelStatusLabel.setText(Msg.t("bar.model")
                    + (config.getSelectedAgent() != null && !config.getSelectedAgent().isEmpty()
                            ? config.getSelectedAgent() : Msg.t("status.notSelected")));
        }
        this.renderApiKeyStatus();
        this.refreshOobStatus();
    }

    /**
     * \u5207\u6362\u754c\u9762\u8bed\u8a00\uff1a\u5148\u843d\u76d8\u518d\u91cd\u8bd1\u3002
     *
     * <p>\u987a\u5e8f\u662f\u6709\u610f\u7684\uff1a\u843d\u76d8\u5931\u8d25\u65f6 {@code Msg.setLang} \u4e0d\u4f1a\u6267\u884c\uff0c\u754c\u9762\u4e0e\u78c1\u76d8\u4fdd\u6301\u4e00\u81f4\uff08\u90fd\u8fd8\u662f\u65e7\u8bed\u8a00\uff09\u3002
     * \u4e0e\u914d\u7f6e\u9875\u90a3\u4e9b\u5f00\u5173\u540c\u4e00\u8303\u5f0f \u2014\u2014 \u663e\u793a\u4e0e\u884c\u4e3a\u4e0d\u8bb8\u6253\u67b6\u3002
     */
    private void toggleLanguage() {
        String next = Msg.isEn() ? "zh" : "en";
        // \u91cd\u65b0\u53d6\u914d\u7f6e\u5bf9\u8c61\uff1aConfigManager.loadConfig() \u4f1a\u6574\u4f53\u66ff\u6362 Config\uff0c\u6301\u6709\u6784\u9020\u65f6\u7684\u526f\u672c\u4f1a\u5199\u8fdb\u5b64\u513f\u5bf9\u8c61
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        config.setUiLanguage(next);
        ConfigManager.getInstance().saveConfig();
        Msg.setLang(next);
    }

    /**
     * \u5237\u300c\u5916\u5e26\u300d\u90a3\u4e00\u683c\uff1a\u5f00\u5173\u5173\u6389\u65f6\u663e\u793a\u300c\u5df2\u5173\u95ed\u300d\u800c\u4e0d\u662f\u4f9b\u5e94\u5546\u540d \u2014\u2014 \u5173\u7740\u7684\u65f6\u5019\u63d2\u4ef6\u4e0d\u7533\u8bf7\u57df\u540d\u3001
     * \u4e5f\u4e0d\u53d1\u4efb\u4f55\u5916\u5e26\u8f7d\u8377\uff0c\u8fd8\u6302\u7740 dnslog.org \u5c31\u662f\u5728\u8bef\u5bfc\u4eba\u3002
     *
     * <p>\u5355\u72ec\u4e00\u4e2a\u65b9\u6cd5\uff08\u800c\u4e0d\u662f\u8ba9\u4eba\u53bb\u8c03 {@link #refreshConfigStatus()}\uff09\u662f\u56e0\u4e3a\u540e\u8005\u4f1a\u987a\u624b\u89e6\u53d1
     * \u4e00\u6b21 API Key \u5728\u7ebf\u6821\u9a8c\uff1a\u62e8\u4e00\u4e0b\u5916\u5e26\u5f00\u5173\u4e0d\u8be5\u987a\u5e26\u6253\u4e00\u6b21 AI \u63a5\u53e3\u3002
     */
    public void refreshOobStatus() {
        if (this.oobStatusLabel == null) {
            return;
        }
        boolean enabled = ConfigManager.getInstance().getConfig().isOobEnabled();
        this.oobStatusLabel.setText(enabled ? Msg.t("bar.oob") + OOB_PROVIDER : Msg.t("bar.oobOff"));
        this.oobStatusLabel.setForeground(enabled ? TEXT_DARK : new Color(200, 100, 100));
    }

    private void autoVerifyApiKey() {
        this.updateApiKeyStatus("status.verifying", new Color(200, 200, 100));
        new Thread(() -> {
            try {
                ConfigManager.Config config = ConfigManager.getInstance().getConfig();
                OkHttpClient client = new OkHttpClient.Builder().connectTimeout(10L, TimeUnit.SECONDS).readTimeout(10L, TimeUnit.SECONDS).build();
                String testJson = "{\"model\":\"" + config.getSelectedAgent() + "\",\"messages\":[{\"role\":\"user\",\"content\":\"test\"}],\"max_tokens\":5}";
                RequestBody body = RequestBody.create(MediaType.parse("application/json"), testJson);
                Request.Builder requestBuilder = new Request.Builder().url(config.getApiEndpoint()).post(body);
                // 与「验证 Key」「获取模型」共用同一份鉴权判断：以前这里只分 anthropic / 其它，
                // Azure 之类端点保存后主界面会显示「API Key: 不可用」（其实 key 是好的）
                com.zackai.core.AuthHeaders.apply(requestBuilder, config.getApiEndpoint(), config.getApiKey());
                try (Response response = client.newCall(requestBuilder.build()).execute()) {
                    if (response.isSuccessful()) {
                        this.updateApiKeyStatus("status.available", TEXT_DARK);
                        this.callbacks.printOutput(Msg.t("log.apiKeyOk"));
                    } else {
                        this.updateApiKeyStatus("status.unavailable", new Color(255, 100, 100));
                        String responseBody = response.body() != null ? response.body().string() : Msg.t("msg.noResponseBody");
                        this.callbacks.printError(Msg.t("log.apiKeyFailDetail", response.code(), responseBody));
                        this.logPanel.logError(Msg.t("log.apiKeyFailHttp", response.code()));
                    }
                }
            }
            catch (Exception e) {
                this.updateApiKeyStatus("status.unavailable", new Color(255, 100, 100));
                this.logPanel.logError(Msg.t("log.apiKeyFail"), e);
            }
        }).start();
    }

    /**
     * @param statusKey 状态文案的 key（不是文本）—— 存 key 才能切语言后重贴，见字段注释
     */
    private void updateApiKeyStatus(String statusKey, Color color) {
        this.apiKeyStatusKey = statusKey;
        this.apiKeyStatusColor = color;
        SwingUtilities.invokeLater(this::renderApiKeyStatus);
    }

    /** 按当前语言重贴 API Key 格 */
    private void renderApiKeyStatus() {
        if (this.apiKeyStatusLabel != null) {
            this.apiKeyStatusLabel.setText("API Key: " + Msg.t(this.apiKeyStatusKey));
            this.apiKeyStatusLabel.setForeground(this.apiKeyStatusColor);
        }
    }

    public String getTabCaption() {
        return "Zack-AI-Scanner";
    }

    public Component getUiComponent() {
        return this;
    }

    public void shutdown() {
        if (this.refreshTimer != null) {
            this.refreshTimer.stop();
        }
        if (this.executorService != null && !this.executorService.isShutdown()) {
            this.executorService.shutdownNow();
            try {
                if (!this.executorService.awaitTermination(5L, TimeUnit.SECONDS)) {
                    this.callbacks.printError(Msg.t("log.execTermTimeout"));
                    this.logPanel.logError(Msg.t("log.execTermTimeout"));
                }
            } catch (InterruptedException e) {
                this.executorService.shutdownNow();
                Thread.currentThread().interrupt();
                this.logPanel.logError(Msg.t("log.execShutdownInterrupted"), e);
            }
        }
    }

    @Override
    public void onVulnerabilityFound(ScanTask task, VulnResult vuln) {
        SwingUtilities.invokeLater(() -> {
            this.taskTablePanel.refreshTask(task);
            this.updateStats();
        });
    }
}
