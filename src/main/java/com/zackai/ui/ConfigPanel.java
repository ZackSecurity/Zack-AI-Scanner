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

import com.zackai.i18n.Msg;
import com.zackai.core.ConfigManager;
import com.zackai.core.OASTClient;
import com.zackai.core.ProxyScanFilter;
import com.zackai.core.ProxyScanHistory;
import com.zackai.model.AIProvider;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JComboBox;
import javax.swing.JList;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JPasswordField;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingWorker;

/**
 * 配置**页面**：以前是模态对话框（{@code APIKeyConfigDialog}），现在作为
 * {@link MainPanel} 里「日志统计」右边的第四个标签页，点开即用、不再弹窗。
 *
 * <p>两条语义原样保留（它们都容易在搬动 layout 时被顺手改掉）：
 * <ul>
 *   <li>「保存配置」按钮只有在验证通过（或本来就存过 Key）时才可点；</li>
 *   <li>「验证 Key」的三种结果都会 {@code saveConfig()} 立刻落盘，不等「保存配置」按钮；</li>
 *   <li>「外带回连」开关同样立刻落盘，并同步「测试回连」按钮的可用状态。</li>
 * </ul>
 */
public class ConfigPanel extends JPanel {
    private JComboBox<String> providerCombo;
    private JPasswordField apiKeyField;
    private JComboBox<String> modelCombo;
    private JTextField apiEndpointField;
    private JTextField modelsEndpointField;
    private JLabel statusLabel;
    /** 验证状态格当前状态的文案 key（存 key 才能切语言后重贴；存文本就没法重贴） */
    private String statusKey = "status.unverified";
    private Color statusColor = new Color(120, 125, 132);
    private JCheckBox oobCheckBox;
    private JCheckBox autoScanCheckBox;
    private JTextArea autoScanWhitelistArea;
    private JButton oastTestButton;
    private JButton fetchModelsButton;
    private JButton verifyKeyButton;
    private JButton saveButton;
    private ConfigManager.Config config;
    private LogPanel logPanel;
    private MainPanel mainPanel;
    private static final Color BG_WHITE = Color.WHITE;
    private static final Color SUCCESS_GREEN = new Color(22, 163, 74);
    private static final Color ERROR_RED = new Color(220, 38, 38);
    private static final int ROW_HEIGHT = 30;
    private static final int LABEL_WIDTH = 100;
    private static final int INPUT_WIDTH = 300;
    /** 白名单多行输入框的高度（约 3 行多一点） */
    private static final int WHITELIST_HEIGHT = 66;

    public ConfigPanel(MainPanel mainPanel, LogPanel logPanel) {
        this.mainPanel = mainPanel;
        this.logPanel = logPanel;
        this.config = ConfigManager.getInstance().getConfig();
        this.initUI();
        this.loadCurrentConfig();
    }

    private void initUI() {
        this.setLayout(new BorderLayout(10, 10));
        this.setBackground(BG_WHITE);
        this.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        JPanel contentPanel = new JPanel(new GridBagLayout());
        contentPanel.setBackground(BG_WHITE);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 5, 4, 5);
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.fill = GridBagConstraints.BOTH;

        int row = 0;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        JLabel providerLabel = new JLabel();
        Msg.bind(() -> providerLabel.setText(Msg.t("cfg.provider")));
        providerLabel.setFont(new Font("微软雅黑", 0, 14));
        providerLabel.setPreferredSize(new Dimension(LABEL_WIDTH, ROW_HEIGHT));
        providerLabel.setVerticalAlignment(JLabel.CENTER);
        contentPanel.add(providerLabel, gbc);

        gbc.gridx = 1;
        gbc.gridy = row;
        gbc.weightx = 1.0;
        this.providerCombo = new JComboBox<>();
        this.providerCombo.setFont(new Font("微软雅黑", 0, 14));
        this.providerCombo.setPreferredSize(new Dimension(INPUT_WIDTH, ROW_HEIGHT));
        this.providerCombo.setMinimumSize(new Dimension(INPUT_WIDTH, ROW_HEIGHT));
        this.providerCombo.addActionListener(e -> onProviderChanged());
        contentPanel.add(this.providerCombo, gbc);
        // 服务商名与「点击获取/获取失败」都是**数据**（会被持久化进配置、并参与 equals 比较），
        // 所以只翻显示：数据层保持中文，换语言不动它们，比较与落盘逻辑一条都不用改
        this.providerCombo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                this.setText(Msg.providerNameOf(String.valueOf(value), ""));
                return this;
            }
        });

        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        JLabel endpointLabel = new JLabel();
        Msg.bind(() -> endpointLabel.setText(Msg.t("cfg.apiEndpoint")));
        endpointLabel.setFont(new Font("微软雅黑", 0, 14));
        endpointLabel.setPreferredSize(new Dimension(LABEL_WIDTH, ROW_HEIGHT));
        endpointLabel.setVerticalAlignment(JLabel.CENTER);
        contentPanel.add(endpointLabel, gbc);

        gbc.gridx = 1;
        gbc.gridy = row;
        gbc.weightx = 1.0;
        this.apiEndpointField = new JTextField();
        this.apiEndpointField.setFont(new Font("Consolas", 0, 13));
        this.apiEndpointField.setPreferredSize(new Dimension(INPUT_WIDTH, ROW_HEIGHT));
        this.apiEndpointField.setMinimumSize(new Dimension(INPUT_WIDTH, ROW_HEIGHT));
        contentPanel.add(this.apiEndpointField, gbc);

        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        JLabel modelsEndpointLbl = new JLabel();
        Msg.bind(() -> modelsEndpointLbl.setText(Msg.t("cfg.modelsEndpoint")));
        modelsEndpointLbl.setFont(new Font("微软雅黑", 0, 14));
        modelsEndpointLbl.setPreferredSize(new Dimension(LABEL_WIDTH, ROW_HEIGHT));
        modelsEndpointLbl.setVerticalAlignment(JLabel.CENTER);
        contentPanel.add(modelsEndpointLbl, gbc);

        gbc.gridx = 1;
        gbc.gridy = row;
        gbc.weightx = 1.0;
        this.modelsEndpointField = new JTextField();
        this.modelsEndpointField.setFont(new Font("Consolas", 0, 13));
        this.modelsEndpointField.setPreferredSize(new Dimension(INPUT_WIDTH, ROW_HEIGHT));
        this.modelsEndpointField.setMinimumSize(new Dimension(INPUT_WIDTH, ROW_HEIGHT));
        contentPanel.add(this.modelsEndpointField, gbc);

        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        JLabel apiKeyLabel = new JLabel("API Key:");
        apiKeyLabel.setFont(new Font("微软雅黑", 0, 14));
        apiKeyLabel.setPreferredSize(new Dimension(LABEL_WIDTH, ROW_HEIGHT));
        apiKeyLabel.setVerticalAlignment(JLabel.CENTER);
        contentPanel.add(apiKeyLabel, gbc);

        gbc.gridx = 1;
        gbc.gridy = row;
        gbc.weightx = 1.0;
        this.apiKeyField = new JPasswordField();
        this.apiKeyField.setFont(new Font("Consolas", 0, 13));
        this.apiKeyField.setPreferredSize(new Dimension(INPUT_WIDTH, ROW_HEIGHT));
        this.apiKeyField.setMinimumSize(new Dimension(INPUT_WIDTH, ROW_HEIGHT));
        contentPanel.add(this.apiKeyField, gbc);

        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        JLabel modelLabel = new JLabel();
        Msg.bind(() -> modelLabel.setText(Msg.t("cfg.model")));
        modelLabel.setFont(new Font("微软雅黑", 0, 14));
        modelLabel.setPreferredSize(new Dimension(LABEL_WIDTH, ROW_HEIGHT));
        modelLabel.setVerticalAlignment(JLabel.CENTER);
        contentPanel.add(modelLabel, gbc);

        gbc.gridx = 1;
        gbc.gridy = row;
        gbc.weightx = 1.0;
        JPanel modelPanel = new JPanel(new BorderLayout(5, 0));
        modelPanel.setBackground(BG_WHITE);
        modelPanel.setPreferredSize(new Dimension(INPUT_WIDTH, ROW_HEIGHT));
        modelPanel.setMinimumSize(new Dimension(INPUT_WIDTH, ROW_HEIGHT));
        this.modelCombo = new JComboBox<>();
        this.modelCombo.setFont(new Font("微软雅黑", 0, 14));
        this.modelCombo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                this.setText(Msg.modelItemOf(String.valueOf(value)));
                return this;
            }
        });
        this.modelCombo.setPreferredSize(new Dimension(INPUT_WIDTH, ROW_HEIGHT));
        this.modelCombo.setMinimumSize(new Dimension(INPUT_WIDTH, ROW_HEIGHT));
        modelPanel.add(this.modelCombo, BorderLayout.CENTER);
        this.fetchModelsButton = new JButton();
        Msg.bind(() -> this.fetchModelsButton.setText(Msg.t("cfg.fetchModels")));
        this.fetchModelsButton.setFont(new Font("微软雅黑", 0, 12));
        this.fetchModelsButton.setPreferredSize(new Dimension(90, ROW_HEIGHT - 2));
        this.fetchModelsButton.setMinimumSize(new Dimension(90, ROW_HEIGHT - 2));
        this.fetchModelsButton.addActionListener(e -> fetchModelsOnline());
        modelPanel.add(this.fetchModelsButton, BorderLayout.EAST);
        contentPanel.add(modelPanel, gbc);

        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        JLabel statusLbl = new JLabel();
        Msg.bind(() -> statusLbl.setText(Msg.t("cfg.verifyStatus")));
        statusLbl.setFont(new Font("微软雅黑", 0, 14));
        statusLbl.setPreferredSize(new Dimension(LABEL_WIDTH, ROW_HEIGHT));
        statusLbl.setVerticalAlignment(JLabel.CENTER);
        contentPanel.add(statusLbl, gbc);

        gbc.gridx = 1;
        gbc.gridy = row;
        gbc.weightx = 1.0;
        this.statusLabel = new JLabel();
        Msg.bind(this::renderStatus);
        this.statusLabel.setFont(new Font("微软雅黑", 0, 14));
        this.statusLabel.setForeground(Color.GRAY);
        this.statusLabel.setPreferredSize(new Dimension(INPUT_WIDTH, ROW_HEIGHT));
        this.statusLabel.setMinimumSize(new Dimension(INPUT_WIDTH, ROW_HEIGHT));
        this.statusLabel.setVerticalAlignment(JLabel.CENTER);
        contentPanel.add(this.statusLabel, gbc);

        // 外带回连开关：勾选时插件加载与每次扫描都会申请专属域名并发外带载荷；
        // 取消勾选则两者都不做（被扫目标全程不会被引导去访问回连服务）。
        // 变更**立即落盘**（不等「保存配置」按钮）：扫描行为与界面显示的开关必须一致。
        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        JLabel oastLabel = new JLabel();
        Msg.bind(() -> oastLabel.setText(Msg.t("cfg.oob")));
        oastLabel.setFont(new Font("微软雅黑", 0, 14));
        oastLabel.setPreferredSize(new Dimension(LABEL_WIDTH, ROW_HEIGHT));
        oastLabel.setVerticalAlignment(JLabel.CENTER);
        contentPanel.add(oastLabel, gbc);

        gbc.gridx = 1;
        gbc.gridy = row;
        gbc.weightx = 1.0;
        this.oobCheckBox = new JCheckBox();
        Msg.bind(() -> this.oobCheckBox.setText(Msg.t("cfg.oobCheck")));
        this.oobCheckBox.setFont(new Font("微软雅黑", 0, 14));
        this.oobCheckBox.setBackground(BG_WHITE);
        this.oobCheckBox.setSelected(this.config.isOobEnabled());
        Msg.bind(() -> this.oobCheckBox.setToolTipText(Msg.t("cfg.oobCheck.tip")));
        this.oobCheckBox.addActionListener(e -> this.applyOobToggle());
        contentPanel.add(this.oobCheckBox, gbc);

        // Proxy 流量自动扫描：勾上之后**每条带参数的、经过代理的请求**都会变成一条 AI 智能扫描任务。
        // 影响面比外带开关更大（会主动向目标发包、也会花 AI 调用），所以默认关、并且在文案里写清楚代价。
        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        JLabel autoScanLabel = new JLabel();
        Msg.bind(() -> autoScanLabel.setText(Msg.t("cfg.autoScan")));
        autoScanLabel.setFont(new Font("微软雅黑", 0, 14));
        autoScanLabel.setPreferredSize(new Dimension(LABEL_WIDTH, ROW_HEIGHT));
        autoScanLabel.setVerticalAlignment(JLabel.CENTER);
        contentPanel.add(autoScanLabel, gbc);

        gbc.gridx = 1;
        gbc.gridy = row;
        gbc.weightx = 1.0;
        this.autoScanCheckBox = new JCheckBox();
        Msg.bind(() -> this.autoScanCheckBox.setText(Msg.t("cfg.autoScanCheck")));
        this.autoScanCheckBox.setFont(new Font("微软雅黑", 0, 14));
        this.autoScanCheckBox.setBackground(BG_WHITE);
        this.autoScanCheckBox.setSelected(this.config.isAutoScanProxy());
        Msg.bind(() -> this.autoScanCheckBox.setToolTipText(Msg.t("cfg.autoScanCheck.tip")));
        this.autoScanCheckBox.addActionListener(e -> this.applyAutoScanToggle());
        contentPanel.add(this.autoScanCheckBox, gbc);

        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        JLabel whitelistLabel = new JLabel();
        Msg.bind(() -> whitelistLabel.setText(Msg.t("cfg.whitelist")));
        whitelistLabel.setFont(new Font("微软雅黑", 0, 14));
        whitelistLabel.setPreferredSize(new Dimension(LABEL_WIDTH, ROW_HEIGHT));
        whitelistLabel.setVerticalAlignment(JLabel.CENTER);
        contentPanel.add(whitelistLabel, gbc);

        gbc.gridx = 1;
        gbc.gridy = row;
        gbc.weightx = 1.0;
        // 多行输入框（不是单行 JTextField）：白名单经常一次贴一串 host，单行框既看不全也不好改。
        // 一行一个最直观（回车就是换行，所以这里没有 ActionListener，靠失焦生效）。
        this.autoScanWhitelistArea = new JTextArea();
        this.autoScanWhitelistArea.setFont(new Font("Consolas", 0, 13));
        this.autoScanWhitelistArea.setBackground(BG_WHITE);
        this.autoScanWhitelistArea.setLineWrap(true);
        this.autoScanWhitelistArea.setWrapStyleWord(false);
        this.autoScanWhitelistArea.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        this.autoScanWhitelistArea.setText(this.config.getAutoScanWhitelist());
        this.autoScanWhitelistArea.setEnabled(this.config.isAutoScanProxy());
        Msg.bind(() -> this.autoScanWhitelistArea.setToolTipText(Msg.t("cfg.whitelist.tip")));
        this.autoScanWhitelistArea.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusLost(java.awt.event.FocusEvent evt) {
                ConfigPanel.this.applyAutoScanWhitelist();
            }
        });
        JScrollPane whitelistScroll = new JScrollPane(this.autoScanWhitelistArea);
        whitelistScroll.setPreferredSize(new Dimension(INPUT_WIDTH, WHITELIST_HEIGHT));
        whitelistScroll.setMinimumSize(new Dimension(INPUT_WIDTH, WHITELIST_HEIGHT));
        whitelistScroll.setBackground(BG_WHITE);
        whitelistScroll.getViewport().setBackground(BG_WHITE);
        whitelistScroll.getVerticalScrollBar().setUnitIncrement(16);   // 滚轮一格只挪 1px 的话根本推不动
        contentPanel.add(whitelistScroll, gbc);

        row++;
        gbc.gridx = 1;
        gbc.gridy = row;
        gbc.weightx = 1.0;
        // 白名单的匹配规则没法靠输入框本身表达清楚（尤其「留空 = 全部」和「写域名含子域」），
        // 直接摆在输入框下面，省得靠 tooltip 才知道。
        JLabel whitelistHint = new JLabel();
        Msg.bind(() -> whitelistHint.setText(Msg.t("cfg.whitelistHint")));
        whitelistHint.setFont(new Font("微软雅黑", 0, 12));
        whitelistHint.setForeground(new Color(120, 125, 132));
        whitelistHint.setPreferredSize(new Dimension(INPUT_WIDTH, 18));
        contentPanel.add(whitelistHint, gbc);

        JPanel buttonPanel = new JPanel(new FlowLayout(1, 20, 10));
        buttonPanel.setBackground(BG_WHITE);

        this.saveButton = new JButton();
        Msg.bind(() -> this.saveButton.setText(Msg.t("cfg.save")));
        this.saveButton.setFont(new Font("微软雅黑", 0, 14));
        this.saveButton.setPreferredSize(new Dimension(110, 38));
        this.saveButton.addActionListener(e -> saveConfig());
        this.saveButton.setEnabled(false);
        buttonPanel.add(this.saveButton);

        this.verifyKeyButton = new JButton();
        Msg.bind(() -> this.verifyKeyButton.setText(Msg.t("cfg.verifyKey")));
        this.verifyKeyButton.setFont(new Font("微软雅黑", 0, 14));
        this.verifyKeyButton.setPreferredSize(new Dimension(110, 38));
        this.verifyKeyButton.addActionListener(e -> verifyApiKey());
        buttonPanel.add(this.verifyKeyButton);

        this.oastTestButton = new JButton();
        Msg.bind(() -> this.oastTestButton.setText(Msg.t("cfg.testOob")));
        this.oastTestButton.setFont(new Font("微软雅黑", 0, 14));
        this.oastTestButton.setPreferredSize(new Dimension(110, 38));
        this.oastTestButton.addActionListener(e -> testOastConnection());
        // 关闭外带回连时这个按钮本身就是一次「不必要的外发」，直接禁用（打开勾选框即可用）
        this.oastTestButton.setEnabled(this.config.isOobEnabled());
        Msg.bind(() -> this.oastTestButton.setToolTipText(
                Msg.t(this.config.isOobEnabled() ? "cfg.testOob.tipOn" : "cfg.testOob.tipOff")));
        buttonPanel.add(this.oastTestButton);

        // 表单靠上居中：这一页要铺满整个 Burp 窗口，把表单拉成整屏宽/高反而难读。
        JPanel formHolder = new JPanel(new GridBagLayout());
        formHolder.setBackground(BG_WHITE);
        GridBagConstraints holderGbc = new GridBagConstraints();
        holderGbc.gridx = 0;
        holderGbc.gridy = 0;
        holderGbc.weightx = 1.0;
        holderGbc.weighty = 1.0;
        holderGbc.anchor = GridBagConstraints.NORTH;
        holderGbc.fill = GridBagConstraints.NONE;
        formHolder.add(contentPanel, holderGbc);

        // 表单放进滚动面板：Burp 主窗口可以拉得很小，以前表单会被直接截断（下面的白名单、按钮
        // 都够不着，只能靠滚轮碰运气）。滚动条 + 滚轮现在都能到。
        // 按钮留在滚动区外（South）：它是「保存」，不该被滚出视野。
        // 这一页没有「关闭」按钮：它不再是模态对话框，切标签页就能离开。
        JScrollPane scrollPane = new JScrollPane(formHolder);
        scrollPane.setBorder(null);
        scrollPane.setBackground(BG_WHITE);
        scrollPane.getViewport().setBackground(BG_WHITE);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);   // 默认一次只挪 1px，滚轮几乎推不动
        this.add((Component)scrollPane, "Center");
        this.add((Component)buttonPanel, "South");
    }

    /**
     * 写盘前重新取一次当前的 {@link ConfigManager.Config}。
     *
     * <p>{@code ConfigManager.loadConfig()} 是**整个替换** config 对象（不是原地改）——
     * 配置是对话框时这个窗口只有几秒，现在这一页是常驻的，构造时缓存的对象有可能变成孤儿：
     * 页面往旧对象里写、{@code saveConfig()} 却序列化管理器的那个，用户填的东西会静默消失。
     * 目前 {@code loadConfig()} 只在插件加载时跑一次（在界面之前），所以还不会发生 ——
     * 这里只是把这个陷阱堵上，取到的对象在正常路径下与构造时是同一个。
     */
    private ConfigManager.Config currentConfig() {
        this.config = ConfigManager.getInstance().getConfig();
        return this.config;
    }

    private void loadCurrentConfig() {
        this.providerCombo.removeAllItems();
        List<AIProvider> providers = AIProvider.getDefaultProviders();
        for (AIProvider provider : providers) {
            this.providerCombo.addItem(provider.getName());
        }

        String savedProvider = this.config.getSelectedProvider();
        if (savedProvider != null && !savedProvider.isEmpty()) {
            this.providerCombo.setSelectedItem(savedProvider);
        } else {
            this.providerCombo.setSelectedItem("自定义");
        }

        this.apiEndpointField.setText(this.config.getApiEndpoint());
        this.modelsEndpointField.setText(this.config.getModelsEndpoint());

        this.apiKeyField.setText(this.config.getApiKey());

        this.modelCombo.removeAllItems();
        this.modelCombo.addItem("点击获取");
        String savedModel = this.config.getSelectedAgent();
        if (savedModel != null && !savedModel.isEmpty()) {
            this.modelCombo.addItem(savedModel);
            this.modelCombo.setSelectedItem(savedModel);
        } else {
            this.modelCombo.setSelectedItem("点击获取");
        }

        if (this.config.getApiKey() != null && !this.config.getApiKey().isEmpty()) {
            this.saveButton.setEnabled(true);
        } else {
            this.saveButton.setEnabled(false);
        }

        if (this.config.isVerified()) {
            this.setStatus("status.verified", SUCCESS_GREEN);
        } else {
            this.setStatus("status.unverified", Color.GRAY);
        }
    }

    private void onProviderChanged() {
        String selectedProvider = (String) this.providerCombo.getSelectedItem();
        if (selectedProvider == null) return;

        if (selectedProvider.equals("自定义")) {
            this.apiEndpointField.setText("");
            this.modelsEndpointField.setText("");
            // 自定义服务商：清空地址，交给用户填
        } else {
            List<AIProvider> providers = AIProvider.getDefaultProviders();
            for (AIProvider provider : providers) {
                if (provider.getName().equals(selectedProvider)) {
                    this.apiEndpointField.setText(provider.getApiEndpoint());
                    this.modelsEndpointField.setText(provider.getModelsEndpoint());
                    break;
                }
            }
        }

        this.modelCombo.removeAllItems();
        this.modelCombo.addItem("点击获取");
        this.modelCombo.setSelectedItem("点击获取");
        this.setStatus("status.unverified", Color.GRAY);
    }

    private void fetchModelsOnline() {
        String apiKey = new String(this.apiKeyField.getPassword());
        String modelsEndpoint = this.modelsEndpointField.getText();
        String apiEndpoint = this.apiEndpointField.getText();

        if (apiKey == null || apiKey.trim().isEmpty()) {
            this.showError(Msg.t("msg.needApiKey"));
            return;
        }

        if (modelsEndpoint == null || modelsEndpoint.trim().isEmpty()) {
            this.showError(Msg.t("msg.needModelEndpoint"));
            return;
        }

        this.fetchModelsButton.setEnabled(false);
        this.fetchModelsButton.setText(Msg.t("msg.fetching"));
        this.modelCombo.removeAllItems();
        this.modelCombo.addItem(Msg.t("msg.fetchingList"));

        new SwingWorker<List<String>, Void>() {
            @Override
            protected List<String> doInBackground() throws Exception {
                return fetchModelsFromAPI(modelsEndpoint, apiEndpoint, apiKey);
            }

            @Override
            protected void done() {
                fetchModelsButton.setEnabled(true);
                fetchModelsButton.setText(Msg.t("cfg.fetchModels"));
                modelCombo.removeAllItems();

                try {
                    List<String> models = get();
                    if (models == null || models.isEmpty()) {
                        modelCombo.addItem("获取失败");
                        modelCombo.setSelectedItem("获取失败");
                        if (logPanel != null) {
                            logPanel.logError(Msg.t("logcfg.fetchFailed"));
                        }
                    } else {
                        for (String model : models) {
                            modelCombo.addItem(model);
                        }
                        modelCombo.setSelectedItem(models.get(0));
                        if (logPanel != null) {
                            logPanel.logSuccess(Msg.t("logcfg.fetchOk", models.size()));
                        }
                    }
                } catch (Exception e) {
                    modelCombo.addItem("获取失败");
                    modelCombo.setSelectedItem("获取失败");
                    if (logPanel != null) {
                        logPanel.logError(Msg.t("logcfg.fetchError"), e);
                    }
                }
            }
        }.execute();
    }

    private List<String> fetchModelsFromAPI(String modelsEndpoint, String apiEndpoint, String apiKey) throws Exception {
        if (modelsEndpoint == null || modelsEndpoint.trim().isEmpty()) {
            return null;
        }

        OkHttpClient client = new OkHttpClient.Builder()
            .connectTimeout(15, java.util.concurrent.TimeUnit.SECONDS)
            .readTimeout(15, java.util.concurrent.TimeUnit.SECONDS)
            .build();

        Request.Builder requestBuilder = new Request.Builder().url(modelsEndpoint).get();
        // 鉴权按 **apiEndpoint** 判（模型列表地址通常同源；判断口径与「验证 Key」一致才不会再出现
        // 「验证成功但获取模型失败」）。以前这里恒发 Bearer。
        com.zackai.core.AuthHeaders.apply(requestBuilder, apiEndpoint, apiKey);

        try (Response response = client.newCall(requestBuilder.build()).execute()) {
            if (!response.isSuccessful()) {
                return null;
            }

            String body = response.body() != null ? response.body().string() : null;
            if (body == null) {
                return null;
            }

            return parseModelsFromResponse(body);
        }
    }

    private List<String> parseModelsFromResponse(String responseBody) {
        List<String> models = new ArrayList<>();
        try {
            com.google.gson.JsonObject json = com.google.gson.JsonParser.parseString(responseBody).getAsJsonObject();

            if (json.has("data")) {
                com.google.gson.JsonArray data = json.getAsJsonArray("data");
                for (int i = 0; i < data.size(); i++) {
                    com.google.gson.JsonObject model = data.get(i).getAsJsonObject();
                    if (model.has("id")) {
                        models.add(model.get("id").getAsString());
                    }
                }
            } else if (json.has("models")) {
                com.google.gson.JsonArray modelArray = json.getAsJsonArray("models");
                for (int i = 0; i < modelArray.size(); i++) {
                    com.google.gson.JsonObject model = modelArray.get(i).getAsJsonObject();
                    if (model.has("model_id") || model.has("name")) {
                        String id = model.has("model_id") ? model.get("model_id").getAsString() : model.get("name").getAsString();
                        models.add(id);
                    }
                }
            }
        } catch (Exception e) {
            return null;
        }
        return models;
    }

    private void verifyApiKey() {
        String selectedProvider = (String) this.providerCombo.getSelectedItem();
        String apiKey = new String(this.apiKeyField.getPassword());
        Object selectedModel = this.modelCombo.getSelectedItem();
        // 在 EDT 上把地址取出来交给后台线程：verifyKey 原来自己在 doInBackground 里读输入框，
        // 边输入边点验证会读到半截内容（而且 Swing 文档不允许在别的线程碰组件）。
        // 同一文件里的「获取模型」早就是这么做的。
        String apiEndpoint = this.apiEndpointField.getText();
        // 模型接口地址也一起取出来：验证通过后要把**这一次验证过的这一套**整体落盘
        String modelsEndpoint = this.modelsEndpointField.getText();

        if (apiKey == null || apiKey.trim().isEmpty()) {
            this.showError(Msg.t("msg.needApiKey"));
            return;
        }

        if (selectedModel == null || selectedModel.toString().trim().isEmpty() || selectedModel.toString().equals("点击获取") || selectedModel.toString().equals("获取失败")) {
            this.showError(Msg.t("msg.needModelNameShort"));
            return;
        }

        this.verifyKeyButton.setEnabled(false);
        this.verifyKeyButton.setText(Msg.t("status.verifyingDots"));
        this.setStatus("status.verifyingDots", new Color(217, 119, 6));

        new SwingWorker<Boolean, Void>() {
            @Override
            protected Boolean doInBackground() throws Exception {
                return verifyKey(selectedProvider, apiKey, selectedModel.toString(), apiEndpoint);
            }

            @Override
            protected void done() {
                verifyKeyButton.setEnabled(true);
                verifyKeyButton.setText(Msg.t("cfg.verifyKey"));
                ConfigManager.Config config = currentConfig();   // 落盘当前对象（理由见 currentConfig）

                try {
                    boolean success = get();
                    if (success) {
                        setStatus("status.verified", SUCCESS_GREEN);
                        saveButton.setEnabled(true);
                        // 验证成功 = 这一套（服务商/Key/地址/模型）确实可用，那就直接落盘。
                        // 以前只写 verified 标记：验证完没点「保存配置」就退出的话，新填的 Key 直接丢了 ——
                        // 界面提示「验证成功」，配置文件里却还是旧的。
                        String provider = (selectedProvider == null || selectedProvider.equals("自定义"))
                                ? "自定义" : selectedProvider;
                        config.setSelectedProvider(provider);
                        config.setApiEndpoint(apiEndpoint == null ? "" : apiEndpoint.trim());
                        config.setModelsEndpoint(modelsEndpoint == null ? "" : modelsEndpoint.trim());
                        config.setApiKey(apiKey.trim());
                        config.setSelectedAgent(selectedModel.toString().trim());
                        config.setVerified(true);
                        ConfigManager.getInstance().saveConfig();
                        if (mainPanel != null) {
                            // false = 别再打一次验证请求：刚刚这次就是验证，结果已知
                            mainPanel.refreshConfigStatus(false);
                        }
                        if (logPanel != null) {
                            logPanel.logSuccess(Msg.t("logcfg.keyVerifiedSaved", provider, selectedModel, modelsEndpoint));
                        }
                    } else {
                        setStatus("status.verifyFailed", ERROR_RED);
                        saveButton.setEnabled(false);
                        config.setVerified(false);
                        ConfigManager.getInstance().saveConfig();
                    }
                } catch (Exception e) {
                    setStatus("status.verifyError", ERROR_RED);
                    saveButton.setEnabled(false);
                    config.setVerified(false);
                    ConfigManager.getInstance().saveConfig();
                    if (logPanel != null) {
                        logPanel.logError(Msg.t("logcfg.keyVerifyError"), e);
                    }
                }
            }
        }.execute();
    }

    private boolean verifyKey(String provider, String apiKey, String model, String apiEndpoint) throws Exception {
        if (apiEndpoint == null || apiEndpoint.trim().isEmpty()) {
            return false;
        }

        OkHttpClient client = new OkHttpClient.Builder()
            .connectTimeout(15, java.util.concurrent.TimeUnit.SECONDS)
            .writeTimeout(15, java.util.concurrent.TimeUnit.SECONDS)
            .readTimeout(15, java.util.concurrent.TimeUnit.SECONDS)
            .build();

        String jsonBody = "{\"model\":\"" + model + "\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"max_tokens\":5}";
        RequestBody body = RequestBody.create(jsonBody, MediaType.parse("application/json"));

        Request.Builder requestBuilder = new Request.Builder()
            .url(apiEndpoint)
            .post(body)
            .addHeader("Content-Type", "application/json");
        // 与服务端调用、主界面自动验证共用同一份鉴权判断（以前这里和「获取模型」各写一套，已经漂移）
        com.zackai.core.AuthHeaders.apply(requestBuilder, apiEndpoint, apiKey);

        try (Response response = client.newCall(requestBuilder.build()).execute()) {
            return response.isSuccessful();
        }
    }

    /**
     * 外带回连开关的即时生效：写进配置并**立刻落盘**（不等「保存配置」按钮 ——
     * 开关状态与实际扫描行为必须一致，否则用户以为关了、扫描却还在发外带载荷）。
     * 关闭时「测试回连」一并禁用，因为它本身就是一次真实外发。
     */
    private void applyOobToggle() {
        boolean enabled = this.oobCheckBox.isSelected();
        this.currentConfig().setOobEnabled(enabled);
        ConfigManager.getInstance().saveConfig();
        this.oastTestButton.setEnabled(enabled);
        if (this.mainPanel != null) {
            // 顶栏那一格也显示「用的是哪家回连服务」，开关一拨就得跟着变（不能等到点「保存配置」）
            this.mainPanel.refreshOobStatus();
        }
        if (this.logPanel != null) {
            if (enabled) {
                this.logPanel.logInfo(Msg.t("logcfg.oobOn"));
            } else {
                this.logPanel.logWarning(Msg.t("logcfg.oobOff"));
            }
        }
    }

    /**
     * Proxy 自动扫描开关的即时生效：写进配置并**立刻落盘**（理由同外带开关 —— 界面上的开关状态
     * 与实际行为不能不一致，何况这个开关会真的往目标发包）。白名单输入框跟着启用/禁用。
     */
    private void applyAutoScanToggle() {
        boolean enabled = this.autoScanCheckBox.isSelected();
        this.currentConfig().setAutoScanProxy(enabled);
        ConfigManager.getInstance().saveConfig();
        this.autoScanWhitelistArea.setEnabled(enabled);
        this.applyAutoScanWhitelist();          // 顺手把输入框里的白名单也应用上（可能刚敲完还没失焦）
        if (enabled) {
            // 重新勾上 = 重新开一轮：去重记录清掉，否则「我改了目标想重扫」只能靠重启插件
            ProxyScanHistory.clear();
        }
        if (this.logPanel != null) {
            if (enabled) {
                String whitelist = this.currentConfig().getAutoScanWhitelist();
                this.logPanel.logWarning(Msg.t("logcfg.autoScanOn", whitelist == null || whitelist.trim().isEmpty()
                            ? Msg.t("logcfg.autoScanNoWhitelist")
                            : Msg.t("logcfg.autoScanWhitelistOnly", ProxyScanFilter.describe(whitelist))));
            } else {
                this.logPanel.logInfo(Msg.t("logcfg.autoScanOff"));
            }
        }
    }

    /**
     * 白名单的即时生效：离开输入框时调用（每敲一个字符就写盘太吵，也扛不住；
     * 多行框里回车是换行，所以这里没有回车快捷方式）。
     * 值没变就直接返回 —— 失焦是高频动作，不该每次都写文件、记日志。
     */
    private void applyAutoScanWhitelist() {
        String value = this.autoScanWhitelistArea.getText() == null ? "" : this.autoScanWhitelistArea.getText().trim();
        ConfigManager.Config config = this.currentConfig();
        String current = config.getAutoScanWhitelist() == null ? "" : config.getAutoScanWhitelist();
        if (value.equals(current)) {
            return;
        }
        config.setAutoScanWhitelist(value);
        ConfigManager.getInstance().saveConfig();
        if (this.logPanel != null) {
            this.logPanel.logInfo(Msg.t("logcfg.whitelistUpdated")
                    + (value.isEmpty() ? Msg.t("logcfg.whitelistEmpty") : ProxyScanFilter.describe(value)));
        }
    }

    /**
     * 测回连功能是否真的可用：走一次**完整回环** —— 申请专属域名 → 让本机真的解析一次
     * {@code <随机前缀>.<专属域名>} → 把这个前缀的解析记录查回来（{@link OASTClient#selfTest()}）。
     *
     * <p>以前只走到「拿到域名」就报成功，可域名能申请到并不代表记录查得回来
     * （域名过期、服务端查不到记录都会让外带判定静默失效）。插件加载时做的是同一件事。
     */
    private void testOastConnection() {
        this.oastTestButton.setEnabled(false);
        this.oastTestButton.setText(Msg.t("status.testingDots"));
        new SwingWorker<OASTClient.SelfTestResult, Void>() {
            @Override
            protected OASTClient.SelfTestResult doInBackground() {
                return OASTClient.shared().selfTest();
            }

            @Override
            protected void done() {
                try {
                    OASTClient.SelfTestResult result = get();
                    if (result.ok) {
                        ConfigPanel.this.setStatus("status.oobOk", SUCCESS_GREEN);
                        if (ConfigPanel.this.logPanel != null) {
                            ConfigPanel.this.logPanel.logSuccess(Msg.t("logcfg.oobOk") + result.message);
                            for (String record : result.records) {
                                ConfigPanel.this.logPanel.logInfo(Msg.t("logcfg.indent") + record);
                            }
                        }
                        JOptionPane.showMessageDialog(ConfigPanel.this, result.message, Msg.t("dlg.oobSelfTest"),
                                JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        ConfigPanel.this.showError(result.message);
                    }
                }
                catch (Exception e) {
                    ConfigPanel.this.showError(Msg.t("msg.oobTestError") + e.getClass().getSimpleName());
                }
                finally {
                    ConfigPanel.this.oastTestButton.setEnabled(
                            ConfigPanel.this.oobCheckBox.isSelected());
                    ConfigPanel.this.oastTestButton.setText(Msg.t("cfg.testOob"));
                }
            }
        }.execute();
    }

    private void saveConfig() {
        String selectedProvider = (String) this.providerCombo.getSelectedItem();
        String apiKey = new String(this.apiKeyField.getPassword());
        Object selectedModel = this.modelCombo.getSelectedItem();
        String customApiEndpoint = this.apiEndpointField.getText();
        String customModelsEndpoint = this.modelsEndpointField.getText();

        if (apiKey == null || apiKey.trim().isEmpty()) {
            this.showError(Msg.t("msg.needApiKeyInput"));
            return;
        }

        if (selectedModel == null || selectedModel.toString().trim().isEmpty() || selectedModel.toString().equals("点击获取") || selectedModel.toString().equals("获取失败")) {
            this.showError(Msg.t("msg.needModelName"));
            return;
        }

        if (customApiEndpoint == null || customApiEndpoint.trim().isEmpty()) {
            this.showError(Msg.t("msg.needApiEndpoint"));
            return;
        }

        if (customModelsEndpoint == null || customModelsEndpoint.trim().isEmpty()) {
            this.showError(Msg.t("msg.needModelsEndpoint"));
            return;
        }

        if (selectedProvider == null || selectedProvider.equals("自定义")) {
            selectedProvider = "自定义";
        }

        ConfigManager.Config config = this.currentConfig();
        // 「保存配置」要落盘**界面上所有能改的东西**：白名单输入框是失焦/回车才生效的，
        // 用户完全可能敲完直接点保存（焦点还没离开，值还没进配置），那样这一项就会漏掉；
        // 两个勾选框虽然变更即落盘，这里再同步一次，保证「点了保存 = 界面所见即配置」。
        config.setAutoScanProxy(this.autoScanCheckBox.isSelected());
        config.setAutoScanWhitelist(this.autoScanWhitelistArea.getText() == null
                ? "" : this.autoScanWhitelistArea.getText().trim());
        config.setOobEnabled(this.oobCheckBox.isSelected());
        config.setSelectedProvider(selectedProvider);
        config.setApiEndpoint(customApiEndpoint.trim());
        config.setModelsEndpoint(customModelsEndpoint.trim());
        config.setApiKey(apiKey.trim());
        config.setSelectedAgent(selectedModel.toString().trim());

        ConfigManager.getInstance().saveConfig();

        if (this.mainPanel != null) {
            this.mainPanel.refreshConfigStatus();
        }

        if (this.logPanel != null) {
            this.logPanel.logSuccess(Msg.t("logcfg.saved") + selectedProvider + " - " + selectedModel);
        }

        // 以前这里还跟着一个 dispose()：配置是对话框时保存完就该关掉它。现在配置是一个常驻标签页，
        // 保存之后继续留在页面上（成功提示已经说明结果了）。
        JOptionPane.showMessageDialog(this, Msg.t("msg.configSaved"), Msg.t("dlg.success"), JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * 设验证状态：**存 key 而不是文本**，切语言时由绑定器 {@link #renderStatus} 按新语言重贴
     * （同 MainPanel 顶栏那个 API Key 格的做法）。
     */
    private void setStatus(String key, Color color) {
        this.statusKey = key;
        this.statusColor = color;
        this.renderStatus();
    }

    private void renderStatus() {
        if (this.statusLabel != null) {
            this.statusLabel.setText(Msg.t(this.statusKey));
            this.statusLabel.setForeground(this.statusColor);
        }
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, Msg.t("dlg.error"), JOptionPane.ERROR_MESSAGE);
    }
}
