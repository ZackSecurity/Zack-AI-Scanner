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
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import com.zackai.i18n.Msg;
import com.zackai.model.ScanTask;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.util.List;
import javax.swing.Timer;
import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.ListSelectionModel;
import javax.swing.border.TitledBorder;

public class TaskDetailPanel extends JPanel implements IMessageEditorController {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private IMessageEditor requestEditor;
    private IMessageEditor responseEditor;
    private JList<String> probeList;
    private DefaultListModel<String> listModel;
    private ScanTask currentTask;
    private IHttpRequestResponse currentMessage;
    private Timer refreshTimer;
    private static final Color BG_WHITE = Color.WHITE;
    private static final Color TEXT_DARK = new Color(33, 37, 41);
    private static final Color PANEL_LIGHT = new Color(245, 247, 250);
    private static final Color BORDER_LIGHT = new Color(210, 214, 220);

    public TaskDetailPanel(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, MainPanel mainPanel) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.initUI();
    }

    private void initUI() {
        this.setLayout(new BorderLayout(8, 8));
        this.setBackground(BG_WHITE);
        this.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER_LIGHT, 1), BorderFactory.createEmptyBorder(8, 8, 8, 8)));

        JSplitPane horizontalSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        // 左侧只是探针索引（"#1 | SQL注入 | 参数: username"），320px 太占地方，压到 220
        horizontalSplit.setDividerLocation(220);
        horizontalSplit.setDividerSize(5);

        JPanel listPanel = new JPanel(new BorderLayout());
        listPanel.setBackground(BG_WHITE);
        TitledBorder listBorder = BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(BORDER_LIGHT, 1),
                Msg.t("detail.probes"),
                TitledBorder.LEFT,
                TitledBorder.TOP,
                new Font("微软雅黑", Font.BOLD, 13),
                TEXT_DARK
        );
        listPanel.setBorder(listBorder);
        Msg.bind(() -> {
            listBorder.setTitle(Msg.t("detail.probes"));
            listPanel.repaint();
        });

        this.listModel = new DefaultListModel<>();
        this.probeList = new JList<>(this.listModel);
        this.probeList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        this.probeList.setFont(new Font("微软雅黑", Font.PLAIN, 12));
        this.probeList.setBackground(BG_WHITE);
        this.probeList.setForeground(TEXT_DARK);
        this.probeList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                this.showSelectedProbe(this.probeList.getSelectedIndex());
            }
        });
        listPanel.add(new JScrollPane(this.probeList), BorderLayout.CENTER);

        JSplitPane reqRespSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        reqRespSplit.setDividerSize(5);
        // 请求包与响应包默认上下各占一半，且随窗口变化保持这个比例。
        // 注意**不能**在构造时直接 setDividerLocation(0.5)：那时组件还没有高度（size 为 0），
        // 比例式调用会被忽略。所以等第一次真正拿到高度时再设一次，之后以用户拖动为准。
        reqRespSplit.setResizeWeight(0.5);
        reqRespSplit.addComponentListener(new java.awt.event.ComponentAdapter() {
            private boolean applied = false;

            @Override
            public void componentResized(java.awt.event.ComponentEvent evt) {
                if (!applied && reqRespSplit.getHeight() > 0) {
                    applied = true;
                    reqRespSplit.setDividerLocation(0.5);
                }
            }
        });

        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBackground(BG_WHITE);
        TitledBorder requestPanelBorder = BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(BORDER_LIGHT, 1),
                Msg.t("detail.request"),
                TitledBorder.LEFT,
                TitledBorder.TOP,
                new Font("微软雅黑", Font.BOLD, 13),
                TEXT_DARK
        );
        Msg.bind(() -> {
            requestPanelBorder.setTitle(Msg.t("detail.request"));
            requestPanel.repaint();
        });
        requestPanel.setBorder(requestPanelBorder);
        this.requestEditor = this.callbacks.createMessageEditor(this, true);
        requestPanel.add(this.requestEditor.getComponent(), BorderLayout.CENTER);

        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBackground(BG_WHITE);
        TitledBorder responsePanelBorder = BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(BORDER_LIGHT, 1),
                Msg.t("detail.response"),
                TitledBorder.LEFT,
                TitledBorder.TOP,
                new Font("微软雅黑", Font.BOLD, 13),
                TEXT_DARK
        );
        Msg.bind(() -> {
            responsePanelBorder.setTitle(Msg.t("detail.response"));
            responsePanel.repaint();
        });
        responsePanel.setBorder(responsePanelBorder);
        this.responseEditor = this.callbacks.createMessageEditor(this, false);
        responsePanel.add(this.responseEditor.getComponent(), BorderLayout.CENTER);

        reqRespSplit.setTopComponent(requestPanel);
        reqRespSplit.setBottomComponent(responsePanel);

        horizontalSplit.setLeftComponent(listPanel);
        horizontalSplit.setRightComponent(reqRespSplit);

        this.add((Component) horizontalSplit, BorderLayout.CENTER);
        this.requestEditor.setMessage(new byte[0], true);
        this.responseEditor.setMessage(new byte[0], false);
        // 探针列表是**派生**文案（每项由类型名、位置拼出来），而 refreshProbeListIfNeeded
        // 只在「条数变了」时重建 —— 不注册钩子的话，切语言后这一列会一直停在旧语言，
        // 直到来了一条新探针或重新选中任务
        Msg.onLangChanged(() -> this.rebuildProbeList(Math.max(0, this.probeList.getSelectedIndex())));
        this.refreshTimer = new Timer(500, e -> this.refreshProbeListIfNeeded());
        this.refreshTimer.start();
    }

    /** 当前正在展示的任务（「清空已完成任务」要据此判断详情面板是否也该清） */
    public ScanTask getCurrentTask() {
        return this.currentTask;
    }

    public void showTask(ScanTask task) {
        this.currentTask = task;
        this.currentMessage = null;
        this.listModel.clear();
        if (task == null || task.getProbeRecords() == null || task.getProbeRecords().isEmpty()) {
            this.requestEditor.setMessage(new byte[0], true);
            this.responseEditor.setMessage(new byte[0], false);
            return;
        }
        this.rebuildProbeList(0);
    }

    private void refreshProbeListIfNeeded() {
        if (this.currentTask == null || this.currentTask.getProbeRecords() == null) {
            return;
        }
        if (this.currentTask.getProbeRecords().size() == this.listModel.size()) {
            return;
        }
        int selectedIndex = this.probeList.getSelectedIndex();
        if (selectedIndex < 0) {
            selectedIndex = 0;
        }
        this.rebuildProbeList(selectedIndex);
    }

    private void rebuildProbeList(int selectedIndex) {
        this.listModel.clear();
        if (this.currentTask == null) return;
        List<ScanTask.ProbeRecord> probeRecords = this.currentTask.getProbeRecords();
        if (probeRecords == null) return;
        // 列表项文案在这里拼，**不在 model 的 getDisplayText() 里拼**：拼法要跟着界面语言走，
        // 而 model 层不该知道当前是什么语言（它同时还要给报告/去重键提供中文类型名）。
        // 序号用循环下标：探针记录是只追加的，下标与记录自带的 index 一致。
        for (int i = 0; i < probeRecords.size(); i++) {
            ScanTask.ProbeRecord record = probeRecords.get(i);
            String type = record.getVulnType() == null ? "UNKNOWN" : Msg.typeNameOf(record.getVulnType());
            String position = record.getPosition() == null ? "auto" : record.getPosition();
            // 「未响应」要写在列表项上：右边响应框是空的，而空响应框和不选任何一条看起来一模一样 ——
            // 不标出来用户会以为这条记录没内容，其实请求就在上面（超时那条尤其如此）
            boolean noResponse = record.getMessage() == null || record.getMessage().getResponse() == null;
            this.listModel.addElement(noResponse
                    ? Msg.t("detail.probeItemNoResponse", i + 1, type, position)
                    : Msg.t("detail.probeItem", i + 1, type, position));
        }
        if (this.listModel.isEmpty()) {
            this.requestEditor.setMessage(new byte[0], true);
            this.responseEditor.setMessage(new byte[0], false);
            return;
        }
        int targetIndex = selectedIndex;
        if (targetIndex < 0) {
            targetIndex = 0;
        }
        if (targetIndex >= this.listModel.size()) {
            targetIndex = this.listModel.size() - 1;
        }
        if (targetIndex < 0) {
            this.requestEditor.setMessage(new byte[0], true);
            this.responseEditor.setMessage(new byte[0], false);
            return;
        }
        this.probeList.setSelectedIndex(targetIndex);
        this.showSelectedProbe(targetIndex);
    }

    private void showSelectedProbe(int index) {
        if (this.currentTask == null || index < 0 || index >= this.currentTask.getProbeRecords().size()) {
            this.currentMessage = null;
            this.requestEditor.setMessage(new byte[0], true);
            this.responseEditor.setMessage(new byte[0], false);
            return;
        }
        ScanTask.ProbeRecord record = this.currentTask.getProbeRecords().get(index);
        this.currentMessage = record.getMessage();
        if (this.currentMessage != null && this.currentMessage.getRequest() != null) {
            this.requestEditor.setMessage(this.currentMessage.getRequest(), true);
        } else {
            this.requestEditor.setMessage(new byte[0], true);
        }
        if (this.currentMessage != null && this.currentMessage.getResponse() != null) {
            this.responseEditor.setMessage(this.currentMessage.getResponse(), false);
        } else {
            this.responseEditor.setMessage(new byte[0], false);
        }
    }

    public IHttpService getHttpService() {
        return this.currentMessage != null ? this.currentMessage.getHttpService() : null;
    }

    public byte[] getRequest() {
        return this.currentMessage != null ? this.currentMessage.getRequest() : null;
    }

    public byte[] getResponse() {
        return this.currentMessage != null ? this.currentMessage.getResponse() : null;
    }

    @Override
    public void removeNotify() {
        super.removeNotify();
        this.stopTimer();
    }

    public void stopTimer() {
        if (this.refreshTimer != null && this.refreshTimer.isRunning()) {
            this.refreshTimer.stop();
        }
        this.refreshTimer = null;
    }

}
