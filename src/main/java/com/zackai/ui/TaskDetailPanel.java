package com.zackai.ui;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import com.zackai.model.ScanTask;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.Timer;
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
        horizontalSplit.setDividerLocation(320);
        horizontalSplit.setDividerSize(5);

        JPanel listPanel = new JPanel(new BorderLayout());
        listPanel.setBackground(BG_WHITE);
        TitledBorder listBorder = BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(BORDER_LIGHT, 1),
                "漏洞探测请求列表",
                TitledBorder.LEFT,
                TitledBorder.TOP,
                new Font("微软雅黑", Font.BOLD, 13),
                TEXT_DARK
        );
        listPanel.setBorder(listBorder);

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
        reqRespSplit.setDividerLocation(360);
        reqRespSplit.setDividerSize(5);

        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBackground(BG_WHITE);
        requestPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(BORDER_LIGHT, 1),
                "请求包",
                TitledBorder.LEFT,
                TitledBorder.TOP,
                new Font("微软雅黑", Font.BOLD, 13),
                TEXT_DARK
        ));
        this.requestEditor = this.callbacks.createMessageEditor(this, true);
        requestPanel.add(this.requestEditor.getComponent(), BorderLayout.CENTER);

        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBackground(BG_WHITE);
        responsePanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(BORDER_LIGHT, 1),
                "响应包",
                TitledBorder.LEFT,
                TitledBorder.TOP,
                new Font("微软雅黑", Font.BOLD, 13),
                TEXT_DARK
        ));
        this.responseEditor = this.callbacks.createMessageEditor(this, false);
        responsePanel.add(this.responseEditor.getComponent(), BorderLayout.CENTER);

        reqRespSplit.setTopComponent(requestPanel);
        reqRespSplit.setBottomComponent(responsePanel);

        horizontalSplit.setLeftComponent(listPanel);
        horizontalSplit.setRightComponent(reqRespSplit);

        this.add((Component) horizontalSplit, BorderLayout.CENTER);
        this.requestEditor.setMessage(new byte[0], true);
        this.responseEditor.setMessage(new byte[0], false);
        this.refreshTimer = new Timer(500, e -> this.refreshProbeListIfNeeded());
        this.refreshTimer.start();
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
        for (ScanTask.ProbeRecord record : probeRecords) {
            this.listModel.addElement(record.getDisplayText());
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

    public void startTimer() {
        if (this.refreshTimer != null) {
            if (this.refreshTimer.isRunning()) {
                return;
            }
            this.refreshTimer.stop();
        }
        this.refreshTimer = new Timer(500, e -> this.refreshProbeListIfNeeded());
        this.refreshTimer.start();
    }
}
