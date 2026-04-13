package com.zackai;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.ITab;
import com.zackai.core.ConfigManager;
import com.zackai.model.ScanTask;
import com.zackai.ui.LogPanel;
import com.zackai.ui.MainPanel;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;

public class AISentryExtender
implements IBurpExtender,
IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private MainPanel mainPanel;
    private LogPanel logPanel;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Zack-AI-Scanner");
        try {
            System.setProperty("file.encoding", "UTF-8");
        }
        catch (Exception exception) {
            callbacks.printOutput("Warning: Failed to set file encoding: " + exception.getMessage());
        }
        ConfigManager.getInstance().init(callbacks);
        SwingUtilities.invokeLater(() -> {
            this.logPanel = new LogPanel();
            this.mainPanel = new MainPanel(callbacks, this.helpers, this.logPanel);
            callbacks.addSuiteTab((ITab)this.mainPanel);
        });
        callbacks.registerContextMenuFactory((IContextMenuFactory)this);
        try {
            String info = "================================\nZack-AI-Scanner v1.0 已加载\nGithub: https://github.com/ZackSecurity/Zack-AI-Scanner\n================================";
            callbacks.printOutput(info);
        }
        catch (Exception e) {
            callbacks.printOutput("Zack-AI-Scanner v1.0 loaded successfully");
        }
    }

    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> menuItems = new ArrayList<JMenuItem>();
        if (invocation.getInvocationContext() == 0 || invocation.getInvocationContext() == 2 || invocation.getInvocationContext() == 6 || invocation.getInvocationContext() == 5) {
            IHttpRequestResponse[] messages = invocation.getSelectedMessages();
            if (messages == null || messages.length == 0) {
                return menuItems;
            }
            JMenu pluginMenu = new JMenu("Zack-AI-Scanner");
            pluginMenu.setFont(new Font("微软雅黑", 0, 12));
            JMenu scanMenu = new JMenu("扫描漏洞类型");
            scanMenu.setFont(new Font("微软雅黑", 0, 12));
            this.addScanModeItem(scanMenu, messages, ScanTask.ScanMode.FILE_UPLOAD);
            this.addScanModeItem(scanMenu, messages, ScanTask.ScanMode.COMMAND_INJECTION);
            this.addScanModeItem(scanMenu, messages, ScanTask.ScanMode.SSTI);
            this.addScanModeItem(scanMenu, messages, ScanTask.ScanMode.SQL_INJECTION);
            this.addScanModeItem(scanMenu, messages, ScanTask.ScanMode.XSS);
            this.addScanModeItem(scanMenu, messages, ScanTask.ScanMode.SSRF);
            this.addScanModeItem(scanMenu, messages, ScanTask.ScanMode.XXE);
            this.addScanModeItem(scanMenu, messages, ScanTask.ScanMode.FILE_INCLUDE);
            this.addScanModeItem(scanMenu, messages, ScanTask.ScanMode.CSRF);
            this.addScanModeItem(scanMenu, messages, ScanTask.ScanMode.DESERIALIZATION);
            this.addScanModeItem(scanMenu, messages, ScanTask.ScanMode.AUTH_BYPASS);
            this.addScanModeItem(scanMenu, messages, ScanTask.ScanMode.PATH_TRAVERSAL);
            this.addScanModeItem(scanMenu, messages, ScanTask.ScanMode.DIRECTORY_TRAVERSAL);
            this.addScanModeItem(scanMenu, messages, ScanTask.ScanMode.SENSITIVE_DATA_EXPOSURE);
            this.addScanModeItem(scanMenu, messages, ScanTask.ScanMode.LOGIC_FLAW);
            this.addScanModeItem(scanMenu, messages, ScanTask.ScanMode.RACE_CONDITION);
            this.addScanModeItem(scanMenu, messages, ScanTask.ScanMode.TYPE_CONFUSION);
            pluginMenu.add(scanMenu);
            JMenuItem aiScanItem = new JMenuItem("AI智能扫描");
            aiScanItem.setFont(new Font("微软雅黑", 0, 12));
            aiScanItem.addActionListener(e -> {
                for (IHttpRequestResponse message : messages) {
                    if (this.mainPanel == null) {
                        continue;
                    }
                    this.mainPanel.addRequest(message, ScanTask.ScanMode.CUSTOM);
                }
                this.callbacks.printOutput("已发送 " + messages.length + " 个请求到 Zack-AI-Scanner，模式: AI智能扫描");
            });
            pluginMenu.add(aiScanItem);
            menuItems.add(pluginMenu);
        }
        return menuItems;
    }

    private void addScanModeItem(JMenu menu, IHttpRequestResponse[] messages, ScanTask.ScanMode scanMode) {
        JMenuItem item = new JMenuItem(scanMode.getDisplayName());
        item.setFont(new Font("微软雅黑", 0, 12));
        item.addActionListener(e -> {
            for (IHttpRequestResponse message : messages) {
                if (this.mainPanel == null) {
                    continue;
                }
                this.mainPanel.addRequest(message, scanMode);
            }
            this.callbacks.printOutput("已发送 " + messages.length + " 个请求到 Zack-AI-Scanner，模式: " + scanMode.getDisplayName());
        });
        menu.add(item);
    }

}
