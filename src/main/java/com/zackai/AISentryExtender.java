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
import com.zackai.core.ConfigManager;
import com.zackai.i18n.Msg;
import com.zackai.core.OASTClient;
import com.zackai.core.ProxyAutoScanListener;
import com.zackai.model.ScanTask;
import com.zackai.ui.LogPanel;
import com.zackai.ui.MainPanel;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;

public class AISentryExtender
implements IBurpExtender,
IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private MainPanel mainPanel;
    private LogPanel logPanel;
    private static final int[] VALID_CONTEXTS = {0, 2, 5, 6};

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        // 这个名字**同时是右键菜单里那一层的标题**（Burp 把扩展的右键项收进以扩展名命名的子菜单），
        // 所以不能带版本号 —— 带上就会显示成「Zack-AI-Scanner v3.0」。版本号在加载横幅与主界面标题里。
        callbacks.setExtensionName("Zack-AI-Scanner");
        try {
            System.setProperty("file.encoding", "UTF-8");
        }
        catch (Exception exception) {
            callbacks.printOutput("Warning: Failed to set file encoding: " + exception.getMessage());
        }
        ConfigManager.getInstance().init(callbacks);
        // 界面语言必须在**构造任何面板之前**定下来：Msg.bind 是「注册即执行」，
        // 面板构造时读到的就是当时的语言（配置里没选过时跟随操作系统语言）。
        // 这里推给它而不是让 Msg 自己去读配置：静态初始化里读 ConfigManager 会形成初始化顺序依赖。
        Msg.init(ConfigManager.getInstance().getConfig().getUiLanguage());
        // 外带回连：挂载时做一次**真实回环自检**（申请域名 → 本机解析一次 → 把记录查回来），
        // 确认这条链路真的可用 —— 只「申请到域名」说明不了什么，域名过期或服务端查不到记录时，
        // 外带类漏洞会在扫描里静默变成「未判定」。网络请求全放后台线程，不卡扩展加载。
        // 配置里关掉外带回连时不做任何网络动作。
        Thread oobInit = new Thread(() -> {
            boolean enabled = ConfigManager.getInstance().getConfig().isOobEnabled();
            final boolean[] ok = {false};
            String message;
            if (!enabled) {
                message = Msg.t("log.oob.off");
            } else {
                OASTClient.SelfTestResult result = OASTClient.shared().selfTest();
                ok[0] = result.ok;
                message = result.ok
                        ? Msg.t("log.oob.ok", result.message)
                        : Msg.t("log.oob.fail", result.message);
            }
            callbacks.printOutput(message);
            SwingUtilities.invokeLater(() -> {
                if (this.logPanel == null) {
                    return;
                }
                if (!enabled) {
                    this.logPanel.logInfo(message);
                } else if (ok[0]) {
                    this.logPanel.logSuccess(message);
                } else {
                    this.logPanel.logWarning(message);
                }
            });
        }, "ZackAI-OAST-Init");
        oobInit.setDaemon(true);
        oobInit.start();
        SwingUtilities.invokeLater(() -> {
            try {
                this.logPanel = new LogPanel();
                this.logPanel.setCallbacks(callbacks);
                ConfigManager.setLogPanel(this.logPanel);
                this.mainPanel = new MainPanel(callbacks, this.helpers, this.logPanel);
                callbacks.addSuiteTab(this.mainPanel);
                // Proxy 自动扫描的监听器在这里注册（不是在上面的加载流程里）：它要拿着 MainPanel 才能
                // 建任务，而 MainPanel 是在这个 invokeLater 里才有的。默认关闭，配置页勾了才生效。
                callbacks.registerProxyListener(new ProxyAutoScanListener(this.mainPanel, this.logPanel, this.helpers));
            } catch (Exception e) {
                callbacks.printError(Msg.t("log.ui.error", e.getClass().getSimpleName() + " - " + e.getMessage()));
                if (this.logPanel != null) {
                    this.logPanel.logError(Msg.t("log.ui.errorShort"), e);
                }
            }
        });
        callbacks.registerContextMenuFactory((IContextMenuFactory)this);
        // 卸载扩展时把线程池关掉：池里是非 daemon 线程，不关的话它们会一直持有
        // MainPanel → AIEngine → 类加载器，Burp 里反复卸载/加载会越积越多
        callbacks.registerExtensionStateListener(() -> {
            if (this.mainPanel != null) {
                this.mainPanel.shutdown();
            }
            // Msg 是静态状态，绑定器持的是界面组件的强引用 —— 不清的话重载插件后
            // 旧界面的整棵组件树（连同旧 classloader）会被一直吊着，和上面线程池是同一类问题
            Msg.shutdown();
        });
        try {
            String info = Msg.t("log.loadBanner");
            callbacks.printOutput(info);
            // GPLv3 建议交互式程序启动时打出简短的版权与免责声明。单独一行，不动上面那行
            // —— 它的字面内容被 ExtenderHarness 断言着。
            callbacks.printOutput(Msg.t("log.license"));
        }
        catch (Exception e) {
            callbacks.printOutput("Zack-AI-Scanner v3.0 loaded successfully");
        }
    }

    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> menuItems = new ArrayList<JMenuItem>();
        int context = invocation.getInvocationContext();
        boolean validContext = false;
        for (int valid : VALID_CONTEXTS) {
            if (context == valid) {
                validContext = true;
                break;
            }
        }
        if (validContext) {
            IHttpRequestResponse[] messages = invocation.getSelectedMessages();
            if (messages == null || messages.length == 0) {
                return menuItems;
            }
            // 类型项**平铺**返回，不再自己套一层菜单：
            // Burp 会把扩展的右键项收进一个以扩展名命名的子菜单（"Zack-AI-Scanner v3.0"），
            // 我们再套一层「Zack-AI-Scanner → 扫描漏洞类型」就变成三层，插件名还重复出现两次。
            // 现在点右键就是：Zack-AI-Scanner v3.0 → 具体类型，一次到位。
            this.addScanModeItem(menuItems, messages, ScanTask.ScanMode.SQL_INJECTION);
            this.addScanModeItem(menuItems, messages, ScanTask.ScanMode.XSS);
            this.addScanModeItem(menuItems, messages, ScanTask.ScanMode.COMMAND_INJECTION);
            this.addScanModeItem(menuItems, messages, ScanTask.ScanMode.FILE_UPLOAD);
            this.addScanModeItem(menuItems, messages, ScanTask.ScanMode.SSRF);
            this.addScanModeItem(menuItems, messages, ScanTask.ScanMode.XXE);
            this.addScanModeItem(menuItems, messages, ScanTask.ScanMode.SSTI);
            this.addScanModeItem(menuItems, messages, ScanTask.ScanMode.FASTJSON);
            this.addScanModeItem(menuItems, messages, ScanTask.ScanMode.LOG4J2);
            this.addScanModeItem(menuItems, messages, ScanTask.ScanMode.STRUTS2);
            this.addScanModeItem(menuItems, messages, ScanTask.ScanMode.SHIRO);
            // 菜单每次右键都重新构造，所以直接读当前语言的文案即可，不用注册绑定器
            JMenuItem aiScanItem = new JMenuItem(Msg.scanModeName(ScanTask.ScanMode.CUSTOM));
            aiScanItem.setFont(new Font("微软雅黑", 0, 12));
            aiScanItem.addActionListener(e -> this.enqueue(messages, ScanTask.ScanMode.CUSTOM));
            menuItems.add(aiScanItem);
        }
        return menuItems;
    }

    private void addScanModeItem(List<JMenuItem> menuItems, IHttpRequestResponse[] messages, ScanTask.ScanMode scanMode) {
        // 显示名走 Msg（数据层的 displayName 仍是中文，见 i18n.Msg 的类注释）
        JMenuItem item = new JMenuItem(Msg.scanModeName(scanMode));
        item.setFont(new Font("微软雅黑", 0, 12));
        item.addActionListener(e -> this.enqueue(messages, scanMode));
        menuItems.add(item);
    }

    /**
     * 把选中的请求丢给主面板扫描。
     *
     * <p>界面是在 {@code invokeLater} 里异步搭的（见 registerExtenderCallbacks），万一初始化失败，
     * mainPanel 会一直是 null —— 以前这里静默 continue，却照样打印「已发送 N 个请求」，
     * 于是 11 个菜单项全都变成「点了没反应，但输出说成功了」。现在如实报告。
     */
    private void enqueue(IHttpRequestResponse[] messages, ScanTask.ScanMode scanMode) {
        if (this.mainPanel == null) {
            this.callbacks.printError(Msg.t("log.menu.notReady", Msg.scanModeName(scanMode)));
            return;
        }
        for (IHttpRequestResponse message : messages) {
            this.mainPanel.addRequest(message, scanMode);
        }
        this.callbacks.printOutput(Msg.t("log.menu.sent", messages.length, Msg.scanModeName(scanMode)));
    }

}
