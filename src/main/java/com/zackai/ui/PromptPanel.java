package com.zackai.ui;

import burp.IBurpExtenderCallbacks;
import com.zackai.core.ConfigManager;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

public class PromptPanel
extends JPanel {
    private IBurpExtenderCallbacks callbacks;
    private JTextArea systemPromptArea;
    private JTextArea verifyPromptArea;
    private static final Color BG_BLACK = Color.WHITE;
    private static final Color TEXT_GREEN = new Color(33, 37, 41);
    private static final Color PANEL_DARK = new Color(245, 247, 250);
    private static final Color BORDER_GREEN = new Color(210, 214, 220);
    private static final Color INPUT_BG = Color.WHITE;

    public PromptPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.initUI();
        this.loadPrompts();
    }

    private void initUI() {
        this.setLayout(new BorderLayout(10, 10));
        this.setBackground(BG_BLACK);
        this.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        JPanel toolBar = new JPanel(new FlowLayout(0, 15, 8));
        toolBar.setBackground(PANEL_DARK);
        toolBar.setBorder(BorderFactory.createLineBorder(BORDER_GREEN));
        JLabel titleLabel = new JLabel("\u63d0\u793a\u8bcd\u7ba1\u7406");
        titleLabel.setForeground(TEXT_GREEN);
        titleLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 16));
        toolBar.add(titleLabel);
        toolBar.add(Box.createHorizontalStrut(30));
        JButton saveButton = this.createButton("\u4fdd\u5b58\u63d0\u793a\u8bcd");
        saveButton.addActionListener(e -> this.savePrompts());
        toolBar.add(saveButton);
        JButton resetButton = this.createButton("\u6062\u590d\u9ed8\u8ba4");
        resetButton.addActionListener(e -> this.resetPrompts());
        toolBar.add(resetButton);
        this.add((Component)toolBar, "North");
        JPanel promptsPanel = new JPanel(new GridLayout(2, 1, 10, 10));
        promptsPanel.setBackground(BG_BLACK);
        this.systemPromptArea = this.createPromptArea();
        JScrollPane systemScroll = new JScrollPane(this.systemPromptArea);
        this.styleScrollPane(systemScroll, "\u5206\u6790\u63d0\u793a\u8bcd\uff08\u7528\u4e8e\u5206\u6790\u8bf7\u6c42\u548c\u751f\u6210\u6d4b\u8bd5\u8f7d\u8377\uff09");
        promptsPanel.add(systemScroll);
        this.verifyPromptArea = this.createPromptArea();
        JScrollPane verifyScroll = new JScrollPane(this.verifyPromptArea);
        this.styleScrollPane(verifyScroll, "\u9a8c\u8bc1\u63d0\u793a\u8bcd\uff08\u7528\u4e8e\u9a8c\u8bc1\u6f0f\u6d1e\u662f\u5426\u771f\u5b9e\u5b58\u5728\uff09");
        promptsPanel.add(verifyScroll);
        this.add((Component)promptsPanel, "Center");
    }

    private JTextArea createPromptArea() {
        JTextArea area = new JTextArea();
        area.setBackground(INPUT_BG);
        area.setForeground(TEXT_GREEN);
        area.setCaretColor(TEXT_GREEN);
        area.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setTabSize(4);
        return area;
    }

    private void styleScrollPane(JScrollPane scroll, String title) {
        scroll.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(BORDER_GREEN, 2), title, 1, 2, new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 14), TEXT_GREEN));
        scroll.getViewport().setBackground(INPUT_BG);
    }

    private JButton createButton(String text) {
        final JButton button = new JButton(text);
        button.setBackground(PANEL_DARK);
        button.setForeground(TEXT_GREEN);
        button.setBorder(BorderFactory.createLineBorder(BORDER_GREEN, 2));
        button.setFocusPainted(false);
        button.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 13));
        button.setCursor(new Cursor(12));
        button.setPreferredSize(new Dimension(120, 35));
        button.addMouseListener(new MouseAdapter(){

            @Override
            public void mouseEntered(MouseEvent evt) {
                button.setBackground(new Color(233, 236, 239));
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                button.setBackground(PANEL_DARK);
            }
        });
        return button;
    }

    private void loadPrompts() {
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        String systemPrompt = config.getSystemPrompt();
        String verifyPrompt = config.getVerifyPrompt();
        this.systemPromptArea.setText(systemPrompt != null && !systemPrompt.isEmpty() ? systemPrompt : this.getDefaultSystemPrompt());
        this.verifyPromptArea.setText(verifyPrompt != null && !verifyPrompt.isEmpty() ? verifyPrompt : this.getDefaultVerifyPrompt());
    }

    private void savePrompts() {
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        config.setSystemPrompt(this.systemPromptArea.getText());
        config.setVerifyPrompt(this.verifyPromptArea.getText());
        ConfigManager.getInstance().saveConfig();
        this.callbacks.printOutput("\u63d0\u793a\u8bcd\u5df2\u4fdd\u5b58");
        JOptionPane.showMessageDialog(this, "\u63d0\u793a\u8bcd\u5df2\u4fdd\u5b58\uff01\n\u4e0b\u6b21\u626b\u63cf\u5c06\u4f7f\u7528\u65b0\u7684\u63d0\u793a\u8bcd\u3002", "\u4fdd\u5b58\u6210\u529f", 1);
    }

    private void resetPrompts() {
        if (JOptionPane.showConfirmDialog(this, "\u786e\u5b9a\u8981\u6062\u590d\u9ed8\u8ba4\u63d0\u793a\u8bcd\u5417\uff1f\n\u5f53\u524d\u7684\u81ea\u5b9a\u4e49\u63d0\u793a\u8bcd\u5c06\u88ab\u8986\u76d6\u3002", "\u786e\u8ba4", 0) == 0) {
            this.systemPromptArea.setText(this.getDefaultSystemPrompt());
            this.verifyPromptArea.setText(this.getDefaultVerifyPrompt());
            this.callbacks.printOutput("\u63d0\u793a\u8bcd\u5df2\u6062\u590d\u9ed8\u8ba4");
        }
    }

    private String getDefaultSystemPrompt() {
        return "\u4f60\u662f\u9876\u7ea7\u6e17\u900f\u6d4b\u8bd5\u4e13\u5bb6\u3002\u5206\u6790HTTP\u8bf7\u6c42\u5e76\u5236\u5b9a\u6d4b\u8bd5\u7b56\u7565\u3002\n\n\u5206\u6790\u8981\u70b9\uff1a\n1. \u8bc6\u522b\u8bf7\u6c42\u7c7b\u578b\u548c\u53c2\u6570\u4f4d\u7f6e\n2. \u5224\u65ad\u53ef\u80fd\u7684\u6f0f\u6d1e\u7c7b\u578b\uff08SQL\u6ce8\u5165/XSS/\u547d\u4ee4\u6ce8\u5165/\u6587\u4ef6\u4e0a\u4f20/SSRF\u7b49\uff09\n3. \u751f\u62102-5\u4e2a\u9ad8\u8d28\u91cf\u6d4b\u8bd5\u8f7d\u8377\n4. \u8003\u8651WAF\u7ed5\u8fc7\u6280\u672f\n\n\u65e0\u5bb3\u5316\u6d4b\u8bd5\u8981\u6c42\uff1a\n- \u6587\u4ef6\u4e0a\u4f20\uff1a\u4e0d\u8981\u4e0a\u4f20webshell\uff0c\u4f7f\u7528\u8f93\u51fa123\u6216hello\u7684PHP/JSP\u6587\u4ef6\u6d4b\u8bd5\n- \u547d\u4ee4\u6ce8\u5165\uff1a\u4f7f\u7528\u65e0\u5bb3\u547d\u4ee4\u5982whoami\u3001id\u3001echo\u3001sleep 1\u7b49\n- SQL\u6ce8\u5165\uff1a\u4f7f\u7528\u67e5\u8be2\u6d4b\u8bd5\uff0c\u4e0d\u8981\u4f7f\u7528DROP/DELETE\u7b49\u7834\u574f\u6027\u8bed\u53e5\n- XSS\uff1a\u4f7f\u7528alert\u3001console.log\u7b49\u65e0\u5bb3\u6d4b\u8bd5\n- SSRF\uff1a\u4f7f\u7528\u516c\u5171DNS\u670d\u52a1\u6216\u81ea\u5df1\u7684\u670d\u52a1\u5668\u6d4b\u8bd5\uff0c\u4e0d\u8981\u653b\u51fb\u5185\u7f51\n\n\u4e25\u683c\u8981\u6c42\uff1a\u5fc5\u987b\u8fd4\u56de\u7eafJSON\u683c\u5f0f\uff0c\u4e0d\u8981markdown\u4ee3\u7801\u5757\uff0c\u4e0d\u8981\u989d\u5916\u8bf4\u660e\u3002\n\nJSON\u683c\u5f0f\u793a\u4f8b\uff1a\n{\"analysis\":\"\u53d1\u73b0\u767b\u5f55\u63a5\u53e3\uff0c\u5b58\u5728SQL\u6ce8\u5165\u98ce\u9669\",\"vulnTypes\":[\"SQL_INJECTION\"],\"testPayloads\":[{\"type\":\"SQL_INJECTION\",\"payload\":\"' OR '1'='1\",\"position\":\"username\"}],\"needsDeepTest\":false}";
    }

    private String getDefaultVerifyPrompt() {
        return "\u4f5c\u4e3a\u6e17\u900f\u6d4b\u8bd5\u4e13\u5bb6\uff0c\u4ed4\u7ec6\u5206\u6790\u6d4b\u8bd5\u7ed3\u679c\uff0c\u5224\u65ad\u6f0f\u6d1e\u662f\u5426\u771f\u5b9e\u5b58\u5728\u3002\n\n\u9a8c\u8bc1\u8981\u6c42\uff1a\n1. \u6df1\u5165\u5206\u6790\u54cd\u5e94\u5185\u5bb9\uff0c\u4e0d\u80fd\u53ea\u770b\u54cd\u5e94\u957f\u5ea6\u6216\u72b6\u6001\u7801\n2. \u67e5\u627e\u54cd\u5e94\u4e2d\u7684\u5177\u4f53\u7279\u5f81\uff1a\n   - SQL\u6ce8\u5165\uff1a\u9519\u8bef\u4fe1\u606f\u3001\u6570\u636e\u5e93\u7279\u5f81\u3001\u67e5\u8be2\u7ed3\u679c\u3001\u5b57\u6bb5\u6cc4\u9732\n   - XSS\uff1a\u8f7d\u8377\u56de\u663e\u3001HTML\u6807\u7b7e\u3001JavaScript\u4ee3\u7801\n   - RCE\uff1a\u547d\u4ee4\u6267\u884c\u7ed3\u679c\u3001\u7cfb\u7edf\u4fe1\u606f\u8f93\u51fa\n   - \u6587\u4ef6\u4e0a\u4f20\uff1a\u4e0a\u4f20\u6210\u529f\u63d0\u793a\u3001\u6587\u4ef6\u8def\u5f84\u3001\u8bbf\u95eeURL\n3. \u6392\u9664\u8bef\u5224\uff1aWAF\u62e6\u622a\u3001\u4e1a\u52a1\u903b\u8f91\u6b63\u5e38\u8fd4\u56de\u3001\u53c2\u6570\u9a8c\u8bc1\u5931\u8d25\n4. \u8bc1\u636e\u5145\u5206\uff1a\u5fc5\u987b\u6709\u660e\u786e\u7684\u6280\u672f\u7279\u5f81\u8bc1\u660e\u6f0f\u6d1e\u5b58\u5728\n5. \u7f6e\u4fe1\u5ea6\uff1a\u53ea\u6709\u226590%\u624d\u62a5\u544a\u6f0f\u6d1e\n\n\u4e25\u683c\u8981\u6c42\uff1a\n- \u5fc5\u987b\u5206\u6790\u54cd\u5e94\u7684\u5177\u4f53\u5185\u5bb9\uff0c\u4e0d\u80fd\u53ea\u770b\u5927\u5c0f\n- \u5fc5\u987b\u627e\u5230\u660e\u786e\u7684\u6f0f\u6d1e\u7279\u5f81\u8bc1\u636e\n- \u5fc5\u987b\u8fd4\u56de\u7eafJSON\u683c\u5f0f\uff0c\u4e0d\u8981markdown\n\nJSON\u683c\u5f0f\uff1a\n{\"vulnerable\":true,\"confidence\":95,\"vulnType\":\"SQL_INJECTION\",\"level\":\"CRITICAL\",\"description\":\"\u54cd\u5e94\u5305\u542bMySQL\u9519\u8bef\uff1aYou have an error in your SQL syntax\uff0c\u8bc1\u660e\u5b58\u5728SQL\u6ce8\u5165\",\"tag\":\"SQL\u6ce8\u5165\",\"needsDeepTest\":false}";
    }

}
