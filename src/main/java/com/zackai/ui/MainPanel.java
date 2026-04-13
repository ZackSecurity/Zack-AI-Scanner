package com.zackai.ui;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.ITab;
import com.zackai.core.AIEngine;
import com.zackai.core.ConfigManager;
import com.zackai.model.ScanTask;
import com.zackai.model.VulnResult;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.nio.charset.StandardCharsets;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
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
    private List<ScanTask> tasks;
    private int taskIdCounter = 1;
    private ExecutorService executorService;
    private static final Color BG_BLACK = Color.WHITE;
    private static final Color TEXT_GREEN = new Color(33, 37, 41);
    private static final Color PANEL_DARK = new Color(245, 247, 250);
    private static final Color BORDER_GREEN = new Color(210, 214, 220);

    public MainPanel(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, LogPanel logPanel) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.logPanel = logPanel;
        this.aiEngine = new AIEngine(callbacks, helpers, logPanel, this);
        this.tasks = new ArrayList<ScanTask>();
        this.executorService = Executors.newFixedThreadPool(3);
        this.initUI();
    }

    private void initUI() {
        this.setLayout(new BorderLayout(10, 10));
        this.setBackground(BG_BLACK);
        this.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        JPanel topPanel = this.createTopPanel();
        this.add((Component)topPanel, "North");
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setBackground(BG_BLACK);
        tabbedPane.setForeground(TEXT_GREEN);
        tabbedPane.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 14));
        this.taskTablePanel = new TaskTablePanel(this, this.logPanel);
        tabbedPane.addTab("\u4efb\u52a1\u5217\u8868", this.taskTablePanel);
        this.taskDetailPanel = new TaskDetailPanel(this.callbacks, this.helpers, this);
        tabbedPane.addTab("\u8bf7\u6c42\u4e0e\u54cd\u5e94\u8be6\u60c5", this.taskDetailPanel);
        tabbedPane.addTab("\u65e5\u5fd7\u7edf\u8ba1", this.logPanel.getUiComponent());
        this.add((Component)tabbedPane, "Center");
    }

    private JPanel createTopPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 0));
        panel.setBackground(BG_BLACK);
        panel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER_GREEN, 1), BorderFactory.createEmptyBorder(8, 10, 8, 10)));
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        this.apiKeyStatusLabel = new JLabel("API Key: \u672a\u9a8c\u8bc1");
        this.apiKeyStatusLabel.setForeground(TEXT_GREEN);
        this.apiKeyStatusLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        this.providerStatusLabel = new JLabel("AI\u670d\u52a1: " + (config.getSelectedProvider() != null && !config.getSelectedProvider().isEmpty() ? config.getSelectedProvider() : "\u672a\u914d\u7f6e"));
        this.providerStatusLabel.setForeground(TEXT_GREEN);
        this.providerStatusLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        this.modelStatusLabel = new JLabel("\u6a21\u578b: " + (config.getSelectedAgent() != null && !config.getSelectedAgent().isEmpty() ? config.getSelectedAgent() : "\u672a\u9009\u62e9"));
        this.modelStatusLabel.setForeground(TEXT_GREEN);
        this.modelStatusLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        JPanel centerPanel = new JPanel(new GridBagLayout());
        centerPanel.setBackground(BG_BLACK);
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
        panel.add((Component)centerPanel, "Center");
        JLabel titleLabel = new JLabel("Zack-AI-Scanner v1.0");
        titleLabel.setForeground(TEXT_GREEN);
        titleLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 15));
        panel.add((Component)titleLabel, "West");
        JButton configButton = new JButton("\u914d\u7f6e");
        configButton.setBackground(PANEL_DARK);
        configButton.setForeground(TEXT_GREEN);
        configButton.setBorder(BorderFactory.createLineBorder(BORDER_GREEN, 1));
        configButton.setFocusPainted(false);
        configButton.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 13));
        configButton.setCursor(new Cursor(12));
        configButton.setPreferredSize(new Dimension(70, 30));
        configButton.addMouseListener(new MouseAdapter(){
            @Override
            public void mouseEntered(MouseEvent evt) {
                configButton.setBackground(new Color(233, 236, 239));
            }
            @Override
            public void mouseExited(MouseEvent evt) {
                configButton.setBackground(PANEL_DARK);
            }
        });
        configButton.addActionListener(e -> {
            Frame parentFrame = (Frame)SwingUtilities.getWindowAncestor(this);
            ConfigDialog dialog = new ConfigDialog(parentFrame, this.callbacks, this.helpers);
            dialog.setVisible(true);
            this.refreshConfigStatus();
        });
        panel.add((Component)configButton, "East");
        if (config.getApiKey() != null && !config.getApiKey().isEmpty() && config.getSelectedAgent() != null && !config.getSelectedAgent().isEmpty()) {
            this.autoVerifyApiKey();
        }
        return panel;
    }

    public void addRequest(IHttpRequestResponse request) {
        this.addRequest(request, ScanTask.ScanMode.CUSTOM);
    }

    public void addRequest(IHttpRequestResponse request, ScanTask.ScanMode scanMode) {
        try {
            if (request == null || request.getRequest() == null || request.getHttpService() == null) {
                this.callbacks.printError("无效的请求：请求或请求内容为空");
                this.logPanel.logError("添加请求失败：无效的请求");
                return;
            }
            byte[] requestBytes = request.getRequest();
            if (requestBytes == null || requestBytes.length == 0) {
                this.logPanel.logError("添加请求失败：请求体为空");
                return;
            }
            String requestStr = new String(requestBytes, StandardCharsets.UTF_8);
            String[] firstLine = requestStr.split("\r?\n")[0].split(" ");
            if (firstLine.length < 2) {
                this.logPanel.logError("添加请求失败：HTTP请求格式无效");
                return;
            }
            String method = firstLine.length > 0 ? firstLine[0] : "UNKNOWN";
            String url = request.getHttpService().getProtocol() + "://" + request.getHttpService().getHost() + (firstLine.length > 1 ? firstLine[1] : "");
            ScanTask task = new ScanTask(this.taskIdCounter++, request, method, url, scanMode);
            this.tasks.add(task);
            this.logPanel.logInfo("[新增] 任务 #" + task.getId() + " | 模式: " + task.getScanMode().getDisplayName());
            SwingUtilities.invokeLater(() -> {
                this.taskTablePanel.addTask(task);
                this.updateStats();
            });
            this.executorService.submit(() -> {
                this.updateStats();
                this.aiEngine.scanRequest(task);
                SwingUtilities.invokeLater(() -> {
                    this.taskTablePanel.refreshTask(task);
                    this.updateStats();
                });
            });
        }
        catch (Exception e) {
            this.callbacks.printError("\u6dfb\u52a0\u8bf7\u6c42\u5931\u8d25: " + e.getMessage());
            this.logPanel.logError("\u6dfb\u52a0\u8bf7\u6c42\u5931\u8d25: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void deleteTask(ScanTask task) {
        this.tasks.remove(task);
        this.taskTablePanel.removeTask(task);
        this.updateStats();
        this.logPanel.logInfo("\u5220\u9664\u4efb\u52a1 #" + task.getId());
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
        this.updateStats();
        this.logPanel.logInfo("\u6e05\u7a7a\u5df2\u5b8c\u6210\u4efb\u52a1\uff0c\u5171 " + toRemove.size() + " \u4e2a");
    }

    public void rescanTask(ScanTask task) {
        task.setStatus(ScanTask.TaskStatus.PENDING);
        task.setVulnLevel(ScanTask.VulnLevel.NONE);
        task.setAiTag("");
        task.getVulnerabilities().clear();
        task.clearProbeRecords();
        this.logPanel.logInfo("\u91cd\u65b0\u626b\u63cf\u4efb\u52a1 #" + task.getId());
        this.taskTablePanel.refreshTask(task);
        this.updateStats();
        this.executorService.submit(() -> {
            this.updateStats();
            this.aiEngine.scanRequest(task);
            SwingUtilities.invokeLater(() -> {
                this.taskTablePanel.refreshTask(task);
                this.updateStats();
            });
        });
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
            totalVulns += task.getVulnerabilities().size();
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
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        if (this.providerStatusLabel != null) {
            this.providerStatusLabel.setText("AI\u670d\u52a1: " + (config.getSelectedProvider() != null && !config.getSelectedProvider().isEmpty() ? config.getSelectedProvider() : "\u672a\u914d\u7f6e"));
        }
        if (this.modelStatusLabel != null) {
            this.modelStatusLabel.setText("\u6a21\u578b: " + (config.getSelectedAgent() != null && !config.getSelectedAgent().isEmpty() ? config.getSelectedAgent() : "\u672a\u9009\u62e9"));
        }
        if (config.getApiKey() != null && !config.getApiKey().isEmpty() && config.getSelectedAgent() != null && !config.getSelectedAgent().isEmpty()) {
            this.autoVerifyApiKey();
        } else {
            this.updateApiKeyStatus("\u672a\u914d\u7f6e", new Color(200, 100, 100));
        }
    }

    private void autoVerifyApiKey() {
        this.updateApiKeyStatus("\u9a8c\u8bc1\u4e2d", new Color(200, 200, 100));
        new Thread(() -> {
            try {
                ConfigManager.Config config = ConfigManager.getInstance().getConfig();
                OkHttpClient client = new OkHttpClient.Builder().connectTimeout(10L, TimeUnit.SECONDS).readTimeout(10L, TimeUnit.SECONDS).build();
                String testJson = "{\"model\":\"" + config.getSelectedAgent() + "\",\"messages\":[{\"role\":\"user\",\"content\":\"test\"}],\"max_tokens\":5}";
                RequestBody body = RequestBody.create(MediaType.parse("application/json"), testJson);
                Request.Builder requestBuilder = new Request.Builder().url(config.getApiEndpoint()).post(body);
                String endpoint = config.getApiEndpoint().toLowerCase();
                if (endpoint.contains("anthropic.com")) {
                    requestBuilder.addHeader("x-api-key", config.getApiKey());
                    requestBuilder.addHeader("anthropic-version", "2023-06-01");
                } else {
                    requestBuilder.addHeader("Authorization", "Bearer " + config.getApiKey());
                }
                try (Response response = client.newCall(requestBuilder.build()).execute()) {
                    if (response.isSuccessful()) {
                        this.updateApiKeyStatus("\u53ef\u7528", TEXT_GREEN);
                        this.logPanel.logSuccess("API Key\u9a8c\u8bc1\u6210\u529f");
                    } else {
                        this.updateApiKeyStatus("\u4e0d\u53ef\u7528", new Color(255, 100, 100));
                        this.logPanel.logError("API Key\u9a8c\u8bc1\u5931\u8d25: HTTP " + response.code());
                    }
                }
            }
            catch (Exception e) {
                this.updateApiKeyStatus("\u4e0d\u53ef\u7528", new Color(255, 100, 100));
                this.logPanel.logError("API Key\u9a8c\u8bc1\u5931\u8d25: " + e.getMessage());
            }
        }).start();
    }

    private void updateApiKeyStatus(String status, Color color) {
        SwingUtilities.invokeLater(() -> {
            if (this.apiKeyStatusLabel != null) {
                this.apiKeyStatusLabel.setText("API Key: " + status);
                this.apiKeyStatusLabel.setForeground(color);
            }
        });
    }

    public String getTabCaption() {
        return "Zack-AI-Scanner";
    }

    public Component getUiComponent() {
        return this;
    }

    public void shutdown() {
        if (this.executorService != null && !this.executorService.isShutdown()) {
            this.executorService.shutdownNow();
            try {
                if (!this.executorService.awaitTermination(5L, TimeUnit.SECONDS)) {
                    this.callbacks.printError("ExecutorService did not terminate in time");
                }
            } catch (InterruptedException e) {
                this.executorService.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }

    @Override
    public void onVulnerabilityFound(ScanTask task, VulnResult vuln) {
        SwingUtilities.invokeLater(() -> {
            this.taskTablePanel.refreshTask(task);
            this.updateStats();
            this.logPanel.logSuccess("[\u5b9e\u65f6] \u4efb\u52a1 #" + task.getId() + " \u53d1\u73b0\u6f0f\u6d1e: " + vuln.getVulnName());
        });
    }
}
