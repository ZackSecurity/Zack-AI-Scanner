package com.zackai.ui;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import com.zackai.core.ConfigManager;
import com.zackai.model.AIProvider;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class ConfigDialog
extends JDialog {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JComboBox<AIProvider> providerComboBox;
    private JTextField apiKeyField;
    private JTextField apiEndpointField;
    private JTextField modelsEndpointField;
    private JComboBox<String> agentComboBox;
    private JLabel statusLabel;
    private boolean isUpdatingProvider = false;
    private static final Color BG_BLACK = Color.WHITE;
    private static final Color TEXT_GREEN = new Color(33, 37, 41);
    private static final Color PANEL_DARK = new Color(245, 247, 250);
    private static final Color BORDER_GREEN = new Color(210, 214, 220);
    private static final Color INPUT_BG = Color.WHITE;

    public ConfigDialog(Frame owner, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        super(owner, "Zack-AI-Scanner - \u914d\u7f6e\u4e2d\u5fc3", true);
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.initUI();
        SwingUtilities.invokeLater(() -> this.loadConfig());
        this.setSize(800, 550);
        this.setLocationRelativeTo(owner);
    }

    private void initUI() {
        this.getContentPane().setBackground(BG_BLACK);
        this.setLayout(new BorderLayout(15, 15));
        JPanel mainPanel = new JPanel(new BorderLayout(15, 15));
        mainPanel.setBackground(BG_BLACK);
        mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        JLabel titleLabel = new JLabel("Zack-AI-Scanner\u914d\u7f6e\u4e2d\u5fc3");
        titleLabel.setForeground(TEXT_GREEN);
        titleLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 24));
        titleLabel.setHorizontalAlignment(0);
        mainPanel.add((Component)titleLabel, "North");
        JPanel apiPanel = this.createApiConfigPanel();
        mainPanel.add((Component)apiPanel, "Center");
        JPanel bottomPanel = new JPanel(new BorderLayout(10, 10));
        bottomPanel.setBackground(BG_BLACK);
        JPanel buttonPanel = new JPanel(new FlowLayout(1, 20, 10));
        buttonPanel.setBackground(BG_BLACK);
        JButton saveButton = this.createStyledButton("\u4fdd\u5b58\u914d\u7f6e");
        saveButton.addActionListener(e -> this.saveConfig());
        buttonPanel.add(saveButton);
        JButton verifyButton = this.createStyledButton("\u9a8c\u8bc1Key");
        verifyButton.addActionListener(e -> this.verifyApiKey());
        buttonPanel.add(verifyButton);
        JButton refreshButton = this.createStyledButton("\u83b7\u53d6\u6a21\u578b");
        refreshButton.addActionListener(e -> this.refreshAgents());
        buttonPanel.add(refreshButton);
        JButton closeButton = this.createStyledButton("\u5173\u95ed");
        closeButton.addActionListener(e -> this.dispose());
        buttonPanel.add(closeButton);
        bottomPanel.add((Component)buttonPanel, "North");
        this.statusLabel = new JLabel("\u72b6\u6001: \u7b49\u5f85\u914d\u7f6e");
        this.statusLabel.setForeground(TEXT_GREEN);
        this.statusLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 14));
        this.statusLabel.setHorizontalAlignment(0);
        this.statusLabel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER_GREEN, 2), BorderFactory.createEmptyBorder(10, 10, 10, 10)));
        bottomPanel.add((Component)this.statusLabel, "Center");
        mainPanel.add((Component)bottomPanel, "South");
        this.add(mainPanel);
    }

    private JPanel createApiConfigPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(BG_BLACK);
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 0.0;
        JLabel providerLabel = new JLabel("AI\u670d\u52a1:");
        providerLabel.setForeground(TEXT_GREEN);
        providerLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 15));
        panel.add((Component)providerLabel, gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        JPanel providerPanel = new JPanel(new BorderLayout(10, 0));
        providerPanel.setBackground(BG_BLACK);
        this.providerComboBox = this.createProviderComboBox();
        this.providerComboBox.addActionListener(e -> {
            if (!this.isUpdatingProvider) {
                this.onProviderChanged();
            }
        });
        providerPanel.add(this.providerComboBox, "Center");
        JButton manageButton = this.createSmallButton("\u7ba1\u7406\u7aef\u70b9");
        manageButton.addActionListener(e -> {
            EndpointManagerDialog dialog = new EndpointManagerDialog((Frame)SwingUtilities.getWindowAncestor(this));
            dialog.setVisible(true);
            this.reloadProviders();
        });
        providerPanel.add((Component)manageButton, "East");
        panel.add((Component)providerPanel, gbc);
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0.0;
        JLabel apiKeyLabel = new JLabel("API Key:");
        apiKeyLabel.setForeground(TEXT_GREEN);
        apiKeyLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 15));
        panel.add((Component)apiKeyLabel, gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        this.apiKeyField = this.createStyledTextField();
        panel.add((Component)this.apiKeyField, gbc);
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 0.0;
        JLabel endpointLabel = new JLabel("API\u7aef\u70b9:");
        endpointLabel.setForeground(TEXT_GREEN);
        endpointLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 15));
        panel.add((Component)endpointLabel, gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        this.apiEndpointField = this.createStyledTextField();
        this.apiEndpointField.setEditable(false);
        this.apiEndpointField.setBackground(PANEL_DARK);
        panel.add((Component)this.apiEndpointField, gbc);
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.weightx = 0.0;
        JLabel modelsLabel = new JLabel("\u6a21\u578b\u7aef\u70b9:");
        modelsLabel.setForeground(TEXT_GREEN);
        modelsLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 15));
        panel.add((Component)modelsLabel, gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        this.modelsEndpointField = this.createStyledTextField();
        this.modelsEndpointField.setEditable(false);
        this.modelsEndpointField.setBackground(PANEL_DARK);
        panel.add((Component)this.modelsEndpointField, gbc);
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.weightx = 0.0;
        JLabel agentLabel = new JLabel("\u9009\u62e9\u6a21\u578b:");
        agentLabel.setForeground(TEXT_GREEN);
        agentLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 15));
        panel.add((Component)agentLabel, gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        this.agentComboBox = this.createStyledComboBox();
        panel.add(this.agentComboBox, gbc);
        return panel;
    }

    private JTextField createStyledTextField() {
        JTextField field = new JTextField(40);
        field.setBackground(INPUT_BG);
        field.setForeground(TEXT_GREEN);
        field.setCaretColor(TEXT_GREEN);
        field.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER_GREEN, 2), BorderFactory.createEmptyBorder(10, 12, 10, 12)));
        field.setFont(new Font("Consolas", 0, 14));
        return field;
    }

    private JComboBox<AIProvider> createProviderComboBox() {
        JComboBox<AIProvider> comboBox = new JComboBox<AIProvider>();
        comboBox.setBackground(INPUT_BG);
        comboBox.setForeground(TEXT_GREEN);
        comboBox.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 14));
        comboBox.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER_GREEN, 2), BorderFactory.createEmptyBorder(8, 10, 8, 10)));
        List<AIProvider> allProviders = ConfigManager.getInstance().getConfig().getAllProviders();
        for (AIProvider provider : allProviders) {
            comboBox.addItem(provider);
        }
        comboBox.addItem(new AIProvider("\u81ea\u5b9a\u4e49", "", "", "bearer", true));
        return comboBox;
    }

    private JComboBox<String> createStyledComboBox() {
        JComboBox<String> comboBox = new JComboBox<String>(new String[]{"\u8bf7\u5148\u83b7\u53d6\u6a21\u578b\u5217\u8868"});
        comboBox.setBackground(INPUT_BG);
        comboBox.setForeground(TEXT_GREEN);
        comboBox.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 14));
        comboBox.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER_GREEN, 2), BorderFactory.createEmptyBorder(8, 10, 8, 10)));
        return comboBox;
    }

    private JButton createStyledButton(String text) {
        final JButton button = new JButton(text);
        button.setBackground(PANEL_DARK);
        button.setForeground(TEXT_GREEN);
        button.setBorder(BorderFactory.createLineBorder(BORDER_GREEN, 2));
        button.setFocusPainted(false);
        button.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 14));
        button.setCursor(new Cursor(12));
        button.setPreferredSize(new Dimension(130, 45));
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

    private JButton createSmallButton(String text) {
        final JButton button = new JButton(text);
        button.setBackground(PANEL_DARK);
        button.setForeground(TEXT_GREEN);
        button.setBorder(BorderFactory.createLineBorder(BORDER_GREEN, 1));
        button.setFocusPainted(false);
        button.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 12));
        button.setCursor(new Cursor(12));
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

    private void loadConfig() {
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        this.callbacks.printOutput("====== \u52a0\u8f7d\u914d\u7f6e ======");
        this.apiKeyField.setText(config.getApiKey() != null ? config.getApiKey() : "");
        this.callbacks.printOutput("Key: " + (config.getApiKey() != null && !config.getApiKey().isEmpty() ? "\u5df2\u52a0\u8f7d" : "\u7a7a"));
        this.agentComboBox.removeAllItems();
        List<String> models = config.getAvailableModels();
        if (models != null && !models.isEmpty()) {
            for (String model : models) {
                this.agentComboBox.addItem(model);
            }
            if (config.getSelectedAgent() != null && !config.getSelectedAgent().isEmpty()) {
                this.agentComboBox.setSelectedItem(config.getSelectedAgent());
            }
            this.callbacks.printOutput("\u6a21\u578b: \u5df2\u52a0\u8f7d" + models.size() + "\u4e2a\uff0c\u9009\u4e2d: " + config.getSelectedAgent());
        } else {
            this.agentComboBox.addItem("\u8bf7\u5148\u83b7\u53d6\u6a21\u578b\u5217\u8868");
            this.callbacks.printOutput("\u6a21\u578b: \u65e0");
        }
        String apiEndpoint = config.getApiEndpoint();
        String modelsEndpoint = config.getModelsEndpoint();
        this.isUpdatingProvider = true;
        AIProvider matchedProvider = null;
        if (apiEndpoint != null && !apiEndpoint.isEmpty()) {
            AIProvider provider;
            int i;
            this.callbacks.printOutput("\u6839\u636e\u7aef\u70b9\u5339\u914d\u670d\u52a1\u5546: " + apiEndpoint);
            for (i = 0; i < this.providerComboBox.getItemCount(); ++i) {
                String providerModelsEndpoint;
                provider = this.providerComboBox.getItemAt(i);
                if (provider.getName().equals("\u81ea\u5b9a\u4e49")) continue;
                String providerApiEndpoint = provider.getApiEndpoint();
                if (providerApiEndpoint != null && providerApiEndpoint.equals(apiEndpoint)) {
                    matchedProvider = provider;
                    this.callbacks.printOutput("\u627e\u5230\u5339\u914d\u7684\u670d\u52a1\u5546: " + provider.getName() + " (\u901a\u8fc7API\u7aef\u70b9)");
                    break;
                }
                if (modelsEndpoint == null || modelsEndpoint.isEmpty() || (providerModelsEndpoint = provider.getModelsEndpoint()) == null || !providerModelsEndpoint.equals(modelsEndpoint)) continue;
                matchedProvider = provider;
                this.callbacks.printOutput("\u627e\u5230\u5339\u914d\u7684\u670d\u52a1\u5546: " + provider.getName() + " (\u901a\u8fc7\u6a21\u578b\u7aef\u70b9)");
                break;
            }
            if (matchedProvider == null) {
                this.callbacks.printOutput("\u672a\u627e\u5230\u5339\u914d\u7684\u9884\u8bbe\u670d\u52a1\u5546\uff0c\u8bbe\u7f6e\u4e3a\u81ea\u5b9a\u4e49");
                for (i = 0; i < this.providerComboBox.getItemCount(); ++i) {
                    provider = this.providerComboBox.getItemAt(i);
                    if (!provider.getName().equals("\u81ea\u5b9a\u4e49")) continue;
                    matchedProvider = provider;
                    break;
                }
            }
        } else {
            String selectedProvider = config.getSelectedProvider();
            if (selectedProvider != null && !selectedProvider.isEmpty()) {
                this.callbacks.printOutput("\u4f7f\u7528\u4fdd\u5b58\u7684\u670d\u52a1\u5546\u540d\u79f0: " + selectedProvider);
                for (int i = 0; i < this.providerComboBox.getItemCount(); ++i) {
                    AIProvider provider = this.providerComboBox.getItemAt(i);
                    if (!provider.getName().equals(selectedProvider)) continue;
                    matchedProvider = provider;
                    break;
                }
            }
        }
        if (matchedProvider != null) {
            this.providerComboBox.setSelectedItem(matchedProvider);
            this.callbacks.printOutput("AI\u670d\u52a1\u5df2\u8bbe\u7f6e\u4e3a: " + matchedProvider.getName());
        }
        this.isUpdatingProvider = false;
        SwingUtilities.invokeLater(() -> {
            AIProvider currentProvider;
            if (apiEndpoint != null && !apiEndpoint.isEmpty()) {
                this.apiEndpointField.setText(apiEndpoint);
            }
            if (modelsEndpoint != null && !modelsEndpoint.isEmpty()) {
                this.modelsEndpointField.setText(modelsEndpoint);
            }
            if ((currentProvider = (AIProvider)this.providerComboBox.getSelectedItem()) != null && currentProvider.getName().equals("\u81ea\u5b9a\u4e49")) {
                this.apiEndpointField.setEditable(true);
                this.modelsEndpointField.setEditable(true);
                this.apiEndpointField.setBackground(INPUT_BG);
                this.modelsEndpointField.setBackground(INPUT_BG);
            } else {
                this.apiEndpointField.setEditable(false);
                this.modelsEndpointField.setEditable(false);
                this.apiEndpointField.setBackground(PANEL_DARK);
                this.modelsEndpointField.setBackground(PANEL_DARK);
            }
        });
        this.callbacks.printOutput("====== \u52a0\u8f7d\u5b8c\u6210 ======");
    }

    private void onProviderChanged() {
        AIProvider selected = (AIProvider)this.providerComboBox.getSelectedItem();
        if (selected == null) {
            return;
        }
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        if (selected.getName().equals("\u81ea\u5b9a\u4e49")) {
            this.apiEndpointField.setEditable(true);
            this.modelsEndpointField.setEditable(true);
            this.apiEndpointField.setBackground(INPUT_BG);
            this.modelsEndpointField.setBackground(INPUT_BG);
            if (config.getApiEndpoint() != null && !config.getApiEndpoint().isEmpty()) {
                this.apiEndpointField.setText(config.getApiEndpoint());
            }
            if (config.getModelsEndpoint() != null && !config.getModelsEndpoint().isEmpty()) {
                this.modelsEndpointField.setText(config.getModelsEndpoint());
            }
            this.statusLabel.setText("\u72b6\u6001: \u81ea\u5b9a\u4e49\u6a21\u5f0f - \u53ef\u624b\u52a8\u4fee\u6539\u7aef\u70b9");
            this.statusLabel.setForeground(new Color(255, 255, 0));
        } else {
            this.apiEndpointField.setEditable(false);
            this.modelsEndpointField.setEditable(false);
            this.apiEndpointField.setBackground(PANEL_DARK);
            this.modelsEndpointField.setBackground(PANEL_DARK);
            this.apiEndpointField.setText(selected.getApiEndpoint());
            this.modelsEndpointField.setText(selected.getModelsEndpoint());
            this.statusLabel.setText("\u72b6\u6001: \u5df2\u9009\u62e9 " + selected.getName());
            this.statusLabel.setForeground(TEXT_GREEN);
        }
    }

    private void reloadProviders() {
        this.isUpdatingProvider = true;
        AIProvider currentSelected = (AIProvider)this.providerComboBox.getSelectedItem();
        String currentName = currentSelected != null ? currentSelected.getName() : "";
        this.providerComboBox.removeAllItems();
        List<AIProvider> allProviders = ConfigManager.getInstance().getConfig().getAllProviders();
        for (AIProvider provider : allProviders) {
            this.providerComboBox.addItem(provider);
        }
        this.providerComboBox.addItem(new AIProvider("\u81ea\u5b9a\u4e49", "", "", "bearer", true));
        for (int i = 0; i < this.providerComboBox.getItemCount(); ++i) {
            if (!this.providerComboBox.getItemAt(i).getName().equals(currentName)) continue;
            this.providerComboBox.setSelectedIndex(i);
            break;
        }
        this.isUpdatingProvider = false;
    }

    private void saveConfig() {
        Object selectedItem;
        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
        config.setApiKey(this.apiKeyField.getText().trim());
        config.setApiEndpoint(this.apiEndpointField.getText().trim());
        config.setModelsEndpoint(this.modelsEndpointField.getText().trim());
        AIProvider selectedProvider = (AIProvider)this.providerComboBox.getSelectedItem();
        if (selectedProvider != null) {
            config.setSelectedProvider(selectedProvider.getName());
            this.callbacks.printOutput("\u4fdd\u5b58\u670d\u52a1\u5546: " + selectedProvider.getName());
        }
        if ((selectedItem = this.agentComboBox.getSelectedItem()) != null && !selectedItem.toString().equals("\u8bf7\u5148\u83b7\u53d6\u6a21\u578b\u5217\u8868")) {
            config.setSelectedAgent(selectedItem.toString());
        }
        ConfigManager.getInstance().saveConfig();
        this.statusLabel.setText("\u72b6\u6001: \u914d\u7f6e\u5df2\u4fdd\u5b58");
        this.statusLabel.setForeground(TEXT_GREEN);
        this.callbacks.printOutput("\u914d\u7f6e\u5df2\u4fdd\u5b58");
        JOptionPane.showMessageDialog(this, "\u914d\u7f6e\u5df2\u6210\u529f\u4fdd\u5b58\n\nAI\u670d\u52a1: " + (selectedProvider != null ? selectedProvider.getName() : "\u672a\u8bbe\u7f6e") + "\nAPI Key: " + (config.getApiKey().isEmpty() ? "\u672a\u8bbe\u7f6e" : "\u5df2\u8bbe\u7f6e") + "\n\u6a21\u578b: " + config.getSelectedAgent(), "\u4fdd\u5b58\u6210\u529f", 1);
    }

    private void verifyApiKey() {
        Object selectedModel = this.agentComboBox.getSelectedItem();
        if (selectedModel == null || selectedModel.toString().trim().isEmpty() || selectedModel.toString().equals("\u8bf7\u5148\u83b7\u53d6\u6a21\u578b\u5217\u8868")) {
            this.statusLabel.setText("\u72b6\u6001: \u8bf7\u5148\u9009\u62e9\u6a21\u578b");
            this.statusLabel.setForeground(new Color(255, 0, 0));
            JOptionPane.showMessageDialog(this, "\u8bf7\u5148\u9009\u62e9\u6a21\u578b", "\u63d0\u793a", 2);
            return;
        }
        this.statusLabel.setText("\u72b6\u6001: \u9a8c\u8bc1\u4e2d...");
        this.statusLabel.setForeground(new Color(255, 255, 0));
        new Thread(() -> {
            String apiKey = this.apiKeyField.getText().trim();
            String endpoint = this.apiEndpointField.getText().trim();
            String model = selectedModel.toString().trim();
            if (apiKey.isEmpty()) {
                SwingUtilities.invokeLater(() -> {
                    this.statusLabel.setText("\u72b6\u6001: API Key\u4e3a\u7a7a");
                    this.statusLabel.setForeground(new Color(255, 0, 0));
                    JOptionPane.showMessageDialog(this, "\u8bf7\u5148\u8f93\u5165API Key", "\u9519\u8bef", 0);
                });
                return;
            }
            if (endpoint.isEmpty()) {
                SwingUtilities.invokeLater(() -> {
                    this.statusLabel.setText("\u72b6\u6001: API\u7aef\u70b9\u4e3a\u7a7a");
                    this.statusLabel.setForeground(new Color(255, 0, 0));
                    JOptionPane.showMessageDialog(this, "\u8bf7\u5148\u8f93\u5165API\u7aef\u70b9", "\u9519\u8bef", 0);
                });
                return;
            }
            try {
                OkHttpClient client = new OkHttpClient.Builder().connectTimeout(15L, TimeUnit.SECONDS).readTimeout(15L, TimeUnit.SECONDS).build();
                String testJson = "{\"model\":\"" + model + "\",\"messages\":[{\"role\":\"user\",\"content\":\"test\"}],\"max_tokens\":5}";
                this.callbacks.printOutput("\u9a8c\u8bc1API - \u7aef\u70b9: " + endpoint);
                this.callbacks.printOutput("\u9a8c\u8bc1API - \u6a21\u578b: " + model);
                this.callbacks.printOutput("\u9a8c\u8bc1API - \u8bf7\u6c42: " + testJson);
                RequestBody body = RequestBody.create(MediaType.parse("application/json; charset=utf-8"), testJson);
                Request.Builder requestBuilder = new Request.Builder().url(endpoint).addHeader("Content-Type", "application/json; charset=utf-8").post(body);
                this.setupAuthHeader(requestBuilder, endpoint, apiKey);
                Request request = requestBuilder.build();
                this.callbacks.printOutput("\u9a8c\u8bc1API - \u8bf7\u6c42\u5934: " + request.headers().toString());
                try (Response response = client.newCall(request).execute()) {
                    String responseBody = "";
                    int responseCode = response.code();
                    if (response.body() != null) {
                        responseBody = new String(response.body().bytes(), StandardCharsets.UTF_8);
                    }
                    this.callbacks.printOutput("\u9a8c\u8bc1API - \u54cd\u5e94\u7801: " + responseCode);
                    this.callbacks.printOutput("\u9a8c\u8bc1API - \u54cd\u5e94\u4f53: " + responseBody);
                    String finalResponseBody = responseBody;
                    boolean finalSuccess = response.isSuccessful();
                    SwingUtilities.invokeLater(() -> {
                        if (finalSuccess) {
                            this.statusLabel.setText("\u72b6\u6001: API Key\u9a8c\u8bc1\u6210\u529f");
                            this.statusLabel.setForeground(TEXT_GREEN);
                            this.callbacks.printOutput("API Key\u9a8c\u8bc1\u6210\u529f");
                            JOptionPane.showMessageDialog(this, "API Key\u9a8c\u8bc1\u6210\u529f\uff01\n\n\u6a21\u578b: " + model + "\n\u54cd\u5e94\u7801: " + responseCode, "\u9a8c\u8bc1\u6210\u529f", 1);
                        } else {
                            this.statusLabel.setText("\u72b6\u6001: API Key\u9a8c\u8bc1\u5931\u8d25 (HTTP " + responseCode + ")");
                            this.statusLabel.setForeground(new Color(255, 0, 0));
                            this.callbacks.printError("API Key\u9a8c\u8bc1\u5931\u8d25: HTTP " + responseCode);
                            this.callbacks.printError("\u54cd\u5e94\u5185\u5bb9: " + finalResponseBody);
                            String errorMsg = "API Key\u9a8c\u8bc1\u5931\u8d25\uff01\n\n\u54cd\u5e94\u7801: HTTP " + responseCode + "\n\u7aef\u70b9: " + endpoint + "\n\u6a21\u578b: " + model;
                            if (finalResponseBody.length() > 0 && finalResponseBody.length() < 200) {
                                errorMsg = errorMsg + "\n\n\u9519\u8bef\u4fe1\u606f: " + finalResponseBody;
                            }
                            JOptionPane.showMessageDialog(this, errorMsg, "\u9a8c\u8bc1\u5931\u8d25", 0);
                        }
                    });
                }
            }
            catch (IOException e) {
                SwingUtilities.invokeLater(() -> {
                    this.statusLabel.setText("\u72b6\u6001: \u8fde\u63a5\u5931\u8d25 \u2717");
                    this.statusLabel.setForeground(new Color(255, 0, 0));
                    JOptionPane.showMessageDialog(this, "\u8fde\u63a5\u5931\u8d25\uff1a" + e.getMessage(), "\u9519\u8bef", 0);
                });
                this.callbacks.printError("API\u9a8c\u8bc1\u5f02\u5e38: " + e.getMessage());
            }
        }).start();
    }

    private void refreshAgents() {
        this.statusLabel.setText("\u72b6\u6001: \u6b63\u5728\u83b7\u53d6\u6a21\u578b\u5217\u8868...");
        this.statusLabel.setForeground(new Color(255, 255, 0));
        new Thread(() -> {
            String apiKey = this.apiKeyField.getText().trim();
            String modelsEndpoint = this.modelsEndpointField.getText().trim();
            this.callbacks.printOutput("\u83b7\u53d6\u6a21\u578b\u5217\u8868 - \u7aef\u70b9: " + modelsEndpoint);
            if (apiKey.isEmpty()) {
                SwingUtilities.invokeLater(() -> {
                    this.statusLabel.setText("\u72b6\u6001: \u8bf7\u5148\u8f93\u5165API Key \u2717");
                    this.statusLabel.setForeground(new Color(255, 0, 0));
                    JOptionPane.showMessageDialog(this, "\u8bf7\u5148\u8f93\u5165API Key", "\u9519\u8bef", 0);
                });
                return;
            }
            if (modelsEndpoint.isEmpty()) {
                SwingUtilities.invokeLater(() -> {
                    this.statusLabel.setText("\u72b6\u6001: \u8bf7\u5148\u8f93\u5165\u6a21\u578b\u7aef\u70b9 \u2717");
                    this.statusLabel.setForeground(new Color(255, 0, 0));
                    JOptionPane.showMessageDialog(this, "\u8bf7\u5148\u8f93\u5165\u6a21\u578b\u7aef\u70b9", "\u9519\u8bef", 0);
                });
                return;
            }
            try {
                OkHttpClient client = new OkHttpClient.Builder().connectTimeout(15L, TimeUnit.SECONDS).readTimeout(15L, TimeUnit.SECONDS).build();
                Request.Builder requestBuilder = new Request.Builder().url(modelsEndpoint).get();
                this.setupAuthHeader(requestBuilder, modelsEndpoint, apiKey);
                Request request = requestBuilder.build();
                try (Response response = client.newCall(request).execute()) {
                    String responseBody = "";
                    int responseCode = response.code();
                    if (response.body() != null) {
                        responseBody = new String(response.body().bytes(), StandardCharsets.UTF_8);
                    }
                    this.callbacks.printOutput("\u83b7\u53d6\u6a21\u578b - \u54cd\u5e94\u7801: " + responseCode);
                    this.callbacks.printOutput("\u83b7\u53d6\u6a21\u578b - \u54cd\u5e94\u4f53: " + responseBody);
                    if (response.isSuccessful()) {
                        int i;
                        JsonObject jsonResponse = JsonParser.parseString(responseBody).getAsJsonObject();
                        ArrayList<String> models = new ArrayList<String>();
                        if (jsonResponse.has("data")) {
                            JsonArray data = jsonResponse.getAsJsonArray("data");
                            for (i = 0; i < data.size(); ++i) {
                                JsonObject model = data.get(i).getAsJsonObject();
                                if (!model.has("id")) continue;
                                models.add(model.get("id").getAsString());
                            }
                        } else if (jsonResponse.has("models")) {
                            JsonArray modelsArray = jsonResponse.getAsJsonArray("models");
                            for (i = 0; i < modelsArray.size(); ++i) {
                                JsonObject model = modelsArray.get(i).getAsJsonObject();
                                if (model.has("name")) {
                                    models.add(model.get("name").getAsString());
                                    continue;
                                }
                                if (!model.has("id")) continue;
                                models.add(model.get("id").getAsString());
                            }
                        }
                        if (models.isEmpty()) {
                            models.add("gpt-4");
                            models.add("gpt-3.5-turbo");
                            this.callbacks.printOutput("\u672a\u80fd\u89e3\u6790\u6a21\u578b\u5217\u8868\uff0c\u4f7f\u7528\u9ed8\u8ba4\u6a21\u578b");
                        }
                        ConfigManager.Config config = ConfigManager.getInstance().getConfig();
                        config.setAvailableModels(models);
                        if (!models.isEmpty()) {
                            config.setSelectedAgent((String)models.get(0));
                        }
                        ConfigManager.getInstance().saveConfig();
                        ArrayList<String> finalModels = models;
                        SwingUtilities.invokeLater(() -> {
                            HashSet<String> existingModels = new HashSet<String>();
                            for (int j = 0; j < this.agentComboBox.getItemCount(); ++j) {
                                existingModels.add(this.agentComboBox.getItemAt(j));
                            }
                            int addedCount = 0;
                            for (String model : finalModels) {
                                if (existingModels.contains(model)) continue;
                                this.agentComboBox.addItem(model);
                                ++addedCount;
                            }
                            this.statusLabel.setText("\u72b6\u6001: \u83b7\u53d6\u5230 " + finalModels.size() + " \u4e2a\u6a21\u578b\uff0c\u65b0\u589e " + addedCount + " \u4e2a");
                            this.statusLabel.setForeground(TEXT_GREEN);
                            this.callbacks.printOutput("\u6210\u529f\u83b7\u53d6 " + finalModels.size() + " \u4e2a\u6a21\u578b\uff0c\u65b0\u589e " + addedCount + " \u4e2a");
                            JOptionPane.showMessageDialog(this, "\u6210\u529f\u83b7\u53d6 " + finalModels.size() + " \u4e2a\u6a21\u578b\uff01\n\u65b0\u589e " + addedCount + " \u4e2a\u5230\u5217\u8868", "\u83b7\u53d6\u6210\u529f", 1);
                        });
                    } else {
                        String errorBody = response.body() != null ? new String(response.body().bytes(), StandardCharsets.UTF_8) : "";
                        this.callbacks.printError("\u83b7\u53d6\u6a21\u578b\u5217\u8868\u5931\u8d25: HTTP " + responseCode + " - " + errorBody);
                        SwingUtilities.invokeLater(() -> {
                            this.statusLabel.setText("\u72b6\u6001: \u83b7\u53d6\u5931\u8d25 \u2717 (HTTP " + responseCode + ")");
                            this.statusLabel.setForeground(new Color(255, 0, 0));
                            JOptionPane.showMessageDialog(this, "\u83b7\u53d6\u6a21\u578b\u5217\u8868\u5931\u8d25\uff01\nHTTP " + responseCode, "\u83b7\u53d6\u5931\u8d25", 0);
                        });
                    }
                }
            }
            catch (Exception e) {
                this.callbacks.printError("\u83b7\u53d6\u6a21\u578b\u5217\u8868\u5f02\u5e38: " + e.getMessage());
                e.printStackTrace();
                SwingUtilities.invokeLater(() -> {
                    this.statusLabel.setText("\u72b6\u6001: \u83b7\u53d6\u5931\u8d25 \u2717");
                    this.statusLabel.setForeground(new Color(255, 0, 0));
                    JOptionPane.showMessageDialog(this, "\u83b7\u53d6\u5931\u8d25\uff1a" + e.getMessage(), "\u9519\u8bef", 0);
                });
            }
        }).start();
    }

    private void setupAuthHeader(Request.Builder requestBuilder, String endpoint, String apiKey) {
        String lowerEndpoint = endpoint.toLowerCase();
        if (lowerEndpoint.contains("anthropic.com")) {
            requestBuilder.addHeader("x-api-key", apiKey);
            requestBuilder.addHeader("anthropic-version", "2023-06-01");
            return;
        }
        if (lowerEndpoint.contains("googleapis.com") || lowerEndpoint.contains("generativelanguage.googleapis.com")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("openai.azure.com")) {
            requestBuilder.addHeader("api-key", apiKey);
            return;
        }
        if (lowerEndpoint.contains("cohere.ai") || lowerEndpoint.contains("cohere.com")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            requestBuilder.addHeader("Cohere-Version", "2022-12-06");
            return;
        }
        if (lowerEndpoint.contains("mistral.ai")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("huggingface.co") || lowerEndpoint.contains("hf.co")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("replicate.com")) {
            requestBuilder.addHeader("Authorization", "Token " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("together.xyz") || lowerEndpoint.contains("together.ai")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("perplexity.ai")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("deepseek.com")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("dashscope.aliyuncs.com")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("qianfan") || (lowerEndpoint.contains("baidu") && lowerEndpoint.contains("wenxin"))) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("bigmodel.cn")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("xfyun.cn") || lowerEndpoint.contains("spark")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("volcengine.com") || lowerEndpoint.contains("doubao")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("hunyuan") || (lowerEndpoint.contains("tencent") && lowerEndpoint.contains("cloud"))) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("moonshot.cn")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("baichuan-ai.com")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("minimax") || lowerEndpoint.contains("api.minimaxi.com")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("sensenova.cn") || lowerEndpoint.contains("sensetime")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("tiangong") || lowerEndpoint.contains("kunlun")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("01.ai") || lowerEndpoint.contains("lingyiwanwu")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("stepfun.com")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        if (lowerEndpoint.contains("modelbest.cn")) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
    }
}
