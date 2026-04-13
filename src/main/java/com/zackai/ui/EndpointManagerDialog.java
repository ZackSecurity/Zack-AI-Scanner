package com.zackai.ui;

import com.zackai.core.ConfigManager;
import com.zackai.model.AIProvider;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.awt.GridLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;

public class EndpointManagerDialog
extends JDialog {
    private JTable endpointTable;
    private DefaultTableModel tableModel;
    private ConfigManager.Config config = ConfigManager.getInstance().getConfig();
    private static final Color BG_BLACK = Color.WHITE;
    private static final Color TEXT_GREEN = new Color(33, 37, 41);
    private static final Color PANEL_DARK = new Color(245, 247, 250);
    private static final Color BORDER_GREEN = new Color(210, 214, 220);
    private static final Color INPUT_BG = Color.WHITE;

    public EndpointManagerDialog(Frame owner) {
        super(owner, "\u7aef\u70b9\u914d\u7f6e\u7ba1\u7406", true);
        this.initUI();
        this.loadEndpoints();
        this.setSize(900, 600);
        this.setLocationRelativeTo(owner);
    }

    private void initUI() {
        this.getContentPane().setBackground(BG_BLACK);
        this.setLayout(new BorderLayout(15, 15));
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBackground(BG_BLACK);
        mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        JLabel titleLabel = new JLabel("AI\u670d\u52a1\u5546\u7aef\u70b9\u914d\u7f6e\u7ba1\u7406", 0);
        titleLabel.setForeground(TEXT_GREEN);
        titleLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 20));
        mainPanel.add((Component)titleLabel, "North");
        Object[] columns = new String[]{"\u540d\u79f0", "API\u7aef\u70b9", "\u6a21\u578b\u7aef\u70b9", "\u8ba4\u8bc1\u65b9\u5f0f", "\u7c7b\u578b"};
        this.tableModel = new DefaultTableModel(columns, 0){

            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        this.endpointTable = new JTable(this.tableModel);
        this.endpointTable.setBackground(BG_BLACK);
        this.endpointTable.setForeground(TEXT_GREEN);
        this.endpointTable.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 12));
        this.endpointTable.setRowHeight(28);
        this.endpointTable.setGridColor(BORDER_GREEN);
        this.endpointTable.setSelectionBackground(new Color(225, 239, 255));
        this.endpointTable.setSelectionForeground(TEXT_GREEN);
        this.endpointTable.getTableHeader().setBackground(PANEL_DARK);
        this.endpointTable.getTableHeader().setForeground(TEXT_GREEN);
        this.endpointTable.getTableHeader().setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 13));
        this.endpointTable.getColumnModel().getColumn(0).setPreferredWidth(150);
        this.endpointTable.getColumnModel().getColumn(1).setPreferredWidth(350);
        this.endpointTable.getColumnModel().getColumn(2).setPreferredWidth(350);
        this.endpointTable.getColumnModel().getColumn(3).setPreferredWidth(100);
        this.endpointTable.getColumnModel().getColumn(4).setPreferredWidth(80);
        JScrollPane scrollPane = new JScrollPane(this.endpointTable);
        scrollPane.setBorder(BorderFactory.createLineBorder(BORDER_GREEN, 2));
        mainPanel.add((Component)scrollPane, "Center");
        JPanel buttonPanel = new JPanel(new FlowLayout(1, 15, 10));
        buttonPanel.setBackground(BG_BLACK);
        JButton addButton = this.createButton("\u65b0\u589e\u7aef\u70b9");
        addButton.addActionListener(e -> this.addEndpoint());
        buttonPanel.add(addButton);
        JButton editButton = this.createButton("\u7f16\u8f91\u7aef\u70b9");
        editButton.addActionListener(e -> this.editEndpoint());
        buttonPanel.add(editButton);
        JButton deleteButton = this.createButton("\u5220\u9664\u7aef\u70b9");
        deleteButton.addActionListener(e -> this.deleteEndpoint());
        buttonPanel.add(deleteButton);
        JButton resetButton = this.createButton("\u6062\u590d\u9ed8\u8ba4");
        resetButton.addActionListener(e -> this.resetToDefault());
        buttonPanel.add(resetButton);
        JButton closeButton = this.createButton("\u5173\u95ed");
        closeButton.addActionListener(e -> this.dispose());
        buttonPanel.add(closeButton);
        mainPanel.add((Component)buttonPanel, "South");
        this.add(mainPanel);
    }

    private JButton createButton(String text) {
        final JButton button = new JButton(text);
        button.setBackground(PANEL_DARK);
        button.setForeground(TEXT_GREEN);
        button.setBorder(BorderFactory.createLineBorder(BORDER_GREEN, 2));
        button.setFocusPainted(false);
        button.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 13));
        button.setCursor(new Cursor(12));
        button.setPreferredSize(new Dimension(100, 35));
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

    private void loadEndpoints() {
        this.tableModel.setRowCount(0);
        List<AIProvider> allProviders = this.config.getAllProviders();
        for (AIProvider provider : allProviders) {
            this.tableModel.addRow(new Object[]{provider.getName(), provider.getApiEndpoint(), provider.getModelsEndpoint(), provider.getAuthType(), provider.isCustom() ? "\u81ea\u5b9a\u4e49" : "\u5185\u7f6e"});
        }
    }

    private void addEndpoint() {
        AIProvider newProvider = this.showEndpointDialog(null);
        if (newProvider != null) {
            newProvider.setCustom(true);
            this.config.getCustomProviders().add(newProvider);
            ConfigManager.getInstance().saveConfig();
            this.loadEndpoints();
        }
    }

    private void editEndpoint() {
        AIProvider updated;
        int selectedRow = this.endpointTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this, "\u8bf7\u5148\u9009\u62e9\u8981\u7f16\u8f91\u7684\u7aef\u70b9");
            return;
        }
        String name = (String)this.tableModel.getValueAt(selectedRow, 0);
        String type = (String)this.tableModel.getValueAt(selectedRow, 4);
        AIProvider provider = this.findProviderByName(name);
        if (provider != null && (updated = this.showEndpointDialog(provider, type.equals("\u5185\u7f6e"))) != null) {
            if (type.equals("\u5185\u7f6e")) {
                updated.setName(updated.getName() + " (Custom)");
                updated.setCustom(true);
                this.config.getCustomProviders().add(updated);
            } else {
                provider.setName(updated.getName());
                provider.setApiEndpoint(updated.getApiEndpoint());
                provider.setModelsEndpoint(updated.getModelsEndpoint());
                provider.setAuthType(updated.getAuthType());
            }
            ConfigManager.getInstance().saveConfig();
            this.loadEndpoints();
        }
    }

    private void deleteEndpoint() {
        int selectedRow = this.endpointTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this, "\u8bf7\u5148\u9009\u62e9\u8981\u5220\u9664\u7684\u7aef\u70b9");
            return;
        }
        String type = (String)this.tableModel.getValueAt(selectedRow, 4);
        if (type.equals("\u5185\u7f6e")) {
            JOptionPane.showMessageDialog(this, "\u5185\u7f6e\u7aef\u70b9\u4e0d\u53ef\u5220\u9664");
            return;
        }
        String name = (String)this.tableModel.getValueAt(selectedRow, 0);
        AIProvider provider = this.findProviderByName(name);
        if (provider != null && JOptionPane.showConfirmDialog(this, "\u786e\u5b9a\u8981\u5220\u9664\u7aef\u70b9 \"" + name + "\" \u5417\uff1f", "\u786e\u8ba4\u5220\u9664", 0) == 0) {
            this.config.getCustomProviders().remove(provider);
            ConfigManager.getInstance().saveConfig();
            this.loadEndpoints();
        }
    }

    private void resetToDefault() {
        if (JOptionPane.showConfirmDialog(this, "\u786e\u5b9a\u8981\u6e05\u7a7a\u6240\u6709\u81ea\u5b9a\u4e49\u7aef\u70b9\u5417\uff1f\n\u5185\u7f6e\u7aef\u70b9\u4e0d\u53d7\u5f71\u54cd\u3002", "\u786e\u8ba4\u91cd\u7f6e", 0) == 0) {
            this.config.getCustomProviders().clear();
            ConfigManager.getInstance().saveConfig();
            this.loadEndpoints();
        }
    }

    private AIProvider findProviderByName(String name) {
        for (AIProvider provider : this.config.getAllProviders()) {
            if (!provider.getName().equals(name)) continue;
            return provider;
        }
        return null;
    }

    private AIProvider showEndpointDialog(AIProvider existing, boolean isBuiltIn) {
        JDialog dialog = new JDialog(this, existing == null ? "\u65b0\u589e\u7aef\u70b9" : (isBuiltIn ? "\u7f16\u8f91\u5185\u7f6e\u7aef\u70b9\uff08\u5c06\u4fdd\u5b58\u4e3a\u81ea\u5b9a\u4e49\uff09" : "\u7f16\u8f91\u7aef\u70b9"), true);
        dialog.setLayout(new BorderLayout(15, 15));
        dialog.getContentPane().setBackground(BG_BLACK);
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBackground(BG_BLACK);
        mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        JPanel formPanel = new JPanel(new GridLayout(4, 2, 10, 15));
        formPanel.setBackground(BG_BLACK);
        JTextField nameField = this.createStyledTextField(existing != null ? existing.getName() : "");
        JTextField apiField = this.createStyledTextField(existing != null ? existing.getApiEndpoint() : "");
        JTextField modelsField = this.createStyledTextField(existing != null ? existing.getModelsEndpoint() : "");
        JComboBox<String> authCombo = new JComboBox<String>(new String[]{"bearer", "x-api-key", "api-key"});
        authCombo.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        authCombo.setBackground(INPUT_BG);
        authCombo.setForeground(TEXT_GREEN);
        authCombo.setBorder(BorderFactory.createLineBorder(BORDER_GREEN));
        if (existing != null) {
            authCombo.setSelectedItem(existing.getAuthType());
        }
        formPanel.add(this.createLabel("\u540d\u79f0:"));
        formPanel.add(nameField);
        formPanel.add(this.createLabel("API\u7aef\u70b9:"));
        formPanel.add(apiField);
        formPanel.add(this.createLabel("\u6a21\u578b\u7aef\u70b9:"));
        formPanel.add(modelsField);
        formPanel.add(this.createLabel("\u8ba4\u8bc1\u65b9\u5f0f:"));
        formPanel.add(authCombo);
        mainPanel.add((Component)formPanel, "Center");
        JPanel buttonPanel = new JPanel(new FlowLayout(1, 20, 10));
        buttonPanel.setBackground(BG_BLACK);
        boolean[] confirmed = new boolean[]{false};
        JButton okButton = this.createButton("\u786e\u5b9a");
        okButton.addActionListener(e -> {
            confirmed[0] = true;
            dialog.dispose();
        });
        buttonPanel.add(okButton);
        JButton cancelButton = this.createButton("\u53d6\u6d88");
        cancelButton.addActionListener(e -> dialog.dispose());
        buttonPanel.add(cancelButton);
        mainPanel.add((Component)buttonPanel, "South");
        dialog.add(mainPanel);
        dialog.setSize(700, 400);
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
        if (confirmed[0]) {
            String name = nameField.getText().trim();
            String api = apiField.getText().trim();
            String models = modelsField.getText().trim();
            String auth = (String)authCombo.getSelectedItem();
            if (name.isEmpty() || api.isEmpty() || models.isEmpty()) {
                JOptionPane.showMessageDialog(this, "\u6240\u6709\u5b57\u6bb5\u90fd\u5fc5\u987b\u586b\u5199", "\u9519\u8bef", 0);
                return null;
            }
            return new AIProvider(name, api, models, auth, true);
        }
        return null;
    }

    private AIProvider showEndpointDialog(AIProvider existing) {
        return this.showEndpointDialog(existing, false);
    }

    private JTextField createStyledTextField(String text) {
        JTextField field = new JTextField(text, 30);
        field.setBackground(INPUT_BG);
        field.setForeground(TEXT_GREEN);
        field.setCaretColor(TEXT_GREEN);
        field.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        field.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER_GREEN), BorderFactory.createEmptyBorder(5, 8, 5, 8)));
        return field;
    }

    private JLabel createLabel(String text) {
        JLabel label = new JLabel(text);
        label.setForeground(TEXT_GREEN);
        label.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        return label;
    }
}
