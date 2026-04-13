package com.zackai.ui;

import com.zackai.model.ScanTask;
import com.zackai.model.VulnResult;
import com.zackai.util.ReportGenerator;
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
import java.io.File;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.SwingUtilities;

public class ExportDialog
extends JDialog {
    private JRadioButton selectedTaskRadio;
    private JRadioButton allTasksRadio;
    private JComboBox<String> levelFilterCombo;
    private JComboBox<String> vulnTypeFilterCombo;
    private JRadioButton htmlFormatRadio;
    private JRadioButton mdFormatRadio;
    private List<ScanTask> allTasks;
    private ScanTask selectedTask;
    private LogPanel logPanel;
    private static final Color BG_BLACK = Color.WHITE;
    private static final Color TEXT_GREEN = new Color(33, 37, 41);
    private static final Color PANEL_DARK = new Color(245, 247, 250);
    private static final Color BORDER_GREEN = new Color(210, 214, 220);
    private static final Color INPUT_BG = Color.WHITE;

    public ExportDialog(Frame owner, List<ScanTask> allTasks, ScanTask selectedTask, LogPanel logPanel) {
        super(owner, "导出报告配置", true);
        this.allTasks = allTasks;
        this.selectedTask = selectedTask;
        this.logPanel = logPanel;
        this.initUI();
        this.setSize(750, 600);
        this.setLocationRelativeTo(owner);
    }

    private void initUI() {
        this.getContentPane().setBackground(BG_BLACK);
        this.setLayout(new BorderLayout(15, 15));
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBackground(BG_BLACK);
        mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        JLabel titleLabel = new JLabel("配置导出选项", 0);
        titleLabel.setForeground(TEXT_GREEN);
        titleLabel.setFont(new Font("微软雅黑", 1, 18));
        mainPanel.add((Component)titleLabel, "North");
        JPanel optionsPanel = new JPanel(new GridLayout(4, 1, 10, 15));
        optionsPanel.setBackground(BG_BLACK);
        JPanel rangePanel = this.createOptionPanel("导出范围");
        ButtonGroup rangeGroup = new ButtonGroup();
        this.selectedTaskRadio = this.createRadioButton("导出选中任务");
        this.allTasksRadio = this.createRadioButton("导出全部任务");
        rangeGroup.add(this.selectedTaskRadio);
        rangeGroup.add(this.allTasksRadio);
        if (this.selectedTask != null) {
            this.selectedTaskRadio.setSelected(true);
        } else if (this.allTasks != null && !this.allTasks.isEmpty()) {
            this.allTasksRadio.setSelected(true);
            this.selectedTaskRadio.setEnabled(false);
        } else {
            this.allTasksRadio.setSelected(true);
            this.selectedTaskRadio.setEnabled(false);
        }
        JPanel rangeButtonPanel = new JPanel(new FlowLayout(0, 20, 5));
        rangeButtonPanel.setBackground(PANEL_DARK);
        rangeButtonPanel.add(this.selectedTaskRadio);
        rangeButtonPanel.add(this.allTasksRadio);
        rangePanel.add(rangeButtonPanel);
        optionsPanel.add(rangePanel);
        JPanel levelPanel = this.createOptionPanel("危险等级筛选");
        this.levelFilterCombo = this.createStyledComboBox(new String[]{"全部等级", "严重", "高危", "中危", "低危"});
        levelPanel.add(this.levelFilterCombo);
        optionsPanel.add(levelPanel);
        JPanel vulnTypePanel = this.createOptionPanel("漏洞类型筛选");
        HashSet<String> vulnTypes = new HashSet<String>();
        vulnTypes.add("全部类型");
        for (ScanTask task : this.allTasks) {
            if (task == null) continue;
            List<VulnResult> vulns = task.getVulnerabilities();
            if (vulns == null) continue;
            for (VulnResult vuln : vulns) {
                if (vuln == null) continue;
                vulnTypes.add(vuln.getVulnName());
            }
        }
        this.vulnTypeFilterCombo = this.createStyledComboBox(vulnTypes.toArray(new String[0]));
        vulnTypePanel.add(this.vulnTypeFilterCombo);
        optionsPanel.add(vulnTypePanel);
        JPanel formatPanel = this.createOptionPanel("导出格式");
        ButtonGroup formatGroup = new ButtonGroup();
        this.htmlFormatRadio = this.createRadioButton("HTML格式");
        this.mdFormatRadio = this.createRadioButton("Markdown格式");
        formatGroup.add(this.htmlFormatRadio);
        formatGroup.add(this.mdFormatRadio);
        this.htmlFormatRadio.setSelected(true);
        JPanel formatButtonPanel = new JPanel(new FlowLayout(0, 20, 5));
        formatButtonPanel.setBackground(PANEL_DARK);
        formatButtonPanel.add(this.htmlFormatRadio);
        formatButtonPanel.add(this.mdFormatRadio);
        formatPanel.add(formatButtonPanel);
        optionsPanel.add(formatPanel);
        mainPanel.add((Component)optionsPanel, "Center");
        JPanel buttonPanel = new JPanel(new FlowLayout(1, 20, 10));
        buttonPanel.setBackground(BG_BLACK);
        JButton exportButton = this.createButton("开始导出");
        exportButton.addActionListener(e -> this.doExport());
        buttonPanel.add(exportButton);
        JButton cancelButton = this.createButton("取消");
        cancelButton.addActionListener(e -> this.dispose());
        buttonPanel.add(cancelButton);
        mainPanel.add((Component)buttonPanel, "South");
        this.add(mainPanel);
    }

    private JPanel createOptionPanel(String title) {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBackground(PANEL_DARK);
        panel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER_GREEN, 2), BorderFactory.createEmptyBorder(15, 20, 15, 20)));
        JLabel titleLabel = new JLabel(title);
        titleLabel.setForeground(TEXT_GREEN);
        titleLabel.setFont(new Font("微软雅黑", 1, 15));
        panel.add((Component)titleLabel, "North");
        return panel;
    }

    private JRadioButton createRadioButton(String text) {
        JRadioButton radio = new JRadioButton(text);
        radio.setBackground(PANEL_DARK);
        radio.setForeground(TEXT_GREEN);
        radio.setFont(new Font("微软雅黑", 0, 14));
        radio.setFocusPainted(false);
        return radio;
    }

    private JComboBox<String> createStyledComboBox(String[] items) {
        JComboBox<String> combo = new JComboBox<String>(items);
        combo.setBackground(INPUT_BG);
        combo.setForeground(TEXT_GREEN);
        combo.setFont(new Font("微软雅黑", 0, 14));
        combo.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER_GREEN, 2), BorderFactory.createEmptyBorder(5, 8, 5, 8)));
        combo.setPreferredSize(new Dimension(300, 35));
        return combo;
    }

    private JButton createButton(String text) {
        final JButton button = new JButton(text);
        button.setBackground(PANEL_DARK);
        button.setForeground(TEXT_GREEN);
        button.setBorder(BorderFactory.createLineBorder(BORDER_GREEN, 2));
        button.setFocusPainted(false);
        button.setFont(new Font("微软雅黑", 1, 14));
        button.setCursor(new Cursor(12));
        button.setPreferredSize(new Dimension(120, 40));
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

    private void doExport() {
        ArrayList<ScanTask> tasksToExport = new ArrayList<ScanTask>();
        if (this.selectedTaskRadio.isSelected() && this.selectedTask != null) {
            tasksToExport.add(this.selectedTask);
        } else {
            String levelFilter = (String)this.levelFilterCombo.getSelectedItem();
            String vulnTypeFilter = (String)this.vulnTypeFilterCombo.getSelectedItem();
            for (ScanTask task : this.allTasks) {
                List<VulnResult> vulns = task.getVulnerabilities();
                if (vulns == null || vulns.isEmpty()) continue;
                if (!levelFilter.equals("全部等级") && !task.getVulnLevel().getDisplayName().equals(levelFilter)) continue;
                if (!vulnTypeFilter.equals("全部类型")) {
                    boolean hasType = false;
                    for (VulnResult vuln : vulns) {
                        if (vuln == null || !vuln.getVulnName().equals(vulnTypeFilter)) continue;
                        hasType = true;
                        break;
                    }
                    if (!hasType) continue;
                }
                tasksToExport.add(task);
            }
        }
        if (tasksToExport.isEmpty()) {
            JOptionPane.showMessageDialog(this, "没有符合筛选条件的任务可以导出", "提示", 1);
            return;
        }
        JFileChooser fileChooser = new JFileChooser();
        if (tasksToExport.size() == 1) {
            String ext = this.htmlFormatRadio.isSelected() ? ".html" : ".md";
            ScanTask task = (ScanTask)tasksToExport.get(0);
            String filename = String.format("Zack-AI-Scanner-Report-%d-%s%s", task.getId(), this.extractDomain(task.getUrl()), ext);
            fileChooser.setSelectedFile(new File(filename));
            fileChooser.setDialogTitle("保存报告");
        } else {
            fileChooser.setFileSelectionMode(1);
            fileChooser.setDialogTitle("选择报告保存目录");
        }
        if (fileChooser.showSaveDialog(this) == 0) {
            this.dispose();
            File target = fileChooser.getSelectedFile();
            boolean isHtml = this.htmlFormatRadio.isSelected();
            new Thread(() -> this.exportReports(tasksToExport, target, isHtml)).start();
        }
    }

    private void exportReports(List<ScanTask> tasks, File target, boolean isHtml) {
        int successCount = 0;
        for (ScanTask task : tasks) {
            try {
                File outputFile;
                if (tasks.size() == 1) {
                    outputFile = target;
                } else {
                    String ext = isHtml ? ".html" : ".md";
                    String filename = String.format("Zack-AI-Scanner-Report-%d-%s%s", task.getId(), this.extractDomain(task.getUrl()), ext);
                    outputFile = new File(target, filename);
                }
                if (isHtml) {
                    ReportGenerator.generateReport(task, outputFile.getAbsolutePath());
                } else {
                    ReportGenerator.generateMarkdownReport(task, outputFile.getAbsolutePath());
                }
                this.logPanel.logSuccess("导出报告 " + ++successCount + "/" + tasks.size() + ": " + outputFile.getName());
            }
            catch (Exception e) {
                this.logPanel.logError("导出失败: " + e.getMessage());
            }
        }
        int count = successCount;
        SwingUtilities.invokeLater(() -> {
            String message = tasks.size() == 1 ? "报告已导出到:\n" + target.getAbsolutePath() : "成功导出 " + count + " 个报告到:\n" + target.getAbsolutePath();
            JOptionPane.showMessageDialog(null, message, "导出成功", 1);
            this.logPanel.logSuccess("批量导出成功: " + count + " 个报告");
        });
    }

    private String extractDomain(String url) {
        try {
            if (url.contains("://")) {
                String domain = url.split("://")[1];
                if (domain.contains("/")) {
                    domain = domain.split("/")[0];
                }
                if (domain.contains(":")) {
                    domain = domain.split(":")[0];
                }
                return domain.replaceAll("[^a-zA-Z0-9.-]", "_");
            }
        }
        catch (Exception exception) {
            System.err.println("extractDomain failed: " + exception.getMessage());
        }
        return "unknown";
    }
}
