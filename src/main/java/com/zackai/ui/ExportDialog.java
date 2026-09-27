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
import com.zackai.i18n.Msg;
import com.zackai.model.ScanTask;
import com.zackai.model.VulnResult;
import com.zackai.util.ReportGenerator;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.awt.GridLayout;
import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JComboBox;
import javax.swing.JList;
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

    /**
     * 「全部等级 / 全部类型」两个哨兵。它们是**数据**（下拉里装的值、{@code doExport} 比较的对象），
     * 文案由渲染器翻 —— 以前直接拿「全部等级」这个中文字面量做比较，界面一换语言，
     * 每个任务都会被判成「命中筛选」，导出范围静默失真。
     */
    private static final String ALL_LEVELS = "__all_levels__";
    private static final String ALL_TYPES = "__all_types__";

    /** 等级下拉项的显示文案；认不出来原样返回，别把值吞掉 */
    private static String levelFilterText(String value) {
        if (ALL_LEVELS.equals(value)) {
            return Msg.t("filter.allLevels");
        }
        try {
            return Msg.levelName(ScanTask.VulnLevel.valueOf(value));
        } catch (IllegalArgumentException e) {
            return value;
        }
    }
    private JRadioButton htmlFormatRadio;
    private JRadioButton mdFormatRadio;
    private List<ScanTask> allTasks;
    /**
     * 勾选的任务（可能多个）。原来是单个 {@code selectedTask}，只取勾选集里的第一个 ——
     * 勾了三个只导出一个，而且导出的是哪个还得看勾选顺序。
     */
    private List<ScanTask> selectedTasks;
    private LogPanel logPanel;
    private IBurpExtenderCallbacks callbacks;
    private static final Color BG_WHITE = Color.WHITE;
    private static final Color TEXT_DARK = new Color(33, 37, 41);
    private static final Color PANEL_LIGHT = new Color(245, 247, 250);
    private static final Color BORDER_GRAY = new Color(210, 214, 220);

    public ExportDialog(Frame owner, IBurpExtenderCallbacks callbacks, List<ScanTask> allTasks, List<ScanTask> selectedTasks, LogPanel logPanel) {
        super(owner, Msg.t("export.title"), true);
        this.callbacks = callbacks;
        this.allTasks = allTasks;
        this.selectedTasks = selectedTasks;
        this.logPanel = logPanel;
        this.initUI();
        this.setSize(750, 600);
        this.setLocationRelativeTo(owner);
    }

    private void initUI() {
        this.getContentPane().setBackground(BG_WHITE);
        this.setLayout(new BorderLayout(15, 15));
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBackground(BG_WHITE);
        mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        JLabel titleLabel = new JLabel(Msg.t("export.heading"), 0);
        titleLabel.setForeground(TEXT_DARK);
        titleLabel.setFont(new Font("微软雅黑", 1, 18));
        mainPanel.add((Component)titleLabel, "North");
        JPanel optionsPanel = new JPanel(new GridLayout(4, 1, 10, 15));
        optionsPanel.setBackground(BG_WHITE);
        JPanel rangePanel = this.createOptionPanel(Msg.t("export.range"));
        ButtonGroup rangeGroup = new ButtonGroup();
        this.selectedTaskRadio = this.createRadioButton(
                this.selectedTasks != null && this.selectedTasks.size() > 1
                        ? Msg.t("export.rangeSelectedN", this.selectedTasks.size())
                        : Msg.t("export.rangeSelected"));
        this.allTasksRadio = this.createRadioButton(Msg.t("export.rangeAll"));
        rangeGroup.add(this.selectedTaskRadio);
        rangeGroup.add(this.allTasksRadio);
        if (this.selectedTasks != null && !this.selectedTasks.isEmpty()) {
            this.selectedTaskRadio.setSelected(true);
        } else {
            // 没有勾选任务时只能导出全部（两条分支原本代码完全相同）
            this.allTasksRadio.setSelected(true);
            this.selectedTaskRadio.setEnabled(false);
        }
        JPanel rangeButtonPanel = new JPanel(new FlowLayout(0, 20, 5));
        rangeButtonPanel.setBackground(PANEL_LIGHT);
        rangeButtonPanel.add(this.selectedTaskRadio);
        rangeButtonPanel.add(this.allTasksRadio);
        rangePanel.add(rangeButtonPanel);
        optionsPanel.add(rangePanel);
        JPanel levelPanel = this.createOptionPanel(Msg.t("export.levelFilter"));
        // 下拉里装的是等级枚举名（数据），显示由渲染器翻 —— 见 ALL_LEVELS 的注释
        this.levelFilterCombo = this.createStyledComboBox(
                new String[]{ALL_LEVELS, "CRITICAL", "HIGH", "MEDIUM", "LOW"});
        this.levelFilterCombo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                this.setText(levelFilterText(String.valueOf(value)));
                return this;
            }
        });
        levelPanel.add(this.levelFilterCombo);
        optionsPanel.add(levelPanel);
        JPanel vulnTypePanel = this.createOptionPanel(Msg.t("export.typeFilter"));
        // LinkedHashSet：既去重又保序 —— HashSet 的顺序是任意的，而 JComboBox 默认选中 index 0，
        // 于是对话框一打开就"预先筛"成了某个随机漏洞类型，用户直接点导出只会导出那一个类型
        LinkedHashSet<String> vulnTypes = new LinkedHashSet<String>();
        vulnTypes.add(ALL_TYPES);
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
        // 类型名是数据（VulnResult.vulnName，中文），只在显示时翻
        this.vulnTypeFilterCombo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                String raw = String.valueOf(value);
                this.setText(ALL_TYPES.equals(raw) ? Msg.t("filter.allTypes") : Msg.typeNameOf(raw));
                return this;
            }
        });
        this.vulnTypeFilterCombo.setSelectedItem(ALL_TYPES);
        this.levelFilterCombo.setSelectedItem(ALL_LEVELS);
        vulnTypePanel.add(this.vulnTypeFilterCombo);
        optionsPanel.add(vulnTypePanel);
        JPanel formatPanel = this.createOptionPanel(Msg.t("export.format"));
        ButtonGroup formatGroup = new ButtonGroup();
        this.htmlFormatRadio = this.createRadioButton(Msg.t("export.formatHtml"));
        this.mdFormatRadio = this.createRadioButton(Msg.t("export.formatMd"));
        formatGroup.add(this.htmlFormatRadio);
        formatGroup.add(this.mdFormatRadio);
        this.htmlFormatRadio.setSelected(true);
        JPanel formatButtonPanel = new JPanel(new FlowLayout(0, 20, 5));
        formatButtonPanel.setBackground(PANEL_LIGHT);
        formatButtonPanel.add(this.htmlFormatRadio);
        formatButtonPanel.add(this.mdFormatRadio);
        formatPanel.add(formatButtonPanel);
        optionsPanel.add(formatPanel);
        mainPanel.add((Component)optionsPanel, "Center");
        JPanel buttonPanel = new JPanel(new FlowLayout(1, 20, 10));
        buttonPanel.setBackground(BG_WHITE);
        JButton exportButton = this.createButton(Msg.t("btn.startExport"));
        exportButton.addActionListener(e -> this.doExport());
        buttonPanel.add(exportButton);
        JButton cancelButton = this.createButton(Msg.t("btn.cancel"));
        cancelButton.addActionListener(e -> this.dispose());
        buttonPanel.add(cancelButton);
        mainPanel.add((Component)buttonPanel, "South");
        this.add(mainPanel);
    }

    private JPanel createOptionPanel(String title) {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBackground(PANEL_LIGHT);
        panel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER_GRAY, 2), BorderFactory.createEmptyBorder(15, 20, 15, 20)));
        JLabel titleLabel = new JLabel(title);
        titleLabel.setForeground(TEXT_DARK);
        titleLabel.setFont(new Font("微软雅黑", 1, 15));
        panel.add((Component)titleLabel, "North");
        return panel;
    }

    private JRadioButton createRadioButton(String text) {
        JRadioButton radio = new JRadioButton(text);
        radio.setBackground(PANEL_LIGHT);
        radio.setForeground(TEXT_DARK);
        radio.setFont(new Font("微软雅黑", 0, 14));
        radio.setFocusPainted(false);
        return radio;
    }

    private JComboBox<String> createStyledComboBox(String[] items) {
        return UiKit.comboBox(items, 300, 35, 14);
    }

    private JButton createButton(String text) {
        return UiKit.button(text, 120, 40, 14);
    }

    /**
     * 按导出范围与筛选条件算出要导出的任务集合。
     *
     * <p>抽成**静态**方法是为了能被离线 harness 直接验证：{@link ExportDialog} 是模态 {@code JDialog}，
     * headless 环境构造不出来，而「勾选多个只导出一个」这个 bug 恰恰就出在这段判定里 ——
     * 修好之前它没有任何自动化覆盖。
     *
     * @param selectedScope 是否「导出选中任务」；true 时返回 {@code selectedTasks} 的全部（不是第一个）
     */
    static List<ScanTask> collectTasksToExport(boolean selectedScope, List<ScanTask> selectedTasks,
                                               List<ScanTask> allTasks, String levelFilter, String vulnTypeFilter) {
        List<ScanTask> tasksToExport = new ArrayList<ScanTask>();
        if (selectedScope && selectedTasks != null && !selectedTasks.isEmpty()) {
            // 勾选了几个就导出几个（多任务走「选目录 + 逐个生成文件名」那条分支）
            tasksToExport.addAll(selectedTasks);
            return tasksToExport;
        }
        if (allTasks == null) {
            return tasksToExport;
        }
        for (ScanTask task : allTasks) {
            List<VulnResult> vulns = task.getVulnerabilities();
            // 比的是枚举名与哨兵常量，**不是显示文案** —— 拿「全部等级」这类文案比较的话，
            // 界面一换语言筛选就静默失效（所有任务都被当成命中）
            if (!ALL_LEVELS.equals(levelFilter) && !task.getVulnLevel().name().equals(levelFilter)) continue;
            if (!ALL_TYPES.equals(vulnTypeFilter)) {
                if (vulns == null || vulns.isEmpty()) continue;
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
        return tasksToExport;
    }

    private void doExport() {
        List<ScanTask> tasksToExport = collectTasksToExport(
                this.selectedTaskRadio.isSelected(), this.selectedTasks, this.allTasks,
                (String)this.levelFilterCombo.getSelectedItem(),
                (String)this.vulnTypeFilterCombo.getSelectedItem());
        if (tasksToExport.isEmpty()) {
            JOptionPane.showMessageDialog(this, Msg.t("msg.noTasksToExport"), Msg.t("dlg.hint"), 1);
            return;
        }
        JFileChooser fileChooser = new JFileChooser();
        if (tasksToExport.size() == 1) {
            String ext = this.htmlFormatRadio.isSelected() ? ".html" : ".md";
            ScanTask task = (ScanTask)tasksToExport.get(0);
            String filename = reportFileName(task, ext);
            fileChooser.setSelectedFile(new File(filename));
            fileChooser.setDialogTitle(Msg.t("dlg.saveReport"));
        } else {
            fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            fileChooser.setDialogTitle(Msg.t("dlg.chooseDir"));
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
        int failCount = 0;
        String lastError = null;
        for (ScanTask task : tasks) {
            try {
                File outputFile;
                if (tasks.size() == 1) {
                    outputFile = target;
                } else {
                    String ext = isHtml ? ".html" : ".md";
                    outputFile = new File(target, reportFileName(task, ext));
                }
                if (isHtml) {
                    ReportGenerator.generateReport(task, outputFile.getAbsolutePath());
                } else {
                    ReportGenerator.generateMarkdownReport(task, outputFile.getAbsolutePath());
                }
                ++successCount;
                this.logPanel.logSuccess(Msg.t("msg.exporting", successCount, tasks.size(), outputFile.getName()));
            }
            catch (Exception e) {
                ++failCount;
                lastError = e.getClass().getSimpleName() + (e.getMessage() != null ? ": " + e.getMessage() : "");
                this.callbacks.printError(Msg.t("msg.exportErrorPrint", target.getAbsolutePath(), lastError));
                this.logPanel.logError(Msg.t("msg.exportErrorLog", target.getName()));
            }
        }
        // 完成提示必须反映真实结果：以前无论成败都弹「导出成功」，单任务分支还完全忽略计数 ——
        // 导出到只读目录失败后，紧接着就是一个「报告已导出到…」的对话框
        final int okCount = successCount;
        final int badCount = failCount;
        final String reason = lastError;
        SwingUtilities.invokeLater(() -> {
            if (badCount == 0) {
                String message = tasks.size() == 1
                        ? Msg.t("msg.reportExported", target.getAbsolutePath())
                        : Msg.t("msg.reportsExported", okCount, target.getAbsolutePath());
                JOptionPane.showMessageDialog(null, message, Msg.t("dlg.exportSuccess"), 1);
                this.logPanel.logSuccess(Msg.t("msg.batchExported", okCount));
                return;
            }
            String message = Msg.t("msg.exportPartial", okCount, badCount)
                    + (reason != null ? Msg.t("msg.lastError", reason) : "")
                    + Msg.t("msg.targetPath", target.getAbsolutePath());
            JOptionPane.showMessageDialog(null, message, okCount == 0 ? Msg.t("dlg.exportFailed") : Msg.t("dlg.exportPartlyFailed"), 0);
            this.logPanel.logError(Msg.t("msg.exportDone", okCount, badCount));
        });
    }

    /** 报告文件名（单任务导出与批量导出共用一份格式，别再各写一遍） */
    private String reportFileName(ScanTask task, String ext) {
        return String.format("Zack-AI-Scanner-Report-%d-%s%s", task.getId(), this.extractDomain(task.getUrl()), ext);
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
                return domain.replaceAll("[^a-zA-Z0-9.\\-]", "_");
            }
        }
        catch (Exception exception) {
            System.err.println("extractDomain failed: " + exception.getMessage());
        }
        return "unknown";
    }
}
