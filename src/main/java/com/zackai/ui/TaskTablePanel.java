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

import com.zackai.i18n.Msg;
import com.zackai.model.ScanTask;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Insets;
import java.awt.Frame;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.DefaultCellEditor;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JList;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableCellRenderer;

public class TaskTablePanel
extends JPanel {
    private MainPanel mainPanel;
    private LogPanel logPanel;
    private JTable taskTable;
    private DefaultTableModel tableModel;
    private Map<Integer, Integer> taskRowMap;
    /**
     * 每行「上次真正写进模型的是哪串值」（taskId → 签名），见 {@link #updateRow} 的跳过判断。
     * 重建行（{@link #filterTasks} / {@link #addTask} / {@link #removeTask}）时必须清掉对应条目：
     * 重建用的是不含排队位次的状态文案，留着旧签名会让那一行一直停在旧文案上。
     */
    private final Map<Integer, String> renderedRows = new HashMap<Integer, String>();
    private JTextField searchField;
    private JComboBox<TaskFilter> filterComboBox;
    private static final Color BG_WHITE = Color.WHITE;
    private static final Color TEXT_DARK = new Color(33, 37, 41);
    private static final Color PANEL_LIGHT = new Color(245, 247, 250);
    private static final Color BORDER_GRAY = new Color(210, 214, 220);
    private static final Color ROW_SELECTED = new Color(225, 239, 255);
    private static final Color RED = new Color(255, 0, 0);
    private static final Color INPUT_BG = Color.WHITE;
    // \u5217\u4e0b\u6807\u4e00\u5f8b\u8d70\u5e38\u91cf\uff1a\u52fe\u9009\u6846\u63d2\u5230\u6700\u5de6\u8fb9\u4e4b\u540e\u540e\u9762\u6bcf\u4e00\u5217\u90fd\u53f3\u79fb\u4e00\u4f4d\uff0c\u800c\u4ee3\u7801\u91cc\u5230\u5904\u662f\u88f8\u4e0b\u6807
    // \uff08getValueAt(row, 0) / setValueAt(..., 6)\uff09\uff0c\u6f0f\u6539\u4e00\u5904\u5c31\u662f\u300c\u64cd\u4f5c\u5230\u522b\u7684\u4efb\u52a1\u300d\u8fd9\u79cd\u4e0d\u62a5\u9519\u7684\u9519
    private static final int COL_SELECT = 0;
    private static final int COL_ID = 1;
    private static final int COL_METHOD = 2;
    private static final int COL_URL = 3;
    private static final int COL_STATUS = 4;
    private static final int COL_RESULT = 5;
    private static final int COL_VULN_COUNT = 6;
    private static final int COL_AI_TAG = 7;

    /** 列头文案的 key，顺序与列一一对应（重贴时按 index 走 setHeaderValue）*/
    private static final String[] COLUMN_KEYS = {"col.select", "col.id", "col.method", "col.url",
            "col.status", "col.result", "col.vulnCount", "col.aiTag"};

    /**
     * \u52fe\u9009\u7684\u4efb\u52a1 id \u2014\u2014 **\u6743\u5a01\u6765\u6e90**\uff0c\u8868\u683c\u91cc\u90a3\u4e2a\u65b9\u6846\u53ea\u662f\u5b83\u7684\u663e\u793a\u3002
     *
     * <p>\u72b6\u6001\u4e0d\u80fd\u53ea\u5b58\u5728\u5355\u5143\u683c\u91cc\uff1afilterTasks()\uff08\u641c\u7d22\u8bcd/\u7b5b\u9009\u53d8\u5316\u65f6\uff09\u4f1a setRowCount(0) \u91cd\u5efa\u6574\u4e2a\u6a21\u578b\uff0c
     * \u90a3\u6837\u7528\u6237\u52fe\u5b8c\u518d\u6253\u5b57\u641c\u7d22\uff0c\u52fe\u9009\u5c31\u5168\u6ca1\u4e86\u3002\u88ab\u7b5b\u9009\u9690\u85cf\u7684\u4efb\u52a1\u4ecd\u7136\u7559\u5728\u96c6\u5408\u91cc \u2014\u2014
     * \u7b5b\u9009\u662f\u300c\u770b\u54ea\u4e9b\u300d\uff0c\u4e0d\u8be5\u987a\u624b\u6539\u300c\u9009\u4e2d\u54ea\u4e9b\u300d\u3002
     *
     * <p>\u53ea\u5728 EDT \u4e0a\u8bbf\u95ee\uff1aTaskTablePanel \u672c\u6765\u5c31\u6ca1\u505a EDT \u6d3e\u53d1\uff0cEDT \u5b89\u5168\u6027\u662f\u8c03\u7528\u65b9\u7684\u5951\u7ea6\u3002
     */
    private final Set<Integer> checkedTaskIds = new LinkedHashSet<Integer>();

    public TaskTablePanel(MainPanel mainPanel, LogPanel logPanel) {
        this.mainPanel = mainPanel;
        this.logPanel = logPanel;
        this.taskRowMap = new HashMap<Integer, Integer>();
        this.initUI();
    }

    private void initUI() {
        this.setLayout(new BorderLayout(10, 10));
        this.setBackground(BG_WHITE);
        this.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER_GRAY, 2), BorderFactory.createEmptyBorder(10, 10, 10, 10)));
        JPanel topPanel = new JPanel(new BorderLayout(10, 5));
        topPanel.setBackground(BG_WHITE);
        JLabel titleLabel = new JLabel();
        Msg.bind(() -> titleLabel.setText(Msg.t("tasks.title")));
        titleLabel.setForeground(TEXT_DARK);
        titleLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 16));
        topPanel.add((Component)titleLabel, "North");
        JPanel filterPanel = new JPanel(new FlowLayout(0, 10, 5));
        filterPanel.setBackground(BG_WHITE);
        JLabel searchLabel = new JLabel();
        Msg.bind(() -> searchLabel.setText(Msg.t("tasks.search")));
        searchLabel.setForeground(TEXT_DARK);
        searchLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        filterPanel.add(searchLabel);
        this.searchField = new JTextField(25);
        this.searchField.setBackground(INPUT_BG);
        this.searchField.setForeground(TEXT_DARK);
        this.searchField.setCaretColor(TEXT_DARK);
        this.searchField.setFont(new Font("Consolas", 0, 13));
        // 5px 的上下内边距把这一格撑到 28px 以上，比旁边的按钮还高 —— 压到 2px 并给个首选高度，
        // 整行高度就由按钮（28）决定
        this.searchField.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER_GRAY), BorderFactory.createEmptyBorder(2, 8, 2, 8)));
        this.searchField.setPreferredSize(new Dimension(220, 26));
        this.searchField.addKeyListener(new KeyAdapter(){

            @Override
            public void keyReleased(KeyEvent evt) {
                TaskTablePanel.this.filterTasks();
            }
        });
        filterPanel.add(this.searchField);
        JLabel filterLabel = new JLabel();
        Msg.bind(() -> filterLabel.setText(Msg.t("tasks.filter")));
        filterLabel.setForeground(TEXT_DARK);
        filterLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        filterPanel.add(filterLabel);
        // \u4e0b\u62c9\u91cc\u88c5\u7684\u662f**\u679a\u4e3e**\u4e0d\u662f\u6587\u6848\uff1a\u5224\u5b9a\u8bfb\u679a\u4e3e\uff08matchesFilter\uff09\uff0c\u663e\u793a\u7531\u6e32\u67d3\u5668\u7ffb\u3002
        // \u88c5\u6587\u6848\u7684\u8bdd\uff0c\u754c\u9762\u4e00\u6362\u8bed\u8a00\uff0cmatchesFilter \u91cc\u90a3\u4e9b equals \u5c31\u5168\u843d\u7a7a\u4e86
        this.filterComboBox = new JComboBox<TaskFilter>(TaskFilter.values());
        this.filterComboBox.setBackground(INPUT_BG);
        this.filterComboBox.setForeground(TEXT_DARK);
        this.filterComboBox.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        this.filterComboBox.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof TaskFilter) {
                    this.setText(((TaskFilter) value).text());
                }
                return this;
            }
        });
        this.filterComboBox.addActionListener(e -> this.filterTasks());
        // \u9009\u4e2d\u9879\u7684\u6587\u5b57\u662f\u6e32\u67d3\u5668\u73b0\u753b\u7684\uff0c\u91cd\u753b\u4e00\u6b21\u5c31\u8ddf\u7740\u65b0\u8bed\u8a00\u8d70\u4e86
        Msg.onLangChanged(() -> this.filterComboBox.repaint());
        filterPanel.add(this.filterComboBox);
        JButton clearCompletedButton = this.createSmallButton("");
        Msg.bind(() -> clearCompletedButton.setText(Msg.t("btn.clearCompleted")));
        clearCompletedButton.addActionListener(e -> this.mainPanel.clearCompletedTasks());
        filterPanel.add(clearCompletedButton);
        JButton exportButton = this.createSmallButton("");
        Msg.bind(() -> exportButton.setText(Msg.t("btn.exportReport")));
        exportButton.addActionListener(e -> this.showExportDialog());
        filterPanel.add(exportButton);
        topPanel.add((Component)filterPanel, "Center");
        this.add((Component)topPanel, "North");
        Object[] columns = new String[]{Msg.t("col.select"), Msg.t("col.id"), Msg.t("col.method"), "URL",
                Msg.t("col.status"), Msg.t("col.result"), Msg.t("col.vulnCount"), Msg.t("col.aiTag")};
        this.tableModel = new DefaultTableModel(columns, 0){
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == COL_SELECT;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == COL_SELECT ? Boolean.class : Object.class;
            }

            /** \u65b9\u6846\u88ab\u70b9\u4e00\u4e0b\u5c31\u8d70\u8fd9\u91cc\uff0c\u987a\u624b\u628a\u6743\u5a01\u96c6\u5408\u6539\u6389 \u2014\u2014 \u53ea\u6539\u5355\u5143\u683c\u7684\u8bdd\uff0c
             *  filterTasks() \u4e00\u91cd\u5efa\u6a21\u578b\uff0c\u7528\u6237\u52fe\u7684\u4e1c\u897f\u5c31\u5168\u6ca1\u4e86 */
            @Override
            public void setValueAt(Object value, int row, int column) {
                super.setValueAt(value, row, column);
                if (column != COL_SELECT) {
                    return;
                }
                Object id = this.getValueAt(row, COL_ID);
                if (!(id instanceof Integer)) {
                    return;
                }
                if (Boolean.TRUE.equals(value)) {
                    TaskTablePanel.this.checkedTaskIds.add((Integer)id);
                } else {
                    TaskTablePanel.this.checkedTaskIds.remove((Integer)id);
                }
            }
        };
        this.taskTable = new JTable(this.tableModel);
        this.taskTable.setBackground(BG_WHITE);
        this.taskTable.setForeground(TEXT_DARK);
        this.taskTable.setGridColor(BORDER_GRAY);
        this.taskTable.setSelectionBackground(ROW_SELECTED);
        this.taskTable.setSelectionForeground(TEXT_DARK);
        this.taskTable.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        this.taskTable.setRowHeight(32);
        this.taskTable.setShowGrid(true);
        this.taskTable.setIntercellSpacing(new Dimension(2, 2));
        JTableHeader header = this.taskTable.getTableHeader();
        header.setBackground(PANEL_LIGHT);
        header.setForeground(TEXT_DARK);
        header.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 14));
        header.setBorder(BorderFactory.createLineBorder(BORDER_GRAY, 2));
        header.setPreferredSize(new Dimension(header.getPreferredSize().width, 35));
        header.setReorderingAllowed(false);
        // URL 列是**唯一会被拉长的列**：其余列一律给 maxWidth 上限（= 自己的首选宽度），
        // 于是 JTable 分配多余宽度时只能落到 URL 上，窗口越宽 URL 越长。
        // 以前所有列都参与分配，窗口不宽时 URL 跟着一起被挤 —— 用户反馈「url 列左右太短，
        // 长 URL 显示不完」（2026-09-24）。URL 另给一个最小宽度，免得窄窗口下被压到没有。
        this.taskTable.getColumnModel().getColumn(COL_SELECT).setPreferredWidth(46);
        this.taskTable.getColumnModel().getColumn(COL_SELECT).setMaxWidth(46);
        this.taskTable.getColumnModel().getColumn(COL_ID).setPreferredWidth(60);
        this.taskTable.getColumnModel().getColumn(COL_ID).setMaxWidth(80);
        this.taskTable.getColumnModel().getColumn(COL_METHOD).setPreferredWidth(70);
        this.taskTable.getColumnModel().getColumn(COL_METHOD).setMaxWidth(90);
        this.taskTable.getColumnModel().getColumn(COL_URL).setPreferredWidth(600);
        this.taskTable.getColumnModel().getColumn(COL_URL).setMinWidth(220);
        this.taskTable.getColumnModel().getColumn(COL_STATUS).setPreferredWidth(110);
        this.taskTable.getColumnModel().getColumn(COL_STATUS).setMaxWidth(130);
        this.taskTable.getColumnModel().getColumn(COL_RESULT).setPreferredWidth(90);
        this.taskTable.getColumnModel().getColumn(COL_RESULT).setMaxWidth(120);
        this.taskTable.getColumnModel().getColumn(COL_VULN_COUNT).setPreferredWidth(70);
        this.taskTable.getColumnModel().getColumn(COL_VULN_COUNT).setMaxWidth(90);
        this.taskTable.getColumnModel().getColumn(COL_AI_TAG).setPreferredWidth(170);
        this.taskTable.getColumnModel().getColumn(COL_AI_TAG).setMaxWidth(200);
        // \u52fe\u9009\u6846\u7684\u6e32\u67d3\u4e0e\u7f16\u8f91\u90fd\u81ea\u5df1\u7ed9\uff1a\u9ed8\u8ba4 Boolean \u6e32\u67d3\u5668\u4e0d\u8ddf\u7740\u884c\u9009\u4e2d\u53d8\u8272\uff0c\u770b\u7740\u50cf\u4e2a\u767d\u6d1e
        this.taskTable.getColumnModel().getColumn(COL_SELECT).setCellRenderer(new TableCellRenderer(){
            private final JCheckBox box = TaskTablePanel.this.createSelectCheckBox();

            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                this.box.setSelected(Boolean.TRUE.equals(value));
                this.box.setBackground(isSelected ? ROW_SELECTED : BG_WHITE);
                return this.box;
            }
        });
        this.taskTable.getColumnModel().getColumn(COL_SELECT).setCellEditor(new DefaultCellEditor(this.createSelectCheckBox()));
        this.taskTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer(){
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (!isSelected) {
                    c.setBackground(BG_WHITE);
                    c.setForeground(TEXT_DARK);
                } else {
                    c.setBackground(ROW_SELECTED);
                    c.setForeground(TEXT_DARK);
                }
                if (column == COL_RESULT && value instanceof ResultCell) {
                    ResultCell cell = (ResultCell) value;
                    if (cell.kind == ResultCell.LEVEL) {
                        c.setForeground(cell.level == ScanTask.VulnLevel.NONE ? TEXT_DARK : RED);
                    } else {
                        c.setForeground(new Color(255, 200, 0));
                    }
                }
                this.setHorizontalAlignment(0);
                return c;
            }
        });
        this.taskTable.getSelectionModel().addListSelectionListener(e -> {
            int taskId;
            ScanTask task;
            int selectedRow;
            if (!e.getValueIsAdjusting() && (selectedRow = this.taskTable.getSelectedRow()) >= 0 && (task = this.findTaskById(taskId = ((Integer)this.tableModel.getValueAt(selectedRow, COL_ID)).intValue())) != null) {
                this.mainPanel.showTaskDetail(task);
            }
        });
        JPopupMenu popupMenu = new JPopupMenu();
        popupMenu.setBackground(PANEL_LIGHT);
        popupMenu.setBorder(BorderFactory.createLineBorder(BORDER_GRAY, 2));
        JMenuItem deleteItem = this.createMenuItem(Msg.t("menu.deleteTask"));
        Msg.bind(() -> deleteItem.setText(Msg.t("menu.deleteTask")));
        deleteItem.addActionListener(e -> this.deleteCheckedTasks());
        popupMenu.add(deleteItem);
        JMenuItem pauseItem = this.createMenuItem(Msg.t("menu.pauseScan"));
        Msg.bind(() -> pauseItem.setText(Msg.t("menu.pauseScan")));
        pauseItem.addActionListener(e -> this.pauseCheckedTasks());
        popupMenu.add(pauseItem);
        JMenuItem resumeItem = this.createMenuItem(Msg.t("menu.resumeScan"));
        Msg.bind(() -> resumeItem.setText(Msg.t("menu.resumeScan")));
        resumeItem.addActionListener(e -> this.resumeCheckedTasks());
        popupMenu.add(resumeItem);
        popupMenu.addSeparator();
        JMenuItem copyUrlItem = this.createMenuItem(Msg.t("menu.copyUrl"));
        Msg.bind(() -> copyUrlItem.setText(Msg.t("menu.copyUrl")));
        copyUrlItem.addActionListener(e -> this.copyCheckedUrls());
        popupMenu.add(copyUrlItem);
        Msg.bind(() -> this.taskTable.getTableHeader().setToolTipText(Msg.t("tip.tasks.header")));
        this.taskTable.setComponentPopupMenu(popupMenu);
        // 列头重贴走 setHeaderValue + repaint：setColumnIdentifiers 会清空全表并丢掉上面设好的列宽
        Msg.bind(() -> {
            for (int i = 0; i < COLUMN_KEYS.length; i++) {
                this.taskTable.getColumnModel().getColumn(i).setHeaderValue(Msg.t(COLUMN_KEYS[i]));
            }
            this.taskTable.getTableHeader().repaint();
        });
        // \u53f3\u952e\u5148\u628a\u5149\u6807\u4e0b\u90a3\u4e00\u884c\u9009\u4e2d\uff1asetComponentPopupMenu \u4e0d\u4f1a\u66ff\u4f60\u9009\u884c\uff0c
        // \u4e8e\u662f\u300c\u53f3\u952e\u8fd9\u4e00\u884c\u3001\u83dc\u5355\u5374\u64cd\u4f5c\u4e86\u53e6\u4e00\u884c\u300d\uff08\u4e0a\u6b21\u70b9\u8fc7\u7684\u90a3\u884c\uff09\u2014\u2014 \u5355\u884c\u65f6\u5c31\u5df2\u7ecf\u5bb9\u6613\u770b\u9519\uff0c
        // \u6279\u91cf\u64cd\u4f5c\u65f6\u66f4\u96be\u53d1\u73b0
        this.taskTable.addMouseListener(new MouseAdapter(){
            private void selectRowUnder(MouseEvent evt) {
                if (!evt.isPopupTrigger()) {
                    return;
                }
                int row = TaskTablePanel.this.taskTable.rowAtPoint(evt.getPoint());
                if (row >= 0) {
                    TaskTablePanel.this.taskTable.setRowSelectionInterval(row, row);
                }
            }

            @Override
            public void mousePressed(MouseEvent evt) {
                this.selectRowUnder(evt);
            }

            @Override
            public void mouseReleased(MouseEvent evt) {
                this.selectRowUnder(evt);
            }
        });
        JScrollPane scrollPane = new JScrollPane(this.taskTable);
        scrollPane.getViewport().setBackground(BG_WHITE);
        scrollPane.setBorder(BorderFactory.createLineBorder(BORDER_GRAY, 2));
        this.add((Component)scrollPane, "Center");
    }

    public void addTask(ScanTask task) {
        // \u4e0e filterTasks \u5171\u7528\u540c\u4e00\u5957\u5224\u636e\uff1a\u4ee5\u524d\u8fd9\u91cc\u53ea\u8ba4 \u5168\u90e8/\u5f85\u5904\u7406/\u626b\u63cf\u4e2d/\u5df2\u5b8c\u6210\uff0c
        // \u7b5b\u300c\u6709\u6f0f\u6d1e\u300d\u65f6\u65b0\u4efb\u52a1\u7167\u6837\u63d2\u8fdb\u5217\u8868\uff0c\u800c\u4e14 refreshTask \u4f1a\u5c31\u5730\u66f4\u65b0\u8fd9\u4e00\u884c\u3001\u6c38\u8fdc\u4e0d\u4f1a\u518d\u8fc7\u6ee4\u5b83
        if (!this.matchesFilter(task, this.searchField.getText().toLowerCase(),
                (TaskFilter)this.filterComboBox.getSelectedItem())) {
            return;
        }
        this.tableModel.addRow(this.buildRow(task));
        this.taskRowMap.put(task.getId(), this.tableModel.getRowCount() - 1);
        // 新行由 buildRow 写的是普通状态文案，签名作废，下一拍才会补上排队位次
        this.renderedRows.remove(task.getId());
    }

    public void refreshTask(ScanTask task) {
        Integer rowIndex = this.taskRowMap.get(task.getId());
        if (rowIndex != null && rowIndex >= 0 && rowIndex < this.tableModel.getRowCount()) {
            this.updateRow(rowIndex, task);
        } else {
            this.filterTasks();
        }
    }

    /**
     * 扫描期间的就地刷新（EDT，每秒一次）：把已有行的状态/结果/漏洞数/AI标签按 task 当前值更新。
     * 不重建模型 —— 重建会丢选中行，而用户往往正盯着某个任务的详情。
     *
     * <p>任务索引在这里**一次建好**：以前每行都调 {@link #findTaskById}（内部又遍历一遍全部任务），
     * 每秒就是「行数 × 任务数」次比较 —— 自动扫描把任务堆到几千条时，拖住 EDT 的是这一处，
     * 与线程池无关。
     */
    public void refreshAllTasks() {
        Map<Integer, ScanTask> tasksById = new HashMap<Integer, ScanTask>();
        // 排队位次：PENDING 的任务按加入顺序（表格也是这个顺序）排，1 = 下一个开工的。
        // 池子固定 10 条线程，排在后面的要等前面的跑完 —— 不显示出来的话，「一直待处理」
        // 和「卡死」在界面上没有任何区别，而自动扫描很容易堆出这种队列。
        Map<Integer, Integer> queuePosition = new HashMap<Integer, Integer>();
        int queueSize = 0;
        for (ScanTask task : this.mainPanel.getTasks()) {
            tasksById.put(task.getId(), task);
            if (task.getStatus() == ScanTask.TaskStatus.PENDING) {
                queuePosition.put(task.getId(), ++queueSize);
            }
        }
        for (int row = 0; row < this.tableModel.getRowCount(); ++row) {
            Object idValue = this.tableModel.getValueAt(row, COL_ID);
            if (!(idValue instanceof Integer)) continue;
            ScanTask task = tasksById.get((Integer) idValue);
            if (task != null) {
                this.updateRow(row, task, queuePosition, queueSize);
            }
        }
    }

    private void updateRow(int rowIndex, ScanTask task) {
        this.updateRow(rowIndex, task, null, 0);
    }

    private void updateRow(int rowIndex, ScanTask task, Map<Integer, Integer> queuePosition, int queueSize) {
        // 结果列的值统一由 resultCellOf(task) 产出（含「扫描中显示 - / 有错误信息优先显示原因」那套规则），
        // 这里不要再自己算一遍：以前这段算出来的 result 根本没被用过，是留着将来改错语言的温床
        int vulnCount = task.getVulnerabilities() != null ? task.getVulnerabilities().size() : 0;
        ResultCell result = resultCellOf(task);
        String statusText = this.statusCellOf(task, queuePosition, queueSize);
        String vulnText = String.valueOf(vulnCount);
        String tagText = Msg.displayAiTag(task.getAiTag());
        // 值没变就整行跳过：已结束的行从此不再被碰（1 秒一次 × 4 次 setValueAt + 重画，
        // 表格几千行时全是白工）。换语言时 Msg 会重译，签名随之变化，照样会刷。
        String signature = statusText + '\u0000' + result.text + '\u0000' + vulnText + '\u0000' + tagText;
        if (signature.equals(this.renderedRows.get(task.getId()))) {
            return;
        }
        this.renderedRows.put(task.getId(), signature);
        this.tableModel.setValueAt(statusText, rowIndex, COL_STATUS);
        this.tableModel.setValueAt(result, rowIndex, COL_RESULT);
        this.tableModel.setValueAt(vulnText, rowIndex, COL_VULN_COUNT);
        this.tableModel.setValueAt(tagText, rowIndex, COL_AI_TAG);
        this.tableModel.fireTableRowsUpdated(rowIndex, rowIndex);
    }

    /**
     * 「状态」列的单元格值：PENDING 时显示排队位次而不是干巴巴的「待处理」。
     * 拿不到位次（单任务刷新路径）时退回不带数字的「排队中」。
     */
    private String statusCellOf(ScanTask task, Map<Integer, Integer> queuePosition, int queueSize) {
        if (task.getStatus() != ScanTask.TaskStatus.PENDING) {
            return Msg.statusName(task.getStatus());
        }
        Integer position = queuePosition == null ? null : queuePosition.get(task.getId());
        return position == null ? Msg.t("task.queued") : Msg.t("task.queuedAt", position, queueSize);
    }

    private ScanTask findTaskById(int taskId) {
        for (ScanTask task : this.mainPanel.getTasks()) {
            if (task.getId() != taskId) continue;
            return task;
        }
        return null;
    }

    /**
     * \u52fe\u9009\u6846\u5217\u7528\u7684 JCheckBox \u2014\u2014 **\u6e32\u67d3\u5668\u548c\u7f16\u8f91\u5668\u5fc5\u987b\u5171\u7528\u8fd9\u4e00\u4e2a\u5de5\u5382**\u3002
     *
     * <p>\u8fd9\u91cc\u8e29\u8fc7\u4e00\u6b21\uff1a\u6e32\u67d3\u5668\u8bbe\u4e86\u6c34\u5e73\u5c45\u4e2d\u3001\u7f16\u8f91\u5668\u5374\u662f {@code new JCheckBox()}\uff08\u9ed8\u8ba4\u5de6\u5bf9\u9f50\uff09\uff0c
     * 于是点下去的一瞬间画的是编辑器（贴着单元格左边）、松开又换回渲染器（居中）——
     * \u770b\u5230\u7684\u5c31\u662f\u300c\u52fe\u9009\u65f6\u6846\u5148\u5de6\u79fb\u518d\u79fb\u56de\u6765\u300d\u3002\u7f16\u8f91\u5668\u662f**\u53e6\u4e00\u4e2a\u7ec4\u4ef6\u5b9e\u4f8b**\uff0c\u6e32\u67d3\u5668\u4e0a\u8bbe\u7684\u4e1c\u897f\u5b83\u4e00\u4e2a\u90fd\u7ee7\u627f\u4e0d\u5230\u3002
     *
     * <p>\u8fb9\u6846\u4e5f\u8981\u7edf\u4e00\u538b\u6210 0 inset\uff1a\u7f16\u8f91\u6001\u4f1a\u5e26\u4e00\u5708 focus \u8fb9\u6846\uff0c\u90a3\u5708\u7684 inset \u540c\u6837\u4f1a\u8ba9\u6846\u4f4d\u79fb\u3002
     */
    private JCheckBox createSelectCheckBox() {
        JCheckBox box = new JCheckBox();
        box.setHorizontalAlignment(0);                          // CENTER\uff0c\u4e24\u8fb9\u5fc5\u987b\u4e00\u6a21\u4e00\u6837
        box.setBackground(BG_WHITE);
        box.setOpaque(true);
        box.setBorder(BorderFactory.createEmptyBorder());
        box.setBorderPainted(false);
        return box;
    }

    /**
     * 与「日志统计」页那两个按钮同款：**朴素 JButton**、微软雅黑 14 号、92×28、无焦点蓝边。
     * （以前走 UiKit 的 100×38，和日志页/配置页都对不上。）
     */
    private JButton createSmallButton(String text) {
        JButton button = new JButton(text);
        button.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 14));
        // 宽度随文字（英文 "Clear completed" 比中文长得多，固定 92px 会截断）
        button.setMargin(new Insets(3, 14, 3, 14));
        button.setFocusPainted(false);
        return button;
    }

    private JMenuItem createMenuItem(String text) {
        JMenuItem item = new JMenuItem(text);
        item.setBackground(PANEL_LIGHT);
        item.setForeground(TEXT_DARK);
        item.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        return item;
    }

    public void removeTask(ScanTask task) {
        Integer rowIndex = this.taskRowMap.remove(task.getId());
        this.renderedRows.remove(task.getId());
        this.checkedTaskIds.remove(task.getId());   // \u52fe\u9009\u8868\u4e5f\u8981\u6e05\uff1a\u7559\u7740\u7684\u8bdd\u300c\u5df2\u52fe\u9009 N \u4e2a\u300d\u4f1a\u628a\u5df2\u7ecf\u5220\u6389\u7684\u4efb\u52a1\u7b97\u8fdb\u53bb
        if (rowIndex != null && rowIndex < this.tableModel.getRowCount()) {
            this.tableModel.removeRow(rowIndex);
            this.rebuildRowMap();
        }
    }

    private void rebuildRowMap() {
        this.taskRowMap.clear();
        for (int i = 0; i < this.tableModel.getRowCount(); ++i) {
            int taskId = (Integer)this.tableModel.getValueAt(i, COL_ID);
            this.taskRowMap.put(taskId, i);
        }
    }

    /** \u5f53\u524d\u7b5b\u9009\u6761\u4ef6\uff08\u641c\u7d22\u8bcd + \u72b6\u6001\u4e0b\u62c9\uff09\u662f\u5426\u63a5\u53d7\u8fd9\u4e2a\u4efb\u52a1 \u2014\u2014 addTask \u4e0e filterTasks \u53ea\u6b64\u4e00\u4efd\u5224\u636e */
    private boolean matchesFilter(ScanTask task, String searchText, TaskFilter filter) {
        if (task == null) return false;
        if (searchText != null && !searchText.isEmpty()) {
            String taskUrl = task.getUrl() == null ? "" : task.getUrl().toLowerCase();
            String taskMethod = task.getMethod() == null ? "" : task.getMethod().toLowerCase();
            // AI\u6807\u7b7e\u5b58\u7684\u662f\u4e2d\u6587\uff08\u6570\u636e\u5c42\uff09\uff0c\u7528\u6237\u770b\u5230\u7684\u5374\u662f\u5f53\u524d\u8bed\u8a00\u7684\u8bd1\u6587 \u2014\u2014 \u4e24\u79cd\u5199\u6cd5\u90fd\u8981\u80fd\u641c\u5230\uff0c
            // \u5426\u5219\u82f1\u6587\u754c\u9762\u4e0b\u641c "SQL Injection" \u4f1a\u4e00\u4e2a\u90fd\u641c\u4e0d\u51fa\u6765
            String rawTag = task.getAiTag() == null ? "" : task.getAiTag().toLowerCase();
            String shownTag = Msg.displayAiTag(task.getAiTag()).toLowerCase();
            if (!taskUrl.contains(searchText) && !taskMethod.contains(searchText)
                    && !rawTag.contains(searchText) && !shownTag.contains(searchText)) {
                return false;
            }
        }
        if (filter == null || filter == TaskFilter.ALL) return true;
        boolean hasVuln = task.getVulnerabilities() != null && !task.getVulnerabilities().isEmpty();
        switch (filter) {
            case PENDING: return task.getStatus() == ScanTask.TaskStatus.PENDING;
            case SCANNING: return task.getStatus() == ScanTask.TaskStatus.SCANNING;
            case FINISHED: return task.getStatus() == ScanTask.TaskStatus.FINISHED;
            case WITH_VULN: return hasVuln;
            case WITHOUT_VULN: return !hasVuln;
            default: return true;
        }
    }

    /**
     * \u4efb\u52a1\u5217\u8868\u7684\u72b6\u6001\u7b5b\u9009\u3002
     *
     * <p>**\u5224\u5b9a\u53ea\u770b\u8fd9\u4e2a\u679a\u4e3e\uff0c\u4e0d\u770b\u663e\u793a\u6587\u6848** \u2014\u2014 \u4ee5\u524d {@code matchesFilter} \u62ff\u300c\u6709\u6f0f\u6d1e\u300d\u300c\u5f85\u5904\u7406\u300d
     * \u8fd9\u4e9b\u4e2d\u6587\u5b57\u9762\u91cf\u505a\u6bd4\u8f83\uff0c\u4e0b\u62c9\u9879\u4e00\u65e6\u7ffb\u6210\u82f1\u6587\uff0c\u6240\u6709\u6bd4\u8f83\u90fd\u4f1a\u843d\u7a7a\u3001\u7b5b\u9009\u9759\u9ed8\u5931\u6548\uff08\u5168\u90e8\u653e\u884c\uff09\u3002
     * \u6587\u6848\u8d70 {@code Msg}\uff0c\u5224\u5b9a\u8d70\u679a\u4e3e\uff0c\u4e24\u8005\u4ece\u6b64\u89e3\u8026\u3002
     */
    private enum TaskFilter {
        ALL("filter.all"),
        PENDING("filter.pending"),
        SCANNING("filter.scanning"),
        FINISHED("filter.finished"),
        WITH_VULN("filter.withVuln"),
        WITHOUT_VULN("filter.withoutVuln");

        private final String key;

        TaskFilter(String key) {
            this.key = key;
        }

        String text() {
            return Msg.t(this.key);
        }
    }

    /**
     * \u300c\u7ed3\u679c\u300d\u5217\u7684\u5355\u5143\u683c\u503c\u3002
     *
     * <p>\u4e3a\u4ec0\u4e48\u4e0d\u662f\u7eaf\u5b57\u7b26\u4e32\uff1a\u6e32\u67d3\u5668\u8981\u6309**\u6570\u636e**\u4e0a\u8272\u3002\u4ee5\u524d\u5b83\u62ff\u663e\u793a\u6587\u6848\u53bb\u731c
     * \uff08{@code equals("\u65e0\u6f0f\u6d1e")}\u3001{@code contains("\u5371")}\uff09\uff0c\u754c\u9762\u4e00\u6362\u8bed\u8a00\u4e0a\u8272\u5c31\u5168\u4e22\u4e86
     * \uff08\u6240\u6709\u884c\u90fd\u843d\u5230 else \u5206\u652f\u53d8\u6210\u9ec4\u8272\uff09\u3002\u5e26\u4e0a kind/level \u4e4b\u540e\uff0c\u663e\u793a\u4ec0\u4e48\u8bed\u8a00\u90fd\u4e0d\u5f71\u54cd\u7740\u8272\u3002
     */
    private static final class ResultCell {
        static final int DASH = 0;      // \u8fd8\u6ca1\u7ed3\u675f
        static final int ERROR = 1;     // \u7ed3\u675f\u4e86\u4f46\u5e26\u9519\u8bef\u4fe1\u606f
        static final int LEVEL = 2;     // \u6b63\u5e38\u7ed3\u675f\uff0c\u6309\u6f0f\u6d1e\u7b49\u7ea7\u4e0a\u8272

        final int kind;
        final ScanTask.VulnLevel level;
        final String text;

        ResultCell(int kind, ScanTask.VulnLevel level, String text) {
            this.kind = kind;
            this.level = level;
            this.text = text;
        }

        @Override
        public String toString() {
            return this.text;
        }
    }

    private Object[] buildRow(ScanTask task) {
        int vulnCount = task.getVulnerabilities() == null ? 0 : task.getVulnerabilities().size();
        return new Object[]{Boolean.valueOf(this.checkedTaskIds.contains(task.getId())), task.getId(),
                task.getMethod(), task.getUrl(), Msg.statusName(task.getStatus()), resultCellOf(task),
                String.valueOf(vulnCount), Msg.displayAiTag(task.getAiTag())};
    }

    /**
     * 「结果」列的值：未结束 / 带错误信息 / 漏洞等级三者取一。
     * 显示文案按当前语言翻，上色所需的类别与等级走结构字段（见 {@link ResultCell}）。
     */
    private static ResultCell resultCellOf(ScanTask task) {
        if (task.getStatus() != ScanTask.TaskStatus.FINISHED) {
            return new ResultCell(ResultCell.DASH, null, "-");
        }
        String error = task.getErrorMessage();
        if (error != null && !error.isEmpty()) {
            return new ResultCell(ResultCell.ERROR, null,
                    error.length() > 40 ? error.substring(0, 40) + "…" : error);
        }
        return new ResultCell(ResultCell.LEVEL, task.getVulnLevel(), Msg.levelName(task.getVulnLevel()));
    }

    private void filterTasks() {
        String searchText = this.searchField.getText().toLowerCase();
        TaskFilter filterType = (TaskFilter)this.filterComboBox.getSelectedItem();
        List<ScanTask> allTasks = this.mainPanel.getTasks();
        this.tableModel.setRowCount(0);
        this.taskRowMap.clear();
        // buildRow 写的是普通状态文案（不含排队位次），签名一律作废
        this.renderedRows.clear();
        int rowIndex = 0;
        for (ScanTask task : allTasks) {
            if (!this.matchesFilter(task, searchText, filterType)) continue;
            this.tableModel.addRow(this.buildRow(task));
            this.taskRowMap.put(task.getId(), rowIndex++);
        }
    }

    /**
     * \u672c\u6b21\u64cd\u4f5c\u8981\u4f5c\u7528\u4e8e\u54ea\u4e9b\u4efb\u52a1\uff1a**\u52fe\u9009\u7684\u5168\u90fd\u7b97**\uff1b\u4e00\u4e2a\u90fd\u6ca1\u52fe\u65f6\u9000\u56de\u5149\u6807/\u9009\u4e2d\u90a3\u4e00\u884c
     * \uff08\u4fdd\u7559\u539f\u6765\u7684\u5355\u884c\u64cd\u4f5c\u4e60\u60ef\uff0c\u4e0d\u81f3\u4e8e\u56e0\u4e3a\u5fd8\u4e86\u52fe\u5c31\u70b9\u4ec0\u4e48\u90fd\u6ca1\u53cd\u5e94\uff09\u3002
     * \u52fe\u9009\u662f\u6743\u5a01\u6765\u6e90\uff0c\u884c\u53f7\u53ea\u7528\u6765\u515c\u5e95\u3002
     */
    private List<ScanTask> actionTargets() {
        ArrayList<ScanTask> targets = new ArrayList<ScanTask>();
        for (Integer id : this.checkedTaskIds) {
            ScanTask task = this.findTaskById(id.intValue());
            if (task != null) {
                targets.add(task);
            }
        }
        if (!targets.isEmpty()) {
            return targets;
        }
        int row = this.taskTable.getSelectedRow();
        if (row >= 0 && row < this.taskTable.getRowCount()) {
            Object taskIdValue = this.taskTable.getValueAt(row, COL_ID);
            if (taskIdValue instanceof Integer) {
                ScanTask task = this.findTaskById((Integer)taskIdValue);
                if (task != null) {
                    targets.add(task);
                }
            }
        }
        return targets;
    }

    private void deleteCheckedTasks() {
        List<ScanTask> targets = this.actionTargets();
        if (targets.isEmpty()) {
            return;
        }
        String message = targets.size() == 1
                ? Msg.t("dlg.deleteOne", targets.get(0).getId())
                : Msg.t("dlg.deleteMany", targets.size());
        if (JOptionPane.showConfirmDialog(this, message, Msg.t("dlg.confirmDelete"), 0) != 0) {
            return;
        }
        for (ScanTask task : targets) {
            this.mainPanel.deleteTask(task);          // \u5b83\u81ea\u5df1\u4f1a removeTask \u5e76\u6e05\u6389\u52fe\u9009
        }
        this.logPanel.logInfo(Msg.t("msg.deleted", targets.size()));
    }

    private void pauseCheckedTasks() {
        int count = 0;
        for (ScanTask task : this.actionTargets()) {
            if (task.getStatus() != ScanTask.TaskStatus.SCANNING) {
                continue;
            }
            task.pause();
            this.refreshTask(task);
            ++count;
        }
        this.logPanel.logInfo(count == 0 ? Msg.t("msg.noScanningToPause")
                : Msg.t("msg.paused", count));
    }

    private void resumeCheckedTasks() {
        int count = 0;
        for (ScanTask task : this.actionTargets()) {
            if (task.getStatus() != ScanTask.TaskStatus.PAUSED) {
                continue;
            }
            task.resume();
            this.refreshTask(task);
            ++count;
        }
        this.logPanel.logInfo(count == 0 ? Msg.t("msg.noPausedToResume")
                : Msg.t("msg.resumed", count));
    }

    private void copyCheckedUrls() {
        List<ScanTask> targets = this.actionTargets();
        if (targets.isEmpty()) {
            return;
        }
        StringBuilder urls = new StringBuilder();
        for (ScanTask task : targets) {
            if (urls.length() > 0) {
                urls.append('\n');
            }
            urls.append(task.getUrl() == null ? "" : task.getUrl());
        }
        StringSelection selection = new StringSelection(urls.toString());
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
        this.logPanel.logInfo(targets.size() == 1 ? Msg.t("msg.copiedUrl")
                : Msg.t("msg.copiedUrls", targets.size()));
    }

    private void showExportDialog() {
        // 勾选优先：勾了几个就交给导出窗口几个（多任务导出走「选目录 + 逐个生成文件名」那条分支）。
        // 以前只传 targets.get(0)，勾了三个只导出一个，而且导出的是哪个还得看勾选顺序。
        List<ScanTask> targets = this.actionTargets();
        Frame parentFrame = (Frame)SwingUtilities.getWindowAncestor(this);
        ExportDialog dialog = new ExportDialog(parentFrame, this.mainPanel.getCallbacks(), this.mainPanel.getTasks(), targets, this.logPanel);
        dialog.setVisible(true);
    }
}
