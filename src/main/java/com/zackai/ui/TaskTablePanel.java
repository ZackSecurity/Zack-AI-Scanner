package com.zackai.ui;

import com.zackai.model.ScanTask;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
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

public class TaskTablePanel
extends JPanel {
    private MainPanel mainPanel;
    private LogPanel logPanel;
    private JTable taskTable;
    private DefaultTableModel tableModel;
    private Map<Integer, Integer> taskRowMap;
    private JTextField searchField;
    private JComboBox<String> filterComboBox;
    private static final Color BG_BLACK = Color.WHITE;
    private static final Color TEXT_GREEN = new Color(33, 37, 41);
    private static final Color PANEL_DARK = new Color(245, 247, 250);
    private static final Color BORDER_GREEN = new Color(210, 214, 220);
    private static final Color ROW_SELECTED = new Color(225, 239, 255);
    private static final Color RED = new Color(255, 0, 0);
    private static final Color INPUT_BG = Color.WHITE;

    public TaskTablePanel(MainPanel mainPanel, LogPanel logPanel) {
        this.mainPanel = mainPanel;
        this.logPanel = logPanel;
        this.taskRowMap = new HashMap<Integer, Integer>();
        this.initUI();
    }

    private void initUI() {
        this.setLayout(new BorderLayout(10, 10));
        this.setBackground(BG_BLACK);
        this.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER_GREEN, 2), BorderFactory.createEmptyBorder(10, 10, 10, 10)));
        JPanel topPanel = new JPanel(new BorderLayout(10, 5));
        topPanel.setBackground(BG_BLACK);
        JLabel titleLabel = new JLabel("\u626b\u63cf\u4efb\u52a1\u5217\u8868");
        titleLabel.setForeground(TEXT_GREEN);
        titleLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 16));
        topPanel.add((Component)titleLabel, "North");
        JPanel filterPanel = new JPanel(new FlowLayout(0, 10, 5));
        filterPanel.setBackground(BG_BLACK);
        JLabel searchLabel = new JLabel("\u641c\u7d22:");
        searchLabel.setForeground(TEXT_GREEN);
        searchLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        filterPanel.add(searchLabel);
        this.searchField = new JTextField(25);
        this.searchField.setBackground(INPUT_BG);
        this.searchField.setForeground(TEXT_GREEN);
        this.searchField.setCaretColor(TEXT_GREEN);
        this.searchField.setFont(new Font("Consolas", 0, 13));
        this.searchField.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER_GREEN), BorderFactory.createEmptyBorder(5, 8, 5, 8)));
        this.searchField.addKeyListener(new KeyAdapter(){

            @Override
            public void keyReleased(KeyEvent evt) {
                TaskTablePanel.this.filterTasks();
            }
        });
        filterPanel.add(this.searchField);
        JLabel filterLabel = new JLabel("\u7b5b\u9009:");
        filterLabel.setForeground(TEXT_GREEN);
        filterLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        filterPanel.add(filterLabel);
        this.filterComboBox = new JComboBox<String>(new String[]{"\u5168\u90e8", "\u5f85\u5904\u7406", "\u626b\u63cf\u4e2d", "\u5df2\u5b8c\u6210", "\u6709\u6f0f\u6d1e", "\u65e0\u6f0f\u6d1e"});
        this.filterComboBox.setBackground(INPUT_BG);
        this.filterComboBox.setForeground(TEXT_GREEN);
        this.filterComboBox.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        this.filterComboBox.addActionListener(e -> this.filterTasks());
        filterPanel.add(this.filterComboBox);
        JButton clearCompletedButton = this.createSmallButton("\u6e05\u7a7a\u5df2\u5b8c\u6210");
        clearCompletedButton.addActionListener(e -> this.mainPanel.clearCompletedTasks());
        filterPanel.add(clearCompletedButton);
        JButton exportButton = this.createSmallButton("\u5bfc\u51fa\u62a5\u544a");
        exportButton.addActionListener(e -> this.showExportDialog());
        filterPanel.add(exportButton);
        topPanel.add((Component)filterPanel, "Center");
        this.add((Component)topPanel, "North");
        Object[] columns = new String[]{"\u7f16\u53f7", "\u65b9\u6cd5", "URL", "AI\u72b6\u6001", "\u7ed3\u679c", "\u6f0f\u6d1e\u6570", "AI\u6807\u7b7e"};
        this.tableModel = new DefaultTableModel(columns, 0){
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        this.taskTable = new JTable(this.tableModel);
        this.taskTable.setBackground(BG_BLACK);
        this.taskTable.setForeground(TEXT_GREEN);
        this.taskTable.setGridColor(BORDER_GREEN);
        this.taskTable.setSelectionBackground(ROW_SELECTED);
        this.taskTable.setSelectionForeground(TEXT_GREEN);
        this.taskTable.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        this.taskTable.setRowHeight(32);
        this.taskTable.setShowGrid(true);
        this.taskTable.setIntercellSpacing(new Dimension(2, 2));
        JTableHeader header = this.taskTable.getTableHeader();
        header.setBackground(PANEL_DARK);
        header.setForeground(TEXT_GREEN);
        header.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 14));
        header.setBorder(BorderFactory.createLineBorder(BORDER_GREEN, 2));
        header.setPreferredSize(new Dimension(header.getPreferredSize().width, 35));
        this.taskTable.getColumnModel().getColumn(0).setPreferredWidth(60);
        this.taskTable.getColumnModel().getColumn(1).setPreferredWidth(70);
        this.taskTable.getColumnModel().getColumn(2).setPreferredWidth(380);
        this.taskTable.getColumnModel().getColumn(3).setPreferredWidth(100);
        this.taskTable.getColumnModel().getColumn(4).setPreferredWidth(80);
        this.taskTable.getColumnModel().getColumn(5).setPreferredWidth(80);
        this.taskTable.getColumnModel().getColumn(6).setPreferredWidth(120);
        this.taskTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer(){
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (!isSelected) {
                    c.setBackground(BG_BLACK);
                    c.setForeground(TEXT_GREEN);
                } else {
                    c.setBackground(ROW_SELECTED);
                    c.setForeground(TEXT_GREEN);
                }
                if (column == 4 && value != null) {
                    String result = value.toString();
                    if (result.equals("\u65e0\u6f0f\u6d1e") || result.isEmpty()) {
                        c.setForeground(TEXT_GREEN);
                    } else if (result.contains("\u5371") || result.contains("\u4e25\u91cd")) {
                        c.setForeground(RED);
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
            if (!e.getValueIsAdjusting() && (selectedRow = this.taskTable.getSelectedRow()) >= 0 && (task = this.findTaskById(taskId = ((Integer)this.tableModel.getValueAt(selectedRow, 0)).intValue())) != null) {
                this.mainPanel.showTaskDetail(task);
            }
        });
        JPopupMenu popupMenu = new JPopupMenu();
        popupMenu.setBackground(PANEL_DARK);
        popupMenu.setBorder(BorderFactory.createLineBorder(BORDER_GREEN, 2));
        JMenuItem rescanItem = this.createMenuItem("\u91cd\u65b0\u626b\u63cf");
        rescanItem.addActionListener(e -> this.rescanSelectedTask());
        popupMenu.add(rescanItem);
        JMenuItem deleteItem = this.createMenuItem("\u5220\u9664\u4efb\u52a1");
        deleteItem.addActionListener(e -> this.deleteSelectedTask());
        popupMenu.add(deleteItem);
        popupMenu.addSeparator();
        JMenuItem copyUrlItem = this.createMenuItem("\u590d\u5236URL");
        copyUrlItem.addActionListener(e -> this.copySelectedUrl());
        popupMenu.add(copyUrlItem);
        JMenuItem exportItem = this.createMenuItem("\u5bfc\u51fa\u62a5\u544a");
        exportItem.addActionListener(e -> this.showExportDialog());
        popupMenu.add(exportItem);
        this.taskTable.setComponentPopupMenu(popupMenu);
        JScrollPane scrollPane = new JScrollPane(this.taskTable);
        scrollPane.getViewport().setBackground(BG_BLACK);
        scrollPane.setBorder(BorderFactory.createLineBorder(BORDER_GREEN, 2));
        this.add((Component)scrollPane, "Center");
    }

    public void addTask(ScanTask task) {
        String filterType = (String)this.filterComboBox.getSelectedItem();
        String searchText = this.searchField.getText().toLowerCase();
        boolean shouldShow = true;
        if (!(searchText.isEmpty() || task.getUrl().toLowerCase().contains(searchText) || task.getMethod().toLowerCase().contains(searchText) || task.getAiTag().toLowerCase().contains(searchText))) {
            shouldShow = false;
        }
        if (shouldShow && !filterType.equals("\u5168\u90e8")) {
            if (filterType.equals("\u5f85\u5904\u7406") && task.getStatus() != ScanTask.TaskStatus.PENDING) {
                shouldShow = false;
            }
            if (filterType.equals("\u626b\u63cf\u4e2d") && task.getStatus() != ScanTask.TaskStatus.SCANNING) {
                shouldShow = false;
            }
            if (filterType.equals("\u5df2\u5b8c\u6210") && task.getStatus() != ScanTask.TaskStatus.FINISHED) {
                shouldShow = false;
            }
        }
        if (shouldShow) {
            String result = task.getStatus() == ScanTask.TaskStatus.FINISHED ? task.getVulnLevel().getDisplayName() : "-";
            int vulnCount = task.getVulnerabilities() != null ? task.getVulnerabilities().size() : 0;
            Object[] row = new Object[]{task.getId(), task.getMethod(), task.getUrl(), task.getStatus().getDisplayName(), result, String.valueOf(vulnCount), task.getAiTag()};
            this.tableModel.addRow(row);
            this.taskRowMap.put(task.getId(), this.tableModel.getRowCount() - 1);
        }
    }

    public void refreshTask(ScanTask task) {
        Integer rowIndex = this.taskRowMap.get(task.getId());
        if (rowIndex != null && rowIndex >= 0 && rowIndex < this.tableModel.getRowCount()) {
            String result = task.getStatus() == ScanTask.TaskStatus.FINISHED ? task.getVulnLevel().getDisplayName() : "-";
            int vulnCount = task.getVulnerabilities() != null ? task.getVulnerabilities().size() : 0;
            this.tableModel.setValueAt(task.getStatus().getDisplayName(), rowIndex, 3);
            this.tableModel.setValueAt(result, rowIndex, 4);
            this.tableModel.setValueAt(String.valueOf(vulnCount), rowIndex, 5);
            this.tableModel.setValueAt(task.getAiTag(), rowIndex, 6);
            this.tableModel.fireTableRowsUpdated(rowIndex, rowIndex);
        } else {
            this.filterTasks();
        }
    }

    private ScanTask findTaskById(int taskId) {
        for (ScanTask task : this.mainPanel.getTasks()) {
            if (task.getId() != taskId) continue;
            return task;
        }
        return null;
    }

    private JButton createSmallButton(String text) {
        final JButton button = new JButton(text);
        button.setBackground(PANEL_DARK);
        button.setForeground(TEXT_GREEN);
        button.setBorder(BorderFactory.createLineBorder(BORDER_GREEN, 2));
        button.setFocusPainted(false);
        button.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 14));
        button.setCursor(new Cursor(12));
        button.setPreferredSize(new Dimension(100, 38));
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

    private JMenuItem createMenuItem(String text) {
        JMenuItem item = new JMenuItem(text);
        item.setBackground(PANEL_DARK);
        item.setForeground(TEXT_GREEN);
        item.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        return item;
    }

    public void removeTask(ScanTask task) {
        Integer rowIndex = this.taskRowMap.remove(task.getId());
        if (rowIndex != null && rowIndex < this.tableModel.getRowCount()) {
            this.tableModel.removeRow(rowIndex);
            this.rebuildRowMap();
        }
    }

    private void rebuildRowMap() {
        this.taskRowMap.clear();
        for (int i = 0; i < this.tableModel.getRowCount(); ++i) {
            int taskId = (Integer)this.tableModel.getValueAt(i, 0);
            this.taskRowMap.put(taskId, i);
        }
    }

    private void filterTasks() {
        String searchText = this.searchField.getText().toLowerCase();
        String filterType = (String)this.filterComboBox.getSelectedItem();
        List<ScanTask> allTasks = this.mainPanel.getTasks();
        this.tableModel.setRowCount(0);
        this.taskRowMap.clear();
        int rowIndex = 0;
        for (ScanTask task : allTasks) {
            boolean searchMismatch = !searchText.isEmpty() && !task.getUrl().toLowerCase().contains(searchText) && !task.getMethod().toLowerCase().contains(searchText) && !task.getAiTag().toLowerCase().contains(searchText);
            boolean filterMismatch = !filterType.equals("\u5168\u90e8") && (
                filterType.equals("\u5f85\u5904\u7406") && task.getStatus() != ScanTask.TaskStatus.PENDING ||
                filterType.equals("\u626b\u63cf\u4e2d") && task.getStatus() != ScanTask.TaskStatus.SCANNING ||
                filterType.equals("\u5df2\u5b8c\u6210") && task.getStatus() != ScanTask.TaskStatus.FINISHED ||
                filterType.equals("\u6709\u6f0f\u6d1e") && task.getVulnLevel() == ScanTask.VulnLevel.NONE ||
                filterType.equals("\u65e0\u6f0f\u6d1e") && task.getVulnLevel() != ScanTask.VulnLevel.NONE
            );
            if (searchMismatch || filterMismatch) continue;
            String result = task.getStatus() == ScanTask.TaskStatus.FINISHED ? task.getVulnLevel().getDisplayName() : "-";
            int vulnCount = task.getVulnerabilities().size();
            Object[] row = new Object[]{task.getId(), task.getMethod(), task.getUrl(), task.getStatus().getDisplayName(), result, String.valueOf(vulnCount), task.getAiTag()};
            this.tableModel.addRow(row);
            this.taskRowMap.put(task.getId(), rowIndex++);
        }
    }

    private void rescanSelectedTask() {
        int taskId;
        ScanTask task;
        int selectedRow = this.taskTable.getSelectedRow();
        if (selectedRow >= 0 && (task = this.findTaskById(taskId = ((Integer)this.tableModel.getValueAt(selectedRow, 0)).intValue())) != null) {
            this.mainPanel.rescanTask(task);
        }
    }

    private void deleteSelectedTask() {
        int taskId;
        ScanTask task;
        int selectedRow = this.taskTable.getSelectedRow();
        if (selectedRow >= 0 && (task = this.findTaskById(taskId = ((Integer)this.tableModel.getValueAt(selectedRow, 0)).intValue())) != null && JOptionPane.showConfirmDialog(this, "\u786e\u5b9a\u8981\u5220\u9664\u4efb\u52a1 #" + taskId + " \u5417\uff1f", "\u786e\u8ba4\u5220\u9664", 0) == 0) {
            this.mainPanel.deleteTask(task);
        }
    }

    private void copySelectedUrl() {
        int selectedRow = this.taskTable.getSelectedRow();
        if (selectedRow >= 0) {
            String url = (String)this.tableModel.getValueAt(selectedRow, 2);
            StringSelection selection = new StringSelection(url);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
            this.logPanel.logInfo("\u5df2\u590d\u5236URL\u5230\u526a\u8d34\u677f");
        }
    }

    private void showExportDialog() {
        int selectedRow = this.taskTable.getSelectedRow();
        ScanTask selectedTask = null;
        if (selectedRow >= 0) {
            int taskId = (Integer)this.tableModel.getValueAt(selectedRow, 0);
            selectedTask = this.findTaskById(taskId);
        }
        Frame parentFrame = (Frame)SwingUtilities.getWindowAncestor(this);
        ExportDialog dialog = new ExportDialog(parentFrame, this.mainPanel.getTasks(), selectedTask, this.logPanel);
        dialog.setVisible(true);
    }
}
