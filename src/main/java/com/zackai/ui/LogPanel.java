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

import burp.ITab;
import com.zackai.i18n.Msg;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Insets;
import java.awt.GridLayout;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.JViewport;
import javax.swing.SwingUtilities;
import javax.swing.border.TitledBorder;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

public class LogPanel
extends JPanel
implements ITab {
    private JTextPane logPane;
    private StyledDocument doc;
    private JLabel totalTasksValue;
    private JLabel completedTasksValue;
    private JLabel vulnerableCountValue;
    private JLabel currentScanningValue;
    private static final Color BG_WHITE = Color.WHITE;
    private static final Color TEXT_DARK = new Color(33, 37, 41);
    private static final Color PANEL_LIGHT = new Color(245, 247, 250);
    private static final Color BORDER_GRAY = new Color(210, 214, 220);
    private static final Color INPUT_BG = Color.WHITE;
    private burp.IBurpExtenderCallbacks callbacks;

    public LogPanel() {
        this.initUI();
    }

    public void setCallbacks(burp.IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    private void initUI() {
        this.setLayout(new BorderLayout(10, 10));
        this.setBackground(BG_WHITE);
        this.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        JPanel statsPanel = new JPanel(new GridLayout(1, 4, 15, 0));
        statsPanel.setBackground(PANEL_LIGHT);
        // 内边距与字号一起压：这一行原来占 ~75px，日志框被挤得只剩几行
        statsPanel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER_GRAY, 2), BorderFactory.createEmptyBorder(6, 15, 6, 15)));
        this.totalTasksValue = this.createStatValueLabel("0");
        this.completedTasksValue = this.createStatValueLabel("0");
        this.vulnerableCountValue = this.createStatValueLabel("0");
        this.currentScanningValue = this.createStatValueLabel("0");
        statsPanel.add(this.createStatLabel("log.stat.total", this.totalTasksValue));
        statsPanel.add(this.createStatLabel("log.stat.completed", this.completedTasksValue));
        statsPanel.add(this.createStatLabel("log.stat.vulns", this.vulnerableCountValue));
        statsPanel.add(this.createStatLabel("log.stat.scanning", this.currentScanningValue));
        this.add((Component)statsPanel, "North");
        this.logPane = new JTextPane();
        this.logPane.setBackground(INPUT_BG);
        this.logPane.setForeground(TEXT_DARK);
        this.logPane.setCaretColor(TEXT_DARK);
        this.logPane.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        this.logPane.setEditable(false);
        this.doc = this.logPane.getStyledDocument();
        JScrollPane scrollPane = new JScrollPane(this.logPane);
        TitledBorder logBorder = BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(BORDER_GRAY, 2), Msg.t("log.title"), 1, 2,
                new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 14), TEXT_DARK);
        Msg.bind(() -> {
            logBorder.setTitle(Msg.t("log.title"));
            scrollPane.repaint();      // setTitle 不保证触发重画
        });
        scrollPane.setBorder(BorderFactory.createCompoundBorder(logBorder, BorderFactory.createEmptyBorder(5, 5, 5, 5)));
        scrollPane.getViewport().setBackground(INPUT_BG);
        // 横向滑动条「按需出现」：面板跟着视口宽度折行（它是 JEditorPane，宽度装得下时就跟视口同宽），
        // 只有当某行**仍然**比视口宽时才不再压缩、把内容完整摆出来并给出滑动条 —— 那一刻用户能拖到行尾。
        // 没有这一条（以前是 NEVER）时，超宽的部分是被直接裁掉的，而「装不下就不折」这件事
        // JTextPane 自己做不到，详见 breakLongRuns。
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        // 窗口宽度变了就按新宽度重新插断点（txt 编辑器那种跟着窗口走的换行）。
        // JTextPane 自己折不了无断点的长串，见 breakLongRuns 的说明。
        this.logPane.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                LogPanel.this.scheduleRewrap();
            }
        });
        scrollPane.setWheelScrollingEnabled(true);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);   // 默认一格只挪几像素，滚轮几乎推不动
        this.add((Component)scrollPane, "Center");
        JPanel buttonPanel = new JPanel(new FlowLayout(2, 12, 4));
        buttonPanel.setBackground(BG_WHITE);
        JButton clearButton = this.createStyledButton("");
        Msg.bind(() -> clearButton.setText(Msg.t("btn.clearLog")));
        clearButton.addActionListener(e -> this.clearLog());
        buttonPanel.add(clearButton);
        JButton exportButton = this.createStyledButton("");
        Msg.bind(() -> exportButton.setText(Msg.t("btn.exportLog")));
        exportButton.addActionListener(e -> this.exportLog());
        buttonPanel.add(exportButton);
        this.add((Component)buttonPanel, "South");
    }

    private JLabel createStatValueLabel(String value) {
        JLabel label = new JLabel(value, 0);
        label.setForeground(TEXT_DARK);
        label.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 1, 13));
        return label;
    }

    private JPanel createStatLabel(String titleKey, JLabel valueLabel) {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBackground(PANEL_LIGHT);
        JLabel titleLabel = new JLabel("", 0);
        Msg.bind(() -> titleLabel.setText(Msg.t(titleKey)));
        titleLabel.setForeground(new Color(100, 200, 100));
        // 与日志正文同号（13 号）：统计格的字号比正文小一号会显得像附注，读起来费劲
        titleLabel.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 13));
        panel.add((Component)titleLabel, "North");
        panel.add((Component)valueLabel, "Center");
        return panel;
    }

    /**
     * 与配置页那几个按钮同款：**朴素 JButton**（不是 UiKit 那套带悬停效果的），微软雅黑 14 号。
     *
     * <p>尺寸比配置页的 110×38 小一圈：这一页下方是日志正文，按钮每高一点日志就少看一行。
     * {@code setFocusPainted(false)} 去掉获得焦点时那圈蓝边（顶栏的语言按钮同样是这个问题）。
     */
    private JButton createStyledButton(String text) {
        JButton button = new JButton(text);
        button.setFont(new Font("\u5fae\u8f6f\u96c5\u9ed1", 0, 14));
        // **不要设固定 preferredSize**：英文文案长度差异很大（"Clear log" 与 "Export log"），
        // 固定宽度会把长的那条截断（中英切换后更明显）。高度靠 margin 控、宽度随文字自己长。
        button.setMargin(new Insets(3, 14, 3, 14));
        button.setFocusPainted(false);
        return button;
    }

    private static final Color COLOR_INFO = new Color(22, 163, 74);
    private static final Color COLOR_VULN = new Color(220, 38, 38);

    public void log(String message) {
        this.log(message, COLOR_INFO);
    }

    public void logInfo(String message) {
        this.log("INFO", message, COLOR_INFO);
    }

    public void logSuccess(String message) {
        this.log("OK", message, new Color(21, 128, 61));
    }

    public void logWarning(String message) {
        this.log("WARN", message, new Color(202, 138, 4));
    }

    // 错误只占一行：以前每条错误上下各加一条 41 字分隔线（另一个「详细错误」重载叠得更多），
    // 一次扫描几个错误就多出十几行纯横线，真正要看的错误行反而被淹没。颜色已经把级别表达出来了。
    public void logError(String message) {
        this.log("ERROR", message, new Color(220, 38, 38));
    }

    public void logError(String message, Throwable e) {
        this.log("ERROR", message, new Color(220, 38, 38));
        if (this.callbacks != null) {
            String detailedMessage = "[Error] " + message + " | Exception: " + (e != null ? e.getClass().getSimpleName() : "null") + " - " + (e != null && e.getMessage() != null ? e.getMessage() : "No message");
            this.callbacks.printError(detailedMessage);
        }
    }

    public void logAI(String message) {
        this.log("AI", message, COLOR_INFO);
    }
    
    public void logStep(String message) {
        this.log("STEP", message, COLOR_INFO);
    }
    
    public void logPayload(String message) {
        this.log("PAYLOAD", message, COLOR_INFO);
    }
    
    public void logVuln(String message) {
        this.log("VULN", message, COLOR_VULN);
    }
    
    public void logParam(String message) {
        this.log("PARAM", message, COLOR_INFO);
    }
    
    public void logDivider(String message) {
        this.log(message, Color.BLACK);
    }
    
    public void logProgress(String message) {
        this.log("PROGRESS", message, COLOR_INFO);
    }

    /**
     * 调用方自己已经写了 `[步骤N]`/`[外带检测]`/`[发送错误]` 这类标签时，不再叠一层 `[LEVEL]` ——
     * 以前每行都是 `[STEP] [步骤1] …` 这种双标签，白占字符又不好读。级别仍由颜色表达。
     */
    private void log(String level, String message, Color color) {
        if (message != null && message.startsWith("[")) {
            this.log(message, color);
        } else {
            this.log("[" + level + "] " + message, color);
        }
    }

    /** 日志面板最多保留的行数：超出后从顶部裁掉（超长会话下文档不能无限增长） */
    private static final int MAX_LOG_LINES = 5000;

    /**
     * 已经写进面板的**段落数**（自己数，别用文档的 element 结构 —— JTextPane 会按换行显示再把长行
     * 拆成多个 element）。
     *
     * <p>注意计的是段落不是消息：一条消息里可能本来就带换行（模型的分析文本），也可能被
     * {@link #breakLongRuns} 折成多段。按消息计数的话，每写一条只裁掉一段、而进来的可能有好几段，
     * 文档里的段落就会无限增长。
     */
    private int logEntries;

    /**
     * 没有断点的超长串在**默认宽度**下最长留多少个字符 —— 见 {@link #breakLongRuns}。
     * 面板还没显示（宽度 0）时用它兜底；显示之后按真实宽度算。
     */
    public static final int LONG_RUN_LIMIT = 96;

    /**
     * 给「一个断点都没有的超长串」插入换行 —— 否则这一行会横向溢出、右边被直接裁掉。
     *
     * <p>为什么必须自己动手：{@code JTextPane} 只在 {@code BreakIterator} 给出的断点处折行，
     * 而 base64、hex、不带空格的 JSON、百分比编码的 URL **一个断点都没有** ——
     * 实测过：400 个字符的长串在 300px 宽的窗格里，{@code breakView} 被调用 0 次（带空格的文本
     * 是 24 次），折行逻辑在 {@code javax.swing.text.Utilities} 里按 BreakIterator 算断点，
     * 外部没有可用的钩子（自定义 View、U+200B 零宽空格都试过，都不行）。所以断点只能自己插。
     *
     * <p>{@code budget} 是「这一行放得下多少个字符」，由面板当前宽度算出来（见 {@link #runBudget()}）：
     * 窗口变宽就少插、变窄就多插，也就是 txt 编辑器那种跟着窗口走的换行。中文、带空格的文本本身
     * 就能折行，遇到它们计数归零、一个字都不插（中文长句不会被切断）。
     *
     * <p>不缩进：续行与普通折行长得一样，才像文本编辑器；新的日志行总有时间戳前缀，分得清。
     * 载荷在日志里本来就被截断（见 {@code AIEngine.loggablePayload}），所以这不会让用户失去
     * 「从日志里复制完整载荷」的能力 —— 那个能力本来就不存在，完整载荷在详情面板里。
     */
    public static String breakLongRuns(String message, int budget) {
        int limit = Math.max(16, budget);
        if (message == null || message.length() <= limit) {
            return message;
        }
        StringBuilder sb = new StringBuilder(message.length() + 32);
        int run = 0;
        for (int i = 0; i < message.length(); ++i) {
            char c = message.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || isBreakableWide(c)) {
                run = 0;
            } else if (++run > limit) {
                sb.append('\n');
                run = 1;
            }
            sb.append(c);
        }
        return sb.toString();
    }

    /** 默认宽度下的折行（自检与面板未显示时用） */
    public static String breakLongRuns(String message) {
        return breakLongRuns(message, LONG_RUN_LIMIT);
    }

    /** 东亚宽字符：CJK 文本在任意字符间都能折行，不必也不该由我们来切 */
    private static boolean isBreakableWide(char c) {
        return c >= 0x2E80;
    }

    /**
     * 一条日志（原始消息 + 已按当时宽度插好断点的显示文本 + 颜色 + 段落数）。
     *
     * <p>窗口宽度变了要重排，就必须留着**原始**消息：显示文本是按旧宽度插的断点，回不去了。
     */
    private static final class Entry {
        final String raw;
        final String line;
        final Color color;
        final int paragraphs;

        Entry(String raw, String line, Color color) {
            this.raw = raw;
            this.line = line;
            this.color = color;
            this.paragraphs = countParagraphs(line);
        }

        static int countParagraphs(String text) {
            int n = 1;
            for (int i = 0; i < text.length(); ++i) {
                if (text.charAt(i) == '\n') {
                    ++n;
                }
            }
            return n;
        }
    }

    /** 文档里保留的条目（与文档同步裁剪），窗口宽度变化时按新宽度整篇重排 */
    private final java.util.ArrayDeque<Entry> entries = new java.util.ArrayDeque<Entry>();
    /** 这些条目占的段落数（与 {@link #logEntries} 对齐，用于同步裁剪，避免每次重算一遍） */
    private int bufferParagraphs;
    /** 当前断点预算（字符数）；宽度没跨过字符边界就不重排 */
    private int currentBudget = LONG_RUN_LIMIT;
    /** 宽度变化的防抖：拖窗口时不要每一像素都重排一遍整篇日志 */
    private javax.swing.Timer rewrapTimer;

    private void log(String message, Color color) {
        SwingUtilities.invokeLater(() -> {
            try {
                SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
                String line = sdf.format(new Date()) + " | " + breakLongRuns(message, this.currentBudget);
                this.appendEntry(new Entry(message, line, color));
                this.trimToMaxLines();
                this.logPane.setCaretPosition(this.doc.getLength());
            }
            catch (BadLocationException e) {
                System.err.println("[LogPanel] " + e.getMessage());
            }
        });
    }

    /** 往文档尾部写一条（EDT 上调用） */
    private void appendEntry(Entry entry) throws BadLocationException {
        SimpleAttributeSet attrs = new SimpleAttributeSet();
        StyleConstants.setForeground(attrs, entry.color);
        this.doc.insertString(this.doc.getLength(), entry.line + "\n", attrs);
        this.logEntries += entry.paragraphs;
        this.entries.addLast(entry);
        this.bufferParagraphs += entry.paragraphs;
    }

    /**
     * 面板宽度能放下多少个字符。按「无断点长串里最常见的字符宽度」估（ASCII，base64/hex/URL 都是），
     * 中文本身是断点，不参与这个预算。宽度未知（还没显示）时用默认值。
     */
    private int runBudget() {
        // 按**视口**宽度算，不能按面板宽度：面板可能已经比视口宽（那正是出现横向滑动条的时候），
        // 拿它当依据会形成「越宽→越少断点→越宽」的正反馈
        JViewport viewport = (JViewport) SwingUtilities.getAncestorOfClass(JViewport.class, this.logPane);
        int width = -1;
        if (viewport != null && viewport.getExtentSize().width > 0) {
            width = viewport.getExtentSize().width;
        } else if (this.logPane.getWidth() > 0) {
            width = this.logPane.getWidth();                  // 还没进滚动面板（自检里就是这样）
        }
        width -= 24;                                          // 去掉内边距与滚动条
        if (width <= 0 || this.logPane.getFont() == null) {
            return LONG_RUN_LIMIT;
        }
        int charWidth = Math.max(1, this.logPane.getFontMetrics(this.logPane.getFont()).charWidth('x'));
        int budget = width / charWidth;
        return Math.max(32, Math.min(400, budget));
    }

    /** 宽度变化（防抖 150ms 后）按新宽度重排整篇 —— 拖窗口时只会在停下来之后排一次 */
    private void scheduleRewrap() {
        if (this.rewrapTimer == null) {
            this.rewrapTimer = new javax.swing.Timer(150, e -> this.rewrapIfNeeded());
            this.rewrapTimer.setRepeats(false);
        }
        this.rewrapTimer.restart();
    }

    /**
     * 按当前宽度重新插断点（EDT）。没有长串的日志 —— 绝大多数 —— 在这里几步就返回，不会重建文档。
     */
    void rewrapIfNeeded() {
        int budget = this.runBudget();
        if (budget == this.currentBudget) {
            return;                                            // 宽度没跨过字符边界，一个字都不用动
        }
        boolean changed = false;
        for (Entry entry : this.entries) {
            if (!breakLongRuns(entry.raw, budget).equals(stripTimestamp(entry.line))) {
                changed = true;
                break;
            }
        }
        if (!changed) {
            this.currentBudget = budget;                       // 这一轮没长串，记下新预算即可
            return;
        }
        this.currentBudget = budget;
        this.rebuild();
    }

    /** 把界面上那条显示文本里的消息部分取回来（去掉 "HH:mm:ss | " 前缀） */
    private static String stripTimestamp(String line) {
        int bar = line.indexOf(" | ");
        return bar < 0 ? line : line.substring(bar + 3);
    }

    /** 整篇重建（EDT）：保留滚动位置与贴底状态，重建后行数/段落数一致地重算 */
    private void rebuild() {
        JViewport viewport = (JViewport) SwingUtilities.getAncestorOfClass(JViewport.class, this.logPane);
        int oldY = viewport != null ? viewport.getViewPosition().y : 0;
        int oldHeight = viewport != null ? viewport.getExtentSize().height : 0;
        boolean wasAtBottom = viewport != null
                && oldY + oldHeight >= this.logPane.getHeight() - 4;
        try {
            // 先在一份**新文档**里排好再整体换上：就地删了再逐条写的话，中途出任何岔子
            // 都会留下一份半截文档（日志就此少一段），而换文档是原子的
            StyledDocument fresh = new javax.swing.text.DefaultStyledDocument();
            int paragraphs = 0;
            for (Entry entry : this.entries) {
                int bar = entry.line.indexOf(" | ");
                String head = bar < 0 ? "" : entry.line.substring(0, bar + 3);
                String display = breakLongRuns(entry.raw, this.currentBudget);
                fresh.insertString(fresh.getLength(), head + display + "\n", attributesOf(entry.color));
                paragraphs += Entry.countParagraphs(display);
            }
            this.doc = fresh;
            this.logPane.setDocument(fresh);
            this.logEntries = paragraphs;
            this.bufferParagraphs = paragraphs;                // 重建后两者一致
            if (viewport != null) {
                int target = wasAtBottom ? Math.max(0, this.logPane.getHeight() - oldHeight) : oldY;
                viewport.setViewPosition(new java.awt.Point(0, target));
            }
        }
        catch (Exception e) {
            // 重建失败就保持原样（旧文档还在屏幕上），只留一行错误，不让日志凭空少一段
            System.err.println("[LogPanel] 重排失败: " + e);
        }
    }

    private static SimpleAttributeSet attributesOf(Color color) {
        SimpleAttributeSet attrs = new SimpleAttributeSet();
        StyleConstants.setForeground(attrs, color);
        return attrs;
    }

    /**
     * 超过上限就裁掉最老的一行（EDT 上调用）。
     * 用**段落**结构定位而不是 getDefaultRootElement()：JTextPane 会把长行按宽度折行，
     * 那个 element 数量是「显示行」而不是「日志行」，拿它当计数会一次性删掉几千行（实测过：写 5200 行只剩 30 行）。
     * 段落元素由文档自身维护（每条日志一行 = 一个段落），不受折行影响。
     */
    private void trimToMaxLines() throws BadLocationException {
        while (this.logEntries > MAX_LOG_LINES) {
            int end = this.doc.getParagraphElement(0).getEndOffset();
            this.doc.remove(0, Math.min(end, this.doc.getLength()));
            --this.logEntries;
        }
        // 条目缓冲跟着文档一起裁：段落数对不上就一直丢最老的条目（两者始终一致，
        // 否则窗口宽度变化后重排出来的内容会比屏幕上多出一截）
        while (this.bufferParagraphs > this.logEntries && !this.entries.isEmpty()) {
            this.bufferParagraphs -= this.entries.removeFirst().paragraphs;
        }
    }

    /** 只更新界面上的四个计数：面板不再自己缓存一份（以前那四个字段只写不读） */
    public void updateStats(int total, int completed, int vulnerable, int scanning) {
        SwingUtilities.invokeLater(() -> {
            if (this.totalTasksValue != null) {
                this.totalTasksValue.setText(String.valueOf(total));
            }
            if (this.completedTasksValue != null) {
                this.completedTasksValue.setText(String.valueOf(completed));
            }
            if (this.vulnerableCountValue != null) {
                this.vulnerableCountValue.setText(String.valueOf(vulnerable));
            }
            if (this.currentScanningValue != null) {
                this.currentScanningValue.setText(String.valueOf(scanning));
            }
        });
    }

    private void clearLog() {
        try {
            this.doc.remove(0, this.doc.getLength());
            this.logEntries = 0;
            // 缓冲区不清的话，窗口一变形就会把刚清掉的内容重排回来
            this.entries.clear();
            this.bufferParagraphs = 0;
            this.logInfo(Msg.t("msg.logCleared"));
        }
        catch (BadLocationException e) {
            System.err.println("[LogPanel] " + e.getMessage());
        }
    }

    private void exportLog() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setSelectedFile(new File("zack-ai-scanner-log.txt"));
        if (fileChooser.showSaveDialog(this) == 0) {
            try {
                File file = fileChooser.getSelectedFile();
                Files.write(file.toPath(), this.logPane.getText().getBytes(StandardCharsets.UTF_8));
                JOptionPane.showMessageDialog(this, Msg.t("msg.logExported", file.getAbsolutePath()));
            }
            catch (Exception e) {
                JOptionPane.showMessageDialog(this, Msg.t("msg.exportFailed", e.getMessage()), Msg.t("dlg.error"), 0);
            }
        }
    }

    /**
     * {@code burp.ITab} 要求的实现，但**这个实例从不作为套件标签页注册**（它是通过
     * {@link #getUiComponent()} 嵌进 MainPanel 的页签里的），Burp 不会调它。
     * 文案仍走 {@link Msg}：万一将来真把它注册成标签页，也不该在界面上留下一句翻不掉的中文。
     */
    public String getTabCaption() {
        return Msg.t("tab.log");
    }

    public Component getUiComponent() {
        return this;
    }
}
