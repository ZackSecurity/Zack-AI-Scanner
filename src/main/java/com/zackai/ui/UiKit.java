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

import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;

/**
 * 统一风格的控件工厂。
 *
 * <p>为什么要有这个类：同一套「浅底 + 灰边 + 悬停变色 + 手型光标」的按钮原来在三个类里各抄了一遍
 * （{@code LogPanel} 110×35 / {@code TaskTablePanel} 100×38 / {@code ExportDialog} 120×40），
 * 配置对话框里那四个按钮更是连悬停效果和手型光标都没有 —— 同一个扩展里按钮手感不一致。
 * 尺寸与字号仍然按调用方给的参数走，保证外观与之前一致。
 */
final class UiKit {

    static final Color PANEL_LIGHT = new Color(245, 247, 250);
    static final Color TEXT_DARK = new Color(33, 37, 41);
    static final Color BORDER_GRAY = new Color(210, 214, 220);
    static final Color HOVER_BG = new Color(233, 236, 239);

    private UiKit() {
    }

    /** 浅底灰边按钮：悬停变深、鼠标变手型 */
    static JButton button(String text, int width, int height, int fontSize) {
        final JButton button = new JButton(text);
        button.setBackground(PANEL_LIGHT);
        button.setForeground(TEXT_DARK);
        button.setBorder(BorderFactory.createLineBorder(BORDER_GRAY, 2));
        button.setFocusPainted(false);
        button.setFont(new Font("微软雅黑", 1, fontSize));
        button.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        button.setPreferredSize(new Dimension(width, height));
        button.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent evt) {
                button.setBackground(HOVER_BG);
            }

            @Override
            public void mouseExited(MouseEvent evt) {
                button.setBackground(PANEL_LIGHT);
            }
        });
        return button;
    }

    /** 与按钮同风格的下拉框 */
    static JComboBox<String> comboBox(String[] items, int width, int height, int fontSize) {
        JComboBox<String> combo = new JComboBox<String>(items);
        combo.setBackground(Color.WHITE);
        combo.setForeground(TEXT_DARK);
        combo.setFont(new Font("微软雅黑", 0, fontSize));
        combo.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER_GRAY, 2),
                BorderFactory.createEmptyBorder(5, 8, 5, 8)));
        combo.setPreferredSize(new Dimension(width, height));
        return combo;
    }
}
