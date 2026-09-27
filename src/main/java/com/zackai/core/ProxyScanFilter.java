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
package com.zackai.core;

import java.util.Locale;

/**
 * Proxy 自动扫描的白名单匹配 —— 纯字符串逻辑，不碰 Burp 接口，所以能离线断言
 * （见 {@code ExtenderHarness.checkProxyAutoScan}）。
 *
 * <p>规则（都写在 {@link #isWhitelisted} 上，别处不要另写一套）：
 * <ul>
 *   <li><b>白名单为空 = 全部放行</b>：勾了自动扫描却没填白名单，就是「扫全部 Proxy 目标」，
 *       这也正是界面上那句「留空 = 全部」的意思；</li>
 *   <li>一项写 {@code example.com} → 匹配它自己**和它的任意子域**（{@code a.b.example.com} 也算），
 *       这是写域名时几乎总是想要的语义；</li>
 *   <li>一项写 {@code example.com:8443} → 只匹配这个 host+端口（写了端口就按精确匹配，不再放子域）；</li>
 *   <li>直接粘一整条 URL、写 {@code *.example.com}、写 FQDN 的结尾点（{@code example.com.}）
 *       都会被归一化成 host，用户不用先自己剪干净。</li>
 * </ul>
 */
public final class ProxyScanFilter {

    private ProxyScanFilter() {
    }

    /** 分隔符：英文/中文逗号、分号、空格、换行、制表符 */
    private static final String SEPARATORS = "[,;，；\\s]+";

    /**
     * @param whitelist 用户填的白名单原文（可为 null / 空 = 全部放行）
     * @param host      请求目标的 host（来自 {@code IHttpService}）
     * @param port      请求目标的端口
     */
    public static boolean isWhitelisted(String whitelist, String host, int port) {
        if (whitelist == null || whitelist.trim().isEmpty()) {
            return true;
        }
        if (host == null || host.trim().isEmpty()) {
            return false;
        }
        String target = host.trim().toLowerCase(Locale.ROOT);
        for (String raw : whitelist.split(SEPARATORS)) {
            String entry = normalize(raw);
            if (entry.isEmpty()) {
                continue;
            }
            if ("*".equals(entry)) {
                return true;                                  // 有人会写 * 当「全部」
            }
            if (entry.indexOf(':') >= 0) {
                if (entry.equals(target + ":" + port)) {
                    return true;                              // 带端口：精确匹配 host:port
                }
            } else if (target.equals(entry) || target.endsWith("." + entry)) {
                return true;                                  // 域名：自身或任意子域
            }
        }
        return false;
    }

    /**
     * 把一项归一成 {@code host} 或 {@code host:port}：
     * 去掉协议、路径、查询串、{@code *.} 前缀、结尾的点（FQDN 写法），并转小写。
     */
    static String normalize(String raw) {
        if (raw == null) {
            return "";
        }
        String s = raw.trim().toLowerCase(Locale.ROOT);
        int scheme = s.indexOf("://");
        if (scheme >= 0) {
            s = s.substring(scheme + 3);
        }
        int slash = s.indexOf('/');
        if (slash >= 0) {
            s = s.substring(0, slash);
        }
        while (s.startsWith("*.")) {
            s = s.substring(2);
        }
        if (s.endsWith(".")) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    /** 归一化后拼成一行，用于日志/界面回显（每项之间用 ", " 连接） */
    public static String describe(String whitelist) {
        if (whitelist == null || whitelist.trim().isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (String raw : whitelist.split(SEPARATORS)) {
            String entry = normalize(raw);
            if (entry.isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(entry);
        }
        return sb.toString();
    }
}
