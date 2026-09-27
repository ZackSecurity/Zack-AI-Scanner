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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Proxy 自动扫描的**去重**记录：同一个请求只扫一次。
 *
 * <p>没有这一步的话，自动扫描就是个放大器 —— 浏览器打开一个页面就是几十个请求，刷新几次、
 * 页面轮询、静态资源重复加载，每一个都会变成一条任务，各自重放请求、发一遍载荷、再逐条调 AI。
 * 用户看到的是几十条一模一样的任务和几十倍的花费。
 *
 * <p>键是 {@code host:port + 方法 + 路径 + 参数名集合}（见 {@link #key}），**参数值与请求头都不参与**：
 * <ul>
 *   <li>请求头里常变的东西（Cookie 轮换、{@code X-Request-Id}、时间戳、Referer）会让同一个接口每次
 *       看起来都是「新请求」，算进去等于没去重；</li>
 *   <li>参数值同理 —— 轮询接口里的时间戳、分页参数、随机 nonce、每次不同的 id，都能让同一个功能点
 *       每次访问都变成一条新任务。用户要的是「这个功能点扫过没有」，不是「这串字节扫过没有」。</li>
 * </ul>
 *
 * <p><b>代价要清楚</b>：{@code ?id=1} 与 {@code ?id=2'} 只算一个请求，先见到的那个值被扫，后面的
 * 不同输入不再各扫一遍（名字不同才算新请求，比如多了一个 {@code uid}）。想按值去重就得回到
 * 「请求体哈希」那套，代价是自动扫描重新变成放大器。
 *
 * <p>参数名由调用方给出（{@code AIEngine.injectableProxyParamNames}，与参数闸门同一份定义）——
 * 这里不自己解析请求体，否则就成了「什么算参数」的第二份实现，迟早和闸门给出不同答案。
 * 解析失败时（{@code names == null}）退回按请求体哈希判重：宁多扫，不漏扫。
 *
 * <p>容量有上限（{@link #MAX_KEYS}）：浏览器挂一天能产生几万个不同请求，无上限的 Set 就是一条
 * 稳定的内存泄漏。超出后丢最老的，被丢掉的请求再出现时会重扫一次 —— 代价可接受。
 */
public final class ProxyScanHistory {

    /** 记住最近多少个请求，超出后淘汰最老的（公开出来是为了让离线自检能断言这个上限） */
    public static final int MAX_KEYS = 5000;

    private static final Map<String, Boolean> SEEN = new LinkedHashMap<String, Boolean>(64, 0.75f, false) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
            return size() > MAX_KEYS;
        }
    };

    private ProxyScanHistory() {
    }

    /**
     * 登记一个请求。
     *
     * @return {@code true} 表示第一次见（该扫），{@code false} 表示重复（跳过）
     */
    public static boolean firstTime(String key) {
        synchronized (SEEN) {
            return SEEN.put(key, Boolean.TRUE) == null;
        }
    }

    /** 重新开一轮（取消再勾上「Proxy 流量自动扫描」时调用），之后同样的请求会重新扫 */
    public static void clear() {
        synchronized (SEEN) {
            SEEN.clear();
        }
    }

    /** 当前记住的请求数（自检用） */
    public static int size() {
        synchronized (SEEN) {
            return SEEN.size();
        }
    }

    /**
     * 去重键：{@code host:port + 方法 + 路径 + 参数名集合}（名字排序去重，值不参与）。
     * 请求头与请求体都不参与（理由见类注释）；请求行按字节原样取（用 ISO-8859-1 是 1:1 映射，
     * 不会因为编码把两个不同的请求行弄成同一个）。
     *
     * <p>参数名排序后再拼：{@code a=1&b=2} 与 {@code b=2&a=1} 是同一个请求形态，不该各扫一遍。
     * 同名出现多次也只算一个（{@code id=1&id=2} 与 {@code id=1} 同键）。
     *
     * @param paramNames 参数形态 {@code 位置:名字}（{@code AIEngine.injectableProxyParamNames} 的返回值 ——
     *                   位置算进去是为了区分「查询串的 id」与「请求体的 id」）；
     *                   为 {@code null} 表示没能解析出参数 —— 那时退回按请求体哈希判重，
     *                   即「解析不了就按老规矩（字节不同就算新请求）」，宁多扫不漏扫
     */
    public static String key(String host, int port, byte[] request, List<String> paramNames) {
        String prefix = host + ":" + port + " ";
        if (request == null || request.length == 0) {
            return prefix + "(empty)";
        }
        String target = methodAndPath(request);
        if (paramNames == null) {
            int firstLineEnd = indexOf(request, (byte) '\n', 0);
            int bodyStart = bodyStart(request, firstLineEnd);
            byte[] body = bodyStart < 0 ? new byte[0] : Arrays.copyOfRange(request, bodyStart, request.length);
            return prefix + target + "\n" + sha256Hex(body);
        }
        Set<String> names = new TreeSet<String>(paramNames);
        return prefix + target + " [" + String.join(",", names) + "]";
    }

    /** 请求行里的「方法 + 路径」：去掉 HTTP 版本号与查询串（查询串里的值不参与判重） */
    private static String methodAndPath(byte[] request) {
        int firstLineEnd = indexOf(request, (byte) '\n', 0);
        int lineLength = firstLineEnd < 0 ? request.length : firstLineEnd;
        String line = new String(request, 0, lineLength, StandardCharsets.ISO_8859_1).trim();
        int version = line.lastIndexOf(" HTTP/");
        if (version > 0) {
            line = line.substring(0, version);
        }
        int query = line.indexOf('?');
        if (query >= 0) {
            line = line.substring(0, query);
        }
        return line;
    }

    /** 请求体起点：请求行之后第一个空行之后（{@code \r\n\r\n} 或 {@code \n\n}）；没有空行就没有请求体 */
    private static int bodyStart(byte[] request, int from) {
        for (int i = Math.max(from, 0); i + 1 < request.length; i++) {
            if (request[i] != '\n') {
                continue;
            }
            if (request[i + 1] == '\n') {
                return i + 2;                                  // \n\n
            }
            if (request[i + 1] == '\r' && i + 2 < request.length && request[i + 2] == '\n') {
                return i + 3;                                  // \n\r\n
            }
        }
        return -1;
    }

    private static int indexOf(byte[] data, byte target, int from) {
        for (int i = from; i < data.length; i++) {
            if (data[i] == target) {
                return i;
            }
        }
        return -1;
    }

    private static String sha256Hex(byte[] data) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 是 JDK 必备算法；真拿不到也不能让自动扫描停下来，退化成内容比较
            return Arrays.toString(data);
        }
    }
}
