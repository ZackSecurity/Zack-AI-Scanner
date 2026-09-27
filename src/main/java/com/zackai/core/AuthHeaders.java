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

import okhttp3.Request;

/**
 * 各家 AI 服务商的鉴权头 —— **唯一**的一份实现。
 *
 * <p>为什么要单独一个类：这套 endpoint → 鉴权头的判断以前在四个地方各写一遍
 * （{@link AIEngine} 的调用、主界面的自动验证、配置对话框的「验证 Key」与「获取模型」），
 * 而且已经漂移：配置对话框的「获取模型」恒发 {@code Authorization: Bearer}，
 * 于是 Anthropic（要 x-api-key + anthropic-version）和 Azure（要 api-key）端点上
 * 「验证 Key」成功、「获取模型」必然失败；主界面的自动验证又只认 Anthropic 一种，
 * Azure 配置保存后主界面显示「API Key: 不可用」，用户去查一个并不存在的问题。
 *
 * <p>新增服务商只改这里一处；判断口径是 endpoint 子串匹配（与服务商自身的地址绑定，
 * 不依赖用户填哪个 provider 名字）。
 */
public final class AuthHeaders {

    private AuthHeaders() {
    }

    /**
     * 按 endpoint 给请求加上鉴权头，以及个别服务商要求的版本头。
     *
     * @param builder  待发请求
     * @param endpoint AI 接口地址（apiEndpoint）；为空时按通用 Bearer 处理
     * @param apiKey   API Key
     */
    public static void apply(Request.Builder builder, String endpoint, String apiKey) {
        if (builder == null) {
            return;
        }
        if (endpoint == null || endpoint.isEmpty()) {
            builder.addHeader("Authorization", "Bearer " + apiKey);
            return;
        }
        String lower = endpoint.toLowerCase(Locale.ROOT);
        if (lower.contains("anthropic.com")) {
            builder.addHeader("x-api-key", apiKey);
            builder.addHeader("anthropic-version", "2023-06-01");
            return;
        }
        if (lower.contains("openai.azure.com")) {
            builder.addHeader("api-key", apiKey);
            return;
        }
        if (lower.contains("cohere.ai") || lower.contains("cohere.com")) {
            builder.addHeader("Authorization", "Bearer " + apiKey);
            builder.addHeader("Cohere-Version", "2022-12-06");
            return;
        }
        // 其余厂商（OpenAI 兼容：deepseek / dashscope / moonshot / googleapis / 自建网关……）
        // 一律 Bearer
        builder.addHeader("Authorization", "Bearer " + apiKey);
    }
}
