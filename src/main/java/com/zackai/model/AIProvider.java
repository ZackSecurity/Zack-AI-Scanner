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
package com.zackai.model;

import java.util.ArrayList;
import java.util.List;

public class AIProvider {
    private String name;
    private String apiEndpoint;
    private String modelsEndpoint;
    private int maxTokens;

    public AIProvider(String name, String apiEndpoint, String modelsEndpoint, int maxTokens) {
        this.name = name;
        this.apiEndpoint = apiEndpoint;
        this.modelsEndpoint = modelsEndpoint;
        this.maxTokens = maxTokens;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getApiEndpoint() {
        return this.apiEndpoint;
    }

    public void setApiEndpoint(String apiEndpoint) {
        this.apiEndpoint = apiEndpoint;
    }

    public String getModelsEndpoint() {
        return this.modelsEndpoint;
    }

    public void setModelsEndpoint(String modelsEndpoint) {
        this.modelsEndpoint = modelsEndpoint;
    }

    public int getMaxTokens() {
        return this.maxTokens;
    }

    public String toString() {
        return this.name;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || this.getClass() != obj.getClass()) {
            return false;
        }
        AIProvider that = (AIProvider)obj;
        if (this.name == null && that.name == null) {
            return true;
        }
        if (this.name == null || that.name == null) {
            return false;
        }
        return this.name.equals(that.name);
    }

    public int hashCode() {
        return this.name != null ? this.name.hashCode() : 0;
    }

    public static List<AIProvider> getDefaultProviders() {
        ArrayList<AIProvider> providers = new ArrayList<AIProvider>();
        // 两家国际厂商（2026-09-23 加）。地址不是随手抄的，两条硬约束：
        //  * Anthropic 的地址**必须**含 anthropic.com —— AuthHeaders 靠它发 x-api-key +
        //    anthropic-version，buildAIRequest 靠它改发顶层 system 字段（Anthropic 没有 system 角色），
        //    改地址时这两处会一起失灵，而症状是「验证 Key 失败/回答跑偏」，很难往回追；
        //  * OpenAI 走 Bearer + messages[]，和其余厂商同一条路，地址里不能出现 anthropic.com /
        //    openai.azure.com（那会命中另外两条认证分支）。
        providers.add(new AIProvider("ChatGPT (OpenAI)", "https://api.openai.com/v1/chat/completions", "https://api.openai.com/v1/models", 8192));
        providers.add(new AIProvider("Anthropic (Claude)", "https://api.anthropic.com/v1/messages", "https://api.anthropic.com/v1/models", 8192));
        providers.add(new AIProvider("通义千问 (Qwen)", "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions", "https://dashscope.aliyuncs.com/compatible-mode/v1/models", 8192));
        providers.add(new AIProvider("智谱 GLM-5", "https://open.bigmodel.cn/api/paas/v4/chat/completions", "https://open.bigmodel.cn/api/paas/v4/models", 8192));
        providers.add(new AIProvider("Kimi (月之暗面)", "https://api.moonshot.cn/v1/chat/completions", "https://api.moonshot.cn/v1/models", 8192));
        providers.add(new AIProvider("DeepSeek", "https://api.deepseek.com/v1/chat/completions", "https://api.deepseek.com/v1/models", 8192));
        providers.add(new AIProvider("MiniMax", "https://api.minimax.chat/v1/text/chatcompletion_v2", "https://api.minimax.chat/v1/models", 8192));
        providers.add(new AIProvider("自定义", "https://api.example.com/v1/chat/completions", "https://api.example.com/v1/models", 8192));
        return providers;
    }
}

