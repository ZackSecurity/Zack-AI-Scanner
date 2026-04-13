package com.zackai.model;

import java.util.ArrayList;
import java.util.List;

public class AIProvider {
    private String name;
    private String apiEndpoint;
    private String modelsEndpoint;
    private String authType;
    private boolean isCustom;

    public AIProvider(String name, String apiEndpoint, String modelsEndpoint, String authType) {
        this.name = name;
        this.apiEndpoint = apiEndpoint;
        this.modelsEndpoint = modelsEndpoint;
        this.authType = authType;
        this.isCustom = false;
    }

    public AIProvider(String name, String apiEndpoint, String modelsEndpoint, String authType, boolean isCustom) {
        this.name = name;
        this.apiEndpoint = apiEndpoint;
        this.modelsEndpoint = modelsEndpoint;
        this.authType = authType;
        this.isCustom = isCustom;
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

    public String getAuthType() {
        return this.authType;
    }

    public void setAuthType(String authType) {
        this.authType = authType;
    }

    public boolean isCustom() {
        return this.isCustom;
    }

    public void setCustom(boolean custom) {
        this.isCustom = custom;
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
        providers.add(new AIProvider("OpenAI", "https://api.openai.com/v1/chat/completions", "https://api.openai.com/v1/models", "bearer"));
        providers.add(new AIProvider("Anthropic (Claude)", "https://api.anthropic.com/v1/messages", "https://api.anthropic.com/v1/models", "x-api-key"));
        providers.add(new AIProvider("Google Gemini", "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent", "https://generativelanguage.googleapis.com/v1/models", "bearer"));
        providers.add(new AIProvider("Azure OpenAI", "https://YOUR_RESOURCE.openai.azure.com/openai/deployments/YOUR_DEPLOYMENT/chat/completions?api-version=2023-05-15", "https://YOUR_RESOURCE.openai.azure.com/openai/models?api-version=2023-05-15", "api-key"));
        providers.add(new AIProvider("\u901a\u4e49\u5343\u95ee", "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions", "https://dashscope.aliyuncs.com/compatible-mode/v1/models", "bearer"));
        providers.add(new AIProvider("\u6587\u5fc3\u4e00\u8a00", "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/completions", "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/models", "bearer"));
        providers.add(new AIProvider("\u667a\u8c31AI (GLM)", "https://open.bigmodel.cn/api/paas/v4/chat/completions", "https://open.bigmodel.cn/api/paas/v4/models", "bearer"));
        providers.add(new AIProvider("Kimi (\u6708\u4e4b\u6697\u9762)", "https://api.moonshot.cn/v1/chat/completions", "https://api.moonshot.cn/v1/models", "bearer"));
        providers.add(new AIProvider("DeepSeek", "https://api.deepseek.com/v1/chat/completions", "https://api.deepseek.com/v1/models", "bearer"));
        providers.add(new AIProvider("\u8baf\u98de\u661f\u706b", "https://spark-api.xf-yun.com/v1/chat/completions", "https://spark-api.xf-yun.com/v1/models", "bearer"));
        providers.add(new AIProvider("\u5b57\u8282\u8c46\u5305", "https://ark.cn-beijing.volces.com/api/v3/chat/completions", "https://ark.cn-beijing.volces.com/api/v3/models", "bearer"));
        providers.add(new AIProvider("\u817e\u8baf\u6df7\u5143", "https://api.hunyuan.cloud.tencent.com/v1/chat/completions", "https://api.hunyuan.cloud.tencent.com/v1/models", "bearer"));
        providers.add(new AIProvider("\u767e\u5ddd\u667a\u80fd", "https://api.baichuan-ai.com/v1/chat/completions", "https://api.baichuan-ai.com/v1/models", "bearer"));
        providers.add(new AIProvider("MiniMax", "https://api.minimax.chat/v1/text/chatcompletion_v2", "https://api.minimax.chat/v1/models", "bearer"));
        providers.add(new AIProvider("\u96f6\u4e00\u4e07\u7269", "https://api.lingyiwanwu.com/v1/chat/completions", "https://api.lingyiwanwu.com/v1/models", "bearer"));
        providers.add(new AIProvider("\u9636\u8dc3\u661f\u8fb0", "https://api.stepfun.com/v1/chat/completions", "https://api.stepfun.com/v1/models", "bearer"));
        return providers;
    }
}

