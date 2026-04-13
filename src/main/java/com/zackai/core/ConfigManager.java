package com.zackai.core;

import burp.IBurpExtenderCallbacks;
import com.zackai.model.AIProvider;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;

public class ConfigManager {
    private static volatile ConfigManager instance;
    private String configPath;
    private Config config;
    private Gson gson = new GsonBuilder().setPrettyPrinting().create();
    private IBurpExtenderCallbacks callbacks;

    private ConfigManager() {
        this.config = new Config();
    }

    public static ConfigManager getInstance() {
        if (instance == null) {
            synchronized (ConfigManager.class) {
                if (instance == null) {
                    instance = new ConfigManager();
                }
            }
        }
        return instance;
    }

    public void init(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        String userHome = System.getProperty("user.home");
        this.configPath = userHome + File.separator + ".zackai_config.json";
        this.loadConfig();
    }

    public void loadConfig() {
        try {
            File file = new File(this.configPath);
            if (file.exists()) {
                String json = new String(Files.readAllBytes(Paths.get(this.configPath, new String[0])), StandardCharsets.UTF_8);
                this.config = this.gson.fromJson(json, Config.class);
                if (this.config == null) {
                    this.config = new Config();
                }
            } else {
                this.config = new Config();
            }
        }
        catch (Exception e) {
            this.config = new Config();
        }
    }

    public void saveConfig() {
        try {
            String json = this.gson.toJson(this.config);
            Files.write(Paths.get(this.configPath, new String[0]), json.getBytes(StandardCharsets.UTF_8), new OpenOption[0]);
        }
        catch (Exception e) {
            if (this.callbacks != null) {
                this.callbacks.printError("\u4fdd\u5b58\u914d\u7f6e\u5931\u8d25: " + e.getMessage());
            }
        }
    }

    public Config getConfig() {
        return this.config;
    }

    public static class Config {
        private String apiKey = "";
        private String apiEndpoint = "https://api.openai.com/v1/chat/completions";
        private String modelsEndpoint = "https://api.openai.com/v1/models";
        private String selectedProvider = "OpenAI";
        private String selectedAgent = "";
        private List<AIProvider> customProviders = new ArrayList<AIProvider>();
        private List<String> availableModels = new ArrayList<String>();
        private String systemPrompt = "";
        private String verifyPrompt = "";

        public String getApiKey() {
            return this.apiKey;
        }

        public void setApiKey(String apiKey) {
            this.apiKey = apiKey;
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

        public String getSelectedProvider() {
            return this.selectedProvider;
        }

        public void setSelectedProvider(String selectedProvider) {
            this.selectedProvider = selectedProvider;
        }

        public String getSelectedAgent() {
            return this.selectedAgent;
        }

        public void setSelectedAgent(String selectedAgent) {
            this.selectedAgent = selectedAgent;
        }

        public List<AIProvider> getCustomProviders() {
            return this.customProviders;
        }

        public void setCustomProviders(List<AIProvider> customProviders) {
            this.customProviders = customProviders;
        }

        public List<String> getAvailableModels() {
            return this.availableModels;
        }

        public void setAvailableModels(List<String> availableModels) {
            this.availableModels = availableModels;
        }

        public List<AIProvider> getAllProviders() {
            ArrayList<AIProvider> all = new ArrayList<AIProvider>(AIProvider.getDefaultProviders());
            if (this.customProviders != null) {
                all.addAll(this.customProviders);
            }
            return all;
        }

        public AIProvider getProviderByName(String name) {
            for (AIProvider provider : this.getAllProviders()) {
                if (!provider.getName().equals(name)) continue;
                return provider;
            }
            return null;
        }

        public String getSystemPrompt() {
            return this.systemPrompt;
        }

        public void setSystemPrompt(String systemPrompt) {
            this.systemPrompt = systemPrompt;
        }

        public String getVerifyPrompt() {
            return this.verifyPrompt;
        }

        public void setVerifyPrompt(String verifyPrompt) {
            this.verifyPrompt = verifyPrompt;
        }
    }
}
