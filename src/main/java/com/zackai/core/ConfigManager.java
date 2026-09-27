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

import com.zackai.i18n.Msg;
import burp.IBurpExtenderCallbacks;
import com.zackai.model.AIProvider;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import java.util.ArrayList;
import java.util.List;

public class ConfigManager {
    /**
     * 配置文件名（放在用户主目录下，明文 API Key，权限 0600）。
     *
     * <p>**public 是给离线自检用的**：{@code ExtenderHarness.disableOob()} 必须往同一个路径写配置，
     * 否则插件加载时会走「外带默认开启」那条真会联网的路径。两边各写一份字面量迟早会漂移 ——
     * 漂移的后果是自检静默失效并且真的发网络请求，所以这里只留一个来源。
     */
    public static final String CONFIG_FILE_NAME = ".zack-ai-scanner-config.json";

    private static volatile ConfigManager instance;
    private String configPath;
    private Config config;
    private Gson gson = new GsonBuilder().setPrettyPrinting().create();
    private IBurpExtenderCallbacks callbacks;
    private static volatile com.zackai.ui.LogPanel logPanel;

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

    public static void setLogPanel(com.zackai.ui.LogPanel panel) {
        ConfigManager.logPanel = panel;
    }

    public void init(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        String userHome = System.getProperty("user.home");
        this.configPath = userHome + File.separator + CONFIG_FILE_NAME;
        this.loadConfig();
    }

    /**
     * 读配置。解析失败**不能静默清空**：以前直接换成 new Config()，于是一次半截写入
     * （保存不是原子的，进程被杀/磁盘满都会留下坏 JSON）或用户手改错一个字符，
     * 下次启动就把 API Key、服务商与模型的选择悄悄清光，再下次保存直接坐实。
     * 现在的做法：把坏文件改名备份 + 明确报警，用户至少知道发生了什么、还能捞回原文件。
     */
    public void loadConfig() {
        try {
            File file = new File(this.configPath);
            if (!file.exists()) {
                this.config = new Config();
                return;
            }
            String json = new String(Files.readAllBytes(Paths.get(this.configPath)), StandardCharsets.UTF_8);
            Config loaded = this.gson.fromJson(json, Config.class);
            if (loaded == null) {
                throw new IllegalStateException(Msg.t("logcfg.parseEmpty"));
            }
            this.config = loaded;
        }
        catch (Exception e) {
            this.config = new Config();
            String backup = this.configPath + ".corrupt";
            String detail;
            try {
                Files.move(Paths.get(this.configPath), Paths.get(backup));
                detail = Msg.t("logcfg.backedUp", backup);
            }
            catch (Exception moveEx) {
                detail = Msg.t("logcfg.backupFailed", moveEx.getClass().getSimpleName());
            }
            String message = Msg.t("logcfg.corrupt", this.configPath, detail, e.getClass().getSimpleName() + " - " + e.getMessage());
            if (this.callbacks != null) {
                this.callbacks.printError(message);
            }
            if (logPanel != null) {
                logPanel.logError(message);
            }
        }
    }

    /**
     * 保存配置：先写临时文件再原子改名（避免"写一半被杀"留下坏 JSON），
     * 并把文件权限收紧到仅本人可读写 —— 里面是明文 API Key。
     */
    public void saveConfig() {
        try {
            String json = this.gson.toJson(this.config);
            java.nio.file.Path target = Paths.get(this.configPath);
            java.nio.file.Path tmp = Paths.get(this.configPath + ".tmp");
            Files.write(tmp, json.getBytes(StandardCharsets.UTF_8));
            try {
                java.util.Set<java.nio.file.attribute.PosixFilePermission> perms =
                        java.util.EnumSet.of(java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE);
                Files.setPosixFilePermissions(tmp, perms);
            }
            catch (UnsupportedOperationException | java.io.IOException ignored) {
                // 非 POSIX 文件系统（Windows）：权限交给系统默认值
            }
            try {
                Files.move(tmp, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            }
            catch (java.nio.file.AtomicMoveNotSupportedException notAtomic) {
                Files.move(tmp, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
        }
        catch (Exception e) {
            if (this.callbacks != null) {
                this.callbacks.printError(Msg.t("logcfg.saveFailed", this.configPath, e.getClass().getSimpleName() + " - " + e.getMessage()));
            }
            if (logPanel != null) {
                logPanel.logError(Msg.t("logcfg.saveFailedShort"), e);
            }
        }
    }

    public Config getConfig() {
        return this.config;
    }

    public static class Config {
        private String apiKey = "";
        private String apiEndpoint = "";
        private String modelsEndpoint = "";
        private String selectedProvider = "";
        private String selectedAgent = "";
        private boolean verified = false;
        /**
         * 外带回连检测开关（v3.0 加回，见 OASTClient）。
         *
         * <p>用**装箱 Boolean 且默认 TRUE**，并且**故意不复用**历史上的 {@code oastEnabled} 键名：
         * Gson 只覆盖 JSON 里出现的键，所以
         * <ul>
         *   <li>旧配置文件（只有 {@code oastEnabled}）读进来后这个字段保持 true —— 外带默认开，
         *       不会出现「老文件里一个 false 让外带静默失效、只能删文件才能恢复」那种老问题；</li>
         *   <li>新写入的 {@code oobEnabled: false} 是用户主动关的，界面上也有勾选框可以随时勾回来。</li>
         * </ul>
         * 服务地址与基础域名仍是 OASTClient 里的代码默认值（不做成配置项）。
         */
        private Boolean oobEnabled = Boolean.TRUE;

        /**
         * Proxy 流量自动扫描（默认**关闭**）。
         *
         * <p>默认必须是关：打开后每条经过代理的**请求**都会新建一条扫描任务，而一条任务 =
         * 重放一次 + 每条参数 9 个载荷 + 逐条 AI 验证。老配置文件里没有这个键，
         * 若按「开」处理，用户升级后随手开个浏览器就在不知情的情况下对着目标打了几百发。
         * 这里用基本类型 boolean（缺键即 false）正是为了这个默认值。
         */
        private boolean autoScanProxy = false;

        /**
         * 自动扫描白名单：逗号/空格/换行分隔，留空 = 全部 Proxy 目标。
         * 只在 {@link #autoScanProxy} 为真时生效（匹配规则见 {@link ProxyScanFilter}）。
         */
        private String autoScanWhitelist = "";

        /**
         * 界面语言：{@code ""} = 用户没选过（跟随操作系统语言）、{@code "en"} / {@code "zh"} = 显式选择。
         *
         * <p>空串正是 String 的零值，所以老配置文件里没有这个键时 Gson 会保留字段初始化值，
         * 不需要像 {@link #oobEnabled} 那样用装箱类型兜底 —— 「缺键 = 未选择」本来就是想要的语义。
         * 语言只影响显示（界面/日志/报告），**AI 提示词与数据层字符串始终是中文**（见 {@code i18n.Msg}）。
         */
        private String uiLanguage = "";

        public boolean isAutoScanProxy() {
            return this.autoScanProxy;
        }

        public void setAutoScanProxy(boolean autoScanProxy) {
            this.autoScanProxy = autoScanProxy;
        }

        public String getAutoScanWhitelist() {
            return this.autoScanWhitelist;
        }

        public void setAutoScanWhitelist(String autoScanWhitelist) {
            this.autoScanWhitelist = autoScanWhitelist;
        }

        /** 界面语言配置值；null 或空 = 跟随操作系统语言（手改过的配置文件可能写成 null） */
        public String getUiLanguage() {
            return this.uiLanguage == null ? "" : this.uiLanguage;
        }

        public void setUiLanguage(String uiLanguage) {
            this.uiLanguage = uiLanguage == null ? "" : uiLanguage;
        }

        public boolean isVerified() {
            return this.verified;
        }

        /** 外带回连检测是否启用；配置里没写过这个键时按**启用**处理（见字段注释） */
        public boolean isOobEnabled() {
            return this.oobEnabled == null || this.oobEnabled;
        }

        public void setOobEnabled(boolean oobEnabled) {
            this.oobEnabled = Boolean.valueOf(oobEnabled);
        }

        public void setVerified(boolean verified) {
            this.verified = verified;
        }

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

        public List<AIProvider> getAllProviders() {
            return new ArrayList<AIProvider>(AIProvider.getDefaultProviders());
        }

        public AIProvider getProviderByName(String name) {
            if (name == null) return null;
            for (AIProvider provider : this.getAllProviders()) {
                // 自定义服务商来自用户可编辑的 JSON，缺 name 键时 getName() 为 null —— 直接 .equals 会 NPE，
                // 异常冒到 AI 调用处就是一个载荷失去判定机会
                if (provider == null || !name.equals(provider.getName())) continue;
                return provider;
            }
            return null;
        }
    }
}
