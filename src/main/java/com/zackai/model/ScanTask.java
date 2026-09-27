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

import burp.IHttpRequestResponse;

import java.util.Date;
import java.util.List;

public class ScanTask {
    private ScanMode scanMode;
    private int id;
    private String method;
    private String url;
    private TaskStatus status;
    private VulnLevel vulnLevel;
    private String aiTag;
    private String vulnName;
    private IHttpRequestResponse originalRequest;
    private byte[] originalResponseBytes;
    private long originalResponseMillis;
    private String oastHost;
    /** 本次扫描涉及的标准中文漏洞类型，见 getMappedVulnTypes() */
    private volatile java.util.Set<String> mappedVulnTypes;
    private Date createTime;
    private Date finishTime;
    /**
     * 漏洞记录与探针记录都用写时复制列表：写方可能在别的线程（延后的外带验证线程会调
     * addOrMergeVulnerability），而读方在 EDT 上遍历（详情面板每 500ms 刷一次探针列表、
     * 导出时遍历漏洞列表）—— 普通 ArrayList 会抛 ConcurrentModificationException。
     * 写入很少（每条载荷至多一次），读很多，正是它适用的场景。
     */
    private List<VulnResult> vulnerabilities;
    private List<ProbeRecord> probeRecords;
    private String errorMessage;
    private String testParams;
    private volatile boolean isPaused = false;
    private volatile boolean isCancelled = false;

    public ScanTask(int id, IHttpRequestResponse request, String method, String url) {
        this(id, request, method, url, ScanMode.CUSTOM);
    }

    public ScanTask(int id, IHttpRequestResponse request, String method, String url, ScanMode scanMode) {
        this.id = id;
        this.originalRequest = request;
        this.method = method;
        this.url = url;
        this.scanMode = scanMode == null ? ScanMode.CUSTOM : scanMode;
        this.status = TaskStatus.PENDING;
        this.vulnLevel = VulnLevel.NONE;
        this.aiTag = "";
        this.vulnName = "";
        this.testParams = "";
        this.createTime = new Date();
        this.vulnerabilities = new java.util.concurrent.CopyOnWriteArrayList<VulnResult>();
        this.probeRecords = new java.util.concurrent.CopyOnWriteArrayList<ProbeRecord>();
    }

    public int getId() {
        return this.id;
    }

    public String getMethod() {
        return this.method;
    }

    public String getUrl() {
        return this.url;
    }

    public TaskStatus getStatus() {
        return this.status;
    }

    public void setStatus(TaskStatus status) {
        this.status = status;
        if (status == TaskStatus.FINISHED) {
            this.finishTime = new Date();
        }
    }

    public boolean isPaused() {
        return this.isPaused;
    }
    
    public boolean isCancelled() {
        return this.isCancelled;
    }
    
    public void cancel() {
        this.isCancelled = true;
        // 必须同时解除暂停：扫描线程要么停在暂停等待里、要么在下一个载荷开头进入等待，
        // 而等待循环只在 isPaused 为真时转 —— 只置 isCancelled 的话线程会永远卡在那里
        // （「暂停扫描」之后右键「删除任务」就是这个组合，池子 10 个线程耗光后所有扫描都不再执行）
        this.isPaused = false;
        if (this.status == TaskStatus.SCANNING || this.status == TaskStatus.PENDING) {
            this.status = TaskStatus.FINISHED;
        }
    }
    
    public void pause() {
        this.isPaused = true;
        if (this.status == TaskStatus.SCANNING) {
            this.status = TaskStatus.PAUSED;
        }
    }

    public void resume() {
        this.isPaused = false;
        if (this.status == TaskStatus.PAUSED) {
            this.status = TaskStatus.SCANNING;
        }
    }

    public VulnLevel getVulnLevel() {
        return this.vulnLevel;
    }

    public void setVulnLevel(VulnLevel vulnLevel) {
        this.vulnLevel = vulnLevel;
    }

    public String getAiTag() {
        return this.aiTag;
    }

    public void setAiTag(String aiTag) {
        this.aiTag = aiTag;
    }

    public String getVulnName() {
        return this.vulnName;
    }

    public void setVulnName(String vulnName) {
        this.vulnName = vulnName;
    }

    public IHttpRequestResponse getOriginalRequest() {
        return this.originalRequest;
    }

    public void setOriginalResponseBytes(byte[] responseBytes) {
        this.originalResponseBytes = responseBytes;
    }

    public byte[] getOriginalResponseBytes() {
        return this.originalResponseBytes;
    }

    /** 步骤 1 原始请求的响应耗时（毫秒），作为时间盲注判定的基线 */
    public void setOriginalResponseMillis(long millis) {
        this.originalResponseMillis = millis;
    }

    public long getOriginalResponseMillis() {
        return this.originalResponseMillis;
    }

    /** 本次扫描用的回连域名（插件加载时申请、所有任务共用；回连服务不可用时为 null，此时不生成外带类载荷） */
    public void setOastHost(String oastHost) {
        this.oastHost = oastHost;
    }

    public String getOastHost() {
        return this.oastHost;
    }

    /**
     * 本次扫描涉及的标准中文漏洞类型（单漏洞模式就是该模式本身；CUSTOM 模式取自 paramVulnMap）。
     * Step3 的指南与验证特征块都按它裁剪 —— 只发要判的类型，省 token 也少干扰。
     * 由扫描线程在 Step3 之前写好，之后**只读**（延后的外带验证会跨线程读，故为 volatile）。
     */
    public void setMappedVulnTypes(java.util.Set<String> types) {
        this.mappedVulnTypes = types;
    }

    public java.util.Set<String> getMappedVulnTypes() {
        return this.mappedVulnTypes;
    }

    public Date getCreateTime() {
        return this.createTime;
    }

    public Date getFinishTime() {
        return this.finishTime;
    }

    public List<VulnResult> getVulnerabilities() {
        return this.vulnerabilities;
    }

    /**
     * 记一条漏洞，按（参数位置 + 漏洞类型）去重。
     *
     * <p>同一个组合有 9 条载荷，常常好几条都能被确认（例如 4 条 SQL 注入载荷都打通了），
     * 直接逐条 add 会让「漏洞数」虚高成 4 —— 用户看到的是「一个参数上发现了 4 个 SQL 注入」。
     * 这里同一（位置, 类型）只留**置信度最高**的那条，其余算重复确认。
     *
     * @return true 表示这条被记下了（新增或替换了较弱的旧记录）；false 表示已有更强的记录
     */
    public synchronized boolean addOrMergeVulnerability(VulnResult vuln) {
        if (vuln == null) return false;
        String key = findingKey(vuln);
        for (int i = 0; i < this.vulnerabilities.size(); i++) {
            VulnResult existing = this.vulnerabilities.get(i);
            if (existing != null && key.equals(findingKey(existing))) {
                if (vuln.getConfidence() > existing.getConfidence()) {
                    this.vulnerabilities.set(i, vuln);
                    recomputeVulnLevel();
                    return true;
                }
                return false;
            }
        }
        this.vulnerabilities.add(vuln);
        recomputeVulnLevel();
        return true;
    }

    /** 去重键：参数位置（大小写不敏感、剥掉 header: 前缀）+ 规范化后的漏洞名 */
    private static String findingKey(VulnResult vuln) {
        String position = vuln.getPosition() == null ? "" : vuln.getPosition().trim().toLowerCase();
        if (position.startsWith("header:")) {
            position = position.substring(7).trim();
        }
        String name = vuln.getVulnName() != null ? vuln.getVulnName()
                : (vuln.getVulnType() != null ? vuln.getVulnType() : "");
        return position + "|" + name;
    }

    /** 漏洞等级 = 现有记录里最高的那个（替换/去重后重算，避免删掉高等级记录后等级不降） */
    private void recomputeVulnLevel() {
        VulnLevel highest = VulnLevel.NONE;
        for (VulnResult v : this.vulnerabilities) {
            if (v != null && v.getLevel() != null && v.getLevel().ordinal() > highest.ordinal()) {
                highest = v.getLevel();
            }
        }
        this.vulnLevel = highest;
    }

    public List<ProbeRecord> getProbeRecords() {
        return this.probeRecords;
    }

    public synchronized void addProbeRecord(ProbeRecord record) {
        if (record != null) {
            this.probeRecords.add(record);
        }
    }

    public void clearProbeRecords() {
        this.probeRecords.clear();
    }

    public String getErrorMessage() {
        return this.errorMessage;
    }

    public ScanMode getScanMode() {
        return this.scanMode;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public String getTestParams() {
        return this.testParams != null ? this.testParams : "";
    }

    public void setTestParams(String testParams) {
        this.testParams = testParams;
    }

    public static enum VulnLevel {
        NONE("\u65e0\u6f0f\u6d1e"),
        LOW("\u4f4e\u5371"),
        MEDIUM("\u4e2d\u5371"),
        HIGH("\u9ad8\u5371"),
        CRITICAL("\u4e25\u91cd");

        private String displayName;

        private VulnLevel(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return this.displayName;
        }
    }

    public static enum TaskStatus {
        PENDING("\u5f85\u5904\u7406"),
        SCANNING("AI\u667a\u80fd\u6e17\u900f\u4e2d"),
        PAUSED("\u6682\u505c\u4e2d"),
        FINISHED("\u5df2\u7ed3\u675f");

        private String displayName;

        private TaskStatus(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return this.displayName;
        }
    }

    public static enum ScanMode {
        FILE_UPLOAD("文件上传", "FILE_UPLOAD"),
        COMMAND_INJECTION("命令注入", "COMMAND_INJECTION"),
        SSTI("SSTI服务端模板注入", "SSTI"),
        SQL_INJECTION("SQL注入", "SQL_INJECTION"),
        XSS("XSS跨站脚本", "XSS"),
        SSRF("SSRF服务端请求伪造", "SSRF"),
        XXE("XXE外部实体注入", "XXE"),
        FASTJSON("Fastjson反序列化", "FASTJSON"),
        LOG4J2("Log4j2 JNDI注入", "LOG4J2"),
        STRUTS2("Struts2 OGNL注入", "STRUTS2"),
        SHIRO("Shiro反序列化", "SHIRO"),
        CUSTOM("AI智能扫描", "CUSTOM");

        private String displayName;
        private String typeKey;

        private ScanMode(String displayName, String typeKey) {
            this.displayName = displayName;
            this.typeKey = typeKey;
        }

        public String getDisplayName() {
            return this.displayName;
        }

        public String getTypeKey() {
            return this.typeKey;
        }

        public boolean isCustom() {
            return this == CUSTOM;
        }
    }

    public static class ProbeRecord {
        private final int index;
        private final String vulnType;
        private final String payload;
        private final String position;
        private final IHttpRequestResponse message;

        public ProbeRecord(int index, String vulnType, String payload, String position, IHttpRequestResponse message) {
            this.index = index;
            this.vulnType = vulnType;
            this.payload = payload;
            this.position = position;
            this.message = message;
        }

        public String getVulnType() {
            return this.vulnType;
        }

        public String getPayload() {
            return this.payload;
        }

        public String getPosition() {
            return this.position;
        }

        public IHttpRequestResponse getMessage() {
            return this.message;
        }
    }
}
