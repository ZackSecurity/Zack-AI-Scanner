package com.zackai.model;

import burp.IHttpRequestResponse;

import java.util.ArrayList;
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
    private Date createTime;
    private Date finishTime;
    private List<VulnResult> vulnerabilities;
    private List<ProbeRecord> probeRecords;
    private String errorMessage;
    private String testParams;

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
        this.vulnerabilities = new ArrayList<VulnResult>();
        this.probeRecords = new ArrayList<ProbeRecord>();
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

    public Date getCreateTime() {
        return this.createTime;
    }

    public Date getFinishTime() {
        return this.finishTime;
    }

    public List<VulnResult> getVulnerabilities() {
        return this.vulnerabilities;
    }

    public void addVulnerability(VulnResult vuln) {
        if (vuln == null) return;
        this.vulnerabilities.add(vuln);
        if (vuln.getLevel() != null && this.vulnLevel != null && 
            vuln.getLevel().ordinal() > this.vulnLevel.ordinal()) {
            this.vulnLevel = vuln.getLevel();
        }
    }

    public List<ProbeRecord> getProbeRecords() {
        return this.probeRecords;
    }

    public void addProbeRecord(ProbeRecord record) {
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

    public void setScanMode(ScanMode scanMode) {
        this.scanMode = scanMode == null ? ScanMode.CUSTOM : scanMode;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public String getTestParams() {
        return this.testParams != null ? this.testParams : "";
    }

    public void setTestParams(String testParams) {
        this.testParams = testParams != null ? testParams : "";
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
        COMMAND_INJECTION("命令执行", "COMMAND_INJECTION"),
        SSTI("SSTI模板注入", "SSTI"),
        SQL_INJECTION("SQL注入", "SQL_INJECTION"),
        XSS("XSS", "XSS"),
        SSRF("SSRF", "SSRF"),
        XXE("XXE", "XXE"),
        FILE_INCLUDE("文件包含", "FILE_INCLUDE"),
        CSRF("CSRF", "CSRF"),
        DESERIALIZATION("反序列化", "DESERIALIZATION"),
        AUTH_BYPASS("越权/IDOR", "AUTH_BYPASS"),
        PATH_TRAVERSAL("路径遍历", "PATH_TRAVERSAL"),
        DIRECTORY_TRAVERSAL("目录穿越", "DIRECTORY_TRAVERSAL"),
        SENSITIVE_DATA_EXPOSURE("敏感信息泄露", "SENSITIVE_DATA_EXPOSURE"),
        LOGIC_FLAW("逻辑漏洞", "LOGIC_FLAW"),
        RACE_CONDITION("条件竞争", "RACE_CONDITION"),
        TYPE_CONFUSION("类型混淆", "TYPE_CONFUSION"),
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

        public int getIndex() {
            return this.index;
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

        public String getDisplayText() {
            String safeType = this.vulnType == null ? "UNKNOWN" : this.vulnType;
            String safePosition = this.position == null ? "auto" : this.position;
            return "#" + this.index + " | " + safeType + " | 参数: " + safePosition;
        }
    }
}
