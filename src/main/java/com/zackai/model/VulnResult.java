package com.zackai.model;

import burp.IHttpRequestResponse;

public class VulnResult {
    private String vulnType;
    private String vulnName;
    private ScanTask.VulnLevel level;
    private String description;
    private String payload;
    private IHttpRequestResponse proofRequest;
    private String requestData;
    private String responseData;
    private String aiAnalysis;
    private String aiReport;
    private String tag;

    public VulnResult(String vulnType, String vulnName, ScanTask.VulnLevel level) {
        this.vulnType = vulnType;
        this.vulnName = vulnName;
        this.level = level;
    }

    public String getVulnType() {
        return this.vulnType;
    }

    public void setVulnType(String vulnType) {
        this.vulnType = vulnType;
    }

    public String getVulnName() {
        return this.vulnName;
    }

    public void setVulnName(String vulnName) {
        this.vulnName = vulnName;
    }

    public ScanTask.VulnLevel getLevel() {
        return this.level;
    }

    public void setLevel(ScanTask.VulnLevel level) {
        this.level = level;
    }

    public String getDescription() {
        return this.description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getPayload() {
        return this.payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public IHttpRequestResponse getProofRequest() {
        return this.proofRequest;
    }

    public void setProofRequest(IHttpRequestResponse proofRequest) {
        this.proofRequest = proofRequest;
    }

    public String getRequestData() {
        return this.requestData;
    }

    public void setRequestData(String requestData) {
        this.requestData = requestData;
    }

    public String getResponseData() {
        return this.responseData;
    }

    public void setResponseData(String responseData) {
        this.responseData = responseData;
    }

    public String getAiAnalysis() {
        return this.aiAnalysis;
    }

    public void setAiAnalysis(String aiAnalysis) {
        this.aiAnalysis = aiAnalysis;
    }

    public String getAiReport() {
        return this.aiReport;
    }

    public void setAiReport(String aiReport) {
        this.aiReport = aiReport;
    }

    public String getTag() {
        return this.tag;
    }

    public void setTag(String tag) {
        this.tag = tag;
    }
}

