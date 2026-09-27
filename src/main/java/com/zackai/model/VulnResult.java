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

public class VulnResult {
    private String vulnType;
    private String vulnName;
    private ScanTask.VulnLevel level;
    private String description;
    private String payload;
    private String requestData;
    private String responseData;
    private String tag;
    private String position;
    /** AI 给出的置信度，见 getConfidence() */
    private int confidence;

    public VulnResult(String vulnType, String vulnName, ScanTask.VulnLevel level) {
        this.vulnType = vulnType;
        this.vulnName = vulnName;
        this.level = level;
    }

    public String getVulnType() {
        return this.vulnType;
    }

    public String getVulnName() {
        return this.vulnName;
    }

    public ScanTask.VulnLevel getLevel() {
        return this.level;
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

    public String getTag() {
        return this.tag;
    }

    public void setTag(String tag) {
        this.tag = tag;
    }

    public String getPosition() {
        return this.position;
    }

    public void setPosition(String position) {
        this.position = position;
    }

    /**
     * AI 给出的置信度（0-100）。存下来是为了「同一参数同一类型被多条载荷各自确认」时
     * 能留下证据更强的那一条（见 ScanTask.addOrMergeVulnerability）。
     */
    public int getConfidence() {
        return this.confidence;
    }

    public void setConfidence(int confidence) {
        this.confidence = confidence;
    }
}

