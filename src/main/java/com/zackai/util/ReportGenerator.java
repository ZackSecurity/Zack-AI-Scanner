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
package com.zackai.util;

import com.zackai.i18n.Msg;
import com.zackai.model.ScanTask;
import com.zackai.model.VulnResult;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;

public class ReportGenerator {
    public static void generateReport(ScanTask task, String outputPath) throws IOException {
        StringBuilder html = new StringBuilder();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        html.append("<!DOCTYPE html>\n");
        html.append("<html lang=\"").append(Msg.isEn() ? "en" : "zh-CN").append("\">\n");
        html.append("<head>\n");
        html.append("<meta charset=\"UTF-8\">\n");
        html.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        // 开标签不能少：只有 </title> 时浏览器会把这段文字并进正文，报告顶部就多出一行
        // 「Zack-AI-Scanner 漏洞报告 #N」——不报错，只是在页面上多一行字。
        html.append("<title>").append(Msg.t("report.html.title")).append(" #").append(task.getId())
                .append("</title>\n");
        html.append("<style>").append(getCSS()).append("</style>\n");
        html.append("</head>\n<body>\n");
        html.append("<div class=\"container\">\n");
        html.append("<header class=\"header\">\n");
        html.append(Msg.t("report.html.h1"));
        html.append(Msg.t("report.html.meta") + " ").append(sdf.format(new Date())).append("</p>\n");
        html.append("</header>\n");

        html.append("<section class=\"card\">\n");
        html.append(Msg.t("report.html.taskInfo"));
        html.append("<table class=\"info-table\">\n");
        appendInfoRow(html, Msg.t("report.label.taskId"), "#" + task.getId());
        appendInfoRow(html, Msg.t("report.label.method"), task.getMethod());
        appendInfoRow(html, Msg.t("report.label.url"), task.getUrl());
        appendInfoRow(html, Msg.t("report.label.testedParams"), testedParamsOf(task));
        appendInfoRow(html, Msg.t("report.label.vulnCount"), String.valueOf(task.getVulnerabilities().size()));
        appendInfoRow(html, Msg.t("report.label.risk"), Msg.levelName(task.getVulnLevel()));
        appendInfoRow(html, Msg.t("report.label.aiTag"), Msg.displayAiTag(task.getAiTag()));
        appendInfoRow(html, Msg.t("report.label.created"), task.getCreateTime() == null ? "" : sdf.format(task.getCreateTime()));
        appendInfoRow(html, Msg.t("report.label.finished"), task.getFinishTime() == null ? "" : sdf.format(task.getFinishTime()));
        html.append("</table>\n");
        html.append("</section>\n");

        if (task.getVulnerabilities().isEmpty()) {
            html.append(Msg.t("report.html.noVuln")).append("\n");
        } else {
            int index = 1;
            for (VulnResult vuln : task.getVulnerabilities()) {
                html.append("<section class=\"card vuln-section\">\n");
                html.append("<h2>").append(Msg.t("report.html.vulnHeading", index++,
                        escapeHtml(Msg.typeNameOf(vuln.getVulnName())))).append("</h2>\n");
                html.append("<p class=\"risk\">").append(Msg.t("report.html.riskLine",
                        escapeHtml(vuln.getLevel() == null ? Msg.t("report.unknown") : Msg.levelName(vuln.getLevel())),
                        escapeHtml(vuln.getVulnType() == null ? Msg.t("report.unknown") : Msg.typeNameOf(vuln.getVulnType())),
                        escapeHtml(vuln.getPosition() == null ? Msg.t("report.unknown") : vuln.getPosition()))).append("</p>\n");

                html.append(Msg.t("report.html.payload") + "\n");
                html.append("<pre class=\"payload\">").append(escapeHtml(vuln.getPayload() == null ? Msg.t("report.notRecorded") : vuln.getPayload())).append("</pre>\n");

                html.append(Msg.t("report.html.evidence") + "\n");
                html.append("<p class=\"description\">").append(escapeHtml(vuln.getDescription() == null ? Msg.t("report.none") : vuln.getDescription())).append("</p>\n");

                html.append(Msg.t("report.html.request") + "\n");
                appendFoldableBlock(html, Msg.t("report.clickToToggle"), vuln.getRequestData());

                html.append(Msg.t("report.html.response") + "\n");
                appendFoldableBlock(html, Msg.t("report.clickToToggle"), vuln.getResponseData());

                html.append(Msg.t("report.html.fixes") + "\n");
                html.append("<ul class=\"fix-list\">\n");
                String fixSuggestions = getFixSuggestionsHtml(vuln.getVulnType());
                html.append(fixSuggestions);
                html.append("</ul>\n");

                html.append("<hr class=\"vuln-divider\">\n");
                html.append("</section>\n");
            }
        }

        html.append("</div>\n</body>\n</html>");
        try (FileWriter writer = new FileWriter(outputPath, StandardCharsets.UTF_8)) {
            writer.write(html.toString());
        }
    }

    public static void generateMarkdownReport(ScanTask task, String outputPath) throws IOException {
        StringBuilder md = new StringBuilder();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        md.append(Msg.t("report.md.title"));
        md.append(Msg.t("report.md.version"));
        md.append(Msg.t("report.md.taskId")).append(task.getId()).append("\n");
        md.append(Msg.t("report.md.url")).append(task.getUrl()).append("\n");
        md.append(Msg.t("report.md.method")).append(task.getMethod()).append("\n");
        md.append(Msg.t("report.md.testedParams")).append(testedParamsOf(task)).append("\n");
        md.append(Msg.t("report.md.risk")).append(Msg.levelName(task.getVulnLevel())).append("\n");
        md.append(Msg.t("report.md.generated")).append(sdf.format(new Date())).append("\n\n");

        if (task.getVulnerabilities().isEmpty()) {
            md.append(Msg.t("report.md.noVuln"));
        } else {
            int index = 1;
            for (VulnResult vuln : task.getVulnerabilities()) {
                md.append(Msg.t("report.md.vulnHeading", index++, oneLine(Msg.typeNameOf(vuln.getVulnName())))).append("\n\n");
                md.append(Msg.t("report.md.type")).append(oneLine(Msg.typeNameOf(vuln.getVulnType()))).append("\n");
                md.append(Msg.t("report.md.level")).append(vuln.getLevel() == null ? Msg.t("report.unknown") : Msg.levelName(vuln.getLevel())).append("\n");
                md.append(Msg.t("report.md.position")).append(oneLine(vuln.getPosition())).append("\n\n");

                md.append(Msg.t("report.md.payload"));
                md.append(fencedBlock("", vuln.getPayload()));

                md.append(Msg.t("report.md.evidence"));
                md.append(oneLine(vuln.getDescription())).append("\n\n");

                md.append(Msg.t("report.md.request"));
                md.append(fencedBlock("http", vuln.getRequestData()));

                md.append(Msg.t("report.md.response"));
                md.append(fencedBlock("http", vuln.getResponseData()));

                md.append(Msg.t("report.md.fixes"));
                md.append(getFixSuggestionsMarkdown(vuln.getVulnType()));

                md.append("---\n\n");
            }
        }
        Files.write(Paths.get(outputPath), md.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Markdown 代码块：围栏长度按内容里最长的一串反引号动态加一。
     *
     * <p>原来固定写 ``` ：被扫目标只要在响应体里回一行 ``` 就能提前闭合围栏，
     * 后面跟的任意 Markdown/HTML 会被当成报告正文渲染（伪造漏洞条目、钓鱼链接都做得到），
     * 而这段内容完全来自被扫目标。CommonMark 规定闭合围栏不得短于开启围栏，
     * 所以「比内容里最长的一串反引号再长一个」是可靠的写法。
     */
    private static String fencedBlock(String info, String content) {
        String body = content == null || content.isEmpty() ? Msg.t("report.notRecorded") : content;
        int longest = 0;
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("`+").matcher(body);
        while (m.find()) {
            longest = Math.max(longest, m.group().length());
        }
        String fence = "`".repeat(Math.max(3, longest + 1));
        return fence + (info == null ? "" : info) + "\n" + body + (body.endsWith("\n") ? "" : "\n") + fence + "\n\n";
    }

    /** 单行字段：去掉换行，避免把内容顶到新的一行去伪造标题/列表 */
    private static String oneLine(String text) {
        if (text == null || text.isEmpty()) {
            return Msg.t("report.notRecorded");
        }
        return text.replace("\r\n", " ").replace('\n', ' ').replace('\r', ' ');
    }

    /**
     * 报告里的「测试参数」= {@link ScanTask#getTestParams()}，也就是**真正发出过载荷的位置**
     * （由 AIEngine 的载荷循环写入，不是 Burp 报上来的候选参数列表）。
     *
     * <p>空表示本次一个载荷都没发出去（step2 判定没有值得测的参数、step3 生成失败、或全被过滤）。
     * 这种情况以前会退化成显示候选参数列表 —— 读起来像是每个参数都测过了。写清楚更好。
     */
    static String testedParamsOf(ScanTask task) {
        String tested = task.getTestParams() == null ? "" : task.getTestParams().trim();
        return tested.isEmpty() ? Msg.t("report.noPayloadsSent") : tested;
    }

    private static void appendInfoRow(StringBuilder html, String key, String value) {
        html.append("<tr><td class=\"label\">").append(escapeHtml(key)).append("</td><td>").append(escapeHtml(value == null ? "" : value)).append("</td></tr>\n");
    }

    private static void appendFoldableBlock(StringBuilder html, String title, String content) {
        String finalContent = content == null || content.trim().isEmpty() ? Msg.t("report.notRecorded") : content;
        html.append("<details class=\"fold\">\n");
        html.append("<summary>").append(escapeHtml(title)).append("</summary>\n");
        html.append("<pre>").append(escapeHtml(finalContent)).append("</pre>\n");
        html.append("</details>\n");
    }

    private static String getCSS() {
        return "*{box-sizing:border-box;}"
                + "body{margin:0;background:#f7f8fa;color:#1f2937;font:14px/1.7 'Microsoft YaHei',sans-serif;}"
                + ".container{max-width:1080px;margin:20px auto;padding:0 16px;}"
                + ".header{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:18px 20px;margin-bottom:14px;}"
                + ".header h1{margin:0 0 4px 0;font-size:24px;}"
                + ".meta{margin:0;color:#6b7280;}"
                + ".card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px 18px;margin-bottom:12px;}"
                + ".vuln-section h2{margin:0 0 8px 0;font-size:20px;color:#1f2937;}"
                + ".vuln-section h3{margin:16px 0 8px 0;font-size:16px;color:#374151;border-bottom:1px solid #e5e7eb;padding-bottom:4px;}"
                + ".risk{font-weight:600;color:#dc2626;margin:0 0 12px 0;}"
                + ".info-table{width:100%;border-collapse:collapse;}"
                + ".info-table td{border:1px solid #e5e7eb;padding:8px 10px;vertical-align:top;}"
                + ".info-table .label{background:#f9fafb;width:160px;font-weight:600;}"
                + ".fix-list{margin:8px 0;padding-left:20px;}"
                + ".fix-list li{margin:6px 0;color:#374151;line-height:1.6;}"
                + "pre{margin:8px 0 0 0;background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px;padding:10px;white-space:pre-wrap;word-break:break-word;}"
                + "pre.payload{background:#1f2937;color:#f9fafb;border-color:#374151;}"
                + ".description{margin:8px 0;color:#374151;line-height:1.6;}"
                + ".fold{margin-top:8px;border:1px solid #e5e7eb;border-radius:8px;padding:8px;background:#fff;}"
                + ".fold>summary{cursor:pointer;font-weight:600;color:#374151;}"
                + ".fold>pre{margin:8px 0 0 0;background:#f8fafc;}"
                + ".vuln-divider{margin:20px 0 0 0;border:none;border-top:1px solid #e5e7eb;}";
    }

    private static String escapeHtml(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }

    /**
     * 某个类型的修复建议。
     *
     * <p>内容（中英两版）统一放在 {@link Msg} 的 {@code fix.<TYPE_KEY>.<n>} 里，
     * 按序号逐个查到缺号为止 —— 不用维护「每类几条」的计数，加一条建议只改文案表。
     * 仍然沿用原来的返回形状（{@code [0]} 是类型 key，后面是建议），两个调用点不用改。
     */
    private static String[] getFixSuggestions(String vulnType) {
        if (vulnType == null) return null;
        String key = normalizeVulnTypeKey(vulnType);
        java.util.List<String> found = new java.util.ArrayList<String>();
        for (int i = 1; Msg.has("fix." + key + "." + i); i++) {
            found.add(Msg.t("fix." + key + "." + i));
        }
        if (found.isEmpty()) {
            return null;
        }
        String[] out = new String[found.size() + 1];
        out[0] = key;
        for (int i = 0; i < found.size(); i++) {
            out[i + 1] = found.get(i);
        }
        return out;
    }

    private static String getFixSuggestionsHtml(String vulnType) {
        String[] suggestions = getFixSuggestions(vulnType);
        if (suggestions == null) {
            return Msg.t("report.fix.genericHtml");
        }
        StringBuilder html = new StringBuilder();
        for (int i = 1; i < suggestions.length; i++) {
            html.append("<li>").append(escapeHtml(suggestions[i])).append("</li>");
        }
        return html.toString();
    }

    private static String getFixSuggestionsMarkdown(String vulnType) {
        String[] suggestions = getFixSuggestions(vulnType);
        if (suggestions == null) {
            return Msg.t("report.fix.genericMd");
        }
        StringBuilder md = new StringBuilder();
        for (int i = 1; i < suggestions.length; i++) {
            md.append("- ").append(suggestions[i]).append("\n");
        }
        return md.toString();
    }


    
    private static String normalizeVulnTypeKey(String vulnType) {
        if (vulnType == null) return "";
        // Locale.ROOT：tr_TR 之类的默认 Locale 会把 "sql_injection" 转成 "SQL_İNJECTİON"，
        // 匹配不上就静默退化成通用修复建议
        String upper = vulnType.toUpperCase(java.util.Locale.ROOT);
        if (upper.equals("SQL注入") || upper.equals("SQL_INJECTION")) return "SQL_INJECTION";
        if (upper.equals("XSS") || upper.equals("XSS跨站脚本")) return "XSS";
        if (upper.equals("命令注入") || upper.equals("COMMAND_INJECTION") || upper.equals("RCE")) return "COMMAND_INJECTION";
        if (upper.equals("文件上传") || upper.equals("FILE_UPLOAD")) return "FILE_UPLOAD";
        if (upper.equals("SSRF") || upper.equals("SSRF服务端请求伪造")) return "SSRF";
        if (upper.equals("XXE") || upper.equals("XXE外部实体注入")) return "XXE";
        if (upper.equals("SSTI") || upper.equals("SSTI服务端模板注入") || upper.equals("服务端模板注入")) return "SSTI";
        if (upper.equals("FASTJSON") || upper.equals("FASTJSON反序列化") || upper.equals("FASTJSON_DESERIALIZE")
                || upper.equals("FASTJSON DESERIALIZE")) return "FASTJSON";
        if (upper.equals("LOG4J2") || upper.equals("LOG4J") || upper.equals("LOG4J2_JNDI")
                || upper.equals("LOG4J2 JNDI注入") || upper.equals("LOG4J2JNDI")) return "LOG4J2";
        if (upper.equals("STRUTS2") || upper.equals("STRUTS2_OGNL") || upper.equals("STRUTS2 OGNL注入")
                || upper.equals("STRUTS2OGNL")) return "STRUTS2";
        if (upper.equals("SHIRO") || upper.equals("SHIRO反序列化") || upper.equals("SHIRO_DESERIALIZE")
                || upper.equals("SHIRO DESERIALIZE")) return "SHIRO";
        return upper;
    }
}
