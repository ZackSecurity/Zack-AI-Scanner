package com.zackai.util;

import com.zackai.model.ScanTask;
import com.zackai.model.VulnResult;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;

public class ReportGenerator {
    public static void generateReport(ScanTask task, String outputPath) throws IOException {
        StringBuilder html = new StringBuilder();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        html.append("<!DOCTYPE html>\n");
        html.append("<html lang=\"zh-CN\">\n");
        html.append("<head>\n");
        html.append("<meta charset=\"UTF-8\">\n");
        html.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.append("<title>Zack-AI-Scanner 漏洞报告 #").append(task.getId()).append("</title>\n");
        html.append("<style>").append(getCSS()).append("</style>\n");
        html.append("</head>\n<body>\n");
        html.append("<div class=\"container\">\n");
        html.append("<header class=\"header\">\n");
        html.append("<h1>Zack-AI-Scanner 漏洞报告</h1>\n");
        html.append("<p class=\"meta\">版本 v1.0 | 生成时间 ").append(sdf.format(new Date())).append("</p>\n");
        html.append("</header>\n");

        html.append("<section class=\"card\">\n");
        html.append("<h2>任务信息</h2>\n");
        html.append("<table class=\"info-table\">\n");
        appendInfoRow(html, "任务编号", "#" + task.getId());
        appendInfoRow(html, "请求方法", task.getMethod());
        appendInfoRow(html, "目标 URL", escapeHtml(task.getUrl()));
        appendInfoRow(html, "测试参数", task.getTestParams());
        appendInfoRow(html, "漏洞数量", String.valueOf(task.getVulnerabilities().size()));
        appendInfoRow(html, "综合风险", task.getVulnLevel().getDisplayName());
        appendInfoRow(html, "AI 标签", task.getAiTag() == null ? "" : task.getAiTag());
        appendInfoRow(html, "创建时间", task.getCreateTime() == null ? "" : sdf.format(task.getCreateTime()));
        appendInfoRow(html, "完成时间", task.getFinishTime() == null ? "" : sdf.format(task.getFinishTime()));
        html.append("</table>\n");
        html.append("</section>\n");

        if (task.getVulnerabilities().isEmpty()) {
            html.append("<section class=\"card\"><h2>扫描结论</h2><p>未发现漏洞。</p></section>\n");
        } else {
            int index = 1;
            for (VulnResult vuln : task.getVulnerabilities()) {
                html.append("<section class=\"card vuln-section\">\n");
                html.append("<h2>漏洞 #").append(index++).append(" - ").append(escapeHtml(vuln.getVulnName())).append("</h2>\n");
                html.append("<p class=\"risk\">风险等级：").append(escapeHtml(vuln.getLevel().getDisplayName())).append(" | 漏洞类型：").append(escapeHtml(vuln.getVulnType())).append("</p>\n");

                html.append("<h3>修复建议</h3>\n");
                html.append("<ul class=\"fix-list\">\n");
                String fixSuggestions = getFixSuggestionsHtml(vuln.getVulnType());
                html.append(fixSuggestions);
                html.append("</ul>\n");

                html.append("<h3>测试载荷</h3>\n");
                html.append("<pre class=\"payload\">").append(escapeHtml(vuln.getPayload() == null ? "未记录" : vuln.getPayload())).append("</pre>\n");

                html.append("<h3>响应特征分析</h3>\n");
                html.append("<p class=\"description\">").append(escapeHtml(vuln.getDescription() == null ? "无" : vuln.getDescription())).append("</p>\n");

                html.append("<h3>完整请求包</h3>\n");
                appendFoldableBlock(html, "点击展开/收起", vuln.getRequestData());

                html.append("<h3>完整响应包</h3>\n");
                appendFoldableBlock(html, "点击展开/收起", vuln.getResponseData());

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
        md.append("# Zack-AI-Scanner 漏洞报告\n\n");
        md.append("- 版本: v1.0\n");
        md.append("- 任务编号: #").append(task.getId()).append("\n");
        md.append("- 目标 URL: ").append(task.getUrl()).append("\n");
        md.append("- 请求方法: ").append(task.getMethod()).append("\n");
        md.append("- 测试参数: ").append(task.getTestParams()).append("\n");
        md.append("- 综合风险: ").append(task.getVulnLevel().getDisplayName()).append("\n");
        md.append("- 生成时间: ").append(sdf.format(new Date())).append("\n\n");

        if (task.getVulnerabilities().isEmpty()) {
            md.append("## 扫描结论\n\n未发现漏洞。\n");
        } else {
            int index = 1;
            for (VulnResult vuln : task.getVulnerabilities()) {
                md.append("## 漏洞 #").append(index++).append(" - ").append(vuln.getVulnName()).append("\n\n");
                md.append("- 漏洞类型: ").append(vuln.getVulnType()).append("\n");
                md.append("- 风险等级: ").append(vuln.getLevel().getDisplayName()).append("\n\n");

                md.append("### 修复建议\n\n");
                md.append(getMarkdownFixSuggestions(vuln.getVulnType()));

                md.append("### 测试载荷\n\n");
                md.append("```\n").append(vuln.getPayload() == null ? "未记录" : vuln.getPayload()).append("\n```\n\n");

                md.append("### 响应特征分析\n\n");
                md.append(vuln.getDescription()).append("\n\n");

                md.append("### 完整请求包\n\n");
                md.append("```http\n").append(vuln.getRequestData() == null ? "未记录" : vuln.getRequestData()).append("\n```\n\n");

                md.append("### 完整响应包\n\n");
                md.append("```http\n").append(vuln.getResponseData() == null ? "未记录" : vuln.getResponseData()).append("\n```\n\n");

                md.append("---\n\n");
            }
        }
        Files.write(Paths.get(outputPath), md.toString().getBytes(StandardCharsets.UTF_8), new OpenOption[0]);
    }

    private static void appendInfoRow(StringBuilder html, String key, String value) {
        html.append("<tr><td class=\"label\">").append(escapeHtml(key)).append("</td><td>").append(escapeHtml(value == null ? "" : value)).append("</td></tr>\n");
    }

    private static void appendFoldableBlock(StringBuilder html, String title, String content) {
        String finalContent = content == null || content.trim().isEmpty() ? "未记录" : content;
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

    private static String getFixSuggestionsHtml(String vulnType) {
        if (vulnType == null) {
            return "<li>对用户输入进行严格校验和过滤。</li>";
        }
        switch (vulnType.toUpperCase()) {
            case "SQL_INJECTION":
                return "<li>使用参数化查询（PreparedStatement）而非字符串拼接SQL语句。</li>"
                     + "<li>使用ORM框架（如Hibernate、MyBatis）时避免动态SQL拼接。</li>"
                     + "<li>对用户输入进行严格的白名单校验。</li>"
                     + "<li>数据库账户使用最小权限原则，禁止使用DBA或管理员权限。</li>";
            case "XSS":
                return "<li>对所有用户输入进行HTML转义（ESCAPE HTML）。</li>"
                     + "<li>使用Content-Security-Policy (CSP) 响应头限制脚本执行。</li>"
                     + "<li>设置HttpOnly和Secure标志防止Cookie被JavaScript读取。</li>"
                     + "<li>对输出到HTML的内容进行上下文感知编码。</li>";
            case "COMMAND_INJECTION":
            case "RCE":
                return "<li>避免使用用户输入直接调用系统命令。</li>"
                     + "<li>使用API替代系统命令执行，如Java的ProcessBuilder或Runtime.exec()。</li>"
                     + "<li>如果必须执行命令，对用户输入进行严格的白名单校验。</li>"
                     + "<li>使用安全的沙箱环境执行动态代码。</li>";
            case "FILE_UPLOAD":
                return "<li>对上传文件类型进行白名单校验，只允许已知安全类型。</li>"
                     + "<li>验证文件魔数和MIME类型，而非仅依赖文件扩展名。</li>"
                     + "<li>将上传文件存储在Web根目录之外或云存储。</li>"
                     + "<li>重命名上传文件，使用随机文件名，保留原始扩展名。</li>"
                     + "<li>限制上传文件大小和执行权限。</li>";
            case "SSRF":
                return "<li>对用户输入的URL进行校验，禁止访问内网IP段。</li>"
                     + "<li>使用URL解析库验证URL合法性，禁止解析IP地址而非域名。</li>"
                     + "<li>配置Web服务器禁止访问内部服务。</li>"
                     + "<li>使用网络隔离，限制出站请求。</li>";
            case "XXE":
                return "<li>禁用XML外部实体（DTD）。</li>"
                     + "<li>使用安全的XML解析器，禁用DTD和外部实体。</li>"
                     + "<li>对用户上传的XML文件进行白名单校验。</li>"
                     + "<li>使用JSON替代XML进行数据传输。</li>";
            case "FILE_INCLUDE":
            case "LFI":
            case "RFI":
                return "<li>禁止用户输入直接传入文件包含函数。</li>"
                     + "<li>使用白名单方式验证包含的文件路径。</li>"
                     + "<li>配置PHP等解释器的open_basedir限制访问目录。</li>"
                     + "<li>对文件路径进行规范化处理，检测路径遍历字符。</li>";
            case "CSRF":
                return "<li>使用CSRF Token验证请求来源。</li>"
                     + "<li>验证Referer和Origin请求头。</li>"
                     + "<li>对于重要操作，使用二次验证或密码确认。</li>"
                     + "<li>设置SameSite Cookie属性。</li>";
            case "DESERIALIZATION":
                return "<li>禁止用户输入直接传入反序列化函数。</li>"
                     + "<li>使用数字签名验证序列化对象完整性。</li>"
                     + "<li>使用白名单限制可反序列化的类。</li>"
                     + "<li>隔离执行环境，限制反序列化操作权限。</li>";
            case "SSTI":
                return "<li>禁止用户输入直接插入模板。</li>"
                     + "<li>使用模板引擎的沙箱模式，禁用危险标签和函数。</li>"
                     + "<li>对用户输入进行严格过滤和转义。</li>"
                     + "<li>考虑使用静态模板生成替代动态渲染。</li>";
            case "AUTH_BYPASS":
                return "<li>所有操作都需要进行权限验证，不依赖客户端传递的ID。</li>"
                     + "<li>使用随机、不可预测的资源标识符（ID）。</li>"
                     + "<li>实施基于角色的访问控制（RBAC）。</li>"
                     + "<li>对资源访问进行审计日志记录。</li>";
            case "PATH_TRAVERSAL":
            case "DIRECTORY_TRAVERSAL":
                return "<li>对用户输入进行路径规范化，移除所有路径遍历字符。</li>"
                     + "<li>使用白名单验证文件路径。</li>"
                     + "<li>配置Web服务器禁止访问Web根目录之外的文件。</li>"
                     + "<li>使用chroot或容器隔离文件系统访问。</li>";
            case "SENSITIVE_DATA_EXPOSURE":
                return "<li>对敏感数据进行加密存储和传输。</li>"
                     + "<li>使用HTTPS进行数据传输，禁止明文传输。</li>"
                     + "<li>实施权限读取控制，只允许授权用户访问。</li>"
                     + "<li>对输出的数据进行脱敏处理，避免泄露。</li>";
            case "LOGIC_FLAW":
                return "<li>对业务逻辑进行完整性校验，避免边缘条件漏洞。</li>"
                     + "<li>实施幂等性设计，确保业务流程不可被绕过。</li>"
                     + "<li>对于重要操作采取双重验证，如密码重置。</li>"
                     + "<li>实施请求频率限制和账号频率计算。</li>";
            case "RACE_CONDITION":
                return "<li>对关键业务操作采取错误处理机制，避免并发竞争。</li>"
                     + "<li>使用事务或锁机制保证数据一致性。</li>"
                     + "<li>对资源进行正确的锁定和释放，避免死锁和空锁。</li>"
                     + "<li>实施并发控制，使用线程安全集合类。</li>";
            case "TYPE_CONFUSION":
                return "<li>对参数类型进行严格校验，避免类型混淆。</li>"
                     + "<li>使用强类型比较（===）而非弱类型比较（==）。</li>"
                     + "<li>对输入参数进行类型转换时采取安全措施。</li>"
                     + "<li>避免使用危险API进行高危操作。</li>";
            default:
                return "<li>对所有用户输入进行严格校验和过滤。</li>"
                     + "<li>遵循最小权限原则。</li>"
                     + "<li>实施纵深防御策略。</li>";
        }
    }

    private static String getMarkdownFixSuggestions(String vulnType) {
        if (vulnType == null) {
            return "- 对用户输入进行严格校验和过滤。\n";
        }
        StringBuilder sb = new StringBuilder();
        switch (vulnType.toUpperCase()) {
            case "SQL_INJECTION":
                sb.append("- 使用参数化查询（PreparedStatement）而非字符串拼接SQL语句。\n");
                sb.append("- 使用ORM框架（如Hibernate、MyBatis）时避免动态SQL拼接。\n");
                sb.append("- 对用户输入进行严格的白名单校验。\n");
                sb.append("- 数据库账户使用最小权限原则，禁止使用DBA或管理员权限。\n");
                break;
            case "XSS":
                sb.append("- 对所有用户输入进行HTML转义（ESCAPE HTML）。\n");
                sb.append("- 使用Content-Security-Policy (CSP) 响应头限制脚本执行。\n");
                sb.append("- 设置HttpOnly和Secure标志防止Cookie被JavaScript读取。\n");
                sb.append("- 对输出到HTML的内容进行上下文感知编码。\n");
                break;
            case "COMMAND_INJECTION":
            case "RCE":
                sb.append("- 避免使用用户输入直接调用系统命令。\n");
                sb.append("- 使用API替代系统命令执行，如Java的ProcessBuilder或Runtime.exec()。\n");
                sb.append("- 如果必须执行命令，对用户输入进行严格的白名单校验。\n");
                sb.append("- 使用安全的沙箱环境执行动态代码。\n");
                break;
            case "FILE_UPLOAD":
                sb.append("- 对上传文件类型进行白名单校验，只允许已知安全类型。\n");
                sb.append("- 验证文件魔数和MIME类型，而非仅依赖文件扩展名。\n");
                sb.append("- 将上传文件存储在Web根目录之外或云存储。\n");
                sb.append("- 重命名上传文件，使用随机文件名，保留原始扩展名。\n");
                sb.append("- 限制上传文件大小和执行权限。\n");
                break;
            case "SSRF":
                sb.append("- 对用户输入的URL进行校验，禁止访问内网IP段。\n");
                sb.append("- 使用URL解析库验证URL合法性，禁止解析IP地址而非域名。\n");
                sb.append("- 配置Web服务器禁止访问内部服务。\n");
                sb.append("- 使用网络隔离，限制出站请求。\n");
                break;
            case "XXE":
                sb.append("- 禁用XML外部实体（DTD）。\n");
                sb.append("- 使用安全的XML解析器，禁用DTD和外部实体。\n");
                sb.append("- 对用户上传的XML文件进行白名单校验。\n");
                sb.append("- 使用JSON替代XML进行数据传输。\n");
                break;
            case "FILE_INCLUDE":
            case "LFI":
            case "RFI":
                sb.append("- 禁止用户输入直接传入文件包含函数。\n");
                sb.append("- 使用白名单方式验证包含的文件路径。\n");
                sb.append("- 配置PHP等解释器的open_basedir限制访问目录。\n");
                sb.append("- 对文件路径进行规范化处理，检测路径遍历字符。\n");
                break;
            case "CSRF":
                sb.append("- 使用CSRF Token验证请求来源。\n");
                sb.append("- 验证Referer和Origin请求头。\n");
                sb.append("- 对于重要操作，使用二次验证或密码确认。\n");
                sb.append("- 设置SameSite Cookie属性。\n");
                break;
            case "DESERIALIZATION":
                sb.append("- 禁止用户输入直接传入反序列化函数。\n");
                sb.append("- 使用数字签名验证序列化对象完整性。\n");
                sb.append("- 使用白名单限制可反序列化的类。\n");
                sb.append("- 隔离执行环境，限制反序列化操作权限。\n");
                break;
            case "SSTI":
                sb.append("- 禁止用户输入直接插入模板。\n");
                sb.append("- 使用模板引擎的沙箱模式，禁用危险标签和函数。\n");
                sb.append("- 对用户输入进行严格过滤和转义。\n");
                sb.append("- 考虑使用静态模板生成替代动态渲染。\n");
                break;
            case "AUTH_BYPASS":
                sb.append("- 所有操作都需要进行权限验证，不依赖客户端传递的ID。\n");
                sb.append("- 使用随机、不可预测的资源标识符（ID）。\n");
                sb.append("- 实施基于角色的访问控制（RBAC）。\n");
                sb.append("- 对资源访问进行审计日志记录。\n");
                break;
            case "PATH_TRAVERSAL":
            case "DIRECTORY_TRAVERSAL":
                sb.append("- 对用户输入进行路径规范化，移除所有路径遍历字符。\n");
                sb.append("- 使用白名单验证文件路径。\n");
                sb.append("- 配置Web服务器禁止访问Web根目录之外的文件。\n");
                sb.append("- 使用chroot或容器隔离文件系统访问。\n");
                break;
            case "SENSITIVE_DATA_EXPOSURE":
                sb.append("- 对敏感数据进行加密存储和传输。\n");
                sb.append("- 使用HTTPS进行数据传输，禁止明文传输。\n");
                sb.append("- 实施权限读取控制，只允许授权用户访问。\n");
                sb.append("- 对输出的数据进行脱敏处理，避免泄露。\n");
                break;
            case "LOGIC_FLAW":
                sb.append("- 对业务逻辑进行完整性校验，避免边缘条件漏洞。\n");
                sb.append("- 实施幂等性设计，确保业务流程不可被绕过。\n");
                sb.append("- 对于重要操作采取双重验证，如密码重置。\n");
                sb.append("- 实施请求频率限制和账号频率计算。\n");
                break;
            case "RACE_CONDITION":
                sb.append("- 对关键业务操作采取错误处理机制，避免并发竞争。\n");
                sb.append("- 使用事务或锁机制保证数据一致性。\n");
                sb.append("- 对资源进行正确的锁定和释放，避免死锁和空锁。\n");
                sb.append("- 实施并发控制，使用线程安全集合类。\n");
                break;
            case "TYPE_CONFUSION":
                sb.append("- 对参数类型进行严格校验，避免类型混淆。\n");
                sb.append("- 使用强类型比较（===）而非弱类型比较（==）。\n");
                sb.append("- 对输入参数进行类型转换时采取安全措施。\n");
                sb.append("- 避免使用危险API进行高危操作。\n");
                break;
            default:
                sb.append("- 对所有用户输入进行严格校验和过滤。\n");
                sb.append("- 遵循最小权限原则。\n");
                sb.append("- 实施纵深防御策略。\n");
                break;
        }
        return sb.toString();
    }
}
