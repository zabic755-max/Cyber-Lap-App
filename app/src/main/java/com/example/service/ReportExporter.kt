package com.example.service

import android.content.Context
import android.content.Intent
import com.example.model.RiskLevel
import com.example.model.VulnerabilityItem
import com.example.model.WebScanResult
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

object ReportExporter {

    fun generateHtmlReport(
        target: String,
        score: Int,
        vulnerabilities: List<VulnerabilityItem>,
        webResult: WebScanResult?
    ): String {
        val dateStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US).format(Date())
        val criticalCount = vulnerabilities.count { it.severity == RiskLevel.CRITICAL }
        val highCount = vulnerabilities.count { it.severity == RiskLevel.HIGH }
        val mediumCount = vulnerabilities.count { it.severity == RiskLevel.MEDIUM }
        val lowCount = vulnerabilities.count { it.severity == RiskLevel.LOW }

        val vulnRows = vulnerabilities.joinToString("\n") { v ->
            val badgeColor = when (v.severity) {
                RiskLevel.CRITICAL -> "#EF4444"
                RiskLevel.HIGH -> "#F97316"
                RiskLevel.MEDIUM -> "#F59E0B"
                RiskLevel.LOW -> "#3B82F6"
                else -> "#10B981"
            }
            """
            <div class="vuln-card">
                <div class="vuln-header">
                    <span class="badge" style="background:${badgeColor}">${v.severity.label}</span>
                    <span class="vuln-title">${escapeHtml(v.title)}</span>
                    <span class="vuln-category">${escapeHtml(v.category)}</span>
                </div>
                <p><strong>Description:</strong> ${escapeHtml(v.description)}</p>
                <p><strong>Impact:</strong> ${escapeHtml(v.impact)}</p>
                <p><strong>Remediation:</strong> ${escapeHtml(v.remediation)}</p>
                ${if (!v.remediationCode.isNullOrBlank()) "<pre><code>${escapeHtml(v.remediationCode)}</code></pre>" else ""}
                ${if (!v.owaspReference.isNullOrBlank()) "<div class='owasp-tag'>OWASP: ${escapeHtml(v.owaspReference)}</div>" else ""}
            </div>
            """.trimIndent()
        }

        val headerRows = webResult?.headers?.joinToString("\n") { h ->
            val statusColor = if (h.isSecure) "#10B981" else "#EF4444"
            """
            <tr>
                <td><code>${escapeHtml(h.headerName)}</code></td>
                <td><span style="color:${statusColor}">${if (h.present) "Present" else "Missing"}</span></td>
                <td><small>${escapeHtml(h.value ?: "None")}</small></td>
                <td><small>${escapeHtml(h.recommendation)}</small></td>
            </tr>
            """.trimIndent()
        } ?: "<tr><td colspan='4'>No HTTP header telemetry recorded</td></tr>"

        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Codex Cyber Agent Security Audit - ${escapeHtml(target)}</title>
            <style>
                body {
                    background-color: #080C14;
                    color: #F8FAFC;
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                    line-height: 1.6;
                    padding: 24px;
                    margin: 0;
                }
                .container { max-width: 900px; margin: 0 auto; }
                .header {
                    border-bottom: 2px solid #00F5D4;
                    padding-bottom: 16px;
                    margin-bottom: 24px;
                }
                .logo { color: #00F5D4; font-size: 26px; font-weight: bold; letter-spacing: 1px; }
                .subtitle { color: #94A3B8; font-size: 14px; }
                .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
                .card {
                    background: #0F172A;
                    border: 1px solid #1E293B;
                    border-radius: 8px;
                    padding: 16px;
                    text-align: center;
                }
                .score { font-size: 38px; font-weight: bold; color: ${if (score >= 75) "#10B981" else if (score >= 50) "#F59E0B" else "#EF4444"}; }
                .vuln-card {
                    background: #0F172A;
                    border-left: 4px solid #00F5D4;
                    border-radius: 6px;
                    padding: 16px;
                    margin-bottom: 16px;
                }
                .badge {
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 11px;
                    font-weight: bold;
                    color: #fff;
                    margin-right: 8px;
                }
                .vuln-title { font-size: 16px; font-weight: bold; color: #F1F5F9; }
                .vuln-category { float: right; color: #64FFDA; font-size: 12px; }
                pre { background: #050811; border: 1px solid #1E293B; padding: 12px; border-radius: 6px; overflow-x: auto; color: #64FFDA; font-size: 13px; }
                table { width: 100%; border-collapse: collapse; margin-top: 16px; margin-bottom: 24px; background: #0F172A; border-radius: 6px; overflow: hidden; }
                th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #1E293B; }
                th { background: #1E293B; color: #00F5D4; font-size: 13px; }
                .owasp-tag { display: inline-block; background: #1E293B; color: #94A3B8; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin-top: 8px; }
                .footer { text-align: center; color: #64748B; font-size: 12px; margin-top: 40px; border-top: 1px solid #1E293B; padding-top: 16px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="logo">⚡ CODEX CYBER AGENT</div>
                    <div class="subtitle">Defensive Security Posture Audit & Technical Remediation Report</div>
                    <div>Target: <code>${escapeHtml(target)}</code> | Timestamp: ${escapeHtml(dateStr)}</div>
                </div>

                <div class="grid">
                    <div class="card">
                        <div>Security Posture Score</div>
                        <div class="score">$score / 100</div>
                    </div>
                    <div class="card">
                        <div>Critical Risks</div>
                        <div style="font-size:32px; font-weight:bold; color:#EF4444">$criticalCount</div>
                    </div>
                    <div class="card">
                        <div>High Risks</div>
                        <div style="font-size:32px; font-weight:bold; color:#F97316">$highCount</div>
                    </div>
                    <div class="card">
                        <div>Medium & Low</div>
                        <div style="font-size:32px; font-weight:bold; color:#F59E0B">${mediumCount + lowCount}</div>
                    </div>
                </div>

                <h3>🛡️ Security Findings & Technical Remediation</h3>
                $vulnRows

                <h3>🌐 HTTP Security Headers Audit</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Header</th>
                            <th>Status</th>
                            <th>Value</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>
                        $headerRows
                    </tbody>
                </table>

                <div class="footer">
                    Generated by Codex Cyber Agent v1.0. All audits conducted in accordance with defensive scope consent.
                </div>
            </div>
        </body>
        </html>
        """.trimIndent()
    }

    fun generateJsonReport(
        target: String,
        score: Int,
        vulnerabilities: List<VulnerabilityItem>,
        webResult: WebScanResult?
    ): String {
        val root = JSONObject()
        root.put("tool", "Codex Cyber Agent")
        root.put("version", "1.0")
        root.put("timestamp", System.currentTimeMillis())
        root.put("target", target)
        root.put("securityScore", score)

        val vulnsArray = JSONArray()
        for (v in vulnerabilities) {
            val vObj = JSONObject().apply {
                put("id", v.id)
                put("title", v.title)
                put("category", v.category)
                put("severity", v.severity.name)
                put("description", v.description)
                put("impact", v.impact)
                put("remediation", v.remediation)
                put("remediationCode", v.remediationCode ?: "")
                put("owasp", v.owaspReference ?: "")
            }
            vulnsArray.put(vObj)
        }
        root.put("vulnerabilities", vulnsArray)

        if (webResult != null) {
            val headersArray = JSONArray()
            for (h in webResult.headers) {
                headersArray.put(JSONObject().apply {
                    put("name", h.headerName)
                    put("present", h.present)
                    put("value", h.value ?: "")
                    put("isSecure", h.isSecure)
                })
            }
            root.put("headers", headersArray)

            if (webResult.tls != null) {
                root.put("tls", JSONObject().apply {
                    put("protocol", webResult.tls.protocol)
                    put("cipher", webResult.tls.cipherSuite)
                    put("subject", webResult.tls.subject)
                    put("issuer", webResult.tls.issuer)
                    put("validTo", webResult.tls.validTo)
                    put("isExpired", webResult.tls.isExpired)
                    put("daysRemaining", webResult.tls.daysRemaining)
                })
            }
        }

        return root.toString(2)
    }

    fun generateMarkdownReport(
        target: String,
        score: Int,
        vulnerabilities: List<VulnerabilityItem>,
        webResult: WebScanResult?
    ): String {
        val dateStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US).format(Date())
        val sb = StringBuilder()
        sb.append("# ⚡ Codex Cyber Agent Ultimate v2.0 — Security Assessment Report\n\n")
        sb.append("- **Target:** `$target`\n")
        sb.append("- **Date:** $dateStr\n")
        sb.append("- **Security Posture Score:** **$score / 100**\n")
        sb.append("- **Total Identified Risks:** ${vulnerabilities.size}\n\n")
        sb.append("---\n\n")
        sb.append("## Identified Vulnerabilities\n\n")
        for ((idx, v) in vulnerabilities.withIndex()) {
            sb.append("### ${idx + 1}. [${v.severity.label}] ${v.title}\n")
            sb.append("- **Category:** ${v.category}\n")
            sb.append("- **Description:** ${v.description}\n")
            sb.append("- **Technical Impact:** ${v.impact}\n")
            sb.append("- **Remediation:** ${v.remediation}\n")
            if (!v.remediationCode.isNullOrBlank()) {
                sb.append("\n```\n${v.remediationCode}\n```\n")
            }
            if (!v.owaspReference.isNullOrBlank()) {
                sb.append("- **OWASP Mapping:** `${v.owaspReference}`\n")
            }
            sb.append("\n")
        }

        if (webResult != null) {
            sb.append("## HTTP Security Headers Audit\n\n")
            sb.append("| Header | Status | Current Value | Recommendation |\n")
            sb.append("| :--- | :--- | :--- | :--- |\n")
            for (h in webResult.headers) {
                sb.append("| `${h.headerName}` | ${if (h.isSecure) "✅ SECURE" else "❌ INSECURE"} | `${h.value ?: "MISSING"}` | ${h.recommendation} |\n")
            }
            sb.append("\n")
        }

        sb.append("---\n*Generated by Codex Cyber Agent Ultimate v2.0*\n")
        return sb.toString()
    }

    fun saveReportFile(context: Context, content: String, fileName: String): File {
        val dir = context.getExternalFilesDir(null) ?: context.filesDir
        val file = File(dir, fileName)
        file.writeText(content)
        return file
    }

    fun shareReport(context: Context, subject: String, content: String) {
        val sendIntent = Intent().apply {
            action = Intent.ACTION_SEND
            putExtra(Intent.EXTRA_SUBJECT, subject)
            putExtra(Intent.EXTRA_TEXT, content)
            type = "text/plain"
        }
        val shareIntent = Intent.createChooser(sendIntent, "Export Security Audit Report")
        shareIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(shareIntent)
    }

    private fun escapeHtml(text: String): String {
        return text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;")
    }
}
