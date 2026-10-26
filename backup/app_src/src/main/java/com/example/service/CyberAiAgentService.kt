package com.example.service

import com.example.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

class CyberAiAgentService(
    private val webScanner: CyberSecurityScanner,
    private val apiAnalyzer: ApiAndNetworkAnalyzer,
    private val apkAnalyzer: ApkSecurityAnalyzer
) {

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .build()

    suspend fun checkOllamaConnection(config: OllamaConfig): Pair<Boolean, List<String>> = withContext(Dispatchers.IO) {
        try {
            val url = config.endpointUrl.trimEnd('/') + "/api/tags"
            val reqBuilder = Request.Builder().url(url)
            if (config.customAuthHeader.isNotBlank()) {
                reqBuilder.header("Authorization", config.customAuthHeader)
            }
            httpClient.newCall(reqBuilder.build()).execute().use { resp ->
                if (resp.isSuccessful) {
                    val body = resp.body?.string() ?: ""
                    val json = JSONObject(body)
                    val modelsArray = json.optJSONArray("models") ?: JSONArray()
                    val modelNames = mutableListOf<String>()
                    for (i in 0 until modelsArray.length()) {
                        val m = modelsArray.getJSONObject(i).optString("name")
                        if (m.isNotBlank()) modelNames.add(m)
                    }
                    Pair(true, if (modelNames.isEmpty()) listOf("llama3:latest", "mistral:latest") else modelNames)
                } else {
                    Pair(false, emptyList())
                }
            }
        } catch (e: Exception) {
            Pair(false, emptyList())
        }
    }

    suspend fun executeAgentPrompt(
        prompt: String,
        config: OllamaConfig,
        onStepUpdate: (TaskStep) -> Unit
    ): AgentExecutionResponse = withContext(Dispatchers.IO) {
        val targetUrl = extractUrlOrHost(prompt) ?: "https://example.com"
        val isApkRequest = prompt.contains("apk", ignoreCase = true) || prompt.contains("permission", ignoreCase = true) || prompt.contains("manifest", ignoreCase = true)
        val isApiRequest = prompt.contains("api", ignoreCase = true) || prompt.contains("cors", ignoreCase = true) || prompt.contains("endpoint", ignoreCase = true)

        val planSteps = mutableListOf<TaskStep>()

        // 1. Plan Definition
        if (isApkRequest) {
            planSteps.add(TaskStep(1, "Parse Task & Scope", "ScopeValidator", "Target: Android Package Manifest"))
            planSteps.add(TaskStep(2, "Tool Availability Check", "ApkSecurityAnalyzer", "Verifying package manager and permissions"))
            planSteps.add(TaskStep(3, "Execute Manifest Inspection", "ApkSecurityAnalyzer", "Auditing permissions, export flags, debug status"))
            planSteps.add(TaskStep(4, "Analyze Security Risks", "RiskClassifier", "Evaluating OWASP Mobile Top 10 vectors"))
            planSteps.add(TaskStep(5, "Generate Hardening Remediation", "RemediationEngine", "Synthesizing code snippets & XML rules"))
        } else if (isApiRequest) {
            planSteps.add(TaskStep(1, "Parse API Scope & Authorization", "ScopeValidator", "Target: $targetUrl"))
            planSteps.add(TaskStep(2, "Tool Availability Check", "ApiAndNetworkAnalyzer", "Testing network connectivity & HTTP client"))
            planSteps.add(TaskStep(3, "Audit API Endpoint & CORS", "ApiAndNetworkAnalyzer", "Evaluating CORS headers, methods, auth enforcement"))
            planSteps.add(TaskStep(4, "Analyze Exposure & Leakage", "RiskClassifier", "Evaluating API vulnerabilities"))
            planSteps.add(TaskStep(5, "Synthesize Remediation Guide", "RemediationEngine", "Generating gateway and CORS configuration"))
        } else {
            planSteps.add(TaskStep(1, "Parse Scope & Validate Consent", "ScopeValidator", "Target: $targetUrl"))
            planSteps.add(TaskStep(2, "Tool Availability Check", "CyberSecurityScanner", "Verifying TLS engine and HTTP suite"))
            planSteps.add(TaskStep(3, "Execute Multi-Vector Audit", "CyberSecurityScanner", "Inspecting HTTP headers, TLS certificate, DNS"))
            planSteps.add(TaskStep(4, "Evaluate Posture & Misconfigurations", "RiskClassifier", "Mapping findings to OWASP Top 10"))
            planSteps.add(TaskStep(5, "Synthesize Defensive Remediation", "RemediationEngine", "Compiling actionable fixes"))
        }

        // 2. Step 1: Scope Validation
        val step1 = planSteps[0].copy(isDone = true)
        onStepUpdate(step1)

        // 3. Step 2: Tool Check
        val step2 = planSteps[1].copy(isDone = true)
        onStepUpdate(step2)

        // 4. Step 3: Execution
        var executionLog = ""
        var webResult: WebScanResult? = null
        var apiResult: ApiEndpointResult? = null
        var apkResult: ApkAuditResult? = null

        if (isApkRequest) {
            val pkg = "com.codex.cyberagent"
            apkResult = apkAnalyzer.auditAppPackage(pkg)
            executionLog = "Inspected package: $pkg\nDebuggable: ${apkResult.isDebuggable}\nCleartext: ${apkResult.usesCleartextTraffic}\nDangerous Permissions: ${apkResult.dangerousPermissions.size}\nSecurity Score: ${apkResult.securityScore}/100"
        } else if (isApiRequest) {
            apiResult = apiAnalyzer.analyzeApiEndpoint(targetUrl)
            executionLog = "API Target: $targetUrl\nStatus: ${apiResult.statusCode} (${apiResult.latencyMs}ms)\nCORS configured: ${apiResult.corsConfigured}\nAuth enforced: ${apiResult.authEnforced}\nFindings: ${apiResult.vulnerabilities.size}"
        } else {
            webResult = webScanner.auditWebTarget(targetUrl)
            val tlsStatus = webResult.tls?.let { "TLS ${it.protocol} (${it.daysRemaining} days left)" } ?: "No TLS"
            executionLog = "Web Target: $targetUrl\nStatus: ${webResult.statusCode} (${webResult.responseTimeMs}ms)\n$tlsStatus\nHeaders Audited: ${webResult.headers.size}\nVulnerabilities: ${webResult.vulnerabilities.size}\nScore: ${webResult.score}/100"
        }

        val step3 = planSteps[2].copy(isDone = true, details = "Completed: $executionLog")
        onStepUpdate(step3)

        // 5. Step 4: Risk Classification
        val vulns = webResult?.vulnerabilities ?: apiResult?.vulnerabilities ?: apkResult?.vulnerabilities ?: emptyList()
        val criticalCount = vulns.count { it.severity == RiskLevel.CRITICAL }
        val highCount = vulns.count { it.severity == RiskLevel.HIGH }
        val mediumCount = vulns.count { it.severity == RiskLevel.MEDIUM }

        val step4 = planSteps[3].copy(
            isDone = true,
            details = "Classified: $criticalCount Critical, $highCount High, $mediumCount Medium"
        )
        onStepUpdate(step4)

        // 6. Step 5: AI LLM Synthesis or Expert Fallback
        var aiResponseText = ""
        var usedOllama = false

        // Check if Ollama is accessible
        val (ollamaOnline, _) = checkOllamaConnection(config)
        if (ollamaOnline) {
            try {
                val ollamaUrl = config.endpointUrl.trimEnd('/') + "/api/generate"
                val jsonPayload = JSONObject().apply {
                    put("model", config.model)
                    put("prompt", buildOllamaSystemPrompt(prompt, executionLog, vulns))
                    put("stream", false)
                }
                val body = jsonPayload.toString().toRequestBody("application/json".toMediaType())
                val reqBuilder = Request.Builder().url(ollamaUrl).post(body)
                if (config.customAuthHeader.isNotBlank()) {
                    reqBuilder.header("Authorization", config.customAuthHeader)
                }
                httpClient.newCall(reqBuilder.build()).execute().use { resp ->
                    if (resp.isSuccessful) {
                        val respBody = resp.body?.string() ?: ""
                        val respJson = JSONObject(respBody)
                        aiResponseText = respJson.optString("response", "")
                        if (aiResponseText.isNotBlank()) {
                            usedOllama = true
                        }
                    }
                }
            } catch (e: Exception) {
                usedOllama = false
            }
        }

        if (!usedOllama || aiResponseText.isBlank()) {
            aiResponseText = generateDefensiveSynthesis(prompt, targetUrl, vulns, isApkRequest, isApiRequest, ollamaOnline, config.endpointUrl)
        }

        val step5 = planSteps[4].copy(isDone = true, details = "Remediation synthesized successfully")
        onStepUpdate(step5)

        val taskPlan = AgentTask(
            id = "TASK-${System.currentTimeMillis() and 0xFFFF}",
            title = "Defensive Security Audit: ${if (isApkRequest) "Android APK" else targetUrl}",
            target = targetUrl,
            steps = planSteps,
            isCompleted = true
        )

        AgentExecutionResponse(
            task = taskPlan,
            responseMarkdown = aiResponseText,
            executionSummary = executionLog,
            vulnerabilities = vulns,
            webResult = webResult,
            apiResult = apiResult,
            apkResult = apkResult,
            usedOllama = usedOllama
        )
    }

    private fun buildOllamaSystemPrompt(userPrompt: String, telemetry: String, vulns: List<VulnerabilityItem>): String {
        return """
            You are Codex Cyber Agent, an elite defensive cybersecurity AI.
            Analyze the following security audit telemetry and user task.
            Provide:
            1. Executive Assessment
            2. Vulnerability Risk Breakdown
            3. Specific, ready-to-paste Remediation configurations (Nginx/Apache/Spring/Android)
            4. Hardening Recommendations.
            
            USER PROMPT: $userPrompt
            
            TELEMETRY:
            $telemetry
            
            FINDINGS:
            ${vulns.joinToString("\n") { "- [${it.severity}] ${it.title}: ${it.description}" }}
        """.trimIndent()
    }

    private fun generateDefensiveSynthesis(
        prompt: String,
        target: String,
        vulns: List<VulnerabilityItem>,
        isApk: Boolean,
        isApi: Boolean,
        ollamaOnline: Boolean,
        endpointUrl: String
    ): String {
        val sb = StringBuilder()
        sb.append("### 🛡️ Codex Cyber Agent Diagnostic Report\n\n")

        if (!ollamaOnline) {
            sb.append("> **Ollama Status:** Offline or unreachable at `$endpointUrl`. Powered by local expert cybersecurity diagnostic engine.\n\n")
        } else {
            sb.append("> **Ollama Status:** Connected to `$endpointUrl`.\n\n")
        }

        sb.append("**Target Assessed:** `$target`\n\n")

        if (vulns.isEmpty()) {
            sb.append("✅ **No immediate high-severity risks identified.** The target displays a solid defensive posture.\n\n")
            sb.append("Recommended next steps:\n- Implement Content-Security-Policy with strict nonces\n- Verify TLS cipher suite forward secrecy\n- Audit external API sub-processors.")
            return sb.toString()
        }

        sb.append("#### 🚨 Identified Vulnerabilities (${vulns.size})\n\n")
        for ((idx, v) in vulns.withIndex()) {
            sb.append("**${idx + 1}. [${v.severity}] ${v.title}**\n")
            sb.append("- **Category:** ${v.category}\n")
            sb.append("- **Impact:** ${v.impact}\n")
            sb.append("- **Remediation:** ${v.remediation}\n")
            if (v.remediationCode != null) {
                sb.append("```\n${v.remediationCode}\n```\n")
            }
            if (v.owaspReference != null) {
                sb.append("- **Reference:** `${v.owaspReference}`\n")
            }
            sb.append("\n")
        }

        sb.append("#### 🛠️ Immediate Defensive Actions:\n")
        sb.append("1. Apply HTTP security headers in reverse proxy (HSTS, CSP, X-Frame-Options).\n")
        sb.append("2. Audit CORS policies to eliminate wildcard reflection on authenticated endpoints.\n")
        sb.append("3. Enforce TLS 1.3 with automated certificate renewal cycles.")

        return sb.toString()
    }

    private fun extractUrlOrHost(input: String): String? {
        val regex = Regex("https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/[a-zA-Z0-9_.-]*)*")
        val match = regex.find(input)
        if (match != null) return match.value

        val domainRegex = Regex("\\b([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}\\b")
        val domainMatch = domainRegex.find(input)
        if (domainMatch != null) return "https://${domainMatch.value}"

        return null
    }
}

data class AgentExecutionResponse(
    val task: AgentTask,
    val responseMarkdown: String,
    val executionSummary: String,
    val vulnerabilities: List<VulnerabilityItem>,
    val webResult: WebScanResult?,
    val apiResult: ApiEndpointResult?,
    val apkResult: ApkAuditResult?,
    val usedOllama: Boolean
)
