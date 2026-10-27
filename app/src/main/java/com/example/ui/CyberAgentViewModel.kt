package com.example.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.model.*
import com.example.service.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

enum class CyberNavScreen(val title: String) {
    DASHBOARD("Dashboard"),
    AI_AGENT("AI Agent Chat"),
    TOOL_REGISTRY("Tool Catalog"),
    SELF_TEST("Test Suite"),
    WEB_SCANNER("Security Scanner"),
    API_ANALYZER("API & WebSocket"),
    APK_ANALYZER("APK Analyzer"),
    NETWORK_DIAG("Network Diagnostics"),
    REPORTS("Vulnerability Reports"),
    SETTINGS("Tools & Settings")
}

data class CyberUiState(
    val currentScreen: CyberNavScreen = CyberNavScreen.DASHBOARD,
    val targetUrl: String = "https://example.com",
    val isScanning: Boolean = false,
    val scopeConsentApproved: Boolean = true,
    val webScanResult: WebScanResult? = null,
    val apiScanResult: ApiEndpointResult? = null,
    val apkScanResult: ApkAuditResult? = null,
    val allVulnerabilities: List<VulnerabilityItem> = emptyList(),
    val overallSecurityScore: Int = 85,
    val chatMessages: List<ChatMessage> = emptyList(),
    val ollamaConfig: OllamaConfig = OllamaConfig(),
    val ollamaStatusText: String = "Ollama: Disconnected (Default fallback ready)",
    val availableModels: List<String> = listOf("llama3:latest", "mistral:latest", "codellama:latest"),
    val statusMessage: String? = null,
    val errorMessage: String? = null,
    val currentTaskPlan: AgentTask? = null,
    val logs: List<String> = emptyList(),
    val staticCodeInput: String = "",
    val staticFindings: List<VulnerabilityItem> = emptyList(),
    // Tool Registry & Runner
    val toolsList: List<SecurityTool> = emptyList(),
    val selectedTool: SecurityTool? = null,
    val isExecutingTool: Boolean = false,
    val lastToolResult: ToolExecutionResult? = null,
    // Automated Self-Test Suite
    val isRunningSelfTest: Boolean = false,
    val selfTestResults: List<Pair<SecurityTool, ToolExecutionResult>> = emptyList(),
    val passedTestsCount: Int = 0,
    val partialTestsCount: Int = 0,
    val blockedTestsCount: Int = 0,
    val failedTestsCount: Int = 0
)

class CyberAgentViewModel(application: Application) : AndroidViewModel(application) {

    private val webScanner = CyberSecurityScanner()
    private val apiAnalyzer = ApiAndNetworkAnalyzer()
    private val apkAnalyzer = ApkSecurityAnalyzer(application)
    private val aiAgentService = CyberAiAgentService(webScanner, apiAnalyzer, apkAnalyzer)
    private val toolRegistry = ToolRegistry(application, webScanner, apiAnalyzer, apkAnalyzer)

    private val _uiState = MutableStateFlow(CyberUiState())
    val uiState: StateFlow<CyberUiState> = _uiState.asStateFlow()

    init {
        val initialTools = toolRegistry.getAllTools()
        _uiState.value = _uiState.value.copy(
            toolsList = initialTools,
            selectedTool = initialTools.firstOrNull()
        )

        addLog("System initialized: Codex Cyber Agent Ultimate active.")
        addLog("Tool Registry loaded: ${initialTools.size} tools discovered.")
        _uiState.value = _uiState.value.copy(
            chatMessages = listOf(
                ChatMessage(
                    sender = "agent",
                    content = "⚡ Codex Cyber Agent Ultimate online.\n\nAll 14 security tool adapters registered:\n- Web & Transport Auditing\n- TLS / SSL Certificate Validator\n- REST API & CORS Probe\n- WebSocket Handshaker\n- Android APK Manifest & Permission Inspector\n- Static Source Code & Secret Reviewer\n- TCP Port Scanner & DNS Diagnostics\n- Tool Self-Test & Verification Engine\n\nEnter a target or task below, or open the Tool Catalog to execute individual security tools."
                )
            )
        )
        // Perform initial APK self-audit
        performApkAudit("com.codex.cyberagent")
    }

    fun navigateTo(screen: CyberNavScreen) {
        _uiState.value = _uiState.value.copy(currentScreen = screen, statusMessage = null)
    }

    fun updateTargetUrl(url: String) {
        _uiState.value = _uiState.value.copy(targetUrl = url)
    }

    fun setScopeConsent(approved: Boolean) {
        _uiState.value = _uiState.value.copy(scopeConsentApproved = approved)
    }

    fun clearStatusMessage() {
        _uiState.value = _uiState.value.copy(statusMessage = null, errorMessage = null)
    }

    fun addLog(msg: String) {
        val timestamp = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        val entry = "[$timestamp] $msg"
        val updated = (_uiState.value.logs + entry).takeLast(100)
        _uiState.value = _uiState.value.copy(logs = updated)
    }

    // --- Tool Catalog & Execution ---
    fun selectTool(tool: SecurityTool) {
        _uiState.value = _uiState.value.copy(selectedTool = tool, lastToolResult = null)
    }

    fun executeSingleTool(toolId: String, params: Map<String, String>) {
        if (!_uiState.value.scopeConsentApproved) {
            _uiState.value = _uiState.value.copy(errorMessage = "Scope Consent Required: Please confirm authorization before scanning.")
            return
        }

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isExecutingTool = true, errorMessage = null)
            addLog("Executing Tool [$toolId] with params $params")
            try {
                val result = toolRegistry.executeTool(toolId, params)
                _uiState.value = _uiState.value.copy(
                    isExecutingTool = false,
                    lastToolResult = result,
                    statusMessage = "Tool execution completed: ${result.status} (${result.executionTimeMs}ms)"
                )
                addLog("Tool [$toolId] exit code ${result.exitCode} in ${result.executionTimeMs}ms")
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isExecutingTool = false,
                    errorMessage = "Tool execution failed: ${e.message}"
                )
                addLog("Tool [$toolId] error: ${e.message}")
            }
        }
    }

    // --- Automated Self-Test Suite ---
    fun runTestSuite() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isRunningSelfTest = true, statusMessage = "Executing automated tool verification suite...")
            addLog("Starting automated self-test suite across all tools...")
            try {
                val results = toolRegistry.runSelfTestSuite()
                val passed = results.count { it.first.testStatus == TestStatus.PASS }
                val partial = results.count { it.first.testStatus == TestStatus.PARTIAL }
                val blocked = results.count { it.first.testStatus == TestStatus.BLOCKED }
                val failed = results.count { it.first.testStatus == TestStatus.FAIL }

                _uiState.value = _uiState.value.copy(
                    isRunningSelfTest = false,
                    selfTestResults = results,
                    toolsList = toolRegistry.getAllTools(),
                    passedTestsCount = passed,
                    partialTestsCount = partial,
                    blockedTestsCount = blocked,
                    failedTestsCount = failed,
                    statusMessage = "Test suite finished: $passed Passed, $partial Partial, $blocked Blocked, $failed Failed"
                )
                addLog("Test Suite Complete: $passed PASS, $partial PARTIAL, $blocked BLOCKED, $failed FAIL")
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isRunningSelfTest = false,
                    errorMessage = "Test suite execution error: ${e.message}"
                )
            }
        }
    }

    // --- Web Security Audit ---
    fun performWebScan(target: String = _uiState.value.targetUrl) {
        if (!_uiState.value.scopeConsentApproved) {
            _uiState.value = _uiState.value.copy(errorMessage = "Scope Consent Required: Please confirm authorization before scanning.")
            return
        }

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isScanning = true, errorMessage = null, statusMessage = "Initiating web security audit...")
            addLog("Starting web audit against $target")
            try {
                val result = webScanner.auditWebTarget(target)
                val allVulns = (result.vulnerabilities + _uiState.value.apkScanResult?.vulnerabilities.orEmpty()).distinctBy { it.id }
                _uiState.value = _uiState.value.copy(
                    webScanResult = result,
                    allVulnerabilities = allVulns,
                    overallSecurityScore = result.score,
                    isScanning = false,
                    statusMessage = "Audit complete. Score: ${result.score}/100. Found ${result.vulnerabilities.size} vulnerabilities."
                )
                addLog("Audit finished for $target with score ${result.score}/100")
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isScanning = false,
                    errorMessage = "Scan failed: ${e.message}"
                )
                addLog("Error during scan: ${e.message}")
            }
        }
    }

    // --- API & WebSocket Analyzer ---
    fun performApiScan(url: String, method: String) {
        if (!_uiState.value.scopeConsentApproved) {
            _uiState.value = _uiState.value.copy(errorMessage = "Scope Consent Required: Please confirm authorization before scanning.")
            return
        }

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isScanning = true, errorMessage = null, statusMessage = "Testing API endpoint...")
            addLog("Executing API analysis on $url [$method]")
            try {
                val result = apiAnalyzer.analyzeApiEndpoint(url, method)
                val updatedVulns = (_uiState.value.allVulnerabilities + result.vulnerabilities).distinctBy { it.id }
                _uiState.value = _uiState.value.copy(
                    apiScanResult = result,
                    allVulnerabilities = updatedVulns,
                    isScanning = false,
                    statusMessage = "API test completed with HTTP ${result.statusCode} (${result.latencyMs}ms)"
                )
                addLog("API test completed: status ${result.statusCode}, CORS: ${result.corsConfigured}")
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(isScanning = false, errorMessage = "API Test failed: ${e.message}")
                addLog("API test error: ${e.message}")
            }
        }
    }

    // --- APK Analyzer ---
    fun performApkAudit(pkgName: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isScanning = true, errorMessage = null)
            addLog("Auditing Android package: $pkgName")
            try {
                val result = apkAnalyzer.auditAppPackage(pkgName)
                val updatedVulns = (_uiState.value.allVulnerabilities + result.vulnerabilities).distinctBy { it.id }
                _uiState.value = _uiState.value.copy(
                    apkScanResult = result,
                    allVulnerabilities = updatedVulns,
                    isScanning = false,
                    statusMessage = "APK Audit complete: Security Score ${result.securityScore}/100"
                )
                addLog("APK audit complete: ${result.dangerousPermissions.size} dangerous permissions")
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(isScanning = false, errorMessage = "APK audit failed: ${e.message}")
            }
        }
    }

    // --- Static Code Review ---
    fun performStaticCodeReview(code: String) {
        viewModelScope.launch {
            addLog("Analyzing static source code snippet (${code.length} chars)")
            val findings = apkAnalyzer.auditStaticSourceCode(code)
            val updatedVulns = (_uiState.value.allVulnerabilities + findings).distinctBy { it.id }
            _uiState.value = _uiState.value.copy(
                staticCodeInput = code,
                staticFindings = findings,
                allVulnerabilities = updatedVulns,
                statusMessage = "Static analysis complete: ${findings.size} issues flagged"
            )
            addLog("Static analysis found ${findings.size} potential issues")
        }
    }

    // --- AI Agent Chat & Multi-Step Planning ---
    fun sendAgentMessage(userText: String) {
        if (userText.isBlank()) return

        val userMsg = ChatMessage(sender = "user", content = userText)
        _uiState.value = _uiState.value.copy(
            chatMessages = _uiState.value.chatMessages + userMsg,
            isScanning = true
        )
        addLog("AI Task initiated: \"$userText\"")

        viewModelScope.launch {
            try {
                val response = aiAgentService.executeAgentPrompt(
                    prompt = userText,
                    config = _uiState.value.ollamaConfig,
                    onStepUpdate = { step ->
                        _uiState.value = _uiState.value.copy(
                            currentTaskPlan = _uiState.value.currentTaskPlan?.let { cur ->
                                val updatedSteps = cur.steps.map { if (it.stepIndex == step.stepIndex) step else it }
                                cur.copy(steps = updatedSteps)
                            } ?: AgentTask(
                                id = "TASK-LIVE",
                                title = "Executing Security Plan",
                                target = _uiState.value.targetUrl,
                                steps = listOf(step)
                            )
                        )
                        addLog("Plan Step ${step.stepIndex}: ${step.title} -> ${step.details}")
                    }
                )

                val agentMsg = ChatMessage(
                    sender = "agent",
                    content = response.responseMarkdown,
                    task = response.task,
                    logOutput = response.executionSummary
                )

                val combinedVulns = (_uiState.value.allVulnerabilities + response.vulnerabilities).distinctBy { it.id }

                _uiState.value = _uiState.value.copy(
                    chatMessages = _uiState.value.chatMessages + agentMsg,
                    currentTaskPlan = response.task,
                    webScanResult = response.webResult ?: _uiState.value.webScanResult,
                    apiScanResult = response.apiResult ?: _uiState.value.apiScanResult,
                    apkScanResult = response.apkResult ?: _uiState.value.apkScanResult,
                    allVulnerabilities = combinedVulns,
                    isScanning = false,
                    statusMessage = "Task completed by Codex Cyber Agent Ultimate"
                )
                addLog("Task finished successfully.")
            } catch (e: Exception) {
                val errorMsg = ChatMessage(
                    sender = "system",
                    content = "Task execution encountered an error: ${e.message}"
                )
                _uiState.value = _uiState.value.copy(
                    chatMessages = _uiState.value.chatMessages + errorMsg,
                    isScanning = false,
                    errorMessage = e.message
                )
                addLog("Error executing AI Task: ${e.message}")
            }
        }
    }

    // --- Ollama Settings ---
    fun updateOllamaConfig(config: OllamaConfig) {
        _uiState.value = _uiState.value.copy(ollamaConfig = config)
    }

    fun testOllamaConnection() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(statusMessage = "Testing connection to Ollama at ${_uiState.value.ollamaConfig.endpointUrl}...")
            val (online, models) = aiAgentService.checkOllamaConnection(_uiState.value.ollamaConfig)
            val updatedConfig = _uiState.value.ollamaConfig.copy(isConnected = online)
            _uiState.value = _uiState.value.copy(
                ollamaConfig = updatedConfig,
                ollamaStatusText = if (online) "Ollama: Connected (${models.size} models available)" else "Ollama: Unreachable (Offline expert engine ready)",
                availableModels = if (models.isNotEmpty()) models else _uiState.value.availableModels,
                statusMessage = if (online) "Ollama connected! Model: ${updatedConfig.model}" else "Could not reach Ollama at ${updatedConfig.endpointUrl}. Check if server is running."
            )
            addLog("Ollama check result: ${if (online) "ONLINE" else "OFFLINE"}")
        }
    }

    // --- Export Reports ---
    fun exportHtmlReport(): String {
        val target = _uiState.value.targetUrl
        val score = _uiState.value.webScanResult?.score ?: _uiState.value.overallSecurityScore
        val html = ReportExporter.generateHtmlReport(
            target = target,
            score = score,
            vulnerabilities = _uiState.value.allVulnerabilities,
            webResult = _uiState.value.webScanResult
        )
        val file = ReportExporter.saveReportFile(getApplication(), html, "codex_security_report.html")
        _uiState.value = _uiState.value.copy(statusMessage = "HTML Report saved to: ${file.name}")
        addLog("Exported HTML report (${file.length()} bytes)")
        return html
    }

    fun exportJsonReport(): String {
        val target = _uiState.value.targetUrl
        val score = _uiState.value.webScanResult?.score ?: _uiState.value.overallSecurityScore
        val json = ReportExporter.generateJsonReport(
            target = target,
            score = score,
            vulnerabilities = _uiState.value.allVulnerabilities,
            webResult = _uiState.value.webScanResult
        )
        val file = ReportExporter.saveReportFile(getApplication(), json, "codex_security_report.json")
        _uiState.value = _uiState.value.copy(statusMessage = "JSON Report saved to: ${file.name}")
        addLog("Exported JSON report (${file.length()} bytes)")
        return json
    }

    fun exportMarkdownReport(): String {
        val target = _uiState.value.targetUrl
        val score = _uiState.value.webScanResult?.score ?: _uiState.value.overallSecurityScore
        val md = ReportExporter.generateMarkdownReport(
            target = target,
            score = score,
            vulnerabilities = _uiState.value.allVulnerabilities,
            webResult = _uiState.value.webScanResult
        )
        val file = ReportExporter.saveReportFile(getApplication(), md, "codex_security_report.md")
        _uiState.value = _uiState.value.copy(statusMessage = "Markdown Report saved to: ${file.name}")
        addLog("Exported Markdown report (${file.length()} bytes)")
        return md
    }

    fun shareCurrentReport() {
        val target = _uiState.value.targetUrl
        val summary = "Codex Cyber Agent Ultimate Security Audit for $target\n" +
                "Score: ${_uiState.value.overallSecurityScore}/100\n" +
                "Vulnerabilities: ${_uiState.value.allVulnerabilities.size}\n\n" +
                _uiState.value.allVulnerabilities.joinToString("\n\n") {
                    "[${it.severity}] ${it.title}\nCategory: ${it.category}\nRemediation: ${it.remediation}"
                }
        ReportExporter.shareReport(getApplication(), "Codex Security Audit - $target", summary)
    }

    fun clearHistory() {
        _uiState.value = _uiState.value.copy(
            allVulnerabilities = emptyList(),
            webScanResult = null,
            apiScanResult = null,
            chatMessages = listOf(
                ChatMessage(sender = "system", content = "Audit history cleared. Environment reset.")
            ),
            logs = emptyList(),
            statusMessage = "History cleared"
        )
        addLog("Audit history purged by operator.")
    }
}
