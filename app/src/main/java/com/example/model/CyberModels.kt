package com.example.model

enum class RiskLevel(val label: String, val weight: Int) {
    CRITICAL("CRITICAL", 25),
    HIGH("HIGH", 15),
    MEDIUM("MEDIUM", 8),
    LOW("LOW", 3),
    INFO("INFO", 0),
    SECURE("SECURE", 0)
}

enum class TestStatus(val label: String) {
    PASS("PASS"),
    PARTIAL("PARTIAL"),
    BLOCKED("BLOCKED"),
    FAIL("FAIL"),
    NOT_TESTED("NOT TESTED")
}

enum class ToolAvailability(val label: String) {
    AVAILABLE_NATIVE("Native Android SDK"),
    AVAILABLE_LOCAL_BACKEND("Local AI / Engine"),
    REQUIRES_EXTERNAL_SERVICE("External Service"),
    REQUIRES_TERMUX_OR_ROOT("Requires Termux / Root")
}

data class ToolParameter(
    val name: String,
    val label: String,
    val defaultValue: String,
    val description: String,
    val required: Boolean = true
)

data class SecurityTool(
    val id: String,
    val name: String,
    val category: String,
    val description: String,
    val executablePath: String,
    val version: String,
    val dependencies: List<String>,
    val inputParameters: List<ToolParameter>,
    val outputFormat: String,
    val availability: ToolAvailability,
    val testStatus: TestStatus = TestStatus.NOT_TESTED,
    val testResultDetails: String = "Test not yet executed",
    val documentation: String = ""
)

data class ToolExecutionResult(
    val toolId: String,
    val toolName: String,
    val status: String, // "SUCCESS", "ERROR", "CANCELLED", "BLOCKED"
    val exitCode: Int,
    val stdout: String,
    val stderr: String,
    val executionTimeMs: Long,
    val timestamp: Long = System.currentTimeMillis()
)

data class VulnerabilityItem(
    val id: String,
    val title: String,
    val category: String,
    val severity: RiskLevel,
    val description: String,
    val impact: String,
    val remediation: String,
    val remediationCode: String? = null,
    val owaspReference: String? = null,
    val target: String = ""
)

data class HeaderAudit(
    val headerName: String,
    val present: Boolean,
    val value: String?,
    val isSecure: Boolean,
    val recommendation: String,
    val risk: RiskLevel
)

data class TlsAuditResult(
    val protocol: String,
    val cipherSuite: String,
    val subject: String,
    val issuer: String,
    val validFrom: String,
    val validTo: String,
    val isExpired: Boolean,
    val daysRemaining: Long,
    val sans: List<String>
)

data class DnsRecord(
    val type: String,
    val value: String,
    val status: String = "Resolved"
)

data class NetworkPortCheck(
    val port: Int,
    val service: String,
    val isOpen: Boolean,
    val latencyMs: Long,
    val statusNote: String
)

data class WebScanResult(
    val targetUrl: String,
    val statusCode: Int,
    val responseTimeMs: Long,
    val headers: List<HeaderAudit>,
    val tls: TlsAuditResult?,
    val dnsRecords: List<DnsRecord>,
    val portChecks: List<NetworkPortCheck>,
    val score: Int,
    val vulnerabilities: List<VulnerabilityItem>,
    val timestamp: Long = System.currentTimeMillis()
)

data class ApiEndpointResult(
    val url: String,
    val method: String,
    val statusCode: Int,
    val latencyMs: Long,
    val corsConfigured: Boolean,
    val corsAllowOrigin: String?,
    val authEnforced: Boolean,
    val contentSniffingPrevented: Boolean,
    val rawResponseSnippet: String,
    val vulnerabilities: List<VulnerabilityItem>
)

data class ApkAuditResult(
    val packageName: String,
    val appName: String,
    val targetSdk: Int,
    val minSdk: Int,
    val isDebuggable: Boolean,
    val allowsBackup: Boolean,
    val usesCleartextTraffic: Boolean,
    val dangerousPermissions: List<String>,
    val declaredPermissions: List<String>,
    val exportedComponents: List<String>,
    val vulnerabilities: List<VulnerabilityItem>,
    val securityScore: Int
)

data class OllamaConfig(
    val endpointUrl: String = "http://10.0.2.2:11434",
    val model: String = "llama3:latest",
    val customAuthHeader: String = "",
    val providerType: String = "OLLAMA", // "OLLAMA", "OPENAI_COMPATIBLE", "LOCAL_ENGINE"
    val temperature: Float = 0.3f,
    val topP: Float = 0.9f,
    val contextLength: Int = 4096,
    val systemPrompt: String = "You are Codex Cyber Agent Ultimate, an elite defensive cybersecurity AI. Analyze findings deeply, map to OWASP/CWE/NIST, explain risk implications, and generate precise hardening configurations.",
    val scopeConsentApproved: Boolean = true,
    val isConnected: Boolean = false
)

data class TaskStep(
    val stepIndex: Int,
    val title: String,
    val tool: String,
    val details: String,
    val isDone: Boolean = false
)

data class AgentTask(
    val id: String,
    val title: String,
    val target: String,
    val steps: List<TaskStep>,
    val isCompleted: Boolean = false
)

data class ChatMessage(
    val id: String = java.util.UUID.randomUUID().toString(),
    val sender: String, // "user", "agent", "system"
    val content: String,
    val timestamp: Long = System.currentTimeMillis(),
    val task: AgentTask? = null,
    val logOutput: String? = null
)
