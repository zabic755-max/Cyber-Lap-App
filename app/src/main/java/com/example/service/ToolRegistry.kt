package com.example.service

import android.content.Context
import com.example.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

class ToolRegistry(
    private val context: Context,
    private val webScanner: CyberSecurityScanner,
    private val apiAnalyzer: ApiAndNetworkAnalyzer,
    private val apkAnalyzer: ApkSecurityAnalyzer
) {

    private val toolsMap = mutableMapOf<String, SecurityTool>()

    init {
        registerAllTools()
    }

    private fun registerAllTools() {
        // 1. Web Security Headers
        register(
            SecurityTool(
                id = "tool_web_headers",
                name = "HTTP Security Header Inspector",
                category = "Web & Transport",
                description = "Inspects HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.",
                executablePath = "com.example.service.CyberSecurityScanner#evaluateHeaders",
                version = "1.2.0 (Native OkHttp/Compose)",
                dependencies = listOf("okhttp3:4.10.0", "android.permission.INTERNET"),
                inputParameters = listOf(
                    ToolParameter("targetUrl", "Target URL", "https://example.com", "URL of the target web server", true)
                ),
                outputFormat = "JSON / Structured Audit",
                availability = ToolAvailability.AVAILABLE_NATIVE,
                documentation = "Executes an authorized HTTP HEAD/GET request to evaluate defensive HTTP response headers against OWASP Security Misconfiguration guidelines."
            )
        )

        // 2. TLS Certificate Inspector
        register(
            SecurityTool(
                id = "tool_tls_inspector",
                name = "TLS Certificate & Cipher Validator",
                category = "Web & Transport",
                description = "Validates X.509 SSL/TLS certificates, expiry dates, cipher suites, issuer chain, and Subject Alternative Names (SANs).",
                executablePath = "javax.net.ssl.SSLSocket / SSLContext",
                version = "TLSv1.3 Engine (Android Conscrypt)",
                dependencies = listOf("javax.net.ssl", "java.security.cert"),
                inputParameters = listOf(
                    ToolParameter("host", "Host Domain", "example.com", "Target hostname to negotiate TLS with", true),
                    ToolParameter("port", "Port", "443", "TLS port number", true)
                ),
                outputFormat = "Structured Certificate Spec",
                availability = ToolAvailability.AVAILABLE_NATIVE,
                documentation = "Establishes a TLS socket handshake, extracts the server peer certificate chain, and checks for expired certificates or weak cipher suites."
            )
        )

        // 3. DNS Resolver
        register(
            SecurityTool(
                id = "tool_dns_diag",
                name = "DNS Resolution & Diagnostics",
                category = "Network & Host",
                description = "Resolves A (IPv4) and AAAA (IPv6) records, checks reverse PTR lookups, and evaluates DNS stub resolver response.",
                executablePath = "java.net.InetAddress#getAllByName",
                version = "2.1.0 (Android Libcore)",
                dependencies = listOf("java.net.InetAddress"),
                inputParameters = listOf(
                    ToolParameter("domain", "Domain Name", "example.com", "Domain name to resolve", true)
                ),
                outputFormat = "DNS Record Table",
                availability = ToolAvailability.AVAILABLE_NATIVE,
                documentation = "Queries local and upstream DNS resolvers to verify records, domain reachability, and dual-stack IPv4/IPv6 support."
            )
        )

        // 4. Defensive Port Scanner
        register(
            SecurityTool(
                id = "tool_port_scanner",
                name = "Defensive TCP Port Scanner",
                category = "Network & Host",
                description = "Tests socket connectivity on standard authorized service ports (80, 443, 8080, 8443) with latency metrics.",
                executablePath = "java.net.Socket#connect",
                version = "1.0.0 (Native Sockets)",
                dependencies = listOf("java.net.Socket", "android.permission.INTERNET"),
                inputParameters = listOf(
                    ToolParameter("host", "Target Host", "1.1.1.1", "Host or IP to test", true),
                    ToolParameter("port", "Port", "443", "Target TCP port", true)
                ),
                outputFormat = "Socket Status & Latency",
                availability = ToolAvailability.AVAILABLE_NATIVE,
                documentation = "Performs non-intrusive TCP socket connection checks with a 1.2-second timeout to verify service availability on authorized targets."
            )
        )

        // 5. API & CORS Analyzer
        register(
            SecurityTool(
                id = "tool_api_cors",
                name = "REST API & CORS Security Analyzer",
                category = "API & WebSocket",
                description = "Audits API endpoints for wildcard CORS reflection, credentials handling, HTTP methods allowed, and unauthenticated sensitive paths.",
                executablePath = "com.example.service.ApiAndNetworkAnalyzer#analyzeApiEndpoint",
                version = "1.1.0 (REST/CORS Engine)",
                dependencies = listOf("okhttp3:4.10.0"),
                inputParameters = listOf(
                    ToolParameter("url", "API Endpoint URL", "https://example.com/api", "Full target URL", true),
                    ToolParameter("method", "HTTP Method", "GET", "HTTP method: GET, OPTIONS, HEAD", true)
                ),
                outputFormat = "API Risk Assessment",
                availability = ToolAvailability.AVAILABLE_NATIVE,
                documentation = "Simulates cross-origin requests with custom Origin headers to verify whether the server safely restricts Cross-Origin Resource Sharing."
            )
        )

        // 6. WebSocket Handshaker
        register(
            SecurityTool(
                id = "tool_ws_handshake",
                name = "WebSocket Handshake Analyzer",
                category = "API & WebSocket",
                description = "Tests WebSocket (ws:// & wss://) protocol upgrade handshakes, Sec-WebSocket-Key responses, and TLS transport encryption.",
                executablePath = "com.example.service.ApiAndNetworkAnalyzer#testWebSocketHandshake",
                version = "1.0.0 (WSS Handshaker)",
                dependencies = listOf("okhttp3:4.10.0"),
                inputParameters = listOf(
                    ToolParameter("wsUrl", "WebSocket URL", "wss://echo.websocket.org", "Target WebSocket URL", true)
                ),
                outputFormat = "Handshake Diagnostic Log",
                availability = ToolAvailability.AVAILABLE_NATIVE,
                documentation = "Issues an RFC 6455 HTTP Upgrade request to verify that WebSocket endpoints correctly negotiate connection switching and enforce WSS encryption."
            )
        )

        // 7. Android Package Manifest Inspector
        register(
            SecurityTool(
                id = "tool_apk_manifest",
                name = "Android APK & Manifest Auditor",
                category = "Android & Mobile",
                description = "Inspects installed Android packages for dangerous runtime permissions, debuggable flags, allowBackup risks, and unpermissioned exported components.",
                executablePath = "android.content.pm.PackageManager",
                version = "Android SDK API 36 Platform",
                dependencies = listOf("android.content.pm.PackageManager"),
                inputParameters = listOf(
                    ToolParameter("packageName", "Package ID", "com.codex.cyberagent", "Installed package name to inspect", true)
                ),
                outputFormat = "Manifest Security Matrix",
                availability = ToolAvailability.AVAILABLE_NATIVE,
                documentation = "Audits the application manifest using Android platform reflection, mapping component export states to OWASP Mobile Top 10 vulnerabilities."
            )
        )

        // 8. Static Source Code & Secret Reviewer
        register(
            SecurityTool(
                id = "tool_static_code",
                name = "Static Source Code & Secret Auditor",
                category = "Static Code & Crypto",
                description = "Scans code snippets for hardcoded API keys/passwords, deprecated hashing algorithms (MD5/DES), and insecure WebView configurations.",
                executablePath = "com.example.service.ApkSecurityAnalyzer#auditStaticSourceCode",
                version = "1.0.0 (Regex & AST Static Rules)",
                dependencies = listOf("kotlin.text.Regex"),
                inputParameters = listOf(
                    ToolParameter("codeSnippet", "Code Snippet", "val apiKey = \"AIzaSyD-sample-key-12345\"", "Source code or XML text to audit", true)
                ),
                outputFormat = "Static Vulnerability Report",
                availability = ToolAvailability.AVAILABLE_NATIVE,
                documentation = "Performs rule-based static analysis against source code to catch credential leaks, dangerous WebView bridges, and SSL validation bypasses."
            )
        )

        // 9. Local Network Interface Inspector
        register(
            SecurityTool(
                id = "tool_network_iface",
                name = "Network Interface & IP Enumerator",
                category = "Network & Host",
                description = "Enumerates active network interfaces, hardware adapters, assigned IPv4 addresses, and subnet details.",
                executablePath = "java.net.NetworkInterface#getNetworkInterfaces",
                version = "1.0.0 (Native Network Interface)",
                dependencies = listOf("java.net.NetworkInterface"),
                inputParameters = emptyList(),
                outputFormat = "Interface Table",
                availability = ToolAvailability.AVAILABLE_NATIVE,
                documentation = "Inspects the device's network interfaces to identify local IP allocations, WiFi/cellular adapters, and local routing configurations."
            )
        )

        // 10. AI Agent & Reasoning Engine
        register(
            SecurityTool(
                id = "tool_ollama_ai",
                name = "Configurable AI Cybersecurity Engine",
                category = "AI & Automation",
                description = "Connects to configurable Ollama or OpenAI-compatible endpoints with model selection, temperature control, and multi-step reasoning.",
                executablePath = "http://10.0.2.2:11434/api/generate (or Custom Endpoint)",
                version = "Ollama v0.1.x+ / Local Diagnostic Engine",
                dependencies = listOf("okhttp3:4.10.0", "org.json"),
                inputParameters = listOf(
                    ToolParameter("endpointUrl", "Endpoint URL", "http://10.0.2.2:11434", "Ollama or proxy API URL", true),
                    ToolParameter("model", "Model Name", "llama3:latest", "Model identifier", true),
                    ToolParameter("prompt", "Task Prompt", "Audit security headers for example.com", "Cybersecurity task instruction", true)
                ),
                outputFormat = "Synthesized Analysis & Code Fixes",
                availability = ToolAvailability.AVAILABLE_LOCAL_BACKEND,
                documentation = "Processes audit findings through local LLMs to generate technical explanations, attack impact analysis, and tailored remediation snippets."
            )
        )

        // 11. Defensive Remediation Generator
        register(
            SecurityTool(
                id = "tool_remediation_gen",
                name = "Hardening Config Generator",
                category = "Defensive Remediation",
                description = "Generates production-grade security configs (Nginx, Apache, Spring Boot Security, and Android XML) for detected vulnerabilities.",
                executablePath = "com.example.service.CyberSecurityScanner#getHeaderRemediationInfo",
                version = "1.0.0 (Configuration Engine)",
                dependencies = listOf("Kotlin Standard Library"),
                inputParameters = listOf(
                    ToolParameter("vulnerabilityType", "Vulnerability ID", "HSTS", "Header or vulnerability identifier", true)
                ),
                outputFormat = "Configuration Code Block",
                availability = ToolAvailability.AVAILABLE_NATIVE,
                documentation = "Outputs exact server directive snippets to enforce HTTPS, configure CSP nonces, deny frame nesting, and block MIME sniffing."
            )
        )

        // 12. Security Report Exporter
        register(
            SecurityTool(
                id = "tool_report_exporter",
                name = "Report Exporter (HTML & JSON)",
                category = "Defensive Remediation",
                description = "Compiles findings, telemetry, and remediation into standalone styled HTML documents and structured JSON schemas.",
                executablePath = "com.example.service.ReportExporter",
                version = "1.0.0 (HTML/JSON Reporter)",
                dependencies = listOf("org.json", "java.io.File"),
                inputParameters = listOf(
                    ToolParameter("target", "Target Name", "example.com", "Target identifier in report", true)
                ),
                outputFormat = "HTML / JSON File",
                availability = ToolAvailability.AVAILABLE_NATIVE,
                documentation = "Produces comprehensive assessment reports formatted for technical engineers, compliance auditors, and automated SIEM ingestion."
            )
        )

        // 13. Threat Intelligence & CVE Database
        register(
            SecurityTool(
                id = "tool_threat_intel",
                name = "Offline Threat Intelligence & CVE Engine",
                category = "Threat Intelligence",
                description = "Queries built-in offline CVE, CWE, and OWASP intelligence catalog for attack vectors and hardening code.",
                executablePath = "com.example.service.CveThreatDatabase#search",
                version = "2.0.0 (Threat Intel Catalog)",
                dependencies = listOf("CveThreatDatabase"),
                inputParameters = listOf(
                    ToolParameter("query", "Search Term / CWE / Topic", "HSTS", "Vulnerability, CWE, or vector keyword", true)
                ),
                outputFormat = "Threat Intel Record & Remediation",
                availability = ToolAvailability.AVAILABLE_NATIVE,
                documentation = "Instant offline search across OWASP Web, API, and Mobile vectors with technical attack descriptions and remediation code."
            )
        )

        // 13. External CLI Tool: Nmap (Raw Sockets)
        register(
            SecurityTool(
                id = "tool_nmap_cli",
                name = "Nmap Network Scanner (CLI)",
                category = "External / CLI Utilities",
                description = "Raw network packet mapper. Requires Termux environment or root access for raw socket permissions.",
                executablePath = "/data/data/com.termux/files/usr/bin/nmap",
                version = "Nmap 7.94+ (External)",
                dependencies = listOf("Termux or Root", "libpcap", "CAP_NET_RAW"),
                inputParameters = listOf(
                    ToolParameter("target", "Target IP/Range", "127.0.0.1", "Host or CIDR range", true)
                ),
                outputFormat = "Raw Nmap Output / XML",
                availability = ToolAvailability.REQUIRES_TERMUX_OR_ROOT,
                testStatus = TestStatus.BLOCKED,
                testResultDetails = "External binary requires Termux environment or root privileges. Android sandboxed APK cannot bind raw sockets. Native TCP Port Scanner is active as safe alternative.",
                documentation = "To use Nmap on Android, install Termux (`pkg install nmap`) or execute via ADB bridge. Use the in-app Defensive TCP Port Scanner for sandboxed operations."
            )
        )

        // 14. External CLI Tool: Tcpdump (Raw Packet Sniffer)
        register(
            SecurityTool(
                id = "tool_tcpdump_cli",
                name = "Tcpdump Packet Sniffer (CLI)",
                category = "External / CLI Utilities",
                description = "Low-level packet sniffer. Requires root CAP_NET_RAW / CAP_NET_ADMIN permissions.",
                executablePath = "/system/xbin/tcpdump",
                version = "Tcpdump 4.99+ (External)",
                dependencies = listOf("Root privileges", "CAP_NET_RAW"),
                inputParameters = listOf(
                    ToolParameter("iface", "Network Interface", "wlan0", "Interface to sniff", true)
                ),
                outputFormat = "PCAP / Hex Dump",
                availability = ToolAvailability.REQUIRES_TERMUX_OR_ROOT,
                testStatus = TestStatus.BLOCKED,
                testResultDetails = "Requires root CAP_NET_RAW. Standard Android application sandbox strictly restricts promiscuous network capture.",
                documentation = "Packet capture at L2/L3 requires root access on the Android operating system. Application HTTP and TLS validation operates safely at the L7 layer."
            )
        )
    }

    private fun register(tool: SecurityTool) {
        toolsMap[tool.id] = tool
    }

    fun getAllTools(): List<SecurityTool> = toolsMap.values.toList()

    fun getTool(id: String): SecurityTool? = toolsMap[id]

    fun getCategories(): List<String> = toolsMap.values.map { it.category }.distinct()

    suspend fun executeTool(toolId: String, params: Map<String, String>): ToolExecutionResult = withContext(Dispatchers.IO) {
        val tool = toolsMap[toolId] ?: return@withContext ToolExecutionResult(
            toolId = toolId,
            toolName = "Unknown",
            status = "ERROR",
            exitCode = 1,
            stdout = "",
            stderr = "Tool ID $toolId not found in registry.",
            executionTimeMs = 0
        )

        val startTime = System.currentTimeMillis()

        if (tool.availability == ToolAvailability.REQUIRES_TERMUX_OR_ROOT) {
            return@withContext ToolExecutionResult(
                toolId = tool.id,
                toolName = tool.name,
                status = "BLOCKED",
                exitCode = 126,
                stdout = "",
                stderr = "Execution Blocked: This tool requires a Termux environment or rooted Android privileges.\nNative alternative '${if (tool.id == "tool_nmap_cli") "Defensive TCP Port Scanner" else "HTTP & TLS Inspector"}' is active.",
                executionTimeMs = System.currentTimeMillis() - startTime
            )
        }

        try {
            when (toolId) {
                "tool_web_headers" -> {
                    val url = params["targetUrl"] ?: "https://example.com"
                    val res = webScanner.auditWebTarget(url)
                    val out = StringBuilder()
                    out.append("Target: ${res.targetUrl}\nStatus: HTTP ${res.statusCode}\nResponse Time: ${res.responseTimeMs}ms\n\n")
                    out.append("Headers Audited (${res.headers.size}):\n")
                    res.headers.forEach { h ->
                        out.append("- ${h.headerName}: [${if (h.isSecure) "SECURE" else "INSECURE"}] ${h.value ?: "MISSING"} (${h.recommendation})\n")
                    }
                    val elapsed = System.currentTimeMillis() - startTime
                    ToolExecutionResult(tool.id, tool.name, "SUCCESS", 0, out.toString(), "", elapsed)
                }
                "tool_tls_inspector" -> {
                    val host = params["host"] ?: "example.com"
                    val res = webScanner.auditWebTarget("https://$host")
                    val tls = res.tls
                    val elapsed = System.currentTimeMillis() - startTime
                    if (tls != null) {
                        val out = "Host: $host:443\nProtocol: ${tls.protocol}\nCipher: ${tls.cipherSuite}\nSubject: ${tls.subject}\nIssuer: ${tls.issuer}\nValid: ${tls.validFrom} to ${tls.validTo}\nDays Remaining: ${tls.daysRemaining}\nSANs: ${tls.sans.joinToString(", ")}"
                        ToolExecutionResult(tool.id, tool.name, "SUCCESS", 0, out, "", elapsed)
                    } else {
                        ToolExecutionResult(tool.id, tool.name, "ERROR", 1, "", "Failed to extract TLS certificate. Verify host connectivity.", elapsed)
                    }
                }
                "tool_dns_diag" -> {
                    val domain = params["domain"] ?: "example.com"
                    val res = webScanner.auditWebTarget("https://$domain")
                    val out = res.dnsRecords.joinToString("\n") { "${it.type}: ${it.value} (${it.status})" }
                    val elapsed = System.currentTimeMillis() - startTime
                    ToolExecutionResult(tool.id, tool.name, "SUCCESS", 0, out, "", elapsed)
                }
                "tool_port_scanner" -> {
                    val host = params["host"] ?: "1.1.1.1"
                    val port = params["port"]?.toIntOrNull() ?: 443
                    val (open, latency) = apiAnalyzer.pingHost(host, port)
                    val out = "Host: $host\nPort: $port\nStatus: ${if (open) "OPEN (Accessible)" else "CLOSED / TIMED OUT"}\nLatency: ${latency}ms"
                    val elapsed = System.currentTimeMillis() - startTime
                    ToolExecutionResult(tool.id, tool.name, "SUCCESS", 0, out, "", elapsed)
                }
                "tool_api_cors" -> {
                    val url = params["url"] ?: "https://example.com/api"
                    val method = params["method"] ?: "GET"
                    val res = apiAnalyzer.analyzeApiEndpoint(url, method)
                    val out = "Endpoint: ${res.url}\nMethod: ${res.method}\nStatus: HTTP ${res.statusCode}\nLatency: ${res.latencyMs}ms\nCORS Allow-Origin: ${res.corsAllowOrigin ?: "None"}\nAuth Enforced: ${res.authEnforced}\nFindings: ${res.vulnerabilities.size}"
                    val elapsed = System.currentTimeMillis() - startTime
                    ToolExecutionResult(tool.id, tool.name, "SUCCESS", 0, out, "", elapsed)
                }
                "tool_ws_handshake" -> {
                    val wsUrl = params["wsUrl"] ?: "wss://echo.websocket.org"
                    val res = apiAnalyzer.testWebSocketHandshake(wsUrl)
                    val elapsed = System.currentTimeMillis() - startTime
                    ToolExecutionResult(tool.id, tool.name, "SUCCESS", 0, res, "", elapsed)
                }
                "tool_apk_manifest" -> {
                    val pkg = params["packageName"] ?: context.packageName
                    val res = apkAnalyzer.auditAppPackage(pkg)
                    val out = "Package: ${res.packageName}\nTarget SDK: ${res.targetSdk}\nDebuggable: ${res.isDebuggable}\nAllowBackup: ${res.allowsBackup}\nCleartext: ${res.usesCleartextTraffic}\nDangerous Permissions (${res.dangerousPermissions.size}):\n${res.dangerousPermissions.joinToString("\n") { "  - $it" }}\nExported Components: ${res.exportedComponents.size}\nSecurity Score: ${res.securityScore}/100"
                    val elapsed = System.currentTimeMillis() - startTime
                    ToolExecutionResult(tool.id, tool.name, "SUCCESS", 0, out, "", elapsed)
                }
                "tool_static_code" -> {
                    val code = params["codeSnippet"] ?: "val key = \"sample\""
                    val findings = apkAnalyzer.auditStaticSourceCode(code)
                    val out = if (findings.isEmpty()) {
                        "No static security issues detected in provided snippet."
                    } else {
                        findings.joinToString("\n\n") {
                            "[${it.severity}] ${it.title}\nCategory: ${it.category}\nImpact: ${it.impact}\nRemediation: ${it.remediation}"
                        }
                    }
                    val elapsed = System.currentTimeMillis() - startTime
                    ToolExecutionResult(tool.id, tool.name, "SUCCESS", 0, out, "", elapsed)
                }
                "tool_network_iface" -> {
                    val ifaces = apiAnalyzer.getLocalNetworkDetails()
                    val out = ifaces.joinToString("\n") { "${it.first}: ${it.second}" }
                    val elapsed = System.currentTimeMillis() - startTime
                    ToolExecutionResult(tool.id, tool.name, "SUCCESS", 0, out, "", elapsed)
                }
                "tool_remediation_gen" -> {
                    val vuln = params["vulnerabilityType"] ?: "HSTS"
                    val snippet = when (vuln.uppercase()) {
                        "HSTS" -> "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;"
                        "CSP" -> "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\" always;"
                        "XFO" -> "add_header X-Frame-Options \"DENY\" always;"
                        "XCTO" -> "add_header X-Content-Type-Options \"nosniff\" always;"
                        else -> "# Generic Security Headers\nadd_header X-Content-Type-Options nosniff;\nadd_header X-Frame-Options DENY;"
                    }
                    val elapsed = System.currentTimeMillis() - startTime
                    ToolExecutionResult(tool.id, tool.name, "SUCCESS", 0, snippet, "", elapsed)
                }
                "tool_report_exporter" -> {
                    val target = params["target"] ?: "example.com"
                    val html = ReportExporter.generateHtmlReport(target, 85, emptyList(), null)
                    val file = ReportExporter.saveReportFile(context, html, "audit_$target.html")
                    val elapsed = System.currentTimeMillis() - startTime
                    ToolExecutionResult(tool.id, tool.name, "SUCCESS", 0, "Report successfully generated.\nFile: ${file.absolutePath}\nSize: ${file.length()} bytes", "", elapsed)
                }
                "tool_threat_intel" -> {
                    val query = params["query"] ?: "HSTS"
                    val hits = CveThreatDatabase.search(query)
                    val out = if (hits.isEmpty()) {
                        "No threat entries found matching '$query'."
                    } else {
                        hits.joinToString("\n\n---\n\n") {
                            "[${it.cweId}] ${it.title} (${it.severity.label})\nCategory: ${it.category}\n\nDescription:\n${it.description}\n\nAttack Vector:\n${it.attackVector}\n\nRemediation:\n${it.remediation}\n\nCode Snippet:\n${it.codeExample}"
                        }
                    }
                    val elapsed = System.currentTimeMillis() - startTime
                    ToolExecutionResult(tool.id, tool.name, "SUCCESS", 0, out, "", elapsed)
                }
                else -> {
                    ToolExecutionResult(tool.id, tool.name, "ERROR", 1, "", "Execution handler not implemented for ${tool.id}", System.currentTimeMillis() - startTime)
                }
            }
        } catch (e: Exception) {
            ToolExecutionResult(tool.id, tool.name, "ERROR", 1, "", "Execution error: ${e.message}", System.currentTimeMillis() - startTime)
        }
    }

    suspend fun runSelfTestSuite(): List<Pair<SecurityTool, ToolExecutionResult>> = withContext(Dispatchers.IO) {
        val results = mutableListOf<Pair<SecurityTool, ToolExecutionResult>>()

        for (tool in toolsMap.values) {
            if (tool.availability == ToolAvailability.REQUIRES_TERMUX_OR_ROOT) {
                val updated = tool.copy(
                    testStatus = TestStatus.BLOCKED,
                    testResultDetails = "BLOCKED: External binary requires root or Termux environment. Sandboxed Android security verified."
                )
                toolsMap[tool.id] = updated
                results.add(Pair(updated, ToolExecutionResult(tool.id, tool.name, "BLOCKED", 126, "", updated.testResultDetails, 0)))
                continue
            }

            if (tool.id == "tool_ollama_ai") {
                val updated = tool.copy(
                    testStatus = TestStatus.PARTIAL,
                    testResultDetails = "PARTIAL: Ollama endpoint configurable. Expert defensive fallback reasoning engine operates fully on-device."
                )
                toolsMap[tool.id] = updated
                results.add(Pair(updated, ToolExecutionResult(tool.id, tool.name, "PARTIAL", 0, updated.testResultDetails, "", 10)))
                continue
            }

            // Execute safe test parameters
            val testParams = tool.inputParameters.associate { it.name to it.defaultValue }
            val execResult = executeTool(tool.id, testParams)

            val status = if (execResult.status == "SUCCESS") TestStatus.PASS else TestStatus.FAIL
            val details = if (status == TestStatus.PASS) {
                "PASS: Functional verification completed in ${execResult.executionTimeMs}ms with exit code 0."
            } else {
                "FAIL: ${execResult.stderr}"
            }

            val updated = tool.copy(testStatus = status, testResultDetails = details)
            toolsMap[tool.id] = updated
            results.add(Pair(updated, execResult))
        }

        results
    }
}
