package com.example.service

import com.example.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.util.concurrent.TimeUnit

class ApiAndNetworkAnalyzer {

    private val client = OkHttpClient.Builder()
        .connectTimeout(6, TimeUnit.SECONDS)
        .readTimeout(6, TimeUnit.SECONDS)
        .followRedirects(false)
        .build()

    suspend fun analyzeApiEndpoint(
        rawUrl: String,
        method: String = "GET",
        headers: Map<String, String> = emptyMap()
    ): ApiEndpointResult = withContext(Dispatchers.IO) {
        val normalizedUrl = if (!rawUrl.startsWith("http://") && !rawUrl.startsWith("https://")) {
            "https://$rawUrl"
        } else {
            rawUrl
        }

        val startTime = System.currentTimeMillis()
        var statusCode = 0
        var corsAllowOrigin: String? = null
        var corsAllowCredentials: String? = null
        var contentType: String? = null
        var responseSnippet = ""
        val vulnerabilities = mutableListOf<VulnerabilityItem>()

        try {
            val reqBuilder = Request.Builder().url(normalizedUrl)
            // Add custom or default headers
            reqBuilder.header("User-Agent", "Codex-Cyber-Agent/1.0-ApiAnalyzer")
            reqBuilder.header("Origin", "https://untrusted-client.codex.internal")
            for ((k, v) in headers) {
                reqBuilder.header(k, v)
            }

            if (method.equals("OPTIONS", true)) {
                reqBuilder.method("OPTIONS", null)
            } else if (method.equals("HEAD", true)) {
                reqBuilder.head()
            } else {
                reqBuilder.get()
            }

            client.newCall(reqBuilder.build()).execute().use { resp ->
                statusCode = resp.code
                corsAllowOrigin = resp.header("Access-Control-Allow-Origin")
                corsAllowCredentials = resp.header("Access-Control-Allow-Credentials")
                contentType = resp.header("Content-Type")

                val bodyStr = resp.body?.string() ?: ""
                responseSnippet = if (bodyStr.length > 500) bodyStr.take(500) + "..." else bodyStr
            }
        } catch (e: Exception) {
            statusCode = 500
            responseSnippet = "Connection error: ${e.message}"
        }

        val latency = System.currentTimeMillis() - startTime

        // Evaluate CORS
        val corsConfigured = corsAllowOrigin != null
        if (corsAllowOrigin == "*") {
            vulnerabilities.add(
                VulnerabilityItem(
                    id = "VULN-API-CORS-01",
                    title = "Permissive CORS Wildcard (*)",
                    category = "API Security",
                    severity = RiskLevel.MEDIUM,
                    description = "API endpoint returns Access-Control-Allow-Origin: *, allowing any arbitrary domain to read responses.",
                    impact = "Potential Cross-Origin data leakage if endpoint returns user-specific records.",
                    remediation = "Restrict CORS to explicit trusted origins and avoid wildcard reflection.",
                    remediationCode = "Access-Control-Allow-Origin: https://app.yourdomain.com",
                    owaspReference = "API7:2023-Server Side Request Forgery / Security Misconfiguration",
                    target = normalizedUrl
                )
            )
        }

        if (corsAllowOrigin != null && corsAllowCredentials.equals("true", true) && corsAllowOrigin == "*") {
            vulnerabilities.add(
                VulnerabilityItem(
                    id = "VULN-API-CORS-02",
                    title = "CORS Wildcard with Credentials Allowed",
                    category = "API Security",
                    severity = RiskLevel.CRITICAL,
                    description = "Dangerous configuration: Wildcard origin specified alongside Access-Control-Allow-Credentials: true.",
                    impact = "Third-party origins can execute authenticated requests and extract private user sessions.",
                    remediation = "Explicitly whitelist origins when credentials (cookies/tokens) are allowed.",
                    owaspReference = "API2:2023-Broken Authentication",
                    target = normalizedUrl
                )
            )
        }

        // Evaluate unauthenticated access on sensitive endpoints
        val isPotentiallySensitivePath = listOf("/admin", "/user", "/account", "/internal", "/keys", "/config", "/actuator", "/env")
            .any { normalizedUrl.lowercase().contains(it) }

        val authEnforced = statusCode in listOf(401, 403)
        if (isPotentiallySensitivePath && statusCode == 200) {
            vulnerabilities.add(
                VulnerabilityItem(
                    id = "VULN-API-AUTH-01",
                    title = "Potential Unauthenticated Access to Sensitive Route",
                    category = "API Access Control",
                    severity = RiskLevel.HIGH,
                    description = "Endpoint returned HTTP 200 without Authorization credentials supplied on potentially sensitive path.",
                    impact = "Unauthorized data disclosure or privilege bypass.",
                    remediation = "Enforce token authentication (Bearer JWT or mutual TLS) at the API gateway or controller.",
                    remediationCode = "// Enforce JWT verification before dispatching handler\n@PreAuthorize(\"hasRole('USER')\")",
                    owaspReference = "API1:2023-Broken Object Level Authorization",
                    target = normalizedUrl
                )
            )
        }

        val contentSniffingPrevented = responseSnippet.contains("nosniff", ignoreCase = true)

        ApiEndpointResult(
            url = normalizedUrl,
            method = method,
            statusCode = statusCode,
            latencyMs = latency,
            corsConfigured = corsConfigured,
            corsAllowOrigin = corsAllowOrigin,
            authEnforced = authEnforced,
            contentSniffingPrevented = contentSniffingPrevented,
            rawResponseSnippet = responseSnippet,
            vulnerabilities = vulnerabilities
        )
    }

    suspend fun testWebSocketHandshake(rawWsUrl: String): String = withContext(Dispatchers.IO) {
        val normalized = if (!rawWsUrl.startsWith("ws://") && !rawWsUrl.startsWith("wss://")) {
            "wss://$rawWsUrl"
        } else {
            rawWsUrl
        }

        val httpUrl = normalized.replace("wss://", "https://").replace("ws://", "http://")
        val startTime = System.currentTimeMillis()

        try {
            val req = Request.Builder()
                .url(httpUrl)
                .header("Upgrade", "websocket")
                .header("Connection", "Upgrade")
                .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
                .header("Sec-WebSocket-Version", "13")
                .build()

            client.newCall(req).execute().use { resp ->
                val elapsed = System.currentTimeMillis() - startTime
                val is101 = resp.code == 101
                val upgradeHeader = resp.header("Upgrade")
                "Handshake status: ${resp.code} (${if (is101) "101 Switching Protocols" else "Response code"})\n" +
                        "Latency: ${elapsed}ms\n" +
                        "Upgrade header: ${upgradeHeader ?: "None"}\n" +
                        "WSS Encryption: ${if (normalized.startsWith("wss://")) "Active (TLS)" else "Insecure (Plain ws://)"}"
            }
        } catch (e: Exception) {
            "WebSocket diagnostic error: ${e.message ?: "Socket failed"}"
        }
    }

    suspend fun getLocalNetworkDetails(): List<Pair<String, String>> = withContext(Dispatchers.IO) {
        val details = mutableListOf<Pair<String, String>>()
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            while (interfaces.hasMoreElements()) {
                val iface = interfaces.nextElement()
                if (iface.isUp && !iface.isLoopback) {
                    val addrs = iface.inetAddresses
                    while (addrs.hasMoreElements()) {
                        val addr = addrs.nextElement()
                        if (!addr.isLoopbackAddress && addr.hostAddress != null && addr.address.size == 4) {
                            details.add(Pair(iface.displayName ?: iface.name, addr.hostAddress ?: ""))
                        }
                    }
                }
            }
        } catch (e: Exception) {
            details.add(Pair("Error", e.message ?: "Cannot inspect interfaces"))
        }

        if (details.isEmpty()) {
            details.add(Pair("Primary Interface", "10.0.2.15 (Emulator / Local subnet)"))
        }
        details
    }

    suspend fun pingHost(host: String, port: Int = 443): Pair<Boolean, Long> = withContext(Dispatchers.IO) {
        val start = System.currentTimeMillis()
        var reachable = false
        try {
            Socket().use { s ->
                s.connect(InetSocketAddress(host, port), 2000)
                reachable = true
            }
        } catch (e: Exception) {
            reachable = false
        }
        Pair(reachable, System.currentTimeMillis() - start)
    }
}
