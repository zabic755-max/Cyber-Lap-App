package com.example.service

import com.example.model.RiskLevel

data class ThreatIntelEntry(
    val id: String,
    val title: String,
    val category: String,
    val cweId: String,
    val severity: RiskLevel,
    val description: String,
    val attackVector: String,
    val remediation: String,
    val codeExample: String
)

object CveThreatDatabase {

    val entries = listOf(
        ThreatIntelEntry(
            id = "THREAT-001",
            title = "Missing HTTP Strict Transport Security (HSTS)",
            category = "Web Transport Security",
            cweId = "CWE-319",
            severity = RiskLevel.HIGH,
            description = "Without HSTS, browsers can be coerced into initiating initial HTTP connections that attackers can intercept using SSL-stripping tools like sslstrip.",
            attackVector = "Attacker on local WiFi or rogue hotspot downgrades HTTPS traffic to unencrypted plaintext HTTP via ARP spoofing or DNS redirection.",
            remediation = "Emit the Strict-Transport-Security header with a minimum 1-year max-age, includeSubDomains directive, and preload token.",
            codeExample = "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;"
        ),
        ThreatIntelEntry(
            id = "THREAT-002",
            title = "Missing or Lax Content-Security-Policy (CSP)",
            category = "Injection & XSS Defense",
            cweId = "CWE-79",
            severity = RiskLevel.HIGH,
            description = "Absence of CSP allows malicious scripts injected via Cross-Site Scripting (XSS) to execute within the victim's authenticated browser context.",
            attackVector = "Reflected or stored XSS payloads extract session cookies, localStorage tokens, or exfiltrate keystrokes to an attacker-controlled listener.",
            remediation = "Deploy Content-Security-Policy with strict nonces or hashes, disallow 'unsafe-inline' and 'unsafe-eval', and restrict object-src to 'none'.",
            codeExample = "add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'nonce-RANDOM'; object-src 'none'; base-uri 'self';\" always;"
        ),
        ThreatIntelEntry(
            id = "THREAT-003",
            title = "Permissive Wildcard CORS with Credentials",
            category = "API & Access Control",
            cweId = "CWE-942",
            severity = RiskLevel.CRITICAL,
            description = "Allowing Access-Control-Allow-Origin: * alongside Access-Control-Allow-Credentials: true or reflecting arbitrary Origin headers allows malicious sites to read private authenticated API responses.",
            attackVector = "Attacker entices victim to visit a malicious website which issues fetch() requests with credentials to the target API and exfiltrates confidential responses.",
            remediation = "Strictly whitelist authorized origin domains and never dynamically mirror untrusted Origin headers when credentials are accepted.",
            codeExample = "if (\$http_origin ~* ^https://(app\\.yourdomain\\.com)\$) {\n    add_header Access-Control-Allow-Origin \$http_origin;\n    add_header Access-Control-Allow-Credentials \"true\";\n}"
        ),
        ThreatIntelEntry(
            id = "THREAT-004",
            title = "Clickjacking via Missing X-Frame-Options",
            category = "UI Redressing",
            cweId = "CWE-1021",
            severity = RiskLevel.MEDIUM,
            description = "Pages lacking X-Frame-Options or CSP frame-ancestors can be framed inside transparent <iframe> elements on adversary sites.",
            attackVector = "Attacker overlays decoy UI buttons directly over the framed target page, tricking users into executing unintended transactions or authorization grants.",
            remediation = "Set X-Frame-Options to DENY or SAMEORIGIN, or configure CSP frame-ancestors 'none'.",
            codeExample = "add_header X-Frame-Options \"DENY\" always;\n# Or in CSP:\nadd_header Content-Security-Policy \"frame-ancestors 'none';\" always;"
        ),
        ThreatIntelEntry(
            id = "THREAT-005",
            title = "MIME-Type Sniffing Exposure",
            category = "MIME Confusion",
            cweId = "CWE-430",
            severity = RiskLevel.LOW,
            description = "Browsers may inspect response bodies and interpret user-uploaded text or image files as executable HTML/JavaScript.",
            attackVector = "Adversary uploads an image file with embedded polyglot JavaScript that executes when viewed directly in the victim's browser.",
            remediation = "Set X-Content-Type-Options to 'nosniff' to force browsers to strictly adhere to declared MIME types.",
            codeExample = "add_header X-Content-Type-Options \"nosniff\" always;"
        ),
        ThreatIntelEntry(
            id = "THREAT-006",
            title = "Android Binary Debuggable Flag (FLAG_DEBUGGABLE)",
            category = "Mobile Binary Hardening",
            cweId = "CWE-215",
            severity = RiskLevel.CRITICAL,
            description = "Building an APK with android:debuggable=\"true\" leaves the JDWP (Java Debug Wire Protocol) interface open for remote debugging.",
            attackVector = "Anyone with ADB access or local malware can attach a debugger (jdb), inspect all memory structures, and bypass security checks dynamically.",
            remediation = "Ensure release builds explicitly set isDebuggable = false in Gradle.",
            codeExample = "buildTypes {\n    release {\n        isDebuggable = false\n        isMinifyEnabled = true\n    }\n}"
        ),
        ThreatIntelEntry(
            id = "THREAT-007",
            title = "Android ADB Backup Data Exposure",
            category = "Mobile Data Protection",
            cweId = "CWE-312",
            severity = RiskLevel.MEDIUM,
            description = "When android:allowBackup=\"true\", users and local tools can run 'adb backup' to dump the app's internal databases, tokens, and SharedPreferences.",
            attackVector = "Physical or temporary device access allows extracting sensitive app tokens and databases without requiring device root.",
            remediation = "Disable allowBackup or define strict dataExtractionRules in AndroidManifest.xml.",
            codeExample = "<application\n    android:allowBackup=\"false\"\n    android:dataExtractionRules=\"@xml/data_extraction_rules\">"
        ),
        ThreatIntelEntry(
            id = "THREAT-008",
            title = "Android Cleartext HTTP Permitted",
            category = "Mobile Network Security",
            cweId = "CWE-319",
            severity = RiskLevel.HIGH,
            description = "Apps configured with usesCleartextTraffic=\"true\" can send API tokens and private data across unencrypted HTTP.",
            attackVector = "Network eavesdroppers monitor WiFi packets and capture plain API tokens and sensitive user telemetry.",
            remediation = "Disallow cleartext traffic and mandate a Network Security Configuration file.",
            codeExample = "<network-security-config>\n    <base-config cleartextTrafficPermitted=\"false\" />\n</network-security-config>"
        ),
        ThreatIntelEntry(
            id = "THREAT-009",
            title = "Broken Object Level Authorization (BOLA)",
            category = "API Security",
            cweId = "CWE-285",
            severity = RiskLevel.CRITICAL,
            description = "APIs that expose object identifiers (e.g. /api/users/123/documents) without verifying that the requesting user owns the object.",
            attackVector = "Attacker iterates through sequential IDs (IDOR) to access, modify, or delete sensitive records belonging to other tenants.",
            remediation = "Enforce object-level ownership checks at the data repository layer for every request.",
            codeExample = "// Verify ownership before returning data\nif (!document.getOwnerId().equals(currentUser.getId())) {\n    throw new AccessDeniedException(\"Unauthorized\");\n}"
        ),
        ThreatIntelEntry(
            id = "THREAT-010",
            title = "Insecure TLS TrustManager / Hostname Bypass",
            category = "Cryptographic Implementation",
            cweId = "CWE-295",
            severity = RiskLevel.CRITICAL,
            description = "Custom TrustManager implementations with empty checkServerTrusted() methods accept any self-signed or forged certificate.",
            attackVector = "Man-in-the-Middle interceptors generate forged certificates that the mobile app blindly trusts, completely bypassing TLS encryption.",
            remediation = "Rely on Android system CA validation and implement certificate transparency or pinning with OkHttp CertificatePinner.",
            codeExample = "val certificatePinner = CertificatePinner.Builder()\n    .add(\"api.yourdomain.com\", \"sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\")\n    .build()"
        )
    )

    fun search(query: String): List<ThreatIntelEntry> {
        if (query.isBlank()) return entries
        return entries.filter {
            it.title.contains(query, ignoreCase = true) ||
            it.cweId.contains(query, ignoreCase = true) ||
            it.category.contains(query, ignoreCase = true) ||
            it.description.contains(query, ignoreCase = true)
        }
    }
}
