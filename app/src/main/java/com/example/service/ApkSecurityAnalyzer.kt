package com.example.service

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.example.model.ApkAuditResult
import com.example.model.RiskLevel
import com.example.model.VulnerabilityItem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class ApkSecurityAnalyzer(private val context: Context) {

    private val dangerousPermissionsList = setOf(
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE",
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.WRITE_SETTINGS"
    )

    suspend fun auditAppPackage(packageName: String): ApkAuditResult = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val vulnerabilities = mutableListOf<VulnerabilityItem>()

        try {
            val flags = PackageManager.GET_PERMISSIONS or
                    PackageManager.GET_ACTIVITIES or
                    PackageManager.GET_SERVICES or
                    PackageManager.GET_RECEIVERS

            val packageInfo: PackageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, flags)
            }

            val appInfo: ApplicationInfo? = packageInfo.applicationInfo
            val appLabel = if (appInfo != null) pm.getApplicationLabel(appInfo).toString() else packageName

            val isDebuggable = if (appInfo != null) (appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0 else false
            val allowsBackup = if (appInfo != null) (appInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP) != 0 else false
            val usesCleartextTraffic = if (appInfo != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                (appInfo.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC) != 0
            } else {
                true
            }

            val requestedPermissions = packageInfo.requestedPermissions?.toList() ?: emptyList()
            val dangerousDetected = requestedPermissions.filter { dangerousPermissionsList.contains(it) }

            // Check exported components
            val exportedList = mutableListOf<String>()
            packageInfo.activities?.forEach { act ->
                if (act.exported && act.permission.isNullOrBlank() && act.name != null && !act.name.contains("MainActivity")) {
                    exportedList.add("Activity: ${act.name.substringAfterLast('.')}")
                }
            }
            packageInfo.services?.forEach { srv ->
                if (srv.exported && srv.permission.isNullOrBlank()) {
                    exportedList.add("Service: ${srv.name.substringAfterLast('.')}")
                }
            }
            packageInfo.receivers?.forEach { rec ->
                if (rec.exported && rec.permission.isNullOrBlank()) {
                    exportedList.add("Receiver: ${rec.name.substringAfterLast('.')}")
                }
            }

            // Vulnerability evaluations
            if (isDebuggable) {
                vulnerabilities.add(
                    VulnerabilityItem(
                        id = "VULN-APK-001",
                        title = "Application Flagged as Debuggable",
                        category = "Android Binary Hardening",
                        severity = RiskLevel.CRITICAL,
                        description = "android:debuggable=\"true\" is set in production binary. Enables JDWP debugging and arbitrary memory inspection.",
                        impact = "Attackers can attach a debugger via ADB, bypass security checks, and dump runtime memory.",
                        remediation = "Set android:debuggable=\"false\" or ensure build type is release in build.gradle.kts.",
                        remediationCode = "buildTypes {\n    release {\n        isDebuggable = false\n    }\n}",
                        owaspReference = "M1: Insecure Data Storage / M7: Client Code Quality",
                        target = packageName
                    )
                )
            }

            if (allowsBackup) {
                vulnerabilities.add(
                    VulnerabilityItem(
                        id = "VULN-APK-002",
                        title = "ADB Backup Enabled (allowBackup=true)",
                        category = "Android Data Protection",
                        severity = RiskLevel.MEDIUM,
                        description = "Application allows local backup via ADB. Application private storage (databases, SharedPreferences) can be extracted.",
                        impact = "Data extraction on unlocked devices or physical access.",
                        remediation = "Set android:allowBackup=\"false\" or configure android:dataExtractionRules.",
                        remediationCode = "<application\n    android:allowBackup=\"false\"\n    tools:replace=\"android:allowBackup\">",
                        owaspReference = "M2: Insecure Data Storage",
                        target = packageName
                    )
                )
            }

            if (usesCleartextTraffic) {
                vulnerabilities.add(
                    VulnerabilityItem(
                        id = "VULN-APK-003",
                        title = "Cleartext HTTP Traffic Allowed",
                        category = "Android Network Security",
                        severity = RiskLevel.HIGH,
                        description = "android:usesCleartextTraffic is true. App allows unencrypted HTTP connections.",
                        impact = "Man-in-the-Middle network sniffing and data manipulation.",
                        remediation = "Enforce HTTPS and implement a Network Security Configuration restricting cleartext.",
                        remediationCode = "<network-security-config>\n    <base-config cleartextTrafficPermitted=\"false\" />\n</network-security-config>",
                        owaspReference = "M3: Insecure Communication",
                        target = packageName
                    )
                )
            }

            if (exportedList.isNotEmpty()) {
                vulnerabilities.add(
                    VulnerabilityItem(
                        id = "VULN-APK-004",
                        title = "Exported Components Lacking Signature / Permission",
                        category = "Android IPC & Attack Surface",
                        severity = RiskLevel.HIGH,
                        description = "Detected ${exportedList.size} exported component(s) without permission requirements.",
                        impact = "Malicious apps installed on the device can launch components or trigger background tasks.",
                        remediation = "Set android:exported=\"false\" unless component must receive intents from external apps.",
                        remediationCode = "android:exported=\"false\"",
                        owaspReference = "M6: Insecure Authorization",
                        target = packageName
                    )
                )
            }

            if (dangerousDetected.isNotEmpty()) {
                vulnerabilities.add(
                    VulnerabilityItem(
                        id = "VULN-APK-005",
                        title = "Over-Privileged Permission Set (${dangerousDetected.size} Dangerous)",
                        category = "Android Permission Scope",
                        severity = RiskLevel.MEDIUM,
                        description = "App requests sensitive permissions: ${dangerousDetected.map { it.substringAfterLast('.') }.take(5).joinToString(", ")}.",
                        impact = "Broad access to sensitive telemetry and hardware sensors.",
                        remediation = "Review permission requirements following the principle of least privilege.",
                        owaspReference = "M6: Insecure Authorization",
                        target = packageName
                    )
                )
            }

            val penalty = vulnerabilities.sumOf { it.severity.weight }
            val score = (100 - penalty).coerceIn(15, 100)

            ApkAuditResult(
                packageName = packageName,
                appName = appLabel,
                targetSdk = appInfo?.targetSdkVersion ?: 36,
                minSdk = if (appInfo != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) appInfo.minSdkVersion else 21,
                isDebuggable = isDebuggable,
                allowsBackup = allowsBackup,
                usesCleartextTraffic = usesCleartextTraffic,
                dangerousPermissions = dangerousDetected,
                declaredPermissions = requestedPermissions,
                exportedComponents = exportedList,
                vulnerabilities = vulnerabilities,
                securityScore = score
            )
        } catch (e: Exception) {
            // Return self-audit fallback if package lookup fails
            ApkAuditResult(
                packageName = packageName,
                appName = "Target App",
                targetSdk = 36,
                minSdk = 24,
                isDebuggable = false,
                allowsBackup = true,
                usesCleartextTraffic = true,
                dangerousPermissions = emptyList(),
                declaredPermissions = emptyList(),
                exportedComponents = emptyList(),
                vulnerabilities = listOf(
                    VulnerabilityItem(
                        id = "VULN-APK-ERR",
                        title = "Audit Error for $packageName",
                        category = "System",
                        severity = RiskLevel.INFO,
                        description = "Failed to inspect package: ${e.message}",
                        impact = "Package not found or restricted by OS permissions.",
                        remediation = "Verify the package name is installed on the device or use the static code auditor.",
                        target = packageName
                    )
                ),
                securityScore = 75
            )
        }
    }

    suspend fun auditStaticSourceCode(codeSnippet: String): List<VulnerabilityItem> = withContext(Dispatchers.Default) {
        val findings = mutableListOf<VulnerabilityItem>()

        // Check for hardcoded API keys/passwords
        val secretPatterns = listOf(
            Regex("(?i)(api[_-]?key|secret|password|auth[_-]?token)\\s*=\\s*[\"'][a-zA-Z0-9_\\-]{8,}[\"']"),
            Regex("(?i)bearer\\s+[a-zA-Z0-9\\-._~+/]+=*")
        )
        for (pattern in secretPatterns) {
            if (pattern.containsMatchIn(codeSnippet)) {
                findings.add(
                    VulnerabilityItem(
                        id = "STATIC-001",
                        title = "Hardcoded Secret / Credential Pattern Detected",
                        category = "Source Code Review",
                        severity = RiskLevel.CRITICAL,
                        description = "Pattern matching an API key, bearer token, or password found in source.",
                        impact = "Credentials can be extracted via static decompilation or source leakage.",
                        remediation = "Use BuildConfig injected via environment secrets or Android Keystore.",
                        remediationCode = "val apiKey = BuildConfig.API_KEY",
                        owaspReference = "M9: Reverse Engineering / A07:2021-Identification and Authentication Failures"
                    )
                )
                break
            }
        }

        // Weak cryptography check
        if (codeSnippet.contains("MD5", ignoreCase = true) || codeSnippet.contains("DES", ignoreCase = true)) {
            findings.add(
                VulnerabilityItem(
                    id = "STATIC-002",
                    title = "Weak Cryptographic Algorithm (MD5 / DES)",
                    category = "Cryptography",
                    severity = RiskLevel.HIGH,
                    description = "Detected usage of deprecated algorithms susceptible to collision or brute force attacks.",
                    impact = "Forged signatures and compromised hash verifications.",
                    remediation = "Upgrade to SHA-256 / SHA-3 or AES-256-GCM.",
                    remediationCode = "MessageDigest.getInstance(\"SHA-256\")",
                    owaspReference = "M5: Insufficient Cryptography"
                )
            )
        }

        // Insecure WebView settings
        if (codeSnippet.contains("setJavaScriptEnabled(true)", ignoreCase = true)) {
            findings.add(
                VulnerabilityItem(
                    id = "STATIC-003",
                    title = "WebView JavaScript Execution Enabled",
                    category = "Android WebView",
                    severity = RiskLevel.MEDIUM,
                    description = "setJavaScriptEnabled(true) allows JavaScript execution inside the WebView context.",
                    impact = "Potential Cross-Site Scripting (XSS) and bridge exploitation if untrusted content is loaded.",
                    remediation = "Disable JavaScript if not required, or strictly whitelist loaded URLs and origins.",
                    owaspReference = "M7: Client Code Quality"
                )
            )
        }

        // Insecure trust manager / SSL bypass
        if (codeSnippet.contains("TrustAll", ignoreCase = true) || codeSnippet.contains("ALLOW_ALL_HOSTNAME_VERIFIER", ignoreCase = true)) {
            findings.add(
                VulnerabilityItem(
                    id = "STATIC-004",
                    title = "Insecure SSL TrustManager / Hostname Verification Bypass",
                    category = "Network Security",
                    severity = RiskLevel.CRITICAL,
                    description = "Custom TrustManager accepting all certificates disables TLS certificate verification.",
                    impact = "Enables total Man-in-the-Middle traffic interception.",
                    remediation = "Use standard Android system CA validation or certificate pinning.",
                    owaspReference = "M3: Insecure Communication"
                )
            )
        }

        findings
    }
}
