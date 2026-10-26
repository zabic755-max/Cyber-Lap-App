package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ui.CyberUiState
import com.example.ui.components.CodeSnippetBox
import com.example.ui.components.CyberSectionCard
import com.example.ui.components.RiskBadge
import com.example.ui.theme.*

@Composable
fun ApkAnalyzerScreen(
    state: CyberUiState,
    onAuditPackage: (String) -> Unit,
    onRunStaticReview: (String) -> Unit
) {
    var pkgInput by remember { mutableStateOf("com.codex.cyberagent") }
    var codeSnippet by remember { mutableStateOf(state.staticCodeInput) }
    var selectedTab by remember { mutableIntStateOf(0) }
    val tabs = listOf("Package & Manifest", "Static Code Review")

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            TabRow(
                selectedTabIndex = selectedTab,
                containerColor = CyberCardBg,
                contentColor = CyberCyan,
                modifier = Modifier.background(CyberCardBg, RoundedCornerShape(8.dp))
            ) {
                tabs.forEachIndexed { index, title ->
                    Tab(
                        selected = selectedTab == index,
                        onClick = { selectedTab = index },
                        text = { Text(title, fontSize = 12.sp, fontWeight = FontWeight.SemiBold) }
                    )
                }
            }
        }

        if (selectedTab == 0) {
            // Package & Manifest Auditor Tab
            item {
                CyberSectionCard(title = "Android Binary & Manifest Inspector") {
                    OutlinedTextField(
                        value = pkgInput,
                        onValueChange = { pkgInput = it },
                        label = { Text("Android Package ID") },
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = CyberCyan,
                            unfocusedBorderColor = CyberSurfaceVariant,
                            focusedTextColor = CyberTextPrimary,
                            unfocusedTextColor = CyberTextPrimary
                        ),
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Button(
                        onClick = { onAuditPackage(pkgInput) },
                        enabled = !state.isScanning,
                        colors = ButtonDefaults.buttonColors(containerColor = CyberCyan),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(48.dp)
                            .testTag("audit_apk_button")
                    ) {
                        if (state.isScanning) {
                            CircularProgressIndicator(color = Color(0xFF021B1A), modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Auditing Package...", color = Color(0xFF021B1A), fontWeight = FontWeight.Bold)
                        } else {
                            Icon(Icons.Default.Android, contentDescription = null, tint = Color(0xFF021B1A))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Audit Installed App Manifest", color = Color(0xFF021B1A), fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }

            state.apkScanResult?.let { res ->
                item {
                    CyberSectionCard(title = "App Manifest & Security Flags") {
                        FlagRow("Package", res.packageName)
                        FlagRow("Target SDK", "${res.targetSdk}")
                        FlagRow("Min SDK", "${res.minSdk}")
                        FlagRow("Debuggable Flag", if (res.isDebuggable) "TRUE (Critical Risk)" else "False (Secure)", isRisk = res.isDebuggable)
                        FlagRow("Allow Backup (ADB)", if (res.allowsBackup) "TRUE (Backup enabled)" else "False", isRisk = res.allowsBackup)
                        FlagRow("Cleartext HTTP", if (res.usesCleartextTraffic) "ALLOWED (Cleartext enabled)" else "Disallowed", isRisk = res.usesCleartextTraffic)
                    }
                }

                item {
                    CyberSectionCard(title = "Dangerous Permissions (${res.dangerousPermissions.size})") {
                        if (res.dangerousPermissions.isEmpty()) {
                            Text("No dangerous runtime permissions declared.", color = CyberNeonGreen, fontSize = 12.sp)
                        } else {
                            for (perm in res.dangerousPermissions) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 3.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(Icons.Default.Warning, contentDescription = null, tint = SeverityMedium, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        text = perm.substringAfterLast('.'),
                                        fontSize = 12.sp,
                                        color = CyberTextPrimary,
                                        fontFamily = FontFamily.Monospace
                                    )
                                }
                            }
                        }
                    }
                }

                if (res.exportedComponents.isNotEmpty()) {
                    item {
                        CyberSectionCard(title = "Exported Components (${res.exportedComponents.size})") {
                            for (comp in res.exportedComponents) {
                                Text(
                                    text = "• $comp",
                                    fontSize = 11.sp,
                                    color = SeverityHigh,
                                    fontFamily = FontFamily.Monospace,
                                    modifier = Modifier.padding(vertical = 2.dp)
                                )
                            }
                        }
                    }
                }
            }
        } else {
            // Static Code Review Tab
            item {
                CyberSectionCard(title = "Static Source Code & Manifest Reviewer") {
                    Text(
                        "Paste AndroidManifest.xml or Kotlin/Java code to detect hardcoded secrets, weak crypto, and insecure WebView bridges.",
                        fontSize = 12.sp,
                        color = CyberTextSecondary
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    OutlinedTextField(
                        value = codeSnippet,
                        onValueChange = { codeSnippet = it },
                        label = { Text("Code / XML Snippet") },
                        minLines = 5,
                        maxLines = 10,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = CyberCyan,
                            unfocusedBorderColor = CyberSurfaceVariant,
                            focusedTextColor = CyberTerminalGreen,
                            unfocusedTextColor = CyberTerminalGreen
                        ),
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(10.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = {
                                codeSnippet = """
                                    val apiKey = "AIzaSyD-sample-production-key-998822"
                                    val digest = MessageDigest.getInstance("MD5")
                                    webView.settings.javaScriptEnabled = true
                                """.trimIndent()
                            },
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Load Sample", fontSize = 11.sp)
                        }

                        Button(
                            onClick = { onRunStaticReview(codeSnippet) },
                            enabled = codeSnippet.isNotBlank(),
                            colors = ButtonDefaults.buttonColors(containerColor = CyberCyan),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Review Code", color = Color(0xFF021B1A), fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }
                    }
                }
            }

            if (state.staticFindings.isNotEmpty()) {
                item {
                    Text(
                        text = "STATIC CODE FINDINGS (${state.staticFindings.size})",
                        color = CyberCyan,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold
                    )
                }

                items(state.staticFindings) { vuln ->
                    Card(
                        shape = RoundedCornerShape(8.dp),
                        colors = CardDefaults.cardColors(containerColor = CyberCardBg),
                        border = CardDefaults.outlinedCardBorder().copy(brush = androidx.compose.ui.graphics.SolidColor(SeverityHigh)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(vuln.title, fontWeight = FontWeight.Bold, color = CyberTextPrimary, fontSize = 13.sp)
                                RiskBadge(vuln.severity)
                            }
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(vuln.description, fontSize = 12.sp, color = CyberTextSecondary)
                            Spacer(modifier = Modifier.height(6.dp))
                            Text("Remediation:", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = CyberCyan)
                            Text(vuln.remediation, fontSize = 11.sp, color = CyberTextPrimary)
                            vuln.remediationCode?.let { code ->
                                Spacer(modifier = Modifier.height(4.dp))
                                CodeSnippetBox(code = code)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun FlagRow(label: String, value: String, isRisk: Boolean = false) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(text = label, fontSize = 12.sp, color = CyberTextSecondary)
        Text(
            text = value,
            fontSize = 12.sp,
            color = if (isRisk) SeverityCritical else CyberCyan,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Medium
        )
    }
}
