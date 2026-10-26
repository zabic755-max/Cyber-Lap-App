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
import com.example.model.HeaderAudit
import com.example.ui.CyberUiState
import com.example.ui.components.CodeSnippetBox
import com.example.ui.components.CyberSectionCard
import com.example.ui.components.RiskBadge
import com.example.ui.components.ScopeConsentNotice
import com.example.ui.theme.*

@Composable
fun WebSecurityScreen(
    state: CyberUiState,
    onUpdateTarget: (String) -> Unit,
    onToggleConsent: (Boolean) -> Unit,
    onRunScan: () -> Unit,
    onExportReport: () -> Unit
) {
    var selectedTab by remember { mutableIntStateOf(0) }
    val tabs = listOf("HTTP Headers", "TLS / SSL", "DNS & Ports")

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            ScopeConsentNotice(
                approved = state.scopeConsentApproved,
                onToggle = onToggleConsent
            )
        }

        item {
            CyberSectionCard(title = "Web Target Scanner") {
                OutlinedTextField(
                    value = state.targetUrl,
                    onValueChange = onUpdateTarget,
                    label = { Text("Web Host or URL (e.g. https://example.com)") },
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
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = onRunScan,
                        enabled = !state.isScanning,
                        colors = ButtonDefaults.buttonColors(containerColor = CyberCyan),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier
                            .weight(1f)
                            .height(48.dp)
                            .testTag("web_scan_button")
                    ) {
                        if (state.isScanning) {
                            CircularProgressIndicator(color = Color(0xFF021B1A), modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Inspecting...", color = Color(0xFF021B1A), fontWeight = FontWeight.Bold)
                        } else {
                            Icon(Icons.Default.Radar, contentDescription = null, tint = Color(0xFF021B1A))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Scan Headers & TLS", color = Color(0xFF021B1A), fontWeight = FontWeight.Bold)
                        }
                    }

                    OutlinedButton(
                        onClick = onExportReport,
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = CyberCyan),
                        border = ButtonDefaults.outlinedButtonBorder().copy(brush = androidx.compose.ui.graphics.SolidColor(CyberCyan)),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.height(48.dp)
                    ) {
                        Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(18.dp))
                    }
                }
            }
        }

        val scanResult = state.webScanResult
        if (scanResult != null) {
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

            when (selectedTab) {
                0 -> {
                    // Headers Tab
                    item {
                        Text(
                            text = "SECURITY HEADERS (${scanResult.headers.size})",
                            color = CyberCyan,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }

                    items(scanResult.headers) { header ->
                        HeaderAuditCard(header)
                    }
                }
                1 -> {
                    // TLS Tab
                    item {
                        val tls = scanResult.tls
                        if (tls != null) {
                            CyberSectionCard(title = "TLS Certificate Details") {
                                TlsRow("Protocol Version", tls.protocol)
                                TlsRow("Cipher Suite", tls.cipherSuite)
                                TlsRow("Certificate Subject", tls.subject)
                                TlsRow("Issuer CA", tls.issuer)
                                TlsRow("Valid Period", "${tls.validFrom} to ${tls.validTo}")
                                TlsRow("Days Remaining", "${tls.daysRemaining} days")
                                TlsRow("Expired Status", if (tls.isExpired) "EXPIRED (Critical)" else "Valid Certificate")
                                Spacer(modifier = Modifier.height(8.dp))
                                Text("Subject Alternative Names (SANs):", fontSize = 11.sp, color = CyberTextSecondary)
                                Text(
                                    text = tls.sans.joinToString(", "),
                                    fontSize = 11.sp,
                                    color = CyberTerminalGreen,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        } else {
                            Text(
                                text = "No TLS certificate retrieved or target is HTTP.",
                                color = SeverityMedium,
                                fontSize = 13.sp
                            )
                        }
                    }
                }
                2 -> {
                    // DNS & Ports Tab
                    item {
                        CyberSectionCard(title = "DNS Resolution") {
                            for (rec in scanResult.dnsRecords) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 4.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(text = rec.type, fontSize = 12.sp, color = CyberCyan, fontWeight = FontWeight.SemiBold)
                                    Text(text = rec.value, fontSize = 12.sp, color = CyberTextPrimary, fontFamily = FontFamily.Monospace)
                                }
                            }
                        }
                    }

                    item {
                        CyberSectionCard(title = "Defensive Port Diagnostics") {
                            for (port in scanResult.portChecks) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 6.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Column {
                                        Text(
                                            text = "Port ${port.port} (${port.service})",
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 12.sp,
                                            color = CyberTextPrimary
                                        )
                                        Text(text = port.statusNote, fontSize = 10.sp, color = CyberTextSecondary)
                                    }
                                    Surface(
                                        color = if (port.isOpen) CyberNeonGreen else Color(0xFF1E293B),
                                        shape = RoundedCornerShape(4.dp)
                                    ) {
                                        Text(
                                            text = if (port.isOpen) "OPEN (${port.latencyMs}ms)" else "CLOSED",
                                            color = if (port.isOpen) Color(0xFF021B1A) else CyberTextSecondary,
                                            fontSize = 10.sp,
                                            fontWeight = FontWeight.Bold,
                                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            item {
                Surface(
                    color = CyberCardBg,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(Icons.Default.Security, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(36.dp))
                        Spacer(modifier = Modifier.height(8.dp))
                        Text("No Web Target Audited Yet", fontWeight = FontWeight.Bold, color = CyberTextPrimary)
                        Text(
                            "Enter an authorized target URL above and click Execute Scan to inspect HTTP headers and TLS certificates.",
                            fontSize = 12.sp,
                            color = CyberTextSecondary,
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun HeaderAuditCard(header: HeaderAudit) {
    Card(
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = CyberCardBg),
        border = CardDefaults.outlinedCardBorder().copy(
            brush = androidx.compose.ui.graphics.SolidColor(if (header.isSecure) CyberSurfaceVariant else SeverityHigh)
        ),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = header.headerName,
                    color = CyberTextPrimary,
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    fontFamily = FontFamily.Monospace
                )
                RiskBadge(header.risk)
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = header.recommendation,
                fontSize = 11.sp,
                color = if (header.isSecure) CyberTextSecondary else SeverityHigh
            )
            header.value?.let { v ->
                Spacer(modifier = Modifier.height(4.dp))
                CodeSnippetBox(code = v)
            }
        }
    }
}

@Composable
private fun TlsRow(label: String, value: String) {
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
            color = CyberCyan,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Medium
        )
    }
}
