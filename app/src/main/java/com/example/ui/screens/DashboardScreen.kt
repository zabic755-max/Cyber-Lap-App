package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.RiskLevel
import com.example.ui.CyberNavScreen
import com.example.ui.CyberUiState
import com.example.ui.components.CyberSectionCard
import com.example.ui.components.ScopeConsentNotice
import com.example.ui.theme.*

@Composable
fun DashboardScreen(
    state: CyberUiState,
    onNavigate: (CyberNavScreen) -> Unit,
    onUpdateTarget: (String) -> Unit,
    onToggleConsent: (Boolean) -> Unit,
    onRunScan: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Scope Consent
        item {
            ScopeConsentNotice(
                approved = state.scopeConsentApproved,
                onToggle = onToggleConsent
            )
        }

        // Executive Score Card
        item {
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = CyberCardBg),
                border = CardDefaults.outlinedCardBorder().copy(brush = androidx.compose.ui.graphics.SolidColor(CyberCyan)),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("dashboard_score_card")
            ) {
                Row(
                    modifier = Modifier
                        .padding(20.dp)
                        .fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "SECURITY POSTURE",
                            color = CyberCyan,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 1.sp
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = if (state.overallSecurityScore >= 75) "HARDENED DEFENSE" else if (state.overallSecurityScore >= 50) "MODERATE RISK" else "VULNERABILITIES DETECTED",
                            style = MaterialTheme.typography.titleMedium,
                            color = CyberTextPrimary,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Target: ${state.targetUrl}",
                            color = CyberTextSecondary,
                            fontSize = 12.sp,
                            fontFamily = FontFamily.Monospace
                        )
                    }

                    Box(
                        contentAlignment = Alignment.Center,
                        modifier = Modifier
                            .size(76.dp)
                            .clip(CircleShape)
                            .background(CyberSurfaceVariant)
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(
                                text = "${state.overallSecurityScore}",
                                fontSize = 24.sp,
                                fontWeight = FontWeight.Bold,
                                color = if (state.overallSecurityScore >= 75) CyberNeonGreen else if (state.overallSecurityScore >= 50) SeverityMedium else SeverityCritical
                            )
                            Text(
                                text = "/100",
                                fontSize = 10.sp,
                                color = CyberTextSecondary
                            )
                        }
                    }
                }
            }
        }

        // Risk breakdown cards
        item {
            val criticalCount = state.allVulnerabilities.count { it.severity == RiskLevel.CRITICAL }
            val highCount = state.allVulnerabilities.count { it.severity == RiskLevel.HIGH }
            val medCount = state.allVulnerabilities.count { it.severity == RiskLevel.MEDIUM }
            val lowCount = state.allVulnerabilities.count { it.severity == RiskLevel.LOW }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                MetricPill("CRITICAL", criticalCount, SeverityCritical, Modifier.weight(1f))
                MetricPill("HIGH", highCount, SeverityHigh, Modifier.weight(1f))
                MetricPill("MEDIUM", medCount, SeverityMedium, Modifier.weight(1f))
                MetricPill("LOW", lowCount, SeverityLow, Modifier.weight(1f))
            }
        }

        // Quick Scan Launchpad
        item {
            CyberSectionCard(title = "Target Audit Launchpad") {
                OutlinedTextField(
                    value = state.targetUrl,
                    onValueChange = onUpdateTarget,
                    label = { Text("Target Web / API URL") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = CyberCyan,
                        unfocusedBorderColor = CyberSurfaceVariant,
                        focusedTextColor = CyberTextPrimary,
                        unfocusedTextColor = CyberTextPrimary
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("target_url_input")
                )
                Spacer(modifier = Modifier.height(12.dp))
                Button(
                    onClick = onRunScan,
                    enabled = !state.isScanning,
                    colors = ButtonDefaults.buttonColors(containerColor = CyberCyan),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp)
                        .testTag("launch_scan_button")
                ) {
                    if (state.isScanning) {
                        CircularProgressIndicator(color = Color(0xFF021B1A), modifier = Modifier.size(20.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Auditing Target...", color = Color(0xFF021B1A), fontWeight = FontWeight.Bold)
                    } else {
                        Icon(Icons.Default.Security, contentDescription = null, tint = Color(0xFF021B1A))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Execute Full Audit", color = Color(0xFF021B1A), fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        // Module Navigation Grid
        item {
            Text(
                text = "OPERATIONAL MODULES",
                color = CyberCyan,
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.sp
            )
            Spacer(modifier = Modifier.height(8.dp))

            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    ModuleCard(
                        title = "AI Agent Chat",
                        desc = "Natural language planning & automated tool executor",
                        icon = Icons.Default.SmartToy,
                        modifier = Modifier.weight(1f)
                    ) { onNavigate(CyberNavScreen.AI_AGENT) }

                    ModuleCard(
                        title = "Web Scanner",
                        desc = "Security headers, TLS inspector & DNS",
                        icon = Icons.Default.Language,
                        modifier = Modifier.weight(1f)
                    ) { onNavigate(CyberNavScreen.WEB_SCANNER) }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    ModuleCard(
                        title = "API & WebSocket",
                        desc = "REST endpoints, CORS rules & WSS test",
                        icon = Icons.Default.Api,
                        modifier = Modifier.weight(1f)
                    ) { onNavigate(CyberNavScreen.API_ANALYZER) }

                    ModuleCard(
                        title = "APK Analyzer",
                        desc = "Manifest, dangerous permissions & static review",
                        icon = Icons.Default.Android,
                        modifier = Modifier.weight(1f)
                    ) { onNavigate(CyberNavScreen.APK_ANALYZER) }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    ModuleCard(
                        title = "Tool Catalog",
                        desc = "14 discovered security tools & live runner",
                        icon = Icons.Default.Build,
                        modifier = Modifier.weight(1f)
                    ) { onNavigate(CyberNavScreen.TOOL_REGISTRY) }

                    ModuleCard(
                        title = "Test Suite",
                        desc = "Automated functional tests & sandbox verify",
                        icon = Icons.Default.FactCheck,
                        modifier = Modifier.weight(1f)
                    ) { onNavigate(CyberNavScreen.SELF_TEST) }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    ModuleCard(
                        title = "Network Diag",
                        desc = "Ping, port scanner & interface lookup",
                        icon = Icons.Default.SettingsEthernet,
                        modifier = Modifier.weight(1f)
                    ) { onNavigate(CyberNavScreen.NETWORK_DIAG) }

                    ModuleCard(
                        title = "Reports & Export",
                        desc = "HTML/JSON export with remediation guide",
                        icon = Icons.Default.Assessment,
                        modifier = Modifier.weight(1f)
                    ) { onNavigate(CyberNavScreen.REPORTS) }
                }
            }
        }

        // Live Log Terminal
        item {
            CyberSectionCard(title = "Live Terminal Feed") {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color(0xFF050811), RoundedCornerShape(8.dp))
                        .padding(10.dp)
                ) {
                    val displayLogs = state.logs.takeLast(6)
                    if (displayLogs.isEmpty()) {
                        Text(
                            text = "> Terminal idle. Ready for operations.",
                            color = CyberTextSecondary,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp
                        )
                    } else {
                        for (log in displayLogs) {
                            Text(
                                text = log,
                                color = CyberTerminalGreen,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                lineHeight = 16.sp
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun MetricPill(label: String, count: Int, color: Color, modifier: Modifier = Modifier) {
    Card(
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = CyberCardBg),
        modifier = modifier
    ) {
        Column(
            modifier = Modifier.padding(vertical = 10.dp, horizontal = 4.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(text = "$count", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = color)
            Text(text = label, fontSize = 9.sp, fontWeight = FontWeight.SemiBold, color = CyberTextSecondary)
        }
    }
}

@Composable
private fun ModuleCard(
    title: String,
    desc: String,
    icon: ImageVector,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    Card(
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = CyberCardBg),
        border = CardDefaults.outlinedCardBorder().copy(brush = androidx.compose.ui.graphics.SolidColor(CyberSurfaceVariant)),
        modifier = modifier
            .height(115.dp)
            .clickable { onClick() }
    ) {
        Column(
            modifier = Modifier
                .padding(12.dp)
                .fillMaxSize(),
            verticalArrangement = Arrangement.SpaceBetween
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(icon, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(22.dp))
                Icon(Icons.Default.ChevronRight, contentDescription = null, tint = CyberTextSecondary, modifier = Modifier.size(16.dp))
            }
            Column {
                Text(text = title, fontWeight = FontWeight.Bold, fontSize = 13.sp, color = CyberTextPrimary)
                Text(text = desc, fontSize = 10.sp, color = CyberTextSecondary, maxLines = 2)
            }
        }
    }
}
