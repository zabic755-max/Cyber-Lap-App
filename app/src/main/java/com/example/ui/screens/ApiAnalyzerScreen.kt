package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
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
import com.example.service.ApiAndNetworkAnalyzer
import com.example.ui.CyberUiState
import com.example.ui.components.CodeSnippetBox
import com.example.ui.components.CyberSectionCard
import com.example.ui.components.RiskBadge
import com.example.ui.components.ScopeConsentNotice
import com.example.ui.theme.*
import kotlinx.coroutines.launch

@Composable
fun ApiAnalyzerScreen(
    state: CyberUiState,
    onRunApiScan: (url: String, method: String) -> Unit,
    onToggleConsent: (Boolean) -> Unit
) {
    var apiUrl by remember { mutableStateOf("${state.targetUrl}/api/v1/health") }
    var selectedMethod by remember { mutableStateOf("GET") }
    var wsUrl by remember { mutableStateOf("wss://echo.websocket.org") }
    var wsResultText by remember { mutableStateOf<String?>(null) }
    var isTestingWs by remember { mutableStateOf(false) }

    val coroutineScope = rememberCoroutineScope()
    val apiAnalyzer = remember { ApiAndNetworkAnalyzer() }

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

        // REST API Config Card
        item {
            CyberSectionCard(title = "API Endpoint Security Tester") {
                OutlinedTextField(
                    value = apiUrl,
                    onValueChange = { apiUrl = it },
                    label = { Text("API Endpoint URL") },
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
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    listOf("GET", "OPTIONS", "HEAD").forEach { method ->
                        FilterChip(
                            selected = selectedMethod == method,
                            onClick = { selectedMethod = method },
                            label = { Text(method, fontSize = 11.sp, fontWeight = FontWeight.Bold) },
                            colors = FilterChipDefaults.filterChipColors(
                                selectedContainerColor = CyberCyan,
                                selectedLabelColor = Color(0xFF021B1A)
                            )
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                Button(
                    onClick = { onRunApiScan(apiUrl, selectedMethod) },
                    enabled = !state.isScanning,
                    colors = ButtonDefaults.buttonColors(containerColor = CyberCyan),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp)
                        .testTag("api_test_button")
                ) {
                    if (state.isScanning) {
                        CircularProgressIndicator(color = Color(0xFF021B1A), modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Analyzing Endpoint...", color = Color(0xFF021B1A), fontWeight = FontWeight.Bold)
                    } else {
                        Icon(Icons.Default.CloudSync, contentDescription = null, tint = Color(0xFF021B1A))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Audit API & CORS Configuration", color = Color(0xFF021B1A), fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        // API Scan Results
        state.apiScanResult?.let { res ->
            item {
                CyberSectionCard(title = "API Telemetry & Analysis") {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column {
                            Text("Status Code", fontSize = 11.sp, color = CyberTextSecondary)
                            Text("HTTP ${res.statusCode}", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = if (res.statusCode < 400) CyberNeonGreen else SeverityCritical)
                        }
                        Column {
                            Text("Latency", fontSize = 11.sp, color = CyberTextSecondary)
                            Text("${res.latencyMs} ms", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = CyberCyan)
                        }
                        Column {
                            Text("CORS Configured", fontSize = 11.sp, color = CyberTextSecondary)
                            Text(if (res.corsConfigured) "Present" else "Not Specified", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = CyberTextPrimary)
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))
                    Text("CORS Allow-Origin:", fontSize = 12.sp, color = CyberTextSecondary)
                    Text(
                        text = res.corsAllowOrigin ?: "None (Same-Origin Only)",
                        color = if (res.corsAllowOrigin == "*") SeverityHigh else CyberCyan,
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold
                    )

                    Spacer(modifier = Modifier.height(8.dp))
                    Text("Response Snippet:", fontSize = 12.sp, color = CyberTextSecondary)
                    CodeSnippetBox(code = res.rawResponseSnippet)
                }
            }

            if (res.vulnerabilities.isNotEmpty()) {
                item {
                    Text(
                        text = "API FINDINGS (${res.vulnerabilities.size})",
                        color = CyberCyan,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
                items(res.vulnerabilities.size) { idx ->
                    val vuln = res.vulnerabilities[idx]
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
                        }
                    }
                }
            }
        }

        // WebSocket Analyzer Card
        item {
            CyberSectionCard(title = "WebSocket Handshake Analyzer") {
                OutlinedTextField(
                    value = wsUrl,
                    onValueChange = { wsUrl = it },
                    label = { Text("WebSocket URL (wss://...)") },
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
                    onClick = {
                        isTestingWs = true
                        coroutineScope.launch {
                            wsResultText = apiAnalyzer.testWebSocketHandshake(wsUrl)
                            isTestingWs = false
                        }
                    },
                    enabled = !isTestingWs,
                    colors = ButtonDefaults.buttonColors(containerColor = CyberBlue),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp)
                ) {
                    if (isTestingWs) {
                        CircularProgressIndicator(color = Color.White, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Handshaking...", color = Color.White)
                    } else {
                        Icon(Icons.Default.NetworkCheck, contentDescription = null, tint = Color.White)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Test WebSocket Handshake", color = Color.White)
                    }
                }

                wsResultText?.let { out ->
                    Spacer(modifier = Modifier.height(10.dp))
                    CodeSnippetBox(code = out)
                }
            }
        }
    }
}
