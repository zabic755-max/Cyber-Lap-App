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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.service.ApiAndNetworkAnalyzer
import com.example.ui.CyberUiState
import com.example.ui.components.CyberSectionCard
import com.example.ui.theme.*
import kotlinx.coroutines.launch

@Composable
fun NetworkDiagnosticsScreen(
    state: CyberUiState,
    onAddLog: (String) -> Unit
) {
    var hostInput by remember { mutableStateOf("1.1.1.1") }
    var pingResult by remember { mutableStateOf<Pair<Boolean, Long>?>(null) }
    var isPinging by remember { mutableStateOf(false) }
    var localInterfaces by remember { mutableStateOf<List<Pair<String, String>>>(emptyList()) }

    val coroutineScope = rememberCoroutineScope()
    val networkAnalyzer = remember { ApiAndNetworkAnalyzer() }

    LaunchedEffect(Unit) {
        localInterfaces = networkAnalyzer.getLocalNetworkDetails()
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            CyberSectionCard(title = "TCP Reachability & Latency Ping") {
                OutlinedTextField(
                    value = hostInput,
                    onValueChange = { hostInput = it },
                    label = { Text("Target Host / IP Address") },
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
                        isPinging = true
                        coroutineScope.launch {
                            val res = networkAnalyzer.pingHost(hostInput, 443)
                            pingResult = res
                            isPinging = false
                            onAddLog("Ping $hostInput: ${if (res.first) "Reachable" else "Unreachable"} (${res.second}ms)")
                        }
                    },
                    enabled = !isPinging,
                    colors = ButtonDefaults.buttonColors(containerColor = CyberCyan),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth().height(48.dp)
                ) {
                    if (isPinging) {
                        CircularProgressIndicator(color = Color(0xFF021B1A), modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Pinging Host...", color = Color(0xFF021B1A), fontWeight = FontWeight.Bold)
                    } else {
                        Icon(Icons.Default.Bolt, contentDescription = null, tint = Color(0xFF021B1A))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Ping Host (Port 443)", color = Color(0xFF021B1A), fontWeight = FontWeight.Bold)
                    }
                }

                pingResult?.let { (ok, latency) ->
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(Color(0xFF050811), RoundedCornerShape(6.dp))
                            .padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = if (ok) "Host Reachable (ACK)" else "Host Unreachable / Timed Out",
                            color = if (ok) CyberNeonGreen else SeverityCritical,
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.sp
                        )
                        Text(
                            text = "${latency} ms",
                            color = CyberCyan,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }

        item {
            CyberSectionCard(title = "Local Network Interfaces") {
                if (localInterfaces.isEmpty()) {
                    Text("Scanning interfaces...", fontSize = 12.sp, color = CyberTextSecondary)
                } else {
                    for ((iface, ip) in localInterfaces) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(text = iface, fontSize = 12.sp, color = CyberCyan, fontWeight = FontWeight.SemiBold)
                            Text(text = ip, fontSize = 12.sp, color = CyberTextPrimary, fontFamily = FontFamily.Monospace)
                        }
                    }
                }
            }
        }

        item {
            CyberSectionCard(title = "Diagnostic Terminal Output") {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color(0xFF050811), RoundedCornerShape(8.dp))
                        .padding(12.dp)
                ) {
                    if (state.logs.isEmpty()) {
                        Text("> Terminal idle.", color = CyberTextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                    } else {
                        for (log in state.logs.takeLast(12)) {
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
