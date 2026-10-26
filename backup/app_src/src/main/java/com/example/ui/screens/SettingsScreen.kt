package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.OllamaConfig
import com.example.ui.CyberUiState
import com.example.ui.components.CyberSectionCard
import com.example.ui.components.ScopeConsentNotice
import com.example.ui.theme.*

@Composable
fun SettingsScreen(
    state: CyberUiState,
    onUpdateOllamaConfig: (OllamaConfig) -> Unit,
    onTestOllama: () -> Unit,
    onToggleConsent: (Boolean) -> Unit,
    onClearHistory: () -> Unit
) {
    var endpointUrl by remember { mutableStateOf(state.ollamaConfig.endpointUrl) }
    var modelName by remember { mutableStateOf(state.ollamaConfig.model) }
    var authHeader by remember { mutableStateOf(state.ollamaConfig.customAuthHeader) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Ollama AI Backend Settings
        item {
            CyberSectionCard(title = "AI Backend & Ollama Configuration") {
                Text(
                    text = "Configure local Ollama or OpenAI-compatible endpoint. For Android emulators, 10.0.2.2 bridges to localhost on the host machine.",
                    fontSize = 12.sp,
                    color = CyberTextSecondary
                )
                Spacer(modifier = Modifier.height(10.dp))

                OutlinedTextField(
                    value = endpointUrl,
                    onValueChange = {
                        endpointUrl = it
                        onUpdateOllamaConfig(state.ollamaConfig.copy(endpointUrl = it))
                    },
                    label = { Text("Ollama Endpoint URL") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = CyberCyan,
                        unfocusedBorderColor = CyberSurfaceVariant,
                        focusedTextColor = CyberTextPrimary,
                        unfocusedTextColor = CyberTextPrimary
                    ),
                    modifier = Modifier.fillMaxWidth().testTag("ollama_endpoint_input")
                )

                Spacer(modifier = Modifier.height(10.dp))

                OutlinedTextField(
                    value = modelName,
                    onValueChange = {
                        modelName = it
                        onUpdateOllamaConfig(state.ollamaConfig.copy(model = it))
                    },
                    label = { Text("Model Name (e.g. llama3:latest, mistral)") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = CyberCyan,
                        unfocusedBorderColor = CyberSurfaceVariant,
                        focusedTextColor = CyberTextPrimary,
                        unfocusedTextColor = CyberTextPrimary
                    ),
                    modifier = Modifier.fillMaxWidth().testTag("ollama_model_input")
                )

                Spacer(modifier = Modifier.height(10.dp))

                OutlinedTextField(
                    value = authHeader,
                    onValueChange = {
                        authHeader = it
                        onUpdateOllamaConfig(state.ollamaConfig.copy(customAuthHeader = it))
                    },
                    label = { Text("Authorization Header (Optional, e.g. Bearer token)") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = CyberCyan,
                        unfocusedBorderColor = CyberSurfaceVariant,
                        focusedTextColor = CyberTextPrimary,
                        unfocusedTextColor = CyberTextPrimary
                    ),
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(12.dp))

                Button(
                    onClick = onTestOllama,
                    colors = ButtonDefaults.buttonColors(containerColor = CyberCyan),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth().height(48.dp).testTag("test_ollama_button")
                ) {
                    Icon(Icons.Default.Link, contentDescription = null, tint = Color(0xFF021B1A))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Test Backend Connection", color = Color(0xFF021B1A), fontWeight = FontWeight.Bold)
                }

                Spacer(modifier = Modifier.height(10.dp))

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color(0xFF050811), RoundedCornerShape(6.dp))
                        .padding(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(10.dp)
                            .clip(CircleShape)
                            .background(if (state.ollamaConfig.isConnected) CyberNeonGreen else SeverityMedium)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = state.ollamaStatusText,
                        color = CyberTextPrimary,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }
        }

        // Scope & Consent Settings
        item {
            CyberSectionCard(title = "Defensive Testing Scope") {
                ScopeConsentNotice(
                    approved = state.scopeConsentApproved,
                    onToggle = onToggleConsent
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Codex Cyber Agent strictly executes benign defensive reconnaissance (HTTP headers, TLS parameters, DNS records, static manifest inspection, and port reachability). Destructive attacks or unauthorized payload injections are structurally prohibited.",
                    fontSize = 11.sp,
                    color = CyberTextSecondary,
                    lineHeight = 16.sp
                )
            }
        }

        // System & Build Information
        item {
            CyberSectionCard(title = "System & Architecture") {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text("Application ID", fontSize = 12.sp, color = CyberTextSecondary)
                    Text("com.codex.cyberagent", fontSize = 12.sp, color = CyberCyan, fontFamily = FontFamily.Monospace)
                }
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text("Target Architecture", fontSize = 12.sp, color = CyberTextSecondary)
                    Text("ARM64 (arm64-v8a)", fontSize = 12.sp, color = CyberNeonGreen, fontFamily = FontFamily.Monospace)
                }
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text("Build Type", fontSize = 12.sp, color = CyberTextSecondary)
                    Text("Native Android APK (Signed)", fontSize = 12.sp, color = CyberTextPrimary)
                }
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text("Target SDK", fontSize = 12.sp, color = CyberTextSecondary)
                    Text("Android 16 (API 36)", fontSize = 12.sp, color = CyberTextPrimary)
                }
            }
        }

        // Data Reset
        item {
            CyberSectionCard(title = "Data Management") {
                OutlinedButton(
                    onClick = onClearHistory,
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = SeverityCritical),
                    border = ButtonDefaults.outlinedButtonBorder().copy(brush = androidx.compose.ui.graphics.SolidColor(SeverityCritical)),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth().height(48.dp).testTag("clear_history_button")
                ) {
                    Icon(Icons.Default.DeleteSweep, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Clear All Audit History & Reset Environment")
                }
            }
        }
    }
}
