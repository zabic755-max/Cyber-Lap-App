package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.SecurityTool
import com.example.model.TestStatus
import com.example.model.ToolAvailability
import com.example.ui.CyberUiState
import com.example.ui.components.CodeSnippetBox
import com.example.ui.components.CyberSectionCard
import com.example.ui.theme.*

@Composable
fun ToolRegistryScreen(
    state: CyberUiState,
    onSelectTool: (SecurityTool) -> Unit,
    onExecuteTool: (toolId: String, params: Map<String, String>) -> Unit
) {
    var searchQuery by remember { mutableStateOf("") }
    var selectedCategory by remember { mutableStateOf<String?>(null) }
    val categories = remember(state.toolsList) {
        listOf("All") + state.toolsList.map { it.category }.distinct()
    }

    val filteredTools = state.toolsList.filter { tool ->
        val matchesCategory = selectedCategory == null || selectedCategory == "All" || tool.category == selectedCategory
        val matchesSearch = searchQuery.isBlank() ||
                tool.name.contains(searchQuery, ignoreCase = true) ||
                tool.description.contains(searchQuery, ignoreCase = true) ||
                tool.id.contains(searchQuery, ignoreCase = true)
        matchesCategory && matchesSearch
    }

    var activeTool by remember { mutableStateOf(state.selectedTool ?: state.toolsList.firstOrNull()) }
    val paramValues = remember(activeTool?.id) {
        mutableStateMapOf<String, String>().apply {
            activeTool?.inputParameters?.forEach { put(it.name, it.defaultValue) }
        }
    }

    val clipboardManager = LocalClipboardManager.current
    var copiedToClipboard by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Header
        item {
            Card(
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = CyberCardBg),
                border = CardDefaults.outlinedCardBorder().copy(brush = androidx.compose.ui.graphics.SolidColor(CyberBorder)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "SECURITY TOOL REGISTRY & RUNNER",
                        color = CyberCyan,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Unified catalog of ${state.toolsList.size} discovered security adapters. Execute tools with live logs, input parameters, and exit codes.",
                        color = CyberTextSecondary,
                        fontSize = 11.sp
                    )
                }
            }
        }

        // Search & Category Filters
        item {
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = { Text("Search tools by name, category, or executable...", fontSize = 12.sp) },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = CyberCyan) },
                singleLine = true,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = CyberCyan,
                    unfocusedBorderColor = CyberSurfaceVariant,
                    focusedTextColor = CyberTextPrimary,
                    unfocusedTextColor = CyberTextPrimary
                ),
                modifier = Modifier.fillMaxWidth().testTag("tool_search_input")
            )
        }

        item {
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                items(categories) { cat ->
                    val isSelected = (selectedCategory == null && cat == "All") || selectedCategory == cat
                    FilterChip(
                        selected = isSelected,
                        onClick = { selectedCategory = if (cat == "All") null else cat },
                        label = { Text(cat, fontSize = 11.sp, fontWeight = FontWeight.Bold) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = CyberCyan,
                            selectedLabelColor = Color(0xFF021B1A)
                        )
                    )
                }
            }
        }

        // Tool Runner Section (Active Tool)
        activeTool?.let { tool ->
            item {
                CyberSectionCard(title = "Tool Runner: ${tool.name}") {
                    Text(text = tool.description, fontSize = 12.sp, color = CyberTextPrimary)
                    Spacer(modifier = Modifier.height(8.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Surface(
                            color = CyberSurfaceVariant,
                            shape = RoundedCornerShape(4.dp)
                        ) {
                            Text(
                                text = tool.availability.label,
                                color = if (tool.availability == ToolAvailability.AVAILABLE_NATIVE) CyberNeonGreen else SeverityMedium,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.SemiBold,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }

                        Surface(
                            color = when (tool.testStatus) {
                                TestStatus.PASS -> Color(0xFF064E3B)
                                TestStatus.PARTIAL -> Color(0xFF1E3A8A)
                                TestStatus.BLOCKED -> Color(0xFF451A03)
                                TestStatus.FAIL -> Color(0xFF7F1D1D)
                                TestStatus.NOT_TESTED -> CyberSurfaceVariant
                            },
                            shape = RoundedCornerShape(4.dp)
                        ) {
                            Text(
                                text = "TEST: ${tool.testStatus.label}",
                                color = when (tool.testStatus) {
                                    TestStatus.PASS -> CyberNeonGreen
                                    TestStatus.PARTIAL -> CyberBlue
                                    TestStatus.BLOCKED -> SeverityHigh
                                    TestStatus.FAIL -> SeverityCritical
                                    TestStatus.NOT_TESTED -> CyberTextSecondary
                                },
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))
                    Text(text = "Engine / Path: ${tool.executablePath}", fontSize = 11.sp, color = CyberTextSecondary, fontFamily = FontFamily.Monospace)

                    if (tool.availability == ToolAvailability.REQUIRES_TERMUX_OR_ROOT) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Surface(
                            color = Color(0xFF2E1919),
                            shape = RoundedCornerShape(6.dp),
                            border = CardDefaults.outlinedCardBorder().copy(brush = androidx.compose.ui.graphics.SolidColor(SeverityCritical)),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(10.dp)) {
                                Text("ENVIRONMENT RESTRICTION NOTICE", color = SeverityCritical, fontWeight = FontWeight.Bold, fontSize = 11.sp)
                                Text(tool.documentation, color = CyberTextSecondary, fontSize = 11.sp)
                            }
                        }
                    }

                    // Input parameter forms
                    if (tool.inputParameters.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Text("Input Parameters:", fontSize = 12.sp, color = CyberCyan, fontWeight = FontWeight.Bold)

                        for (param in tool.inputParameters) {
                            Spacer(modifier = Modifier.height(6.dp))
                            OutlinedTextField(
                                value = paramValues[param.name] ?: param.defaultValue,
                                onValueChange = { paramValues[param.name] = it },
                                label = { Text(param.label) },
                                singleLine = true,
                                colors = OutlinedTextFieldDefaults.colors(
                                    focusedBorderColor = CyberCyan,
                                    unfocusedBorderColor = CyberSurfaceVariant,
                                    focusedTextColor = CyberTextPrimary,
                                    unfocusedTextColor = CyberTextPrimary
                                ),
                                modifier = Modifier.fillMaxWidth().testTag("param_${param.name}")
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = { onExecuteTool(tool.id, paramValues.toMap()) },
                            enabled = !state.isExecutingTool,
                            colors = ButtonDefaults.buttonColors(containerColor = CyberCyan),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.weight(1f).height(46.dp).testTag("run_tool_button")
                        ) {
                            if (state.isExecutingTool) {
                                CircularProgressIndicator(color = Color(0xFF021B1A), modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("Executing...", color = Color(0xFF021B1A), fontWeight = FontWeight.Bold)
                            } else {
                                Icon(Icons.Default.PlayArrow, contentDescription = null, tint = Color(0xFF021B1A))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Run Tool Adapter", color = Color(0xFF021B1A), fontWeight = FontWeight.Bold)
                            }
                        }
                    }

                    // Execution Output Box
                    state.lastToolResult?.let { res ->
                        Spacer(modifier = Modifier.height(14.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("EXECUTION LOGS", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = CyberCyan)
                                Spacer(modifier = Modifier.width(8.dp))
                                Surface(
                                    color = if (res.status == "SUCCESS") Color(0xFF064E3B) else if (res.status == "BLOCKED") Color(0xFF451A03) else Color(0xFF7F1D1D),
                                    shape = RoundedCornerShape(4.dp)
                                ) {
                                    Text(
                                        text = "${res.status} [Exit ${res.exitCode}]",
                                        color = if (res.status == "SUCCESS") CyberNeonGreen else if (res.status == "BLOCKED") SeverityHigh else SeverityCritical,
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                    )
                                }
                            }

                            Text("${res.executionTimeMs} ms", fontSize = 11.sp, color = CyberTextSecondary, fontFamily = FontFamily.Monospace)
                        }

                        Spacer(modifier = Modifier.height(6.dp))
                        val logText = if (res.stdout.isNotBlank()) res.stdout else res.stderr
                        CodeSnippetBox(code = logText)

                        Spacer(modifier = Modifier.height(6.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.End
                        ) {
                            TextButton(
                                onClick = {
                                    clipboardManager.setText(AnnotatedString(logText))
                                    copiedToClipboard = true
                                }
                            ) {
                                Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text(if (copiedToClipboard) "Copied!" else "Copy Output", fontSize = 11.sp)
                            }
                        }
                    }
                }
            }
        }

        // Tool List
        item {
            Text(
                text = "DISCOVERED TOOLS (${filteredTools.size})",
                color = CyberCyan,
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold
            )
        }

        items(filteredTools) { tool ->
            val isSelected = activeTool?.id == tool.id
            Card(
                shape = RoundedCornerShape(8.dp),
                colors = CardDefaults.cardColors(containerColor = if (isSelected) Color(0xFF13233D) else CyberCardBg),
                border = CardDefaults.outlinedCardBorder().copy(
                    brush = androidx.compose.ui.graphics.SolidColor(if (isSelected) CyberCyan else CyberSurfaceVariant)
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable {
                        activeTool = tool
                        onSelectTool(tool)
                    }
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = tool.name,
                            fontWeight = FontWeight.Bold,
                            color = CyberTextPrimary,
                            fontSize = 13.sp
                        )

                        Surface(
                            color = when (tool.testStatus) {
                                TestStatus.PASS -> Color(0xFF064E3B)
                                TestStatus.PARTIAL -> Color(0xFF1E3A8A)
                                TestStatus.BLOCKED -> Color(0xFF451A03)
                                TestStatus.FAIL -> Color(0xFF7F1D1D)
                                TestStatus.NOT_TESTED -> CyberSurfaceVariant
                            },
                            shape = RoundedCornerShape(4.dp)
                        ) {
                            Text(
                                text = tool.testStatus.label,
                                color = when (tool.testStatus) {
                                    TestStatus.PASS -> CyberNeonGreen
                                    TestStatus.PARTIAL -> CyberBlue
                                    TestStatus.BLOCKED -> SeverityHigh
                                    TestStatus.FAIL -> SeverityCritical
                                    TestStatus.NOT_TESTED -> CyberTextSecondary
                                },
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(4.dp))
                    Text(text = tool.description, fontSize = 11.sp, color = CyberTextSecondary, maxLines = 2)

                    Spacer(modifier = Modifier.height(6.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(text = "Category: ${tool.category}", fontSize = 10.sp, color = CyberCyan)
                        Text(text = tool.version.take(24), fontSize = 10.sp, color = CyberTextSecondary, fontFamily = FontFamily.Monospace)
                    }
                }
            }
        }
    }
}
