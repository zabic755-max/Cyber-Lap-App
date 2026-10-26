package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.SecurityTool
import com.example.model.TestStatus
import com.example.ui.CyberUiState
import com.example.ui.components.CodeSnippetBox
import com.example.ui.components.CyberSectionCard
import com.example.ui.theme.*

@Composable
fun SelfTestSuiteScreen(
    state: CyberUiState,
    onRunTestSuite: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Header Card
        item {
            Card(
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = CyberCardBg),
                border = CardDefaults.outlinedCardBorder().copy(brush = androidx.compose.ui.graphics.SolidColor(CyberBorder)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "AUTOMATED TOOL TEST & REPAIR SUITE",
                        color = CyberCyan,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Real functional test execution across all 14 security adapters. Validates outputs, verifies sandbox integrity, and captures stdout/stderr diagnostics.",
                        color = CyberTextSecondary,
                        fontSize = 11.sp
                    )
                    Spacer(modifier = Modifier.height(14.dp))

                    Button(
                        onClick = onRunTestSuite,
                        enabled = !state.isRunningSelfTest,
                        colors = ButtonDefaults.buttonColors(containerColor = CyberCyan),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(48.dp)
                            .testTag("run_test_suite_button")
                    ) {
                        if (state.isRunningSelfTest) {
                            CircularProgressIndicator(color = Color(0xFF021B1A), modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Executing Safe Tests...", color = Color(0xFF021B1A), fontWeight = FontWeight.Bold)
                        } else {
                            Icon(Icons.Default.FactCheck, contentDescription = null, tint = Color(0xFF021B1A))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Run Automated Test Suite", color = Color(0xFF021B1A), fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }

        // Test Status Metrics
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                TestMetricPill("PASS", state.passedTestsCount, CyberNeonGreen, Modifier.weight(1f))
                TestMetricPill("PARTIAL", state.partialTestsCount, CyberBlue, Modifier.weight(1f))
                TestMetricPill("BLOCKED", state.blockedTestsCount, SeverityHigh, Modifier.weight(1f))
                TestMetricPill("FAIL", state.failedTestsCount, SeverityCritical, Modifier.weight(1f))
            }
        }

        // Test Results List
        item {
            Text(
                text = "TOOL VERIFICATION MATRIX (${state.toolsList.size} tools)",
                color = CyberCyan,
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold
            )
        }

        items(state.toolsList) { tool ->
            ToolTestCard(tool)
        }
    }
}

@Composable
private fun TestMetricPill(label: String, count: Int, color: Color, modifier: Modifier = Modifier) {
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
private fun ToolTestCard(tool: SecurityTool) {
    Card(
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = CyberCardBg),
        border = CardDefaults.outlinedCardBorder().copy(
            brush = androidx.compose.ui.graphics.SolidColor(
                when (tool.testStatus) {
                    TestStatus.PASS -> CyberNeonGreen.copy(alpha = 0.4f)
                    TestStatus.PARTIAL -> CyberBlue.copy(alpha = 0.4f)
                    TestStatus.BLOCKED -> SeverityHigh.copy(alpha = 0.4f)
                    TestStatus.FAIL -> SeverityCritical.copy(alpha = 0.4f)
                    TestStatus.NOT_TESTED -> CyberSurfaceVariant
                }
            )
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
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(4.dp))
            Text(text = "Executable: ${tool.executablePath}", fontSize = 11.sp, color = CyberTextSecondary, fontFamily = FontFamily.Monospace)

            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = tool.testResultDetails,
                fontSize = 12.sp,
                color = when (tool.testStatus) {
                    TestStatus.PASS -> CyberNeonGreen
                    TestStatus.PARTIAL -> CyberBlue
                    TestStatus.BLOCKED -> SeverityHigh
                    TestStatus.FAIL -> SeverityCritical
                    TestStatus.NOT_TESTED -> CyberTextSecondary
                }
            )
        }
    }
}
