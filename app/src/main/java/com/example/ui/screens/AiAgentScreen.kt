package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
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
import com.example.model.AgentTask
import com.example.model.ChatMessage
import com.example.ui.CyberUiState
import com.example.ui.theme.*
import kotlinx.coroutines.launch

@Composable
fun AiAgentScreen(
    state: CyberUiState,
    onSendMessage: (String) -> Unit
) {
    var inputText by remember { mutableStateOf("") }
    val listState = rememberLazyListState()
    val coroutineScope = rememberCoroutineScope()

    LaunchedEffect(state.chatMessages.size) {
        if (state.chatMessages.isNotEmpty()) {
            listState.animateScrollToItem(state.chatMessages.size - 1)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        // AI Backend Status Banner
        Surface(
            color = CyberSurfaceVariant,
            shape = RoundedCornerShape(8.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .padding(horizontal = 12.dp, vertical = 8.dp)
                    .fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(10.dp)
                            .clip(CircleShape)
                            .background(if (state.ollamaConfig.isConnected) CyberNeonGreen else SeverityMedium)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = if (state.ollamaConfig.isConnected) "Ollama: ${state.ollamaConfig.model}" else "Expert Local Engine (Ollama Offline)",
                        color = CyberTextPrimary,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }

                Surface(
                    color = Color(0xFF0F172A),
                    shape = RoundedCornerShape(4.dp)
                ) {
                    Text(
                        text = state.ollamaConfig.endpointUrl.take(22),
                        color = CyberCyan,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Active Multi-Step Plan (if currently executing or last executed)
        state.currentTaskPlan?.let { plan ->
            TaskPlanCard(plan = plan)
            Spacer(modifier = Modifier.height(8.dp))
        }

        // Chat message list
        LazyColumn(
            state = listState,
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            items(state.chatMessages) { msg ->
                ChatBubble(msg)
            }

            if (state.isScanning) {
                item {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(vertical = 8.dp)
                    ) {
                        CircularProgressIndicator(
                            color = CyberCyan,
                            modifier = Modifier.size(16.dp),
                            strokeWidth = 2.dp
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Codex Agent executing multi-step reasoning plan...",
                            color = CyberCyan,
                            fontSize = 12.sp,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Suggested prompt chips
        val prompts = listOf(
            "Audit headers for ${state.targetUrl}",
            "Test API CORS and auth on ${state.targetUrl}/api",
            "Inspect Android APK permissions",
            "Generate CSP remediation rule"
        )
        LazyRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            items(prompts) { p ->
                SuggestionChip(
                    onClick = {
                        inputText = p
                        onSendMessage(p)
                    },
                    label = { Text(p, fontSize = 11.sp) },
                    colors = SuggestionChipDefaults.suggestionChipColors(
                        containerColor = CyberCardBg,
                        labelColor = CyberCyan
                    ),
                    border = SuggestionChipDefaults.suggestionChipBorder(
                        enabled = true,
                        borderColor = CyberSurfaceVariant
                    )
                )
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Input Bar
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = inputText,
                onValueChange = { inputText = it },
                placeholder = { Text("Ask Codex Agent or instruct task...", fontSize = 13.sp) },
                singleLine = false,
                maxLines = 3,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = CyberCyan,
                    unfocusedBorderColor = CyberSurfaceVariant,
                    focusedTextColor = CyberTextPrimary,
                    unfocusedTextColor = CyberTextPrimary
                ),
                modifier = Modifier
                    .weight(1f)
                    .testTag("agent_chat_input")
            )
            Spacer(modifier = Modifier.width(8.dp))
            IconButton(
                onClick = {
                    if (inputText.isNotBlank() && !state.isScanning) {
                        val text = inputText
                        inputText = ""
                        onSendMessage(text)
                        coroutineScope.launch {
                            listState.animateScrollToItem(state.chatMessages.size)
                        }
                    }
                },
                enabled = inputText.isNotBlank() && !state.isScanning,
                modifier = Modifier
                    .size(48.dp)
                    .background(if (inputText.isNotBlank()) CyberCyan else CyberSurfaceVariant, RoundedCornerShape(8.dp))
                    .testTag("agent_send_button")
            ) {
                Icon(
                    Icons.Default.Send,
                    contentDescription = "Send",
                    tint = if (inputText.isNotBlank()) Color(0xFF021B1A) else CyberTextSecondary
                )
            }
        }
    }
}

@Composable
private fun TaskPlanCard(plan: AgentTask) {
    Card(
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF071424)),
        border = CardDefaults.outlinedCardBorder().copy(brush = androidx.compose.ui.graphics.SolidColor(CyberBorder)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(10.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "TASK PLAN: ${plan.title.take(35)}",
                    color = CyberCyan,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace
                )
                Text(
                    text = if (plan.isCompleted) "COMPLETED" else "EXECUTING",
                    color = if (plan.isCompleted) CyberNeonGreen else SeverityMedium,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold
                )
            }
            Spacer(modifier = Modifier.height(6.dp))
            for (step in plan.steps) {
                Row(
                    modifier = Modifier.padding(vertical = 2.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        if (step.isDone) Icons.Default.CheckCircle else Icons.Default.RadioButtonUnchecked,
                        contentDescription = null,
                        tint = if (step.isDone) CyberNeonGreen else CyberTextSecondary,
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "Step ${step.stepIndex}: ${step.title}",
                        fontSize = 11.sp,
                        color = if (step.isDone) CyberTextPrimary else CyberTextSecondary,
                        fontWeight = if (step.isDone) FontWeight.SemiBold else FontWeight.Normal
                    )
                }
            }
        }
    }
}

@Composable
private fun ChatBubble(msg: ChatMessage) {
    val isUser = msg.sender == "user"
    val isSystem = msg.sender == "system"

    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = if (isUser) Alignment.End else Alignment.Start
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(bottom = 2.dp)
        ) {
            Icon(
                if (isUser) Icons.Default.Person else if (isSystem) Icons.Default.Warning else Icons.Default.Shield,
                contentDescription = null,
                tint = if (isUser) CyberBlue else if (isSystem) SeverityMedium else CyberCyan,
                modifier = Modifier.size(14.dp)
            )
            Spacer(modifier = Modifier.width(4.dp))
            Text(
                text = if (isUser) "Operator" else if (isSystem) "System Alert" else "Codex Agent",
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = if (isUser) CyberBlue else if (isSystem) SeverityMedium else CyberCyan
            )
        }

        Box(
            modifier = Modifier
                .widthIn(max = 320.dp)
                .background(
                    if (isUser) Color(0xFF0A2540) else if (isSystem) Color(0xFF2E1919) else CyberCardBg,
                    RoundedCornerShape(12.dp)
                )
                .border(
                    1.dp,
                    if (isUser) CyberBlue.copy(alpha = 0.3f) else if (isSystem) SeverityCritical.copy(alpha = 0.3f) else CyberBorder,
                    RoundedCornerShape(12.dp)
                )
                .padding(12.dp)
        ) {
            Column {
                Text(
                    text = msg.content,
                    color = CyberTextPrimary,
                    fontSize = 13.sp,
                    lineHeight = 18.sp
                )

                msg.logOutput?.let { log ->
                    Spacer(modifier = Modifier.height(8.dp))
                    Surface(
                        color = Color(0xFF050811),
                        shape = RoundedCornerShape(6.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = log,
                            color = CyberTerminalGreen,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            modifier = Modifier.padding(8.dp)
                        )
                    }
                }
            }
        }
    }
}
