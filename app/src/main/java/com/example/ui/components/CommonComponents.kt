package com.example.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
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
import com.example.model.RiskLevel
import com.example.ui.theme.*

@Composable
fun RiskBadge(level: RiskLevel, modifier: Modifier = Modifier) {
    val (bg, fg) = when (level) {
        RiskLevel.CRITICAL -> Pair(SeverityCritical, Color.White)
        RiskLevel.HIGH -> Pair(SeverityHigh, Color.White)
        RiskLevel.MEDIUM -> Pair(SeverityMedium, Color.Black)
        RiskLevel.LOW -> Pair(SeverityLow, Color.White)
        RiskLevel.INFO -> Pair(Color(0xFF64748B), Color.White)
        RiskLevel.SECURE -> Pair(SeveritySecure, Color(0xFF022014))
    }

    Surface(
        color = bg,
        shape = RoundedCornerShape(4.dp),
        modifier = modifier
    ) {
        Text(
            text = level.label,
            color = fg,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
        )
    }
}

@Composable
fun CyberSectionCard(
    title: String,
    modifier: Modifier = Modifier,
    headerAction: @Composable (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = CyberCardBg),
        border = CardDefaults.outlinedCardBorder().copy(brush = androidx.compose.ui.graphics.SolidColor(CyberBorder)),
        modifier = modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    color = CyberCyan,
                    fontWeight = FontWeight.Bold
                )
                headerAction?.invoke()
            }
            Spacer(modifier = Modifier.height(12.dp))
            content()
        }
    }
}

@Composable
fun CodeSnippetBox(code: String, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .fillMaxWidth()
            .background(Color(0xFF050811), RoundedCornerShape(6.dp))
            .border(1.dp, CyberSurfaceVariant, RoundedCornerShape(6.dp))
            .padding(10.dp)
    ) {
        Text(
            text = code,
            color = CyberTerminalGreen,
            fontFamily = FontFamily.Monospace,
            fontSize = 12.sp,
            lineHeight = 16.sp
        )
    }
}

@Composable
fun ScopeConsentNotice(
    approved: Boolean,
    onToggle: (Boolean) -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        color = if (approved) Color(0xFF042B24) else Color(0xFF331616),
        shape = RoundedCornerShape(8.dp),
        border = CardDefaults.outlinedCardBorder().copy(
            brush = androidx.compose.ui.graphics.SolidColor(if (approved) CyberNeonGreen else SeverityCritical)
        ),
        modifier = modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .padding(horizontal = 12.dp, vertical = 8.dp)
                .fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = if (approved) "DEFENSIVE SCOPE AUTHORIZED" else "AUTHORIZATION REQUIRED",
                    color = if (approved) CyberNeonGreen else SeverityCritical,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = if (approved) "Defensive scans permitted on authorized targets only." else "Check consent to permit non-destructive audits.",
                    color = CyberTextSecondary,
                    fontSize = 11.sp
                )
            }
            Switch(
                checked = approved,
                onCheckedChange = onToggle,
                modifier = Modifier.testTag("scope_consent_switch")
            )
        }
    }
}
