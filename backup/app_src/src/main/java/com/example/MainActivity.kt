package com.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
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
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.ui.CyberAgentViewModel
import com.example.ui.CyberNavScreen
import com.example.ui.screens.*
import com.example.ui.theme.*

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MyApplicationTheme {
                CyberAgentApp()
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CyberAgentApp(viewModel: CyberAgentViewModel = viewModel()) {
    val state by viewModel.uiState.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }

    // Handle back button: if in subscreen, return to dashboard
    BackHandler(enabled = state.currentScreen != CyberNavScreen.DASHBOARD) {
        viewModel.navigateTo(CyberNavScreen.DASHBOARD)
    }

    LaunchedEffect(state.statusMessage) {
        state.statusMessage?.let { msg ->
            snackbarHostState.showSnackbar(msg)
            viewModel.clearStatusMessage()
        }
    }

    LaunchedEffect(state.errorMessage) {
        state.errorMessage?.let { err ->
            snackbarHostState.showSnackbar("Error: $err")
            viewModel.clearStatusMessage()
        }
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = CyberDarkBg,
        contentWindowInsets = WindowInsets.safeDrawing,
        snackbarHost = {
            SnackbarHost(snackbarHostState) { data ->
                Snackbar(
                    containerColor = CyberCardBg,
                    contentColor = CyberCyan,
                    shape = RoundedCornerShape(8.dp),
                    snackbarData = data
                )
            }
        },
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(28.dp)
                                .clip(RoundedCornerShape(6.dp))
                                .background(CyberCyan),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                Icons.Default.Shield,
                                contentDescription = null,
                                tint = Color(0xFF021B1A),
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = "CODEX CYBER AGENT",
                                color = CyberCyan,
                                fontSize = 15.sp,
                                fontWeight = FontWeight.Bold,
                                letterSpacing = 1.sp
                            )
                            Text(
                                text = state.currentScreen.title,
                                color = CyberTextSecondary,
                                fontSize = 11.sp
                            )
                        }
                    }
                },
                navigationIcon = {
                    if (state.currentScreen != CyberNavScreen.DASHBOARD) {
                        IconButton(
                            onClick = { viewModel.navigateTo(CyberNavScreen.DASHBOARD) },
                            modifier = Modifier.testTag("top_bar_back_button")
                        ) {
                            Icon(
                                Icons.AutoMirrored.Filled.ArrowBack,
                                contentDescription = "Back to Dashboard",
                                tint = CyberCyan
                            )
                        }
                    }
                },
                actions = {
                    // Quick Status Pill
                    Surface(
                        color = CyberSurfaceVariant,
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.padding(end = 4.dp)
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(8.dp)
                                    .clip(CircleShape)
                                    .background(if (state.overallSecurityScore >= 75) CyberNeonGreen else SeverityMedium)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "${state.overallSecurityScore}",
                                color = CyberCyan,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }

                    // Settings Icon
                    IconButton(
                        onClick = { viewModel.navigateTo(CyberNavScreen.SETTINGS) },
                        modifier = Modifier.testTag("settings_nav_button")
                    ) {
                        Icon(
                            Icons.Default.Settings,
                            contentDescription = "Settings",
                            tint = if (state.currentScreen == CyberNavScreen.SETTINGS) CyberCyan else CyberTextSecondary
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = CyberSurface,
                    titleContentColor = CyberCyan
                )
            )
        },
        bottomBar = {
            NavigationBar(
                containerColor = CyberSurface,
                contentColor = CyberCyan,
                windowInsets = WindowInsets.navigationBars,
                modifier = Modifier.testTag("main_navigation_bar")
            ) {
                val navItems = listOf(
                    NavTabItem(CyberNavScreen.DASHBOARD, "Dashboard", Icons.Default.Dashboard),
                    NavTabItem(CyberNavScreen.AI_AGENT, "AI Agent", Icons.Default.SmartToy),
                    NavTabItem(CyberNavScreen.WEB_SCANNER, "Scanner", Icons.Default.Security),
                    NavTabItem(CyberNavScreen.API_ANALYZER, "API & WS", Icons.Default.Api),
                    NavTabItem(CyberNavScreen.APK_ANALYZER, "APK Audit", Icons.Default.Android),
                    NavTabItem(CyberNavScreen.REPORTS, "Reports", Icons.Default.Assessment)
                )

                navItems.forEach { item ->
                    val isSelected = state.currentScreen == item.screen
                    NavigationBarItem(
                        selected = isSelected,
                        onClick = { viewModel.navigateTo(item.screen) },
                        icon = {
                            Icon(
                                item.icon,
                                contentDescription = item.label,
                                tint = if (isSelected) Color(0xFF021B1A) else CyberTextSecondary
                            )
                        },
                        label = {
                            Text(
                                text = item.label,
                                fontSize = 10.sp,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                                color = if (isSelected) CyberCyan else CyberTextSecondary
                            )
                        },
                        colors = NavigationBarItemDefaults.colors(
                            indicatorColor = CyberCyan
                        )
                    )
                }
            }
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            when (state.currentScreen) {
                CyberNavScreen.DASHBOARD -> DashboardScreen(
                    state = state,
                    onNavigate = { viewModel.navigateTo(it) },
                    onUpdateTarget = { viewModel.updateTargetUrl(it) },
                    onToggleConsent = { viewModel.setScopeConsent(it) },
                    onRunScan = { viewModel.performWebScan() }
                )
                CyberNavScreen.AI_AGENT -> AiAgentScreen(
                    state = state,
                    onSendMessage = { viewModel.sendAgentMessage(it) }
                )
                CyberNavScreen.WEB_SCANNER -> WebSecurityScreen(
                    state = state,
                    onUpdateTarget = { viewModel.updateTargetUrl(it) },
                    onToggleConsent = { viewModel.setScopeConsent(it) },
                    onRunScan = { viewModel.performWebScan() },
                    onExportReport = { viewModel.exportHtmlReport() }
                )
                CyberNavScreen.API_ANALYZER -> ApiAnalyzerScreen(
                    state = state,
                    onRunApiScan = { url, method -> viewModel.performApiScan(url, method) },
                    onToggleConsent = { viewModel.setScopeConsent(it) }
                )
                CyberNavScreen.APK_ANALYZER -> ApkAnalyzerScreen(
                    state = state,
                    onAuditPackage = { viewModel.performApkAudit(it) },
                    onRunStaticReview = { viewModel.performStaticCodeReview(it) }
                )
                CyberNavScreen.NETWORK_DIAG -> NetworkDiagnosticsScreen(
                    state = state,
                    onAddLog = { viewModel.addLog(it) }
                )
                CyberNavScreen.REPORTS -> VulnerabilityReportScreen(
                    state = state,
                    onExportHtml = { viewModel.exportHtmlReport() },
                    onExportJson = { viewModel.exportJsonReport() },
                    onShareReport = { viewModel.shareCurrentReport() }
                )
                CyberNavScreen.SETTINGS -> SettingsScreen(
                    state = state,
                    onUpdateOllamaConfig = { viewModel.updateOllamaConfig(it) },
                    onTestOllama = { viewModel.testOllamaConnection() },
                    onToggleConsent = { viewModel.setScopeConsent(it) },
                    onClearHistory = { viewModel.clearHistory() }
                )
            }
        }
    }
}

private data class NavTabItem(
    val screen: CyberNavScreen,
    val label: String,
    val icon: ImageVector
)
