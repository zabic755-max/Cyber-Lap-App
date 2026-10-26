package com.example.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val CyberDarkColorScheme = darkColorScheme(
    primary = CyberCyan,
    onPrimary = Color(0xFF021B1A),
    primaryContainer = Color(0xFF004D40),
    onPrimaryContainer = Color(0xFFA7F3D0),
    secondary = CyberBlue,
    onSecondary = Color(0xFF002233),
    secondaryContainer = Color(0xFF003852),
    onSecondaryContainer = Color(0xFFBAE6FD),
    tertiary = CyberNeonGreen,
    onTertiary = Color(0xFF022014),
    tertiaryContainer = Color(0xFF064E3B),
    onTertiaryContainer = Color(0xFF6EE7B7),
    background = CyberDarkBg,
    onBackground = CyberTextPrimary,
    surface = CyberSurface,
    onSurface = CyberTextPrimary,
    surfaceVariant = CyberSurfaceVariant,
    onSurfaceVariant = CyberTextSecondary,
    outline = CyberBorder,
    error = SeverityCritical,
    onError = Color.White
)

@Composable
fun MyApplicationTheme(
    darkTheme: Boolean = true,
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = CyberDarkColorScheme,
        typography = Typography,
        content = content
    )
}
