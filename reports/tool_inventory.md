# Codex Cyber Agent Ultimate — Tool Inventory & Architecture Specification

**Generated Date:** 2026-10-26  
**Application:** Codex Cyber Agent Ultimate (`com.codex.cyberagent`)  
**Target Architecture:** ARM64 (`arm64-v8a`), multi-ABI support (`x86_64`, `armeabi-v7a`)  
**Runtime Environment:** Native Android Platform API 36 / Linux sandboxed container  

---

## 1. Executive Summary & Inventory Counts

| Total Discovered Tools | Integrated Native Adapters | Local Backend Adapters | External / CLI (Requires Root/Termux) | Verified Passing |
| :---: | :---: | :---: | :---: | :---: |
| **14** | **11** | **1** | **2** | **11 PASS, 1 PARTIAL, 2 BLOCKED** |

* **PASS (11):** All core defensive security analyzers (HTTP Headers, TLS Certificate & Cipher Validator, DNS Diagnostics, TCP Port Scanner, REST API & CORS Probe, WebSocket Handshaker, Android Package Manifest Inspector, Static Source Code & Secret Auditor, Network Interface Enumerator, Hardening Config Generator, Report Exporter).
* **PARTIAL (1):** Configurable AI Engine (`tool_ollama_ai`). Connects to external Ollama / OpenAI-compatible instances; provides full on-device defensive expert reasoning when the external model server is offline.
* **BLOCKED (2):** `tool_nmap_cli` and `tool_tcpdump_cli`. These tools require raw socket capabilities (`CAP_NET_RAW` / root / Termux Linux environment) which are restricted in standard Android user sandboxes. The application transparently marks them as BLOCKED and activates the native in-app socket scanners as safe alternatives.

---

## 2. Complete Tool Registry

### 1. HTTP Security Header Inspector
* **Tool ID:** `tool_web_headers`
* **Category:** Web & Transport
* **Executable Engine:** `com.example.service.CyberSecurityScanner#evaluateHeaders`
* **Version:** 1.2.0 (Native OkHttp/Compose)
* **Dependencies:** `okhttp3:4.10.0`, `android.permission.INTERNET`
* **Input Parameters:** `targetUrl` (String, default: `https://example.com`)
* **Output Format:** JSON / Structured Header Audit
* **Availability:** `AVAILABLE_NATIVE`
* **Test Status:** `PASS`
* **Documentation:** Audits `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.

### 2. TLS Certificate & Cipher Validator
* **Tool ID:** `tool_tls_inspector`
* **Category:** Web & Transport
* **Executable Engine:** `javax.net.ssl.SSLSocket` / `SSLContext` (Android Conscrypt)
* **Version:** TLSv1.3 Engine
* **Dependencies:** `javax.net.ssl`, `java.security.cert`
* **Input Parameters:** `host` (String, default: `example.com`), `port` (Int, default: `443`)
* **Output Format:** Structured Certificate Spec
* **Availability:** `AVAILABLE_NATIVE`
* **Test Status:** `PASS`
* **Documentation:** Extracts X.509 certificate subject DN, issuer, signature algorithm, serial number, validity window, days remaining, cipher suite, and Subject Alternative Names (SANs).

### 3. DNS Resolution & Diagnostics
* **Tool ID:** `tool_dns_diag`
* **Category:** Network & Host
* **Executable Engine:** `java.net.InetAddress#getAllByName`
* **Version:** 2.1.0 (Android Libcore)
* **Dependencies:** `java.net.InetAddress`
* **Input Parameters:** `domain` (String, default: `example.com`)
* **Output Format:** DNS Record Table
* **Availability:** `AVAILABLE_NATIVE`
* **Test Status:** `PASS`
* **Documentation:** Resolves IPv4 (A) and IPv6 (AAAA) records, checks reverse PTR lookups, and validates stub resolver latency.

### 4. Defensive TCP Port Scanner
* **Tool ID:** `tool_port_scanner`
* **Category:** Network & Host
* **Executable Engine:** `java.net.Socket#connect`
* **Version:** 1.0.0 (Native Sockets)
* **Dependencies:** `java.net.Socket`, `android.permission.INTERNET`
* **Input Parameters:** `host` (String, default: `1.1.1.1`), `port` (Int, default: `443`)
* **Output Format:** Socket Status & Latency
* **Availability:** `AVAILABLE_NATIVE`
* **Test Status:** `PASS`
* **Documentation:** Probes socket accessibility with a non-intrusive 1.2-second timeout on authorized targets.

### 5. REST API & CORS Security Analyzer
* **Tool ID:** `tool_api_cors`
* **Category:** API & WebSocket
* **Executable Engine:** `com.example.service.ApiAndNetworkAnalyzer#analyzeApiEndpoint`
* **Version:** 1.1.0 (REST/CORS Engine)
* **Dependencies:** `okhttp3:4.10.0`
* **Input Parameters:** `url` (String, default: `https://example.com/api`), `method` (String, default: `GET`)
* **Output Format:** API Risk Assessment
* **Availability:** `AVAILABLE_NATIVE`
* **Test Status:** `PASS`
* **Documentation:** Evaluates permissive CORS reflection (`Access-Control-Allow-Origin: *`), credential reflection risks, and unauthenticated sensitive endpoint access.

### 6. WebSocket Handshake Analyzer
* **Tool ID:** `tool_ws_handshake`
* **Category:** API & WebSocket
* **Executable Engine:** `com.example.service.ApiAndNetworkAnalyzer#testWebSocketHandshake`
* **Version:** 1.0.0 (WSS Handshaker)
* **Dependencies:** `okhttp3:4.10.0`
* **Input Parameters:** `wsUrl` (String, default: `wss://echo.websocket.org`)
* **Output Format:** Handshake Diagnostic Log
* **Availability:** `AVAILABLE_NATIVE`
* **Test Status:** `PASS`
* **Documentation:** Emits RFC 6455 HTTP upgrade headers to verify WebSocket switching and transport layer security (WSS).

### 7. Android APK & Manifest Auditor
* **Tool ID:** `tool_apk_manifest`
* **Category:** Android & Mobile
* **Executable Engine:** `android.content.pm.PackageManager`
* **Version:** Android SDK API 36 Platform
* **Dependencies:** `android.content.pm.PackageManager`
* **Input Parameters:** `packageName` (String, default: `com.codex.cyberagent`)
* **Output Format:** Manifest Security Matrix
* **Availability:** `AVAILABLE_NATIVE`
* **Test Status:** `PASS`
* **Documentation:** Inspects targetSdk, minSdk, `FLAG_DEBUGGABLE`, `FLAG_ALLOW_BACKUP`, `FLAG_USES_CLEARTEXT_TRAFFIC`, dangerous permissions, and unpermissioned exported components.

### 8. Static Source Code & Secret Auditor
* **Tool ID:** `tool_static_code`
* **Category:** Static Code & Crypto
* **Executable Engine:** `com.example.service.ApkSecurityAnalyzer#auditStaticSourceCode`
* **Version:** 1.0.0 (Regex & AST Static Rules)
* **Dependencies:** `kotlin.text.Regex`
* **Input Parameters:** `codeSnippet` (String)
* **Output Format:** Static Vulnerability Report
* **Availability:** `AVAILABLE_NATIVE`
* **Test Status:** `PASS`
* **Documentation:** Identifies hardcoded API tokens/secrets, deprecated cryptography (MD5/DES), and insecure WebView JavaScript bridges.

### 9. Network Interface & IP Enumerator
* **Tool ID:** `tool_network_iface`
* **Category:** Network & Host
* **Executable Engine:** `java.net.NetworkInterface#getNetworkInterfaces`
* **Version:** 1.0.0 (Native Network Interface)
* **Dependencies:** `java.net.NetworkInterface`
* **Input Parameters:** None
* **Output Format:** Interface Table
* **Availability:** `AVAILABLE_NATIVE`
* **Test Status:** `PASS`
* **Documentation:** Enumerates all local and wireless adapters, loopback interfaces, and assigned IPv4 addresses.

### 10. Configurable AI Cybersecurity Engine
* **Tool ID:** `tool_ollama_ai`
* **Category:** AI & Automation
* **Executable Engine:** `http://10.0.2.2:11434/api/generate` (Configurable endpoint)
* **Version:** Ollama v0.1.x+ / Local Diagnostic Engine
* **Dependencies:** `okhttp3:4.10.0`, `org.json`
* **Input Parameters:** `endpointUrl`, `model`, `prompt`, `temperature`, `systemPrompt`
* **Output Format:** Markdown Technical Reasoning
* **Availability:** `AVAILABLE_LOCAL_BACKEND`
* **Test Status:** `PARTIAL`
* **Documentation:** Connects to local or remote Ollama and OpenAI-compatible inference servers. When offline, seamlessly falls back to the native expert reasoning engine.

### 11. Hardening Config Generator
* **Tool ID:** `tool_remediation_gen`
* **Category:** Defensive Remediation
* **Executable Engine:** `com.example.service.CyberSecurityScanner#getHeaderRemediationInfo`
* **Version:** 1.0.0
* **Dependencies:** Kotlin Standard Library
* **Input Parameters:** `vulnerabilityType` (String)
* **Output Format:** Configuration Snippet
* **Availability:** `AVAILABLE_NATIVE`
* **Test Status:** `PASS`
* **Documentation:** Outputs ready-to-paste hardening configurations for Nginx, Apache, Spring Boot, and Android Network Security Config.

### 12. Report Exporter (HTML & JSON)
* **Tool ID:** `tool_report_exporter`
* **Category:** Defensive Remediation
* **Executable Engine:** `com.example.service.ReportExporter`
* **Version:** 1.0.0
* **Dependencies:** `org.json`, `java.io.File`
* **Input Parameters:** `target` (String)
* **Output Format:** HTML / JSON Documents
* **Availability:** `AVAILABLE_NATIVE`
* **Test Status:** `PASS`
* **Documentation:** Compiles vulnerability findings, headers, TLS, and OWASP mappings into standalone styled HTML and structured JSON documents.

### 13. Nmap Network Scanner (CLI)
* **Tool ID:** `tool_nmap_cli`
* **Category:** External / CLI Utilities
* **Executable Path:** `/data/data/com.termux/files/usr/bin/nmap`
* **Version:** Nmap 7.94+
* **Dependencies:** Termux or Root, `libpcap`, `CAP_NET_RAW`
* **Availability:** `REQUIRES_TERMUX_OR_ROOT`
* **Test Status:** `BLOCKED`
* **Documentation:** Low-level raw packet scanning. In non-root sandboxed Android environments, the native in-app TCP Port Scanner serves as the functional alternative.

### 14. Tcpdump Packet Sniffer (CLI)
* **Tool ID:** `tool_tcpdump_cli`
* **Category:** External / CLI Utilities
* **Executable Path:** `/system/xbin/tcpdump`
* **Version:** Tcpdump 4.99+
* **Dependencies:** Root privileges, `CAP_NET_RAW`
* **Availability:** `REQUIRES_TERMUX_OR_ROOT`
* **Test Status:** `BLOCKED`
* **Documentation:** Promiscuous packet capture requires root capability. L7 application analysis is performed natively via OkHttp and SSLSocket.
