# 🛡️ NetGuard

<p align="left">
  <a href="README.md">🌐 <b>English</b></a> |
  <a href="README-KR.md">🇰🇷 <b>한국어</b></a>
</p>

**NetGuard** is a lightweight, open-source macOS network security daemon and CLI tool written natively in Swift. It automatically monitors network transitions, audits the security of newly connected Wi-Fi or wired networks, and protects against packet sniffing, Man-in-the-Middle (MITM) attacks, ARP spoofing, and DNS hijacking.

---

## 🌟 Key Features

- **📶 Wi-Fi Encryption Audit (`CoreWLAN`)**: Instantly detects unencrypted Open Wi-Fi, obsolete WEP networks, or weak configurations.
- **⚡ ARP Spoofing & MITM Detection**: Continuously monitors the local subnet ARP cache to catch gateway MAC spoofing and packet interception.
- **🔒 DNS Integrity & Hijacking Prevention**: Compares system DNS queries against trusted DNS-over-HTTPS (DoH) endpoints (Cloudflare, Google) to detect DNS poisoning and pharming.
- **🔑 SSL/TLS Interception Inspection**: Validates certificate trust chains on key hosts using `Security.SecTrust` to detect fake root CAs and proxy interception.
- **🚪 Captive Portal Detection**: Identifies network login walls before sensitive traffic is transmitted.
- **🖥️ macOS Menu Bar (Header Bar) App**: Live status indicator (🟢 Safe / 🚨 Threat) in the top menu bar with one-click quick controls.
- **⚙️ Background Service (`launchd`)**: Daemon On / Off control via CLI or Homebrew (`brew services start net-guard`).
- **🚀 Automated Protection Actions**:
  - Native macOS Desktop Notifications
  - Automated Fallback to Secure DNS (`1.1.1.1`, `8.8.8.8`)
  - Configurable VPN Auto-Connect Hooks (WireGuard, Tailscale, Cloudflare WARP, OpenVPN)

---

## 📦 Installation Guide (Homebrew)

### Method 1: Via Homebrew Tap (Recommended)

```bash
# 1. Tap the repository
brew tap ashcastle/net-guard https://github.com/ashcastle/net-guard

# 2. Install NetGuard
brew install net-guard

# (Optional) Start automatically on macOS login via Homebrew Services
brew services start net-guard
```

### Method 2: Direct Formula Installation

You can also install NetGuard directly using the raw Formula URL without tapping:

```bash
brew install https://raw.githubusercontent.com/ashcastle/net-guard/main/formula/net-guard.rb
```

### Method 3: Manual Build via Swift Package Manager

```bash
git clone https://github.com/ashcastle/net-guard.git
cd net-guard

# Build release binary
swift build -c release

# Install to /usr/local/bin
sudo cp .build/release/netguard /usr/local/bin/
```

---

## 🚀 Quick Start & Usage

### 1. Instant Security Scan
Audit your active network connection immediately:
```bash
netguard scan
```

Output in JSON format (useful for scripts & automation):
```bash
netguard scan --json
```

### 2. macOS Top Menu Bar (Header Bar) App
Launch the lightweight menu bar status monitor in your macOS top panel:
```bash
netguard menu
```
- **Live Icons**: `🛡️🟢 Safe` | `🛡️🚨 Threat Level` | `🛡️📡 Checking`
- **Menu Actions**: Quick Scan, Background Daemon Toggle, Secure DNS Switcher, Config directory shortcut.

### 3. Background Daemon On / Off (`launchd`)
Control the 24/7 background security monitor without keeping a terminal open:
```bash
# Turn Daemon ON (registers and starts macOS LaunchAgent)
netguard daemon on

# Check Daemon status
netguard daemon status

# Turn Daemon OFF (stops and unregisters LaunchAgent)
netguard daemon off
```

### 4. Interactive Foreground Watcher
Monitor network switches in the foreground terminal:
```bash
netguard watch
```

### 5. Check Overall Status
```bash
netguard status
```

### 6. Configuration Management
View or edit configuration (`~/.config/netguard/config.json`):
```bash
# View current configuration
netguard config

# Set automatic VPN connect command on threat detection
netguard config --set-vpn "tailscale up --exit-node=my-secure-node"

# Add a trusted home/office Wi-Fi SSID to whitelist
netguard config --add-trusted-ssid "MyHomeSecureWiFi"

# Reset configuration to default
netguard config --reset
```

---

## ⚙️ Configuration File (`~/.config/netguard/config.json`)

```json
{
  "action": {
    "auto_secure_dns": false,
    "auto_vpn_command": "",
    "enable_notification": true,
    "secure_dns_addresses": [
      "1.1.1.1",
      "1.0.0.1",
      "8.8.8.8"
    ]
  },
  "detection": {
    "check_arp_spoof": true,
    "check_captive": true,
    "check_dns_hijack": true,
    "check_ssl_mitm": true,
    "check_wifi_security": true,
    "doh_servers": [
      "https://cloudflare-dns.com/dns-query",
      "https://dns.google/dns-query"
    ],
    "test_domains": [
      "google.com",
      "cloudflare.com",
      "apple.com",
      "github.com"
    ]
  },
  "trust": {
    "trusted_bssids": [],
    "trusted_ssids": []
  }
}
```

---

## 🛠️ Native Architecture

NetGuard is built natively for macOS using Apple's core frameworks:
- **`CoreWLAN`**: Native Wi-Fi interface and encryption audit.
- **`Network (NWPathMonitor)`**: Low-overhead event-driven network monitoring.
- **`Security`**: `SecTrust` certificate validation.
- **`AppKit`**: `NSStatusItem` menu bar integration.
- **`swift-argument-parser`**: Modern type-safe CLI subcommands.

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).
