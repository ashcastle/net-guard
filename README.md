# 🛡️ NetGuard

**NetGuard** is a lightweight, open-source macOS network security daemon and CLI tool. It automatically monitors network transitions, audits the security of newly connected Wi-Fi or wired networks, and protects against packet sniffing, Man-in-the-Middle (MITM) attacks, ARP spoofing, and DNS hijacking.

---

## 🌟 Key Features

- **📶 Wi-Fi Encryption Audit (`CoreWLAN`)**: Instantly detects unencrypted Open Wi-Fi, obsolete WEP networks, or weak configurations.
- **⚡ ARP Spoofing & MITM Detection**: Continuously monitors the local subnet ARP cache to catch gateway MAC spoofing and packet interception.
- **🔒 DNS Integrity & Hijacking Prevention**: Compares system DNS queries against trusted DNS-over-HTTPS (DoH) endpoints (Cloudflare, Google) to detect DNS poisoning and pharming.
- **🔑 SSL/TLS Interception Inspection**: Validates certificate trust chains on key hosts to detect fake root CAs and proxy interception.
- **🚪 Captive Portal Detection**: Identifies network login walls before sensitive traffic is transmitted.
- **🚀 Automated Protection Actions**:
  - Native macOS Desktop Notifications
  - Automated Fallback to Secure DNS (`1.1.1.1`, `8.8.8.8`)
  - Configurable VPN Auto-Connect Hooks (WireGuard, Tailscale, Cloudflare WARP, OpenVPN)
- **⚙️ Background Service (`launchd`)**: Seamlessly runs as a background service via Homebrew (`brew services start net-guard`).

---

## 📦 Installation

### Via Homebrew (Recommended)

```bash
# Tap the repository
brew tap ashcastle/netguard https://github.com/ashcastle/netguard

# Install NetGuard
brew install net-guard

# Start as a background service on login
brew services start net-guard
```

### Manual Build via Swift Package Manager

```bash
git clone https://github.com/ashcastle/netguard.git
cd netguard

# Build release binary
swift build -c release

# Copy to your PATH
cp .build/release/netguard /usr/local/bin/
```

---

## 🚀 Usage

### 1. Instant Security Scan
Audit the currently connected network:
```bash
netguard scan
```

Output format in JSON for scripts and CI pipelines:
```bash
netguard scan --json
```

### 2. Foreground Network Monitoring
Monitor network transitions interactively:
```bash
netguard watch
```

### 3. Service Status
Check active connection status and configuration summary:
```bash
netguard status
```

### 4. Configuration Management
View or modify configuration (`~/.config/netguard/config.json`):
```bash
# View configuration
netguard config

# Set automatic VPN connection command on unsafe network detection
netguard config --set-vpn "tailscale up --exit-node=my-secure-node"

# Add a trusted home/office Wi-Fi network
netguard config --add-trusted-ssid "MyHomeSecureWiFi"

# Reset configuration to default
netguard config --reset
```

---

## ⚙️ Configuration (`config.json`)

The configuration file is automatically created at `~/.config/netguard/config.json`:

```json
{
  "detection": {
    "check_wifi_security": true,
    "check_arp_spoof": true,
    "check_dns_hijack": true,
    "check_ssl_mitm": true,
    "check_captive": true,
    "test_domains": ["google.com", "cloudflare.com", "apple.com", "github.com"],
    "doh_servers": ["https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"]
  },
  "action": {
    "enable_notification": true,
    "auto_secure_dns": false,
    "secure_dns_addresses": ["1.1.1.1", "1.0.0.1", "8.8.8.8"],
    "auto_vpn_command": ""
  },
  "trust": {
    "trusted_ssids": [],
    "trusted_bssids": []
  }
}
```

---

## 🛠️ Architecture

NetGuard is built natively for macOS using Apple's modern system frameworks:
- **`CoreWLAN`**: Direct query of Wi-Fi interfaces and security modes without external shell dependencies.
- **`Network (NWPathMonitor)`**: Asynchronous, event-driven network state monitoring.
- **`Security`**: Native TLS trust evaluation.
- **`swift-argument-parser`**: Type-safe CLI subcommand architecture.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
