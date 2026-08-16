import Foundation
import ArgumentParser

@main
struct NetGuardCLI: AsyncParsableCommand {
    static var configuration = CommandConfiguration(
        commandName: "netguard",
        abstract: "🛡️ NetGuard: Automated macOS Network Security & Eavesdropping Prevention Tool",
        version: "1.1.0",
        subcommands: [
            ScanCommand.self,
            MenuCommand.self,
            DaemonCommand.self,
            WatchCommand.self,
            ConfigCommand.self,
            StatusCommand.self
        ],
        defaultSubcommand: ScanCommand.self
    )
}

// MARK: - Scan Command
struct ScanCommand: AsyncParsableCommand {
    static var configuration = CommandConfiguration(
        commandName: "scan",
        abstract: "Perform an instant security audit on the active network connection."
    )

    @Flag(name: .shortAndLong, help: "Output results in JSON format.")
    var json: Bool = false

    func run() async throws {
        let config = ConfigManager.shared.load()
        let scanner = Scanner(config: config)

        if !json {
            print("\n🔍 NetGuard: Auditing active network security...")
        }

        let report = await scanner.runAudit()

        if json {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            if let data = try? encoder.encode(report), let jsonStr = String(data: data, encoding: .utf8) {
                print(jsonStr)
            }
            return
        }

        printReport(report)

        // Run protection handler if unsafe
        let handler = ProtectionHandler(config: config)
        handler.handle(report: report)
    }

    private func printReport(_ report: AuditReport) {
        let net = report.network
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(" 📡 Active Interface:  \(net.interfaceName)")
        if net.isWireless {
            print(" 📶 Wi-Fi SSID:        \(net.ssid ?? "Unknown")")
            print(" 🔒 Security Protocol: \(net.securityType ?? "None")")
            print(" 🏷️  BSSID:             \(net.bssid ?? "Unknown")")
        }
        print(" 🌐 Gateway IP:        \(net.gatewayIP ?? "Unknown") (\(net.gatewayMAC ?? "Unknown"))")
        print(" 📝 DNS Servers:       \(net.configuredDNS.joined(separator: ", "))")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(" 📊 Security Findings:")

        for finding in report.findings {
            let icon = finding.passed ? "✅" : (finding.severity == .critical || finding.severity == .high ? "🚨" : "⚠️")
            let statusText = finding.passed ? "[PASSED]" : "[\(finding.severity.rawValue)]"
            print("   \(icon) \(finding.name.padding(toLength: 35, withPad: " ", startingAt: 0)) \(statusText)")
            print("      └─ \(finding.description)")
            if let details = finding.details, !details.isEmpty {
                print("         Details: \(details)")
            }
            if let remediation = finding.remediation, !remediation.isEmpty {
                print("         Remedy:  \(remediation)")
            }
        }

        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        if report.isSafe {
            print(" 🎉 Overall Status: SAFE - No packet sniffing/eavesdropping risks detected.")
        } else {
            print(" ⚠️  Overall Status: \(report.overallStatus.rawValue) - Action Recommended!")
        }
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
    }
}

// MARK: - Menu Bar Command (Header Bar)
struct MenuCommand: AsyncParsableCommand {
    static var configuration = CommandConfiguration(
        commandName: "menu",
        abstract: "Launch the macOS status bar (menu bar) app for real-time visual monitoring."
    )

    func run() async throws {
        print("🛡️ Launching NetGuard in macOS Menu Bar...")
        let controller = MenuBarController()
        controller.start()
    }
}

// MARK: - Daemon Command
struct DaemonCommand: AsyncParsableCommand {
    static var configuration = CommandConfiguration(
        commandName: "daemon",
        abstract: "Control or run the NetGuard background daemon service.",
        subcommands: [
            DaemonOn.self,
            DaemonOff.self,
            DaemonRun.self,
            DaemonStatus.self
        ],
        defaultSubcommand: DaemonStatus.self
    )

    struct DaemonOn: AsyncParsableCommand {
        static var configuration = CommandConfiguration(
            commandName: "on",
            abstract: "Register and start the NetGuard daemon via macOS launchd."
        )

        func run() async throws {
            let result = DaemonManager.enableDaemon()
            print(result.message)
        }
    }

    struct DaemonOff: AsyncParsableCommand {
        static var configuration = CommandConfiguration(
            commandName: "off",
            abstract: "Stop and unregister the NetGuard daemon."
        )

        func run() async throws {
            let result = DaemonManager.disableDaemon()
            print(result.message)
        }
    }

    struct DaemonRun: AsyncParsableCommand {
        static var configuration = CommandConfiguration(
            commandName: "run",
            abstract: "Execute the daemon event loop (invoked by launchd)."
        )

        func run() async throws {
            let config = ConfigManager.shared.load()
            let scanner = Scanner(config: config)
            let handler = ProtectionHandler(config: config)

            let monitor = NetworkMonitor { _ in
                Task {
                    let report = await scanner.runAudit()
                    handler.handle(report: report)
                }
            }

            monitor.start()
            dispatchMain()
        }
    }

    struct DaemonStatus: AsyncParsableCommand {
        static var configuration = CommandConfiguration(
            commandName: "status",
            abstract: "Show current daemon service status."
        )

        func run() async throws {
            print(DaemonManager.getStatus())
        }
    }
}

// MARK: - Watch Command
struct WatchCommand: AsyncParsableCommand {
    static var configuration = CommandConfiguration(
        commandName: "watch",
        abstract: "Monitor network transitions in foreground and trigger automatic protection."
    )

    func run() async throws {
        let config = ConfigManager.shared.load()
        let scanner = Scanner(config: config)
        let handler = ProtectionHandler(config: config)

        print("🛡️ NetGuard Watcher started. Monitoring network transitions (Ctrl+C to quit)...")

        let monitor = NetworkMonitor { _ in
            Task {
                let report = await scanner.runAudit()
                handler.handle(report: report)
            }
        }

        monitor.start()

        while true {
            try await Task.sleep(nanoseconds: 1_000_000_000)
        }
    }
}

// MARK: - Config Command
struct ConfigCommand: AsyncParsableCommand {
    static var configuration = CommandConfiguration(
        commandName: "config",
        abstract: "View or modify NetGuard configuration."
    )

    @Flag(name: .long, help: "Reset configuration to defaults.")
    var reset: Bool = false

    @Option(name: .long, help: "Set auto VPN connect shell command.")
    var setVpn: String?

    @Option(name: .long, help: "Add a trusted Wi-Fi SSID.")
    var addTrustedSSID: String?

    func run() async throws {
        var config = ConfigManager.shared.load()

        if reset {
            config = NetGuardConfig.default
            _ = ConfigManager.shared.save(config)
            print("✅ Configuration reset to defaults at \(ConfigManager.shared.configURL.path)")
            return
        }

        var modified = false
        if let vpnCmd = setVpn {
            config.action.autoVpnCommand = vpnCmd
            modified = true
            print("✅ Set Auto-VPN command: \(vpnCmd)")
        }

        if let ssid = addTrustedSSID {
            if !config.trust.trustedSSIDs.contains(ssid) {
                config.trust.trustedSSIDs.append(ssid)
                modified = true
                print("✅ Added '\(ssid)' to trusted SSIDs whitelist.")
            }
        }

        if modified {
            _ = ConfigManager.shared.save(config)
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(config), let jsonStr = String(data: data, encoding: .utf8) {
            print("\n📄 Current Configuration (\(ConfigManager.shared.configURL.path)):")
            print(jsonStr)
        }
    }
}

// MARK: - Status Command
struct StatusCommand: AsyncParsableCommand {
    static var configuration = CommandConfiguration(
        commandName: "status",
        abstract: "Check active network status and protection settings."
    )

    func run() async throws {
        let config = ConfigManager.shared.load()
        let net = WifiDetector.collectNetworkInfo()

        print("\n🛡️ NetGuard Status:")
        print("  • Interface:        \(net.interfaceName)")
        print("  • Wi-Fi SSID:       \(net.ssid ?? "N/A (Wired/Ethernet)")")
        print("  • Security Type:    \(net.securityType ?? "N/A")")
        print("  • Daemon Active:    \(DaemonManager.isRunning() ? "Yes (🟢 Active)" : "No (⚪ Inactive)")")
        print("  • Notifications:    \(config.action.enableNotification ? "Enabled" : "Disabled")")
        print("  • Auto Secure DNS:  \(config.action.autoSecureDNS ? "Enabled" : "Disabled")")
        print("  • Auto VPN Hook:    \(config.action.autoVpnCommand.isEmpty ? "None" : config.action.autoVpnCommand)")
        print("  • Trusted Networks: \(config.trust.trustedSSIDs.isEmpty ? "None" : config.trust.trustedSSIDs.joined(separator: ", "))\n")
    }
}
