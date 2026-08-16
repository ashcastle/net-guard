import Foundation
import ArgumentParser

struct NetGuardCLI: ParsableCommand {
    static var configuration = CommandConfiguration(
        commandName: "netguard",
        abstract: "🛡️ NetGuard: Automated macOS Network Security & Eavesdropping Prevention Tool",
        version: "1.0.4",
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
struct ScanCommand: ParsableCommand {
    static var configuration = CommandConfiguration(
        commandName: "scan",
        abstract: "Perform an instant security audit on the active network connection."
    )

    @Flag(name: .shortAndLong, help: "Output results in JSON format.")
    var json: Bool = false

    func run() throws {
        let config = ConfigManager.shared.load()
        let scanner = Scanner(config: config)

        if !json {
            print("\n🔍 NetGuard: Auditing active network security...")
        }

        let semaphore = DispatchSemaphore(value: 0)
        var reportResult: AuditReport?

        Task {
            let report = await scanner.runAudit()
            reportResult = report
            semaphore.signal()
        }

        semaphore.wait()

        guard let report = reportResult else {
            print("❌ Failed to generate audit report.")
            return
        }

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
        print(" 📝 DNS Servers:       \(net.configuredDNS.isEmpty ? "System Default" : net.configuredDNS.joined(separator: ", "))")
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

// MARK: - Menu Bar Command
struct MenuCommand: ParsableCommand {
    static var configuration = CommandConfiguration(
        commandName: "menu",
        abstract: "Launch the macOS status bar (menu bar) app in background or foreground."
    )

    @Flag(name: .shortAndLong, help: "Run in foreground terminal instead of background daemon.")
    var foreground: Bool = false

    func run() throws {
        if foreground {
            print("🛡️ NetGuard Menu Bar running in foreground (Ctrl+C to quit)...")
            let controller = MenuBarController()
            controller.start()
        } else {
            let result = DaemonManager.enableDaemon()
            print(result.message)
            print("🛡️ NetGuard Menu Bar is now running in your macOS Top Bar (Background).")
            print("   Look at the top-right menu bar for the 🛡️ Shield icon.")
            print("   To turn off: run 'netg daemon off'\n")
        }
    }
}

// MARK: - Daemon Command
struct DaemonCommand: ParsableCommand {
    static var configuration = CommandConfiguration(
        commandName: "daemon",
        abstract: "Control or run the NetGuard background daemon service with top menu bar integration.",
        subcommands: [
            DaemonOn.self,
            DaemonOff.self,
            DaemonRun.self,
            DaemonStatus.self
        ],
        defaultSubcommand: DaemonStatus.self
    )

    struct DaemonOn: ParsableCommand {
        static var configuration = CommandConfiguration(
            commandName: "on",
            abstract: "Register and start NetGuard background daemon and menu bar icon."
        )

        func run() throws {
            let result = DaemonManager.enableDaemon()
            print(result.message)
            print("🛡️ NetGuard daemon is active in the background. (Menu bar icon enabled)\n")
        }
    }

    struct DaemonOff: ParsableCommand {
        static var configuration = CommandConfiguration(
            commandName: "off",
            abstract: "Stop and unregister NetGuard background daemon."
        )

        func run() throws {
            let result = DaemonManager.disableDaemon()
            print(result.message)
        }
    }

    struct DaemonRun: ParsableCommand {
        static var configuration = CommandConfiguration(
            commandName: "run",
            abstract: "Execute the daemon event loop with menu bar (invoked by launchd)."
        )

        func run() throws {
            // Launch MenuBarController which handles both menu bar UI and network monitoring
            let controller = MenuBarController()
            controller.start()
        }
    }

    struct DaemonStatus: ParsableCommand {
        static var configuration = CommandConfiguration(
            commandName: "status",
            abstract: "Show current daemon service status."
        )

        func run() throws {
            print(DaemonManager.getStatus())
        }
    }
}

// MARK: - Watch Command
struct WatchCommand: ParsableCommand {
    static var configuration = CommandConfiguration(
        commandName: "watch",
        abstract: "Monitor network transitions in foreground and trigger automatic protection."
    )

    func run() throws {
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
        dispatchMain()
    }
}

// MARK: - Config Command
struct ConfigCommand: ParsableCommand {
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

    func run() throws {
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
struct StatusCommand: ParsableCommand {
    static var configuration = CommandConfiguration(
        commandName: "status",
        abstract: "Check active network status and protection settings."
    )

    func run() throws {
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

// MARK: - Entry Point
NetGuardCLI.main()
