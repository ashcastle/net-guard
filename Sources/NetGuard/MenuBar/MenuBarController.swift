import Foundation
import AppKit

public final class MenuBarController: NSObject, NSMenuDelegate {
    private var statusItem: NSStatusItem?
    private let menu = NSMenu()
    private var scanner: Scanner
    private var config: NetGuardConfig
    private var handler: ProtectionHandler
    private var monitor: NetworkMonitor?
    private var latestReport: AuditReport?
    private var isScanning = false

    public override init() {
        self.config = ConfigManager.shared.load()
        self.scanner = Scanner(config: config)
        self.handler = ProtectionHandler(config: config)
        super.init()
    }

    public func start() {
        NSApplication.shared.setActivationPolicy(.accessory)

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem?.button {
            button.title = "🛡️ NetGuard"
            button.toolTip = "NetGuard: Network Security Monitor"
        }

        menu.delegate = self
        statusItem?.menu = menu

        // Start Network Monitor
        monitor = NetworkMonitor { [weak self] _ in
            Task { @MainActor in
                await self?.performScan()
            }
        }
        monitor?.start()

        // Initial scan
        Task { @MainActor in
            await self.performScan()
        }

        NSApplication.shared.run()
    }

    @MainActor
    private func performScan() async {
        guard !isScanning else { return }
        isScanning = true
        updateStatusButton(title: "🛡️📡 Checking...", toolTip: "NetGuard: Auditing network security...")

        let report = await scanner.runAudit()
        self.latestReport = report
        self.handler.handle(report: report)
        self.isScanning = false

        if report.isSafe {
            updateStatusButton(title: "🛡️🟢 Safe", toolTip: "NetGuard: Network is secure (\(report.network.ssid ?? report.network.interfaceName))")
        } else {
            updateStatusButton(title: "🛡️🚨 \(report.overallStatus.rawValue)", toolTip: "NetGuard: \(report.summaryMessage)")
        }

        rebuildMenu()
    }

    private func updateStatusButton(title: String, toolTip: String) {
        DispatchQueue.main.async {
            if let button = self.statusItem?.button {
                button.title = title
                button.toolTip = toolTip
            }
        }
    }

    public func menuWillOpen(_ menu: NSMenu) {
        rebuildMenu()
    }

    private func rebuildMenu() {
        menu.removeAllItems()

        // 1. Header & Status Title
        let headerItem = NSMenuItem(title: "NetGuard Network Security", action: nil, keyEquivalent: "")
        headerItem.attributedTitle = NSAttributedString(
            string: "🛡️ NetGuard Network Monitor",
            attributes: [.font: NSFont.boldSystemFont(ofSize: 13)]
        )
        menu.addItem(headerItem)
        menu.addItem(NSMenuItem.separator())

        // 2. Active Network Information
        if let report = latestReport {
            let net = report.network
            let networkTitle = net.isWireless ? "📶 Wi-Fi: \(net.ssid ?? "Unknown")" : "📡 Interface: \(net.interfaceName)"
            let netItem = NSMenuItem(title: networkTitle, action: nil, keyEquivalent: "")
            netItem.isEnabled = false
            menu.addItem(netItem)

            let secTitle = "🔒 Security: \(net.securityType ?? (net.isWireless ? "Open" : "Ethernet"))"
            let secItem = NSMenuItem(title: secTitle, action: nil, keyEquivalent: "")
            secItem.isEnabled = false
            menu.addItem(secItem)

            if let gw = net.gatewayIP {
                let gwTitle = "🌐 Gateway: \(gw) (\(net.gatewayMAC ?? "MAC Unknown"))"
                let gwItem = NSMenuItem(title: gwTitle, action: nil, keyEquivalent: "")
                gwItem.isEnabled = false
                menu.addItem(gwItem)
            }

            menu.addItem(NSMenuItem.separator())

            // 3. Security Findings Submenu
            let findingsMenu = NSMenu()
            for finding in report.findings {
                let icon = finding.passed ? "✅" : (finding.severity == .critical || finding.severity == .high ? "🚨" : "⚠️")
                let item = NSMenuItem(title: "\(icon) \(finding.name): \(finding.passed ? "Passed" : finding.severity.rawValue)", action: nil, keyEquivalent: "")
                let subSubMenu = NSMenu()
                subSubMenu.addItem(NSMenuItem(title: finding.description, action: nil, keyEquivalent: ""))
                if let details = finding.details {
                    subSubMenu.addItem(NSMenuItem(title: "Details: \(details)", action: nil, keyEquivalent: ""))
                }
                if let remedy = finding.remediation {
                    subSubMenu.addItem(NSMenuItem(title: "Remedy: \(remedy)", action: nil, keyEquivalent: ""))
                }
                item.submenu = subSubMenu
                findingsMenu.addItem(item)
            }

            let statusSubmenuItem = NSMenuItem(title: report.isSafe ? "✅ Security Status: Protected" : "⚠️ Security Status: Threats Found", action: nil, keyEquivalent: "")
            statusSubmenuItem.submenu = findingsMenu
            menu.addItem(statusSubmenuItem)
        } else {
            let loadingItem = NSMenuItem(title: "Collecting Network Info...", action: nil, keyEquivalent: "")
            loadingItem.isEnabled = false
            menu.addItem(loadingItem)
        }

        menu.addItem(NSMenuItem.separator())

        // 4. Quick Actions
        let scanItem = NSMenuItem(title: "⚡ Scan Network Now", action: #selector(scanNowClicked), keyEquivalent: "r")
        scanItem.target = self
        menu.addItem(scanItem)

        // 5. Daemon Toggle Item
        let isDaemonRunning = DaemonManager.isRunning()
        let daemonTitle = isDaemonRunning ? "⚙️ Background Daemon: Active (Turn Off)" : "⚙️ Background Daemon: Inactive (Turn On)"
        let daemonItem = NSMenuItem(title: daemonTitle, action: #selector(toggleDaemonClicked), keyEquivalent: "d")
        daemonItem.target = self
        menu.addItem(daemonItem)

        // 6. Secure DNS Toggle
        let dnsItem = NSMenuItem(
            title: config.action.autoSecureDNS ? "🔒 Secure DNS (DoH): Enabled" : "🔓 Secure DNS: Disabled (Enable)",
            action: #selector(toggleSecureDNSClicked),
            keyEquivalent: ""
        )
        dnsItem.target = self
        menu.addItem(dnsItem)

        menu.addItem(NSMenuItem.separator())

        // 7. Open Config & Quit
        let openConfigItem = NSMenuItem(title: "📄 Open Config Directory", action: #selector(openConfigClicked), keyEquivalent: "c")
        openConfigItem.target = self
        menu.addItem(openConfigItem)

        let quitItem = NSMenuItem(title: "Quit NetGuard", action: #selector(quitClicked), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)
    }

    @objc private func scanNowClicked() {
        Task { @MainActor in
            await performScan()
        }
    }

    @objc private func toggleDaemonClicked() {
        if DaemonManager.isRunning() {
            _ = DaemonManager.disableDaemon()
        } else {
            _ = DaemonManager.enableDaemon()
        }
        rebuildMenu()
    }

    @objc private func toggleSecureDNSClicked() {
        config.action.autoSecureDNS.toggle()
        _ = ConfigManager.shared.save(config)

        if config.action.autoSecureDNS, let iface = latestReport?.network.interfaceName {
            _ = DnsSwitcher.applySecureDNS(interface: iface, servers: config.action.secureDNSAddresses)
        }
        rebuildMenu()
    }

    @objc private func openConfigClicked() {
        let dir = ConfigManager.shared.configURL.deletingLastPathComponent()
        NSWorkspace.shared.open(dir)
    }

    @objc private func quitClicked() {
        NSApplication.shared.terminate(nil)
    }
}
