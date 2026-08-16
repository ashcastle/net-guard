import Foundation
import AppKit

public final class MenuBarController: NSObject, NSApplicationDelegate, NSMenuDelegate {
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
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        app.delegate = self
        app.run()
    }

    public func applicationDidFinishLaunching(_ notification: Notification) {
        // Setup Status Item in macOS Menu Bar
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        
        if let button = statusItem?.button {
            if #available(macOS 11.0, *) {
                let config = NSImage.SymbolConfiguration(pointSize: 14, weight: .medium)
                let img = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "NetGuard")?.withSymbolConfiguration(config)
                img?.isTemplate = true
                button.image = img
                button.imagePosition = .imageLeading
            }
            button.title = " NetGuard"
            button.toolTip = "NetGuard: Network Security Monitor"
        }

        menu.delegate = self
        statusItem?.menu = menu
        rebuildMenu()

        // Start Network Monitor
        monitor = NetworkMonitor { [weak self] _ in
            Task { @MainActor in
                await self?.performScan()
            }
        }
        monitor?.start()

        // Trigger initial security scan
        Task { @MainActor in
            await self.performScan()
        }
    }

    @MainActor
    private func performScan() async {
        guard !isScanning else { return }
        isScanning = true
        updateStatusButton(title: " NetGuard (Scanning...)", isSafe: nil, isChecking: true)

        let report = await scanner.runAudit()
        self.latestReport = report
        self.handler.handle(report: report)
        self.isScanning = false

        if report.isSafe {
            let name = report.network.ssid ?? report.network.interfaceName
            updateStatusButton(title: " NetGuard (\(name))", isSafe: true, isChecking: false)
        } else {
            updateStatusButton(title: " NetGuard (⚠️ \(report.overallStatus.rawValue))", isSafe: false, isChecking: false)
        }

        rebuildMenu()
    }

    private func updateStatusButton(title: String, isSafe: Bool?, isChecking: Bool) {
        DispatchQueue.main.async {
            guard let button = self.statusItem?.button else { return }
            button.title = title

            if #available(macOS 11.0, *) {
                let symbolName: String
                if isChecking {
                    symbolName = "antenna.radiowaves.left.and.right"
                } else if isSafe == true {
                    symbolName = "checkmark.shield.fill"
                } else if isSafe == false {
                    symbolName = "exclamationmark.shield.fill"
                } else {
                    symbolName = "shield.lefthalf.filled"
                }

                let config = NSImage.SymbolConfiguration(pointSize: 14, weight: .medium)
                let img = NSImage(systemSymbolName: symbolName, accessibilityDescription: "NetGuard")?.withSymbolConfiguration(config)
                img?.isTemplate = (isSafe != false)
                button.image = img
            }
        }
    }

    public func menuWillOpen(_ menu: NSMenu) {
        rebuildMenu()
    }

    private func rebuildMenu() {
        menu.removeAllItems()

        // 1. Header & Title
        let headerItem = NSMenuItem(title: "NetGuard Network Security", action: nil, keyEquivalent: "")
        headerItem.attributedTitle = NSAttributedString(
            string: "🛡️ NetGuard Monitor",
            attributes: [.font: NSFont.boldSystemFont(ofSize: 13)]
        )
        menu.addItem(headerItem)
        menu.addItem(NSMenuItem.separator())

        // 2. Active Network Details
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

            // 3. Security Audit Findings Submenu
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

            let statusSubmenuItem = NSMenuItem(title: report.isSafe ? "✅ Security Status: Protected" : "⚠️ Security Status: Threats Detected", action: nil, keyEquivalent: "")
            statusSubmenuItem.submenu = findingsMenu
            menu.addItem(statusSubmenuItem)
        } else {
            let loadingItem = NSMenuItem(title: "Auditing Network Connection...", action: nil, keyEquivalent: "")
            loadingItem.isEnabled = false
            menu.addItem(loadingItem)
        }

        menu.addItem(NSMenuItem.separator())

        // 4. Quick Actions
        let scanItem = NSMenuItem(title: "⚡ Scan Network Now", action: #selector(scanNowClicked), keyEquivalent: "r")
        scanItem.target = self
        menu.addItem(scanItem)

        // 5. Daemon Toggle
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

        // 7. Config & Quit
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
