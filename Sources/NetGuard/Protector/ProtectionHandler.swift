import Foundation

public final class ProtectionHandler {
    private let config: NetGuardConfig

    public init(config: NetGuardConfig) {
        self.config = config
    }

    public func handle(report: AuditReport) {
        // 1. Check if network is trusted
        if isTrusted(network: report.network) {
            print("[INFO] Network '\(report.network.ssid ?? "Active Network")' is in trusted whitelist. Bypassing protection.")
            return
        }

        if report.isSafe {
            print("[INFO] \(report.summaryMessage)")
            return
        }

        print("[WARN] \(report.summaryMessage)")

        // 2. Send Desktop Notification
        if config.action.enableNotification {
            let title = "🛡️ NetGuard Security Alert"
            let subtitle = "Threat Level: \(report.overallStatus.rawValue)"
            let failedFindings = report.findings.filter { !$0.passed }
            let message = failedFindings.first?.description ?? "Unsafe network detected! Packet sniffing or MITM risk."

            Notifier.sendNotification(title: title, subtitle: subtitle, message: message)
        }

        // 3. Auto Secure DNS
        if config.action.autoSecureDNS && !config.action.secureDNSAddresses.isEmpty {
            print("[ACTION] Applying secure DNS servers: \(config.action.secureDNSAddresses)")
            _ = DnsSwitcher.applySecureDNS(
                interface: report.network.interfaceName,
                servers: config.action.secureDNSAddresses
            )
        }

        // 4. Auto VPN Hook
        if !config.action.autoVpnCommand.isEmpty {
            print("[ACTION] Executing VPN command: \(config.action.autoVpnCommand)")
            VpnHook.triggerVpn(command: config.action.autoVpnCommand)
        }
    }

    private func isTrusted(network: NetworkInfo) -> Bool {
        if let ssid = network.ssid, config.trust.trustedSSIDs.contains(ssid) {
            return true
        }
        if let bssid = network.bssid, config.trust.trustedBSSIDs.contains(bssid) {
            return true
        }
        return false
    }
}
