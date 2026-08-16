import Foundation

public final class Scanner {
    private let config: NetGuardConfig

    public init(config: NetGuardConfig) {
        self.config = config
    }

    public func runAudit() async -> AuditReport {
        let netInfo = WifiDetector.collectNetworkInfo()
        var findings: [Finding] = []

        // 1. Wi-Fi Security
        if config.detection.checkWifiSecurity {
            findings.append(WifiDetector.auditWifiSecurity(info: netInfo))
        }

        // 2. ARP Spoofing
        if config.detection.checkArpSpoof {
            findings.append(ArpDetector.auditArpIntegrity(gatewayIP: netInfo.gatewayIP))
        }

        // 3. DNS Hijacking (Async)
        if config.detection.checkDnsHijack {
            let dnsFinding = await DnsDetector.auditDnsIntegrity(
                testDomains: config.detection.testDomains,
                dohServers: config.detection.dohServers
            )
            findings.append(dnsFinding)
        }

        // 4. SSL Interception (Async)
        if config.detection.checkSslMitm {
            let sslFinding = await SslDetector.auditSslInterception(testHosts: config.detection.testDomains)
            findings.append(sslFinding)
        }

        // 5. Captive Portal (Async)
        if config.detection.checkCaptive {
            let captiveFinding = await CaptiveDetector.auditCaptivePortal()
            findings.append(captiveFinding)
        }

        // Calculate overall severity and safety status
        var highestSeverity: Severity = .safe
        var isSafe = true

        for f in findings {
            if !f.passed {
                isSafe = false
                if f.severity > highestSeverity {
                    highestSeverity = f.severity
                }
            }
        }

        let displayName = netInfo.isWireless ? (netInfo.ssid ?? netInfo.interfaceName) : netInfo.interfaceName
        let summary: String
        if isSafe {
            summary = "Network '\(displayName)' verified secure. No eavesdropping or MITM threats detected."
        } else {
            summary = "WARNING: Network '\(displayName)' has security risks (Status: \(highestSeverity.rawValue))!"
        }

        return AuditReport(
            timestamp: Date(),
            network: netInfo,
            overallStatus: highestSeverity,
            isSafe: isSafe,
            findings: findings,
            summaryMessage: summary
        )
    }
}
