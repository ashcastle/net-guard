import Foundation

public enum Severity: String, Codable, Comparable, CaseIterable {
    case safe = "SAFE"
    case low = "LOW"
    case medium = "MEDIUM"
    case high = "HIGH"
    case critical = "CRITICAL"

    public var rank: Int {
        switch self {
        case .safe: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .critical: return 4
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool {
        return lhs.rank < rhs.rank
    }
}

public enum CheckType: String, Codable {
    case wifiSecurity = "WIFI_SECURITY"
    case arpSpoofing = "ARP_SPOOFING"
    case dnsHijacking = "DNS_HIJACKING"
    case sslMitm = "SSL_MITM"
    case captivePortal = "CAPTIVE_PORTAL"
}

public struct Finding: Codable {
    public let type: CheckType
    public let name: String
    public let severity: Severity
    public let passed: Bool
    public let description: String
    public let details: String?
    public let remediation: String?

    public init(
        type: CheckType,
        name: String,
        severity: Severity,
        passed: Bool,
        description: String,
        details: String? = nil,
        remediation: String? = nil
    ) {
        self.type = type
        self.name = name
        self.severity = severity
        self.passed = passed
        self.description = description
        self.details = details
        self.remediation = remediation
    }
}

public struct NetworkInfo: Codable {
    public var interfaceName: String
    public var ipv4Address: String?
    public var gatewayIP: String?
    public var gatewayMAC: String?
    public var ssid: String?
    public var bssid: String?
    public var securityType: String?
    public var configuredDNS: [String]
    public var isWireless: Bool

    public init(
        interfaceName: String = "",
        ipv4Address: String? = nil,
        gatewayIP: String? = nil,
        gatewayMAC: String? = nil,
        ssid: String? = nil,
        bssid: String? = nil,
        securityType: String? = nil,
        configuredDNS: [String] = [],
        isWireless: Bool = false
    ) {
        self.interfaceName = interfaceName
        self.ipv4Address = ipv4Address
        self.gatewayIP = gatewayIP
        self.gatewayMAC = gatewayMAC
        self.ssid = ssid
        self.bssid = bssid
        self.securityType = securityType
        self.configuredDNS = configuredDNS
        self.isWireless = isWireless
    }
}

public struct AuditReport: Codable {
    public let timestamp: Date
    public let network: NetworkInfo
    public let overallStatus: Severity
    public let isSafe: Bool
    public let findings: [Finding]
    public let summaryMessage: String

    public init(
        timestamp: Date = Date(),
        network: NetworkInfo,
        overallStatus: Severity,
        isSafe: Bool,
        findings: [Finding],
        summaryMessage: String
    ) {
        self.timestamp = timestamp
        self.network = network
        self.overallStatus = overallStatus
        self.isSafe = isSafe
        self.findings = findings
        self.summaryMessage = summaryMessage
    }
}
