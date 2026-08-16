import Foundation

public struct NetGuardConfig: Codable {
    public var detection: DetectionSettings
    public var action: ActionSettings
    public var trust: TrustSettings
    public var logging: LoggingSettings

    public init(
        detection: DetectionSettings = DetectionSettings(),
        action: ActionSettings = ActionSettings(),
        trust: TrustSettings = TrustSettings(),
        logging: LoggingSettings = LoggingSettings()
    ) {
        self.detection = detection
        self.action = action
        self.trust = trust
        self.logging = logging
    }

    public static let `default` = NetGuardConfig()
}

public struct DetectionSettings: Codable {
    public var checkWifiSecurity: Bool
    public var checkArpSpoof: Bool
    public var checkDnsHijack: Bool
    public var checkSslMitm: Bool
    public var checkCaptive: Bool
    public var testDomains: [String]
    public var dohServers: [String]

    public init(
        checkWifiSecurity: Bool = true,
        checkArpSpoof: Bool = true,
        checkDnsHijack: Bool = true,
        checkSslMitm: Bool = true,
        checkCaptive: Bool = true,
        testDomains: [String] = ["google.com", "cloudflare.com", "apple.com", "github.com"],
        dohServers: [String] = ["https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"]
    ) {
        self.checkWifiSecurity = checkWifiSecurity
        self.checkArpSpoof = checkArpSpoof
        self.checkDnsHijack = checkDnsHijack
        self.checkSslMitm = checkSslMitm
        self.checkCaptive = checkCaptive
        self.testDomains = testDomains
        self.dohServers = dohServers
    }
}

public struct ActionSettings: Codable {
    public var enableNotification: Bool
    public var autoSecureDNS: Bool
    public var secureDNSAddresses: [String]
    public var autoVpnCommand: String

    public init(
        enableNotification: Bool = true,
        autoSecureDNS: Bool = false,
        secureDNSAddresses: [String] = ["1.1.1.1", "1.0.0.1", "8.8.8.8"],
        autoVpnCommand: String = ""
    ) {
        self.enableNotification = enableNotification
        self.autoSecureDNS = autoSecureDNS
        self.secureDNSAddresses = secureDNSAddresses
        self.autoVpnCommand = autoVpnCommand
    }
}

public struct TrustSettings: Codable {
    public var trustedSSIDs: [String]
    public var trustedBSSIDs: [String]

    public init(
        trustedSSIDs: [String] = [],
        trustedBSSIDs: [String] = []
    ) {
        self.trustedSSIDs = trustedSSIDs
        self.trustedBSSIDs = trustedBSSIDs
    }
}

public struct LoggingSettings: Codable {
    public var logLevel: String
    public var logFile: String

    public init(
        logLevel: String = "info",
        logFile: String = "~/.local/state/netguard/netguard.log"
    ) {
        self.logLevel = logLevel
        self.logFile = logFile
    }
}

public final class ConfigManager {
    public static let shared = ConfigManager()

    private let fileManager = FileManager.default

    public var configURL: URL {
        let home = fileManager.homeDirectoryForCurrentUser
        return home.appendingPathComponent(".config/netguard/config.json")
    }

    public func load() -> NetGuardConfig {
        do {
            let data = try Data(contentsOf: configURL)
            let decoder = JSONDecoder()
            return try decoder.decode(NetGuardConfig.self, from: data)
        } catch {
            let defaultConfig = NetGuardConfig.default
            _ = save(defaultConfig)
            return defaultConfig
        }
    }

    public func save(_ config: NetGuardConfig) -> Bool {
        do {
            let dirURL = configURL.deletingLastPathComponent()
            try fileManager.createDirectory(at: dirURL, withIntermediateDirectories: true, attributes: nil)

            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(config)
            try data.write(to: configURL, options: .atomic)
            return true
        } catch {
            fputs("Failed to save config: \(error.localizedDescription)\n", stderr)
            return false
        }
    }
}
