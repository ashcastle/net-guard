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
    public var checkWifiSecurity: Bool = true
    public var checkArpSpoof: Bool = true
    public var checkDnsHijack: Bool = true
    public var checkSslMitm: Bool = true
    public var checkCaptive: Bool = true
    public var testDomains: [String] = [
        "google.com",
        "cloudflare.com",
        "apple.com",
        "github.com"
    ]
    public var dohServers: [String] = [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/dns-query"
    ]
}

public struct ActionSettings: Codable {
    public var enableNotification: Bool = true
    public var autoSecureDNS: Bool = false
    public var secureDNSAddresses: [String] = ["1.1.1.1", "1.0.0.1", "8.8.8.8"]
    public var autoVpnCommand: String = ""
}

public struct TrustSettings: Codable {
    public var trustedSSIDs: [String] = []
    public var trustedBSSIDs: [String] = []
}

public struct LoggingSettings: Codable {
    public var logLevel: String = "info"
    public var logFile: String = "~/.local/state/netguard/netguard.log"
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
