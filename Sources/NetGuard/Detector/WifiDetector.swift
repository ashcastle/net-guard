import Foundation
import CoreWLAN
import SystemConfiguration

public final class WifiDetector {
    public static func collectNetworkInfo() -> NetworkInfo {
        var info = NetworkInfo()

        // 1. Get default routing interface and gateway IP
        let routeOutput = runProcess(executable: "/sbin/route", arguments: ["-n", "get", "default"])
        var ifaceName = ""
        var gateway = ""

        for line in routeOutput.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("gateway:") {
                let parts = trimmed.split(separator: " ")
                if parts.count >= 2 {
                    gateway = String(parts[1])
                }
            } else if trimmed.hasPrefix("interface:") {
                let parts = trimmed.split(separator: " ")
                if parts.count >= 2 {
                    ifaceName = String(parts[1])
                }
            }
        }

        info.interfaceName = ifaceName.isEmpty ? "en0" : ifaceName
        info.gatewayIP = gateway.isEmpty ? nil : gateway

        // 2. Query CoreWLAN for Wi-Fi details
        if let wifiInterface = CWWiFiClient.shared().interface(withName: info.interfaceName) ?? CWWiFiClient.shared().interface() {
            if let currentSSID = wifiInterface.ssid(), !currentSSID.isEmpty {
                info.isWireless = true
                info.ssid = currentSSID
                info.bssid = wifiInterface.bssid()
                info.securityType = parseSecurityType(wifiInterface.security())
            }
        }

        // 3. Query DNS servers via scutil
        info.configuredDNS = getConfiguredDNSServers()

        // 4. Get Gateway MAC from ARP table if gateway IP is known
        if let gwIP = info.gatewayIP {
            info.gatewayMAC = ArpDetector.lookupMAC(forIP: gwIP)
        }

        return info
    }

    public static func auditWifiSecurity(info: NetworkInfo) -> Finding {
        guard info.isWireless else {
            return Finding(
                type: .wifiSecurity,
                name: "Wi-Fi Security Encryption",
                severity: .safe,
                passed: true,
                description: "Wired Ethernet connection in use (No Wi-Fi broadcast/snooping risks)."
            )
        }

        let ssid = info.ssid ?? "Unknown Network"
        let sec = (info.securityType ?? "").lowercased()

        if sec.isEmpty || sec.contains("open") || sec.contains("none") {
            return Finding(
                type: .wifiSecurity,
                name: "Wi-Fi Security Encryption",
                severity: .critical,
                passed: false,
                description: "Connected to an UNENCRYPTED Open Wi-Fi ('\(ssid)'). Plaintext traffic can be intercepted by anyone nearby.",
                details: "SSID: \(ssid), BSSID: \(info.bssid ?? "N/A"), Auth: \(info.securityType ?? "Open")",
                remediation: "Enable VPN immediately or disconnect from this open network."
            )
        }

        if sec.contains("wep") {
            return Finding(
                type: .wifiSecurity,
                name: "Wi-Fi Security Encryption",
                severity: .high,
                passed: false,
                description: "Connected to an insecure WEP Wi-Fi ('\(ssid)'). WEP encryption is obsolete and vulnerable.",
                details: "SSID: \(ssid), Auth: \(info.securityType ?? "WEP")",
                remediation: "Upgrade the router configuration to WPA2-AES or WPA3."
            )
        }

        if sec.contains("wpa3") {
            return Finding(
                type: .wifiSecurity,
                name: "Wi-Fi Security Encryption",
                severity: .safe,
                passed: true,
                description: "Strong WPA3 encryption active on '\(ssid)'.",
                details: "SSID: \(ssid), Auth: \(info.securityType ?? "WPA3")"
            )
        }

        return Finding(
            type: .wifiSecurity,
            name: "Wi-Fi Security Encryption",
            severity: .safe,
            passed: true,
            description: "Standard WPA/WPA2 encryption active on '\(ssid)'.",
            details: "SSID: \(ssid), Auth: \(info.securityType ?? "WPA2")"
        )
    }

    private static func parseSecurityType(_ sec: CWSecurity) -> String {
        switch sec.rawValue {
        case CWSecurity.none.rawValue: return "Open (None)"
        case CWSecurity.wpaPersonal.rawValue: return "WPA Personal"
        case CWSecurity.wpaPersonalMixed.rawValue: return "WPA/WPA2 Mixed Personal"
        case CWSecurity.wpa2Personal.rawValue: return "WPA2 Personal"
        case CWSecurity.personal.rawValue: return "Personal (WPA/WPA2/WPA3)"
        case CWSecurity.dynamicWEP.rawValue: return "Dynamic WEP"
        case CWSecurity.wpaEnterprise.rawValue: return "WPA Enterprise"
        case CWSecurity.wpaEnterpriseMixed.rawValue: return "WPA/WPA2 Enterprise Mixed"
        case CWSecurity.wpa2Enterprise.rawValue: return "WPA2 Enterprise"
        case CWSecurity.enterprise.rawValue: return "Enterprise"
        case CWSecurity.wpa3Personal.rawValue: return "WPA3 Personal (SAE)"
        case CWSecurity.wpa3Enterprise.rawValue: return "WPA3 Enterprise"
        case CWSecurity.wpa3Transition.rawValue: return "WPA3 Transition"
        case CWSecurity.unknown.rawValue: return "Unknown"
        default:
            return "WPA/WPA2/WPA3 (\(sec.rawValue))"
        }
    }

    private static func getConfiguredDNSServers() -> [String] {
        let output = runProcess(executable: "/usr/sbin/scutil", arguments: ["--dns"])
        var servers: [String] = []
        var seen = Set<String>()

        for line in output.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("nameserver[") {
                let parts = trimmed.split(separator: ":")
                if parts.count >= 2 {
                    let ip = parts[1].trimmingCharacters(in: .whitespaces)
                    if !ip.isEmpty && !seen.contains(ip) {
                        seen.insert(ip)
                        servers.append(ip)
                    }
                }
            }
        }
        return servers
    }

    public static func runProcess(executable: String, arguments: [String]) -> String {
        let process = Process()
        let pipe = Pipe()

        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = pipe
        process.standardError = Pipe() // suppress stderr

        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return String(data: data, encoding: .utf8) ?? ""
        } catch {
            return ""
        }
    }
}
