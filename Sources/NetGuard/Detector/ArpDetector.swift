import Foundation

public struct ARPEntry {
    public let ip: String
    public let mac: String
}

public final class ArpDetector {
    public static func getArpTable() -> [ARPEntry] {
        let output = WifiDetector.runProcess(executable: "/usr/sbin/arp", arguments: ["-an"])
        var entries: [ARPEntry] = []

        let pattern = #"\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)\s+at\s+([0-9a-fA-F:]+)"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return entries }

        let lines = output.components(separatedBy: .newlines)
        for line in lines {
            let range = NSRange(location: 0, length: line.utf16.count)
            if let match = regex.firstMatch(in: line, options: [], range: range) {
                if let ipRange = Range(match.range(at: 1), in: line),
                   let macRange = Range(match.range(at: 2), in: line) {
                    let ip = String(line[ipRange])
                    let mac = String(line[macRange]).lowercased()

                    if mac != "(incomplete)" && mac != "ff:ff:ff:ff:ff:ff" {
                        entries.append(ARPEntry(ip: ip, mac: mac))
                    }
                }
            }
        }
        return entries
    }

    public static func lookupMAC(forIP targetIP: String) -> String? {
        let entries = getArpTable()
        return entries.first(where: { $0.ip == targetIP })?.mac
    }

    public static func auditArpIntegrity(gatewayIP: String?) -> Finding {
        guard let gwIP = gatewayIP, !gwIP.isEmpty else {
            return Finding(
                type: .arpSpoofing,
                name: "ARP Spoofing & Gateway Integrity",
                severity: .low,
                passed: true,
                description: "Gateway IP not determined; ARP spoof check skipped."
            )
        }

        let entries = getArpTable()
        var macToIPs: [String: [String]] = [:]
        var gatewayMAC: String?

        for entry in entries {
            macToIPs[entry.mac, default: []].append(entry.ip)
            if entry.ip == gwIP {
                gatewayMAC = entry.mac
            }
        }

        if let gwMAC = gatewayMAC, let sharedIPs = macToIPs[gwMAC] {
            let conflictingIPs = sharedIPs.filter { $0 != gwIP }
            if !conflictingIPs.isEmpty {
                return Finding(
                    type: .arpSpoofing,
                    name: "ARP Spoofing & Gateway Integrity",
                    severity: .critical,
                    passed: false,
                    description: "CRITICAL: Suspected ARP Spoofing (MITM Attack)! Gateway MAC (\(gwMAC)) is also claimed by \(conflictingIPs.joined(separator: ", "))",
                    details: "Gateway: \(gwIP) (\(gwMAC)), Conflicting IPs: \(conflictingIPs)",
                    remediation: "Disconnect immediately. Your local network traffic is being actively intercepted."
                )
            }
        }

        return Finding(
            type: .arpSpoofing,
            name: "ARP Spoofing & Gateway Integrity",
            severity: .safe,
            passed: true,
            description: "Gateway ARP mapping is clean (\(gwIP) -> \(gatewayMAC ?? "unknown")). No duplicate MAC conflicts."
        )
    }
}
