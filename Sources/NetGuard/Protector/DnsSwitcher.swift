import Foundation

public final class DnsSwitcher {
    public static func getNetworkServiceName(forInterface iface: String) -> String {
        let output = WifiDetector.runProcess(
            executable: "/usr/sbin/networksetup",
            arguments: ["-listallhardwareports"]
        )

        var currentPort: String?
        for line in output.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("Hardware Port:") {
                currentPort = trimmed.replacingOccurrences(of: "Hardware Port:", with: "").trimmingCharacters(in: .whitespaces)
            } else if trimmed.hasPrefix("Device:") {
                let dev = trimmed.replacingOccurrences(of: "Device:", with: "").trimmingCharacters(in: .whitespaces)
                if dev == iface, let port = currentPort {
                    return port
                }
            }
        }

        return "Wi-Fi"
    }

    public static func applySecureDNS(interface: String, servers: [String]) -> Bool {
        guard !servers.isEmpty else { return false }
        let serviceName = getNetworkServiceName(forInterface: interface)
        var args = ["-setdnsservers", serviceName]
        args.append(contentsOf: servers)

        let output = WifiDetector.runProcess(
            executable: "/usr/sbin/networksetup",
            arguments: args
        )
        return output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}
