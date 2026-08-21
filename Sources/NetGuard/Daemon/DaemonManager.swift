import Foundation

public final class DaemonManager {
    public static let label = "com.netguard.daemon"

    public static var plistURL: URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return home.appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    public static var logURL: URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return home.appendingPathComponent(".local/state/netguard/daemon.log")
    }

    public static var errorLogURL: URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return home.appendingPathComponent(".local/state/netguard/daemon.err.log")
    }

    private static var currentUID: String {
        return String(getuid())
    }

    public static func enableDaemon() -> (success: Bool, message: String) {
        // Find executable binary path
        let binaryPath = ProcessInfo.processInfo.arguments.first ?? "/usr/local/bin/netguard"
        let resolvedPath: String
        if binaryPath.hasPrefix("/") {
            resolvedPath = binaryPath
        } else {
            resolvedPath = WifiDetector.runProcess(executable: "/usr/bin/which", arguments: ["netguard"]).trimmingCharacters(in: .whitespacesAndNewlines)
            if resolvedPath.isEmpty {
                return (false, "Could not resolve 'netguard' binary path. Please ensure netguard is installed in your PATH (e.g. /usr/local/bin or via brew).")
            }
        }

        // Create log directory
        let logDir = logURL.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: logDir, withIntermediateDirectories: true, attributes: nil)

        // Create LaunchAgents directory if not exists
        let launchAgentsDir = plistURL.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: launchAgentsDir, withIntermediateDirectories: true, attributes: nil)

        // Generate plist XML (KeepAlive only on abnormal crash, not on normal exit)
        let plistContent = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(label)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(resolvedPath)</string>
                <string>daemon</string>
                <string>run</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <dict>
                <key>SuccessfulExit</key>
                <false/>
            </dict>
            <key>StandardOutPath</key>
            <string>\(logURL.path)</string>
            <key>StandardErrorPath</key>
            <string>\(errorLogURL.path)</string>
        </dict>
        </plist>
        """

        do {
            try plistContent.write(to: plistURL, atomically: true, encoding: .utf8)
        } catch {
            return (false, "Failed to write plist file to \(plistURL.path): \(error.localizedDescription)")
        }

        // Bootout / Unload any existing service first
        _ = WifiDetector.runProcess(executable: "/bin/launchctl", arguments: ["bootout", "gui/\(currentUID)/\(label)"])
        _ = WifiDetector.runProcess(executable: "/bin/launchctl", arguments: ["unload", plistURL.path])

        // Load new service
        let bootstrapOutput = WifiDetector.runProcess(executable: "/bin/launchctl", arguments: ["bootstrap", "gui/\(currentUID)", plistURL.path])
        if !isRunning() {
            _ = WifiDetector.runProcess(executable: "/bin/launchctl", arguments: ["load", "-w", plistURL.path])
        }

        if isRunning() {
            return (true, "✅ NetGuard daemon successfully enabled and started! (LaunchAgent: \(plistURL.path))")
        } else {
            return (true, "✅ NetGuard daemon registered. Output: \(bootstrapOutput)")
        }
    }

    public static func disableDaemon() -> (success: Bool, message: String) {
        var actionsPerformed = false

        // 1. Bootout service domain in launchctl
        _ = WifiDetector.runProcess(executable: "/bin/launchctl", arguments: ["bootout", "gui/\(currentUID)/\(label)"])
        
        // 2. Unload plist if exists
        if FileManager.default.fileExists(atPath: plistURL.path) {
            _ = WifiDetector.runProcess(executable: "/bin/launchctl", arguments: ["unload", "-w", plistURL.path])
            try? FileManager.default.removeItem(at: plistURL)
            actionsPerformed = true
        }

        // 3. Terminate any remaining netguard daemon processes
        _ = WifiDetector.runProcess(executable: "/usr/bin/pkill", arguments: ["-f", "netguard daemon run"])

        if actionsPerformed || !isRunning() {
            return (true, "🛑 NetGuard daemon and all associated processes stopped.")
        } else {
            return (true, "NetGuard daemon is already disabled.")
        }
    }

    public static func isRunning() -> Bool {
        let output = WifiDetector.runProcess(executable: "/bin/launchctl", arguments: ["list"])
        return output.contains(label)
    }

    public static func getStatus() -> String {
        let running = isRunning()
        let plistExists = FileManager.default.fileExists(atPath: plistURL.path)

        var status = "🛡️ NetGuard Daemon Status:\n"
        status += "  • State:        \(running ? "🟢 Running (Active)" : "⚪ Stopped (Inactive)")\n"
        status += "  • LaunchAgent:  \(plistExists ? "Registered (\(plistURL.path))" : "Not Registered")\n"
        status += "  • Log Path:     \(logURL.path)\n"
        return status
    }
}
