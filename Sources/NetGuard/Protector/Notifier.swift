import Foundation

public final class Notifier {
    public static func sendNotification(title: String, subtitle: String, message: String) {
        let cleanTitle = escapeAppleScript(title)
        let cleanSubtitle = escapeAppleScript(subtitle)
        let cleanMessage = escapeAppleScript(message)

        let script = """
        display notification "\(cleanMessage)" with title "\(cleanTitle)" subtitle "\(cleanSubtitle)" sound name "Basso"
        """

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]

        try? process.run()
    }

    private static func escapeAppleScript(_ string: String) -> String {
        return string
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }
}
