import Foundation

private final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        // Do not follow redirects to capture captive portals
        completionHandler(nil)
    }
}

public final class CaptiveDetector {
    public static func auditCaptivePortal() async -> Finding {
        guard let url = URL(string: "http://captive.apple.com/hotspot-detect.html") else {
            return Finding(
                type: .captivePortal,
                name: "Captive Portal & Web Wall",
                severity: .safe,
                passed: true,
                description: "Captive endpoint URL invalid."
            )
        }

        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 3.0
        let delegate = NoRedirectDelegate()
        let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)

        var request = URLRequest(url: url)
        request.setValue("CaptiveNetworkSupport-355.0.1", forHTTPHeaderField: "User-Agent")

        do {
            let (data, response) = try await session.data(for: request)
            if let httpResp = response as? HTTPURLResponse {
                if [301, 302, 307, 308].contains(httpResp.statusCode) {
                    let loc = httpResp.value(forHTTPHeaderField: "Location") ?? "Unknown URL"
                    return Finding(
                        type: .captivePortal,
                        name: "Captive Portal & Web Wall",
                        severity: .medium,
                        passed: false,
                        description: "Captive Portal detected! Network is redirected to a login wall.",
                        details: "HTTP \(httpResp.statusCode) redirect to: \(loc)",
                        remediation: "Complete captive portal authentication before transmitting sensitive data."
                    )
                }

                let body = String(data: data, encoding: .utf8) ?? ""
                if !body.contains("Success") {
                    return Finding(
                        type: .captivePortal,
                        name: "Captive Portal & Web Wall",
                        severity: .medium,
                        passed: false,
                        description: "Captive Portal or modified web response detected.",
                        details: "Non-standard HTML response body received.",
                        remediation: "Verify network authentication before sending sensitive data."
                    )
                }
            }
        } catch {
            return Finding(
                type: .captivePortal,
                name: "Captive Portal & Web Wall",
                severity: .safe,
                passed: true,
                description: "Captive portal check completed (Offline or unrestricted direct connection)."
            )
        }

        return Finding(
            type: .captivePortal,
            name: "Captive Portal & Web Wall",
            severity: .safe,
            passed: true,
            description: "Direct Internet access verified (No captive portal redirection)."
        )
    }
}
