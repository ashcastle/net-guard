import Foundation
import Security

private final class TLSCheckDelegate: NSObject, URLSessionDelegate {
    var hasSSLError: Bool = false
    var errorDetails: String?

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        var error: CFError?
        let isTrusted = SecTrustEvaluateWithError(serverTrust, &error)

        if !isTrusted {
            hasSSLError = true
            errorDetails = error?.localizedDescription ?? "Untrusted certificate authority / invalid certificate"
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        completionHandler(.performDefaultHandling, nil)
    }
}

public final class SslDetector {
    public static func auditSslInterception(testHosts: [String]) async -> Finding {
        let hosts = testHosts.isEmpty ? ["cloudflare.com", "google.com", "apple.com"] : testHosts
        var compromisedHosts: [String] = []

        for host in hosts {
            guard let url = URL(string: "https://\(host)") else { continue }
            let delegate = TLSCheckDelegate()
            let config = URLSessionConfiguration.ephemeral
            config.timeoutIntervalForRequest = 4.0
            let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)

            var request = URLRequest(url: url)
            request.httpMethod = "HEAD"

            do {
                _ = try await session.data(for: request)
                if delegate.hasSSLError {
                    compromisedHosts.append("\(host) (\(delegate.errorDetails ?? "Untrusted CA"))")
                }
            } catch {
                if delegate.hasSSLError || error.localizedDescription.lowercased().contains("certificate") {
                    compromisedHosts.append("\(host) (\(error.localizedDescription))")
                }
            }
        }

        if !compromisedHosts.isEmpty {
            return Finding(
                type: .sslMitm,
                name: "SSL/TLS Certificate & MITM Inspection",
                severity: .critical,
                passed: false,
                description: "CRITICAL: SSL/TLS Interception / MITM Proxy detected on \(compromisedHosts.count) host(s)!",
                details: compromisedHosts.joined(separator: "; "),
                remediation: "Do NOT proceed with secure browsing. Your HTTPS encrypted traffic is being decrypted and intercepted."
            )
        }

        return Finding(
            type: .sslMitm,
            name: "SSL/TLS Certificate & MITM Inspection",
            severity: .safe,
            passed: true,
            description: "SSL/TLS trust chains and root certificates validated securely."
        )
    }
}
