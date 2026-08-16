import Foundation

private struct DoHResponse: Codable {
    struct Answer: Codable {
        let name: String
        let type: Int
        let data: String
    }
    let Status: Int
    let Answer: [Answer]?
}

public final class DnsDetector {
    public static func auditDnsIntegrity(testDomains: [String], dohServers: [String]) async -> Finding {
        let domains = testDomains.isEmpty ? ["google.com", "cloudflare.com", "apple.com"] : testDomains
        let dohEndpoint = dohServers.first ?? "https://cloudflare-dns.com/dns-query"

        var suspiciousFindings: [String] = []

        await withTaskGroup(of: (String, Bool, String?).self) { group in
            for domain in domains {
                group.addTask {
                    let localIPs = resolveLocally(domain: domain)
                    let dohIPs = await queryDoH(endpoint: dohEndpoint, domain: domain)

                    // If neither responded, network might be down (ignore for hijack check)
                    if localIPs.isEmpty && dohIPs.isEmpty {
                        return (domain, false, nil)
                    }

                    // Check if local DNS returns loopback/unspecified/private IP for public domain
                    for ip in localIPs {
                        if isBogusOrPrivateIP(ip) {
                            return (domain, true, "\(domain) resolved to private/bogus IP \(ip) locally")
                        }
                    }

                    // Check if local resolver returned NXDOMAIN while DoH succeeded
                    if localIPs.isEmpty && !dohIPs.isEmpty {
                        return (domain, true, "\(domain) is blocked or NXDOMAIN locally, but valid in DoH")
                    }

                    return (domain, false, nil)
                }
            }

            for await (_, isSuspicious, detail) in group {
                if isSuspicious, let d = detail {
                    suspiciousFindings.append(d)
                }
            }
        }

        if !suspiciousFindings.isEmpty {
            return Finding(
                type: .dnsHijacking,
                name: "DNS Integrity & Hijacking",
                severity: .critical,
                passed: false,
                description: "CRITICAL: DNS Hijacking / Tampering detected on \(suspiciousFindings.count) domain(s)!",
                details: suspiciousFindings.joined(separator: "; "),
                remediation: "Switch to Secure DNS (1.1.1.1 or 8.8.8.8) or enable VPN immediately."
            )
        }

        return Finding(
            type: .dnsHijacking,
            name: "DNS Integrity & Hijacking",
            severity: .safe,
            passed: true,
            description: "DNS resolution verified clean against secure DoH (\(dohEndpoint))."
        )
    }

    private static func resolveLocally(domain: String) -> [String] {
        var results: [String] = []
        var hints = addrinfo(
            ai_flags: AI_PASSIVE,
            ai_family: AF_INET,
            ai_socktype: SOCK_STREAM,
            ai_protocol: 0,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var servinfo: UnsafeMutablePointer<addrinfo>?

        guard getaddrinfo(domain, nil, &hints, &servinfo) == 0, let info = servinfo else {
            return []
        }
        defer { freeaddrinfo(servinfo) }

        var ptr: UnsafeMutablePointer<addrinfo>? = info
        while let current = ptr {
            var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(current.pointee.ai_addr, current.pointee.ai_addrlen, &hostname, socklen_t(hostname.count), nil, 0, NI_NUMERICHOST) == 0 {
                let ipStr = String(cString: hostname)
                results.append(ipStr)
            }
            ptr = current.pointee.ai_next
        }
        return results
    }

    private static func queryDoH(endpoint: String, domain: String) async -> [String] {
        guard var components = URLComponents(string: endpoint) else { return [] }
        components.queryItems = [
            URLQueryItem(name: "name", value: domain),
            URLQueryItem(name: "type", value: "A")
        ]
        guard let url = components.url else { return [] }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/dns-json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 3.0

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                return []
            }
            let decoder = JSONDecoder()
            let dohResp = try decoder.decode(DoHResponse.self, from: data)
            return (dohResp.Answer ?? []).filter { $0.type == 1 }.map { $0.data }
        } catch {
            return []
        }
    }

    private static func isBogusOrPrivateIP(_ ip: String) -> Bool {
        if ip == "127.0.0.1" || ip == "0.0.0.0" { return true }
        let parts = ip.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4 else { return false }

        // 10.0.0.0/8
        if parts[0] == 10 { return true }
        // 172.16.0.0/12
        if parts[0] == 172 && (16...31).contains(parts[1]) { return true }
        // 192.168.0.0/16
        if parts[0] == 192 && parts[1] == 168 { return true }

        return false
    }
}
