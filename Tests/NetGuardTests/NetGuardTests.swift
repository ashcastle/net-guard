import XCTest
@testable import NetGuard

final class NetGuardTests: XCTestCase {
    func testDefaultConfig() {
        let config = NetGuardConfig.default
        XCTAssertTrue(config.detection.checkWifiSecurity)
        XCTAssertTrue(config.detection.checkArpSpoof)
        XCTAssertTrue(config.detection.checkDnsHijack)
        XCTAssertTrue(config.detection.checkSslMitm)
        XCTAssertTrue(config.action.enableNotification)
    }

    func testSeverityComparison() {
        XCTAssertTrue(Severity.safe < Severity.low)
        XCTAssertTrue(Severity.low < Severity.medium)
        XCTAssertTrue(Severity.medium < Severity.high)
        XCTAssertTrue(Severity.high < Severity.critical)
    }

    func testWifiSecurityAuditOpenNetwork() {
        var info = NetworkInfo()
        info.isWireless = true
        info.ssid = "Public_Free_WiFi"
        info.securityType = "Open (None)"

        let finding = WifiDetector.auditWifiSecurity(info: info)
        XCTAssertFalse(finding.passed)
        XCTAssertEqual(finding.severity, .critical)
    }

    func testWifiSecurityAuditWpa3Network() {
        var info = NetworkInfo()
        info.isWireless = true
        info.ssid = "Secure_Home_WiFi"
        info.securityType = "WPA3 Personal (SAE)"

        let finding = WifiDetector.auditWifiSecurity(info: info)
        XCTAssertTrue(finding.passed)
        XCTAssertEqual(finding.severity, .safe)
    }
}
