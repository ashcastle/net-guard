import Foundation
import Network

public final class NetworkMonitor {
    private let monitor: NWPathMonitor
    private let queue: DispatchQueue
    private var lastInterface: String?
    private var lastSSID: String?
    private let onChange: (NetworkInfo) -> Void

    public init(onChange: @escaping (NetworkInfo) -> Void) {
        self.monitor = NWPathMonitor()
        self.queue = DispatchQueue(label: "com.netguard.networkmonitor", qos: .utility)
        self.onChange = onChange
    }

    public func start() {
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }

            guard path.status == .satisfied else {
                print("[EVENT] Network disconnected / offline.")
                self.lastInterface = nil
                self.lastSSID = nil
                return
            }

            // Collect active network info
            let info = WifiDetector.collectNetworkInfo()

            // Check if network session changed (SSID or Interface or Gateway changed)
            if self.hasNetworkChanged(current: info) {
                print("[EVENT] Network change detected: Interface=\(info.interfaceName), SSID=\(info.ssid ?? "N/A"), Gateway=\(info.gatewayIP ?? "N/A")")
                self.lastInterface = info.interfaceName
                self.lastSSID = info.ssid
                self.onChange(info)
            }
        }

        monitor.start(queue: queue)
        print("[INFO] NetGuard NetworkMonitor (NWPathMonitor) active.")
    }

    public func stop() {
        monitor.cancel()
    }

    private func hasNetworkChanged(current: NetworkInfo) -> Bool {
        guard let prevIface = lastInterface else { return true }
        if prevIface != current.interfaceName { return true }
        if lastSSID != current.ssid { return true }
        return false
    }
}
