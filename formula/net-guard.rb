class NetGuard < Formula
  desc "Automated macOS Network Security & Eavesdropping Prevention Tool"
  homepage "https://github.com/ashcastle/net-guard"
  url "https://github.com/ashcastle/net-guard/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "eb7a66634b523681baf9f442134f8ca4be810d9531c94eb6341c9313450a815f"
  license "MIT"
  head "https://github.com/ashcastle/net-guard.git", branch: "main"

  depends_on :macos
  depends_on xcode: ["14.0", :build]

  def install
    system "swift", "build", "-c", "release", "--disable-sandbox"
    bin.install ".build/release/netguard"
  end

  service do
    run [opt_bin/"netguard", "daemon", "run"]
    keep_alive true
    log_path var/"log/netguard.log"
    error_log_path var/"log/netguard.err.log"
  end

  test do
    system "#{bin}/netguard", "--version"
  end
end
