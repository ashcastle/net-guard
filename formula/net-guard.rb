class NetGuard < Formula
  desc "Automated macOS Network Security & Eavesdropping Prevention Tool"
  homepage "https://github.com/ashcastle/net-guard"
  url "https://github.com/ashcastle/net-guard/archive/refs/tags/v1.0.3.tar.gz"
  sha256 "373d1eac1a1d22f4b9f65dce0b31c8307bf0786ede2b0042d5f49436444f847d"
  license "MIT"
  head "https://github.com/ashcastle/net-guard.git", branch: "main"

  depends_on :macos
  depends_on xcode: ["14.0", :build]

  def install
    system "swift", "build", "-c", "release", "--disable-sandbox"
    bin.install ".build/release/netguard"
    bin.install_symlink bin/"netguard" => "net-guard"
    bin.install_symlink bin/"netguard" => "netg"
  end

  service do
    run [opt_bin/"netguard", "daemon", "run"]
    keep_alive true
    log_path var/"log/netguard.log"
    error_log_path var/"log/netguard.err.log"
  end

  test do
    system "#{bin}/netguard", "--version"
    system "#{bin}/net-guard", "--version"
    system "#{bin}/netg", "--version"
  end
end
