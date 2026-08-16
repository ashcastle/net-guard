class NetGuard < Formula
  desc "Automated macOS Network Security & Eavesdropping Prevention Tool"
  homepage "https://github.com/ashcastle/net-guard"
  url "https://github.com/ashcastle/net-guard/archive/refs/tags/v1.0.2.tar.gz"
  sha256 "64ef6d660a4fa06fca7343ee3a20b3bcc189ca00a13b2fabdc2f518e1c7d67e2"
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
