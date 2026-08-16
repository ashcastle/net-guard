# 🛡️ NetGuard

<p align="left">
  <a href="README.md">🌐 <b>English</b></a> |
  <a href="README-KR.md">🇰🇷 <b>한국어</b></a>
</p>

**NetGuard**는 macOS 환경에 최적화된 초경량 오픈소스 네트워크 보안 데몬 및 CLI 도구입니다. Swift 네이티브 프레임워크를 기반으로 작성되어, Wi-Fi나 유선 네트워크에 연결되는 즉시 자동으로 보안 상태를 진단하고 패킷 감청(Sniffing), 중간자 공격(MITM), ARP 스푸핑, DNS 하이재킹 등으로부터 사용자를 실시간으로 보호합니다.

---

## 🌟 주요 기능

- **📶 Wi-Fi 보안 수준 정밀 진단 (`CoreWLAN`)**: 암호화되지 않은 오픈 Wi-Fi, 취약한 WEP, WPA2/WPA3 보안 설정을 네이티브 API로 즉시 감지합니다.
- **⚡ ARP 스푸핑 및 게이트웨이 무결성 감시**: 로컬 서브넷의 ARP 캐시를 상시 감시하여 게이트웨이 MAC 주소 위변조 및 패킷 가로채기 공격을 탐지합니다.
- **🔒 DNS 위변조 및 하이재킹 방어**: 신뢰할 수 있는 DoH(DNS-over-HTTPS, Cloudflare/Google) 질의 결과와 로컬 DNS 응답을 실시간 대조하여 파밍 및 악성 리다이렉션을 탐지합니다.
- **🔑 SSL/TLS 가로채기(MITM) 감지**: `Security.SecTrust`를 통해 주요 호스트의 인증서 체인을 검증하고 사설/가짜 루트 CA에 의한 패킷 복호화 가로채기를 탐지합니다.
- **🚪 Captive Portal 자동 감지**: 공공장소 로그인 인증 페이지 및 트래픽 가로채기를 사전에 감지합니다.
- **🖥️ macOS 상단 메뉴바(헤더바) 앱**: 상단 메뉴바에서 실시간 보안 상태(🛡️🟢 안전 / 🛡️🚨 위협)를 한눈에 확인하고 마우스로 원클릭 제어할 수 있습니다.
- **⚙️ 백그라운드 데몬 On / Off 제어 (`launchd`)**: 터미널을 열어두지 않아도 `netguard daemon on/off` 명령이나 `brew services`로 간편하게 24시간 상시 감시를 관리합니다.
- **🚀 위협 감지 시 자동 보호 조치**:
  - macOS 네이티브 데스크톱 알림 발송
  - 안전한 DoH / 보안 DNS(`1.1.1.1`, `8.8.8.8`) 자동 전환
  - 사용자 지정 VPN 자동 연결 훅 실행 (WireGuard, Tailscale, Cloudflare WARP, OpenVPN 등)

---

## 📦 Homebrew 설치 가이드

### 방법 1: Homebrew Tap으로 설치 (권장)

```bash
# 1. 저장소 Tap 추가
brew tap ashcastle/net-guard https://github.com/ashcastle/net-guard

# 2. NetGuard 설치
brew install net-guard

# (선택 사항) 맥 로그인 시 항상 백그라운드에서 자동 실행
brew services start net-guard
```

### 방법 2: Formula URL로 직접 설치

Tap 추가 없이 직접 설치할 수도 있습니다:

```bash
brew install https://raw.githubusercontent.com/ashcastle/net-guard/main/formula/net-guard.rb
```

### 방법 3: Swift 소스 빌드 직접 설치

```bash
git clone https://github.com/ashcastle/net-guard.git
cd net-guard

# 릴리즈 바이너리 빌드
swift build -c release

# PATH에 복사
sudo cp .build/release/netguard /usr/local/bin/
```

---

## 🚀 빠른 시작 및 사용법

### 1. 즉시 네트워크 보안 진단
현재 연결된 네트워크의 보안 상태를 즉각 진단합니다:
```bash
netguard scan
```

JSON 형식으로 출력 (스크립트 및 자동화 연동 시):
```bash
netguard scan --json
```

### 2. macOS 상단 메뉴바(헤더바) 모니터링 실행
맥 상단 메뉴바에 상태 표시 아이콘을 띄워 마우스로 편리하게 조작합니다:
```bash
netguard menu
```
- **실시간 아이콘**: `🛡️🟢 Safe(안전)` | `🛡️🚨 위협 등급` | `🛡️📡 검사 중`
- **메뉴 항목**: 즉시 재검사, 백그라운드 데몬 On/Off 토글, Secure DNS 토글, 설정 디렉토리 바로가기

### 3. 백그라운드 데몬 On / Off (`launchd`)
터미널을 닫아도 상시 감시하도록 데몬을 켜고 끕니다:
```bash
# 데몬 켜기 (macOS LaunchAgent 등록 및 백그라운드 실행)
netguard daemon on

# 데몬 동작 상태 확인
netguard daemon status

# 데몬 끄기 (LaunchAgent 해제 및 서비스 중지)
netguard daemon off
```

### 4. 포그라운드 실시간 모니터링
터미널에서 네트워크 전환 이벤트를 실시간으로 확인합니다:
```bash
netguard watch
```

### 5. 현재 네트워크 및 보호 설정 요약
```bash
netguard status
```

### 6. 환경설정 관리
설정 확인 및 커스텀 옵션을 설정합니다 (`~/.config/netguard/config.json`):
```bash
# 현재 설정 확인
netguard config

# 위험 네트워크 감지 시 자동 실행할 VPN 커맨드 설정
netguard config --set-vpn "tailscale up --exit-node=my-secure-node"

# 신뢰하는 집/사무실 Wi-Fi를 화이트리스트에 추가
netguard config --add-trusted-ssid "MyHomeSecureWiFi"

# 설정을 기본값으로 초기화
netguard config --reset
```

---

## ⚙️ 설정 파일 예시 (`~/.config/netguard/config.json`)

```json
{
  "action": {
    "auto_secure_dns": false,
    "auto_vpn_command": "",
    "enable_notification": true,
    "secure_dns_addresses": [
      "1.1.1.1",
      "1.0.0.1",
      "8.8.8.8"
    ]
  },
  "detection": {
    "check_arp_spoof": true,
    "check_captive": true,
    "check_dns_hijack": true,
    "check_ssl_mitm": true,
    "check_wifi_security": true,
    "doh_servers": [
      "https://cloudflare-dns.com/dns-query",
      "https://dns.google/dns-query"
    ],
    "test_domains": [
      "google.com",
      "cloudflare.com",
      "apple.com",
      "github.com"
    ]
  },
  "trust": {
    "trusted_bssids": [],
    "trusted_ssids": []
  }
}
```

---

## 🛠️ 네이티브 아키텍처

NetGuard는 macOS 공식 네이티브 시스템 프레임워크를 기반으로 구축되었습니다:
- **`CoreWLAN`**: 외부 셸 명령 없이 Wi-Fi 인터페이스 및 암호화 방식을 직접 쿼리
- **`Network (NWPathMonitor)`**: 시스템 리소스를 최소화하며 네트워크 전환 이벤트를 비동기로 실시간 감지
- **`Security`**: `SecTrust`를 통한 네이티브 TLS 인증서 체인 무결성 평가
- **`AppKit`**: `NSStatusItem` 기반의 macOS 상단 메뉴바 통합
- **`swift-argument-parser`**: Apple 공식 CLI 서브커맨드 프레임워크

---

## 📄 라이선스 (License)

이 프로젝트는 [MIT License](LICENSE)에 따라 자유롭게 사용할 수 있는 오픈소스 소프트웨어입니다.
