> 이 문서는 [English](../CLI.md) 버전의 한국어 번역입니다.

# CLI 참조 문서

PRX-SD는 위협 탐지 및 시스템 보호를 위한 `sd` 커맨드라인 도구를 제공합니다.

## 전역 옵션

| 플래그 | 설명 | 기본값 |
|--------|------|--------|
| `--log-level <LEVEL>` | 로그 상세 수준: `trace`, `debug`, `info`, `warn`, `error` | `warn` |
| `--data-dir <PATH>` | 서명, 격리, 설정을 위한 데이터 디렉터리 | `~/.prx-sd/` |

---

## 스캔

### `sd scan <PATH>`

파일 또는 디렉터리에서 위협을 스캔합니다.

```bash
sd scan /path/to/file
sd scan /home --recursive
sd scan /tmp --auto-quarantine --remediate
sd scan /path --json
sd scan /path --report report.html
```

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `-r, --recursive <BOOL>` | 하위 디렉터리 재귀 탐색 | 디렉터리의 경우 `true` |
| `--json` | 결과를 JSON으로 출력 | |
| `-t, --threads <NUM>` | 스캐너 스레드 수 | CPU 코어 수 |
| `--auto-quarantine` | 악성 파일을 자동으로 격리 | |
| `--remediate` | 자동 조치: 프로세스 종료, 격리, 지속성 메커니즘 제거 | |
| `-e, --exclude <PATTERN>` | 제외할 glob 패턴 (반복 사용 가능) | |
| `--report <PATH>` | 결과를 독립형 HTML 보고서로 내보내기 | |

### `sd scan-memory`

실행 중인 프로세스 메모리에서 위협을 스캔합니다 (Linux 전용, root 권한 필요).

```bash
sudo sd scan-memory
sudo sd scan-memory --pid 1234
sudo sd scan-memory --json
```

| 옵션 | 설명 |
|------|------|
| `--pid <PID>` | 특정 프로세스를 스캔 (생략 시 전체 프로세스 스캔) |
| `--json` | JSON으로 출력 |

### `sd scan-usb [DEVICE]`

USB/이동식 장치를 스캔합니다.

```bash
sd scan-usb
sd scan-usb /dev/sdb1 --auto-quarantine
```

| 옵션 | 설명 |
|------|------|
| `--auto-quarantine` | 탐지된 위협을 자동으로 격리 |

### `sd check-rootkit`

루트킷 징후를 확인합니다 (Linux 전용).

```bash
sudo sd check-rootkit
sudo sd check-rootkit --json
```

확인 항목: 숨겨진 프로세스, 커널 모듈 무결성, LD_PRELOAD 후킹, /proc 이상 징후.

---

## 실시간 보호

### `sd monitor <PATHS...>`

실시간 파일 시스템 모니터링.

```bash
sd monitor /home /tmp
sd monitor /home --block
sd monitor /home --daemon
```

| 옵션 | 설명 |
|------|------|
| `--block` | 악성 파일의 접근을 사전 차단 (Linux에서 root + fanotify 필요) |
| `--daemon` | 백그라운드 데몬으로 실행 |

### `sd daemon [PATHS...]`

실시간 모니터링 및 자동 업데이트를 포함한 백그라운드 데몬으로 실행합니다.

```bash
sd daemon
sd daemon /home /tmp --update-hours 2
```

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `--update-hours <NUM>` | 서명 업데이트 확인 간격 (시간 단위) | `4` |

기본 모니터링 경로: `/home`, `/tmp`.

---

## 격리 관리

### `sd quarantine <SUBCOMMAND>`

암호화된 격리 저장소를 관리합니다 (AES-256-GCM).

```bash
sd quarantine list
sd quarantine restore <ID>
sd quarantine restore <ID> --to /safe/path
sd quarantine delete <ID>
sd quarantine delete-all --yes
sd quarantine stats
```

| 하위 명령 | 설명 |
|-----------|------|
| `list` | 격리된 모든 파일 목록 표시 |
| `restore <ID>` | 격리된 파일 복원 (`--to <PATH>`로 대체 경로 지정 가능) |
| `delete <ID>` | 격리된 파일을 영구 삭제 |
| `delete-all` | 격리된 모든 파일 삭제 (`--yes`로 확인 과정 생략) |
| `stats` | 격리 통계 표시 |

---

## 서명 데이터베이스

### `sd update`

서명 데이터베이스 업데이트를 확인하고 적용합니다.

```bash
sd update
sd update --check-only
sd update --force
sd update --server-url https://custom-server.example.com
```

| 옵션 | 설명 |
|------|------|
| `--check-only` | 업데이트 가용 여부만 확인 |
| `--force` | 이미 최신 상태인 경우에도 강제 재다운로드 |
| `--server-url <URL>` | 업데이트 서버 URL 재지정 |

### `sd import <PATH>`

차단 목록 파일에서 해시 서명을 가져옵니다.

```bash
sd import /path/to/blocklist.txt
```

파일 형식: 한 줄에 하나의 항목으로 `hex_hash malware_name` 형식입니다. `#`으로 시작하는 줄은 주석입니다.

```
# Example blocklist
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f EICAR.Test
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa Ransom.WannaCry
```

### `sd import-clamav <PATHS...>`

ClamAV 서명 데이터베이스 파일을 가져옵니다.

```bash
sd import-clamav main.cvd daily.cvd
sd import-clamav custom.hdb custom.hsb
```

지원 형식: `.cvd`, `.cld`, `.hdb`, `.hsb`.

### `sd info`

엔진 버전, 서명 데이터베이스 상태 및 시스템 정보를 표시합니다.

```bash
sd info
```

표시 항목: 버전, YARA 규칙 수, 해시 서명 수, 격리 통계, 플랫폼 정보.

---

## 설정

### `sd config <SUBCOMMAND>`

엔진 설정을 관리합니다.

```bash
sd config show
sd config set scan.max_file_size 104857600
sd config set scan.follow_symlinks true
sd config reset
```

| 하위 명령 | 설명 |
|-----------|------|
| `show` | 현재 설정 표시 |
| `set <KEY> <VALUE>` | 설정 키 변경 (점으로 구분된 경로) |
| `reset` | 기본 설정으로 초기화 |

값은 JSON 타입을 지원합니다: boolean (`true`/`false`), 숫자, `null`, 배열, 객체.

---

## 대응 정책

### `sd policy <ACTION> [KEY] [VALUE]`

위협 대응 정책을 관리합니다.

```bash
sd policy show
sd policy set on_malicious "kill,quarantine,clean"
sd policy set on_suspicious "report,quarantine"
sd policy set kill_processes true
sd policy reset
```

| 동작 | 설명 |
|------|------|
| `show` | 현재 정책 표시 |
| `set <KEY> <VALUE>` | 정책 필드 설정 |
| `reset` | 기본 정책으로 초기화 |

**정책 키:**

| 키 | 설명 | 값 |
|----|------|-----|
| `on_malicious` | 악성 위협에 대한 조치 | 쉼표로 구분: `report`, `quarantine`, `block`, `kill`, `clean`, `delete`, `isolate`, `blocklist` |
| `on_suspicious` | 의심스러운 위협에 대한 조치 | 위와 동일 |
| `kill_processes` | 관련 프로세스 종료 | `true` / `false` |
| `clean_persistence` | 지속성 메커니즘 제거 | `true` / `false` |
| `network_isolation` | 네트워크 연결 격리 | `true` / `false` |
| `audit_logging` | 모든 조치를 감사 추적에 기록 | `true` / `false` |

---

## 스케줄링

### `sd schedule <SUBCOMMAND>`

예약 스캔을 관리합니다. 플랫폼 네이티브 스케줄러를 사용합니다: systemd timers (Linux), cron (Linux/macOS), launchd (macOS), Task Scheduler (Windows).

```bash
sd schedule add /home --frequency daily
sd schedule add /tmp --frequency hourly
sd schedule status
sd schedule remove
```

| 하위 명령 | 설명 |
|-----------|------|
| `add <PATH>` | 반복 예약 스캔 등록 |
| `remove` | 예약 스캔 제거 |
| `status` | 현재 스케줄 상태 표시 |

**주기:** `hourly`, `4h`, `12h`, `daily`, `weekly` (기본값: `weekly`).

---

## 알림

### `sd webhook <SUBCOMMAND>`

웹훅 알림 엔드포인트를 관리합니다.

```bash
sd webhook list
sd webhook add my-slack https://hooks.slack.com/services/... --format slack
sd webhook add my-discord https://discord.com/api/webhooks/... --format discord
sd webhook add custom https://example.com/alert --format generic
sd webhook remove my-slack
sd webhook test
```

| 하위 명령 | 설명 |
|-----------|------|
| `list` | 설정된 웹훅 목록 표시 |
| `add <NAME> <URL>` | 웹훅 추가 (`--format`: `slack`, `discord`, `generic`) |
| `remove <NAME>` | 이름으로 웹훅 제거 |
| `test` | 모든 웹훅에 테스트 알림 전송 |

### `sd email-alert <SUBCOMMAND>`

이메일 알림 설정을 관리합니다.

```bash
sd email-alert configure
sd email-alert test
sd email-alert send "Trojan.Generic" "high" "/tmp/malware.exe"
```

| 하위 명령 | 설명 |
|-----------|------|
| `configure` | SMTP 이메일 설정 생성 또는 표시 |
| `test` | 테스트 알림 이메일 전송 |
| `send <NAME> <LEVEL> <PATH>` | 사용자 정의 알림 이메일 전송 |

---

## DNS 및 네트워크 필터링

### `sd adblock <SUBCOMMAND>`

광고 차단 및 악성 도메인 필터링을 관리합니다.

```bash
sd adblock enable
sd adblock disable
sd adblock sync
sd adblock stats
sd adblock check https://suspicious-site.example.com
sd adblock log --count 100
sd adblock add custom-list https://example.com/blocklist.txt --category malware
sd adblock remove custom-list
```

| 하위 명령 | 설명 |
|-----------|------|
| `enable` | 차단 목록을 다운로드하고 DNS 차단 설치 (`/etc/hosts`) |
| `disable` | DNS 차단 항목 제거 |
| `sync` | 모든 필터 목록 강제 재다운로드 |
| `stats` | 필터링 통계 표시 |
| `check <URL>` | URL/도메인의 차단 여부 확인 |
| `log` | 최근 차단 항목 표시 (`-c, --count <NUM>`, 기본값: 50) |
| `add <NAME> <URL>` | 사용자 정의 필터 목록 추가 (`--category`: `ads`, `tracking`, `malware`, `social`) |
| `remove <NAME>` | 필터 목록 제거 |

### `sd dns-proxy`

adblock, IOC 및 사용자 정의 차단 목록 필터링을 포함한 로컬 DNS 프록시를 시작합니다.

```bash
sudo sd dns-proxy
sudo sd dns-proxy --listen 127.0.0.1:5353 --upstream 1.1.1.1:53
```

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `--listen <ADDR>` | 수신 주소 | `127.0.0.1:53` |
| `--upstream <ADDR>` | 상위 DNS 서버 | `8.8.8.8:53` |
| `--log-path <PATH>` | JSONL 쿼리 로그 경로 | `/tmp/prx-sd-dns.log` |

---

## 보고서

### `sd report <OUTPUT>`

JSON 스캔 결과로부터 독립형 HTML 보고서를 생성합니다.

```bash
sd scan /path --json | sd report report.html
sd report report.html --input results.json
```

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `--input <FILE>` | 입력 JSON 파일 (`-`는 표준 입력) | `-` (표준 입력) |

### `sd status`

PID, 가동 시간, 서명 버전, 차단된 위협 수 등 데몬 상태를 표시합니다.

```bash
sd status
```

---

## 통합

### `sd install-integration`

파일 관리자 우클릭 스캔 통합을 설치합니다.

```bash
sd install-integration
```

지원되는 파일 관리자:
- **Linux:** Nautilus (GNOME Files), Dolphin (KDE), Nemo (Cinnamon)
- **macOS:** Finder Quick Action

### `sd self-update`

GitHub Releases에서 바이너리 업데이트를 확인하고 적용합니다.

```bash
sd self-update
sd self-update --check-only
```

| 옵션 | 설명 |
|------|------|
| `--check-only` | 업데이트 가용 여부만 확인 |

---

## 사용 예시

### 초기 설정

```bash
# 설치
curl -fsSL https://raw.githubusercontent.com/openprx/prx-sd/main/install.sh | bash

# 추가 서명 가져오기
sd import my-custom-hashes.txt
sd import-clamav main.cvd daily.cvd

# 설정 확인
sd info
```

### 일상 보호

```bash
# 데몬 시작 (/home과 /tmp 모니터링, 4시간마다 업데이트)
sd daemon

# 또는 수동 스캔
sd scan /home --recursive --auto-quarantine

# 상태 확인
sd status
```

### 사고 대응

```bash
# 전체 조치를 포함한 스캔
sudo sd scan /tmp --auto-quarantine --remediate

# 메모리 내 위협 확인
sudo sd scan-memory

# 루트킷 확인
sudo sd check-rootkit

# 격리 항목 검토
sd quarantine list
sd quarantine restore <ID> --to /safe/location
```

### 자동화

```bash
# 주간 스캔 예약
sd schedule add /home --frequency weekly

# 알림 설정
sd webhook add slack https://hooks.slack.com/services/T.../B.../xxx --format slack
sd email-alert configure

# 스크립트용 JSON 출력
sd scan /path --json | jq '.threats[] | .name'
```
