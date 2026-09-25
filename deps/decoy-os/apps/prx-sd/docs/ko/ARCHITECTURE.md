> 이 문서는 [English](../ARCHITECTURE.md) 버전의 한국어 번역입니다.

# 아키텍처

PRX-SD는 Cargo 워크스페이스로 구성되며, 각 크레이트가 특정 도메인을 담당하는 모듈형 구조입니다.

## 워크스페이스 구조

```
prx-sd/
├── crates/
│   ├── cli/           # "sd" 바이너리 — 커맨드라인 인터페이스
│   ├── core/          # 스캔 엔진 조율
│   ├── signatures/    # 해시 DB (LMDB) + YARA-X 규칙 엔진
│   ├── parsers/       # 바이너리 포맷 파서
│   ├── heuristic/     # 휴리스틱 스코어링 + ML 추론
│   ├── realtime/      # 파일 시스템 모니터링 + 네트워크 필터링
│   ├── quarantine/    # 암호화된 격리 저장소
│   ├── remediation/   # 위협 대응 조치
│   ├── sandbox/       # 프로세스 격리 + 행위 분석
│   ├── plugins/       # WebAssembly 플러그인 런타임
│   └── updater/       # 서명 업데이트 클라이언트
├── update-server/     # 서명 배포 서버 (Axum)
├── gui/               # 데스크톱 GUI (Tauri 2 + Vue 3)
├── drivers/           # OS 커널 드라이버
│   └── windows-minifilter/  # Windows 파일 시스템 미니필터 (C)
├── signatures-db/     # 내장 최소 서명
├── packaging/         # 배포 패키징
├── tests/             # 통합 테스트
├── tools/             # 빌드 및 유틸리티 스크립트
├── install.sh         # 설치 스크립트
└── uninstall.sh       # 제거 스크립트
```

## 크레이트 의존성 그래프

```
cli
 ├── core
 │    ├── signatures
 │    │    └── (heed, yara-x, sha2, md5)
 │    ├── parsers
 │    │    └── (goblin)
 │    └── heuristic
 │         └── (tract-onnx [optional])
 ├── realtime
 │    ├── core
 │    └── (notify, nix [linux], adblock)
 ├── quarantine
 │    └── (aes-gcm, rand)
 ├── remediation
 │    ├── quarantine
 │    └── (nix [unix])
 ├── sandbox
 │    └── (nix [unix])
 ├── plugins
 │    └── (wasmtime, wasmtime-wasi)
 └── updater
      └── (ed25519-dalek, zstd, reqwest)
```

## 탐지 파이프라인

스캔 엔진(`core`)은 다계층 탐지 파이프라인을 조율합니다:

```
                    ┌──────────────┐
                    │  파일 입력   │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  매직 넘버   │  식별: PE, ELF, MachO,
                    │    탐지      │  PDF, ZIP, Office, unknown
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐    │     ┌──────▼──────┐
       │    해시      │    │     │   YARA-X    │
       │    매칭      │    │     │    규칙     │
       │   (LMDB)    │    │     │   (38K+)    │
       └──────┬──────┘    │     └──────┬──────┘
              │     ┌─────▼─────┐      │
              │     │ 휴리스틱  │      │
              │     │   분석    │      │
              │     └─────┬─────┘      │
              │           │            │
              │    ┌──────▼──────┐     │
              │    │  ML 추론   │     │
              │    │   (ONNX)   │     │
              │    └──────┬─────┘     │
              │           │            │
              │    ┌──────▼──────┐     │
              │    │ VirusTotal  │     │
              │    │ 클라우드    │     │
              │    │   쿼리     │     │
              │    └──────┬─────┘     │
              │           │            │
              └───────────┼────────────┘
                          │
                   ┌──────▼──────┐
                   │   종합 판정  │
                   └─────────────┘
                   Clean / Suspicious / Malicious
```

### 계층 상세

1. **해시 매칭** -- ClamAV, abuse.ch, VirusShare 및 사용자 정의 차단 목록의 SHA-256과 MD5 해시가 저장된 LMDB 데이터베이스에 대한 O(1) 조회.

2. **YARA-X 규칙** -- YARA-X 엔진(Rust 네이티브 YARA 구현)을 사용한 패턴 매칭. 내장 기본 규칙과 외부 서명 저장소에서 규칙을 로드합니다.

3. **휴리스틱 분석** -- 파일 유형별 분석:
   - **PE:** 섹션 엔트로피, 의심스러운 API 임포트 (CreateRemoteThread, VirtualAllocEx), 패커 탐지 (UPX, Themida), 타임스탬프 이상 징후
   - **ELF:** 섹션 엔트로피, LD_PRELOAD 참조, cron/systemd 지속성, SSH 백도어 패턴
   - **MachO:** 섹션 엔트로피, dylib 인젝션, LaunchAgent 지속성, Keychain 접근

4. **ML 추론** (선택 사항, 기능 플래그 `onnx`) -- tract를 통한 ONNX 모델 평가:
   - PE: 64차원 특성 벡터 (임포트 테이블 해시, 섹션 엔트로피, API 시그니처)
   - ELF: 48차원 특성 벡터 (섹션 엔트로피, 심볼 테이블, 동적 라이브러리)

5. **VirusTotal 클라우드** -- 로컬에서 매칭되지 않은 파일에 대한 폴백. VirusTotal API를 쿼리합니다 (무료 등급: 일일 500건). 결과는 LMDB에 캐싱됩니다.

### 점수 체계

- 점수 >= 60: **Malicious** (악성)
- 점수 30-59: **Suspicious** (의심)
- 점수 < 30: **Clean** (정상)

최종 판정은 모든 탐지 계층에서 가장 높은 위협 수준을 기준으로 합니다.

## 실시간 보호

`realtime` 크레이트는 여러 하위 시스템을 통해 지속적인 보호를 제공합니다:

| 하위 시스템 | Linux | macOS | Windows |
|-------------|-------|-------|---------|
| 파일 모니터링 | fanotify + epoll | FSEvents (notify) | ReadDirectoryChangesW (notify) |
| 프로세스 차단 | FAN_OPEN_EXEC_PERM | - | Minifilter (계획 중) |
| 메모리 스캔 | /proc/pid/mem | - | - |
| 랜섬웨어 탐지 | 쓰기+이름변경 패턴 모니터링 | 쓰기+이름변경 패턴 모니터링 | 쓰기+이름변경 패턴 모니터링 |
| 보호 디렉터리 | ~/.ssh, /etc/shadow, /etc/systemd | ~/Library, /etc | Registry Run keys |
| DNS 필터링 | Adblock 엔진 + IOC 목록 | Adblock 엔진 + IOC 목록 | Adblock 엔진 + IOC 목록 |
| 행위 모니터링 | /proc + audit (execve/connect/open) | - | - |

## 격리 저장소

파일은 AES-256-GCM 인증 암호화를 사용하여 격리됩니다:

1. 임의의 256비트 키 + 96비트 논스 생성
2. AES-256-GCM으로 파일 내용 암호화
3. UUID 파일명으로 암호화된 파일 저장
4. JSON 메타데이터 저장 (원본 경로, 해시, 위협 이름, 타임스탬프)
5. 복원 시 무결성을 검증한 후 복호화하여 원래 위치에 기록

## 대응 파이프라인

`--remediate` 사용 시:

```
위협 탐지됨
  ├── 1. 프로세스 종료  (Linux/macOS에서 SIGKILL, Windows에서 TerminateProcess)
  ├── 2. 파일 격리      (AES-256-GCM 암호화 저장소)
  └── 3. 지속성 제거
        ├── Linux:   cron 작업, systemd 서비스, LD_PRELOAD
        ├── macOS:   LaunchAgents, plist 항목, Keychain
        └── Windows: Run/RunOnce 레지스트리, 예약된 작업, 서비스
```

조치는 `sd policy set`을 통해 설정할 수 있습니다.

## 서명 데이터베이스

### 내장 서명 (`signatures-db/`)

`include_str!`를 통해 `sd` 바이너리에 컴파일되는 최소 서명 세트:
- EICAR 테스트 서명
- 핵심 YARA 규칙 (랜섬웨어, 트로이 목마, 백도어 등)
- 알려진 악성코드 해시 (WannaCry, Emotet, NotPetya)

### 외부 서명 ([prx-sd-signatures](https://github.com/openprx/prx-sd-signatures))

포괄적이고 자주 업데이트되는 위협 인텔리전스:
- 9개 출처의 38,800+ YARA 규칙
- abuse.ch 피드의 해시 차단 목록
- IOC 목록: 585K+ 악성 IP, 도메인, URL

### 저장소

- **해시:** O(1) 키-값 조회를 위한 LMDB (heed 크레이트)
- **YARA 규칙:** 시작 시 YARA-X에 의해 로드 및 컴파일
- **IOC 목록:** 빠른 IP/도메인/URL 매칭을 위한 인메모리 HashSet

## 플러그인 시스템

PRX-SD는 Wasmtime을 통한 WebAssembly 플러그인을 지원합니다:

- 플러그인은 매니페스트(`plugin.json`)를 포함한 `.wasm` 파일입니다
- 파일 시스템 및 환경 접근을 위한 WASI 지원
- 탐색 및 로딩을 위한 플러그인 레지스트리
- 스캔 결과 및 설정을 위해 플러그인에 노출되는 호스트 함수

## 업데이트 시스템

`updater` 크레이트와 `update-server`는 안전한 업데이트 파이프라인을 제공합니다:

1. 클라이언트가 업데이트 서버에 새 서명 버전을 확인
2. 서버가 버전 정보와 다운로드 URL로 응답
3. 클라이언트가 zstd 압축된 서명 패키지를 다운로드
4. Ed25519 (ed25519-dalek)로 패키지 서명 검증
5. 서명을 추출하여 LMDB에 로드

## GUI 애플리케이션

Tauri 2 (Rust 백엔드) + Vue 3 (TypeScript 프론트엔드)로 구축:

- 상태 표시기가 포함된 시스템 트레이 통합
- 위협 통계가 포함된 대시보드
- 드래그 앤 드롭 파일 스캔
- 복원/삭제가 가능한 격리 브라우저
- 실시간 모니터링 제어
- 설정 및 구성
- 다국어 지원 (10개 언어)

## 주요 의존성

| 카테고리 | 크레이트 | 버전 | 용도 |
|----------|----------|------|------|
| 비동기 | tokio | 1.x | 비동기 런타임 |
| 병렬 처리 | rayon | - | 스캔용 스레드 풀 |
| YARA | yara-x | 1.14 | 규칙 매칭 엔진 |
| 데이터베이스 | heed | - | LMDB 바인딩 |
| 바이너리 파싱 | goblin | 0.9 | PE/ELF/MachO 파서 |
| 암호화 | aes-gcm | - | 격리 암호화 |
| 암호화 | ed25519-dalek | - | 업데이트 검증 |
| ML | tract-onnx | - | ONNX 추론 (선택 사항) |
| WASM | wasmtime | 29 | 플러그인 런타임 |
| DNS | adblock | 0.12 | Brave adblock 엔진 |
| CLI | clap | 4.x | 인자 파싱 |
| HTTP | axum | 0.8 | 업데이트 서버 |
