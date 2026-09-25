> 이 문서는 [English](../BUILDING.md) 버전의 한국어 번역입니다.

# 소스에서 빌드하기

## 사전 요구 사항

### 필수

- **Rust** 1.70+ ([rustup](https://rustup.rs/)으로 설치)
- **pkg-config**
- **OpenSSL 개발 헤더** (reqwest/TLS용)

### 선택 사항

- **Node.js** 18+ 및 **npm** (GUI용)
- **Tauri CLI** (`cargo install tauri-cli`) (GUI용)

### 플랫폼별 요구 사항

**Debian/Ubuntu:**
```bash
sudo apt install -y build-essential pkg-config libssl-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install -y gcc pkg-config openssl-devel
```

**macOS:**
```bash
xcode-select --install
brew install pkg-config openssl
```

**Windows:**
- [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) 설치
- [vcpkg](https://github.com/microsoft/vcpkg) 설치 후 실행: `vcpkg install openssl`

## CLI 빌드

```bash
git clone https://github.com/openprx/prx-sd.git
cd prx-sd

# 디버그 빌드
cargo build

# 릴리스 빌드 (최적화)
cargo build --release

# 바이너리 위치:
#   디버그:  target/debug/sd
#   릴리스: target/release/sd
```

### 기능 플래그

```bash
# ONNX ML 모델 지원 포함 빌드
cargo build --release --features onnx

# WASM 플러그인 지원 제외 빌드 (더 작은 바이너리)
cargo build --release --no-default-features
```

| 기능 | 기본값 | 설명 |
|------|--------|------|
| `wasm-runtime` | 예 | WebAssembly 플러그인 지원 (Wasmtime) |
| `onnx` | 아니오 | ONNX ML 모델 추론 (tract-onnx) |

## GUI 빌드

데스크톱 GUI는 Tauri 2 (Rust) + Vue 3 (TypeScript)을 사용합니다.

```bash
# 프론트엔드 의존성 설치
cd gui
npm install

# 개발 모드 (핫 리로드)
npm run tauri dev

# 프로덕션 빌드
npm run tauri build
```

빌드된 애플리케이션은 `gui/src-tauri/target/release/bundle/`에 생성됩니다.

## 업데이트 서버 빌드

```bash
cargo build --release --manifest-path update-server/Cargo.toml
```

## 테스트 실행

```bash
# 전체 테스트 실행
cargo test

# 특정 크레이트 테스트 실행
cargo test -p prx-sd-core
cargo test -p prx-sd-signatures

# 통합 테스트 실행
cargo test --test '*'
```

## 코드 품질

```bash
# 컴파일 오류 확인 (빠름, 링킹 없음)
cargo check

# 자동 수정 적용
cargo fix --allow-dirty

# 코드 포맷팅
cargo fmt

# 린트
cargo clippy -- -D warnings
```

## 크로스 컴파일

프로젝트에는 `.cargo/config.toml`에 크로스 컴파일 설정이 포함되어 있습니다.

### Linux ARM64 (aarch64)

```bash
# 타겟 설치
rustup target add aarch64-unknown-linux-gnu

# 크로스 컴파일 툴체인 설치
sudo apt install -y gcc-aarch64-linux-gnu

# 빌드
cargo build --release --target aarch64-unknown-linux-gnu
```

### macOS (Linux에서)

Linux에서 macOS로 크로스 컴파일하려면 [osxcross](https://github.com/tpoechtrager/osxcross)가 필요합니다.

### Windows (Linux에서)

```bash
# 타겟 설치
rustup target add x86_64-pc-windows-gnu

# 크로스 컴파일 툴체인 설치
sudo apt install -y gcc-mingw-w64-x86-64

# 빌드
cargo build --release --target x86_64-pc-windows-gnu
```

## 패키징

사전 제작된 패키징 스크립트는 `tools/`에 있습니다:

```bash
# Debian 패키지 (.deb)
./tools/build-deb.sh

# macOS 디스크 이미지 (.dmg)
./tools/build-dmg.sh

# Windows 설치 프로그램 (.msi)
./tools/build-msi.sh

# Linux AppImage
./tools/build-appimage.sh
```

플랫폼별 패키징 설정은 `packaging/`에 있습니다:

```
packaging/
├── appimage/       # Linux AppImage
├── completions/    # 셸 자동완성 (bash, zsh, fish)
├── desktop/        # .desktop 파일
├── filemanager/    # 파일 관리자 통합 스크립트
├── homebrew/       # Homebrew formula
├── launchd/        # macOS launch agent plist
├── systemd/        # Linux systemd 서비스 유닛
├── udev/           # Linux udev 규칙 (USB 자동 스캔)
└── windows/        # WiX MSI 설치 프로그램 설정
```

## 프로젝트 구조

```
prx-sd/
├── Cargo.toml          # 워크스페이스 루트
├── Cargo.lock          # 의존성 잠금 파일
├── crates/
│   ├── cli/            # sd 바이너리
│   ├── core/           # 스캔 엔진
│   ├── signatures/     # 서명 데이터베이스
│   ├── parsers/        # 바이너리 포맷 파서
│   ├── heuristic/      # 휴리스틱 + ML 탐지
│   ├── realtime/       # 실시간 모니터링
│   ├── quarantine/     # 격리 저장소
│   ├── remediation/    # 위협 대응
│   ├── sandbox/        # 프로세스 샌드박싱
│   ├── plugins/        # WASM 플러그인 시스템
│   └── updater/        # 업데이트 클라이언트
├── update-server/      # 서명 배포 서버
├── gui/                # Tauri + Vue 3 데스크톱 앱
├── drivers/            # OS 커널 드라이버
├── signatures-db/      # 내장 서명
├── tests/              # 통합 테스트
├── tools/              # 빌드 스크립트
└── packaging/          # 배포 패키징
```
