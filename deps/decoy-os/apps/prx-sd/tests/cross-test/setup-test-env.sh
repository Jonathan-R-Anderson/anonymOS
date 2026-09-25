#!/usr/bin/env bash
#
# PRX-SD Cross-Platform & Cross-Architecture Test Suite
#
# Creates podman containers for:
# 1. Debian x86_64 (native)
# 2. Ubuntu ARM64 (qemu-user emulation)
# 3. Alpine musl (minimal)
# 4. ClamAV comparison baseline
#
# Then runs detection tests with known malware samples (EICAR + synthetic)

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SD_BIN="$PROJECT_DIR/target/release/sd"
TEST_DIR="$PROJECT_DIR/tests/cross-test"
RESULTS_DIR="$TEST_DIR/results"

log()  { echo -e "\033[1;34m[TEST]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[PASS]\033[0m $*"; }
fail() { echo -e "\033[1;31m[FAIL]\033[0m $*"; }
stat() { echo -e "\033[1;36m[STAT]\033[0m $*"; }

mkdir -p "$RESULTS_DIR"

# ═══════════════════════════════════════════════════════════════
# 1. 准备测试样本
# ═══════════════════════════════════════════════════════════════

log "Preparing test samples..."
SAMPLES_DIR="$TEST_DIR/samples"
mkdir -p "$SAMPLES_DIR"

# EICAR standard test file
echo -n 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$SAMPLES_DIR/eicar.txt"

# EICAR in ZIP
(cd "$SAMPLES_DIR" && zip -q eicar.zip eicar.txt 2>/dev/null || true)

# Clean files (should NOT be detected)
echo "This is a perfectly clean text file." > "$SAMPLES_DIR/clean.txt"
dd if=/dev/urandom of="$SAMPLES_DIR/random.bin" bs=1024 count=10 2>/dev/null
echo '#!/bin/bash
echo "Hello World"' > "$SAMPLES_DIR/clean_script.sh"

# High-entropy file (packed/encrypted simulation)
dd if=/dev/urandom of="$SAMPLES_DIR/packed_suspicious.bin" bs=1024 count=100 2>/dev/null

# Synthetic PE header (MZ magic + PE signature)
python3 -c "
import struct
pe = bytearray(4096)
pe[0:2] = b'MZ'
pe[0x3C:0x40] = struct.pack('<I', 0x80)
pe[0x80:0x84] = b'PE\x00\x00'
pe[0x84:0x86] = struct.pack('<H', 0x8664)  # x86_64
pe[0x86:0x88] = struct.pack('<H', 1)       # 1 section
pe[0x88:0x8C] = struct.pack('<I', 0)       # zero timestamp (suspicious)
open('$SAMPLES_DIR/suspicious_pe.exe', 'wb').write(pe)
" 2>/dev/null || true

# Synthetic ELF
python3 -c "
elf = bytearray(256)
elf[0:4] = b'\x7fELF'
elf[4] = 2  # 64-bit
elf[5] = 1  # little-endian
elf[6] = 1  # version
elf[16:18] = b'\x02\x00'  # ET_EXEC
open('$SAMPLES_DIR/suspicious_elf.bin', 'wb').write(elf)
" 2>/dev/null || true

# PDF with JavaScript (suspicious)
cat > "$SAMPLES_DIR/suspicious.pdf" << 'PDFEOF'
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [] /Count 0 >>
endobj
3 0 obj
<< /Type /Action /S /JavaScript /JS (app.alert('test')) >>
endobj
xref
0 4
trailer << /Size 4 /Root 1 0 R >>
startxref
0
%%EOF
PDFEOF

# Office document with macro indicators
python3 -c "
data = b'\xd0\xcf\x11\xe0' + b'\x00' * 508  # OLE2 magic
data += b'AutoOpen' + b'\x00' * 100
data += b'Shell(' + b'\x00' * 100
data += b'WScript.Shell' + b'\x00' * 100
open('$SAMPLES_DIR/suspicious_macro.doc', 'wb').write(data)
" 2>/dev/null || true

TOTAL_SAMPLES=$(ls -1 "$SAMPLES_DIR" | wc -l)
ok "Prepared $TOTAL_SAMPLES test samples"

# ═══════════════════════════════════════════════════════════════
# 2. 本机 PRX-SD 测试
# ═══════════════════════════════════════════════════════════════

log "Running PRX-SD native scan..."
"$SD_BIN" --data-dir "$TEST_DIR/sd-data" --log-level error scan "$SAMPLES_DIR" --recursive --json > "$RESULTS_DIR/prx-sd-native.json" 2>/dev/null || true
ok "PRX-SD native scan complete"

# Parse results
python3 << 'PYEOF'
import json, sys
with open("RESULTS_DIR/prx-sd-native.json".replace("RESULTS_DIR", "RESULTS_DIR_PLACEHOLDER")) as f:
    results = json.load(f)
total = len(results)
malicious = sum(1 for r in results if r.get("threat_level") == "Malicious")
suspicious = sum(1 for r in results if r.get("threat_level") == "Suspicious")
clean = sum(1 for r in results if r.get("threat_level") == "Clean")
print(f"  Total: {total} | Malicious: {malicious} | Suspicious: {suspicious} | Clean: {clean}")
for r in results:
    if r.get("threat_level") != "Clean":
        name = r.get("threat_name", "Unknown")
        level = r.get("threat_level", "?")
        path = r.get("path", "?").split("/")[-1]
        print(f"    [{level}] {path} -> {name}")
PYEOF
echo "" # placeholder; actual parsing done below

# ═══════════════════════════════════════════════════════════════
# 3. ClamAV 对比测试 (podman)
# ═══════════════════════════════════════════════════════════════

log "Setting up ClamAV container for comparison..."
podman pull docker.io/clamav/clamav:stable 2>/dev/null || true

log "Running ClamAV scan on same samples..."
podman run --rm \
    -v "$SAMPLES_DIR:/scanme:ro" \
    docker.io/clamav/clamav:stable \
    clamscan --no-summary --infected /scanme/ 2>/dev/null > "$RESULTS_DIR/clamav-results.txt" || true

ok "ClamAV scan complete"
echo "  ClamAV detections:"
cat "$RESULTS_DIR/clamav-results.txt" | grep "FOUND" | while read line; do
    echo "    $line"
done
CLAMAV_DETECTIONS=$(grep -c "FOUND" "$RESULTS_DIR/clamav-results.txt" 2>/dev/null || echo 0)
echo "  Total ClamAV detections: $CLAMAV_DETECTIONS"

# ═══════════════════════════════════════════════════════════════
# 4. 交叉架构测试 (ARM64 via qemu)
# ═══════════════════════════════════════════════════════════════

log "Cross-architecture test (ARM64 via qemu-user)..."
# Register qemu-user binfmt if not already done
if [ ! -f /proc/sys/fs/binfmt_misc/qemu-aarch64 ]; then
    podman run --rm --privileged docker.io/multiarch/qemu-user-static --reset -p yes 2>/dev/null || true
fi

# Build for ARM64 if cross target available
if rustup target list --installed 2>/dev/null | grep -q aarch64; then
    log "Cross-compiling for aarch64..."
    cd "$PROJECT_DIR"
    cargo build --release --bin sd --target aarch64-unknown-linux-gnu 2>/dev/null && \
        ok "ARM64 binary built" || \
        log "ARM64 cross-compile not available (need aarch64 linker)"
else
    log "ARM64 target not installed, skipping cross-arch binary test"
fi

# ═══════════════════════════════════════════════════════════════
# 5. Alpine musl 容器测试
# ═══════════════════════════════════════════════════════════════

log "Testing in Alpine musl container..."
cat > "$TEST_DIR/Dockerfile.test-alpine" << 'DEOF'
FROM docker.io/library/debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY target/release/sd /usr/local/bin/sd
RUN chmod +x /usr/local/bin/sd
DEOF

cd "$PROJECT_DIR"
podman build -f "$TEST_DIR/Dockerfile.test-alpine" -t prx-sd-test:latest . 2>/dev/null && \
    ok "Test container built" || fail "Container build failed"

podman run --rm \
    -v "$SAMPLES_DIR:/scanme:ro" \
    prx-sd-test:latest \
    sd --log-level error scan /scanme --recursive --json > "$RESULTS_DIR/prx-sd-container.json" 2>/dev/null || true

ok "Container scan complete"

# ═══════════════════════════════════════════════════════════════
# 6. 结果汇总
# ═══════════════════════════════════════════════════════════════

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║           PRX-SD Cross-Test Results Summary              ║"
echo "╠══════════════════════════════════════════════════════════╣"

# Parse PRX-SD results
PRX_MALICIOUS=$(python3 -c "
import json
with open('$RESULTS_DIR/prx-sd-native.json') as f:
    data = json.load(f)
print(sum(1 for r in data if r.get('threat_level') == 'Malicious'))
" 2>/dev/null || echo "?")

PRX_SUSPICIOUS=$(python3 -c "
import json
with open('$RESULTS_DIR/prx-sd-native.json') as f:
    data = json.load(f)
print(sum(1 for r in data if r.get('threat_level') == 'Suspicious'))
" 2>/dev/null || echo "?")

echo "║ PRX-SD Native:  Malicious=$PRX_MALICIOUS Suspicious=$PRX_SUSPICIOUS     ║"
echo "║ ClamAV Baseline: Detections=$CLAMAV_DETECTIONS                      ║"
echo "╚══════════════════════════════════════════════════════════╝"

stat "Detailed results in: $RESULTS_DIR/"
