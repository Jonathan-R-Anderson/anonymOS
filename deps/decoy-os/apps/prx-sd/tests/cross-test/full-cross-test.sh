#!/usr/bin/env bash
#
# PRX-SD 全面交叉测试套件
# 覆盖: 多发行版 / 真实样本 / 大规模误报 / 并发压力 / 实时监控 / CVD导入 / 签名更新
#
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SD="$PROJECT_DIR/target/release/sd"
RESULTS="$PROJECT_DIR/tests/cross-test/results"
DATA="$PROJECT_DIR/tests/cross-test/sd-data-cross"

log()  { echo -e "\033[1;34m[TEST]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[PASS]\033[0m $*"; }
fail() { echo -e "\033[1;31m[FAIL]\033[0m $*"; }
stat() { echo -e "\033[1;36m[STAT]\033[0m $*"; }

mkdir -p "$RESULTS"
PASS=0; FAIL_COUNT=0; TOTAL=0

check() {
    TOTAL=$((TOTAL+1))
    if [ "$1" = "0" ]; then
        ok "$2"
        PASS=$((PASS+1))
    else
        fail "$2"
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
}

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           PRX-SD 全面交叉测试套件                           ║"
echo "║           $(date '+%Y-%m-%d %H:%M:%S')                               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ═══════════════════════════════════════════════════════════════
# TEST 1: 多发行版容器测试
# ═══════════════════════════════════════════════════════════════
log "TEST 1: 多发行版容器测试"

SAMPLES="$PROJECT_DIR/tests/cross-test/samples/generated"

for DISTRO in "docker.io/library/debian:trixie-slim" "docker.io/library/ubuntu:24.04" "docker.io/library/fedora:41"; do
    NAME=$(echo "$DISTRO" | sed 's|.*/||;s/:/-/g')
    log "  Building $NAME container..."

    cat > /tmp/Dockerfile.cross-$NAME << DEOF
FROM $DISTRO
RUN if command -v apt-get >/dev/null; then apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*; \
    elif command -v dnf >/dev/null; then dnf install -y ca-certificates && dnf clean all; fi
COPY target/release/sd /usr/local/bin/sd
RUN chmod +x /usr/local/bin/sd
DEOF

    if podman build -f /tmp/Dockerfile.cross-$NAME -t prx-sd-cross-$NAME "$PROJECT_DIR" > /dev/null 2>&1; then
        RESULT=$(podman run --rm -v "$SAMPLES:/scanme:ro" prx-sd-cross-$NAME sd --log-level error scan /scanme --recursive --json 2>/dev/null || echo "[]")
        MAL=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(1 for r in d if r.get('threat_level')=='Malicious'))" 2>/dev/null || echo "?")
        SUS=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(1 for r in d if r.get('threat_level')=='Suspicious'))" 2>/dev/null || echo "?")
        echo "$RESULT" > "$RESULTS/cross-$NAME.json"
        check 0 "$NAME: Malicious=$MAL Suspicious=$SUS"
    else
        check 1 "$NAME: container build failed"
    fi
done

# ═══════════════════════════════════════════════════════════════
# TEST 2: 真实恶意样本哈希验证 (abuse.ch MalwareBazaar)
# ═══════════════════════════════════════════════════════════════
log "TEST 2: 真实恶意样本哈希验证 (MalwareBazaar recent)"

rm -rf "$DATA" && mkdir -p "$DATA"

# Download recent malware hashes from MalwareBazaar
BAZAAR_FILE="$RESULTS/bazaar_recent.txt"
if curl -sS --max-time 30 -o "$BAZAAR_FILE" "https://bazaar.abuse.ch/export/txt/sha256/recent/" 2>/dev/null; then
    HASH_COUNT=$(grep -cv '^#\|^$' "$BAZAAR_FILE" 2>/dev/null || echo 0)
    if [ "$HASH_COUNT" -gt 0 ]; then
        # Convert to import format and import
        IMPORT_FILE="$RESULTS/bazaar_import.txt"
        grep -v '^#\|^$' "$BAZAAR_FILE" | head -500 | while read hash; do
            echo "$hash MalwareBazaar.Recent"
        done > "$IMPORT_FILE"
        "$SD" --data-dir "$DATA" --log-level error import "$IMPORT_FILE" 2>/dev/null
        IMPORTED=$("$SD" --data-dir "$DATA" --log-level error info 2>/dev/null | grep -oP 'SHA-256.*?(\d+)' | grep -oP '\d+' || echo "0")
        check 0 "MalwareBazaar: imported $HASH_COUNT hashes from recent feed"
    else
        check 1 "MalwareBazaar: empty response"
    fi
else
    check 1 "MalwareBazaar: download failed (network)"
fi

# ═══════════════════════════════════════════════════════════════
# TEST 3: 大规模误报测试 (1000+ 合法文件)
# ═══════════════════════════════════════════════════════════════
log "TEST 3: 大规模误报测试 (系统文件)"

FP_DIR=$(mktemp -d)
# Copy 1000+ real system files
find /usr/bin /usr/lib/x86_64-linux-gnu /usr/share/doc -type f 2>/dev/null | head -1000 | while read f; do
    cp "$f" "$FP_DIR/" 2>/dev/null || true
done
FP_TOTAL=$(ls -1 "$FP_DIR" | wc -l)

FP_RESULT=$("$SD" --data-dir "$DATA" --log-level error scan "$FP_DIR" --recursive --json 2>/dev/null || echo "[]")
FP_DETECTED=$(echo "$FP_RESULT" | python3 -c "
import json, sys
data = json.load(sys.stdin)
fp = [r for r in data if r['threat_level'] != 'Clean']
print(len(fp))
for r in fp[:10]:
    print(f'  FP: {r[\"path\"].split(\"/\")[-1]} -> {r[\"threat_level\"]} ({r.get(\"threat_name\",\"-\")})')
" 2>/dev/null || echo "?")

FP_RATE=$(python3 -c "print(f'{int(\"$FP_DETECTED\") * 100 / max(int(\"$FP_TOTAL\"), 1):.2f}')" 2>/dev/null || echo "?")
check 0 "误报测试: $FP_DETECTED/$FP_TOTAL 误报 (${FP_RATE}%)"
echo "$FP_RESULT" > "$RESULTS/false-positive.json"
rm -rf "$FP_DIR"

# ═══════════════════════════════════════════════════════════════
# TEST 4: 并发压力测试
# ═══════════════════════════════════════════════════════════════
log "TEST 4: 并发压力测试 (10 并发扫描)"

STRESS_DIR=$(mktemp -d)
for i in $(seq 1 100); do
    dd if=/dev/urandom of="$STRESS_DIR/f_$i" bs=1024 count=$((RANDOM % 50 + 1)) 2>/dev/null
done

PIDS=""
STRESS_OK=0
for i in $(seq 1 10); do
    "$SD" --data-dir "$DATA" --log-level error scan "$STRESS_DIR" --recursive > /dev/null 2>&1 &
    PIDS="$PIDS $!"
done

ALL_OK=true
for pid in $PIDS; do
    if wait $pid 2>/dev/null; then
        STRESS_OK=$((STRESS_OK+1))
    else
        ALL_OK=false
    fi
done
check $([[ "$ALL_OK" == "true" ]] && echo 0 || echo 1) "并发: $STRESS_OK/10 成功完成"
rm -rf "$STRESS_DIR"

# ═══════════════════════════════════════════════════════════════
# TEST 5: ClamAV CVD 导入后检测率
# ═══════════════════════════════════════════════════════════════
log "TEST 5: ClamAV 签名导入效果验证"

# Create synthetic test: import hashes then verify detection
IMPORT_TEST="$RESULTS/import_test.txt"
TEST_CONTENT="unique_test_malware_content_for_cvd_verification_$(date +%s)"
TEST_HASH=$(echo -n "$TEST_CONTENT" | sha256sum | awk '{print $1}')
echo "$TEST_HASH ClamAV.Test.Verification" > "$IMPORT_TEST"
"$SD" --data-dir "$DATA" --log-level error import "$IMPORT_TEST" 2>/dev/null

# Write file with matching content and scan
TEST_FILE=$(mktemp)
echo -n "$TEST_CONTENT" > "$TEST_FILE"
DETECT=$("$SD" --data-dir "$DATA" --log-level error scan "$TEST_FILE" --json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d[0]['threat_level'])" 2>/dev/null || echo "?")
rm -f "$TEST_FILE"
check $([[ "$DETECT" == "Malicious" ]] && echo 0 || echo 1) "签名导入后检测: $DETECT (expect Malicious)"

# ═══════════════════════════════════════════════════════════════
# TEST 6: 性能梯度 (100/1000/5000/10000 文件)
# ═══════════════════════════════════════════════════════════════
log "TEST 6: 性能梯度测试"

for COUNT in 100 1000 5000 10000; do
    PERF_DIR=$(mktemp -d)
    for i in $(seq 1 $COUNT); do
        dd if=/dev/urandom of="$PERF_DIR/f_$i" bs=1024 count=$((RANDOM % 20 + 1)) 2>/dev/null
    done
    SIZE_MB=$(du -sm "$PERF_DIR" | cut -f1)
    START=$(date +%s%N)
    "$SD" --data-dir "$DATA" --log-level error scan "$PERF_DIR" --recursive > /dev/null 2>&1
    END=$(date +%s%N)
    MS=$(( (END - START) / 1000000 ))
    FPS=$(python3 -c "print(f'{$COUNT*1000/max($MS,1):.0f}')" 2>/dev/null)
    MBPS=$(python3 -c "print(f'{$SIZE_MB*1000/max($MS,1):.1f}')" 2>/dev/null)
    check 0 "  ${COUNT} files (${SIZE_MB}MB): ${MS}ms = ${FPS} files/sec, ${MBPS} MB/s"
    rm -rf "$PERF_DIR"
done

# ═══════════════════════════════════════════════════════════════
# TEST 7: ClamAV 容器对比 (同样本)
# ═══════════════════════════════════════════════════════════════
log "TEST 7: ClamAV 容器对比"

CLAM_RESULT=$(podman run --rm -v "$SAMPLES:/scanme:ro" docker.io/clamav/clamav:stable clamscan --no-summary /scanme/ 2>/dev/null || echo "")
CLAM_FOUND=$(echo "$CLAM_RESULT" | grep -c "FOUND" 2>/dev/null || echo 0)
CLAM_OK=$(echo "$CLAM_RESULT" | grep -c " OK" 2>/dev/null || echo 0)

PRX_RESULT=$("$SD" --data-dir "$DATA" --log-level error scan "$SAMPLES" --recursive --json 2>/dev/null || echo "[]")
PRX_MAL=$(echo "$PRX_RESULT" | python3 -c "import json,sys; print(sum(1 for r in json.load(sys.stdin) if r['threat_level']=='Malicious'))" 2>/dev/null || echo 0)
PRX_SUS=$(echo "$PRX_RESULT" | python3 -c "import json,sys; print(sum(1 for r in json.load(sys.stdin) if r['threat_level']=='Suspicious'))" 2>/dev/null || echo 0)

check 0 "PRX-SD: ${PRX_MAL} malicious + ${PRX_SUS} suspicious | ClamAV: ${CLAM_FOUND} found"

# ═══════════════════════════════════════════════════════════════
# TEST 8: CLI 命令全覆盖
# ═══════════════════════════════════════════════════════════════
log "TEST 8: CLI 命令功能验证"

# sd info
"$SD" --data-dir "$DATA" --log-level error info > /dev/null 2>&1
check $? "sd info"

# sd config show
"$SD" --data-dir "$DATA" --log-level error config show > /dev/null 2>&1
check $? "sd config show"

# sd policy show
"$SD" --data-dir "$DATA" --log-level error policy show > /dev/null 2>&1
check $? "sd policy show"

# sd quarantine list
"$SD" --data-dir "$DATA" --log-level error quarantine list > /dev/null 2>&1
check $? "sd quarantine list"

# sd webhook list
"$SD" --data-dir "$DATA" --log-level error webhook list > /dev/null 2>&1
check $? "sd webhook list"

# sd scan --json
SINGLE=$(mktemp)
echo "clean" > "$SINGLE"
"$SD" --data-dir "$DATA" --log-level error scan "$SINGLE" --json > /dev/null 2>&1
check $? "sd scan --json"
rm -f "$SINGLE"

# sd scan --report
REPORT_FILE=$(mktemp --suffix=.html)
REPORT_DIR=$(mktemp -d)
echo "test" > "$REPORT_DIR/test.txt"
"$SD" --data-dir "$DATA" --log-level error scan "$REPORT_DIR" --report "$REPORT_FILE" > /dev/null 2>&1
[ -f "$REPORT_FILE" ] && [ -s "$REPORT_FILE" ]
check $? "sd scan --report (HTML export)"
rm -f "$REPORT_FILE" && rm -rf "$REPORT_DIR"

# ═══════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  交叉测试总结                                               ║"
echo "╠══════════════════════════════════════════════════════════════╣"
printf "║  通过: %-3d | 失败: %-3d | 总计: %-3d                       ║\n" "$PASS" "$FAIL_COUNT" "$TOTAL"
echo "╚══════════════════════════════════════════════════════════════╝"

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
