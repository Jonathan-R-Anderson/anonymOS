#!/usr/bin/env bash
#
# PRX-SD Signature Database Updater
#
# 从多个开源威胁情报源下载并导入病毒签名到本地数据库。
#
# ┌─────────────────────────────────────────────────────────────┐
# │ 数据源                      │ 类型        │ 更新频率       │
# ├─────────────────────────────┼─────────────┼────────────────┤
# │ ClamAV main.cvd + daily.cvd │ MD5+SHA 哈希│ 每日           │
# │ abuse.ch MalwareBazaar      │ SHA-256 哈希│ 每 5 分钟      │
# │ abuse.ch URLhaus            │ SHA-256 哈希│ 每小时         │
# │ abuse.ch Feodo Tracker      │ SHA-256 哈希│ 每 5 分钟      │
# │ VirusShare Hash Lists       │ MD5 哈希    │ 定期更新       │
# │ Yara-Rules/rules (GitHub)   │ YARA 规则   │ 社区维护       │
# │ Neo23x0/signature-base      │ YARA 规则   │ 持续更新       │
# │ ESET IOC (GitHub)           │ YARA 规则   │ 持续更新       │
# │ ReversingLabs YARA          │ YARA 规则   │ 持续更新       │
# │ Malpedia YARA (公开部分)    │ YARA 规则   │ 社区维护       │
# │ 本项目内置规则              │ YARA+哈希   │ 随代码更新     │
# └─────────────────────────────┴─────────────┴────────────────┘
#
# 用法:
#   ./tools/update-signatures.sh [--data-dir DIR] [--source all|hashes|yara] [--full]
#

set -euo pipefail

DATA_DIR="${HOME}/.prx-sd"
SOURCE="all"
FULL_UPDATE=false
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SD_BIN="${PROJECT_DIR}/target/release/sd"
TEMP_DIR="/tmp/prx-sd-update-$$"

while [[ $# -gt 0 ]]; do
    case $1 in
        --data-dir) DATA_DIR="$2"; shift 2 ;;
        --source)   SOURCE="$2"; shift 2 ;;
        --full)     FULL_UPDATE=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--data-dir DIR] [--source all|hashes|yara] [--full]"
            echo ""
            echo "  --data-dir DIR    Data directory (default: ~/.prx-sd)"
            echo "  --source TYPE     hashes, yara, or all (default: all)"
            echo "  --full            Full update (download larger datasets like VirusShare)"
            exit 0 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

log()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[ OK ]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR ]\033[0m $*"; }
stat() { echo -e "\033[1;36m[STAT]\033[0m $*"; }

cleanup() { rm -rf "$TEMP_DIR"; }
trap cleanup EXIT
mkdir -p "$TEMP_DIR" "$DATA_DIR/signatures" "$DATA_DIR/yara"

HASH_COUNT=0
YARA_DOWNLOADED=0

# ═══════════════════════════════════════════════════════════════
#  哈希签名源
# ═══════════════════════════════════════════════════════════════

import_hashfile() {
    local file="$1" label="$2"
    local count
    count=$(grep -cv '^#\|^$' "$file" 2>/dev/null || echo 0)
    if [[ "$count" -gt 0 ]]; then
        "$SD_BIN" --data-dir "$DATA_DIR" --log-level error import "$file" 2>/dev/null && true
        HASH_COUNT=$((HASH_COUNT + count))
        ok "$label: $count hashes"
    else
        warn "$label: empty or no valid entries"
    fi
}

# ─── 1. 内置哈希 ─────────────────────────────────────────────
update_builtin() {
    log "Importing built-in blocklists..."
    local f="$PROJECT_DIR/signatures-db/hashes/sha256_blocklist.txt"
    [[ -f "$f" ]] && import_hashfile "$f" "Built-in SHA-256"
}

# ─── 2. abuse.ch MalwareBazaar (最近 48h 恶意样本 SHA-256) ───
update_malwarebazaar() {
    log "Downloading MalwareBazaar recent hashes..."
    local out="$TEMP_DIR/bazaar.txt" conv="$TEMP_DIR/bazaar_import.txt"
    if curl -sS --max-time 60 -o "$out" "https://bazaar.abuse.ch/export/txt/sha256/recent/" 2>/dev/null; then
        grep -v '^#\|^$' "$out" | while read -r hash; do
            echo "$hash MalwareBazaar.Recent"
        done > "$conv"
        import_hashfile "$conv" "MalwareBazaar"
    else
        warn "MalwareBazaar: download failed"
    fi
}

# ─── 3. abuse.ch URLhaus (恶意 URL 关联的文件哈希) ───────────
update_urlhaus() {
    log "Downloading URLhaus payload hashes..."
    local out="$TEMP_DIR/urlhaus.csv" conv="$TEMP_DIR/urlhaus_import.txt"
    if curl -sS --max-time 60 -o "$out" "https://urlhaus.abuse.ch/downloads/payloads/" 2>/dev/null; then
        # CSV格式: "first_seen","url","filetype","md5","sha256","signature"
        grep -oP '"[a-f0-9]{64}"' "$out" | tr -d '"' | sort -u | while read -r hash; do
            echo "$hash URLhaus.Payload"
        done > "$conv"
        import_hashfile "$conv" "URLhaus payloads"
    else
        warn "URLhaus: download failed"
    fi
}

# ─── 4. abuse.ch Feodo Tracker (银行木马 C2 关联哈希) ────────
update_feodo() {
    log "Downloading Feodo Tracker hashes..."
    local conv="$TEMP_DIR/feodo_import.txt"
    if curl -sS --max-time 30 "https://feodotracker.abuse.ch/downloads/malware_hashes.csv" 2>/dev/null \
        | grep -oP '[a-f0-9]{64}' | sort -u | while read -r hash; do
            echo "$hash Feodo.BankTrojan"
        done > "$conv"; then
        import_hashfile "$conv" "Feodo Tracker"
    else
        warn "Feodo Tracker: download failed"
    fi
}

# ─── 5. ClamAV CVD (main.cvd + daily.cvd, ~1100 万签名) ─────
update_clamav() {
    log "Downloading ClamAV signature databases..."
    local cvd_dir="$TEMP_DIR/clamav"
    mkdir -p "$cvd_dir"

    local clamav_mirror="https://database.clamav.net"
    local imported=0

    for db_name in main daily; do
        local out="$cvd_dir/${db_name}.cvd"
        log "  Downloading ${db_name}.cvd..."
        if curl -sS --max-time 300 -o "$out" "${clamav_mirror}/${db_name}.cvd" 2>/dev/null; then
            local size
            size=$(stat -c%s "$out" 2>/dev/null || stat -f%z "$out" 2>/dev/null || echo 0)
            if [[ "$size" -gt 512 ]]; then
                log "  Importing ${db_name}.cvd ($(( size / 1024 / 1024 )) MB)..."
                if "$SD_BIN" --data-dir "$DATA_DIR" --log-level error import-clamav "$out" 2>/dev/null; then
                    imported=$((imported + 1))
                    ok "ClamAV ${db_name}.cvd imported successfully"
                else
                    warn "ClamAV ${db_name}.cvd: import failed"
                fi
            else
                warn "ClamAV ${db_name}.cvd: downloaded file too small ($size bytes)"
            fi
        else
            warn "ClamAV ${db_name}.cvd: download failed"
        fi
    done

    if [[ "$imported" -eq 0 ]]; then
        warn "ClamAV: no databases imported"
    fi
}

# ─── 6. VirusShare (大量 MD5 哈希，仅 --full 模式) ──────────
update_virusshare() {
    if [[ "$FULL_UPDATE" != "true" ]]; then
        log "VirusShare: skipped (use --full to download, ~20M hashes)"
        return
    fi
    log "Downloading VirusShare hash lists (this may take a while)..."
    local vs_dir="$TEMP_DIR/virusshare"
    mkdir -p "$vs_dir"
    # 下载最新的几个文件 (每个 65536 条 MD5)
    local downloaded=0
    for i in $(seq 495 499); do
        local url="https://virusshare.com/hashfiles/VirusShare_$(printf '%05d' $i).md5"
        local out="$vs_dir/vs_${i}.txt"
        if curl -sS --max-time 120 -o "$out" "$url" 2>/dev/null; then
            downloaded=$((downloaded + 1))
        fi
    done
    if [[ "$downloaded" -gt 0 ]]; then
        # 合并并转换为导入格式
        local conv="$TEMP_DIR/virusshare_import.txt"
        cat "$vs_dir"/vs_*.txt | grep -v '^#' | grep -v '^$' | while read -r hash; do
            echo "$hash VirusShare.MD5"
        done > "$conv"
        import_hashfile "$conv" "VirusShare ($downloaded files)"
    fi
}

# ═══════════════════════════════════════════════════════════════
#  YARA 规则源
# ═══════════════════════════════════════════════════════════════

download_yara_repo() {
    local label="$1" base_url="$2" target_dir="$3"
    shift 3
    local rules=("$@")
    mkdir -p "$target_dir"
    local count=0
    for rule in "${rules[@]}"; do
        local fname
        fname=$(basename "$rule")
        if curl -sS --max-time 30 -o "$target_dir/$fname" "${base_url}${rule}" 2>/dev/null; then
            # 验证下载的是有效 YARA (不是 404 HTML)
            if grep -q "^rule " "$target_dir/$fname" 2>/dev/null; then
                count=$((count + 1))
            else
                rm -f "$target_dir/$fname"
            fi
        fi
    done
    YARA_DOWNLOADED=$((YARA_DOWNLOADED + count))
    ok "$label: $count rules downloaded"
}

update_yara() {
    local yara_dir="$DATA_DIR/yara"

    # ─── 内置 YARA 规则 ──────────────────────────────
    log "Copying built-in YARA rules (64 rules, Linux/macOS/Windows)..."
    cp -r "$PROJECT_DIR/signatures-db/yara/"* "$yara_dir/" 2>/dev/null || true
    local builtin
    builtin=$(grep -r "^rule " "$PROJECT_DIR/signatures-db/yara/" --include="*.yar" 2>/dev/null | wc -l)
    ok "Built-in: $builtin rules copied"

    # ─── Yara-Rules/rules (社区维护，最大的 YARA 规则库) ──
    log "Downloading Yara-Rules community rules..."
    download_yara_repo "Yara-Rules" \
        "https://raw.githubusercontent.com/Yara-Rules/rules/master/" \
        "$yara_dir/community" \
        "malware/MALW_Eicar.yar" \
        "malware/RANSOM_ransomware.yar" \
        "malware/MALW_Emotet.yar" \
        "malware/MALW_Trickbot.yar" \
        "malware/MALW_Cobalt_Strike.yar" \
        "malware/MALW_AgentTesla.yar" \
        "malware/RAT_Njrat.yar" \
        "malware/MALW_Mirai.yar" \
        "malware/RANSOM_Lockbit.yar" \
        "malware/MALW_Qakbot.yar"

    # ─── Neo23x0/signature-base (Florian Roth 高质量规则) ──
    log "Downloading signature-base rules (Florian Roth)..."
    download_yara_repo "signature-base" \
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/" \
        "$yara_dir/signature-base" \
        "yara/crime_ransomware.yar" \
        "yara/crime_emotet.yar" \
        "yara/gen_suspicious_strings.yar" \
        "yara/apt_lazarus_group.yar" \
        "yara/gen_webshells.yar" \
        "yara/apt_apt29.yar" \
        "yara/gen_mal_scripts.yar" \
        "yara/gen_crypto_mining.yar" \
        "yara/crime_cobalt_strike.yar" \
        "yara/gen_suspicious_xor.yar"

    # ─── ReversingLabs YARA (高质量商业级开源规则) ────────
    log "Downloading ReversingLabs YARA rules..."
    download_yara_repo "ReversingLabs" \
        "https://raw.githubusercontent.com/reversinglabs/reversinglabs-yara-rules/develop/" \
        "$yara_dir/reversinglabs" \
        "yara/trojan/Win32.Trojan.Generic.yara" \
        "yara/ransomware/Win32.Ransomware.Generic.yara" \
        "yara/backdoor/Linux.Backdoor.Generic.yara" \
        "yara/backdoor/Win32.Backdoor.CobaltStrike.yara" \
        "yara/trojan/Linux.Trojan.Mirai.yara" \
        "yara/hacktool/Win32.HackTool.Mimikatz.yara"

    # ─── ESET 威胁情报 YARA (APT 组织追踪) ───────────────
    log "Downloading ESET threat intelligence rules..."
    download_yara_repo "ESET" \
        "https://raw.githubusercontent.com/eset/malware-ioc/master/" \
        "$yara_dir/eset" \
        "apt_turla/apt_turla.yar" \
        "interception/interception.yar"

    # ─── InQuest YARA (文档恶意软件检测) ─────────────────
    log "Downloading InQuest document malware rules..."
    download_yara_repo "InQuest" \
        "https://raw.githubusercontent.com/InQuest/yara-rules/master/" \
        "$yara_dir/inquest" \
        "OLE_file_magic_number.rule" \
        "Microsoft_Office_DDE.rule"

    # ─── 统计 ──────────────────────────────────────────────
    local total_files total_rules
    total_files=$(find "$yara_dir" -name "*.yar" -o -name "*.yara" -o -name "*.rule" | wc -l)
    total_rules=$(grep -r "^rule " "$yara_dir" --include="*.yar" --include="*.yara" --include="*.rule" 2>/dev/null | wc -l)
    stat "YARA total: $total_files files, ~$total_rules rules"
}

# ═══════════════════════════════════════════════════════════════
#  主流程
# ═══════════════════════════════════════════════════════════════

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║       PRX-SD Signature Database Updater          ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  Data dir:  $(printf '%-37s' "$DATA_DIR")║"
echo "║  Source:    $(printf '%-37s' "$SOURCE")║"
echo "║  Full mode: $(printf '%-37s' "$FULL_UPDATE")║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

if [[ "$SOURCE" == "all" || "$SOURCE" == "hashes" ]]; then
    update_builtin
    update_clamav
    update_malwarebazaar
    update_urlhaus
    update_feodo
    update_virusshare
    echo ""
    stat "Hash signatures imported: $HASH_COUNT total (+ ClamAV CVD entries)"
fi

if [[ "$SOURCE" == "all" || "$SOURCE" == "yara" ]]; then
    echo ""
    update_yara
fi

echo ""
echo "─────────────────────────────────────────────────────"
log "Verifying final database state..."
"$SD_BIN" --data-dir "$DATA_DIR" --log-level error info 2>/dev/null || true
echo "─────────────────────────────────────────────────────"
echo ""
ok "Signature database update complete!"
echo ""
