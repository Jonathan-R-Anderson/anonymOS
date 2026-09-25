#!/bin/bash
# Copyright (C) 2026 Musa Jaradat
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# src/orin/collectors/remote_agent.sh
#
# Orin Remote Agent (Bash Fallback)
# =================================
# A pure-bash, zero-dependency script designed to execute on remote Linux
# hosts over SSH when Python is unavailable. It gathers coarse system security
# telemetry using ONLY standard POSIX utilities and outputs JSON to stdout.
#
# This covers routers, stripped-down containers, old systems, and embedded devices.

set -euo pipefail

# --- JSON HELPERS ---
json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/\\r}"
    str="${str//$'\t'/\\t}"
    printf '%s' "$str"
}

json_array_start() {
    printf '['
}

json_array_end() {
    printf ']'
}

json_object_start() {
    printf '{'
}

json_object_end() {
    printf '}'
}

json_field() {
    local name="$1"
    local value="$2"
    local is_last="${3:-false}"
    local comma=","
    if [[ "$is_last" == "true" ]]; then
        comma=""
    fi
    printf '"%s":%s%s' "$(json_escape "$name")" "$value" "$comma"
}

json_string_field() {
    local name="$1"
    local value="$2"
    local is_last="${3:-false}"
    json_field "$name" "\"$(json_escape "$value")\"" "$is_last"
}

json_int_field() {
    local name="$1"
    local value="$2"
    local is_last="${3:-false}"
    json_field "$name" "$value" "$is_last"
}

json_bool_field() {
    local name="$1"
    local value="$2"
    local is_last="${3:-false}"
    json_field "$name" "$value" "$is_last"
}

# --- SYSTEM INFO ---
gather_system_info() {
    local hostname_val
    local os_val

    hostname_val=$(hostname 2>/dev/null || echo "unknown_host")

    # Try multiple methods to get OS info
    if [[ -f /etc/os-release ]]; then
        os_val=$(grep -E "^PRETTY_NAME=" /etc/os-release 2>/dev/null | cut -d'"' -f2 || echo "Linux")
    elif [[ -f /etc/redhat-release ]]; then
        os_val=$(cat /etc/redhat-release 2>/dev/null || echo "Linux")
    elif command -v uname >/dev/null 2>&1; then
        os_val=$(uname -a 2>/dev/null || echo "Linux")
    else
        os_val="Linux"
    fi

    [[ -z "$os_val" ]] && os_val="Linux"

    json_object_start
    json_string_field "hostname" "$hostname_val" "false"
    json_string_field "os_platform" "$os_val" "true"
    json_object_end
}

# --- PROCESS COLLECTOR ---
gather_processes() {
    local first=true

    json_array_start

    # Try /proc first (most detailed)
    if [[ -d /proc ]]; then
        for pid_dir in /proc/[0-9]*; do
            [[ -d "$pid_dir" ]] || continue
            local pid
            pid=$(basename "$pid_dir")

            local ppid="-1"
            local name="unknown"
            local exe="unknown"
            local cmdline=""

            # Read stat for ppid and name
            if [[ -r "$pid_dir/stat" ]]; then
                local stat_content
                stat_content=$(cat "$pid_dir/stat" 2>/dev/null || echo "")
                if [[ -n "$stat_content" ]]; then
                    # Extract name between parentheses using sed
                    name=$(echo "$stat_content" | sed 's/.*(\(.*\)).*/\1/' 2>/dev/null || echo "unknown")
                    # Get ppid (field after closing paren)
                    local after_paren="${stat_content##*) }"
                    ppid=$(echo "$after_paren" | awk '{print $2}' 2>/dev/null || echo "-1")
                fi
            fi

            # Read comm as fallback for name
            if [[ "$name" == "unknown" ]] && [[ -r "$pid_dir/comm" ]]; then
                name=$(cat "$pid_dir/comm" 2>/dev/null | tr -d '\n' || echo "unknown")
            fi

            # Read exe link
            if [[ -L "$pid_dir/exe" ]]; then
                exe=$(readlink "$pid_dir/exe" 2>/dev/null || echo "unknown")
            fi

            # Read cmdline
            if [[ -r "$pid_dir/cmdline" ]]; then
                cmdline=$(cat "$pid_dir/cmdline" 2>/dev/null | tr '\0' ' ' | sed 's/ *$//' || echo "")
                [[ -z "$cmdline" ]] && cmdline="$name"
            fi

            [[ "$ppid" == "" ]] && ppid="-1"

            if [[ "$first" != "true" ]]; then
                printf ','
            fi
            first=false

            json_object_start
            json_int_field "pid" "$pid" "false"
            json_int_field "ppid" "$ppid" "false"
            json_string_field "name" "$name" "false"
            json_string_field "exe" "$exe" "false"
            json_string_field "cmdline" "$cmdline" "true"
            json_object_end
        done
    # Fallback to ps command
    elif command -v ps >/dev/null 2>&1; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            # Skip header
            [[ "$line" =~ ^[[:space:]]*PID ]] && continue

            local pid ppid name cmdline
            read -r pid ppid _ _ _ _ _ _ _ _ _ _ name_cmd <<< "$line"
            name=$(echo "$name_cmd" | awk '{print $1}')
            cmdline="$name_cmd"

            [[ -z "$pid" ]] && continue

            if [[ "$first" != "true" ]]; then
                printf ','
            fi
            first=false

            json_object_start
            json_int_field "pid" "$pid" "false"
            json_int_field "ppid" "${ppid:--1}" "false"
            json_string_field "name" "${name:-unknown}" "false"
            json_string_field "exe" "unknown" "false"
            json_string_field "cmdline" "${cmdline:-unknown}" "true"
            json_object_end
        done < <(ps aux 2>/dev/null || ps -ef 2>/dev/null || true)
    fi

    json_array_end
}

# --- NETWORK CONNECTIONS ---
gather_listening_ports() {
    local first=true
    local seen_ports=""

    json_array_start

    # Try /proc/net/tcp and tcp6
    parse_proc_net() {
        local file="$1"
        local proto="$2"
        [[ -r "$file" ]] || return

        while IFS= read -r line; do
            # Skip header
            [[ "$line" =~ ^[[:space:]]*sl ]] && continue

            local parts
            read -ra parts <<< "$line"
            [[ ${#parts[@]} -lt 10 ]] && continue

            local state="${parts[3]}"
            # State 0A = LISTEN
            [[ "$state" != "0A" ]] && continue

            local local_addr="${parts[1]}"
            local inode="${parts[9]}"

            # Parse port from hex
            local port_hex="${local_addr##*:}"
            local port=$((16#$port_hex)) 2>/dev/null || continue

            local port_key="${port}_${proto}"
            [[ "$seen_ports" == *"$port_key"* ]] && continue
            seen_ports="${seen_ports}${port_key}:"

            # Try to find process via /proc/*/fd
            local proc_name="unknown"
            if [[ -d /proc ]]; then
                for fd_dir in /proc/*/fd; do
                    [[ -d "$fd_dir" ]] || continue
                    local target
                    target=$(readlink "$fd_dir/$inode" 2>/dev/null || true)
                    if [[ -n "$target" ]]; then
                        local pid_dir
                        pid_dir=$(dirname "$(dirname "$fd_dir")")
                        local pid
                        pid=$(basename "$pid_dir")
                        proc_name=$(cat "$pid_dir/comm" 2>/dev/null | tr -d '\n' || echo "unknown")
                        proc_name="${proc_name} (PID: ${pid})"
                        break
                    fi
                done
            fi

            if [[ "$first" != "true" ]]; then
                printf ','
            fi
            first=false

            json_object_start
            json_int_field "port" "$port" "false"
            json_string_field "protocol" "$proto" "false"
            json_string_field "process_name" "$proc_name" "true"
            json_object_end
        done < "$file"
    }

    parse_proc_net "/proc/net/tcp" "TCP"
    parse_proc_net "/proc/net/tcp6" "TCP"
    parse_proc_net "/proc/net/udp" "UDP"
    parse_proc_net "/proc/net/udp6" "UDP"

    # Fallback to netstat/ss
    if [[ "$first" == "true" ]] && command -v ss >/dev/null 2>&1; then
        while IFS= read -r line; do
            [[ "$line" =~ ^Netid ]] && continue
            [[ -z "$line" ]] && continue

            local proto port proc_name
            proto=$(echo "$line" | awk '{print $1}' | tr '[:lower:]' '[:upper:]')
            local local_addr
            local_addr=$(echo "$line" | awk '{print $5}')
            port=$(echo "$local_addr" | rev | cut -d':' -f1 | rev)
            proc_name=$(echo "$line" | awk '{print $7}' | grep -oP 'users:\(\("\K[^"]+' || echo "unknown")

            [[ ! "$port" =~ ^[0-9]+$ ]] && continue

            if [[ "$first" != "true" ]]; then
                printf ','
            fi
            first=false

            json_object_start
            json_int_field "port" "$port" "false"
            json_string_field "protocol" "$proto" "false"
            json_string_field "process_name" "$proc_name" "true"
            json_object_end
        done < <(ss -tuln 2>/dev/null || true)
    elif [[ "$first" == "true" ]] && command -v netstat >/dev/null 2>&1; then
        while IFS= read -r line; do
            [[ "$line" =~ ^Proto ]] && continue
            [[ "$line" =~ ^Active ]] && continue
            [[ -z "$line" ]] && continue

            local proto port
            proto=$(echo "$line" | awk '{print $1}' | tr '[:lower:]' '[:upper:]')
            local local_addr
            local_addr=$(echo "$line" | awk '{print $4}')
            port=$(echo "$local_addr" | rev | cut -d':' -f1 | rev)

            [[ ! "$port" =~ ^[0-9]+$ ]] && continue

            if [[ "$first" != "true" ]]; then
                printf ','
            fi
            first=false

            json_object_start
            json_int_field "port" "$port" "false"
            json_string_field "protocol" "$proto" "false"
            json_string_field "process_name" "unknown" "true"
            json_object_end
        done < <(netstat -tuln 2>/dev/null || true)
    fi

    json_array_end
}

gather_outbound_connections() {
    local first=true

    json_array_start

    # Try /proc/net/tcp
    if [[ -r /proc/net/tcp ]]; then
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*sl ]] && continue

            local parts
            read -ra parts <<< "$line"
            [[ ${#parts[@]} -lt 10 ]] && continue

            local state="${parts[3]}"
            # State 01 = ESTABLISHED
            [[ "$state" != "01" ]] && continue

            local local_addr="${parts[1]}"
            local remote_addr="${parts[2]}"
            local inode="${parts[9]}"

            # Parse IPs and ports
            local local_ip_hex="${local_addr%%:*}"
            local remote_ip_hex="${remote_addr%%:*}"

            # Convert hex IP to decimal (IPv4 only for simplicity)
            if [[ ${#local_ip_hex} -eq 8 ]]; then
                local ip_int=$((16#$local_ip_hex))
                local_ip="$((ip_int & 0xFF)).$(((ip_int >> 8) & 0xFF)).$(((ip_int >> 16) & 0xFF)).$(((ip_int >> 24) & 0xFF))"

                ip_int=$((16#$remote_ip_hex))
                remote_ip="$((ip_int & 0xFF)).$(((ip_int >> 8) & 0xFF)).$(((ip_int >> 16) & 0xFF)).$(((ip_int >> 24) & 0xFF))"
            else
                continue
            fi

            # Skip loopback
            [[ "$remote_ip" == "127.0.0.1" ]] && continue

            local local_port=$((16#${local_addr##*:})) 2>/dev/null || continue
            local remote_port=$((16#${remote_addr##*:})) 2>/dev/null || continue

            # Find process
            local proc_name="unknown"
            if [[ -d /proc ]]; then
                for fd_dir in /proc/*/fd; do
                    [[ -d "$fd_dir" ]] || continue
                    local target
                    target=$(readlink "$fd_dir"/* 2>/dev/null | grep "socket:\[$inode\]" || true)
                    if [[ -n "$target" ]]; then
                        local pid_dir
                        pid_dir=$(dirname "$(dirname "$fd_dir")")
                        local pid
                        pid=$(basename "$pid_dir")
                        proc_name=$(cat "$pid_dir/comm" 2>/dev/null | tr -d '\n' || echo "unknown")
                        proc_name="${proc_name} (PID: ${pid})"
                        break
                    fi
                done
            fi

            if [[ "$first" != "true" ]]; then
                printf ','
            fi
            first=false

            json_object_start
            json_string_field "local_ip" "$local_ip" "false"
            json_int_field "local_port" "$local_port" "false"
            json_string_field "remote_ip" "$remote_ip" "false"
            json_int_field "remote_port" "$remote_port" "false"
            json_string_field "state" "ESTABLISHED" "false"
            json_string_field "process_name" "$proc_name" "true"
            json_object_end
        done < /proc/net/tcp
    fi

    # Fallback to ss
    if [[ "$first" == "true" ]] && command -v ss >/dev/null 2>&1; then
        while IFS= read -r line; do
            [[ "$line" =~ ^State ]] && continue
            [[ "$line" =~ ^Netid ]] && continue
            [[ ! "$line" =~ ESTAB ]] && continue

            local local_addr remote_addr local_ip local_port remote_ip remote_port
            local_addr=$(echo "$line" | awk '{print $4}')
            remote_addr=$(echo "$line" | awk '{print $5}')

            local_ip=$(echo "$local_addr" | rev | cut -d':' -f2- | rev)
            local_port=$(echo "$local_addr" | rev | cut -d':' -f1 | rev)
            remote_ip=$(echo "$remote_addr" | rev | cut -d':' -f2- | rev)
            remote_port=$(echo "$remote_addr" | rev | cut -d':' -f1 | rev)

            [[ "$remote_ip" == "127.0.0.1" ]] && continue
            [[ "$remote_ip" == "::1" ]] && continue

            if [[ "$first" != "true" ]]; then
                printf ','
            fi
            first=false

            json_object_start
            json_string_field "local_ip" "$local_ip" "false"
            json_string_field "local_port" "$local_port" "false"
            json_string_field "remote_ip" "$remote_ip" "false"
            json_string_field "remote_port" "$remote_port" "false"
            json_string_field "state" "ESTABLISHED" "false"
            json_string_field "process_name" "unknown" "true"
            json_object_end
        done < <(ss -tn 2>/dev/null || true)
    fi

    json_array_end
}

# --- PROMISCUOUS INTERFACES ---
gather_promisc_interfaces() {
    local first=true

    json_array_start

    # Try /sys/class/net
    if [[ -d /sys/class/net ]]; then
        for iface_dir in /sys/class/net/*; do
            [[ -d "$iface_dir" ]] || continue
            local iface_name
            iface_name=$(basename "$iface_dir")

            local flags_file="$iface_dir/flags"
            local flags_content="unknown"
            local is_promiscuous=0

            if [[ -r "$flags_file" ]]; then
                flags_content=$(cat "$flags_file" 2>/dev/null | tr -d '\n' || echo "ERROR_ACCESS_DENIED")

                # Check for PROMISC flag (0x100 bit)
                local flags_clean
                flags_clean=$(echo "$flags_content" | tr '[:upper:]' '[:lower:]')
                flags_clean="${flags_clean#0x}"
                local flags_int=$((16#$flags_clean)) 2>/dev/null || flags_int=0

                if (( (flags_int & 0x100) != 0 )); then
                    is_promiscuous=1
                fi
            fi

            if [[ "$first" != "true" ]]; then
                printf ','
            fi
            first=false

            json_object_start
            json_string_field "interface" "$iface_name" "false"
            json_string_field "flags" "$flags_content" "false"
            json_bool_field "is_promiscuous" "$is_promiscuous" "true"
            json_object_end
        done
    # Fallback to ip command
    elif command -v ip >/dev/null 2>&1; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue

            local iface_name flags_str is_promiscuous=0
            iface_name=$(echo "$line" | grep -oP '^\d+:\s+\K[^:@]+' || echo "unknown")
            flags_str=$(echo "$line" | grep -oP '<\K[^>]+' || echo "")

            if [[ "$flags_str" == *"PROMISC"* ]]; then
                is_promiscuous=1
            fi

            if [[ "$first" != "true" ]]; then
                printf ','
            fi
            first=false

            json_object_start
            json_string_field "interface" "$iface_name" "false"
            json_string_field "flags" "<$flags_str>" "false"
            json_bool_field "is_promiscuous" "$is_promiscuous" "true"
            json_object_end
        done < <(ip link show 2>/dev/null || true)
    fi

    json_array_end
}

# --- KERNEL MODULES ---
gather_kernel_modules() {
    local first=true

    json_array_start

    if [[ -r /proc/modules ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue

            local mod_name mem_size instances
            read -r mod_name mem_size instances _ <<< "$line"

            [[ -z "$mod_name" ]] && continue

            if [[ "$first" != "true" ]]; then
                printf ','
            fi
            first=false

            json_object_start
            json_string_field "module_name" "$mod_name" "false"
            json_int_field "memory_size" "${mem_size:-0}" "false"
            json_int_field "instances_loaded" "${instances:-0}" "true"
            json_object_end
        done < /proc/modules
    elif command -v lsmod >/dev/null 2>&1; then
        while IFS= read -r line; do
            [[ "$line" =~ ^Module ]] && continue
            [[ -z "$line" ]] && continue

            local mod_name mem_size instances
            read -r mod_name mem_size instances _ <<< "$line"

            [[ -z "$mod_name" ]] && continue

            if [[ "$first" != "true" ]]; then
                printf ','
            fi
            first=false

            json_object_start
            json_string_field "module_name" "$mod_name" "false"
            json_int_field "memory_size" "${mem_size:-0}" "false"
            json_int_field "instances_loaded" "${instances:-0}" "true"
            json_object_end
        done < <(lsmod 2>/dev/null || true)
    fi

    json_array_end
}

# --- USER ACCOUNTS ---
gather_users() {
    local first=true

    json_array_start

    if [[ -r /etc/passwd ]]; then
        while IFS=: read -r username _ uid gid gecos home shell; do
            [[ -z "$username" ]] && continue

            if [[ "$first" != "true" ]]; then
                printf ','
            fi
            first=false

            json_object_start
            json_string_field "username" "$username" "false"
            json_int_field "uid" "${uid:--1}" "false"
            json_int_field "gid" "${gid:--1}" "false"
            json_string_field "home" "${home:-unknown}" "false"
            json_string_field "shell" "${shell:-unknown}" "true"
            json_object_end
        done < /etc/passwd
    fi

    json_array_end
}

# --- SSH KEYS ---
gather_ssh_keys() {
    local first=true

    json_array_start

    # Check common locations for authorized_keys and known_hosts
    local key_files=()

    # System-wide
    [[ -r /etc/ssh/authorized_keys ]] && key_files+=("/etc/ssh/authorized_keys")
    [[ -r /etc/ssh/ssh_known_hosts ]] && key_files+=("/etc/ssh/ssh_known_hosts")

    # User homes (if we can read them)
    if [[ -d /home ]]; then
        for home_dir in /home/*; do
            [[ -d "$home_dir/.ssh" ]] || continue
            [[ -r "$home_dir/.ssh/authorized_keys" ]] && key_files+=("$home_dir/.ssh/authorized_keys")
            [[ -r "$home_dir/.ssh/known_hosts" ]] && key_files+=("$home_dir/.ssh/known_hosts")
        done
    fi

    # Root
    [[ -r /root/.ssh/authorized_keys ]] && key_files+=("/root/.ssh/authorized_keys")
    [[ -r /root/.ssh/known_hosts ]] && key_files+=("/root/.ssh/known_hosts")

    for key_file in "${key_files[@]}"; do
        [[ -r "$key_file" ]] || continue

        local line_num=0
        while IFS= read -r line; do
            ((line_num++))
            [[ -z "$line" ]] && continue
            [[ "$line" =~ ^[[:space:]]*# ]] && continue

            local key_type key_data comment
            read -r key_type key_data comment <<< "$line"

            [[ -z "$key_type" ]] && continue

            if [[ "$first" != "true" ]]; then
                printf ','
            fi
            first=false

            json_object_start
            json_string_field "path" "$key_file" "false"
            json_string_field "type" "$key_type" "false"
            json_string_field "comment" "${comment:-}" "false"
            json_int_field "line" "$line_num" "true"
            json_object_end
        done < "$key_file"
    done

    json_array_end
}

# --- CRONTABS ---
gather_crontabs() {
    local first=true

    json_array_start

    # System crontab
    if [[ -r /etc/crontab ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            [[ "$line" =~ ^[[:space:]]*# ]] && continue

            if [[ "$first" != "true" ]]; then
                printf ','
            fi
            first=false

            json_object_start
            json_string_field "source" "/etc/crontab" "false"
            json_string_field "content" "$line" "true"
            json_object_end
        done < /etc/crontab
    fi

    # Cron directories
    for cron_dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        [[ -d "$cron_dir" ]] || continue

        for cron_file in "$cron_dir"/*; do
            [[ -f "$cron_file" ]] || continue
            [[ -r "$cron_file" ]] || continue

            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                [[ "$line" =~ ^[[:space:]]*# ]] && continue

                if [[ "$first" != "true" ]]; then
                    printf ','
                fi
                first=false

                json_object_start
                json_string_field "source" "$cron_file" "false"
                json_string_field "content" "$line" "true"
                json_object_end
            done < "$cron_file"
        done
    done

    # User crontabs (if readable)
    if [[ -d /var/spool/cron ]]; then
        for user_cron in /var/spool/cron/*; do
            [[ -f "$user_cron" ]] || continue
            [[ -r "$user_cron" ]] || continue

            local username
            username=$(basename "$user_cron")

            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                [[ "$line" =~ ^[[:space:]]*# ]] && continue

                if [[ "$first" != "true" ]]; then
                    printf ','
                fi
                first=false

                json_object_start
                json_string_field "source" "/var/spool/cron/$username" "false"
                json_string_field "user" "$username" "false"
                json_string_field "content" "$line" "true"
                json_object_end
            done < "$user_cron"
        done
    fi

    json_array_end
}

# --- SUID BINARIES ---
gather_suid_binaries() {
    local first=true
    local search_paths="/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin"

    json_array_start

    for base_path in $search_paths; do
        [[ -d "$base_path" ]] || continue

        while IFS= read -r suid_file; do
            [[ -z "$suid_file" ]] && continue

            local perms owner
            perms=$(stat -c '%a' "$suid_file" 2>/dev/null || echo "000")
            owner=$(stat -c '%U' "$suid_file" 2>/dev/null || echo "unknown")

            if [[ "$first" != "true" ]]; then
                printf ','
            fi
            first=false

            json_object_start
            json_string_field "path" "$suid_file" "false"
            json_string_field "permissions" "$perms" "false"
            json_string_field "owner" "$owner" "true"
            json_object_end
        done < <(find "$base_path" -perm -4000 -type f 2>/dev/null || true)
    done

    json_array_end
}

# --- FILE INTEGRITY (basic hashes) ---
gather_file_integrity() {
    local first=true
    local critical_paths="${1:-/etc/passwd /etc/shadow /etc/ssh/sshd_config /etc/sudoers}"

    json_array_start

    for filepath in $critical_paths; do
        [[ -f "$filepath" ]] || continue

        local hash_val="unknown"

        # Try different hash tools
        if command -v sha256sum >/dev/null 2>&1; then
            hash_val=$(sha256sum "$filepath" 2>/dev/null | awk '{print $1}' || echo "unknown")
        elif command -v shasum >/dev/null 2>&1; then
            hash_val=$(shasum -a 256 "$filepath" 2>/dev/null | awk '{print $1}' || echo "unknown")
        elif command -v md5sum >/dev/null 2>&1; then
            hash_val=$(md5sum "$filepath" 2>/dev/null | awk '{print $1}' || echo "unknown")
        fi

        local mtime="unknown"
        mtime=$(stat -c '%Y' "$filepath" 2>/dev/null || echo "unknown")

        if [[ "$first" != "true" ]]; then
            printf ','
        fi
        first=false

        json_object_start
        json_string_field "path" "$filepath" "false"
        json_string_field "sha256" "$hash_val" "false"
        json_string_field "mtime" "$mtime" "true"
        json_object_end
    done

    json_array_end
}

# --- AUTH LOGS (recent entries) ---
gather_auth_logs() {
    local log_files=("/var/log/auth.log" "/var/log/secure" "/var/log/messages")
    local max_lines=100

    json_array_start

    local first=true
    for log_file in "${log_files[@]}"; do
        [[ -r "$log_file" ]] || continue

        while IFS= read -r line; do
            [[ -z "$line" ]] && continue

            if [[ "$first" != "true" ]]; then
                printf ','
            fi
            first=false

            json_object_start
            json_string_field "source" "$log_file" "false"
            json_string_field "entry" "$line" "true"
            json_object_end
        done < <(tail -n "$max_lines" "$log_file" 2>/dev/null | grep -iE "(failed|invalid|error|accepted|session opened|session closed)" || true)
    done

    json_array_end
}

# --- MAIN EXECUTION ---
main() {
    # Gather all telemetry
    local system_info processes ports outbound promisc modules users ssh_keys crontabs suid fim auth_logs

    system_info=$(gather_system_info)
    processes=$(gather_processes)
    ports=$(gather_listening_ports)
    outbound=$(gather_outbound_connections)
    promisc=$(gather_promisc_interfaces)
    modules=$(gather_kernel_modules)
    users=$(gather_users)
    ssh_keys=$(gather_ssh_keys)
    crontabs=$(gather_crontabs)
    suid=$(gather_suid_binaries)
    fim=$(gather_file_integrity)
    auth_logs=$(gather_auth_logs)

    # Build final JSON output
    printf '{"hostname":%s,"os_platform":%s,"processes":%s,"ports":%s,"outbound":%s,"promisc":%s,"modules":%s,"kernel_symbols":[],"kernel_analysis":{"risk_level":"unknown","suspicious_symbols_count":0},"users":%s,"ssh_keys":%s,"crontabs":%s,"wtmp":[],"lastlog":[],"deleted":[],"fim":%s,"suid":%s,"pkg_integrity":[],"auth_logs":%s,"ebpf_programs":[],"ebpf_pinned":[],"ld_preload":[],"special_fds":[]}' \
        "$(echo "$system_info" | grep -oP '"hostname":\s*"\K[^"]+' || echo "unknown")" \
        "$(echo "$system_info" | grep -oP '"os_platform":\s*"\K[^"]+' || echo "Linux")" \
        "$processes" \
        "$ports" \
        "$outbound" \
        "$promisc" \
        "$modules" \
        "$users" \
        "$ssh_keys" \
        "$crontabs" \
        "$fim" \
        "$suid" \
        "$auth_logs"
}

main "$@"