#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <config> <fragment>" >&2
    exit 1
fi

config=$1
fragment=$2
tmp="${config}.tmp.$$"

awk '
FNR == NR {
    if ($0 ~ /^CONFIG_[A-Za-z0-9_]+=.+$/) {
        split($0, parts, "=")
        key = substr(parts[1], 8)
        updates[key] = $0
        next
    }
    if ($0 ~ /^# CONFIG_[A-Za-z0-9_]+ is not set$/) {
        key = substr($2, 8)
        updates[key] = $0
    }
    next
}
{
    if ($0 ~ /^CONFIG_[A-Za-z0-9_]+=.+$/) {
        split($0, parts, "=")
        key = substr(parts[1], 8)
        if (key in updates) {
            print updates[key]
            delete updates[key]
            next
        }
    }
    if ($0 ~ /^# CONFIG_[A-Za-z0-9_]+ is not set$/) {
        key = substr($2, 8)
        if (key in updates) {
            print updates[key]
            delete updates[key]
            next
        }
    }
    print
}
END {
    for (key in updates) {
        print updates[key]
    }
}
' "$fragment" "$config" > "$tmp"

mv "$tmp" "$config"
