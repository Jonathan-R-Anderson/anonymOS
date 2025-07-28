#!/bin/sh
# Simple script to convert ANSI art to a D string constant
input="$1"
[ -z "$input" ] && exit 1
cat <<'EOM'
module kernel.utils.ansi_art;
immutable string ANSI_ART = q"EOF"
EOM
cat "$input"
cat <<'EOM'
EOF";
EOM
