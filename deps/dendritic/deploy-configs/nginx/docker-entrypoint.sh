#!/bin/sh
set -eu

TLS_DIR="${TLS_DIR:-/etc/nginx/tls}"
DEFAULT_CERT_PATH="$TLS_DIR/default.crt"
DEFAULT_KEY_PATH="$TLS_DIR/default.key"
AUTO_CERT_PATH="$TLS_DIR/fullchain.pem"
AUTO_KEY_PATH="$TLS_DIR/privkey.pem"
CERT_PATH="${TLS_CERT_PATH:-}"
KEY_PATH="${TLS_KEY_PATH:-}"
COMMON_NAME="${SSL_CERT_COMMON_NAME:-localhost}"
ALT_NAMES="${SSL_ALT_NAMES:-DNS:localhost,IP:127.0.0.1,DNS:${COMMON_NAME}}"

mkdir -p "$TLS_DIR"

# ---------------------------------------------------------------------------
# Domain-only access guard
#
# When DOMAIN is set to a real hostname, only that host (plus optional
# DOMAIN_ALIASES and localhost) is served; every other Host header / TLS SNI
# (raw IP, parked/alternate domains) is rejected. When DOMAIN is empty or
# "localhost", the guard stays permissive so the site is reachable by any host
# (the previous default behavior) - this makes the feature safe to ship
# disabled and impossible to accidentally lock yourself out of.
# Generated here (before the cert-handling exits below) so the include files
# nginx.conf references always exist regardless of which cert branch runs.
# ---------------------------------------------------------------------------
GUARD_DIR="/etc/nginx/domain-guard"
mkdir -p "$GUARD_DIR"
GUARD_DOMAIN="${DOMAIN:-}"
if [ -n "$GUARD_DOMAIN" ] && [ "$GUARD_DOMAIN" != "localhost" ]; then
    SERVER_NAMES="$GUARD_DOMAIN localhost"
    # DOMAIN_ALIASES: optional comma/space separated extra allowed hostnames.
    for extra in $(printf '%s' "${DOMAIN_ALIASES:-}" | tr ',' ' '); do
        [ -n "$extra" ] && SERVER_NAMES="$SERVER_NAMES $extra"
    done
    printf 'server_name %s;\n' "$SERVER_NAMES" > "$GUARD_DIR/allowed-host.conf"
    # Reject any other Host (444 = close connection) and any other TLS SNI
    # (ssl_reject_handshake terminates the handshake for non-matching SNI, so no
    # throwaway certificate is needed on nginx 1.19.4+).
    cat > "$GUARD_DIR/default-deny.conf" <<'DENY'
    server {
        listen 80 default_server;
        server_name _;
        return 444;
    }
    server {
        listen 443 ssl default_server;
        ssl_reject_handshake on;
    }
DENY
    printf 'Domain-only access enabled for: %s\n' "$SERVER_NAMES" >&2
else
    printf 'server_name _;\n' > "$GUARD_DIR/allowed-host.conf"
    : > "$GUARD_DIR/default-deny.conf"
    printf 'Domain-only access disabled (DOMAIN not set); serving all hosts.\n' >&2
fi

ensure_default_aliases() {
    if [ "$CERT_PATH" != "$DEFAULT_CERT_PATH" ]; then
        rm -f "$DEFAULT_CERT_PATH"
        ln -s "$CERT_PATH" "$DEFAULT_CERT_PATH"
    fi
    if [ "$KEY_PATH" != "$DEFAULT_KEY_PATH" ]; then
        rm -f "$DEFAULT_KEY_PATH"
        ln -s "$KEY_PATH" "$DEFAULT_KEY_PATH"
    fi
}

if [ -n "$CERT_PATH" ] || [ -n "$KEY_PATH" ]; then
    CERT_PATH="${CERT_PATH:-$DEFAULT_CERT_PATH}"
    KEY_PATH="${KEY_PATH:-$DEFAULT_KEY_PATH}"
    if [ ! -s "$CERT_PATH" ] || [ ! -s "$KEY_PATH" ]; then
        printf 'Configured TLS files are missing: cert=%s key=%s\n' "$CERT_PATH" "$KEY_PATH" >&2
        exit 1
    fi
    ensure_default_aliases
    exit 0
fi

if [ -s "$AUTO_CERT_PATH" ] && [ -s "$AUTO_KEY_PATH" ]; then
    CERT_PATH="$AUTO_CERT_PATH"
    KEY_PATH="$AUTO_KEY_PATH"
    ensure_default_aliases
    exit 0
fi

CERT_PATH="$DEFAULT_CERT_PATH"
KEY_PATH="$DEFAULT_KEY_PATH"

if [ -s "$CERT_PATH" ] && [ -s "$KEY_PATH" ]; then
    exit 0
fi

OPENSSL_CONFIG="$(mktemp)"
cat >"$OPENSSL_CONFIG" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
CN = ${COMMON_NAME}

[req_ext]
subjectAltName = ${ALT_NAMES}
EOF

openssl req \
    -x509 \
    -nodes \
    -days 3650 \
    -newkey rsa:2048 \
    -keyout "$KEY_PATH" \
    -out "$CERT_PATH" \
    -config "$OPENSSL_CONFIG" \
    -extensions req_ext

rm -f "$OPENSSL_CONFIG"
