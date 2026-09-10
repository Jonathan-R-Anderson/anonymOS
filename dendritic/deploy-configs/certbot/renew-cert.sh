#!/bin/bash
# Boot-time Let's Encrypt provision/renew for the maniwani stack.
#
# Checks the certificate in the TLS mount dir; if it is missing, does not
# cover $DOMAIN, or expires within $CERT_MIN_DAYS_LEFT days, it obtains or
# renews one with certbot's webroot challenge (served by the running nginx
# container via /.well-known/acme-challenge/), installs fullchain.pem and
# privkey.pem where the nginx and coturn entrypoints auto-detect them, and
# restarts those two containers so they pick the new certificate up.
#
# Always exits 0 on renewal failure so a Let's Encrypt outage or network
# problem never blocks boot — the site keeps serving its previous cert.
#
# Requirements on the host: certbot, openssl, curl, docker compose v2, root
# (certbot needs /etc/letsencrypt and the restart needs docker).
set -u

log() { printf '[cert-renew] %s\n' "$*"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_DIR="${COMPOSE_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
TLS_DIR="${TLS_MOUNT_PATH:-$COMPOSE_DIR/deploy-configs/tls}"
WEBROOT="${ACME_WEBROOT:-$COMPOSE_DIR/deploy-configs/acme-webroot}"
MIN_DAYS_LEFT="${CERT_MIN_DAYS_LEFT:-30}"
CERT_PATH="$TLS_DIR/fullchain.pem"
KEY_PATH="$TLS_DIR/privkey.pem"

env_from_dotenv() {
    # $1 = variable name; prints the last assignment in the compose .env file.
    [ -f "$COMPOSE_DIR/.env" ] || return 0
    sed -n "s/^$1=//p" "$COMPOSE_DIR/.env" | tail -1
}

DOMAIN="${DOMAIN:-$(env_from_dotenv DOMAIN)}"
DOMAIN_ALIASES="${DOMAIN_ALIASES:-$(env_from_dotenv DOMAIN_ALIASES)}"
CERTBOT_EMAIL="${CERTBOT_EMAIL:-$(env_from_dotenv CERTBOT_EMAIL)}"

if [ -z "$DOMAIN" ] || [ "$DOMAIN" = "localhost" ]; then
    log "DOMAIN is not set (checked environment and $COMPOSE_DIR/.env);" \
        "nothing to renew for a localhost/self-signed deployment."
    exit 0
fi

cert_is_current() {
    [ -s "$CERT_PATH" ] || return 1
    # Expiring within the threshold?
    openssl x509 -in "$CERT_PATH" -noout \
        -checkend "$((MIN_DAYS_LEFT * 86400))" >/dev/null 2>&1 || return 1
    # Does it actually cover the configured domain? (Guards against a stale
    # cert for a previous domain, or the self-signed localhost fallback.)
    openssl x509 -in "$CERT_PATH" -noout -ext subjectAltName 2>/dev/null \
        | grep -q "DNS:$DOMAIN" || return 1
}

if cert_is_current; then
    log "certificate for $DOMAIN is valid for more than $MIN_DAYS_LEFT days; nothing to do."
    exit 0
fi

log "certificate for $DOMAIN is missing, mismatched, or expires within $MIN_DAYS_LEFT days — renewing."

# Renewal needs root: certbot writes /etc/letsencrypt (and in standalone mode
# binds port 80), and the container restart talks to docker.
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        log "re-executing with sudo for certbot/docker access."
        exec sudo COMPOSE_DIR="$COMPOSE_DIR" DOMAIN="$DOMAIN" \
            DOMAIN_ALIASES="$DOMAIN_ALIASES" CERTBOT_EMAIL="$CERTBOT_EMAIL" \
            CERT_MIN_DAYS_LEFT="$MIN_DAYS_LEFT" "$0" "$@"
    fi
    log "renewal requires root (certbot + docker); re-run with sudo."
    exit 1
fi

mkdir -p "$WEBROOT"

# nginx serves the challenge files when it is up; probe it on port 80.
nginx_ready() {
    code="$(curl -s -o /dev/null -m 5 -w '%{http_code}' \
        -H "Host: $DOMAIN" "http://127.0.0.1/.well-known/acme-challenge/probe" 2>/dev/null)"
    [ -n "$code" ] && [ "$code" != "000" ]
}

nginx_container_running() {
    [ -n "$(docker compose --project-directory "$COMPOSE_DIR" ps -q --status running nginx 2>/dev/null)" ]
}

# Pick the challenge mode:
# - nginx answering        -> webroot (zero downtime, no port juggling)
# - nginx starting up      -> wait for it, then webroot (boot races the stack)
# - nginx/stack down       -> certbot --standalone spins up its own temporary
#                             web server on the now-free port 80
CHALLENGE_MODE=""
if nginx_ready; then
    CHALLENGE_MODE="webroot"
elif nginx_container_running; then
    tries=0
    while [ "$tries" -lt 30 ]; do
        tries=$((tries + 1))
        sleep 3
        if nginx_ready; then break; fi
    done
    if nginx_ready; then
        CHALLENGE_MODE="webroot"
    else
        # nginx holds (or will grab) port 80, so standalone cannot work either.
        log "nginx container is running but never answered on port 80; giving up (keeping existing cert)."
        exit 0
    fi
else
    log "nginx is not running; using certbot's temporary standalone server on port 80."
    CHALLENGE_MODE="standalone"
fi

CERTBOT_ARGS=(certonly -d "$DOMAIN"
              --non-interactive --agree-tos --keep-until-expiring)
if [ "$CHALLENGE_MODE" = "webroot" ]; then
    CERTBOT_ARGS+=(--webroot -w "$WEBROOT")
else
    CERTBOT_ARGS+=(--standalone --preferred-challenges http)
fi
for alias in $(printf '%s' "$DOMAIN_ALIASES" | tr ',' ' '); do
    [ -n "$alias" ] && CERTBOT_ARGS+=(-d "$alias")
done
if [ -n "$CERTBOT_EMAIL" ]; then
    CERTBOT_ARGS+=(-m "$CERTBOT_EMAIL")
else
    CERTBOT_ARGS+=(--register-unsafely-without-email)
fi

if ! certbot "${CERTBOT_ARGS[@]}"; then
    log "certbot failed; keeping the existing certificate. See /var/log/letsencrypt/letsencrypt.log"
    exit 0
fi

LIVE_DIR="/etc/letsencrypt/live/$DOMAIN"
if [ ! -s "$LIVE_DIR/fullchain.pem" ] || [ ! -s "$LIVE_DIR/privkey.pem" ]; then
    log "certbot reported success but $LIVE_DIR is missing files; aborting install."
    exit 0
fi

# Install where the nginx/coturn entrypoints auto-detect Let's Encrypt certs.
cp -L "$LIVE_DIR/fullchain.pem" "$CERT_PATH"
cp -L "$LIVE_DIR/privkey.pem" "$KEY_PATH"
chmod 644 "$CERT_PATH" "$KEY_PATH"
log "installed new certificate into $TLS_DIR."

# Both entrypoints only evaluate the TLS dir at container start (and coturn
# cannot reload certs at runtime), so restart the two consumers — but only if
# the stack is actually up; a stopped stack picks the new files up on its own
# next start.
if nginx_container_running; then
    if docker compose --project-directory "$COMPOSE_DIR" restart nginx coturn; then
        log "restarted nginx and coturn with the new certificate."
    else
        log "WARNING: could not restart nginx/coturn automatically; restart them to apply the new cert."
    fi
else
    log "stack is not running; the new certificate will be used automatically on the next start."
fi
exit 0
