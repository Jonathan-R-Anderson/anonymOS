# Let's Encrypt: boot-time renewal

## How certificates work in this stack

Both TLS consumers auto-detect certificates from the shared TLS mount
(`TLS_MOUNT_PATH`, default `deploy-configs/tls/`, mounted into nginx at
`/etc/nginx/tls` and into coturn at `/tls`):

1. If `TLS_CERT_PATH`/`TLS_KEY_PATH` env vars are set, those exact files are used.
2. Otherwise, if `fullchain.pem` + `privkey.pem` exist in the TLS dir
   (Let's Encrypt naming), they are used automatically.
3. Otherwise nginx generates a **self-signed** `default.crt`/`default.key`
   (CN from `SSL_CERT_COMMON_NAME`, default `localhost`) and coturn falls back
   to the same files.

Entrypoints only evaluate this at **container start**; there is no runtime
reload, and coturn cannot reload certs at all — renewing means replacing the
files and restarting `nginx` + `coturn`.

## The renewal mechanism

`renew-cert.sh` (run on the **host**, as root):

- Reads `DOMAIN`, `DOMAIN_ALIASES`, `CERTBOT_EMAIL` from the environment or the
  compose `.env` file.
- Exits immediately if the cert in the TLS dir covers `DOMAIN` and is valid for
  more than `CERT_MIN_DAYS_LEFT` (default 30) days.
- Otherwise picks a challenge mode automatically:
  - **nginx up** (or still starting at boot — it waits): `certbot certonly
    --webroot` against `deploy-configs/acme-webroot/`, which nginx serves at
    `/.well-known/acme-challenge/` (plain HTTP, exempt from the HTTPS
    redirect). No downtime, no port conflicts.
  - **stack down**: `certbot certonly --standalone` — certbot spins up its own
    temporary web server on the now-free port 80, so renewal also works before
    the stack has ever started.
- Re-executes itself under sudo when run unprivileged (certbot and docker both
  need root).
- Installs `fullchain.pem`/`privkey.pem` into the TLS dir and restarts the
  `nginx` and `coturn` containers.
- **Never fails the boot**: on any error it logs and exits 0, keeping the
  previous certificate.

## Setup (once, on the server)

```sh
# 1. Config — add to the compose .env (DOMAIN also enables the domain guard
#    and fixes RTMP/torrent public URLs):
#      DOMAIN=syndichan.org
#      CERTBOT_EMAIL=you@example.com
# 2. Deploy the updated nginx.conf + compose file (rebuild/recreate nginx).
# 3. Install the boot service (+ optional weekly timer for long uptimes):
sudo cp deploy-configs/certbot/maniwani-cert-renew.service /etc/systemd/system/
sudo cp deploy-configs/certbot/maniwani-cert-renew.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable maniwani-cert-renew.service maniwani-cert-renew.timer
# 4. First provision, right now:
sudo systemctl start maniwani-cert-renew.service
journalctl -u maniwani-cert-renew -n 50
```

`certbot`, `openssl`, `curl`, and docker compose v2 must be present on the
host (they already are on the current server).

## Security note

Do not commit real `privkey.pem` files to git. Keep the TLS dir out of version
control on deployments (only the generated/renewed files live there).
