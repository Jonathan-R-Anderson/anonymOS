# Gateway controller deployment

Build and import `gateway-controller/Dockerfile`, then create the two server-only
Secrets. Never place their values in ConfigMaps, client configuration,
container arguments, or shell history.

`NAMECOM_USERNAME` and `NAMECOM_API_TOKEN` live in the stack's
`/home/ubuntu/maniwani/.env`, the same file `maniwani-dotenv` is built from.
Project only those two keys, the way `maniwani-env` is built in the bootstrap
runbook — the controller must not receive the rest of the app tier's config:

```sh
umask 077 && d="$(mktemp -d)" && cd "$d"
grep -E '^NAMECOM_(USERNAME|API_TOKEN)=' /home/ubuntu/maniwani/.env > namecom.env
test "$(wc -l < namecom.env)" -eq 2 || echo 'FATAL: .env is missing a NAMECOM_ key'
kubectl -n maniwani create secret generic gateway-controller-namecom \
  --from-env-file=namecom.env
shred -u namecom.env && cd / && rmdir "$d"

kubectl -n maniwani create secret generic gateway-controller-database \
  --from-file=url=/secure/path/gateway-database-url
kubectl apply -f doc/gateway-controller-rbac.yaml
kubectl apply -f k8s/gateway-controller/10-gateway-controller.yaml
```

The bootstrap manifest creates a dedicated ServiceAccount, Role, and RoleBinding.
Its only mutation permission is `patch` on the exact
`NetworkPolicy/nginx-gateway-ingress`; this lets the controller admit and
withdraw healthy gateway `/32` and `/128` addresses without granting Secret,
pod, ConfigMap, or broader networking access. It is deliberately separate from
the runtime manifest because the restricted updater must never own RBAC; apply
it manually once, before enabling NetworkPolicy synchronization.

`--from-env-file` does not strip quotes, so keep both values unquoted in `.env`.
After editing either value there, rebuild the Secret and restart the
Deployment — `kubectl -n maniwani rollout restart deploy/gateway-controller`.

Route only these public paths to the service:

- `POST /api/v1/gateways/reserve`
- `POST /api/v1/gateways/register`
- `POST /api/v1/gateways/unregister`
- `GET /api/v1/gateways`

Keep `/metrics` cluster-internal. The ingress must overwrite
`X-Forwarded-For`; configure its pod/network CIDR in `trusted_proxy_cidrs`.
If that trust boundary is wrong, the controller will probe or record the proxy
address instead of the gateway address.
