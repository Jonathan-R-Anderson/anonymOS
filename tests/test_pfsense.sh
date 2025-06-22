#!/bin/bash
set -e
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
mkdir -p tmpbin
cat > tmpbin/docker <<'D'
#!/bin/sh
echo docker "$@"
D
chmod +x tmpbin/docker
PATH=$(pwd)/tmpbin:$PATH

cat > pfsense_cfg.json <<'J'
{
  "network": {
    "pfsense": {"enabled": true, "method": "docker", "ip": "10.1.1.1"}
  }
}
J
out=$("$ROOT_DIR"/scripts/pfsense_setup.sh --dry-run --config pfsense_cfg.json)
[[ $out == docker* ]]
[[ $out == *10.1.1.1* ]]
rm pfsense_cfg.json
rm -rf tmpbin
echo "pfsense setup dry-run passed"
