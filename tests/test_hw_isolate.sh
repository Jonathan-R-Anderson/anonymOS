#!/bin/bash
set -e
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
# Fake docker to test detection
mkdir -p tmpbin
cat > tmpbin/docker <<'D'
#!/bin/sh
echo docker "$@"
D
chmod +x tmpbin/docker
PATH=$(pwd)/tmpbin:$PATH cmd=$(PATH=$(pwd)/tmpbin:$PATH "$ROOT_DIR"/scripts/hardware_isolate.sh --dry-run --device /dev/null driver)
[[ $cmd == docker\ run* ]] && [[ $cmd == *--device* ]]
rm -rf tmpbin
PATH=/bin cmd=$(PATH=/bin "$ROOT_DIR"/scripts/hardware_isolate.sh --dry-run driver)
[[ $cmd == lxc-execute* ]]
echo "hardware isolation script dry-run passed"
