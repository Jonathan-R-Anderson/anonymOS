# Shared helpers for the compatibility-runtime build scripts (scripts/build-{wine,darling,waydroid}.sh).
#
# Each runtime's SOURCE IS NOT VENDORED (large, and these are long-lived upstreams tracked by commit),
# exactly like scripts/build-cloud-hypervisor.sh: the script clones a pinned commit into deps/<name>/
# (gitignored), builds it, and installs the result under deps/<name>/install so the OS image build
# or a per-domain install can pick it up.  docs/COMPAT.md is the integration overview.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

compat_fetch() {   # <dir> <repo> <commit> [--recurse]
    local dir="$1" repo="$2" commit="$3" recurse="${4:-}"
    mkdir -p "$dir"
    if [ ! -e "$dir/.git" ]; then
        git -C "$dir" init -q
        git -C "$dir" remote add origin "$repo"
    fi
    if ! git -C "$dir" cat-file -e "$commit^{commit}" 2>/dev/null; then
        echo "Fetching $(basename "$dir") $commit ..."
        git -C "$dir" fetch --depth 1 origin "$commit"
    fi
    git -C "$dir" checkout -q "$commit"
    if [ "$recurse" = "--recurse" ]; then
        git -C "$dir" submodule update --init --recursive --depth 1
    fi
}
