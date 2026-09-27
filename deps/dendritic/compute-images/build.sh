#!/bin/sh
# Build and import the catalogue images.
#
# Imports into containerd as well as building, because registry.local is not a
# real registry — a built image the node cannot pull is a job that fails at
# dispatch, which is the failure this script exists to prevent.
set -eu
ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
LANGS="${*:-python c go embed}"

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"
if [ -n "$SUDO" ] && ! sudo -n true 2>/dev/null; then
    echo "This needs root and sudo wants a password, which it cannot ask for here." >&2
    echo "Run it from a terminal:  ./compute-images/build.sh $LANGS" >&2
    exit 1
fi

for lang in $LANGS; do
    dir="$ROOT/$lang"
    [ -d "$dir" ] || { echo "!! no image definition for '$lang'" >&2; exit 1; }
    tag="registry.local/compute-$lang:latest"

    printf '\n== build %s\n' "$tag"
    $SUDO docker build -t "$tag" "$dir"

    printf '== import %s into containerd\n' "$tag"
    tmp="$(mktemp -t "compute-$lang-XXXXXX.tar")"
    # Save and import as SEPARATE steps, each checked. Piping docker save into
    # ctr import means a failure mid-stream feeds a truncated tar to a happily
    # succeeding import — the same trap scripts/deploy.sh documents.
    $SUDO docker save "$tag" -o "$tmp"
    $SUDO k3s ctr -n k8s.io images import "$tmp"
    $SUDO rm -f "$tmp"
done

printf '\n== done. Images built: %s\n' "$LANGS"
echo "   These names must match the node's two closed tables:"
echo "     cmd/syndichan-node/computeapi.go catalogueImages — language runtimes"
echo "       (python, go, c), keyed by language"
echo "     internal/compute/catalogue.go Workloads — fixed workloads (embed),"
echo "       keyed by workload name, and carrying the published artifact + digest"
echo "   Both are closed. A name in neither is refused, never guessed at, so an"
echo "   image built here that no table lists runs nothing, and a table entry with"
echo "   no image built here fails at dispatch instead of at submission."
printf '\n== these images reach nobody else\n'
echo "   They are on THIS machine. A volunteer who did not run this script cannot"
echo "   obtain them, and their node will stop advertising compute rather than"
echo "   accept work it would die on. To distribute a workload image:"
echo "     ./scripts/publish-compute-images.sh --save-only   # save + hash"
echo "     ./scripts/publish-compute-images.sh               # publish"
echo "   A node fetches it from /dl/ and checks the sha256 against a value"
echo "   compiled into its own binary, so a REBUILT image needs its new hash in"
echo "   both catalogue tables and a node build before it can be published."
echo "   See compute-images/README.md."
