#!/bin/sh
# Turn a Dockerfile into a content-addressed microVM rootfs.
#
# WHY THIS EXISTS
# ---------------
# The catalogue rule -- volunteers run only signed images -- was a stand-in for
# isolation the node did not yet have. M2 shipped that isolation, so the
# restriction can be relaxed on purpose. This is how: a user brings a
# Dockerfile, it is built ONCE here, and what travels to the network is the
# resulting filesystem addressed by its SHA-256.
#
# NODES NEVER BUILD ANYTHING. They fetch a rootfs by hash, check the hash, and
# boot it. That single choice is what keeps M5 working:
#
#   * `apt-get install` is not reproducible. Two nodes building the same
#     Dockerfile a week apart get different packages, different libc, different
#     BLAS -- and then produce different results for entirely honest reasons.
#     M5 would score that as a disagreement and M8 would charge it to a correct
#     node's reputation, which is the one failure this network cannot absorb.
#   * Building is itself arbitrary code execution WITH network access. Doing it
#     on volunteer hardware hands an attacker a free build farm, and none of the
#     microVM guarantees apply to the builder.
#
# So the build being reproducible does not matter. The ARTEFACT being identical
# does, and a hash gives that for free. The guarantee moves from "somebody
# signed this" to "we all ran the same bytes", which is stronger and needs no
# central authority.
#
# USAGE
#   ./build-rootfs.sh <context-dir> [output.ext4]
#   ./build-rootfs.sh --image <docker-image-tag> [output.ext4]
#
# Prints the SHA-256 of the finished image on stdout, which IS its address.
set -eu

usage() {
    echo "usage: $0 <context-dir> [out.ext4]" >&2
    echo "       $0 --image <tag> [out.ext4]" >&2
    exit 2
}

[ $# -ge 1 ] || usage

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"

# mke2fs -d populates a filesystem from a directory WITHOUT root, a loop device
# or a mount. The obvious alternative -- losetup + mount + cp -- needs
# privileges this script should not want, on a developer's machine, to produce
# an artefact that is going to be hashed anyway.
command -v mke2fs >/dev/null 2>&1 || {
    echo "!! mke2fs not found (Debian/Ubuntu: apt install e2fsprogs)" >&2
    exit 1
}

if [ "$1" = "--image" ]; then
    [ $# -ge 2 ] || usage
    IMAGE="$2"
    OUT="${3:-rootfs.ext4}"
else
    CONTEXT="$1"
    OUT="${2:-rootfs.ext4}"
    [ -f "$CONTEXT/Dockerfile" ] || {
        echo "!! no Dockerfile in $CONTEXT" >&2
        exit 1
    }
    IMAGE="syndichan-rootfs-build:$$"
    echo "== build $CONTEXT" >&2
    $SUDO docker build -t "$IMAGE" "$CONTEXT" >&2
fi

WORK="$(mktemp -d)"
cleanup() {
    $SUDO rm -rf "$WORK"
    # Only remove the image if this script created it. A tag the caller passed
    # in with --image is theirs, not ours.
    [ -n "${CONTAINER:-}" ] && $SUDO docker rm -f "$CONTAINER" >/dev/null 2>&1
    case "$IMAGE" in
        syndichan-rootfs-build:*) $SUDO docker rmi -f "$IMAGE" >/dev/null 2>&1 ;;
    esac
    return 0
}
trap cleanup EXIT

echo "== export filesystem" >&2
CONTAINER="$($SUDO docker create "$IMAGE" /bin/true)"
mkdir -p "$WORK/root"
# `docker export` flattens the layers into the filesystem the container would
# actually see, which is what a VM needs -- an OCI image with its layer
# metadata is not bootable.
$SUDO docker export "$CONTAINER" | $SUDO tar -x -C "$WORK/root"

# Firecracker boots this directly, so it needs the pieces a container gets from
# its runtime and a VM does not. Absent /dev, /proc and /sys the guest init
# fails in ways that look like a broken program rather than a broken image.
$SUDO mkdir -p "$WORK/root/dev" "$WORK/root/proc" "$WORK/root/sys" "$WORK/root/work"
$SUDO chmod 0777 "$WORK/root/work"

# Sized from the contents plus 25% slack, floor 128MB. Too tight and the copy
# fails late; too generous and every node pays for the emptiness on every fetch.
KB="$($SUDO du -sk "$WORK/root" | cut -f1)"
SIZE_MB=$(( (KB / 1024) * 125 / 100 + 64 ))
[ "$SIZE_MB" -lt 128 ] && SIZE_MB=128

# Flatten every timestamp before hashing. ext4 stores mtime/ctime/atime per
# inode, so without this two builds of an IDENTICAL tree differ purely in when
# they ran -- which is what the first version of this script did, and it made
# the address useless as a way to compare two builders' output.
#
# Epoch 0 rather than SOURCE_DATE_EPOCH: nothing in a compute rootfs should care
# what time it is, and a fixed constant needs no environment to be threaded
# through. -h so symlinks are touched rather than their targets, which may sit
# outside the tree.
$SUDO find "$WORK/root" -exec touch -h -d @0 {} +

echo "== make ext4 (${SIZE_MB}MB)" >&2
rm -f "$OUT"
# -d populates from the directory; -F because the target is a plain file;
# -U and -E hash_seed pin the UUID and directory hash seed, which mke2fs would
# otherwise randomise per run.
#
# NOT YET BYTE-REPRODUCIBLE, and measured rather than assumed: two runs over an
# identical tree still produce different images. Pinning the UUID, the hash seed
# and every file timestamp removed most of the variance but not all of it --
# mke2fs also stamps creation//last-write times into the superblock, and
# E2FSPROGS_FAKE_TIME only helps if e2fsprogs was compiled with fake-time
# support, which is not something this script can assume.
#
# THE DESIGN DOES NOT DEPEND ON THIS. The artefact is built ONCE and travels by
# the hash of the bytes that were actually built; nodes fetch that hash, verify
# it, and boot it, so every node still runs provably identical bytes and M5 is
# unaffected.
#
# What reproducibility would ADD is auditability: an independent party rebuilding
# a submitter's Dockerfile and getting the same address is the only way to check
# a published rootfs matches the source it claims to come from. Worth finishing
# later -- superblock normalisation via a post-pass -- but it is a stronger
# property than the network needs to function, and claiming it before it is true
# would be worse than not having it.
$SUDO mke2fs -q -t ext4 -F \
    -d "$WORK/root" \
    -U "00000000-0000-0000-0000-000000000000" \
    -E hash_seed=00000000-0000-0000-0000-000000000000 \
    "$OUT" "${SIZE_MB}m"
$SUDO chown "$(id -u):$(id -g)" "$OUT" 2>/dev/null || true

DIGEST="$(sha256sum "$OUT" | cut -d' ' -f1)"
echo "== $OUT  $(du -h "$OUT" | cut -f1)" >&2
echo "rootfs sha256:$DIGEST"
