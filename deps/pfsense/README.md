# pfSense / Netgate installer — split for GitHub

The pfSense firewall installer (`netgate-installer-v1.2-RELEASE-amd64.iso.gz`, a bootable ISO 9660
hybrid image, ~327 MB gzipped / ~1.06 GB raw) cannot be committed whole: GitHub rejects any single
file over 100 MiB. So it is committed **split** into byte-exact ~95 MiB parts:

    netgate-installer-v1.2-RELEASE-amd64.iso.gz.00.part
    netgate-installer-v1.2-RELEASE-amd64.iso.gz.01.part
    netgate-installer-v1.2-RELEASE-amd64.iso.gz.02.part
    netgate-installer-v1.2-RELEASE-amd64.iso.gz.03.part
    netgate-installer.iso.gz.sha256          # checksum of the reassembled .gz

## Reassemble

    scripts/pfsense-assemble.sh            # -> deps/netgate-installer-v1.2-RELEASE-amd64.iso.gz
    scripts/pfsense-assemble.sh --gunzip   # also expands the raw .iso the VMM boots
    # or: make pfsense-iso

Reassembly is `cat`-of-the-parts and is verified against the recorded SHA-256, so a partial or
corrupt checkout fails loudly instead of yielding a broken installer.  The reassembled
`.iso.gz`/`.iso` are build artifacts and are git-ignored (never re-commit the whole image).

To re-split after replacing the image (keep parts under 100 MiB):

    split -b 95m -d --additional-suffix=.part \
        deps/netgate-installer-v1.2-RELEASE-amd64.iso.gz \
        deps/pfsense/netgate-installer-v1.2-RELEASE-amd64.iso.gz.
    sha256sum deps/netgate-installer-v1.2-RELEASE-amd64.iso.gz \
        > deps/pfsense/netgate-installer.iso.gz.sha256

## How it is used

The reassembled ISO is the bootable pfSense installer. When the OS is configured to include the
pfSense firewall, the VMM boots this installer to lay pfSense down onto the firewall VM's disk, then
boots that disk and routes the laptop's traffic through it. That VMM runtime path depends on the
native hypervisor's guest-entry tier (`src/kernel/d/core/virt/`), which is still being brought up —
see `docs/hw-bringup/CLOUD_HYPERVISOR.md`. This directory only ensures the installer image itself is
committable and byte-exactly reconstructable.
