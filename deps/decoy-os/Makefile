# deps/decoy-os — build the §H1 decoy Linux distribution (roadmap/INSTALLER.md §H1).
#
# The decoy OS is a REAL Linux distro (Alpine) so it's maximally believable, customized
# into a lived-in workstation and seeded with the §G/§H2 deterministic fake history. The
# resulting rootfs can be packed into decoy.ext4, which the installer encrypts into
# the decoy system partition when Hidden OS is selected.
SELF := $(abspath .)
PROJECT_ROOT ?= $(abspath ../..)
BLD  := $(SELF)/build
DL   := $(SELF)/dl
CC   ?= cc

ALPINE_VER    := 3.19.9
ALPINE_BRANCH := v3.19
ALPINE_ARCH   := x86_64
MINIROOT      := alpine-minirootfs-$(ALPINE_VER)-$(ALPINE_ARCH).tar.gz
URL           := https://dl-cdn.alpinelinux.org/alpine/$(ALPINE_BRANCH)/releases/$(ALPINE_ARCH)/$(MINIROOT)
APKMAIN       := https://dl-cdn.alpinelinux.org/alpine/$(ALPINE_BRANCH)/main
APKCOMM       := https://dl-cdn.alpinelinux.org/alpine/$(ALPINE_BRANCH)/community

# ── the decoy's kernel: built from kernel.org source, NOT Alpine's apk linux-lts ────────────
# We compile Linux ourselves so the decoy's boot path (dm-crypt aes-xts + squashfs/overlay root,
# every storage/input/GPU driver init-crypt needs) is built =y and self-contained — no reliance
# on Alpine's module packaging or the initramfs module-closure guesswork. See kernel/decoy-kernel.config.
KERNEL_VER    ?= 6.12.111
KERNEL_TAR    := linux-$(KERNEL_VER).tar.xz
KERNEL_URL    := https://cdn.kernel.org/pub/linux/kernel/v6.x/$(KERNEL_TAR)
KERNEL_SHA256 := 9e59dc67624188fa12a6601f9598499cd6662a9066be572b59f935e3d7849810
KSRC          := $(BLD)/linux-$(KERNEL_VER)
KJOBS         ?= $(shell nproc 2>/dev/null || echo 4)

# §H1 believability — a REAL toolchain installed with apk (so `apk info`, `which`, the shell
# history and the /var/log daemons are all CONSISTENT: a workstation that claims git/ssh/vim
# but has none installed is a decoy tell). apk.static installs into the rootfs from the host
# with no chroot (--no-scripts), the Alpine-supported way to build a rootfs from a foreign OS.
DECOY_PKGS ?= openssh git vim htop tmux curl wget chrony bash sudo less tree rsync nano \
              tcpdump bind-tools mtr iproute2 file jq man-db docs

# Runtimes for the apps staged by stage-apps.sh: openjdk -> apps/log-synth (Java),
# python3+pip -> apps/evidenceforge (Python; the shared OpenRC service is
# apps/synthetic-logs), py3-fusepy+fuse -> apps/qafs (a Python FUSE filesystem).
# Added to BOTH rootfs variants' apk add below.
SYNTH_PKGS ?= openjdk17-jre-headless python3 py3-pip py3-fusepy fuse

# Block-layer tooling used by apps/disk-reclaim (the deniability duress tool that reclaims
# foreign partitions into the decoy and grows its dm-crypt+ext4 to fill the disk). These are
# also plausible on an ordinary admin workstation, so they double as cover. NB: Alpine splits
# util-linux — blockdev/wipefs/blkdiscard/partx live in util-linux-misc; sfdisk/lsblk are their
# own subpackages; resize2fs is in e2fsprogs-extra; sgdisk is in gptfdisk. Verify these names
# against the target Alpine version. growpart (cloud-utils) is optional (sfdisk fallback).
RECLAIM_PKGS ?= sfdisk lsblk util-linux-misc e2fsprogs-extra cryptsetup gptfdisk

# Runtime deps for the vendored snoop-detectors (apps/argus, spectre, orin, prx-sd), consumed by
# snoop-monitor. argus is a dynamic musl binary needing libbpf/libelf/zlib/zstd at runtime (it is
# cross-built by apps/argus/build-musl.sh; the decoy kernel provides BTF via CONFIG_DEBUG_INFO_BTF).
# prx-sd is a mostly-static musl binary (apps/prx-sd/build-musl.sh; static openssl) — no rootfs pkg.
# spectre pip-installs its deps into the rootfs (needs py3-pip, already in SYNTH_PKGS); orin is
# Python-stdlib. Added to BOTH rootfs variants' apk add below.
DETECTOR_PKGS ?= libbpf libelf zlib zstd-libs libgcc

# Your own programs. Everything under apps/ is installed into BOTH rootfs variants by
# stage-apps.sh: apps/<name>/bin -> /usr/local/bin, files/ -> /, service -> an OpenRC
# init script enabled at boot, install.sh -> run for anything else. See apps/README.md.
# We track each app's CONTROL surface (install.sh, service, bin/, files/) as build
# prerequisites, not the whole vendored source tree — apps/evidenceforge alone is 1400+
# files, and listing them all would be slow, would rebuild on any upstream churn, and
# would break Make if a re-vendor ever introduced a filename with a space. Re-vendoring
# a source tree, when it must force a rebuild, is picked up by touching that app's
# install.sh (or `make clean`). Docs are excluded so editing a README costs nothing.
APP_FILES := $(shell find $(SELF)/apps -maxdepth 2 \( -name install.sh -o -name service \) 2>/dev/null; \
                     find $(SELF)/apps/*/bin $(SELF)/apps/*/files -type f ! -name '*.md' 2>/dev/null)

# a real install reseeds with the user's decoy password
DECOY_PW ?= decoy-password
# The decoy OS's own settings — supplied by the installer (§E6 hidden-OS step) in the SAME
# flow; defaulted here for the standalone build, exported so customize.sh picks them up.
# plausible defaults — never "decoy…" (§H4); the installer overrides with the user's choices
DECOY_USER     ?= alex
DECOY_HOSTNAME ?= workstation
export DECOY_USER DECOY_HOSTNAME DECOY_USER_FULLNAME DECOY_USER_PASSWORD DECOY_NOW
DECOY    := ../decoy
ROOTFS   := $(BLD)/rootfs
DECOY_IMG_MB ?= 256

# Assembling a REAL distro rootfs (apk install, correct root:root ownership, device nodes) is
# inherently a privileged operation — fakeroot cannot fake a STATIC apk.static's syscalls, and
# Ubuntu's AppArmor blocks unprivileged user namespaces. So run the privileged steps as root:
# passwordless when already root (the ISO build runs in Docker as root), else via sudo. The
# artifacts are chown'd back to the caller so later unprivileged steps (git, verify) can read.
SUDO := $(shell [ "$$(id -u)" -eq 0 ] || echo sudo)
UGID := $(shell id -u):$(shell id -g)

VMLINUZ_URL := https://dl-cdn.alpinelinux.org/alpine/$(ALPINE_BRANCH)/releases/$(ALPINE_ARCH)/netboot/vmlinuz-lts
# The decoy is booted as a self-contained UKI (kernel + initramfs + cmdline, one PE) that the
# §E5 pre-boot loader decrypts off the encrypted disk and StartImages — no LoadOptions reach the
# kernel, so everything must be embedded. Needs ukify + systemd-boot's linuxx64.efi.stub.
UKI_STUB    := /usr/lib/systemd/boot/efi/linuxx64.efi.stub
# NB: ttyS0 must be the LAST console= — the last one becomes /dev/console, where PID 1's stdout
# lands. With tty0 last, the userspace banner goes to VGA and the serial boot-check sees nothing.
UKI_CMDLINE ?= console=tty0 console=ttyS0,115200 rdinit=/init loglevel=4

.PHONY: rootfs image verify consistency h4 uki boot-check kernel kernel-mods desktop-rootfs desktop-image desktop-boot-check clean

# §H1 desktop cover story — a graphical XFCE daily-driver decoy. The CLI believability set stays;
# these add a real Xorg + XFCE + Firefox stack (so booting the decoy lands in Alex's desktop).
DROOT       := $(BLD)/desktop-rootfs
DESKTOP_MB  ?= 3072
# NB: no linux-lts — the decoy runs the from-scratch kernel built above (KERNEL_VER), whose
# modules the $(DROOT)/.kernel-mods target installs into this rootfs. Shipping the apk 6.6 kernel
# alongside a 6.12 uname would be a decoy tell (apk info vs uname mismatch).
DESKTOP_PKGS ?= alpine-base xorg-server xf86-input-libinput xf86-video-modesetting \
                mesa-dri-gallium mesa-egl mesa-gbm xfce4 xfce4-terminal thunar \
                xfce4-screenshooter xfconf xfce4-settings dbus dbus-x11 elogind \
                polkit-elogind firefox-esr font-dejavu ttf-dejavu adwaita-icon-theme \
                hicolor-icon-theme gtk+3.0 networkmanager networkmanager-tui xinit e2fsprogs
rootfs: $(BLD)/decoy-rootfs.tar.gz

$(BLD) $(DL):
	@mkdir -p $@

$(DL)/$(MINIROOT): | $(DL)
	curl -fL -o $@ $(URL)

# apk.static — the standalone package manager, extracted from apk-tools-static, so the host
# (Ubuntu, no apk) can install real Alpine packages into the rootfs. Version discovered from
# the repo index so it tracks the pinned branch.
$(BLD)/apk.static: | $(BLD)
	@AV=$$(curl -fsSL $(APKMAIN)/$(ALPINE_ARCH)/ | grep -oE 'apk-tools-static-[0-9][0-9.r-]+\.apk' | head -1); \
	  test -n "$$AV" || { echo "[decoy-os] cannot find apk-tools-static in repo index"; exit 1; }; \
	  echo "[decoy-os] fetching $$AV"; \
	  curl -fsSL "$(APKMAIN)/$(ALPINE_ARCH)/$$AV" | tar -xzO sbin/apk.static > $@; \
	  chmod +x $@; $@ --version

# the §H2 fake-log generator (built standalone here to avoid the cross-Makefile self-test)
$(BLD)/fakelogd: $(DECOY)/decoy.c $(DECOY)/decoy_render.c $(DECOY)/h2/fakelogd.c | $(BLD)
	$(CC) -O2 -I$(DECOY) $^ -o $@

$(BLD)/decoy-rootfs.tar.gz: $(DL)/$(MINIROOT) $(BLD)/apk.static $(BLD)/fakelogd stage-apps.sh $(APP_FILES) customize.sh | $(BLD)
	$(SUDO) rm -rf $(ROOTFS)
	mkdir -p $(ROOTFS)
	$(SUDO) tar -xzf $(DL)/$(MINIROOT) -C $(ROOTFS)
	$(SUDO) $(BLD)/apk.static --root $(ROOTFS) --repository $(APKMAIN) --repository $(APKCOMM) \
	    --no-scripts --no-cache --update-cache add $(DECOY_PKGS) $(SYNTH_PKGS) $(RECLAIM_PKGS) $(DETECTOR_PKGS)
	$(SUDO) env DECOY_USER='$(DECOY_USER)' DECOY_HOSTNAME='$(DECOY_HOSTNAME)' \
	    DECOY_USER_FULLNAME='$(DECOY_USER_FULLNAME)' DECOY_USER_PASSWORD='$(DECOY_USER_PASSWORD)' \
	    DECOY_NOW='$(DECOY_NOW)' $(SELF)/customize.sh $(ROOTFS) $(BLD)/fakelogd "$(DECOY_PW)"
	$(SUDO) $(SELF)/stage-apps.sh $(ROOTFS)
	$(SUDO) tar -czf $@ -C $(ROOTFS) .
	$(SUDO) chown $(UGID) $@
	@echo "[decoy-os] built $@ ($$(du -h $@ | cut -f1)), $$(wc -l < $(ROOTFS)/etc/apk/world) pkgs in world, seeded with the §H2 fake history"

# ── §E5d/§H1 — the bootable decoy UKI (real Alpine kernel, decrypt-and-booted) ──────────────
$(DL)/vmlinuz-lts: | $(DL)
	curl -fL -o $@ $(VMLINUZ_URL)

# a static busybox for the initramfs PID 1 (extracted from the busybox-static apk)
$(BLD)/busybox.static: | $(BLD)
	@BB=$$(curl -fsSL $(APKMAIN)/$(ALPINE_ARCH)/ | grep -oE 'busybox-static-[0-9][0-9.p_r-]+\.apk' | head -1); \
	  test -n "$$BB" || { echo "[decoy-os] cannot find busybox-static in repo index"; exit 1; }; \
	  echo "[decoy-os] fetching $$BB"; \
	  curl -fsSL "$(APKMAIN)/$(ALPINE_ARCH)/$$BB" | tar -xzO bin/busybox.static > $@; chmod +x $@

# the initramfs: static busybox + our /init (deps/decoy-os/initramfs/init)
$(BLD)/initramfs.gz: $(BLD)/busybox.static initramfs/init | $(BLD)
	@rm -rf $(BLD)/ir && mkdir -p $(BLD)/ir/bin $(BLD)/ir/proc $(BLD)/ir/sys $(BLD)/ir/dev
	@cp $(BLD)/busybox.static $(BLD)/ir/bin/busybox
	@cp $(SELF)/initramfs/init $(BLD)/ir/init && chmod +x $(BLD)/ir/init
	@( cd $(BLD)/ir && find . | $(BLD)/busybox.static cpio -o -H newc 2>/dev/null | gzip -9 > $(BLD)/initramfs.gz )
	@echo "[decoy-os] built initramfs.gz ($$(du -h $(BLD)/initramfs.gz | cut -f1))"

$(BLD)/decoy-uki.efi: $(DL)/vmlinuz-lts $(BLD)/initramfs.gz | $(BLD)
	@test -f $(UKI_STUB) || { echo "[decoy-os] missing $(UKI_STUB) — apt install systemd-boot-efi systemd-ukify"; exit 1; }
	ukify build --linux=$(DL)/vmlinuz-lts --initrd=$(BLD)/initramfs.gz \
	    --cmdline="$(UKI_CMDLINE)" --stub=$(UKI_STUB) --output=$@
	@echo "[decoy-os] built decoy-uki.efi ($$(du -h $@ | cut -f1)) — a self-contained bootable Alpine PE"
uki: $(BLD)/decoy-uki.efi

# ── §E5d/§H1 — the decoy's from-scratch Linux $(KERNEL_VER) kernel ──────────────────────────
# Fetched from kernel.org, sha256-verified, configured from x86_64_defconfig + kernel/decoy-kernel.config
# (the whole boot path built =y), then compiled. The result is vmlinuz-decoy — the bzImage the
# desktop/crypt UKIs embed as --linux=. Needs the usual kernel build deps (flex bison libelf-dev)
# PLUS pahole (dwarves) — apps/argus's eBPF CO-RE needs kernel BTF, so decoy-kernel.config now sets
# CONFIG_DEBUG_INFO_BTF=y; without pahole olddefconfig silently drops BTF and the assert below fails.
$(DL)/$(KERNEL_TAR): | $(DL)
	curl -fL -o $@.part $(KERNEL_URL)
	echo "$(KERNEL_SHA256)  $@.part" | sha256sum -c -
	mv $@.part $@

$(BLD)/vmlinuz-decoy: $(DL)/$(KERNEL_TAR) kernel/decoy-kernel.config | $(BLD)
	rm -rf $(KSRC)
	tar -xf $(DL)/$(KERNEL_TAR) -C $(BLD)
	$(MAKE) -C $(KSRC) ARCH=x86_64 defconfig
	cat $(SELF)/kernel/decoy-kernel.config >> $(KSRC)/.config
	$(MAKE) -C $(KSRC) ARCH=x86_64 olddefconfig
	@# fail loudly if an unmet dependency silently dropped a driver the decoy MUST have to boot
	@for s in EXT4_FS SQUASHFS SQUASHFS_ZSTD OVERLAY_FS MD BLK_DEV_DM DM_CRYPT \
	         CRYPTO_XTS CRYPTO_AES CRYPTO_AES_NI_INTEL BLK_DEV_INITRD DEVTMPFS \
	         VIRTIO_PCI VIRTIO_BLK SCSI_VIRTIO VIRTIO_NET ATA SATA_AHCI ATA_PIIX \
	         SCSI BLK_DEV_SD BLK_DEV_SR BLK_DEV_NVME \
	         USB USB_XHCI_HCD USB_EHCI_HCD USB_STORAGE USB_UAS \
	         INPUT_EVDEV SERIO_I8042 KEYBOARD_ATKBD MOUSE_PS2 HID_GENERIC USB_HID \
	         DRM DRM_VIRTIO_GPU DRM_BOCHS DRM_FBDEV_EMULATION FRAMEBUFFER_CONSOLE \
	         EFI EFI_STUB DEBUG_INFO_BTF; do \
	   grep -q "^CONFIG_$$s=y" $(KSRC)/.config || { echo "[decoy-os] FATAL: kernel config lost CONFIG_$$s (unmet dep?) — the decoy would not boot"; exit 1; }; \
	 done
	$(MAKE) -C $(KSRC) ARCH=x86_64 -j$(KJOBS) bzImage modules
	cp $(KSRC)/arch/x86/boot/bzImage $@
	@echo "[decoy-os] built from-scratch kernel $(KERNEL_VER) -> $@ ($$(du -h $@|cut -f1))"
kernel: $(BLD)/vmlinuz-decoy

# Install OUR kernel's modules + boot files into the desktop rootfs (there is no apk linux-lts to
# provide them). With the boot path built =y this is a small tree, but /lib/modules/$(KVER) +
# modules.dep must exist (the initramfs module-closure reads it), and a real 6.12 workstation
# carries /boot/vmlinuz-*, config-*, System.map-* — so the decoy does too (§H1 believability).
$(DROOT)/.kernel-mods: $(BLD)/vmlinuz-decoy $(DROOT)/.stamp
	$(SUDO) rm -rf $(DROOT)/lib/modules
	$(SUDO) $(MAKE) -C $(KSRC) ARCH=x86_64 INSTALL_MOD_PATH=$(DROOT) modules_install
	$(SUDO) mkdir -p $(DROOT)/boot
	$(SUDO) cp $(BLD)/vmlinuz-decoy $(DROOT)/boot/vmlinuz-$(KERNEL_VER)
	$(SUDO) cp $(KSRC)/.config      $(DROOT)/boot/config-$(KERNEL_VER)
	$(SUDO) cp $(KSRC)/System.map   $(DROOT)/boot/System.map-$(KERNEL_VER)
	$(SUDO) touch $@
	@echo "[decoy-os] installed kernel $(KERNEL_VER) modules + /boot files into the desktop rootfs"
kernel-mods: $(DROOT)/.kernel-mods

# boot the UKI directly in OVMF (no encryption) and assert it reaches Alpine userspace — proves
# the UKI itself is bootable, independent of the §E5 decrypt path (which decrypt-boot-check covers).
boot-check: uki
	@echo "--- §H1 decoy UKI direct-boot (OVMF) ---"
	@cd $(BLD) && rm -f esp-uki.img serial-uki.log && dd if=/dev/zero of=esp-uki.img bs=1M count=64 status=none && \
	  mformat -i esp-uki.img -F :: && mmd -i esp-uki.img ::/EFI ::/EFI/BOOT && \
	  mcopy -i esp-uki.img decoy-uki.efi ::/EFI/BOOT/BOOTX64.EFI && \
	  cp /usr/share/OVMF/OVMF_VARS_4M.fd vars-uki.fd && \
	  timeout 70 qemu-system-x86_64 -enable-kvm -m 1024 \
	    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
	    -drive if=pflash,format=raw,file=vars-uki.fd \
	    -drive file=esp-uki.img,format=raw,if=ide \
	    -serial file:serial-uki.log -display none -no-reboot >/dev/null 2>&1 || true; \
	  tr -d '\0' < serial-uki.log | grep -aq 'DECOY-INIT-OK' && echo "  [PASS] decoy UKI boots real Alpine Linux to userspace" || { echo "  [FAIL] UKI did not reach userspace"; exit 1; }

# ── §H1 desktop variant: believable rootfs + XFCE, autologin, rendering caches ──────────────
$(DROOT)/.stamp: $(DL)/$(MINIROOT) $(BLD)/apk.static $(BLD)/fakelogd stage-apps.sh $(APP_FILES) customize.sh customize-desktop.sh | $(BLD)
	$(SUDO) rm -rf $(DROOT)
	mkdir -p $(DROOT)
	$(SUDO) tar -xzf $(DL)/$(MINIROOT) -C $(DROOT)
	$(SUDO) $(BLD)/apk.static --root $(DROOT) --repository $(APKMAIN) --repository $(APKCOMM) \
	    --no-scripts --no-cache --update-cache add $(DECOY_PKGS) $(DESKTOP_PKGS) $(SYNTH_PKGS) $(RECLAIM_PKGS) $(DETECTOR_PKGS)
	$(SUDO) env DECOY_USER='$(DECOY_USER)' DECOY_HOSTNAME='$(DECOY_HOSTNAME)' \
	    DECOY_USER_FULLNAME='$(DECOY_USER_FULLNAME)' DECOY_USER_PASSWORD='$(DECOY_USER_PASSWORD)' \
	    DECOY_NOW='$(DECOY_NOW)' $(SELF)/customize.sh $(DROOT) $(BLD)/fakelogd "$(DECOY_PW)"
	$(SUDO) env DECOY_USER='$(DECOY_USER)' DECOY_HOSTNAME='$(DECOY_HOSTNAME)' \
	    $(SELF)/customize-desktop.sh $(DROOT)
	$(SUDO) $(SELF)/stage-apps.sh $(DROOT)
	$(SUDO) touch $(DROOT)/.stamp
	@echo "[decoy-os] desktop rootfs built ($$($(SUDO) du -sh $(DROOT)|cut -f1))"
desktop-rootfs: $(DROOT)/.stamp

# pack the desktop rootfs into an ext4 image sized to the visible disk (§H3), + a module-carrying
# initramfs that reaches the ext4 root on virtio-blk.
KVER = $(shell $(SUDO) sh -c 'ls $(DROOT)/lib/modules 2>/dev/null | head -1')
desktop-image: desktop-rootfs $(DROOT)/.kernel-mods $(BLD)/vmlinuz-decoy
	$(SUDO) rm -f $(BLD)/decoy-desktop.ext4
	$(SUDO) sh -c 'dd if=/dev/zero of=$(BLD)/decoy-desktop.ext4 bs=1M count=$(DESKTOP_MB) status=none && \
	  mkfs.ext4 -q -L decoyroot -d $(DROOT) $(BLD)/decoy-desktop.ext4'
	@# vmlinuz-decoy IS the from-scratch kernel (built by its own rule); nothing to copy from the rootfs
	$(SUDO) chown $(UGID) $(BLD)/decoy-desktop.ext4
	@# module-carrying initramfs (Alpine .ko.gz -> gunzip -> /mod; init-disk multi-pass insmods)
	@$(SUDO) rm -rf $(BLD)/dir && mkdir -p $(BLD)/dir/bin $(BLD)/dir/mod $(BLD)/dir/proc $(BLD)/dir/sys $(BLD)/dir/dev $(BLD)/dir/sysroot
	@cp $(BLD)/busybox.static $(BLD)/dir/bin/busybox
	@cp $(SELF)/initramfs/init-disk $(BLD)/dir/init && chmod +x $(BLD)/dir/init
	@set -e; M=$(DROOT)/lib/modules/$(KVER)/kernel; for name in virtio virtio_ring \
	   virtio_pci_modern_dev virtio_pci_legacy_dev virtio_pci virtio_blk crc16 crc32c_generic \
	   libcrc32c mbcache jbd2 ext4; do \
	   f=$$($(SUDO) find $$M -name "$$name.ko.gz" 2>/dev/null | head -1); \
	   [ -n "$$f" ] && $(SUDO) sh -c "gunzip -c '$$f' > $(BLD)/dir/mod/$$name.ko" || true; done
	@$(SUDO) chown -R $(UGID) $(BLD)/dir
	@( cd $(BLD)/dir && find . | $(BLD)/busybox.static cpio -o -H newc 2>/dev/null | gzip > $(BLD)/initramfs-decoy.gz )
	@echo "[decoy-os] desktop image: decoy-desktop.ext4 ($(DESKTOP_MB) MiB) + initramfs-decoy.gz + vmlinuz-decoy (kver $(KVER))"

# boot the desktop image in QEMU and assert a real desktop RENDERED — a failed session leaves a
# flat solid colour (near-zero variance); a painted XFCE desktop (wallpaper+panel) has high
# variance. -vga virtio so screendump captures the DRM scanout, not just the legacy VGA plane.
desktop-boot-check: desktop-image
	@echo "--- §H1 decoy XFCE desktop boot (direct kernel boot, QMP screendump) ---"
	@$(SELF)/desktop-boot-check.sh $(BLD)

# ── §E5d/§H1 Level 2 — the decoy XFCE desktop booted through the pre-boot loader ────────────
# The believable rootfs is too big to embed, so it stays XTS-encrypted on the install disk and a
# dm-crypt-capable UKI (init-crypt) mounts it after the loader hands the master key + geometry
# forward on the kernel command line. These targets build that UKI and prove the crypt-mount →
# XFCE boot HEADLESS (direct kernel boot, key passed on -append) before any real install.

# static dmsetup for the initramfs (busybox has no dmsetup applet)
$(BLD)/dmsetup.static: | $(BLD)
	@DM=$$(curl -fsSL $(APKMAIN)/$(ALPINE_ARCH)/ | grep -oE 'device-mapper-static-[0-9][0-9.p_r-]+\.apk' | head -1); \
	  test -n "$$DM" || { echo "[decoy-os] cannot find device-mapper-static in repo index"; exit 1; }; \
	  echo "[decoy-os] fetching $$DM"; \
	  rm -rf $(BLD)/dmtmp && mkdir -p $(BLD)/dmtmp; \
	  curl -fsSL "$(APKMAIN)/$(ALPINE_ARCH)/$$DM" | tar -xz -C $(BLD)/dmtmp 2>/dev/null || true; \
	  f=$$(find $(BLD)/dmtmp \( -name 'dmsetup.static' -o -name 'dmsetup' \) -type f 2>/dev/null | head -1); \
	  test -n "$$f" || { echo "[decoy-os] dmsetup not found inside device-mapper-static apk"; exit 1; }; \
	  cp "$$f" $@; chmod +x $@; echo "[decoy-os] dmsetup.static ready ($$(du -h $@|cut -f1))"

# crypt initramfs: busybox + static dmsetup + init-crypt + the storage/crypt/fs modules needed to
# reach an ENCRYPTED ext4 root on AHCI (VirtualBox/real HW) or virtio (QEMU test).
# dm-crypt's FULL load-time closure (from modules.dep) + the storage + the runtime crypto for
# aes-xts-plain64. NB dm-crypt.ko hard-depends on encrypted-keys/trusted/asn1_encoder/tpm/rng-core
# (kernel keyring), which must all insmod before it, or the "crypt" target never registers.
# STORAGE IS THE WHOLE POINT: this initramfs exists to reach the decoy's root, so every
# controller a real machine might use has to be here.  The set below was virtio + IDE/AHCI only,
# with NO NVMe -- so on any modern laptop (an NVMe SSD) init-crypt found no block device at all,
# printed NO-DISK and dropped to a shell: the decoy "tried to boot and wouldn't", while the hidden
# OS (whose kernel has its own drivers) came up fine.  nvme/nvme-core fix that; the USB and
# virtio-scsi entries cover install sticks and the other common hypervisor configuration.
# INPUT drivers are in this list deliberately.  The decoy booted to a full XFCE desktop with a
# cursor that could not move and a system that took no keystrokes: i8042/atkbd/serio are built into
# this kernel, so the PS/2 keyboard worked, but psmouse (the PS/2 mouse) and usbhid/hid-generic
# (every USB keyboard and mouse) are MODULES, and the rootfs only lists bochs/virtio_gpu/evdev in
# /etc/modules.  Nothing ever loaded them -- busybox mdev does not autoload by modalias the way
# udev does -- so on real hardware, where keyboard and mouse are both USB, the decoy came up
# completely dead.  Loading them here means console input does not depend on a rootfs service that
# can (and does) fail: `modloop failed to start` is printed twice on every boot.
CRYPT_MODS = virtio virtio_ring virtio_pci_modern_dev virtio_pci_legacy_dev virtio_pci virtio_blk \
  virtio_scsi ata_piix ahci libahci libata scsi_mod sd_mod sr_mod cdrom \
  nvme-core nvme nvme-common t10-pi \
  usb-common usbcore xhci-pci-renesas xhci-pci xhci-hcd ehci-pci ehci-hcd uas usb-storage \
  crc16 crc32c_generic crc32c-intel crc64 crc64-rocksoft libcrc32c mbcache jbd2 ext4 \
  rng-core tpm asn1_encoder trusted encrypted-keys dm-mod dm-crypt \
  evdev psmouse hid hid-generic usbhid i2c-hid hid-multitouch \
  libaes aes_generic aesni-intel crypto_simd cryptd xts ecb gf128mul \
  squashfs overlay loop
$(BLD)/initramfs-crypt.gz: $(BLD)/busybox.static $(BLD)/dmsetup.static initramfs/init-crypt $(DROOT)/.kernel-mods | $(BLD)
	@$(SUDO) rm -rf $(BLD)/crdir && mkdir -p $(BLD)/crdir/bin $(BLD)/crdir/mod $(BLD)/crdir/proc $(BLD)/crdir/sys $(BLD)/crdir/dev $(BLD)/crdir/sysroot
	@cp $(BLD)/busybox.static $(BLD)/crdir/bin/busybox
	@cp $(BLD)/dmsetup.static $(BLD)/crdir/bin/dmsetup
	@cp $(SELF)/initramfs/init-crypt $(BLD)/crdir/init && chmod +x $(BLD)/crdir/init
	@# X input driver for a rootfs with no udevd -- see initramfs/README-evdev.md.
	@cp $(SELF)/initramfs/evdev_drv.so $(BLD)/crdir/evdev_drv.so
	@# Modules are a MIX of .ko.gz (drivers) and .ko (crypto) in this rootfs — handle both.
	@# Take the DEPENDENCY CLOSURE from the kernel's own modules.dep, not the names above:
	@# busybox insmod resolves nothing, so a module whose dependency is absent silently never
	@# loads -- which is how this initramfs ended up with no scsi_mod/libata/ahci and no nvme at
	@# all, and the decoy found no disk on real hardware.  Numbered so insmod order is satisfiable.
	@set -e; MR=$(DROOT)/lib/modules/$(KVER); n=0; \
	 python3 $(PROJECT_ROOT)/scripts/decoy-initramfs-mods.py $$MR $(CRYPT_MODS) | while read -r f; do \
	   n=$$((n+1)); b=$$(basename "$$f"); b=$${b%.gz}; b=$${b%.ko}; \
	   case "$$f" in *.gz) gunzip -c "$$f" > $(BLD)/crdir/mod/$$(printf '%02d' $$n)-$$b.ko ;; \
	                 *)    cp "$$f" $(BLD)/crdir/mod/$$(printf '%02d' $$n)-$$b.ko ;; esac; \
	 done
	@$(SUDO) chown -R $(UGID) $(BLD)/crdir
	@( cd $(BLD)/crdir && find . | $(BLD)/busybox.static cpio -o -H newc 2>/dev/null | gzip > $(BLD)/initramfs-crypt.gz )
	@echo "[decoy-os] built initramfs-crypt.gz ($$(du -h $(BLD)/initramfs-crypt.gz|cut -f1)), $$(ls $(BLD)/crdir/mod|wc -l) modules"

# The production decoy desktop UKI: vmlinuz + crypt initramfs. No key in the embedded cmdline —
# the pre-boot loader appends decoykey=/decoyrl=/decoyiv=/decoysz= via EFI LoadOptions.
$(BLD)/decoy-crypt-uki.efi: $(BLD)/vmlinuz-decoy $(BLD)/initramfs-crypt.gz | $(BLD)
	@test -f $(UKI_STUB) || { echo "[decoy-os] missing $(UKI_STUB) — apt install systemd-boot-efi systemd-ukify"; exit 1; }
	ukify build --linux=$(BLD)/vmlinuz-decoy --initrd=$(BLD)/initramfs-crypt.gz \
	    --cmdline="console=tty0 console=ttyS0,115200 rw rdinit=/init loglevel=4" --stub=$(UKI_STUB) --output=$@
	@echo "[decoy-os] built decoy-crypt-uki.efi ($$(du -h $@|cut -f1)) — the believable XFCE decoy, dm-crypt on-disk root"
crypt-uki: $(BLD)/decoy-crypt-uki.efi

# The decoy region the installer writes at sysFirst+1: [ANOSBOOT descriptor][desktop UKI][encrypted
# rootfs]. The installer XTS-encrypts these bytes as-is (no code change — it already streams this
# module), the pre-boot loader decrypts the UKI and hands init-crypt the rootfs geometry. This
# replaces the old raw-ext4 decoy image as cd/decoy-linux.ext4 for a Level-2 (desktop) install.
# Compress the full desktop rootfs into a squashfs so the installer's in-RAM boot module is ~1 GB
# instead of the 2.4 GB raw ext4 (limine cannot practically load a 3 GB module — OOM/stall). The
# Linux kernel decompresses squashfs at mount time (init-crypt), so the decoy keeps every file.
$(BLD)/decoy-desktop.squashfs: desktop-rootfs $(DROOT)/.kernel-mods | $(BLD)
	@command -v mksquashfs >/dev/null || { echo "[decoy-os] need squashfs-tools (apt install squashfs-tools)"; exit 1; }
	$(SUDO) rm -f $@
	$(SUDO) mksquashfs $(DROOT) $@ -comp zstd -noappend -no-progress -quiet
	$(SUDO) chown $(UGID) $@
	@echo "[decoy-os] built decoy-desktop.squashfs ($$(du -h $@|cut -f1)) — full desktop, compressed"
squashfs: $(BLD)/decoy-desktop.squashfs

$(BLD)/decoy-boot.img: $(BLD)/decoy-crypt-uki.efi $(BLD)/decoy-desktop.squashfs wrap-decoy-payload.py | $(BLD)
	python3 $(SELF)/wrap-decoy-payload.py $(BLD)/decoy-crypt-uki.efi $(BLD)/decoy-desktop.squashfs $@
decoy-boot: $(BLD)/decoy-boot.img

# Prove it headless: encrypt decoy-desktop.ext4 with dm-crypt (definitionally aes-xts-plain64),
# direct-kernel-boot the crypt initramfs with the key on the cmdline, assert XFCE rendered.
crypt-boot-check: $(BLD)/vmlinuz-decoy $(BLD)/initramfs-crypt.gz $(BLD)/decoy-desktop.squashfs
	@echo "--- §H1 Level 2: decoy XFCE from an ENCRYPTED squashfs root (dm-crypt+overlay, QMP screendump) ---"
	@$(SELF)/crypt-boot-check.sh $(BLD)

# Pack the rootfs into an ext4 image for the installer to encrypt into the decoy system partition.
# DECOY_IMG_MB sizes the filesystem the decoy will believe it owns (§H3 disk-illusion — the
# installer passes the visible-disk size so `df` shows the whole disk, no hidden-volume gap).
image: rootfs
	$(SUDO) rm -f $(BLD)/decoy.ext4
	$(SUDO) sh -c 'dd if=/dev/zero of=$(BLD)/decoy.ext4 bs=1M count=$(DECOY_IMG_MB) status=none && \
	  mkfs.ext4 -q -L decoy -d $(ROOTFS) $(BLD)/decoy.ext4'
	$(SUDO) chown $(UGID) $(BLD)/decoy.ext4
	@echo "[decoy-os] built $(BLD)/decoy.ext4 ($(DECOY_IMG_MB) MiB)"

verify: rootfs
	@echo "--- §H1 decoy rootfs verify ---"
	@grep -qi alpine $(ROOTFS)/etc/os-release && echo "  [PASS] real distro ($$(. $(ROOTFS)/etc/os-release; echo $$PRETTY_NAME))" || echo "  [FAIL] no os-release"
	@test -x $(ROOTFS)/bin/busybox && echo "  [PASS] busybox userland + apk present" || echo "  [FAIL] no userland"
	@test -s $(ROOTFS)/var/log/messages && test -s $(ROOTFS)/var/log/auth.log && echo "  [PASS] /var/log seeded ($$(wc -l < $(ROOTFS)/var/log/messages) syslog + $$(wc -l < $(ROOTFS)/var/log/auth.log) auth lines)" || echo "  [FAIL] logs not seeded"
	@grep -q "^$(DECOY_USER):" $(ROOTFS)/etc/passwd && echo "  [PASS] user account present" || echo "  [FAIL] no user"
	@test -s $(ROOTFS)/home/$(DECOY_USER)/.bash_history && echo "  [PASS] shell history present" || echo "  [FAIL] no bash_history"

# §H1/E7 believability — INTERNAL CONSISTENCY. A coerced examiner who has the decoy password
# and root must find nothing that contradicts "an ordinary, used workstation". Each check here
# is a specific decoy tell if it fails.
consistency: rootfs
	@echo "--- §H1 decoy internal-consistency ---"
	@R=$(ROOTFS); U=$(DECOY_USER); Hh=$$R/home/$$U; fail=0; \
	  grep -qE '^[0-9a-f]{32}$$' $$R/etc/machine-id && echo "  [PASS] machine-id is 32-hex (not the all-zero tell)" || { echo "  [FAIL] machine-id not 32 hex"; fail=1; }; \
	  miss=""; for t in git ssh vim htop tmux curl rsync sudo; do \
	    find $$R/usr/bin $$R/bin $$R/usr/sbin $$R/sbin -name $$t 2>/dev/null | grep -q . || miss="$$miss $$t"; done; \
	  [ -z "$$miss" ] && echo "  [PASS] every tool the shell history uses is really installed" || { echo "  [FAIL] history uses uninstalled tools:$$miss"; fail=1; }; \
	  test -d $$Hh/Projects/infra/.git && echo "  [PASS] the git repo the history references exists (real .git)" || { echo "  [FAIL] history references a missing repo"; fail=1; }; \
	  $(SUDO) test -s $$Hh/.ssh/known_hosts && $(SUDO) test -s $$Hh/.ssh/id_ed25519.pub && echo "  [PASS] ssh state (known_hosts + key) matches the ssh history" || { echo "  [FAIL] ssh usage without ssh state"; fail=1; }; \
	  pm=""; for p in $(DECOY_PKGS); do grep -qx "$$p" $$R/etc/apk/world || pm="$$pm $$p"; done; \
	  [ -z "$$pm" ] && echo "  [PASS] apk world records every installed package ($$(wc -l < $$R/etc/apk/world) total)" || { echo "  [FAIL] world missing:$$pm"; fail=1; }; \
	  nt=$$(cut -f1 $$Hh/.bash_history 2>/dev/null; :); \
	  test -f $$Hh/Documents/notes.txt && echo "  [PASS] files the history edits (notes.txt) exist" || { echo "  [FAIL] history edits an absent file"; fail=1; }; \
	  u=$$(ls -l --time-style=+%s $$Hh/.bash_history $$Hh/.gitconfig $$Hh/.vimrc 2>/dev/null | awk '{print $$6}' | sort -u | wc -l); \
	  [ "$$u" -gt 1 ] && echo "  [PASS] file mtimes are varied ($$u distinct), not a uniform build stamp" || { echo "  [FAIL] uniform mtimes (build tell)"; fail=1; }; \
	  [ $$fail -eq 0 ] && echo "  §H1 consistency: PASS" || { echo "  §H1 consistency: FAIL"; exit 1; }

# §H4 hide-in-plain-sight — the decoy must contain NOTHING that reveals it's a decoy or
# that manufactures the fake history (no generator binary/process/cron, no "*decoy*" file,
# no "decoy…" account). Fails loudly on any tell.
h4: rootfs
	@echo "--- §H4 concealment tell-scan ---"
	@n=$$($(SUDO) find $(ROOTFS) -iname 'fakelogd*' -o -iname '*decoy*' 2>/dev/null | wc -l); \
	  [ $$n -eq 0 ] && echo "  [PASS] no generator binary / *decoy* file shipped" || { echo "  [FAIL] tells:"; $(SUDO) find $(ROOTFS) -iname 'fakelogd*' -o -iname '*decoy*' | sed "s#$(ROOTFS)#    #"; }
	@n=$$($(SUDO) grep -rIl -iE 'fakelogd|\bdecoy' $(ROOTFS)/etc $(ROOTFS)/home $(ROOTFS)/var 2>/dev/null | wc -l); \
	  [ $$n -eq 0 ] && echo "  [PASS] no 'decoy'/'fakelogd' string in any config/script/log" || { echo "  [FAIL]:"; $(SUDO) grep -rIl -iE 'fakelogd|\bdecoy' $(ROOTFS)/etc $(ROOTFS)/home $(ROOTFS)/var; }
	@n=$$($(SUDO) grep -rIl -iE 'fakelogd|decoy|fake.?log' $(ROOTFS)/etc/periodic $(ROOTFS)/etc/crontabs $(ROOTFS)/etc/init.d 2>/dev/null | wc -l); \
	  [ $$n -eq 0 ] && echo "  [PASS] no resident generator (cron/init runs nothing suspicious)" || echo "  [FAIL] resident generator"
	@u=$$(cut -d: -f1 $(ROOTFS)/etc/passwd | grep -iE 'decoy|fake' | tr '\n' ' '); \
	  [ -z "$$u" ] && echo "  [PASS] no 'decoy…' account name" || echo "  [FAIL] tell account: $$u"
	@echo "  (go-forward logs come from the real Alpine daemons; the generator ran build-time only)"

clean:
	rm -rf $(BLD)
