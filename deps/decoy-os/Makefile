# deps/decoy-os — build the §H1 decoy Linux distribution (roadmap/INSTALLER.md §H1).
#
# The decoy OS is a REAL Linux distro (Alpine) so it's maximally believable, customized
# into a lived-in workstation and seeded with the §G/§H2 deterministic fake history. The
# resulting rootfs can be packed into decoy.ext4, which the installer encrypts into
# the decoy system partition when Hidden OS is selected.
SELF := $(abspath .)
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

# §H1 believability — a REAL toolchain installed with apk (so `apk info`, `which`, the shell
# history and the /var/log daemons are all CONSISTENT: a workstation that claims git/ssh/vim
# but has none installed is a decoy tell). apk.static installs into the rootfs from the host
# with no chroot (--no-scripts), the Alpine-supported way to build a rootfs from a foreign OS.
DECOY_PKGS ?= openssh git vim htop tmux curl wget chrony bash sudo less tree rsync nano \
              tcpdump bind-tools mtr iproute2 file jq man-db docs

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

.PHONY: rootfs image verify consistency h4 uki boot-check desktop-rootfs desktop-image desktop-boot-check clean

# §H1 desktop cover story — a graphical XFCE daily-driver decoy. The CLI believability set stays;
# these add a real Xorg + XFCE + Firefox stack (so booting the decoy lands in Alex's desktop).
DROOT       := $(BLD)/desktop-rootfs
DESKTOP_MB  ?= 3072
DESKTOP_PKGS ?= alpine-base linux-lts xorg-server xf86-input-libinput xf86-video-modesetting \
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

$(BLD)/decoy-rootfs.tar.gz: $(DL)/$(MINIROOT) $(BLD)/apk.static $(BLD)/fakelogd customize.sh | $(BLD)
	$(SUDO) rm -rf $(ROOTFS)
	mkdir -p $(ROOTFS)
	$(SUDO) tar -xzf $(DL)/$(MINIROOT) -C $(ROOTFS)
	$(SUDO) $(BLD)/apk.static --root $(ROOTFS) --repository $(APKMAIN) --repository $(APKCOMM) \
	    --no-scripts --no-cache --update-cache add $(DECOY_PKGS)
	$(SUDO) env DECOY_USER='$(DECOY_USER)' DECOY_HOSTNAME='$(DECOY_HOSTNAME)' \
	    DECOY_USER_FULLNAME='$(DECOY_USER_FULLNAME)' DECOY_USER_PASSWORD='$(DECOY_USER_PASSWORD)' \
	    DECOY_NOW='$(DECOY_NOW)' $(SELF)/customize.sh $(ROOTFS) $(BLD)/fakelogd "$(DECOY_PW)"
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
$(DROOT)/.stamp: $(DL)/$(MINIROOT) $(BLD)/apk.static $(BLD)/fakelogd customize.sh customize-desktop.sh | $(BLD)
	$(SUDO) rm -rf $(DROOT)
	mkdir -p $(DROOT)
	$(SUDO) tar -xzf $(DL)/$(MINIROOT) -C $(DROOT)
	$(SUDO) $(BLD)/apk.static --root $(DROOT) --repository $(APKMAIN) --repository $(APKCOMM) \
	    --no-scripts --no-cache --update-cache add $(DECOY_PKGS) $(DESKTOP_PKGS)
	$(SUDO) env DECOY_USER='$(DECOY_USER)' DECOY_HOSTNAME='$(DECOY_HOSTNAME)' \
	    DECOY_USER_FULLNAME='$(DECOY_USER_FULLNAME)' DECOY_USER_PASSWORD='$(DECOY_USER_PASSWORD)' \
	    DECOY_NOW='$(DECOY_NOW)' $(SELF)/customize.sh $(DROOT) $(BLD)/fakelogd "$(DECOY_PW)"
	$(SUDO) env DECOY_USER='$(DECOY_USER)' DECOY_HOSTNAME='$(DECOY_HOSTNAME)' \
	    $(SELF)/customize-desktop.sh $(DROOT)
	$(SUDO) touch $(DROOT)/.stamp
	@echo "[decoy-os] desktop rootfs built ($$($(SUDO) du -sh $(DROOT)|cut -f1))"
desktop-rootfs: $(DROOT)/.stamp

# pack the desktop rootfs into an ext4 image sized to the visible disk (§H3), + a module-carrying
# initramfs that reaches the ext4 root on virtio-blk.
KVER = $(shell $(SUDO) sh -c 'ls $(DROOT)/lib/modules 2>/dev/null | head -1')
desktop-image: desktop-rootfs
	$(SUDO) rm -f $(BLD)/decoy-desktop.ext4
	$(SUDO) sh -c 'dd if=/dev/zero of=$(BLD)/decoy-desktop.ext4 bs=1M count=$(DESKTOP_MB) status=none && \
	  mkfs.ext4 -q -L decoyroot -d $(DROOT) $(BLD)/decoy-desktop.ext4'
	$(SUDO) cp $(DROOT)/boot/vmlinuz-lts $(BLD)/vmlinuz-decoy
	$(SUDO) chown $(UGID) $(BLD)/decoy-desktop.ext4 $(BLD)/vmlinuz-decoy
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
