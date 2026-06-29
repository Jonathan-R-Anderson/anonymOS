# deps/decoy-os — build the §H1 decoy Linux distribution (roadmap/INSTALLER.md §H1).
#
# The decoy OS is a REAL Linux distro (Alpine) so it's maximally believable, customized
# into a lived-in workstation and seeded with the §G/§H2 deterministic fake history. The
# resulting rootfs tarball is what the installer (E4c) clones into the encrypted system
# partition + the EFI loader (§E5) chain-loads (replacing the stage2.efi stub).
SELF := $(abspath .)
BLD  := $(SELF)/build
DL   := $(SELF)/dl
CC   ?= cc

ALPINE_VER  := 3.19.9
ALPINE_ARCH := x86_64
MINIROOT    := alpine-minirootfs-$(ALPINE_VER)-$(ALPINE_ARCH).tar.gz
URL         := https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/$(ALPINE_ARCH)/$(MINIROOT)

# a real install reseeds with the user's decoy password
DECOY_PW ?= decoy-password
# The decoy OS's own settings — supplied by the installer (§E6 hidden-OS step) in the SAME
# flow; defaulted here for the standalone build, exported so customize.sh picks them up.
DECOY_USER     ?= decoyuser
DECOY_HOSTNAME ?= helix
export DECOY_USER DECOY_HOSTNAME DECOY_USER_FULLNAME DECOY_USER_PASSWORD DECOY_NOW
DECOY    := ../decoy
ROOTFS   := $(BLD)/rootfs

.PHONY: rootfs image verify clean
rootfs: $(BLD)/decoy-rootfs.tar.gz

$(BLD) $(DL):
	@mkdir -p $@

$(DL)/$(MINIROOT): | $(DL)
	curl -fL -o $@ $(URL)

# the §H2 fake-log generator (built standalone here to avoid the cross-Makefile self-test)
$(BLD)/fakelogd: $(DECOY)/decoy.c $(DECOY)/decoy_render.c $(DECOY)/h2/fakelogd.c | $(BLD)
	$(CC) -O2 -I$(DECOY) $^ -o $@

$(BLD)/decoy-rootfs.tar.gz: $(DL)/$(MINIROOT) $(BLD)/fakelogd customize.sh | $(BLD)
	@rm -rf $(ROOTFS); mkdir -p $(ROOTFS)
	fakeroot -s $(BLD)/fakeroot.db sh -c '\
	  tar -xzf $(DL)/$(MINIROOT) -C $(ROOTFS) && \
	  $(SELF)/customize.sh $(ROOTFS) $(BLD)/fakelogd "$(DECOY_PW)" && \
	  tar -czf $@ -C $(ROOTFS) .'
	@echo "[decoy-os] built $@ ($$(du -h $@ | cut -f1)), seeded with the §H2 fake history"

# pack the rootfs into an ext4 image for the installer (E4c clones this into the system part.)
image: rootfs
	@rm -f $(BLD)/decoy.ext4
	fakeroot -i $(BLD)/fakeroot.db sh -c 'dd if=/dev/zero of=$(BLD)/decoy.ext4 bs=1M count=256 status=none && \
	  mkfs.ext4 -q -L decoy -d $(ROOTFS) $(BLD)/decoy.ext4'
	@echo "[decoy-os] built $(BLD)/decoy.ext4"

verify: rootfs
	@echo "--- §H1 decoy rootfs verify ---"
	@grep -qi alpine $(ROOTFS)/etc/os-release && echo "  [PASS] real distro ($$(. $(ROOTFS)/etc/os-release; echo $$PRETTY_NAME))" || echo "  [FAIL] no os-release"
	@test -x $(ROOTFS)/bin/busybox && echo "  [PASS] busybox userland + apk present" || echo "  [FAIL] no userland"
	@test -s $(ROOTFS)/var/log/messages && test -s $(ROOTFS)/var/log/auth.log && echo "  [PASS] /var/log seeded ($$(wc -l < $(ROOTFS)/var/log/messages) syslog + $$(wc -l < $(ROOTFS)/var/log/auth.log) auth lines)" || echo "  [FAIL] logs not seeded"
	@grep -q "^$(DECOY_USER):" $(ROOTFS)/etc/passwd && echo "  [PASS] user account present" || echo "  [FAIL] no user"
	@test -s $(ROOTFS)/home/$(DECOY_USER)/.bash_history && echo "  [PASS] shell history present" || echo "  [FAIL] no bash_history"

clean:
	rm -rf $(BLD)
