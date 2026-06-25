# Vendored upstream `-sh` — a native-D Lisp/LFE interpreter, the AnonymOS native-personality shell.
# Pinned snapshot of github.com/Jonathan-R-Anderson/-sh.  L1 of ZSH_INTEGRATION_ROADMAP.md.
# Mirrors deps/zsh/ : a cached, sha256-pinned source tarball that a Makefile unpacks + builds.
LFE_COMMIT := a44ee38bfa8771f665d1a39590325a29b328d045
LFE_TAR    := lfe-sh-a44ee38bfa87.tar.gz
LFE_SHA    := 28ca96a57ef470f28d5a488fd95e8c375f7022e7a210d2d4525839dc333eaf26
SRCDIR     := lfe-sh
DC         ?= ldc2

.PHONY: all host-build clean

# L1 default: unpack + checksum-verify the pinned source (the vendoring itself).
all: $(SRCDIR)/Makefile

$(SRCDIR)/Makefile: $(LFE_TAR)
	echo "$(LFE_SHA)  $(LFE_TAR)" | sha256sum -c -
	rm -rf $(SRCDIR) && tar xf $(LFE_TAR)
	@echo "vendored -sh source unpacked at $(SRCDIR)/ (pinned $(LFE_COMMIT))"

# Host sanity build (full-D Phobos + libreadline) — validates the vendored source compiles with the
# same ldc2 the kernel uses.  The OS build is a SEPARATE concern (L2): an ldc2 musl triple with
# Phobos/druntime + replacing libreadline with the OS PTY line input (hos-sh-style); NOT wired here.
host-build: all
	cd $(SRCDIR) && $(DC) $$(find src -name '*.d') -L-lreadline -of=lfe-sh
	@echo "host lfe-sh built: $(SRCDIR)/lfe-sh"

clean:
	rm -rf $(SRCDIR)
