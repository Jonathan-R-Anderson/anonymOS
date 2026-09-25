CLANG   ?= clang
CC      ?= gcc
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

SRC     = src
BPF_SRC = src/bpf

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I/usr/include/$(shell uname -m)-linux-gnu \
              -I$(BPF_SRC) -I$(SRC)
CFLAGS     := -g -Wall -I$(SRC) -I$(BPF_SRC)

# Optional OpenSSL — detected automatically via pkg-config; used for TLS forwarding
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)
ifneq ($(OPENSSL_LIBS),)
CFLAGS += -DHAVE_OPENSSL $(shell pkg-config --cflags openssl 2>/dev/null)
endif

# Optional YARA — detected automatically; used for in-process rule scanning
YARA_LIBS := $(shell pkg-config --libs yara 2>/dev/null)
ifneq ($(YARA_LIBS),)
CFLAGS += -DHAVE_YARA $(shell pkg-config --cflags yara 2>/dev/null)
else
YARA_LIBS :=
endif

# Optional SQLite3 — used for persistent event store
SQLITE_LIBS := $(shell pkg-config --libs sqlite3 2>/dev/null)
ifneq ($(SQLITE_LIBS),)
CFLAGS += -DHAVE_SQLITE3 $(shell pkg-config --cflags sqlite3 2>/dev/null)
else
SQLITE_LIBS :=
endif

# Seccomp — present on Linux kernels; gracefully absent on non-Linux
HAVE_SECCOMP := $(shell test -f /usr/include/linux/seccomp.h && echo yes)
# (seccomp.c guards itself with #ifdef __linux__ so no extra CFLAGS needed)

PREFIX      ?= /usr/local
BINDIR       = $(DESTDIR)$(PREFIX)/bin
UNITDIR      = $(DESTDIR)/etc/systemd/system
TMPFILESDIR  = $(DESTDIR)/usr/lib/tmpfiles.d
LOGROTATEDIR = $(DESTDIR)/etc/logrotate.d
MANDIR       = $(DESTDIR)$(PREFIX)/share/man/man8

VERSION     := $(shell grep 'ARGUS_VERSION' $(SRC)/argus.h | sed 's/.*"\(.*\)".*/\1/')
ARCH_PKG    := $(shell uname -m)

.PHONY: all clean test test-unit test-integration test-asan install uninstall deb rpm man bench

all: argus argus-server

# 1. Generate vmlinux.h from the running kernel's BTF
$(BPF_SRC)/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# 2. Compile the BPF program to BPF ELF
$(BPF_SRC)/argus.bpf.o: $(BPF_SRC)/argus.bpf.c $(BPF_SRC)/vmlinux.h $(SRC)/argus.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# 3. Generate the libbpf skeleton header
$(BPF_SRC)/argus.skel.h: $(BPF_SRC)/argus.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# 4. Compile the userspace loader
ARGUS_SRCS = \
    $(SRC)/argus.c $(SRC)/output.c $(SRC)/lineage.c $(SRC)/config.c \
    $(SRC)/rules.c $(SRC)/forward.c $(SRC)/dns.c $(SRC)/baseline.c \
    $(SRC)/seccomp.c $(SRC)/metrics.c $(SRC)/fim.c $(SRC)/ldpreload.c \
    $(SRC)/threatintel.c $(SRC)/canary.c $(SRC)/dedup.c $(SRC)/hollow.c \
    $(SRC)/beacon.c $(SRC)/seqdetect.c $(SRC)/yara_scan.c \
    $(SRC)/mitre.c $(SRC)/webhook.c $(SRC)/exechash.c $(SRC)/isolate.c \
    $(SRC)/memforensics.c $(SRC)/store.c $(SRC)/iocenrich.c \
    $(SRC)/container.c $(SRC)/compliance.c $(SRC)/syscallanom.c

ARGUS_HDRS = \
    $(SRC)/argus.h $(SRC)/output.h $(SRC)/lineage.h $(SRC)/config.h \
    $(SRC)/rules.h $(SRC)/forward.h $(SRC)/dns.h $(SRC)/baseline.h \
    $(SRC)/seccomp.h $(SRC)/metrics.h $(SRC)/fim.h $(SRC)/ldpreload.h \
    $(SRC)/threatintel.h $(SRC)/canary.h $(SRC)/dedup.h $(SRC)/hollow.h \
    $(SRC)/beacon.h $(SRC)/seqdetect.h $(SRC)/yara_scan.h \
    $(SRC)/mitre.h $(SRC)/webhook.h $(SRC)/exechash.h $(SRC)/isolate.h \
    $(SRC)/memforensics.h $(SRC)/store.h $(SRC)/iocenrich.h \
    $(SRC)/container.h $(SRC)/compliance.h $(SRC)/syscallanom.h \
    $(BPF_SRC)/argus.skel.h

argus: $(ARGUS_SRCS) $(ARGUS_HDRS)
	$(CC) $(CFLAGS) -o $@ $(ARGUS_SRCS) \
	    -lbpf -lelf -lz -lpthread -lm \
	    $(OPENSSL_LIBS) $(YARA_LIBS) $(SQLITE_LIBS)

# 5. Fleet aggregator — no BPF dependency
argus-server: $(SRC)/argus-server.c $(SRC)/argus.h
	$(CC) $(CFLAGS) -o $@ $(SRC)/argus-server.c -lpthread

# ── unit tests (no BPF, no root) ──────────────────────────────────────────────

COMMON_SRCS = $(SRC)/output.c $(SRC)/lineage.c $(SRC)/dns.c $(SRC)/metrics.c
COMMON_HDRS = $(SRC)/output.h $(SRC)/lineage.h $(SRC)/dns.h $(SRC)/metrics.h $(SRC)/argus.h

tests/test_lineage: tests/test_lineage.c $(SRC)/lineage.c $(SRC)/lineage.h $(SRC)/argus.h
	$(CC) $(CFLAGS) -o $@ tests/test_lineage.c $(SRC)/lineage.c

tests/test_output: tests/test_output.c $(COMMON_SRCS) $(COMMON_HDRS)
	$(CC) $(CFLAGS) -o $@ tests/test_output.c $(COMMON_SRCS) -lpthread

tests/test_rules: tests/test_rules.c $(SRC)/rules.c $(COMMON_SRCS) \
                  $(SRC)/rules.h $(COMMON_HDRS)
	$(CC) $(CFLAGS) -o $@ tests/test_rules.c $(SRC)/rules.c $(COMMON_SRCS) -lpthread -lbpf

tests/test_forward: tests/test_forward.c $(SRC)/forward.c $(COMMON_SRCS) \
                    $(SRC)/forward.h $(COMMON_HDRS)
	$(CC) $(CFLAGS) -o $@ tests/test_forward.c $(SRC)/forward.c $(COMMON_SRCS) -lpthread $(OPENSSL_LIBS)

tests/test_baseline: tests/test_baseline.c $(SRC)/baseline.c $(COMMON_SRCS) \
                     $(SRC)/baseline.h $(COMMON_HDRS)
	$(CC) $(CFLAGS) -o $@ tests/test_baseline.c $(SRC)/baseline.c $(COMMON_SRCS) -lpthread

tests/test_metrics: tests/test_metrics.c $(SRC)/metrics.c $(SRC)/argus.h $(SRC)/metrics.h
	$(CC) $(CFLAGS) -o $@ tests/test_metrics.c $(SRC)/metrics.c -lpthread

tests/test_fim: tests/test_fim.c $(SRC)/fim.c $(SRC)/fim.h $(SRC)/argus.h
	$(CC) $(CFLAGS) -o $@ tests/test_fim.c $(SRC)/fim.c

tests/test_netcorr: tests/test_netcorr.c $(SRC)/threatintel.c $(SRC)/threatintel.h $(SRC)/argus.h
	$(CC) $(CFLAGS) -o $@ tests/test_netcorr.c $(SRC)/threatintel.c -lpthread -lbpf -lm

tests/test_enterprise: tests/test_enterprise.c \
                       $(SRC)/output.c $(SRC)/lineage.c $(SRC)/dns.c $(SRC)/metrics.c \
                       $(SRC)/compliance.c \
                       $(SRC)/output.h $(SRC)/compliance.h $(SRC)/argus.h
	$(CC) $(CFLAGS) -o $@ tests/test_enterprise.c \
	    $(SRC)/output.c $(SRC)/lineage.c $(SRC)/dns.c $(SRC)/metrics.c \
	    $(SRC)/compliance.c \
	    -lpthread

test-unit: tests/test_lineage tests/test_output tests/test_rules \
           tests/test_forward tests/test_baseline tests/test_metrics \
           tests/test_fim tests/test_netcorr tests/test_enterprise
	@echo "── lineage ──────────────────────────────────"
	@./tests/test_lineage
	@echo "── output / filter ──────────────────────────"
	@./tests/test_output
	@echo "── alert rules ──────────────────────────────"
	@./tests/test_rules
	@echo "── forwarding ───────────────────────────────"
	@./tests/test_forward
	@echo "── baseline / anomaly ───────────────────────"
	@./tests/test_baseline
	@echo "── metrics ──────────────────────────────────"
	@./tests/test_metrics
	@echo "── FIM ──────────────────────────────────────"
	@./tests/test_fim
	@echo "── DNS correlation / entropy ────────────────"
	@./tests/test_netcorr
	@echo "── enterprise modules (v0.4.0) ──────────────"
	@./tests/test_enterprise

# ── integration test (requires root + built argus binary) ────────────────────
test-integration: argus
	@echo "── filter integration ───────────────────────"
	sudo bash tests/test_filter.sh ./argus

# ── ASAN / UBSan unit tests ───────────────────────────────────────────────
ASAN_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer

tests/test_lineage_asan: tests/test_lineage.c $(SRC)/lineage.c $(SRC)/lineage.h $(SRC)/argus.h
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ tests/test_lineage.c $(SRC)/lineage.c

tests/test_output_asan: tests/test_output.c $(COMMON_SRCS) $(COMMON_HDRS)
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ tests/test_output.c $(COMMON_SRCS) -lpthread

tests/test_rules_asan: tests/test_rules.c $(SRC)/rules.c $(COMMON_SRCS) \
                       $(SRC)/rules.h $(COMMON_HDRS)
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ tests/test_rules.c $(SRC)/rules.c $(COMMON_SRCS) -lpthread -lbpf

tests/test_forward_asan: tests/test_forward.c $(SRC)/forward.c $(COMMON_SRCS) \
                         $(SRC)/forward.h $(COMMON_HDRS)
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ tests/test_forward.c $(SRC)/forward.c $(COMMON_SRCS) -lpthread $(OPENSSL_LIBS)

tests/test_baseline_asan: tests/test_baseline.c $(SRC)/baseline.c $(COMMON_SRCS) \
                          $(SRC)/baseline.h $(COMMON_HDRS)
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ tests/test_baseline.c $(SRC)/baseline.c $(COMMON_SRCS) -lpthread

tests/test_metrics_asan: tests/test_metrics.c $(SRC)/metrics.c $(SRC)/argus.h $(SRC)/metrics.h
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ tests/test_metrics.c $(SRC)/metrics.c -lpthread

test-asan: tests/test_lineage_asan tests/test_output_asan tests/test_rules_asan \
           tests/test_forward_asan tests/test_baseline_asan tests/test_metrics_asan
	@echo "── lineage (ASAN) ───────────────────────────────"
	@./tests/test_lineage_asan
	@echo "── output / filter (ASAN) ───────────────────────"
	@./tests/test_output_asan
	@echo "── alert rules (ASAN) ───────────────────────────"
	@./tests/test_rules_asan
	@echo "── forwarding (ASAN) ────────────────────────────"
	@./tests/test_forward_asan
	@echo "── baseline / anomaly (ASAN) ────────────────────"
	@./tests/test_baseline_asan
	@echo "── metrics (ASAN) ───────────────────────────────"
	@./tests/test_metrics_asan

# ── benchmark ─────────────────────────────────────────────────────────────────

BENCH_SRCS = tools/argus-bench.c $(SRC)/output.c $(SRC)/lineage.c \
             $(SRC)/dns.c $(SRC)/metrics.c

argus-bench: $(BENCH_SRCS) $(COMMON_HDRS)
	$(CC) $(CFLAGS) -o $@ $(BENCH_SRCS) -lpthread

bench: argus-bench
	@echo "Built argus-bench — run with: ./argus-bench [N]"

# Run unit tests only (no root required)
test: test-unit

# ── packaging ──────────────────────────────────────────────────────────────────

# Debian/Ubuntu package — requires dpkg-deb
deb: argus argus-server
	rm -rf pkg/deb
	mkdir -p pkg/deb/DEBIAN
	mkdir -p pkg/deb$(BINDIR)
	mkdir -p pkg/deb$(UNITDIR)
	mkdir -p pkg/deb$(TMPFILESDIR)
	mkdir -p pkg/deb$(LOGROTATEDIR)
	install -m755 argus            pkg/deb$(BINDIR)/argus
	install -m755 argus-server     pkg/deb$(BINDIR)/argus-server
	install -m644 packaging/argus.service         pkg/deb$(UNITDIR)/argus.service
	install -m644 packaging/argus-server.service  pkg/deb$(UNITDIR)/argus-server.service
	install -m644 packaging/argus.tmpfiles        pkg/deb$(TMPFILESDIR)/argus.conf
	install -m644 packaging/argus.logrotate       pkg/deb$(LOGROTATEDIR)/argus
	mkdir -p pkg/deb/etc/bash_completion.d pkg/deb/usr/share/zsh/site-functions \
	         pkg/deb/usr/share/doc/argus
	install -m644 packaging/argus-completion.bash pkg/deb/etc/bash_completion.d/argus
	install -m644 packaging/argus-completion.zsh  pkg/deb/usr/share/zsh/site-functions/_argus
	install -m644 packaging/argus.conf.example    pkg/deb/usr/share/doc/argus/argus.conf.example
	printf 'Package: argus\nVersion: $(VERSION)\nSection: security\nPriority: optional\nArchitecture: $(ARCH_PKG)\nDepends: libbpf0\nMaintainer: argus project\nDescription: eBPF-based syscall telemetry daemon\n argus monitors process execution, file access, network connections\n and security-relevant syscalls via eBPF tracepoints.\n' \
	    > pkg/deb/DEBIAN/control
	install -m755 packaging/debian/postinst pkg/deb/DEBIAN/postinst
	install -m755 packaging/debian/prerm    pkg/deb/DEBIAN/prerm
	dpkg-deb --build pkg/deb argus_$(VERSION)_$(ARCH_PKG).deb
	rm -rf pkg/deb
	@echo "Built: argus_$(VERSION)_$(ARCH_PKG).deb"

# RPM package — requires rpmbuild
rpm: argus packaging/argus.spec
	mkdir -p ~/rpmbuild/{SPECS,SOURCES,BUILD,RPMS,SRPMS,BUILDROOT}
	cp packaging/argus.spec ~/rpmbuild/SPECS/argus.spec
	rpmbuild -bb \
	    --define "_bindir $(PREFIX)/bin" \
	    --define "version $(VERSION)" \
	    ~/rpmbuild/SPECS/argus.spec
	@echo "RPM built in ~/rpmbuild/RPMS/"

man: man/argus.8
	gzip -k man/argus.8 -c > man/argus.8.gz

BASHCOMPDIR  = $(DESTDIR)/etc/bash_completion.d
ZSHCOMPDIR   = $(DESTDIR)/usr/share/zsh/site-functions
EXAMPLEDIR   = $(DESTDIR)/usr/share/doc/argus

install: argus argus-server
	install -Dm755 argus                              $(BINDIR)/argus
	install -Dm755 argus-server                       $(BINDIR)/argus-server
	install -Dm644 packaging/argus.service            $(UNITDIR)/argus.service
	install -Dm644 packaging/argus-server.service     $(UNITDIR)/argus-server.service
	install -Dm644 packaging/argus.tmpfiles           $(TMPFILESDIR)/argus.conf
	install -Dm644 packaging/argus.logrotate          $(LOGROTATEDIR)/argus
	install -Dm644 man/argus.8                        $(MANDIR)/argus.8
	install -Dm644 packaging/argus-completion.bash    $(BASHCOMPDIR)/argus
	install -Dm644 packaging/argus-completion.zsh     $(ZSHCOMPDIR)/_argus
	install -Dm644 packaging/argus.conf.example       $(EXAMPLEDIR)/argus.conf.example
	@echo "Run: systemd-tmpfiles --create && systemctl daemon-reload && systemctl enable --now argus"

uninstall:
	rm -f $(BINDIR)/argus $(BINDIR)/argus-server \
	      $(UNITDIR)/argus.service $(UNITDIR)/argus-server.service \
	      $(TMPFILESDIR)/argus.conf $(LOGROTATEDIR)/argus $(MANDIR)/argus.8 \
	      $(BASHCOMPDIR)/argus $(ZSHCOMPDIR)/_argus \
	      $(EXAMPLEDIR)/argus.conf.example

clean:
	rm -f argus argus-server argus-bench \
	      $(BPF_SRC)/argus.bpf.o $(BPF_SRC)/argus.skel.h $(BPF_SRC)/vmlinux.h \
	      man/argus.8.gz \
	      tests/test_lineage tests/test_output tests/test_rules tests/test_forward \
	      tests/test_baseline tests/test_metrics tests/test_fim tests/test_netcorr \
	      tests/test_enterprise \
	      tests/test_lineage_asan tests/test_output_asan tests/test_rules_asan \
	      tests/test_forward_asan tests/test_baseline_asan tests/test_metrics_asan
	rm -rf pkg/
