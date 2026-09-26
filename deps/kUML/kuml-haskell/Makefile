# =========================================================
# kuml-haskell — the Haskell port of the kUML CLI
#
#   make dev     host build via GHC (multi-module)      -> build/kuml-ghc
#   make anos    anonymOS binary via JHC + musl-clang    -> build/kuml
#   make check   build both and assert byte-parity
#   make clean
#
# The anonymOS binary (`build/kuml`) is a fully static, NON-PIE musl ELF with
# no PT_INTERP — the same shape as the other anonymOS userland tools
# (hos-ethsign, busybox), so it loads under the kernel's Linux personality.
# =========================================================

PROJECT_ROOT ?= $(abspath ../../..)

GHC      ?= ghc
JHC      ?= jhc
JHC_LIBS ?= /usr/local/lib/jhc-0.8.2
# JHC cache dir. Honours an inherited JHC_CACHE (the top anonymOS build exports
# one under .build-home); falls back to the per-user default. jhc needs it to
# already exist, so the recipe mkdir's it first.
JHC_CACHE ?= $(HOME)/.jhc/cache
# In-tree musl C compiler (anonymOS's canonical userland cc); JHC uses it as
# its C backend so the output is static-musl instead of host glibc.
MUSL_CC  ?= $(PROJECT_ROOT)/deps/musl/install/bin/musl-clang

SRC    := src
SINGLE := build/kuml_single.hs
HS     := $(wildcard src/*.hs src/Kuml/*.hs)

.PHONY: all dev anos single check clean jhc-target

all: anos

# ── host development build (fast; for iterating + `make check`) ──────────────
dev: build/kuml-ghc
build/kuml-ghc: $(HS)
	@mkdir -p build/ghc
	$(GHC) -O2 -isrc -outputdir build/ghc -o $@ src/Main.hs

# ── single-file source that JHC can compile without its multi-module bug ─────
single: $(SINGLE)
$(SINGLE): $(HS) scripts/concat-single.sh
	@sh scripts/concat-single.sh $(SRC) $(SINGLE)

# ── the anonymOS binary: static-musl, non-PIE, no interpreter ────────────────
anos: build/kuml
build/kuml: $(SINGLE) jhc-target
	@mkdir -p $(JHC_CACHE)
	$(JHC) --cache-dir=$(JHC_CACHE) --cross -manos -L$(JHC_LIBS) $(SINGLE) -o $@
	@file $@

# Ensure JHC has an [anos] target aimed at the musl C compiler. JHC only reads
# custom targets from ~/.jhc/targets.ini (no CLI override), so we append the
# stanza once if it is absent. Change MUSL_CC => remove the stale [anos] block.
#
# gc=none is deliberate: JHC 0.8.2's default region collector (jgc) corrupts the
# heap on the allocation-heavy render path (consistent SIGSEGV mid-output).
# kuml is a short-lived one-shot CLI, so allocate-and-exit (no collection) is
# both correct and the simplest fix — memory is reclaimed by process exit.
jhc-target:
	@mkdir -p $(HOME)/.jhc
	@if ! grep -q '^\[anos\]' $(HOME)/.jhc/targets.ini 2>/dev/null; then \
	  printf '[anos]\ncc=%s\ngc=none\ncflags+=-static -fno-pie\nmerge=x86_64\n' "$(MUSL_CC)" >> $(HOME)/.jhc/targets.ini; \
	  echo "kuml-haskell: added [anos] JHC target (cc=$(MUSL_CC), gc=none)"; \
	fi

# ── parity: the GHC and anonymOS binaries must render byte-identically ───────
check: dev anos
	@./build/kuml-ghc render examples/orders.kuml 2>/dev/null > build/o.ghc.svg
	@./build/kuml     render examples/orders.kuml 2>/dev/null > build/o.anos.svg
	@cmp build/o.ghc.svg build/o.anos.svg && echo "PARITY OK (ghc == anos, $$(wc -c < build/o.ghc.svg) bytes)"
	@./build/kuml validate examples/orders.kuml

clean:
	rm -rf build
