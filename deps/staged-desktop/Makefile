PROJECT_ROOT ?= $(abspath ../..)
include $(PROJECT_ROOT)/build.opts

SELF         := $(abspath .)
MUSL_INSTALL := $(abspath ../musl/install)
SYSROOT      := $(abspath ../gtk-stack/sysroot)
MUSL_CC      := $(MUSL_INSTALL)/bin/musl-clang
CC           := $(MUSL_CC)
STRIP        := llvm-strip
GTK3_PC      := $(SYSROOT)/lib/pkgconfig/gtk+-3.0.pc

APP_NAME     := desktop-stage
APP_SRC      := $(SELF)/desktop_stage.c
# desktop_stage.c never made it into the repo (batch-commit gap) while the binary it
# produces IS committed here.  $(wildcard) makes the source an OPTIONAL prerequisite
# so a checkout without it keeps the committed binary instead of dying with
# "No rule to make target ./desktop_stage.c".
APP_SRC_OPT  := $(wildcard $(APP_SRC))
APP_BIN      := $(SELF)/$(APP_NAME)

BASE_CFLAGS  := -O2 -fno-pic -fno-pie -I$(SYSROOT)/include -I$(MUSL_INSTALL)/include
BASE_LDFLAGS := -no-pie -L$(SYSROOT)/lib -L$(MUSL_INSTALL)/lib

PKG_CONFIG_ENV := \
	PKG_CONFIG_LIBDIR="$(SYSROOT)/lib/pkgconfig:$(SYSROOT)/share/pkgconfig" \
	PKG_CONFIG_PATH="" \
	PKG_CONFIG_SYSROOT_DIR="$(SYSROOT)"

GTK3_CFLAGS := $(BASE_CFLAGS) $$($(PKG_CONFIG_ENV) pkg-config --cflags gtk+-3.0)
GTK3_LIBS   := $(BASE_LDFLAGS) $$($(PKG_CONFIG_ENV) pkg-config --static --libs gtk+-3.0) \
	-Wl,-rpath,$(SYSROOT)/lib -Wl,-rpath-link,$(SYSROOT)/lib \
	-lwayland-server -lglapi \
	-lm -ldl -lpthread -lutil -lrt

.PHONY: all clean

all: $(APP_BIN)

$(MUSL_CC):
	$(MAKE) -C ../musl all

$(GTK3_PC): $(MUSL_CC)
	$(MAKE) -C ../gtk-stack gtk3

$(APP_BIN): $(APP_SRC_OPT) $(GTK3_PC)
	@if [ -n "$(APP_SRC_OPT)" ]; then \
		$(CC) $(GTK3_CFLAGS) -o $@ $(APP_SRC) $(GTK3_LIBS) && \
		$(STRIP) $@ && \
		echo "[staged-desktop] Built: $@"; \
	elif [ -f $@ ]; then \
		echo "[staged-desktop] keeping the committed $(APP_NAME) (desktop_stage.c not in this checkout)"; \
		touch $@; \
	else \
		echo "[staged-desktop] $(APP_NAME) missing, and desktop_stage.c is not in this checkout" >&2; \
		exit 1; \
	fi

clean:
	rm -f $(APP_BIN)
