PROJECT_ROOT ?= $(abspath ../..)
include $(PROJECT_ROOT)/build.opts

SELF      := $(abspath .)
SRC_ROOT  := $(SELF)/src
BUILD_ROOT:= $(SELF)/build

GNOME_GIT_BASE ?= https://gitlab.gnome.org/GNOME
GIT_DEPTH ?= 1

REPOS := \
	glib \
	gsettings-desktop-schemas \
	gnome-desktop \
	mutter \
	gnome-shell \
	gdm \
	gnome-session

.PHONY: help all clone update build iso clean

help:
	@echo "GNOME source/bootstrap targets:"
	@echo "  make -C deps/gnome clone   # clone upstream GNOME repositories into deps/gnome/src"
	@echo "  make -C deps/gnome update  # git pull --ff-only for cloned repos"
	@echo "  make -C deps/gnome build   # build the in-tree staged desktop stack and real Mutter"
	@echo "  make -C deps/gnome iso     # rebuild hos.iso with the staged desktop artifacts"

all: build

clone: $(addprefix clone-,$(REPOS))

update: $(addprefix update-,$(REPOS))

build: clone
	$(MAKE) -C ../cxxrt all
	$(MAKE) -C ../gtk-stack all
	$(MAKE) -C ../staged-desktop all
	$(MAKE) -C ../mutter all

iso: build
	$(MAKE) -C $(PROJECT_ROOT) hos.iso

clean:
	rm -rf $(BUILD_ROOT)

define CLONE_RULE
clone-$(1):
	mkdir -p $(SRC_ROOT)
	if [ ! -d $(SRC_ROOT)/$(1)/.git ]; then \
		git clone --depth $(GIT_DEPTH) $(GNOME_GIT_BASE)/$(1).git $(SRC_ROOT)/$(1); \
	else \
		echo "$(1) already cloned"; \
	fi

update-$(1):
	if [ -d $(SRC_ROOT)/$(1)/.git ]; then \
		git -C $(SRC_ROOT)/$(1) pull --ff-only; \
	else \
		echo "$(1) is not cloned yet"; \
	fi
endef

$(foreach repo,$(REPOS),$(eval $(call CLONE_RULE,$(repo))))
