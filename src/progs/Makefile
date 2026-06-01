# =========================================================
# src/progs/Makefile
# =========================================================

PROJECT_ROOT := $(abspath ../..)
export PROJECT_ROOT

include $(PROJECT_ROOT)/build.opts

.PHONY: all runtime services shells bundle clean

# =========================================================
# Main Build
# =========================================================

all: runtime services shells bundle

# =========================================================
# Runtime
# =========================================================

runtime:
	@echo "==== Building Runtime ===="

	set -e; \
	for dir in runtime/cbits runtime/hos; do \
		$(MAKE) $(MAKE_BUILD_FLAGS) -C ./$$dir all; \
	done

# =========================================================
# Services
# =========================================================

services: runtime
	@echo "==== Building Services ===="

	set -e; \
	for dir in \
		os/services/init \
		os/services/storage \
		os/services/pci \
		os/services/ata; do \
		$(MAKE) $(MAKE_BUILD_FLAGS) -C ./$$dir all; \
	done

# =========================================================
# Shells
# =========================================================

shells: runtime
	@echo "==== Building Shells ===="

	set -e; \
	for dir in \
		os/shells/shell; do \
		$(MAKE) $(MAKE_BUILD_FLAGS) -C ./$$dir all; \
	done

# =========================================================
# Bundle
# =========================================================

bundle: services shells
	@echo "==== Building Bundle ===="

	cd build && \
	$(PROJECT_ROOT)/src/util/bin/hos-build-bundle \
		boot.bundle-spec \
		$(PROJECT_ROOT)/build/hos.bundle

# =========================================================
# Cleanup
# =========================================================

clean:
	@echo "==== Cleaning Progs ===="

	rm -rf \
		$(PROJECT_ROOT)/build/progs \
		$(PROJECT_ROOT)/build/cbits-user \
		$(PROJECT_ROOT)/build/depends/cbits-user
