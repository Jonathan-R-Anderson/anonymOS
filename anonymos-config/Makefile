# =========================================================
# anonymos-config/Makefile
# Builds the host-side declarative-config compiler in D (ldc2 + Phobos).
#
# This is a HOST tool, so it deliberately does NOT use the kernel's cross
# DFLAGS (-betterC -mtriple=... -code-model=large from build.opts): it needs
# std.json, std.digest, std.file — the full Phobos runtime. This mirrors the
# plain-ldc2+Phobos build used by the in-tree esh vendored dep
# (src/progs/deps/redepend/esh/Makefile.anonymos). DC defaults to the project's
# compiler (build.opts:19 `DC ?= ldc2`).
# =========================================================

PROJECT_ROOT := $(abspath ..)
DC         ?= ldc2
SRC_DIR    := source
BUILD_DIR  := build
BIN        := $(BUILD_DIR)/anonymos-config
TEST_BIN   := $(BUILD_DIR)/run_tests

SOURCES := $(wildcard $(SRC_DIR)/*.d)
# The test driver has its own main(); exclude the CLI's main.d so there is only
# one entry point in the test binary.
TEST_SOURCES := $(filter-out $(SRC_DIR)/main.d,$(SOURCES))
TEST_SRC := tests/run_tests.d

DFLAGS := -O2 -release -I$(SRC_DIR)

.PHONY: all test clean schema-example

all: $(BIN)

$(BIN): $(SOURCES)
	@echo "==== Building anonymos-config (ldc2 + Phobos) ===="
	mkdir -p $(BUILD_DIR)
	$(DC) $(DFLAGS) -of=$(BIN) $(SOURCES)

# Phase 12 test driver: compiles tests/run_tests.d against the source modules.
test: $(TEST_BIN)
	@echo "==== Running anonymos-config test suite ===="
	./$(TEST_BIN)

$(TEST_BIN): $(TEST_SRC) $(TEST_SOURCES)
	mkdir -p $(BUILD_DIR)
	$(DC) $(DFLAGS) -of=$(TEST_BIN) $(TEST_SRC) $(TEST_SOURCES)

# Convenience: emit the JSON-Schema document (editor autocomplete).
schema-example: $(BIN)
	./$(BIN) schema > anonymos-config.schema.json

clean:
	rm -rf $(BUILD_DIR) anonymos-config.schema.json
