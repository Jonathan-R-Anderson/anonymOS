# deps/decoy — the deterministic decoy activity generator engine (roadmap/INSTALLER.md §G).
# Portable C, no libc dependency in the engine itself; the test links libm for stats.
SELF := $(abspath .)
BLD  := $(SELF)/build
CC   ?= clang

.PHONY: test clean
test: | $(BLD)
	$(CC) -O2 -I$(SELF) $(SELF)/decoy.c $(SELF)/test/decoy_test.c -lm -o $(BLD)/decoy-test
	$(BLD)/decoy-test

$(BLD):
	@mkdir -p $@

clean:
	rm -rf $(BLD)
