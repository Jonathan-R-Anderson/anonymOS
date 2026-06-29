# deps/decoy — the deterministic decoy activity generator engine (roadmap/INSTALLER.md §G).
# Portable C, no libc dependency in the engine itself; the test links libm for stats.
SELF := $(abspath .)
BLD  := $(SELF)/build
CC   ?= clang

.PHONY: test render clean
test: | $(BLD)
	$(CC) -O2 -I$(SELF) $(SELF)/decoy.c $(SELF)/test/decoy_test.c -lm -o $(BLD)/decoy-test
	$(BLD)/decoy-test

# §G G3.3 — render decoy events into a realistic, deterministic syslog (+ a visible sample)
render: | $(BLD)
	$(CC) -O2 -I$(SELF) $(SELF)/decoy.c $(SELF)/decoy_render.c $(SELF)/test/render_test.c -o $(BLD)/decoy-render
	$(BLD)/decoy-render

$(BLD):
	@mkdir -p $@

clean:
	rm -rf $(BLD)
