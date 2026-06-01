PROJECT_ROOT ?= $(abspath ../..)
.PHONY: all clean

all:
	$(MAKE) -C ../progs/deps/bdepend/hos-build-bundle all

clean:
	$(MAKE) -C ../progs/deps/bdepend/hos-build-bundle clean
	rm -rf bin
