PROJECT_ROOT ?= $(abspath ../../../../..)
.PHONY: all clean

BUILD_DIR := $(PROJECT_ROOT)/build/deps/bdepend/hos-build-bundle

all: $(PROJECT_ROOT)/src/util/bin/hos-build-bundle

$(PROJECT_ROOT)/src/util/bin/hos-build-bundle: hos-build-bundle.hs
	mkdir -p $(BUILD_DIR)
	mkdir -p $(PROJECT_ROOT)/src/util/bin
	stack exec -- ghc --make hos-build-bundle.hs -odir $(BUILD_DIR) -hidir $(BUILD_DIR) -o $(PROJECT_ROOT)/src/util/bin/hos-build-bundle -i$(PROJECT_ROOT)/src/libs/common/ -package yaml -package unordered-containers -package scientific

clean:
	rm -f $(PROJECT_ROOT)/src/util/bin/hos-build-bundle hos-build-bundle.o hos-build-bundle.hi
	rm -rf $(BUILD_DIR)
