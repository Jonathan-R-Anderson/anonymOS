PROJECT_ROOT ?= $(abspath ../../../../..)
DC ?= ldc2
SRC := $(shell find src -name '*.d')
BUILD_DIR := $(PROJECT_ROOT)/build/deps/redepend/esh
TARGET := $(BUILD_DIR)/lfe-sh

.RECIPEPREFIX := >

all: $(TARGET)

$(TARGET): $(SRC)
>mkdir -p $(BUILD_DIR)
>$(DC) $(SRC) -L-lreadline -of=$(TARGET)

.PHONY: all clean
clean:
>rm -rf $(BUILD_DIR)
>rm -f esh esh.o lfe-sh output.txt
