DC=ldc2
TARGET_TRIPLE ?= x86_64-unknown-linux-gnu
BIN_DIR=bin

SRCS=$(shell find distributed_fs -name '*.d')

all: $(BIN_DIR)/fs_server

$(BIN_DIR)/fs_server: $(SRCS)
	mkdir -p $(BIN_DIR)
	$(DC) -I. -mtriple=$(TARGET_TRIPLE) $(SRCS) -of=$@

clean:
	rm -rf $(BIN_DIR)
