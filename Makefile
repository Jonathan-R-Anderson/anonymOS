# Makefile for GremlinOS System Activator

# D Compiler
DMD = dmd

# Compiler flags
# -O: optimize
# -release: enable release mode (disables asserts, etc.)
# -boundscheck=off: turn off array bounds checking for release builds (optional)
# -g: add debugging information (useful for development)
DFLAGS_RELEASE = -O -release -boundscheck=off
DFLAGS_DEBUG = -g

# Default to release build
DFLAGS ?= $(DFLAGS_RELEASE)

# Application name and directories
APP_NAME = system_activator
SRC_BASE_DIR = src/user/apps
SRC_DIR = $(SRC_BASE_DIR)/$(APP_NAME)
BIN_DIR = bin

# Source files
SRC_FILES = $(SRC_DIR)/$(APP_NAME).d

# Target executable
TARGET = $(BIN_DIR)/$(APP_NAME)

.PHONY: all clean debug

all: $(TARGET)

$(TARGET): $(SRC_FILES)
	@echo "Compiling $(APP_NAME) with $(DMD)..."
	@mkdir -p $(BIN_DIR) # Ensure bin directory exists
	$(DMD) $(DFLAGS) -of$(TARGET) $(SRC_FILES)

debug:
	$(MAKE) DFLAGS="$(DFLAGS_DEBUG)" all

clean:
	@echo "Cleaning up..."
	rm -f $(TARGET)
	# Optionally, remove the bin directory if it's empty and only for this app
	# rmdir --ignore-fail-on-non-empty $(BIN_DIR)