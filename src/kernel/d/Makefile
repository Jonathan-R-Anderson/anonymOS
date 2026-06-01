PROJECT_ROOT ?= $(abspath ../../..)
include $(PROJECT_ROOT)/build.opts

USERLAND_DIR := $(PROJECT_ROOT)/src/libs/userland/userland
LOCAL_D_SOURCES := $(patsubst ./%,%,$(shell find . -name '*.d' -print))
USERLAND_D_SOURCES := $(patsubst ./%,%,$(shell cd $(USERLAND_DIR) && find . -name '*.d' -print))
D_SOURCES := $(LOCAL_D_SOURCES) $(USERLAND_D_SOURCES)
D_OBJECTS := $(addprefix $(BUILD_ROOT)/d/, $(D_SOURCES:.d=.o))
ASM_SOURCES := $(patsubst ./%,%,$(shell find . -name '*.S' -print))
ASM_OBJECTS := $(addprefix $(BUILD_ROOT)/d/, $(ASM_SOURCES:.S=.o))

.PHONY: all clean

all: $(BUILD_ROOT)/libkernel_d.a

$(BUILD_ROOT)/libkernel_d.a: $(D_OBJECTS) $(ASM_OBJECTS)
	$(CROSSCOMPILE_AR) rcs $@ $(D_OBJECTS) $(ASM_OBJECTS)

# Rule for local kernel sources
$(BUILD_ROOT)/d/%.o: %.d
	mkdir -p $(dir $@)
	$(BUILD_RESOURCE_RUN) $(DC) -c $< -of=$@ $(DFLAGS) -I. -I../../../src/libs/userland

# Rule for userland sources linked into kernel
$(BUILD_ROOT)/d/%.o: $(USERLAND_DIR)/%.d
	mkdir -p $(dir $@)
	$(BUILD_RESOURCE_RUN) $(DC) -c $< -of=$@ $(DFLAGS) -I. -I../../../src/libs/userland

$(BUILD_ROOT)/d/%.o: %.S
	mkdir -p $(dir $@)
	$(BUILD_RESOURCE_RUN) $(CROSSCOMPILE_CLANG) -c $< -o $@ -D TARGET=x86_64 -I.

clean:
	rm -rf $(BUILD_ROOT)/d $(BUILD_ROOT)/libkernel_d.a
