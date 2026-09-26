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

# INSTALLER §E6: the crypto + RNG modules carry the whole encrypted-install data path (XTS over a
# 512 MiB boot volume, a multi-GB CSPRNG fill) and are pure computation; at the tree's default -O0
# they ran at ~3-8 MB/s.  Compile just these at -O2 (a later -O wins in LDC).  They use no inline
# asm on shared state; the one cross-CPU protocol in veracrypt_impl.d goes through volatileLoad/
# volatileStore + mfence, so the optimiser cannot hoist it.
D_HOT_OPT ?= -O2
$(BUILD_ROOT)/d/drivers/veracrypt_crypto.o $(BUILD_ROOT)/d/drivers/veracrypt_impl.o $(BUILD_ROOT)/d/core/random.o: D_OPT_OVERRIDE = $(D_HOT_OPT)

# DESKTOP HOT PATH — every frame + input event crosses the syscall dispatcher (posix.d), the scanout
# blit + scheduler (kernel_main.d) and the framebuffer pixel writes; at the tree -O0 default these
# cost several times the instructions they need (no reg-alloc/inlining/vectorization). Compile them
# at -O2 (verified: all three compile clean at -O2). `make OPT_LEVEL=-O2` bumps the whole tree;
# `make OPT_LEVEL=-O0` (the default reason: low-RAM build hosts) still opts these out too.
$(BUILD_ROOT)/d/core/syscalls/posix.o $(BUILD_ROOT)/d/core/kernel_main.o $(BUILD_ROOT)/d/display/framebuffer.o: D_OPT_OVERRIDE = $(D_HOT_OPT)

# Rule for local kernel sources
$(BUILD_ROOT)/d/%.o: %.d
	mkdir -p $(dir $@)
	$(BUILD_RESOURCE_RUN) $(DC) -c $< -of=$@ $(DFLAGS) $(D_OPT_OVERRIDE) -I. -I../../../src/libs/userland

# Rule for userland sources linked into kernel
$(BUILD_ROOT)/d/%.o: $(USERLAND_DIR)/%.d
	mkdir -p $(dir $@)
	$(BUILD_RESOURCE_RUN) $(DC) -c $< -of=$@ $(DFLAGS) -I. -I../../../src/libs/userland

$(BUILD_ROOT)/d/%.o: %.S
	mkdir -p $(dir $@)
	$(BUILD_RESOURCE_RUN) $(CROSSCOMPILE_CLANG) -c $< -o $@ -D TARGET=x86_64 -I.

clean:
	rm -rf $(BUILD_ROOT)/d $(BUILD_ROOT)/libkernel_d.a
