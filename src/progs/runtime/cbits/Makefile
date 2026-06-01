PROJECT_ROOT ?= $(abspath ../../../..)
include $(PROJECT_ROOT)/build.opts
CBITS_C_SOURCES=syscall.c dlmalloc.c hos.c math_stubs.c
CBITS_AS_SOURCES=start.S

CBITS_OBJECTS=$(addprefix $(BUILD_ROOT)/cbits-user/, $(CBITS_C_SOURCES:.c=.o) $(CBITS_AS_SOURCES:.S=.o))

.PHONY: all clean

all: $(BUILD_ROOT)/libcbits-user.a

$(BUILD_ROOT)/libcbits-user.a: $(CBITS_OBJECTS)
	$(CROSSCOMPILE_AR) rcs $(BUILD_ROOT)/libcbits-user.a $(CBITS_OBJECTS)

$(BUILD_ROOT)/cbits-user/%.o: %.c
	mkdir -p $(BUILD_ROOT)/cbits-user
	$(BUILD_RESOURCE_RUN) $(CROSSCOMPILE_CLANG) $< -c -I . $(CBITS_INC) $(RTS_INC) $(USER_CFLAGS) -o $@ -DCLANG=1 -g3

$(BUILD_ROOT)/cbits-user/%.o: $(BUILD_ROOT)/cbits-user/%.S
	$(CROSSCOMPILE_AS) -c $< -o $@

$(BUILD_ROOT)/cbits-user/start.o: start.S
	mkdir -p $(BUILD_ROOT)/cbits-user
	$(CROSSCOMPILE_AS) -c start.S -o $@

$(BUILD_ROOT)/depends/cbits-user/%.P: %.c
	mkdir -p $(BUILD_ROOT)/cbits-user
	mkdir -p $(BUILD_ROOT)/depends/cbits-user
	(printf $(BUILD_ROOT)/cbits-user/; $(CROSSCOMPILE_CLANG) -MM $< -I . $(CBITS_INC) $(RTS_INC)) > $@

include $(addprefix $(BUILD_ROOT)/depends/cbits-user/, $(CBITS_C_SOURCES:.c=.P))

clean:
	rm -rf $(BUILD_ROOT)/cbits-user $(BUILD_ROOT)/libcbits-user.a $(BUILD_ROOT)/depends/cbits-user
