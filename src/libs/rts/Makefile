PROJECT_ROOT ?= $(abspath ../../..)
include $(PROJECT_ROOT)/build.opts
RTS_SOURCES=rts.c gc_jgc.c
RTS_USER_SOURCES=$(RTS_SOURCES) stableptr.c

.PHONY: all test clean

all: $(BUILD_ROOT)/librts.a $(BUILD_ROOT)/librts-user.a

$(BUILD_ROOT)/librts.a: $(addprefix $(BUILD_ROOT)/rts/, $(RTS_SOURCES:.c=.o))
	$(CROSSCOMPILE_AR) rcs $(BUILD_ROOT)/librts.a $(addprefix $(BUILD_ROOT)/rts/, $(RTS_SOURCES:.c=.o))

$(BUILD_ROOT)/librts-user.a: $(addprefix $(BUILD_ROOT)/rts-user/, $(RTS_USER_SOURCES:.c=.o))
	$(CROSSCOMPILE_AR) rcs $(BUILD_ROOT)/librts-user.a $(addprefix $(BUILD_ROOT)/rts-user/, $(RTS_USER_SOURCES:.c=.o))

$(BUILD_ROOT)/rts/%.s: %.c
	mkdir -p $(BUILD_ROOT)/rts
	$(BUILD_RESOURCE_RUN) $(CROSSCOMPILE_CLANG) $< -S -I . $(CBITS_INC) $(KERNEL_CFLAGS) -o $@ -D _JHC_BAREBONES=1 -D_JHC_GC=1

$(BUILD_ROOT)/rts-user/%.s: %.c
	mkdir -p $(BUILD_ROOT)/rts-user
	$(BUILD_RESOURCE_RUN) $(CROSSCOMPILE_CLANG) $< -S -I . $(USER_CFLAGS) -o $@ -D_JHC_GC=1

$(BUILD_ROOT)/rts/%.o: $(BUILD_ROOT)/rts/%.s
	$(CROSSCOMPILE_AS) -c $< -o $@

$(BUILD_ROOT)/rts-user/%.o: $(BUILD_ROOT)/rts-user/%.s
	$(CROSSCOMPILE_AS) -c $< -o $@

$(BUILD_ROOT)/depends/rts/%.P: %.c
	mkdir -p $(BUILD_ROOT)/rts/
	mkdir -p $(BUILD_ROOT)/depends/rts
	(printf $(BUILD_ROOT)/rts/; $(CROSSCOMPILE_CLANG) -MM $< -I.) > $@

$(BUILD_ROOT)/depends/rts-user/%.P: %.c
	mkdir -p $(BUILD_ROOT)/rts-user/
	mkdir -p $(BUILD_ROOT)/depends/rts-user
	(printf $(BUILD_ROOT)/rts-user/; $(CROSSCOMPILE_CLANG) -MM $< -I.) > $@

test:

include $(addprefix $(BUILD_ROOT)/depends/rts/, $(RTS_SOURCES:.c=.P))
include $(addprefix $(BUILD_ROOT)/depends/rts-user/, $(RTS_USER_SOURCES:.c=.P))

clean:
	rm -rf $(BUILD_ROOT)/rts $(BUILD_ROOT)/rts-user $(BUILD_ROOT)/librts.a $(BUILD_ROOT)/librts-user.a $(BUILD_ROOT)/depends/rts $(BUILD_ROOT)/depends/rts-user
