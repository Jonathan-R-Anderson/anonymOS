PROJECT_ROOT ?= $(abspath ../../..)
include $(PROJECT_ROOT)/build.opts

.PHONY: all clean

all: $(BUILD_ROOT)/prog-libs/hos-common-0.0.1.hl

$(BUILD_ROOT)/prog-libs/hos-common-0.0.1.hl: \
	Hos/Data/Sequence.hs \
	Data/Binary.hs \
	Data/Elf.hs \
	Hos/Common/Bundle.hs \
	Hos/Common/Types.hs \
	common.yaml

	mkdir -p $(BUILD_ROOT)/prog-libs

	@log="$(BUILD_ROOT)/prog-libs/hos-common.jhc.log"; \
	echo "JHC common library (log: $$log)"; \
	$(BUILD_RESOURCE_RUN) $(JHC) \
		-L $(JHC_LIBS_PREFIX) \
		--build-hl=common.yaml \
		>"$$log" 2>&1 || { \
			tail -n $(BUILD_TAIL_LINES) "$$log"; \
			exit 1; \
		}

	mv hos-common-0.0.1.hl $(BUILD_ROOT)/prog-libs/

clean:
	rm -f $(BUILD_ROOT)/prog-libs/hos-common-0.0.1.hl
