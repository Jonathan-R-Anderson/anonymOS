PROJECT_ROOT ?= $(abspath ../../../../..)
PROG_NAME=init
PROG_HS_FILES=init.hs
PROG_LIB_HS_FILES=Hos/Init/Msg.hs
PROG_CFLAGS=-DBUILDING_INIT
PROG_JHC_FLAGS=-pcontainers

include $(PROJECT_ROOT)/src/progs/build/build-prog.mk
include $(PROJECT_ROOT)/src/progs/build/build-prog-lib.mk
