CLANG ?= clang
CFLAGS ?= -g -O2 -target bpf -D__TARGET_ARCH_x86

all: streamer.bpf.o

streamer.bpf.o: streamer.c vmlinux.h
	$(CLANG) $(CFLAGS) -c streamer.c -o streamer.bpf.o

clean:
	rm -f streamer.bpf.o
