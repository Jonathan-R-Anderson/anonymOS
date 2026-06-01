cmd_libbb/makedev.o := /home/bruns/Documents/EpinAnonymOS/deps/musl/install/bin/musl-clang -Wp,-MD,libbb/.makedev.o.d  -std=gnu99 -Iinclude -Ilibbb  -include include/autoconf.h -D_GNU_SOURCE -DNDEBUG  -DBB_VER='"1.36.1"' -Wall -Wshadow -Wwrite-strings -Wundef -Wstrict-prototypes -Wunused -Wunused-parameter -Wunused-function -Wunused-value -Wmissing-prototypes -Wmissing-declarations -Wno-format-security -Wdeclaration-after-statement -Wold-style-definition -finline-limit=0 -fno-builtin-strlen -fomit-frame-pointer -ffunction-sections -fdata-sections -funsigned-char -falign-functions=1 -falign-jumps=1 -falign-labels=1 -falign-loops=1 -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-builtin-printf -Oz -O2 -pipe    -DKBUILD_BASENAME='"makedev"'  -DKBUILD_MODNAME='"makedev"' -c -o libbb/makedev.o libbb/makedev.c

deps_libbb/makedev.o := \
  libbb/makedev.c \
  include/platform.h \
    $(wildcard include/config/werror.h) \
    $(wildcard include/config/big/endian.h) \
    $(wildcard include/config/little/endian.h) \
    $(wildcard include/config/nommu.h) \
  /home/bruns/Documents/HanonymOS/deps/musl/install/include/limits.h \
  /home/bruns/Documents/HanonymOS/deps/musl/install/include/features.h \
  /home/bruns/Documents/HanonymOS/deps/musl/install/include/bits/alltypes.h \
  /home/bruns/Documents/HanonymOS/deps/musl/install/include/bits/limits.h \
  /home/bruns/Documents/HanonymOS/deps/musl/install/include/byteswap.h \
  /home/bruns/Documents/HanonymOS/deps/musl/install/include/stdint.h \
  /home/bruns/Documents/HanonymOS/deps/musl/install/include/bits/stdint.h \
  /home/bruns/Documents/HanonymOS/deps/musl/install/include/endian.h \
  /home/bruns/Documents/HanonymOS/deps/musl/install/include/stdbool.h \
  /home/bruns/Documents/HanonymOS/deps/musl/install/include/unistd.h \
  /home/bruns/Documents/HanonymOS/deps/musl/install/include/bits/posix.h \
  /home/bruns/Documents/HanonymOS/deps/musl/install/include/sys/sysmacros.h \

libbb/makedev.o: $(deps_libbb/makedev.o)

$(deps_libbb/makedev.o):
