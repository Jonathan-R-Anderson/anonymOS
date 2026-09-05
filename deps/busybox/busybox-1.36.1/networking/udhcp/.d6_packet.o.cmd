cmd_networking/udhcp/d6_packet.o := /home/bruns/Documents/anonymOS/deps/musl/install/bin/musl-clang -Wp,-MD,networking/udhcp/.d6_packet.o.d  -std=gnu99 -Iinclude -Ilibbb  -include include/autoconf.h -D_GNU_SOURCE -DNDEBUG -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DBB_VER='"1.36.1"' -Wall -Wshadow -Wwrite-strings -Wundef -Wstrict-prototypes -Wunused -Wunused-parameter -Wunused-function -Wunused-value -Wmissing-prototypes -Wmissing-declarations -Wno-format-security -Wdeclaration-after-statement -Wold-style-definition -finline-limit=0 -fno-builtin-strlen -fomit-frame-pointer -ffunction-sections -fdata-sections -funsigned-char -static-libgcc -falign-functions=1 -falign-jumps=1 -falign-labels=1 -falign-loops=1 -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-builtin-printf -Oz -O2 -pipe    -DKBUILD_BASENAME='"d6_packet"'  -DKBUILD_MODNAME='"d6_packet"' -c -o networking/udhcp/d6_packet.o networking/udhcp/d6_packet.c

deps_networking/udhcp/d6_packet.o := \
  networking/udhcp/d6_packet.c \
    $(wildcard include/config/udhcp/debug.h) \
  networking/udhcp/common.h \
    $(wildcard include/config/udhcpc/slack/for/buggy/servers.h) \
    $(wildcard include/config/feature/udhcp/rfc3397.h) \
    $(wildcard include/config/feature/udhcpc6/rfc3646.h) \
    $(wildcard include/config/feature/udhcpc6/rfc4704.h) \
    $(wildcard include/config/udhcpc.h) \
    $(wildcard include/config/udhcpd.h) \
    $(wildcard include/config/udhcpc6.h) \
    $(wildcard include/config/udhcp/verbose.h) \
  include/libbb.h \
    $(wildcard include/config/feature/shadowpasswds.h) \
    $(wildcard include/config/use/bb/shadow.h) \
    $(wildcard include/config/selinux.h) \
    $(wildcard include/config/feature/utmp.h) \
    $(wildcard include/config/locale/support.h) \
    $(wildcard include/config/use/bb/pwd/grp.h) \
    $(wildcard include/config/lfs.h) \
    $(wildcard include/config/feature/buffers/go/on/stack.h) \
    $(wildcard include/config/feature/buffers/go/in/bss.h) \
    $(wildcard include/config/extra/cflags.h) \
    $(wildcard include/config/variable/arch/pagesize.h) \
    $(wildcard include/config/feature/verbose.h) \
    $(wildcard include/config/feature/etc/services.h) \
    $(wildcard include/config/feature/ipv6.h) \
    $(wildcard include/config/feature/seamless/xz.h) \
    $(wildcard include/config/feature/seamless/lzma.h) \
    $(wildcard include/config/feature/seamless/bz2.h) \
    $(wildcard include/config/feature/seamless/gz.h) \
    $(wildcard include/config/feature/seamless/z.h) \
    $(wildcard include/config/float/duration.h) \
    $(wildcard include/config/feature/check/names.h) \
    $(wildcard include/config/feature/prefer/applets.h) \
    $(wildcard include/config/long/opts.h) \
    $(wildcard include/config/feature/pidfile.h) \
    $(wildcard include/config/feature/syslog.h) \
    $(wildcard include/config/feature/syslog/info.h) \
    $(wildcard include/config/warn/simple/msg.h) \
    $(wildcard include/config/feature/individual.h) \
    $(wildcard include/config/shell/ash.h) \
    $(wildcard include/config/shell/hush.h) \
    $(wildcard include/config/echo.h) \
    $(wildcard include/config/sleep.h) \
    $(wildcard include/config/printf.h) \
    $(wildcard include/config/test.h) \
    $(wildcard include/config/test1.h) \
    $(wildcard include/config/test2.h) \
    $(wildcard include/config/kill.h) \
    $(wildcard include/config/killall.h) \
    $(wildcard include/config/killall5.h) \
    $(wildcard include/config/chown.h) \
    $(wildcard include/config/ls.h) \
    $(wildcard include/config/xxx.h) \
    $(wildcard include/config/route.h) \
    $(wildcard include/config/feature/hwib.h) \
    $(wildcard include/config/desktop.h) \
    $(wildcard include/config/feature/crond/d.h) \
    $(wildcard include/config/feature/setpriv/capabilities.h) \
    $(wildcard include/config/run/init.h) \
    $(wildcard include/config/feature/securetty.h) \
    $(wildcard include/config/pam.h) \
    $(wildcard include/config/use/bb/crypt.h) \
    $(wildcard include/config/feature/adduser/to/group.h) \
    $(wildcard include/config/feature/del/user/from/group.h) \
    $(wildcard include/config/ioctl/hex2str/error.h) \
    $(wildcard include/config/feature/editing.h) \
    $(wildcard include/config/feature/editing/history.h) \
    $(wildcard include/config/feature/tab/completion.h) \
    $(wildcard include/config/feature/username/completion.h) \
    $(wildcard include/config/feature/editing/fancy/prompt.h) \
    $(wildcard include/config/feature/editing/savehistory.h) \
    $(wildcard include/config/feature/editing/vi.h) \
    $(wildcard include/config/feature/editing/save/on/exit.h) \
    $(wildcard include/config/pmap.h) \
    $(wildcard include/config/feature/show/threads.h) \
    $(wildcard include/config/feature/ps/additional/columns.h) \
    $(wildcard include/config/feature/topmem.h) \
    $(wildcard include/config/feature/top/smp/process.h) \
    $(wildcard include/config/pgrep.h) \
    $(wildcard include/config/pkill.h) \
    $(wildcard include/config/pidof.h) \
    $(wildcard include/config/sestatus.h) \
    $(wildcard include/config/unicode/support.h) \
    $(wildcard include/config/feature/mtab/support.h) \
    $(wildcard include/config/feature/clean/up.h) \
    $(wildcard include/config/feature/devfs.h) \
  include/platform.h \
    $(wildcard include/config/werror.h) \
    $(wildcard include/config/big/endian.h) \
    $(wildcard include/config/little/endian.h) \
    $(wildcard include/config/nommu.h) \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/limits.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/features.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/bits/alltypes.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/bits/limits.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/byteswap.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/stdint.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/bits/stdint.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/endian.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/stdbool.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/unistd.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/bits/posix.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/ctype.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/dirent.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/bits/dirent.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/errno.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/bits/errno.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/fcntl.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/bits/fcntl.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/inttypes.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/netdb.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/netinet/in.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/sys/socket.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/bits/socket.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/setjmp.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/bits/setjmp.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/signal.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/bits/signal.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/paths.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/stdio.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/stdlib.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/alloca.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/stdarg.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/stddef.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/string.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/strings.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/libgen.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/poll.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/bits/poll.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/sys/ioctl.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/bits/ioctl.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/bits/ioctl_fix.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/sys/mman.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/bits/mman.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/sys/resource.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/sys/time.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/sys/select.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/bits/resource.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/sys/stat.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/bits/stat.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/sys/types.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/sys/sysmacros.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/sys/wait.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/termios.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/bits/termios.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/time.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/sys/param.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/pwd.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/grp.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/mntent.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/sys/statfs.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/sys/statvfs.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/bits/statfs.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/utmp.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/utmpx.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/arpa/inet.h \
  include/pwd_.h \
  include/grp_.h \
  include/shadow_.h \
  include/xatonum.h \
  include/common_bufsiz.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/netinet/udp.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/netinet/ip.h \
  networking/udhcp/d6_common.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/netinet/ip6.h \
  networking/udhcp/dhcpc.h \
    $(wildcard include/config/feature/udhcp/port.h) \
  networking/udhcp/dhcpd.h \
    $(wildcard include/config/dhcpd/leases/file.h) \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/netinet/if_ether.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/net/ethernet.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/net/if_arp.h \
  /home/bruns/Documents/anonymOS/deps/musl/install/include/netpacket/packet.h \

networking/udhcp/d6_packet.o: $(deps_networking/udhcp/d6_packet.o)

$(deps_networking/udhcp/d6_packet.o):
