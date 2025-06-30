# anonymos-posix

This repository provides wrappers for POSIX system calls that can be used with
[anonymOS's internetcomputer](https://github.com/Jonathan-R-Anderson/internetcomputer)
microkernel.  The wrappers are implemented in D and compiled with the
cross-compiled `ldc2` used by the OS build.

Most wrappers simply forward to the host C library.  The goal is to expose a
complete POSIX surface usable from `-betterC` D code.  See `src/posix.d` for the
current list of supported calls.

## Building

The library can be built either with the host `ldc2` or with the cross
compiler from the internetcomputer repository.  An example using the cross
compiler:

```bash
# assuming ../internetcomputer/build/bin/ldc2 exists
../internetcomputer/build/bin/ldc2 \
    -betterC -I=src examples/test.d src/posix.d -of=test
./test | head -n 2
```

This should print the first lines of `README.md` demonstrating that the
wrappers work under the cross compiler as well.
