// HOST TEST 1: boot selftest under version=HostTest.
//
// Builds core.virt.selftest with -d-version=HostTest so the host-only
// compat block (stubMapUser userspace buffers, XSAVE/XCRS/debugregs/TSC
// round-trips, ENOTTY interrupt ioctls) runs too.  virtSelfTest() prints
// "[virt] selftest PASS" itself; build.sh greps for that line and fails
// loudly if it is absent.
module run_selftest;

import core.virt.selftest : virtSelfTest;

extern (C) @nogc nothrow:

extern (C) int main() {
    virtSelfTest();
    return 0;
}
