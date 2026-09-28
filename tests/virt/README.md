# tests/virt — KVM smoke test

`kvm-smoke.c` exercises the anonymOS KVM compatibility ABI end to end from
userspace, using only raw ioctl numbers transcribed from
`src/kernel/d/core/virt/kvmabi.d` (no `<linux/kvm.h>`). It runs on
anonymOS's Linux personality on real VT-x/AMD-V hardware, and also compiles
and runs on stock Linux.

## Build

No dependencies beyond a C99 compiler and libc:

```sh
gcc -std=c99 -Wall -Wextra -o /tmp/kvm-smoke tests/virt/kvm-smoke.c
```

It must build `-Wall -Wextra` clean (also checked with `-pedantic`). It
cannot execute in this sandbox — there is no `/dev/kvm` here — so a build
plus the graceful step-1 failure is the most this environment can verify.

## Run (anonymOS hardware target)

1. Boot the anonymOS image on a machine with VT-x/AMD-V enabled in firmware.
2. Confirm the device node exists and is accessible: `ls -l /dev/kvm`.
3. Copy the binary over (or build on target) and run it:

```sh
./kvm-smoke
```

## Expected output

```
PASS: open /dev/kvm
PASS: KVM_GET_API_VERSION == 12
PASS: KVM_CHECK_EXTENSION KVM_CAP_USER_MEMORY == 1
PASS: KVM_CHECK_EXTENSION KVM_CAP_IRQCHIP == 1 (probe shim)
PASS: KVM_CHECK_EXTENSION KVM_CAP_IRQFD == 0
PASS: KVM_CREATE_VM
PASS: KVM_SET_USER_MEMORY_REGION (slot 0, 2 MiB @ 0x0)
PASS: KVM_CREATE_VCPU(0)
PASS: mmap vcpu fd -> struct kvm_run
PASS: real-mode entry state (cs.base=0, rip=0)
PASS: KVM_RUN #1 -> KVM_EXIT_IO (IN, port 0x10, size 1)
PASS: KVM_RUN #2 -> KVM_EXIT_HLT
ALL TESTS PASSED
```

Exit status 0 on all-pass, 1 otherwise. What it does: creates a VM, maps
2 MiB of guest memory at guest-physical 0x0 containing `in al, 0x10; hlt`,
brings vCPU 0 up in real mode at 0x0, and checks the two expected exits —
first `KVM_EXIT_IO` (direction IN, port 0x10, size 1, count 1), then
`KVM_EXIT_HLT`.

## Interpreting failures

- `FAIL: open /dev/kvm (errno=2 ...)` — no `/dev/kvm`: KVM module not
  loaded, no hardware virtualization, or the personality did not create the
  node. Expected in containers/VMs without nested virt.
- `FAIL: KVM_CREATE_VM (errno=19 ...)` — ENODEV: `/dev/kvm` opened but the
  kernel reports no usable virtualization hardware (check BIOS/firmware
  VT-x/AMD-V settings).
- `FAIL: KVM_RUN #1 ... exit_reason=...` — the guest did not execute the
  loaded bytes; check the real-mode entry state (step 8) and that the
  memory region is actually mapped at guest-physical 0x0.
- Any `ENOTTY` on an ioctl — the fd is not a KVM fd, or the compat layer
  does not implement that ioctl number.

## Notes

- Ioctl numbers, cap numbers, exit reasons, and the `kvm_run` (2352 B) /
  `kvm_userspace_memory_region` (32 B) layouts are hand-transcribed from
  `src/kernel/d/core/virt/kvmabi.d`; compile-time size asserts guard the
  structs. If kvmabi.d changes, update this file to match.
- The guest's `in al, 0x10` produces `KVM_EXIT_IO` with direction
  `KVM_EXIT_IO_IN` (0). See the header comment in `kvm-smoke.c` for the
  note on the task text's "out" wording.
- `KVM_CAP_IRQCHIP` returns 1 as a probe shim while `KVM_CREATE_IRQCHIP`
  is rejected with `ENOTTY` (split-irqchip model); `KVM_CAP_IRQFD`
  returns 0 (not implemented).
