# eBPF Real-Time Streaming — Troubleshooting Guide

Orin's real-time eBPF streaming engine (`orin stream`) attaches directly to kernel tracepoints to harvest process creation, network connection, and file events via the BPF ring buffer.

Orin uses a **CO-RE (Compile Once – Run Everywhere)** architecture: the eBPF C program is compiled once on a build machine and loaded directly on target systems without requiring any compiler toolchain at runtime.

---

## System Requirements

### Target / Production Hosts

Target hosts have **zero compiler requirements**. They only need the `libbpf` shared library installed:

```bash
# Debian / Ubuntu
sudo apt-get install libbpf1     # Try libbpf0 if libbpf1 is unavailable

# RHEL / Rocky / Alma
sudo dnf install libbpf
```

No kernel headers, `clang`, `llvm`, or BPF compilation tools are required on runtime machines.

### Developer / Build Machines

If you are modifying the eBPF source (`ebpf/streamer.c`) and need to recompile `streamer.bpf.o`, run the setup script with the `--build` flag:

```bash
sudo ./scripts/setup_ebpf.sh --build
```

This installs the required build toolchain (`clang`, `llvm`, `bpftool`, `libbpf-dev` / `libbpf-devel`) and generates a local `vmlinux.h`.

---

## Common Errors and Resolutions

### `libbpf shared library is not loaded` / `Could not find system libbpf library`

**Cause:** The system `libbpf` shared library is missing on the target host.

**Fix:**

```bash
# Debian / Ubuntu
sudo apt-get install libbpf1

# RHEL / Rocky / Alma
sudo dnf install libbpf
```

---

### `Failed to load eBPF program: [Errno 13] Permission denied`

**Cause:** Attaching to kernel tracepoints and creating BPF maps requires root privileges.

**Fix:**

```bash
sudo orin stream
```

---

### `BTF is not supported on this kernel` / `CONFIG_DEBUG_INFO_BTF` is missing

**Cause:** The target kernel does not have BPF Type Format (BTF) data, which is required for CO-RE offset relocation.

**Fix:**

1. Check whether BTF is present:

   ```bash
   ls -la /sys/kernel/btf/vmlinux
   ```

2. If BTF is absent, the kernel cannot support `orin stream`. Use `orin collect` instead, which parses `/proc` and has no kernel BTF requirement.

---

## Kernel Verification

Use the following commands to inspect kernel compilation flags on any machine:

```bash
# Verify the BPF syscall is enabled
grep CONFIG_BPF_SYSCALL /boot/config-$(uname -r)

# Verify BTF is enabled (required for CO-RE)
grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)

# Verify ring buffer support (requires kernel 5.8+)
grep CONFIG_BPF_JIT /boot/config-$(uname -r)
```