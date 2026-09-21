# Proposal: add-native-vmm-kvm-compat

## Why

anonymOS has no hypervisor. Verified by repository-wide search: zero hits for
`vmx|svm|vmcs|vmcb|ept|npt|vcpu` in `src/`, `tests/`, `docs/` — `CR4.VMXE` is never
set and the roadmap explicitly states "anonymOS has no hypervisor … so VM management
means managing *domains*, not guests". Domains provide process-level isolation, but
there is no hardware-virtualized boundary anywhere in the system: no confidential
compute, no running untrusted OS kernels, no reuse of the mature Linux VMM
ecosystem (Cloud Hypervisor, Firecracker, crosvm). This change adds a native
hardware-virtualization substrate to the anonymOS kernel and a KVM-compatible ABI
on top of it, so existing VMMs can run as confined anonymOS programs.

## What Changes

- **Native VM objects**: new kernel object types for virtual machines and virtual
  CPUs, created only by the kernel and handed out as capabilities. VM lifecycle
  (create → configure memory → create vCPU → run → known exit → teardown) is
  capability-gated at every step; rights attenuate strictly and revocation kills
  the forward derive-DAG.
- **x86 virtualization backend**: kernel-owned VMX implementation (VMXON,
  per-vCPU VMCS, EPT for guest-physical → host-physical translation, host-state
  safety on every transition). SVM is staged and fail-closed: detected, reported,
  never claimed without validation on real AMD hardware.
- **KVM compatibility ABI**: a `/dev/kvm` device node plus ioctl dispatch
  implementing the evidence-derived subset that Cloud Hypervisor needs to boot a
  guest on x86_64 (system/VM/vCPU fd trinity, `kvm_run` mmap, split-irqchip via
  `KVM_ENABLE_CAP`, GSI routing, irqfd, ioeventfd). KVM is a *compatibility* ABI
  only — the native VM objects remain the authority model.
- **VMM confinement**: the VMM process runs in a normal restricted anonymOS
  domain (deny-by-default namespace, identity rights ceiling, explicit device
  grants). No ambient filesystem, device, or physical-memory access.
- **Machine profiles**: lightweight (microVM-style) and compatibility (full-VM)
  profiles as machine *composition* over the one substrate, following StratoVirt's
  `LightMachine`/`StdMachine` precedent — profiles, not separate security
  technologies.
- **AppVM execution integration**: AppVM gains a backend that launches
  applications inside hardware-virtualized VMs through this substrate.

What this change does **not** do: no in-kernel 8259 PIC / IOAPIC / PIT
(`KVM_CREATE_IRQCHIP`/`KVM_CREATE_PIT2`) — required by Firecracker, crosvm,
libkrun and StratoVirt on x86_64 but explicitly *not* by Cloud Hypervisor, which
uses split irqchip with a userspace IOAPIC. Full-irqchip VMMs are a documented
later tier. No arbitrary physical-device passthrough. No Windows-guest claims
without evidence.

## Capabilities

### New Capabilities

- `native-hardware-virtualization`: kernel VMX backend — VMXON/VMCLEAR/VMLAUNCH/
  VMRESUME, per-vCPU VMCS management, EPT mapping of guest memory, VM-exit
  dispatch (IO, MMIO, HLT, shutdown, EPT violations), host-state save/restore
  safety. SVM detection present, execution fail-closed until validated.
- `vm-capability-model`: VM and vCPU as first-class kernel objects with
  capability handles — creation, rights (create/configure/run/teardown),
  lifecycle states, stale-handle protection, memory-range and CPU-state
  validation, resource ceilings, teardown and page reclamation.
- `kvm-compatibility`: `/dev/kvm` node, system/VM/vCPU fd model, ioctl dispatch
  for the Cloud Hypervisor baseline subset (`KVM_GET_API_VERSION`,
  `KVM_CHECK_EXTENSION`, `KVM_CREATE_VM`, `KVM_SET_USER_MEMORY_REGION`,
  `KVM_SET_TSS_ADDR`, `KVM_SET_IDENTITY_MAP_ADDR`, `KVM_ENABLE_CAP`
  (split-irqchip), `KVM_CREATE_VCPU`, `KVM_GET_VCPU_MMAP_SIZE`,
  `KVM_SET_CPUID2`, `KVM_SET_MSRS`, `KVM_SET_REGS`, `KVM_GET/SET_SREGS`,
  `KVM_SET_FPU`, `KVM_GET/SET_LAPIC`, `KVM_SET_GSI_ROUTING`, `KVM_IRQFD`,
  `KVM_IOEVENTFD`, `KVM_RUN`), `kvm_run` shared-memory mmap, exit structs the
  kernel must produce.
- `vmm-domain-confinement`: policy for running a VMM inside a restricted
  anonymOS domain — required/forbidden capabilities, namespace bindings, device
  grant denials, resource ceilings, audit expectations.
- `reusable-vmm-integration`: bringing up an existing VMM (primary: Cloud
  Hypervisor) against the compat ABI — build/packaging, boot protocol, virtio
  device expectations, known gaps vs the VMM's required surface.
- `appvm-execution-integration`: AppVM backend targeting the native substrate —
  VM lifecycle from AppVM's orchestration, guest image handling, console/serial
  expectations.

### Modified Capabilities

(none — OpenSpec was initialized with this change; there is no prior spec
inventory. All behavior above is new.)

## Impact

- **Kernel** (`src/kernel/d/`): new `core/vm.d`-area modules (VM/vCPU objects),
  `arch/x86_64` VMX backend, `/dev/kvm` node in `sys_open`, new `FileType`
  + ioctl/mmap arms in `core/syscalls/posix.d`, EPT integration with `memory/`.
  All new code is `-betterC` D, matching the kernel.
- **Security model**: extends the capability/domain model to hardware
  virtualization; the fundamental boundary becomes (1) native anonymOS domain
  vs (2) hardware-virtualized VM. No change to existing rights semantics.
- **Linux compat**: Linux-personality tasks (the VMM binaries) reach the ABI
  through the existing syscall translation layer (`ioctl`, `mmap`, `eventfd`,
  `epoll`, `memfd_create` all already implemented).
- **Build/test**: kernel build remains LDC2; new in-guest test modules assert
  via the existing `boot-test.sh` serial-log mechanism. No new host-side test
  framework.
- **Docs**: `docs/` gains virtualization architecture and KVM-ABI conformance
  notes; roadmap hypervisor statements stay true (domains unchanged; the
  hypervisor is a new, separate substrate).
