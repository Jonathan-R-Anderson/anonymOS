# Capability: reusable-vmm-integration

Behavior contract for running an existing, unmodified-as-possible VMM
against the anonymOS KVM-compatibility ABI.

## ADDED Requirements

### Requirement: Cloud Hypervisor boots a guest

Cloud Hypervisor (pinned version, documented in `design.md`), running as
a confined Linux-personality program, SHALL be able to boot a Linux guest
to userspace using only the `kvm-compatibility` ABI: open `/dev/kvm`,
create VM, register memory, create vCPUs, initialize vCPU state, wire
irqfd/ioeventfd/GSI routing, and run the `KVM_RUN` loop with userspace
virtio device emulation. Success is defined as guest kernel boot logs on
the virtual serial port.

#### Scenario: guest boot

Cloud Hypervisor is launched in the VMM domain with a Linux guest image.
The guest kernel boots to userspace; its boot logs appear on the virtual
serial port. No Cloud Hypervisor error about unsupported KVM ioctls
appears.

### Requirement: No VMM source forks

Integration SHALL NOT fork or patch the VMM's source to accommodate
anonymOS. If the VMM needs an anonymOS-specific adaptation, it SHALL be
done via configuration, a documented ABI gap, or a clearly-marked
compatibility shim outside the VMM tree — never a private fork.

#### Scenario: pristine VMM tree

The Cloud Hypervisor sources used for the boot test are byte-identical
to the pinned upstream release (verified by hash). All anonymOS-specific
handling lives in configuration or documented shims.

### Requirement: Documented ABI gaps per VMM

For each evaluated VMM (Cloud Hypervisor, Firecracker, crosvm, libkrun,
StratoVirt), the integration notes SHALL document: which required ioctls
are supported, which are missing, and the resulting boot/no-boot verdict
with the exact failing call. A VMM SHALL NOT be claimed as supported
without a demonstrated boot.

#### Scenario: gap table

The integration notes contain a per-VMM table. Firecracker's row names
`KVM_CREATE_IRQCHIP` as the first failing call and records the verdict
"blocked on full-irqchip tier" — not "supported".

### Requirement: Full-irqchip VMMs are a later tier

VMMs requiring `KVM_CREATE_IRQCHIP`/`KVM_CREATE_PIT2` (Firecracker,
crosvm default, libkrun default, StratoVirt) SHALL be documented as
"blocked on the full-irqchip tier", with the missing ioctls named. No
partial or emulated claim of support is permitted.

#### Scenario: honest non-support

A user asks whether Firecracker runs on anonymOS. The documentation
answers: no — it requires the in-kernel irqchip, which is a planned
later tier; Cloud Hypervisor is the supported VMM today.

### Requirement: Virtio device expectations

The guest SHALL observe virtio devices (block, net, console at minimum)
emulated in userspace by the VMM via `KVM_EXIT_IO`/`KVM_EXIT_MMIO` and
doorbell/eventfd mechanisms. The kernel SHALL NOT implement virtio
devices itself.

#### Scenario: virtio block I/O

The guest reads a file from its virtio-blk root disk. The block I/O
completes through the VMM's userspace device model; the kernel's role is
limited to delivering MMIO exits and irqfd interrupts.
