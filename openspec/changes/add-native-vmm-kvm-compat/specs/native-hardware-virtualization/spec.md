# Capability: native-hardware-virtualization

Behavior contract for the anonymOS kernel's x86 hardware-virtualization
backend. This is the native substrate; the KVM compatibility ABI is a
separate capability layered on top.

## ADDED Requirements

### Requirement: VMX availability detection and enablement

The kernel SHALL detect Intel VMX support via `CPUID.1:ECX[5]` and the
`IA32_VMX_BASIC` / `IA32_FEATURE_CONTROL` MSRs, and enable VMX operation
(`CR4.VMXE`, `VMXON` with a per-CPU VMXON region) only when every required
check passes. If VMX is unavailable (bit clear, FEATURE_CONTROL locked off,
or the CPU is AMD), VM creation SHALL fail with a descriptive error and the
kernel SHALL continue to operate normally — virtualization is an optional
subsystem, never a boot dependency.

#### Scenario: boot without VMX

On a CPU without VMX, klog records `vmx: not available (<reason>)`; all VM
creation attempts return `ENODEV`; the rest of the OS is unaffected.

#### Scenario: boot with VMX

On Intel VMX-capable hardware, klog records `vmx: enabled` including the
VMX revision identifier, and `VMXON` succeeds on each CPU that will run
vCPUs.

### Requirement: vCPU execution with host-state safety

Each vCPU SHALL have kernel-owned control state (VMCS) that userspace can
never read or write directly. On every VM entry the kernel SHALL load
host-state fields (host CR3/CR4/RSP/RIP, segment bases, MSRs) from
kernel-owned memory, and on every VM exit the kernel SHALL verify host
state was not corrupted before resuming normal execution. A VM exit caused
by guest misbehavior SHALL never panic the host kernel; it is delivered
to the controlling domain as a contained exit event.

#### Scenario: hostile guest cannot corrupt the host

A test guest executes `VMCALL`, triple-faults, and attempts a
confused-deputy VMCS write. The host kernel continues scheduling; the VM
object moves to `Failed` with a diagnostic; other VMs and native tasks
are unaffected.

### Requirement: EPT-based guest memory isolation

Guest-physical addresses SHALL translate through kernel-managed Extended
Page Tables to host-physical pages. The EPT SHALL map exactly the pages
the VM object was granted — no more. EPT violations (guest access outside
granted memory, or violating granted permissions) SHALL cause a VM exit
that terminates or suspends the VM; they SHALL NOT resolve to host memory.

#### Scenario: guest escapes its grant

A test guest reads a guest-physical page outside its grant. An EPT
violation exit fires naming the faulting guest-physical address; the VM
is paused/terminated. Host memory outside the grant is never exposed.

### Requirement: VM-exit dispatch

The kernel SHALL produce exits for at least: port I/O (`IN`/`OUT`), MMIO
reads/writes, `HLT`, guest shutdown (triple fault), and EPT violations.
Each exit SHALL carry the information a userspace device model needs
(port number / direction / size / data; MMIO address / length / data;
exit reason). Unknown or unhandled exit reasons SHALL terminate the VM
with a diagnostic rather than resuming the guest blindly.

#### Scenario: port I/O exit

A test guest executes `OUT 0x3F8, AL`. The kernel returns a `KVM_EXIT_IO`
(or native equivalent) with port `0x3F8`, direction out, size 1, and the
byte value; the VMM handles it and resumes the guest.

### Requirement: SVM staging is fail-closed

On AMD CPUs the kernel SHALL detect SVM (`CPUID.80000001h:ECX[2]`), record
its presence, and refuse VM creation with `ENODEV` ("SVM backend not
validated") until an SVM backend is implemented *and* tested on real AMD
hardware. The system SHALL NOT claim AMD support based on untested code.

#### Scenario: boot on AMD without validated backend

On AMD EPYC hardware, klog records `svm: detected, backend not validated
— VM creation disabled`; VM creation returns `ENODEV`.
