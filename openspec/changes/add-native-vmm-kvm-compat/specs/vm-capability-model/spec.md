# Capability: vm-capability-model

Behavior contract for VM and vCPU as first-class anonymOS kernel objects
governed by the capability model.

## ADDED Requirements

### Requirement: VM and vCPU are kernel objects with capability handles

Virtual machines and virtual CPUs SHALL be kernel objects (`ObjType`-level,
alongside File/Process/Domain), created only by the kernel and referenced
from userspace exclusively through capabilities. There SHALL be no ambient
authority to create, configure, run, or destroy a VM: every operation
requires a capability whose rights cover that operation.

#### Scenario: unprivileged creation attempt

A task without any VM capability attempts VM creation → denied and
audit-logged. A task holding a VM capability with only `VM_RUN` rights
attempts to add memory → denied.

### Requirement: Strictly attenuating rights

VM capabilities SHALL carry rights bits (create/configure/run/teardown at
minimum). Delegation SHALL follow the system's existing rule: derived
rights = `want ∩ source.rights ∩ identity.rightsCeiling`; widening is
refused; a missing identity fails closed. Revocation of a VM capability
SHALL transitively revoke all capabilities derived from it.

#### Scenario: attenuation and revocation

An identity whose ceiling lacks VM rights is granted a VM cap → the grant
fails. After revoking a VM cap while a delegated vCPU-run handle exists →
the derived handle stops working.

### Requirement: Explicit lifecycle states

A VM object SHALL move through explicit states: `Defined → Configured →
Running ⇄ Paused → Stopped`, plus `Failed` from any state on unrecoverable
error. Operations invalid in the current state SHALL be rejected (e.g.,
adding memory while `Running`, running while `Defined` without vCPUs).
State transitions SHALL be visible to the holder (queryable) and
audit-logged for create/destroy.

#### Scenario: illegal transition

A VM in `Running` state receives an add-memory request → rejected. A VM in
`Defined` with no vCPUs receives a run request → rejected. Both leave the
VM's state unchanged.

### Requirement: Stale-handle protection

VM/vCPU handles SHALL carry generation counters. Using a handle after its
object was destroyed and its slot recycled SHALL be detected and rejected —
never silently operating on a different VM.

#### Scenario: handle use after destroy

A VM is created (handle generation 3), destroyed, and a new VM reuses the
slot (generation 4). An operation issued with the generation-3 handle →
rejected as stale; the generation-4 VM is untouched.

### Requirement: Memory-range validation

Every guest-physical memory registration SHALL be validated: ranges must
not overlap, must be within the granter's authority (backed by pages the
VM's identity is entitled to via its Untyped budget or explicit grant),
and flags (read-only vs writable) must be honored by the EPT. Overlapping
or out-of-authority registrations SHALL be rejected before any mapping is
created.

#### Scenario: overlapping and out-of-authority regions

Registering region B overlapping already-registered region A → rejected.
Registering a region backed by pages outside the VM's entitlement →
rejected. No EPT mapping is created in either case.

### Requirement: CPU-state validation

vCPU state set from userspace (registers, segment registers, MSRs, CPUID
leaves, LAPIC state) SHALL be validated for values that would compromise
the host: reserved-bit violations, host-MSR clobbering attempts, and
real-mode/protected-mode inconsistencies the backend cannot safely enter
SHALL be rejected with `EINVAL`. The kernel SHALL NOT trust the VMM to
provide safe state.

#### Scenario: hostile vCPU state

A VMM attempts to set a reserved bit in CR4 and a host-owned MSR via the
vCPU state ioctls → both rejected with `EINVAL`; the vCPU's prior valid
state is unchanged.

### Requirement: Resource ceilings

Per-identity and per-domain ceilings SHALL bound: maximum VMs, maximum
vCPUs per VM and total, maximum guest memory. Allocation beyond a ceiling
SHALL fail cleanly with `ENOSPC`/`EDQUOT`-style errors, never partially
applied.

#### Scenario: ceiling enforcement

A domain ceiling is 2 VMs / 4 GiB. Creating a third VM → rejected;
creating a 5 GiB VM → rejected. The first two VMs keep running
undisturbed.

### Requirement: Teardown and reclamation

Destroying a VM SHALL synchronously stop all its vCPUs, tear down EPT
mappings, release all granted pages back to the free pool (honoring CoW
refcounts), invalidate all handles, and move the object to `Stopped`.
After teardown, no guest code SHALL be executable and no host page SHALL
remain mapped for the guest. Repeated create/destroy cycles SHALL NOT
leak pages (verified by the page allocator's audit counters).

#### Scenario: teardown reclaims everything

A VM with 1 GiB of guest memory and 2 vCPUs is destroyed. The allocator's
audit counters return to their pre-creation values; all handles are
invalid; no EPT mapping for the VM remains.
