# Capability: vmm-domain-confinement

Behavior contract for confining the VMM process itself inside a normal
restricted anonymOS domain.

## ADDED Requirements

### Requirement: VMM runs as a confined domain task

The VMM SHALL execute as an ordinary task inside a restricted anonymOS
domain — not as a privileged service, not in the kernel. The domain SHALL
be created deny-by-default: it sees only its own `/Home` (rw), `/tmp`
(rw), and `/Shared` (ro); `/System` and other domains' private areas are
denied. The VMM SHALL NOT require ambient authority to function.

#### Scenario: namespace denial

A process in the VMM domain attempts to open `/System/config` →
`EACCES`. It opens its VM image under its own `/Home` → success.

### Requirement: Least-authority capability set

The VMM domain's identity SHALL grant exactly: open/read/write/ioctl/mmap
on `/dev/kvm`; `eventfd`/`epoll`/`timerfd`/`memfd_create`/`mmap` for its
own bookkeeping; file access to the VM image/config paths explicitly
granted; network access only if the deployment's virtual network needs
it. It SHALL NOT hold: raw PCI config/MMIO capabilities, physical-memory
mapping rights outside its grants, admin capabilities, or the right to
create domains/identities. Any VMM operation requiring a capability it
does not hold SHALL fail closed and be audit-logged.

#### Scenario: PCI access denied

The VMM attempts a raw PCI config read → denied (`EPERM`) and
audit-logged. Its normal `/dev/kvm` ioctl flow is unaffected.

### Requirement: No device passthrough by default

The VMM domain SHALL NOT be granted arbitrary physical devices. PCI
device grants to the VMM's identity SHALL be denied unless an explicit,
audited administrator action grants a specific device — and physical
device passthrough to guests is out of scope for this change regardless.

#### Scenario: passthrough request

An administrator has not granted any device. The VMM requests a PCI
device grant for its guest → denied. Guest devices remain virtio
emulated in userspace.

### Requirement: Resource ceilings for the VMM domain

The VMM's domain SHALL carry ceilings for CPU time, resident memory, and
number of VMs/vCPUs (inherited from `vm-capability-model`). A runaway
VMM (or a malicious guest driving excessive exits) SHALL be throttled or
killed by the domain's limits without affecting other domains.

#### Scenario: exit storm contained

A malicious guest executes port I/O in a tight loop, generating millions
of exits. The domain's CPU ceiling throttles the VMM; other domains keep
running normally.

### Requirement: Audit of virtualization operations

VM creation, destruction, and failed privilege-escalation attempts
(capability denials) SHALL be audit-logged with the acting identity and
domain. Logs SHALL be readable by the system auditor role.

#### Scenario: audit trail

After a VM lifecycle, the auditor reads the log → finds create/destroy
entries naming the identity and domain, plus any denial entries for
operations the VMM attempted without rights.
