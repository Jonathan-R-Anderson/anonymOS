# Capability: appvm-execution-integration

Behavior contract for AppVM's use of the native virtualization substrate
as an execution backend.

## ADDED Requirements

### Requirement: AppVM can launch a workload in a hardware VM

AppVM SHALL gain an execution backend that creates a VM through the
native substrate (`vm-capability-model`), boots a guest image, and runs
the requested application or command inside it. The backend SHALL reuse
the same VM objects, capability checks, and domain confinement as any
other VMM — AppVM gets no privileged hypervisor path.

#### Scenario: app launch in a VM

A user runs an AppVM command targeting the new backend. A VM is created
through the standard capability flow, the guest boots, the workload
runs, and the VM is torn down afterwards — all without AppVM holding any
hypervisor-privileged capability.

### Requirement: Lifecycle integration

AppVM's existing lifecycle (start/stop/snapshot semantics where they
apply) SHALL map onto the VM object's lifecycle states. Destroying the
AppVM instance SHALL tear down the VM and reclaim its pages; a leaked
VM after AppVM teardown is a bug.

#### Scenario: teardown reclaims the VM

An AppVM instance is destroyed while its VM is running. The VM object
reaches `Stopped`, its pages return to the free pool, and no vCPU thread
survives.

### Requirement: Console and status reporting

The backend SHALL expose the guest's serial console output and report VM
state (running/paused/failed, exit diagnostics) through AppVM's existing
status channels. A guest that fails to boot SHALL produce a diagnostic
naming the failure (bad image, capability denial, resource ceiling)
rather than hanging silently.

#### Scenario: failed boot diagnosis

The guest image is corrupt. Instead of hanging, AppVM reports
"guest failed to boot: <reason>" naming the actual failure (e.g.,
invalid kernel image, memory registration denied).

### Requirement: Same confinement as any VMM

The AppVM backend's VMM component SHALL run under `vmm-domain-confinement`
with no additional ambient authority. AppVM orchestration code keeps its
existing privileges; only the virtualization operations move through the
confined path.

#### Scenario: no privileged path

An audit of the AppVM backend's capabilities shows the virtualization
component holds exactly the VMM-domain capability set — no admin caps,
no raw device access beyond what `vmm-domain-confinement` allows.
