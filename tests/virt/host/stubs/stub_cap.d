// HOST STUB for core.cap — used only by tests/virt/host.
//
// Capability-right bits consumed by core.virt.kvm.kvmRequiredRight.
// Values match the real core/cap.d so ioctl right-mapping stays honest.
module core.cap;

extern (C) @nogc nothrow:

enum uint CAP_RIGHT_VM_CREATE  = 1u << 19;
enum uint CAP_RIGHT_VM_MEM     = 1u << 20;
enum uint CAP_RIGHT_VM_RUN     = 1u << 21;
enum uint CAP_RIGHT_VM_CONTROL = 1u << 22;
