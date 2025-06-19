module kernel.core.init_stubs;

public:
extern(C) void init_cpu_features() {}
extern(C) void init_cmos_rtc() {}
extern(C) void init_frame_allocator(void* multiboot_info_ptr) {}
extern(C) void init_paging() {}
extern(C) void init_kernel_heap() {}
extern(C) void init_device_manager(void* multiboot_info_ptr) {}
extern(C) void init_namespace_manager(void* multiboot_info_ptr) {}
extern(C) void init_capability_supervisor() {}
extern(C) void init_keyboard_driver() {}
extern(C) void init_pci_bus() {}
extern(C) void init_scheduler() {}
extern(C) void init_syscall_interface() {}
extern(C) void init_filesystem(void* multiboot_info_ptr) {}
extern(C) void launch_init_process() {}
