module kernel.core.init_stubs;

// Prevent generation of ModuleInfo when using LDC. Without this pragma the
// linker may fail if druntime is not linked in. These stub implementations are
// only placeholders so we explicitly disable ModuleInfo emission.
pragma(LDC_no_moduleinfo);

public:
extern(C) void init_cpu_features() {}
extern(C) void init_cmos_rtc() {}
extern(C) void init_frame_allocator(void* multiboot_info_ptr) {}
extern(C) void init_paging() {}
extern(C) void init_kernel_heap() {}
extern(C) void init_device_manager(void* multiboot_info_ptr) {}
extern(C) void init_namespace_manager(void* multiboot_info_ptr) {}
extern(C) void init_capability_supervisor() {}
extern(C) void init_keyboard_driver()
{
    import kernel.keyboard : initialize_keyboard;
    import kernel.device.pic : irq_clear_mask;

    initialize_keyboard();
    // Ensure keyboard interrupts are unmasked
    irq_clear_mask(1);
}
extern(C) void init_pci_bus() {}
extern(C) void init_scheduler() {}
extern(C) void init_syscall_interface()
{
    import kernel.syscall : syscall_init;
    syscall_init();
}
extern(C) void launch_init_process() {}
