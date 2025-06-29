// kernel/main.d

module kernel.main;

import kernel.types : VGAColor, ErrorCode;
import kernel.terminal; // Imports VGA_ADDRESS, vga_entry, vga_entry_color, terminal_initialize, etc.
import kernel.device.vga : clear_screen;
import kernel.arch_interface.gdt : init_gdt; // Updated import path
import kernel.arch_interface.idt : init_idt, idt_ptr; // Updated import path
import kernel.device.pic : initialize_pic, irq_clear_mask; // PIC initialization and PIC setup
import kernel.shell : sh_shell, build_d_compiler, build_shell, init_setup; // -sh shell and build helpers
import kernel.lib.stdc.stdlib : system;
import kernel.logger : logger_init, log_message, log_register_state, log_hex, log_mem_dump, log_test; // New logging utilities
import kernel.arch_interface.gdt : gdt_ptr;
import kernel.hardware.network : net_init;
import kernel.net.stack : net_stack_init, net_poll;
import kernel.sanity : run_sanity_checks;
import kernel.thread : thread_init, thread_create, thread_start, thread_yield, threads_active, thread_exit;

// kernel.interrupts is not directly called by kmain but its symbols are needed by IDT setup.
// kernel.panic is used implicitly if needed.

// --- Placeholder FFI Declarations for OS Subsystems ---
// These functions would need to be implemented in their respective modules.
// Their exact signatures (especially regarding parameters like Multiboot info)
// will depend on your design.

// CPU & Architecture Specific
extern (C) void init_cpu_features();      // e.g., LAPIC, TSC (Time Stamp Counter)

// Memory Management
extern (C) void init_frame_allocator(void* multiboot_info_ptr); // Needs memory map
extern (C) void init_paging();
extern (C) void init_kernel_heap();

// Hardware Drivers
extern (C) void init_cmos_rtc();          // For time/date
extern (C) void init_keyboard_driver();   // Essential for an interactive shell
extern (C) void init_pci_bus();           // For discovering hardware

// Core OS Services
extern (C) void init_scheduler();         // May be needed by Haskell RTS
extern (C) void init_syscall_interface(); // If shell/apps need kernel services
extern (C) void init_filesystem(void* multiboot_info_ptr); // For initrd/root fs
extern (C) void init_user_manager();
extern (C) void init_container_service();
extern (C) void vmm_init();

// Core OS Managers from the Blueprint
extern (C) void init_device_manager(void* multiboot_info_ptr);      // Manages /dev, user-space drivers
extern (C) void init_namespace_manager(void* multiboot_info_ptr);   // Manages per-process namespaces, overlays
extern (C) void init_capability_supervisor(); // Enforces capability-based security
extern (C) void launch_init_process();        // Launches the first user-space process (e.g., /system/init) and returns when it exits



// Utility to halt the system safely
void loop_forever_hlt() {
    terminal_writestring_color("System Halted.\n", VGAColor.WHITE, VGAColor.RED);
    while (true) {
        asm { "hlt"; } // Halt until next interrupt (or forever if none)
    }
}

// Startup thread routines
extern(C) void t_init_process() { launch_init_process(); thread_exit(); }
extern(C) void t_sanity() { run_sanity_checks(); thread_exit(); }
extern(C) void t_build() { build_d_compiler(); build_shell(); thread_exit(); }

// VGA Constants

// Kernel's main entry point
// The 'multiboot_info_ptr' would be passed from your assembly _start routine
extern (C) void kmain(void* multiboot_info_ptr) {
    ushort* pVGATest = cast(ushort*) VGA_ADDRESS;
    pVGATest[0] = vga_entry('K', vga_entry_color(VGAColor.CYAN, VGAColor.BLACK));
    pVGATest[1] = vga_entry('0', vga_entry_color(VGAColor.CYAN, VGAColor.BLACK));

    logger_init();

    // Initialize terminal early so Plymouth output is visible
    terminal_initialize();
    terminal_writestring_color("anonymOS booting...\n", VGAColor.LIGHT_BLUE, VGAColor.BLACK);

    // Phase 1: Early Architecture Setup (GDT, IDT) & Terminal
    // These are fundamental and must come first.
    pVGATest[2] = vga_entry('G', vga_entry_color(VGAColor.CYAN, VGAColor.BLACK)); // G for GDT
    init_gdt();
    log_message("GDT base: ");
    log_hex(gdt_ptr.base);
    log_message("\n");
    log_register_state("After GDT Setup");
    pVGATest[3] = vga_entry('D', vga_entry_color(VGAColor.LIGHT_GREEN, VGAColor.BLACK)); // D for GDT Done (or I for IDT)
    clear_screen();

    pVGATest[4] = vga_entry('I', vga_entry_color(VGAColor.LIGHT_MAGENTA, VGAColor.BLACK)); // I for IDT
    init_idt(); // Set up IDT
    log_message("IDT ptr base after init: ");
    log_hex(idt_ptr.base);
    log_message("\n");
    initialize_pic(); // Remap and configure PIC
    irq_clear_mask(0); // Timer
    irq_clear_mask(1); // Keyboard
    asm { "sti"; } // Enable interrupts
    //log_register_state("After IDT Setup");
    pVGATest[5] = vga_entry('D', vga_entry_color(VGAColor.LIGHT_MAGENTA, VGAColor.BLACK)); // D for IDT Done
    //clear_screen();

    // Terminal was initialized earlier to display Plymouth. Mark progress here.
    pVGATest[6] = vga_entry('T', vga_entry_color(VGAColor.YELLOW, VGAColor.BLACK)); // T for Terminal Init
    pVGATest[7] = vga_entry('D', vga_entry_color(VGAColor.YELLOW, VGAColor.BLACK)); // D for Terminal Done
    
    //clear_screen();

    
    log_test();
    log_message("anonymOS: Core Arch & Terminal Initialized.\n");
    log_message("Boot info ptr: ");
    log_hex(cast(ulong)multiboot_info_ptr);
    log_message("\n");
    log_mem_dump(multiboot_info_ptr, 64);
    clear_screen();
    log_register_state("Initial Registers");

    // Phase 2: "preInit" - CPU features, early hardware
    log_message("Initializing CPU features & early hardware...\n");
    terminal_writestring("Initializing CPU features...\n");
    init_cpu_features(); // For LAPIC, TSC etc. Important for SMP and precise timing.
                         // The Haskell RTS might benefit from a timer source.
    init_cmos_rtc();     // To get current time, if needed.
    clear_screen();

    // Phase 3: Memory Management - CRITICAL for Haskell
    // Also foundational for all subsequent managers and processes.
    log_message("Initializing Memory Management (Frames, Paging, Heap)...\n");
    terminal_writestring("Initializing memory management...\n");
    init_frame_allocator(multiboot_info_ptr); // Needs memory map from bootloader
    init_paging();                            // Enable virtual memory
    init_kernel_heap();                       // For dynamic allocations by kernel & RTS
    log_register_state("After Memory Init");
    log_message("First 64 bytes of boot info:\n");
    log_mem_dump(multiboot_info_ptr, 64);
    clear_screen();

    // Phase 4: Core OS Managers (as per blueprint)
    // These managers are crucial for realizing the dynamic, secure architecture.
    log_message("Initializing Core OS Managers...\n");
    terminal_writestring("Setting up core managers...\n");
    init_device_manager(multiboot_info_ptr);      // Sets up /dev and prepares for user-space drivers.
                                                 // Aligns with "Everything is a file" for devices.
    init_namespace_manager(multiboot_info_ptr);   // Prepares for per-process virtual filesystems and overlays.
                                                 // Key for modular inheritance and isolation.
    init_capability_supervisor(); // Initializes the framework for capability-based security.
    clear_screen();

    // Phase 5: Other Drivers and Kernel Services (can be managed/loaded via Device Manager later)
    log_message("Initializing remaining Drivers & Kernel Services...\n");
    terminal_writestring("Starting drivers and services...\n");
    init_keyboard_driver();   // Essential for interactive shell input!
    init_pci_bus();           // For discovering other devices (e.g., network, storage)
    net_init();               // Initialize NIC queues
    ubyte[6] mac = [0x02,0x00,0x00,0x00,0x00,0x02];
    uint ip = 0xC0A80064; // 192.168.0.100
    net_stack_init(mac.ptr, ip);
    net_poll();               // Process any early packets
    vmm_init();               // Initialize hypervisor
    init_scheduler();         // If Haskell RTS uses preemptive scheduling or needs timers
    init_syscall_interface(); // If the shell or Haskell programs need kernel services
    init_container_service(); // Initialize container service (stub)
    clear_screen();

    // Phase 6: Filesystem Initialization (Root FS, Initrd)
    // The Namespace Manager will heavily interact with this.
    log_message("Initializing Filesystem (e.g., initrd)...\n");
    terminal_writestring("Mounting filesystem...\n");
    init_filesystem(multiboot_info_ptr); // To load files, e.g., shell resources or other programs
    init_user_manager();
    log_message("Temporary user 'setup' created for initial account setup.\n");
    clear_screen();

    log_message("All subsystems (stubs) initialized.\n");
    log_register_state("Before Init Process");
    log_message("Boot info snapshot:\n");
    log_mem_dump(multiboot_info_ptr, 64);
    clear_screen();

    // Phase 7: Launch the first user-space process (PID 1 - /system/init)
    // This process will then use the initialized managers to set up the user environment,
    // load applications (snaps/recipes), etc., according to the declarative configuration.
    log_message("Attempting to launch Init Process...\n");
    terminal_writestring_color("Boot complete.\n", VGAColor.GREEN, VGAColor.BLACK);
    // Run setup tasks sequentially instead of using the minimal
    // cooperative thread system. This avoids the possibility of a
    // misbehaving thread preventing the system from reaching the shell.
    launch_init_process();
    run_sanity_checks();
    build_d_compiler();
    build_shell();

    // All setup tasks completed
    clear_screen();

    // Start the builtin -sh shell for direct testing.
    log_message("Starting -sh shell...\n");
    system("sh");
    clear_screen();

    log_register_state("Shell exited");

    // This part should ideally not be reached if the shell takes over.
    // If it is, it means the shell exited or failed to start.
    log_message("Shell exited or failed to initialize.\n");
    terminal_writestring_color("Shell exited or failed to initialize.\n", VGAColor.RED, VGAColor.BLACK);
    clear_screen();
    loop_forever_hlt();
}
