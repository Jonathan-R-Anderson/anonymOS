// kernel/main.d

module kernel.main;

import kernel.types : VGAColor, ErrorCode;
import kernel.terminal; // Imports VGA_ADDRESS, vga_entry, vga_entry_color, terminal_initialize, etc.
import kernel.arch_interface.gdt : init_gdt; // Updated import path
import kernel.arch_interface.idt : init_idt; // Updated import path
import kernel.shell : basic_tty_shell;       // Simple interactive shell
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

// Core OS Managers from the Blueprint
extern (C) void init_device_manager(void* multiboot_info_ptr);      // Manages /dev, user-space drivers
extern (C) void init_namespace_manager(void* multiboot_info_ptr);   // Manages per-process namespaces, overlays
extern (C) void init_capability_supervisor(); // Enforces capability-based security
extern (C) void launch_init_process();        // Launches the first user-space process (e.g., /system/init)



// Utility to halt the system safely
void loop_forever_hlt() {
    terminal_writestring_color("System Halted.\n", VGAColor.WHITE, VGAColor.RED);
    while (true) {
        asm { "hlt"; } // Halt until next interrupt (or forever if none)
    }
}

// VGA Constants

// Kernel's main entry point
// The 'multiboot_info_ptr' would be passed from your assembly _start routine
extern (C) void kmain(void* multiboot_info_ptr) {
    ushort* pVGATest = cast(ushort*) VGA_ADDRESS;
    pVGATest[0] = vga_entry('K', vga_entry_color(VGAColor.CYAN, VGAColor.BLACK));
    pVGATest[1] = vga_entry('0', vga_entry_color(VGAColor.CYAN, VGAColor.BLACK));

    // Phase 1: Early Architecture Setup (GDT, IDT) & Terminal
    // These are fundamental and must come first.
    pVGATest[2] = vga_entry('G', vga_entry_color(VGAColor.LIGHT_GREEN, VGAColor.BLACK)); // G for GDT
    init_gdt();
    pVGATest[3] = vga_entry('D', vga_entry_color(VGAColor.LIGHT_GREEN, VGAColor.BLACK)); // D for GDT Done (or I for IDT)

    pVGATest[4] = vga_entry('I', vga_entry_color(VGAColor.LIGHT_MAGENTA, VGAColor.BLACK)); // I for IDT
    init_idt(); // This will also enable interrupts if designed to do so, be ready!
    pVGATest[5] = vga_entry('D', vga_entry_color(VGAColor.LIGHT_MAGENTA, VGAColor.BLACK)); // D for IDT Done

    // Initialize terminal (console output)
    pVGATest[6] = vga_entry('T', vga_entry_color(VGAColor.YELLOW, VGAColor.BLACK)); // T for Terminal Init
    terminal_initialize();
    pVGATest[7] = vga_entry('D', vga_entry_color(VGAColor.YELLOW, VGAColor.BLACK)); // D for Terminal Done

    terminal_writestring("GremlinOS: Core Arch & Terminal Initialized.\n");

    // Phase 2: "preInit" - CPU features, early hardware
    terminal_writestring("Initializing CPU features & early hardware...\n");
    // init_cpu_features(); // For LAPIC, TSC etc. Important for SMP and precise timing.
                         // The Haskell RTS might benefit from a timer source.
    // init_cmos_rtc();     // To get current time, if needed.

    // Phase 3: Memory Management - CRITICAL for Haskell
    // Also foundational for all subsequent managers and processes.
    terminal_writestring("Initializing Memory Management (Frames, Paging, Heap)...\n");
    // init_frame_allocator(multiboot_info_ptr); // Needs memory map from bootloader
    // init_paging();                            // Enable virtual memory
    // init_kernel_heap();                     // For dynamic allocations by kernel & RTS

    // Phase 4: Core OS Managers (as per blueprint)
    // These managers are crucial for realizing the dynamic, secure architecture.
    terminal_writestring("Initializing Core OS Managers...\n");
    // init_device_manager(multiboot_info_ptr);      // Sets up /dev and prepares for user-space drivers.
                                                 // Aligns with "Everything is a file" for devices.
    // init_namespace_manager(multiboot_info_ptr);   // Prepares for per-process virtual filesystems and overlays.
                                                 // Key for modular inheritance and isolation.
    // init_capability_supervisor(); // Initializes the framework for capability-based security.

    // Phase 5: Other Drivers and Kernel Services (can be managed/loaded via Device Manager later)
    terminal_writestring("Initializing remaining Drivers & Kernel Services...\n");
    // init_keyboard_driver();   // Essential for interactive shell input!
    // init_pci_bus();           // For discovering other devices (e.g., network, storage)
    // init_scheduler();         // If Haskell RTS uses preemptive scheduling or needs timers
    // init_syscall_interface(); // If the shell or Haskell programs need kernel services

    // Phase 6: Filesystem Initialization (Root FS, Initrd)
    // The Namespace Manager will heavily interact with this.
    terminal_writestring("Initializing Filesystem (e.g., initrd)...\n");
    // init_filesystem(multiboot_info_ptr); // To load files, e.g., shell resources or other programs

    terminal_writestring("All subsystems (stubs) initialized.\n");

    // Phase 7: Launch the first user-space process (PID 1 - /system/init)
    // This process will then use the initialized managers to set up the user environment,
    // load applications (snaps/recipes), etc., according to the declarative configuration.
    // terminal_writestring("Attempting to launch Init Process...\n");
    // launch_init_process(); // This would not return if successful.

    // For now, we'll fall through to the Haskell shell for direct testing.
    // In the full blueprint, the Haskell shell itself might be an app launched by /system/init.
    // For now, fall through to a very basic built-in shell for direct testing.
    terminal_writestring("Starting basic TTY shell...\n");
    basic_tty_shell();

    // This part should ideally not be reached if the shell takes over.
    // If it is, it means the shell exited or failed to start.
    terminal_writestring_color("Shell exited or failed to initialize.\n", VGAColor.RED, VGAColor.BLACK);
    loop_forever_hlt();
}