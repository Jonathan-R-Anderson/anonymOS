module anonymos.kernel.kernel;

public import anonymos.kernel.memory;

import anonymos.display.framebuffer;
import anonymos.display.modesetting : enableDisplayPipeline, ModesetResult;
import anonymos.display.gpu_accel : configureAccelerationFromModeset;
import anonymos.display.splash : renderBootSplash;
import anonymos.console : clearScreen, print, printLine, printStageHeader, printUnsigned, setFramebufferConsoleEnabled;
import anonymos.serial : initSerial;
import anonymos.hardware : probeHardware;
import anonymos.kernel.physmem : physMemInit;
import anonymos.multiboot : FramebufferModeRequest, MultibootContext;
import anonymos.display.desktop : desktopProcessEntry;
import anonymos.syscalls.posix : posixInit, registerProcessExecutable, spawnRegisteredProcess,
    schedYield, ProcessEntry;
import anonymos.kernel.interrupts : initializeInterrupts;
import anonymos.kernel.cpu : initializeCPUState;
import anonymos.drivers.pci : initializePCI;
import anonymos.kernel.shell_integration : compilerBuilderProcessEntry;
import anonymos.syscalls.syscalls : initSyscalls;
import anonymos.security_config : verifySecurityConfig;

/// Entry point invoked from boot.s once the CPU is ready to run D code.
/// Initialises the VGA output and runs the compiler build program.
extern(C) void kmain(ulong magic, ulong info)
{
    cast(void) magic;
    cast(void) info;

    clearScreen();
    initSerial();
    
    verifySecurityConfig();
    initializeCPUState();
    
    auto context = probeHardware(magic, info);
    if (!context.valid)
    {
        printLine("[kernel] Multiboot info unavailable; halting.");
        while (true)
        {
            asm { hlt; }
        }
    }
    physMemInit(cast(void*)&context);

    import anonymos.kernel.pagetable : initKernelLinearMapping;
    import anonymos.kernel.physmem : totalFrames;
    initKernelLinearMapping(totalFrames() * 4096);

    initializePCI();
    
    import anonymos.drivers.ahci : initAHCI;
    initAHCI();

    const ModesetResult display = tryBringUpDisplay(context);
    const bool framebufferReady = display.framebufferReady;

    // If no framebuffer, inform user that shell will be available via serial
    if (!framebufferReady)
    {
        printLine("");
        printLine("========================================");
        printLine("  No Framebuffer Detected");
        printLine("========================================");
        printLine("Graphics desktop is unavailable.");
        printLine("The lfe-sh shell will be accessible");
        printLine("via serial console after toolchain build.");
        printLine("");
        printLine("Connect via: -serial stdio (QEMU)");
        printLine("========================================");
        printLine("");
    }

    initializeInterrupts();
    initSyscalls();

    // Reset object store before parsing initrd to avoid stale entries between boots.
    import anonymos.objects : resetObjectStore;
    resetObjectStore();

    posixInit();

    // Ensure g_current is set before enabling interrupts so PIT/NMI don't
    // run on an uninitialised stack.
    schedYield();

    // Load initrd if present
    if (context.valid)
    {
        const size_t modCount = context.moduleCount();
        for (size_t i = 0; i < modCount; ++i)
        {
            auto mod = context.moduleAt(i);
            if (mod !is null)
            {
                // Check if it's the initrd (simple check: assume first module or check string)
                // For now, just assume any module is the initrd.
                // In future, check mod.stringPtr for "initrd"
                
                const(ubyte)[] modData = (cast(const(ubyte)*)cast(size_t)mod.modStart)[0 .. (mod.modEnd - mod.modStart)];
                
                printLine("[kernel] Loading initrd module...");
                import anonymos.fs : parseTarball;
                parseTarball(modData);
                printLine("[kernel] Initrd loaded.");
            }
        }
    }

    // Register processes that should run alongside the kernel core.
    version (MinimalOsUserlandLinked)
    {
        ProcessEntry builderEntry = &compilerBuilderProcessEntry;
        const int builderRegistration = registerProcessExecutable(
            "/sbin/compiler-builder",
            builderEntry
        );
        if (builderRegistration == 0)
        {
            cast(void) spawnRegisteredProcess("/sbin/compiler-builder", null, null);
        }
    }
    else
    {
        printLine("[kernel] Compiler builder disabled (MinimalOsUserlandLinked not set)");
    }

    // Only spawn desktop if framebuffer is available
    if (framebufferReady)
    {
        const int desktopRegistration = registerProcessExecutable("/sbin/desktop",
            &desktopProcessEntry);
        if (desktopRegistration == 0)
        {
            cast(void) spawnRegisteredProcess("/sbin/desktop", null, null);
        }
    }
    else
    {
        printLine("[kernel] Graphics desktop disabled - framebuffer unavailable");
        printLine("[kernel] Serial shell will be available after build completes");
        printLine("");
    }

    // Spawn installer for testing
    printLine("[kernel] Spawning /bin/installer...");
    cast(void) spawnRegisteredProcess("/bin/installer", null, null);

    // Now that init/g_current are ready, enable interrupts.
    asm { sti; }
}

private @nogc nothrow ModesetResult tryBringUpDisplay(const MultibootContext context)
{
    FramebufferModeRequest fbRequest;
    fbRequest.desiredWidth  = 1024;
    fbRequest.desiredHeight = 768;
    fbRequest.desiredBpp    = 32;
    fbRequest.desiredModeNumber = context.valid ? context.info.vbeMode : 0;
    fbRequest.allowFallback = true;

    ModesetResult result = enableDisplayPipeline(context, fbRequest);
    if (result.framebufferReady)
    {
        configureAccelerationFromModeset(result);
        renderBootSplash();
        // Keep framebuffer console enabled so kernel logs remain visible during
        // desktop bring-up and debugging.
        setFramebufferConsoleEnabled(true);
    }
    else
    {
        printLine("[kernel] Graphics desktop disabled - framebuffer unavailable");
        printLine("[kernel] Serial shell will be available after build completes");
        printLine("");
    }

    return result;
}
