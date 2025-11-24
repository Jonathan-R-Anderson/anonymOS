module minimal_os.kernel.kernel;

public import minimal_os.kernel.memory;

import minimal_os.display.framebuffer;
import minimal_os.display.modesetting : enableDisplayPipeline, ModesetResult;
import minimal_os.display.gpu_accel : configureAccelerationFromModeset;
import minimal_os.display.splash : renderBootSplash;
import minimal_os.console : clearScreen, print, printLine, printStageHeader, printUnsigned, setFramebufferConsoleEnabled;
import minimal_os.serial : initSerial;
import minimal_os.hardware : probeHardware;
import minimal_os.multiboot : FramebufferModeRequest, MultibootContext;
import minimal_os.display.desktop : desktopProcessEntry;
import minimal_os.posix : posixInit, registerProcessExecutable, spawnRegisteredProcess,
    schedYield, ProcessEntry;
import minimal_os.kernel.interrupts : initializeInterrupts;
import minimal_os.kernel.cpu : initializeCPUState;
import minimal_os.drivers.pci : initializePCI;
import minimal_os.kernel.shell_integration : compilerBuilderProcessEntry;
import minimal_os.kernel.syscalls : initSyscalls;

/// Entry point invoked from boot.s once the CPU is ready to run D code.
/// Initialises the VGA output and runs the compiler build program.
extern(C) void kmain(ulong magic, ulong info)
{
    cast(void) magic;
    cast(void) info;

    clearScreen();
    initSerial();
    initializeCPUState();
    auto context = probeHardware(magic, info);

    initializePCI();

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
    import minimal_os.objects : resetObjectStore;
    resetObjectStore();

    posixInit();

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
                import minimal_os.fs : parseTarball;
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

    // Idle the kernel while co-operative tasks (desktop, compiler, shell) run.
    while (true)
    {
        schedYield();
        asm { hlt; }
    }
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
