module minimal_os.kernel.kernel;

public import minimal_os.kernel.memory;

import minimal_os.display.framebuffer;
import minimal_os.display.modesetting : enableDisplayPipeline, ModesetResult;
import minimal_os.display.gpu_accel : configureAccelerationFromModeset;
import minimal_os.console : clearScreen, print, printLine, printStageHeader, printUnsigned;
import minimal_os.serial : initSerial;
import minimal_os.hardware : probeHardware;
import minimal_os.multiboot : FramebufferModeRequest, MultibootContext;
import minimal_os.display.desktop : desktopProcessEntry, runSimpleDesktopOnce;
import minimal_os.posix : posixInit, registerProcessExecutable, spawnRegisteredProcess,
    schedYield, initializeInterrupts, ProcessEntry;
import minimal_os.kernel.shell_integration : compilerBuilderProcessEntry;

/// Entry point invoked from boot.s once the CPU is ready to run D code.
/// Initialises the VGA output and runs the compiler build program.
extern(C) void kmain(ulong magic, ulong info)
{
    cast(void) magic;
    cast(void) info;

    clearScreen();
    initSerial();
    auto context = probeHardware(magic, info);

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

    posixInit();

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
    }

    if (result.framebufferReady)
    {
        runSimpleDesktopOnce();
    }
    else
    {
        printLine("[kernel] Graphics desktop disabled - framebuffer unavailable");
        printLine("[kernel] Serial shell will be available after build completes");
        printLine("");
    }

    return result;
}
