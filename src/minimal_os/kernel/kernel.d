module minimal_os.kernel.kernel;

public import minimal_os.kernel.memory;

import minimal_os.display.framebuffer;
import minimal_os.console : clearScreen, printLine, printStageHeader;
import minimal_os.serial : initSerial;
import minimal_os.hardware : probeHardware;
import minimal_os.multiboot : MultibootInfoFlag, selectFramebufferMode, FramebufferModeRequest;
import minimal_os.display.desktop : desktopProcessEntry, runSimpleDesktopOnce;
import minimal_os.posix : posixInit, registerProcessExecutable, spawnRegisteredProcess,
    schedYield, initializeInterrupts, ProcessEntry;
import minimal_os.kernel.shell_integration : compilerBuilderProcessEntry;

// Treat the compiler builder entry point as optional so the kernel can still link
// in environments where the full userland object was not provided. When the
// definition is absent, we rely on a weak symbol to resolve to null so we can
// skip registration gracefully at runtime.
extern(C) @nogc nothrow void compilerBuilderProcessEntry(const(char*)* /*argv*/, const(char*)* /*envp*/);

// Prefer a weak reference on LDC so undefined references resolve to null rather
// than producing a link error. Guard the pragmas so they remain harmless on
// compilers that do not understand LDC-specific attributes.  The explicit
// `LDC_extern_weak` pragma is required for references to remain optional when
// no definition is linked, whereas `LDC_attributes` alone is insufficient.
static if (__traits(compiles, { pragma(LDC_extern_weak, compilerBuilderProcessEntry); }))
{
    pragma(LDC_extern_weak, compilerBuilderProcessEntry);
}
static if (__traits(compiles, { pragma(LDC_attributes, "weak", compilerBuilderProcessEntry); }))
{
    pragma(LDC_attributes, "weak", compilerBuilderProcessEntry);
}

// Ensure the symbol is retained when available even if the linker performs
// aggressive dead-stripping.
static if (__traits(compiles, { pragma(LDC_force_link, compilerBuilderProcessEntry); }))
{
    pragma(LDC_force_link, compilerBuilderProcessEntry);
}

/// Entry point invoked from boot.s once the CPU is ready to run D code.
/// Initialises the VGA output and runs the compiler build program.
extern(C) void kmain(ulong magic, ulong info)
{
    cast(void) magic;
    cast(void) info;

    clearScreen();
    initSerial();
    auto context = probeHardware(magic, info);

    bool framebufferReady = false;

    if (context.valid && context.hasFlag(MultibootInfoFlag.framebufferInfo))
    {
        FramebufferModeRequest fbRequest;
        fbRequest.desiredWidth  = 1024;
        fbRequest.desiredHeight = 768;
        fbRequest.desiredBpp    = 32;
        fbRequest.desiredModeNumber = context.info.vbeMode;

        const fbInfo = selectFramebufferMode(context.info, fbRequest);
        if (fbInfo.valid())
        {
            initFramebuffer(fbInfo.base, fbInfo.width, fbInfo.height, fbInfo.pitch, fbInfo.bpp, fbInfo.isBGR, fbInfo.modeNumber, true);

            framebufferReady = framebufferAvailable();
            if (framebufferReady)
            {
                framebufferBootBanner("minimal_os is booting...");
                runSimpleDesktopOnce();
            }
        }
    }

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
        // Explicitly type the function pointer so overload resolution cannot be
        // confused by multiple weak/strong definitions of the symbol that may
        // be present depending on the build configuration.
        ProcessEntry builderEntry = &compilerBuilderProcessEntry;
        if (builderEntry !is null)
        {
            const int builderRegistration = registerProcessExecutable("/sbin/compiler-builder",
                builderEntry);
            if (builderRegistration == 0)
            {
                cast(void) spawnRegisteredProcess("/sbin/compiler-builder", null, null);
            }
        }
        else
        {
            printLine("[kernel] Compiler builder unavailable (symbol not linked)");
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
