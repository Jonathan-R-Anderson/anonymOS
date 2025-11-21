module minimal_os.kernel.kernel;

public import minimal_os.kernel.memory;

import minimal_os.display.framebuffer;
import minimal_os.console : clearScreen, printLine;
import minimal_os.serial : initSerial;
import minimal_os.hardware : probeHardware;
import minimal_os.multiboot : MultibootInfoFlag, framebufferInfoFromMultiboot;
import minimal_os.display.desktop : desktopProcessEntry, runSimpleDesktopOnce;
version (MinimalOsUserlandLinked)
{
    // Prefer the fully featured builder entry when the userland module is
    // linked, but keep the stub around as a fallback so the kernel still links
    // in minimal build configurations. If neither module is available, define a
    // tiny in-place stub so the linker always has a symbol to resolve.
    static if (__traits(compiles, { import minimal_os.kernel.shell_integration : compilerBuilderProcessEntry; }))
    {
        import minimal_os.kernel.shell_integration : realCompilerBuilderProcessEntry = compilerBuilderProcessEntry,
            posixInit, initializeInterrupts, registerProcessExecutable, spawnRegisteredProcess, schedYield;

        alias compilerBuilderProcessEntry = realCompilerBuilderProcessEntry;
    }
    else static if (__traits(compiles, { import minimal_os.kernel.compiler_builder_stub : compilerBuilderProcessEntry; }))
    {
        import minimal_os.kernel.shell_integration : posixInit, initializeInterrupts, registerProcessExecutable,
            spawnRegisteredProcess, schedYield;
        import minimal_os.kernel.compiler_builder_stub : compilerBuilderProcessEntry;
    }
    else
    {
        import minimal_os.kernel.shell_integration : posixInit, initializeInterrupts, registerProcessExecutable,
            spawnRegisteredProcess, schedYield;

        pragma(mangle, "compilerBuilderProcessEntry")
        extern(C) @nogc nothrow void compilerBuilderProcessEntry(const(char*)* /*argv*/, const(char*)* /*envp*/)
        {
            import minimal_os.console : printLine;
            printLine("[kernel] compiler builder unavailable; inline stub entry used");
        }
    }
}
else
{
    import minimal_os.kernel.shell_integration : posixInit, initializeInterrupts, registerProcessExecutable,
        spawnRegisteredProcess, schedYield;
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
        const fbInfo = framebufferInfoFromMultiboot(context.info);
        if (fbInfo.valid())
        {
            initFramebuffer(fbInfo.base, fbInfo.width, fbInfo.height, fbInfo.pitch, fbInfo.bpp, fbInfo.isBGR);

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
        const int builderRegistration = registerProcessExecutable("/sbin/compiler-builder",
            &compilerBuilderProcessEntry);
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
