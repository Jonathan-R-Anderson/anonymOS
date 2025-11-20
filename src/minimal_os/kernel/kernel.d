module minimal_os.kernel.kernel;

public import minimal_os.kernel.memory;

import minimal_os.framebuffer;
import minimal_os.console : clearScreen;
import minimal_os.serial : initSerial;
import minimal_os.hardware : probeHardware;
import minimal_os.multiboot : MultibootInfoFlag, framebufferInfoFromMultiboot;
import minimal_os.desktop : desktopProcessEntry, runSimpleDesktopOnce;
import minimal_os.kernel.shell_integration : compilerBuilderProcessEntry, posixInit, initializeInterrupts;
import minimal_os.posix : registerProcessExecutable, spawnRegisteredProcess, schedYield;

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

    initializeInterrupts();

    posixInit();

    // Register processes that should run alongside the kernel core.
    const int builderRegistration = registerProcessExecutable("/sbin/compiler-builder",
        &compilerBuilderProcessEntry);

    if (framebufferReady)
    {
        const int desktopRegistration = registerProcessExecutable("/sbin/desktop",
            &desktopProcessEntry);
        if (desktopRegistration == 0)
        {
            cast(void) spawnRegisteredProcess("/sbin/desktop", null, null);
        }
    }

    if (builderRegistration == 0)
    {
        cast(void) spawnRegisteredProcess("/sbin/compiler-builder", null, null);
    }

    // Idle the kernel while co-operative tasks (desktop, compiler, shell) run.
    while (true)
    {
        schedYield();
        asm { hlt; }
    }
}
