module minimal_os.kernel.shell_integration;

import sh_metadata : shRepositoryPath, shBinaryName, shRevision, shSourceFileCount,
    shDocumentedCommandCount, shBinarySizeBytes;

import minimal_os.console : putChar, print, printLine, printCString, printUnsigned,
    printDivider, printStageHeader, printStatus, printStatusValue, clearActiveStage,
    stageSummaryData;
import minimal_os.compiler : compileStage, frontEndSources, optimizerSources,
    runtimeSources;
import minimal_os.posix : ProcessEntry, launchInteractiveShell, shellExecEntry,
    registerBareMetalShellInterfaces, ensureBareMetalShellInterfaces,
    g_posixConfigured, ensurePosixUtilitiesConfigured, registerPosixUtilities,
    detectConsoleAvailability, g_consoleAvailable, g_shellRegistered,
    registerProcessExecutable;
import minimal_os.toolchain : resetBuilderState, configureToolchain, linkCompiler,
    packageArtifacts, toolchainConfiguration, linkArtifacts, packageManifest,
    linkedArtifactSize;
import minimal_os.kernel.posixbundle : compileEmbeddedPosixUtilities;


// Import userland bootstrap functions directly
import minimal_os.userland : UserlandRuntime, SystemProperties, normaliseState, 
    g_servicePlans, g_servicePlansInitialized, ServicePlan, INVALID_INDEX, processReady, logServiceProvision, logUserlandSnapshot;





// In this configuration we always compile & link userland.
enum bool userlandAvailable = true;




nothrow:
@nogc:

struct ShellIntegrationState
{
    bool repositoryFetched;
    immutable(char)[] repository;
    immutable(char)[] revision;
    immutable(char)[] binaryName;
    immutable(char)[] failureReason;
    size_t binaryBytes;
    size_t documentedCommandCount;
    size_t sourceFileCount;
    bool runtimeBound;
    bool compilerAccessible;
    bool shellActivated;
}

__gshared ShellIntegrationState shellState = ShellIntegrationState(
    false,
    shRepositoryPath,
    shRevision,
    shBinaryName,
    null,
    0,
    0,
    0,
    false,
    false,
    false,
);

pragma(mangle, "compilerBuilderProcessEntry")
pragma(inline, false)
export extern(C) @nogc nothrow
void compilerBuilderProcessEntry(const(char*)* argv, const(char*)* envp)
{
    cast(void) argv;
    cast(void) envp;

    resetBuilderState();

    printLine("========================================");
    printLine("   Cross Compiler Build Orchestrator");
    printLine("   Target: Full D language toolchain");
    printLine("========================================");

    configureToolchain();

    compileStage("Compile front-end", "front-end", frontEndSources());
    compileStage("Build optimizer + codegen", "optimizer", optimizerSources());
    compileStage("Assemble runtime libraries", "runtime", runtimeSources());
    linkCompiler();
    packageArtifacts();
    compileEmbeddedPosixUtilities();
    integrateShell();
    printBuildSummary();

    printLine("[debug] Shell state snapshot: pre-boot");
    print("         repository fetched : ");
    printLine(shellState.repositoryFetched ? "yes" : "no");
    print("         repository         : ");
    printLine(shellState.repository);
    print("         revision           : ");
    printLine(shellState.revision);
    print("         binary name        : ");
    printLine(shellState.binaryName);
    print("         binary bytes       : ");
    printUnsigned(shellState.binaryBytes);
    putChar('\n');
    print("         documented cmds    : ");
    printUnsigned(shellState.documentedCommandCount);
    putChar('\n');
    print("         source files       : ");
    printUnsigned(shellState.sourceFileCount);
    putChar('\n');
    print("         runtime bound      : ");
    printLine(shellState.runtimeBound ? "yes" : "no");
    print("         compiler access    : ");
    printLine(shellState.compilerAccessible ? "yes" : "no");
    print("         shell activated    : ");
    printLine(shellState.shellActivated ? "yes" : "no");
    print("         failure reason     : ");
    if (shellState.failureReason !is null)
    {
        printLine(shellState.failureReason);
    }
    else
    {
        printLine("<none>");
    }

    printLine("");
    printLine("[kernel] Bootstrapping userland services...");
    
    // Inline userland bootstrap (avoiding LDC betterC extern(C) dead code elimination)
    {
        printStageHeader("Provision userland services");

        UserlandRuntime runtime;
        runtime.reset();

        if (!g_servicePlansInitialized)
        {
            g_servicePlans[0] = ServicePlan("init", "/sbin/init", "Capability supervisor",
                          [ "ipc.bootstrap", "scheduler.control", "namespace.grant" ], "running", false);
            g_servicePlans[1] = ServicePlan("vfsd", "/bin/vfsd", "Immutable namespace + VMO store",
                          [ "vmo.map", "vmo.clone", "namespace.publish", "namespace.read" ], "running", false);
            g_servicePlans[2] = ServicePlan("pkgd", "/bin/pkgd", "Package + manifest resolver",
                          [ "package.open", "package.verify", "cache.commit" ], "ready", false);
            g_servicePlans[3] = ServicePlan("netd", "/bin/netd", "Network capability broker",
                          [ "net.bind", "net.connect", "net.capability" ], "running", true);
            g_servicePlans[4] = ServicePlan("xorg-server", "/bin/Xorg", "X11 display server",
                          [ "display.x11", "display.driver", "input.bridge", "namespace.publish" ], "waiting", false);
            g_servicePlans[5] = ServicePlan("xinit", "/bin/xinit", "X11 session bootstrapper",
                          [ "display.x11", "session.launch", "ipc.userland", "posix.exec" ], "waiting", false);
            g_servicePlans[6] = ServicePlan("display-manager", "/bin/xdm", "Graphical login + session manager",
                          [ "display.login", "session.control", "ipc.userland" ], "waiting", false);
            g_servicePlans[7] = ServicePlan("i3", "/bin/i3", "Tiling window manager and desktop",
                          [ "display.manage", "ipc.userland", "workspace.control", "console.claim" ], "waiting", false);
            g_servicePlans[8] = ServicePlan("lfe-sh", "/bin/sh", "Interactive shell bridge",
                          [ "ipc.bootstrap", "posix.exec", "console.claim" ], "ready", false);
            g_servicePlansInitialized = true;
        }
        
        foreach (plan; g_servicePlans)
        {
            immutable(char)[] desiredState = normaliseState(plan.desiredState);
            const size_t serviceIndex = runtime.registerService(plan.name,
                                                                plan.binary,
                                                                plan.summary,
                                                                plan.capabilities,
                                                                plan.optional);
            const bool registered = serviceIndex != size_t.max;
            const bool launched = registered ? runtime.launchService(serviceIndex, desiredState) : false;
            logServiceProvision(plan, desiredState, registered, launched);
        }

        SystemProperties systemProperties;
        immutable(char)[][4] desktopStack =
            [ "xorg-server", "xinit", "display-manager", "i3" ];

        systemProperties.desktopReady = true;
        foreach (service; desktopStack)
        {
            if (!processReady(runtime, service))
            {
                systemProperties.desktopReady = false;
                break;
            }
        }

        logUserlandSnapshot(runtime, systemProperties);
    }
    
    printLine("");
    printLine("[done] D language cross compiler ready.");
    if (shellState.shellActivated)
    {
        printLine("[done] 'lfe-sh' interactive shell ready.");
        printLine("");
        printLine("Booting 'lfe-sh' interactive shell...");
        launchInteractiveShell();
    }
    else
    {
        print("[warn] 'lfe-sh' shell unavailable: ");
        if (shellState.failureReason !is null)
        {
            printLine(shellState.failureReason);
        }
        else
        {
            printLine("compiler access is required.");
        }
    }
}

// In some toolchain configurations the linker may aggressively discard
// unreferenced symbols. Explicitly request that the compiler builder entry
// point is retained so `kmain` can always register it when
// `MinimalOsUserlandLinked` is enabled.
static if (__traits(compiles, { pragma(LDC_force_link, compilerBuilderProcessEntry); }))
{
    pragma(LDC_force_link, compilerBuilderProcessEntry);
}


private void integrateShell()
{
    printStageHeader("Integrate 'lfe-sh' shell environment");

    ensureBareMetalShellRuntimeHooks();
    fetchShellSnapshot();
    updateShellBinaryMetrics();
    checkShellRuntimeBindings();
    checkShellCompilerAccess();
    bindPosixUtilitiesToKernel();
    finalizeShellActivation();
}

private void fetchShellSnapshot()
{
    shellState.repositoryFetched = true;
    shellState.repository = shRepositoryPath;
    shellState.revision = shRevision;
    shellState.binaryName = shBinaryName;
    shellState.failureReason = null;

    printStatus("[shell] Source repository : ", shellState.repository, "");
    printStatus("[shell] Revision pinned   : ", shellState.revision, "");
    printStatus("[shell] Shell binary      : ", shellState.binaryName, "");
}

private void updateShellBinaryMetrics()
{
    shellState.binaryBytes = shBinarySizeBytes;
    shellState.documentedCommandCount = shDocumentedCommandCount;
    shellState.sourceFileCount = shSourceFileCount;

    printStatusValue("[shell] Package bytes     : ", cast(long)shBinarySizeBytes);
    printStatusValue("[shell] Documented cmds   : ", cast(long)shDocumentedCommandCount);
    printStatusValue("[shell] Source modules    : ", cast(long)shSourceFileCount);
}

private void checkShellRuntimeBindings()
{
    shellState.runtimeBound = linkArtifacts.bootstrapEmbedded;
    immutable(char)[] runtimeStatus = shellState.runtimeBound ? "connected" : "missing bootstrap";
    printStatus("[shell] Runtime bindings  : ", runtimeStatus, "");

    if (!shellState.runtimeBound && (shellState.failureReason is null || shellState.failureReason.length == 0))
    {
        shellState.failureReason = "runtime bootstrap required";
    }
}

private void checkShellCompilerAccess()
{
    const bool cross = toolchainConfiguration.crossCompilationSupport;
    const bool manifest = toolchainConfiguration.cacheManifestGenerated;
    const bool deployed = packageManifest.readyForDeployment;

    shellState.compilerAccessible = cross && manifest && deployed;

    immutable(char)[] compilerStatus = shellState.compilerAccessible ? "available" : "unavailable";
    immutable(char)[] crossStatus = cross ? "enabled" : "disabled";
    immutable(char)[] manifestStatus = manifest ? "present" : "missing";
    immutable(char)[] deployStatus = deployed ? "ready" : "pending";

    printStatus("[shell] Compiler access   : ", compilerStatus, "");
    printStatus("[shell] Host cross-comp   : ", crossStatus, "");
    printStatus("[shell] Cache manifest    : ", manifestStatus, "");
    printStatus("[shell] Toolchain deploy  : ", deployStatus, "");

    if (!shellState.compilerAccessible && (shellState.failureReason is null || shellState.failureReason.length == 0))
    {
        if (!cross)
        {
            shellState.failureReason = "cross-compiler support disabled";
        }
        else if (!manifest)
        {
            shellState.failureReason = "cache manifest missing";
        }
        else if (!deployed)
        {
            shellState.failureReason = "toolchain deployment incomplete";
        }
        else
        {
            shellState.failureReason = "compiler path inaccessible";
        }
    }
}

private void bindPosixUtilitiesToKernel()
{
    if (!g_posixConfigured)
    {
        ensurePosixUtilitiesConfigured();
    }

    const size_t registered = registerPosixUtilities();

    immutable(char)[] status = (registered > 0) ? "available" : "unavailable";
    printStatus("[shell] POSIX utilities  : ", status, "");
    printStatusValue("[shell] POSIX execs    : ", cast(long)registered);
}

private void finalizeShellActivation()
{
    ensureBareMetalShellRuntimeHooks();

    const auto consoleDetection = detectConsoleAvailability();
    const bool detectedConsole = consoleDetection.available;
    const bool consoleDisabledByConfig = consoleDetection.disabledByConfiguration;
    immutable(char)[] consoleDiagnostic = consoleDetection.reason;
    if (detectedConsole)
    {
        if (!g_consoleAvailable)
        {
            g_consoleAvailable = true;
        }

        if (!g_shellRegistered)
        {
            const int registration = registerProcessExecutable("/bin/sh", &shellExecEntry);
            g_shellRegistered = (registration == 0);
        }
    }
    else
    {
        g_consoleAvailable = false;
        g_shellRegistered = false;
    }

    const bool prerequisitesMet = shellState.compilerAccessible && shellState.runtimeBound;
    const bool consoleReady = g_consoleAvailable && g_shellRegistered;

    if (prerequisitesMet && consoleReady)
    {
        shellState.shellActivated = true;
        shellState.failureReason = null;
        printStatus("[shell] Activation        : ", "ready", "");
    }
    else
    {
        shellState.shellActivated = false;

        immutable(char)[] reason = shellState.failureReason;
        if (reason is null || reason.length == 0)
        {
            if (!prerequisitesMet)
            {
                if (!shellState.compilerAccessible || !shellState.runtimeBound)
                {
                    reason = "integration prerequisites missing";
                }
                else
                {
                    reason = "integration prerequisites missing";
                }
            }
            else if (!g_consoleAvailable)
            {
                if (consoleDiagnostic !is null && consoleDiagnostic.length != 0)
                {
                    reason = consoleDiagnostic;
                }
                else
                {
                    reason = consoleDisabledByConfig
                        ? "console disabled by configuration"
                        : "console unavailable";
                }
            }
            else if (!g_shellRegistered)
            {
                reason = "shell executable not registered";
            }
            else
            {
                reason = "shell activation blocked";
            }

            shellState.failureReason = reason;
        }

        printStatus("[shell] Activation        : ", "blocked", "");
        printStatus("[shell] Failure reason    : ", reason, "");
    }
}

private void ensureBareMetalShellRuntimeHooks()
{
    static bool runtimeHooksRegistered = false;
    if (runtimeHooksRegistered)
    {
        return;
    }

    // Let the Posix shim wire up g_spawnRegisteredProcessFn/g_waitpidFn.  On
    // host builds the hooks normally arrive via module constructors, but in
    // bare-metal builds we have to request them explicitly.  Calling into
    // ensureBareMetalShellInterfaces() in every configuration guarantees the
    // pointers are populated before the console loop runs, even when the
    // Posix shim is fully implemented and no lightweight fallback is in use.
    ensureBareMetalShellInterfaces();
    runtimeHooksRegistered = true;
}

// POSIX-in-Kernel shim implementation now lives in minimal_os.posix::PosixKernelShim.
private void printBuildSummary()
{
    clearActiveStage();

    auto summaries = stageSummaryData();
    size_t totalModules = 0;
    size_t totalStatuses = 0;
    size_t totalExports = 0;

    foreach (summary; summaries)
    {
        totalModules += summary.moduleCount;
        totalStatuses += summary.statusCount;
        totalExports += summary.exportCount;
    }

    printLine("");
    printDivider();
    printLine("Build summary");
    printDivider();

    print(" Host triple      : ");
    printLine(toolchainConfiguration.hostTriple);

    print(" Target triple    : ");
    printLine(toolchainConfiguration.targetTriple);

    print(" Runtime variant  : ");
    printLine(toolchainConfiguration.runtimeVariant);

    print(" Cross support    : ");
    if (toolchainConfiguration.crossCompilationSupport)
    {
        printLine("enabled");
    }
    else
    {
        printLine("disabled");
    }

    print(" Cache manifest   : ");
    if (toolchainConfiguration.cacheManifestGenerated)
    {
        printLine("generated");
    }
    else
    {
        printLine("missing");
    }

    print(" Link target      : ");
    printLine(linkArtifacts.targetName);

    print(" Bootstrap stage  : ");
    if (linkArtifacts.bootstrapEmbedded)
    {
        printLine("embedded");
    }
    else
    {
        printLine("not embedded");
    }

    print(" Debug symbols    : ");
    if (linkArtifacts.debugSymbols)
    {
        printLine("produced");
    }
    else
    {
        printLine("not produced");
    }

    print(" Package archive  : ");
    printLine(packageManifest.archiveName);

    print(" Headers path     : ");
    printLine(packageManifest.headersPath);

    print(" Library path     : ");
    printLine(packageManifest.libraryPath);

    print(" Manifest file    : ");
    printLine(packageManifest.manifestName);

    print(" Deployment ready : ");
    if (packageManifest.readyForDeployment)
    {
        printLine("yes");
    }
    else
    {
        printLine("no");
    }

    print(" Stage count      : ");
    printUnsigned(summaries.length);
    putChar('\n');

    print(" Total statuses   : ");
    printUnsigned(totalStatuses);
    putChar('\n');

    print(" Modules compiled : ");
    printUnsigned(totalModules);
    putChar('\n');

    print(" Exported symbols : ");
    printUnsigned(totalExports);
    putChar('\n');

    print(" Artifact bytes   : ");
    printUnsigned(linkedArtifactSize);
    putChar('\n');

    print(" Shell repository : ");
    printLine(shellState.repository);

    print(" Shell revision   : ");
    printLine(shellState.revision);

    print(" Shell binary     : ");
    printLine(shellState.binaryName);

    print(" Shell package    : ");
    printUnsigned(shellState.binaryBytes);
    putChar('\n');

    print(" Shell commands   : ");
    printUnsigned(shellState.documentedCommandCount);
    putChar('\n');

    print(" Shell source     : ");
    printUnsigned(shellState.sourceFileCount);
    putChar('\n');

    print(" Shell ready      : ");
    if (shellState.shellActivated)
    {
        printLine("yes");
    }
    else
    {
        printLine("no");
    }

    print(" Shell status     : ");
    if (shellState.shellActivated)
    {
        printLine("available");
    }
    else
    {
        if (shellState.failureReason !is null)
        {
            print("unavailable (");
            print(shellState.failureReason);
            printLine(")");
        }
        else
        {
            printLine("unavailable");
        }
    }

    printDivider();
}


