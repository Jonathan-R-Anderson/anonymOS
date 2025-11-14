module minimal_os.kernel.shell_integration;

import sh_metadata : shRepositoryPath, shBinaryName, shRevision, shSourceFileCount, shDocumentedCommandCount, shBinarySizeBytes;

import minimal_os.console : putChar, print, printLine, printCString, printUnsigned, printDivider, printStageHeader, printStatus, printStatusValue, clearActiveStage, stageSummaryData;
import minimal_os.compiler : compileStage, frontEndSources, optimizerSources, runtimeSources;
import minimal_os.posix : PosixKernelShim, launchInteractiveShell, shellExecEntry;
import minimal_os.toolchain : resetBuilderState, configureToolchain, linkCompiler, packageArtifacts,
    toolchainConfiguration, linkArtifacts, packageManifest, linkedArtifactSize;
import minimal_os.kernel.posixbundle : compileEmbeddedPosixUtilities;

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

mixin PosixKernelShim;

extern(C) @nogc nothrow void runCompilerBuilder()
{
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

private void integrateShell()
{
    printStageHeader("Integrate 'lfe-sh' shell environment");

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
    version (Posix)
    {
        if (!g_posixConfigured)
        {
            ensurePosixUtilitiesConfigured();
        }

        const size_t registered = registerPosixUtilities();

        immutable(char)[] status = (registered > 0) ? "available" : "unavailable";
        printStatus("[shell] POSIX utilities  : ", status, "");
        printStatusValue("[shell] POSIX execs    : ", cast(long)registered);

        if (registered == 0 && (shellState.failureReason is null || shellState.failureReason.length == 0))
        {
            shellState.failureReason = "POSIX utilities unavailable";
        }
    }
    else
    {
        const size_t registered = registerPosixUtilities();

        immutable(char)[] status = (registered > 0) ? "available" : "unavailable";
        printStatus("[shell] POSIX utilities  : ", status, "");
        printStatusValue("[shell] POSIX execs    : ", cast(long)registered);

        if (registered == 0 && (shellState.failureReason is null || shellState.failureReason.length == 0))
        {
            shellState.failureReason = "POSIX utilities unavailable";
        }
    }
}

private void finalizeShellActivation()
{
    const bool detectedConsole = detectConsoleAvailability();
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

    const bool posixReady = g_posixUtilitiesRegistered;
    const bool prerequisitesMet = shellState.compilerAccessible && shellState.runtimeBound && posixReady;
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
                else if (!posixReady)
                {
                    reason = "POSIX utilities unavailable";
                }
                else
                {
                    reason = "integration prerequisites missing";
                }
            }
            else if (!g_consoleAvailable)
            {
                reason = "console unavailable";
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

    if (!shellState.shellActivated && shellState.failureReason !is null)
    {
        print(" Shell status     : ");
        printLine(shellState.failureReason);
    }

    printDivider();
}


