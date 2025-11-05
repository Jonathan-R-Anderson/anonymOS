module toolchain_demo.pipeline;

import toolchain_demo.output : logDivider, logEmptyLine, logLine, logSummary;
import toolchain_demo.stages :
    buildFrontEnd,
    buildOptimizer,
    buildRuntime,
    configureToolchain,
    linkCompiler,
    packageArtifacts,
    verifyToolchain;

@nogc nothrow
void runToolchainDemo() @system
{
    configureToolchain();
    buildFrontEnd();
    buildOptimizer();
    buildRuntime();
    linkCompiler();
    packageArtifacts();
    verifyToolchain();

    logEmptyLine();
    logDivider();
    logLine("Toolchain build completed successfully!");
    logSummary("Artifacts staged at    : ", "build/toolchain");
    logSummary("Executable output      : ", "build/toolchain/toolchain_demo.bin");
    logSummary("Sysroot includes       : ", "build/toolchain/sysroot");
    logDivider();
}
