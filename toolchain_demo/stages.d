module toolchain_demo.stages;

import toolchain_demo.output :
    logLine,
    logModuleCompilation,
    logStageHeader,
    logStatus;

@nogc nothrow
void configureToolchain() @system
{
    logStageHeader("Configure host + target");
    logStatus("[config] Host triple      : ", "x86_64-unknown-elf", "");
    logStatus("[config] Target triple    : ", "wasm32-unknown-unknown", "");
    logStatus("[config] Runtime variant  : ", "druntime bare-metal", "");
    logStatus("[config] Cross compiler   : ", "ldc2 with custom runtime", "");
    logLine("[config] Generating cache manifest ... ok");
    logLine("[config] Writing response file ... ok");
}

@nogc nothrow
void buildFrontEnd() @system
{
    logStageHeader("Compile front-end");
    enum modules = [
        "dmd/lexer.d",
        "dmd/parser.d",
        "dmd/semantic.d",
        "dmd/types.d",
        "dmd/dsymbol.d",
        "dmd/expressionsem.d",
        "dmd/template.d",
        "dmd/backend/astdumper.d",
    ];
    foreach (moduleName; modules)
    {
        logModuleCompilation("front-end", moduleName);
    }
    logLine("[front-end] Generating module map ... ok");
    logLine("[front-end] Caching semantic analysis ... ok");
}

@nogc nothrow
void buildOptimizer() @system
{
    logStageHeader("Build optimizer + codegen");
    enum modules = [
        "dmd/backend/ir.d",
        "dmd/backend/abi.d",
        "dmd/backend/optimize.d",
        "dmd/backend/eliminate.d",
        "dmd/backend/target.d",
        "dmd/backend/codegen.d",
    ];
    foreach (moduleName; modules)
    {
        logModuleCompilation("optimizer", moduleName);
    }
    logLine("[optimizer] Wiring up LLVM passes ... ok");
    logLine("[optimizer] Emitting position independent code ... ok");
}

@nogc nothrow
void buildRuntime() @system
{
    logStageHeader("Assemble runtime libraries");
    enum runtimeModules = [
        "druntime/core/memory.d",
        "druntime/core/thread.d",
        "druntime/object.d",
        "phobos/std/algorithm.d",
        "phobos/std/array.d",
        "phobos/std/io.d",
    ];
    foreach (moduleName; runtimeModules)
    {
        logModuleCompilation("runtime", moduleName);
    }
    logLine("[runtime] Archiving libdruntime-cross.a ... ok");
    logLine("[runtime] Archiving libphobos-cross.a ... ok");
}

@nogc nothrow
void linkCompiler() @system
{
    logStageHeader("Link cross compiler executable");
    logStatus("[link] Linking target ", "ldc-cross", " ... ok");
    logLine("[link] Embedding druntime bootstrap ... ok");
    logLine("[link] Producing debug symbols ... ok");
    logLine("[link] Signing executable manifest ... ok");
}

@nogc nothrow
void packageArtifacts() @system
{
    logStageHeader("Package distribution");
    logStatus("[pkg] Creating archive       ", "ldc-cross.tar", " ... ok");
    logStatus("[pkg] Installing headers     ", "include/dlang", " ... ok");
    logStatus("[pkg] Installing libraries   ", "lib/libphobos-cross.a", " ... ok");
    logLine("[pkg] Bundling sample projects ... ok");
    logLine("[pkg] Writing README bootstrap notes ... ok");
}

@nogc nothrow
void verifyToolchain() @system
{
    logStageHeader("Verify toolchain build");
    logLine("[verify] Running smoke tests ... ok");
    logLine("[verify] Checking relocation records ... ok");
    logLine("[verify] Validating sysroot manifests ... ok");
}
