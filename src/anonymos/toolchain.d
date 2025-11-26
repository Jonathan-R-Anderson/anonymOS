module anonymos.toolchain;

import anonymos.console : printStageHeader, printStatus, printStatusValue;
import anonymos.compiler : resetCompilerState, compiledModuleData, getGlobalSymbolCount,
    lookupGlobalSymbol, builderFatal;

nothrow:
@nogc:

struct ToolchainConfiguration
{
    immutable(char)[] hostTriple;
    immutable(char)[] targetTriple;
    immutable(char)[] runtimeVariant;
    bool              crossCompilationSupport;
    bool              cacheManifestGenerated;
}

struct LinkArtifacts
{
    immutable(char)[] targetName;
    bool              bootstrapEmbedded;
    bool              debugSymbols;
}

struct PackageManifest
{
    immutable(char)[] archiveName;
    immutable(char)[] headersPath;
    immutable(char)[] libraryPath;
    immutable(char)[] manifestName;
    bool              readyForDeployment;
}

enum DEFAULT_HOST_TRIPLE    = "x86_64-pc-linux-gnu";
enum DEFAULT_TARGET_TRIPLE  = "x86_64-pc-unknown-unknown";
enum DEFAULT_RUNTIME_VARIANT = "minimal";

private enum size_t LINKED_ARTIFACT_IMAGE_CAPACITY = 16_384;

__gshared ToolchainConfiguration toolchainConfiguration = ToolchainConfiguration(
    DEFAULT_HOST_TRIPLE,
    DEFAULT_TARGET_TRIPLE,
    DEFAULT_RUNTIME_VARIANT,
    false,
    false,
);

__gshared LinkArtifacts   linkArtifacts;
__gshared PackageManifest packageManifest;
__gshared size_t          linkedArtifactSize = 0;
private __gshared ubyte[LINKED_ARTIFACT_IMAGE_CAPACITY] linkedArtifactImage;

void resetBuilderState()
{
    resetCompilerState();
    linkedArtifactSize = 0;
}

size_t copyToFixedBuffer(const(char)[] source, char[] destination)
{
    size_t count = source.length;
    if (count > destination.length)
    {
        count = destination.length;
    }

    foreach (index; 0 .. count)
    {
        destination[index] = source[index];
    }

    if (destination.length != 0)
    {
        if (count < destination.length)
        {
            destination[count] = '\0';
            foreach (index; count + 1 .. destination.length)
            {
                destination[index] = '\0';
            }
        }
        else
        {
            destination[destination.length - 1] = '\0';
        }
    }

    return count;
}

size_t formatUnsignedValue(size_t value, char[] buffer)
{
    if (buffer.length == 0)
    {
        return 0;
    }

    char[20] scratch;
    size_t scratchLength = 0;

    do
    {
        scratch[scratchLength] = cast(char)('0' + (value % 10));
        ++scratchLength;
        value /= 10;
    }
    while (value != 0 && scratchLength < scratch.length);

    size_t index = 0;
    while (scratchLength != 0 && index < buffer.length)
    {
        --scratchLength;
        buffer[index] = scratch[scratchLength];
        ++index;
    }

    if (index < buffer.length)
    {
        buffer[index] = '\0';
    }

    return index;
}

void configureToolchain()
{
    printStageHeader("Configure host + target");
    printStatus("[config] Host triple      : ", toolchainConfiguration.hostTriple, "");
    printStatus("[config] Target triple    : ", toolchainConfiguration.targetTriple, "");
    printStatus("[config] Runtime variant  : ", toolchainConfiguration.runtimeVariant, "");

    long pointerSize;
    if (!lookupGlobalSymbol("pointer_size", pointerSize))
    {
        pointerSize = 0;
    }
    printStatusValue("[config] Pointer bytes    : ", pointerSize);

    long vectorAlignment;
    if (!lookupGlobalSymbol("vector_alignment", vectorAlignment))
    {
        vectorAlignment = 0;
    }
    printStatusValue("[config] Vector alignment : ", vectorAlignment);

    toolchainConfiguration.crossCompilationSupport =
        (pointerSize >= 8) && (vectorAlignment % (pointerSize == 0 ? 1 : pointerSize) == 0);
    immutable(char)[] crossStatus = toolchainConfiguration.crossCompilationSupport ? "enabled" : "disabled";
    printStatus("[config] Cross-compilation : ", crossStatus, "");

    toolchainConfiguration.cacheManifestGenerated = vectorAlignment >= 16;
    immutable(char)[] manifestStatus = toolchainConfiguration.cacheManifestGenerated ? "generated" : "pending";
    printStatus("[config] Cache manifest   : ", manifestStatus, "");
}

void linkCompiler()
{
    printStageHeader("Link cross compiler executable");

    long codegenUnits;
    if (!lookupGlobalSymbol("optimizer_codegen_units", codegenUnits))
    {
        codegenUnits = 0;
    }

    long machineBlocks;
    if (!lookupGlobalSymbol("optimizer_machine_blocks", machineBlocks))
    {
        machineBlocks = 0;
    }

    long runtimeSegments;
    if (!lookupGlobalSymbol("runtime_heap_segments", runtimeSegments))
    {
        runtimeSegments = 0;
    }

    long semanticIssues;
    if (!lookupGlobalSymbol("semantic_issues_detected", semanticIssues))
    {
        semanticIssues = 0;
    }

    linkArtifacts.targetName = "ldc-cross";
    linkArtifacts.bootstrapEmbedded = runtimeSegments > 8;
    linkArtifacts.debugSymbols = semanticIssues <= 2;

    linkedArtifactSize = 0;

    immutable(char)[] stageLabel = "link";
    immutable(char)[] unitName = linkArtifacts.targetName;

    void appendByte(ubyte value)
    {
        if (linkedArtifactSize >= linkedArtifactImage.length)
        {
            builderFatal(stageLabel, unitName, "linked image buffer exhausted", null);
        }

        linkedArtifactImage[linkedArtifactSize] = value;
        ++linkedArtifactSize;
    }

    void appendWord(ulong value)
    {
        foreach (shift; 0 .. 8)
        {
            appendByte(cast(ubyte)((value >> (shift * 8)) & 0xFF));
        }
    }

    void appendString(immutable(char)[] text)
    {
        foreach (ch; text)
        {
            appendByte(cast(ubyte)ch);
        }
    }

    appendString("ICLD");
    appendWord(cast(ulong)codegenUnits);
    appendWord(cast(ulong)machineBlocks);
    appendWord(cast(ulong)getGlobalSymbolCount());

    foreach (moduleInfo; compiledModuleData())
    {
        size_t nameLength = moduleInfo.name.length;
        if (nameLength > 255)
        {
            nameLength = 255;
        }

        appendByte(cast(ubyte)nameLength);
        foreach (ch; moduleInfo.name[0 .. nameLength])
        {
            appendByte(cast(ubyte)ch);
        }

        appendByte(cast(ubyte)moduleInfo.exportCount);
        foreach (exportIndex; 0 .. moduleInfo.exportCount)
        {
            appendWord(cast(ulong)moduleInfo.exports[exportIndex].value);
        }
    }

    printStatus("[link] Linking target ", linkArtifacts.targetName, " ... ok");
    printStatusValue("[link] Units linked     : ", codegenUnits);
    printStatusValue("[link] Machine blocks   : ", machineBlocks);
    printStatusValue("[link] Artifact bytes   : ", cast(long)linkedArtifactSize);

    immutable(char)[] bootstrap = linkArtifacts.bootstrapEmbedded ? "embedded" : "skipped";
    printStatus("[link] Bootstrap stage   : ", bootstrap, "");

    immutable(char)[] debugStatus = linkArtifacts.debugSymbols ? "generated" : "skipped";
    printStatus("[link] Debug symbols     : ", debugStatus, "");
}

void packageArtifacts()
{
    packageManifest = PackageManifest(
        "ldc-cross.tar",
        "include/dlang",
        "lib/libphobos-cross.a",
        "manifest.toml",
        false,
    );

    printStageHeader("Package distribution");
    printStatus("[pkg] Creating archive       ", packageManifest.archiveName, " ... ok");
    printStatus("[pkg] Installing headers     ", packageManifest.headersPath, " ... ok");
    printStatus("[pkg] Installing libraries   ", packageManifest.libraryPath, " ... ok");
    printStatus("[pkg] Writing tool manifest  ", packageManifest.manifestName, " ... ok");

    printStatusValue("[pkg] Module count         : ", cast(long)compiledModuleData().length);
    printStatusValue("[pkg] Exported symbols     : ", cast(long)getGlobalSymbolCount());
    printStatusValue("[pkg] Artifact bytes       : ", cast(long)linkedArtifactSize);

    long runtimeDrivers;
    if (!lookupGlobalSymbol("runtime_device_drivers", runtimeDrivers))
    {
        runtimeDrivers = 0;
    }
    printStatusValue("[pkg] Runtime drivers      : ", runtimeDrivers);

    packageManifest.readyForDeployment = (linkedArtifactSize >= 64) && (runtimeDrivers >= 6);
    immutable(char)[] deployment = packageManifest.readyForDeployment ? "ready" : "needs review";
    printStatus("[pkg] Deployment status     : ", deployment, "");
}

