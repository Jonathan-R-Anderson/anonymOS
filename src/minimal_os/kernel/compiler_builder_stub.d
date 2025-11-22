module minimal_os.kernel.compiler_builder_stub;

import minimal_os.console : printLine, printStageHeader;
import minimal_os.userland : UserlandRuntime, SystemProperties, normaliseState,
    DEFAULT_SERVICE_PLANS, processReady, logServiceProvision, logUserlandSnapshot;

// Provide a weak fallback for the compiler builder entry point so the kernel
// still links when the full userland is not present. When the real
// implementation is linked (from shell_integration.d), the strong symbol
// overrides this stub.
pragma(mangle, "compilerBuilderProcessEntry")
export extern(C) @nogc nothrow void compilerBuilderProcessEntry(const(char*)* /*argv*/, const(char*)* /*envp*/)
{
    printLine("[kernel] compiler builder unavailable; stub entry used");

    // Even without the full toolchain build, bring up the userland roster so
    // the placeholder desktop (including wallpaper preview) still renders.
    printStageHeader("Provision userland services (stub)");

    UserlandRuntime runtime;
    runtime.reset();

    foreach (plan; DEFAULT_SERVICE_PLANS)
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
    immutable(char)[][] desktopStack = [ "xorg-server", "xinit", "display-manager", "i3" ];

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

// Prefer a weak symbol when supported by the compiler (e.g. LDC) so the
// userland implementation can override this stub without link errors.
static if (__traits(compiles, { pragma(LDC_attributes, "weak", compilerBuilderProcessEntry); }))
{
    pragma(LDC_attributes, "weak", compilerBuilderProcessEntry);
}

// In builds that aggressively drop unreferenced symbols, explicitly request that
// the stubbed entry point is retained. The real implementation in
// shell_integration.d provides a strong definition and will override this
// version when linked.
static if (__traits(compiles, { pragma(LDC_force_link, compilerBuilderProcessEntry); }))
{
    pragma(LDC_force_link, compilerBuilderProcessEntry);
}
