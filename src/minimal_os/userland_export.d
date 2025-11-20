module minimal_os.userland_export;

// This module exists solely to export the bootUserland function with C linkage
// The function implementation is here directly to avoid LDC betterC dead code elimination

import minimal_os.userland : UserlandRuntime, SystemProperties, normaliseState, 
    DEFAULT_SERVICE_PLANS, INVALID_INDEX, processReady, logServiceProvision, logUserlandSnapshot;
import minimal_os.console : printStageHeader;

export extern(C) @nogc nothrow void minimal_os_bootUserland()
{
    printStageHeader("Provision userland services");

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
        const bool registered = serviceIndex != INVALID_INDEX;
        const bool launched = registered ? runtime.launchService(serviceIndex, desiredState) : false;
        logServiceProvision(plan, desiredState, registered, launched);
    }

    SystemProperties systemProperties;
    immutable(char)[][] desktopStack =
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
