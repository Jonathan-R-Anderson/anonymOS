module anonymos.security_config;

/// Read-only security posture baked into the kernel image. Changing these
/// requires rebuilding a new, trusted kernel.
enum bool securityWXEnforced       = true;
enum bool securityASLREnforced     = true;
enum bool securityHeapHardening    = true;
enum bool securityShadowStacks     = true;
enum bool securitySyscallFiltering = true;

/// Panic if any mandatory control is disabled in this build.
void verifySecurityConfig()
{
    import anonymos.console : printLine;
    if (!securityWXEnforced || !securityASLREnforced ||
        !securityHeapHardening || !securityShadowStacks ||
        !securitySyscallFiltering)
    {
        printLine("[security] fatal: security configuration not enforced");
        for (;;)
        {
            asm { hlt; }
        }
    }
}
