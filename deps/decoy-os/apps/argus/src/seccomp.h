#ifndef __SECCOMP_H
#define __SECCOMP_H

/*
 * seccomp_apply() — install a minimal seccomp denylist filter.
 *
 * After argus drops root privileges and enters the event loop it no longer
 * needs to exec programs, fork processes, attach to other processes, or
 * change its own credentials.  seccomp_apply() denies these operations so
 * that a hypothetical memory-corruption exploit in the event loop cannot be
 * escalated into arbitrary code execution.
 *
 * The filter is a *denylist* (allowlist would be too fragile given the many
 * syscalls needed by glibc, libbpf, and DNS/TLS libraries):
 *
 *   Denied with EPERM:
 *     execve, execveat, fork, vfork,   (no new processes / exec chains)
 *     ptrace,                           (no process inspection)
 *     setuid, setgid, setresuid,        (no credential changes)
 *     setresgid,
 *     mount,                            (no filesystem changes)
 *     init_module, finit_module,        (no kernel modules)
 *     kexec_load, kexec_file_load       (no kernel replacement)
 *
 * On non-Linux platforms or kernels without seccomp support the function
 * is a no-op.
 */
void seccomp_apply(void);

#endif /* __SECCOMP_H */
