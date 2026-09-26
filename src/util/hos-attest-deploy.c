/*
 * hos-attest-deploy.c — on-device deploy glue for the EncryptedAttestationVault (static musl).
 *
 * anonymOS kernel-spawned processes get a fixed env (no LD_PRELOAD), and only a `hos-`-named
 * binary is unconfined enough to write /config (kernel_main.d isSystemProgram). This tiny static
 * wrapper closes the last mile of the on-device deploy:
 *   1. reads the contract CREATION bytecode from a file (default /attest-vault.bin, a boot module);
 *   2. fork()+execve()s the DYNAMIC signer (/hos-ethsign-dyn) with LD_PRELOAD=/libnshim.so, so its
 *      TCP is routed to the LKL network provider (the only userland outbound-TCP path — the kernel
 *      has none, and LD_PRELOAD needs a dynamic binary, hence hos-ethsign-DYN);
 *   3. captures the signer's "contract=0x…" stdout line (its progress goes to stderr → console);
 *   4. writes that address to /config/attest-contract, which wl-installer records into install.json
 *      as "attestContract" (boot_integrity.d then verifies against it on-chain). Do this BEFORE
 *      clicking "Install to Disk" — the address is captured when the config is built.
 *
 * The mnemonic is passed to the signer as a FILE path (never argv); the bytecode is public so it
 * rides on argv. Prereqs at runtime (see src/util/hos-ethsign/README.md): the LKL network up
 * (LIVE_NET=1 on install media), a FUNDED deployer seed in --mnemonic-file, and — for Tor — a
 * SOCKS proxy via --socks (the hidden OS has no Tor daemon yet; without --socks the tx is not
 * Tor-routed).
 *
 * ⚠ UNTESTED on hardware: the on-device libnshim->LKL network path can't be exercised off-device.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

static const char *opt(int argc, char **argv, const char *name, const char *dflt)
{
    size_t n = strlen(name);
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], name) && i + 1 < argc)
            return argv[i + 1];
        if (!strncmp(argv[i], name, n) && argv[i][n] == '=')
            return argv[i] + n + 1;
    }
    return dflt;
}
static int has(int argc, char **argv, const char *name)
{
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], name))
            return 1;
    return 0;
}

int main(int argc, char **argv)
{
    if (has(argc, argv, "-h") || has(argc, argv, "--help")) {
        fprintf(stderr,
            "hos-attest-deploy — deploy EncryptedAttestationVault on-device, record to /config/attest-contract\n"
            "  --mnemonic-file F   REQUIRED: funded deployer seed (path; never on argv)\n"
            "  --rpc URL           default https://sepolia.base.org\n"
            "  --bytecode-file F   default /attest-vault.bin (staged boot module)\n"
            "  --socks H:P         route via Tor SOCKS5 (optional; no on-device Tor daemon yet)\n"
            "  --value WEI         optional   --gas-limit N   optional\n"
            "  --signer PATH       default /hos-ethsign-dyn\n"
            "  --out PATH          default /config/attest-contract\n");
        return 0;
    }

    const char *rpc = opt(argc, argv, "--rpc", "https://sepolia.base.org");
    const char *bcf = opt(argc, argv, "--bytecode-file", "/attest-vault.bin");
    const char *mnf = opt(argc, argv, "--mnemonic-file", 0);
    const char *socks = opt(argc, argv, "--socks", 0);
    const char *value = opt(argc, argv, "--value", 0);
    const char *gas = opt(argc, argv, "--gas-limit", 0);
    const char *signer = opt(argc, argv, "--signer", "/hos-ethsign-dyn");
    const char *out = opt(argc, argv, "--out", "/config/attest-contract");
    if (!mnf) {
        fprintf(stderr, "hos-attest-deploy: --mnemonic-file is required (funded deployer seed)\n");
        return 2;
    }

    /* creation bytecode (public — safe on argv) */
    int bf = open(bcf, O_RDONLY);
    if (bf < 0) {
        fprintf(stderr, "hos-attest-deploy: cannot open bytecode %s\n", bcf);
        return 2;
    }
    static char bc[131072];
    ssize_t bn = read(bf, bc, sizeof bc - 1);
    close(bf);
    if (bn <= 0) {
        fprintf(stderr, "hos-attest-deploy: empty bytecode %s\n", bcf);
        return 2;
    }
    bc[bn] = 0;
    while (bn > 0 && (bc[bn - 1] == '\n' || bc[bn - 1] == '\r' || bc[bn - 1] == ' ' || bc[bn - 1] == '\t'))
        bc[--bn] = 0;

    char *s[24];
    int a = 0;
    s[a++] = (char *)signer;
    s[a++] = "deploy";
    s[a++] = "--rpc";           s[a++] = (char *)rpc;
    s[a++] = "--bytecode";      s[a++] = bc;
    s[a++] = "--mnemonic-file"; s[a++] = (char *)mnf;
    if (socks) { s[a++] = "--socks";     s[a++] = (char *)socks; }
    if (value) { s[a++] = "--value";     s[a++] = (char *)value; }
    if (gas)   { s[a++] = "--gas-limit"; s[a++] = (char *)gas; }
    s[a] = 0;
    /* kernel snapshots a non-zero caller envp, so LD_PRELOAD reaches the dynamic child (see
     * hos-netlaunch.c). */
    char *envp[] = { "LD_PRELOAD=/libnshim.so", "PATH=/", "HOME=/", 0 };

    int p[2];
    if (pipe(p) != 0) {
        perror("hos-attest-deploy: pipe");
        return 1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        perror("hos-attest-deploy: fork");
        return 1;
    }
    if (pid == 0) {
        close(p[0]);
        dup2(p[1], STDOUT_FILENO);
        close(p[1]);
        execve(signer, s, envp);
        fprintf(stderr, "hos-attest-deploy: execve(%s) failed (missing dyn binary/interp?)\n", signer);
        _exit(127);
    }
    close(p[1]);

    static char acc[16384];
    size_t al = 0;
    char buf[4096];
    ssize_t r;
    while ((r = read(p[0], buf, sizeof buf)) > 0) {
        (void)!write(STDOUT_FILENO, buf, r); /* tee the signer's stdout through */
        for (ssize_t i = 0; i < r; i++)
            if (al < sizeof acc - 1)
                acc[al++] = buf[i];
    }
    close(p[0]);
    acc[al] = 0;
    int status = 0;
    waitpid(pid, &status, 0);

    if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
        fprintf(stderr, "hos-attest-deploy: signer failed (status 0x%x)\n", status);
        return 1;
    }

    /* extract "contract=0x" + 40 hex */
    char addr[43];
    addr[0] = 0;
    char *c = strstr(acc, "contract=0x");
    if (c) {
        c += 9; /* past "contract=" -> at "0x" */
        int ok = 1;
        for (int i = 2; i < 42; i++) {
            char ch = c[i];
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))) {
                ok = 0;
                break;
            }
        }
        if (ok) {
            memcpy(addr, c, 42);
            addr[42] = 0;
        }
    }
    if (!addr[0]) {
        fprintf(stderr, "hos-attest-deploy: no contract address in signer output\n");
        return 1;
    }

    int of = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (of < 0) {
        fprintf(stderr, "hos-attest-deploy: cannot write %s\n", out);
        return 1;
    }
    (void)!write(of, addr, strlen(addr));
    (void)!write(of, "\n", 1);
    close(of);
    fprintf(stderr, "hos-attest-deploy: recorded %s -> %s (wl-installer bakes it into install.json)\n", addr, out);
    return 0;
}
