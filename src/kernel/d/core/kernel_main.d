// D replacement for the Haskell kernel (hosMain + kernelize + dispatch).
// Called from bootstrap_kernel() after hardware init; never returns.
module core.kernel_main;

import core.task;
import core.hoscall : hosQuery, HOS_SYS_QUERY, HOSQ_DEV_READ, HOSQ_SPAWN, HOSQ_WAIT;   // Track B0 / Z4a–b native ABI
import core.hoscall : configDomainsDump, domObjViewDump, domFsViewDump;   // DOMAIN_MANAGER DM0/DM2.4 boot proofs
import core.hoscall : configPackagesDump;                                 // DOMAIN_MANAGER DM7 packages view proof
import core.hoscall : configDisksDump;                                    // INSTALLER disks view proof
import core.addrspace;
import core.elf_loader;
import core.io;
import core.console : console_set_framebuffer_enabled, console_force_framebuffer_log,
                      console_framebuffer_write;
import core.globals;
import core.exports :
    phys_to_virt, copy_phys_page,
    alloc_from_regions,
    curUserSpaceState, kernelState,
    x64TrapErrorCode,
    x64LastSyscallRax, x64LastSyscallRdi, x64LastSyscallRsi,
    x64LastSyscallRdx, x64LastSyscallR10, x64LastSyscallR8, x64LastSyscallR9,
    x64LastSyscallRip,
    x64_set_user_state_word, x64_get_user_state_word,
    g_current_task_id,
    d_store_task_fsbase, d_apply_task_fsbase,
    d_do_cleartid,
    linux_seed_initial_stack,
    linux_seed_initial_stack_with_args,
    x64_ready_for_userspace,
    x64_setup_full_idt,
    setupSysCalls,
    g_module_count, g_mboot_modules, multiboot_module_t;
import memory.mm;
import arch.x86_64.arch;
import arch.x86_64.bootstrap : g_fb, g_terminal, fb_draw_hud;

// Linux syscall implementations already in D
import core.syscalls.posix;
import core.objmgr : objStats; // Phase 2: object-table runtime stats (objReconcileFds comes via core.syscalls.posix)
import core.cap : capTableSetActive, capTableClear, capStats,
                  capInstallIn, CAP_INVALID, CAP_RIGHT_RETYPE;
import core.untyped : untypedRootInit, untypedCreateProcess, untypedSelfTest,
                      untypedStats, UNTYPED_CAP_HANDLE;
import core.ipc : ipcSelfTest, ipcStats; // Phase 7: IPC router proof
import core.device : deviceRegistryInit, deviceSelfTest, deviceStats; // Phase 8
import core.namespace : nsSelfTest, nsStats, nsClone; // Phase 9: per-process namespaces
import core.namespace : nsRestrictedSelfTest;          // DOMAIN_MANAGER DM2: deny-by-default proof
import core.user : userRegistryInit, userSelfTest, userStats, userDefaultObjId,
                  userRootObjId, userSetActiveSubject, USER_RIGHT_LOGIN, USER_RIGHT_SPAWN; // Phase 10 / IR-P3
import core.admin : adminInstallInitCaps, adminSelfTest, adminStats; // IR-P3 typed admin caps
import core.store : storeSelfTest, storeStats, storeMountSystem; // IR-P4 immutable store
import core.update : updateInit, updateSelfTest, updateStats; // IR-P6 A/B update + rollback
import drivers.block.disk : diskInit, diskSelfTest; // A5/F4 persistence: SATA disk layer
import core.diskpart : gptPartProof, gptWriteProof;  // INSTALLER §D2(b): native GPT partition engine
import drivers.veracrypt_crypto : vcCryptoKat;       // INSTALLER §E2b: real kernel AES-256 + SHA-512
import drivers.veracrypt_impl : bootHasInstallPayload,
                                vcHeaderProof, vcEncryptedLayoutProof, vcVolumeDataProof,
                                vcEncryptedInstallProof, vcFullInstallProof; // §E2b/§E3/§E4a/§E4b/full
import core.install_cap : installCapProof;             // INSTALLER §E4c: one-shot block-write cap
import core.objstore : objstoreMount, objstoreResolveExecPath, objstoreAppRights,
                       objstoreLoadExec; // F4/F4.2 persisted object store (/objects/apps) + launch
import core.crypto : cryptoSelfTest, cryptoStats; // IR-P8.1/8.2 SHA-256/HMAC + measured boot
import core.hardening : hardeningSelfTest, hardeningStats; // IR-P8.3/8.4 W^X + cap audit
import core.distos : distosSelfTest, distosStats; // IR-P9 distributed refs + macaroons + dist store
import core.secipc : secipcSelfTest, secipcStats; // SECURE_IPC P1 identity + descriptors + routing gate
import core.libsecipc : libsecipcSelfTest; // SECURE_IPC P0 crypto+transport foundation (X25519/AEAD/HKDF)
import core.secsession : secsessionSelfTest, secsessionStats,
                        seclifeSelfTest; // SECURE_IPC P2 sessions / P3 lifecycle
import core.secobj : secobjSelfTest, secobjStats; // SECURE_IPC P4 object-tree + Linux shim
import core.sechard : sechardSelfTest, sechardStats; // SECURE_IPC P5 hardening + parser fuzz
import core.servicemgr : serviceManagerInit, serviceSelfTest, serviceStats,
                        servicePhase5SelfTest; // Phase 10 / IR-P5 service management
import core.window : windowRegistryInit, windowSelfTest, windowStats; // Phase 11
import core.identity : identityInitDefaults, identityInitLaunchRules, identityByName,
                       identitySelfTest, idprocSelfTest, identityStats, identityNamePrint,
                       identityById; // IDENTITY_DOMAIN P2/P3 (+ F4.2 launch cap-gate)
import core.domain : domainInitDefaults, domainSelfTest, domainStats; // DOMAIN_MANAGER DM0
import core.domain : domainNsProof;        // DOMAIN_MANAGER DM2: per-domain restricted-namespace proof
import core.domain : domFsManifestProof;   // DOMAIN_MANAGER DM2.3: manifest-built fs policy proof
import core.domain : domainBuildAllNamespaces; // DOMAIN_MANAGER DM10.2: eager per-domain ns for the GUI Filesystem view
import core.domain : domainControlWrite, domainControlProof; // DOMAIN_MANAGER DM10.3: parsed control-string executor + proof
import core.domain : domDistroProof;                        // DOMAIN_MANAGER DM11: distro/pkgMgr + /linux proof
import core.domain : domInheritProof;                       // DOMAIN_MANAGER DM9: inheritance least-privilege merge
import core.kmain : smpWorkReport, smpActivateAp;           // SMP_ROADMAP S4 foundation report + S4.4a activation
import core.kmain : bklAcquire, bklRelease, g_bkl;          // SMP_ROADMAP S4.4d: BKL around the kernelLoop coroutine
import core.kmain : g_apSyscallCount, apActivatedApicTicks;  // SMP_ROADMAP S4.4d/S5: AP's parallel getpid + timer counters
import core.kmain : sendApIpi, apActivatedLapicId, apActivatedIpiCount, g_apActivatedIdx;  // S7: BSP→AP IPIs
import core.kmain : apAllocCount;                          // SMP_ROADMAP S6: AP's BKL-free allocations
// NETWORK_AND_MARKETPLACE_ROADMAP N0/N1: bring up the IPv4 stack on a NIC + an ARP round-trip proof.
import network.stack : configureNetwork, startNetworkStack, networkStackPoll, ping;
import drivers.network.network : isNetworkAvailable, getMacAddress, getNetRxFrames, getNetRxLastEtherType;
import drivers.pci : wifiSurvey;   // WiFi/network-controller hardware survey (real-HW bring-up)
import network.arp : arpSendRequest, arpLookup;
import network.types : IPv4Address, MACAddress;
import network.icmp : getIcmpEchoReplies;   // N2: verify a ping round-trips
import network.dns : dnsResolve;            // N2/N3/N6: prove the IPv4 RX path via a DNS reply
import network.dhcp : dhcpAcquire, dhcpGetConfig;   // N6 DHCP: the offline-verifiable IPv4+UDP RX proof
import network.ipv4 : setLocalIPAddress, setGateway, setNetmask;  // apply a real DHCP lease
import network.dns  : setDNSServer;                 // ...including the leased resolver
import core.pkgrepo : pkgRepoSeed, pkgRepoSelfTest;          // DOMAIN_MANAGER DM7: software repository + package manager
import core.template_bundle : templateBundleProof, tplSeed; // DOMAIN_MANAGER DM12: signed template bundles
import core.domain : domainLifecycleProof; // DOMAIN_MANAGER DM4: lifecycle state machine proof
import core.domain : domainRehydrateFromDisk, domainPersistProof; // DOMAIN_MANAGER DM5: on-disk persistence
import core.domain : domainTemplateProof;  // DOMAIN_MANAGER DM6: immutable templates proof
import core.overlay : overlaySelfTest;     // DOMAIN_MANAGER DM6.2: writable overlay (CoW) proof
import core.idns : idnsInitRoots, idnsSelfTest, idnsStats; // IDENTITY_DOMAIN P4 per-identity namespaces
import core.idipc : idipcInit, idipcSelfTest, idipcStats; // IDENTITY_DOMAIN P5 cross-identity IPC policy
import core.idwin : idwinInit, idwinSelfTest, idwinStats; // IDENTITY_DOMAIN P6 unspoofable window identity borders
import display.compositor.compositor : compositorIdentitySelfTest; // GUI: trusted identity borders
import core.linuxobj : linuxObjectInit, linuxEnabled, linuxNoteTranslate,
                       linuxNoteBlocked, linuxNoteElfLoad, linuxSelfTest,
                       linuxStats; // Phase 12: Linux-compat object subtree
import core.linuxpers : linuxPersSelfTest, linuxPersStats; // IR-P7: Linux personality → cap/ns ops
import core.census : kernelCensusReport, kernelCensusStats; // Phase 13: six-pillar census
import core.org : orgInit, orgSelfTest, orgStats, orgAudit, orgIntegReport,
                  orgApiSelfTest, orgCycleSelfTest, orgGcSelfTest,
                  orgSecuritySelfTest, orgVizSelfTest,
                  orgLinuxSelfTest; // ORG P2–P10 (validator → daemon)
import core.cap : capRevokeClosureSelfTest; // ORG P7.2
import core.org_validator : orgValidatorInit, orgValidatorTick,
                            orgValidatorSelfTest, orgValidatorStats; // ORG P8
import core.audit : auditStats; // ORG P8.2
import core.org_dist : orgDistSelfTest, orgDistTick, orgDistStats; // ORG P11
import core.org_test : orgTestSuite; // ORG P12: invariant/fuzz/scale test suite
import core.configboot : configBootApply; // DECLARITIVE_MODEL_ROADMAP §4: verified-config boot lowering
import core.install_config : installConfigApply; // INSTALLER: first-boot install.json apply
import display.splash : splashRun;        // native boot splash (particle network + boot log)
import core.syscalls.mmap : sys_munmap, sys_mprotect;
import core.ticks : increment_ticks, get_ticks, pitMs, cpuAccountTick;
import core.random;

extern (C) @nogc nothrow:

extern (C) ulong x64ReadCR2() @nogc nothrow;
extern (C) ulong x64ReadCR3() @nogc nothrow;
extern (C) void  x64WriteCR3(ulong) @nogc nothrow;

// Assembly context switcher — defined in context.S
extern (C) ulong x64SwitchToUserspace(void* userState, void* kernelState) @nogc nothrow;

// ------------------------------------------------------------------
// Helpers: load / save task register state from/to curUserSpaceState
// ------------------------------------------------------------------

private void loadTaskState(ref Task task) {
    // reason word at curUserSpaceState[0]
    *cast(ulong*)&curUserSpaceState[0] = REASON_TRAP;

    // registers at curUserSpaceState[8..144]
    auto dst = cast(ulong*)(&curUserSpaceState[0] + 8);
    for (uint i = 0; i < NUM_REGS; i++)
        dst[i] = task.regs[i];

    // A freshly created task starts with a zero-filled FXSAVE image, whose MXCSR
    // (offset 24) is 0 — meaning every SSE floating-point exception is UNMASKED.
    // On a real FPU (KVM) the first invalid/overflow op (e.g. Hyprgraphics' OkLab
    // colour math) then raises #XM and kills the task; QEMU's TCG software FPU
    // happened to tolerate it.  Seed an uninitialised image with the standard
    // masked default (MXCSR 0x1F80, FCW 0x037F) so no FP op ever traps.
    {
        auto mxcsr = cast(uint*)(task.sseState.ptr + 24);
        if (*mxcsr == 0) {
            *mxcsr = 0x1F80;
            *cast(ushort*)(task.sseState.ptr + 0) = 0x037F; // x87 control word
        }
    }

    // SSE state at curUserSpaceState[8 + 0x90]
    auto sseDst = cast(ubyte*)(&curUserSpaceState[0] + 8 + 0x90);
    auto sseSrc = task.sseState.ptr;
    for (int i = 0; i < 512; i++)
        sseDst[i] = sseSrc[i];
}

private void saveTaskState(ref Task task) {
    // registers
    auto src = cast(ulong*)(&curUserSpaceState[0] + 8);
    for (uint i = 0; i < NUM_REGS; i++)
        task.regs[i] = src[i];

    // SSE state
    auto sseSrc = cast(ubyte*)(&curUserSpaceState[0] + 8 + 0x90);
    auto sseDst = task.sseState.ptr;
    for (int i = 0; i < 512; i++)
        sseDst[i] = sseSrc[i];
}

// Set RAX in the saved user state (syscall return value)
private void setReturnValue(ref Task task, ulong val) {
    task.regs[REG_RAX] = val;
}

// ------------------------------------------------------------------
// Scheduler: simple round-robin
// ------------------------------------------------------------------

private enum FUTEX_WAIT           = 0;
private enum FUTEX_WAKE           = 1;
private enum FUTEX_REQUEUE        = 3;
private enum FUTEX_CMP_REQUEUE    = 4;
private enum FUTEX_WAKE_OP        = 5;
private enum FUTEX_WAIT_BITSET    = 9;
private enum FUTEX_WAKE_BITSET    = 10;
private enum FUTEX_PRIVATE_FLAG   = 0x80;
private enum FUTEX_CLOCK_REALTIME = 0x100;
private enum uint FUTEX_BITSET_MATCH_ANY = 0xffffffffU;

__gshared bool[MAX_TASKS]  g_futexWaitActive;
__gshared ulong[MAX_TASKS] g_futexWaitUaddr;

// PERF profiling: per-task userspace CPU cycles (one quantum = one trip through
// x64SwitchToUserspace) — reveals a CPU hog starving the compositor.  Interval
// counters reset each stats dump.
__gshared ulong[MAX_TASKS] g_schedCyc;
__gshared ulong[MAX_TASKS] g_schedN;

// PERF: cooperative poll/epoll sleep.  A task that polls with nothing ready and a
// non-zero timeout is parked (waiting=true) instead of being re-run every
// round-robin cycle (which busy-spins the single core, starving the compositor).
// It is re-checked when woken: every PIT tick (≤1 ms latency) and on input IRQs.
__gshared bool[MAX_TASKS]  g_pollBlocked;
__gshared ulong[MAX_TASKS] g_pollDeadline;   // pitMs deadline; 0 = infinite (fd-only)
__gshared uint g_lklIrqBurst = 0;            // op6 storm protection: back-to-back wakes before a forced yield

// The idle task: a userspace PAUSE-spinner the scheduler runs ONLY when every real
// task is parked, so the kernel isn't re-running parked pollers' epoll scans at full
// rate (which saturated the kernel and starved the compositor).  -1 until spawned.
__gshared int g_idleTid = -1;

// Wake parked pollers so they re-check their fds.  Called from the PIT tick and
// input IRQs.  Clearing `waiting` lets the scheduler pick them; they re-run their
// poll/epoll and either return (fd ready / timed out) or re-park.
// DIAG: dump the CURRENT task's user RIP + text-looking return addresses from its stack.
// Runs inside the task's own syscall (its CR3 is live), so user memory is directly
// readable.  Text filters: the non-PIE Hyprland image (0x400000+) and the musl/lib
// region (0x5a00_0000_0000+); addresses resolve offline with addr2line.
public void dumpCurrentTaskUserStack() @nogc nothrow {
    int tid = cast(int)g_current_task_id;
    if (tid < 0 || tid >= MAX_TASKS) return;
    auto task = &g_tasks[tid];
    ulong rsp = task.regs[REG_RSP];
    klog("[ustack] t="); klog_hex(cast(ulong)tid);
    klog(" rip="); klog_hex(task.regs[REG_RIP]);
    klog(" rsp="); klog_hex(rsp);
    klog("\n[ustack]");
    if (rsp >= 0x1000) {
        int logged = 0;
        for (ulong i = 0; i < 400 && logged < 24; i++) {
            ulong a = rsp + i * 8;
            if (!userPageMapped(tid, a)) break;
            ulong v = *cast(ulong*)a;
            if ((v >= 0x400000 && v < 0x10000000) || (v >= 0x5a0000000000 && v < 0x5b0000000000)) {
                klog(" "); klog_hex(v); ++logged;
            }
        }
    }
    klog("\n");
}

// ── Lost-wakeup watchdog ──────────────────────────────────────────────────────
// The FW13 "desktop frozen, cursor moves" hard-freeze root cause (freeze-probe verified):
// the CPU sits IDLE (cur=2:idle, syscalls flowing, HOG even) while Weston stays PARKED
// forever — a lost wakeup (its poll/epoll/futex wake got dropped in a burst, e.g. when the
// WiFi scan floods events).  Recovery: when the desktop has stopped presenting for >2 s,
// re-wake all poll-parked tasks (safe: their RIP is rewound, poll re-evaluates its fds and
// either returns real events or re-parks).  If the stall persists past 5 s, also spurious-
// wake infinitely-parked futex waiters (futex(2) explicitly allows spurious wakeups; the
// waiter re-checks the futex word and re-waits).  No-op while the desktop presents normally.
__gshared ulong g_fwdLastMs = 0;
__gshared uint  g_fwdWakes = 0;

// Expanded when THIS file is compiled -- see the note at the klog(BUILD_STAMP.ptr) call.
private enum string BUILD_STAMP = "[build] kernel compiled " ~ __DATE__ ~ " " ~ __TIME__ ~ "\n\0";

// PERF: presentProfStats() is the one measurement that splits a frame's cost into the
// kernel-side present (the scanout blit) and the compositor's own render time -- exactly
// what decides where a slow desktop gets fixed.  Its only call site was gated on
// (g_objReconcileCtr & 0x3FFF) == 0, which does not fire in a desktop boot: a full serial
// log of a Hyprland session contains ZERO "[present]" lines.  Drive it off the wall clock
// instead so the numbers exist whether or not the reconcile counter ever lands on 0.
__gshared ulong g_presProfLastMs = 0;

// Is the compositor BUSY or merely IDLE between frames?  present_share_permil already proves the
// kernel blit is ~2 ms of a ~1100 ms frame, so the missing second is in userspace -- but "burning
// a second compositing" and "asleep waiting for a client to damage something" look identical from
// the present timestamps alone, and they need opposite fixes.  So sample the presenter's own run
// state on every main-loop pass and report the parked fraction alongside the frame time:
//
//   cmp_park_permil ~= 0    -> render-bound: the compositor is computing the whole time, and the
//                             cost is per-frame work (overdraw / texture upload / fragment cost).
//   cmp_park_permil -> 1000 -> damage-bound: the desktop is idle and simply repaints when a client
//                             asks it to, so the frame rate is a CLIENT redraw cadence, not a
//                             compositor limit, and chasing render cost would be wasted effort.
//
// g_presenterTid is set by presentAccount(), so it names the task that actually reaches the
// scanout -- no guessing which of the several "Hyprland" tasks is the compositor's main thread.
__gshared ulong g_cmpParkSamples = 0;
__gshared ulong g_cmpRunSamples  = 0;
private void presentProfSample() @nogc nothrow {
    const int ct = g_presenterTid;
    if (ct < 0 || ct >= MAX_TASKS) return;
    if (!g_tasks[ct].active || g_tasks[ct].exited) return;
    if (g_tasks[ct].waiting || g_pollBlocked[ct]) ++g_cmpParkSamples;
    else                                          ++g_cmpRunSamples;
}

private void presentProfTick() {
    if (g_lastPresentMs == 0) return;                  // desktop not up yet — nothing to profile
    presentProfSample();                               // every pass: parked-vs-running duty cycle
    const ulong now = pitMs();
    if (now - g_presProfLastMs < 5000) return;         // one rolling 5 s window per line
    g_presProfLastMs = now;
    presentProfStats();                                // NB: prints AND resets the interval counters

    const ulong tot = g_cmpParkSamples + g_cmpRunSamples;
    klog("[cmpduty] parked_permil=");
    klog_dec(tot ? (g_cmpParkSamples * 1000) / tot : 0);
    klog(" parked="); klog_dec(g_cmpParkSamples);
    klog(" running="); klog_dec(g_cmpRunSamples);
    klog(" tid="); klog_dec(cast(ulong)g_presenterTid);
    klog("\n");
    g_cmpParkSamples = 0;
    g_cmpRunSamples  = 0;
}
private void freezeWatchdog() {
    if (g_lastPresentMs == 0) return;                    // desktop not up yet
    const ulong now = pitMs();
    if (now < g_lastPresentMs) return;
    const ulong stall = now - g_lastPresentMs;
    if (stall < 2000) { g_fwdWakes = 0; return; }        // presenting fine (or brief hiccup)
    // An IDLE desktop is not a lost wakeup.  Once clients stop damaging anything the compositor
    // parks in poll on purpose and presents nothing; re-waking it every second achieves nothing
    // and floods the log (81 bogus stall episodes in one boot).  desktopIsIdle() distinguishes
    // "parked with nothing outstanding" from "parked with a completion it never read", and only
    // the latter is the lost-wakeup this watchdog exists to recover from.
    if (desktopIsIdle()) { g_fwdWakes = 0; return; }
    if (now - g_fwdLastMs < 1000) return;                // retry at most 1/s while stalled
    g_fwdLastMs = now;
    ++g_fwdWakes;
    wakePollers();                                        // tier 1: poll/epoll/read-parked tasks
    klog("[freeze] watchdog: re-woke parked pollers (stall ");
    klog_dec(stall / 1000); klog("s, attempt "); klog_dec(g_fwdWakes); klog(")\n");
    if (stall >= 5000) {                                  // tier 2: infinite futex waiters
        uint n = 0;
        for (int i = 0; i < MAX_TASKS; i++) {
            if (g_futexWaitActive[i] && g_futexWaitDeadline[i] == 0 &&
                g_tasks[i].active && !g_tasks[i].exited) {
                clearFutexWait(i, 0);                     // spurious wake: waiter re-checks + re-waits
                ++n;
            }
        }
        klog("[freeze] watchdog: spurious-woke "); klog_dec(n); klog(" futex waiters\n");
    }
}

private void wakePollers() @nogc nothrow {
    // ITIMER_REAL expiry -> pending SIGALRM.  Driven here because wakePollers() already runs on
    // every PIT tick and is the natural place to un-park time-based waiters.
    itimerTick();
    foreach (i; 0 .. MAX_TASKS) {
        // Never bare-unpark a futex-parked task: only clearFutexWait may wake one (it sets
        // RAX; a bare waiting=false returns garbage to the middle of a FUTEX_WAIT and musl
        // spin-retries).  A stale g_pollBlocked can coexist with a futex park (see the
        // g_pollBlocked clear at the futex park site for the main leak fix).
        if (g_pollBlocked[i] && !g_futexWaitActive[i] && g_tasks[i].active && !g_tasks[i].exited)
            g_tasks[i].waiting = false;
    }
}
__gshared int[MAX_TASKS]   g_futexWaitVal;
__gshared uint[MAX_TASKS]  g_futexWaitBitset;
__gshared ulong[MAX_TASKS] g_futexWaitDeadline; // pitMs deadline for a timed FUTEX_WAIT; 0 = wait forever
__gshared ulong g_futexLogCount = 0;
__gshared ulong g_futexWakeLogCount = 0;
__gshared ulong g_futexRegionMiss = 0;
// BISECT FLAG: true disables futex timeout arming (waits park forever, pre-timeout behavior).
__gshared bool g_futexTimeoutsOff = false;
__gshared bool g_guiClientAutostartEnabled = false;
__gshared bool g_guiClientStarted = false;
__gshared bool g_guiClientListenerSeen = false;
__gshared ulong g_guiClientLaunchTick = 0;
private enum ulong GUI_CLIENT_SETTLE_TICKS = 6000;
private enum ulong USER_MAIN_PIE_BASE = 0x550000000000UL;
private enum ulong USER_INTERP_BASE   = 0x5A0000000000UL;

private bool futexWaitMatches(int tid, ulong uaddr, uint wakeBits) {
    if (tid < 0 || tid >= MAX_TASKS) return false;
    if (!g_futexWaitActive[tid]) return false;
    if (g_futexWaitUaddr[tid] != uaddr) return false;
    return (g_futexWaitBitset[tid] & wakeBits) != 0;
}

private void clearFutexWait(int tid, long ret) {
    if (tid < 0 || tid >= MAX_TASKS) return;
    g_futexWaitActive[tid] = false;
    g_futexWaitUaddr[tid] = 0;
    g_futexWaitVal[tid] = 0;
    g_futexWaitBitset[tid] = 0;
    g_futexWaitDeadline[tid] = 0;

    auto t = &g_tasks[tid];
    if (t.active && !t.exited) {
        t.waiting = false;
        t.regs[REG_RAX] = cast(ulong)ret;
    }
}

private void installTaskUntypedCap(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return;
    auto task = &g_tasks[tid];
    if (task.untypedObjId == 0) return;
    capInstallIn(task.capTabId, UNTYPED_CAP_HANDLE, task.untypedObjId,
                 CAP_RIGHT_RETYPE, CAP_INVALID);
}

private bool refreshFutexWaiter(int tid) {
    if (tid < 0 || tid >= MAX_TASKS || !g_futexWaitActive[tid]) return false;

    auto t = &g_tasks[tid];
    if (!t.active || t.exited) {
        clearFutexWait(tid, -4); // EINTR-like cleanup for dead slots
        return false;
    }

    ulong uaddr = g_futexWaitUaddr[tid];
    // Validate uaddr by walking the REAL page tables (shared by all CLONE_VM threads), NOT
    // the per-task region list.  A thread's region bookkeeping misses regions mmap'd by a
    // SIBLING thread after the clone (regions are recorded per-task; threads share only the
    // page tables) — so findRegion(*t, uaddr) failed for a futex word living in a
    // sibling-mmap'd region, and this function then cleared the park with EINTR on the very
    // scheduleNext() call inside the park itself.  musl retries on EINTR → the thread
    // re-parked and was re-cleared ~80,000×/s, monopolizing the core and starving the
    // compositor (Hyprland froze after its initial render burst).  The page-table walk is
    // the ground truth; the word was just read by userspace so it is faulted in.
    if (t.pml4Phys == 0 || !userPageMapped(tid, uaddr)) {
        clearFutexWait(tid, -4);
        return false;
    }
    if (findRegion(*t, uaddr) is null) {
        // Mechanism confirmation (capped): region bookkeeping missed a mapped page.
        if (g_futexRegionMiss < 12) {
            ++g_futexRegionMiss;
            klog("[futex-region-miss] t="); klog_hex(cast(ulong)tid);
            klog(" u="); klog_hex(uaddr); klog(" (page mapped, region list missed it)\n");
        }
    }

    ulong savedCr3 = x64ReadCR3();
    bool switchedCr3 = savedCr3 != t.pml4Phys;
    if (switchedCr3) x64WriteCR3(t.pml4Phys);
    int cur = *cast(int*)uaddr;
    if (switchedCr3) x64WriteCR3(savedCr3);
    if (cur != g_futexWaitVal[tid]) {
        klog("[futex-unblock] t="); klog_hex(cast(ulong)tid);
        klog(" u="); klog_hex(uaddr);
        klog(" want="); klog_hex(cast(ulong)cast(uint)g_futexWaitVal[tid]);
        klog(" now="); klog_hex(cast(ulong)cast(uint)cur);
        klog("\n");
        clearFutexWait(tid, 0);
        return true;
    }
    // Timed FUTEX_WAIT: expire with ETIMEDOUT once the pitMs deadline passes.  This runs
    // every scheduleNext() pass, so expiry latency is one pass.  clearFutexWait un-parks
    // AND sets RAX, so musl's __timedwait / pthread_cond_timedwait sees a clean -ETIMEDOUT.
    // (Checked AFTER the value-change unblock so a same-pass genuine wake wins.)
    if (g_futexWaitDeadline[tid] != 0 && pitMs() >= g_futexWaitDeadline[tid]) {
        clearFutexWait(tid, -110); // ETIMEDOUT
        return true;
    }
    return false;
}

private uint futexWakeAddress(ulong uaddr, uint maxWake, uint wakeBits, int wakerTid) {
    if (uaddr == 0 || maxWake == 0 || wakeBits == 0) return 0;

    // A userspace futex address is only meaningful WITHIN its own address space, and we match
    // waiters by raw uaddr.  Without confining the wake to the waker's address space, a private-futex
    // FUTEX_WAKE in one process wakes — and, worse, spends its maxWake budget on — a DIFFERENT
    // process's waiter that merely sits at the same virtual address.  musl loads libc at a fixed base,
    // so e.g. EVERY process's malloc lock lives at the same uaddr; a cross-process match steals the
    // wake from the waker's OWN thread and permanently strands it (this wedged Hyprland's multi-thread
    // event loop once other wayland clients — bar/demo/dbus — were also blocked on their same-uaddr
    // locks).  Threads of one process share pml4Phys, so require the waiter to be in the waker's
    // address space.  (Cross-process SHARED futexes would need physical-page matching, which this
    // uaddr-keyed table never supported anyway.)
    ulong wakerPml4 = (wakerTid >= 0 && wakerTid < MAX_TASKS) ? g_tasks[wakerTid].pml4Phys : 0;

    uint woke = 0;
    for (int i = 0; i < MAX_TASKS && woke < maxWake; i++) {
        if (!futexWaitMatches(i, uaddr, wakeBits)) continue;
        if (wakerPml4 != 0 && g_tasks[i].pml4Phys != wakerPml4) continue;
        clearFutexWait(i, 0);
        woke++;
        klog("[futex-wake-one] waker="); klog_hex(cast(ulong)wakerTid);
        klog(" waiter="); klog_hex(cast(ulong)i);
        klog(" u="); klog_hex(uaddr);
        klog("\n");
    }
    return woke;
}

private uint futexRequeueAddress(ulong from, ulong to, uint maxRequeue, uint wakeBits) {
    if (from == 0 || to == 0 || maxRequeue == 0 || wakeBits == 0) return 0;

    uint moved = 0;
    for (int i = 0; i < MAX_TASKS && moved < maxRequeue; i++) {
        if (!futexWaitMatches(i, from, wakeBits)) continue;
        g_futexWaitUaddr[i] = to;
        moved++;
        klog("[futex-requeue-one] waiter="); klog_hex(cast(ulong)i);
        klog(" from="); klog_hex(from);
        klog(" to="); klog_hex(to);
        klog("\n");
    }
    return moved;
}

private void scheduleNext() {
    for (int i = 0; i < MAX_TASKS; i++)
        refreshFutexWaiter(i);

    ulong cur = g_current_task_id;
    // Round-robin over ALL task slots including 0: task 0 is the main userspace
    // process, so once it blocks (poll/futex/vfork) it must be reschedulable like
    // any other.  (Previously slot 0 was skipped, which permanently starved the
    // main thread whenever it yielded.)
    for (uint i = 1; i <= MAX_TASKS; i++) {
        uint next = cast(uint)((cur + i) % MAX_TASKS);
        if (cast(int)next == g_idleTid) continue;   // idle is a last resort only
        auto t = &g_tasks[next];
        if (t.active && !t.exited && !t.waiting) {
            g_current_task_id = next;
            freezeSchedSample(cast(int)next);   // freeze probe: who is the core spending time on?
            return;
        }
    }
    // Nothing runnable: check for waiting tasks that might now be unblocked
    for (uint i = 0; i < MAX_TASKS; i++) {
        auto t = &g_tasks[i];
        // CRITICAL: skip poll/read/select-parked tasks (g_pollBlocked) AND futex-parked tasks
        // (g_futexWaitActive).  `t.waiting` is shared between a wait4() block, a poll/read/select park,
        // and a FUTEX_WAIT park, and `t.waitingForPid` is NOT reset when a task later parks a different
        // way — so a thread that once did wait4(-1) and now blocks in FUTEX_WAIT still has
        // waitingForPid=-1 + a stale childExited[] bit.  Without this guard, this block "un-blocks its
        // waitpid" tens of thousands of times/sec (the task re-runs futex→*u==val→park→here→un-wait→
        // re-issue FUTEX_WAIT…), pinning the core and starving the compositor — the exact spin observed
        // as task 0x19 hammering FUTEX_WAIT(val=0,*u=0) while aquamarine could not get scheduled.  A
        // genuine wait4 waiter has both flags false and is still woken by the child-exit path (src=5) /
        // wakePollers; this fallback only handles the pre-parked race.
        if (t.active && !t.exited && t.waiting && !g_pollBlocked[i] && !g_futexWaitActive[i]) {
            // poll whether the waited-for child has exited
            bool found = false;
            if (t.waitingForPid == -1) {
                for (uint j = 0; j < MAX_TASKS; j++)
                    if (t.childExited[j]) { found = true; break; }
            } else {
                uint c = cast(uint)t.waitingForPid;
                if (c < MAX_TASKS && t.childExited[c]) found = true;
            }
            if (found) {
                t.waiting = false;
                g_current_task_id = i;
                return;
            }
        }
    }
    // Nothing else runnable: rather than spin the run loop with interrupts masked
    // (which would freeze the PIT/input IRQs and deadlock the parked poll/epoll
    // sleepers), wake them so at least one becomes runnable and the system stays
    // live to service interrupts.  During active work the compositor is runnable
    // and chosen above, so the parked pollers keep yielding it the core — they are
    // only force-woken here when truly *everyone* is idle.
    // Every real task is parked.  Run the dedicated idle task (a cheap userspace
    // PAUSE-spinner) so the PIT/input IRQs keep firing WITHOUT re-running the parked
    // pollers' expensive epoll scans — that re-run was saturating the kernel (~190k
    // scans/s) and starving the compositor.  The pollers stay parked until a real
    // event (input IRQ / sendmsg) or the ~8 ms timer wake.
    if (g_idleTid > 0 && g_tasks[g_idleTid].active && !g_tasks[g_idleTid].exited
        && !g_tasks[g_idleTid].waiting) {
        g_current_task_id = cast(ulong)g_idleTid;
        return;
    }
    // No idle task yet — fall back to waking one parked poller to keep IRQs alive.
    // (!g_futexWaitActive: never bare-unpark a futex waiter — and note next==cur at
    // i==MAX_TASKS, so without the guard a just-futex-parked current task with a stale
    // g_pollBlocked could wake ITSELF inside its own park's scheduleNext -> syscall-rate spin.)
    for (uint i = 1; i <= MAX_TASKS; i++) {
        uint next = cast(uint)((cur + i) % MAX_TASKS);
        if (g_pollBlocked[next] && !g_futexWaitActive[next] && g_tasks[next].active && !g_tasks[next].exited
            && g_tasks[next].waiting) {
            g_tasks[next].waiting = false;
            g_current_task_id = next;
            return;
        }
    }
    // All tasks gone or stuck — just keep running the current one
}

// ------------------------------------------------------------------
// Task exit
// ------------------------------------------------------------------

// Poor-man's backtrace for a crashed user task, printed BEFORE the address space is torn down.
//
// Motivated by a real dead end: Hyprland died with `exception 0x0d rip=<ld-musl>+0x1f2ad`, which
// symbolised to abort()+0x7d -- musl's abort() falls through to a_crash(), and a_crash() on
// x86-64 is `hlt`, which faults #GP in ring 3.  So we knew it aborted but not WHO called abort,
// and by the time the monitor could look, exitTask had already unmapped the stack (every word
// read back as zero).  There is no frame pointer to walk (-O2 omits it), so scan the top of the
// stack for values that land inside a user text mapping: return addresses stand out, and even an
// approximate chain names the caller.  Cheap, bounded, and only runs on an actual crash.
private void crashBacktrace(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return;
    auto t = &g_tasks[tid];
    const ulong rsp = t.regs[REG_RSP];
    if (rsp == 0) return;

    // The faulting task's address space is still live here (exitTask has not reclaimed it), but
    // we may be on another CR3 -- switch to the crashed task's tables to read its stack.
    const ulong savedCr3 = x64ReadCR3();
    if (t.pml4Phys != 0) x64WriteCR3(t.pml4Phys);

    klog("[freeze] backtrace rsp="); klog_hex(rsp); klog("\n");
    // Stay inside the page rsp already sits in.  Walking past it could touch an unmapped page
    // and fault the KERNEL while it is in the middle of reporting a user crash -- turning a
    // diagnosable client death into a kernel panic.  One page of stack is plenty to catch the
    // nearest few return addresses.
    const ulong pageEnd = (rsp | 0xFFF) + 1;
    int shown = 0;
    for (ulong addr = rsp & ~7UL; addr + 8 <= pageEnd && shown < 12; addr += 8) {
        const ulong off = addr - rsp;
        const ulong v = *cast(ulong*)addr;
        // Keep values that look like a return address: the main image (0x400000..topVirt) or the
        // musl interp at 0x5a0000000000.  Everything else is data and would just be noise.
        const bool inMain   = (v >= 0x400000UL && v < 0x4000_0000UL);
        const bool inInterp = (v >= 0x5a00_0000_0000UL && v < 0x5a00_0100_0000UL);
        if (!inMain && !inInterp) continue;
        klog("  [+"); klog_hex(off); klog("] "); klog_hex(v);
        klog(inInterp ? "  (ld-musl+" : "  (main+");
        klog_hex(inInterp ? (v - 0x5a00_0000_0000UL) : v);
        klog(")\n");
        ++shown;
    }
    if (shown == 0) klog("  (no return addresses found on the stack)\n");
    x64WriteCR3(savedCr3);
}

private void exitTask(int tid, int code) {
    if (tid < 0 || tid >= MAX_TASKS) return;
    if (g_futexWaitActive[tid])
        clearFutexWait(tid, -4); // EINTR-like cleanup for the exiting waiter

    auto t = &g_tasks[tid];
    // Z1: snapshot the Linux pid NOW, before any cleanup below resets processLeaderTid;
    // the parent-notify further down stores it for wait4 to return (zsh matches on it).
    const int exitLinuxPid = linuxPidForTask(tid);
    t.exited   = true;
    t.exitCode = code;
    // Freeze probe: if the COMPOSITOR (the presenting task) dies, the desktop hard-freezes with a
    // moving cursor — record the cause so the on-screen overlay can show it (the klog ring does not
    // survive the hard reset the user then has to do).
    if (tid == g_presenterTid) {
        g_cmpExitCode = code;
        g_cmpExitMs   = pitMs();
        g_cmpExitRip  = t.regs[REG_RIP];   // for a code-11 crash this is the faulting user RIP
        klog("[freeze] COMPOSITOR DIED t="); klog_dec(cast(ulong)tid);
        klog(" code="); klog_dec(cast(ulong)(cast(uint)code & 0xffff));
        klog(" rip="); klog_hex(t.regs[REG_RIP]);
        klog(" (11 = segfault/exception; 128+sig = killed by signal)\n");
    } else if (code != 0) {
        // A CLIENT crashed (the panel is the prime suspect).  Record its site for the overlay.
        g_lastCrashTid = tid; g_lastCrashCode = code; g_lastCrashRip = t.regs[REG_RIP]; g_lastCrashMs = pitMs();
        auto cn = g_taskExecName[tid];
        int k = 0; if (cn !is null) { while (cn[k] && k < 23) { g_lastCrashName[k] = cn[k]; ++k; } }
        g_lastCrashName[k] = 0;
        klog("[freeze] CLIENT CRASH t="); klog_dec(cast(ulong)tid);
        klog(" code="); klog_dec(cast(ulong)(cast(uint)code & 0xffff));
        klog(" rip="); klog_hex(t.regs[REG_RIP]); klog("\n");
        crashBacktrace(tid);
    }
    // direct-fb (real-HW): a process died — name + code. If init=weston shows up here
    // with a nonzero code, the compositor crashed before claiming the display.
    if (g_procFbLogN < 64) {
        ++g_procFbLogN;
        console_framebuffer_write("\n[proc] exit t="); fbDec(cast(ulong)tid);
        console_framebuffer_write(" code="); fbDec(cast(ulong)(cast(uint)code & 0xffff));
        auto _enm = g_taskExecName[tid];
        if (_enm !is null) { console_framebuffer_write(" "); console_framebuffer_write(_enm); }
    }
    g_pollBlocked[tid] = false;   // PERF: drop any parked poll/epoll state
    if (tid >= 0 && tid < MAX_TASKS) {
        g_taskExecModPhys[tid] = 0;                 // A4: clear exe info
        g_taskPgid[tid] = 0; g_taskSigCustom[tid] = 0; g_taskPendingSig[tid] = 0;
        g_sigHandler[tid][] = 0; g_sigRestorer[tid][] = 0;   // Z1: clear signal handlers
    }
    if (tid == g_idleTid) g_idleTid = -1;   // idle task died — re-spawn next loop
    objReleaseTask(tid);

    // Close the dying task's fds so socket PEERS see the hangup — without this a
    // Wayland client's exit never reaches Weston, so a closed window's surface is
    // never destroyed and its pixels linger on screen.  Skipped while a live thread
    // still shares the fd table (CLONE_VM); fork copies the table (own fdTabId), so
    // the refcount-aware close only hangs up a peer when the last holder goes.
    {
        bool fdTabShared = false;
        for (int i = 0; i < MAX_TASKS; i++) {
            if (i == tid) continue;
            if (g_tasks[i].active && !g_tasks[i].exited && g_tasks[i].fdTabId == t.fdTabId) {
                fdTabShared = true; break;
            }
        }
        if (!fdTabShared) taskCloseAllFds(t.fdTabId);
    }
    bool capTableStillShared = false;
    for (int i = 0; i < MAX_TASKS; ++i) {
        if (i != tid && g_tasks[i].active && !g_tasks[i].exited &&
            g_tasks[i].capTabId == t.capTabId) {
            capTableStillShared = true;
            break;
        }
    }
    if (!capTableStillShared)
        capTableClear(t.capTabId);
    d_do_cleartid(cast(ulong)tid);

    // If a vfork parent is suspended on this child, resume it (the child is gone).
    resumeVforkParent(tid);

    // CLONE_CHILD_CLEARTID: zero the thread's tid word so a joining thread's
    // futex wait observes termination.  Runs in the exiting thread's context, so
    // the (shared) address space is active and the user pointer is valid.
    if (tid >= 0 && tid < MAX_TASKS && g_threadCleartidVirt[tid] != 0) {
        ulong clearTid = g_threadCleartidVirt[tid];
        *cast(int*)clearTid = 0;
        futexWakeAddress(clearTid, 1, FUTEX_BITSET_MATCH_ANY, tid);
        g_threadCleartidVirt[tid] = 0;
    }

    // Notify parent
    int parent = t.parentId;
    // parent >= 0: task 0 (the main process) can also be a parent — children of
    // it (fork/vfork) must set its childExited[] so its wait4() returns.
    if (parent >= 0 && parent < MAX_TASKS && parent != tid) {
        auto p = &g_tasks[parent];
        if (p.active) {
            p.childExited[tid]   = true;
            p.childExitCode[tid] = code;
            // The child's Linux pid snapshotted at entry (processLeaderTid is reset by the
            // cleanup above), so wait4 returns the same pid fork() gave the parent.
            g_childExitLinuxPid[tid] = exitLinuxPid;
            if (p.waiting && !g_futexWaitActive[parent] && !g_pollBlocked[parent]) {
                // Only a genuine wait4() waiter may be bare-unparked here.  A parent that
                // is futex-parked (or poll-parked) has a stale waitingForPid; unparking it
                // returns garbage RAX into the middle of its FUTEX_WAIT/poll.  Its
                // childExited[] flag (set above) still satisfies the eventual wait4().
                bool unblock = false;
                if (p.waitingForPid == -1) unblock = true;
                else if (p.waitingForPid == tid) unblock = true;
                if (unblock) p.waiting = false;
            }
            // Z1: if the parent installed a SIGCHLD handler (zsh does, and waits for jobs
            // via sigsuspend+SIGCHLD rather than a blocking waitpid), raise a pending
            // SIGCHLD so the run loop invokes that handler — which reaps the child and
            // lets sigsuspend return.  Tasks without a handler use the blocking-wait path
            // (childExited above) and never see this.
            // SIGCHLD delivery is driven from rt_sigsuspend (case 130), where zsh
            // temporarily unblocks SIGCHLD — not from here, since outside sigsuspend zsh
            // keeps SIGCHLD blocked (child_block) and would queue, not reap.  The
            // childExited[] flag set above is what sigsuspendTask polls; the waiting-clear
            // below wakes the parent so it re-runs sigsuspend and delivers.
        }
    }
    // Reclaim this task's private physical pages if it is the LAST user of its
    // address space.  Threads (CLONE_VM) share pml4Phys, so freeing while a
    // sibling is still alive would corrupt the shared space — in that case we
    // leak (safe).  Only `owned` regions (anonymous / private file maps) are
    // freed; device (g_fb) / shared (memfd) maps are left intact.
    if (t.pml4Phys != 0) {
        bool sharedAS = false;
        for (int i = 0; i < MAX_TASKS; i++) {
            if (i == tid) continue;
            if (g_tasks[i].active && !g_tasks[i].exited &&
                g_tasks[i].pml4Phys == t.pml4Phys) { sharedAS = true; break; }
        }
        if (!sharedAS) {
            x64WriteCR3(t.pml4Phys);
            for (int ri = 0; ri < t.regionCount; ri++) {
                auto r = &t.regions[ri];
                if (!r.owned) continue;
                for (ulong va = r.start; va < r.end; va += 4096) {
                    ulong phys = unmap_page_hhdm(va);
                    if (phys != 0) free_phys_page(phys);
                }
            }
        }
    }
    clearRegions(*t);
    objReleaseUntyped(tid);

    klog("[kernel] task "); klog_hex(tid); klog(" exited code="); klog_hex(code); klog("\n");
    scheduleNext();
}

// ------------------------------------------------------------------
// Fork
// ------------------------------------------------------------------

private int forkTask(int parentTid) {
    int childTid = allocTask();
    if (childTid < 0) {
        klog("[fork] no free task slot\n");
        return -12; // ENOMEM
    }

    auto parent = &g_tasks[parentTid];
    auto child  = &g_tasks[childTid];
    objEnsureProcess(parentTid);

    // Copy register state; child returns 0 from fork
    for (uint i = 0; i < NUM_REGS; i++)
        child.regs[i] = parent.regs[i];
    child.regs[REG_RAX] = 0;

    for (int i = 0; i < 512; i++)
        child.sseState[i] = parent.sseState[i];

    // Copy address space regions metadata
    child.regionCount = parent.regionCount;
    for (int i = 0; i < parent.regionCount; i++) {
        child.regions[i] = parent.regions[i];
        child.regions[i].objId = 0;
        child.regions[i].vmoRetained = false;
    }

    child.brkStart   = parent.brkStart;
    child.brkCurrent = parent.brkCurrent;
    child.mmapNext   = parent.mmapNext;
    child.parentId   = parentTid;
    child.userObjId  = parent.userObjId;
    child.identityObjId = parent.identityObjId; // IDENTITY_DOMAIN §3: inherit by default
    // DM3 CONTAINMENT: a forked child MUST stay inside its parent's namespace and domain.
    // Neither field was inherited here, and objEnsureNamespace() hands any task with no
    // namespace a fresh nsAlloc() whose default "/" binding grants ALL rights -- so a
    // domain-confined process escaped its own confinement just by calling fork(), and lost
    // its domainObjId (and with it the device/network gates) at the same time.
    child.domainObjId = parent.domainObjId;
    child.execMode    = parent.execMode;      // DM13: the ratchet is inherited, never reset
    if (parent.namespaceObjId != 0) {
        // Private clone, matching domainBindTaskNs: the child gets its own lifetime, and a
        // later rebind of the parent does not reach into it.
        child.namespaceObjId = nsClone(parent.namespaceObjId);
        if (child.namespaceObjId == 0 && parent.domainObjId != 0) {
            // Fail CLOSED: a confined parent must never produce an unconfined child.
            releaseTask(childTid);
            return -12;
        }
    }
    child.untypedObjId = untypedCreateProcess(parent.untypedObjId);
    if (child.untypedObjId == 0) {
        releaseTask(childTid);
        return -12;
    }

    // Allocate new PML4 and copy kernel mappings
    uint savedUntyped = physActiveUntyped();
    physSetActiveUntyped(child.untypedObjId);
    ulong childPml4 = alloc_phys_page();
    if (childPml4 == 0) {
        physSetActiveUntyped(savedUntyped);
        releaseTask(childTid);
        return -12;
    }
    child.pml4Phys = childPml4;
    archMapKernel(childPml4);

    // Copy-on-write the parent's user pages into the child (shares frames
    // read-only instead of duplicating them — see walkAndCopyUserPages). Must
    // run while parent's CR3 is active so HHDM accesses resolve.
    walkAndCopyUserPages(parent.pml4Phys, childPml4, child);
    physSetActiveUntyped(savedUntyped);
    // The walk demoted the parent's now-shared pages to read-only; flush its TLB
    // so stale writable entries can't bypass the CoW fault on the next write.
    x64WriteCR3(parent.pml4Phys);

    // Copy FS base
    d_store_task_fsbase(cast(ulong)childTid,
                        g_task_fsbase[parentTid]);
    child.active = true;

    // The child is a new process: give it its own fd table (id = childTid) with an
    // independent copy of the parent's descriptors, so each can close() its own
    // copies (POSIX fork semantics — required by libseat's embedded seatd).
    child.fdTabId = childTid;
    child.capTabId = childTid;
    fdtabForkCopy(parent.fdTabId, childTid);
    installTaskUntypedCap(childTid);
    objEnsureTask(childTid);
    objSetProcess(childTid, childTid, parent.processObjId);
    objCloneNamespace(childTid, parentTid); // Phase 9: child gets a private namespace clone

    // Track A A4: the child runs the same binary as the parent (CoW fork), so it
    // inherits /proc/self/exe resolution (busybox standalone re-execs it for applets).
    if (parentTid >= 0 && parentTid < MAX_TASKS && childTid >= 0 && childTid < MAX_TASKS) {
        g_taskExecModPhys[childTid] = g_taskExecModPhys[parentTid];
        g_taskExecModSize[childTid] = g_taskExecModSize[parentTid];
        g_taskExecName[childTid]    = g_taskExecName[parentTid];
        // NATIVE_OBJECT_ABI §3: the native personality is inherited across fork (native
        // helpers the shell spawns stay native; a Linux fork stays Linux).
        g_taskNativeAbi[childTid]   = g_taskNativeAbi[parentTid];
        g_taskNativeLaunch[childTid] = g_taskNativeLaunch[parentTid];   // L5.2: inherit the native-launch authorization
        // A4: a child inherits its parent's process group + signal dispositions.
        g_taskPgid[childTid]      = g_taskPgid[parentTid];
        g_taskSigCustom[childTid] = g_taskSigCustom[parentTid];
        g_taskPendingSig[childTid] = 0;
        g_sigHandler[childTid]  = g_sigHandler[parentTid];    // Z1: inherit signal handlers
        g_sigRestorer[childTid] = g_sigRestorer[parentTid];
    }

    klog("[fork] parent="); klog_hex(parentTid);
    klog(" child="); klog_hex(childTid); klog("\n");
    return childTid;
}

// ------------------------------------------------------------------
// clone (thread creation): CLONE_VM path — a new task sharing the caller's
// address space (page tables), used by pthread_create / std::thread.
// ------------------------------------------------------------------

// Linux clone() flag bits we care about.
enum : ulong {
    CLONE_VM             = 0x00000100,
    CLONE_FS             = 0x00000200,
    CLONE_FILES          = 0x00000400,
    CLONE_SIGHAND        = 0x00000800,
    CLONE_VFORK          = 0x00004000,
    CLONE_THREAD         = 0x00010000,
    CLONE_SETTLS         = 0x00080000,
    CLONE_PARENT_SETTID  = 0x00100000,
    CLONE_CHILD_CLEARTID = 0x00200000,
    CLONE_CHILD_SETTID   = 0x01000000,
}

// Per-thread CLONE_CHILD_CLEARTID address (user virtual). On thread exit the
// kernel writes 0 here so a joiner's futex wait observes termination.
__gshared ulong[MAX_TASKS] g_threadCleartidVirt;

// vfork: when a child is created with CLONE_VFORK, its parent is suspended until
// the child execve()s or exits.  g_vforkParentPlus1[child] = parentTid+1 records
// who to resume (0 = none).
__gshared int[MAX_TASKS] g_vforkParentPlus1;

// Resume a vfork parent suspended on `childTid` (called when the child execs or
// exits).  Clears the parent's `waiting` flag so the scheduler runs it again.
void resumeVforkParent(int childTid) {
    if (childTid < 0 || childTid >= MAX_TASKS) return;
    int p1 = g_vforkParentPlus1[childTid];
    if (p1 == 0) return;
    g_vforkParentPlus1[childTid] = 0;
    int p = p1 - 1;
    if (p >= 0 && p < MAX_TASKS)
        g_tasks[p].waiting = false;
}

// clone(flags, childStack, ptid, ctid, tls).  Returns the new tid, or a negative
// errno.  The child shares the parent's page tables (CLONE_VM); the caller-
// supplied stack and TLS are already mapped in that shared address space, so no
// page setup is needed here.
private int cloneThread(int parentTid, ulong flags, ulong childStack,
                        ulong ptidPtr, ulong ctidPtr, ulong tls) {
    int childTid = allocTask();
    if (childTid < 0) {
        klog("[clone] no free task slot\n");
        return -11; // EAGAIN (matches pthread_create's resource error)
    }

    auto parent = &g_tasks[parentTid];
    auto child  = &g_tasks[childTid];
    objEnsureProcess(parentTid);

    // Child resumes right after the `syscall` instruction with rax=0, on the
    // caller-provided stack.  The userspace __clone trampoline pops the thread
    // entry/arg from that stack and calls it.
    for (uint i = 0; i < NUM_REGS; i++)
        child.regs[i] = parent.regs[i];
    child.regs[REG_RAX] = 0;
    child.regs[REG_RSP] = childStack;
    child.regs[REG_RBP] = 0;

    for (int i = 0; i < 512; i++)
        child.sseState[i] = parent.sseState[i];

    // Share the address space: same PML4, same region view, same brk.
    child.pml4Phys   = parent.pml4Phys;
    child.regionCount = parent.regionCount;
    for (int i = 0; i < parent.regionCount; i++) {
        child.regions[i] = parent.regions[i];
        child.regions[i].objId = 0;
        child.regions[i].vmoRetained = false;
    }
    child.brkStart   = parent.brkStart;
    child.brkCurrent = parent.brkCurrent;
    child.parentId   = parentTid;

    // A thread shares its process's fd table (CLONE_FILES semantics): same
    // descriptors, opens/closes are visible to all threads of the process.
    child.fdTabId    = parent.fdTabId;
    child.capTabId   = parent.capTabId;
    child.untypedObjId = parent.untypedObjId;
    child.userObjId  = parent.userObjId;
    child.identityObjId = parent.identityObjId; // IDENTITY_DOMAIN §3: threads share the label
    // DM3 CONTAINMENT: a thread must carry the same domain label as its process.  Threads
    // already share the leader's namespace (objEnsureNamespace routes them to it), but
    // without this the device/network gates -- which read domainObjId -- stopped applying
    // the moment a confined process started a thread.
    child.domainObjId = parent.domainObjId;
    child.execMode    = parent.execMode;      // DM13: the ratchet is inherited, never reset
    g_taskNativeAbi[childTid] = g_taskNativeAbi[parentTid]; // NATIVE_OBJECT_ABI §3: same personality
    g_taskNativeLaunch[childTid] = g_taskNativeLaunch[parentTid];   // L5.2: inherit the native-launch authorization
    g_taskExecName[childTid]  = g_taskExecName[parentTid];

    // Threads share one address space but keep separate mmap bump pointers; give
    // each thread a disjoint 64 GiB window so concurrent mmap()s never collide.
    child.mmapNext   = parent.mmapNext + cast(ulong)childTid * 0x1000000000UL;

    // TLS (FS base): use the supplied tls for CLONE_SETTLS, else inherit.
    if (flags & CLONE_SETTLS)
        d_store_task_fsbase(cast(ulong)childTid, tls);
    else
        d_store_task_fsbase(cast(ulong)childTid, g_task_fsbase[parentTid]);

    // tid notifications — written through the shared (currently active) address
    // space, so direct user-pointer writes are valid here.
    int childLinuxTid = linuxTidForTask(childTid);
    if ((flags & CLONE_PARENT_SETTID) && ptidPtr != 0)
        *cast(int*)ptidPtr = childLinuxTid;
    if ((flags & CLONE_CHILD_SETTID) && ctidPtr != 0)
        *cast(int*)ctidPtr = childLinuxTid;
    if ((flags & CLONE_CHILD_CLEARTID) && ctidPtr != 0)
        g_threadCleartidVirt[childTid] = ctidPtr;
    else
        g_threadCleartidVirt[childTid] = 0;

    child.active = true;
    objEnsureTask(childTid);
    objSetProcess(childTid, parent.processLeaderTid, parent.processObjId);
    objEnsureNamespace(childTid); // Phase 9: thread shares the process namespace

    klog("[clone] parent="); klog_hex(parentTid);
    klog(" thread="); klog_hex(childTid);
    klog(" stack="); klog_hex(childStack); klog("\n");
    return childTid;
}

// ------------------------------------------------------------------
// execve: replace current task's address space with a new ELF
// ------------------------------------------------------------------

// execve environment snapshot — see the capture in execveTask. Kernel-resident
// (always mapped, survives the CR3 switch) so the new image's stack seeder can
// read the real env after the outgoing address space is gone.
private enum size_t EXEC_ENV_MAX     = 256;
private enum size_t EXEC_ENV_STR_CAP = 16384;
__gshared char[EXEC_ENV_STR_CAP]  g_execEnvStrings;
__gshared ulong[EXEC_ENV_MAX + 1] g_execEnvPtrs;
__gshared size_t g_execEnvCount;

// Track A A4: argv snapshot (mirror of the envp snapshot) so an exec'd program gets
// its REAL arguments, not just [execName].  busybox standalone's applet dispatch
// re-execs /proc/self/exe with argv[0]=<applet> — passing the real argv is what makes
// `cat`, `grep`, … run the right applet.
private enum size_t EXEC_ARG_MAX     = 128;
private enum size_t EXEC_ARG_STR_CAP = 8192;
__gshared char[EXEC_ARG_STR_CAP]  g_execArgStrings;
__gshared ulong[EXEC_ARG_MAX + 1] g_execArgPtrs;
__gshared size_t g_execArgCount;

// Track A A4: per-task loaded binary, so /proc/self/exe re-exec resolves to the
// task's own image (busybox), not the global /init.elf.  g_taskExecModPhys/Size live
// here; g_taskExecName moved to core.task so posix.d's /proc/<pid> can read the comm.
__gshared ulong[MAX_TASKS] g_taskExecModPhys;
__gshared ulong[MAX_TASKS] g_taskExecModSize;

private long execveTask(int tid, ulong pathPtr, ulong argvPtr, ulong envpPtr) {
    auto task = &g_tasks[tid];

    // Find the ELF binary in the boot modules by filename
    const(char)* path = cast(const(char)*)pathPtr;
    const(char)* execName = null;
    ulong modPhys = 0;
    ulong modSize = 0;

    // Track A A4: /proc/self/exe re-exec (busybox standalone applet dispatch) resolves
    // to THIS task's own loaded binary, recorded on its last successful exec.
    if (cstrEqK(path, "/proc/self/exe") && tid >= 0 && tid < MAX_TASKS &&
        g_taskExecModPhys[tid] != 0) {
        modPhys  = g_taskExecModPhys[tid];
        modSize  = g_taskExecModSize[tid];
        execName = g_taskExecName[tid];
    }

    // Track A A4: follow a leading RT-overlay symlink chain (e.g. /bin/cat -> /busybox)
    // so the boot-module scan below matches by the real binary's basename.
    char[512] _canonPath = void;
    if (modPhys == 0 && posixCanonExecPath(path, _canonPath.ptr, 512))
        path = _canonPath.ptr;
    const(char)* pathBase = cstrBasenameK(path);

    // Try boot module scan
    if (modPhys == 0 && g_mboot_modules !is null && g_module_count > 0) {
        auto recs = cast(ubyte*)g_mboot_modules;
        for (int i = 0; i < g_module_count; i++) {
            auto rec = cast(multiboot_module_t*)(recs + i * 128);
            // compare path to the tail of the module name
            const(char)* modName = cast(const(char)*)(cast(ubyte*)rec + 16); // name field at byte 16 (two ulong addrs)
            // basename of module name (part after last '/')
            const(char)* modBase = modName;
            for (const(char)* p = modName; *p != 0; p++)
                if (*p == '/') modBase = p + 1;
            if (cstrEqK(path, modBase) || cstrEqK(path, modName) || cstrEqK(pathBase, modBase)) {
                modPhys = cast(ulong)rec.mod_start;
                modSize = cast(ulong)rec.mod_end - cast(ulong)rec.mod_start;
                execName = modBase;
                break;
            }
        }
    }

    // F4.2: a persisted app object — /objects/apps/<app>/executable — launched from
    // the on-disk store, CAP-GATED on the app's declared rights ⊆ the launching
    // task's identity ceiling.  Grant → load the executable blob like a boot module;
    // exceed the ceiling → deny (EPERM) + audit.  (The original path is used here,
    // before posixCanonExecPath, since /objects/apps/... is not an RT symlink.)
    if (modPhys == 0) {
        const(char)* origPath = cast(const(char)*)pathPtr;
        int appIdx = objstoreResolveExecPath(origPath);
        if (appIdx >= 0) {
            uint declared = objstoreAppRights(appIdx);
            uint ceiling = 0;
            if (tid >= 0 && tid < MAX_TASKS) {
                auto idr = identityById(g_tasks[tid].identityObjId);
                if (idr !is null) ceiling = idr.rightsCeiling;
            }
            if ((declared & ~ceiling) != 0) {
                klog("[objstore] launch DENIED: "); klog(origPath);
                klog(" declared=0x"); klog_hex(declared);
                klog(" ceiling=0x"); klog_hex(ceiling); klog("\n");
                return -1; // EPERM — declared capabilities exceed the identity ceiling
            }
            ulong ep, es;
            if (objstoreLoadExec(appIdx, &ep, &es) && es > 0) {
                modPhys  = ep;
                modSize  = es;
                execName = "store-app".ptr;
                klog("[objstore] launch GRANTED: "); klog(origPath);
                klog(" rights=0x"); klog_hex(declared); klog("\n");
            }
        }
    }

    if (modPhys == 0) {
        klog("[exec] not found: ");
        klog(path);
        klog("\n");
        procFb("exec-ENOENT", cstrBasenameK(path));  // direct-fb: a missing binary on real HW
        return -2; // ENOENT
    }
    procFb("exec", execName !is null ? execName : pathBase);  // direct-fb: process launched

    // Track A A4: remember this task's binary so a later /proc/self/exe re-exec
    // (busybox standalone) resolves back to it.
    if (tid >= 0 && tid < MAX_TASKS) {
        g_taskExecModPhys[tid] = modPhys;
        g_taskExecModSize[tid] = modSize;
        g_taskExecName[tid]    = execName;
        // NATIVE_OBJECT_ABI §3 / Z4a.5: enter the native personality iff this is the
        // trusted /hos-sh image, OR a native-shell launch of zsh — requested via /hos-zsh,
        // a symlink to the shared zsh boot module (the *request path* marks it native, the
        // same activation model as /hos-sh; the image is shared, no duplication).  Any
        // other exec leaves the personality (the native shell can't launch a Linux tool
        // INTO the native object ABI).  fork/clone inherit the flag below.
        const(char)* origBase = cstrBasenameK(cast(const(char)*)pathPtr);
        // Z12.1 hardening: the native flag must require the TRUSTED *image*, not merely the
        // request basename — otherwise a user-created symlink (/tmp/hos-zsh -> /busybox) would
        // smuggle an arbitrary boot module onto the native object ABI (origBase=="hos-zsh").
        // /hos-zsh canonicalises to the /zsh boot module (execName=="zsh"); origBase only
        // distinguishes the native launch (/hos-zsh) from the Linux one (/bin/zsh), both /zsh.
        // /hos-sh is its own trusted image.  So: native iff a trusted image AND, for zsh, the
        // hos-zsh request path.  A spoofed /tmp/hos-zsh -> /busybox has execName=="busybox" -> denied.
        const bool trustedNativeImage =
            (execName !is null && cstrEqK(execName, "hos-sh")) ||
            (execName !is null && cstrEqK(execName, "zsh") &&
             origBase !is null && cstrEqK(origBase, "hos-zsh"));
        // L5.2 — confine the Linux shell: a trusted native image enters the native personality only
        // when the caller is ALREADY native OR holds the native-launch authorization.  That
        // authorization rides the trusted desktop/terminal chain (default true, inherited on fork)
        // and is DROPPED on the Linux-shell exec just below — so a Linux-personality shell, and
        // everything it spawns, can never reach the native object ABI even by exec'ing /hos-sh.
        const bool wasNative = g_taskNativeAbi[tid];
        g_taskNativeAbi[tid] = trustedNativeImage && (wasNative || g_taskNativeLaunch[tid]);
        // Exec'ing the Linux interactive shell (/bin/zsh: execName "zsh", NOT the /hos-zsh request
        // path) drops the authorization; a re-run /wl-term from that shell inherits the cleared flag.
        if (execName !is null && cstrEqK(execName, "zsh") &&
            !(origBase !is null && cstrEqK(origBase, "hos-zsh")))
            g_taskNativeLaunch[tid] = false;
        // A4: execve resets caught/ignored signals to the default disposition (POSIX),
        // so a freshly exec'd foreground command (cat/grep) is interruptible by ^C.
        g_taskSigCustom[tid]   = 0;
        g_taskPendingSig[tid]  = 0;
        g_sigHandler[tid][] = 0; g_sigRestorer[tid][] = 0;   // Z1: exec resets handlers to default
        itimerClear(tid);   // POSIX: execve disarms ITIMER_REAL, so a recycled slot cannot
                            // inherit a stale alarm and SIGALRM an unrelated program.
    }

    // Track A A4: snapshot the caller's argv (mirror of the envp snapshot below) so the
    // new image gets its real arguments + argv[0].  For busybox, argv[0] is the applet
    // name (e.g. "cat"), which is how it dispatches the right applet after re-exec.
    g_execArgCount = 0;
    {
        size_t strOff = 0;
        if (argvPtr != 0) {
            auto argArr = cast(const(ulong)*)argvPtr;
            for (size_t i = 0; i < EXEC_ARG_MAX && argArr[i] != 0; ++i) {
                auto s = cast(const(char)*)argArr[i];
                if (s is null) continue;
                size_t len = 0;
                while (s[len] != 0 && len < 4095) ++len;
                if (strOff + len + 1 >= EXEC_ARG_STR_CAP) break;
                foreach (j; 0 .. len) g_execArgStrings[strOff + j] = s[j];
                g_execArgStrings[strOff + len] = 0;
                g_execArgPtrs[g_execArgCount++] = cast(ulong)&g_execArgStrings[strOff];
                strOff += len + 1;
            }
        }
        g_execArgPtrs[g_execArgCount] = 0;   // NULL terminator
    }

    // Snapshot the caller's envp into kernel buffers WHILE the outgoing address
    // space is still active (its user pages are unmapped just below, and the CR3
    // switch a few lines later makes the user pointers unreadable). The stack
    // seeder then propagates the REAL environment to the new image instead of the
    // kernel's fixed default — this is what carries Weston's WAYLAND_SOCKET=<fd>
    // to its spawned clients, so the privileged desktop-shell rebinds the trusted
    // wl_client connection instead of being denied. (envp==0 → keep fixed env.)
    g_execEnvCount = 0;
    {
        size_t strOff = 0;
        if (envpPtr != 0) {
            auto envArr = cast(const(ulong)*)envpPtr;
            for (size_t i = 0; i < EXEC_ENV_MAX && envArr[i] != 0; ++i) {
                auto s = cast(const(char)*)envArr[i];
                if (s is null) continue;
                size_t len = 0;
                while (s[len] != 0 && len < 4095) ++len;
                if (strOff + len + 1 >= EXEC_ENV_STR_CAP) break;
                foreach (j; 0 .. len) g_execEnvStrings[strOff + j] = s[j];
                g_execEnvStrings[strOff + len] = 0;
                g_execEnvPtrs[g_execEnvCount++] = cast(ulong)&g_execEnvStrings[strOff];
                strOff += len + 1;
            }
        }
        g_execEnvPtrs[g_execEnvCount] = 0;   // NULL terminator
    }

    // Release the outgoing address space's private pages before installing a
    // fresh one (old CR3 is still active, so unmap_page_hhdm operates on it).
    // A freshly forked child reaches execve sharing all of its parent's pages
    // copy-on-write; dropping those references here returns the parent's frames
    // to exclusive ownership (no needless CoW copies later) and reclaims any
    // truly private pages instead of leaking them.  Shared (device/memfd) maps
    // are left intact.  Page-table pages and the old PML4 are left mapped (a
    // small, pre-existing leak) since CR3 still points at them until the switch.
    for (int ri = 0; ri < task.regionCount; ri++) {
        auto r = &task.regions[ri];
        if (!r.owned) continue;
        for (ulong va = r.start; va < r.end; va += 4096) {
            ulong phys = unmap_page_hhdm(va);
            if (phys != 0) free_phys_page(phys);
        }
    }

    // Switch to a fresh page table
    ulong newPml4 = alloc_phys_page();
    if (newPml4 == 0) return -12;
    archMapKernel(newPml4);
    x64WriteCR3(newPml4);

    task.pml4Phys    = newPml4;
    clearRegions(*task);
    task.brkStart    = 0;
    task.brkCurrent  = 0;
    task.mmapNext    = 0x740000000000UL;

    ulong elfVirt = phys_to_virt(modPhys);
    ushort elfType = *cast(ushort*)(elfVirt + 16);
    ulong mainBias = (elfType == ET_DYN) ? USER_MAIN_PIE_BASE : 0;
    char[256] interpPath;
    linuxNoteElfLoad(); // Phase 12: LinuxELFLoaderObject sees the execve load
    auto res = loadElf(*task, elfVirt, modPhys, mainBias,
                       interpPath.ptr, interpPath.length);
    if (!res.ok) {
        klog("[exec] loadElf failed\n");
        return -8; // ENOEXEC
    }

    // Set brk base to top of ELF image
    task.brkStart   = res.topVirt;
    task.brkCurrent = res.topVirt;

    ulong entryRip = res.entry;
    ulong atBase = 0;
    if (res.hasInterp) {
        klog("[exec] PT_INTERP="); klog(interpPath.ptr); klog("\n");
        ulong ipPhys = 0, ipSize = 0;
        if (!findInterpModule(interpPath.ptr, ipPhys, ipSize)) {
            klog("[exec] interp module NOT FOUND\n");
            return -2;
        }
        ulong ipVirt = phys_to_virt(ipPhys);
        auto ires = loadElf(*task, ipVirt, ipPhys, USER_INTERP_BASE, null, 0);
        if (!ires.ok) {
            klog("[exec] interp load FAILED\n");
            return -8;
        }
        entryRip = ires.entry;
        atBase = USER_INTERP_BASE;
        klog("[exec] interp loaded base="); klog_hex(USER_INTERP_BASE);
        klog(" entry="); klog_hex(entryRip); klog("\n");
    }

    // Allocate user stack (256 pages = 1 MB).  Z8: zsh's completion system recurses deep
    // (_main_complete -> _complete -> _normal -> _dispatch -> _<cmd> -> _arguments -> _files …)
    // and the 128 KB stack overflowed mid-completion (esp. inside a forked $() subshell),
    // faulting below the stack region; 1 MB gives the interpreter ample headroom.
    enum stackPages = 256;
    ulong stackPhys = alloc_phys_pages(stackPages);
    if (stackPhys == 0) return -12;
    ulong stackSize = stackPages * 4096;
    ulong stackBase = 0x700000000000UL;
    ulong stackTop  = stackBase + stackSize;

    for (ulong pg = 0; pg < stackPages; pg++)
        map_page_hhdm(stackPhys + pg * 4096, stackBase + pg * 4096,
                      PTE_PRESENT | PTE_RW | PTE_USER, &alloc_phys_page);

    auto stackRegion = addRegion(*task, stackBase, stackTop, RegionType.Mapped,
                                 RegionPerms.ReadWrite, stackPhys, true);
    if (stackRegion !is null)
        physPagesSetOwner(stackPhys, stackPages, stackRegion.objId, stackRegion.vmoObjId);

    // Seed a Linux-style process stack using auxv from the loaded ELF. argv[0] is
    // the matched boot-module basename (execfn). The environment is the caller's
    // real env, snapshotted above into g_execEnvPtrs/Strings (kernel memory, valid
    // after the CR3 switch); fall back to the kernel's fixed GUI env only when the
    // caller passed no envp (e.g. kernel-internal exec).
    ulong[7] infoWords = [
        res.entry,
        res.phdrVaddr,
        cast(ulong)res.phEnt,
        cast(ulong)res.phNum,
        atBase,
        mainBias,
        cast(ulong)execName
    ];
    // Track A A4: pass the caller's real argv (snapshotted above) so the new image
    // gets its arguments + the right argv[0]; fall back to execfn-as-argv[0] only for
    // kernel-internal execs that supply no argv (e.g. /idle).
    ulong rsp;
    if (g_execArgCount > 0 || g_execEnvCount > 0) {
        rsp = linux_seed_initial_stack_with_args(
            stackPhys, stackSize, stackBase, infoWords.ptr, 4096,
            (g_execArgCount > 0) ? cast(ulong)&g_execArgPtrs[0] : 0,
            (g_execEnvCount > 0) ? cast(ulong)&g_execEnvPtrs[0] : 0);
    } else {
        rsp = linux_seed_initial_stack(
            stackPhys, stackSize, stackBase, infoWords.ptr, 4096);
    }

    // The legacy freestanding C probes were compiled with GCC treating _start
    // like a regular function.  Keep their old call-like stack alignment while
    // giving libc-linked programs the normal process-entry stack.
    if (isFreestandingExecName(execName) && (rsp & 0xF) == 0) rsp -= 8;

    klog("[exec] entry="); klog_hex(entryRip);
    klog(" rsp="); klog_hex(rsp); klog("\n");

    // Reset registers
    for (uint r = 0; r < NUM_REGS; r++) task.regs[r] = 0;
    task.regs[REG_RIP]    = entryRip;
    task.regs[REG_RSP]    = rsp;
    task.regs[REG_RFLAGS] = 0x202;

    // Clear FS base
    d_store_task_fsbase(cast(ulong)tid, 0);
    objEnsureTask(tid);
    if (task.processLeaderTid != tid)
        objSetProcess(tid, tid, task.parentObjId);
    else
        objEnsureProcess(tid);

    // vfork semantics: a successful execve releases the suspended parent (the
    // child now has its own fresh address space, no longer sharing the parent's).
    resumeVforkParent(tid);

    return 0;
}

// GUI roadmap clients: launch Wayland clients once Hyprland has a listener. Each
// client is a boot module, reusing the existing task/exec machinery. Best-effort
// and isolated: failure logs and leaves desktop boot untouched.
private bool spawnWaylandProgram(const(char)* prog, const(char)* tag) {
    int t = allocTask();
    if (t <= 0) {
        klog(tag); klog(" no free task slot for "); klog(prog); klog("\n");
        return false;
    }
    g_tasks[t].parentId         = 0;
    g_tasks[t].processLeaderTid = t;
    g_tasks[t].userObjId        = g_tasks[0].userObjId;
    g_tasks[t].untypedObjId     = untypedCreateProcess(0);
    if (g_tasks[t].untypedObjId == 0) {
        klog(tag); klog(" no untyped budget for "); klog(prog); klog("\n");
        releaseTask(t);
        return false;
    }
    g_tasks[t].namespaceObjId   = nsClone(g_tasks[0].namespaceObjId);
    capTableClear(g_tasks[t].capTabId);
    installTaskUntypedCap(t);
    fdtabSetupConsoleStdio(g_tasks[t].fdTabId);

    ulong savedCr3 = x64ReadCR3();
    uint savedUntyped = physActiveUntyped();
    physSetActiveUntyped(g_tasks[t].untypedObjId);
    long r = execveTask(t, cast(ulong)prog, 0, 0);
    physSetActiveUntyped(savedUntyped);
    x64WriteCR3(savedCr3);
    if (r != 0) {
        klog(tag); klog(" "); klog(prog); klog(" spawn failed\n");
        releaseTask(t);
        return false;
    }
    klog(tag); klog(" "); klog(prog); klog(" launched as task ");
    klog_hex(cast(ulong)t); klog("\n");
    g_current_task_id = cast(ulong)t;
    return true;
}

// DOMAIN_MANAGER DM3: launch a program CONFINED TO A DOMAIN.
//
// Registered as core.domain's spawn hook at boot, so `spawn <domain> <program>` written to
// /config/domain.action lands here.  Until this existed, domainEnterTask()/domainBindTaskNs()
// had no caller but a self-test: no live task carried a domainObjId, so the namespace
// confinement in namespaceCheckOpen() and the per-domain device/network gates were all
// evaluated against nothing.  This is what makes the domain policy real.
//
// ORDERING, deliberate: the binary is exec'd FIRST (resolved through task 0's namespace) and
// the domain namespace is bound immediately AFTER, before the task is ever scheduled.  So a
// domain can run a program it could not itself open -- the template provides the binary, the
// domain confines what the running process can reach.  Binding before exec would instead
// require every domain to expose its own /wl-term etc., which is not how the templates are
// built.  The child's console stdio is already open by then and deliberately survives, so a
// confined program can still print.
private extern(C) bool domainSpawnProgram(uint domObjId, const(char)* prog) {
    // domainBindTaskNs lives in core.task (NOT core.domain, despite the name), which this
    // module already imports wholesale at the top.
    if (domObjId == 0 || prog is null) return false;

    int t = allocTask();
    if (t <= 0) { klog("[domain] spawn: no free task slot\n"); return false; }

    g_tasks[t].parentId         = 0;
    g_tasks[t].processLeaderTid = t;
    g_tasks[t].userObjId        = g_tasks[0].userObjId;
    g_tasks[t].untypedObjId     = untypedCreateProcess(0);
    if (g_tasks[t].untypedObjId == 0) {
        klog("[domain] spawn: no untyped budget\n");
        releaseTask(t);
        return false;
    }
    g_tasks[t].namespaceObjId   = nsClone(g_tasks[0].namespaceObjId);
    capTableClear(g_tasks[t].capTabId);
    installTaskUntypedCap(t);
    fdtabSetupConsoleStdio(g_tasks[t].fdTabId);

    // Stage EPIN_DOMAIN / EPIN_SHELL for the seeder (see g_spawnEnvDomain in exports.d).
    // execveTask() takes envp=0, so without this a confined program got only the fixed boot
    // environment and the domain's shell selection was silently ignored -- picking "native"
    // in the Domain Manager did nothing at all.  The shell follows the domain's own mode:
    // DISTRO_NATIVE means the native personality, anything else is a Linux one.
    {
        import core.domain : domainById, domainDistro, DISTRO_NATIVE;
        import core.exports : g_spawnEnvDomain, g_spawnEnvShell;
        auto dr = domainById(domObjId);
        size_t p = 0;
        immutable string kd = "EPIN_DOMAIN=";
        foreach (c; kd) g_spawnEnvDomain[p++] = c;
        if (dr !is null)
            foreach (i; 0 .. dr.nameLen)
                if (p < g_spawnEnvDomain.length - 1) g_spawnEnvDomain[p++] = dr.name[i];
        g_spawnEnvDomain[p] = 0;

        immutable string ks = "EPIN_SHELL=";
        immutable string vn = "native";
        immutable string vl = "linux";
        p = 0;
        foreach (c; ks) g_spawnEnvShell[p++] = c;
        if (domainDistro(domObjId) == DISTRO_NATIVE) { foreach (c; vn) g_spawnEnvShell[p++] = c; }
        else                                         { foreach (c; vl) g_spawnEnvShell[p++] = c; }
        g_spawnEnvShell[p] = 0;
    }

    ulong savedCr3 = x64ReadCR3();
    uint savedUntyped = physActiveUntyped();
    physSetActiveUntyped(g_tasks[t].untypedObjId);
    long r = execveTask(t, cast(ulong)prog, 0, 0);
    physSetActiveUntyped(savedUntyped);
    x64WriteCR3(savedCr3);
    if (r != 0) {
        klog("[domain] spawn: exec failed for "); klog(prog); klog("\n");
        import core.exports : g_spawnEnvDomain, g_spawnEnvShell;
        g_spawnEnvDomain[0] = 0; g_spawnEnvShell[0] = 0;   // exec never consumed them
        releaseTask(t);
        return false;
    }

    // Confine it: private clone of the domain's restricted namespace + the domain's identity
    // + domainObjId.  From here its absolute opens run the namespaceCheckOpen gauntlet and its
    // device/network access is the domain's mask.
    if (domainBindTaskNs(t, domObjId) == 0) {
        klog("[domain] spawn: bind FAILED (domain has no namespace) -- killing task\n");
        releaseTask(t);
        return false;
    }

    // DM13: the confined task starts in its domain's mode.  A native domain starts native
    // (execMode is already 0 from allocTask); a Linux-flavoured one starts already dropped,
    // which is a legal native->linux transition and therefore never trips the ratchet.
    {
        import core.domain : domainDistro, DISTRO_NATIVE;
        import core.task : taskSetExecMode, EXECMODE_LINUX;
        if (domainDistro(domObjId) != DISTRO_NATIVE)
            taskSetExecMode(t, EXECMODE_LINUX);
    }

    klog("[domain] spawn: "); klog(prog); klog(" confined in domain ");
    klog_hex(cast(ulong)domObjId); klog(" as task "); klog_hex(cast(ulong)t); klog("\n");
    return true;
}

// DM13 bridge: core.domain cannot import core.task (core.task already imports core.domain),
// so "mode self <native|linux>" routes through here.  Applies to the CALLING task.
private extern(C) bool domainModeSelf(int linuxMode) {
    import core.task : taskSetExecMode, EXECMODE_NATIVE, EXECMODE_LINUX;
    return taskSetExecMode(cast(int)g_current_task_id,
                           linuxMode != 0 ? EXECMODE_LINUX : EXECMODE_NATIVE);
}

// Spawn the idle task (/idle boot module) once.  Like spawnWaylandProgram but does
// NOT make it current (the scheduler only runs it as a last resort) and records its
// tid in g_idleTid.
private void maybeSpawnIdle() {
    if (g_idleTid >= 0) return;                  // already spawned
    int t = allocTask();
    if (t <= 0) return;
    g_tasks[t].parentId         = 0;
    g_tasks[t].processLeaderTid = t;
    g_tasks[t].userObjId        = g_tasks[0].userObjId;
    g_tasks[t].untypedObjId     = untypedCreateProcess(0);
    if (g_tasks[t].untypedObjId == 0) { releaseTask(t); return; }
    g_tasks[t].namespaceObjId   = nsClone(g_tasks[0].namespaceObjId);
    capTableClear(g_tasks[t].capTabId);
    installTaskUntypedCap(t);
    fdtabSetupConsoleStdio(g_tasks[t].fdTabId);

    ulong savedCr3 = x64ReadCR3();
    uint savedUntyped = physActiveUntyped();
    ulong savedCur = g_current_task_id;          // execveTask/our setup must not steal `current`
    physSetActiveUntyped(g_tasks[t].untypedObjId);
    long r = execveTask(t, cast(ulong)"/idle\0".ptr, 0, 0);
    physSetActiveUntyped(savedUntyped);
    x64WriteCR3(savedCr3);
    g_current_task_id = savedCur;
    if (r != 0) { releaseTask(t); return; }
    g_idleTid = t;
    klog("[idle] idle task spawned as tid "); klog_hex(cast(ulong)t); klog("\n");
}

private void spawnWaylandClients() {
    const int mode = guiAutostartMode();
    if (mode == 0) {
        klog("[gui] autostart disabled by display.conf\n");
        return;
    }
    if (mode == 1 || mode == 3)
        spawnWaylandProgram("wl-term\0".ptr, "[g4]\0".ptr);
    if (mode == 2 || mode == 3) {
        // GNOME-style top bar (wlr-layer-shell).  Hyprland's own exec-once=/wl-layer-bar in the
        // synthesized config never actually spawns, so launch it here via the proven kernel autostart.
        // Safe on Weston too: wl-layer-bar exits cleanly (returns 1) when no zwlr_layer_shell is offered.
        spawnWaylandProgram("wl-layer-bar\0".ptr, "[bar]\0".ptr);
        // Domain Manager, present on the desktop at boot.  Hyprland ONLY -- this whole
        // autostart is gated on g_guiClientAutostartEnabled = initIsHyprland, and Weston
        // keeps taking its list from /desktop.conf (where `autostart = /wl-domain-manager`
        // is deliberately commented out; there it is SUPER+D only).
        //
        // Moved here from custom/execs.lua's hl.exec_cmd("/wl-domain-manager").  That did
        // work -- it came up as tid 6 and spoke real Wayland -- but it fired on
        // hyprland.start, i.e. BEFORE the compositor had settled, and logged nothing, so
        // the only way to answer "is the domain manager running?" was to grep trace lines
        // for a tid name.  This path waits for /run/user/1000/wayland-0 plus
        // GUI_CLIENT_SETTLE_TICKS, and prints the tid like every other client.
        // ...but NOT on live media, where the installer is meant to be the only window.  The
        // bar above is a layer surface and covers nothing, so it stays; these are real windows
        // and would sit on top of the installer.  Both remain on their keybindings (SUPER+D for
        // the domain manager), so this hides them at boot rather than removing them.
        {
            import drivers.veracrypt_impl : bootHasInstallPayload;
            if (!bootHasInstallPayload()) {
                spawnWaylandProgram("wl-domain-manager\0".ptr, "[dm]\0".ptr);
                spawnWaylandProgram("wl-cairo-demo\0".ptr, "[g11]\0".ptr);
            }
        }
    }
    if (mode == 4)
        spawnWaylandProgram("wl-files\0".ptr, "[g17]\0".ptr);

    // /desktop.conf autostart — the Hyprland path now honours it.
    //
    // The file declares `autostart = X` and `autostart-live = X`, but its ONLY parser in the
    // tree was Weston's desktop shell (deps/weston-14.0.0/desktop-shell/shell.c), which does
    // not run under Hyprland.  So the file was dead configuration on this path: it looked like
    // it configured the running desktop and did not -- which is why the installer never popped
    // up, and why `autostart = /wl-overview` / `/wl-logview` did nothing either.
    //
    // `-live` entries run only on live install media, matching the file's own statement that
    // they are "LIVE-MEDIA ONLY ... and SKIPS them once it is [installed]".  The test is
    // bootHasInstallPayload(), the same one kernel_main.d:4556 uses to skip disk-writing boot
    // proofs; an installed system boots without the esp-image module.
    //
    // Ordered after the built-ins so an autostart maps above the bar, and `-live` last so the
    // installer is the front window (D4.1).  `bind =` is deliberately NOT handled: the kernel
    // cannot install compositor keybindings, and Hyprland binds the same apps itself in
    // system/hypr/custom/keybinds.lua.
    // ON LIVE MEDIA THE INSTALLER IS THE ONLY WINDOW.
    //
    // Both lists used to run on install media, so the installer opened behind the Activities
    // grid, the log viewer and the domain manager -- the first thing a new user saw was three
    // windows they did not ask for, with the one that matters buried underneath.
    //
    // Live media has exactly one job.  So `-live` entries run INSTEAD of the ordinary autostart
    // list there, not in addition to it, and the desktop's own built-in windows are skipped too.
    // The top bar stays: it is a layer surface rather than a window, it does not cover anything,
    // and it is where the clock and status live.
    //
    // Nothing is lost, because every one of those apps still has its keybinding from
    // /desktop.conf (SUPER+A activities, SUPER+D domains, SUPER+ALT+L logs, and the rest) --
    // they are one keystroke away rather than in the way.
    {
        import core.syscalls.posix : desktopAutostartAt;
        import drivers.veracrypt_impl : bootHasInstallPayload;
        enum int AUTOSTART_MAX = 16;         // bounded: a malformed conf must not spawn forever
        char[128] abuf;
        const bool liveMedia = bootHasInstallPayload();

        if (!liveMedia) {
            for (int i = 0; i < AUTOSTART_MAX; i++) {
                if (!desktopAutostartAt(false, i, abuf.ptr, abuf.length)) break;
                spawnWaylandProgram(abuf.ptr, "[auto]\0".ptr);
            }
        } else {
            klog("[gui] live media — installer only; everything else is on its keybinding\n");
            for (int i = 0; i < AUTOSTART_MAX; i++) {
                if (!desktopAutostartAt(true, i, abuf.ptr, abuf.length)) break;
                spawnWaylandProgram(abuf.ptr, "[inst]\0".ptr);
            }
        }
    }
}

private void maybeSpawnWaylandClient() {
    if (!g_guiClientAutostartEnabled || g_guiClientStarted) return;
    if (!unixSocketListenerReady("/run/user/1000/wayland-0\0".ptr)) return;

    ulong now = get_ticks();
    if (!g_guiClientListenerSeen) {
        g_guiClientListenerSeen = true;
        g_guiClientLaunchTick = now + GUI_CLIENT_SETTLE_TICKS;
        klog("[g2] wayland listener ready; waiting for compositor settle\n");
        return;
    }
    if (now < g_guiClientLaunchTick) return;

    g_guiClientStarted = true;
    klog("[g11] wayland listener ready; launching GUI clients\n");
    spawnWaylandClients();
}

// R2.4a — when the virtio-gpu-gl device is present (the headless GPU-test config;
// g_gpuVirgl is false on the normal desktop device set), launch the userspace
// drm-gpu-test once, after a brief settle.  It drives /dev/dri/renderD128 through
// the virtgpu DRM ioctls to clear a texture RED and prints PASS/FAIL to serial.
private __gshared bool g_gpuTestStarted = false;
private __gshared int  g_gpuTestDelay   = 0;
private void maybeSpawnGpuTest() {
    if (g_gpuTestStarted) return;
    import drivers.graphics.virtio_gpu : g_gpuVirgl;
    if (!g_gpuVirgl) return;
    if (g_gpuTestDelay++ < 20) return;   // let early boot settle before the first exec
    g_gpuTestStarted = true;
    klog("[r24] virtio-gpu-gl present; launching drm-gpu-test\n");
    spawnWaylandProgram("drm-gpu-test\0".ptr, "[r24]\0".ptr);
}

// R2.4b-step4 — after drm-gpu-test has run (longer delay avoids racing the shared GPU control
// queue), launch drm-gl-test: a real GLES2 program that renders through Mesa's virgl driver + the
// render node.  Dynamic musl (dlopens virtio_gpu_dri.so), so NOT in isFreestandingExecName.
private __gshared bool g_glTestStarted = false;
private __gshared int  g_glTestDelay   = 0;

// L2: boot LKL (the Linux kernel as a library) once, a little after startup, output to serial.
private __gshared bool g_lklTestStarted = false;
private __gshared int  g_lklTestDelay   = 0;
private void maybeSpawnLklTest() {
    if (g_lklTestStarted) return;
    if (g_lklTestDelay++ < 80) return;   // settle: let PCI fully enumerate before touching the
                                         // device.  (Polling findDeviceByClass from reconcile 1 hung
                                         // the whole boot on real HW — reverted to this known-good delay.)
    g_lklTestStarted = true;             // one-shot, whether or not we actually launch
    // SINGLE-LKL MULTI-DEVICE: the LKL kernel now drives SEVERAL PCI devices in ONE instance (each on its
    // own PCI bus — see arch/lkl/drivers/pci.c), so we spawn ONE lkl-boot and grant it EVERY driveable
    // device.  This replaces the earlier "one LKL per device" scheme, which ran two full embedded-Linux
    // instances on the single core and saturated it (black desktop, frozen cursor on the FW13).  One
    // kernel/scheduler/memory footprint drives the AX210 WiFi + the xHCI USB together.  Deny-by-default
    // is preserved: an allowlist of classes, never "all devices" — WiFi (0x0280) + xHCI USB (0x0c03),
    // skipping EpinOS's own virtio (0x1AF4).  WiFi is collected FIRST so the AX210 is bus 0 (unchanged
    // MSI path) and its net-provider comes up before hos-netlaunch waits on it.
    import drivers.pci : scanPCIDevices;
    auto devs = scanPCIDevices();
    // AX210 RF/FSEQ "-110" fix: the LKL enumerates the WiFi card as a parent-less root device, so its
    // pci_disable_link_state() is a no-op and iwlwifi can't turn ASPM off — ASPM L1 during the RF
    // power-up corrupts the FSEQ sequencer (FSEQ_ERROR_CODE=0x2.., "Failed to run INIT ucode -110").
    // We own the real PCIe links, so disable ASPM on every link BEFORE granting the card to the LKL.
    import drivers.pci : pciDisableAspmAll;
    pciDisableAspmAll();
    uint[MAX_TASK_DEVS] grantBdf; int ngrant = 0;
    // STABILITY RETREAT (FW13): pass 1 (grant the xHCI so usb-storage can capture the log to a USB stick)
    // is DISABLED — driving usb-storage on the FW13's real xHCI hard-freezes the machine (dead cursor).
    // A tighter serial-spin fix did NOT cure it, which points at usb-storage's bulk/scatter-gather DMA
    // through the no-IOMMU path corrupting kernel memory.  The USB keyboard path (usbhid, tiny DMA) was
    // fine, but bulk mass-storage is not.  So grant ONLY the AX210 (WiFi, bus 0) — the known-good config.
    // The FW13's built-in keyboard/trackpad use the NATIVE PS/2 path, so no input is lost.  The log-USB
    // capture is abandoned on this hardware; the scan-load freeze will be captured another way instead.
    // DECOY_DISTRO US0: pass 0 = WiFi (always); pass 1 = xHCI (USB) ONLY when /epin-usb.conf is
    // staged — driving usb-storage bulk DMA hard-freezes the FW13's no-IOMMU path (see below), so
    // USB is opt-in for QEMU dev boots + the decoy-install path (US5 must fix the freeze first).
    const int NPASS_STABLE = debugUsbBootPresent() ? 2 : 1;
    for (int pass = 0; pass < NPASS_STABLE && ngrant < MAX_TASK_DEVS; pass++) {
        const uint wantCls = (pass == 0) ? 0x0280 : 0x0c03; // pass 0 = WiFi (bus 0), pass 1 = xHCI(s)
        foreach (ref d; devs) {
            if (ngrant >= MAX_TASK_DEVS) break;
            if (d.vendorId == 0x1AF4) continue;             // never hand EpinOS's own virtio devices to the LKL
            if (((cast(uint)d.classCode << 8) | d.subClass) != wantCls) continue;
            grantBdf[ngrant++] = (cast(uint)d.bus << 16) | (cast(uint)d.slot << 8) | d.func;
        }
    }
    if (debugUsbBootPresent())
        klog("[lkl] USB enabled (/epin-usb.conf present) — granting xHCI for usb-storage\n");
    // QEMU log-egress path: grant a VIRTIO-NET NIC (class 0x0200, vendor 0x1AF4) to the LKL so
    // its TCP stack has a real route for the scp uploader.  No-op on the FW13 (no virtio
    // devices) and on default QEMU boots (-nic none): the device only exists when explicitly
    // attached.
    //
    // ONLY when the native stack did NOT claim it.  The comment that used to sit here asserted
    // virtio-net was exempt from the vendor-0x1AF4 skip above "because EpinOS never drives one
    // natively (its own stack uses e1000)".  That stopped being true when
    // drivers/network/virtio_net.d landed.  Handing the same BDF to both drivers makes each one
    // reset the device and reprogram the other's virtqueues out from under it: LKL's TX then
    // wedges ("NETDEV WATCHDOG: transmit queue 0 timed out"), and its ~40 worker threads spin on
    // futexes forever (>22k wakes from one thread in 90s), starving weston so the desktop never
    // comes up.  The native driver owns the NIC; LKL's scp egress is what we give up.
    import drivers.network.virtio_net : virtioNetReady;
    if (virtioNetReady()) {
        klog("[lkl] virtio-net claimed by native driver -> NOT granting to LKL\n");
    } else {
        foreach (ref d; devs) {
            if (ngrant >= MAX_TASK_DEVS) break;
            if (d.vendorId != 0x1AF4) continue;
            if (((cast(uint)d.classCode << 8) | d.subClass) != 0x0200) continue;
            grantBdf[ngrant++] = (cast(uint)d.bus << 16) | (cast(uint)d.slot << 8) | d.func;
            klog("[lkl] virtio-net granted for scp egress\n");
        }
    }
    if (ngrant == 0) {
        // Fallback demo (no WiFi + no xHCI): a GPU/NVMe if present (opt-in LKL_GPU=1 / LKL_NVME=1 in QEMU).
        uint fb = findDeviceByClass(0x0380);
        if (fb == 0xFFFFFFFF) {
            // NEVER steal the NVMe the native disk layer owns (install target / object
            // store): LKL's nvme driver resets the controller, killing the native
            // driver's queues -> every disk write times out -> installer FAIL (gpt).
            import drivers.block.disk : diskIsNvme;
            if (!diskIsNvme()) fb = findDeviceByClass(0x0108);
        }
        if (fb == 0xFFFFFFFF) {
            klog("[lkl] no driveable PCI device (WiFi/xHCI/GPU/NVMe) -> not launching lkl-boot\n");
            return;
        }
        grantBdf[ngrant++] = fb;
    }
    if (!spawnWaylandProgram("lkl-boot\0".ptr, "[lkl]\0".ptr)) return;
    const int lklTid = cast(int)g_current_task_id;          // spawnWaylandProgram set this to the new task
    if (lklTid > 0) {
        for (int i = 0; i < ngrant; i++) {                  // multi-cap: grant EVERY device to the one LKL
            grantDeviceCap(lklTid, grantBdf[i]);
            klog("[lkl] granted device-cap bdf="); klog_hex(grantBdf[i]); klog("\n");
        }
        klog("[lkl] single LKL granted "); klog_hex(cast(ulong)ngrant); klog(" device(s) (WiFi bus0 + xHCI)\n");
    }
    // NOTE: hos-netlaunch (-> wpa_supplicant) is NOT spawned here.  Spawning it in this same
    // iteration overwrote g_current_task_id (spawnWaylandProgram sets it to the last-spawned task),
    // so wpa ran BEFORE lkl-boot and then spun connect()-ing to a provider socket that didn't exist
    // yet (lkl-boot hadn't booted embedded Linux) — burning scheduler slices for ~10 min on real HW.
    // Instead maybeSpawnNetLaunch() (below) launches it ONLY once the provider socket is listening.
}

// H3: launch the native WiFi client (hos-netlaunch -> unmodified wpa_supplicant under the transparent
// shim) ONLY after lkl-boot's cap-gated provider socket is actually accepting.  Gating on the live
// listener means wpa never spins against a dead socket and never steals lkl-boot's first CPU slice.
private __gshared bool g_netLaunchStarted = false;
private void maybeSpawnNetLaunch() {
    if (g_netLaunchStarted) return;
    if (!unixSocketListenerReady("/run/hos-net.sock\0".ptr)) return;   // provider not up yet (cheap check)
    g_netLaunchStarted = true;
    klog("[lkl] H3: net-provider is live -> launching hos-netlaunch -> wpa_supplicant under the shim\n");
    spawnWaylandProgram("hos-netlaunch\0".ptr, "[wpa]\0".ptr);
}

// M2b: launch the REAL NetworkManager daemon once BOTH the system dbus-daemon (M0) and the LKL
// cap-gated net-provider (so the shim can route NM's rtnetlink/nl80211 to wlan0) are live.  NM owns
// org.freedesktop.NetworkManager on the system bus; nmcli / the GUI drive it from there.  Replaces the
// standalone wpa launch above (NM spawns + drives wpa_supplicant itself over D-Bus at M5).
// M5: launch wpa_supplicant in D-Bus mode (fi.w1.wpa_supplicant1) BEFORE NM, so the name is owned on
// the system bus when NM's wifi.backend=wpa_supplicant looks for it.  NM watches for the name owner, so
// exact ordering is not critical, but starting wpa first avoids the initial "not running" retry.
// TEMP TEST FLAG: skip the whole NM/wpa/wifi-agent/boot-doctor chain to isolate the
// Hyprland render loop from the (currently-broken, WIP) NetworkManager path. Set true only
// to debug the desktop without WiFi bring-up; false = normal boot.
private __gshared bool g_skipNetForTest = false;

// Explicit headless debug boots (/epin-debug-fast-net.conf boot module present) use direct
// wpa_supplicant (-c) + external
// udhcpc for the log-upload path.  NetworkManager + its agent + the nmcli boot-doctor are then pure
// dead weight: NM never registers on D-Bus and they SPIN retrying it, churning dbus-daemon and starving
// the Weston compositor into repeated freezes — THE "OS keeps crashing" instability (reproduced under
// VirtualBox).  So skip that whole stack on debug boots and leave the CPU to the compositor.
private __gshared int g_debugNetBoot = -1;   // -1=unknown, 0=no, 1=yes (cached)
private bool debugNetBootPresent() {
    if (g_debugNetBoot < 0) {
        g_debugNetBoot = 0;
        if (g_mboot_modules !is null && g_module_count > 0) {
            auto recs = cast(ubyte*)g_mboot_modules;
            for (int i = 0; i < g_module_count; i++) {
                auto rec = cast(multiboot_module_t*)(recs + i * 128);
                const(char)* modName = cast(const(char)*)(cast(ubyte*)rec + 16);
                const(char)* modBase = modName;
                for (const(char)* p = modName; *p != 0; p++) if (*p == '/') modBase = p + 1;
                if (cstrEqK(modBase, "epin-debug-fast-net.conf")) { g_debugNetBoot = 1; break; }
            }
        }
    }
    return g_debugNetBoot == 1;
}

// Direct-wpa Wi-Fi is the DEFAULT.  NetworkManager hangs at `platform-linux: create`, never registers
// its D-Bus name here, and its NM+dbus+nmcli chain churns the CPU -> Weston starvation ("Wi-Fi
// unavailable").  Instead hos-wpa-agent drives wpa_supplicant directly (writes /run/wpa-net.conf +
// SIGHUP reload) and publishes scan results read from the LKL provider (NSP_SCAN) to /run/wifi/networks; the
// kernel-supervised udhcpc leases.  NM can be restored by staging an /epin-use-nm.conf opt-out marker.
private __gshared int g_useNm = -1;   // -1=unknown, 0=direct-wpa (default), 1=NM (opt-out marker present)
private bool useDirectWifi() {
    if (g_useNm < 0) {
        g_useNm = 0;
        if (g_mboot_modules !is null && g_module_count > 0) {
            auto recs = cast(ubyte*)g_mboot_modules;
            for (int i = 0; i < g_module_count; i++) {
                auto rec = cast(multiboot_module_t*)(recs + i * 128);
                const(char)* modName = cast(const(char)*)(cast(ubyte*)rec + 16);
                const(char)* modBase = modName;
                for (const(char)* p = modName; *p != 0; p++) if (*p == '/') modBase = p + 1;
                if (cstrEqK(modBase, "epin-use-nm.conf")) { g_useNm = 1; break; }
            }
        }
    }
    return g_useNm == 0;   // direct-wpa unless the NM opt-out marker is staged
}

// DECOY_DISTRO US0: gate granting the xHCI (USB) controller to the LKL behind a boot marker.
// Driving usb-storage bulk DMA hard-freezes the FW13 (no-IOMMU path — see maybeSpawnLklTest);
// so USB is OFF by default and enabled only when /epin-usb.conf is staged (QEMU dev boots +
// the future decoy-install path once US5 fixes the freeze). Mirrors debugNetBootPresent().
private __gshared int g_usbBoot = -1;   // -1=unknown, 0=no, 1=yes (cached)
public bool debugUsbBootPresent() {
    if (g_usbBoot < 0) {
        g_usbBoot = 0;
        if (g_mboot_modules !is null && g_module_count > 0) {
            auto recs = cast(ubyte*)g_mboot_modules;
            for (int i = 0; i < g_module_count; i++) {
                auto rec = cast(multiboot_module_t*)(recs + i * 128);
                const(char)* modName = cast(const(char)*)(cast(ubyte*)rec + 16);
                const(char)* modBase = modName;
                for (const(char)* p = modName; *p != 0; p++) if (*p == '/') modBase = p + 1;
                if (cstrEqK(modBase, "epin-usb.conf")) { g_usbBoot = 1; break; }
            }
        }
    }
    return g_usbBoot == 1;
}

// Compositor selection.  Weston has always won unconditionally (GW3), so the Hyprland module --
// which IS staged, all 38 MB of it -- was never even looked at: its selection loop is guarded on
// `initPhys == 0` and Weston had already set it.
//
// Rather than delete Weston (which would leave no desktop at all if Hyprland fails to come up),
// this is a reversible marker, exactly like /epin-usb.conf above: stage /epin-hyprland.conf with
// `HYPRLAND=1 make iso` and Hyprland wins; leave it out and Weston still does.  Switching back
// costs a rebuild, not a debugging session with a black screen.
private __gshared int g_hyprPref = -1;   // -1=unknown, 0=no, 1=yes (cached)
public bool hyprlandPreferred() {
    if (g_hyprPref < 0) {
        g_hyprPref = 0;
        if (g_mboot_modules !is null && g_module_count > 0) {
            auto recs = cast(ubyte*)g_mboot_modules;
            for (int i = 0; i < g_module_count; i++) {
                auto rec = cast(multiboot_module_t*)(recs + i * 128);
                const(char)* modName = cast(const(char)*)(cast(ubyte*)rec + 16);
                const(char)* modBase = modName;
                for (const(char)* p = modName; *p != 0; p++) if (*p == '/') modBase = p + 1;
                if (cstrEqK(modBase, "epin-hyprland.conf")) { g_hyprPref = 1; break; }
            }
        }
    }
    return g_hyprPref == 1;
}

// The AX210 firmware load is a large multi-page host->device DMA.  On the no-IOMMU FW13, if the LKL
// backs that buffer with physically-SCATTERED pages, op5's single-address translation makes the
// device DMA garbage for pages 2..N -> corrupt LMAC ucode -> "Failed to start RT ucode -110"
// (LMAC PC stuck 0xd0), intermittently.  The US5 bounce fixes that but is gated off on WiFi boots
// because it once broke streaming-RX scanning; so re-enable it ONLY when /epin-wifi-dma-bounce.conf
// is staged (build with WIFI_DMA_BOUNCE=1), so it is safe to A/B test on real HW.
private __gshared int g_wifiDmaBounce = -1;   // -1=unknown, 0=no, 1=yes (cached)
public bool wifiDmaBounceBootPresent() {
    if (g_wifiDmaBounce < 0) {
        g_wifiDmaBounce = 0;
        if (g_mboot_modules !is null && g_module_count > 0) {
            auto recs = cast(ubyte*)g_mboot_modules;
            for (int i = 0; i < g_module_count; i++) {
                auto rec = cast(multiboot_module_t*)(recs + i * 128);
                const(char)* modName = cast(const(char)*)(cast(ubyte*)rec + 16);
                const(char)* modBase = modName;
                for (const(char)* p = modName; *p != 0; p++) if (*p == '/') modBase = p + 1;
                if (cstrEqK(modBase, "epin-wifi-dma-bounce.conf")) { g_wifiDmaBounce = 1; break; }
            }
        }
    }
    return g_wifiDmaBounce == 1;
}

private __gshared bool g_wpaStarted = false;
// Bounded-retry state.  maybeSpawnWpa() is the ONLY spawner that clears its own latch when a
// spawn fails -- every other one latches permanently on the first attempt -- so a missing
// hos-wpa-launch boot module made it retry on EVERY kernel-loop pass.  Measured: 88,070
// attempts in one boot, three klog lines each, all written to the 115200-baud UART while the
// loop holds the BKL.  That starves the compositor and every task; it is why the live desktop
// was unusable.  Give up after a few failures instead.
private __gshared bool g_wpaGaveUp    = false;
private __gshared int  g_wpaSpawnFails = 0;
private enum int WPA_MAX_SPAWN_FAILS  = 3;
private __gshared int  g_wpaTid = 0;
private void maybeSpawnWpa() {
    if (g_skipNetForTest || g_wpaGaveUp) return;
    if (g_wpaStarted) {
        /* The agent reloads configuration in-place with SIGHUP so this process retains its
         * initialized nl80211 sockets and radio ownership.  Still supervise genuine exits. */
        if (g_wpaTid > 0 && g_wpaTid < MAX_TASKS &&
            g_tasks[g_wpaTid].active && !g_tasks[g_wpaTid].exited)
            return;
        g_wpaStarted = false;
        g_wpaTid = 0;
        klog("[wpa] supplicant exited; restarting with current /run/wpa-net.conf\n");
    }
    // Debug-net boots drive wpa in direct -c mode (no D-Bus) and dbus is gated off there, so requiring
    // g_dbusStarted would wedge wifi forever. Only normal (-u/NetworkManager) boots need the bus first.
    if (!useDirectWifi() && !g_dbusStarted) return;                   // direct-wpa needs no dbus; only NM mode waits for the bus
    if (!unixSocketListenerReady("/run/hos-net.sock\0".ptr)) return;   // provider (LKL netlink) not up yet
    g_wpaStarted = true;
    klog("[wpa] M5: net-provider live -> launching hos-wpa-launch -> wpa_supplicant under the shim\n");
    if (spawnWaylandProgram("hos-wpa-launch\0".ptr, "[wpa]\0".ptr))
        g_wpaTid = cast(int)g_current_task_id;
    else
    {
        g_wpaStarted = false;
        if (++g_wpaSpawnFails >= WPA_MAX_SPAWN_FAILS) {
            g_wpaGaveUp = true;
            klog("[wpa] hos-wpa-launch could not be spawned 3x -- giving up (was retrying every kernel-loop pass)\n");
        }
    }
}
private __gshared bool g_nmStarted = false;
private __gshared ulong g_nmStartedMs = 0;
private void maybeSpawnNetworkManager() {
    if (g_skipNetForTest) return;
    if (g_nmStarted) return;
    if (useDirectWifi()) return;   // direct-wpa is the default; NM never registers + churns dbus -> freezes
    if (!g_dbusStarted) return;                                        // system bus must be up first
    if (!unixSocketListenerReady("/run/hos-net.sock\0".ptr)) return;   // provider (LKL netlink) not up yet
    g_nmStarted = true;
    g_nmStartedMs = pitMs();
    klog("[nm] M2b: dbus + net-provider live -> launching hos-nm-launch -> NetworkManager under the shim\n");
    spawnWaylandProgram("hos-nm-launch\0".ptr, "[nm]\0".ptr);
}
// M2b confirmation: once NM has had time to register on the system bus, run nmcli to query it.
// M6: the Wi-Fi menu's D-Bus engine.  Once NM is up, hos-wifi-agent (libdbus) polls NM for the Wi-Fi
// device + access points and bridges them to /run/wifi/networks (+ processes /run/wifi/connect), so the
// Wayland menu stays a pure file renderer.  It only speaks D-Bus (native AF_UNIX to our dbus-daemon) so
// it needs neither LD_PRELOAD nor the net-provider.
private __gshared bool g_wifiAgentStarted = false;
private void maybeSpawnWifiAgent() {
    if (g_skipNetForTest) return;
    if (g_wifiAgentStarted) return;
    if (useDirectWifi()) return;   // direct-wpa uses hos-wpa-agent instead; this D-Bus agent would spin against the bypassed NM
    if (g_wifiBridgePresent) return;   // the COM2 host-WiFi bridge owns /run/wifi/* — no demo agent
    // Do not start it merely because the dbus launcher was spawned: dbus-daemon may
    // not be accepting/authenticating clients yet, and an early dbus_bus_get() used
    // to wedge the agent + daemon before NM had registered.
    if (!g_dbusStarted) return;
    if (!g_nmStarted || g_nmStartedMs == 0) return;
    /* The reconcile loop runs thousands of times per second, so the old 60-iteration
     * "head start" was only milliseconds.  Use the real PIT millisecond clock and let
     * dbus + NM finish their expensive netlink/platform initialization first. */
    if (pitMs() - g_nmStartedMs < 20_000) return;
    g_wifiAgentStarted = true;
    klog("[wifi] M6: launching hos-wifi-agent -> /run/wifi/networks (NM<->menu D-Bus bridge)\n");
    /* Keep the ordinary service User identity.  Forcing this task to UID 0 made
     * dbus-daemon's EXTERNAL authentication wait forever for Hello even though
     * an immediately preceding non-root dbus-send readiness probe succeeded.
     * NetworkManager explicitly runs auth-polkit=false, so connection requests
     * are allowed without ambient root; actual NIC access remains independently
     * capability-gated by DEVCLASS_NET. */
    spawnWaylandProgram("hos-wifi-agent\0".ptr, "[wifiag]\0".ptr);
}
// Direct-wpa menu backend (default): replaces the NM D-Bus bridge (hos-wifi-agent).  hos-wpa-agent
// asks the LKL provider for scan results (NSP_SCAN) and publishes /run/wifi/networks, and turns a
// menu connect request (/run/wifi/connect) into a wpa association by rewriting /run/wpa-net.conf and
// SIGHUP-reloading wpa_supplicant.  It speaks only plain AF_UNIX to the provider
// (no dbus, no LD_PRELOAD).
private __gshared bool g_wpaAgentStarted = false;
private __gshared int  g_wpaAgentDelay   = 0;
private void maybeSpawnWpaAgent() {
    if (g_skipNetForTest) return;
    if (g_wpaAgentStarted) return;
    if (!useDirectWifi()) return;                                     // NM mode uses hos-wifi-agent instead
    if (g_wifiBridgePresent) return;                                  // the COM2 host-WiFi bridge owns /run/wifi/*
    if (!unixSocketListenerReady("/run/hos-net.sock\0".ptr)) return;  // needs the LKL provider for NSP_SCAN
    if (g_wpaAgentDelay++ < 40) return;                               // let wpa + the provider settle first
    g_wpaAgentStarted = true;
    klog("[wifi] direct-wpa: launching hos-wpa-agent -> NSP_SCAN -> /run/wifi/networks (connect via wpa config + SIGHUP)\n");
    spawnWaylandProgram("hos-wpa-agent\0".ptr, "[wpaag]\0".ptr);
}
// External DHCP: NM's in-process n-dhcp4 stalls before ever sending a DISCOVER (its nested epoll+timerfd
// never fires here), so a standalone busybox udhcpc gets the lease instead (proven: full
// DISCOVER→OFFER→REQUEST→ACK through the LKL/AX210).  Kernel-spawned (the wifi-agent's fork()+execve of
// it was unreliable); the launcher execve()s /busybox-dyn udhcpc under LD_PRELOAD=/libnshim.so.
private __gshared bool g_udhcpcLeased = false;
private __gshared int  g_udhcpcDelay  = 0;   // initial settle before the first launch
private __gshared int  g_udhcpcRetry  = 0;   // respawn throttle once we're launching
private __gshared int  g_udhcpcSpawns = 0;   // respawn CAP: a udhcpc that keeps crashing must not churn forever
private __gshared int  g_udhcpcTid    = 0;   // tid of the live udhcpc — never stack a 2nd resident instance
private void maybeSpawnUdhcpc() {
    if (g_skipNetForTest) return;
    if (g_udhcpcLeased) return;                                       // lease already obtained — done, never respawn
    if (g_wifiBridgePresent) return;                                  // COM2 host-bridge owns wifi
    if (!useDirectWifi() && !g_dbusStarted) return;                   // dbus is gated off in direct-wpa mode; udhcpc never needs it
    if (!unixSocketListenerReady("/run/hos-net.sock\0".ptr)) return;  // LKL net-provider (owns wlan0) up
    // The udhcpc lease script writes /run/wifi/dhcp-ok on a successful bind.  Once it exists we're
    // done: latch off and let the live udhcpc stay up to renew.
    if (linux_sys_access(cast(ulong)"/run/wifi/dhcp-ok\0".ptr, 0) == 0) { g_udhcpcLeased = true; return; }
    // RESIDENCY CAP = 1.  busybox udhcpc runs -f with NO -n, so ONE instance stays alive forever
    // retrying DISCOVER — a second is pure waste.  Without this, the %600 respawn throttle STACKS up to
    // 12 CONCURRENT resident udhcpc, and each re-checks readiness with an NSP_POLL RPC to the single
    // serialized LKL provider on EVERY tick (wakePollers wakes all parked pollers) -> a 12x RPC storm
    // that starved Weston (the direct-wpa "CPU hog / SUPER+L dead" regression: wlan0 comes up early but
    // never associates, so all 12 persisted).  Only (re)spawn once the prior udhcpc has actually exited.
    if (g_udhcpcTid > 0 && g_udhcpcTid < MAX_TASKS &&
        g_tasks[g_udhcpcTid].active && !g_tasks[g_udhcpcTid].exited) return;
    if (g_udhcpcDelay++ < 90) return;                                 // initial settle: let NM/wpa bring wlan0 up first
    // SUPERVISE, don't one-shot.  The old latch meant that if the first udhcpc died early (it exec'd
    // before wlan0 was actually associated, so its AF_PACKET setup failed and busybox udhcpc exited)
    // DHCP was dead for the whole session — which is exactly what we saw: manual `udhcpc` gets a lease
    // instantly, but the boot-time one never persisted.  So keep (re)launching until /run/wifi/dhcp-ok
    // appears, throttled (~every 600 reconciles) so an actively-retrying udhcpc isn't duplicated faster
    // than it can finish DISCOVER→ACK.
    if ((g_udhcpcRetry++ % 600) != 0) return;
    // CAP the respawns: on hardware where busybox-dyn udhcpc segfaults (code=1, the 0x5a00.. musl crash),
    // an uncapped supervisor respawns it forever — that was the tid-249 crash-loop churning the FW13's CPU
    // and (before the reaper) exhausting the task table.  Give up after 12 tries; the reaper still frees the
    // dead slots, and WiFi can be brought up by hand (LD_PRELOAD=/libnshim.so /busybox-dyn udhcpc -i wlan0 …).
    if (g_udhcpcSpawns >= 12) {
        if (g_udhcpcSpawns == 12) {
            klog("[udhcpc] gave up after 12 launches with no lease — no auto-IP; run udhcpc by hand if needed\n");
            g_udhcpcSpawns = 13;   // log this once
        }
        return;
    }
    g_udhcpcSpawns++;
    klog("[udhcpc] (re)launch hos-udhcpc-launch -> busybox udhcpc; supervising until lease (/run/wifi/dhcp-ok)\n");
    spawnWaylandProgram("hos-udhcpc-launch\0".ptr, "[udhcpc]\0".ptr);
    g_udhcpcTid = cast(int)g_current_task_id;   // remember the live instance so we never stack a 2nd (spawnWaylandProgram set g_current_task_id)
}
private __gshared bool g_nmcliStarted = false;
private __gshared int  g_nmcliDelay   = 0;
private void maybeSpawnNmcli() {
    if (g_skipNetForTest) return;
    if (g_nmcliStarted) return;
    if (useDirectWifi()) return;   // direct-wpa: the NM boot-doctor poll is a foregone "stuck" verdict + churns dbus
    // UNGATED (not requiring g_nmStarted): the boot-doctor diagnoses the whole chain — dbus, the LKL
    // provider socket, and NM registration — and writes /run/boot-status.txt.  It must run even when
    // NM never launched (that is exactly what we are diagnosing).
    if (g_dbusDelay < 40) return;       // let dbus + LKL get a chance to come up first
    if (g_nmcliDelay++ < 80) return;
    g_nmcliStarted = true;
    klog("[nm] boot-doctor: launching hos-nmcli-test -> writes /run/boot-status.txt\n");
    spawnWaylandProgram("hos-nmcli-test\0".ptr, "[bootdr]\0".ptr);
}
// Debug log egress: after NM starts, launch a small uploader that snapshots
// /run/klog plus NM/wpa diagnostics and invokes /scp if an SSH client is staged.
private __gshared bool g_logUploadStarted = false;
private __gshared int  g_logUploadDelay   = 0;
private void maybeSpawnLogUpload() {
    if (g_skipNetForTest) return;
    if (g_logUploadStarted) return;
    if (!g_nmStarted) return;
    if (g_logUploadDelay++ < 180) return;
    g_logUploadStarted = true;
    klog("[log-upload] launching hos-log-upload -> /tmp/epin-debug-logs.txt + scp\n");
    spawnWaylandProgram("hos-log-upload\0".ptr, "[logup]\0".ptr);
}
// M0: start the REAL system dbus-daemon once, a little after boot.  D-Bus is pure local AF_UNIX IPC
// (no LKL, no net-provider), so it is independent of the WiFi path.  hos-dbus-launch also runs a
// dbus-send GetId self-test that proves EXTERNAL auth (SO_PEERCRED over native AF_UNIX) works here --
// the prerequisite for every NetworkManager client.  Later this becomes a persistent service for NM.
private __gshared bool g_dbusStarted = false;
private __gshared int  g_dbusDelay   = 0;
// SSH-in: start the dropbear launcher (listens on AF_UNIX /run/sshd.sock; lkl-boot's tcp/22
// bridge relays inbound SSH to it). Runs on any boot that has the LKL network path.
private __gshared bool g_sshdStarted = false;
private __gshared int  g_sshdDelay   = 0;
private __gshared int g_sshBoot = -1;
public bool sshBootPresent() {   // SSH-in is OPT-IN (/epin-ssh.conf, SSH=1) — off by default so
    if (g_sshBoot < 0) {         // it never runs on a normal boot (it touches the LKL WiFi path).
        g_sshBoot = 0;
        if (g_mboot_modules !is null && g_module_count > 0) {
            auto recs = cast(ubyte*)g_mboot_modules;
            for (int i = 0; i < g_module_count; i++) {
                auto rec = cast(multiboot_module_t*)(recs + i * 128);
                const(char)* modName = cast(const(char)*)(cast(ubyte*)rec + 16);
                const(char)* modBase = modName;
                for (const(char)* p = modName; *p != 0; p++) if (*p == '/') modBase = p + 1;
                if (cstrEqK(modBase, "epin-ssh.conf")) { g_sshBoot = 1; break; }
            }
        }
    }
    return g_sshBoot == 1;
}
private void maybeSpawnSshd() {
    if (g_sshdStarted) return;
    if (!sshBootPresent()) { g_sshdStarted = true; return; }   // opt-in only (SSH=1)
    if (g_sshdDelay++ < 40) return;      // let the desktop settle first
    g_sshdStarted = true;
    klog("[sshd] launching hos-sshd-launch (SSH-in via lkl-boot tcp/22 -> /run/sshd.sock -> dropbear)\n");
    spawnWaylandProgram("hos-sshd-launch\0".ptr, "[sshd]\0".ptr);
}

private void maybeSpawnDbus() {
    if (g_dbusStarted) return;
    // ROADMAP 2.5.  The `if (useDirectWifi()) return;` that used to sit here skipped the bus
    // ENTIRELY on the default boot path, reasoning that "direct-wpa needs no dbus" -- true of
    // NETWORK MANAGEMENT, and the reason it was written, but it conflated "networking does not
    // need a bus" with "nothing does".  GTK applications need one whatever the network is
    // doing: gtk-hello's own boot log shows it hunting for
    // dbus-update-activation-environment across five paths and finding none, and many GTK apps
    // abort rather than degrade when they cannot reach a session bus.
    //
    // The bus is pure local AF_UNIX IPC with no dependency on the LKL or the net-provider shim
    // (as this file's own comment above says), so starting it costs nothing on the direct-wpa
    // path -- it simply has no NetworkManager clients there.
    if (g_dbusDelay++ < 40) return;   // let the desktop settle first
    g_dbusStarted = true;
    klog("[dbus] M0: launching hos-dbus-launch -> dbus-daemon (persistent system bus)\n");
    spawnWaylandProgram("hos-dbus-launch\0".ptr, "[dbus]\0".ptr);
}
// M0 smoke test: run a real dbus-send GetId client once, after the bus is up, to prove EXTERNAL auth
// (SO_PEERCRED over native AF_UNIX) works.  Separate one-shot so we depend on neither fork nor a long nap.
private __gshared bool g_dbusTestStarted = false;
private __gshared ulong g_dbusTestDeadlineMs = 0;
// ROADMAP 2.1: run the /proc proof once, 20 s in.  Run at store-mount it reported
// "cpu  0 0 0 0 ..." and "uptime 0.00" -- both correct at that instant and both useless as
// evidence, because no time had passed and the idle task did not exist yet.
// Automatic time from pool.ntp.org.  Retried rather than attempted once: at the moment the lease
// lands the link is often not yet passing traffic, and a single failed lookup would leave the
// clock at 1970 for the rest of the session.
private __gshared bool  g_netConfigured  = false;
private __gshared ulong g_ntpNextTryMs   = 0;
private __gshared int   g_ntpAttempts    = 0;
enum int   NTP_MAX_ATTEMPTS = 6;
// Thresholds are deliberately small: pitMs() advances well behind wall time on this kernel, so a
// "20 s" retry never came round twice in a 200 s boot.  Anything gating on pitMs must be sized
// against that, not against real seconds.
enum ulong NTP_FIRST_TRY_MS = 1_500;    // let the link settle after the lease
enum ulong NTP_RETRY_MS     = 4_000;
// Re-sync interval, in pitMs which runs behind wall clock -- so the real gap between corrections
// is longer than this number suggests.  Sized to bound drift, not to be precise.
enum ulong NTP_RESYNC_MS    = 60_000;
private void maybeSyncNtp() {
    import network.ntp : ntpRequest, ntpSynced, ntpResetForRetry, ntpHaveServer;
    if (!g_netConfigured || !ntpHaveServer()) return;

    // ONE timer, whose interval depends on whether the clock has been set yet: retry briskly
    // until the first success, then re-sync periodically so the clock cannot drift away for as
    // long as the machine stays up (ntpNowSec() extrapolates from pitMs between syncs).
    //
    // The earlier two-timer version never re-synced at all.  Its resync branch re-armed
    // g_ntpResyncAtMs and cleared g_ntpNextTryMs, so the first-try delay made it return, and the
    // next pass re-gated on the deadline it had just pushed forward -- a round that armed itself
    // and never fired.  That looked exactly like a clock running 30x slow, and very nearly got
    // diagnosed as one.
    const ulong now = pitMs();
    if (g_ntpNextTryMs == 0) g_ntpNextTryMs = now + NTP_FIRST_TRY_MS;
    if (now < g_ntpNextTryMs) return;

    // Bounded only before the first success; after that the periodic re-sync runs indefinitely.
    if (!ntpSynced() && g_ntpAttempts >= NTP_MAX_ATTEMPTS) return;

    g_ntpNextTryMs = now + (ntpSynced() ? NTP_RESYNC_MS : NTP_RETRY_MS);
    if (!ntpSynced()) ++g_ntpAttempts;

    klog(ntpSynced() ? "[ntp] resync at pitMs=" : "[ntp] sync attempt at pitMs=");
    klog_dec(now); klog("\n");
    ntpResetForRetry();
    if (!ntpRequest() && !ntpSynced() && g_ntpAttempts >= NTP_MAX_ATTEMPTS)
        klog("[ntp] giving up; clock stays at uptime-since-boot\n");
}

// ROADMAP 2.2: the syscall audit.  Its whole point is to record what is missing ONCE, instead of
// finding out one app crash at a time.
//
// It probes through dispatchLinuxSyscall rather than reading the switch statement, because being
// routed and being implemented are different things: inotify_init1 has a case arm AND returns
// ENOSYS from a stub, so a static reading of the table would have called it present.  Grepping
// for "case <nr>:" answers the wrong question.
//
// Arguments are chosen to fail cheaply and harmlessly -- a bad fd, a null pointer, a zero size --
// so the probe distinguishes "not implemented" (ENOSYS) from "implemented, rejected these args"
// (EBADF/EINVAL/EFAULT), which is the distinction that matters.  Anything that could create a
// real object, block, or touch the filesystem is deliberately not probed.
private struct SyscallProbe { ulong nr; const(char)* name; ulong a, b, c; }
private __gshared bool g_syscallAudited = false;
private void maybeSyscallAudit() {
    if (g_syscallAudited) return;
    if (pitMs() < 5_000) return;      // after the desktop is up, so the report sits with the rest
    g_syscallAudited = true;

    static immutable SyscallProbe[14] probes = [
        { 253, "inotify_init\0".ptr,      0, 0, 0 },
        { 294, "inotify_init1\0".ptr,     0, 0, 0 },
        { 254, "inotify_add_watch\0".ptr, 0xFFFF_FFFF, 0, 0 },
        { 255, "inotify_rm_watch\0".ptr,  0xFFFF_FFFF, 0, 0 },
        { 284, "eventfd\0".ptr,           0, 0, 0 },
        { 290, "eventfd2\0".ptr,          0, 0, 0 },
        // -1 has to be sign-extended to 64 bits.  Passing 0xFFFF_FFFF reaches the kernel as a
        // positive 4294967295, and signalfd echoed that straight back as though it were a valid
        // descriptor instead of rejecting it -- which made the audit read "ret=4294967295" and
        // told us nothing.  The echo is worth chasing separately; it is not what this asks.
        { 282, "signalfd\0".ptr,          ulong.max, 0, 0 },
        { 289, "signalfd4\0".ptr,         ulong.max, 0, 0 },
        { 283, "timerfd_create\0".ptr,    0, 0, 0 },
        { 319, "memfd_create\0".ptr,      0, 0, 0 },
        { 271, "ppoll\0".ptr,             0, 0, 0 },
        { 291, "epoll_create1\0".ptr,     0, 0, 0 },
        { 292, "dup3\0".ptr,              0xFFFF_FFFF, 0xFFFF_FFFF, 0 },
        { 293, "pipe2\0".ptr,             0, 0, 0 },
    ];

    klog("[audit] ROADMAP 2.2 syscall audit — probing through the real dispatcher\n");
    int missing = 0;
    foreach (ref p; probes) {
        const long r = dispatchLinuxSyscall(p.nr, p.a, p.b, p.c, 0, 0, 0);
        klog("[audit] ");
        klog(p.name);
        klog(" nr="); klog_dec(p.nr);
        // ENOSYS is private to posix.d, so the value is spelled out here.
        if (r == -38) { klog(" MISSING (ENOSYS)\n"); ++missing; }
        else if (r < 0)   { klog(" present (errno "); klog_dec(cast(ulong)(-r)); klog(")\n"); }
        else {
            klog(" present (ok, ret="); klog_dec(cast(ulong)r); klog(")\n");
            // Several of these DO create a real object -- eventfd, timerfd_create, memfd_create
            // and epoll_create1 each returned a live descriptor.  An audit that leaks five fds
            // every boot is a worse bug than the one it reports, so hand them straight back.
            // (Probes given deliberately-bad arguments return an errno and allocate nothing.)
            linux_sys_close(cast(ulong)r);
        }
    }
    klog("[audit] missing: "); klog_dec(cast(ulong)missing);
    klog(" of "); klog_dec(cast(ulong)probes.length); klog("\n");
}

// ROADMAP 2.3: both GTK clients (gtk-hello and gtk3-widget-factory) connect, sendmsg, then block
// in poll(nfds=1, timeout=-1) forever without ever mapping a window, while Hyprland sits idle with
// flipQ == flipRd.  Each is waiting on the other, so the question is whether the compositor is
// actually watching the new client's fd.  epollDumpAll() was written to answer exactly that and
// has never been called.  Dump periodically rather than once: the client is launched by hand from
// a keybinding, so a single fixed-time dump would almost certainly miss it.
private __gshared ulong g_epDumpNext = 0;
private __gshared int   g_epDumpN    = 0;
private void maybeEpollDump() {
    if (g_epDumpN >= 6) return;
    const ulong now = pitMs();
    if (now < 20_000) return;              // let the desktop finish coming up first
    if (now < g_epDumpNext) return;
    g_epDumpNext = now + 30_000;
    ++g_epDumpN;
    klog("[epdump] #"); klog_dec(cast(ulong)g_epDumpN);
    klog(" at pitMs="); klog_dec(now); klog("\n");
    epollDumpAll();
}

private __gshared bool g_procTested = false;
private void maybeProcSelfTest() {
    if (g_procTested) return;
    if (pitMs() < 4_000) return;
    g_procTested = true;
    procSelfTest();
}
private void maybeSpawnDbusTest() {
    if (g_dbusTestStarted) return;
    if (!g_dbusStarted) return;         // launch the daemon first
    // Wait for the bus to be *accepting*, not for time to elapse.  The original fixed 40-tick
    // delay was a guess and lost the race: dbus-send ran, got ECONNREFUSED, and the daemon only
    // finished binding long afterwards.
    //
    // The bound is wall-clock, not a poll count.  This runs in the main scheduler loop, so a poll
    // count measures nothing physical -- a 400-poll bound expired while the daemon was still
    // starting up, which is exactly how the first attempt at this fix still fired too early.
    if (g_dbusTestDeadlineMs == 0) g_dbusTestDeadlineMs = pitMs() + 60_000;
    if (!unixListenerReady("/run/dbus/system_bus_socket\0".ptr))
    {
        // Bounded, so a daemon that never binds cannot wedge this poll forever.
        if (pitMs() < g_dbusTestDeadlineMs) return;
        klog("[dbus] bus still not listening after 60s; running the test anyway to surface the error\n");
    }
    g_dbusTestStarted = true;
    klog("[dbus] M0: launching hos-dbus-test -> dbus-send GetId (EXTERNAL-auth round-trip)\n");
    spawnWaylandProgram("hos-dbus-test\0".ptr, "[dbust]\0".ptr);
}
// Diagnostic: isolate the glib GMainContext cross-thread wakeup deadlock that hangs NM's early init.
// Runs eventfd+poll / eventfd+epoll / pipe+poll cross-thread with bounded timeouts.  Independent of
// everything, so spawn it early.
private __gshared bool g_thrTestStarted = false;
private __gshared int  g_thrTestDelay   = 0;
private void maybeSpawnThreadTest() {
    if (g_thrTestStarted) return;
    if (g_thrTestDelay++ < 30) return;
    g_thrTestStarted = true;
    klog("[thr] diag: launching hos-thread-test (eventfd/epoll/pipe cross-thread wakeup)\n");
    spawnWaylandProgram("hos-thread-test\0".ptr, "[thr]\0".ptr);
}
private void maybeSpawnGlTest() {
    if (g_glTestStarted) return;
    import drivers.graphics.virtio_gpu : g_gpuVirgl;
    if (!g_gpuVirgl) return;
    if (g_glTestDelay++ < 150) return;   // run well after drm-gpu-test has exited
    g_glTestStarted = true;
    klog("[r24] launching drm-gl-test (Mesa virgl GLES2)\n");
    spawnWaylandProgram("drm-gl-test\0".ptr, "[r24gl]\0".ptr);
}

// ------------------------------------------------------------------
// wait4
// ------------------------------------------------------------------

private long wait4Task(int tid, int waitPid, ulong statusPtr, ulong options) {
    auto task = &g_tasks[tid];

    // waitPid semantics (Track A A4): -1 = any child; 0 = any child in the caller's
    // process group; < -1 = any child in process group |waitPid|; > 0 = that pid.
    // We don't track process groups precisely, so 0 and < -1 are treated as "any
    // child" — the case busybox ash's job control uses (waitpid(0)/waitpid(-pgid)).
    // Without this, those calls checked childExited[0], never matched, and the shell
    // blocked forever after its first forking command.
    const bool anyChild = (waitPid <= 0);
    int targetTid = -1;
    if (waitPid > 0) {
        targetTid = taskIdFromLinuxPid(waitPid);
        if (targetTid < 0 || targetTid >= MAX_TASKS) return -10; // ECHILD
    }

    // Reap an already-exited matching child.
    if (anyChild) {
        for (int c = 1; c < MAX_TASKS; c++) {
            if (task.childExited[c]) {
                int code = task.childExitCode[c];
                task.childExited[c] = false;
                if (statusPtr != 0) *cast(int*)statusPtr = (code & 0xff) << 8;
                int childPid = g_childExitLinuxPid[c] != 0 ? g_childExitLinuxPid[c] : linuxPidForTask(c);
                releaseTask(c);
                return cast(long)childPid;
            }
        }
    } else {
        uint c = cast(uint)targetTid;
        if (c < MAX_TASKS && task.childExited[c]) {
            int code = task.childExitCode[c];
            task.childExited[c] = false;
            if (statusPtr != 0) *cast(int*)statusPtr = (code & 0xff) << 8;
            int childPid = g_childExitLinuxPid[c] != 0 ? g_childExitLinuxPid[c] : linuxPidForTask(cast(int)c);
            releaseTask(c);
            return cast(long)childPid;
        }
    }

    // No matching child has exited.  If the task has no living matching child either,
    // return ECHILD instead of blocking — otherwise ash's reap loop (which waits until
    // ECHILD) would hang.
    bool hasLivingChild = false;
    if (anyChild) {
        for (int i = 1; i < MAX_TASKS; i++)
            if (g_tasks[i].active && !g_tasks[i].exited && g_tasks[i].parentId == tid) {
                hasLivingChild = true; break;
            }
    } else {
        if (targetTid > 0 && targetTid < MAX_TASKS &&
            g_tasks[targetTid].active && !g_tasks[targetTid].exited &&
            g_tasks[targetTid].parentId == tid)
            hasLivingChild = true;
    }
    if (!hasLivingChild) return -10; // ECHILD — no matching child at all

    // WNOHANG?
    enum WNOHANG = 1;
    if (options & WNOHANG) return 0;

    // Block.  Return the -4 sentinel so the dispatcher rewinds RIP and reschedules —
    // the task transparently re-runs wait4 when a child exits (no spurious EINTR).
    task.waiting       = true;
    task.waitingForPid = anyChild ? -1 : targetTid;
    return -4;
}

// ------------------------------------------------------------------
// Z1: userspace signal-handler delivery (rt_sigframe).  See task.d g_sigHandler.
// ------------------------------------------------------------------

// Build an x86-64 rt_sigframe on `tid`'s user stack and redirect the task into its
// installed handler for `sig`.  Mirrors what Linux pushes (struct rt_sigframe): the
// restorer trampoline at the top (pretcode), then a ucontext whose uc_mcontext.gregs[]
// hold the interrupted register state.  The handler runs `void h(int signo)`, returns
// into the restorer, which calls rt_sigreturn → sigreturnTask restores the context.
// Returns false (caller does the default action) if no usable handler/restorer exists.
private bool deliverUserSignal(int tid, int sig) {
    if (tid < 0 || tid >= MAX_TASKS || sig <= 0 || sig >= 64) return false;
    auto task = &g_tasks[tid];
    const ulong handler  = g_sigHandler[tid][sig];
    const ulong restorer = g_sigRestorer[tid][sig];
    if (handler == 0 || restorer == 0) return false;

    // Carve the frame from the user stack below the 128-byte red zone; 16-align then -8 so
    // the handler sees the ABI's post-`call` alignment (RSP % 16 == 8 at entry).
    enum ulong FRAME = 512;
    enum ulong GREGS = 48;          // pretcode(8) + offsetof(ucontext,uc_mcontext)=40
    ulong sp = task.regs[REG_RSP];
    sp -= 128;
    sp -= FRAME;
    sp &= ~15UL;
    sp -= 8;
    const ulong frame = sp;

    const ulong savedCr3 = x64ReadCR3();
    x64WriteCR3(task.pml4Phys);     // user stack is in the low half; kernel stays mapped (high half)
    {
        auto b = cast(ubyte*)frame;
        for (ulong i = 0; i < FRAME; ++i) b[i] = 0;
        *cast(ulong*)(frame + 0) = restorer;            // pretcode = restorer trampoline
        ulong* g = cast(ulong*)(frame + GREGS);         // uc_mcontext.gregs[] (R8..CR2 order)
        g[0]=task.regs[REG_R8];  g[1]=task.regs[REG_R9];  g[2]=task.regs[REG_R10];
        g[3]=task.regs[REG_R11]; g[4]=task.regs[REG_R12]; g[5]=task.regs[REG_R13];
        g[6]=task.regs[REG_R14]; g[7]=task.regs[REG_R15]; g[8]=task.regs[REG_RDI];
        g[9]=task.regs[REG_RSI]; g[10]=task.regs[REG_RBP];g[11]=task.regs[REG_RBX];
        g[12]=task.regs[REG_RDX];g[13]=task.regs[REG_RAX];g[14]=task.regs[REG_RCX];
        g[15]=task.regs[REG_RSP];g[16]=task.regs[REG_RIP];g[17]=task.regs[REG_RFLAGS];
    }
    x64WriteCR3(savedCr3);

    task.regs[REG_RIP] = handler;
    task.regs[REG_RSP] = frame;
    task.regs[REG_RDI] = cast(ulong)sig;     // void handler(int signo)
    task.regs[REG_RSI] = frame + 312;        // &siginfo  (zeroed; SA_SIGINFO handlers)
    task.regs[REG_RDX] = frame + 8;          // &ucontext
    task.regs[REG_RAX] = 0;
    task.regs[REG_RFLAGS] &= ~(0x100UL | 0x400UL);   // clear TF, DF for the handler
    return true;
}

// rt_sigreturn: restore the context deliverUserSignal saved.  The restorer was reached by
// the handler's `ret` (which popped pretcode), so the user RSP now points at the ucontext
// (frame+8); uc_mcontext.gregs[] is at RSP+40.  We run in syscall context with the task's
// CR3 active, so the user stack is directly readable.
private void sigreturnTask(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return;
    auto task = &g_tasks[tid];
    const ulong uc = task.regs[REG_RSP];
    ulong* g = cast(ulong*)(uc + 40);
    task.regs[REG_R8]=g[0];   task.regs[REG_R9]=g[1];   task.regs[REG_R10]=g[2];
    task.regs[REG_R11]=g[3];  task.regs[REG_R12]=g[4];  task.regs[REG_R13]=g[5];
    task.regs[REG_R14]=g[6];  task.regs[REG_R15]=g[7];  task.regs[REG_RDI]=g[8];
    task.regs[REG_RSI]=g[9];  task.regs[REG_RBP]=g[10]; task.regs[REG_RBX]=g[11];
    task.regs[REG_RDX]=g[12]; task.regs[REG_RAX]=g[13]; task.regs[REG_RCX]=g[14];
    task.regs[REG_RSP]=g[15]; task.regs[REG_RIP]=g[16]; task.regs[REG_RFLAGS]=g[17];
}

// rt_sigsuspend (Z1): zsh waits for a foreground job here, temporarily unblocking SIGCHLD.
// This is the correct point to deliver the SIGCHLD handler (it runs wait_for_processes(),
// reaps the child, marks the job done).  Returns:
//   SIGSUSP_DELIVERED — a handler was armed (task.regs set up; dispatcher must `return`)
//   SIGSUSP_BLOCK     — no child has exited yet (dispatcher rewinds RIP + reschedules)
//   -4 (-EINTR)       — nothing to wait for / no handler (classic immediate return)
private enum long SIGSUSP_DELIVERED = 0x7fffffff;
private enum long SIGSUSP_BLOCK     = 0x7ffffffe;
private long sigsuspendTask(int tid) {
    if (tid < 0 || tid >= MAX_TASKS) return cast(long)(-4); // -EINTR
    auto task = &g_tasks[tid];
    enum int SIGCHLD = 17;
    const bool hasHandler = (g_taskSigCustom[tid] & (1UL << SIGCHLD)) != 0 &&
                            g_sigHandler[tid][SIGCHLD] != 0;
    if (hasHandler) {
        // A child has already exited → deliver the handler now.  Arrange that, after the
        // handler returns (rt_sigreturn), sigsuspend itself returns -EINTR so zsh's
        // zwaitjob loop re-checks the (now STAT_DONE) job.
        for (int c = 1; c < MAX_TASKS; c++) {
            if (task.childExited[c]) {
                task.regs[REG_RAX] = cast(ulong)(-4);   // saved as the post-handler sigsuspend result
                if (deliverUserSignal(tid, SIGCHLD)) return SIGSUSP_DELIVERED;
                break;
            }
        }
        // No child has exited yet, but one is still running → block until it does (the
        // child's exitTask clears `waiting`), then re-run sigsuspend and deliver.
        for (int c = 1; c < MAX_TASKS; c++) {
            if (g_tasks[c].active && !g_tasks[c].exited && g_tasks[c].parentId == tid) {
                task.waiting = true; task.waitingForPid = -1;
                return SIGSUSP_BLOCK;
            }
        }
    }
    return cast(long)(-4); // -EINTR: no handler / no children
}

// ------------------------------------------------------------------
// brk — allocate/release heap pages
// ------------------------------------------------------------------

private long brkTask(int tid, ulong newBrk) {
    auto task = &g_tasks[tid];

    // brk is a per-ADDRESS-SPACE resource, but CLONE_VM threads each keep their OWN copy of
    // brkStart/brkCurrent (cloneThread) while sharing one PML4.  Route EVERY thread's brk() to
    // the process leader's single monotonic break.  Otherwise a sibling whose brkCurrent is stale
    // (lower than the true shared break) re-maps FRESH ZERO pages over the leader's already-populated
    // heap on its next grow — and musl mallocng keeps its `struct meta` areas inside the brk region,
    // so the clobbered meta gets prev/next=0 and the next allocation faults writing NULL->next
    // (cr2=0x8) in alloc_slot.  (Bug hit by Hyprland/Mesa worker threads; single-thread apps + apps
    // that only grow brk from the leader before spawning threads were unaffected.)
    int leadTid = tid;
    {
        int lead = task.processLeaderTid;
        if (lead >= 0 && lead < MAX_TASKS) {
            auto L = &g_tasks[lead];
            if (L.active && !L.exited && L.pml4Phys == task.pml4Phys) { task = L; leadTid = lead; }
        }
    }

    if (newBrk == 0)
        return cast(long)task.brkCurrent;

    if (newBrk < task.brkStart || newBrk > 0x8000000UL)
        return cast(long)task.brkCurrent;

    ulong oldAligned = (task.brkCurrent + 0xFFF) & ~0xFFFUL;
    ulong newAligned = (newBrk + 0xFFF) & ~0xFFFUL;

    if (newAligned > oldAligned) {
        auto heapRegion = addRegion(*task, oldAligned, newAligned,
                                    RegionType.Mapped, RegionPerms.ReadWrite,
                                    0, true);
        if (heapRegion is null) return cast(long)task.brkCurrent;
        // Defense-in-depth: NEVER re-map a page that is already live.  With leader routing
        // oldAligned is the true shared break so nothing in [oldAligned,newAligned) is mapped;
        // if that invariant is ever violated, refuse to clobber live heap/meta pages rather than
        // zero them (which is exactly the corruption this fix eliminates).
        for (ulong chk = oldAligned; chk < newAligned; chk += 4096) {
            if (userPageMapped(leadTid, chk)) { removeRegion(*task, oldAligned, newAligned); return cast(long)task.brkCurrent; }
        }
        // Allocate pages from oldAligned to newAligned
        ulong mappedBytes = 0;
        for (ulong pg = oldAligned; pg < newAligned; pg += 4096) {
            ulong phys = alloc_phys_page();
            if (phys == 0) {
                if (mappedBytes != 0) sys_munmap(oldAligned, mappedBytes, true);
                removeRegion(*task, oldAligned, newAligned);
                return cast(long)task.brkCurrent;
            }
            map_page_hhdm(phys, pg, PTE_PRESENT | PTE_RW | PTE_USER, &alloc_phys_page);
            physPageSetOwner(phys, heapRegion.objId, heapRegion.vmoObjId);
            mappedBytes += 4096;
        }
    }

    task.brkCurrent = newBrk;
    return cast(long)newBrk;
}

// ------------------------------------------------------------------
// Helper: case-insensitive/exact C-string comparison
// ------------------------------------------------------------------

private bool cstrEqK(const(char)* a, const(char)* b) {
    if (a is null || b is null) return false;
    while (*a != 0 && *b != 0) {
        if (*a != *b) return false;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

private bool isFreestandingExecName(const(char)* name) {
    return cstrEqK(name, "test-drm\0".ptr) ||
           cstrEqK(name, "drm-gpu-test\0".ptr) ||
           cstrEqK(name, "compositor\0".ptr) ||
           cstrEqK(name, "hello-gui\0".ptr) ||
           cstrEqK(name, "wl-probe\0".ptr);
}

// ------------------------------------------------------------------
// PIC (8259A) helpers
// ------------------------------------------------------------------

// Use outb/inb from core.io (already imported)
private void picIOwait() @nogc nothrow { outb(0x80, 0); }

// Remap PIC1→vectors 32-39, PIC2→vectors 40-47, then unmask kbd (IRQ1) and mouse (IRQ12).
private void initPIC() @nogc nothrow {
    // ICW1: start initialisation, edge-triggered, ICW4 needed
    outb(0x20, 0x11); picIOwait();
    outb(0xA0, 0x11); picIOwait();
    // ICW2: vector offsets
    outb(0x21, 0x20); picIOwait(); // PIC1 base = 32 (IRQ0→int 32)
    outb(0xA1, 0x28); picIOwait(); // PIC2 base = 40 (IRQ8→int 40)
    // ICW3
    outb(0x21, 0x04); picIOwait(); // PIC1: cascade on IRQ2
    outb(0xA1, 0x02); picIOwait(); // PIC2: cascade ID = 2
    // ICW4: 8086 mode
    outb(0x21, 0x01); picIOwait();
    outb(0xA1, 0x01); picIOwait();
    // OCW1: bit set = masked.  Unmask IRQ0 (timer), IRQ1 (kbd), IRQ2 (cascade).
    outb(0x21, cast(ubyte)~(0x01 | 0x02 | 0x04));
    // PIC2 mask: unmask bit 4 (IRQ12 = mouse)
    outb(0xA1, cast(ubyte)~0x10);           // unmask IRQ12
}

// Program PIT channel 0 to ~1000 Hz square wave so IRQ0 ticks every ~1 ms.
private void initPIT() @nogc nothrow {
    enum ushort divisor = 1193; // 1193182 Hz / 1193 ≈ 1000.15 Hz
    outb(0x43, 0x36);                              // ch0, lo/hi byte, mode 3
    outb(0x40, cast(ubyte)(divisor & 0xFF));
    outb(0x40, cast(ubyte)((divisor >> 8) & 0xFF));
}

// Send End-Of-Interrupt.  slave=true also sends EOI to PIC2 (for IRQ8-15).
private void picEOI(bool slave) @nogc nothrow {
    if (slave) outb(0xA0, 0x20);
    outb(0x20, 0x20);
}

// ── BSP Local-APIC timer = the real-hardware system tick ──────────────────────
// On UEFI laptops (Framework 13) the firmware routes the legacy PIT IRQ0 through
// the IOAPIC, not the 8259 PIC the kernel programmed — so the PIT tick never fires,
// g_pitMs freezes, clock_gettime stops advancing, and the compositor's repaint
// timerfd never expires (it builds its scanout buffers but never does the first
// modeset → no picture; verified: the boot log reaches addfb2 with no [irq0] tag).
// Drive the tick from the BSP's own local-APIC timer instead — per-CPU MSRs, no
// PIC/IOAPIC routing — on vector 0x20, the SAME vector the PIT used, so the
// existing irqIdx==0 handler runs unchanged.  The APs already do this (setupApTimer).
extern(C) void setupBspX2apic() @nogc nothrow;     // asm.S: enable x2APIC mode on this CPU

private enum uint X2APIC_EOI        = 0x80B;
private enum uint X2APIC_LVT_TIMER  = 0x832;
private enum uint X2APIC_TIMER_INIT = 0x838;
private enum uint X2APIC_TIMER_CUR  = 0x839;
private enum uint X2APIC_TIMER_DIV  = 0x83E;

private void apicWriteReg(uint reg, uint val) @nogc nothrow {
    asm @nogc nothrow {
        mov ECX, reg;
        mov EAX, val;
        xor EDX, EDX;
        wrmsr;
    }
}
private uint apicReadReg(uint reg) @nogc nothrow {
    uint outv;
    asm @nogc nothrow {
        mov ECX, reg;
        rdmsr;
        mov outv, EAX;
    }
    return outv;
}
// The local-APIC timer's input frequency, from CPUID.15h ECX = the core crystal
// clock (populated on modern Intel — Skylake+ / all 12th-gen+ parts, i.e. this
// Framework 13).  0 if the CPU doesn't report it.  This is the reliable rate source
// when the legacy PIT (and thus PIT-channel-2 calibration) is dead on UEFI laptops.
private uint apicCrystalHz() @nogc nothrow {
    uint crystal;
    asm @nogc nothrow {
        push RBX;
        mov EAX, 0x15;
        xor ECX, ECX;
        cpuid;
        mov crystal, ECX;   // ECX = core crystal clock frequency in Hz
        pop RBX;
    }
    return crystal;
}

// x2APIC End-Of-Interrupt (MSR 0x80B = 0).  MUST be sent from the irqIdx==0 tick
// handler so the local-APIC delivers the next timer interrupt.
public void lapicEOI() @nogc nothrow {
    asm @nogc nothrow {
        mov ECX, 0x80B;
        xor EAX, EAX;
        xor EDX, EDX;
        wrmsr;
    }
}

// Calibrate the local-APIC timer against PIT channel 2 (its counter is pollable via
// port 0x61 regardless of IRQ routing) and start it as a ~1000 Hz periodic tick on
// vector 0x20.  Then mask the PIC's PIT IRQ0 so a still-working legacy timer (e.g.
// in QEMU) can't double-tick.  Hang-safe: if channel 2 never reaches terminal count
// the spin is capped and we fall back to a conservative count so the clock still
// advances rather than freezing the boot.
private void startBspApicTimer() @nogc nothrow {
    setupBspX2apic();                          // ensure x2APIC mode (idempotent)
    apicWriteReg(X2APIC_TIMER_DIV, 0x3);       // divide bus clock by 16

    // --- measure APIC timer ticks over a ~10 ms PIT channel-2 window ---
    enum uint PIT_HZ   = 1193182;
    enum ushort window = cast(ushort)(PIT_HZ / 100);   // 10 ms ≈ 11931 PIT ticks

    ubyte p = cast(ubyte)((inb(0x61) & 0xFC) | 0x01);  // speaker off, ch2 gate on
    outb(0x61, p);
    outb(0x43, 0xB0);                                  // ch2, lo/hi, mode 0, binary
    outb(0x42, cast(ubyte)(window & 0xFF));
    outb(0x42, cast(ubyte)((window >> 8) & 0xFF));
    p = cast(ubyte)(inb(0x61) & 0xFE);                 // toggle gate low→high: (re)start
    outb(0x61, p);
    outb(0x61, cast(ubyte)(p | 0x01));

    apicWriteReg(X2APIC_LVT_TIMER, 0x10020);           // vec 0x20, one-shot, MASKED (measuring)
    apicWriteReg(X2APIC_TIMER_INIT, 0xFFFFFFFF);       // start counting down from max
    uint startCnt = apicReadReg(X2APIC_TIMER_CUR);

    bool done = false;
    for (ulong guard = 0; guard < 5_000_000UL; ++guard) {
        if (inb(0x61) & 0x20) { done = true; break; }  // ch2 OUT high → window elapsed
    }
    uint endCnt = apicReadReg(X2APIC_TIMER_CUR);

    // Prefer CPUID.15h (the crystal clock ÷16 divider → 1000 Hz) — it is exact and does
    // not depend on a working legacy PIT, which UEFI laptops (Framework 13) gate off.
    // Fall back to the PIT-channel-2 measurement, then to a fixed count.  'src': 0=fixed,
    // 1=PIT, 2=CPUID.
    uint initCount = 0x1000;
    int  src = 0;
    uint crystal = apicCrystalHz();
    if (crystal != 0) {
        uint c = crystal / 16 / TICK_HZ;               // crystal ÷16 ÷TICK_HZ
        if (c >= 200 && c <= 10_000_000) { initCount = c; src = 2; }
    }
    if (src == 0 && done && startCnt > endCnt) {
        // (startCnt-endCnt) APIC ticks in 10 ms → count for one 1/TICK_HZ s period.
        uint perTick = cast(uint)(cast(ulong)(startCnt - endCnt) * 100 / TICK_HZ);
        if (perTick >= 200 && perTick <= 10_000_000) { initCount = perTick; src = 1; }
    }

    outb(0x21, cast(ubyte)(inb(0x21) | 0x01));         // mask PIC1 IRQ0 (legacy PIT)
    // Make the 4 kHz poll the SOLE reader of the i8042: also mask IRQ1 (keyboard) and
    // IRQ12 (mouse).  If the PIC delivers IRQ12, handleMouseIRQ runs concurrently with
    // the poll and its reads interleave/duplicate the mouse packet bytes → desync/jump.
    // The poll drains both kbd + mouse, so masking these loses nothing.
    outb(0x21, cast(ubyte)(inb(0x21) | 0x02));         // mask IRQ1  (master PIC, bit 1)
    outb(0xA1, cast(ubyte)(inb(0xA1) | 0x10));         // mask IRQ12 (slave PIC, bit 4)

    apicWriteReg(X2APIC_LVT_TIMER, 0x20020);           // vec 0x20, PERIODIC (bit17), unmasked
    apicWriteReg(X2APIC_TIMER_INIT, initCount);
    // Direct-fb (visible on a serial-less laptop): the calibration result.  If this
    // says "fallback" or the count is implausible, the tick rate is wrong — which
    // makes the mouse jump (packets pile up between infrequent polls) and the 3 s
    // installer autostart stretch to many real seconds.
    console_framebuffer_write("\n[apic-timer] src=");
    console_framebuffer_write(src == 2 ? "CPUID.15h".ptr : (src == 1 ? "PIT-ch2".ptr : "FIXED-fallback".ptr));
    console_framebuffer_write(" crystalHz=0x"); { char[9] hb; char[16] hx="0123456789abcdef"; uint v=crystal; for(int i=7;i>=0;--i){hb[i]=hx[v&0xF];v>>=4;} hb[8]=0; console_framebuffer_write(hb.ptr); }
    console_framebuffer_write(" init=0x"); { char[9] hb; char[16] hx="0123456789abcdef"; uint v=initCount; for(int i=7;i>=0;--i){hb[i]=hx[v&0xF];v>>=4;} hb[8]=0; console_framebuffer_write(hb.ptr); }
    console_framebuffer_write("\n");
    klog("[apic-timer] BSP tick vec 0x20 src="); klog_hex(src);
    klog(" init="); klog_hex(initCount); klog("\n");
}

// ------------------------------------------------------------------
// PS/2 mouse initialisation
// ------------------------------------------------------------------

private void ps2WaitWrite() @nogc nothrow {
    // Wait until input buffer empty (bit 1 of status = 0)
    uint timeout = 100000;
    while (timeout-- && (inb(0x64) & 0x02)) {}
}
private void ps2WaitRead() @nogc nothrow {
    uint timeout = 100000;
    while (timeout-- && !(inb(0x64) & 0x01)) {}
}

private void initPS2Mouse() @nogc nothrow {
    // Enable both devices (keyboard + auxiliary/mouse).
    ps2WaitWrite(); outb(0x64, 0xAE);       // enable keyboard port
    ps2WaitWrite(); outb(0x64, 0xA8);       // enable aux (mouse) port
    // Configure the command byte: read, set our bits, write back.
    ps2WaitWrite(); outb(0x64, 0x20);       // read command byte
    ps2WaitRead();
    ubyte cb = inb(0x60);
    cb |= 0x01;  // enable IRQ1  (keyboard) — harmless if the PIC never delivers it
    cb |= 0x02;  // enable IRQ12 (mouse)
    cb |= 0x40;  // TRANSLATION on → scancode set 1 (matches g_sc1_keycode)
    cb &= ~0x10; // clear "keyboard clock disable" → keyboard active
    cb &= ~0x20; // clear "mouse clock disable"   → mouse active
    ps2WaitWrite(); outb(0x64, 0x60);       // write command byte
    ps2WaitWrite(); outb(0x60, cb);
    // RESET the mouse to a known STANDARD 3-byte relative mode.  UEFI firmware (e.g. the
    // Framework 13 EC) can leave the trackpad in a non-default / extended packet format —
    // Synaptics absolute (6-byte) or IntelliMouse (4-byte) — which our 3-byte parser
    // misframes, so the cursor "floats around and jumps".  0xFF resets it to defaults +
    // standard relative 3-byte packets (device id 0x00).
    ps2WaitWrite(); outb(0x64, 0xD4);
    ps2WaitWrite(); outb(0x60, 0xFF);       // reset
    // Drain the reset responses (0xFA ACK, then after the ~500 ms BAT self-test: 0xAA, 0x00).
    // Generous bounded waits cover the self-test without hanging if no device answers.
    foreach (_drain; 0 .. 3) {
        uint t = 8_000_000;
        while (t-- != 0 && !(inb(0x64) & 0x01)) {}
        if (inb(0x64) & 0x01) inb(0x60);
    }
    // Set defaults (100 Hz, 4 cnt/mm, scaling 1:1, stream mode) — normalizes sensitivity.
    ps2WaitWrite(); outb(0x64, 0xD4);
    ps2WaitWrite(); outb(0x60, 0xF6);
    ps2WaitRead();  inb(0x60);              // discard ACK
    // Mouse: enable data reporting (stream mode).
    ps2WaitWrite(); outb(0x64, 0xD4);       // route next byte to mouse
    ps2WaitWrite(); outb(0x60, 0xF4);       // enable reporting
    ps2WaitRead();  inb(0x60);              // discard ACK
    // Keyboard: enable scanning (0xF4 goes to the keyboard, the default port-1 target).
    ps2WaitWrite(); outb(0x60, 0xF4);
    ps2WaitRead();  inb(0x60);              // discard ACK
}

// ------------------------------------------------------------------
// PS/2 IRQ handlers
// ------------------------------------------------------------------

// State machine for extended (0xE0) scancodes
private __gshared bool g_kbd_extended = false;

// Decode ONE keyboard scancode byte (set 1, controller-translated) into the input
// ring.  Shared by the IRQ1 handler and the PIT-tick poll so the 0xE0-extended
// state stays consistent no matter which path drains the byte.
private void ps2FeedKbdByte(ubyte sc) @nogc nothrow {
    if (sc == 0xE0) { g_kbd_extended = true; return; }
    bool extended = g_kbd_extended;
    g_kbd_extended = false;

    bool release = (sc & 0x80) != 0;
    ubyte key    = sc & 0x7F;

    ushort code;
    if (extended) {
        // Map common E0 keys to Linux keycodes
        switch (key) {
            case 0x48: code = 103; break; // KEY_UP
            case 0x50: code = 108; break; // KEY_DOWN
            case 0x4B: code = 105; break; // KEY_LEFT
            case 0x4D: code = 106; break; // KEY_RIGHT
            case 0x1C: code = 96;  break; // KEY_KPENTER
            case 0x35: code = 98;  break; // KEY_KPSLASH
            case 0x47: code = 102; break; // KEY_HOME
            case 0x4F: code = 107; break; // KEY_END
            case 0x49: code = 104; break; // KEY_PAGEUP
            case 0x51: code = 109; break; // KEY_PAGEDOWN
            case 0x52: code = 110; break; // KEY_INSERT
            case 0x53: code = 111; break; // KEY_DELETE
            case 0x38: code = 100; break; // KEY_RIGHTALT
            case 0x1D: code = 97;  break; // KEY_RIGHTCTRL
            case 0x5B: code = 125; break; // KEY_LEFTMETA  (Super) — GUI G15 launcher
            case 0x5C: code = 126; break; // KEY_RIGHTMETA (Super)
            case 0x5D: code = 127; break; // KEY_COMPOSE   (Menu)
            default:   code = 0;   break;
        }
    } else {
        code = g_sc1_keycode(key);
    }
    if (code == 0) return;

    input_enqueue(true, EV_KEY, code, release ? 0 : 1);
    input_enqueue(true, EV_SYN, SYN_REPORT, 0);   // SYN_REPORT after each key event
}

private void handleKbdIRQ() @nogc nothrow {
    // Read all available bytes from the keyboard data port
    while (inb(0x64) & 0x01) ps2FeedKbdByte(inb(0x60));
}

// 3-byte PS/2 mouse packet accumulator
private __gshared ubyte[3] g_mouse_buf;
private __gshared int      g_mouse_idx = 0;
// Last reported button bitmask (bit0 left, bit1 right, bit2 middle).  evdev only
// reports EV_KEY transitions, not level — libinput/Hyprland treat a repeated
// press without an intervening release as a protocol error, so we diff state and
// emit a button event only when it actually changes (GUI roadmap G3).
private __gshared ubyte g_mouse_prevButtons = 0;
private __gshared uint  g_btnLogN = 0;   // bounded [btn] probe: are button packets reaching us?

// Decode ONE PS/2 aux (mouse) byte, accumulating 3-byte packets.  Shared by the
// IRQ12 handler and the PIT-tick poll so packet framing stays consistent.
// DIAG (real-HW trackpad): a ring of the last raw aux bytes + the last framed dx/dy,
// shown by a top-of-screen HUD so the ACTUAL packet format the Framework trackpad
// sends can be read off a photo (3-byte relative? 4-byte IntelliMouse? 6-byte
// Synaptics absolute?).  g_mouseHud gates it; set false once the format is known.
__gshared ubyte[16] g_mdbg;
__gshared uint  g_mdbgIdx;
__gshared int   g_mdbgDx, g_mdbgDy;
__gshared bool  g_mouseHud = false;   // cursor fixed (IRQ1/12 masked + strict framing) — HUD off
private void mouseHudDraw() @nogc nothrow {
    if (!g_mouseHud) return;
    static immutable char[16] hx = "0123456789abcdef";
    char[96] b; int n = 0;
    void put(char c) @nogc nothrow { if (n < 95) b[n++] = c; }
    void dec(int v) @nogc nothrow {
        if (v < 0) { put('-'); v = -v; }
        char[12] t; int m = 0;
        if (v == 0) t[m++] = '0';
        while (v) { t[m++] = cast(char)('0' + v % 10); v /= 10; }
        while (m) put(t[--m]);
    }
    put('M'); put(' ');
    for (int i = 0; i < 16; i++) {
        ubyte v = g_mdbg[(g_mdbgIdx - 16 + i) & 15];
        put(hx[(v >> 4) & 0xF]); put(hx[v & 0xF]); put(' ');
    }
    put('d'); put('='); dec(g_mdbgDx); put(','); dec(g_mdbgDy);
    b[n] = 0;
    fb_draw_hud(b.ptr);
}

private void ps2FeedMouseByte(ubyte b) @nogc nothrow {
    g_mdbg[g_mdbgIdx & 15] = b; ++g_mdbgIdx;   // DIAG: capture raw stream
    if ((g_mdbgIdx & 7) == 0) mouseHudDraw();  // throttle the HUD redraw
    // Resync on the packet HEADER (byte 0).  A real movement header has bit 3 = 1 AND
    // both overflow bits (6,7) = 0.  The PS/2 protocol/error responses the trackpad emits
    // — 0xFA (ACK), 0xFE (resend), 0xFF (error), 0xAA (self-test), 0xEE (echo) — ALL have
    // bit 3 set too, so a bit-3-only check accepts them as a header and desyncs the frame
    // (cursor jumps).  Requiring the overflow bits clear rejects every one of them (they
    // all have bit 6 or 7 set), while still accepting real headers 0x08..0x3F.
    if (g_mouse_idx == 0 && (!(b & 0x08) || (b & 0xC0) != 0)) return;
    g_mouse_buf[g_mouse_idx++] = b;
    if (g_mouse_idx < 3) return;
    g_mouse_idx = 0;

    ubyte status = g_mouse_buf[0];
    int dx = cast(int)g_mouse_buf[1];
    int dy = cast(int)g_mouse_buf[2];
    // Sign-extend using bit 4/5 of status byte
    if (status & 0x10) dx |= 0xFFFFFF00;
    if (status & 0x20) dy |= 0xFFFFFF00;
    // PS/2 Y axis is inverted relative to screen
    dy = -dy;

    // Reject packets whose motion overflowed a single byte (status bit 6 = X-overflow,
    // bit 7 = Y-overflow): the dx/dy are then meaningless and teleport the cursor.  This
    // also filters the garbage deltas that appear when bytes are lost to a too-slow drain
    // (the i8042 output buffer is 1 byte deep), the main cause of cursor "jumping".
    if (status & 0xC0) { dx = 0; dy = 0; }

    // Backstop: DROP (don't clamp) implausibly large single-packet deltas.  A misframed
    // header with a sign bit set + a small magnitude byte sign-extends to ±256, so a
    // clamp would still move the cursor by the clamp limit — dropping avoids the jump
    // entirely.  A real per-sample move stays well under this, so normal motion passes.
    enum int MAXD = 80;
    if (dx > MAXD || dx < -MAXD || dy > MAXD || dy < -MAXD) { dx = 0; dy = 0; }
    g_mdbgDx = dx; g_mdbgDy = dy;   // DIAG: last framed delta for the HUD

    bool any = false;
    if (dx != 0 || dy != 0) {
        // Stamp the kernel cursor at the accumulated absolute position (snappy, drawn by us),
        // and report RELATIVE deltas to userspace.
        //
        // This used to report EV_ABS with the absolute position, chosen so Weston's pointer
        // tracked the kernel-drawn cursor exactly with no acceleration drift.  Under Hyprland
        // that path delivers nothing: measured, the compositor reads every event we queue
        // (mouseEnq=64 mouseRead=64, an exact 1:1) and libinput accepts the device
        // ("libinput: New device Virtual Mouse: 1-2"), yet clicks reach no client -- a click
        // aimed at the Activities close button, with the cursor visibly on it, did nothing.
        //
        // libinput's support for an ABSOLUTE pointing device that is neither a touchscreen nor
        // a tablet is the weak point: EV_REL with REL_X/REL_Y is the shape every pointer stack
        // handles without special-casing.  The kernel already receives relative deltas from the
        // PS/2 packet, so this reports what the hardware actually said and keeps the absolute
        // accumulation purely for drawing our own cursor.
        //
        // The drift the old comment worried about is real and is handled in config: Hyprland's
        // input:accel_profile = flat with sensitivity 0 applies no acceleration, so one device
        // unit stays one pixel and the compositor's pointer tracks the kernel cursor 1:1.
        cursorSetPos(cursorGetX() + dx, cursorGetY() + dy);
        input_enqueue(false, EV_REL, REL_X, dx);
        input_enqueue(false, EV_REL, REL_Y, dy);
        any = true;
    }

    // Button state — emit only the bits that changed since the last packet.
    ubyte cur     = cast(ubyte)(status & 0x07);
    ubyte changed = cast(ubyte)(cur ^ g_mouse_prevButtons);
    // Probe: does a physical button press reach the kernel at all?  Clicks demonstrably do not
    // reach clients while keyboard input does, and that could break in three different places --
    // the PS/2 packet never arriving, the event never being enqueued, or the compositor never
    // reading it.  This settles the first two.  Bounded so a real session cannot flood the log.
    if (changed != 0 && g_btnLogN < 12) {
        ++g_btnLogN;
        klog("[btn] state=0x"); klog_hex(cur);
        klog(" changed=0x"); klog_hex(changed);
        klog(" (L="); klog_dec((cur & 0x01) ? 1 : 0); klog(")\n");
    }
    if (changed & 0x01) { input_enqueue(false, EV_KEY, BTN_LEFT,   (cur & 0x01) ? 1 : 0); any = true; }
    if (changed & 0x02) { input_enqueue(false, EV_KEY, BTN_RIGHT,  (cur & 0x02) ? 1 : 0); any = true; }
    if (changed & 0x04) { input_enqueue(false, EV_KEY, BTN_MIDDLE, (cur & 0x04) ? 1 : 0); any = true; }
    g_mouse_prevButtons = cur;

    // One SYN_REPORT terminates each evdev frame, but only when the frame
    // carried at least one motion/button event.
    if (any) input_enqueue(false, EV_SYN, SYN_REPORT, 0);
}

private void handleMouseIRQ() @nogc nothrow {
    while (inb(0x64) & 0x21) {      // output-buffer-full AND aux-data bit
        if (!(inb(0x64) & 0x20)) break; // not aux data — skip
        ps2FeedMouseByte(inb(0x60));
    }
}

// IRQ-INDEPENDENT PS/2 drain.  On real UEFI hardware (e.g. this Framework laptop)
// the legacy 8259 PIC often does NOT deliver IRQ1/IRQ12 — those route through the
// IOAPIC instead — so handleKbdIRQ/handleMouseIRQ never fire and input is dead even
// though the i8042 works (the survey's self-test passed).  The PIT IRQ0 timer DOES
// fire reliably, so we drain the i8042 here on every tick, routing each byte by the
// status-register aux bit (0x20) to the shared keyboard/mouse decoders.  In QEMU
// (where IRQ1/12 work) this is a harmless backstop — the shared decode state keeps
// it consistent with the IRQ path.
public void ps2PollUnified() @nogc nothrow {
    // Read AT MOST ONE byte per call.  The i8042 output buffer is only 1 byte deep, and
    // after inb(0x60) the OUTPUT-BUFFER-FULL flag (status bit 0) takes a few µs to clear.
    // A tight re-read loop races that clear on fast real hardware and reads port 0x60
    // again while it is stale/empty → returns 0xFF (empty read) or a duplicate byte,
    // which injects garbage into the 3-byte mouse packet stream and desyncs the framing
    // (the cursor jumps).  The fast 4 kHz tick already guarantees every byte is caught,
    // so one-byte-per-tick is both correct and sufficient (and drains keyboard too).
    ubyte status = inb(0x64);
    if (!(status & 0x01)) return;                   // nothing pending
    ubyte data = inb(0x60);
    if (status & 0x20) ps2FeedMouseByte(data);      // aux → mouse
    else               ps2FeedKbdByte(data);        // else → keyboard
}

// IDENTITY_DOMAIN §3/§10: the `idps` process-identity table — pid, parent, and
// the security-domain each live task is labelled with.  One-shot for now (the
// interactive debug command is wired in §10); proves fork/clone inheritance —
// every process descends from PID1 (System) and carries that label.
__gshared bool g_idpsDumped = false;
private void identityDumpProcesses() @nogc nothrow {
    if (g_idpsDumped) return;
    g_idpsDumped = true;
    klog("[idps] pid parent identity\n");
    for (int i = 0; i < MAX_TASKS; ++i) {
        if (!g_tasks[i].active || g_tasks[i].exited) continue;
        klog("[idps]  "); klog_hex(cast(ulong)i);
        klog(" <- "); klog_hex(cast(ulong)g_tasks[i].parentId);
        klog(" id="); klog_hex(cast(ulong)g_tasks[i].identityObjId);
        klog(" ["); identityNamePrint(g_tasks[i].identityObjId); klog("]\n");
    }
}

// ------------------------------------------------------------------
// Syscall dispatch
// ------------------------------------------------------------------

// g_task_fsbase / g_task_fsbase_set are in exports.d
extern __gshared ulong[1024] g_task_fsbase;
extern __gshared bool[1024]  g_task_fsbase_set;

// Toggle for the very verbose per-syscall trace ([sc] t=/n=).  Off by default.
__gshared bool g_traceSyscalls = false;

// Phase 2: amortization counter for objReconcileFds()/objStats() (see dispatchSyscall).
__gshared uint g_objReconcileCtr = 0;

// PERF: dump per-task CPU share (permil = tenths of a percent) over the interval,
// so a busy-looping task that starves the compositor stands out.  Resets counters.
private void schedProfStats() {
    ulong total = 0;
    foreach (i; 0 .. MAX_TASKS) total += g_schedCyc[i];
    if (total == 0) return;
    klog("[sched] cpu_permil:");
    foreach (i; 0 .. MAX_TASKS) {
        if (g_schedCyc[i] == 0) continue;
        const ulong permil = g_schedCyc[i] * 1000 / total;
        if (permil < 5) continue;                 // hide <0.5%
        klog(" t"); klog_dec(cast(ulong)i);
        klog("="); klog_dec(permil);
        klog("("); if (g_taskExecName[i] !is null) klog(g_taskExecName[i]); else klog("?"); klog(")");
    }
    klog("\n");
    foreach (i; 0 .. MAX_TASKS) { g_schedCyc[i] = 0; g_schedN[i] = 0; }
}

// Bring-up: bounded counter for the [initfail] syscall-error trace below.
private __gshared int g_initFailLogN = 0;

private void dispatchSyscall(int tid) {
    ulong rax = x64LastSyscallRax;
    ulong rdi = x64LastSyscallRdi;
    ulong rsi = x64LastSyscallRsi;
    ulong rdx = x64LastSyscallRdx;
    ulong r10 = x64LastSyscallR10;
    ulong r8  = x64LastSyscallR8;
    ulong r9  = x64LastSyscallR9;

    // Freeze probe: snapshot every syscall ENTRY.  During a hard freeze the kernel loop is stuck
    // inside ONE handler — entries stop, so the last snapshot names the stuck syscall + task, and
    // the cursor-IRQ overlay shows it with its in-flight time.
    g_freezeSysNr = rax; g_freezeSysTid = tid; g_freezeSysStartMs = pitMs();

    ++g_syscallScreenTrace;
    const bool screenTraceThis =
        g_syscallScreenTrace <= 96 ||
        (g_syscallScreenTrace & 0xFFu) == 0;
    if (screenTraceThis) {
        bootProgressHex("sc", rax);
    }

    // Per-syscall trace — extremely verbose (hundreds of thousands of lines) and a
    // heavy perf drain since every syscall writes to the serial port.  Gated off by
    // default now that bring-up is past the syscall-by-syscall debugging stage.
    if (g_traceSyscalls) {
        kchar('S');
        klog("[sc] t="); klog_hex(cast(ulong)tid); klog(" n="); klog_hex(rax); klog("\n");
    }

    auto task = &g_tasks[tid];
    // Select this task's process fd table before servicing the syscall, so each
    // process sees its own descriptors (fork gives the child an independent copy).
    fdtabSetActive(task.fdTabId);
    capTableSetActive(task.capTabId);
    physSetActiveUntyped(task.untypedObjId);
    userSetActiveSubject(task.userObjId);

    // Phase 2 (roadmap/OBJECT_OS_ROADMAP.md): keep the core.objmgr object table
    // mirrored onto the now-active fd table, and periodically run the object-graph
    // reconciliation + research self-test proofs.  This block costs ~hundreds of
    // millions of cycles per run (graph walks + crypto self-tests), so running it
    // every 256 syscalls dominated runtime — Hyprland issues ~hundreds of syscalls
    // per frame, so it fired roughly once per frame and pinned the desktop at ~5
    // fps.  These are non-functional proofs/audits; amortize them over 64k syscalls
    // so they remain runtime evidence without throttling interactive work.
    // WiFi/real-HW COMPOSITOR-FREEZE FIX: this whole block (object-graph reconcile + ~40 one-shot
    // self-test proofs + graph fuzz/scale suites + ~40 stats klog dumps) costs hundreds of millions of
    // cycles per firing and renders dozens of text lines to the framebuffer.  Gated per-SYSCALL, it
    // fired every ~1M syscalls — fine for QEMU (NM idles, low syscall rate) but on real hardware NM
    // actively drives the AX210, so the syscall rate + object graph climb until this block fires often
    // enough (and costs enough each time) to STARVE the compositor -> the desktop freezes ~1-3 min in
    // (kernel still alive: cursor overlay keeps moving) while weston never gets scheduled.  These are
    // non-functional audits/proofs, so gate them to essentially-never (~1e9 syscalls) — removes the
    // starvation without affecting the OS.  (Was 0xFFFFF.)
    if (((++g_objReconcileCtr) & 0x3FFFFFFF) == 0) {
        objReconcileTasks();
        objReconcileFds();
        objReconcileRegions();
        orgReconcileOwnership(); // ORG P3: process/memory ownership edges
        orgReconcileFdEdges();   // ORG P3: fd capability + epoll observer edges
        ipcSelfTest(); // Phase 7: one-shot proof the IPC router round-trips
        deviceSelfTest(); // Phase 8: one-shot proof /dev resolves to Device objects
        nsSelfTest(); // Phase 9: one-shot proof per-process namespaces clone & route
        userSelfTest(); // Phase 10: one-shot proof identity/passwd derive from User objects
        adminSelfTest(); // IR-P3: one-shot proof typed admin caps gate actions
        serviceSelfTest(); // Phase 10: one-shot proof services are rights-narrowed
        servicePhase5SelfTest(); // IR-P5: dependency-ordered start, FS-first migration, versioning
        windowSelfTest(); // Phase 11: one-shot proof Output/Window/Surface objects
        identitySelfTest(); // IDENTITY_DOMAIN P2: one-shot proof identity create/lookup/validate/freeze
        idprocSelfTest();   // IDENTITY_DOMAIN P3: one-shot proof inherit / transition-gate / cap⊆ceiling
        idnsSelfTest();     // IDENTITY_DOMAIN P4: one-shot proof per-identity disjoint roots + shares
        idipcSelfTest();    // IDENTITY_DOMAIN P5: one-shot proof same-domain OK / cross denied / brokered allowed
        idwinSelfTest();    // IDENTITY_DOMAIN P6: one-shot proof window identity stamped from owner / unspoofable / border
        identityDumpProcesses(); // IDENTITY_DOMAIN P3: one-shot idps process-identity table
        compositorIdentitySelfTest(); // GUI: one-shot proof of trusted, unspoofable identity borders
        linuxSelfTest(); // Phase 12: one-shot proof the Linux-compat subtree & gate
        linuxPersSelfTest(); // IR-P7: ephemeral-root sandbox + ns/cap op translation + gated /dev
        kernelCensusReport(); // Phase 13: Milestone 3 proof once the graph is populated
        orgSelfTest(); // ORG P2: one-shot proof of typed edges + weak coherence
        orgIntegReport(); // ORG P3: one-shot proof the real graph passes I1/I4 audit
        orgApiSelfTest(); // ORG P4: one-shot proof of query/reachability/ns-validation
        orgCycleSelfTest(); // ORG P5: one-shot proof of cycle prevention + SCC GC
        orgGcSelfTest(); // ORG P6: one-shot proof of invariant/quarantine/GC/rebuild
        orgSecuritySelfTest(); // ORG P7: one-shot proof of label/rights escalation rejection
        capRevokeClosureSelfTest(); // ORG P7.2: one-shot proof of transitive revocation
        orgValidatorSelfTest(); // ORG P8: one-shot proof of the validator daemon + control
        orgVizSelfTest(); // ORG P9: one-shot proof of DOT/stats graph export
        orgLinuxSelfTest(); // ORG P10: one-shot proof SCM cycle GC + sandboxed edges
        orgDistSelfTest(); // ORG P11: one-shot proof of federated refs + leased edges
        orgDistTick(1);    // ORG P11: advance the distributed clock / expire stale leases
        orgTestSuite();    // ORG P12: one-shot invariant + GC-fuzz + scale test suite
        untypedSelfTest(); // IMMUTABLE_ROOTLESS §1.4: one-shot proof no ambient allocation
        storeSelfTest(); // IMMUTABLE_ROOTLESS §4: content-addr store + verity + split + generations
        updateSelfTest(); // IMMUTABLE_ROOTLESS §6: A/B slots + signed apply + anti-downgrade + auto-rollback
        cryptoSelfTest(); // IMMUTABLE_ROOTLESS §8.1/8.2: real SHA-256/HMAC + measured/verified boot
        hardeningSelfTest(); // IMMUTABLE_ROOTLESS §8.3/8.4: W^X / NX policy + capability audit log
        distosSelfTest(); // IMMUTABLE_ROOTLESS §9: network-transparent refs + macaroon caps + dist store
        libsecipcSelfTest(); // SECURE_IPC P0: X25519/HKDF/ChaCha20-Poly1305/framing (RFC vectors)
        secipcSelfTest(); // SECURE_IPC P1: identity certs + broker-signed descriptors + cap-gated routing
        secsessionSelfTest(); // SECURE_IPC P2: signed-DH handshake + HKDF keys + AEAD record layer
        seclifeSelfTest(); // SECURE_IPC P3: rekey + revocation + failure handling (fail-closed)
        secobjSelfTest(); // SECURE_IPC P4: channel/session/cert/descriptor objects + Linux AEAD shim
        sechardSelfTest(); // SECURE_IPC P5: const-time + nonce-reuse + zeroize + parser fuzz + state machine
        // ORG P8: drive the runtime validator daemon one bounded step per reconcile
        // tick — it cycles reachability → SCC → invariant → GC → audit across ticks,
        // epoch-driven, never stalling the scheduler (replaces the old inline pass).
        orgValidatorTick();
        if ((g_objReconcileCtr & 0x3FFF) == 0) {
            objStats();
            capStats();
            ipcStats();
            deviceStats();
            nsStats();
            userStats();
            adminStats();
            serviceStats();
            windowStats();
            identityStats(); // IDENTITY_DOMAIN P2: identity count / created / frozen
            domainStats();   // DOMAIN_MANAGER DM0: domain count / created / frozen / objects
            idnsStats();     // IDENTITY_DOMAIN P4: ns clones / shares / roots
            idipcStats();    // IDENTITY_DOMAIN P5: gate checks / allow / deny
            idwinStats();    // IDENTITY_DOMAIN P6: windows stamped / hook installed
            presentProfStats(); // PERF: frame rate + kernel-present share of each frame
            schedProfStats();   // PERF: per-task CPU share (find a hog starving the compositor)
            fdReadableStats();  // PERF: which fd type keeps reporting ready (busy-spin source)
            inputStats();       // R1: input events enqueued / dropped / read
            linuxStats();
            linuxPersStats();
            kernelCensusStats();
            orgAudit(); // refresh I1/I4 violation counters for the stats line
            orgStats();
            orgValidatorStats();
            auditStats();
            orgDistStats();
            untypedStats();
            storeStats();
            updateStats();
            cryptoStats();
            hardeningStats();
            distosStats();
            secipcStats();
            secsessionStats();
            secobjStats();
            sechardStats();
        }
    }

    long ret  = 0;

    switch (rax) {
        // mmap — use per-task bump pointer so we never collide with the stack.
        // When fd is a DRM device and offset is non-zero (= physical framebuffer
        // address from MAP_DUMB), map those existing physical pages directly
        // instead of allocating fresh anonymous pages.
        case 9: {
            enum MAP_FIXED = 0x10;
            enum MAP_ANONYMOUS = 0x20;
            ulong mlen    = rsi;
            ulong mflags  = r10;
            ulong mfd     = r8;
            ulong moffset = r9;
            if (mlen == 0) {
                klog("[mmap-einval] len=0 flags="); klog_hex(mflags);
                klog(" fd="); klog_hex(mfd); klog(" off="); klog_hex(moffset); klog("\n");
                ret = -22; break;
            }
            ulong alignedLen = (mlen + 0xFFF) & ~0xFFFUL;
            ulong vaddr;
            if (mflags & MAP_FIXED) {
                if (rdi == 0 || (rdi & 0xFFF) != 0) { ret = -22; break; }
                vaddr = rdi;
            } else {
                vaddr = task.mmapNext;
                task.mmapNext += alignedLen;
            }
            x64WriteCR3(task.pml4Phys);
            ulong numPgs = alignedLen >> 12;
            bool mmapOk = true;

            // Shared fd backings (DRM dumb-buffer mmap and memfd mmap) now route
            // through the fd object's mmap op instead of peeking at File.type here.
            ulong backingPhys = 0;
            uint vmoObjId = 0;
            bool useObjectBacking = false;
            if (mfd < 1024) {
                long backing = fdMmapBacking(mfd, moffset, &backingPhys,
                                             null, &vmoObjId,
                                             &useObjectBacking);
                if (backing <= 0) useObjectBacking = false;
            }

            // File-backed mmap (MAP_PRIVATE of a regular file): the dynamic linker
            // maps each shared object's segments this way.  Allocate fresh pages
            // and copy the file's bytes at `moffset`, zero-filling past EOF.  Pages
            // stay writable + executable (the kernel never sets NX, so PROT_EXEC is
            // satisfied and ld.so can write relocations); ld.so tightens perms via
            // mprotect afterwards.
            bool useFile = !useObjectBacking &&
                           (mflags & MAP_ANONYMOUS) == 0 &&
                           cast(long)mfd >= 0 && mfd < 1024;

            ulong regionPhysBase = useObjectBacking ? backingPhys : 0;

            auto mappedRegion = addRegion(*task, vaddr, vaddr + alignedLen,
                                           RegionType.Mapped,
                                           RegionPerms.ReadWrite,
                                           regionPhysBase,
                                           !useObjectBacking,
                                           vmoObjId);
            if (mappedRegion is null) {
                if ((mflags & MAP_FIXED) == 0) task.mmapNext -= alignedLen;
                ret = -12;
                break;
            }

            ulong mappedPgs = 0;
            for (ulong pg = 0; pg < numPgs; pg++) {
                ulong phys = useObjectBacking ? (backingPhys + pg * 4096)
                           : alloc_phys_page();
                if (phys == 0) { mmapOk = false; break; }
                map_page_hhdm(phys, vaddr + pg * 4096,
                              PTE_PRESENT | PTE_RW | PTE_USER, &alloc_phys_page);
                if (useFile)
                    mmapCopyFileRange(cast(int)mfd, moffset + pg * 4096,
                                      cast(ubyte*)phys_to_virt(phys), 4096);
                physPageSetOwner(phys, mappedRegion.objId, mappedRegion.vmoObjId);
                ++mappedPgs;
            }
            if (mmapOk) {
                ret = cast(long)vaddr;
                // Diagnostic: log file-backed maps so a crash RIP inside a dlopen'd
                // .so can be mapped back to a base.
                //
                // The threshold used to be 1 MiB, which hid the mappings that matter
                // most: drm-backend.so is 0xd7000 (880 KiB) and libexec_weston.so.0 is
                // 0x8b000 (556 KiB), so the ONLY line ever printed was libweston-14.so.0
                // and a crash RIP in the DRM backend could not be attributed to anything.
                // 64 KiB still skips the small-fry without hiding a real module.
                if (useFile && alignedLen >= 0x10000) {
                    klog("[mmap-so] base="); klog_hex(vaddr);
                    klog(" len="); klog_hex(alignedLen);
                    klog(" fd="); klog_hex(mfd); klog("\n");
                }
            } else {
                if (mappedPgs != 0)
                    sys_munmap(vaddr, mappedPgs * 4096, mappedRegion.owned);
                removeRegion(*task, vaddr, vaddr + alignedLen);
                if ((mflags & MAP_FIXED) == 0) task.mmapNext -= alignedLen;
                ret = -12;
            }
            break;
        }

        // mremap(old_addr, old_size, new_size, flags, new_addr)
        // Only the wl_shm pool-growth pattern is supported: a shared, memfd/VMO-
        // backed mapping is re-pointed at the memfd's current (ftruncate-grown)
        // physical backing.  The compositor's wayland-shm uses this to enlarge a
        // pool; everything else gets ENOSYS so glibc/GIO fall back to malloc/copy.
        case 25: {
            enum MREMAP_MAYMOVE = 1;
            ulong mrOld   = rdi;
            ulong mrOldSz = rsi;
            ulong mrNewSz = rdx;
            ulong mrFlags = r10;
            if (mrNewSz == 0) { ret = -22; break; }              // EINVAL
            ulong mrOldAligned = (mrOldSz + 0xFFF) & ~0xFFFUL;
            ulong mrNewAligned = (mrNewSz + 0xFFF) & ~0xFFFUL;
            auto mrR = findRegion(*task, mrOld);
            if (mrR is null || mrR.vmoObjId == 0 ||
                mrR.type != RegionType.Mapped) { ret = -38; break; }  // ENOSYS
            // Capture region fields before any addRegion/removeRegion churns the
            // table (swap-remove would invalidate the pointer).
            ulong mrStart = mrR.start;
            ulong mrEnd   = mrR.end;
            uint  mrVmo   = mrR.vmoObjId;
            ulong mfSize  = 0;
            ulong mfPhys  = memfdPhysByVmo(mrVmo, &mfSize);
            if (mfPhys == 0) { ret = -38; break; }                // not a live memfd
            // Same-or-smaller: keep the existing mapping (it already covers it).
            if (mrNewAligned <= (mrEnd - mrStart)) { ret = cast(long)mrOld; break; }
            if ((mrFlags & MREMAP_MAYMOVE) == 0) { ret = -12; break; }  // ENOMEM
            if (mrNewAligned > mfSize) { ret = -22; break; }      // backing too small
            x64WriteCR3(task.pml4Phys);
            ulong mrVa = task.mmapNext;
            task.mmapNext += mrNewAligned;
            auto mrNew = addRegion(*task, mrVa, mrVa + mrNewAligned,
                                   RegionType.Mapped, RegionPerms.ReadWrite,
                                   mfPhys, false, mrVmo);
            if (mrNew is null) { task.mmapNext -= mrNewAligned; ret = -12; break; }
            ulong mrPgs = mrNewAligned >> 12;
            for (ulong pg = 0; pg < mrPgs; pg++) {
                map_page_hhdm(mfPhys + pg * 4096, mrVa + pg * 4096,
                              PTE_PRESENT | PTE_RW | PTE_USER, &alloc_phys_page);
                physPageSetOwner(mfPhys + pg * 4096, mrNew.objId, mrNew.vmoObjId);
            }
            // Drop the old mapping (shared memfd pages must NOT be freed).
            sys_munmap(mrStart, mrEnd - mrStart, false);
            removeRegion(*task, mrStart, mrEnd);
            ret = cast(long)mrVa;
            break;
        }

        // brk
        case 12:
            ret = brkTask(tid, rdi);
            break;

        // clone / fork (clone with SIGCHLD flags acts like fork)
        case 56:
            // TEMP boot-hang trace: is clone() even reached?  libudev-zero spawns one
            // pthread per /sys/dev/char entry and joins them; no [clone] line in the boot
            // log means the threads were never created and the join can never return.
            klog("[trace] clone flags="); klog_hex(rdi);
            klog(" stack="); klog_hex(rsi); klog("\n");
            // clone(flags=rdi, stack=rsi, ptid=rdx, ctid=r10, tls=r8).
            // CLONE_VM ⇒ thread creation (pthread_create / std::thread): a new
            // task sharing this address space, running on the supplied stack.
            if (rdi & CLONE_VM) {
                ret = cast(long)cloneThread(tid, rdi, rsi, rdx, r10, r8);
                if (ret > 0)
                    task.regs[REG_RAX] = cast(ulong)linuxTidForTask(cast(int)ret);
                else {
                    task.regs[REG_RAX] = cast(ulong)ret; // negative errno
                    return;
                }
                // vfork (posix_spawn): the child shares this address space and
                // runs to execve()/_exit() on its own stack; suspend the parent
                // until then.  This avoids fork's deep copy of the address space
                // (which would inherit locked mutexes from other threads and
                // deadlock the child before it can exec).
                if (rdi & CLONE_VFORK) {
                    int childTid = cast(int)ret;
                    g_vforkParentPlus1[childTid] = tid + 1;
                    task.waiting = true;   // resumed by resumeVforkParent() on exec/exit
                    scheduleNext();         // run the child now
                }
                return;
            }
            // No shared VM: treat as fork (clone with a fresh address space).
            goto case 57;

        // fork
        case 57:
        // vfork (treat as fork)
        case 58:
            ret = cast(long)forkTask(tid);
            if (ret > 0) {
                // Parent gets child pid; child already has RAX=0 in its Task.regs
                task.regs[REG_RAX] = cast(ulong)linuxPidForTask(cast(int)ret);
            } else {
                // fork FAILED (forkTask returns -12 ENOMEM on slot exhaustion).  Without this
                // else, RAX keeps the syscall number (57) → fork() looks like it returned a bogus
                // positive child pid, so callers that check `pid < 0` (e.g. the panel's epin_spawn)
                // never see the failure and store a fake "live child".  Return the negative errno.
                task.regs[REG_RAX] = cast(ulong)(ret < 0 ? ret : -12 /*ENOMEM*/);
            }
            return; // already set return value

        // execve
        case 59:
            ret = execveTask(tid, rdi, rsi, rdx);
            if (ret == 0) {
                // execve succeeded — re-enter userspace from scratch
                // The task registers were reset by execveTask
                return;
            }
            break;

        // Z4a.7 / Track B0 + native ABI (HOS_SYS_QUERY): handled in the OUTER dispatcher so
        // spawn_process can re-enter userspace (like execve).  GATED to the native shell
        // personality — a Linux task gets ENOSYS, so the object surface is unreachable from
        // the Linux shell.  HOSQ_SPAWN(rsi=path, rdx=argv, r10=envp) loads the image into the
        // (forked) caller via execveTask — the native-ABI counterpart of execve; all other
        // ops format/return through hosQuery.
        case HOS_SYS_QUERY: {
            const int ctid = cast(int)g_current_task_id;
            if (ctid < 0 || ctid >= MAX_TASKS || !g_taskNativeAbi[ctid]) { ret = -38; break; }
            if (rdi == HOSQ_SPAWN) {
                ret = execveTask(ctid, rsi, rdx, r10);
                if (ret == 0) return;   // image loaded — re-enter from scratch (regs reset)
                break;
            }
            if (rdi == HOSQ_WAIT) {
                // Z4b.1: object_wait(pid, statusbuf, options) over wait4Task, with the SAME
                // cooperative wait-block the Linux wait4 (case 61) uses — rewind RIP so the
                // task transparently re-runs the wait on wake (the child's exit clears it).
                ret = wait4Task(ctid, cast(int)rsi, rdx, r10);
                if (ret == -4) { task.regs[REG_RIP] -= 2; scheduleNext(); return; }
                break;
            }
            ret = hosQuery(rdi, rsi, rdx, r10);
            break;
        }

        // exit
        case 60:
        // exit_group
        case 231:
            exitTask(tid, cast(int)rdi);
            return; // exitTask switches tasks; we never reach the set-RAX below

        // rt_sigreturn (Z1: return from a signal handler — restore the saved context)
        case 15:
            sigreturnTask(tid);
            return;   // task.regs fully restored (incl. RAX/RIP/RSP); don't touch them

        // pause (34) / rt_sigsuspend (130): zsh's foreground-job wait point.  zsh's
        // configure picked BROKEN_POSIX_SIGSUSPEND (our sigsuspend returned EINTR), so it
        // actually waits with sigprocmask+pause — handle both.  This is where SIGCHLD is
        // unblocked, so deliver its handler here (it reaps the child, returns from the
        // wait), instead of from the generic run-loop point where zsh keeps it blocked.
        case 34:
        case 130:
            ret = sigsuspendTask(tid);
            if (ret == SIGSUSP_DELIVERED) return;   // handler armed; task.regs set up
            if (ret == SIGSUSP_BLOCK) { task.regs[REG_RIP] -= 2; scheduleNext(); return; }
            break;                                  // -EINTR → set RAX below

        // wait4
        case 61:
            ret = wait4Task(tid, cast(int)rdi, rsi, rdx);
            // Blocking: rewind RIP so the task transparently re-runs wait4 on wake
            // (the child's exit clears `waiting`), instead of returning EINTR.
            if (ret == -4) { task.regs[REG_RIP] -= 2; scheduleNext(); return; }
            break;

        // kill — liveness/ESRCH semantics from linux_sys_kill, then ACTUAL delivery:
        // mark the signal pending and wake the target so the run loop applies it
        // (default disposition → exitTask; installed handler → EINTR delivery at the
        // task's next blocking syscall — same machinery as the ^C line discipline).
        // Without this, kill() was a no-op and the desktop popover toggles (panel
        // SIGTERMs the open Wi-Fi drop-down to collapse it) silently did nothing.
        case 62:
            ret = linux_sys_kill(rdi, rsi);
            if (ret == 0 && rsi > 0 && rsi < 64) {
                int sigTarget = taskIdFromLinuxPid(cast(int)cast(long)rdi);
                if (sigTarget > 0 && sigTarget < MAX_TASKS &&
                    g_tasks[sigTarget].active && !g_tasks[sigTarget].exited) {
                    // custom disposition with no handler = SIG_IGN → drop
                    if (!((g_taskSigCustom[sigTarget] & (1UL << cast(int)rsi)) &&
                          g_sigHandler[sigTarget][cast(int)rsi] == 0)) {
                        // Freeze probe: remember the last kill() so the overlay can name a stray-killer.
                        g_lastSigSig = cast(int)rsi; g_lastSigFrom = tid; g_lastSigTo = sigTarget; g_lastSigMs = pitMs();
                        g_taskPendingSig[sigTarget] = cast(int)rsi;
                        // Wake through the proper channel: a futex waiter must be
                        // released via clearFutexWait (sets RAX=-EINTR); poll/read
                        // parks are RIP-rewound so a bare un-wait re-runs them.
                        if (g_futexWaitActive[sigTarget]) clearFutexWait(sigTarget, -4);
                        else g_tasks[sigTarget].waiting = false;
                    }
                }
            }
            break;

        // waitpid (via wait4 with NULL rusage)
        case 114:
            ret = wait4Task(tid, cast(int)rdi, rsi, rdx);
            if (ret == -4) { task.regs[REG_RIP] -= 2; scheduleNext(); return; }
            break;

        // mprotect
        case 10:
            ret = sys_mprotect(rdi, rsi, rdx);
            break;

        // munmap
        case 11: {
            // Free the underlying physical pages only when they belong to an
            // owned (private anonymous / file) region; device (g_fb) and shared
            // (memfd) maps must stay intact.  Walk on the task's own page tables.
            bool freePages = (rsi != 0) && regionOwnedAt(*task, rdi);
            if (rsi != 0) x64WriteCR3(task.pml4Phys);
            ret = sys_munmap(rdi, rsi, freePages);
            if (ret == 0 && rsi != 0) {
                ulong ulen = (rsi + 0xFFF) & ~0xFFFUL;
                removeRegion(*task, rdi, rdi + ulen);
            }
            break;
        }

        // arch_prctl (handles ARCH_SET_FS, updates g_task_fsbase)
        case 158:
            ret = linux_sys_arch_prctl(rdi, rsi);
            break;

        // sched_yield — cooperatively hand the CPU to the next runnable task.
        case 24:
            task.regs[REG_RAX] = 0;
            scheduleNext();
            return;

        // futex — cooperative blocking implementation.  Under this single-core
        // round-robin scheduler we block FUTEX_WAIT in the task table and wake
        // it from FUTEX_WAKE.  We also poll the word from scheduleNext() so a
        // userspace store without an explicit wake cannot strand the process.
        case 202: {
            ulong op = rsi & ~cast(ulong)(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

            // Diagnostic: log early futex traffic + a periodic sample of the
            // steady state, to identify a stuck FUTEX_WAIT and its waker.
            if (g_futexLogCount < 80 || (g_futexLogCount % 50000) == 0) {
                klog("[futex] t="); klog_hex(cast(ulong)tid);
                klog(" op="); klog_hex(op);
                klog(" u="); klog_hex(rdi);
                klog(" val="); klog_hex(rdx);
                if (rdi != 0) { klog(" *u="); klog_hex(cast(ulong)cast(uint)*cast(int*)rdi); }
                klog("\n");
            }
            g_futexLogCount++;

            if (rdi == 0) { task.regs[REG_RAX] = cast(ulong)(-14); return; } // EFAULT
            if (op == FUTEX_WAIT || op == FUTEX_WAIT_BITSET) {
                uint waitBits = (op == FUTEX_WAIT_BITSET)
                              ? cast(uint)r9
                              : FUTEX_BITSET_MATCH_ANY;
                if (waitBits == 0) { task.regs[REG_RAX] = cast(ulong)(-22); return; } // EINVAL
                int cur = *cast(int*)rdi;
                if (cur != cast(int)rdx) {
                    task.regs[REG_RAX] = cast(ulong)(-11); // EAGAIN: value changed
                } else {
                    g_futexWaitActive[tid] = true;
                    g_futexWaitUaddr[tid] = rdi;
                    g_futexWaitVal[tid] = cast(int)rdx;
                    g_futexWaitBitset[tid] = waitBits;
                    // Timeout (r10 = userspace timespec*).  FUTEX_WAIT takes a RELATIVE
                    // timeout; FUTEX_WAIT_BITSET an ABSOLUTE deadline.  sys_clock_gettime
                    // returns pitMs() for every clock id, so an absolute userspace deadline
                    // is already in the g_pitMs ms domain (same reasoning as timerfd
                    // TFD_TIMER_ABSTIME) — and FUTEX_CLOCK_REALTIME needs no conversion.
                    ulong fwDeadline = 0;                       // 0 = wait forever
                    if (r10 != 0 && !g_futexTimeoutsOff) {
                        const long tSec  = *cast(long*)(r10 + 0);
                        const long tNsec = *cast(long*)(r10 + 8);
                        if (tSec < 0 || tNsec < 0 || tNsec >= 1_000_000_000) {
                            clearFutexWait(tid, 0);
                            task.regs[REG_RAX] = cast(ulong)(-22); // EINVAL
                            return;
                        }
                        const ulong ms = cast(ulong)tSec * 1000 + cast(ulong)tNsec / 1_000_000;
                        fwDeadline = (op == FUTEX_WAIT_BITSET) ? ms : pitMs() + ms;
                        if (fwDeadline == 0) fwDeadline = 1;    // keep 0 = "no timeout"
                    }
                    g_futexWaitDeadline[tid] = fwDeadline;
                    // A task issuing FUTEX_WAIT is by definition not poll-parked; clear any
                    // stale g_pollBlocked so wakePollers / the no-idle poller fallback can't
                    // spuriously unpark this futex waiter (bare waiting=false, garbage RAX).
                    g_pollBlocked[tid] = false;
                    task.waiting = true;
                    bootProgressEventHex("park", rax, g_parkScreenTrace);
                    scheduleNext();
                }
                return;
            } else if (op == FUTEX_WAKE || op == FUTEX_WAKE_BITSET) {
                uint wakeBits = (op == FUTEX_WAKE_BITSET)
                              ? cast(uint)r9
                              : FUTEX_BITSET_MATCH_ANY;
                if (wakeBits == 0) { task.regs[REG_RAX] = cast(ulong)(-22); return; } // EINVAL

                uint maxWake = rdx > uint.max ? uint.max : cast(uint)rdx;
                uint woke = futexWakeAddress(rdi, maxWake, wakeBits, tid);
                if (g_futexWakeLogCount < 80 || woke != 0 || (g_futexWakeLogCount % 50000) == 0) {
                    klog("[futex-wake] t="); klog_hex(cast(ulong)tid);
                    klog(" u="); klog_hex(rdi);
                    klog(" max="); klog_hex(cast(ulong)maxWake);
                    klog(" bits="); klog_hex(cast(ulong)wakeBits);
                    klog(" woke="); klog_hex(cast(ulong)woke);
                    klog("\n");
                }
                g_futexWakeLogCount++;
                task.regs[REG_RAX] = cast(ulong)woke;
                return;
            } else if (op == FUTEX_REQUEUE || op == FUTEX_CMP_REQUEUE) {
                if (r8 == 0) { task.regs[REG_RAX] = cast(ulong)(-14); return; } // EFAULT
                if (op == FUTEX_CMP_REQUEUE && *cast(int*)rdi != cast(int)r9) {
                    task.regs[REG_RAX] = cast(ulong)(-11); // EAGAIN
                    return;
                }

                uint maxWake = rdx > uint.max ? uint.max : cast(uint)rdx;
                uint maxRequeue = r10 > uint.max ? uint.max : cast(uint)r10;
                uint woke = futexWakeAddress(rdi, maxWake, FUTEX_BITSET_MATCH_ANY, tid);
                uint moved = futexRequeueAddress(rdi, r8, maxRequeue, FUTEX_BITSET_MATCH_ANY);
                klog("[futex-requeue] t="); klog_hex(cast(ulong)tid);
                klog(" from="); klog_hex(rdi);
                klog(" to="); klog_hex(r8);
                klog(" woke="); klog_hex(cast(ulong)woke);
                klog(" moved="); klog_hex(cast(ulong)moved);
                klog("\n");
                task.regs[REG_RAX] = cast(ulong)(woke + moved);
                return;
            } else if (op == FUTEX_WAKE_OP) {
                uint maxWake1 = rdx > uint.max ? uint.max : cast(uint)rdx;
                uint maxWake2 = r10 > uint.max ? uint.max : cast(uint)r10;
                uint woke = futexWakeAddress(rdi, maxWake1, FUTEX_BITSET_MATCH_ANY, tid);
                woke += futexWakeAddress(r8, maxWake2, FUTEX_BITSET_MATCH_ANY, tid);
                klog("[futex-wake-op] t="); klog_hex(cast(ulong)tid);
                klog(" u1="); klog_hex(rdi);
                klog(" u2="); klog_hex(r8);
                klog(" woke="); klog_hex(cast(ulong)woke);
                klog("\n");
                task.regs[REG_RAX] = cast(ulong)woke;
                return;
            }
            task.regs[REG_RAX] = cast(ulong)(-38); // ENOSYS for unsupported ops
            return;
        }

        // All other Linux syscalls are translated by the LinuxSyscallObject
        // (Phase 12): the personality is reached only through its gate, so the
        // whole Linux subtree can be disabled without touching the native kernel.
        // The translation bodies still live in posix.d, which now calls native
        // object ops from Phases 3–11.
        default:
            if (!linuxEnabled()) {
                linuxNoteBlocked();
                ret = -38; // ENOSYS — Linux personality not present
                break;
            }
            linuxNoteTranslate();
            ret = dispatchLinuxSyscall(rax, rdi, rsi, rdx, r10, r8, r9);
            break;
    }

    // diagnostic: for read(), snapshot the fd's type/O_NONBLOCK AND the return value in the CALLER's
    // context (the fd table is still the caller's here) so the [sched] hog readout is trustworthy.
    // Cooperative blocking for console reads: when a task read()s the console
    // but no keyboard input is pending, posix.d returns EAGAIN.  Rather than
    // spin in-kernel (which starves every other task under this cooperative
    // scheduler), rewind RIP to the `syscall` instruction (2 bytes: 0F 05) and
    // yield.  The task transparently re-runs read() next time it is scheduled,
    // so userspace still sees a normal blocking read once data arrives.
    // Z4a.6: a native device_read (HOS_SYS_QUERY, op=rdi=HOSQ_DEV_READ, fd=rsi) over the PTY
    // is a blocking terminal read too — give it the same treatment as a Linux read(rdi) so
    // native zsh's terminal input blocks correctly and ^C still interrupts it.
    // A blocking read that returned data/EOF/error (anything but EAGAIN) is no longer read-parked: clear
    // g_pollBlocked so a later wait4() on this task isn't misread as a poll/read park (see the scheduler
    // guard above).  The EAGAIN case re-sets it in the park block just below.
    if (rax == 0 && ret != -11 && tid >= 0 && tid < MAX_TASKS) g_pollBlocked[tid] = false;

    // Bring-up diagnostic: log FAILING syscalls made by the init task (the compositor).
    //
    // Hyprland dies of an uncaught std::system_error before it initialises its logger, so
    // nothing it would print ever reaches serial -- the crash backtrace only shows the terminate
    // machinery (std::__terminate / abort_message / demangling_terminate_handler) and the
    // typeinfos for system_error/runtime_error/exception, not the throw site.  A system_error
    // is built FROM AN ERRNO, so the failing syscall that produced it is observable right here.
    //
    // Scoped tightly so it cannot become log spam: init task only, errno range only, and a hard
    // cap of 40 lines.  EAGAIN/EINTR are excluded -- they are ordinary flow control on the
    // poll/read paths and would drown the signal.
    if (tid == 0 && ret < 0 && ret > -4096 && g_initFailLogN < 40) {
        const long e = -ret;
        if (e != 11 /*EAGAIN*/ && e != 4 /*EINTR*/) {
            ++g_initFailLogN;
            klog("[initfail] syscall="); klog_dec(rax);
            klog(" errno="); klog_dec(cast(ulong)e);
            klog(" a="); klog_hex(rdi); klog(" b="); klog_hex(rsi);
            klog("\n");
        }
    }

    const bool blkRead =
        (rax == 0 && (isConsoleFd(rdi) || ptyBlockingReadFd(rdi) || pipeBlockingReadFd(rdi))) ||
        // recvfrom(45)/recvmsg(47) on a BLOCKING AF_INET socket with an empty ring: same
        // rewind+yield treatment.  Without this, busybox ping got EAGAIN from its blocking raw
        // socket and died with "recvfrom: Resource temporarily unavailable" before the echo
        // reply could arrive.
        ((rax == 45 || rax == 47) && inetBlockingRecvFd(rdi)) ||
        (rax == HOS_SYS_QUERY && rdi == HOSQ_DEV_READ &&
         (ptyBlockingReadFd(rsi) || pipeBlockingReadFd(rsi) || isConsoleFd(rsi)));
    if (blkRead && ret == -11 /*EAGAIN*/) {
        // Z3: a pending handler-signal (e.g. ^C -> SIGINT for zsh) interrupts the blocking
        // read with EINTR — POSIX semantics.  RIP is still just past the `syscall`, so we
        // make the read "return" -EINTR (saved by deliverUserSignal) and run the handler;
        // after rt_sigreturn the read has returned EINTR and zsh's ZLE re-checks its abort
        // flag instead of swallowing the keystroke.  Else: rewind + yield (normal block).
        int psig = g_taskPendingSig[tid];
        if (psig > 0 && psig < 64 && (g_taskSigCustom[tid] & (1UL << psig)) &&
            g_sigHandler[tid][psig] != 0) {
            g_taskPendingSig[tid] = 0;
            task.regs[REG_RAX] = cast(ulong)(-4);   // the read returns -EINTR after the handler
            if (deliverUserSignal(tid, psig)) return;
        }
        // PARK (not a busy-yield): a blocking read on an fd with no data yet must consume ZERO cpu until
        // data arrives.  The old bare `RIP-=2; scheduleNext()` left the task RUNNABLE, so zsh's ZLE
        // read-loop re-ran read()->EAGAIN every scheduler turn (~73% cpu), starving the compositor + the
        // LKL's USB-input thread -> the desktop (and the kernel-drawn cursor) froze the moment a terminal
        // opened.  Mirror the poll-park: block until the fd is readable (deadline 0 = no timeout);
        // wakePollers() (every PIT tick) un-waits us to re-run read() -> data or re-park.  ^C/EINTR is
        // handled above; a real EOF makes the re-run read() return 0 (not EAGAIN) so we don't re-park.
        g_pollBlocked[tid]  = true;
        g_pollDeadline[tid] = 0;
        task.waiting        = true;
        task.regs[REG_RIP] -= 2;
        bootProgressEventHex("park", rax, g_parkScreenTrace);
        scheduleNext();
        return;
    }

    // Cooperative blocking for poll/ppoll/select: when nothing is ready yet but
    // the caller is willing to wait, yield instead of returning 0 immediately.
    // Otherwise an event-loop thread busy-spins on poll(), monopolising this
    // cooperative scheduler so the *other* task (e.g. the worker thread that
    // would signal the awaited fd) never runs — a livelock.  Rewinding RIP re-runs
    // the poll when this task is next scheduled, after others have had a turn.
    //   poll(7):   fds=rdi nfds=rsi timeout_ms=rdx (0 = non-blocking, else wait)
    //   ppoll(271):fds=rdi nfds=rsi timeout_ts=rdx (NULL = infinite)
    // Both scan fd readiness (ppoll fixed below); select/pselect are excluded
    // since they don't scan and would yield forever.
    //   epoll_pwait(281): handled below without RIP rewind. Hyprland's
    //     wl_event_loop must see timeout returns to fire timers, but other tasks
    //     still need a turn before Hyprland immediately re-enters epoll.
    // ppoll(271) / epoll_pwait2(441): timeout is a userspace timespec we don't parse
    // here, so keep the original rewind/return-0 yield (re-runs each round-robin turn).
    //
    // A real signal must interrupt every blocking fd wait, not only read().  In particular,
    // wpa_supplicant's eloop sleeps in poll(); hos-wpa-agent sends it SIGHUP after replacing
    // /run/wpa-net.conf.  kill() wakes the task, but without delivery here the re-run poll simply
    // parked again forever with SIGHUP still pending, so wpa never loaded the selected network.
    // Save -EINTR as the post-handler syscall result: after the handler returns, eloop processes
    // its signal flag and runs wpa_supplicant_reconfig().
    if (ret == 0 && (rax == 7 || rax == 271 || rax == 232 || rax == 281 ||
                     rax == 441 || rax == 23 || rax == 270)) {
        int psig = g_taskPendingSig[tid];
        if (psig > 0 && psig < 64 && (g_taskSigCustom[tid] & (1UL << psig)) &&
            g_sigHandler[tid][psig] != 0) {
            g_taskPendingSig[tid] = 0;
            g_pollBlocked[tid] = false;
            g_pollDeadline[tid] = 0;
            task.regs[REG_RAX] = cast(ulong)(-4);   // poll/select returns -EINTR after handler
            if (deliverUserSignal(tid, psig)) return;
        }
    }
    if (ret == 0 && rax == 271) {
        task.regs[REG_RIP] -= 2;
        bootProgressEventHex("yield", rax, g_yieldScreenTrace);
        scheduleNext();
        return;
    }
    if (ret == 0 && rax == 441) {
        task.regs[REG_RAX] = 0;
        bootProgressEventHex("yield", rax, g_yieldScreenTrace);
        scheduleNext();
        return;
    }

    // poll(7) + epoll_wait/pwait(232/281): PARK the task until an fd is ready or the
    // timeout expires, instead of returning 0 immediately (which busy-spins the
    // single core).  Woken by wakePollers() on the PIT tick + input IRQs.
    //   poll(7) timeout_ms = rdx ; epoll timeout_ms = r10 ; 0 = nonblock, <0 = infinite.
    {
        const bool isPoll  = (rax == 7);
        const bool isEpoll = (rax == 232 || rax == 281);
        if (ret == 0 && (isPoll || isEpoll)) {
            const long tmo = isPoll ? cast(long)rdx : cast(long)r10;
            if (tmo != 0) {
                if (g_pollBlocked[tid]) {
                    const ulong dl = g_pollDeadline[tid];
                    if (dl != 0 && pitMs() >= dl) {
                        g_pollBlocked[tid] = false;
                        task.regs[REG_RAX] = 0;        // timed out → return 0
                        return;
                    }
                } else {
                    g_pollBlocked[tid]  = true;
                    g_pollDeadline[tid] = (tmo < 0) ? 0 : (pitMs() + cast(ulong)tmo);
                }
                task.waiting = true;                  // park: scheduler skips us
                task.regs[REG_RIP] -= 2;              // re-run the syscall on wake
                bootProgressEventHex("park", rax, g_parkScreenTrace);
                scheduleNext();
                return;
            }
        }
        // got events (or an error): the wait is satisfied.
        if ((isPoll || isEpoll) && ret != 0) g_pollBlocked[tid] = false;
    }

    // select(23) / pselect6(270): linux_sys_select now SCANS fd readiness (returns 0 when none ready), so
    // PARK the caller like poll instead of returning 0 immediately — else zsh's ZLE select()-on-tty loop
    // spins in USERSPACE (~73% cpu) and freezes the desktop.  Timeout is a userspace POINTER (r8):
    // select=timeval{sec,usec}, pselect6=timespec{sec,nsec}; NULL=block forever, {0,0}=non-blocking.
    {
        const bool isSelect = (rax == 23 || rax == 270);
        if (ret == 0 && isSelect) {
            long tmo;                               // ms; <0 = infinite, 0 = non-blocking
            if (r8 == 0) tmo = -1;                  // NULL timeout → block until an fd is ready
            else {
                const long sec   = *cast(long*)r8;
                const long sub   = *cast(long*)(r8 + 8);                 // usec (select) or nsec (pselect6)
                const long subMs = (rax == 23) ? (sub / 1000) : (sub / 1000000);
                tmo = sec * 1000 + subMs;
            }
            if (tmo != 0) {
                if (g_pollBlocked[tid]) {
                    const ulong dl = g_pollDeadline[tid];
                    if (dl != 0 && pitMs() >= dl) {
                        g_pollBlocked[tid] = false;
                        task.regs[REG_RAX] = 0;     // timed out → 0 fds ready (sets already cleared by scan)
                        return;
                    }
                } else {
                    g_pollBlocked[tid]  = true;
                    g_pollDeadline[tid] = (tmo < 0) ? 0 : (pitMs() + cast(ulong)tmo);
                }
                task.waiting = true;
                task.regs[REG_RIP] -= 2;
                bootProgressEventHex("park", rax, g_parkScreenTrace);
                scheduleNext();
                return;
            }
        }
        if (isSelect && ret != 0) g_pollBlocked[tid] = false;
    }

    // L5 kernel-side INTx wake (op6 of the 0x4100 LKL PCI bridge): PARK the LKL's IRQ thread until its
    // granted device's INTx asserts, instead of a userspace 250us busy-poll that competed for CPU with
    // (and raced) the LKL's enumeration thread.  wakePollers() re-runs this every PIT tick (<=1ms) to
    // re-check; we return 0 on INTx or a 50ms safety timeout, then the LKL fires lkl_trigger_irq + re-blocks.
    if (rax == 0x4100 && rdi == 6) {
        const uint gbdf = taskGrantedBdf(tid);     // first granted device (for the CSR diagnostic below)
        if (gbdf == 0xFFFFFFFFu) {                 // no device cap → -EPERM (LKL always holds its grant)
            g_pollBlocked[tid] = false;
            task.regs[REG_RAX] = cast(ulong)(-1);
            return;
        }
        // INTx or a real MSI (vec 0x30) → wake immediately.  The real single-MSI now delivers
        // (FIRES>0), and it is EDGE-triggered + self-limiting: the device asserts once per event
        // and the driver's hard ISR masks until its threaded handler re-enables, so lkl_trigger_irq
        // fires only a handful of times per handshake — no storm.
        // If the native MSI edge is dropped, recover it from iwlwifi's authoritative CSR_INT status.
        // This is safe because wifiCsrPending() requires an UNMASKED cause: the first synthetic IRQ
        // makes iwlwifi mask CSR_INT while its threaded handler drains/ACKs it, so it cannot storm or
        // starve the timer thread.  It is also attempted only when no native MSI delta is pending.
        wifiIrqDiagKlog();                         // W1 diagnostic → /run/klog (throttled 1 Hz): FIRES/CSR_INT/MASK/ALIVE
        // MULTI-DEVICE: one LKL may hold several devices (AX210 + xHCI).  MSI is global (any device's MSI
        // bumps g_msiIrqCount), so lklMsiPending already covers all of them; for INTx, wake if ANY granted
        // device is asserting.  On wake the LKL fires lkl_trigger_irq for ALL its registered irqs and each
        // driver's ISR checks whether its own device actually raised — the standard shared-vector pattern.
        bool wake = lklMsiPending();
        if (!wake)
            wake = wifiCsrPending();
        if (!wake)
            for (int di = 0; di < 8; di++) {       // taskGrantedDevByIndex returns -1 past the last device
                const long b = taskGrantedDevByIndex(tid, di);
                if (b < 0) break;
                if (deviceIntxAsserted(cast(uint)b)) { wake = true; break; }
            }
        if (wake) {
            // STORM PROTECTION: a device that asserts an un-acked cause continuously (observed after the
            // gen2 plain-reset path — the AX210 interrupt-storms) would make op6 return 1 forever, so the
            // LKL irq thread spins in userspace (lkl_trigger_irq → op6 → …) and NEVER yields → the
            // compositor is starved ("desktop frozen, cursor still moves").  Allow a short burst of
            // back-to-back wakes (low interrupt latency during firmware load), then FORCE one park to
            // yield the CPU to Weston.  During a real storm this caps the irq thread at ~a burst per PIT
            // tick, leaving ~all of each ms for the desktop; normal edge interrupts never hit the cap.
            if (g_lklIrqBurst < 32) {
                ++g_lklIrqBurst;
                g_pollBlocked[tid] = false;
                task.regs[REG_RAX] = 1;            // 1 = woken by a real interrupt (vs 0 = safety timeout)
                return;
            }
            g_lklIrqBurst = 0;                     // burst spent → fall through to a one-tick park (yield)
        } else {
            g_lklIrqBurst = 0;                     // nothing pending → reset the burst
        }
        if (g_pollBlocked[tid]) {
            if (g_pollDeadline[tid] != 0 && pitMs() >= g_pollDeadline[tid]) {
                g_pollBlocked[tid] = false;
                task.regs[REG_RAX] = 0;            // 50ms safety timeout → return (LKL re-blocks)
                return;
            }
        } else {
            g_pollBlocked[tid]  = true;
            g_pollDeadline[tid] = pitMs() + 50;
        }
        task.waiting = true;                       // park (NOT a busy spin); re-checked next PIT tick
        task.regs[REG_RIP] -= 2;
        bootProgressEventHex("park", rax, g_parkScreenTrace);
        scheduleNext();
        return;
    }

    // nanosleep(35) / clock_nanosleep(230, RELATIVE): a REAL sleep. The libc wrapper in posix.d is a
    // no-op (returns 0), so without this the caller never actually sleeps. Park the task for the
    // requested duration, reusing the poll/epoll park + PIT-tick wake. (LKL's timer host-op relies on
    // this so the Linux-kernel-as-a-library clock can advance — see src/lkl/.)
    {
        const bool isSleep = (rax == 35 || rax == 230);
        // clock_nanosleep TIMER_ABSTIME (flags bit 0) is not supported here; our LKL timer uses
        // relative nanosleep, which is all that's needed.
        const bool absTime = (rax == 230) && (rsi & 1);
        if (isSleep && ret == 0 && !absTime) {
            const ulong reqPtr = (rax == 35) ? rdi : rdx;   // nanosleep req=rdi; clock_nanosleep req=rdx
            if (reqPtr != 0) {
                if (g_pollBlocked[tid]) {
                    if (g_pollDeadline[tid] != 0 && pitMs() >= g_pollDeadline[tid]) {
                        g_pollBlocked[tid] = false;
                        task.regs[REG_RAX] = 0;             // slept long enough
                        return;
                    }
                } else {
                    const long sec  = *cast(long*)(reqPtr + 0);
                    const long nsec = *cast(long*)(reqPtr + 8);
                    const ulong ms  = cast(ulong)sec * 1000 + cast(ulong)nsec / 1_000_000;
                    if (ms == 0) { task.regs[REG_RAX] = 0; return; }   // sub-ms: just return done
                    g_pollBlocked[tid]  = true;
                    g_pollDeadline[tid] = pitMs() + ms;
                }
                task.waiting = true;
                task.regs[REG_RIP] -= 2;                    // re-run the sleep syscall on wake
                bootProgressEventHex("park", rax, g_parkScreenTrace);
                scheduleNext();
                return;
            }
        }
    }

    // Wayland and other local-socket protocols use sendmsg() as an IPC handoff.
    // After a successful write, yield once so the peer can accept/read/reply
    // without relying on debug logging or timer timing for fairness.
    if (ret > 0 && rax == 46) {
        task.regs[REG_RAX] = cast(ulong)ret;
        wakePollers();   // the peer (parked on its socket via poll/epoll) can now read
        bootProgressEventHex("yield", rax, g_yieldScreenTrace);
        scheduleNext();
        return;
    }

    if (screenTraceThis) bootProgressHex("ret", cast(ulong)ret);
    task.regs[REG_RAX] = cast(ulong)ret;
}

// Dispatch to the large posix.d table
private long dispatchLinuxSyscall(ulong n, ulong a, ulong b, ulong c,
                                   ulong d, ulong e, ulong f) {
    if (n == 0x4100) return linux_sys_epin_lkl_pci(a, b, c, d, e);  // L3a: LKL PCI bridge (custom)

    long capPrecheck = linuxSyscallCapPrecheck(n, a, b, c, d, e, f);
    if (capPrecheck < 0) return capPrecheck;

    switch (n) {
        case 0:   return linux_sys_read(a, b, c);
        case 1:   return linux_sys_write(a, b, c);
        case 2:   return linux_sys_open(a, b, c);
        case 3:   return linux_sys_close(a);
        case 4:   return linux_sys_stat(a, b);
        case 5:   return linux_sys_fstat(a, b);
        case 6:   return linux_sys_lstat(a, b);
        case 7:   return linux_sys_poll(a, b, c);
        case 8:   return linux_sys_lseek_wrap(a, b, c);
        case 13:  return linux_sys_rt_sigaction(a, b, c, d);
        case 14:  return linux_sys_rt_sigprocmask(a, b, c, d);
        case 16:  return linux_sys_ioctl(a, b, c);
        case 17:  return linux_sys_pread64(a, b, c, d);
        case 18:  return linux_sys_pwrite64(a, b, c, d);
        case 19:  return linux_sys_readv(a, b, c);
        case 20:  return linux_sys_writev(a, b, c);
        case 21:  return linux_sys_access(a, b);
        case 22:  return linux_sys_pipe(a);
        case 23:  return linux_sys_select(a, b, c, d, e);
        case 24:  return linux_sys_sched_yield();
        case 28:  return linux_sys_madvise(a, b, c);
        case 32:  return linux_sys_dup(a);
        case 33:  return linux_sys_dup2(a, b);
        case 34:  return linux_sys_pause();
        case 35:  return linux_sys_nanosleep(a, b);
        case 36:  return linux_sys_getitimer(a, b);
        case 37:  return linux_sys_alarm(a);
        // setitimer: was UNROUTED (35,36,37 then 39), so it returned ENOSYS and busybox ping
        // never got the SIGALRM that sends packets 2..N -- it hung after the first reply.
        case 38:  return linux_sys_setitimer(a, b, c);
        case 39:  return linux_sys_getpid();
        case 40:  return linux_sys_sendfile(a, b, c, d);
        case 41:  return linux_sys_socket(a, b, c);
        case 42:  return linux_sys_connect(a, b, c);
        case 43:  return linux_sys_accept(a, b, c);
        case 44:  return linux_sys_sendto(a, b, c, d, e, f);
        case 45:  return linux_sys_recvfrom(a, b, c, d, e, f);
        case 46:  return linux_sys_sendmsg(a, b, c);
        case 47:  return linux_sys_recvmsg(a, b, c);
        case 49:  return linux_sys_bind(a, b, c);
        case 50:  return linux_sys_listen(a, b);
        case 51:  return linux_sys_getsockname(a, b, c);
        case 52:  return linux_sys_getpeername(a, b, c);
        case 53:  return linux_sys_socketpair(a, b, c, d);
        case 54:  return linux_sys_setsockopt(a, b, c, d, e);
        case 55:  return linux_sys_getsockopt(a, b, c, d, e);
        case 63:  return linux_sys_uname(a);
        case 72:  return linux_sys_fcntl(a, b, c);
        case 73:  return linux_sys_flock(a, b);
        case 77:  return linux_sys_ftruncate(a, b);
        case 285: return linux_sys_fallocate(a, b, c, d);  // posix_fallocate (wl_shm buffers)
        case 79:  return linux_sys_getcwd(a, b);
        case 80:  return linux_sys_chdir(a);
        case 81:  return linux_sys_fchdir(a);
        case 82:  return linux_sys_rename(a, b);
        case 83:  return linux_sys_mkdir(a, b);
        case 84:  return linux_sys_rmdir(a);
        case 87:  return linux_sys_unlink(a);
        case 89:  return linux_sys_readlink(a, b, c);
        case 90:  return linux_sys_chmod(a, b);        // musl chmod() emits SYS_chmod(90) on x86-64
        case 91:  return linux_sys_fchmod(a, b);       // was ENOSYS -> chmod()/fchmod() silently no-op'd
        case 92:  return linux_sys_chown(a, b, c);      // NM keyfile writer sets profile ownership
        case 93:  return linux_sys_fchown(a, b, c);
        case 94:  return linux_sys_lchown(a, b, c);
        case 96:  return linux_sys_gettimeofday(a, b);
        case 97:  return linux_sys_getrlimit(a, b);
        case 98:  return linux_sys_getrusage(a, b);   // Z1: zsh's `time`/resource reporting
        case 99:  return linux_sys_sysinfo(a);
        case 100: return linux_sys_times(a);
        case 102: return linux_sys_getuid();
        case 104: return linux_sys_getgid();
        case 105: return linux_sys_setuid(a);
        case 106: return linux_sys_setgid(a);
        case 107: return linux_sys_geteuid();
        case 108: return linux_sys_getegid();
        case 109: return linux_sys_setpgid(a, b);
        case 110: return linux_sys_getppid();
        case 111: return linux_sys_getpgrp();
        case 112: return linux_sys_setsid();
        case 113: return linux_sys_setreuid(a, b);
        case 116: return linux_sys_setgroups(a, b);
        case 117: return linux_sys_setresuid(a, b, c);
        case 118: return linux_sys_getresuid(a, b, c);
        case 119: return linux_sys_setresgid(a, b, c);
        case 120: return linux_sys_getresgid(a, b, c);
        case 121: return linux_sys_getpgid(a);
        case 124: return linux_sys_getsid(a);
        case 131: return linux_sys_sigaltstack(a, b);
        case 137: return linux_sys_statfs(a, b);
        case 138: return linux_sys_fstatfs(a, b);     // Z1: zsh probes the cwd filesystem
        case 154: return linux_sys_sched_setparam(a, b);
        case 155: return linux_sys_sched_getparam(a, b);
        case 140: return linux_sys_getpriority(a, b);        // no-op: priority is moot on the
        case 141: return linux_sys_setpriority(a, b, c);     // cooperative scheduler (zsh nice's bg jobs)
        case 157: return linux_sys_prctl(a, b, c, d, e);
        case 160: return linux_sys_setrlimit(a, b);
        case 162: return linux_sys_sync();
        case 165: return linux_sys_mount(a, b, c, d, e);
        case 186: return linux_sys_gettid();
        case 200: return linux_sys_tkill(a, b);
        case 202: return linux_sys_futex(a, b, c, d, e, f);
        case 78:  return linux_sys_getdents(a, b, c);
        case 217: return linux_sys_getdents64(a, b, c);
        case 218: return linux_sys_set_tid_address(a);
        case 228: return linux_sys_clock_gettime(a, b);
        case 229: return linux_sys_clock_getres(a, b);
        case 230: return linux_sys_clock_nanosleep(a, b, c, d);
        case 213: return linux_sys_epoll_create(a);
        case 232: return linux_sys_epoll_pwait(a, b, c, d, 0, 0);  // epoll_wait
        case 233: return linux_sys_epoll_ctl(a, b, c, d);          // was mis-routed to epoll_create!
        case 234: return linux_sys_tgkill(a, b, c);
        // x86_64: 253 = inotify_init, 254 = inotify_add_watch, 255 = inotify_rm_watch.
        // 254 used to route to inotify_init() and 253 was not routed at all -- the same mis-map
        // that case 233 above carries a note about.  Harmless only while every one of these is a
        // stub; the moment inotify is implemented, inotify_add_watch(fd, path, mask) would have
        // silently run inotify_init instead.
        case 253: return linux_sys_inotify_init();
        case 254: return linux_sys_inotify_add_watch(a, b, c);
        case 255: return linux_sys_inotify_rm_watch(a, b);
        case 257: return linux_sys_openat(a, b, c, d);
        case 258: return linux_sys_mkdirat(a, b, c);
        case 260: return linux_sys_fchownat(a, b, c, d, e);
        case 262: return linux_sys_newfstatat(a, b, c, d);
        case 263: return linux_sys_unlinkat(a, b, c);
        case 264: return linux_sys_renameat(a, b, c, d);
        case 265: return linux_sys_linkat(a, b, c, d, e);
        case 266: return linux_sys_symlinkat(a, b, c);
        case 267: return linux_sys_readlinkat(a, b, c, d);
        case 268: return linux_sys_fchmodat(a, b, c, d);
        case 269: return linux_sys_faccessat(a, b, c, d);
        case 270: return linux_sys_pselect6(a, b, c, d, e, f);
        case 271: return linux_sys_ppoll(a, b, c, d, e);
        case 275: return linux_sys_splice(a, b, c, d, e, f);
        case 276: return linux_sys_tee(a, b, c, d);
        case 277: return linux_sys_sync_file_range(a, b, c, d);
        case 280: return linux_sys_utimensat(a, b, c, d);
        case 281: return linux_sys_epoll_pwait(a, b, c, d, e, f);
        case 282: return linux_sys_signalfd4(a, b, c, 0);
        case 283: return linux_sys_timerfd_create(a, b);
        case 284: return linux_sys_eventfd2(a, 0);
        case 286: return linux_sys_timerfd_settime(a, b, c, d);
        case 287: return linux_sys_timerfd_gettime(a, b);
        case 288: return linux_sys_accept4(a, b, c, d);
        case 289: return linux_sys_signalfd4(a, b, c, d);
        case 290: return linux_sys_eventfd2(a, b);
        case 291: return linux_sys_epoll_create1(a);
        case 292: return linux_sys_dup3(a, b, c);
        case 293: return linux_sys_pipe2(a, b);
        case 294: return linux_sys_inotify_init1(a);
        case 295: return linux_sys_pread64(a, b, c, d);
        case 296: return linux_sys_pwrite64(a, b, c, d);
        case 299: return linux_sys_recvmmsg(a, b, c, d, e);
        case 302: return linux_sys_prlimit64(a, b, c, d);
        case 307: return linux_sys_sendmmsg(a, b, c, d);
        case 316: return linux_sys_renameat2(a, b, c, d, e);
        case 318: return linux_sys_getrandom(a, b, c);
        case 319: return linux_sys_memfd_create(a, b);
        case 323: return linux_sys_userfaultfd(a);
        case 324: return linux_sys_membarrier(a, b, c);
        case 332: return linux_sys_statx(a, b, c, d, e);
        case 334: return linux_sys_rseq(a, b, c, d);
        case 435: return linux_sys_clone3(a, b);
        case 439: return linux_sys_faccessat2(a, b, c, d);  // Z1: zsh/musl access() checks
        case 441: return linux_sys_epoll_pwait2(a, b, c, d, e);

        // NOTE: HOS_SYS_QUERY (the native object ABI) is handled in the OUTER dispatchSyscall
        // (so HOSQ_SPAWN can re-enter userspace like execve); it never reaches here.

        default:
            klog("[syscall] ENOSYS "); klog_hex(n); klog("\n");
            return -38; // ENOSYS
    }
}

// ------------------------------------------------------------------
// Kernel main loop
// ------------------------------------------------------------------

// NETWORK_AND_MARKETPLACE_ROADMAP N0/N1: bring up the IPv4 stack + prove a frame round-trips (ARP).
// Gated: the default boot has `-nic none`, so initNetwork finds no NIC → isNetworkAvailable() is false
// → we skip everything device-touching.  Only `NET=1` (e1000 + user-net) exercises the driver.
private void networkSelfTest(bool deepProbe) @nogc nothrow {
    import drivers.network.network : netHudClear, netHudNic, netHudAddr, netHudProbe, netHudLine;
    import core.syscalls.posix : publishNetStatus;

    // configureNetwork() is what runs the PCI probe (initNetwork), so it has to happen
    // before isNetworkAvailable() can answer.  The address passed here is a placeholder --
    // DHCP below decides the real one.
    configureNetwork(0,0,0,0,  0,0,0,0,  255,255,255,0,  0,0,0,0);
    if (!isNetworkAvailable()) {
        klog("[net] no NIC present — IPv4 stack not started\n");
        publishNetStatus(false, 0, 0, 0, 0, false);
        netHudClear(); netHudLine("NET: NO NIC FOUND - check the VM network device".ptr);
        return;
    }
    startNetworkStack();
    ubyte[6] mac; getMacAddress(mac.ptr);
    ulong macv = 0; foreach (i; 0 .. 6) macv = (macv << 8) | mac[i];
    klog("[net] N0: NIC up, MAC="); klog_hex(macv); klog("\n");

    // ── Addressing: DHCP FIRST, and KEEP the lease ────────────────────────────────
    // This used to hardcode QEMU-slirp's 10.0.2.15 / gw 10.0.2.2, and then -- after using a
    // successful DHCP round-trip purely as a RECEIVE proof -- deliberately throw the lease
    // away and restore the static address.  That works on QEMU user-mode networking and is
    // useless anywhere else: on a bridged network (Proxmox vmbr0, real hardware) 10.0.2.x
    // belongs to nobody, so the box ARPs for a gateway that does not exist and nothing ever
    // routes.  Ask the network who we are; fall back to the slirp static only if nothing
    // answers, so the plain-QEMU path keeps behaving exactly as it did.
    auto zeroIP = IPv4Address(0,0,0,0);
    setLocalIPAddress(&zeroIP);                  // a DHCP client is IP-less until it has a lease
    const uint dhcpMs = deepProbe ? 5000 : 3000; // install media pays 3 s for real addressing
    const bool bound = dhcpAcquire(dhcpMs);

    IPv4Address ip, gw, nm, dns4;
    if (bound) {
        dhcpGetConfig(&ip, &gw, &nm, &dns4);
        klog("[net] DHCP BOUND — using the leased address\n");
    } else {
        ip = IPv4Address(10,0,2,15);  gw   = IPv4Address(10,0,2,2);
        nm = IPv4Address(255,255,255,0); dns4 = IPv4Address(10,0,2,3);
        klog("[net] DHCP: no OFFER/ACK — falling back to the QEMU user-net static\n");
    }
    setLocalIPAddress(&ip);
    setGateway(&gw);
    setNetmask(&nm);
    setDNSServer(&dns4);
    // NTP needs a resolver and a route, both of which exist only from here on.  The sync itself
    // runs from the periodic loop rather than inline: a DNS lookup for pool.ntp.org can block for
    // seconds or fail outright, and boot must not wait on the clock.
    g_netConfigured = true;

    const ulong ipv = (cast(ulong)ip.bytes[0] << 24) | (cast(ulong)ip.bytes[1] << 16)
                    | (cast(ulong)ip.bytes[2] << 8)  | ip.bytes[3];
    const ulong gwv = (cast(ulong)gw.bytes[0] << 24) | (cast(ulong)gw.bytes[1] << 16)
                    | (cast(ulong)gw.bytes[2] << 8)  | gw.bytes[3];
    klog("[net] addr ip=0x"); klog_hex(ipv); klog(" gw=0x"); klog_hex(gwv); klog("\n");

    publishNetStatus(true, ip.bytes[0], ip.bytes[1], ip.bytes[2], ip.bytes[3], false);
    netHudClear();
    netHudNic();
    netHudAddr(ip.bytes[0], ip.bytes[1], ip.bytes[2], ip.bytes[3],
               gw.bytes[0], gw.bytes[1], gw.bytes[2], gw.bytes[3]);
    netHudProbe("dhcp".ptr, bound);

    // ── N1: ARP the REAL gateway ──────────────────────────────────────────────────
    // Runs on EVERY boot, install media included: it is the cheapest true proof that a
    // frame round-tripped, and on a box whose pointer does not work the HUD line it writes
    // is the only way to find out.  It was the 8,000,000-iteration budget that was too slow
    // for the installer, so bound it tightly there rather than skipping the probe.
    arpSendRequest(gw);
    MACAddress gwmac; bool resolved = false;
    const uint arpSpin = deepProbe ? 8_000_000u : 400_000u;
    for (uint i = 0; i < arpSpin && !resolved; ++i) {
        networkStackPoll();
        if (arpLookup(gw, &gwmac)) resolved = true;
    }
    klog("[net] N0 rx frames="); klog_hex(getNetRxFrames());
    klog(" lastEtherType="); klog_hex(getNetRxLastEtherType());
    klog(resolved ? " — N1: gateway ARP RESOLVED (a frame round-tripped!)\n"
                  : " — N1: gateway ARP not resolved\n");
    netHudProbe("arp".ptr, resolved);
    // If nothing was received, dump what the NIC itself thinks its rx ring is.
    if (getNetRxFrames() == 0) { import drivers.network.network : e1000Diag; e1000Diag(); }

    // A DNS lookup is the ACTUAL answer to "do I have internet?".  arp=OK only proves the
    // gateway is reachable on the LAN; resolving a name needs routing past it and a working
    // resolver.  So run it on every boot, install media included, with a short budget there:
    // it costs ~50 ms when the network works and is hard-bounded when it does not.  The
    // draft IP-send has no ARP defer-and-retransmit, so pre-resolve the resolver's MAC.
    if (resolved) {
        arpSendRequest(dns4);
        MACAddress dm;
        const uint dnsSpin = deepProbe ? 8_000_000u : 400_000u;
        for (uint i = 0; i < dnsSpin; ++i) { networkStackPoll(); if (arpLookup(dns4, &dm)) break; }
        IPv4Address dip;
        const bool dns = dnsResolve("example.com", &dip, deepProbe ? 4000 : 1500);
        const ulong dipv = (cast(ulong)dip.bytes[0] << 24) | (cast(ulong)dip.bytes[1] << 16)
                         | (cast(ulong)dip.bytes[2] << 8) | dip.bytes[3];
        netHudProbe("dns".ptr, dns);
        // Republish now that we KNOW whether the box can reach the internet, so the desktop
        // indicator can say "online" rather than merely "cable plugged in".
        publishNetStatus(true, ip.bytes[0], ip.bytes[1], ip.bytes[2], ip.bytes[3], dns);
        klog("[net] DNS resolve(example.com) ");
        klog(dns ? "OK — INTERNET REACHABLE, ip=0x" : "FAILED (no internet route) ip=0x");
        klog_hex(dipv); klog("\n");

        // Resolve the time server HERE, in the same proven-good context as the probe above,
        // rather than from the scheduler loop.  dnsResolve() busy-waits while pumping the stack:
        // acceptable during boot, not on the loop that drives the desktop -- and the loop-side
        // lookup failed outright while this identical call for example.com had just succeeded.
        if (dns) {
            import network.ntp : ntpResolveServer;
            ntpResolveServer("pool.ntp.org".ptr, 4000);
        }
    }

    if (!deepProbe) {
        klog("[net] install media: DHCP+ARP+DNS done; skipping the slower ICMP ping probe\n");
        return;
    }
    if (!resolved) return;

    // N2: ping the gateway we actually have.
    ping(gw.bytes[0], gw.bytes[1], gw.bytes[2], gw.bytes[3]);
    bool gotReply = false;
    for (uint i = 0; i < 8_000_000u && !gotReply; ++i) {
        networkStackPoll();
        if (getIcmpEchoReplies() > 0) gotReply = true;
    }
    netHudProbe("ping".ptr, gotReply);
    klog("[net] N2: ping gateway ");
    klog(gotReply ? "ECHO REPLY received — IPv4 + ICMP work end-to-end!\n"
                  : "no reply (many gateways and slirp drop guest ICMP)\n");

}

__gshared uint g_apPitLogCtr = 0;   // SMP_ROADMAP S4.4d: paces the BSP-side AP-progress klog
__gshared uint g_apPitLogN   = 0;   // SMP_ROADMAP S4.4d: caps the proof klog (stop after 40 — no forever-spam)
private __gshared bool g_loopTagPrinted = false;
private __gshared bool g_runTagPrinted = false;
private __gshared bool g_backTagPrinted = false;
private __gshared bool g_syscallTagPrinted = false;
private __gshared bool g_irq0TagPrinted = false;
// The BSP local-APIC timer fires at TICK_HZ so the i8042 (1-byte buffer) is drained
// fast enough to never lose a PS/2 byte; the clock/scheduler run every TICK_DIV-th
// tick to stay at 1000 Hz.  TICK_HZ = 1000 * TICK_DIV.
private enum uint TICK_DIV = 4;
private enum uint TICK_HZ  = 1000 * TICK_DIV;   // 4000 Hz
private __gshared uint g_tickDiv = 0;
private __gshared bool g_schedTagPrinted = false;
private __gshared uint g_syscallScreenTrace = 0;
private __gshared uint g_parkScreenTrace = 0;
private __gshared uint g_yieldScreenTrace = 0;
// Real-hardware desktop bring-up: the per-syscall sc/ret/yield/park screen trace
// below writes DIRECTLY to the framebuffer (ungated by g_fbConsoleEnabled), so it
// would keep painting over the compositor's output forever once the desktop comes
// up.  Once userspace is running (the "run-user" stage) the syscall-by-syscall
// debugging is done, so go quiet: this leaves the screen clean for the [disp]
// display-claim markers and the desktop itself.  The one-time stage tags
// (bootProgress) are unaffected — they print once each.
private __gshared bool g_screenTraceQuiet = false;

private void bootProgressHex(const(char)* tag, ulong value) {
    if (g_screenTraceQuiet) return;
    char[17] buf;
    char[16] hex = "0123456789abcdef";
    for (int i = 15; i >= 0; --i) {
        buf[i] = hex[cast(size_t)(value & 0xF)];
        value >>= 4;
    }
    buf[16] = 0;
    console_framebuffer_write("[");
    console_framebuffer_write(tag);
    console_framebuffer_write("=");
    console_framebuffer_write(buf.ptr);
    console_framebuffer_write("] ");
}

private void bootProgressEventHex(const(char)* tag, ulong value, ref uint counter) {
    if (g_screenTraceQuiet) return;
    ++counter;
    if (counter <= 32 || (counter & 0x3Fu) == 0) {
        bootProgressHex(tag, value);
    }
}

// STABILITY: reap LEAKED task slots.  exitTask() marks a task exited but ONLY wait4()/releaseTask frees
// its slot.  A task whose parent is init (tid 0) or is already dead is never wait4()'d, so under a crash
// loop (a NM/dbus probe or a udhcpc/busybox-dyn respawn that segfaults) those dead slots pile up until
// MAX_TASKS (256) is exhausted — then NO new process can fork/spawn, so the desktop "won't open windows"
// and the installer can't launch its helper tools, while the respawn churn also hogs the CPU.  Auto-reap
// them here — exactly what wait4() would do.  A LIVE, non-init parent keeps its zombies untouched (the
// panel wait4()s its popovers via the owned-flag toggle; zsh reaps its own jobs), so this is safe.
private __gshared int g_reapTick = 0;
private void maybeReapZombies() {
    if ((g_reapTick++ & 0x3F) != 0) return;   // ~every 64 reconcile loops — cheap
    for (int t = 1; t < MAX_TASKS; t++) {
        auto tk = &g_tasks[t];
        if (!tk.active || !tk.exited) continue;          // only zombies (exited but slot still held)
        const int p = tk.parentId;
        const bool nobodyWaits = (p <= 0) || (p >= MAX_TASKS) ||
                                 !g_tasks[p].active || g_tasks[p].exited;   // init / invalid / dead parent
        if (nobodyWaits) releaseTask(t);
    }
}

private void kernelLoop() {
    while (true) {
        if (!g_loopTagPrinted) {
            g_loopTagPrinted = true;
            bootProgress("loop-start");
        }
        // SMP_ROADMAP S4.4d: take the Big Kernel Lock across the whole kernel-handling portion of
        // the loop so the AP and BSP never race on shared state (g_current_task_id, g_tasks,
        // scheduleNext, the syscall dispatch).  It is released ONLY around the userspace run below,
        // so the AP can hold it (and dispatch its own task's syscalls) while the BSP is in ring 3.
        // EVERY exit path from here to the userspace run, and the end of the body, must release it.
        bklAcquire(&g_bkl);
        freezeProbeKlog();     // freeze diagnostic → /run/klog (filter "freeze"): who hogs the core during a stall
        presentProfTick();     // PERF: per-frame cost split (kernel blit vs compositor render), every 5 s
        fsPersistTick(pitMs());// ROADMAP 1.2: flush /home if it changed, at most every 30 s
        freezeWatchdog();      // LOST-WAKEUP RECOVERY: un-park stalled sleepers so the compositor resumes
        maybeReapZombies();    // free leaked task slots (crash-loop zombies) so new apps/installer can spawn
        maybeSpawnWaylandClient();
        // R2.5: GPU-test launchers OFF during Weston-GL bring-up — they contend with
        // Weston for the single shared GPU control queue. Re-enable once GL desktop is stable.
        // maybeSpawnGpuTest();   // R2.3: in-kernel virtio-gpu 3D clear (red pixel readback)
        // maybeSpawnGlTest();    // R2.4b: Mesa virgl GLES2 test — GL_RENDERER=virgl end-to-end
        //maybeSpawnThreadTest(); // diag (served its purpose): glib cross-thread wakeup — see g_pitMs/x2apic
        maybeSpawnDbus();      // M0: start the real system dbus-daemon (persistent bus)
        maybeSpawnSshd();      // SSH-in: start the dropbear launcher for remote access
        maybeSpawnDbusTest();  // M0: dbus-send GetId once the bus is up (proves EXTERNAL auth)
        maybeProcSelfTest();   // ROADMAP 2.1: prove /proc once real time and load have accrued
        maybeSyscallAudit();   // ROADMAP 2.2: record which syscalls are missing, once
        maybeEpollDump();      // ROADMAP 2.3: is the compositor watching the new client fd?
        maybeSyncNtp();        // NTP: set the wall clock from pool.ntp.org, with retries
        maybeSpawnLklTest();   // L2: boot LKL on EpinAnonymOS (musl + a thread-based timer host-op)
        //maybeSpawnNetLaunch(); // H3: standalone wpa (superseded by NM, which drives wpa itself at M5)
        maybeSpawnWpa();            // M5: launch wpa_supplicant (D-Bus) just before NM
        maybeSpawnNetworkManager(); // M2b: launch the real NetworkManager daemon once dbus + provider are up
        wifiBridgeDetect();         // WIFI=1: probe COM2 for the host WiFi bridge (one-shot)
        wifiBridgePoll();           // …and pump it: real host nmcli scan/connect <-> /run/wifi/*
        maybeSpawnWifiAgent();      // M6: Wi-Fi menu's D-Bus bridge (NM mode only; skipped by useDirectWifi + COM2 bridge)
        maybeSpawnWpaAgent();       // direct-wpa menu backend (default): NSP_SCAN -> /run/wifi/networks, connect via wpa config+SIGHUP
        maybeSpawnUdhcpc();         // external DHCP: busybox udhcpc gets the lease (NM's n-dhcp4 stalls)
        maybeSpawnNmcli();     // M2b: confirm NM is up by querying it over D-Bus with nmcli
        maybeSpawnLogUpload(); // debug: snapshot logs and scp them when a client is staged
        maybeSpawnIdle();   // ensure the scheduler's idle task exists

        int tid = cast(int)g_current_task_id;
        auto task = &g_tasks[tid];

        if (!task.active || task.exited) {
            if (!g_schedTagPrinted) {
                g_schedTagPrinted = true;
                bootProgress("sched");
            }
            scheduleNext();
            // If scheduleNext found nothing new, check whether any task can
            // still run; if not, halt cleanly instead of spinning forever.
            if (cast(int)g_current_task_id == tid) {
                bool anyRunnable = false;
                for (uint i = 0; i < MAX_TASKS; i++) {
                    if (g_tasks[i].active && !g_tasks[i].exited) {
                        anyRunnable = true;
                        break;
                    }
                }
                if (!anyRunnable) {
                    klog("[kernel] all tasks exited — halting\n");
                    while (true) { asm @nogc nothrow { cli; hlt; } }   // terminal: BKL held, fine
                }
            }
            bklRelease(&g_bkl);
            continue;
        }
        if (task.waiting) {
            scheduleNext();
            bklRelease(&g_bkl);
            continue;
        }

        // Track A A4: a terminal signal (^C/^\) marked this task for the default
        // terminate action.  Apply it now from the victim's own context (about to run
        // tid) — exitTask switches to tid's CR3 to free its pages, which is unsafe to
        // do from the keystroke-writer's context where the signal was raised.
        if (g_taskPendingSig[tid] != 0) {
            int psig = g_taskPendingSig[tid];
            if (psig > 0 && psig < 64 && (g_taskSigCustom[tid] & (1UL << psig)) &&
                g_sigHandler[tid][psig] != 0) {
                // Z3: the task has a real handler (e.g. zsh's SIGINT for ^C).  Leave the
                // signal pending and run the task — it will be delivered at its next
                // blocking syscall (the read/pause yield below), where it interrupts that
                // syscall with EINTR so userspace (zsh's ZLE) re-checks its interrupt flag.
                // Delivering it async here would resume the rewound read and never EINTR.
            } else {
                g_taskPendingSig[tid] = 0;
                exitTask(tid, 128 + psig);   // default action: 128+signo (killed job)
                bklRelease(&g_bkl);
                continue;
            }
        }

        physSetActiveUntyped(task.untypedObjId);

        // Apply this task's FS base (for TLS)
        d_apply_task_fsbase(cast(ulong)tid);

        // Load task registers into curUserSpaceState
        loadTaskState(*task);

        // Switch to this task's page table
        x64WriteCR3(task.pml4Phys);

        // S4.4d: release the BKL across the userspace run — while the BSP is in ring 3 the AP can
        // hold the lock and dispatch its own task's syscalls.  Re-acquired immediately on return.
        bklRelease(&g_bkl);

        // Hand off to userspace; returns when an interrupt/syscall fires
        if (!g_runTagPrinted) {
            g_runTagPrinted = true;
            bootProgress("run-user");
            // Userspace is now live; stop the per-syscall framebuffer trace flood so
            // the screen is free for the [disp] display-claim markers and the desktop.
            g_screenTraceQuiet = true;
        }
        const ulong _sw0 = rdtsc();
        ulong reason = x64SwitchToUserspace(
            cast(void*)&curUserSpaceState[0],
            cast(void*)&kernelState[0]);

        bklAcquire(&g_bkl);   // back in the kernel — re-take the lock for the handling below
        if (!g_backTagPrinted) {
            g_backTagPrinted = true;
            bootProgress("back");
        }
        if (tid >= 0 && tid < MAX_TASKS) {
            g_schedCyc[tid] += rdtsc() - _sw0;   // userspace cycles this quantum
            ++g_schedN[tid];
        }

        // Kernel is back; switch page table back to the kernel's own CR3
        // (not strictly needed since kernel is in high half, but safer)
        // x64WriteCR3(kernelCr3);  — skip; kernel mappings are always valid

        // Save user register state
        saveTaskState(*task);

        if (reason == 0x100) {
            // SYSCALL instruction
            if (!g_syscallTagPrinted) {
                g_syscallTagPrinted = true;
                bootProgress("syscall");
            }
            dispatchSyscall(tid);
        } else if ((reason & 0x80) != 0) {
            // Hardware IRQ — irq0 pushes 0x80, irq1 → 0x81, …, irq12 → 0x8C
            uint irqIdx = cast(uint)(reason - 0x80);

            if (irqIdx == 0) {
                // Local-APIC timer, TICK_HZ (4000 Hz).  The i8042 output buffer is ONLY
                // 1 byte deep and a PS/2 byte arrives every ~0.7-1.1 ms, so a 1000 Hz
                // drain falls behind and LOSES bytes → 3-byte mouse packets desync → the
                // cursor jumps.  Drain the i8042 on EVERY (fast) tick so no byte is lost;
                // run the clock + scheduler only every TICK_DIV-th tick to keep them at
                // 1000 Hz (clock_gettime/timerfd are in ms, and over-preempting is wasteful).
                if (!g_irq0TagPrinted) {
                    g_irq0TagPrinted = true;
                    bootProgress("irq0");
                }
                ps2PollUnified();
                lapicEOI();       // EOI every interrupt so the local-APIC keeps firing
                if ((++g_tickDiv) >= TICK_DIV) {
                    g_tickDiv = 0;
                    increment_ticks();   // 1000 Hz monotonic ms
                    // Sample who was running for /proc/stat.  g_idleTid is -1 before the idle
                    // task exists, which never equals a valid task id, so early ticks count busy.
                    cpuAccountTick(g_idleTid >= 0 && g_current_task_id == cast(ulong)g_idleTid);
                    // SMP_ROADMAP S4.4d: surface the AP task's parallel getpid progress from HERE.
                    if (g_apSyscallCount != 0 && (++g_apPitLogCtr % 2000) == 0) {
                        if (g_apActivatedIdx != 0) sendApIpi(apActivatedLapicId(), 0x40);
                        if (g_apPitLogN < 40) {
                            ++g_apPitLogN;
                            klog("[smp] cpu1 getpid x"); klog_hex(g_apSyscallCount);
                            klog(" apicTicks="); klog_hex(apActivatedApicTicks());
                            klog(" ipiCount="); klog_hex(apActivatedIpiCount());
                            klog(" allocNoBKL="); klog_hex(apAllocCount());
                            klog(" — AP runs preemptibly + handles IPIs + allocs lock-free-of-BKL, in PARALLEL with the desktop\n");
                        }
                    }
                    // Service the NIC rx ring.  networkStackPoll() early-returns unless the stack
                    // is running, so this costs nothing on a NIC-less boot.  Nothing else pumps it:
                    // every other call site is inside a blocking helper (dhcp/dns/http/https), so
                    // before this the LAN only received while some request was already spinning on
                    // it -- no background RX, no unsolicited inbound packet, ever.  One frame per
                    // 1 kHz tick caps RX at ~1000 pps, which is ample for DHCP/DNS/TCP; raise it to
                    // a bounded drain loop if throughput ever matters.
                    networkStackPoll();
                    wakePollers();
                    picEOI(false);    // harmless when PIC IRQ0 is masked; covers the legacy-PIT case
                    scheduleNext();
                }
            } else if (irqIdx == 1) {
                // PS/2 keyboard — read all available scancodes
                handleKbdIRQ();
                wakePollers();   // wake input-waiting clients immediately (low latency)
                picEOI(false);
            } else if (irqIdx == 12) {
                // PS/2 mouse — accumulate 3-byte packet
                handleMouseIRQ();
                wakePollers();
                picEOI(true);   // mouse is on PIC2 (slave), needs both EOIs
            } else {
                // All other IRQs: just send EOI so PIC doesn't stay masked
                if (irqIdx >= 8) picEOI(true);
                else             picEOI(false);
            }
        } else if (reason == 14) {
            // Page fault (#PF)
            ulong cr2     = x64ReadCR2();
            bool  isWrite = (x64TrapErrorCode & 2) != 0;

            // Special TLS arch_prctl compatibility path:
            // Some runtimes trigger a read fault at 0x10 with RDI=0x1002 (ARCH_SET_FS)
            if (cr2 == 0x10 && !isWrite) {
                ulong rdi = task.regs[REG_RDI];
                ulong rsi = task.regs[REG_RSI];
                if (rdi == 0x1002 && rsi != 0) {
                    linux_sys_arch_prctl(rdi, rsi);
                    // No page was mapped; advance RIP past the faulting instruction
                    // (the fault is at a "mov (%rdi), ..." — 3 bytes for movq (%r), r)
                    // Just resume; the instruction will fault again on next access
                    // if it is truly accessing 0x10. For arch_prctl emulation we
                    // can just return 0 to RAX and skip ahead.
                    task.regs[REG_RAX] = 0;
                    bklRelease(&g_bkl);
                    continue;
                }
            }

            if (!handlePageFault(tid, cr2, isWrite)) {
                console_force_framebuffer_log();
                klog("[kernel] fatal PF tid="); klog_hex(tid);
                klog(" cr2="); klog_hex(cr2);
                klog(" rip="); klog_hex(task.regs[REG_RIP]);
                klog(" rsp="); klog_hex(task.regs[REG_RSP]);
                // For a fault on the first instruction of a leaf like strlen(),
                // [rsp] holds the return address into the caller — log it (and a
                // few stack slots) to locate the offending call site.
                {
                    // Only peek at the user stack if it is actually mapped — on a STACK
                    // OVERFLOW rsp itself is unmapped, and dereferencing it here would fault
                    // the kernel (a fatal nested KERNEL FAULT, exactly what zsh's deep
                    // completion triggered).  Guard every read.
                    ulong rsp = task.regs[REG_RSP];
                    if (rsp >= 0x1000 && userPageMapped(tid, rsp)) {
                        klog(" ret0="); klog_hex(*cast(ulong*)(rsp));
                        if (userPageMapped(tid, rsp + 8)) { klog(" ret1="); klog_hex(*cast(ulong*)(rsp + 8)); }
                        // Backtrace: dump up to 40 stack words so the offending call site (e.g. the
                        // caller of strdup that passed NULL) can be mapped to a Hyprland/-no-pie symbol.
                        klog("\n[kernel] stackwalk:");
                        for (ulong i = 0; i < 40; i++) {
                            ulong a = rsp + i * 8;
                            if (!userPageMapped(tid, a)) break;
                            ulong v = *cast(ulong*)a;
                            // only print plausible code addresses (main .text ~0x40xxxxx, libs 0x74xxxx.., interp 0x5axxx..)
                            if ((v >= 0x400000 && v < 0x5000000) || (v >= 0x740000000000 && v < 0x750000000000) ||
                                (v >= 0x5a0000000000 && v < 0x5b0000000000)) {
                                klog(" "); klog_hex(v);
                            }
                        }
                    }
                }
                klog(" err="); klog_hex(x64TrapErrorCode); klog("\n");
                exitTask(tid, 11); // SIGSEGV
            }
        } else if (reason <= 31) {
            // CPU exception — kill task
            console_force_framebuffer_log();
            klog("[kernel] exception "); klog_hex(reason);
            klog(" tid="); klog_hex(tid);
            klog(" rip="); klog_hex(task.regs[REG_RIP]);
            klog(" rsp="); klog_hex(task.regs[REG_RSP]);
            klog("\n");
            exitTask(tid, 11);
        }
        // else: unknown — ignore and continue
        bklRelease(&g_bkl);   // S4.4d: end of the BKL-protected handling for this iteration
    }
}

// ------------------------------------------------------------------
// Entry point called from bootstrap_kernel()
// ------------------------------------------------------------------

// Locate the dynamic-linker boot module (ld-musl) for a PT_INTERP request.
// Matched by a stable substring of the module name rather than the exact
// PT_INTERP path, which is the host build path until binaries are linked with
// -Wl,--dynamic-linker=/lib/ld-musl-x86_64.so.1.
private bool findInterpModule(const(char)* interpPath, out ulong physOut, out ulong sizeOut) {
    physOut = 0;
    sizeOut = 0;
    if (g_mboot_modules is null || g_module_count <= 0) return false;
    auto recs = cast(ubyte*)g_mboot_modules;
    for (int i = 0; i < g_module_count; i++) {
        auto rec  = cast(multiboot_module_t*)(recs + i * 128);
        auto name = cast(const(char)*)(cast(ubyte*)rec + 16);
        if (cstrContainsK(name, "ld-musl") || cstrContainsK(name, "ld.so")) {
            physOut = cast(ulong)rec.mod_start;
            sizeOut = cast(ulong)rec.mod_end - physOut;
            return true;
        }
    }
    return false;
}

private void bootProgress(const(char)* stage) {
    console_framebuffer_write("[");
    console_framebuffer_write(stage);
    console_framebuffer_write("] ");
}

// Direct-to-framebuffer process trace (real-hardware bring-up).  The fast-boot
// fb-log-off below routes klog to serial only — invisible on a serial-less laptop —
// so process exec/exit must be written straight to the framebuffer to be seen.
// Bounded (<=64 lines) so it can never flood the way the per-syscall trace did.
// Shows whether the compositor (init=weston) launched, forked helpers, or died early.
private __gshared uint g_procFbLogN = 0;
private void fbDec(ulong v) {
    if (v == 0) { console_framebuffer_write("0"); return; }
    char[20] b; int i = 20;
    while (v != 0 && i > 0) { b[--i] = cast(char)('0' + cast(uint)(v % 10)); v /= 10; }
    char[21] t; int n = 0;
    for (int j = i; j < 20; ++j) t[n++] = b[j];
    t[n] = 0;
    console_framebuffer_write(t.ptr);
}
private void procFb(const(char)* label, const(char)* name) {
    if (g_procFbLogN >= 64) return;
    ++g_procFbLogN;
    console_framebuffer_write("\n[proc] ");
    console_framebuffer_write(label);
    if (name !is null) { console_framebuffer_write(" "); console_framebuffer_write(name); }
}

void d_kernel_main() {
    klog("[dkernel] EpinAnonymOS D kernel starting\n");
    // BUILD STAMP.  __DATE__/__TIME__ are expanded when THIS FILE is compiled, so the line
    // below dates the kernel binary, not the ISO or the boot.  It exists because "the change
    // is committed, the ISO is newer than the commit, and the behaviour did not change" has
    // now cost four debugging rounds in a row -- each one spent re-deriving from behaviour
    // whether a build actually picked the edit up.  One grep answers that now:
    //     grep -a '\[build\]' serial.log
    // If the stamp predates the edit you are testing, stop reading the log: the kernel in
    // that ISO is stale.  Rebuild with `make -C src/kernel/d clean` first, because `make iso`
    // reaches the D sub-make through the phony refresh-d-kernel and a stale object there is
    // invisible from the top level.
    // NB: klog takes const(char)*, and a `~` concatenation is a string, not a literal, so it
    // needs the explicit "\0".ptr idiom used elsewhere in this tree -- not a bare literal.
    klog(BUILD_STAMP.ptr);
    klog("[dkernel] framebuffer log off for fast boot; faults re-enable it\n");
    console_set_framebuffer_enabled(false);
    bootProgress("boot");

    // Initialise task 0 (init process) slot
    g_tasks[0] = Task.init;
    g_tasks[0].active   = true;
    g_tasks[0].parentId = -1;
    g_tasks[0].processLeaderTid = 0;
    g_tasks[0].fdTabId = 0;
    g_tasks[0].capTabId = 0;
    g_tasks[0].mmapNext = 0x740000000000UL;
    g_current_task_id   = 0;
    untypedRootInit();
    g_tasks[0].untypedObjId = untypedCreateProcess(0);
    if (g_tasks[0].untypedObjId == 0) {
        console_force_framebuffer_log();
        klog("[dkernel] ERROR: no init untyped budget\n");
        while (true) { asm @nogc nothrow { cli; hlt; } }
    }
    installTaskUntypedCap(0);
    // Task 0 (PID1) is the ONLY task built by hand here instead of by a spawner wrapper, so it
    // was the only task whose fd table nobody ever populated: spawnWaylandProgram (1368),
    // domainSpawnProgram (1422) and maybeSpawnIdle (1512) each call fdtabSetupConsoleStdio()
    // on the tid they just allocTask()'d (allocTask scans from 1, so never 0), and execveTask
    // itself touches no fd state.  PID1's stdio was therefore left to initFdTable()'s lazy
    // one-shot, which writes through the ACTIVE table pointer (g_fdTable, repointed by
    // fdtabSetActive() before every syscall) and then latches globally -- so whichever process
    // happened to make the first fd syscall got console stdio, and nobody else ever would.
    // On a Hyprland boot that was hos-sshd-launch's socket() as tid 2: table 0 stayed
    // all-FD_NONE, and the compositor's writev(1)/writev(2)/ioctl(1, TIOCGWINSZ) were all
    // rejected with EBADF in linuxSyscallCapPrecheck -- libc++'s std::print THROWS on a failed
    // write, so the first std::println() died in abort() before it could report anything.
    // (Weston only ever worked by accident: it is dynamically linked, so ld.so's open() ran the
    // one-shot inside tid 0's own syscall, with table 0 active.)  Install PID1's console stdio
    // eagerly, by table INDEX, exactly like every other task gets at spawn time.
    fdtabSetupConsoleStdio(g_tasks[0].fdTabId);
    klog("[build] fdcap-diag-v6 pid1 stdio installed\n");
    physSetActiveUntyped(g_tasks[0].untypedObjId);
    physEnableUntypedGate(true);
    bootProgress("task");

    // Find an ELF module to use as the init process.
    // Preference order: Hyprland desktop, busybox shell, then init.elf.
    ulong initPhys = 0;
    ulong initSize = 0;
    const(char)* initExecName = "sh\0".ptr;
    bool initIsHyprland = false;
    random_init();
    // R2.1 (GPU stack): probe the modern virtio-gpu for virgl 3D capability and log it — the
    // foundation for GPU-accelerated compositing/ratty (R2.2+).  Safe no-op if absent.
    { import drivers.graphics.virtio_gpu : virtioGpuDetectVirgl; virtioGpuDetectVirgl(); }
    // Phase 8: stand up Driver/Device objects for the synthetic /dev tree (and
    // wrap the block/NIC driver globals) before the init process opens /dev nodes.
    deviceRegistryInit();
    // Phase 10 / IMMUTABLE_ROOTLESS §3: register User objects, flip task 0 to
    // the non-root subject, then grant PID1 only explicit typed admin caps needed
    // by the current compatibility stubs.
    userRegistryInit();
    installConfigApply();
    { import core.boot_integrity : bootIntegrityVerifyLocal; bootIntegrityVerifyLocal(); }
    g_tasks[0].userObjId = userDefaultObjId();
    userSetActiveSubject(g_tasks[0].userObjId);
    adminInstallInitCaps(g_tasks[0].capTabId);
    // IMMUTABLE_ROOTLESS §4.3: assemble the read-only /usr · overlay /etc · user-state
    // /var system namespace so its mount-rights write gate exists from first boot.
    storeMountSystem();
    // IMMUTABLE_ROOTLESS §6.1: stand up the A/B slots with the booted generation in
    // the active slot, marked known-good (the boot we are in succeeded this far).
    updateInit();
    // A5/F4: bring up the SATA disk so the object store can persist (no-op if no
    // disk is attached — the store then stays in-memory).
    diskInit();
    diskSelfTest();
    const bool installMedia = bootHasInstallPayload();
    vcCryptoKat();    // INSTALLER §E2b: validate the kernel AES-256 + SHA-512 (FIPS-197 / NIST)
    gptPartProof();   // INSTALLER §D2(b): build+validate a GPT layout (in-memory; no disk write)
    if (!installMedia) {
        gptWriteProof();  // INSTALLER §D2(b): write a GPT to a spare target disk + reread (SKIP if none)
        vcHeaderProof();  // INSTALLER §E2b: write a VeraCrypt header to a spare disk (host parity check)
        vcEncryptedLayoutProof(); // INSTALLER §E3: write the decoy/hidden encrypted layout (host validates)
        vcVolumeDataProof();      // INSTALLER §E4a: multi-sector XTS volume data + random free-fill
        installCapProof();        // INSTALLER §E4c: one-shot block-write capability gate (Phase 11)
        vcEncryptedInstallProof(); // INSTALLER §E4b: 3-partition encrypted GPT + ESP + decoy header
        vcFullInstallProof();      // INSTALLER: in-kernel FULL-DISK install (F2 featureless) on a small disk
    } else {
        klog("[install] INSTALL image: skipping disk-writing boot proofs; target disk is reserved for the GUI installer\n");
    }
    {                          // INSTALLER §D: in-OS BOOTABLE install (esp-image → target disk; INSTALL=1 only)
        import drivers.veracrypt_impl : installBootableProof;
        installBootableProof();
    }
    bootProgress("install");
    // F4: mount the persisted object store (formats on first boot, seeds the sample
    // app, bumps the on-disk boot counter — the cross-reboot persistence proof).
    // F4.2: locate the store-app image boot module so seeded apps get a real,
    // launchable executable blob (phys -> HHDM virt for the CPU read).
    const(void)* appImg = null; uint appImgLen = 0;
    if (g_mboot_modules !is null && g_module_count > 0) {
        auto recs = cast(ubyte*)g_mboot_modules;
        for (int i = 0; i < g_module_count; i++) {
            auto rec = cast(multiboot_module_t*)(recs + i * 128);
            const(char)* modName = cast(const(char)*)(cast(ubyte*)rec + 16);
            const(char)* modBase = modName;
            for (const(char)* p = modName; *p != 0; p++) if (*p == '/') modBase = p + 1;
            if (cstrEqK(modBase, "store-app")) {
                appImgLen = cast(uint)(cast(ulong)rec.mod_end - cast(ulong)rec.mod_start);
                appImg = cast(const(void)*)(cast(ulong)rec.mod_start + hhdm_offset);
                break;
            }
        }
    }
    objstoreMount(appImg, appImgLen);
    // ROADMAP 1.2: restore /home from the store, immediately after it mounts and before any
    // userspace runs, so a shell or app started later sees the files it saw last boot.
    fsPersistInitRoots();  // ROADMAP 1.2: read `persist =` from /desktop.conf
    fsPersistLoad();
    fsPersistSelfTest();   // ROADMAP 1.2: prove the round trip across reboots
    // procSelfTest() deliberately does NOT run here: at store-mount the PIT has barely ticked and
    // the idle task does not exist yet, so /proc/stat and /proc/uptime correctly read zero and the
    // proof shows nothing.  It runs from the periodic loop once the desktop is up instead.
    bootProgress("store");
    serviceManagerInit(USER_RIGHT_LOGIN | USER_RIGHT_SPAWN);
    // Phase 11: register the primary Output object for the firmware framebuffer
    // (the in-kernel compositor's Window/Surface objects register as it runs).
    windowRegistryInit(g_fb !is null ? cast(uint)g_fb.width : 0,
                       g_fb !is null ? cast(uint)g_fb.height : 0);
    // IDENTITY_DOMAIN §2/§3: build the compiled-in security-domain identities and
    // label PID1 (task 0) with the System identity before its first syscall.
    // fork/clone inherit this label; transitions into other identities (§3) require
    // CAP_RIGHT_ADMIN_IDENTITY + a launch rule.
    identityInitDefaults();
    identityInitLaunchRules();   // §3 compiled-in transition rules (after the identities exist)
    idnsInitRoots();             // §4 private object-root Directory per identity
    domainInitDefaults();        // DOMAIN_MANAGER DM0: 7 RAM domains, one per identity (after they exist)
    {   // DM3: give core.domain a launcher, so "spawn <domain> <prog>" can create a confined
        // task.  core.domain cannot reach allocTask/execveTask (kernel_main already imports it,
        // so importing back would be a cycle) -- hence the hook.
        import core.domain : domainSetSpawnHook, domainSetModeHook;
        domainSetSpawnHook(&domainSpawnProgram);
        domainSetModeHook(&domainModeSelf);   // DM13: "mode self linux" ratchet
    }
    domainSelfTest();            // DOMAIN_MANAGER DM0: one-shot proof create/lookup/dup/unknown-id/freeze (deterministic at boot)
    nsRestrictedSelfTest();      // DOMAIN_MANAGER DM2: one-shot proof deny-by-default restricted namespace (deterministic at boot)
    domainNsProof();             // DOMAIN_MANAGER DM2.2: build a real domain's restricted ns + prove its policy
    idipcInit();                 // §5 install cross-identity IPC gate + default brokered pairs
    idwinInit();                 // §6 install winRegister identity-stamp hook (unspoofable borders)
    g_tasks[0].identityObjId = identityByName("System\0".ptr);
    // Phase 12: build the Linux-compat object subtree and enable the personality
    // before the init process issues its first syscall (the dispatcher routes all
    // Linux syscalls through the LinuxSyscallObject gate from here on).
    linuxObjectInit();
    // ORG P2: initialise the object reference graph (installs the free-notify hook
    // for weak-edge coherence) before any object churn.
    orgInit();
    orgValidatorInit(); // ORG P8: stand up the validator daemon + its capability token
    // DECLARITIVE_MODEL_ROADMAP §4: apply the verified declarative-config manifest
    // (if staged as the manifest.blob boot module).  Locates it, HMAC-verifies it
    // (cryptoVerify), and lowers it onto the service/identity/namespace managers
    // — so a declared config, not hardcoded init, constructs running state.  Safe
    // fallthrough: a missing/tampered manifest logs + continues to hardcoded init.
    configBootApply();
    domainRehydrateFromDisk();   // DOMAIN_MANAGER DM5: recreate persisted domains (after seed+manifest; dedup by name)
    // DOMAIN_MANAGER DM0.d/DM1: run the domain VIEW proofs AFTER the manifest applies, so they
    // reflect the final registry (DM0 seed + any DM1 manifest-declared domains).
    configDomainsDump();         // /config/domains.json render (now includes manifest domains)
    domObjViewDump();            // /objects/domains/<name>/{meta,relationships,capabilities}
    domReadPathProof();          // end-to-end /objects/domains read path (parse+render)
    domFsManifestProof();        // DOMAIN_MANAGER DM2.3: DevSandbox's ns reflects its manifest filesystemAccess
    domFsViewDump();             // DOMAIN_MANAGER DM2.4: dump DevSandbox's RuntimeView (/objects/domains/<name>/filesystem)
    domainEnterProof();          // DOMAIN_MANAGER DM3: bind a task into a domain → its opens are enforced against the domain ns
    domainLifecycleProof();      // DOMAIN_MANAGER DM4: clone/start/pause/resume/shutdown/rename/delete state machine
    domainPersistProof();        // DOMAIN_MANAGER DM5: 2-boot persistence probe (boot1 persists, boot2 rehydrates)
    domainTemplateProof();       // DOMAIN_MANAGER DM6: immutable template + domain→template reference
    overlaySelfTest();           // DOMAIN_MANAGER DM6.2: writable overlay (CoW) — snapshot/discard/commit over the real store
    domainOverlayWriteProof();   // DOMAIN_MANAGER DM6.2 data plane: a domain-bound task's file create lands in its overlay
    domainBuildAllNamespaces();  // DOMAIN_MANAGER DM10.2: give every domain a restricted ns so the GUI's Filesystem RuntimeView shows a policy for each
    domainControlProof();        // DOMAIN_MANAGER DM10.3: drive a domain through its lifecycle via parsed control strings (the action-panel executor)
    domDeviceProof();            // DOMAIN_MANAGER DM8: §7 device-class enforcement (deviceClassGate)
    pkgRepoSelfTest();           // DOMAIN_MANAGER DM7: software repo + cap-gated per-domain package install
    configPackagesDump();        // DOMAIN_MANAGER DM7: /config/packages.json render proof (catalog + installs)
    configDisksDump();           // INSTALLER: /config/disks.json install-target view (AHCI or NVMe idx 0)
    { import core.sysupdate : updateAdoptBootSlot; updateAdoptBootSlot(); } // UPDATE U1: read A/B boot-state → g_bootSlot
    { import core.sysversion : updateVersionProof; updateVersionProof(); } // UPDATE U0: version identity proof
    {   // UPDATE U1: prove the boot-state on-disk contract, but only on a scratch/install
        // target — never round-trip a real installed system's live boot-state sector.
        import drivers.veracrypt_impl : bootHasInstallPayload;
        import core.bootstate : bootStateSelfTest;
        import core.sysupdate : updateEngineSelfTest;
        if (bootHasInstallPayload()) { bootStateSelfTest(); updateEngineSelfTest(); }
    }
    domDistroProof();            // DOMAIN_MANAGER DM11: per-domain distro/pkgMgr + RO /linux compat root
    templateBundleProof();       // DOMAIN_MANAGER DM12: signed .hosdt template export/import + trust + rollback
    domInheritProof();           // DOMAIN_MANAGER DM9: template inheritance least-privilege merge
    smpWorkReport();             // SMP_ROADMAP S4 foundation: APs ran parallel kernel work during boot
    bootProgress("domains");
    if (g_mboot_modules !is null && g_module_count > 0) {
        auto recs = cast(ubyte*)g_mboot_modules;

        // Highest priority: the dynamic-linking verification harness (Phase E).
        // Only present when the "dyntest" module is staged for testing; in normal
        // builds this finds nothing and falls through to the desktop target.
        for (int i = 0; i < g_module_count && initPhys == 0; i++) {
            auto rec  = cast(multiboot_module_t*)(recs + i * 128);
            auto name = cast(const(char)*)(cast(ubyte*)rec + 16);
            if (cstrContainsK(name, "dyntest")) {
                initPhys = cast(ulong)rec.mod_start;
                initSize = cast(ulong)rec.mod_end - cast(ulong)rec.mod_start;
                initExecName = cstrBasenameK(name);
                klog("[dkernel] init = dyntest (dynamic-linker test)\n");
            }
        }

        // GW3: Weston (Wayland reference compositor + Pixman software renderer)
        // takes priority over Hyprland as the desktop target when its module is
        // staged. Match the binary by EXACT basename "weston" so the weston-*
        // helper-client modules (weston-desktop-shell, weston-terminal, …) aren't
        // mistaken for the compositor. Staging weston is what toggles this on;
        // remove it from the ISO to fall back to Hyprland for comparison.
        // ...UNLESS /epin-hyprland.conf is staged, in which case skip this pass entirely and let
        // the Hyprland loop below claim init.  Both compositors stay in the image either way.
        for (int i = 0; i < g_module_count && initPhys == 0 && !hyprlandPreferred(); i++) {
            auto rec  = cast(multiboot_module_t*)(recs + i * 128);
            auto name = cast(const(char)*)(cast(ubyte*)rec + 16);
            if (cstrEqK(cstrBasenameK(name), "weston\0".ptr)) {
                initPhys = cast(ulong)rec.mod_start;
                initSize = cast(ulong)rec.mod_end - cast(ulong)rec.mod_start;
                initExecName = cstrBasenameK(name);
                klog("[dkernel] init = Weston module (GW3)\n");
            }
        }
        if (hyprlandPreferred())
            klog("[dkernel] /epin-hyprland.conf staged -> Weston skipped, selecting Hyprland\n");

        // First pass: Hyprland is the desktop autostart target when present.
        for (int i = 0; i < g_module_count && initPhys == 0; i++) {
            auto rec  = cast(multiboot_module_t*)(recs + i * 128);
            auto name = cast(const(char)*)(cast(ubyte*)rec + 16);
            // Basename-EXACT, not substring.  "/epin-hyprland.conf" also contains
            // "hyprland", and it sorts ahead of "/Hyprland" in the module list, so a
            // substring match selected the 32-byte TEXT marker as init:
            //     [dkernel] init = Hyprland module
            //     [dkernel] init phys=... size=0000000000000020   <- 32 bytes, not 38 MB
            //     [elf] bad magic / [dkernel] ELF load failed
            // and the machine came up with no desktop at all.  That marker exists purely to
            // CHOOSE Hyprland (staged by `HYPRLAND=1 make iso`), so the substring match made
            // the flag defeat itself -- HYPRLAND=1 was strictly worse than not passing it.
            const(char)* hlBase = cstrBasenameK(name);
            if (cstrEqK(hlBase, "Hyprland") || cstrEqK(hlBase, "hyprland")) {
                initPhys = cast(ulong)rec.mod_start;
                initSize = cast(ulong)rec.mod_end - cast(ulong)rec.mod_start;
                initExecName = cstrBasenameK(name);
                initIsHyprland = true;
                klog("[dkernel] init = Hyprland module\n");
            }
        }

        // Second pass: look for busybox and dispatch it as ash.
        for (int i = 0; i < g_module_count && initPhys == 0; i++) {
            auto rec  = cast(multiboot_module_t*)(recs + i * 128);
            auto name = cast(const(char)*)(cast(ubyte*)rec + 16);
            if (cstrContainsK(name, "busybox")) {
                initPhys = cast(ulong)rec.mod_start;
                initSize = cast(ulong)rec.mod_end - cast(ulong)rec.mod_start;
                initExecName = "sh\0".ptr;
                klog("[dkernel] init = busybox module\n");
            }
        }

        // Third pass: init.elf
        for (int i = 0; i < g_module_count && initPhys == 0; i++) {
            auto rec  = cast(multiboot_module_t*)(recs + i * 128);
            auto name = cast(const(char)*)(cast(ubyte*)rec + 16);
            if (cstrContainsK(name, "init.elf") || cstrContainsK(name, "init")) {
                initPhys = cast(ulong)rec.mod_start;
                initSize = cast(ulong)rec.mod_end - cast(ulong)rec.mod_start;
                initExecName = cstrBasenameK(name);
                klog("[dkernel] init = init.elf module\n");
            }
        }

        // Fallback: last module that looks like an ELF
        for (int i = g_module_count - 1; i >= 0 && initPhys == 0; i--) {
            auto rec  = cast(multiboot_module_t*)(recs + i * 128);
            auto name = cast(const(char)*)(cast(ubyte*)rec + 16);
            ulong phys = cast(ulong)rec.mod_start;
            ulong size = cast(ulong)rec.mod_end - phys;
            if (size < 16) continue;
            auto magic = cast(ubyte*)(phys + hhdm_offset);
            if (magic[0] == 0x7f && magic[1] == 'E' &&
                magic[2] == 'L'  && magic[3] == 'F') {
                initPhys = phys;
                initSize = size;
                initExecName = cstrBasenameK(name);
                klog("[dkernel] init = fallback ELF module\n");
            }
        }
    }

    if (initPhys == 0) {
        console_force_framebuffer_log();
        klog("[dkernel] ERROR: no init module found, halting\n");
        while (true) { asm @nogc nothrow { cli; hlt; } }
    }

    klog("[dkernel] init phys="); klog_hex(initPhys);
    klog(" size="); klog_hex(initSize); klog("\n");
    procFb("init=", initExecName);   // direct-fb: which compositor/binary is PID1
    // PID1 is loaded HERE, not through execveTask, so it never passed the boot-module
    // scan that assigns g_taskExecName — leaving task 0 (and every task forked from it,
    // which inherits the null) nameless in every diagnostic that names a task: the freeze
    // watchdog's cur=/HOG= line, the crash HUD, and the hang trace's who=.  They all
    // printed "?" for the compositor, the one process those diagnostics exist to watch.
    g_taskExecName[0] = initExecName;
    bootProgress("elf");

    // Allocate a new PML4 for the init process
    ulong pml4Phys = alloc_phys_page();
    if (pml4Phys == 0) {
        console_force_framebuffer_log();
        klog("[dkernel] OOM allocating PML4\n");
        while (true) { asm @nogc nothrow { cli; hlt; } }
    }
    g_tasks[0].pml4Phys = pml4Phys;
    objEnsureTask(0);
    objSetProcess(0, 0, 0);

    // Copy kernel high-half mappings into the new page table
    archMapKernel(pml4Phys);

    // Switch to the init process page table
    x64WriteCR3(pml4Phys);

    // Load the ELF binary.  A fixed-address ET_EXEC loads at its own vaddrs
    // (bias 0); an ET_DYN (PIE) main exe is relocated to a high base.
    ulong elfVirt = phys_to_virt(initPhys);
    ushort initType = *cast(ushort*)(elfVirt + 16);
    ulong mainBias = (initType == 3 /*ET_DYN*/) ? USER_MAIN_PIE_BASE : 0;

    char[256] interpPath;
    linuxNoteElfLoad(); // Phase 12: LinuxELFLoaderObject sees the init load
    auto res = loadElf(g_tasks[0], elfVirt, initPhys, mainBias,
                       interpPath.ptr, interpPath.length);
    if (!res.ok) {
        console_force_framebuffer_log();
        klog("[dkernel] ELF load failed\n");
        while (true) { asm @nogc nothrow { cli; hlt; } }
    }

    klog("[dkernel] ELF entry="); klog_hex(res.entry);
    klog(" topVirt="); klog_hex(res.topVirt); klog("\n");

    g_tasks[0].brkStart   = res.topVirt;
    g_tasks[0].brkCurrent = res.topVirt;

    // If the binary is dynamically linked, load its interpreter (ld-musl) at a
    // high base and begin execution there.  ld.so then maps the exe's shared
    // libraries, relocates everything, and jumps to the real entry itself — the
    // kernel does not implement relocations.
    ulong entryRip = res.entry;
    ulong atBase   = 0;
    if (res.hasInterp) {
        klog("[dkernel] PT_INTERP="); klog(interpPath.ptr); klog("\n");
        ulong ipPhys = 0, ipSize = 0;
        if (findInterpModule(interpPath.ptr, ipPhys, ipSize)) {
            ulong ipVirt = phys_to_virt(ipPhys);
            auto ires = loadElf(g_tasks[0], ipVirt, ipPhys, USER_INTERP_BASE, null, 0);
            if (ires.ok) {
                entryRip = ires.entry;
                atBase   = USER_INTERP_BASE;
                klog("[dkernel] interp loaded base="); klog_hex(USER_INTERP_BASE);
                klog(" entry="); klog_hex(entryRip); klog("\n");
            } else {
                klog("[dkernel] interp load FAILED\n");
            }
        } else {
            klog("[dkernel] interp module NOT FOUND\n");
        }
    }

    // Allocate user stack (256 pages = 1 MB at 0x700000000000).  See the matching note above:
    // zsh's completion recursion overflowed the old 128 KB stack.
    enum stackPages = 256;
    ulong stackPhys = alloc_phys_pages(stackPages);
    if (stackPhys == 0) {
        console_force_framebuffer_log();
        klog("[dkernel] OOM allocating stack\n");
        while (true) { asm @nogc nothrow { cli; hlt; } }
    }
    ulong stackSize = stackPages * 4096;
    ulong stackBase = 0x700000000000UL;
    ulong stackTop  = stackBase + stackSize;

    for (ulong pg = 0; pg < stackPages; pg++)
        map_page_hhdm(stackPhys + pg * 4096, stackBase + pg * 4096,
                      PTE_PRESENT | PTE_RW | PTE_USER, &alloc_phys_page);

    auto initStackRegion = addRegion(g_tasks[0], stackBase, stackTop,
                                     RegionType.Mapped, RegionPerms.ReadWrite,
                                     stackPhys, true);
    if (initStackRegion !is null)
        physPagesSetOwner(stackPhys, stackPages, initStackRegion.objId,
                          initStackRegion.vmoObjId);

    // Auxv from the loaded image (handles PIE bias + dynamic interpreter).
    ulong[7] infoWords = [
        res.entry,                      // AT_ENTRY  (real exe entry, with bias)
        res.phdrVaddr,                  // AT_PHDR   (phdr table in memory)
        cast(ulong)res.phEnt,           // AT_PHENT
        cast(ulong)res.phNum,           // AT_PHNUM
        atBase,                         // AT_BASE   (interp base, 0 if static)
        0,                              // execBase
        cast(ulong)initExecName         // execfn kernel ptr -> argv[0]
    ];
    ulong rsp = linux_seed_initial_stack(
        stackPhys, stackSize, stackBase, infoWords.ptr, 4096);

    klog("[dkernel] rsp="); klog_hex(rsp);
    klog(" rip="); klog_hex(entryRip); klog("\n");

    // Set initial register state for init task.  For a dynamic binary RIP is the
    // interpreter's entry; for a static one it's the exe's own entry.
    for (uint i = 0; i < NUM_REGS; i++) g_tasks[0].regs[i] = 0;
    g_tasks[0].regs[REG_RIP]    = entryRip;
    g_tasks[0].regs[REG_RSP]    = rsp;
    g_tasks[0].regs[REG_RFLAGS] = 0x202; // IF=1
    bootProgress("user");

    g_guiClientAutostartEnabled = initIsHyprland;
    if (g_guiClientAutostartEnabled)
        klog("[g11] GUI client autostart armed\n");

    // Set up IDT and SYSCALL MSRs
    x64_ready_for_userspace();

    // Remap PIC to vectors 32-47 and unmask timer (IRQ0) + keyboard (IRQ1) + mouse (IRQ12)
    initPIC();
    // Start the ~1000 Hz PIT tick so clock_gettime / timerfd advance
    initPIT();
    // Enable PS/2 mouse and its IRQ
    initPS2Mouse();
    bootProgress("input");

    // Native boot splash: particle-network animation + boot-log console drawn
    // directly to the framebuffer (~6s). Runs now — after initPIT (so pitMs
    // paces it) and before kernelLoop (so it owns the framebuffer until the
    // desktop compositor presents). No-op on serial-only/headless boots.
    // Size the display BEFORE anything paints.  The desktop was locked to whatever mode
    // limine picked at boot (DRM advertises exactly one mode, synthesised from g_fb in
    // fillModeInfo), which on Proxmox is the bootloader default regardless of how large
    // the console actually is -- hence "the dimensions do not auto resize".  This asks the
    // EDID what the display wants and reprograms the stdvga VBE registers to match.  It is
    // a no-op on any non-Bochs device, and must run before splashRun() paints.
    { import display.modesetting : displayAutoSizeFromEdid; displayAutoSizeFromEdid(); }
    if (installMedia) {
        bootProgress("splash-skip");
    } else {
        bootProgress("splash");
        splashRun();
        bootProgress("post-splash");
    }

    bootProgress("smp");
    smpActivateAp();             // SMP_ROADMAP S4.4a: activate an AP into apKernelLoop (desktop is up)
    // Real-hardware tick: now that x2APIC is enabled (smpActivateAp), start the BSP's
    // local-APIC timer as the system tick — the legacy PIT IRQ0 does not fire on UEFI
    // laptops, which froze the clock and stalled the compositor's first present.
    startBspApicTimer();
    g_bspApicId = readApicId();   // WiFi W1: capture the BSP's x2APIC ID (runs on the BSP) for MSI targeting
    wifiSurvey();   // print the machine's network controllers (id + driver/firmware) to the panel
    // LAN comes up on EVERY boot, install media included.  Probing the NIC and starting the
    // IPv4 stack touches no disk; `installMedia` exists to reserve the target DISK for the GUI
    // installer (see the gptWriteProof branch above), and networking was swept into that gate
    // by mistake.  That is why hos-install.iso -- the image everyone actually boots -- came up
    // with no NIC at all: networkSelfTest() is the only caller of startNetworkStack(), which is
    // the only caller of initNetwork(), so the PCI probe never ran.  Proven with NET=1: the boot
    // log was byte-identical to a -nic none boot and net.pcap held 0 packets.
    // Only the multi-second ARP/ping/DNS/DHCP proofs stay off install media, so it still boots fast.
    bootProgress("net");
    networkSelfTest(!installMedia);
    bootProgress("post-net");
    bootProgress("integrity");
    { import core.boot_integrity : bootIntegrityVerifyChain; bootIntegrityVerifyChain(); }
    klog("[dkernel] entering kernel loop\n");
    bootProgress("loop");
    kernelLoop();

    // Should never reach here
    while (true) { asm @nogc nothrow { cli; hlt; } }
}

// ------------------------------------------------------------------
// Utilities
// ------------------------------------------------------------------

private bool cstrContainsK(const(char)* haystack, string needle) {
    if (haystack is null) return false;
    size_t hl = 0;
    while (haystack[hl] != 0) hl++;
    if (needle.length > hl) return false;
    for (size_t i = 0; i <= hl - needle.length; i++) {
        bool match = true;
        for (size_t j = 0; j < needle.length; j++) {
            if (haystack[i + j] != needle[j]) { match = false; break; }
        }
        if (match) return true;
    }
    return false;
}

private const(char)* cstrBasenameK(const(char)* path) {
    if (path is null) return null;

    const(char)* base = path;
    for (const(char)* p = path; *p != 0; p++) {
        if (*p == '/') base = p + 1;
    }
    return base;
}
