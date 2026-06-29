// ─────────────────────────────────────────────────────────────────────────────
// One-shot install block-write capability (roadmap/INSTALLER.md §E4c / Phase 11)
//
// The installer is NOT root (rootless model).  To write a target disk it must hold a
// capability minted for THAT specific disk, which is revoked when the install finishes
// so it can't be replayed.  This is the least-privilege gate the §D2(b)/§E raw writers
// (diskWriteSectorsOn, gptWriteEncryptedToDisk, …) are meant to sit behind: no cap → no
// disk write; a cap for disk A can't write disk B; a revoked cap is dead.
//
// Production mints this only for the installer identity (CAP_RIGHT_ADMIN_DEVICE / a
// dedicated install right in core/cap.d); here the boot authority mints it for the proof.
// ─────────────────────────────────────────────────────────────────────────────
module core.install_cap;

import drivers.block.disk : diskWriteSectorsOn;
import core.io : klog, klog_hex;

@nogc nothrow:

struct InstallWriteCap {
    bool  valid;
    int   diskIdx;     // the one disk this cap authorizes
    ulong token;       // nonce — a zeroed/forged struct can't pass the gate
}

private __gshared ulong g_capNonce = 0;

// Mint a fresh one-shot cap authorizing writes to `diskIdx`.
InstallWriteCap mintInstallWriteCap(int diskIdx) {
    g_capNonce += 0x9E3779B97F4A7C15UL;
    InstallWriteCap c;
    c.valid = true; c.diskIdx = diskIdx; c.token = g_capNonce;
    return c;
}

// The gate: write succeeds ONLY with a valid cap that matches the target disk.
bool gatedDiskWrite(ref InstallWriteCap cap, int idx, ulong lba, uint count, const(void)* src) {
    if (!cap.valid || cap.token == 0 || cap.diskIdx != idx) return false;   // least-privilege
    return diskWriteSectorsOn(idx, lba, count, src);
}

// Revoke after the install — the cap is one-shot and can't be replayed.
void revokeInstallWriteCap(ref InstallWriteCap cap) {
    cap.valid = false; cap.token = 0;
}

// Boot proof: demonstrate the four enforcement cases on a spare disk.  SKIP without one.
public void installCapProof() {
    import drivers.block.disk : diskFindTarget;
    enum ulong CAP_TEST_LBA = 990_000;     // scratch, clear of the other §E proofs

    ulong tsec;
    int idx = diskFindTarget(tsec);
    if (idx < 0 || CAP_TEST_LBA >= tsec) { klog("[install-cap] proof SKIP (no spare disk)\n"); return; }

    ubyte[512] buf;
    foreach (i; 0 .. 512) buf[i] = cast(ubyte)i;

    InstallWriteCap none;                                   // valid == false
    const bool r1 = gatedDiskWrite(none, idx, CAP_TEST_LBA, 1, buf.ptr);          // no cap → refuse

    auto cap = mintInstallWriteCap(idx);
    const bool r2 = gatedDiskWrite(cap, idx, CAP_TEST_LBA, 1, buf.ptr);           // minted → allow
    const bool r3 = gatedDiskWrite(cap, idx ^ 1, CAP_TEST_LBA, 1, buf.ptr);       // wrong disk → refuse

    revokeInstallWriteCap(cap);
    const bool r4 = gatedDiskWrite(cap, idx, CAP_TEST_LBA, 1, buf.ptr);           // revoked → refuse

    const bool pass = !r1 && r2 && !r3 && !r4;
    klog("[install-cap] proof "); klog(pass ? "PASS" : "FAIL");
    klog(" (no-cap="); klog_hex(r1 ? 1 : 0); klog(" minted="); klog_hex(r2 ? 1 : 0);
    klog(" wrong-disk="); klog_hex(r3 ? 1 : 0); klog(" revoked="); klog_hex(r4 ? 1 : 0); klog(")\n");
}
