// sysversion.d — the system's release identity (U0, roadmap/SYSTEM_UPDATE_ROADMAP.md).
// SYSTEM_VERSION is the MONOTONIC integer the update engine compares for anti-rollback
// (U2); SYSTEM_VERSION_STRING is the human-readable name. Bumped by release tooling.
module core.sysversion;

import core.io : klog, klog_hex;

@nogc nothrow:

public enum uint SYSTEM_VERSION = 1;
public immutable string SYSTEM_VERSION_STRING = "0.1.0";
public immutable string SYSTEM_CHANNEL = "stable";

// Boot slot this system came up from: 'A' until the U1 slot-arbiter passes the
// tried slot through the boot-state; the kernel reports it, never guesses it.
public __gshared char g_bootSlot = 'A';

// U0 boot proof: one klog line so version identity is verifiable headlessly
// (Logs app filter `update`) — same discipline as the other one-shot proofs.
public void updateVersionProof() {
    char[2] slot = [g_bootSlot, '\0'];
    klog("[update] system version=0x"); klog_hex(SYSTEM_VERSION);
    klog(" ("); klog(SYSTEM_VERSION_STRING.ptr);
    klog(") channel="); klog(SYSTEM_CHANNEL.ptr);
    klog(" slot="); klog(slot.ptr);
    klog("\n");
}
