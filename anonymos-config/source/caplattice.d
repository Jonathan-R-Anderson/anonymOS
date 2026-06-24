// caplattice.d — Phase 6 (Stage 7) capability lattice, mirroring
// src/kernel/d/core/cap.d.  The kernel's capDerive invariant is "a child's
// rights mask must be a bitwise subset of the parent's".  This module makes the
// name↔bit mapping available to the host compiler so it can enforce that subset
// rule AT COMPILE TIME, before the kernel ever receives a request.
//
// All 19 right names + the three aggregates, exactly as core/cap.d defines them
// (verified against src/kernel/d/core/cap.d:19-48).  "all" expands to the
// fd-surface universe CAP_RIGHT_ALL, NOT the god-right UNIVERSE — admin rights
// are separate typed ObjType.Admin caps (spec Appendix B).
module anonymos.config.caplattice;

import std.array;

// Right name → bit mask.  Mirrors core/cap.d enum uint CAP_RIGHT_*.
immutable uint[string] CAP_RIGHTS = [
    "read"           : 1u << 0,
    "write"          : 1u << 1,
    "close"          : 1u << 2,
    "stat"           : 1u << 3,
    "ioctl"          : 1u << 4,
    "mmap"           : 1u << 5,
    "dup"            : 1u << 6,
    "pass"           : 1u << 7,
    "retype"         : 1u << 8,
    "call"           : 1u << 9,
    "admin_mount"    : 1u << 10,
    "admin_reboot"   : 1u << 11,
    "admin_update"   : 1u << 12,
    "admin_user"     : 1u << 13,
    "admin_device"   : 1u << 14,
    "admin_inspect"  : 1u << 15,
    "exec"           : 1u << 16,
    "admin_identity" : 1u << 17,
    "id_share"       : 1u << 18,
];

immutable uint CAP_RIGHT_ALL = (1u << 0) | (1u << 1) | (1u << 2) | (1u << 3) |
                               (1u << 4) | (1u << 5) | (1u << 6) | (1u << 7);

// Resolve a rights specification (a right name, "all", or a list) to a mask.
// `unknown` accumulates any names that are not real rights so the caller can
// report them.  Returns whether every name resolved.
bool resolveRights(in string[] rights, out uint mask, out string[] unknown)
{
    mask = 0;
    unknown = null;
    foreach (r; rights)
    {
        if (r == "all") { mask |= CAP_RIGHT_ALL; continue; }
        if (auto p = r in CAP_RIGHTS) { mask |= *p; }
        else unknown ~= r;
    }
    return unknown.length == 0;
}

// Is `child` a bitwise subset of `parent`?  (own & ~parent == 0) — capDerive.
bool isSubset(uint child, uint parent) { return (child & ~parent) == 0; }

// Human-readable list of the rights present in a mask (deterministic order).
string[] rightsNames(uint mask)
{
    string[] out_;
    foreach (name, bit; CAP_RIGHTS)
        if (mask & bit) out_ ~= name;
    return out_;
}
