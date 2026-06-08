// Identity / Security-Domain model — Phase 1 (data model) of
// roadmap/IDENTITY_DOMAIN_ROADMAP.md.
//
// A Qubes-style *identity* (security domain) is a first-class object
// (ObjType.Identity): every user-facing process is labelled with one, windows
// are bordered with the identity's color by the trusted compositor, and
// isolation is enforced by the existing capability + object + namespace
// substrate — not Unix uids or VMs.  Deny-by-default; the capability is always
// the authority (there is no ambient "current identity" global).
//
// Phase 1 is *only* the data model: the typed records, enums and fixed tables.
// No registry logic, validation, policy, or enforcement yet — those land in
// later phases (Identity Manager §2, namespaces §4, IPC §5, GUI §6, …).  Keeping
// the first slice to declarations matches the roadmap's "do not over-build."
//
// Kernel build constraints (hard): -betterC (ldc2, no GC/druntime/exceptions),
// plain structs, __gshared fixed-size tables, @nogc nothrow, -O0.
module core.identity;

import core.objmgr : ObjType;   // an identity *is* an ObjType.Identity object

extern (C) @nogc nothrow:

// --- identifiers (all are object ids; 0 = none) ------------------------------
alias IdentityId   = uint;   // objId of an ObjType.Identity
alias NamespaceId  = uint;   // objId of an ObjType.Namespace (core/namespace.d)
alias GuiContextId = uint;   // objId grouping an identity's windows/surfaces
alias IdentityColor = uint;  // packed 0xAARRGGBB, drawn by the trusted compositor

// Trust levels — higher = more trusted; used only as default-flow hints (e.g. a
// "down-trust" clipboard rule), never as an ambient authority check.
enum ubyte TRUST_SYSTEM    = 100;
enum ubyte TRUST_BANKING   = 80;
enum ubyte TRUST_WORK      = 60;
enum ubyte TRUST_PERSONAL  = 50;
enum ubyte TRUST_DEV       = 40;
enum ubyte TRUST_UNTRUSTED = 10;
enum ubyte TRUST_DISPOSABLE = 5;

enum NetPolicy : ubyte { None = 0, NAT, VPN, Tor, LocalOnly, Disposable }
enum ClipPolicy : ubyte { Deny = 0, AskApproval, AllowSameIdentity, AllowDownTrust }
enum GuiPolicy : uint {
    BorderAlways        = 1,
    TitleLabel          = 2,
    NoScreenshotAcrossId = 4,
    NoGlobalGrab        = 8,
}

// --- the identity object (immutable once `active`) ---------------------------
enum int ID_NAME_MAX = 24;
struct IdentityRec {
    bool          inUse;
    bool          active;        // once true: immutable except via signed txn (§9)
    bool          disposable;    // §8 throwaway domain
    IdentityId    objId;         // ObjType.Identity
    uint          templateId;    // disposable: the template it was cloned from (else 0)
    uint          nameLen;
    char[ID_NAME_MAX] name;      // "System","Personal","Work","Banking",…
    IdentityColor color;         // border color (compositor-drawn)
    ubyte         trust;         // TRUST_*
    uint          rightsCeiling; // max cap rights any process in this identity may hold
    NamespaceId   nsTemplate;    // object-tree root / namespace template cloned per process
    uint          objRootObjId;  // /identities/<name> Directory object
    uint          allowedDevices;// bitmask of brokered device classes (§7)
    NetPolicy     net;
    ClipPolicy    clip;
    uint          gui;           // GuiPolicy flags
    ulong         policyEpoch;   // bumped by each signed policy transaction (§9)
}

// --- per-identity allow-lists (deny-by-default; small fixed tables) ----------
// 0 brokerSvcObjId = direct allow; non-zero = the brokered service the pair routes through.
struct IpcPairRule { bool inUse; IdentityId from, to; uint brokerSvcObjId; }
// A cap-wrapped cross-identity object share (audited; rights ⊆ owner's).
struct ShareRule   { bool inUse; IdentityId owner; uint objId; uint rights; IdentityId grantee; }

// --- fixed registry tables (capacity chosen small; deny-by-default) ----------
// Logic that fills these (identityCreate/validate/freeze, rule install) is Phase 2+.
enum int ID_MAX          = 32;   // distinct identities
enum int ID_IPC_RULES_MAX = 64;  // cross-identity IPC allow-list entries
enum int ID_SHARE_RULES_MAX = 64;// cross-identity object-share entries

// Names are identity-prefixed because the -betterC `extern (C)` blanket exports
// module globals as flat C symbols (so `g_ids` would clash with core/secipc.d).
public __gshared IdentityRec[ID_MAX]           g_identities;
public __gshared IpcPairRule[ID_IPC_RULES_MAX]  g_idIpcRules;
public __gshared ShareRule[ID_SHARE_RULES_MAX]  g_idShareRules;
public __gshared bool g_idFrozen = false;      // registry immutable after policy load (§2)
