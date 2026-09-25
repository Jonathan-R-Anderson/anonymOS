/*
 * PRX-SD Minifilter ↔ User-mode IPC Shared Definitions
 *
 * Include this header in both the kernel driver and the Rust user-mode
 * component (via bindgen or manual FFI definitions).
 */

#ifndef PRXSD_IPC_SHARED_H
#define PRXSD_IPC_SHARED_H

#define PRXSD_PORT_NAME      L"\\PrxSdScanPort"
#define PRXSD_MAX_PATH       520

/* Commands from kernel → user-mode */
typedef enum _PRXSD_COMMAND {
    PrxSdCommandScanFile = 1,       /* Request file scan */
    PrxSdCommandScanResult = 2,     /* Scan result (unused direction) */
    PrxSdCommandShutdown = 3,       /* Driver unloading */
} PRXSD_COMMAND;

/* Scan verdicts from user-mode → kernel */
typedef enum _PRXSD_SCAN_RESULT {
    PrxSdResultClean = 0,           /* File is clean */
    PrxSdResultSuspicious = 1,      /* File is suspicious (allow but log) */
    PrxSdResultMalicious = 2,       /* File is malicious (block access) */
    PrxSdResultError = 3,           /* Scan error (allow by default) */
} PRXSD_SCAN_RESULT;

/* Kernel → User-mode: scan request */
typedef struct _PRXSD_SCAN_REQUEST {
    PRXSD_COMMAND Command;
    WCHAR FilePath[PRXSD_MAX_PATH];
    ULONG ProcessId;
    LARGE_INTEGER FileSize;
} PRXSD_SCAN_REQUEST, *PPRXSD_SCAN_REQUEST;

/* User-mode → Kernel: scan reply */
typedef struct _PRXSD_SCAN_REPLY {
    PRXSD_SCAN_RESULT Result;
    WCHAR ThreatName[256];
} PRXSD_SCAN_REPLY, *PPRXSD_SCAN_REPLY;

#endif /* PRXSD_IPC_SHARED_H */
