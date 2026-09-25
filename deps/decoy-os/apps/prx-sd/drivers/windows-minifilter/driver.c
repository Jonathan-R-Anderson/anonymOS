/*
 * PRX-SD Windows Minifilter Driver
 *
 * A file system minifilter driver that intercepts file I/O operations
 * and communicates with the PRX-SD user-mode antivirus engine for
 * real-time file scanning.
 *
 * Build Requirements:
 *   - Windows Driver Kit (WDK)
 *   - Visual Studio with WDK integration
 *
 * This driver registers as a minifilter and intercepts:
 *   - IRP_MJ_CREATE (file open/create)
 *   - IRP_MJ_WRITE (file write)
 *   - IRP_MJ_SET_INFORMATION (file rename/delete)
 *
 * Communication with user-mode is via a Filter Communication Port.
 */

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, \
    "Not valid for kernel mode drivers")

/* ---------- Constants ---------- */

#define PRXSD_FILTER_NAME    L"PrxSdMinifilter"
#define PRXSD_PORT_NAME      L"\\PrxSdScanPort"
#define PRXSD_MAX_CONNECTIONS 1
#define PRXSD_MAX_PATH       520
#define PRXSD_SCAN_TIMEOUT   30  /* seconds */

/* ---------- Message structures (shared with user-mode) ---------- */

typedef enum _PRXSD_COMMAND {
    PrxSdCommandScanFile = 1,
    PrxSdCommandScanResult = 2,
} PRXSD_COMMAND;

typedef enum _PRXSD_SCAN_RESULT {
    PrxSdResultClean = 0,
    PrxSdResultSuspicious = 1,
    PrxSdResultMalicious = 2,
    PrxSdResultError = 3,
} PRXSD_SCAN_RESULT;

/* Message sent to user-mode for scanning */
typedef struct _PRXSD_SCAN_REQUEST {
    PRXSD_COMMAND Command;
    WCHAR FilePath[PRXSD_MAX_PATH];
    ULONG ProcessId;
    LARGE_INTEGER FileSize;
} PRXSD_SCAN_REQUEST, *PPRXSD_SCAN_REQUEST;

/* Reply from user-mode with scan result */
typedef struct _PRXSD_SCAN_REPLY {
    PRXSD_SCAN_RESULT Result;
    WCHAR ThreatName[256];
} PRXSD_SCAN_REPLY, *PPRXSD_SCAN_REPLY;

/* ---------- Global data ---------- */

typedef struct _PRXSD_GLOBAL_DATA {
    PFLT_FILTER     Filter;
    PFLT_PORT       ServerPort;
    PFLT_PORT       ClientPort;
    BOOLEAN         Connected;
} PRXSD_GLOBAL_DATA, *PPRXSD_GLOBAL_DATA;

PRXSD_GLOBAL_DATA PrxSdGlobals;

/* ---------- Forward declarations ---------- */

DRIVER_INITIALIZE DriverEntry;
NTSTATUS PrxSdUnload(FLT_FILTER_UNLOAD_FLAGS Flags);

/* Minifilter callbacks */
FLT_PREOP_CALLBACK_STATUS
PrxSdPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
PrxSdPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
PrxSdPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

/* Communication port callbacks */
NTSTATUS PrxSdPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
);

VOID PrxSdPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
);

/* ---------- Callback registration ---------- */

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    {
        IRP_MJ_CREATE,
        0,
        PrxSdPreCreate,
        PrxSdPostCreate
    },
    {
        IRP_MJ_WRITE,
        0,
        PrxSdPreWrite,
        NULL
    },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),       /* Size */
    FLT_REGISTRATION_VERSION,       /* Version */
    0,                              /* Flags */
    NULL,                           /* Context */
    Callbacks,                      /* Operation callbacks */
    PrxSdUnload,                    /* MiniFilterUnload */
    NULL,                           /* InstanceSetup */
    NULL,                           /* InstanceQueryTeardown */
    NULL,                           /* InstanceTeardownStart */
    NULL,                           /* InstanceTeardownComplete */
    NULL, NULL, NULL                /* Unused */
};

/* ---------- Helper: Send scan request to user-mode ---------- */

NTSTATUS
PrxSdSendScanRequest(
    _In_ PUNICODE_STRING FilePath,
    _In_ ULONG ProcessId,
    _Out_ PPRXSD_SCAN_RESULT ScanResult
)
{
    PRXSD_SCAN_REQUEST request;
    PRXSD_SCAN_REPLY reply;
    ULONG replyLength = sizeof(FILTER_REPLY_HEADER) + sizeof(PRXSD_SCAN_REPLY);
    NTSTATUS status;
    LARGE_INTEGER timeout;

    *ScanResult = PrxSdResultClean;

    if (!PrxSdGlobals.Connected || PrxSdGlobals.ClientPort == NULL) {
        /* No user-mode scanner connected; allow by default */
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&request, sizeof(request));
    request.Command = PrxSdCommandScanFile;
    request.ProcessId = ProcessId;

    /* Copy file path (truncate if too long) */
    ULONG copyLen = min(FilePath->Length, (PRXSD_MAX_PATH - 1) * sizeof(WCHAR));
    RtlCopyMemory(request.FilePath, FilePath->Buffer, copyLen);
    request.FilePath[copyLen / sizeof(WCHAR)] = L'\0';

    /* Set timeout */
    timeout.QuadPart = -(LONGLONG)(PRXSD_SCAN_TIMEOUT * 10000000LL);

    /* Send message and wait for reply */
    status = FltSendMessage(
        PrxSdGlobals.Filter,
        &PrxSdGlobals.ClientPort,
        &request,
        sizeof(request),
        &reply,
        &replyLength,
        &timeout
    );

    if (NT_SUCCESS(status)) {
        *ScanResult = reply.Result;
    }

    return status;
}

/* ---------- Pre-Create callback ---------- */

FLT_PREOP_CALLBACK_STATUS
PrxSdPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    /* Skip kernel-mode requests */
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Skip directory opens */
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Continue to post-create for scanning after the file is opened */
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

/* ---------- Post-Create callback ---------- */

FLT_POSTOP_CALLBACK_STATUS
PrxSdPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
    PRXSD_SCAN_RESULT scanResult;

    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    /* Only scan successfully opened files */
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* Get the file name */
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &fileNameInfo
    );

    if (!NT_SUCCESS(status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    FltParseFileNameInformation(fileNameInfo);

    /* Send to user-mode scanner */
    status = PrxSdSendScanRequest(
        &fileNameInfo->Name,
        FltGetRequestorProcessId(Data),
        &scanResult
    );

    if (NT_SUCCESS(status) && scanResult == PrxSdResultMalicious) {
        /* Block access to malicious file */
        FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
    }

    FltReleaseFileNameInformation(fileNameInfo);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* ---------- Pre-Write callback ---------- */

FLT_PREOP_CALLBACK_STATUS
PrxSdPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    /*
     * TODO: Implement write-time scanning.
     * For now, allow all writes and rely on create-time scanning.
     * Future: buffer the write data, send to user-mode for scanning,
     * block if malicious content detected.
     */

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ---------- Communication port callbacks ---------- */

NTSTATUS
PrxSdPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);

    PrxSdGlobals.ClientPort = ClientPort;
    PrxSdGlobals.Connected = TRUE;

    DbgPrint("PrxSd: User-mode scanner connected\n");
    return STATUS_SUCCESS;
}

VOID
PrxSdPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    FltCloseClientPort(PrxSdGlobals.Filter, &PrxSdGlobals.ClientPort);
    PrxSdGlobals.Connected = FALSE;

    DbgPrint("PrxSd: User-mode scanner disconnected\n");
}

/* ---------- Unload ---------- */

NTSTATUS
PrxSdUnload(
    FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    if (PrxSdGlobals.ServerPort != NULL) {
        FltCloseCommunicationPort(PrxSdGlobals.ServerPort);
    }

    if (PrxSdGlobals.Filter != NULL) {
        FltUnregisterFilter(PrxSdGlobals.Filter);
    }

    DbgPrint("PrxSd: Minifilter unloaded\n");
    return STATUS_SUCCESS;
}

/* ---------- DriverEntry ---------- */

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("PrxSd: Minifilter loading...\n");

    RtlZeroMemory(&PrxSdGlobals, sizeof(PrxSdGlobals));

    /* Register the minifilter */
    status = FltRegisterFilter(
        DriverObject,
        &FilterRegistration,
        &PrxSdGlobals.Filter
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("PrxSd: FltRegisterFilter failed: 0x%08X\n", status);
        return status;
    }

    /* Create communication port for user-mode scanner */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

    if (NT_SUCCESS(status)) {
        RtlInitUnicodeString(&portName, PRXSD_PORT_NAME);

        InitializeObjectAttributes(
            &oa,
            &portName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            sd
        );

        status = FltCreateCommunicationPort(
            PrxSdGlobals.Filter,
            &PrxSdGlobals.ServerPort,
            &oa,
            NULL,
            PrxSdPortConnect,
            PrxSdPortDisconnect,
            NULL,                /* MessageNotify - not used */
            PRXSD_MAX_CONNECTIONS
        );

        FltFreeSecurityDescriptor(sd);
    }

    if (!NT_SUCCESS(status)) {
        DbgPrint("PrxSd: Failed to create communication port: 0x%08X\n", status);
        FltUnregisterFilter(PrxSdGlobals.Filter);
        return status;
    }

    /* Start filtering */
    status = FltStartFiltering(PrxSdGlobals.Filter);

    if (!NT_SUCCESS(status)) {
        DbgPrint("PrxSd: FltStartFiltering failed: 0x%08X\n", status);
        FltCloseCommunicationPort(PrxSdGlobals.ServerPort);
        FltUnregisterFilter(PrxSdGlobals.Filter);
        return status;
    }

    DbgPrint("PrxSd: Minifilter loaded successfully\n");
    return STATUS_SUCCESS;
}
