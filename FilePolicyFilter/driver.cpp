#include <fltKernel.h>
#include <ntstrsafe.h>
#include "policy.h"
#include "events.h"
#include "comms.h"

PFLT_FILTER gFilterHandle = NULL;

NTSTATUS
FilterUnload(
    FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    CloseCommunicationPort();

    if (gFilterHandle)
    {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }

    return STATUS_SUCCESS;
}

static VOID
BuildFileEventMessage(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _In_ TL_FILE_EVENT_ACTION Action,
    _Out_ PTL_FILE_EVENT_MESSAGE EventMessage
)
{
    RtlZeroMemory(EventMessage, sizeof(TL_FILE_EVENT_MESSAGE));

    EventMessage->ProcessId = FltGetRequestorProcessId(Data);
    EventMessage->Action = (ULONG)Action;

    RtlStringCchCopyUnicodeString(
        EventMessage->FinalName,
        TL_MAX_NAME_CHARS,
        &NameInfo->FinalComponent
    );

    RtlStringCchCopyUnicodeString(
        EventMessage->FullPath,
        TL_MAX_PATH_CHARS,
        &NameInfo->Name
    );
}

FLT_PREOP_CALLBACK_STATUS
PreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    if (CompletionContext != NULL)
    {
        *CompletionContext = NULL;
    }

    if (!NT_SUCCESS(FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED,
        &nameInfo)))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!NT_SUCCESS(FltParseFileNameInformation(nameInfo)))
    {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (HasExecutableExtension(&nameInfo->Name))
    {
        TL_FILE_EVENT_MESSAGE eventMessage;

        BOOLEAN shouldAllow = ShouldAllowByPolicy(&nameInfo->Name, &nameInfo->FinalComponent);
        BOOLEAN shouldBlock = !shouldAllow && ShouldBlockByPolicy(&nameInfo->Name, &nameInfo->FinalComponent);

        BuildFileEventMessage(
            Data,
            nameInfo,
            shouldBlock ? TlFileEventBlocked : TlFileEventAllowed,
            &eventMessage
        );

        SendFileEventToUserMode(&eventMessage);

        DbgPrint(
            "EVENT PID=%lu ACTION=%lu FINAL=%ws PATH=%ws\n",
            eventMessage.ProcessId,
            eventMessage.Action,
            eventMessage.FinalName,
            eventMessage.FullPath
        );

        if (shouldBlock)
        {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;

            FltReleaseFileNameInformation(nameInfo);
            return FLT_PREOP_COMPLETE;
        }
    }

    FltReleaseFileNameInformation(nameInfo);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] =
{
    { IRP_MJ_CREATE, 0, PreCreateCallback, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration =
{
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    FilterUnload,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

extern "C"
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrint("FILEPOLICYFILTER: DriverEntry marker 2026-07-05-PORT-ROLLBACK\n");
    SetBlockedPattern(L"Notepad.exe");

    NTSTATUS status;

    status = FltRegisterFilter(
        DriverObject,
        &FilterRegistration,
        &gFilterHandle
    );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = InitializeCommunicationPort(gFilterHandle);

    if (!NT_SUCCESS(status))
    {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }

    status = FltStartFiltering(gFilterHandle);

    if (!NT_SUCCESS(status))
    {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }

    return status;
}