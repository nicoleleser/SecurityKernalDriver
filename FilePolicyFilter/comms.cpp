#include <fltKernel.h>
#include "comms.h"
#include "events.h"
#include "policy.h"
#include <ntifs.h>


PFLT_PORT gServerPort = NULL;
PFLT_PORT gClientPort = NULL;

static PFLT_FILTER gCommsFilterHandle = NULL;

VOID
SetCommunicationFilterHandle(
    _In_ PFLT_FILTER Filter
)
{
    gCommsFilterHandle = Filter;
}

NTSTATUS
InitializeCommunicationPort(
    _In_ PFLT_FILTER Filter
)
{
    UNICODE_STRING portName;
    OBJECT_ATTRIBUTES objectAttributes;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    NTSTATUS status;

    SetCommunicationFilterHandle(Filter);

    RtlInitUnicodeString(&portName, L"\\FilePolicyFilterPort");

    status = FltBuildDefaultSecurityDescriptor(
        &securityDescriptor,
        FLT_PORT_ALL_ACCESS
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("COMMS: FltBuildDefaultSecurityDescriptor failed: 0x%X\n", status);
        return status;
    }

    InitializeObjectAttributes(
        &objectAttributes,
        &portName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        securityDescriptor
    );

    status = FltCreateCommunicationPort(
        Filter,
        &gServerPort,
        &objectAttributes,
        NULL,
        ConnectNotifyCallback,
        DisconnectNotifyCallback,
        MessageNotifyCallback,
        1
    );

    FltFreeSecurityDescriptor(securityDescriptor);

    if (NT_SUCCESS(status))
    {
        DbgPrint("COMMS: communication port created successfully\n");
    }
    else
    {
        DbgPrint("COMMS: FltCreateCommunicationPort failed: 0x%X\n", status);
    }

    return status;
}

VOID
CloseCommunicationPort()
{
    if (gClientPort != NULL && gCommsFilterHandle != NULL)
    {
        FltCloseClientPort(gCommsFilterHandle, &gClientPort);
        gClientPort = NULL;
    }

    if (gServerPort != NULL)
    {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
    }
}

NTSTATUS
ConnectNotifyCallback(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionCookie);

    if (ConnectionContext == NULL || SizeOfContext != sizeof(TL_CONNECT_CONTEXT))
    {
        DbgPrint("COMMS: rejected client connection due to missing/invalid context size\n");
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        PTL_CONNECT_CONTEXT context = (PTL_CONNECT_CONTEXT)ConnectionContext;

        if (context->Version != TL_CONNECT_CONTEXT_VERSION ||
            context->Magic != TL_CONNECT_CONTEXT_MAGIC)
        {
            DbgPrint("COMMS: rejected client connection due to invalid handshake\n");
            return STATUS_INVALID_PARAMETER;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return GetExceptionCode();
    }

    gClientPort = ClientPort;

    DbgPrint("COMMS: user-mode client connected and handshake accepted\n");

    return STATUS_SUCCESS;
}


NTSTATUS
MessageNotifyCallback(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
)
{
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (ReturnOutputBufferLength != NULL)
    {
        *ReturnOutputBufferLength = 0;
    }

    if (InputBuffer == NULL || InputBufferLength < sizeof(TL_POLICY_SYNC_MESSAGE))
    {
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        PTL_POLICY_SYNC_MESSAGE message = (PTL_POLICY_SYNC_MESSAGE)InputBuffer;

        NTSTATUS status = SetAllowedPattern(
            message->AllowedPattern[0] != L'\0'
            ? message->AllowedPattern
            : NULL
        );


        if (!NT_SUCCESS(status))
        {
            DbgPrint("COMMS: failed to update allowed executable name: 0x%X\n", status);
            return status;
        }

        status = SetBlockedPattern(
            message->BlockedPattern[0] != L'\0'
            ? message->BlockedPattern
            : NULL
        );

        if (!NT_SUCCESS(status))
        {
            DbgPrint("COMMS: failed to update blocked executable name: 0x%X\n", status);
            return status;
        }

        DbgPrint(
            "COMMS: synced policy allow=%ws block=%ws\n",
            message->AllowedPattern,
            message->BlockedPattern
        );

        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return GetExceptionCode();
    }
}

NTSTATUS
SendFileEventToUserMode(
    _In_ PTL_FILE_EVENT_MESSAGE EventMessage
)
{
    if (EventMessage == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (gClientPort == NULL || gCommsFilterHandle == NULL)
    {
        return STATUS_PORT_DISCONNECTED;
    }

    LARGE_INTEGER timeout;
    timeout.QuadPart = -1000 * 10; // relative timeout, 1 ms in 100-ns units

    NTSTATUS status = FltSendMessage(
        gCommsFilterHandle,
        &gClientPort,
        EventMessage,
        sizeof(TL_FILE_EVENT_MESSAGE),
        NULL,
        NULL,
        &timeout
    );

    if (!NT_SUCCESS(status) && status != STATUS_TIMEOUT)
    {
        DbgPrint("COMMS: FltSendMessage failed: 0x%X\n", status);
    }

    return status;
}

VOID
DisconnectNotifyCallback(
    _In_opt_ PVOID ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    if (gClientPort != NULL && gCommsFilterHandle != NULL)
    {
        FltCloseClientPort(gCommsFilterHandle, &gClientPort);
        gClientPort = NULL;
    }

    DbgPrint("COMMS: user-mode client disconnected\n");
}
