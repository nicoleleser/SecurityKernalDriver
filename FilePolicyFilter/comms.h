#pragma once

#include <fltKernel.h>
#include "events.h"


extern PFLT_PORT gServerPort;
extern PFLT_PORT gClientPort;

NTSTATUS
InitializeCommunicationPort(
    _In_ PFLT_FILTER Filter
);

VOID
CloseCommunicationPort();

VOID
SetCommunicationFilterHandle(
    _In_ PFLT_FILTER Filter
);


NTSTATUS
SendFileEventToUserMode(
    _In_ PTL_FILE_EVENT_MESSAGE EventMessage
);

NTSTATUS
ConnectNotifyCallback(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionCookie
);

VOID
DisconnectNotifyCallback(
    _In_opt_ PVOID ConnectionCookie
);

NTSTATUS
MessageNotifyCallback(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
);

