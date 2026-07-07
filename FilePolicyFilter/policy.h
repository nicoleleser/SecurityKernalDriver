#pragma once

#include <fltKernel.h>

BOOLEAN
HasExecutableExtension(
    _In_ PUNICODE_STRING FileName
);

BOOLEAN
ShouldAllowByPolicy(
    _In_ PUNICODE_STRING FullPath,
    _In_ PUNICODE_STRING FinalComponent
);

BOOLEAN
ShouldBlockByPolicy(
    _In_ PUNICODE_STRING FullPath,
    _In_ PUNICODE_STRING FinalComponent
);

NTSTATUS
SetAllowedPattern(
    _In_opt_ PCWSTR NewPattern
);

NTSTATUS
SetBlockedPattern(
    _In_opt_ PCWSTR NewPattern
);