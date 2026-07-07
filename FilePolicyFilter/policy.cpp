#include <fltKernel.h>
#include <ntifs.h>
#include <ntstrsafe.h>
#include "policy.h"
#include "events.h"

static WCHAR gAllowedPatternBuffer[TL_MAX_POLICY_PATTERN_CHARS] = L"";
static WCHAR gBlockedPatternBuffer[TL_MAX_POLICY_PATTERN_CHARS] = L"Notepad.exe";

static UNICODE_STRING gAllowedPattern =
{
    0,
    sizeof(gAllowedPatternBuffer),
    gAllowedPatternBuffer
};

static UNICODE_STRING gBlockedPattern =
{
    sizeof(L"Notepad.exe") - sizeof(WCHAR),
    sizeof(gBlockedPatternBuffer),
    gBlockedPatternBuffer
};

static BOOLEAN
PatternContainsWildcard(
    _In_ PUNICODE_STRING Pattern
)
{
    if (Pattern == NULL || Pattern->Buffer == NULL)
    {
        return FALSE;
    }

    USHORT count = Pattern->Length / sizeof(WCHAR);

    for (USHORT i = 0; i < count; i++)
    {
        WCHAR ch = Pattern->Buffer[i];
        if (ch == L'*' || ch == L'?')
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
PatternContainsPathSeparator(
    _In_ PUNICODE_STRING Pattern
)
{
    if (Pattern == NULL || Pattern->Buffer == NULL)
    {
        return FALSE;
    }

    USHORT count = Pattern->Length / sizeof(WCHAR);

    for (USHORT i = 0; i < count; i++)
    {
        WCHAR ch = Pattern->Buffer[i];
        if (ch == L'\\' || ch == L'/')
        {
            return TRUE;
        }
    }

    return FALSE;
}

static VOID
UpcaseBufferInPlace(
    _Inout_updates_(CharCount) PWCHAR Buffer,
    _In_ USHORT CharCount
)
{
    for (USHORT i = 0; i < CharCount; i++)
    {
        Buffer[i] = RtlUpcaseUnicodeChar(Buffer[i]);
    }
}

static BOOLEAN
MatchPolicyPattern(
    _In_ PUNICODE_STRING Pattern,
    _In_ PUNICODE_STRING FullPath,
    _In_ PUNICODE_STRING FinalComponent
)
{
    if (Pattern == NULL || Pattern->Buffer == NULL || Pattern->Length == 0)
    {
        return FALSE;
    }

    if (FullPath == NULL || FullPath->Buffer == NULL ||
        FinalComponent == NULL || FinalComponent->Buffer == NULL)
    {
        return FALSE;
    }

    if (!PatternContainsWildcard(Pattern) && !PatternContainsPathSeparator(Pattern))
    {
        // Simple leaf-name exact match like "notepad.exe"
        return RtlEqualUnicodeString(FinalComponent, Pattern, TRUE);
    }

    // Full path or wildcard pattern match
    __try
    {
        WCHAR upperNameBuffer[TL_MAX_POLICY_PATTERN_CHARS] = { 0 };
        size_t charsCopied = 0;

        NTSTATUS status = RtlStringCchCopyNW(
            upperNameBuffer,
            TL_MAX_POLICY_PATTERN_CHARS,
            FullPath->Buffer,
            FullPath->Length / sizeof(WCHAR)
        );

        if (!NT_SUCCESS(status))
        {
            return FALSE;
        }

        status = RtlStringCchLengthW(
            upperNameBuffer,
            TL_MAX_POLICY_PATTERN_CHARS,
            &charsCopied
        );

        if (!NT_SUCCESS(status))
        {
            return FALSE;
        }

        UpcaseBufferInPlace(upperNameBuffer, (USHORT)charsCopied);

        UNICODE_STRING upperName;
        RtlInitUnicodeString(&upperName, upperNameBuffer);

        return FsRtlIsNameInExpression(
            Pattern,
            &upperName,
            TRUE,
            NULL
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

BOOLEAN
HasExecutableExtension(
    _In_ PUNICODE_STRING FileName
)
{
    UNICODE_STRING exeExt = RTL_CONSTANT_STRING(L".exe");
    UNICODE_STRING dllExt = RTL_CONSTANT_STRING(L".dll");
    UNICODE_STRING sysExt = RTL_CONSTANT_STRING(L".sys");

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0)
    {
        return FALSE;
    }

    USHORT lengthInChars = FileName->Length / sizeof(WCHAR);

    if (lengthInChars < 4)
    {
        return FALSE;
    }

    WCHAR* buffer = FileName->Buffer;

    if (_wcsnicmp(buffer + lengthInChars - 4, exeExt.Buffer, 4) == 0)
    {
        return TRUE;
    }

    if (_wcsnicmp(buffer + lengthInChars - 4, dllExt.Buffer, 4) == 0)
    {
        return TRUE;
    }

    if (_wcsnicmp(buffer + lengthInChars - 4, sysExt.Buffer, 4) == 0)
    {
        return TRUE;
    }

    return FALSE;
}

BOOLEAN
ShouldAllowByPolicy(
    _In_ PUNICODE_STRING FullPath,
    _In_ PUNICODE_STRING FinalComponent
)
{
    return MatchPolicyPattern(&gAllowedPattern, FullPath, FinalComponent);
}

BOOLEAN
ShouldBlockByPolicy(
    _In_ PUNICODE_STRING FullPath,
    _In_ PUNICODE_STRING FinalComponent
)
{
    return MatchPolicyPattern(&gBlockedPattern, FullPath, FinalComponent);
}

NTSTATUS
SetAllowedPattern(
    _In_opt_ PCWSTR NewPattern
)
{
    size_t charsCopied = 0;

    if (NewPattern == NULL || NewPattern[0] == L'\0')
    {
        gAllowedPatternBuffer[0] = L'\0';
        gAllowedPattern.Length = 0;
        gAllowedPattern.MaximumLength = sizeof(gAllowedPatternBuffer);
        gAllowedPattern.Buffer = gAllowedPatternBuffer;
        return STATUS_SUCCESS;
    }

    NTSTATUS status = RtlStringCchCopyW(
        gAllowedPatternBuffer,
        TL_MAX_POLICY_PATTERN_CHARS,
        NewPattern
    );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = RtlStringCchLengthW(
        gAllowedPatternBuffer,
        TL_MAX_POLICY_PATTERN_CHARS,
        &charsCopied
    );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    UpcaseBufferInPlace(gAllowedPatternBuffer, (USHORT)charsCopied);

    gAllowedPattern.Length = (USHORT)(charsCopied * sizeof(WCHAR));
    gAllowedPattern.MaximumLength = sizeof(gAllowedPatternBuffer);
    gAllowedPattern.Buffer = gAllowedPatternBuffer;

    return STATUS_SUCCESS;
}

NTSTATUS
SetBlockedPattern(
    _In_opt_ PCWSTR NewPattern
)
{
    size_t charsCopied = 0;

    if (NewPattern == NULL || NewPattern[0] == L'\0')
    {
        gBlockedPatternBuffer[0] = L'\0';
        gBlockedPattern.Length = 0;
        gBlockedPattern.MaximumLength = sizeof(gBlockedPatternBuffer);
        gBlockedPattern.Buffer = gBlockedPatternBuffer;
        return STATUS_SUCCESS;
    }

    NTSTATUS status = RtlStringCchCopyW(
        gBlockedPatternBuffer,
        TL_MAX_POLICY_PATTERN_CHARS,
        NewPattern
    );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = RtlStringCchLengthW(
        gBlockedPatternBuffer,
        TL_MAX_POLICY_PATTERN_CHARS,
        &charsCopied
    );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    UpcaseBufferInPlace(gBlockedPatternBuffer, (USHORT)charsCopied);

    gBlockedPattern.Length = (USHORT)(charsCopied * sizeof(WCHAR));
    gBlockedPattern.MaximumLength = sizeof(gBlockedPatternBuffer);
    gBlockedPattern.Buffer = gBlockedPatternBuffer;

    return STATUS_SUCCESS;
}