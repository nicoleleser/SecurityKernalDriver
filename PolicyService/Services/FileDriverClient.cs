using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;
using System.Security.Principal;


namespace PolicyService.Services;

public sealed class FileDriverClient : IDisposable
{
    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterConnectCommunicationPort(
        string lpPortName,
        uint dwOptions,
        IntPtr lpContext,
        ushort wSizeOfContext,
        IntPtr lpSecurityAttributes,
        out SafeFileHandle hPort
    );

    [DllImport("fltlib.dll")]
    private static extern int FilterGetMessage(
        SafeFileHandle hPort,
        IntPtr lpMessageBuffer,
        uint dwMessageBufferSize,
        IntPtr lpOverlapped
    );
    [DllImport("fltlib.dll")]
    private static extern int FilterSendMessage(
    SafeFileHandle hPort,
    IntPtr lpInBuffer,
    uint dwInBufferSize,
    IntPtr lpOutBuffer,
    uint dwOutBufferSize,
    out uint lpBytesReturned
);

    [StructLayout(LayoutKind.Sequential)]
    private struct FILTER_MESSAGE_HEADER
    {
        public uint ReplyLength;
        public ulong MessageId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct TL_FILE_EVENT_MESSAGE
    {
        public uint ProcessId;
        public uint Action;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string FinalName;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string FullPath;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FILE_EVENT_PACKET
    {
        public FILTER_MESSAGE_HEADER Header;
        public TL_FILE_EVENT_MESSAGE Event;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct TL_POLICY_UPDATE_MESSAGE
    {
        public uint CommandType;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string BlockedExecutableName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TL_CONNECT_CONTEXT
    {
        public uint Version;
        public uint Magic;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct TL_POLICY_SYNC_MESSAGE
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string AllowedPattern;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string BlockedPattern;
    }

    private readonly ILogger<FileDriverClient> _logger;
    private SafeFileHandle? _portHandle;

    public bool IsConnected =>
        _portHandle is not null &&
        !_portHandle.IsInvalid &&
        !_portHandle.IsClosed;

    public FileDriverClient(ILogger<FileDriverClient> logger)
    {
        _logger = logger;
    }

    public void Connect()
    {
        if (IsConnected)
        {
            _logger.LogInformation("File driver port already connected");
            return;
        }

        TL_CONNECT_CONTEXT context = new()
        {
            Version = 1,
            Magic = 0x544C4343
        };

        int contextSize = Marshal.SizeOf<TL_CONNECT_CONTEXT>();
        IntPtr contextBuffer = Marshal.AllocHGlobal(contextSize);

        try
        {
            Marshal.StructureToPtr(context, contextBuffer, false);

            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new(identity);

            _logger.LogInformation(
                "Connect() identity check: User={User} IsAdmin={IsAdmin}",
                identity.Name,
                principal.IsInRole(WindowsBuiltInRole.Administrator));

            int hr = FilterConnectCommunicationPort(
                @"\FilePolicyFilterPort",
                0,
                contextBuffer,
                (ushort)contextSize,
                IntPtr.Zero,
                out SafeFileHandle handle
            );

            if (hr != 0)
            {
                _logger.LogError("FilterConnectCommunicationPort failed with HRESULT 0x{Hr:X8}", hr);

                Exception? ex = Marshal.GetExceptionForHR(hr);
                if (ex is not null)
                {
                    throw ex;
                }

                throw new InvalidOperationException($"FilterConnectCommunicationPort failed: 0x{hr:X8}");
            }

            _portHandle = handle;
            _logger.LogInformation("Connected to FilePolicyFilter communication port");
        }
        finally
        {
            Marshal.FreeHGlobal(contextBuffer);
        }
    }

    public void SendPolicySync(string? allowedPattern, string? blockedPattern)
    {
        if (!IsConnected || _portHandle is null)
        {
            throw new InvalidOperationException("Driver port is not connected.");
        }

        TL_POLICY_SYNC_MESSAGE message = new()
        {
            AllowedPattern = allowedPattern ?? string.Empty,
            BlockedPattern = blockedPattern ?? string.Empty
        };

        int size = Marshal.SizeOf<TL_POLICY_SYNC_MESSAGE>();
        IntPtr buffer = Marshal.AllocHGlobal(size);

        try
        {
            Marshal.StructureToPtr(message, buffer, false);

            int hr = FilterSendMessage(
                _portHandle,
                buffer,
                (uint)size,
                IntPtr.Zero,
                0,
                out uint bytesReturned
            );

            if (hr != 0)
            {
                _logger.LogError("FilterSendMessage failed with HRESULT 0x{Hr:X8}", hr);

                Exception? ex = Marshal.GetExceptionForHR(hr);
                if (ex is not null)
                {
                    throw ex;
                }

                throw new InvalidOperationException($"FilterSendMessage failed: 0x{hr:X8}");
            }

            _logger.LogInformation(
                "Sent policy sync to driver: allow={AllowPattern} block={BlockedPattern}",
                allowedPattern,
                blockedPattern
            );
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
    public Task ListenAsync(CancellationToken cancellationToken)
    {
        return Task.Run(() =>
        {
            if (!IsConnected || _portHandle is null)
            {
                throw new InvalidOperationException("Driver port is not connected.");
            }

            int packetSize = Marshal.SizeOf<FILE_EVENT_PACKET>();
            IntPtr buffer = Marshal.AllocHGlobal(packetSize);

            try
            {
                while (!cancellationToken.IsCancellationRequested && IsConnected)
                {
                    Marshal.WriteInt32(buffer, 0);

                    int hr = FilterGetMessage(
                        _portHandle,
                        buffer,
                        (uint)packetSize,
                        IntPtr.Zero
                    );

                    if (hr != 0)
                    {
                        _logger.LogWarning("FilterGetMessage returned HRESULT 0x{Hr:X8}", hr);
                        break;
                    }

                    FILE_EVENT_PACKET packet = Marshal.PtrToStructure<FILE_EVENT_PACKET>(buffer);

                    _logger.LogInformation(
                        "Driver event received: PID={Pid} Action={Action} Final={Final} Path={Path}",
                        packet.Event.ProcessId,
                        packet.Event.Action,
                        packet.Event.FinalName,
                        packet.Event.FullPath
                    );
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }, cancellationToken);
    }

    public void Dispose()
    {
        _portHandle?.Dispose();
        _portHandle = null;
    }
}