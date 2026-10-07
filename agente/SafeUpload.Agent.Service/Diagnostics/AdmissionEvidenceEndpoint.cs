#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using Microsoft.Extensions.Configuration;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Diagnostics;

/// <summary>
/// A feature-build-only, local administrator capture pipe bound to the service's
/// already-connected FilterPort. It never opens or reconnects a filter port.
/// </summary>
public sealed class AdmissionEvidenceEndpoint : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly ILogger<AdmissionEvidenceEndpoint> _logger;
    private readonly AdmissionEvidenceRunLedger _runs = new();
    private AdmissionEvidenceBinding? _binding;
    private CancellationTokenSource? _serverStop;
    private Task? _serverTask;
    private NamedPipeServerStream? _currentPipe;
    private long _nextBindingGeneration;

    internal bool StagedProofEnabled { get; }

    public AdmissionEvidenceEndpoint(ILogger<AdmissionEvidenceEndpoint> logger, IConfiguration? configuration = null)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        StagedProofEnabled = configuration?.GetValue<bool>("Diagnostics:StagedProofProxy") == true;
    }

    internal bool TryBind(
        IAdmissionEvidenceSender sender,
        int acceptedPolicyVersion,
        byte[] canonicalCandidateFingerprint)
    {
        ArgumentNullException.ThrowIfNull(sender);
        ArgumentNullException.ThrowIfNull(canonicalCandidateFingerprint);

        lock (_gate)
        {
            if (_binding is not null) return false;
        }

        try
        {
            using WindowsIdentity serviceIdentity = WindowsIdentity.GetCurrent();
            if (serviceIdentity.User?.IsWellKnown(WellKnownSidType.LocalSystemSid) != true)
                return false;

            long generation = Interlocked.Increment(ref _nextBindingGeneration);
            AdmissionEvidenceBinding binding = AdmissionEvidenceBinding.TryCreate(
                sender, generation, acceptedPolicyVersion, canonicalCandidateFingerprint);
            var stop = new CancellationTokenSource();

            lock (_gate)
            {
                if (_binding is not null)
                {
                    stop.Dispose();
                    return false;
                }
                _runs.Clear();
                _binding = binding;
                _serverStop = stop;
                _serverTask = Task.Run(() => ListenAsync(binding, stop.Token));
            }
            return true;
        }
        catch (Exception ex)
        {
            // Diagnostics must never prevent the already-accepted service policy from running.
            _logger.LogWarning("Admission evidence endpoint was not bound ({FailureType}).", ex.GetType().Name);
            return false;
        }
    }

    internal async Task UnbindAsync(IAdmissionEvidenceSender sender)
    {
        ArgumentNullException.ThrowIfNull(sender);
        AdmissionEvidenceBinding? binding;
        CancellationTokenSource? serverStop;
        Task? serverTask;
        NamedPipeServerStream? currentPipe;

        lock (_gate)
        {
            if (_binding is null || !ReferenceEquals(_binding.Sender, sender)) return;
            binding = _binding;
            _binding = null;
            serverStop = _serverStop;
            serverTask = _serverTask;
            currentPipe = _currentPipe;
            _serverStop = null;
            _serverTask = null;
            _currentPipe = null;
            _runs.Clear();
        }

        // Close rejects new sends immediately. It waits for any send already
        // using this FilterPort before MinifilterInterceptor leaves its using scope.
        binding.StopAcceptingAndDrain();
        try { serverStop?.Cancel(); } catch (ObjectDisposedException) { }
        try { currentPipe?.Dispose(); } catch (ObjectDisposedException) { }
        if (serverTask is not null)
        {
            try { await serverTask.ConfigureAwait(false); }
            catch (OperationCanceledException) { }
        }
        serverStop?.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        AdmissionEvidenceBinding? binding;
        lock (_gate) binding = _binding;
        if (binding is not null)
            await UnbindAsync(binding.Sender).ConfigureAwait(false);
    }

    private async Task ListenAsync(AdmissionEvidenceBinding binding, CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested && IsCurrent(binding))
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = CreatePrivatePipe();
                lock (_gate)
                {
                    if (!ReferenceEquals(_binding, binding) || stoppingToken.IsCancellationRequested)
                    {
                        pipe.Dispose();
                        return;
                    }
                    _currentPipe = pipe;
                }

                await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
                await ServeOneAsync(pipe, binding, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                // Do not log client data, identities, paths, or raw replies.
                _logger.LogWarning("Admission evidence pipe instance failed ({FailureType}).", ex.GetType().Name);
                try { await Task.Delay(TimeSpan.FromMilliseconds(250), stoppingToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
            }
            finally
            {
                lock (_gate)
                {
                    if (ReferenceEquals(_currentPipe, pipe)) _currentPipe = null;
                }
                if (pipe is not null)
                {
                    try { await pipe.DisposeAsync().ConfigureAwait(false); }
                    catch (ObjectDisposedException) { }
                }
            }
        }
    }

    private async Task ServeOneAsync(
        NamedPipeServerStream pipe,
        AdmissionEvidenceBinding binding,
        CancellationToken stoppingToken)
    {
        using var readDeadline = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        readDeadline.CancelAfter(TimeSpan.FromSeconds(5));

        byte[] body;
        try
        {
            body = await ReadRequestAsync(pipe, readDeadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
        {
            await AdmissionEvidenceFrames.WriteErrorAsync(pipe, "REQUEST_TIMEOUT", stoppingToken).ConfigureAwait(false);
            return;
        }
        catch (InvalidDataException)
        {
            await AdmissionEvidenceFrames.WriteErrorAsync(pipe, "INVALID_REQUEST", stoppingToken).ConfigureAwait(false);
            return;
        }
        catch (EndOfStreamException)
        {
            await AdmissionEvidenceFrames.WriteErrorAsync(pipe, "TRUNCATED_REQUEST", stoppingToken).ConfigureAwait(false);
            return;
        }

        // Windows binds RunAsClient to the identity that sent the last pipe
        // message, so authenticate after the bounded first request is read.
        if (!TryGetAuthorizedCaller(pipe, out AdmissionEvidenceCaller? caller))
            return;

        // A distinct, explicitly enabled SYSTEM-only protocol. The existing
        // capture protocol remains limited to read-only controls 19/20/23.
        if (BinaryPrimitives.ReadUInt32LittleEndian(body) == StagedProofProxyWire.Magic)
        {
            await ServeStagedProofAsync(pipe, binding, caller!.Sid, StagedProofEnabled, IsCurrent, body, stoppingToken).ConfigureAwait(false);
            return;
        }

        AdmissionEvidenceRequest request;
        try
        {
            request = AdmissionEvidenceRequest.Parse(body);
        }
        catch (InvalidDataException)
        {
            await AdmissionEvidenceFrames.WriteErrorAsync(pipe, "INVALID_REQUEST", stoppingToken).ConfigureAwait(false);
            return;
        }

        if (request.Hook == AdmissionEvidenceHook.BeforeExpandedLaunch)
        {
            await AdmissionEvidenceFrames.WriteErrorAsync(pipe, "PRELAUNCH_HOOK_UNAVAILABLE", stoppingToken)
                .ConfigureAwait(false);
            return;
        }

        string? ledgerError = AdvanceRun(request, binding);
        if (ledgerError is not null)
        {
            await AdmissionEvidenceFrames.WriteErrorAsync(pipe, ledgerError, stoppingToken).ConfigureAwait(false);
            return;
        }

        var capture = new AdmissionEvidenceCapture(
            (current, command, startIndex) => current.TrySend(command, startIndex, out var reply) ? reply : null,
            IsCurrent);
        using var captureDeadline = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        captureDeadline.CancelAfter(AdmissionEvidenceLimits.MaxCaptureDuration);
        bool completed = false;
        try
        {
            AdmissionEvidenceCaptureSummary summary = await capture.CaptureAsync(
                pipe, request, binding, caller!, captureDeadline.Token).ConfigureAwait(false);
            completed = string.Equals(summary.Outcome, "EvidenceCaptured", StringComparison.Ordinal);
        }
        catch (OperationCanceledException)
        {
            // Service shutdown or the capture/write deadline. Do not append an
            // error frame: a write deadline means the privileged reader may be
            // stalled. Finally marks the reserved hook terminal either way.
        }
        catch (IOException)
        {
            // A disconnected reader gets no completion claim; the next client starts a new request.
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Admission evidence capture stopped ({FailureType}).", ex.GetType().Name);
            try
            {
                await AdmissionEvidenceFrames.WriteErrorAsync(pipe, "CAPTURE_INCOMPLETE", stoppingToken)
                    .ConfigureAwait(false);
            }
            catch (Exception writeFailure) when (writeFailure is IOException or ObjectDisposedException or OperationCanceledException)
            {
            }
        }
        finally
        {
            if (!completed)
                _runs.MarkCaptureIncomplete(request, binding.Generation);
        }
    }

    internal static bool IsStagedProofAuthorized(bool enabled, string? sid) =>
        enabled && string.Equals(sid, "S-1-5-18", StringComparison.Ordinal);

    internal static async Task ServeStagedProofAsync(Stream pipe, AdmissionEvidenceBinding binding,
        string? callerSid, bool enabled, Func<AdmissionEvidenceBinding, bool> isCurrent,
        byte[] body, CancellationToken stoppingToken, TimeSpan? writeDeadline = null)
    {
        if (!IsStagedProofAuthorized(enabled, callerSid)) return;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        // This bounds response I/O only. A native synchronous send retains its
        // port lease until it actually returns; it cannot safely be abandoned.
        deadline.CancelAfter(writeDeadline ?? TimeSpan.FromSeconds(5));
        int hr = unchecked((int)0x80070057); // E_INVALIDARG; no payload on errors.
        byte[] raw = [];
        try
        {
            var request = StagedProofProxyWire.Parse(body);
            if (isCurrent(binding) && binding.TrySendStagedProof(request.Input, request.OutputBytes, out var reply)
                && isCurrent(binding) && binding.IsAccepting && reply is not null)
            {
                hr = reply.HResult;
                if (hr == 0 && reply.IsWirePayloadValid && reply.BytesReturned == request.OutputBytes)
                    raw = reply.RawReply;
                else if (hr == 0) hr = unchecked((int)0x80004005); // E_FAIL
            }
            else hr = unchecked((int)0x80004004); // E_ABORT
        }
        catch (InvalidDataException) { }
        catch (ObjectDisposedException) { hr = unchecked((int)0x80004004); }
        byte[] header = new byte[12];
        BinaryPrimitives.WriteUInt32LittleEndian(header, StagedProofProxyWire.Magic);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(4), hr);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8), (uint)raw.Length);
        await pipe.WriteAsync(header, deadline.Token).ConfigureAwait(false);
        if (raw.Length != 0) await pipe.WriteAsync(raw, deadline.Token).ConfigureAwait(false);
    }

    private string? AdvanceRun(AdmissionEvidenceRequest request, AdmissionEvidenceBinding binding)
    {
        lock (_gate)
        {
            if (!ReferenceEquals(_binding, binding)) return "PORT_UNBOUND";
            if (!binding.IsAccepting) return "BINDING_EPOCH_CHANGED";
            return _runs.Advance(request, binding.Generation);
        }
    }

    private bool IsCurrent(AdmissionEvidenceBinding binding)
    {
        lock (_gate) return ReferenceEquals(_binding, binding);
    }

    internal static async Task<byte[]> ReadRequestAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] lengthBytes = new byte[sizeof(uint)];
        await ReadExactlyAsync(stream, lengthBytes, cancellationToken).ConfigureAwait(false);
        uint length = BinaryPrimitives.ReadUInt32LittleEndian(lengthBytes);
        if (length is < 65 or > AdmissionEvidenceLimits.MaxRequestBytes)
            throw new InvalidDataException("Admission evidence request length is out of bounds.");

        byte[] body = new byte[checked((int)length)];
        await ReadExactlyAsync(stream, body, cancellationToken).ConfigureAwait(false);
        return body;
    }

    private static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int current = await stream.ReadAsync(buffer[read..], cancellationToken).ConfigureAwait(false);
            if (current == 0) throw new EndOfStreamException();
            read += current;
        }
    }

    private static bool TryGetAuthorizedCaller(
        NamedPipeServerStream pipe,
        out AdmissionEvidenceCaller? caller)
    {
        caller = null;
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint processId) || processId == 0)
            return false;

        string? sid = null;
        bool authorized = false;
        try
        {
            pipe.RunAsClient(() =>
            {
                using WindowsIdentity identity = WindowsIdentity.GetCurrent();
                sid = identity.User?.Value;
                bool administrator = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
                authorized = IsAuthorizedToken(sid, administrator);
            });

            if (!authorized || string.IsNullOrEmpty(sid)) return false;
            using Process process = Process.GetProcessById(checked((int)processId));
            if (process.HasExited) return false;

            caller = new AdmissionEvidenceCaller(processId, sid);
            return true;
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or Win32Exception or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return false;
        }
    }

    private static NamedPipeServerStream CreatePrivatePipe()
    {
        const string sddl = PipeDaclSddl;
        const uint pipeAccessDuplex = 0x00000003;
        const uint fileFlagOverlapped = 0x40000000;
        const uint fileFlagFirstPipeInstance = FileFlagFirstPipeInstance;
        const uint pipeTypeByte = 0x00000000;
        const uint pipeReadmodeByte = 0x00000000;
        const uint pipeWait = 0x00000000;
        const uint pipeRejectRemoteClients = PipeRejectRemoteClientsMode;
        const uint pipeUnlimitedTimeout = 0;

        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
            sddl, 1, out IntPtr securityDescriptor, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = securityDescriptor,
                InheritHandle = false,
            };
            using var nativeHandle = CreateNamedPipe(
                AdmissionEvidencePipeName,
                pipeAccessDuplex | fileFlagOverlapped | fileFlagFirstPipeInstance,
                pipeTypeByte | pipeReadmodeByte | pipeWait | pipeRejectRemoteClients,
                maxInstances: 1,
                outBufferSize: 4096,
                inBufferSize: 4096,
                defaultTimeout: pipeUnlimitedTimeout,
                ref attributes);
            if (nativeHandle.IsInvalid)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            // The native handle already carries PIPE_REJECT_REMOTE_CLIENTS,
            // FILE_FLAG_OVERLAPPED, and the explicit SYSTEM/Admin DACL.
            var ownedHandle = new SafePipeHandle(nativeHandle.DangerousGetHandle(), ownsHandle: true);
            nativeHandle.SetHandleAsInvalid();
            try
            {
                return new NamedPipeServerStream(PipeDirection.InOut,
                    isAsync: true, isConnected: false, ownedHandle);
            }
            catch
            {
                ownedHandle.Dispose();
                throw;
            }
        }
        finally
        {
            _ = LocalFree(securityDescriptor);
        }
    }

    internal const string AdmissionEvidencePipeName = @"\\.\pipe\SafeUploadAdmissionEvidence.Capture";
    internal const string PipeDaclSddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";
    internal const uint FileFlagFirstPipeInstance = 0x00080000;
    internal const uint PipeRejectRemoteClientsMode = 0x00000008;

    internal static bool IsAuthorizedToken(string? sid, bool isAdministrator)
    {
        if (string.IsNullOrEmpty(sid)) return false;
        return string.Equals(sid, "S-1-5-18", StringComparison.Ordinal) || isAdministrator;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        internal int Length;
        internal IntPtr SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] internal bool InheritHandle;
    }

    [DllImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string stringSecurityDescriptor,
        uint stringSdRevision,
        out IntPtr securityDescriptor,
        out uint securityDescriptorSize);

    [DllImport("kernel32.dll", EntryPoint = "CreateNamedPipeW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafePipeHandle CreateNamedPipe(
        string name,
        uint openMode,
        uint pipeMode,
        uint maxInstances,
        uint outBufferSize,
        uint inBufferSize,
        uint defaultTimeout,
        ref SecurityAttributes securityAttributes);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(
        SafePipeHandle pipe,
        out uint clientProcessId);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
#endif
