// Connection to the minifilter's communication port.
//
// Wraps the four fltlib entry points the contract needs and nothing else.
// The port takes ONE client at a time and its ACL admits only SYSTEM and
// Administrators, so the process that owns this object is the Windows
// service - not the WPF UI, which talks to the service instead.

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Minifilter;

/// <summary>
/// Header the Filter Manager puts in front of every kernel-to-user
/// message. 16 bytes: the ulong forces 8-byte alignment, so there are
/// four bytes of padding after ReplyLength.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct FilterMessageHeader
{
    public uint ReplyLength;
    public ulong MessageId;
}

/// <summary>
/// Header that must precede every reply. MessageId has to be the one that
/// arrived; Status is an NTSTATUS and is not the verdict - the verdict
/// travels in the payload.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct FilterReplyHeader
{
    public int Status;
    public ulong MessageId;
}

public sealed partial class FilterPort : IDisposable
#if SAFEUPLOAD_ADMISSION_EVIDENCE
    , IAdmissionEvidenceSender
#endif
{
    private const int StatusSuccess = 0;

    private readonly object _sendLifecycle = new();
    private readonly SemaphoreSlim _sendGate = new(1, 1);
    private SafeFileHandle? _handle;
    private bool _acceptingSends = true;
    private bool _disposed;
    private int _activeSenders;

#if SAFEUPLOAD_ADMISSION_EVIDENCE
    private readonly IAdmissionEvidenceNativeSender? _admissionEvidenceNativeSender = null;
#endif

    private FilterPort(SafeFileHandle handle, string portName)
    {
        _handle = handle;
        _ = portName;
    }

    public static FilterPort Connect(string portName = Contract.PortName)
    {
#if SAFEUPLOAD_ADMISSION_EVIDENCE
        AdmissionEvidenceWire.VerifyLayout();
#endif
        int hr = FilterConnectCommunicationPort(
            portName, 0, IntPtr.Zero, 0, IntPtr.Zero, out SafeFileHandle handle);

        if (hr != 0)
        {
            handle.Dispose();

            // E_ACCESSDENIED here usually means the process is not
            // elevated, and ERROR_FILE_NOT_FOUND wrapped as an HRESULT
            // means the filter is not loaded - neither is a bug in this
            // code, and both are worth telling apart in a log.
            throw new Win32Exception(hr, $"FilterConnectCommunicationPort falhou: 0x{hr:X8}");
        }

        return new FilterPort(handle, portName);
    }

    private SafeFileHandle Handle =>
        _handle ?? throw new ObjectDisposedException(nameof(FilterPort));

    // All synchronous FilterSendMessage calls share this lease. Dispose first
    // rejects new senders, then waits for accepted senders (including those
    // queued on _sendGate) to drain before closing the native handle. The
    // blocking FilterGetMessage receive deliberately does not use this gate.
    private SendLease EnterSend()
    {
        lock (_sendLifecycle)
        {
            if (!_acceptingSends
#if SAFEUPLOAD_ADMISSION_EVIDENCE
                || _resourceRevoked
#endif
                )
            {
                throw new ObjectDisposedException(nameof(FilterPort));
            }

            checked { _activeSenders++; }
        }

        bool gateTaken = false;
        try
        {
            _sendGate.Wait();
            gateTaken = true;
            return new SendLease(this, Handle);
        }
        catch
        {
            if (gateTaken) _sendGate.Release();
            CompleteSend();
            throw;
        }
    }

    private void ExitSend()
    {
        _sendGate.Release();
        CompleteSend();
    }

    private void CompleteSend()
    {
        lock (_sendLifecycle)
        {
            _activeSenders--;
            if (_activeSenders == 0) Monitor.PulseAll(_sendLifecycle);
        }
    }

    private sealed class SendLease(FilterPort owner, SafeFileHandle handle) : IDisposable
    {
        private FilterPort? _owner = owner;
        public SafeFileHandle Handle { get; } = handle;

        public void Dispose()
        {
            Interlocked.Exchange(ref _owner, null)?.ExitSend();
        }
    }

    /// <summary>
    /// Blocks until the driver sends a request.
    ///
    /// This call is synchronous and the driver is waiting on the other
    /// side with a 500 ms budget. Whatever happens between this returning
    /// and Reply() being called is time the file open is stalled - and if
    /// it runs past the budget the driver stops waiting and allows the
    /// operation uninspected (RN-013), silently. Anything slow belongs on
    /// another thread, not here.
    /// </summary>
    public unsafe bool TryGetMessage(out SafeUploadRequest request, out ulong messageId,
        CancellationToken cancellationToken = default)
    {
        int size = sizeof(FilterMessageHeader) + sizeof(SafeUploadRequest);
        byte* buffer = stackalloc byte[size];

        // A null OVERLAPPED waits on the port handle itself. A concurrent
        // FilterSendMessage can signal that same handle and wake the receive
        // before its request has completed. Own the completion event for this
        // receive and keep its buffer/OVERLAPPED alive until completion.
        using var completed = new EventWaitHandle(false, EventResetMode.ManualReset);
        NativeOverlapped overlapped = new()
        {
            EventHandle = completed.SafeWaitHandle.DangerousGetHandle()
        };
        IntPtr pending = (IntPtr)(&overlapped);
        int hr = FilterGetMessage(Handle, (IntPtr) buffer, (uint) size, pending);
        if (hr == unchecked((int)0x800703E5)) // HRESULT_FROM_WIN32(ERROR_IO_PENDING)
        {
            bool canceled = false;
            while (!completed.WaitOne(250))
            {
                if (!canceled && cancellationToken.IsCancellationRequested)
                {
                    _ = CancelIoEx(Handle, pending);
                    canceled = true;
                }
            }
            hr = GetOverlappedResult(Handle, pending, out _, false)
                ? 0 : Marshal.GetHRForLastWin32Error();
        }

        if (hr != 0)
        {
            request = default;
            messageId = 0;
            return false;
        }

        var header = *(FilterMessageHeader*) buffer;
        request = *(SafeUploadRequest*) (buffer + sizeof(FilterMessageHeader));
        messageId = header.MessageId;

        return true;
    }

    public void Reply(ulong messageId, ulong requestId, uint verdict, string? stageName = null)
    {
        int hr = ReplyCore(messageId, requestId, verdict, stageName);
        // Preserve the existing ordinary/bound reply exception behavior.
        if (hr != 0 && hr != unchecked((int)0x8007010B))
            throw new Win32Exception(hr, $"FilterReplyMessage falhou: 0x{hr:X8}");
    }

    public FilterReplyResult ReplyAllocation(ulong messageId, ulong requestId, uint verdict, string stageName)
        => DecodeReplyResult(ReplyCore(messageId, requestId, verdict, stageName));

    internal static FilterReplyResult DecodeReplyResult(int hr)
    {
        if (hr == unchecked((int)0x801F0020)) return FilterReplyResult.NoWaiter;
        if (hr != 0) throw new Win32Exception(hr, $"FilterReplyMessage falhou: 0x{hr:X8}");
        return FilterReplyResult.Delivered;
    }

    private unsafe int ReplyCore(ulong messageId, ulong requestId, uint verdict, string? stageName)
    {
        if (stageName is { Length: >= Contract.MaxStageNameChars } ||
            (stageName is not null &&
             (stageName.IndexOfAny(['\\', '/', ':']) >= 0 || stageName is "." or "..")))
        {
            throw new ArgumentException("Invalid stage basename.", nameof(stageName));
        }

        int size = sizeof(FilterReplyHeader) + sizeof(SafeUploadResponse);
        byte* buffer = stackalloc byte[size];
        new Span<byte>(buffer, size).Clear();

        *(FilterReplyHeader*) buffer = new FilterReplyHeader
        {
            Status = StatusSuccess,
            MessageId = messageId,
        };

        SafeUploadResponse* response = (SafeUploadResponse*) (buffer + sizeof(FilterReplyHeader));
        *response = new SafeUploadResponse
        {
            Version = Contract.Version,
            StructSize = (uint) sizeof(SafeUploadResponse),
            RequestId = requestId,
            Verdict = verdict,
            StageNameLength = (uint) ((stageName?.Length ?? 0) * sizeof(char)),
        };
        if (stageName is not null)
        {
            for (int i = 0; i < stageName.Length; i += 1)
            {
                response->StageName[i] = stageName[i];
            }
        }

        return SendObservedReply((IntPtr)buffer, (uint)size);
    }

    public static SafeUploadStageAllocationResolutionReplyV20 CreateAllocationResolutionReplyV20(SafeUploadRequest request, uint result = StageV20Result.NoAllocationCommitted)
    {
        if (!request.TryReadStagePayload<SafeUploadStageAllocateV20>(Operation.StageAllocate, out var source) ||
            source.RequestorCreationTime <= 0 || source.Intent.AllocationReservationId == Guid.Empty ||
            source.Intent.DriverInstanceId == Guid.Empty || request.RequestId == 0 || request.RequestorProcessId == 0 ||
            result is not (StageV20Result.NoAllocationCommitted or StageV20Result.RetryableFailure))
            throw new ArgumentException("Invalid exact allocation resolution source.", nameof(request));
        return new SafeUploadStageAllocationResolutionReplyV20
        {
            Version = Contract.Version, StructSize = Contract.StageAllocationResolutionReplyV20Size,
            RequestId = request.RequestId, Verdict = Verdict.Allow,
            Result = result, OriginalRequest = request
        };
    }

    public unsafe bool ReplyAllocationResolutionV20(ulong messageId, SafeUploadRequest request, uint result)
    {
        var reply = CreateAllocationResolutionReplyV20(request, result);
        int size = sizeof(FilterReplyHeader) + sizeof(SafeUploadStageAllocationResolutionReplyV20);
        byte* buffer = stackalloc byte[size];
        new Span<byte>(buffer, size).Clear();
        *(FilterReplyHeader*)buffer = new FilterReplyHeader { Status = StatusSuccess, MessageId = messageId };
        *(SafeUploadStageAllocationResolutionReplyV20*)(buffer + sizeof(FilterReplyHeader)) = reply;
        return ReplyTypedStageBuffer(messageId, buffer, size);
    }

    internal static void ValidateAllocationResolutionReplyV20(SafeUploadStageAllocationResolutionReplyV20 reply,
        SafeUploadRequest request)
    {
        var expected = CreateAllocationResolutionReplyV20(request, reply.Result);
        if (!MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref reply, 1)).SequenceEqual(
                MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref expected, 1))))
            throw new ArgumentException("The terminal receipt does not match the original allocation bytes.", nameof(reply));
    }

    private int SendObservedReply(IntPtr buffer, uint size)
    {
        using var observation = FilterReplyObservation.Begin();
        int hr = FilterReplyMessage(Handle, buffer, size);
        observation?.Complete(hr);
        return hr;
    }

    /// <summary>
    /// Replies to a v19 seal or discard request. StageNameLength carries the
    /// operation-specific result code for this typed request, so this must
    /// not be sent through the ordinary text StageName reply path.
    /// </summary>
    public unsafe void ReplyStageStatusV19(ulong messageId, ulong requestId, uint result)
    {
        if (result is not (StageV19Result.Sealed or
                           StageV19Result.DiscardPending or StageV19Result.DiscardAcknowledged))
        {
            throw new ArgumentOutOfRangeException(nameof(result), "Unknown v19 stage result.");
        }

        int size = sizeof(FilterReplyHeader) + sizeof(SafeUploadStageCreateReplyV19);
        byte* buffer = stackalloc byte[size];
        new Span<byte>(buffer, size).Clear();
        *(FilterReplyHeader*)buffer = new FilterReplyHeader { Status = StatusSuccess, MessageId = messageId };

        SafeUploadStageCreateReplyV19* response =
            (SafeUploadStageCreateReplyV19*)(buffer + sizeof(FilterReplyHeader));
        response->Version = Contract.Version;
        response->StructSize = (uint)sizeof(SafeUploadStageCreateReplyV19);
        response->RequestId = requestId;
        response->Verdict = Verdict.Allow;
        response->StageNameLength = result;

        ReplyTypedStageBuffer(messageId, buffer, size);
    }

    /// <summary>Replies with the exact operation-specific v20 receipt payload.</summary>
    public unsafe bool ReplyStageLifecycleV20(ulong messageId,
        in SafeUploadStageLifecycleV20 payload)
    {
        if (payload.Version != Contract.StageExtensionVersion ||
            payload.StructSize != Contract.StageLifecycleV20Size ||
            payload.RequestId == 0 || payload.TransferId == Guid.Empty ||
            payload.DestinationGeneration == 0 || !payload.StageIdentity.HasNonzeroFileId ||
            payload.DriverInstanceId == Guid.Empty || !payload.ParentDirectoryIdentity.HasNonzeroFileId ||
            !IsValidStageLifecycleResult(payload.Operation, payload.Result))
            throw new ArgumentException("Invalid v20 lifecycle receipt.", nameof(payload));

        int size = sizeof(FilterReplyHeader) + sizeof(SafeUploadStageCreateReplyV19);
        byte* buffer = stackalloc byte[size];
        new Span<byte>(buffer, size).Clear();
        *(FilterReplyHeader*)buffer = new FilterReplyHeader { Status = StatusSuccess, MessageId = messageId };

        SafeUploadResponse* outer = (SafeUploadResponse*)(buffer + sizeof(FilterReplyHeader));
        *outer = new SafeUploadResponse
        {
            Version = Contract.Version,
            StructSize = (uint)sizeof(SafeUploadResponse),
            RequestId = payload.RequestId,
            Verdict = Verdict.Allow,
            StageNameLength = Contract.StageLifecycleV20Size
        };
        *(SafeUploadStageLifecycleV20*)((byte*)outer + 24) = payload;
        return ReplyTypedStageBuffer(messageId, buffer, size);
    }

    public static unsafe SafeUploadStageRenameReplyV20 CreateStageRenameReplyV20(
        in SafeUploadStageRenameV20 source, ulong destinationGeneration, string destinationName, uint result)
    {
        if (source.Version != Contract.StageExtensionVersion || source.StructSize != Contract.StageRenameV20Size ||
            source.Operation != Operation.StageRenameCommit || source.Result != 0 || source.RequestId == 0 ||
            source.TransferId == Guid.Empty || source.SourceGeneration == 0 || source.SourceGeneration > long.MaxValue ||
            destinationGeneration > long.MaxValue || !source.StageIdentity.HasNonzeroFileId ||
            source.DriverInstanceId == Guid.Empty || !source.ParentDirectoryIdentity.HasNonzeroFileId ||
            source.ViewGeneration == 0 || source.OwnerProcessId == 0 || source.SealedVersion > 1 ||
            string.IsNullOrEmpty(destinationName) || destinationName.Length >= Contract.MaxPathChars ||
            destinationName.Contains('\0') ||
            (result == StageV20Result.RenameCommitted ? destinationGeneration == 0 :
                result != StageV20Result.RetryableFailure || destinationGeneration != 0))
            throw new ArgumentException("Invalid v20 rename receipt.", nameof(source));
        SafeUploadStageRenameReplyV20 reply = new()
        {
            Version = Contract.Version,
            StructSize = Contract.StageRenameReplyV20Size,
            RequestId = source.RequestId,
            Verdict = Verdict.Allow,
            PayloadLength = Contract.StageRenameCommitV20Size,
            Receipt = new SafeUploadStageRenameCommitV20
            {
                Source = source,
                DestinationGeneration = destinationGeneration,
                DestinationNameLength = checked((uint)(destinationName.Length * sizeof(char)))
            }
        };
        reply.Receipt.Source.StructSize = Contract.StageRenameCommitV20Size;
        reply.Receipt.Source.Result = result;
        char* name = reply.Receipt.DestinationName;
        destinationName.AsSpan().CopyTo(new Span<char>(name, Contract.MaxPathChars));
        return reply;
    }

    internal static unsafe void ValidateStageRenameReplyV20(in SafeUploadStageRenameReplyV20 reply)
    {
        // Rebuild/validate at the transport boundary; padding and unused name bytes must be zero.
        SafeUploadStageRenameReplyV20 supplied = reply;
        SafeUploadStageRenameV20 source = supplied.Receipt.Source;
        source.StructSize = Contract.StageRenameV20Size;
        source.Result = 0;
        if (supplied.Receipt.DestinationNameLength > (Contract.MaxPathChars - 1) * sizeof(char) ||
            supplied.Receipt.DestinationNameLength % sizeof(char) != 0)
            throw new ArgumentException("Invalid v20 rename name length.", nameof(reply));
        string name = new(supplied.Receipt.DestinationName, 0,
            checked((int)supplied.Receipt.DestinationNameLength / sizeof(char)));
        SafeUploadStageRenameReplyV20 expected = CreateStageRenameReplyV20(source,
            supplied.Receipt.DestinationGeneration, name, supplied.Receipt.Source.Result);
        if (!new ReadOnlySpan<byte>(&supplied, sizeof(SafeUploadStageRenameReplyV20)).SequenceEqual(
                new ReadOnlySpan<byte>(&expected, sizeof(SafeUploadStageRenameReplyV20))))
            throw new ArgumentException("Invalid v20 rename receipt envelope or padding.", nameof(reply));
    }

    public unsafe bool ReplyStageRenameCommitV20(ulong messageId, in SafeUploadStageRenameReplyV20 reply)
    {
        ValidateStageRenameReplyV20(reply);
        int size = sizeof(FilterReplyHeader) + sizeof(SafeUploadStageRenameReplyV20);
        byte* buffer = stackalloc byte[size];
        new Span<byte>(buffer, size).Clear();
        *(FilterReplyHeader*)buffer = new FilterReplyHeader { Status = StatusSuccess, MessageId = messageId };
        *(SafeUploadStageRenameReplyV20*)(buffer + sizeof(FilterReplyHeader)) = reply;
        return ReplyTypedStageBuffer(messageId, buffer, size);
    }

    /// <summary>Replies with the exact v20 capability negotiation result.</summary>
    public unsafe bool ReplyStageReconcileV20(ulong messageId,
        in SafeUploadStageReconcileReplyV20 payload)
    {
        if (payload.Version != Contract.StageExtensionVersion ||
            payload.StructSize != Contract.StageReconcileReplyV20Size ||
            payload.Operation != Operation.StageReconcile || payload.RequestId == 0 ||
            payload.DriverInstanceId == Guid.Empty || payload.ReservedZero != 0 ||
            (payload.Result == StageV20Result.CapabilitiesAccepted &&
                payload.AcceptedCapabilityMask != (uint)StageV20Capability.Required) ||
            (payload.Result == StageV20Result.EpochBusy && payload.AcceptedCapabilityMask != 0) ||
            payload.Result is not (StageV20Result.CapabilitiesAccepted or StageV20Result.EpochBusy))
            throw new ArgumentException("Invalid v20 capability receipt.", nameof(payload));

        SafeUploadStageReconcileReplyV20 copy = payload;
        return ReplyStageStatusPayloadV20(messageId, copy.RequestId, Contract.StageReconcileReplyV20Size,
            &copy, sizeof(SafeUploadStageReconcileReplyV20));
    }

    /// <summary>Replies with the exact v20 epoch-drain result.</summary>
    public unsafe bool ReplyStageEpochDrainV20(ulong messageId,
        in SafeUploadStageEpochDrainReplyV20 payload)
    {
        if (payload.Version != Contract.StageExtensionVersion ||
            payload.StructSize != Contract.StageEpochDrainReplyV20Size ||
            payload.Operation != Operation.StageEpochDrain || payload.RequestId == 0 ||
            payload.DriverInstanceId == Guid.Empty || payload.DrainNonce == 0 ||
            payload.Result is not (StageV20Result.EpochDrained or StageV20Result.EpochBusy))
            throw new ArgumentException("Invalid v20 epoch-drain receipt.", nameof(payload));

        SafeUploadStageEpochDrainReplyV20 copy = payload;
        return ReplyStageStatusPayloadV20(messageId, copy.RequestId, Contract.StageEpochDrainReplyV20Size,
            &copy, sizeof(SafeUploadStageEpochDrainReplyV20));
    }

    private unsafe bool ReplyStageStatusPayloadV20(ulong messageId, ulong requestId,
        int payloadLength, void* payload, int payloadSize)
    {
        if (payloadSize != payloadLength || payloadLength > 128)
            throw new ArgumentOutOfRangeException(nameof(payloadLength));
        int size = sizeof(FilterReplyHeader) + sizeof(SafeUploadResponse);
        byte* buffer = stackalloc byte[size];
        new Span<byte>(buffer, size).Clear();
        *(FilterReplyHeader*)buffer = new FilterReplyHeader { Status = StatusSuccess, MessageId = messageId };
        SafeUploadResponse* outer = (SafeUploadResponse*)(buffer + sizeof(FilterReplyHeader));
        *outer = new SafeUploadResponse
        {
            Version = Contract.Version,
            StructSize = (uint)sizeof(SafeUploadResponse),
            RequestId = requestId,
            Verdict = Verdict.Allow,
            StageNameLength = checked((uint)payloadLength)
        };
        Buffer.MemoryCopy(payload, (byte*)outer + 24, 128, payloadLength);
        return ReplyTypedStageBuffer(messageId, buffer, size);
    }

    private static bool IsValidStageLifecycleResult(uint operation, uint result) => operation switch
    {
        Operation.StageAttachPrepare => result == StageV20Result.AttachPrepared,
        Operation.StageAttachCommit => result is StageV20Result.AttachCommitted or
            StageV20Result.AttachCommitDenied or StageV20Result.AttachAlreadyCommitted,
        Operation.StageAttachAbort => result is StageV20Result.AttachAborted or
            StageV20Result.AttachAlreadyCommitted,
        Operation.StageCompletionPermit => result == StageV20Result.CompletionPermitted,
        Operation.StageRetireUnexposed => result == StageV20Result.AttachRetiredUnexposed,
        Operation.StageRetireAttachedPrivate => result == StageV20Result.AttachRetiredPrivate,
        Operation.StageHandleObserved => result is StageV20Result.HandleLifetimeObserved or StageV20Result.RetryableFailure,
        _ => false
    };

    /// <summary>
    /// Replies to a v19 allocate or CREATE_AFTER_DISCARD request with the
    /// exact stage identity. The 48-WCHAR name capacity preserves the full
    /// 32-character transfer GUID plus the existing 16-character suffix.
    /// </summary>
    public unsafe void ReplyStageCreateV19(ulong messageId, ulong requestId, string stageName,
        ulong destinationGeneration, in SafeUploadStageIdentityV19 stageIdentity)
    {
        ArgumentNullException.ThrowIfNull(stageName);
        if (!IsValidV19StageName(stageName))
            throw new ArgumentException("Invalid v19 stage basename.", nameof(stageName));
        if (destinationGeneration == 0)
            throw new ArgumentOutOfRangeException(nameof(destinationGeneration));
        if (!stageIdentity.HasNonzeroFileId)
            throw new ArgumentException("The v19 stage FILE_ID_128 must be nonzero.", nameof(stageIdentity));

        int size = sizeof(FilterReplyHeader) + sizeof(SafeUploadStageCreateReplyV19);
        byte* buffer = stackalloc byte[size];
        new Span<byte>(buffer, size).Clear();
        *(FilterReplyHeader*)buffer = new FilterReplyHeader { Status = StatusSuccess, MessageId = messageId };

        SafeUploadStageCreateReplyV19* response =
            (SafeUploadStageCreateReplyV19*)(buffer + sizeof(FilterReplyHeader));
        response->Version = Contract.Version;
        response->StructSize = (uint)sizeof(SafeUploadStageCreateReplyV19);
        response->RequestId = requestId;
        response->Verdict = Verdict.Allow;
        response->StageNameLength = (uint)(stageName.Length * sizeof(char));
        response->DestinationGeneration = destinationGeneration;
        response->StageIdentity = stageIdentity;
        for (int i = 0; i < stageName.Length; i++) response->StageName[i] = stageName[i];

        ReplyTypedStageBuffer(messageId, buffer, size);
    }

    private static bool IsValidV19StageName(string name)
    {
        if (name.Length is < 32 or > Contract.StageCreateReplyV19NameChars) return false;
        for (int i = 0; i < 32; i++)
        {
            char ch = name[i];
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
        }
        for (int i = 32; i < name.Length; i++)
        {
            char ch = name[i];
            if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                  (ch >= '0' && ch <= '9') || ch is '.' or '_')) return false;
        }
        return true;
    }

    private unsafe bool ReplyTypedStageBuffer(ulong messageId, byte* buffer, int size)
    {
        int hr = SendObservedReply((IntPtr)buffer, (uint)size);
        if (hr == unchecked((int)0x8007010B))
        {
            return false;
        }
        if (hr != 0)
        {
            throw new Win32Exception(hr, $"FilterReplyMessage falhou: 0x{hr:X8}");
        }
        return true;
    }

    /// <summary>
    /// Pushes the policy. Until this succeeds the driver has no policy at
    /// all and inspects nothing, so this is not optional setup - it is the
    /// step that turns the filter on.
    /// </summary>
    public unsafe void SetPolicy(in SafeUploadPolicyMessage policy, bool finalizeDurableBootScopes = false)
    {
        using var send = EnterSend();
        fixed (SafeUploadPolicyMessage* p = &policy)
        {
            p->Control.Version = Contract.Version;
            p->Control.StructSize = (uint) sizeof(SafeUploadPolicyMessage);
            p->Control.Command = ControlCommand.SetPolicy;
            p->Control.Reserved = finalizeDurableBootScopes ? Contract.FinalizeDurableBootScopes : 0;

            int hr = FilterSendMessage(send.Handle, (IntPtr) p, (uint) sizeof(SafeUploadPolicyMessage),
                                       IntPtr.Zero, 0, out _);

            if (hr != 0)
            {
                throw new Win32Exception(hr, $"Envio da politica falhou: 0x{hr:X8}");
            }
        }
    }


    /// <summary>
    /// Concede uma excecao: um processo, um caminho de destino exato, por um
    /// prazo curto e valida para um uso.
    ///
    /// Quem chama tem de ter registrado a justificativa ANTES - a excecao e
    /// a consequencia do registro, nao o contrario. Um caminho que conceda
    /// primeiro e audite depois deixa de auditar quando o segundo passo
    /// falha, e o que fica e o buraco sem o registro.
    /// </summary>
    /// <param name="processId">Processo que levou a recusa.</param>
    /// <param name="ntPath">Caminho de destino em forma de dispositivo.</param>
    /// <param name="duration">Prazo pedido; o driver limita.</param>
    public unsafe void GrantOverride(uint processId, string ntPath, TimeSpan duration)
    {
        ArgumentException.ThrowIfNullOrEmpty(ntPath);

        if (ntPath.Length >= Contract.MaxPathChars)
        {
            throw new ArgumentException($"Caminho com {ntPath.Length} caracteres; o limite e {Contract.MaxPathChars - 1}.", nameof(ntPath));
        }

        var message = new SafeUploadOverrideMessage
        {
            Control = new SafeUploadControl
            {
                Version = Contract.Version,
                StructSize = (uint) sizeof(SafeUploadOverrideMessage),
                Command = ControlCommand.GrantOverride,
                Reserved = 0,
            },
            ProcessId = processId,
            DurationSeconds = (uint) Math.Clamp(duration.TotalSeconds, 1, 600),
            PathLength = (uint) (ntPath.Length * sizeof(char)),
            Reserved = 0,
        };

        for (int i = 0; i < ntPath.Length; i += 1)
        {
            message.Path[i] = ntPath[i];
        }

        using var send = EnterSend();
        int hr = FilterSendMessage(send.Handle, (IntPtr) (&message), (uint) sizeof(SafeUploadOverrideMessage),
                                   IntPtr.Zero, 0, out _);

        if (hr != 0)
        {
            throw new Win32Exception(hr, $"Concessao de excecao falhou: 0x{hr:X8}");
        }
    }

    public void SetPublicationPermit(Guid transferId, string temporaryPath, string destinationPath, string digest)
        => SendPublicationPermit(transferId, PolicyBuilder.ToNtPath(temporaryPath),
            PolicyBuilder.ToNtPath(destinationPath), Convert.FromHexString(digest), false);

    public void RevokePublicationPermit(Guid transferId)
        => SendPublicationPermit(transferId, "", "", new byte[32], true);

    private unsafe void SendPublicationPermit(Guid id, string temporaryPath,
        string destinationPath, byte[] digest, bool revoke)
    {
        if (id == Guid.Empty || digest.Length != 32 ||
            temporaryPath.Length >= Contract.MaxPathChars ||
            destinationPath.Length >= Contract.MaxPathChars)
            throw new ArgumentException("Invalid publication permit.");
        SafeUploadPublicationMessage message = new()
        {
            Control = new() { Version = Contract.Version,
                StructSize = (uint)sizeof(SafeUploadPublicationMessage),
                Command = ControlCommand.StagePublication },
            TransferId = id, Revoke = revoke ? 1u : 0u,
            TemporaryPathLength = (uint)(temporaryPath.Length * sizeof(char)),
            DestinationPathLength = (uint)(destinationPath.Length * sizeof(char))
        };
        for (int i = 0; i < digest.Length; ++i) message.Digest[i] = digest[i];
        for (int i = 0; i < temporaryPath.Length; ++i) message.TemporaryPath[i] = temporaryPath[i];
        for (int i = 0; i < destinationPath.Length; ++i) message.DestinationPath[i] = destinationPath[i];
        using var send = EnterSend();
        int hr = FilterSendMessage(send.Handle, (IntPtr)(&message), (uint)sizeof(SafeUploadPublicationMessage),
            IntPtr.Zero, 0, out _);
        if (hr != 0) throw new Win32Exception(hr, $"Publication permit refused: 0x{hr:X8}");
    }

    /// <summary>
    /// Tells the driver the service no longer needs a staged version (SAFEUPLOAD_CONTROL_STAGE_DISPOSE). Returns true when
    /// the driver still holds the version: it releases it once nothing references it and, for a released (approved)
    /// version, deletes the stage file then; a disposal that a later rename made stale is also answered true (the driver
    /// keeps the version for the new inspection). False means nothing references it and the stage is the service's.
    /// </summary>
    public unsafe bool DisposeStage(Guid transferId, uint outcome, uint committedRenames)
    {
        if (transferId == Guid.Empty ||
            (outcome != StageDisposeOutcome.Released && outcome != StageDisposeOutcome.CleanedUp))
            throw new ArgumentException("Invalid stage disposal.");
        SafeUploadStageDisposeMessage message = new()
        {
            Control = new() { Version = Contract.Version,
                StructSize = (uint)sizeof(SafeUploadStageDisposeMessage),
                Command = ControlCommand.StageDispose },
            TransferId = transferId,
            Outcome = outcome,
            CommittedRenames = committedRenames,
        };
        SafeUploadStageDisposeReply reply = default;
        using var send = EnterSend();
        int hr = FilterSendMessage(send.Handle, (IntPtr)(&message), (uint)sizeof(SafeUploadStageDisposeMessage),
            (IntPtr)(&reply), (uint)sizeof(SafeUploadStageDisposeReply), out uint returned);
        if (hr != 0) throw new Win32Exception(hr, $"Stage disposal refused: 0x{hr:X8}");
        if (returned != sizeof(SafeUploadStageDisposeReply) ||
            reply.StructSize != sizeof(SafeUploadStageDisposeReply) || reply.Held > 1)
            throw new System.IO.IOException("Malformed stage disposal reply.");
        return reply.Held == 1;
    }

    /// <summary>Old drivers must never enter a large-file allocation profile.</summary>
    public unsafe void RequireStageSpaceCapabilities()
    {
        var control = new SafeUploadControl { Version = Contract.Version,
            StructSize = (uint)sizeof(SafeUploadControl), Command = ControlCommand.StageSpaceCapabilities };
        uint version = 0;
        using var send = EnterSend();
        int result = FilterSendMessage(send.Handle, (IntPtr)(&control), (uint)sizeof(SafeUploadControl),
            (IntPtr)(&version), sizeof(uint), out uint returned);
        ValidateStageSpaceCapabilities(result, returned, version);
    }

    internal static void ValidateStageSpaceCapabilities(int result, uint returned, uint version)
    {
        if (result != 0 || returned != sizeof(uint) || version != 31)
            throw new IOException("The connected driver does not support the exact large-file grant/failure-seal contract.");
    }

    public unsafe SafeUploadCounters GetCounters()
    {
        var control = new SafeUploadControl
        {
            Version = Contract.Version,
            StructSize = (uint) sizeof(SafeUploadControl),
            Command = ControlCommand.GetCounters,
            Reserved = 0,
        };

        SafeUploadCounters counters = default;

        using var send = EnterSend();
        int hr = FilterSendMessage(send.Handle, (IntPtr) (&control), (uint) sizeof(SafeUploadControl),
                                   (IntPtr) (&counters), (uint) sizeof(SafeUploadCounters), out _);

        if (hr != 0)
        {
            throw new Win32Exception(hr, $"Leitura dos contadores falhou: 0x{hr:X8}");
        }

        return counters;
    }

    public void Dispose()
    {
        SafeFileHandle? handle;
        lock (_sendLifecycle)
        {
            if (!_acceptingSends)
            {
                while (!_disposed) Monitor.Wait(_sendLifecycle);
                return;
            }

            _acceptingSends = false;
#if SAFEUPLOAD_ADMISSION_EVIDENCE
            CloseResourceSends();
#endif
            while (_activeSenders != 0) Monitor.Wait(_sendLifecycle);
            handle = _handle;
            _handle = null;
        }

        try
        {
            handle?.Dispose();
#if SAFEUPLOAD_ADMISSION_EVIDENCE
            _resourceHandle?.Dispose();
            _resourceHandle = null;
#endif
        }
        finally
        {
            lock (_sendLifecycle)
            {
                _disposed = true;
                Monitor.PulseAll(_sendLifecycle);
            }
        }
    }

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterConnectCommunicationPort(
        string lpPortName, uint dwOptions, IntPtr lpContext, ushort wSizeOfContext,
        IntPtr lpSecurityAttributes, out SafeFileHandle hPort);

    [DllImport("fltlib.dll")]
    private static extern int FilterGetMessage(
        SafeFileHandle hPort, IntPtr lpMessageBuffer, uint dwMessageBufferSize, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetOverlappedResult(SafeFileHandle handle,
        IntPtr overlapped, out uint bytes, [MarshalAs(UnmanagedType.Bool)] bool wait);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CancelIoEx(SafeFileHandle handle, IntPtr overlapped);

    [DllImport("fltlib.dll")]
    private static extern int FilterReplyMessage(
        SafeFileHandle hPort, IntPtr lpReplyBuffer, uint dwReplyBufferSize);

    [DllImport("fltlib.dll")]
    private static extern int FilterSendMessage(
        SafeFileHandle hPort, IntPtr lpInBuffer, uint dwInBufferSize,
        IntPtr lpOutBuffer, uint dwOutBufferSize, out uint lpBytesReturned);
}
