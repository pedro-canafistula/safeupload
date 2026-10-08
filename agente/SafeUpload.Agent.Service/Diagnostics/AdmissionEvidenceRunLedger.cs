#if SAFEUPLOAD_ADMISSION_EVIDENCE
namespace SafeUpload.Agent.Service.Diagnostics;

/// <summary>
/// Tracks ordered per-target capture requests. Ordinal and request ID are
/// reserved before sampling starts; if any sampled hook is incomplete, that
/// run target becomes terminal and must use a new RunId. Replaying a request
/// cannot recreate an earlier mapping boundary. At most 128 target records
/// are retained for the full binding lifetime; only Clear, called during
/// bind/unbind, releases those tombstones.
/// </summary>
internal sealed class AdmissionEvidenceRunLedger
{
    private readonly object _gate = new();
    private readonly Dictionary<RunTargetKey, RunProgress> _runs = new();

    internal void Clear()
    {
        lock (_gate) _runs.Clear();
    }

    internal string? Advance(AdmissionEvidenceRequest request, long bindingGeneration)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (bindingGeneration <= 0) throw new ArgumentOutOfRangeException(nameof(bindingGeneration));

        var key = new RunTargetKey(request.RunId, request.VolumeGuid.ToUpperInvariant(),
            request.VolumeSerial, Convert.ToHexString(request.FileId));
        lock (_gate)
        {
            if (!_runs.TryGetValue(key, out RunProgress? progress))
            {
                if (request.Hook != AdmissionEvidenceHook.ExpandedPolicyPostAck)
                    return "HOOK_SEQUENCE_MUST_START_AT_2";
                if (_runs.Count >= 128) return "RUN_LIMIT_REACHED";
                progress = new RunProgress(bindingGeneration);
                _runs.Add(key, progress);
            }

            if (progress.TerminalCaptureIncomplete)
                return "RUN_TERMINAL_CAPTURE_INCOMPLETE_NEW_RUN_REQUIRED";
            if (progress.BindingGeneration != bindingGeneration)
                return "BINDING_GENERATION_CHANGED";
            if (progress.RequestIds.Contains(request.RequestId)) return "DUPLICATE_REQUEST_ID";
            byte expected = checked((byte)(progress.LastOrdinal + 1));
            if ((byte)request.Hook != expected) return "HOOK_SEQUENCE_OUT_OF_ORDER";

            // Reserve before the native observations so duplicate requests
            // never imply that a consumed hook was recaptured.
            progress.RequestIds.Add(request.RequestId);
            progress.LastOrdinal = (byte)request.Hook;
            return null;
        }
    }

    internal void MarkCaptureIncomplete(AdmissionEvidenceRequest request, long bindingGeneration)
    {
        ArgumentNullException.ThrowIfNull(request);
        var key = new RunTargetKey(request.RunId, request.VolumeGuid.ToUpperInvariant(),
            request.VolumeSerial, Convert.ToHexString(request.FileId));
        lock (_gate)
        {
            if (!_runs.TryGetValue(key, out RunProgress? progress) ||
                progress.BindingGeneration != bindingGeneration ||
                progress.LastOrdinal != (byte)request.Hook ||
                !progress.RequestIds.Contains(request.RequestId))
                return;

            progress.TerminalCaptureIncomplete = true;
        }
    }

    internal int Count
    {
        get { lock (_gate) return _runs.Count; }
    }

    private sealed class RunProgress(long bindingGeneration)
    {
        internal long BindingGeneration { get; } = bindingGeneration;
        internal HashSet<Guid> RequestIds { get; } = new();
        internal byte LastOrdinal { get; set; } = 1;
        internal bool TerminalCaptureIncomplete { get; set; }
    }

    private readonly record struct RunTargetKey(Guid RunId, string VolumeGuid, ulong VolumeSerial, string FileIdHex);
}
#endif
