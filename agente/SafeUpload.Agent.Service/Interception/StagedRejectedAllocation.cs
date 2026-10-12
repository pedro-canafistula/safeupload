using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

internal sealed record StagedAllocation(TransferJournalEntry Entry, StagedStageIdentity? Identity);

// Diagnostics use monotonic time and are never allocation/cleanup authority.
internal sealed class StagedRequestTiming
{
    private readonly long _started = Stopwatch.GetTimestamp();
    private long _previous = Stopwatch.GetTimestamp();
    private readonly List<string> _phases = [];
    internal double ElapsedMs => Stopwatch.GetElapsedTime(_started).TotalMilliseconds;
    internal void Mark(string phase)
    {
        long now = Stopwatch.GetTimestamp();
        Observe(phase, Stopwatch.GetElapsedTime(_previous, now).TotalMilliseconds);
        _previous = now;
    }
    internal void Observe(string phase, double milliseconds) =>
        _phases.Add(phase + "=" + milliseconds.ToString("F1", CultureInfo.InvariantCulture));
    public override string ToString() => string.Join(",", _phases);
}

// Created only for the exact NO_WAITER return from the sole reply call. A
// generic failure, elapsed deadline, missing log or restart is not this proof.
internal sealed class StagedRejectedAllocation(ulong messageId, ulong requestId, StagedAllocation allocation)
{
    internal ulong MessageId { get; } = messageId;
    internal ulong RequestId { get; } = requestId;
    internal StagedAllocation Allocation { get; } = allocation;
    internal TransferJournalEntry? Disposition { get; set; }
    internal int Failures { get; private set; }
    internal long RetryAt { get; private set; }

    internal static StagedRejectedAllocation? FromReply(ulong messageId, ulong requestId,
        StagedAllocation? allocation, FilterReplyResult result) =>
        result == FilterReplyResult.NoWaiter && allocation is not null
            ? new(messageId, requestId, allocation) : null;

    internal void Backoff()
    {
        Failures = Math.Min(6, Failures + 1);
        RetryAt = Stopwatch.GetTimestamp() +
            (long)(Math.Min(8, .25 * (1 << (Failures - 1))) * Stopwatch.Frequency);
    }
}

internal static class StagedRejectedAllocationFile
{
    internal static SafeFileHandle OpenExact(StagedAllocation allocation)
    {
        if (!OperatingSystem.IsWindows() || allocation.Identity is null)
            throw new IOException("No original allocation file identity is available.");
        // DELETE | READ_ATTRIBUTES; exclusive, OPEN_EXISTING, OPEN_REPARSE_POINT.
        // No data access, following a reparse point, or path-based deletion.
        SafeFileHandle file = CreateFile(allocation.Entry.Transfer.StagePath, 0x10080, 0,
            IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
        try
        {
            if (file.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            byte[] attributes = new byte[8]; // FILE_ATTRIBUTE_TAG_INFO
            if (!GetFileInformationByHandleEx(file, 9, attributes, (uint)attributes.Length))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if ((BitConverter.ToUInt32(attributes) & (0x400u | 0x10u)) != 0 ||
                StagedDestinationFile.ReadIdentity(file) != allocation.Identity)
                throw new IOException("The rejected allocation's file identity changed.");
            return file;
        }
        catch { file.Dispose(); throw; }
    }

    internal static void Delete(SafeFileHandle file)
    {
        if (!SetFileInformationByHandle(file, 4, [1], 1))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int kind, byte[] buffer, uint length);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file, int kind, byte[] buffer, int length);
}

public sealed partial class StagedTransferJournal
{
    internal async Task RetireRejectedAllocationAsync(StagedRejectedAllocation rejected, CancellationToken token)
    {
        StagedAllocation allocation = rejected.Allocation;
        Guid id = allocation.Entry.Transfer.TransferId;
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            TransferJournalEntry current = await ReadCoreAsync(id, token).ConfigureAwait(false);
            // Disposition is retained before writing: replacement may succeed
            // then throw. Only exact equality with our attempted write may retry.
            if (rejected.Disposition is null)
            {
                if (current != allocation.Entry || current.State != TransferJournalState.Allocated ||
                    current.SealedOnce || current.PendingRename is not null ||
                    current.StageCleanupStarted || current.StageDeleted)
                    throw new IOException("The rejected allocation's journal changed.");
                var history = AppendState(current, TransferJournalState.Unsealed);
                rejected.Disposition = current with { State = TransferJournalState.Unsealed,
                    StateHistory = history, UpdatedAtUtc = history[^1].OccurredAtUtc };
            }
            else if (current != allocation.Entry && current != rejected.Disposition)
                throw new IOException("The rejected allocation's journal changed during cleanup.");

            using SafeFileHandle file = StagedRejectedAllocationFile.OpenExact(allocation);
            if (current != rejected.Disposition)
                await ReplaceAsync(ManifestPath(id), rejected.Disposition, token).ConfigureAwait(false);
            // Keep the generation; do not reuse StageDeleted's hand-back meaning.
            // No basename was delivered, hence no legitimate future seal exists.
            StagedRejectedAllocationFile.Delete(file);
        }
        finally { _gate.Release(); }
    }
}
