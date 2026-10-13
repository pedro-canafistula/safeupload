#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Security.AccessControl;
using System.Security.Principal;

namespace SafeUpload.Agent.Service.Interception;

public sealed partial class StagedTransferJournal
{
    internal async Task<StagedAllocationSecuritySnapshot?> ReadBoundAllocationSecurityAsync(Guid transfer,
        CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var entry = await ReadCoreAsync(transfer, token).ConfigureAwait(false);
            return entry.AllocationSecurity is null ? null : await ReadAllocationSecurityCoreAsync(entry, token)
                .ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    // Descriptor pairs can exceed the existing 128-KiB JSON manifest bound.
    // Flush the bounded private binary record first, then commit its immutable
    // reference with the allocation manifest. An interrupted candidate remains
    // private; it cannot authorize allocation or publication without that reference.
    private async Task PersistAllocationSecurityCoreAsync(StagedAllocationSecuritySnapshot snapshot,
        CancellationToken token)
    {
        byte[] bytes = snapshot.Encode();
        string path = AllocationSecurityPath(snapshot.SnapshotId);
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var stream = CreatePrivateTemporary(temporary))
            {
                await stream.WriteAsync(bytes, token).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            try { File.Move(temporary, path); } // Never replace a snapshot, including an interrupted exact retry.
            catch (IOException) when (File.Exists(path))
            {
                byte[] existing = await ReadAllocationSecurityBytesCoreAsync(snapshot.SnapshotId, token)
                    .ConfigureAwait(false);
                if (!bytes.AsSpan().SequenceEqual(existing))
                    throw new InvalidDataException("The immutable security snapshot changed on retry.");
            }
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private async Task<StagedAllocationSecuritySnapshot> ReadAllocationSecurityCoreAsync(
        TransferJournalEntry entry, CancellationToken token)
    {
        var reference = entry.AllocationSecurity!;
        reference.Validate();
        byte[] bytes;
        try { bytes = await ReadAllocationSecurityBytesCoreAsync(reference.SnapshotId, token).ConfigureAwait(false); }
        catch (IOException error) when (error is FileNotFoundException or DirectoryNotFoundException)
        {
            // FindBoundAllocationAsync treats only a missing MANIFEST as
            // unjournaled backing. A lost committed dependency must never
            // enter that orphan-delete path or silently become legacy data.
            throw new InvalidDataException("The committed allocation security snapshot is missing.", error);
        }
        var snapshot = StagedAllocationSecuritySnapshot.Decode(bytes);
        snapshot.RequireBinding(entry.BoundAllocation!);
        if (snapshot.Reference() != reference)
            throw new InvalidDataException("The allocation security snapshot lost its committed length or digest.");
        return snapshot;
    }

    private async Task<byte[]> ReadAllocationSecurityBytesCoreAsync(Guid snapshot, CancellationToken token)
    {
        await using var stream = StagedJournalFile.Open(AllocationSecurityPath(snapshot),
            maximumBytes: StagedAllocationSecuritySnapshot.MaximumBytes);
        return await ReadAllocationSecurityBytesHeldAsync(stream, token).ConfigureAwait(false);
    }

    private async Task<byte[]> ReadAllocationSecurityBytesHeldAsync(FileStream stream, CancellationToken token)
    {
        if (stream.Length > StagedAllocationSecuritySnapshot.MaximumBytes)
            throw new InvalidDataException("Security snapshot exceeds its component bound.");
        if (_owner is not null)
        {
            var security = stream.GetAccessControl();
            if (_owner.IsWellKnown(WellKnownSidType.LocalSystemSid)) RequireTrustedOwner(security, "security snapshot");
            RequireNoUntrustedWriters(security, _owner);
        }
        byte[] bytes = new byte[checked((int)stream.Length)];
        await stream.ReadExactlyAsync(bytes, token).ConfigureAwait(false);
        if (stream.ReadByte() != -1) throw new InvalidDataException("Security snapshot grew while held for reading.");
        return bytes;
    }

    private string AllocationSecurityPath(Guid snapshot) => Path.Combine(_directory, snapshot.ToString("N") + ".security");

    // The caller holds the same journal gate used to publish snapshot references.
    // Retained high-water/ancestry manifests keep their records. A crash after
    // binary flush but before manifest commit leaves a private, unreferenced
    // record that becomes eligible only after the ordinary retention cutoff.
    private async Task CompactAllocationSecurityCoreAsync(HashSet<Guid> retained, DateTimeOffset cutoff,
        CancellationToken token)
    {
        foreach (var file in new DirectoryInfo(_directory).EnumerateFiles("*.security"))
        {
            token.ThrowIfCancellationRequested();
            if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(file.Name), "N", out Guid id))
                throw new InvalidDataException("Unexpected allocation security record name.");
            if (retained.Contains(id) || file.LastWriteTimeUtc >= cutoff.UtcDateTime) continue;
            StagedStageIdentity identity;
            long length;
            using (var held = StagedStageFile.Open(file.FullName))
            {
                // Read ACL/data and identity from this same no-follow object.
                // A pathname replacement is checked again by exact deletion.
                byte[] bytes = await ReadAllocationSecurityBytesHeldAsync(held.Stream, token).ConfigureAwait(false);
                var snapshot = StagedAllocationSecuritySnapshot.Decode(bytes);
                if (snapshot.SnapshotId != id)
                    throw new InvalidDataException("The allocation security record changed its identity.");
                identity = held.Identity;
                length = held.Stream.Length;
            }
            if (!StagedStageFile.TryDeleteExactAndConfirmAbsent(file.FullName, identity,
                    out Exception? failure, expectedLength: length))
                throw new IOException("The unreferenced security record could not be exactly removed.", failure);
        }
    }
}
#endif
