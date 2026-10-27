
namespace SafeUpload.Agent.Service.Interception;

public sealed partial class StagedSpaceBudget
{
    private readonly HashSet<Guid> _legacyCompleted = [];
    private readonly HashSet<Guid> _legacySecuritySnapshots = [];
    private long _legacyJournalAllowance;
    private long _legacyNegativeAllowance;

    private void UpgradeLegacyJournal(StagedTransferJournal journal)
    {
        // These are storage debits only. Exact record validation below grants
        // inventory compatibility; neither operation authorizes public I/O/deletion.
        string directory = journal.DirectoryPath;
        long existing = MetadataFiles(directory).Concat(MetadataFiles(Path.Combine(directory, "completed"))).Sum(x => x.Value);
        _legacyJournalAllowance = checked(existing * 2 + 16 * MetadataBytes);
        journal.PrivateTemporaryAdmission = RequireMetadataAdmission;
        journal.ArchiveGrowthAdmission = RequireArchiveAdmission;
        journal.ArchiveStorageChanged = RefreshArchiveStorage;
        journal.VisitStageSpaceUpgradeAsync(entry =>
        {
            lock (_gate)
            {
                Guid id = entry.Transfer.TransferId;
                if (_reservations.TryGetValue(id, out var previous))
                {
                    if (previous.LegacyGuard)
                    {
                        string expectedSid = LegacyOwner(entry);
                        if (previous.StagePath != Path.GetFullPath(entry.Transfer.StagePath) || previous.Sid != expectedSid ||
                            previous.StageIdentity != entry.StageIdentity)
                            throw new IOException("The legacy reservation no longer matches its recorded custody.");
                        ValidateLegacyGuard(entry);
                    }
                    return;
                }
                if (StagedTransferJournal.StageSpaceUpgradeComplete(entry) &&
                    StagedStageFile.TryConfirmAbsent(entry.Transfer.StagePath, out _))
                {
                    _legacyCompleted.Add(id);
                    return;
                }
                string path = ValidateLegacyGuard(entry);
                var record = new Reservation(id, LegacyOwner(entry), MinimumCapacity,
                    path, entry.StageIdentity, null, 1, LegacyGuard: true);
                Persist(record, create: true); AdoptReservation(record);
            }
        }, id => { lock (_gate) _legacySecuritySnapshots.Add(id); }, CancellationToken.None).GetAwaiter().GetResult();
        // Pending imported versions already own retained per-transfer metadata.
        // Only exempt, completed history needs the separate shared envelope.
        if (_legacyCompleted.Count == 0 && _legacySecuritySnapshots.Count == 0) _legacyJournalAllowance = 0;
        VerifyJournalInventory(directory, journal);
    }

    private bool LegacySecurityMetadataPath(string path)
    {
        string leaf = Path.GetFileName(path);
        if (leaf.Length < 32 || !Guid.TryParseExact(leaf[..32], "N", out Guid id) || !_legacySecuritySnapshots.Contains(id))
            return false;
        string suffix = leaf[32..];
        return suffix == ".security" || suffix.Length == 10 + 32 + 4 &&
            suffix.StartsWith(".security.", StringComparison.Ordinal) && suffix.EndsWith(".tmp", StringComparison.Ordinal) &&
            Guid.TryParseExact(suffix.AsSpan(10, 32), "N", out _);
    }

    private static string LegacyOwner(TransferJournalEntry entry) =>
        string.IsNullOrWhiteSpace(entry.Transfer.RequestorSid) ? "legacy:unattributed" : entry.Transfer.RequestorSid;

    private string ValidateLegacyGuard(TransferJournalEntry entry)
    {
        string path = Path.GetFullPath(entry.Transfer.StagePath);
        if (!string.Equals(Path.GetDirectoryName(path), Path.GetDirectoryName(_directory), StringComparison.OrdinalIgnoreCase))
            throw new IOException("A legacy stage locator escaped the private staging root.");
        if (!StagedStageFile.TryConfirmAbsent(path + ".space", out _))
            throw new IOException("An existing capacity grant has no durable reservation; retain it for recovery.");
        if (entry.SealedLength is > MinimumCapacity || entry.HandbackLength is > MinimumCapacity)
            throw new IOException("The legacy content evidence exceeds the original guarded capacity.");
        // Do not adopt a newly observed identity as object authority. Missing
        // identity remains missing, and an uncertain preexisting object stays held.
        if (!StagedStageFile.TryConfirmAbsent(path, out var absenceFailure))
        {
            if (absenceFailure is not null) throw new IOException("Legacy stage custody could not be checked.", absenceFailure);
            var actual = StagedStageFile.ReadAttachedMetadata(path);
            if (actual.Length > MinimumCapacity || actual.Length < 0 ||
                entry.StageIdentity is not null && actual.Identity != entry.StageIdentity)
                throw new IOException("The legacy stage does not match its recorded guarded version.");
        }
        return path;
    }
}
