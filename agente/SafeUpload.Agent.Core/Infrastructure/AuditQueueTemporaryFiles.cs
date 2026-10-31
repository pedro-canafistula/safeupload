namespace SafeUpload.Agent.Core.Infrastructure;

public sealed record AuditQueueTemporarySnapshot(bool DirectoryExists, long EntriesExamined,
    long CandidateFiles, long TotalBytes, long UnreadableCandidates, long SkippedReparsePoints,
    bool ScanLimitReached, bool DirectoryTraversalBlocked)
{
    public bool Complete => !ScanLimitReached && !DirectoryTraversalBlocked &&
        UnreadableCandidates == 0 && SkippedReparsePoints == 0;
    public bool RequiresAttention => CandidateFiles > 0 || !Complete;
}

public sealed partial class LocalQueueAuditSink
{
    /// <summary>
    /// Metadata-only inventory of queue-name.GUID(N).tmp candidates. Does not open
    /// contents, recurse, follow reparse points, promote or delete anything.
    /// Counts are lower bounds when Complete is false. A matching name proves
    /// neither ownership nor that a file is abandoned. The lock excludes only
    /// this sink's own writes; other processes can change entries during scanning.
    /// </summary>
    public async Task<AuditQueueTemporarySnapshot> InspectTemporaryFilesAsync(CancellationToken cancellationToken)
    {
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var directory = new DirectoryInfo(Path.GetDirectoryName(Path.GetFullPath(_queueFile))!);
            try
            {
                // Also reject a link in any ancestor of the configured directory.
                for (var ancestor = directory; ancestor is not null; ancestor = ancestor.Parent)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if ((File.GetAttributes(ancestor.FullName) & FileAttributes.ReparsePoint) != 0)
                        return new(true, 0, 0, 0, 0, 0, false, true);
                }
            }
            catch (DirectoryNotFoundException) { return new(false, 0, 0, 0, 0, 0, false, false); }
            catch (FileNotFoundException) { return new(false, 0, 0, 0, 0, 0, false, false); }

            const int entryLimit = 10_000;
            long entries = 0, candidates = 0, bytes = 0, unreadable = 0, links = 0;
            var prefix = Path.GetFileName(_queueFile) + ".";
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            var options = new EnumerationOptions { RecurseSubdirectories = false,
                IgnoreInaccessible = false, AttributesToSkip = 0, ReturnSpecialDirectories = false };
            foreach (var path in Directory.EnumerateFileSystemEntries(directory.FullName, "*", options))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (entries == entryLimit)
                    return new(true, entries, candidates, bytes, unreadable, links, true, false);
                entries++;
                var name = Path.GetFileName(path);
                if (name.Length != prefix.Length + 32 + 4 || !name.StartsWith(prefix, comparison) ||
                    !name.EndsWith(".tmp", comparison) ||
                    !Guid.TryParseExact(name.AsSpan(prefix.Length, 32), "N", out _)) continue;
                try
                {
                    var attributes = File.GetAttributes(path);
                    if ((attributes & FileAttributes.ReparsePoint) != 0) { links++; continue; }
                    if ((attributes & FileAttributes.Directory) != 0) continue;
                    var length = new FileInfo(path).Length;
                    bytes = checked(bytes + length);
                    candidates++;
                }
                catch (IOException) { unreadable++; }
                catch (UnauthorizedAccessException) { unreadable++; }
            }
            cancellationToken.ThrowIfCancellationRequested();
            return new(true, entries, candidates, bytes, unreadable, links, false, false);
        }
        finally { _writeLock.Release(); }
    }
}
