using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

internal sealed class ArchiveInspectionBudget(long maximumBytes)
{
    internal const int MaximumEntries = 16_384;
    internal const int MaximumDepth = 3; // Including the outer ZIP.
    internal const int MaximumRatio = 1_000;
    internal long MaximumBytes { get; } = maximumBytes;
    internal long ExpandedBytes { get; private set; }
    private int _entries;
    private int _metadata;
    internal void ChargeMetadata(int bytes)
    {
        const int maximumMetadata = 4 * 1024 * 1024;
        if (bytes < 0 || bytes > maximumMetadata - _metadata) throw new InspectionLimitException();
        _metadata += bytes;
    }
    private long _diagnosticCharacters;
    internal long RemainingBytes => MaximumBytes - ExpandedBytes;

    internal void Enter(int depth, int entries)
    {
        if (depth > MaximumDepth || entries > MaximumEntries - _entries) throw new InspectionLimitException();
        _entries += entries;
    }
    internal void CheckSize(long bytes)
    {
        if (bytes < 0 || bytes > MaximumBytes) throw new ArchiveSizeException();
    }
    internal void CheckExpansion(long bytes)
    {
        if (bytes < 0 || bytes > RemainingBytes) throw new ArchiveSizeException();
    }
    internal void Charge(long bytes)
    {
        CheckExpansion(bytes);
        ExpandedBytes += bytes;
    }
    internal void RetainDiagnostic(int characters)
    {
        if (characters > MaximumBytes / sizeof(char) - _diagnosticCharacters) throw new InspectionLimitException();
        _diagnosticCharacters += characters;
    }
}

internal sealed class ArchiveSizeException : Exception { }

internal enum ArchiveRefusal { Encrypted, UnsupportedMember, UnsupportedStructure, SevenZipUnavailable }

internal sealed class ArchiveRefusalException(ArchiveRefusal refusal) : NotSupportedException
{
    internal string ReasonCode => refusal switch
    {
        ArchiveRefusal.Encrypted => "archive_encrypted",
        ArchiveRefusal.UnsupportedMember => "archive_unsupported_member",
        ArchiveRefusal.SevenZipUnavailable => "archive_7z_unavailable",
        _ => "archive_unsupported_structure"
    };
}
