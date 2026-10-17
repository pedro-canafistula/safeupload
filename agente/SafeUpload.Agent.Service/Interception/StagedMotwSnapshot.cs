using System.Security.Cryptography;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Interception;

// Content primitive for a future whole-version producer. This is NOT a
// completion witness, stream authority, publication permit or justification.
// The live unbound path continues to refuse Zone.Identifier until it has an
// object/generation-bound completion contract and an atomic stream publisher.
internal sealed class StagedMotwSnapshot
{
    internal const int MaximumBytes = 64 * 1024;
    private readonly byte[] _bytes;
    internal int Length => _bytes.Length;
    internal string Sha256Hex { get; }

    private StagedMotwSnapshot(byte[] bytes)
    {
        _bytes = bytes;
        Sha256Hex = Convert.ToHexString(SHA256.HashData(bytes));
    }

    // The producer owns an exact read lease. Bound allocation before reading,
    // consume precisely the measured length and require EOF. Never inspect a
    // prefix of an oversized, truncated, growing or canceled stream.
    internal static async Task<StagedMotwSnapshot> CaptureAsync(Stream source, long expectedLength,
        CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(source);
        token.ThrowIfCancellationRequested();
        if (expectedLength < 0 || expectedLength > MaximumBytes)
            throw new StagedMetadataException("metadata_zone_size_unsupported");
        byte[] bytes = new byte[checked((int)expectedLength)];
        int offset = 0;
        while (offset < bytes.Length)
        {
            int read = await source.ReadAsync(bytes.AsMemory(offset), token).ConfigureAwait(false);
            if (read == 0) throw new StagedMetadataException("metadata_zone_measurement_changed");
            offset = checked(offset + read);
        }
        byte[] tail = new byte[1];
        if (await source.ReadAsync(tail, token).ConfigureAwait(false) != 0)
            throw new StagedMetadataException("metadata_zone_measurement_changed");
        token.ThrowIfCancellationRequested();
        return new(bytes);
    }

    internal Stream OpenRead() => new MemoryStream(_bytes, writable: false);

    // Inspect the entire stream, including HostUrl/ReferrerUrl and unknown
    // fields, through the same strict text extractor/policy as a .txt file.
    // Destination scope remains that of the owning file. The result still
    // requires current-policy validation together with the base-file result.
    internal async Task<InspectionResult> InspectAsync(InspectionService inspection, FileOperation owningFile,
        CancellationToken token)
    {
        InspectionResult result = await inspection.InspectStagedAsync(owningFile with
        {
            FilePath = owningFile.FilePath + ":Zone.Identifier",
            FileName = "Zone.Identifier.txt",
            Extension = ".txt",
            SizeBytes = Length
        }, OpenRead, token).ConfigureAwait(false);
        if (!result.InScope || result.Verdict is not (Verdict.Approved or Verdict.Blocked))
            throw new StagedMetadataException("metadata_zone_inspection_incomplete");
        return result;
    }
}
