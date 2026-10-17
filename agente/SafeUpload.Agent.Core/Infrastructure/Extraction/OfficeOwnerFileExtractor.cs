using System.Text;

namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

/// <summary>
/// Office owner (lock) files: Word, Excel and PowerPoint write "~$name.docx" next to an open document. It is a small binary
/// record holding the editing user's name (ANSI, then UTF-16), never an Open XML package, so the package readers refused it
/// as unreadable and every open from a protected folder raised a block alert.
///
/// Owner decision 2026-10-16: inspect these files as plain text instead of refusing them. Every byte is scanned twice, as
/// Latin-1 (one character per byte, never fails) and as UTF-16LE, so no byte is approved uninspected. Anything larger than
/// <see cref="MaxBytes"/> is not an owner file and keeps the normal package reader.
/// </summary>
public sealed class OfficeOwnerFileExtractor : ITextExtractor
{
    /// <summary>Owner files are 162 bytes in current Office builds; anything larger keeps the package reader.</summary>
    public const int MaxBytes = 4096;

    private static readonly HashSet<string> OfficeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm", ".pptx", ".pptm", ".potx", ".potm"
    };

    /// <summary>Shared stateless instance.</summary>
    public static OfficeOwnerFileExtractor Instance { get; } = new();

    /// <inheritdoc />
    public IReadOnlySet<string> SupportedExtensions { get; } = new HashSet<string>();

    /// <summary>True for "~$*" files with an Office Open XML extension and at most <see cref="MaxBytes"/> bytes.</summary>
    public static bool Matches(string? fileName, string? extension, long sizeBytes) =>
        fileName is not null && fileName.StartsWith("~$", StringComparison.Ordinal) &&
        extension is not null && OfficeExtensions.Contains(extension) &&
        sizeBytes >= 0 && sizeBytes <= MaxBytes;

    /// <inheritdoc />
    public async Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        var bytes = new byte[MaxBytes + 1];
        int length = 0, read;
        while (length < bytes.Length &&
               (read = await content.ReadAsync(bytes.AsMemory(length), cancellationToken).ConfigureAwait(false)) != 0)
            length += read;
        if (length > MaxBytes) throw new InvalidDataException("The Office owner file is larger than expected.");

        var span = bytes.AsSpan(0, length);
        var text = new StringBuilder(length * 2 + 1);
        text.Append(Encoding.Latin1.GetString(span)).Append('\n');
        // UTF-16LE from both alignments, so a name stored at an odd offset is still read whole.
        text.Append(Encoding.Unicode.GetString(span[..(length & ~1)])).Append('\n');
        if (length > 1) text.Append(Encoding.Unicode.GetString(span[1..(1 + ((length - 1) & ~1))]));
        return text.ToString();
    }
}
