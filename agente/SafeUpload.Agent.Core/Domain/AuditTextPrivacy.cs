namespace SafeUpload.Agent.Core.Domain;

/// <summary>For new human-readable audit fields, never operational paths, identities or replayed payloads.</summary>
public static class AuditTextPrivacy
{
    public const string Redacted = "[dados sensiveis omitidos]";
    public const string Oversized = "[metadado omitido: limite de tamanho]";
    public const int MaximumTextLength = 4096;
    private static readonly IReadOnlySet<Category> Categories = Enum.GetValues<Category>().ToHashSet();

    /// <summary>
    /// Conservatively omits the entire field if a supported detector recognizes a value.
    /// Independent of enabled inspection rules. Not a universal anonymizer.
    /// </summary>
    public static string Sanitize(string? text)
    {
        if (string.IsNullOrEmpty(text)) return text ?? string.Empty;
        if (text.Length > MaximumTextLength) return Oversized;
        return ContentScanner.Scan(text, Categories).Count > 0 ? Redacted : text;
    }
}
