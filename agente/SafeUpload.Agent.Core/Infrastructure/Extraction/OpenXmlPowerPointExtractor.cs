namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

/// <summary>
/// Inspects Open XML presentations, templates and slide shows through the same
/// complete-or-refuse XML reader as Word/Excel. Macro-enabled containers use the
/// same part model; actual VBA, images, media and embedded packages are refused.
/// </summary>
public sealed class OpenXmlPowerPointExtractor : IStreamingTextExtractor
{
    /// <inheritdoc />
    public IReadOnlySet<string> SupportedExtensions { get; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".pptx", ".pptm", ".potx", ".ppsx" };

    /// <inheritdoc />
    public Task<TextReader> OpenReaderAsync(Stream content, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<TextReader>(new PresentationTextReader(content, cancellationToken));
    }

    /// <inheritdoc />
    public async Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
    {
        using var reader = await OpenReaderAsync(content, cancellationToken).ConfigureAwait(false);
        var text = new System.Text.StringBuilder();
        var buffer = new char[8192];
        int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false)) != 0)
            text.Append(buffer, 0, count);
        return text.ToString();
    }
}
