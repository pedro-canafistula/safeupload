namespace SafeUpload.Agent.Core.Application;

/// <summary>Minimizes metadata when a new audit identity is created, never during replay.</summary>
internal static class AuditMetadata
{
    internal static string FileNameOnly(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return string.Empty;
        int slash = name.LastIndexOfAny(['/', '\\']);
        return slash < 0 ? name : name[(slash + 1)..];
    }

    internal static string WebOrigin(string? destination)
    {
        if (!Uri.TryCreate(destination, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp)) return string.Empty;
        // Paths can contain secrets too. Retain only scheme, host and effective port.
        return new UriBuilder(uri.Scheme, uri.Host, uri.Port).Uri.GetLeftPart(UriPartial.Authority);
    }
}
