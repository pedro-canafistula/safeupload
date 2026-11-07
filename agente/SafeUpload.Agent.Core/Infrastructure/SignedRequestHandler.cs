using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>
/// Assina toda requisição ao servidor (docs/console-agente.md, "Assinatura"): método, rota após /agent/, host,
/// horário, nonce e SHA-256 do corpo. O servidor recusa qualquer requisição sem assinatura válida.
/// </summary>
public sealed class SignedRequestHandler(SignedAgentIdentity identity, TimeProvider? clock = null) : DelegatingHandler
{
    public const string HostHeader = "X-SafeUpload-Host";
    public const string TimeHeader = "X-SafeUpload-Time";
    public const string NonceHeader = "X-SafeUpload-Nonce";
    public const string SignatureHeader = "X-SafeUpload-Signature";

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    public static string Message(string method, string route, int hostId, long time, string nonce, byte[] body) =>
        string.Join('\n', "SafeUpload-v1", method, route, hostId.ToString(CultureInfo.InvariantCulture),
            time.ToString(CultureInfo.InvariantCulture), nonce, Convert.ToHexStringLower(SHA256.HashData(body)));

    /// <summary>Rota depois do último "/agent/", com a query se houver.</summary>
    public static string Route(Uri uri)
    {
        string path = uri.AbsolutePath;
        int index = path.LastIndexOf("/agent/", StringComparison.Ordinal);
        if (index < 0) throw new InvalidOperationException("Requisição fora de /agent/.");
        return path[(index + "/agent/".Length)..] + uri.Query;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        byte[] body = [];
        if (request.Content is { } content)
        {
            // Os bytes assinados são exatamente os enviados: o conteúdo é trocado pela cópia já serializada.
            body = await content.ReadAsByteArrayAsync(token).ConfigureAwait(false);
            var copy = new ByteArrayContent(body);
            foreach (var header in content.Headers) copy.Headers.TryAddWithoutValidation(header.Key, header.Value);
            request.Content = copy;
            content.Dispose();
        }
        long time = _clock.GetUtcNow().ToUnixTimeSeconds();
        string nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        string message = Message(request.Method.Method, Route(request.RequestUri!), identity.HostId, time, nonce, body);
        request.Headers.Remove(HostHeader);
        request.Headers.Add(HostHeader, identity.HostId.ToString(CultureInfo.InvariantCulture));
        request.Headers.Add(TimeHeader, time.ToString(CultureInfo.InvariantCulture));
        request.Headers.Add(NonceHeader, nonce);
        request.Headers.Add(SignatureHeader, identity.Sign(Encoding.UTF8.GetBytes(message)));
        return await base.SendAsync(request, token).ConfigureAwait(false);
    }
}

/// <summary>Cliente HTTP do agente: sem redirecionamento e, com certificado fixado, só aceita aquele certificado.</summary>
public static class AgentHttp
{
    public static HttpClientHandler CreateHandler(string? certificateSha256)
    {
        var handler = new HttpClientHandler { AllowAutoRedirect = false };
        if (certificateSha256 is { } pin)
        {
            string expected = NormalizePin(pin);
            handler.ServerCertificateCustomValidationCallback = (_, certificate, _, _) =>
                certificate is not null &&
                CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Fingerprint(certificate)),
                    Encoding.ASCII.GetBytes(expected));
        }
        return handler;
    }

    public static string Fingerprint(X509Certificate2 certificate) =>
        Convert.ToHexStringLower(SHA256.HashData(certificate.RawData));

    /// <summary>Aceita "AB:CD:..." ou hexa contínuo; devolve 64 dígitos minúsculos.</summary>
    public static string NormalizePin(string pin)
    {
        string value = pin.Replace(":", "", StringComparison.Ordinal).Trim().ToLowerInvariant();
        if (value.Length != 64 || !value.All(Uri.IsHexDigit))
            throw new ArgumentException("Certificado deve ser o SHA-256 em hexadecimal (64 dígitos).");
        return value;
    }

    /// <summary>Fora do loopback, só HTTPS: a URL vem do cadastro e termina em /agent/.</summary>
    public static Uri ServerUri(string address)
    {
        if (!Uri.TryCreate(address.Trim(), UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) ||
            uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0)
            throw new ArgumentException("URL do servidor inválida.");
        if (!uri.AbsolutePath.EndsWith('/')) uri = new Uri(uri.AbsoluteUri + "/");
        if (!uri.AbsolutePath.EndsWith("/agent/", StringComparison.Ordinal))
            throw new ArgumentException("A URL do servidor termina em /agent/, ex.: https://servidor:8443/agent/");
        if (uri.Scheme != Uri.UriSchemeHttps && !uri.IsLoopback)
            throw new ArgumentException("Fora do loopback o agente só fala HTTPS.");
        return uri;
    }
}
