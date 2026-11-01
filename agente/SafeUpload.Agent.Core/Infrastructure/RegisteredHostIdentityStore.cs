using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Text.Json;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>Binding for an already provisioned host. Never registers or replaces an identity.</summary>
[SupportedOSPlatform("windows")]
public sealed class RegisteredHostIdentityStore
{
    private const int MaxBytes = 16 * 1024;
    private readonly string _file;
    private readonly bool _enforceProtectedAcl;

    public RegisteredHostIdentityStore(string file) : this(file, enforceProtectedAcl: true) { }

    // Same isolated-file testing boundary as DurableHttpPolicyStore; production always enforces ACLs.
    internal RegisteredHostIdentityStore(string file, bool enforceProtectedAcl)
    {
        _file = Path.GetFullPath(file);
        _enforceProtectedAcl = enforceProtectedAcl;
    }

    public int Resolve(Uri server, int? configuredHostId)
    {
        string key = ServerKey(server);
        if (configuredHostId is <= 0) throw new HostIdentityException("invalid_host");
        try
        {
            if (_enforceProtectedAcl)
            {
                if (!OperatingSystem.IsWindows()) throw new HostIdentityException("unsupported_platform");
                ProtectedPolicyAcl.EnsureDirectory(_file);
            }
            else Directory.CreateDirectory(Path.GetDirectoryName(_file)!);

            var existing = Read();
            if (existing is not null) return Match(existing.Value, key, configuredHostId);
            if (configuredHostId is null) throw new HostIdentityException("missing");
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1, serverBaseUrl = key, registeredHostId = configuredHostId.Value
            });
            if (bytes.Length > MaxBytes) throw new HostIdentityException("invalid_server");
            string temporary = Path.Combine(Path.GetDirectoryName(_file)!, ".host-" + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (var stream = _enforceProtectedAcl
                    ? new FileInfo(temporary).Create(FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None,
                        4096, FileOptions.WriteThrough, ProtectedPolicyAcl.CreatePolicyFileSecurity())
                    : new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    stream.Write(bytes);
                    stream.Flush(flushToDisk: true);
                }
                try { File.Move(temporary, _file, overwrite: false); }
                catch (IOException)
                {
                    // Another start may have committed first; accept only the same binding.
                    var concurrent = Read();
                    if (concurrent is null) throw;
                    return Match(concurrent.Value, key, configuredHostId);
                }
                return configuredHostId.Value;
            }
            finally
            {
                try { File.Delete(temporary); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
        catch (HostIdentityException) { throw; }
        catch (PolicyFileAclRejectedException) { throw new HostIdentityException("unsafe_permissions"); }
        catch (UnauthorizedAccessException) { throw new HostIdentityException("access_denied"); }
        catch (IOException) { throw new HostIdentityException("storage_error"); }
        catch (System.Security.SecurityException) { throw new HostIdentityException("access_denied"); }
    }

    private (string Server, int HostId)? Read()
    {
        try
        {
            var attributes = File.GetAttributes(_file);
            if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
                throw new HostIdentityException("invalid_file");
        }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
        if (_enforceProtectedAcl) ProtectedPolicyAcl.VerifyPolicyFile(_file);

        using var stream = new FileStream(_file, FileMode.Open, FileAccess.Read, FileShare.Read);
        byte[] bytes = new byte[MaxBytes + 1];
        int count = 0, read;
        while (count < bytes.Length && (read = stream.Read(bytes, count, bytes.Length - count)) != 0) count += read;
        if (count > MaxBytes) throw new HostIdentityException("invalid_file");
        try
        {
            using var document = JsonDocument.Parse(bytes.AsMemory(0, count));
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new HostIdentityException("invalid_file");
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
                if (!names.Add(property.Name) || property.Name is not ("schemaVersion" or "serverBaseUrl" or "registeredHostId"))
                    throw new HostIdentityException("invalid_file");
            if (names.Count != 3 || !root.GetProperty("schemaVersion").TryGetInt32(out int version) || version != 1 ||
                !root.GetProperty("registeredHostId").TryGetInt32(out int id) || id <= 0 ||
                root.GetProperty("serverBaseUrl").ValueKind != JsonValueKind.String ||
                !Uri.TryCreate(root.GetProperty("serverBaseUrl").GetString(), UriKind.Absolute, out var server))
                throw new HostIdentityException("invalid_file");
            return (ServerKey(server), id);
        }
        catch (JsonException) { throw new HostIdentityException("invalid_file"); }
        catch (InvalidOperationException error) when (error is not HostIdentityException)
        { throw new HostIdentityException("invalid_file"); }
    }

    private static int Match((string Server, int HostId) identity, string server, int? configuredHostId)
    {
        if (identity.Server != server) throw new HostIdentityException("server_mismatch");
        if (configuredHostId is { } configured && configured != identity.HostId)
            throw new HostIdentityException("host_mismatch");
        return identity.HostId;
    }

    private static string ServerKey(Uri server)
    {
        if (!server.IsAbsoluteUri || (server.Scheme != "http" && server.Scheme != "https") ||
            server.UserInfo.Length != 0 || server.Query.Length != 0 || server.Fragment.Length != 0 ||
            !server.AbsolutePath.EndsWith("/agent/", StringComparison.Ordinal))
            throw new HostIdentityException("invalid_server");
        return server.GetComponents(UriComponents.SchemeAndServer, UriFormat.UriEscaped).ToLowerInvariant()
            + server.GetComponents(UriComponents.Path | UriComponents.KeepDelimiter, UriFormat.UriEscaped);
    }
}

/// <summary>Closed operator messages; no URL, identity contents or raw I/O exception.</summary>
public sealed class HostIdentityException(string code) : InvalidOperationException(code switch
{
    "missing" => "Identidade do host ausente. Informe RegisteredHostId de um cadastro existente para o primeiro provisionamento.",
    "server_mismatch" => "Identidade vinculada a outro servidor. Revise o provisionamento; o arquivo não foi substituído.",
    "host_mismatch" => "RegisteredHostId conflita com a identidade salva. Revise o provisionamento; o arquivo não foi substituído.",
    "unsafe_permissions" => "Identidade local sem as permissões protegidas exigidas. Revisão administrativa necessária.",
    "invalid_file" or "invalid_server" or "invalid_host" => "Identidade ou servidor inválido. Revise o provisionamento sem cadastrar novamente automaticamente.",
    _ => "Não foi possível acessar ou persistir a identidade do host. Revisão administrativa necessária."
})
{
    public string Code { get; } = code;
}
