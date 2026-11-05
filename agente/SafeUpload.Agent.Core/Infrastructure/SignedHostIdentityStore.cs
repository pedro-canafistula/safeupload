using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>Machine DPAPI plus protected SYSTEM/Administrators ACL. Never stores the enrollment token.</summary>
[SupportedOSPlatform("windows")]
public sealed class SignedHostIdentityStore
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("SafeUpload/AgentApi/Ed25519/v1");
    private static readonly JsonSerializerOptions Json = new() { AllowDuplicateProperties = false, MaxDepth = 8 };
    private readonly string _file;
    private readonly bool _enforceAcl;

    public SignedHostIdentityStore(string file) : this(file, true) { }
    // Isolated tests still use real Windows DPAPI; they do not claim SYSTEM ACL qualification.
    internal SignedHostIdentityStore(string file, bool enforceAcl)
    {
        _file = Path.GetFullPath(file);
        _enforceAcl = enforceAcl;
    }

    public SignedAgentIdentity Load(Uri server, int? expectedHostId = null) => Safe(() =>
    {
        using var gate = Lock();
        using var document = Read(server);
        if (document.HostId == 0) throw new AgentIdentityException("registration_pending");
        if (expectedHostId is { } expected && expected != document.HostId)
            throw new AgentIdentityException("host_mismatch");
        return Identity(server, document);
    });

    /// <summary>One explicit attempt. Persist a pending key before HTTP; no restart/timeout retry.</summary>
    public async Task<SignedAgentIdentity> RegisterAsync(AgentApiClient client, string enrollmentToken,
        AgentHeartbeatHost host, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(client);
        client.EnsureSignedTransport();
        ArgumentNullException.ThrowIfNull(host);
        host.EnsureValid();
        if (string.IsNullOrWhiteSpace(enrollmentToken)) throw new ArgumentException("Token de cadastro obrigatório.");
        token.ThrowIfCancellationRequested();
        using var gate = Safe(Lock);
        if (File.Exists(_file))
        {
            using var previous = Safe(() => Read(client.BaseUri));
            throw new AgentIdentityException(previous.HostId == 0 ? "registration_pending" : "already_registered");
        }
        using var document = new StoredIdentity
        {
            Format = 1, Server = ServerKey(client.BaseUri), Seed = Ed25519AgentKey.GenerateSeed()
        };
        document.PublicKey = Ed25519AgentKey.PublicKey(document.Seed);
        Safe(() => { Save(document, overwrite: false); return true; });
        // From this point any exception (including a lost response) leaves the SAME pending key on disk.
        int hostId = await client.RegisterEd25519Async(enrollmentToken, document.PublicKey, host, token).ConfigureAwait(false);
        document.HostId = hostId;
        Safe(() => { Save(document, overwrite: true); return true; });
        return Identity(client.BaseUri, document);
    }

    /// <summary>Explicit recovery only: the backend must prove the pending key authenticates this ID.</summary>
    public async Task<SignedAgentIdentity> RecoverAsync(AgentApiClient client, int hostId,
        AgentHeartbeatHost host, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(host);
        client.EnsureSignedTransport();
        host.EnsureValid();
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(hostId);
        token.ThrowIfCancellationRequested();
        using var gate = Safe(Lock);
        using var document = Safe(() => Read(client.BaseUri));
        if (document.HostId != 0) throw new AgentIdentityException("already_registered");
        await client.HeartbeatAuthenticatedAsync(hostId, Ed25519AgentKey.SignHost(document.Seed, hostId), host, token)
            .ConfigureAwait(false);
        document.HostId = hostId;
        Safe(() => { Save(document, overwrite: true); return true; });
        return Identity(client.BaseUri, document);
    }

    internal string Sign(Uri server, int hostId, string publicKey) => Safe(() =>
    {
        using var gate = Lock();
        using var document = Read(server);
        if (document.HostId != hostId || document.PublicKey != publicKey)
            throw new AgentIdentityException("identity_changed");
        return Ed25519AgentKey.SignHost(document.Seed, hostId);
    });

    private SignedAgentIdentity Identity(Uri server, StoredIdentity document) =>
        new(this, server, document.HostId, document.PublicKey);

    private FileStream Lock()
    {
        if (!OperatingSystem.IsWindows()) throw new AgentIdentityException("windows_required");
        if (_enforceAcl) EnsureDirectory();
        else Directory.CreateDirectory(Path.GetDirectoryName(_file)!);
        string lockFile = _file + ".lock";
        if (_enforceAcl && File.Exists(lockFile)) ProtectedPolicyAcl.VerifyPolicyFile(lockFile);
        return _enforceAcl
            ? new FileInfo(lockFile).Create(FileMode.OpenOrCreate, FileSystemRights.FullControl, FileShare.None,
                4096, FileOptions.None, FileSecurity())
            : new FileStream(lockFile, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }

    private StoredIdentity Read(Uri server)
    {
        string key = ServerKey(server);
        if (!File.Exists(_file)) throw new AgentIdentityException("missing");
        if ((File.GetAttributes(_file) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
            throw new AgentIdentityException("invalid_file");
        if (_enforceAcl) ProtectedPolicyAcl.VerifyPolicyFile(_file);
        using var stream = new FileStream(_file, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is < 1 or > 65536) throw new AgentIdentityException("invalid_file");
        byte[] encrypted = new byte[(int)stream.Length];
        stream.ReadExactly(encrypted);
        byte[] plaintext = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.LocalMachine);
        StoredIdentity? document = null;
        try
        {
            document = JsonSerializer.Deserialize<StoredIdentity>(plaintext, Json);
            if (document is null || document.Format != 1 || document.HostId < 0 || document.Seed?.Length != 32 ||
                document.PublicKey != Ed25519AgentKey.PublicKey(document.Seed))
                throw new AgentIdentityException("invalid_file");
            if (document.Server != key) throw new AgentIdentityException("server_mismatch");
            return document;
        }
        catch { document?.Dispose(); throw; }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    private void Save(StoredIdentity document, bool overwrite)
    {
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(document, Json);
        byte[] encrypted;
        try { encrypted = ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.LocalMachine); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
        string temporary = _file + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = _enforceAcl
                ? new FileInfo(temporary).Create(FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None,
                    4096, FileOptions.WriteThrough, FileSecurity())
                : new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(encrypted);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, _file, overwrite);
        }
        finally
        {
            try { File.Delete(temporary); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private void EnsureDirectory()
    {
        string directory = Path.GetDirectoryName(_file)!;
        for (string? ancestor = directory; ancestor is not null; ancestor = Path.GetDirectoryName(ancestor))
            if (Directory.Exists(ancestor) && (File.GetAttributes(ancestor) & FileAttributes.ReparsePoint) != 0)
                throw new AgentIdentityException("unsafe_permissions");
        // An elevated administrator may provision for LocalSystem without setting an arbitrary owner.
        // EnsureDirectory below still rejects reparse ancestors and every non-exact existing ACL.
        if (!Directory.Exists(directory))
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (!identity.IsSystem && !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new AgentIdentityException("access_denied");
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            acl.SetOwner(new SecurityIdentifier(identity.IsSystem ? WellKnownSidType.LocalSystemSid :
                WellKnownSidType.BuiltinAdministratorsSid, null));
            foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
                acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(directory).Create(acl);
        }
        ProtectedPolicyAcl.EnsureDirectory(_file);
    }

    private static FileSecurity FileSecurity()
    {
        var security = ProtectedPolicyAcl.CreatePolicyFileSecurity();
        using var identity = WindowsIdentity.GetCurrent();
        if (!identity.IsSystem) security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        return security;
    }

    private static string ServerKey(Uri server)
    {
        if (!server.IsAbsoluteUri || server.Scheme is not ("http" or "https") ||
            !server.AbsolutePath.EndsWith("/agent/", StringComparison.Ordinal) ||
            server.UserInfo.Length != 0 || server.Query.Length != 0 || server.Fragment.Length != 0)
            throw new AgentIdentityException("invalid_server");
        return server.AbsoluteUri;
    }

    private static T Safe<T>(Func<T> action)
    {
        try { return action(); }
        catch (AgentIdentityException) { throw; }
        catch (PolicyFileAclRejectedException) { throw new AgentIdentityException("unsafe_permissions"); }
        catch (UnauthorizedAccessException) { throw new AgentIdentityException("access_denied"); }
        catch (IOException) { throw new AgentIdentityException("storage_unavailable"); }
        catch (CryptographicException) { throw new AgentIdentityException("key_unavailable"); }
        catch (JsonException) { throw new AgentIdentityException("invalid_file"); }
    }

    private sealed class StoredIdentity : IDisposable
    {
        public int Format { get; set; }
        public string Server { get; set; } = "";
        public int HostId { get; set; }
        public string PublicKey { get; set; } = "";
        public byte[] Seed { get; set; } = [];
        public void Dispose() => CryptographicOperations.ZeroMemory(Seed);
    }
}

public sealed class SignedAgentIdentity
{
    private readonly SignedHostIdentityStore _store;
    private readonly Uri _server;
    public int HostId { get; }
    public string PublicKey { get; }
    internal SignedAgentIdentity(SignedHostIdentityStore store, Uri server, int hostId, string publicKey) =>
        (_store, _server, HostId, PublicKey) = (store, server, hostId, publicKey);
    internal string SignHost()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        return _store.Sign(_server, HostId, PublicKey);
    }
}

/// <summary>Closed messages; never retains plaintext key, token, response or raw I/O exception.</summary>
public sealed class AgentIdentityException(string code) : InvalidOperationException(
    "Identidade Ed25519 indisponível (" + code + "). Revise o provisionamento; nenhum cadastro automático será realizado.")
{
    public string Code { get; } = code;
}
