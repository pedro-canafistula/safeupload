using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>
/// Identidade da máquina no servidor: URL, id_host, chave Ed25519 e certificado fixado (docs/console-agente.md).
/// DPAPI de máquina + ACL só SYSTEM/Administradores. O token de cadastro nunca é gravado.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SignedHostIdentityStore
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("SafeUpload/AgentApi/Ed25519/v2");
    private static readonly JsonSerializerOptions Json = new() { AllowDuplicateProperties = false, MaxDepth = 8 };
    private readonly string _file;
    private readonly bool _enforceAcl;

    public SignedHostIdentityStore(string file) : this(file, true) { }
    // Testes isolados usam DPAPI real, sem a ACL de produção.
    internal SignedHostIdentityStore(string file, bool enforceAcl)
    {
        _file = Path.GetFullPath(file);
        _enforceAcl = enforceAcl;
    }

    public bool Exists => File.Exists(_file);

    /// <summary>A identidade cadastrada, ou null sem cadastro. Arquivo inválido ou cadastro pela metade lança.</summary>
    public SignedAgentIdentity? Load() => Safe(() =>
    {
        if (!File.Exists(_file)) return null;
        using var gate = Lock();
        using var document = Read();
        if (document.HostId == 0) throw new AgentIdentityException("registration_pending");
        return Identity(document);
    });

    /// <summary>
    /// Cria a chave e cadastra com o token (uma tentativa). Só grava após receber um ID válido.
    /// Uma identidade já cadastrada só pode ser substituída com <paramref name="replace"/>.
    /// </summary>
    public async Task<SignedAgentIdentity> EnrollAsync(AgentApiClient client, string? certificateSha256,
        string enrollmentToken, AgentHeartbeatHost host, bool replace, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(client);
        if (string.IsNullOrWhiteSpace(enrollmentToken)) throw new ArgumentException("Token de cadastro obrigatório.");
        host.EnsureValid();
        using var gate = Safe(Lock);
        if (File.Exists(_file) && !replace)
        {
            bool enrolled;
            try { using var previous = Safe(Read); enrolled = previous.HostId != 0; }
            catch (AgentIdentityException) { enrolled = false; }
            if (enrolled) throw new AgentIdentityException("already_registered");
        }
        using var document = new StoredIdentity
        {
            Format = 2, Server = client.BaseUri.AbsoluteUri, Seed = Ed25519AgentKey.GenerateSeed(),
            CertificateSha256 = certificateSha256 is null ? null : AgentHttp.NormalizePin(certificateSha256)
        };
        document.PublicKey = Ed25519AgentKey.PublicKey(document.Seed);
        document.HostId = await client.EnrollAsync(enrollmentToken, document.PublicKey, host, token).ConfigureAwait(false);
        Safe(() => { Save(document); return true; });
        return Identity(document);
    }

    internal string Sign(int hostId, string publicKey, byte[] message) => Safe(() =>
    {
        using var gate = Lock();
        using var document = Read();
        if (document.HostId != hostId || document.PublicKey != publicKey)
            throw new AgentIdentityException("identity_changed");
        return Ed25519AgentKey.Sign(document.Seed, message);
    });

    private SignedAgentIdentity Identity(StoredIdentity document) =>
        new(this, new Uri(document.Server), document.HostId, document.PublicKey, document.CertificateSha256);

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

    private StoredIdentity Read()
    {
        if (!File.Exists(_file)) throw new AgentIdentityException("missing");
        if ((File.GetAttributes(_file) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
            throw new AgentIdentityException("invalid_file");
        if (_enforceAcl) ProtectedPolicyAcl.VerifyPolicyFile(_file);
        byte[] encrypted = File.ReadAllBytes(_file);
        if (encrypted.Length is < 1 or > 65536) throw new AgentIdentityException("invalid_file");
        byte[] plaintext = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.LocalMachine);
        StoredIdentity? document = null;
        try
        {
            document = JsonSerializer.Deserialize<StoredIdentity>(plaintext, Json);
            if (document is null || document.Format != 2 || document.HostId < 0 || document.Seed?.Length != 32 ||
                document.PublicKey != Ed25519AgentKey.PublicKey(document.Seed))
                throw new AgentIdentityException("invalid_file");
            AgentHttp.ServerUri(document.Server);
            return document;
        }
        catch (ArgumentException) { document?.Dispose(); throw new AgentIdentityException("invalid_file"); }
        catch { document?.Dispose(); throw; }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    private void Save(StoredIdentity document)
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
            File.Move(temporary, _file, overwrite: true);
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
        public string? CertificateSha256 { get; set; }
        public void Dispose() => CryptographicOperations.ZeroMemory(Seed);
    }
}

/// <summary>Identidade cadastrada. A chave privada fica no arquivo; cada assinatura a lê de novo.</summary>
public sealed class SignedAgentIdentity
{
    private readonly SignedHostIdentityStore? _store;
    private readonly Func<byte[], string>? _signer;
    public Uri Server { get; }
    public int HostId { get; }
    public string PublicKey { get; }
    public string? CertificateSha256 { get; }

    internal SignedAgentIdentity(SignedHostIdentityStore store, Uri server, int hostId, string publicKey, string? pin)
        : this(server, hostId, publicKey, pin) => _store = store;

    /// <summary>Identidade em memória (testes).</summary>
    internal SignedAgentIdentity(Uri server, int hostId, byte[] seed, string? pin = null)
        : this(server, hostId, Ed25519AgentKey.PublicKey(seed), pin)
    {
        byte[] copy = seed.ToArray();
        _signer = message => Ed25519AgentKey.Sign(copy, message);
    }

    private SignedAgentIdentity(Uri server, int hostId, string publicKey, string? pin) =>
        (Server, HostId, PublicKey, CertificateSha256) = (server, hostId, publicKey, pin);

    internal string Sign(byte[] message)
    {
        if (_signer is not null) return _signer(message);
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        return _store!.Sign(HostId, PublicKey, message);
    }
}

/// <summary>Mensagens fechadas; nunca guarda chave, token, resposta ou exceção de E/S.</summary>
public sealed class AgentIdentityException(string code) : InvalidOperationException(
    "Identidade do agente indisponível (" + code + "). Cadastre de novo com \"SafeUpload.Agent.Service.exe cadastrar\".")
{
    public string Code { get; } = code;
}
