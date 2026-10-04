using System.Buffers.Binary;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

internal sealed record BootPolicyScopes(IReadOnlyList<string> Prefixes, uint Flags);

internal interface IBootPolicyRegistryBackend
{
    BootPolicyScopes ReadKnownScopes();
    void WritePending(byte[] value);
    void WriteCommitted(byte[] value);
    void ClearPending();
}

/// <summary>
/// Persists destination scopes before asking the driver to replace its current
/// snapshot. PendingScopes carries the union of the previous durable scopes
/// and the candidate. If the process or machine stops mid-update, boot can
/// only retain an equally strict or stricter union. The second authenticated
/// SET_POLICY is sent only after the candidate value is flushed and pending
/// union removed; it lets the driver drop its in-memory boot union last.
/// </summary>
internal sealed class BootPolicyRegistryWriter
{
    internal const string RegistryPath = @"SYSTEM\CurrentControlSet\Services\SafeUpload\Parameters\BootPolicy";
    internal const string SecurityDescriptorSddl = "O:SYD:P(A;;KA;;;SY)(A;;KA;;;TI)";
    private readonly IBootPolicyRegistryBackend _backend;

    internal BootPolicyRegistryWriter(IBootPolicyRegistryBackend backend) =>
        _backend = backend ?? throw new ArgumentNullException(nameof(backend));

    internal void Apply(SafeUploadPolicyMessage candidate, Action applyAuthenticatedPolicy,
        Action finalizeAuthenticatedPolicy)
    {
        ArgumentNullException.ThrowIfNull(applyAuthenticatedPolicy);
        ArgumentNullException.ThrowIfNull(finalizeAuthenticatedPolicy);
        byte[] candidateBytes = BootPolicyCodec.Encode(candidate);
        BootPolicyScopes prior = _backend.ReadKnownScopes();
        BootPolicyScopes pending = BootPolicyCodec.Union(prior,
            BootPolicyCodec.DecodeKnown(candidateBytes));

        _backend.WritePending(BootPolicyCodec.Encode(pending));
        applyAuthenticatedPolicy();
        _backend.WriteCommitted(candidateBytes);
        _backend.ClearPending();
        finalizeAuthenticatedPolicy();
    }
}

internal static unsafe class BootPolicyCodec
{
    internal const uint Version = 1;
    internal const int HeaderBytes = 16;
    internal const int MaxPrefixes = 32;
    internal const int PrefixChars = Contract.MaxPrefixChars;
    internal const int PayloadBytes = HeaderBytes + MaxPrefixes * PrefixChars * sizeof(char);
    private const uint DestinationFlagMask = (uint)(PolicyFlags.Removable | PolicyFlags.Network);

    internal static byte[] Encode(SafeUploadPolicyMessage policy)
    {
        if (policy.PrefixCount > Contract.MaxPrefixes)
            throw new InvalidDataException("Driver policy prefix count exceeds the port contract.");

        var prefixes = new List<string>((int)policy.PrefixCount);
        unsafe
        {
            fixed (char* table = policy.Prefixes)
            {
                for (int index = 0; index < (int)policy.PrefixCount; index++)
                    prefixes.Add(ReadSlot(table + index * PrefixChars));
            }
        }
        return Encode(new BootPolicyScopes(prefixes, policy.Flags & DestinationFlagMask));
    }

    internal static byte[] Encode(BootPolicyScopes scopes)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        if (scopes.Prefixes.Count > MaxPrefixes)
            throw new InvalidDataException($"Durable policy supports at most {MaxPrefixes} union prefixes.");
        if ((scopes.Flags & ~DestinationFlagMask) != 0)
            throw new InvalidDataException("Durable policy contains unknown destination flags.");

        var payload = new byte[PayloadBytes];
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(0, 4), Version);
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(4, 4), PayloadBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(8, 4), checked((uint)scopes.Prefixes.Count));
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(12, 4), scopes.Flags);

        for (int index = 0; index < scopes.Prefixes.Count; index++)
        {
            string prefix = scopes.Prefixes[index];
            ValidatePrefix(prefix);
            int offset = HeaderBytes + index * PrefixChars * sizeof(char);
            for (int character = 0; character < prefix.Length; character++)
                BinaryPrimitives.WriteUInt16LittleEndian(payload.AsSpan(offset + character * 2, 2), prefix[character]);
            // New byte array is zeroed; it supplies the required terminator and zero tail.
        }
        return payload;
    }

    internal static BootPolicyScopes DecodeKnown(byte[]? payload, int maximumPrefixes = MaxPrefixes)
    {
        if (maximumPrefixes < 0 || maximumPrefixes > MaxPrefixes)
            throw new ArgumentOutOfRangeException(nameof(maximumPrefixes));
        if (payload is null || payload.Length < HeaderBytes) return new BootPolicyScopes([], 0);
        uint version = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(0, 4));
        uint structSize = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(4, 4));
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(8, 4));
        uint rawFlags = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(12, 4));
        bool envelopeKnown = version == Version && structSize == PayloadBytes;
        uint flags = envelopeKnown ? rawFlags & DestinationFlagMask : 0;
        int completeSlots = Math.Min(MaxPrefixes, Math.Max(0, (payload.Length - HeaderBytes) / (PrefixChars * 2)));
        var prefixes = new List<string>();

        if (payload.Length == PayloadBytes && envelopeKnown && count <= maximumPrefixes &&
            (rawFlags & ~DestinationFlagMask) == 0 &&
            TryDecodeStrict(payload, (int)count, out List<string> strict))
        {
            return new BootPolicyScopes(strict, rawFlags);
        }

        if (!envelopeKnown) return new BootPolicyScopes([], 0);

        // Corrupt records are never accepted as policy. Salvage only complete,
        // independently valid NT or UNC prefixes from the known v1 slot layout;
        // enforcement treats the key's reported state as invalid until live push.
        for (int index = 0; index < completeSlots; index++)
        {
            int offset = HeaderBytes + index * PrefixChars * 2;
            if (TryDecodeSlot(payload.AsSpan(offset, PrefixChars * 2), out string prefix))
                AddUnique(prefixes, prefix);
        }
        return new BootPolicyScopes(prefixes, flags);
    }

    internal static BootPolicyScopes Union(BootPolicyScopes left, BootPolicyScopes right)
    {
        var prefixes = new List<string>(left.Prefixes.Count + right.Prefixes.Count);
        foreach (string prefix in left.Prefixes) AddUnique(prefixes, prefix);
        foreach (string prefix in right.Prefixes) AddUnique(prefixes, prefix);
        if (prefixes.Count > MaxPrefixes)
            throw new InvalidDataException("The boot union would exceed 32 prefixes; policy was not applied.");
        return new BootPolicyScopes(prefixes, (left.Flags | right.Flags) & DestinationFlagMask);
    }

    private static bool TryDecodeStrict(byte[] payload, int count, out List<string> prefixes)
    {
        prefixes = new List<string>(count);
        for (int index = 0; index < MaxPrefixes; index++)
        {
            int offset = HeaderBytes + index * PrefixChars * 2;
            ReadOnlySpan<byte> slot = payload.AsSpan(offset, PrefixChars * 2);
            if (index < count)
            {
                if (!TryDecodeSlot(slot, out string prefix)) return false;
                prefixes.Add(prefix);
            }
            else
            {
                // UTF-16 zero fields must be zero in both bytes.
                for (int byteIndex = 0; byteIndex < slot.Length; byteIndex++)
                    if (slot[byteIndex] != 0) return false;
            }
        }
        return true;
    }

    private static bool TryDecodeSlot(ReadOnlySpan<byte> slot, out string prefix)
    {
        prefix = string.Empty;
        if (slot.Length != PrefixChars * 2) return false;
        int length = -1;
        for (int index = 0; index < PrefixChars; index++)
        {
            ushort value = BinaryPrimitives.ReadUInt16LittleEndian(slot.Slice(index * 2, 2));
            if (value == 0) { length = index; break; }
        }
        if (length <= 0) return false;
        for (int index = length; index < PrefixChars; index++)
            if (BinaryPrimitives.ReadUInt16LittleEndian(slot.Slice(index * 2, 2)) != 0) return false;
        var characters = new char[length];
        for (int index = 0; index < length; index++)
            characters[index] = (char)BinaryPrimitives.ReadUInt16LittleEndian(slot.Slice(index * 2, 2));
        prefix = new string(characters);
        try { ValidatePrefix(prefix); return true; }
        catch (InvalidDataException) { prefix = string.Empty; return false; }
    }

    private static string ReadSlot(char* slot)
    {
        int length = 0;
        while (length < PrefixChars && slot[length] != '\0') length++;
        if (length == 0 || length == PrefixChars)
            throw new InvalidDataException("Destination prefix is empty or unterminated.");
        for (int index = length + 1; index < PrefixChars; index++)
            if (slot[index] != '\0') throw new InvalidDataException("Destination prefix has data after its terminator.");
        string prefix = new(slot, 0, length);
        ValidatePrefix(prefix);
        return prefix;
    }

    private static void ValidatePrefix(string prefix)
    {
        if (string.IsNullOrEmpty(prefix) || prefix.Length >= PrefixChars ||
            !(prefix.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase) || prefix.StartsWith(@"\\", StringComparison.Ordinal)) ||
            prefix.IndexOfAny(['\0', '/', ':', '*', '?']) >= 0)
            throw new InvalidDataException("Destination prefix is not a bounded NT or UNC path.");

        bool uncPath = prefix.StartsWith(@"\\", StringComparison.Ordinal);
        int start = uncPath ? 2 : @"\Device\".Length;
        if (start >= prefix.Length) throw new InvalidDataException("Destination prefix has no volume or server component.");
        string[] components = prefix[start..].Split('\\');
        int componentCount = 0;
        for (int index = 0; index < components.Length; index++)
        {
            string component = components[index];
            if (component.Length == 0)
            {
                if (index == components.Length - 1 && prefix.EndsWith('\\')) continue;
                throw new InvalidDataException("Destination prefix contains an empty path component.");
            }
            if (component is "." or "..") throw new InvalidDataException("Destination prefix contains a traversal component.");
            componentCount++;
        }
        if (uncPath && componentCount < 2)
            throw new InvalidDataException("UNC destination prefix must name both server and share.");
    }

    private static void AddUnique(List<string> prefixes, string value)
    {
        if (!prefixes.Contains(value, StringComparer.OrdinalIgnoreCase)) prefixes.Add(value);
    }
}

internal sealed class WindowsBootPolicyRegistryBackend : IBootPolicyRegistryBackend
{
    private const string ServiceKeyPath = @"SYSTEM\CurrentControlSet\Services\SafeUpload";
    private const string ParametersKey = "Parameters";
    private const string BootPolicyKey = "BootPolicy";
    private const string ScopesValue = "Scopes";
    private const string PendingValue = "PendingScopes";
    private const string TrustedInstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier InstallerSid = new(TrustedInstallerSid);

    public BootPolicyScopes ReadKnownScopes()
    {
        using RegistryKey parameters = OpenProtectedKeys(create: true, out RegistryKey policy);
        using (policy)
        {
            byte[]? committed = ReadBinary(policy, ScopesValue);
            byte[]? pending = ReadBinary(policy, PendingValue);
            return BootPolicyCodec.Union(BootPolicyCodec.DecodeKnown(committed, Contract.MaxPrefixes),
                BootPolicyCodec.DecodeKnown(pending, BootPolicyCodec.MaxPrefixes));
        }
    }

    public void WritePending(byte[] value) => WriteValue(PendingValue, value);
    public void WriteCommitted(byte[] value) => WriteValue(ScopesValue, value);

    public void ClearPending()
    {
        using RegistryKey parameters = OpenProtectedKeys(create: true, out RegistryKey policy);
        using (policy)
        {
            policy.DeleteValue(PendingValue, throwOnMissingValue: false);
            policy.Flush();
            if (ReadBinary(policy, PendingValue) is not null)
                throw new IOException("Pending boot policy remained after deletion.");
            VerifySecurity(parameters);
            VerifySecurity(policy);
        }
    }

    private static void WriteValue(string name, byte[] value)
    {
        using RegistryKey parameters = OpenProtectedKeys(create: true, out RegistryKey policy);
        using (policy)
        {
            policy.SetValue(name, value, RegistryValueKind.Binary);
            policy.Flush(); // RegFlushKey: the value must be durable before policy is reported active.
            VerifySecurity(parameters);
            VerifySecurity(policy);
            byte[]? readback = ReadBinary(policy, name);
            if (readback is null || !readback.AsSpan().SequenceEqual(value))
                throw new IOException($"Durable registry value {name} failed exact read-back.");
        }
    }

    private static byte[]? ReadBinary(RegistryKey key, string name)
    {
        object? value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (value is null) return null;
        // A wrong-type legacy/corrupt value carries no independently
        // identifiable scope. Let the pending-union write repair it; DriverEntry
        // reports the corrupt state and enforces any scopes from a known v1
        // record it can safely decode.
        if (key.GetValueKind(name) != RegistryValueKind.Binary || value is not byte[] bytes)
            return null;
        return bytes;
    }

    private static RegistryKey OpenProtectedKeys(bool create, out RegistryKey policy)
    {
        using RegistryKey service = Registry.LocalMachine.OpenSubKey(ServiceKeyPath, writable: true)
            ?? throw new IOException("SafeUpload service registry key is missing or not writable.");
        RegistrySecurity security = CreateExactSecurity();
        RegistryKey parameters = create
            ? service.CreateSubKey(ParametersKey, RegistryKeyPermissionCheck.ReadWriteSubTree,
                RegistryOptions.None, security) ?? throw new IOException("Could not create Parameters key.")
            : service.OpenSubKey(ParametersKey, writable: true) ?? throw new IOException("Parameters key is missing.");
        RegistryKey? openedPolicy = null;
        try
        {
            parameters.SetAccessControl(security);
            parameters.Flush();
            VerifySecurity(parameters);
            RegistryKey createdPolicy = create
                ? parameters.CreateSubKey(BootPolicyKey, RegistryKeyPermissionCheck.ReadWriteSubTree,
                    RegistryOptions.None, security) ?? throw new IOException("Could not create BootPolicy key.")
                : parameters.OpenSubKey(BootPolicyKey, writable: true) ?? throw new IOException("BootPolicy key is missing.");
            openedPolicy = createdPolicy;
            createdPolicy.SetAccessControl(security);
            createdPolicy.Flush();
            VerifySecurity(createdPolicy);
            policy = createdPolicy;
            return parameters;
        }
        catch
        {
            openedPolicy?.Dispose();
            parameters.Dispose();
            throw;
        }
    }

    private static RegistrySecurity CreateExactSecurity()
    {
        var security = new RegistrySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(SystemSid);
        security.SetAccessRule(new RegistryAccessRule(SystemSid, RegistryRights.FullControl,
            AccessControlType.Allow));
        security.SetAccessRule(new RegistryAccessRule(InstallerSid, RegistryRights.FullControl,
            AccessControlType.Allow));
        return security;
    }

    private static void VerifySecurity(RegistryKey key)
    {
        RegistrySecurity security = key.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        SecurityIdentifier? owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || !SystemSid.Equals(owner) || !security.AreAccessRulesProtected)
            throw new UnauthorizedAccessException("Boot policy key owner or protected DACL is not exact.");
        AuthorizationRuleCollection rules = security.GetAccessRules(includeExplicit: true,
            includeInherited: true, targetType: typeof(SecurityIdentifier));
        if (rules.Count != 2) throw new UnauthorizedAccessException("Boot policy DACL has unexpected ACEs.");
        bool system = false, installer = false;
        foreach (RegistryAccessRule rule in rules)
        {
            if (rule.AccessControlType != AccessControlType.Allow || rule.IsInherited ||
                rule.InheritanceFlags != InheritanceFlags.None || rule.PropagationFlags != PropagationFlags.None ||
                rule.RegistryRights != RegistryRights.FullControl)
                throw new UnauthorizedAccessException("Boot policy DACL contains a non-exact ACE.");
            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (SystemSid.Equals(sid) && !system) system = true;
            else if (InstallerSid.Equals(sid) && !installer) installer = true;
            else throw new UnauthorizedAccessException("Boot policy DACL contains an unexpected trustee.");
        }
        if (!system || !installer) throw new UnauthorizedAccessException("Boot policy DACL is missing a required trustee.");
    }
}
