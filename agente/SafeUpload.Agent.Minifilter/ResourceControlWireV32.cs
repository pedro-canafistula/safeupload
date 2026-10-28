#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Runtime.InteropServices;

namespace SafeUpload.Agent.Minifilter;

internal enum ResourceControlOpcodeV32 : uint { Negotiate = 1, Revoke, RegisterRoot, RegisterChildIntent, FenceAllocation, ResolveAllocationAck, ShellSnapshot }
internal enum MetadataRoleV32 : uint
{
    LedgerCurrent = 1, LedgerNew, CompanionCurrent, CompanionNew, ManifestCurrent, ManifestNew,
    Segment, InventoryCurrent, InventoryNew, MarkerCurrent, MarkerNew, LegacyNegative, LegacySecurity,
    EpochCurrent, EpochNew, HistoryCandidate, AppendIntentCurrent, AppendIntentNew,
    CompactionIntentCurrent, CompactionIntentNew
}

[StructLayout(LayoutKind.Sequential, Pack = 4)]
internal struct ResourceControlHeaderV32
{
    internal uint Version, StructSize, Command, Reserved, ResourceVersion;
    internal ResourceControlOpcodeV32 Opcode;
    internal ulong ControlRequestId, ConnectionCookie;
    internal Guid DriverInstance;
    internal uint PayloadBytes, Flags;
}
[StructLayout(LayoutKind.Sequential, Pack = 4)]
internal unsafe struct ResourceNegotiateV32
{
    internal Guid AgentInstance;
    internal ulong OfferedCapabilities, RequiredCapabilities, GrowthWaitTicks;
    internal uint AllocationLimit, SidLimit, GrowthWorkers, GrowthQueue, LifecycleWorkers, LifecycleQueue;
    internal Guid ReadinessEpoch;
    internal uint Phase;
    internal fixed byte Reserved[12];
}
[StructLayout(LayoutKind.Sequential, Pack = 4)]
internal unsafe struct ResourceNegotiateReplyV32
{
    internal uint Result, Mode;
    internal ulong AcceptedCapabilities;
    internal Guid AgentInstance, ReadinessEpoch, BootDomain;
    internal ulong GrowthWaitTicks;
    internal uint AllocationLimit, SidLimit, GrowthWorkers, GrowthQueue, LifecycleWorkers, LifecycleQueue;
    internal fixed byte Reserved[16];
}
[StructLayout(LayoutKind.Sequential, Pack = 4)]
internal unsafe struct ResourceRegisterRootV32
{
    internal uint Role, Flags;
    internal ulong Handle;
    internal SafeUploadStageIdentityV19 Identity;
    internal ulong ParentRootId;
    internal uint SecurityContractVersion;
    internal fixed byte Reserved[12];
}
[StructLayout(LayoutKind.Sequential, Pack = 4)]
internal struct ResourceRegisterRootReplyV32
{
    internal uint Result, Reserved;
    internal ulong RootId;
    internal SafeUploadStageIdentityV19 Identity;
}
[StructLayout(LayoutKind.Sequential, Pack = 4)]
internal unsafe struct ResourceRegisterChildV32
{
    internal ulong RootId;
    internal Guid TransactionId;
    internal MetadataRoleV32 Role;
    internal uint AccessMask;
    internal ulong MaximumLogicalBytes;
    internal SafeUploadStageIdentityV19 ExpectedIdentity, ReplaceTargetIdentity;
    internal uint LeafBytes, CreateDisposition;
    internal fixed char Leaf[256];
    internal fixed byte Reserved[32];
}
[StructLayout(LayoutKind.Sequential, Pack = 4)]
internal struct ResourceRegisterChildReplyV32 { internal uint Result, Reserved; internal ulong ChildIntentId; }
[StructLayout(LayoutKind.Sequential, Pack = 4)]
internal struct ResourceRevokeV32 { internal uint Reason, Reserved; }
[StructLayout(LayoutKind.Sequential, Pack = 4)]
internal struct ResourceRevokeReplyV32 { internal uint Result, Reserved; }
[StructLayout(LayoutKind.Sequential, Pack = 4)]
internal struct ResourcePairContextV32 { internal Guid DriverInstance; internal ulong ConnectionCookie; }

// Passive only: no production caller sends these controls in increment 3.
internal static class ResourceControlWireV32
{
    internal static void Verify()
    {
        Size<ResourceControlHeaderV32>(64); Size<ResourceNegotiateV32>(96); Size<ResourceNegotiateReplyV32>(112);
        Size<ResourceRegisterRootV32>(64); Size<ResourceRegisterRootReplyV32>(40);
        Size<ResourceRegisterChildV32>(640); Size<ResourceRegisterChildReplyV32>(16);
        Size<ResourceRevokeV32>(8); Size<ResourceRevokeReplyV32>(8); Size<ResourcePairContextV32>(24);
    }
    private static void Size<T>(int size) where T : struct
    {
        if (Marshal.SizeOf<T>() != size) throw new InvalidOperationException(typeof(T).Name + " layout mismatch.");
    }
    internal static bool LeafValid(string leaf) => !string.IsNullOrEmpty(leaf) && leaf.Length <= 255 &&
        leaf is not ("." or "..") && leaf.IndexOfAny(['\\', '/', ':', '\0']) < 0;

    internal static bool HeaderValid(in ResourceControlHeaderV32 value, int length, ResourceControlOpcodeV32 opcode, int payload) =>
        value.Version == 18 && value.StructSize == length && length == 64 + payload && value.Command == 36 &&
        value.Reserved == 0 && value.ResourceVersion == 32 && value.Opcode == opcode && value.ControlRequestId != 0 &&
        value.PayloadBytes == payload && value.Flags == 0;

    internal static bool TryReadRoot(ReadOnlySpan<byte> bytes, out ResourceRegisterRootV32 root)
    {
        root = default;
        if (bytes.Length != 64) return false;
        var value = MemoryMarshal.Read<ResourceRegisterRootV32>(bytes);
        if (value.Role is < 1 or > 4 || value.Flags != 0 || value.Handle == 0 || !value.Identity.HasNonzeroFileId ||
            value.SecurityContractVersion != 1 || bytes[52..].IndexOfAnyExcept((byte)0) >= 0 ||
            (value.Role is 1 or 3 ? value.ParentRootId != 0 : value.ParentRootId == 0)) return false;
        root = value; return true;
    }

    internal static unsafe bool TryReadChild(ReadOnlySpan<byte> bytes, out ResourceRegisterChildV32 child)
    {
        child = default;
        if (bytes.Length != 640) return false;
        var value = MemoryMarshal.Read<ResourceRegisterChildV32>(bytes);
        bool output = value.Role is MetadataRoleV32.LedgerNew or MetadataRoleV32.CompanionNew or MetadataRoleV32.ManifestNew or
            MetadataRoleV32.InventoryNew or MetadataRoleV32.MarkerNew or MetadataRoleV32.EpochNew or MetadataRoleV32.AppendIntentNew or
            MetadataRoleV32.CompactionIntentNew or MetadataRoleV32.Segment or MetadataRoleV32.HistoryCandidate;
        bool replace = output && value.Role is not (MetadataRoleV32.Segment or MetadataRoleV32.HistoryCandidate);
        uint allowed = 0x120081u | (output ? 2u : 0) |
            (value.Role is MetadataRoleV32.Segment or MetadataRoleV32.MarkerCurrent or MetadataRoleV32.LegacySecurity ? 0u : 0x10000u);
        bool identity = value.ExpectedIdentity.HasNonzeroFileId;
        bool predecessor = value.ReplaceTargetIdentity.HasNonzeroFileId;
        if (!Enum.IsDefined(value.Role) || value.RootId == 0 || value.TransactionId == Guid.Empty ||
            (value.AccessMask & 0x120081) != 0x120081 || (value.AccessMask & ~allowed) != 0 ||
            value.MaximumLogicalBytes == 0 || value.MaximumLogicalBytes > RoleMaximum(value.Role) ||
            value.LeafBytes is 0 or > 510 || (value.LeafBytes & 1) != 0 || value.CreateDisposition is not (1 or 2) ||
            (value.CreateDisposition == 1 ? !identity : identity || value.ExpectedIdentity.VolumeSerialNumber != 0 || !output) ||
            (!predecessor && value.ReplaceTargetIdentity.VolumeSerialNumber != 0) ||
            (predecessor && (!replace || value.CreateDisposition != 2)) ||
            bytes[(96 + (int)value.LeafBytes)..608].IndexOfAnyExcept((byte)0) >= 0 || bytes[608..].IndexOfAnyExcept((byte)0) >= 0) return false;
        string leaf = new(value.Leaf, 0, (int)value.LeafBytes / 2);
        if (!LeafValid(leaf)) return false;
        child = value; return true;
    }
    private static ulong RoleMaximum(MetadataRoleV32 role) => role switch
    {
        MetadataRoleV32.CompanionCurrent or MetadataRoleV32.CompanionNew => 192,
        MetadataRoleV32.InventoryCurrent or MetadataRoleV32.InventoryNew or MetadataRoleV32.MarkerCurrent or MetadataRoleV32.MarkerNew => 128,
        MetadataRoleV32.EpochCurrent or MetadataRoleV32.EpochNew => 4096,
        MetadataRoleV32.ManifestCurrent or MetadataRoleV32.ManifestNew or MetadataRoleV32.HistoryCandidate => 128 * 1024,
        MetadataRoleV32.Segment => 4 * 1024 * 1024,
        // Immutable legacy snapshot: 112-byte header, two descriptors and the
        // existing writer envelope. A control binds this to the service limit.
        MetadataRoleV32.LegacySecurity => 112 + 2 * (20 + 2 * 68 + 2 * 65536) + WriterMetadataV27.MaximumEnvelopeBytes,
        MetadataRoleV32.LegacyNegative => 1192,
        _ => 64 * 1024
    };
    internal static bool PairValid(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 24) return false;
        var pair = MemoryMarshal.Read<ResourcePairContextV32>(bytes);
        return pair.DriverInstance != Guid.Empty && pair.ConnectionCookie != 0;
    }
    internal static bool RevokeValid(ReadOnlySpan<byte> bytes) => bytes.Length == 8 &&
        MemoryMarshal.Read<ResourceRevokeV32>(bytes) is { Reason: >= 1 and <= 3, Reserved: 0 };

    internal static bool TryReadProbe(ReadOnlySpan<byte> reply, ulong requestId, Guid agent,
        out (ulong Cookie, Guid DriverInstance) provisional)
    {
        provisional = default;
        if (reply.Length != 176 || requestId == 0 || agent == Guid.Empty) return false;
        var header = MemoryMarshal.Read<ResourceControlHeaderV32>(reply);
        var body = MemoryMarshal.Read<ResourceNegotiateReplyV32>(reply[64..]);
        if (!HeaderValid(header, reply.Length, ResourceControlOpcodeV32.Negotiate, 112) ||
            header.ControlRequestId != requestId || header.ConnectionCookie == 0 || header.DriverInstance == Guid.Empty ||
            body.Result != 2 || body.Mode != 0 || body.AcceptedCapabilities != 0 || body.AgentInstance != agent ||
            body.ReadinessEpoch != Guid.Empty || body.GrowthWaitTicks != 0 ||
            reply[136..].IndexOfAnyExcept((byte)0) >= 0) return false;
        provisional = (header.ConnectionCookie, header.DriverInstance);
        return true;
    }

    // Even a syntactically Ready peer cannot activate this unfinished agent.
    internal static ResourceNegotiateReplyV32 Commit(Guid agent, Guid epoch) => new()
    { Result = 2, Mode = 0, AgentInstance = agent, ReadinessEpoch = epoch };
}
#endif
