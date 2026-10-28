#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Runtime.InteropServices;

namespace SafeUpload.Agent.Minifilter;

// Passive byte contract only. No transport registration or runtime authority.
// Live consumers still need negotiation, exact ledger/companion custody and
// current-connection/deadline checks immediately before adopting a grant.
public static unsafe class ResourceWireV32
{
    public const uint Version = 32, GrowOperation = 23, RetirementOperation = 24, Control = 36;
    public const int BindingBytes = 112, IntentBytes = 104, RequestBytes = 160,
        ResultBytes = 352, ReplyBytes = 376;
    public const ulong AllocationWaitTicks = 1_200_000_000, MinimumCapacity = 16 * 1024 * 1024;

    public static void Verify()
    {
        if (sizeof(ResourceBindingV32) != BindingBytes || sizeof(ResourceAllocationV32) != IntentBytes ||
            sizeof(ResourceGrowthV32) != RequestBytes || sizeof(ResourceRetirementV32) != RequestBytes ||
            sizeof(ResourceResultV32) != ResultBytes || sizeof(ResourceReplyV32) != ReplyBytes)
            throw new InvalidOperationException("Resource v32 ABI size mismatch.");
        Offset<ResourceBindingV32>(nameof(ResourceBindingV32.StageIdentity), 72);
        Offset<ResourceBindingV32>(nameof(ResourceBindingV32.Sequence), 104);
        Offset<ResourceAllocationV32>(nameof(ResourceAllocationV32.ConnectionCookie), 72);
        Offset<ResourceGrowthV32>(nameof(ResourceGrowthV32.Deadline), 136);
        Offset<ResourceRetirementV32>(nameof(ResourceRetirementV32.AuthorizedCapacity), 128);
        Offset<ResourceResultV32>(nameof(ResourceResultV32.StageName), 192);
        Offset<ResourceResultV32>(nameof(ResourceResultV32.Tail), 320);
        Offset<ResourceReplyV32>(nameof(ResourceReplyV32.Body), 24);
    }

    private static void Offset<T>(string name, int expected) where T : struct
    {
        if (Marshal.OffsetOf<T>(name).ToInt32() != expected)
            throw new InvalidOperationException("Resource v32 ABI offset mismatch: " + name);
    }

    public static bool DeadlineValid(ulong issued, ulong deadline, ulong now, ulong maximumDuration) =>
        maximumDuration is > 0 and <= AllocationWaitTicks && deadline > issued &&
        deadline - issued <= maximumDuration && issued <= now && now < deadline;

    public static bool CapacityValid(ulong capacity, ulong alignment) =>
        alignment >= 65536 && alignment <= long.MaxValue && (alignment & (alignment - 1)) == 0 &&
        capacity is >= MinimumCapacity and <= long.MaxValue && capacity % alignment == 0;

    public static bool TryReadGrowth(ReadOnlySpan<byte> bytes, ulong alignment, out ResourceGrowthV32 request)
    {
        request = default;
        if (bytes.Length != RequestBytes) return false;
        var value = MemoryMarshal.Read<ResourceGrowthV32>(bytes);
        if (!GrowthValid(value, alignment)) return false;
        request = value;
        return true;
    }

    public static bool TryReadRetirement(ReadOnlySpan<byte> bytes, ulong alignment, out ResourceRetirementV32 request)
    {
        request = default;
        if (bytes.Length != RequestBytes) return false;
        var value = MemoryMarshal.Read<ResourceRetirementV32>(bytes);
        if (!RetirementValid(value, alignment)) return false;
        request = value;
        return true;
    }

    public static bool TryReadAllocation(ReadOnlySpan<byte> bytes, out ResourceAllocationV32 request)
    {
        request = default;
        if (bytes.Length != IntentBytes) return false;
        var value = MemoryMarshal.Read<ResourceAllocationV32>(bytes);
        if (!AllocationValid(value)) return false;
        request = value;
        return true;
    }

    private static bool AllocationValid(ResourceAllocationV32 value)
    {
        var intent = value.Intent.Intent;
        bool parent = intent.ParentTransferId != Guid.Empty;
        return intent.Version == Version && intent.StructSize == IntentBytes &&
            intent.AllocationReservationId != Guid.Empty && intent.DriverInstanceId != Guid.Empty &&
            intent.Disposition <= 5 && intent.ReferenceKind <= 2 &&
            (intent.ReferenceKind == 0 ? !parent : parent) &&
            (intent.ReferenceKind != 2 || intent.Disposition == 2) && value.Intent.RequestorCreationTime > 0 &&
            value.ConnectionCookie != 0 && value.Mode == 1 && value.Reserved == 0 &&
            DeadlineShape(value.Issued, value.Deadline) && value.Deadline - value.Issued == AllocationWaitTicks;
    }

    // This is syntax/correlation, not evidence of a persisted grant. Callers
    // must compare the positive capacity/revision to the exact held companion
    // and ledger before adoption. Failure enum values grant no cleanup authority.
    public static bool TryReadReply(ReadOnlySpan<byte> bytes, ulong requestId, out ResourceResultV32 result)
    {
        result = default;
        if (bytes.Length != ReplyBytes || requestId == 0) return false;
        var frame = MemoryMarshal.Read<ResourceReplyV32>(bytes);
        var value = frame.Body;
        if (frame.Version != Contract.Version || frame.StructSize != ReplyBytes || frame.RequestId != requestId ||
            frame.Verdict != Verdict.Deny || frame.StageNameLength != 0 ||
            value.Version != Version || value.StructSize != ResultBytes || value.RequestId != requestId ||
            value.Kind > ResourceKindV32.Retirement || value.Result is < ResourceResultCodeV32.Allocated or > ResourceResultCodeV32.Unresolved ||
            value.ConnectionCookie == 0 || value.DriverInstanceId == Guid.Empty || value.TransferId == Guid.Empty ||
            value.Flags != 0 || value.Reserved != 0 || value.NameReserved != 0 ||
            !Zero(new ReadOnlySpan<byte>(value.Tail, 32))) return false;
        bool success = value.Result is ResourceResultCodeV32.Allocated or ResourceResultCodeV32.CapacityCommitted or ResourceResultCodeV32.RetirementAccepted;
        if (success ? value.LedgerRevision is 0 or > long.MaxValue : value.Capacity != 0 || value.LedgerRevision != 0) return false;
        if (!success && value.Result == ResourceResultCodeV32.NoAllocationCommitted && value.Kind != ResourceKindV32.Allocation) return false;
        if (success && (uint)value.Result != (uint)value.Kind + 1) return false;
        if (success && value.Kind != ResourceKindV32.Retirement && !CapacityValid(value.Capacity, 65536)) return false;
        if (value.Kind == ResourceKindV32.Allocation)
        {
            if (value.Sequence != 0 || value.ObservedCapacity != 0 || value.RequiredExtent != 0 ||
                value.RetirementEndOfFile != 0 || value.RetirementAllocationSize != 0 ||
                !DeadlineShape(value.Issued, value.Deadline) || value.Deadline - value.Issued != AllocationWaitTicks) return false;
            if (success)
            {
                if (!VersionIdentityValid(value) || !StageNameValid(value)) return false;
            }
            else if (value.AllocationGeneration != 0 || value.DestinationGeneration != 0 ||
                !IdentityZero(value.StageIdentity) || !NameZero(value)) return false;
        }
        else
        {
            if (!VersionIdentityValid(value) || value.Sequence == 0 || !NameZero(value)) return false;
            if (value.Kind == ResourceKindV32.Growth)
            {
                if (value.RetirementEndOfFile != 0 || value.RetirementAllocationSize != 0 ||
                    !CapacityValid(value.ObservedCapacity, 65536) || !CapacityValid(value.RequiredExtent, 65536) ||
                    value.RequiredExtent <= value.ObservedCapacity ||
                    success && value.Capacity < value.RequiredExtent ||
                    !DeadlineShape(value.Issued, value.Deadline)) return false;
            }
            else if (value.Capacity != 0 || value.RequiredExtent != 0 || value.Issued != 0 || value.Deadline != 0 ||
                value.Result == ResourceResultCodeV32.DeadlineExpired || !CapacityValid(value.ObservedCapacity, 65536) ||
                value.RetirementEndOfFile > value.ObservedCapacity || value.RetirementAllocationSize > value.ObservedCapacity) return false;
        }
        result = value;
        return true;
    }

    private static bool MatchesGrowth(in ResourceResultV32 result, in ResourceGrowthV32 request,
        ulong alignment, ulong committedCapacity, ulong committedRevision, ulong now) =>
        MatchesBinding(result, request.Binding) && result.ObservedCapacity == request.ObservedCapacity &&
        result.RequiredExtent == request.RequiredExtent && result.Issued == request.Issued && result.Deadline == request.Deadline &&
        (result.Result != ResourceResultCodeV32.CapacityCommitted ||
            CapacityValid(result.Capacity, alignment) && result.Capacity >= request.RequiredExtent &&
            result.Capacity == committedCapacity && result.LedgerRevision == committedRevision &&
            DeadlineValid(request.Issued, request.Deadline, now, AllocationWaitTicks));

    private static bool MatchesRetirement(in ResourceResultV32 result, in ResourceRetirementV32 request) =>
        MatchesBinding(result, request.Binding) && result.ObservedCapacity == request.AuthorizedCapacity &&
        result.RetirementEndOfFile == request.EndOfFile && result.RetirementAllocationSize == request.AllocationSize;

    public static bool TryReadGrowthReply(ReadOnlySpan<byte> bytes, in ResourceGrowthV32 request,
        ulong alignment, ulong committedCapacity, ulong committedRevision, ulong now, out ResourceResultV32 result)
    {
        result = default;
        if (!GrowthValid(request, alignment) || !TryReadReply(bytes, request.Binding.RequestId, out var value) ||
            !MatchesGrowth(value, request, alignment, committedCapacity, committedRevision, now)) return false;
        result = value;
        return true;
    }

    public static bool TryReadRetirementReply(ReadOnlySpan<byte> bytes, in ResourceRetirementV32 request, ulong alignment,
        out ResourceResultV32 result)
    {
        result = default;
        if (!RetirementValid(request, alignment) || !TryReadReply(bytes, request.Binding.RequestId, out var value) || !MatchesRetirement(value, request)) return false;
        result = value;
        return true;
    }

    public static bool TryReadAllocationReply(ReadOnlySpan<byte> bytes, in ResourceAllocationV32 request,
        ulong requestId, ulong alignment, ulong requiredInitialCapacity, ulong committedCapacity, ulong committedRevision,
        ulong now, out ResourceResultV32 result)
    {
        result = default;
        if (!AllocationValid(request) || !TryReadReply(bytes, requestId, out var value) || value.Kind != ResourceKindV32.Allocation ||
            value.ConnectionCookie != request.ConnectionCookie || value.DriverInstanceId != request.Intent.Intent.DriverInstanceId ||
            value.TransferId != request.Intent.Intent.AllocationReservationId || value.Issued != request.Issued || value.Deadline != request.Deadline) return false;
        if (value.Result == ResourceResultCodeV32.Allocated &&
            (!CapacityValid(requiredInitialCapacity, alignment) || !CapacityValid(value.Capacity, alignment) ||
             value.Capacity < requiredInitialCapacity || value.Capacity != committedCapacity || value.LedgerRevision != committedRevision ||
             !DeadlineValid(request.Issued, request.Deadline, now, AllocationWaitTicks))) return false;
        result = value;
        return true;
    }

    private static bool BindingValid(ResourceBindingV32 value, ResourceKindV32 kind) =>
        value.Version == Version && value.StructSize == RequestBytes && value.Kind == kind && value.Reserved == 0 &&
        value.RequestId != 0 && value.ConnectionCookie != 0 && value.DriverInstanceId != Guid.Empty &&
        value.TransferId != Guid.Empty && value.StageIdentity.HasNonzeroFileId &&
        value.AllocationGeneration is > 0 and <= long.MaxValue && value.DestinationGeneration is > 0 and <= long.MaxValue && value.Sequence != 0;

    private static bool GrowthValid(ResourceGrowthV32 value, ulong alignment) =>
        BindingValid(value.Binding, ResourceKindV32.Growth) && CapacityValid(value.ObservedCapacity, alignment) &&
        CapacityValid(value.RequiredExtent, alignment) && value.RequiredExtent > value.ObservedCapacity &&
        DeadlineShape(value.Issued, value.Deadline) && Zero(new ReadOnlySpan<byte>(value.Tail, 16));
    private static bool RetirementValid(ResourceRetirementV32 value, ulong alignment) =>
        BindingValid(value.Binding, ResourceKindV32.Retirement) && CapacityValid(value.AuthorizedCapacity, alignment) &&
        value.EndOfFile <= value.AuthorizedCapacity && value.AllocationSize <= value.AuthorizedCapacity &&
        Zero(new ReadOnlySpan<byte>(value.Tail, 24));

    private static bool VersionIdentityValid(ResourceResultV32 value) => value.StageIdentity.HasNonzeroFileId &&
        value.AllocationGeneration is > 0 and <= long.MaxValue && value.DestinationGeneration is > 0 and <= long.MaxValue;
    private static bool DeadlineShape(ulong issued, ulong deadline) => deadline > issued && deadline - issued <= AllocationWaitTicks;
    private static bool MatchesBinding(ResourceResultV32 value, ResourceBindingV32 expected) =>
        value.Kind == expected.Kind && value.RequestId == expected.RequestId && value.ConnectionCookie == expected.ConnectionCookie &&
        value.DriverInstanceId == expected.DriverInstanceId && value.TransferId == expected.TransferId &&
        value.AllocationGeneration == expected.AllocationGeneration && value.StageIdentity.Equals(expected.StageIdentity) &&
        value.DestinationGeneration == expected.DestinationGeneration && value.Sequence == expected.Sequence;
    private static bool IdentityZero(SafeUploadStageIdentityV19 value) => value.VolumeSerialNumber == 0 && !value.HasNonzeroFileId;
    private static bool NameZero(ResourceResultV32 value) => value.StageNameBytes == 0 && Zero(new ReadOnlySpan<byte>(value.StageName, 128));
    private static bool StageNameValid(ResourceResultV32 value)
    {
        if (value.StageNameBytes is 0 or >= 128 || (value.StageNameBytes & 1) != 0 ||
            !Zero(new ReadOnlySpan<byte>((byte*)value.StageName + value.StageNameBytes, 128 - (int)value.StageNameBytes))) return false;
        string name = new(value.StageName, 0, (int)value.StageNameBytes / 2);
        return name.Length is >= 32 and <= 48 && name[..32] == value.TransferId.ToString("N") &&
            (name.Length == 32 || name[32] == '.' && name.AsSpan(33).IndexOfAnyExcept("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._".AsSpan()) < 0);
    }
    private static bool Zero(ReadOnlySpan<byte> bytes)
    {
        foreach (byte value in bytes) if (value != 0) return false;
        return true;
    }
}

public enum ResourceKindV32 : uint { Allocation = 0, Growth = 1, Retirement = 2 }
public enum ResourceResultCodeV32 : uint
{
    Allocated = 1, CapacityCommitted = 2, RetirementAccepted = 3, NoAllocationCommitted = 4,
    RetryableBusy = 5, NotEnoughSpace = 6, DeadlineExpired = 7, Closed = 8, InvalidBinding = 9, Unresolved = 10
}

[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct ResourceBindingV32
{
    public uint Version, StructSize;
    public ResourceKindV32 Kind;
    public uint Reserved;
    public ulong RequestId, ConnectionCookie;
    public Guid DriverInstanceId, TransferId;
    public ulong AllocationGeneration;
    public SafeUploadStageIdentityV19 StageIdentity;
    public ulong DestinationGeneration, Sequence;
}
[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct ResourceAllocationV32
{
    public SafeUploadStageAllocateV20 Intent;
    public ulong ConnectionCookie, Issued, Deadline;
    public uint Mode, Reserved;
}
[StructLayout(LayoutKind.Sequential, Pack = 4)]
public unsafe struct ResourceGrowthV32
{
    public ResourceBindingV32 Binding;
    public ulong ObservedCapacity, RequiredExtent, Issued, Deadline;
    public fixed byte Tail[16];
}
[StructLayout(LayoutKind.Sequential, Pack = 4)]
public unsafe struct ResourceRetirementV32
{
    public ResourceBindingV32 Binding;
    public ulong EndOfFile, AllocationSize, AuthorizedCapacity;
    public fixed byte Tail[24];
}
[StructLayout(LayoutKind.Sequential, Pack = 4)]
public unsafe struct ResourceResultV32
{
    public uint Version, StructSize;
    public ResourceKindV32 Kind;
    public ResourceResultCodeV32 Result;
    public ulong RequestId, ConnectionCookie;
    public Guid DriverInstanceId, TransferId;
    public ulong AllocationGeneration;
    public SafeUploadStageIdentityV19 StageIdentity;
    public ulong DestinationGeneration, Sequence, ObservedCapacity, RequiredExtent, Issued, Deadline,
        Capacity, LedgerRevision, RetirementEndOfFile, RetirementAllocationSize;
    public uint Flags, Reserved, StageNameBytes, NameReserved;
    public fixed char StageName[64];
    public fixed byte Tail[32];
}
[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct ResourceReplyV32
{
    public uint Version, StructSize;
    public ulong RequestId;
    public uint Verdict, StageNameLength;
    public ResourceResultV32 Body;
}
#endif
