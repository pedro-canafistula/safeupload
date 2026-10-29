namespace SafeUpload.Agent.Service.Interception;

/// <summary>
/// M2 MVP staging resource guard (owner, 2026-10-29): with per-user/total reservations disabled, a global free-space floor
/// is the only staging guard. A new backing file is refused before it is created when the staging volume would fall below
/// the floor. A refusal never grants inspection or publication authority.
/// </summary>
public sealed class StagedSpaceFloor
{
    private readonly Func<long> _available;

    internal StagedSpaceFloor(long floorBytes, Func<long> available)
    {
        if (floorBytes < 0) throw new ArgumentOutOfRangeException(nameof(floorBytes));
        FloorBytes = floorBytes;
        _available = available ?? throw new ArgumentNullException(nameof(available));
    }

    internal long FloorBytes { get; }

    internal void Require(long bytes)
    {
        if (bytes < 0) throw new ArgumentOutOfRangeException(nameof(bytes));
        long available = _available();
        // Unknown or nonsensical space information fails closed, like the budget's volume read.
        if (available < 0 || available - bytes < FloorBytes)
            throw new StagedSpaceFloorException();
    }
}

/// <summary>
/// The floor's own refusal, raised before any backing file exists. Only this type (or the budget's refusal) counts as
/// a space authority's proof of non-allocation; a bare <see cref="StagedSpaceException"/> stays uncertain.
/// </summary>
public sealed class StagedSpaceFloorException()
    : StagedSpaceException("Not enough free disk space for this save. Free some disk space and try again.");
