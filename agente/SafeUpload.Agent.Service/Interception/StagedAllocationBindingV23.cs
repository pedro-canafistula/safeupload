namespace SafeUpload.Agent.Service.Interception;

// Persisted driver authority, never reconstructed from a locator. Normal
// builds recognize the marker and reject these entries as unsupported.
public sealed record StagedAllocationBindingV23(
    Guid ReservationId, Guid DriverInstanceId, Guid ParentTransferId,
    uint Disposition, uint ReferenceKind, Guid MountManagerVolumeId,
    StagedStageIdentity VolumeRoot, StagedStageIdentity Parent,
    bool ParentCaseSensitive, string CanonicalLeaf, StagedStageIdentity? PublicTarget)
{
    internal StagedDestinationIdentity Destination =>
        new(VolumeRoot, Parent, ParentCaseSensitive, CanonicalLeaf, MountManagerVolumeId);

    internal void Validate()
    {
        if (ReservationId == Guid.Empty || DriverInstanceId == Guid.Empty || MountManagerVolumeId == Guid.Empty ||
            VolumeRoot is null || Parent is null || Disposition > 5 || ReferenceKind > 2 ||
            (ReferenceKind == 0) != (ParentTransferId == Guid.Empty))
            throw new InvalidDataException("Invalid bound allocation identity or ancestry.");
        _ = Destination;
        if (PublicTarget is { } target &&
            ((target.FileIdHigh | target.FileIdLow) == 0 || target.VolumeSerialNumber != Parent.VolumeSerialNumber))
            throw new InvalidDataException("The public target has an unknown or foreign identity.");
        if (ReferenceKind == 0 && (((Disposition is 1 or 4) && PublicTarget is null) ||
                                  (Disposition == 2 && PublicTarget is not null)) ||
            ReferenceKind == 2 && (Disposition != 2 || PublicTarget is not null))
            throw new InvalidDataException("The bound disposition conflicts with the captured public presence.");
    }
}
