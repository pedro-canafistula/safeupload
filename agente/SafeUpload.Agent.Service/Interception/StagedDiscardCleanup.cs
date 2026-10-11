namespace SafeUpload.Agent.Service.Interception;

/// <summary>
/// Removes a manifest-backed private stage only when its exact saved identity
/// matches and confirms absence before a caller records cleanup completion.
/// An unknown legacy identity can only pass when the path is already absent.
/// </summary>
internal static class StagedDiscardCleanup
{
    public static bool TryDeleteExactAndConfirmAbsent(string stagePath,
        StagedStageIdentity? expectedIdentity, out Exception? failure)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stagePath);
        return expectedIdentity is { } identity
            ? StagedStageFile.TryDeleteExactAndConfirmAbsent(stagePath, identity, out failure)
            : StagedStageFile.TryConfirmAbsent(stagePath, out failure);
    }
}
