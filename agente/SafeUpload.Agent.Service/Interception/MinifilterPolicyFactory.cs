using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>
/// Builds the one port policy used both by the running service and by the
/// pre-boot seeder. Keeping scope conversion here prevents the durable record
/// from drifting away from what the service sends to the driver.
/// </summary>
internal static class MinifilterPolicyFactory
{
    /// <summary>Safety margin between the engine budget and the kernel's wait (RN-012).</summary>
    internal static readonly TimeSpan Margin = TimeSpan.FromMilliseconds(500);

    internal static SafeUploadPolicyMessage Build(Policy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        MonitoredScopes scopes = policy.MonitoredScopes;
        var builder = new PolicyBuilder();
#if SAFEUPLOAD_ADMISSION_EVIDENCE
        builder.WithTestDisableTaint();
#endif

        foreach (string extension in scopes.Extensions)
            builder.WithExtension(extension);

        foreach (string path in scopes.DestinationPaths)
            builder.WithDestination(path);

        // Classify supported files by content wherever they reside.
        // The minifilter only sets source scope for read opens. Its
        // path-sensitive stream cache is disabled in this mode.
        builder.WithAllSources();

        foreach (string image in policy.ExcludedProcesses)
            builder.WithExcludedImage(image);

        builder.WithVolumeKinds(scopes.RemovableDrives, scopes.NetworkPaths);

        // The engine receives less time than the driver waits so its reply
        // arrives before the kernel's deadline.
        TimeSpan kernelDeadline = policy.InspectionTimeout + Margin;
        builder.WithVerdictTimeout(kernelDeadline);
        builder.WithAuditOnly(policy.AuditOnly);
        builder.WithOverrideAllowed(policy.OverrideAllowed);
        return builder.Build();
    }
}
