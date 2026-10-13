using System.Security.Cryptography;
using System.Text;

namespace SafeUpload.Agent.Core.Domain;

/// <summary>Complete policy-content binding for staged decisions, independent of its human-assigned version.</summary>
public static class PolicyContentFingerprint
{
    /// <summary>Hashes a deterministic, length-framed representation of every policy field.</summary>
    public static string Compute(Policy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        policy.EnsureValid();
        using var bytes = new MemoryStream();
        using (var writer = new BinaryWriter(bytes, new UTF8Encoding(false, true), leaveOpen: true))
        {
            writer.Write("SafeUpload staged policy content 1");
            writer.Write(policy.Version);
            var categories = policy.ActiveCategories.Order().ToArray();
            writer.Write(categories.Length);
            foreach (var category in categories) writer.Write((int)category);
            WriteStrings(writer, policy.MonitoredScopes.Extensions);
            WriteStrings(writer, policy.MonitoredScopes.DestinationPaths);
            writer.Write(policy.MonitoredScopes.RemovableDrives);
            writer.Write(policy.MonitoredScopes.NetworkPaths);
            writer.Write(policy.MaxFileSizeMb);
            writer.Write(policy.InspectionTimeoutSeconds);
            writer.Write(policy.FailOpen);
            WriteStrings(writer, policy.ExcludedProcesses);
            writer.Write(policy.AuditOnly);
            writer.Write(policy.OverrideAllowed);
            var clipboard = policy.EffectiveClipboard;
            writer.Write((int)clipboard.Mode);
            WriteStrings(writer, clipboard.EgressDestinations);
            WriteStrings(writer, clipboard.ExcludedSources);
            writer.Write(clipboard.MaxTextLength);
            writer.Write(clipboard.OversizedTextIsDirty);
        }
        bytes.Position = 0;
        return Convert.ToHexString(SHA256.HashData(bytes));
    }

    private static void WriteStrings(BinaryWriter writer, IEnumerable<string> values)
    {
        // Collection order is not authority. Preserve exact strings rather
        // than inventing a casing/normalization rule for paths or process names.
        string[] ordered = values.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        writer.Write(ordered.Length);
        foreach (string value in ordered) writer.Write(value);
    }
}
