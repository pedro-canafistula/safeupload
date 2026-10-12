using System.ComponentModel;
using System.Security.AccessControl;

namespace SafeUpload.Agent.Service.Interception;

// A failure to persist progress is not evidence that the operation itself
// failed. Callers must reread durable state before retrying its bookkeeping.
internal sealed class StagedJournalPersistenceException : IOException
{
    internal StagedJournalPersistenceException(string manifest, string temporary,
        TransferJournalEntry entry, string step, bool replacementReturned, Exception inner, string? evidence = null)
        : base($"Journal persistence failed: transfer={entry.Transfer.TransferId}; " +
            $"generation={entry.DestinationGeneration}; state={entry.State}; handback={entry.HandbackState}; " +
            $"step={step}; replacementReturned={replacementReturned}; nativeError={NativeError(inner)}; " +
            $"manifest={manifest}; temporary={temporary}; evidence={evidence ?? "unavailable"}.", inner)
    {
        TransferId = entry.Transfer.TransferId;
        ReplacementReturned = replacementReturned;
    }

    internal Guid TransferId { get; }
    internal bool ReplacementReturned { get; }

    // Failure-only metadata, captured before closing the exact writer. These
    // observations are diagnostic, never evidence authorizing a transition.
    internal static string CaptureEvidence(FileStream temporary, string manifest)
    {
        string Describe(FileStream file)
        {
            try
            {
                var id = StagedDestinationFile.ReadIdentity(file.SafeFileHandle);
                string acl = file.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Owner |
                    AccessControlSections.Group | AccessControlSections.Access);
                return $"volume={id.VolumeSerialNumber:X16},id={id.FileIdHigh:X16}{id.FileIdLow:X16}," +
                    $"length={file.Length},acl={acl}";
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or Win32Exception or NotSupportedException)
            { return "unavailable:" + error.Message; }
        }
        string target;
        try
        {
            using var current = StagedJournalFile.Open(manifest);
            target = Describe(current);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or Win32Exception)
        { target = "unavailable:" + error.Message; }
        return $"pointInTimeOnly=true; temporary=[{Describe(temporary)}]; manifest=[{target}]";
    }

    private static int? NativeError(Exception error)
    {
        for (Exception? current = error; current is not null; current = current.InnerException)
            if (current is Win32Exception native) return native.NativeErrorCode;
        return null;
    }
}

internal enum StagedJournalWritePoint { BeforeReplacement, AfterReplacement }
