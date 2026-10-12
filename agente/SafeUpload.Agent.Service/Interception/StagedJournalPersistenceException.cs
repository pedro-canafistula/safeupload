using System.ComponentModel;

namespace SafeUpload.Agent.Service.Interception;

// A failure to persist progress is not evidence that the operation itself
// failed. Callers must reread durable state before retrying its bookkeeping.
internal sealed class StagedJournalPersistenceException : IOException
{
    internal StagedJournalPersistenceException(string manifest, string temporary,
        TransferJournalEntry entry, string step, bool replacementReturned, Exception inner)
        : base($"Journal persistence failed: transfer={entry.Transfer.TransferId}; " +
            $"generation={entry.DestinationGeneration}; state={entry.State}; handback={entry.HandbackState}; " +
            $"step={step}; replacementReturned={replacementReturned}; nativeError={NativeError(inner)}; " +
            $"manifest={manifest}; temporary={temporary}.", inner)
    {
        TransferId = entry.Transfer.TransferId;
        ReplacementReturned = replacementReturned;
    }

    internal Guid TransferId { get; }
    internal bool ReplacementReturned { get; }

    private static int? NativeError(Exception error)
    {
        for (Exception? current = error; current is not null; current = current.InnerException)
            if (current is Win32Exception native) return native.NativeErrorCode;
        return null;
    }
}

internal enum StagedJournalWritePoint { BeforeReplacement, AfterReplacement }
