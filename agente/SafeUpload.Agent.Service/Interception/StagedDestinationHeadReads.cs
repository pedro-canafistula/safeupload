using System.Runtime.CompilerServices;

namespace SafeUpload.Agent.Service.Interception;

public sealed partial class StagedTransferJournal
{
    private const int MaximumConcurrentHeadReads = 8;

    // Keep complete fresh validation: an exact filename or a cached head cannot
    // establish Windows leaf equality, private ACLs or current durable state.
    // The journal gate serializes callers; one fixed-size batch owns the readers.
    private async IAsyncEnumerable<StagedDestinationHead> ReadAllDestinationHeadFilesCoreAsync(
        [EnumeratorCancellation] CancellationToken token)
    {
        using var paths = Directory.EnumerateFiles(_directory, "destination-*.state").GetEnumerator();
        while (true)
        {
            var batch = new List<string>(MaximumConcurrentHeadReads);
            while (batch.Count < MaximumConcurrentHeadReads)
            {
                token.ThrowIfCancellationRequested();
                if (!paths.MoveNext()) break;
                batch.Add(paths.Current);
            }
            if (batch.Count == 0) yield break;

            StagedDestinationHead?[] heads;
            if (batch.Count == 1)
            {
                heads = [await ReadDestinationHeadFileCoreAsync(batch[0], null, token).ConfigureAwait(false)];
            }
            else
            {
                // Opening/querying security is synchronous Windows I/O. Bound
                // the worker count as well as async reads; no global pool tuning.
                // Do not cancel task admission: every started reader must finish
                // and dispose before this batch releases the journal gate.
                var reads = batch.Select(path => Task.Run(
                    () => ReadDestinationHeadFileCoreAsync(path, null, token), CancellationToken.None)).ToArray();
                heads = await Task.WhenAll(reads).ConfigureAwait(false);
            }

            token.ThrowIfCancellationRequested();
            foreach (var head in heads)
                yield return head ?? throw new InvalidDataException("A destination head disappeared during validation.");
        }
    }
}
