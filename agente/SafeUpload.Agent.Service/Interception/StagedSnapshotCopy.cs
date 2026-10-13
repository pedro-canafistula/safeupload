namespace SafeUpload.Agent.Service.Interception;

/// <summary>Copies at most the measured seal length; source growth cannot consume unbounded snapshot space.</summary>
internal static class StagedSnapshotCopy
{
    internal static async Task CopyAsync(Stream source, Stream target, long expectedLength, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(target);
        if (expectedLength < 0) throw new ArgumentOutOfRangeException(nameof(expectedLength));
        if (source.Length != expectedLength)
            throw new IOException("The snapshot source does not match the measured seal length.");
        source.Position = 0;
        byte[] buffer = new byte[64 * 1024];
        long remaining = expectedLength;
        while (remaining != 0)
        {
            token.ThrowIfCancellationRequested();
            int count = await source.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, remaining)), token)
                .ConfigureAwait(false);
            if (count == 0) throw new EndOfStreamException("The snapshot source ended before the measured seal length.");
            await target.WriteAsync(buffer.AsMemory(0, count), token).ConfigureAwait(false);
            remaining -= count;
        }
        token.ThrowIfCancellationRequested();
        if (source.Length != expectedLength)
            throw new IOException("The snapshot source length changed during capture.");
        source.Position = 0;
    }
}
