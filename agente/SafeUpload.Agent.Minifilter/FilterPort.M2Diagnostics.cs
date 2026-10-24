namespace SafeUpload.Agent.Minifilter;

public sealed partial class FilterPort : IM2DiagnosticTransport
{
    /// <summary>
    /// Opt-in diagnostic client for the pinned M2 layout. Does not connect/load a
    /// driver, replace legacy readers, negotiate capabilities or change policy.
    /// </summary>
    public M2DiagnosticClient CreateM2DiagnosticClient() => new(this);

    unsafe int IM2DiagnosticTransport.Query(M2DiagnosticQuery query, Span<byte> response)
    {
        M2DiagnosticContract.Verify();
        // Reject unknown commands and wrong capacities before entering the native
        // send path. The driver requires equality, not a generic oversized buffer.
        if (response.Length != M2DiagnosticContract.ResponseBytes(query))
            throw new ArgumentException("M2 diagnostic buffer has an unexpected capacity.", nameof(response));
        fixed (byte* buffer = response)
        {
            // QueryControl constructs the existing v18/16-byte/Reserved=0 header,
            // uses EnterSend's shared lifetime lease and checks native bytes returned.
            QueryControl((uint)query, (IntPtr)buffer, (uint)response.Length);
        }
        return response.Length;
    }
}
