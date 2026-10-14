#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.ComponentModel;

namespace SafeUpload.Agent.Minifilter;

public sealed partial class FilterPort
{
    private int _writerMetadataFetches;

    public WriterMetadataSnapshot ReadWriterMetadata(Guid driver, Guid reservation, ulong requestId,
        CancellationToken cancellationToken = default)
    {
        if (Interlocked.Increment(ref _writerMetadataFetches) > 4)
        {
            Interlocked.Decrement(ref _writerMetadataFetches);
            throw new IOException("writer_metadata_resource_limit");
        }
        try
        {
            using var lease = EnterSend();
            return WriterMetadataV27.Fetch(input => SendBoundPublicationControl(lease.Handle, input,
                WriterMetadataV27.PageBytes), driver, reservation, requestId, cancellationToken);
        }
        catch (Win32Exception error) { throw new IOException("writer_metadata_transport_refused", error); }
        finally { Interlocked.Decrement(ref _writerMetadataFetches); }
    }
}
#endif
