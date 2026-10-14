#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

internal interface IStagedBoundPublicationTransport
{
    BoundPublicationReplyV26 Send(BoundPublicationRequestV26 request);
    BoundPublicationReplay ReadFacts();
    BoundPublicationReplyV26 Acknowledge(BoundPublicationReplay replay, BoundPublicationReplayRow row);
}

internal sealed class StagedBoundPublicationTransport(FilterPort port, StagedBoundReadiness? readiness = null) : IStagedBoundPublicationTransport
{
    public BoundPublicationReplyV26 Send(BoundPublicationRequestV26 request)
    {
        try
        {
            var reply = port.SendBoundPublication(request);
            readiness?.ObserveAuthority(reply.DriverInstanceId, reply.ConnectionEpoch, reply.AuthorityRevision);
            return reply;
        }
        catch { readiness?.Invalidate(StagedBoundBlocker.ProtocolChanged); throw; }
    }
    public BoundPublicationReplay ReadFacts()
    {
        try
        {
            var replay = port.ReadBoundPublicationFacts();
            readiness?.ObserveReplay("publication", replay.DriverInstanceId, replay.ConnectionEpoch,
                replay.OsBootSequence, replay.Revision);
            return replay;
        }
        catch { readiness?.Invalidate(StagedBoundBlocker.ReplayInvalidated); throw; }
    }
    public BoundPublicationReplyV26 Acknowledge(BoundPublicationReplay replay, BoundPublicationReplayRow row)
    {
        try { return port.AcknowledgeBoundPublication(replay, row); }
        catch { readiness?.Invalidate(StagedBoundBlocker.ReplayInvalidated); throw; }
    }
}

internal interface IStagedBoundPublicationNative
{
    IStagedBoundPublicationDirectory Open(StagedAllocationBindingV23 binding);
}
internal interface IStagedBoundPublicationDirectory : IDisposable
{
    StagedDestinationNameObservation Observe(CancellationToken token);
    IStagedBoundPublicationFile Create(BoundPublicationRequestV26 request, StagedAllocationSecuritySnapshot security);
    void Rename(IStagedBoundPublicationFile file, BoundPublicationRequestV26 request);
}
internal interface IStagedBoundPublicationFile : IDisposable
{
    StagedStageIdentity Identity { get; }
    Task<long> WriteAsync(Stream snapshot, CancellationToken token);
    void Delete();
}

internal sealed class StagedBoundPublicationNative : IStagedBoundPublicationNative
{
    public IStagedBoundPublicationDirectory Open(StagedAllocationBindingV23 binding) => new DirectoryLease(binding);

    private sealed class DirectoryLease(StagedAllocationBindingV23 binding) : IStagedBoundPublicationDirectory
    {
        private readonly StagedDestinationDirectory _directory = StagedDestinationDirectory.Open(binding);
        public StagedDestinationNameObservation Observe(CancellationToken token) =>
            StagedDestinationNameObserver.Observe(_directory.VolumeRoot, _directory.Parent, binding.Destination, token);
        public IStagedBoundPublicationFile Create(BoundPublicationRequestV26 request, StagedAllocationSecuritySnapshot security)
        {
            security.RequireBinding(binding);
            return new FileLease(_directory.CreatePublication(request, security));
        }
        public void Rename(IStagedBoundPublicationFile file, BoundPublicationRequestV26 request)
        {
            if (file is not FileLease held) throw new IOException("publication_original_handle_missing");
            _directory.RenamePublication(held.Handle, request);
        }
        public void Dispose() => _directory.Dispose();
    }
    private sealed class FileLease(SafeFileHandle handle) : IStagedBoundPublicationFile
    {
        internal SafeFileHandle Handle { get; } = handle;
        public StagedStageIdentity Identity => StagedDestinationFile.ReadIdentity(Handle);
        public Task<long> WriteAsync(Stream snapshot, CancellationToken token) =>
            StagedDestinationFile.WriteUnbufferedAsync(Handle, snapshot, token);
        public void Delete()
        {
            if (!SetFileInformationByHandle(Handle, 4, [1], 1))
                throw new IOException("publication_cleanup_native_failed", new Win32Exception(Marshal.GetLastWin32Error()));
        }
        public void Dispose() => Handle.Dispose();
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file, int kind, byte[] data, int length);
}

internal sealed partial class StagedDestinationDirectory
{
    private void RequirePublicationAnchors(BoundPublicationRequestV26 request)
    {
        if (!BoundPublicationV26.Valid(request) || request.MountManagerVolumeId != Destination.MountManagerVolumeId ||
            new StagedStageIdentity(request.VolumeRootIdentity.VolumeSerialNumber, request.VolumeRootIdentity.FileIdHigh,
                request.VolumeRootIdentity.FileIdLow) != Destination.VolumeRoot ||
            new StagedStageIdentity(request.ParentIdentity.VolumeSerialNumber, request.ParentIdentity.FileIdHigh,
                request.ParentIdentity.FileIdLow) != Destination.Parent ||
            (request.ParentCaseSensitive == 1) != Destination.CaseSensitive || !Destination.LeafEquals(request.GetDestinationLeaf()))
            throw new IOException("publication_anchors_changed");
        RequireIdentity(VolumeRoot, Destination.VolumeRoot, directory: true);
        RequireIdentity(Parent, Destination.Parent, directory: true);
        RequireCaseMode();
    }

    internal SafeFileHandle CreatePublication(BoundPublicationRequestV26 request, StagedAllocationSecuritySnapshot security)
    {
        RequirePublicationAnchors(request);
        if (request.Phase != BoundPublicationPhase.Create) throw new IOException("publication_create_permit_missing");
        // Original NtCreateFile, no access-state injection/post-set/default ACL.
        // Kernel validates construction and complete stored descriptor equality.
        return OpenRelative(request.GetTemporaryLeaf(), 0x00110082, 0, 2, 0x0020006A,
            Convert.FromHexString(security.ConstructionHex), 0x80);
    }

    internal void RenamePublication(SafeFileHandle temporary, BoundPublicationRequestV26 request)
    {
        RequirePublicationAnchors(request);
        if (request.Phase != BoundPublicationPhase.Rename) throw new IOException("publication_rename_permit_missing");
        RequireIdentity(temporary, new(request.TemporaryIdentity.VolumeSerialNumber,
            request.TemporaryIdentity.FileIdHigh, request.TemporaryIdentity.FileIdLow), directory: false);
        // Same original FILE_OBJECT and retained root handle, one native POSIX
        // replacement. No locator/full-path reopening participates in authority.
        byte[] leaf = Encoding.Unicode.GetBytes(request.GetDestinationLeaf());
        int rootOffset = IntPtr.Size == 8 ? 8 : 4, nameOffset = IntPtr.Size == 8 ? 20 : 12;
        IntPtr buffer = Marshal.AllocHGlobal(nameOffset + leaf.Length);
        bool parentReference = false;
        try
        {
            Parent.DangerousAddRef(ref parentReference);
            Marshal.Copy(new byte[nameOffset + leaf.Length], 0, buffer, nameOffset + leaf.Length);
            Marshal.WriteInt32(buffer, 3); // REPLACE_IF_EXISTS | POSIX_SEMANTICS
            Marshal.WriteIntPtr(buffer, rootOffset, Parent.DangerousGetHandle());
            Marshal.WriteInt32(buffer, nameOffset - 4, leaf.Length);
            Marshal.Copy(leaf, 0, buffer + nameOffset, leaf.Length);
            int status = NtSetInformationFile(temporary, out _, buffer, checked((uint)(nameOffset + leaf.Length)), 65);
            if (status != 0) throw new IOException("publication_rename_native_failed",
                new Win32Exception(checked((int)RtlNtStatusToDosError(status))));
        }
        finally
        {
            if (parentReference) Parent.DangerousRelease();
            Marshal.FreeHGlobal(buffer);
        }
    }
    [DllImport("ntdll.dll")]
    private static extern int NtSetInformationFile(SafeFileHandle file, out IoStatusBlock status,
        IntPtr information, uint length, int kind);
}
#endif
