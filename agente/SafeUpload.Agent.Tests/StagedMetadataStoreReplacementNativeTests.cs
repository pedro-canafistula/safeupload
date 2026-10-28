#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.ComponentModel;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;
using Xunit.Abstractions;

namespace SafeUpload.Agent.Tests;

// Builder OS discovery only. Native refusal is recorded, never treated as a
// pass of the strict N-U4-05 positive store/recovery gate. No production choice
// is made from these hypotheses, and each fresh fixture issues one rename.
[Trait("Category", "NativeWindows")]
public sealed class StagedMetadataStoreReplacementNativeTests(ITestOutputHelper output)
{
    public static IEnumerable<object[]> ReplacementVectors()
    {
        foreach (string mechanism in new[] { "Classic", "Extended", "ExtendedPosix", "ReleasedClassic" })
        foreach (bool keepPredecessor in new[] { false, true })
        foreach (bool shareDelete in new[] { false, true })
        foreach (bool predecessorDeleteAccess in new[] { false, true })
            yield return [mechanism, keepPredecessor, shareDelete, predecessorDeleteAccess];
    }

    [Theory]
    [MemberData(nameof(ReplacementVectors))]
    public void N_U4_05_Replacement_discovery_records_status_owners_and_both_objects(
        string mechanism, bool keepPredecessor, bool shareDelete, bool predecessorDeleteAccess)
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new StagedMetadataStoreNativeTests.Fixture();
        var native = fixture.Native;
        byte[] oldBytes = Enumerable.Repeat((byte)1, 128).ToArray(), newBytes = Enumerable.Repeat((byte)2, 192).ToArray();
        StagedStageIdentity oldIdentity;
        // The writable seed handle is closed before the configured predecessor
        // opens. There is no hidden writable target owner during the attempt.
        using (var seed = Prepare("target", oldBytes, native)) oldIdentity = native.Query(seed).Identity;
        using var source = Prepare("source", newBytes, native);
        var sourceIdentity = native.Query(source).Identity;
        uint predecessorAccess = predecessorDeleteAccess ? MetadataStoreRoles.ReadDelete : MetadataStoreRoles.Read;
        uint predecessorShare = shareDelete ? 7u : 3u;
        using var predecessor = native.OpenForReplacementDiscovery("target", predecessorAccess, predecessorShare, out var opened);
        opened.Require();
        var before = native.Query(predecessor);
        Assert.Equal(oldIdentity, before.Identity);
        uint attributes = native.AttributesForReplacementDiscovery(predecessor);
        Assert.Equal(0u, attributes & 1); // Read-only attribute is excluded as a baseline confounder.
        bool heldAtIssue = keepPredecessor && mechanism != "ReleasedClassic";
        if (!heldAtIssue) predecessor.Dispose();
        var selected = mechanism switch
        {
            "Classic" or "ReleasedClassic" => MetadataReplacementMechanism.Classic,
            "Extended" => MetadataReplacementMechanism.Extended,
            "ExtendedPosix" => MetadataReplacementMechanism.ExtendedPosix,
            _ => throw new ArgumentException("Unknown discovery mechanism.", nameof(mechanism))
        };
        var operation = StagedMetadataStoreNative.ReplacementOperation(selected);
        output.WriteLine($"DiscoveryOnly=true MechanismEvidence=BuilderOSOnly OS={Environment.OSVersion} Mechanism={mechanism} " +
            $"Class={operation.InformationClass} Flags=0x{operation.Flags:X8} ReplaceIfExists=true " +
            $"SourceAccess=0x{MetadataStoreRoles.Output:X8} SourceShare=7 SourceOptions=0x{StagedMetadataStoreNative.OutputOptions:X8} " +
            $"AnchorAccess=0x{StagedMetadataStoreNative.AnchorAccess:X8} AnchorShare={StagedMetadataStoreNative.AnchorShare} AnchorIdentity={native.ParentIdentity} " +
            $"PredecessorAccess=0x{predecessorAccess:X8} PredecessorShare={predecessorShare} PredecessorOptions=0x{StagedMetadataStoreNative.OutputOptions:X8} " +
            $"RequestedKeepPredecessor={keepPredecessor} PredecessorHeldAtIssue={heldAtIssue} PredecessorHandleCount={(heldAtIssue ? 1 : 0)} " +
            $"SeedHandleClosed=true OtherTestOwnedTargetHandles=0 TestOwnedTargetSections=0 TestOwnedTargetViews=0 ExternalOwners=NotEnumerated " +
            $"TargetAttributes=0x{attributes:X8} TargetReadOnly=false TargetOwnerDacl=ValidatedPrivate SourceIdentity={sourceIdentity}");
        LogObservation("OldBefore", before);
        LogObservation("NewBefore", native.Query(source));
        int mutationsBefore = native.SuccessfulRenames;
        var renamed = native.RenameForReplacementDiscovery(source, "target", selected);
        output.WriteLine($"Step=Rename AttemptCount=1 Class={operation.InformationClass} Flags=0x{operation.Flags:X8} " +
            $"NTSTATUS=0x{renamed.Status:X8} Information={renamed.Information} SuccessfulRenamesBefore={mutationsBefore} " +
            $"SuccessfulRenamesAfter={native.SuccessfulRenames} DiscoveryOnly=true PositiveGatePass=false");
        // No Require() on the discovery rename: all native statuses are data.
        if (renamed.Success)
        {
            var flushed = native.Flush(source);
            output.WriteLine($"Step=F3 NTSTATUS=0x{flushed.Status:X8} Information={flushed.Information} PowerLossCertificate=false");
        }
        TryObserve("NewHeldAfter", native, source);
        if (heldAtIssue)
        {
            TryObserve("OldHeldAfter", native, predecessor);
            TryRead("OldHeldBytesAfter", native, predecessor, oldBytes);
        }
        else output.WriteLine("OldHeldAfter=Unavailable OldHeldReadability=Unavailable Reason=NoPredecessorHandleOrSectionRetained");

        // Open only after the rename attempt, with read-only access and all
        // sharing. Requesting DELETE here would conflict with the no-share-
        // delete negative and confound the independent name observation.
        using var independent = native.OpenForReplacementDiscovery("target", MetadataStoreRoles.Read, 7, out var independentOpen);
        output.WriteLine($"Step=IndependentOpen Leaf=target Access=0x{MetadataStoreRoles.Read:X8} Share=7 " +
            $"NTSTATUS=0x{independentOpen.Status:X8} Information={independentOpen.Information}");
        if (independentOpen.Success)
        {
            var current = TryObserve("IndependentCurrentAfter", native, independent);
            if (current is not null)
            {
                bool successor = current.Identity == sourceIdentity, original = current.Identity == oldIdentity;
                output.WriteLine($"IndependentSuccessorOpenable={successor} IndependentOriginalStillNamed={original}");
                TryRead("IndependentCurrentBytesAfter", native, independent, successor ? newBytes : oldBytes);
                if (!heldAtIssue && original) LogObservation("OldAfterFromIndependentName", current);
            }
        }
        output.WriteLine("DiscoveryRecorded=true ProductGateVerdict=None ModernAdmission=NotReady NoRenameRetry=true");
    }

    private static SafeFileHandle Prepare(string leaf, byte[] bytes, StagedMetadataStoreNative native)
    {
        var file = native.Create(leaf, MetadataRoleV32.ManifestNew, out var created);
        try
        {
            created.Require();
            byte[] padded = new byte[BoundedOutputPlan.Round(bytes.Length, native.Alignment)]; bytes.CopyTo(padded, 0);
            native.Allocation(file, padded.Length).Require();
            var written = native.Write(file, 0, padded); written.Require(); Assert.Equal((ulong)padded.Length, written.Information);
            native.Flush(file).Require(); native.EndOfFile(file, bytes.Length).Require(); native.Flush(file).Require();
            Assert.Equal(bytes.Length, native.Query(file).EndOfFile); return file;
        }
        catch { file.Dispose(); throw; }
    }
    private void LogObservation(string label, MetadataNativeObservation observation) => output.WriteLine(
        $"Step={label} QueryClass=FileStandardInformation(5) Identity={observation.Identity} EOF={observation.EndOfFile} " +
        $"AllocationSize={observation.AllocationSize} Links={observation.Links} DeletePending={observation.DeletePending}");
    private MetadataNativeObservation? TryObserve(string label, StagedMetadataStoreNative native, SafeFileHandle file)
    {
        try { var observation = native.Query(file); LogObservation(label, observation); return observation; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { LogFailure(label, error); return null; }
    }
    private void TryRead(string label, StagedMetadataStoreNative native, SafeFileHandle file, byte[] expected)
    {
        try
        {
            byte[] block = new byte[native.Alignment];
            var read = native.Read(file, 0, block);
            bool readable = read.Success && read.Information >= (ulong)expected.Length;
            bool equal = readable && block.AsSpan(0, expected.Length).SequenceEqual(expected);
            output.WriteLine($"Step={label} NTSTATUS=0x{read.Status:X8} Information={read.Information} Readable={readable} ExpectedBytesMatch={equal}");
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { LogFailure(label, error); }
    }
    private void LogFailure(string label, Exception error)
    {
        string native = error is MetadataNativeException exact ? $"NTSTATUS=0x{exact.Result.Status:X8} Information={exact.Result.Information}" :
            error.InnerException is Win32Exception win32 ? $"Win32={win32.NativeErrorCode}" : $"HResult=0x{error.HResult:X8}";
        output.WriteLine($"Step={label} ObservationUnavailable=true {native} Error={error.Message}");
    }
}
#endif
