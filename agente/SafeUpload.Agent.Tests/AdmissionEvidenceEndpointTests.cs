using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;
#if SAFEUPLOAD_ADMISSION_EVIDENCE
using SafeUpload.Agent.Service.Diagnostics;
using ServiceEvidenceWire = SafeUpload.Agent.Service.Diagnostics.AdmissionEvidenceWire;
#endif
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class AdmissionEvidenceEndpointTests
{
    private const string NativeVolumeGuid = @"\??\Volume{8b4e3cc2-29ab-4c77-aeab-10d6c93d527d}";

    [Fact]
    public void EvidenceTypesExistOnlyInFeatureBuilds()
    {
        Assembly service = typeof(MinifilterInterceptor).Assembly;
        Assembly minifilter = typeof(FilterPort).Assembly;

        string[] serviceTypeNames =
        [
            "SafeUpload.Agent.Service.Diagnostics.AdmissionEvidenceEndpoint",
            "SafeUpload.Agent.Service.Diagnostics.AdmissionEvidenceRequest",
            "SafeUpload.Agent.Service.Diagnostics.AdmissionEvidenceCapture",
            "SafeUpload.Agent.Service.Diagnostics.AdmissionEvidenceBinding",
            "SafeUpload.Agent.Service.Diagnostics.AdmissionEvidenceWire",
            "SafeUpload.Agent.Service.Diagnostics.AdmissionEvidenceRunLedger",
        ];
        string[] minifilterTypeNames =
        [
            "SafeUpload.Agent.Minifilter.IAdmissionEvidenceSender",
            "SafeUpload.Agent.Minifilter.AdmissionEvidenceCommand",
            "SafeUpload.Agent.Minifilter.AdmissionEvidenceReply",
        ];

#if SAFEUPLOAD_ADMISSION_EVIDENCE
        Assert.All(serviceTypeNames, name => Assert.NotNull(service.GetType(name, throwOnError: false)));
        Assert.All(minifilterTypeNames, name => Assert.NotNull(minifilter.GetType(name, throwOnError: false)));
#else
        Assert.All(serviceTypeNames, name => Assert.Null(service.GetType(name, throwOnError: false)));
        Assert.All(minifilterTypeNames, name => Assert.Null(minifilter.GetType(name, throwOnError: false)));
#endif
    }

#if SAFEUPLOAD_ADMISSION_EVIDENCE
    [Fact]
    public void RequestParserRequiresExactBoundedCanonicalIdentity()
    {
        byte[] fileId = Enumerable.Range(0, 16).Select(value => (byte)value).ToArray();
        byte[] body = AdmissionEvidenceRequest.EncodeForTest(
            Guid.NewGuid(), Guid.NewGuid(), AdmissionEvidenceHook.ExpandedPolicyPostAck,
            NativeVolumeGuid, 0x1234567890abcdef, fileId);

        AdmissionEvidenceRequest parsed = AdmissionEvidenceRequest.Parse(body);
        Assert.Equal(NativeVolumeGuid, parsed.VolumeGuid);
        Assert.Equal(0x1234567890abcdeful, parsed.VolumeSerial);
        Assert.Equal(fileId, parsed.FileId);
        Assert.Equal(AdmissionEvidenceHook.ExpandedPolicyPostAck, parsed.Hook);

        Assert.Throws<InvalidDataException>(() => AdmissionEvidenceRequest.Parse(body.Concat(new byte[] { 0 }).ToArray()));
        Assert.Throws<InvalidDataException>(() => AdmissionEvidenceRequest.Parse(new byte[4097]));

        byte[] unknownFlags = (byte[])body.Clone();
        unknownFlags[7] = 1;
        Assert.Throws<InvalidDataException>(() => AdmissionEvidenceRequest.Parse(unknownFlags));

        byte[] unknownHook = (byte[])body.Clone();
        unknownHook[6] = 8;
        Assert.Throws<InvalidDataException>(() => AdmissionEvidenceRequest.Parse(unknownHook));

        byte[] invalidUtf8 = (byte[])body.Clone();
        invalidUtf8[^1] = 0xff;
        Assert.Throws<InvalidDataException>(() => AdmissionEvidenceRequest.Parse(invalidUtf8));

        byte[] wrongVolumeForm = AdmissionEvidenceRequest.EncodeForTest(
            Guid.NewGuid(), Guid.NewGuid(), AdmissionEvidenceHook.ExpandedPolicyPostAck,
            NativeVolumeGuid, 3, fileId);
        Encoding.UTF8.GetBytes(@"C:\").CopyTo(wrongVolumeForm, 65);
        Assert.Throws<InvalidDataException>(() => AdmissionEvidenceRequest.Parse(wrongVolumeForm));
    }

    [Fact]
    public void IncompleteHookConsumesOrdinalAndMakesThatRunTargetTerminal()
    {
        var ledger = new AdmissionEvidenceRunLedger();
        Guid run = Guid.NewGuid();
        byte[] fileId = Enumerable.Range(0, 16).Select(value => (byte)(value + 3)).ToArray();
        AdmissionEvidenceRequest hook2 = MakeRequest(run, Guid.NewGuid(),
            AdmissionEvidenceHook.ExpandedPolicyPostAck, fileId);

        Assert.Null(ledger.Advance(hook2, bindingGeneration: 2));
        ledger.MarkCaptureIncomplete(hook2, bindingGeneration: 2);

        AdmissionEvidenceRequest retryHook2 = MakeRequest(run, Guid.NewGuid(),
            AdmissionEvidenceHook.ExpandedPolicyPostAck, fileId);
        AdmissionEvidenceRequest nextHook = MakeRequest(run, Guid.NewGuid(),
            AdmissionEvidenceHook.ExpansionPrewrite, fileId);
        Assert.Equal("RUN_TERMINAL_CAPTURE_INCOMPLETE_NEW_RUN_REQUIRED",
            ledger.Advance(retryHook2, bindingGeneration: 2));
        Assert.Equal("RUN_TERMINAL_CAPTURE_INCOMPLETE_NEW_RUN_REQUIRED",
            ledger.Advance(nextHook, bindingGeneration: 2));

        byte[] otherFileId = Enumerable.Repeat((byte)0x55, 16).ToArray();
        AdmissionEvidenceRequest otherTarget = MakeRequest(run, Guid.NewGuid(),
            AdmissionEvidenceHook.ExpandedPolicyPostAck,
            otherFileId);
        Assert.Null(ledger.Advance(otherTarget, bindingGeneration: 2));
        AdmissionEvidenceRequest otherTargetNext = MakeRequest(run, Guid.NewGuid(),
            AdmissionEvidenceHook.ExpansionPrewrite, otherFileId);
        Assert.Null(ledger.Advance(otherTargetNext, bindingGeneration: 2));
        Assert.Equal("RUN_TERMINAL_CAPTURE_INCOMPLETE_NEW_RUN_REQUIRED",
            ledger.Advance(nextHook, bindingGeneration: 2));
        AdmissionEvidenceRequest newRun = MakeRequest(Guid.NewGuid(), Guid.NewGuid(),
            AdmissionEvidenceHook.ExpandedPolicyPostAck, fileId);
        Assert.Null(ledger.Advance(newRun, bindingGeneration: 2));
    }

    [Fact]
    public void RunTargetTombstonesStayUntilBindingClearAndCapacityDoesNotEvictThem()
    {
        var ledger = new AdmissionEvidenceRunLedger();
        Guid run = Guid.NewGuid();
        byte[] terminalFileId = new byte[16];
        AdmissionEvidenceRequest first = MakeRequest(run, Guid.NewGuid(),
            AdmissionEvidenceHook.ExpandedPolicyPostAck, terminalFileId);

        Assert.Null(ledger.Advance(first, bindingGeneration: 4));
        ledger.MarkCaptureIncomplete(first, bindingGeneration: 4);

        for (byte value = 1; value < 128; value++)
        {
            byte[] fileId = Enumerable.Repeat(value, 16).ToArray();
            AdmissionEvidenceRequest otherTarget = MakeRequest(run, Guid.NewGuid(),
                AdmissionEvidenceHook.ExpandedPolicyPostAck, fileId);
            Assert.Null(ledger.Advance(otherTarget, bindingGeneration: 4));
        }

        Assert.Equal(128, ledger.Count);
        AdmissionEvidenceRequest retry = MakeRequest(run, Guid.NewGuid(),
            AdmissionEvidenceHook.ExpandedPolicyPostAck, terminalFileId);
        Assert.Equal("RUN_TERMINAL_CAPTURE_INCOMPLETE_NEW_RUN_REQUIRED",
            ledger.Advance(retry, bindingGeneration: 4));

        byte[] overflowFileId = Enumerable.Repeat((byte)0x80, 16).ToArray();
        AdmissionEvidenceRequest overLimit = MakeRequest(run, Guid.NewGuid(),
            AdmissionEvidenceHook.ExpandedPolicyPostAck, overflowFileId);
        Assert.Equal("RUN_LIMIT_REACHED", ledger.Advance(overLimit, bindingGeneration: 4));
        Assert.Equal(128, ledger.Count);

        // Binding teardown/recreation is the only point at which old
        // per-target tombstones are discarded and the same RunId can restart.
        ledger.Clear();
        Assert.Equal(0, ledger.Count);
        Assert.Null(ledger.Advance(retry, bindingGeneration: 4));
    }

    [Fact]
    public async Task LengthPrefixIsBoundedBeforeAllocationAndRequiresCompleteBody()
    {
        byte[] tooLarge = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(tooLarge, 4097);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            AdmissionEvidenceEndpoint.ReadRequestAsync(new MemoryStream(tooLarge), CancellationToken.None));

        byte[] truncated = new byte[6];
        BinaryPrimitives.WriteUInt32LittleEndian(truncated, 65);
        await Assert.ThrowsAsync<EndOfStreamException>(() =>
            AdmissionEvidenceEndpoint.ReadRequestAsync(new MemoryStream(truncated), CancellationToken.None));
    }

    [Fact]
    public void PipeAuthorizationRequiresSystemOrAdministratorTokenAndLocalPipePolicy()
    {
        Assert.True(AdmissionEvidenceEndpoint.IsAuthorizedToken("S-1-5-18", isAdministrator: false));
        Assert.True(AdmissionEvidenceEndpoint.IsAuthorizedToken("S-1-5-21-1-2-3-1000", isAdministrator: true));
        Assert.False(AdmissionEvidenceEndpoint.IsAuthorizedToken("S-1-5-21-1-2-3-1000", isAdministrator: false));
        Assert.False(AdmissionEvidenceEndpoint.IsAuthorizedToken(null, isAdministrator: true));

        Assert.Contains("SY", AdmissionEvidenceEndpoint.PipeDaclSddl, StringComparison.Ordinal);
        Assert.Contains("BA", AdmissionEvidenceEndpoint.PipeDaclSddl, StringComparison.Ordinal);
        Assert.DoesNotContain("BU", AdmissionEvidenceEndpoint.PipeDaclSddl, StringComparison.Ordinal);
        Assert.Equal(0x00080000u, AdmissionEvidenceEndpoint.FileFlagFirstPipeInstance);
        Assert.Equal(0x00000008u, AdmissionEvidenceEndpoint.PipeRejectRemoteClientsMode);
    }

    [Fact]
    public async Task CaptureStreamsStablePagedSnapshotAndRetriesStatusRetryWithoutReadinessClaim()
    {
        byte[] targetFileId = Enumerable.Range(0, 16).Select(value => (byte)(value + 1)).ToArray();
        var native = new FakeNativeSender(targetFileId, retryFirstActivatingPage: true);
        using var handle = new SafeFileHandle(new IntPtr(47), ownsHandle: false);
        using FilterPort port = FilterPort.CreateForTesting(handle, native);
        byte[] policyHash = SHA256.HashData("accepted-candidate"u8);
        AdmissionEvidenceBinding binding = AdmissionEvidenceBinding.TryCreate(
            port, 9, 7, policyHash);

        AdmissionEvidenceRequest request = AdmissionEvidenceRequest.Parse(
            AdmissionEvidenceRequest.EncodeForTest(Guid.NewGuid(), Guid.NewGuid(),
                AdmissionEvidenceHook.ExpandedPolicyPostAck, NativeVolumeGuid,
                0x1234567890abcdef, targetFileId));
        var output = new MemoryStream();
        var capture = new AdmissionEvidenceCapture(
            (current, command, start) => current.TrySend(command, start, out var reply) ? reply : null,
            _ => true);

        AdmissionEvidenceCaptureSummary summary = await capture.CaptureAsync(
            output, request, binding, new AdmissionEvidenceCaller(2718, "S-1-5-21-10"),
            CancellationToken.None);

        Assert.Equal("EvidenceCaptured", summary.Outcome);
        Assert.True(summary.BindingReceiptIncluded);
        Assert.True(summary.StableActivatingSnapshot);
        Assert.Equal(1u, summary.TargetEntryMatches);
        Assert.Equal("Unique", summary.TargetAssessment);
        Assert.Equal(1u, summary.TargetState);
        Assert.Equal(7u, summary.TargetGeneration);
        Assert.True(summary.BindingGenerationStable);
        Assert.False(summary.ReadyClaim);
        Assert.Equal("Unique", summary.VolumeGuidAssessmentBefore);
        Assert.Equal("Unique", summary.VolumeGuidAssessmentAfter);
        Assert.Equal(33, native.LastSnapshotEntryCount);
        Assert.Equal(new uint[] { 0, 32 }, native.SuccessfulActivatingStarts);
        Assert.All(native.Commands, command => Assert.Contains(command,
            new[] { AdmissionEvidenceCommand.ActivatingStatus, AdmissionEvidenceCommand.EpochStatus,
                AdmissionEvidenceCommand.VolumeObserve }));

        List<byte[]> frames = ReadFrames(output.ToArray());
        Assert.Equal(1, frames.Count(frame => frame[6] == (byte)AdmissionEvidenceFrameKind.BindingReceipt));
        List<byte[]> calls = frames.Where(frame => frame[6] == (byte)AdmissionEvidenceFrameKind.RawCall).ToList();
        Assert.All(calls, frame => Assert.Equal(0, frame[8] & ~0x03));
        Assert.Contains(calls, frame => ReadUInt32(frame, 44) == 19 &&
            ReadUInt32(frame, 48) == 1 && ReadUInt32(frame, 52) == 0 &&
            ReadInt32(frame, 56) == unchecked((int)0x800704D5) && frame[8] == 0 &&
            (frame[8] & 0x02) == 0 &&
            ReadUInt32(frame, 68) == 0 && ReadUInt32(frame, 60) == 0);

        byte[] successfulPage = calls.Single(frame => ReadUInt32(frame, 44) == 19 && ReadUInt32(frame, 52) == 32);
        Assert.Equal((byte)0x03, successfulPage[8]);
        Assert.True((successfulPage[8] & 0x01) != 0); // reply bytes are present
        Assert.True((successfulPage[8] & 0x02) != 0); // returned length is defined
        int diagnosticLength = BinaryPrimitives.ReadUInt16LittleEndian(successfulPage.AsSpan(10, 2));
        int inputLength = checked((int)ReadUInt32(successfulPage, 64));
        int rawLength = checked((int)ReadUInt32(successfulPage, 68));
        int inputOffset = AdmissionEvidenceFrames.RawCallHeaderBytes + diagnosticLength;
        int rawOffset = inputOffset + inputLength;
        byte[] rawReply = successfulPage.AsSpan(rawOffset, rawLength).ToArray();
        Assert.Equal(0x1234567890abcdeful,
            BinaryPrimitives.ReadUInt64LittleEndian(successfulPage.AsSpan(220, 8)));
        Assert.Equal(targetFileId, successfulPage.AsSpan(228, 16).ToArray());
        Assert.Equal(NativeVolumeGuid, Encoding.ASCII.GetString(successfulPage, 244, 48));
        Assert.Equal(SHA256.HashData(rawReply), successfulPage.AsSpan(188, 32).ToArray());
        Assert.Equal(SHA256.HashData(successfulPage.AsSpan(inputOffset, inputLength).ToArray()),
            successfulPage.AsSpan(156, 32).ToArray());
    }

    [Fact]
    public async Task StableSnapshotWithAbsentTargetIsCapturedAndAllowsNextHook()
    {
        byte[] targetFileId = Enumerable.Repeat((byte)0x42, 16).ToArray();
        var native = new FakeNativeSender(targetFileId, targetEntryCopies: 0);
        using var handle = new SafeFileHandle(new IntPtr(53), ownsHandle: false);
        using FilterPort port = FilterPort.CreateForTesting(handle, native);
        AdmissionEvidenceBinding binding = AdmissionEvidenceBinding.TryCreate(
            port, 21, 10, SHA256.HashData("candidate"u8));
        Guid run = Guid.NewGuid();
        AdmissionEvidenceRequest request = MakeRequest(run, Guid.NewGuid(),
            AdmissionEvidenceHook.ExpandedPolicyPostAck, targetFileId);
        var ledger = new AdmissionEvidenceRunLedger();
        Assert.Null(ledger.Advance(request, binding.Generation));

        var output = new MemoryStream();
        var capture = new AdmissionEvidenceCapture(
            (current, command, start) => current.TrySend(command, start, out var reply) ? reply : null,
            _ => true);
        AdmissionEvidenceCaptureSummary summary = await capture.CaptureAsync(
            output, request, binding, new AdmissionEvidenceCaller(2721, "S-1-5-21-13"),
            CancellationToken.None);

        Assert.Equal("EvidenceCaptured", summary.Outcome);
        Assert.True(summary.StableActivatingSnapshot);
        Assert.Equal(0u, summary.TargetEntryMatches);
        Assert.Equal("Absent", summary.TargetAssessment);
        Assert.Null(summary.TargetState);
        Assert.False(summary.ReadyClaim);
        AdmissionEvidenceRequest next = MakeRequest(run, Guid.NewGuid(),
            AdmissionEvidenceHook.ExpansionPrewrite, targetFileId);
        Assert.Null(ledger.Advance(next, binding.Generation));
    }

    [Fact]
    public async Task StableSnapshotWithAmbiguousTargetCarriesNoSelectedEntryFields()
    {
        byte[] targetFileId = Enumerable.Repeat((byte)0x43, 16).ToArray();
        var native = new FakeNativeSender(targetFileId, targetEntryCopies: 2);
        using var handle = new SafeFileHandle(new IntPtr(54), ownsHandle: false);
        using FilterPort port = FilterPort.CreateForTesting(handle, native);
        AdmissionEvidenceBinding binding = AdmissionEvidenceBinding.TryCreate(
            port, 22, 10, SHA256.HashData("candidate"u8));
        AdmissionEvidenceRequest request = MakeRequest(Guid.NewGuid(), Guid.NewGuid(),
            AdmissionEvidenceHook.ExpandedPolicyPostAck, targetFileId);
        var output = new MemoryStream();
        var capture = new AdmissionEvidenceCapture(
            (current, command, start) => current.TrySend(command, start, out var reply) ? reply : null,
            _ => true);

        AdmissionEvidenceCaptureSummary summary = await capture.CaptureAsync(
            output, request, binding, new AdmissionEvidenceCaller(2722, "S-1-5-21-14"),
            CancellationToken.None);

        Assert.Equal("EvidenceCaptured", summary.Outcome);
        Assert.Equal(2u, summary.TargetEntryMatches);
        Assert.Equal("Ambiguous", summary.TargetAssessment);
        Assert.Null(summary.TargetState);
        Assert.Null(summary.TargetGeneration);
        Assert.Null(summary.TargetH);
        Assert.Null(summary.TargetS);
        Assert.Null(summary.TargetC);
        Assert.Null(summary.TargetT);
        Assert.Null(summary.TargetW);
        Assert.Null(summary.TargetUnknownReasons);
        Assert.False(summary.ReadyClaim);
    }

    [Theory]
    [InlineData(0, "Absent")]
    [InlineData(2, "Ambiguous")]
    public async Task StableVolumeObservationKeepsGuidAttributionSeparate(int copies, string assessment)
    {
        byte[] targetFileId = Enumerable.Repeat((byte)0x44, 16).ToArray();
        var native = new FakeNativeSender(targetFileId, volumeGuidCopies: copies);
        using var handle = new SafeFileHandle(new IntPtr(55), ownsHandle: false);
        using FilterPort port = FilterPort.CreateForTesting(handle, native);
        AdmissionEvidenceBinding binding = AdmissionEvidenceBinding.TryCreate(
            port, 23, 10, SHA256.HashData("candidate"u8));
        AdmissionEvidenceRequest request = MakeRequest(Guid.NewGuid(), Guid.NewGuid(),
            AdmissionEvidenceHook.ExpandedPolicyPostAck, targetFileId);
        var output = new MemoryStream();
        var capture = new AdmissionEvidenceCapture(
            (current, command, start) => current.TrySend(command, start, out var reply) ? reply : null,
            _ => true);

        AdmissionEvidenceCaptureSummary summary = await capture.CaptureAsync(
            output, request, binding, new AdmissionEvidenceCaller(2723, "S-1-5-21-15"),
            CancellationToken.None);

        Assert.Equal("EvidenceCaptured", summary.Outcome);
        Assert.Equal("Unique", summary.TargetAssessment);
        Assert.Equal((uint)copies, summary.VolumeGuidMatchesBefore);
        Assert.Equal((uint)copies, summary.VolumeGuidMatchesAfter);
        Assert.Equal(assessment, summary.VolumeGuidAssessmentBefore);
        Assert.Equal(assessment, summary.VolumeGuidAssessmentAfter);
        Assert.True(summary.VolumeSnapshotsByteIdentical);
        Assert.False(summary.ReadyClaim);
    }

    [Fact]
    public async Task NonzeroReservedFlagsInNonTargetActivatingEntryPreserveRawPageAndInvalidateCapture()
    {
        byte[] targetFileId = Enumerable.Repeat((byte)0x45, 16).ToArray();
        var native = new FakeNativeSender(targetFileId, malformedReservedFlagsAtGlobalIndex: 0);
        using var handle = new SafeFileHandle(new IntPtr(56), ownsHandle: false);
        using FilterPort port = FilterPort.CreateForTesting(handle, native);
        AdmissionEvidenceBinding binding = AdmissionEvidenceBinding.TryCreate(
            port, 24, 10, SHA256.HashData("candidate"u8));
        AdmissionEvidenceRequest request = MakeRequest(Guid.NewGuid(), Guid.NewGuid(),
            AdmissionEvidenceHook.ExpandedPolicyPostAck, targetFileId);
        var output = new MemoryStream();
        var capture = new AdmissionEvidenceCapture(
            (current, command, start) => current.TrySend(command, start, out var reply) ? reply : null,
            _ => true);

        AdmissionEvidenceCaptureSummary summary = await capture.CaptureAsync(
            output, request, binding, new AdmissionEvidenceCaller(2724, "S-1-5-21-16"),
            CancellationToken.None);

        Assert.Equal("EvidenceIncomplete", summary.Outcome);
        Assert.Equal("ActivatingStatusPageInvalid", summary.Reason);
        Assert.Equal("Unavailable", summary.TargetAssessment);
        Assert.False(summary.ReadyClaim);
        List<byte[]> frames = ReadFrames(output.ToArray());
        byte[] firstPage = Assert.Single(frames, frame => frame[6] == (byte)AdmissionEvidenceFrameKind.RawCall &&
            ReadUInt32(frame, 44) == 19 && ReadUInt32(frame, 52) == 0);
        int diagnosticLength = BinaryPrimitives.ReadUInt16LittleEndian(firstPage.AsSpan(10, 2));
        int inputLength = checked((int)ReadUInt32(firstPage, 64));
        int replyLength = checked((int)ReadUInt32(firstPage, 68));
        int replyOffset = AdmissionEvidenceFrames.RawCallHeaderBytes + diagnosticLength + inputLength;
        byte[] rawPage = firstPage.AsSpan(replyOffset, replyLength).ToArray();
        int reservedOffset = ServiceEvidenceWire.ActivatingHeaderBytes + 56;
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(rawPage.AsSpan(reservedOffset, 4)));
        Assert.Equal(SHA256.HashData(rawPage), firstPage.AsSpan(188, 32).ToArray());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task BackpressureDeadlineCancelsCaptureAndTerminalizesReservedHook(bool usePerWriteDeadline)
    {
        byte[] targetFileId = Enumerable.Repeat((byte)0x46, 16).ToArray();
        var native = new FakeNativeSender(targetFileId);
        using var handle = new SafeFileHandle(new IntPtr(57), ownsHandle: false);
        using FilterPort port = FilterPort.CreateForTesting(handle, native);
        AdmissionEvidenceBinding binding = AdmissionEvidenceBinding.TryCreate(
            port, 25, 10, SHA256.HashData("candidate"u8));
        Guid run = Guid.NewGuid();
        AdmissionEvidenceRequest request = MakeRequest(run, Guid.NewGuid(),
            AdmissionEvidenceHook.ExpandedPolicyPostAck, targetFileId);
        var ledger = new AdmissionEvidenceRunLedger();
        Assert.Null(ledger.Advance(request, binding.Generation));

        using var output = new BlockingAfterFirstWriteStream();
        using var captureDeadline = new CancellationTokenSource();
        TimeSpan? frameWriteDeadline = usePerWriteDeadline
            ? TimeSpan.FromMilliseconds(50)
            : null;
        var capture = new AdmissionEvidenceCapture(
            (current, command, start) => current.TrySend(command, start, out var reply) ? reply : null,
            _ => true,
            frameWriteDeadline);
        Task<AdmissionEvidenceCaptureSummary> captureTask = capture.CaptureAsync(
            output, request, binding, new AdmissionEvidenceCaller(2725, "S-1-5-21-17"),
            captureDeadline.Token);
        if (!usePerWriteDeadline)
        {
            await output.BlockedWriteStarted.WaitAsync(TimeSpan.FromSeconds(5));
            captureDeadline.Cancel();
        }
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => captureTask);

        // This is the same finally-path used by ServeOneAsync after any
        // incomplete capture, including a stalled output write.
        ledger.MarkCaptureIncomplete(request, binding.Generation);
        Assert.True(output.BlockedWriteStarted.IsCompleted);
        byte[] preservedBytes = output.ToArray();
        List<byte[]> preservedFrames = ReadFrames(preservedBytes);
        byte[] preservedReceipt = Assert.Single(preservedFrames);
        Assert.Equal((byte)AdmissionEvidenceFrameKind.BindingReceipt, preservedReceipt[6]);

        AdmissionEvidenceRequest retry = MakeRequest(run, Guid.NewGuid(),
            AdmissionEvidenceHook.ExpandedPolicyPostAck, targetFileId);
        Assert.Equal("RUN_TERMINAL_CAPTURE_INCOMPLETE_NEW_RUN_REQUIRED",
            ledger.Advance(retry, binding.Generation));
    }

    [Fact]
    public async Task BackendGenerationDriftProducesIncompleteEvidenceAndStillNeverReady()
    {
        byte[] targetFileId = Enumerable.Range(0, 16).Select(value => (byte)(31 - value)).ToArray();
        var native = new FakeNativeSender(targetFileId, changeEpochOnFinalStatus: true);
        using var handle = new SafeFileHandle(new IntPtr(48), ownsHandle: false);
        using FilterPort port = FilterPort.CreateForTesting(handle, native);
        AdmissionEvidenceBinding binding = AdmissionEvidenceBinding.TryCreate(
            port, 11, 8, SHA256.HashData("candidate"u8));
        AdmissionEvidenceRequest request = AdmissionEvidenceRequest.Parse(
            AdmissionEvidenceRequest.EncodeForTest(Guid.NewGuid(), Guid.NewGuid(),
                AdmissionEvidenceHook.ExpandedPolicyPostAck, NativeVolumeGuid, 77, targetFileId));
        var output = new MemoryStream();
        var capture = new AdmissionEvidenceCapture(
            (current, command, start) => current.TrySend(command, start, out var reply) ? reply : null,
            _ => true);

        AdmissionEvidenceCaptureSummary summary = await capture.CaptureAsync(
            output, request, binding, new AdmissionEvidenceCaller(2719, "S-1-5-21-11"),
            CancellationToken.None);

        Assert.Equal("EvidenceIncomplete", summary.Outcome);
        Assert.False(summary.BindingGenerationStable);
        Assert.False(summary.ReadyClaim);
        Assert.False(binding.TrySend(AdmissionEvidenceCommand.EpochStatus, 0, out _));
        Assert.Contains(ReadFrames(output.ToArray()), frame => frame[6] == (byte)AdmissionEvidenceFrameKind.RawCall &&
            ReadUInt32(frame, 44) == 19);
    }

    [Fact]
    public async Task InvalidBindingEpochIsPreservedAndDoesNotSuppressLiveCapture()
    {
        byte[] targetFileId = Enumerable.Range(0, 16).Select(value => (byte)(40 + value)).ToArray();
        var native = new FakeNativeSender(targetFileId, failInitialEpoch: true);
        using var handle = new SafeFileHandle(new IntPtr(52), ownsHandle: false);
        using FilterPort port = FilterPort.CreateForTesting(handle, native);
        AdmissionEvidenceBinding binding = AdmissionEvidenceBinding.TryCreate(
            port, 13, 9, SHA256.HashData("candidate"u8));
        AdmissionEvidenceRequest request = MakeRequest(Guid.NewGuid(), Guid.NewGuid(),
            AdmissionEvidenceHook.ExpandedPolicyPostAck, targetFileId);
        var output = new MemoryStream();
        var capture = new AdmissionEvidenceCapture(
            (current, command, start) => current.TrySend(command, start, out var reply) ? reply : null,
            _ => true);

        AdmissionEvidenceCaptureSummary summary = await capture.CaptureAsync(
            output, request, binding, new AdmissionEvidenceCaller(2720, "S-1-5-21-12"),
            CancellationToken.None);

        Assert.Equal("EvidenceIncomplete", summary.Outcome);
        Assert.False(summary.ReadyClaim);
        Assert.Null(summary.BindingPolicyGeneration);
        Assert.True(summary.BindingReceiptIncluded);
        List<byte[]> frames = ReadFrames(output.ToArray());
        byte[] receipt = Assert.Single(frames, frame => frame[6] == (byte)AdmissionEvidenceFrameKind.BindingReceipt);
        Assert.Equal(unchecked((int)0x800704D5), ReadInt32(receipt, 56));
        Assert.Equal(0u, ReadUInt32(receipt, 68));
        Assert.Contains(frames, frame => frame[6] == (byte)AdmissionEvidenceFrameKind.RawCall &&
            ReadUInt32(frame, 44) == 19);
    }

    [Fact]
    public async Task BindingDrainWaitsForAcceptedSendAndRejectsLaterCalls()
    {
        byte[] targetFileId = new byte[16];
        var native = new FakeNativeSender(targetFileId);
        using var handle = new SafeFileHandle(new IntPtr(49), ownsHandle: false);
        using FilterPort port = FilterPort.CreateForTesting(handle, native);
        AdmissionEvidenceBinding binding = AdmissionEvidenceBinding.TryCreate(
            port, 1, 1, SHA256.HashData("candidate"u8));
        native.BlockNextVolumeSend();

        Task<bool> active = Task.Run(() => binding.TrySend(
            AdmissionEvidenceCommand.VolumeObserve, 0, out _));
        Assert.True(native.BlockEntered.Wait(TimeSpan.FromSeconds(5)));
        Task drain = Task.Run(binding.StopAcceptingAndDrain);
        await Task.Delay(100);
        Assert.False(drain.IsCompleted);
        native.ReleaseBlockedSend.Set();

        Assert.True(await active);
        await drain;
        Assert.False(binding.IsAccepting);
        Assert.False(binding.TrySend(AdmissionEvidenceCommand.EpochStatus, 0, out _));
    }

    [Fact]
    public async Task RawFrameKeepsActualBytesEvenWhenNativeCallFailed()
    {
        using var handle = new SafeFileHandle(new IntPtr(50), ownsHandle: false);
        var native = new FakeNativeSender(new byte[16]);
        using FilterPort port = FilterPort.CreateForTesting(handle, native);
        AdmissionEvidenceBinding binding = AdmissionEvidenceBinding.TryCreate(
            port, 1, 1, SHA256.HashData("candidate"u8));
        byte[] rawInput = new byte[16];
        byte[] actualBytesReturnedByTestSeam = [0xde, 0xad, 0xbe, 0xef];
        var failedReceipt = new AdmissionEvidenceReply(rawInput, actualBytesReturnedByTestSeam,
            unchecked((int)0x800704D5), 19, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow,
            Stopwatch.GetTimestamp(), Stopwatch.GetTimestamp(), "retry HRESULT; no status payload");
        var stream = new MemoryStream();

        await AdmissionEvidenceFrames.WriteCallAsync(stream, AdmissionEvidenceFrameKind.RawCall,
            null, binding, AdmissionEvidenceCommand.EpochStatus, failedReceipt, 1, 0,
            CancellationToken.None);

        byte[] frame = Assert.Single(ReadFrames(stream.ToArray()));
        int diagnosticLength = BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(10, 2));
        int inputLength = checked((int)ReadUInt32(frame, 64));
        int replyLength = checked((int)ReadUInt32(frame, 68));
        int replyOffset = AdmissionEvidenceFrames.RawCallHeaderBytes + diagnosticLength + inputLength;
        Assert.Equal(unchecked((int)0x800704D5), ReadInt32(frame, 56));
        Assert.Equal(19u, ReadUInt32(frame, 60));
        Assert.Equal((byte)0x01, frame[8]);
        Assert.True((frame[8] & 0x01) != 0); // test seam supplied actual bytes
        Assert.False((frame[8] & 0x02) != 0); // native failure makes length unavailable
        Assert.Equal(actualBytesReturnedByTestSeam, frame.AsSpan(replyOffset, replyLength).ToArray());
    }

    [Fact]
    public void SenderRejectsMutatorsAndUnboundedPagesBeforeNativeSend()
    {
        using var handle = new SafeFileHandle(new IntPtr(51), ownsHandle: false);
        var native = new FakeNativeSender(new byte[16]);
        using FilterPort port = FilterPort.CreateForTesting(handle, native);
        int initialCalls = native.Commands.Count;

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            port.SendAdmissionEvidence((AdmissionEvidenceCommand)13));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            port.SendAdmissionEvidence(AdmissionEvidenceCommand.ActivatingStatus, 20481));
        Assert.Equal(initialCalls, native.Commands.Count);
    }

    private static List<byte[]> ReadFrames(byte[] stream)
    {
        var frames = new List<byte[]>();
        int offset = 0;
        while (offset < stream.Length)
        {
            Assert.True(stream.Length - offset >= 4);
            uint bodyLength = BinaryPrimitives.ReadUInt32LittleEndian(stream.AsSpan(offset, 4));
            Assert.InRange(bodyLength, 8u, 64u * 1024u);
            int size = checked((int)bodyLength);
            Assert.True(stream.Length - offset - 4 >= size);
            frames.Add(stream.AsSpan(offset + 4, size).ToArray());
            offset += 4 + size;
        }
        return frames;
    }

    private static uint ReadUInt32(byte[] body, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(offset, 4));

    private static int ReadInt32(byte[] body, int offset) =>
        BinaryPrimitives.ReadInt32LittleEndian(body.AsSpan(offset, 4));

    private static AdmissionEvidenceRequest MakeRequest(
        Guid run,
        Guid request,
        AdmissionEvidenceHook hook,
        byte[] fileId) => AdmissionEvidenceRequest.Parse(
            AdmissionEvidenceRequest.EncodeForTest(run, request, hook,
                NativeVolumeGuid, 0x1234567890abcdeful, fileId));

    private sealed class BlockingAfterFirstWriteStream : Stream
    {
        private readonly MemoryStream _written = new();
        private readonly TaskCompletionSource<bool> _blockedWriteStarted =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _writeCount;

        internal Task BlockedWriteStarted => _blockedWriteStarted.Task;
        internal byte[] ToArray() => _written.ToArray();

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref _writeCount) == 1)
            {
                await _written.WriteAsync(buffer, cancellationToken);
                return;
            }

            _blockedWriteStarted.TrySetResult(true);
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _written.Dispose();
            base.Dispose(disposing);
        }
    }

    private sealed class FakeNativeSender : IAdmissionEvidenceNativeSender
    {
        private readonly byte[] _targetFileId;
        private readonly bool _retryFirstActivatingPage;
        private readonly bool _changeEpochOnFinalStatus;
        private readonly bool _failInitialEpoch;
        private readonly int _targetEntryCopies;
        private readonly int _volumeGuidCopies;
        private readonly uint? _malformedReservedFlagsAtGlobalIndex;
        private int _activatingCalls;
        private int _epochCalls;
        private int _blockNextVolume;

        internal FakeNativeSender(
            byte[] targetFileId,
            bool retryFirstActivatingPage = false,
            bool changeEpochOnFinalStatus = false,
            bool failInitialEpoch = false,
            int targetEntryCopies = 1,
            int volumeGuidCopies = 1,
            uint? malformedReservedFlagsAtGlobalIndex = null)
        {
            if (targetEntryCopies < 0 || targetEntryCopies > 32)
                throw new ArgumentOutOfRangeException(nameof(targetEntryCopies));
            if (volumeGuidCopies < 0 || volumeGuidCopies >
                (ServiceEvidenceWire.VolumeStatusBytes - 16) / ServiceEvidenceWire.VolumeEntryBytes)
                throw new ArgumentOutOfRangeException(nameof(volumeGuidCopies));
            _targetFileId = (byte[])targetFileId.Clone();
            _retryFirstActivatingPage = retryFirstActivatingPage;
            _changeEpochOnFinalStatus = changeEpochOnFinalStatus;
            _failInitialEpoch = failInitialEpoch;
            _targetEntryCopies = targetEntryCopies;
            _volumeGuidCopies = volumeGuidCopies;
            _malformedReservedFlagsAtGlobalIndex = malformedReservedFlagsAtGlobalIndex;
        }

        internal ConcurrentQueue<AdmissionEvidenceCommand> RecordedCommands { get; } = new();
        internal IReadOnlyCollection<AdmissionEvidenceCommand> Commands => RecordedCommands.ToArray();
        internal ManualResetEventSlim BlockEntered { get; } = new(false);
        internal ManualResetEventSlim ReleaseBlockedSend { get; } = new(false);
        internal int LastSnapshotEntryCount { get; private set; }
        internal uint[] SuccessfulActivatingStarts => SuccessfulPages
            .Where(page => page.HResult == 0)
            .Select(page => page.Start)
            .ToArray();
        private ConcurrentQueue<(uint Start, int HResult)> SuccessfulPages { get; } = new();

        internal void BlockNextVolumeSend() => Interlocked.Exchange(ref _blockNextVolume, 1);

        public int Send(SafeFileHandle handle, ReadOnlyMemory<byte> input, Memory<byte> output, out uint bytesReturned)
        {
            _ = handle;
            AdmissionEvidenceCommand command = (AdmissionEvidenceCommand)
                BinaryPrimitives.ReadUInt32LittleEndian(input.Span.Slice(8, 4));
            uint startIndex = BinaryPrimitives.ReadUInt32LittleEndian(input.Span.Slice(12, 4));
            RecordedCommands.Enqueue(command);
            bytesReturned = 0;

            if (command == AdmissionEvidenceCommand.VolumeObserve &&
                Interlocked.Exchange(ref _blockNextVolume, 0) == 1)
            {
                BlockEntered.Set();
                ReleaseBlockedSend.Wait();
            }

            if (command == AdmissionEvidenceCommand.EpochStatus && _failInitialEpoch &&
                Interlocked.CompareExchange(ref _epochCalls, 1, 0) == 0)
            {
                return unchecked((int)0x800704D5);
            }

            if (command == AdmissionEvidenceCommand.ActivatingStatus &&
                _retryFirstActivatingPage && Interlocked.Increment(ref _activatingCalls) == 1)
            {
                SuccessfulPages.Enqueue((startIndex, unchecked((int)0x800704D5)));
                return unchecked((int)0x800704D5);
            }

            byte[] response = command switch
            {
                AdmissionEvidenceCommand.EpochStatus => BuildEpoch(),
                AdmissionEvidenceCommand.VolumeObserve => BuildVolume(),
                AdmissionEvidenceCommand.ActivatingStatus => BuildPage(startIndex),
                _ => throw new InvalidOperationException("Unexpected control in fake evidence sender."),
            };
            response.AsMemory().CopyTo(output);
            bytesReturned = checked((uint)response.Length);
            if (command == AdmissionEvidenceCommand.ActivatingStatus)
            {
                SuccessfulPages.Enqueue((startIndex, 0));
                LastSnapshotEntryCount = Math.Max(33, 32 + _targetEntryCopies);
            }
            return 0;
        }

        private byte[] BuildEpoch()
        {
            int number = Interlocked.Increment(ref _epochCalls);
            var response = new byte[ServiceEvidenceWire.EpochBytes];
            BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(0, 4), ServiceEvidenceWire.EpochBytes);
            uint policy = _changeEpochOnFinalStatus && number == 3 ? 8u : 7u;
            uint epoch = _changeEpochOnFinalStatus && number == 3 ? 5u : 4u;
            BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(4, 4), policy);
            BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(8, 4), epoch);
            BinaryPrimitives.WriteUInt64LittleEndian(response.AsSpan(24, 8), number == 3 ? 10ul : 9ul);
            return response;
        }

        private byte[] BuildVolume()
        {
            var response = new byte[ServiceEvidenceWire.VolumeStatusBytes];
            BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(0, 4), ServiceEvidenceWire.VolumeStatusBytes);
            BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(4, 4), checked((uint)_volumeGuidCopies));
            for (int index = 0; index < _volumeGuidCopies; index++)
            {
                int entry = 16 + index * ServiceEvidenceWire.VolumeEntryBytes;
                BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(entry + ServiceEvidenceWire.VolumeGuidCharsOffset, 4),
                    checked((uint)NativeVolumeGuid.Length));
                WriteUtf16(response.AsSpan(entry + ServiceEvidenceWire.VolumeGuidOffset), NativeVolumeGuid);
            }
            return response;
        }

        private byte[] BuildPage(uint start)
        {
            uint total = checked((uint)Math.Max(33, 32 + _targetEntryCopies));
            uint count = Math.Min((uint)AdmissionEvidenceLimits.ActivatingPageEntries, total - start);
            uint next = start + count;
            var response = new byte[ServiceEvidenceWire.ActivatingPageBytes];
            BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(0, 4), ServiceEvidenceWire.ActivatingPageBytes);
            BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(4, 4), total);
            BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(8, 4), count);
            BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(12, 4), start);
            BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(16, 4), next);
            BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(20, 4), 7);
            BinaryPrimitives.WriteUInt64LittleEndian(response.AsSpan(24, 8), 9);

            for (uint i = 0; i < count; i++)
            {
                uint globalIndex = start + i;
                int entry = ServiceEvidenceWire.ActivatingHeaderBytes +
                    checked((int)i * ServiceEvidenceWire.ActivatingEntryBytes);
                BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(entry + 96, 4), 0);
                if (_malformedReservedFlagsAtGlobalIndex == globalIndex)
                    BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(entry + 56, 4), 1);
                if (_targetEntryCopies != 0 && globalIndex >= 32 &&
                    globalIndex < (uint)(32 + _targetEntryCopies))
                {
                    BinaryPrimitives.WriteUInt64LittleEndian(response.AsSpan(entry, 8), 0x1234567890abcdef);
                    _targetFileId.CopyTo(response.AsSpan(entry + 8, 16));
                    BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(entry + 24, 4), 7);
                    BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(entry + 28, 4), 1);
                    BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(entry + 32, 4), 0);
                }
            }
            return response;
        }

        private static void WriteUtf16(Span<byte> destination, string value)
        {
            for (int index = 0; index < value.Length; index++)
                BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(index * 2, 2), value[index]);
        }
    }
#endif
}
