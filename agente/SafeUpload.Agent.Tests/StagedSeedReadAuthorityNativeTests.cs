using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

[Trait("Category", "NativeWindows")]
public sealed class StagedSeedReadAuthorityNativeTests
{
    [Fact]
    public void Native_readable_current_primary_is_allowed_only_in_the_supported_profile()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var workspace = new TestWorkspace();
        using var identity = WindowsIdentity.GetCurrent();
        string path = workspace.WriteText("readable.txt", "prior bytes");
        var file = new FileInfo(path);
        var security = file.GetAccessControl();
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new FileSystemAccessRule(identity.User!, FileSystemRights.FullControl, AccessControlType.Allow));
        file.SetAccessControl(security);
        // Independent native token queries determine the expectation, not the
        // evaluator's result. A standard medium primary must return Allowed;
        // the elevated user/SYSTEM matrix legs must return Unproven.
        bool eligible = NativeTokenFact(identity.AccessToken, 25) == 0x2000 &&
            NativeTokenFact(identity.AccessToken, 18) == 1 && NativeTokenFact(identity.AccessToken, 20) == 0 &&
            NativeTokenFact(identity.AccessToken, 21) == 0 && NativeTokenFact(identity.AccessToken, 29) == 0;
        Assert.True(DuplicateToken(identity.AccessToken, 2, out var subject));
        using (subject)
        {
            Assert.True(LookupPrivilegeValue(null, "SeChangeNotifyPrivilege", out long luid));
            var privilege = new PrivilegeSet { Count = 1, Control = 1, Luid = luid, Attributes = 2 };
            Assert.True(PrivilegeCheck(subject, ref privilege, out bool traverses));
            eligible &= traverses;
        }
        using var source = StagedStageFile.Open(path);
        Assert.Equal(eligible ? StagedSeedAuthority.Allowed : StagedSeedAuthority.Unproven,
            new StagedSeedReadAuthorityEvaluator().Evaluate(CurrentRequestor(path), source.Stream.SafeFileHandle));
    }

    private static int NativeTokenFact(SafeAccessTokenHandle token, int informationClass)
    {
        IntPtr buffer = Marshal.AllocHGlobal(4096);
        try
        {
            Assert.True(GetTokenInformation(token, informationClass, buffer, 4096, out _));
            return informationClass == 25 ? int.Parse(new SecurityIdentifier(Marshal.ReadIntPtr(buffer)).Value.Split('-')[3]) :
                Marshal.ReadInt32(buffer);
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    // Owner decision 2026-10-21 (option A): read access Windows grants through a group counts as read authority, so the
    // verdict is the real token's AccessCheck on the descriptor: own SID or a group the token holds (Everyone, Authenticated
    // Users) allow; any applicable deny, or a grant only to some other SID, does not.
    [Theory]
    [InlineData("(A;;0x1;;;{sid})", StagedSeedAuthority.Allowed)]
    [InlineData("(A;;0x1;;;WD)", StagedSeedAuthority.Allowed)]
    [InlineData("(A;;0x1;;;AU)", StagedSeedAuthority.Allowed)]
    [InlineData("(D;;0x1;;;{sid})(A;;0x1;;;{sid})", StagedSeedAuthority.Denied)]
    [InlineData("(D;;0x1;;;WD)(A;;0x1;;;{sid})", StagedSeedAuthority.Denied)]
    [InlineData("(A;;0x1;;;S-1-5-21-111-222-333-1000)", StagedSeedAuthority.Denied)]
    [InlineData("(A;;0x2;;;WD)", StagedSeedAuthority.Denied)]
    public void Native_AccessCheck_read_data_uses_the_supplied_token_and_descriptor(string dacl, StagedSeedAuthority expected)
    {
        if (!OperatingSystem.IsWindows()) return;
        using var identity = WindowsIdentity.GetCurrent();
        string sid = identity.User!.Value;
        var descriptor = new RawSecurityDescriptor("O:SYG:SYD:" + dacl.Replace("{sid}", sid));
        byte[] bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0);
        Assert.True(DuplicateToken(identity.AccessToken, 2, out var subject));
        using (subject)
        {
            GCHandle pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try { Assert.Equal(expected, StagedSeedReadAuthorityEvaluator.CheckReadData(pinned.AddrOfPinnedObject(), subject)); }
            finally { pinned.Free(); }
        }
    }

    [Theory]
    [InlineData(0x2000, 1, 0, 0, true, true)]
    [InlineData(0x1000, 1, 0, 0, true, false)]
    [InlineData(0x3000, 1, 0, 0, true, false)]
    [InlineData(0x2000, 3, 0, 0, true, false)]
    [InlineData(0x2000, 1, 1, 0, true, false)]
    [InlineData(0x2000, 1, 0, 1, true, false)]
    [InlineData(0x2000, 1, 0, 0, false, false)]
    [InlineData(0x2000, -1, 0, 0, true, false)]
    public void Export_envelope_keeps_unsupported_primary_subjects_unproven(
        int integrity, int elevationType, int elevated, int restrictions, bool traverse, bool expected)
    {
        Assert.Equal(expected, StagedSeedReadAuthorityEvaluator.ExportEnvelopePermitsProof(
            integrity, elevationType, elevated, restrictions, traverse));
    }

    private static StagedTransfer CurrentRequestor(string path)
    {
        using var process = Process.GetCurrentProcess();
        using var identity = WindowsIdentity.GetCurrent();
        return new(Guid.NewGuid(), path, path, DestinationKind.RemovableDrive, "fixture", process.Id, (uint)process.SessionId)
        {
            RequestorSid = identity.User!.Value,
            RequestorProcessCreationTime = process.StartTime.ToUniversalTime().ToFileTimeUtc()
        };
    }

    [Fact]
    public void Native_descriptor_read_denial_is_not_overridden_by_the_held_service_read_handle()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var workspace = new TestWorkspace();
        string path = workspace.WriteText("source.txt", "service-readable prior bytes");
        var file = new FileInfo(path); var original = file.GetAccessControl();
        using var source = StagedStageFile.Open(path);
        var requestor = CurrentRequestor(path);
        var denied = file.GetAccessControl();
        denied.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(requestor.RequestorSid!),
            FileSystemRights.ReadData, AccessControlType.Deny));
        file.SetAccessControl(denied);
        try
        {
            Assert.Equal(StagedSeedAuthority.Denied,
                new StagedSeedReadAuthorityEvaluator().Evaluate(requestor, source.Stream.SafeFileHandle));
        }
        finally { file.SetAccessControl(original); }
    }

    [Theory]
    [InlineData("pid")]
    [InlineData("lifetime")]
    [InlineData("sid")]
    [InlineData("session")]
    [InlineData("missing-subject")]
    [InlineData("invalid-handle")]
    public void Native_subject_or_source_uncertainty_never_becomes_allowed(string damage)
    {
        if (!OperatingSystem.IsWindows()) return;
        using var workspace = new TestWorkspace();
        string path = workspace.WriteText("source.txt", "prior bytes");
        var requestor = CurrentRequestor(path);
        requestor = damage switch
        {
            "pid" => requestor with { ProcessId = int.MaxValue },
            "lifetime" => requestor with { RequestorProcessCreationTime = requestor.RequestorProcessCreationTime + 1 },
            "sid" => requestor with { RequestorSid = "S-1-5-21-111-222-333-1000" == requestor.RequestorSid ? "S-1-5-18" : "S-1-5-21-111-222-333-1000" },
            "session" => requestor with { SessionId = null },
            "missing-subject" => requestor with { RequestorSid = null },
            _ => requestor
        };
        using var source = StagedStageFile.Open(path);
        using var invalid = new SafeFileHandle(new IntPtr(-1), false);
        Assert.Equal(StagedSeedAuthority.Unproven, new StagedSeedReadAuthorityEvaluator().Evaluate(requestor,
            damage == "invalid-handle" ? invalid : source.Stream.SafeFileHandle));
    }

    [Theory]
    [InlineData("O:SYG:SYD:(A;;FR;;;WD)", 0x2000, true)]
    [InlineData("O:SYG:SYD:(A;;FR;;;WD)", 0x1000, false)]
    [InlineData("O:SYG:SYD:(A;;FR;;;WD)S:(ML;;NW;;;ME)", 0x2000, true)]
    [InlineData("O:SYG:SYD:(A;;FR;;;WD)S:(ML;;NW;;;HI)", 0x2000, false)]
    [InlineData("O:SYG:SYD:(A;;FR;;;WD)S:(ML;;NR;;;ME)", 0x2000, false)]
    [InlineData("O:SYG:SYD:(A;;FR;;;WD)S:(ML;;NW;;;ME)", -1, false)]
    public void Label_proof_refuses_read_up_or_uncertain_integrity(string sddl, int integrity, bool expected)
    {
        if (!OperatingSystem.IsWindows()) return;
        Assert.Equal(expected, StagedSeedReadAuthorityEvaluator.LabelPermitsProof(new RawSecurityDescriptor(sddl), integrity));
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateToken(SafeAccessTokenHandle token, int level, out SafeAccessTokenHandle duplicate);
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct PrivilegeSet { public uint Count, Control; public long Luid; public uint Attributes; }
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int informationClass, IntPtr buffer, int size, out int needed);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(string? system, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PrivilegeCheck(SafeAccessTokenHandle token, ref PrivilegeSet privilege, [MarshalAs(UnmanagedType.Bool)] out bool result);
}
