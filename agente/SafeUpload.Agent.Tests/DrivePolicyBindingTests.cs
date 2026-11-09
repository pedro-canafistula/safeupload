using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Service.Notifications;
using SafeUpload.Agent.Service.Policies;
using SafeUpload.Agent.Drive;
using Microsoft.Extensions.Logging.Abstractions;

namespace SafeUpload.Agent.Tests;

public sealed partial class DrivePublicationTests
{
    [Fact]
    public void Policy_change_can_reinspect_and_publish_clean_bytes_without_modifying_the_file()
    {
        using var f = Create("Clean unchanged stage");
        f.Inspect();
        f.Store.Current = f.Policy with { Version = 2 };
        f.Reconcile();
        Assert.Empty(f.Observer.Publications);
        f.Inspect();
        Assert.Equal(1, f.Content.Version);
        Assert.Equal(2, f.Observer.Decisions[1].Result!.PolicyVersion);
        f.Reconcile();
        Assert.True(Assert.Single(f.Observer.Publications).Succeeded);
        Assert.Equal("Clean unchanged stage", File.ReadAllText(f.Target));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Policy_binding_preserves_explicit_unmonitored_extensions_and_excluded_processes(bool excluded)
    {
        using var f = Create("Clean bytes");
        string target = f.Target;
        if (excluded) f.Store.Current = f.Policy with { ExcludedProcesses = new HashSet<string> { "explorer.exe" } };
        else
        {
            File.WriteAllBytes(f.Content.Path, [0, 1, 2]);
            f.Content.Size = 3;
            Assert.Equal(0, f.FileSystem.Open(@"\report.txt", 0, 0, out var node, out var handle, out _, out _));
            try { Assert.Equal(0, f.FileSystem.Rename(node, handle, @"\report.txt", @"\report.bin", true)); }
            finally { f.FileSystem.Close(node, handle); }
            target = Path.Combine(Path.GetDirectoryName(f.Target)!, "report.bin");
        }
        f.Inspect();
        var decision = Assert.Single(f.Observer.Decisions);
        Assert.True(decision.Approved);
        Assert.Equal(excluded ? "excluded_process" : "out_of_scope", decision.Result!.Reason);
        Assert.NotNull(decision.Result.PolicyContentFingerprint);
        f.Reconcile();
        Assert.True(Assert.Single(f.Observer.Publications).Succeeded);
        Assert.Equal(File.ReadAllBytes(f.Content.Path), File.ReadAllBytes(target));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Malformed_monitored_docx_is_retained_regardless_of_zip_scope(bool monitorZip)
    {
        using var f = Create("unused", alert: true, name: "report.DOCX");
        File.Delete(f.Target);
        byte[] bytes = [0x50, 0x4B, 0x03, 0x04, 0x0A, 0x14, 0x1E];
        File.WriteAllBytes(f.Content.Path, bytes);
        f.Content.Size = bytes.Length;
        var extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".txt", ".docx" };
        if (monitorZip) extensions.Add(".zip");
        f.Store.Current = f.Policy with { MonitoredScopes = f.Policy.MonitoredScopes with { Extensions = extensions } };

        f.Inspect();
        var decision = Assert.Single(f.Observer.Decisions);
        Assert.False(decision.Approved);
        Assert.Equal(Verdict.Blocked, decision.Result!.Verdict);
        Assert.StartsWith("parse_error:", decision.Result.Reason);
        await f.Service.HandleDecisionAsync(decision, f.Policy, kind => f.FileSystem.Approve(decision.VersionId, kind));
        f.Reconcile();

        Assert.Empty(f.Observer.Publications);
        Assert.False(File.Exists(f.Target));
        Assert.Equal(bytes, File.ReadAllBytes(f.Content.Path));
        var audit = Assert.Single(await f.Pending());
        Assert.Equal(Verdict.Blocked, audit.Verdict);
        Assert.Equal("report.DOCX", audit.FileName);
        Assert.StartsWith("parse_error:", audit.NotInspectedReason);
        Assert.Null(audit.PublishedSha256Hex);
    }

    [Theory]
    [InlineData(".zip", true)]
    [InlineData(".zip", false)]
    [InlineData(".docx", true)]
    [InlineData(".docx", false)]
    public void Valid_clean_files_are_published_with_the_expected_scope(string extension, bool monitored)
    {
        using var f = Create("unused", name: "report" + extension);
        byte[] bytes = extension == ".zip"
            ? ArchiveFixture.Zip(ArchiveFixture.Text("report.txt", "Clean content"))
            : File.ReadAllBytes(_workspace.WriteWordDocument("fixture.docx", "Clean content"));
        File.WriteAllBytes(f.Content.Path, bytes);
        f.Content.Size = bytes.Length;
        var extensions = new HashSet<string> { monitored ? extension : ".txt" };
        f.Store.Current = f.Policy with { MonitoredScopes = f.Policy.MonitoredScopes with { Extensions = extensions } };

        f.Inspect();
        var decision = Assert.Single(f.Observer.Decisions);
        Assert.True(decision.Approved);
        Assert.Equal(monitored ? Verdict.Approved : Verdict.AllowedWithoutInspection, decision.Result!.Verdict);
        Assert.Equal(monitored ? null : "out_of_scope", decision.Result.Reason);
        f.Reconcile();

        Assert.True(Assert.Single(f.Observer.Publications).Succeeded);
        Assert.Equal(bytes, File.ReadAllBytes(f.Target));
    }

    [Theory]
    [InlineData("~WRL0001.tmp", true)]
    [InlineData("1A2B3C4D", false)]
    public void Office_temporary_names_are_inspected_by_content(string name, bool word)
    {
        using var f = Create("unused", name: name);
        const string sensitive = "CPF: 529.982.247-25";
        var office = word ? _workspace.WriteWordDocument("fixture.docx", sensitive)
            : _workspace.WriteSpreadsheet("fixture.xlsx", sensitive);
        File.Copy(office, f.Content.Path, overwrite: true);
        f.Content.Size = new FileInfo(office).Length;
        f.Store.Current = f.Policy with
        {
            MonitoredScopes = f.Policy.MonitoredScopes with { Extensions = new HashSet<string> { ".docx", ".xlsx" } }
        };

        f.Inspect();
        var decision = Assert.Single(f.Observer.Decisions);
        Assert.False(decision.Approved);
        Assert.Contains(Category.Cpf, decision.Result!.Categories);
        f.Reconcile();
        Assert.Empty(f.Observer.Publications);
        Assert.Equal("Previous bytes", File.ReadAllText(f.Target));
    }

    [Fact]
    public async Task Policy_removed_destination_is_retained_without_offering_a_justification()
    {
        using var f = Create("Clean bytes");
        f.Inspect();
        f.Store.Current = f.Policy with { MonitoredScopes = f.Policy.MonitoredScopes with { RemovableDrives = false } };
        f.Reconcile();
        f.Inspect();
        var decision = f.Observer.Decisions[1];
        Assert.False(decision.Approved);
        await f.Service.HandleDecisionAsync(decision, f.Policy, kind => f.FileSystem.Approve(decision.VersionId, kind));
        Assert.False(f.Justifications.TryConsume(decision.VersionId.ToString(), 7, decision.Writer!.UserSid,
            PolicyContentFingerprint.Compute(f.Policy), out _));
        f.Reconcile();
        Assert.Empty(f.Observer.Publications);
        Assert.Equal("Previous bytes", File.ReadAllText(f.Target));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Policy_change_before_copy_retains_bytes_and_reinspects_even_without_a_new_version(bool newVersion)
    {
        using var f = Create("CPF: 529.982.247-25");
        f.Store.Current = f.Policy with { ActiveCategories = new HashSet<Category> { Category.Secret } };
        f.Inspect();
        Assert.True(Assert.Single(f.Observer.Decisions).Approved);
        f.Store.Current = f.Policy with
        {
            Version = newVersion ? 2 : 1,
            ActiveCategories = new HashSet<Category> { Category.Cpf }
        };
        f.Reconcile();
        Assert.Empty(f.Observer.Publications);
        Assert.Equal("Previous bytes", File.ReadAllText(f.Target));
        Assert.True(File.Exists(f.Content.Path));
        f.Inspect();
        Assert.Equal(2, f.Observer.Decisions.Count);
        Assert.False(f.Observer.Decisions[1].Approved);
        f.Reconcile();
        Assert.Empty(f.Observer.Publications);
    }

    [Fact]
    public void Policy_change_during_copy_discards_only_the_temporary_and_never_replaces_the_destination()
    {
        using var f = Create("Clean bytes");
        f.Inspect();
        f.Store.BeforeLoad = () =>
        {
            if (Directory.GetFiles(Path.GetDirectoryName(f.Target)!, ".~su-*").Length > 0)
                f.Store.Current = f.Policy with { Version = 2 };
        };
        f.Reconcile();
        Assert.Empty(f.Observer.Publications);
        Assert.Equal("Previous bytes", File.ReadAllText(f.Target));
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(f.Target)!, ".~su-*"));
        Assert.True(File.Exists(f.Content.Path));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Policy_read_failure_preserves_approval_and_retries_when_the_same_policy_recovers(bool duringCopy)
    {
        using var f = Create("Clean recovered bytes");
        f.Inspect();
        var snapshot = f.Content.ApprovedSnapshot;
        var failure = new InvalidPolicyException("Synthetic unavailable policy");
        if (duringCopy) f.Store.BeforeLoad = () =>
        {
            if (Directory.GetFiles(Path.GetDirectoryName(f.Target)!, ".~su-*").Length > 0) f.Store.Failure = failure;
        };
        else f.Store.Failure = failure;
        f.Reconcile();
        Assert.Empty(f.Observer.Publications);
        Assert.Equal("Previous bytes", File.ReadAllText(f.Target));
        Assert.Equal(snapshot, f.Content.ApprovedSnapshot);
        Assert.True(File.Exists(snapshot));
        f.Store.Failure = null;
        f.Store.BeforeLoad = null;
        f.Reconcile();
        Assert.True(Assert.Single(f.Observer.Publications).Succeeded);
    }

    [Fact]
    public void Policy_change_after_queued_justification_revokes_the_old_authorization()
    {
        using var f = Create("CPF: 529.982.247-25");
        f.Inspect();
        Assert.True(f.FileSystem.Approve(Assert.Single(f.Observer.Decisions).VersionId));
        f.Store.Current = f.Policy with { OverrideAllowed = false };
        f.Reconcile();
        Assert.Empty(f.Observer.Publications);
        Assert.Equal("Previous bytes", File.ReadAllText(f.Target));
        f.Inspect();
        Assert.False(f.Observer.Decisions[1].Approved);
    }

    [Theory]
    [InlineData("version")]
    [InlineData("same-version-content")]
    [InlineData("override-disabled")]
    public async Task Policy_change_before_a_justification_rejects_it_without_recording_an_override(string change)
    {
        using var f = Create("CPF: 529.982.247-25");
        f.Inspect();
        var decision = Assert.Single(f.Observer.Decisions);
        await f.Service.HandleDecisionAsync(decision, f.Policy, kind => f.FileSystem.Approve(decision.VersionId, kind));
        f.Store.Current = change switch
        {
            "version" => f.Policy with { Version = 2 },
            "override-disabled" => f.Policy with { OverrideAllowed = false },
            _ => f.Policy with { MaxFileSizeMb = f.Policy.MaxFileSizeMb + 1 }
        };
        using var server = new JustificationPipeServer(f.Store, f.Sink, f.Justifications,
            NullLogger<JustificationPipeServer>.Instance);
        Assert.False(await server.HandleAsync(new JustificationRequest(decision.VersionId.ToString(), "Synthetic reason"),
            7, decision.Writer!.UserSid, CancellationToken.None));
        Assert.Empty(await f.Sink.ReadPendingOverridesAsync(10, CancellationToken.None));
        Assert.Null(f.Content.ApprovedSnapshot);
    }

    [Theory]
    [InlineData("version")]
    [InlineData("same-version-content")]
    [InlineData("override-disabled")]
    [InlineData("unavailable")]
    [InlineData("cancelled")]
    public async Task Policy_is_rechecked_after_override_audit_and_a_refusal_keeps_the_audit_record(string change)
    {
        using var f = Create("CPF: 529.982.247-25");
        using var stop = new CancellationTokenSource();
        f.Inspect();
        var decision = Assert.Single(f.Observer.Decisions);
        bool approved = false;
        await f.Service.HandleDecisionAsync(decision, f.Policy, kind =>
        {
            approved = true;
            return f.FileSystem.Approve(decision.VersionId, kind);
        });
        var audit = new OverrideHook(f.Sink, () =>
        {
            switch (change)
            {
                case "version": f.Store.Current = f.Policy with { Version = 2 }; break;
                case "same-version-content": f.Store.Current = f.Policy with { MaxFileSizeMb = 11 }; break;
                case "override-disabled": f.Store.Current = f.Policy with { OverrideAllowed = false }; break;
                case "unavailable": f.Store.Failure = new InvalidPolicyException("Synthetic unreadable policy"); break;
                case "cancelled": stop.Cancel(); break;
            }
        });
        using var server = new JustificationPipeServer(f.Store, audit, f.Justifications,
            NullLogger<JustificationPipeServer>.Instance);
        Task<bool> Submit() => server.HandleAsync(new JustificationRequest(decision.VersionId.ToString(), "Synthetic reason"),
            7, decision.Writer!.UserSid, stop.Token);
        if (change == "cancelled") await Assert.ThrowsAnyAsync<OperationCanceledException>(Submit);
        else if (change == "unavailable") await Assert.ThrowsAsync<InvalidPolicyException>(Submit);
        else Assert.False(await Submit());
        Assert.False(approved);
        Assert.Null(f.Content.ApprovedSnapshot);
        Assert.Equal(decision.VersionId, Assert.Single(await f.Sink.ReadPendingOverridesAsync(10, CancellationToken.None)).EventId);
        f.Reconcile();
        Assert.Empty(f.Observer.Publications);
    }

    [Theory]
    [InlineData(7u, "S-1-5-21-111-222-333-9999")]
    [InlineData(8u, "S-1-5-21-111-222-333-1001")]
    public async Task Policy_binding_keeps_session_identity_and_single_use_checks(uint session, string sid)
    {
        using var f = Create("CPF: 529.982.247-25");
        f.Inspect();
        var decision = Assert.Single(f.Observer.Decisions);
        await f.Service.HandleDecisionAsync(decision, f.Policy, kind => f.FileSystem.Approve(decision.VersionId, kind));
        using var server = new JustificationPipeServer(f.Store, f.Sink, f.Justifications,
            NullLogger<JustificationPipeServer>.Instance);
        var request = new JustificationRequest(decision.VersionId.ToString(), "Synthetic reason");
        Assert.False(await server.HandleAsync(request, session, sid, CancellationToken.None));
        Assert.Empty(await f.Sink.ReadPendingOverridesAsync(10, CancellationToken.None));
        Assert.True(await server.HandleAsync(request, 7, decision.Writer!.UserSid, CancellationToken.None));
        Assert.False(await server.HandleAsync(request, 7, decision.Writer.UserSid, CancellationToken.None));
        Assert.Single(await f.Sink.ReadPendingOverridesAsync(10, CancellationToken.None));
        Assert.Empty(f.Observer.Publications);
        f.Reconcile();
        Assert.True(Assert.Single(f.Observer.Publications).Succeeded);
    }

    [Fact]
    public async Task Policy_changed_to_alertar_does_not_release_a_block_from_a_different_policy()
    {
        using var f = Create("CPF: 529.982.247-25");
        f.Inspect();
        var decision = Assert.Single(f.Observer.Decisions);
        f.Store.Current = f.Policy with { AuditOnly = true };
        bool called = false;
        await f.Service.HandleDecisionAsync(decision, f.Policy, _ => { called = true; return true; });
        Assert.False(called);
        Assert.Equal(Verdict.Blocked, Assert.Single(await f.Pending()).Verdict);
        Assert.False(f.FileSystem.Approve(decision.VersionId, DriveApprovalKind.Audit));
    }

    [Fact]
    public void Alert_category_releases_a_finding_with_audit()
    {
        using var f = Create("CPF: 529.982.247-25", alertCategories: new HashSet<Category> { Category.Cpf });
        f.Inspect();
        var decision = Assert.Single(f.Observer.Decisions);
        Assert.True(f.FileSystem.Approve(decision.VersionId, DriveApprovalKind.Audit));
    }

    [Fact]
    public void Blocking_category_still_blocks_when_another_category_only_alerts()
    {
        using var f = Create("CPF: 529.982.247-25", alertCategories: new HashSet<Category> { Category.Rg });
        f.Inspect();
        var decision = Assert.Single(f.Observer.Decisions);
        Assert.False(f.FileSystem.Approve(decision.VersionId, DriveApprovalKind.Audit));
    }

    [Fact]
    public void Policy_changed_after_alertar_was_queued_prevents_publication()
    {
        using var f = Create("CPF: 529.982.247-25", alert: true);
        f.Inspect();
        var decision = Assert.Single(f.Observer.Decisions);
        Assert.True(f.FileSystem.Approve(decision.VersionId, DriveApprovalKind.Audit));
        f.Store.Current = f.Policy with { AuditOnly = false };
        f.Reconcile();
        Assert.Empty(f.Observer.Publications);
        Assert.Equal("Previous bytes", File.ReadAllText(f.Target));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Policy_snapshot_allows_offline_publication_without_a_per_file_remote_request(bool justified)
    {
        var remote = new OfflinePolicy();
        RefreshingPolicyStore? snapshot = null;
        var bytes = justified ? "CPF: 529.982.247-25" : "Offline clean bytes";
        using var f = Create(bytes, wrapPolicy: cached => snapshot = new RefreshingPolicyStore(remote,
            cached.LoadAsync, TimeSpan.FromHours(1), NullLogger<RefreshingPolicyStore>.Instance));
        f.Inspect();
        Assert.Equal(0, remote.Calls);
        await Assert.ThrowsAsync<HttpRequestException>(() => snapshot!.RefreshAsync(CancellationToken.None));
        f.Store.Failure = new InvalidPolicyException("Disk is not consulted once the snapshot is loaded");
        if (justified)
        {
            var decision = Assert.Single(f.Observer.Decisions);
            await f.Service.HandleDecisionAsync(decision, f.Policy, kind => f.FileSystem.Approve(decision.VersionId, kind));
            using var server = new JustificationPipeServer(snapshot!, f.Sink, f.Justifications,
                NullLogger<JustificationPipeServer>.Instance);
            Assert.True(await server.HandleAsync(new JustificationRequest(decision.VersionId.ToString(), "Offline reason"),
                7, decision.Writer!.UserSid, CancellationToken.None));
        }
        f.Reconcile();
        Assert.True(Assert.Single(f.Observer.Publications).Succeeded);
        Assert.Equal(bytes, File.ReadAllText(f.Target));
        Assert.Equal(1, remote.Calls);
    }

    private sealed class OfflinePolicy : IPolicyStore
    {
        public int Calls;
        public Task<Policy> LoadAsync(CancellationToken token)
        {
            Calls++;
            throw new HttpRequestException("Synthetic offline server");
        }
    }

    private sealed class OverrideHook(IAuditSink inner, Action afterWrite) : IAuditSink
    {
        public Task WriteAsync(AuditEvent auditEvent, CancellationToken token) => inner.WriteAsync(auditEvent, token);
        public Task RecordOverrideAsync(string eventId, string justification, CancellationToken token)
            => throw new InvalidOperationException("The authenticated override overload must be used");
        public async Task RecordOverrideAsync(AuditOverride record, CancellationToken token)
        {
            await inner.RecordOverrideAsync(record, token);
            afterWrite();
        }
        public Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int max, CancellationToken token) => inner.ReadRecentAsync(max, token);
        public Task<IReadOnlyList<AuditEvent>> ReadPendingAsync(int max, CancellationToken token) => inner.ReadPendingAsync(max, token);
        public Task MarkDispatchedAsync(IReadOnlyCollection<Guid> ids, CancellationToken token) => inner.MarkDispatchedAsync(ids, token);
    }
}
