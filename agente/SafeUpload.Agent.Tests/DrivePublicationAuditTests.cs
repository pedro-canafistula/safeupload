using System.Reflection;
using SafeUpload.Agent.Core.Infrastructure;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Drive;
using SafeUpload.Agent.App.ViewModels;
using System.Text.Json.Nodes;

namespace SafeUpload.Agent.Tests;

public sealed class DrivePublicationAuditTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Publication_survives_lost_observer_callback_and_queue_unavailable_until_restart(bool unavailable)
    {
        using var f = new DriveRecoveryTests.Fixture();
        var content = f.Write(@"\report.txt", "Published and audited after restart");
        Invoke(f.Fs, "InspectOne", content);
        if (unavailable) Directory.CreateDirectory(f.Work.QueueFile);
        Invoke(f.Fs, "Reconcile");
        var sent = Assert.Single(f.Observer.Publications);
        Assert.True(sent.Succeeded);
        Assert.Equal("Published and audited after restart", File.ReadAllText(f.Target));
        f.Fs.Stop();
        if (unavailable) Directory.Delete(f.Work.QueueFile);
        f.Mount();
        var audit = Assert.Single(await new LocalQueueAuditSink(f.Work.QueueFile).ReadPendingAsync(10, default));
        Assert.Equal(sent.EventId, audit.EventId);
        Assert.Equal(f.Target, audit.DestinationPath);
        Assert.Equal(DriveRecoveryTests.Fixture.Sid, audit.OwnerSid);
    }

    [Theory]
    [InlineData(PublicationAuditPhase.Prepared)]
    [InlineData(PublicationAuditPhase.Moved)]
    [InlineData(PublicationAuditPhase.Completed)]
    [InlineData(PublicationAuditPhase.Queued)]
    internal async Task Interruption_at_each_boundary_recovers_one_immutable_event(PublicationAuditPhase phase)
    {
        using var f = new DriveRecoveryTests.Fixture();
        var content = f.Write(@"\report.txt", "Crash boundary version");
        Invoke(f.Fs, "InspectOne", content);
        f.Fs.AuditFault = reached => { if (reached == phase) throw new Crash(); };
        AssertCrash(() => Invoke(f.Fs, "Reconcile"));
        var entry = Assert.Single(Entries(f));
        byte[]? before = File.Exists(f.Work.QueueFile) ? File.ReadAllBytes(f.Work.QueueFile) : null;
        f.Restart();
        var audit = Assert.Single(await Queue(f).ReadRecentAsync(0, default));
        Assert.Equal(entry.Event.EventId, audit.EventId);
        Assert.Equal(entry.Event.OccurredAtUtc, audit.OccurredAtUtc);
        Assert.Equal(entry.Event.OwnerSid, audit.OwnerSid);
        bool confirmed = phase is PublicationAuditPhase.Completed or PublicationAuditPhase.Queued;
        Assert.Equal(confirmed ? Verdict.Approved : Verdict.Blocked, audit.Verdict);
        Assert.Equal(confirmed ? null : "publication_outcome_unknown", audit.NotInspectedReason);
        Assert.Equal(phase == PublicationAuditPhase.Prepared ? "Published old version" : "Crash boundary version", File.ReadAllText(f.Target));
        Assert.Empty(Entries(f));
        if (phase == PublicationAuditPhase.Queued) Assert.Equal(before, File.ReadAllBytes(f.Work.QueueFile));
    }

    [Theory]
    [InlineData("same_bytes_different_id")]
    [InlineData("different_bytes_same_id")]
    [InlineData("missing")]
    [InlineData("old_target_same_bytes")]
    public async Task An_unconfirmed_intent_never_becomes_success_from_hash_or_path_alone(string mode)
    {
        using var f = new DriveRecoveryTests.Fixture();
        var content = f.Write(@"\report.txt", mode == "old_target_same_bytes" ? "Published old version" : "Evidence version");
        Invoke(f.Fs, "InspectOne", content);
        f.Fs.AuditFault = reached => { if (reached == (mode == "old_target_same_bytes" ? PublicationAuditPhase.Prepared : PublicationAuditPhase.Moved)) throw new Crash(); };
        AssertCrash(() => Invoke(f.Fs, "Reconcile"));
        var intent = Assert.Single(Entries(f));
        if (mode == "same_bytes_different_id")
        {
            var replacement = Path.Combine(f.Work.Root, "replacement.txt");
            File.Copy(f.Target, replacement);
            File.Move(replacement, f.Target, true);
        }
        else if (mode == "different_bytes_same_id") File.WriteAllText(f.Target, "Changed after move");
        else if (mode == "missing") File.Delete(f.Target);
        f.Restart();
        var audit = Assert.Single(await Queue(f).ReadRecentAsync(0, default));
        Assert.Equal(intent.Event.EventId, audit.EventId);
        Assert.Equal("publication_outcome_unknown", audit.NotInspectedReason);
        Assert.Equal(Verdict.Blocked, audit.Verdict);
        Assert.Null(audit.PublishedSha256Hex);
        Assert.Equal("NÃO CONFIRMADO", new HistoryRowViewModel(audit).Status.Text);
        Assert.Equal("Não confirmado", new QueueRowViewModel(audit).Verdict);
    }

    [Fact]
    public async Task An_unreadable_target_cannot_convert_an_uncompleted_intent_into_a_success()
    {
        using var f = new DriveRecoveryTests.Fixture();
        var content = f.Write(@"\report.txt", "Temporarily locked evidence");
        Invoke(f.Fs, "InspectOne", content);
        f.Fs.AuditFault = reached => { if (reached == PublicationAuditPhase.Moved) throw new Crash(); };
        AssertCrash(() => Invoke(f.Fs, "Reconcile"));
        var id = Assert.Single(Entries(f)).Event.EventId;
        f.Fs.Stop();
        using (var held = new FileStream(f.Target, FileMode.Open, FileAccess.Read, FileShare.None))
            f.Mount();
        f.Restart();
        var audit = Assert.Single(await Queue(f).ReadRecentAsync(0, default));
        Assert.Equal(id, audit.EventId);
        Assert.Equal("publication_outcome_unknown", audit.NotInspectedReason);
    }

    [Fact]
    public async Task A_durable_completed_result_is_not_rewritten_when_destination_changes_later()
    {
        using var f = new DriveRecoveryTests.Fixture();
        var content = f.Write(@"\report.txt", "Confirmed old publication");
        Invoke(f.Fs, "InspectOne", content);
        f.Fs.AuditFault = reached => { if (reached == PublicationAuditPhase.Completed) throw new Crash(); };
        AssertCrash(() => Invoke(f.Fs, "Reconcile"));
        var original = Assert.Single(Entries(f)).Event;
        File.WriteAllText(f.Target, "A later external version");
        f.Restart();
        var audit = Assert.Single(await Queue(f).ReadRecentAsync(0, default));
        Assert.Equal(original.EventId, audit.EventId);
        Assert.Equal(original.PublishedSha256Hex, audit.PublishedSha256Hex);
        Assert.Equal(Verdict.Approved, audit.Verdict);
        Assert.Equal("A later external version", File.ReadAllText(f.Target));
    }

    [Fact]
    public async Task An_already_dispatched_event_is_not_reenqueued_after_journal_cleanup_interruption()
    {
        using var f = new DriveRecoveryTests.Fixture();
        var content = f.Write(@"\report.txt", "Dispatched publication");
        Invoke(f.Fs, "InspectOne", content);
        f.Fs.AuditFault = reached => { if (reached == PublicationAuditPhase.Queued) throw new Crash(); };
        AssertCrash(() => Invoke(f.Fs, "Reconcile"));
        var id = Assert.Single(Entries(f)).Event.EventId;
        await Queue(f).MarkDispatchedAsync([id], default);
        byte[] before = File.ReadAllBytes(f.Work.QueueFile);
        f.Restart();
        Assert.Equal(before, File.ReadAllBytes(f.Work.QueueFile));
        Assert.Empty(await Queue(f).ReadPendingAsync(10, default));
        Assert.True(Assert.Single(await Queue(f).ReadRecentAsync(0, default)).Dispatched);
    }

    [Fact]
    public async Task Queue_recovery_without_restart_keeps_the_original_id_and_does_not_republish()
    {
        using var f = new DriveRecoveryTests.Fixture();
        var content = f.Write(@"\report.txt", "Retry audit only");
        Invoke(f.Fs, "InspectOne", content);
        Directory.CreateDirectory(f.Work.QueueFile);
        Invoke(f.Fs, "Reconcile");
        var id = Assert.Single(Entries(f)).Event.EventId;
        Directory.Delete(f.Work.QueueFile);
        Invoke(f.Fs, "Reconcile");
        Assert.Equal(id, Assert.Single(await Queue(f).ReadRecentAsync(0, default)).EventId);
        Assert.Single(f.Observer.Publications);
        Assert.Empty(Entries(f));
    }

    [Fact]
    public async Task Failure_then_success_are_replayed_in_journal_order_with_distinct_ids()
    {
        using var f = new DriveRecoveryTests.Fixture();
        var content = f.Write(@"\report.txt", "Retry after destination unlocks");
        Invoke(f.Fs, "InspectOne", content);
        Directory.CreateDirectory(f.Work.QueueFile);
        using (var held = new FileStream(f.Target, FileMode.Open, FileAccess.Read, FileShare.Read))
            Assert.Throws<TargetInvocationException>(() => Invoke(f.Fs, "Reconcile"));
        var failure = Assert.Single(Entries(f));
        Invoke(f.Fs, "Reconcile");
        Assert.Equal(2, Entries(f).Length);
        var success = Entries(f).Single(e => e.Event.EventId != failure.Event.EventId);
        Assert.True(failure.Order < success.Order);
        f.Fs.Stop();
        Directory.Delete(f.Work.QueueFile);
        f.Mount();
        var events = await Queue(f).ReadPendingAsync(10, default);
        Assert.Equal(new[] { failure.Event.EventId, success.Event.EventId }, events.Select(e => e.EventId));
        Assert.Equal("publication_failed", events[0].NotInspectedReason);
        Assert.Equal(Verdict.Approved, events[1].Verdict);
    }

    [Fact]
    public async Task Failed_journal_cleanup_keeps_a_replayable_record_without_duplicating_the_queue()
    {
        using var f = new DriveRecoveryTests.Fixture();
        var content = f.Write(@"\report.txt", "Cleanup retry");
        Invoke(f.Fs, "InspectOne", content);
        FileStream? locked = null;
        f.Fs.AuditFault = phase =>
        {
            if (phase == PublicationAuditPhase.Completed)
                locked = new FileStream(Directory.GetFiles(JournalDirectory(f), "*.json").Single(), FileMode.Open,
                    FileAccess.Read, FileShare.Read);
        };
        try
        {
            Invoke(f.Fs, "Reconcile");
            Assert.Single(Entries(f));
            Assert.Single(await Queue(f).ReadRecentAsync(0, default));
        }
        finally { locked?.Dispose(); }
        f.Restart();
        Assert.Empty(Entries(f));
        Assert.Single(await Queue(f).ReadRecentAsync(0, default));
    }

    [Theory]
    [InlineData("truncated")]
    [InlineData("format")]
    [InlineData("state")]
    [InlineData("id")]
    [InlineData("order")]
    [InlineData("hash")]
    [InlineData("target")]
    [InlineData("temporary")]
    [InlineData("destination")]
    [InlineData("backing")]
    [InlineData("empty_hash")]
    public async Task Invalid_or_mismatched_pending_evidence_blocks_recovery_without_deleting_the_record(string mode)
    {
        using var f = new DriveRecoveryTests.Fixture();
        var content = f.Write(@"\report.txt", "Journal kept for repair");
        Invoke(f.Fs, "InspectOne", content);
        f.Fs.AuditFault = reached => { if (reached == PublicationAuditPhase.Prepared) throw new Crash(); };
        AssertCrash(() => Invoke(f.Fs, "Reconcile"));
        f.Fs.Stop();
        string path = Directory.GetFiles(JournalDirectory(f), "*.json").Single();
        byte[] original = File.ReadAllBytes(path);
        var json = JsonNode.Parse(original)!;
        switch (mode)
        {
            case "format": json["Format"] = 2; break;
            case "state": json["State"] = "unrecognized"; break;
            case "id": json["Event"]!["EventId"] = Guid.NewGuid(); break;
            case "order": json["Order"] = 0; break;
            case "hash": json["Event"]!["PublishedSha256Hex"] = "not-a-sha256"; break;
            case "target": json["RelativeTarget"] = @"..\outside.txt"; break;
            case "temporary": json["TemporaryName"] = @"..\outside.txt"; break;
            case "destination": json["DestinationIdentity"] = "another-volume"; break;
            case "backing": json["Backing"] = Path.Combine(f.Work.Root, "elsewhere"); break;
            case "empty_hash": json["Event"]!["PublishedSha256Hex"] = null; break;
        }
        string damaged = mode == "truncated" ? "{" : json.ToJsonString();
        File.WriteAllText(path, damaged);
        var error = Record.Exception(f.Mount);
        Assert.True(error is IOException or JsonException, error?.ToString());
        Assert.Equal(damaged, File.ReadAllText(path));
        Assert.Equal("Published old version", File.ReadAllText(f.Target));
        Assert.Equal("Journal kept for repair", File.ReadAllText(content.Path));
        File.WriteAllBytes(path, original);
        f.Mount();
        Assert.Equal("publication_outcome_unknown", Assert.Single(await Queue(f).ReadRecentAsync(0, default)).NotInspectedReason);
    }

    [Fact]
    public async Task A_conflicting_queue_event_preserves_both_records_until_repaired()
    {
        using var f = new DriveRecoveryTests.Fixture();
        var content = f.Write(@"\report.txt", "Conflicting queue id");
        Invoke(f.Fs, "InspectOne", content);
        f.Fs.AuditFault = reached => { if (reached == PublicationAuditPhase.Queued) throw new Crash(); };
        AssertCrash(() => Invoke(f.Fs, "Reconcile"));
        var original = Assert.Single(Entries(f)).Event;
        File.WriteAllText(f.Work.QueueFile, "");
        await Queue(f).WriteAsync(original with { UserName = "different-user" }, default);
        var before = File.ReadAllBytes(f.Work.QueueFile);
        f.Restart();
        Assert.Single(Entries(f));
        Assert.Equal(before, File.ReadAllBytes(f.Work.QueueFile));
        File.WriteAllText(f.Work.QueueFile, "");
        await Queue(f).WriteAsync(original, default);
        f.Restart();
        Assert.Empty(Entries(f));
        Assert.Single(await Queue(f).ReadRecentAsync(0, default));
    }

    [Fact]
    public async Task Policy_change_after_preparation_cancels_the_intent_without_publishing_or_auditing_success()
    {
        using var f = new DriveRecoveryTests.Fixture();
        var content = f.Write(@"\report.txt", "Policy changes before move");
        Invoke(f.Fs, "InspectOne", content);
        f.Fs.AuditFault = reached =>
        {
            if (reached == PublicationAuditPhase.Prepared) f.Policies.Current = f.Policies.Current with { Version = 2 };
        };
        Invoke(f.Fs, "Reconcile");
        Assert.Empty(Entries(f));
        Assert.Empty(f.Observer.Publications);
        Assert.Empty(await Queue(f).ReadRecentAsync(0, default));
        Assert.Equal("Published old version", File.ReadAllText(f.Target));
        Invoke(f.Fs, "InspectOne", content);
        Invoke(f.Fs, "Reconcile");
        Assert.Equal(2, Assert.Single(await Queue(f).ReadRecentAsync(0, default)).PolicyVersion);
    }

    [Fact]
    public void Failure_to_persist_an_intent_holds_the_file_before_the_destination_is_replaced()
    {
        using var f = new DriveRecoveryTests.Fixture();
        var content = f.Write(@"\report.txt", "Held before move");
        Invoke(f.Fs, "InspectOne", content);
        string directory = JournalDirectory(f), original = Path.Combine(f.Private, "saved-journal-directory");
        Directory.Move(directory, original);
        File.WriteAllText(directory, "blocked journal path");
        try
        {
            var wrapped = Assert.Throws<TargetInvocationException>(() => Invoke(f.Fs, "Reconcile"));
            Assert.True(wrapped.InnerException is IOException or UnauthorizedAccessException);
            Assert.Equal("Published old version", File.ReadAllText(f.Target));
            Assert.Empty(f.Observer.Publications);
            Assert.Equal("Held before move", File.ReadAllText(content.Path));
        }
        finally { File.Delete(directory); Directory.Move(original, directory); }
        Invoke(f.Fs, "Reconcile");
        Assert.True(Assert.Single(f.Observer.Publications).Succeeded);
    }

    [Fact]
    public void The_journal_contains_audit_metadata_and_evidence_without_file_contents_or_raw_decision_diagnostics()
    {
        using var f = new DriveRecoveryTests.Fixture();
        var content = f.Write(@"\report.txt", "PRIVATE-PAYLOAD-NEVER-PERSIST-IN-METADATA");
        Invoke(f.Fs, "InspectOne", content);
        f.Fs.AuditFault = reached => { if (reached == PublicationAuditPhase.Prepared) throw new Crash(); };
        AssertCrash(() => Invoke(f.Fs, "Reconcile"));
        string json = File.ReadAllText(Directory.GetFiles(JournalDirectory(f), "*.json").Single());
        Assert.DoesNotContain("PRIVATE-PAYLOAD-NEVER-PERSIST-IN-METADATA", json);
        Assert.DoesNotContain(content.Path, json);
        Assert.DoesNotContain("Summary", json);
        Assert.DoesNotContain("Snapshot", json);
    }

    private static LocalQueueAuditSink Queue(DriveRecoveryTests.Fixture f) => new(f.Work.QueueFile);
    private static string JournalDirectory(DriveRecoveryTests.Fixture f) => Path.Combine(f.Private, PublicationAuditJournal.DirectoryName);
    private static PublicationAuditEntry[] Entries(DriveRecoveryTests.Fixture f) =>
        Directory.GetFiles(JournalDirectory(f), "*.json")
            .Select(path => JsonSerializer.Deserialize<PublicationAuditEntry>(File.ReadAllText(path))!).ToArray();
    private sealed class Crash : Exception;
    private static void AssertCrash(Action action) => Assert.IsType<Crash>(Assert.Throws<TargetInvocationException>(action).InnerException);

    private static void Invoke(object target, string name, params object[] arguments) =>
        target.GetType().GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(target, arguments);
}
