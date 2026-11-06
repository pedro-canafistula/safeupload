using System.Text;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.App.ViewModels;

namespace SafeUpload.Agent.Tests;

public sealed class WebAuditConsistencyTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Audit_mode_records_the_actual_release_with_findings(bool file)
    {
        using var workspace = new TestWorkspace();
        var queue = new LocalQueueAuditSink(workspace.QueueFile);
        var store = new Policies { Current = LocalPolicyStore.CreateDefault() with { AuditOnly = true } };
        var service = new WebInspectionService(store, queue, ExtractorRegistry.CreateDefault());
        var part = new WebUploadPart(file ? "dados.txt" : null,
            Encoding.UTF8.GetBytes("meu cpf 529.982.247-25"), file);
        var result = await service.InspectAsync(new WebUpload("https://example.test/upload", "browser", 7, [part]), CancellationToken.None);

        Assert.False(result.IsBlocked);
        Assert.NotEmpty(result.Findings);
        var record = Assert.Single(result.Records);
        Assert.Equal(Verdict.Approved, record.Event.Verdict);
        Assert.Contains(Category.Cpf, record.Event.Categories);
        var persisted = Assert.Single(await queue.ReadPendingAsync(10, CancellationToken.None));
        Assert.Equal(record.Event.EventId, persisted.EventId);
        Assert.Equal(Verdict.Approved, persisted.Verdict);
        Assert.Contains(Category.Cpf, persisted.Categories);
        Assert.Equal("APROVADO COM ACHADOS", StatusPill.For(persisted).Text);
    }

    [Theory]
    [InlineData(false, false, 8)]
    [InlineData(true, false, 7)]
    [InlineData(false, true, 7)]
    public async Task A_changed_policy_is_not_hidden_by_a_previous_text_repeat(bool beforeAudit, bool afterAudit, int nextVersion)
    {
        using var workspace = new TestWorkspace();
        var queue = new LocalQueueAuditSink(workspace.QueueFile);
        var store = new Policies { Current = LocalPolicyStore.CreateDefault() with { Version = 7, AuditOnly = beforeAudit } };
        var service = new WebInspectionService(store, queue, ExtractorRegistry.CreateDefault()) { PolicyLifetime = TimeSpan.Zero };
        var upload = new WebUpload("https://example.test/upload", "browser", 7,
            [new WebUploadPart(null, Encoding.UTF8.GetBytes("meu cpf 529.982.247-25"), false)]);
        Assert.Single((await service.InspectAsync(upload, CancellationToken.None)).Records);
        Assert.Empty((await service.InspectAsync(upload, CancellationToken.None)).Records);

        store.Current = store.Current with { Version = nextVersion, AuditOnly = afterAudit };
        var changed = await service.InspectAsync(upload, CancellationToken.None);
        Assert.Equal(!afterAudit, changed.IsBlocked);
        var record = Assert.Single(changed.Records);
        Assert.Equal(nextVersion, record.Event.PolicyVersion);
        Assert.Equal(afterAudit ? Verdict.Approved : Verdict.Blocked, record.Event.Verdict);
        Assert.Equal(2, (await queue.ReadPendingAsync(10, CancellationToken.None)).Count);
    }

    [Fact]
    public async Task Moving_wall_clock_back_does_not_extend_the_policy_cache()
    {
        using var workspace = new TestWorkspace();
        var store = new Policies { Current = LocalPolicyStore.CreateDefault() with { Version = 7 } };
        var clock = new Clock();
        var service = new WebInspectionService(store, new LocalQueueAuditSink(workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), clock: clock) { PolicyLifetime = TimeSpan.FromSeconds(10) };
        var upload = new WebUpload("https://example.test", "browser", 7, []);
        Assert.Equal(7, (await service.InspectAsync(upload, CancellationToken.None)).PolicyVersion);
        store.Current = store.Current with { Version = 8 };
        clock.Advance(TimeSpan.FromSeconds(11));
        clock.AdjustWallClock(TimeSpan.FromHours(-2));

        Assert.Equal(8, (await service.InspectAsync(upload, CancellationToken.None)).PolicyVersion);
    }

    [Fact]
    public async Task Moving_wall_clock_back_does_not_extend_text_event_suppression()
    {
        using var workspace = new TestWorkspace();
        var store = new Policies { Current = LocalPolicyStore.CreateDefault() };
        var clock = new Clock();
        var service = new WebInspectionService(store, new LocalQueueAuditSink(workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), clock: clock);
        var upload = new WebUpload("https://example.test", "browser", 7,
            [new WebUploadPart(null, Encoding.UTF8.GetBytes("meu cpf 529.982.247-25"), false)]);
        Assert.Single((await service.InspectAsync(upload, CancellationToken.None)).Records);
        clock.Advance(TimeSpan.FromSeconds(61));
        clock.AdjustWallClock(TimeSpan.FromHours(-2));

        Assert.Single((await service.InspectAsync(upload, CancellationToken.None)).Records);
    }

    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset _utc = DateTimeOffset.UnixEpoch;
        private long _elapsed;
        public override DateTimeOffset GetUtcNow() => _utc;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _elapsed;
        public void Advance(TimeSpan time) { _elapsed += time.Ticks; _utc += time; }
        public void AdjustWallClock(TimeSpan time) => _utc += time;
    }

    private sealed class Policies : IPolicyStore
    {
        public required Policy Current { get; set; }
        public Task<Policy> LoadAsync(CancellationToken cancellationToken) => Task.FromResult(Current);
    }
}
