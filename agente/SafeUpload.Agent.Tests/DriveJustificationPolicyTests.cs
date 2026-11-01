using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Drive;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

public sealed class DriveJustificationPolicyTests
{
    private const string Sid = "S-1-5-21-100-200-300-1001";
    private static Policy Allowed => LocalPolicyStore.CreateDefault() with { OverrideAllowed = true };

    [Theory]
    [InlineData("disabled")]
    [InlineData("revision")]
    [InlineData("content")]
    public void Changed_policy_cannot_consume_a_previous_block(string change)
    {
        var pending = new DriveJustifications();
        var id = Guid.NewGuid();
        pending.Remember(id, 1, Sid, PolicyContentFingerprint.Compute(Allowed), () => true);
        var current = Changed(change);
        Assert.False(pending.TryConsume(id.ToString(), 1, Sid, current, out var approval));
        Assert.Null(approval);
    }

    [Theory]
    [InlineData(2, Sid)]
    [InlineData(1, "S-1-5-21-100-200-300-9999")]
    public void Matching_policy_does_not_relax_session_or_user_binding(uint session, string sid)
    {
        var pending = new DriveJustifications();
        var id = Guid.NewGuid();
        pending.Remember(id, 1, Sid, PolicyContentFingerprint.Compute(Allowed), () => true);
        Assert.False(pending.TryConsume(id.ToString(), session, sid, Allowed, out _));
        Assert.True(pending.TryConsume(id.ToString(), 1, Sid, Allowed, out _));
        Assert.False(pending.TryConsume(id.ToString(), 1, Sid, Allowed, out _));
    }

    [Fact]
    public async Task Valid_justification_audits_before_publication_and_is_single_use()
    {
        var audit = new Audit();
        var policies = new Policies();
        bool published = false;
        using var server = Server(policies, audit, () => { Assert.Equal(1, audit.Writes); published = true; return true; }, out var request);
        Assert.True(await server.HandleAsync(request, 1, Sid, default));
        Assert.True(published);
        Assert.Equal(2, policies.CurrentReads);
        Assert.False(await server.HandleAsync(request, 1, Sid, default));
        Assert.Equal(1, audit.Writes);
    }

    [Theory]
    [InlineData("disabled")]
    [InlineData("revision")]
    [InlineData("content")]
    public async Task Policy_change_during_audit_prevents_publication(string change)
    {
        var policies = new Policies();
        var audit = new Audit { OnWrite = () => policies.Current = Changed(change) };
        bool published = false;
        using var server = Server(policies, audit, () => published = true, out var request);
        Assert.False(await server.HandleAsync(request, 1, Sid, default));
        Assert.False(published);
        Assert.Equal(1, audit.Writes); // Records a request, not a successful publication receipt.
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Unavailable_current_policy_never_uses_legacy_fallback(bool afterAudit)
    {
        var policies = new Policies { Unavailable = !afterAudit };
        var audit = new Audit { OnWrite = () => policies.Unavailable = true };
        bool published = false;
        using var server = Server(policies, audit, () => published = true, out var request);
        await Assert.ThrowsAsync<HttpRequestException>(() => server.HandleAsync(request, 1, Sid, default));
        Assert.False(published);
        Assert.Equal(afterAudit ? 1 : 0, audit.Writes);
    }

    [Fact]
    public async Task Failed_audit_cannot_publish()
    {
        bool published = false;
        using var server = Server(new Policies(), new Audit { OnWrite = () => throw new IOException("Synthetic audit failure") },
            () => published = true, out var request);
        await Assert.ThrowsAsync<IOException>(() => server.HandleAsync(request, 1, Sid, default));
        Assert.False(published);
    }

    private static Policy Changed(string change) => change switch
    {
        "disabled" => Allowed with { OverrideAllowed = false },
        "revision" => Allowed with { Version = Allowed.Version + 1 },
        _ => Allowed with { MaxFileSizeMb = Allowed.MaxFileSizeMb + 1 }
    };
    private static JustificationPipeServer Server(Policies policy, Audit audit, Func<bool> approve, out JustificationRequest request)
    {
        var pending = new DriveJustifications();
        var id = Guid.NewGuid();
        pending.Remember(id, 1, Sid, PolicyContentFingerprint.Compute(Allowed), approve);
        request = new(id.ToString(), "Synthetic justification");
        return new(policy, audit, pending, NullLogger<JustificationPipeServer>.Instance);
    }
    private sealed class Policies : IPolicyStore
    {
        public Policy Current = Allowed;
        public bool Unavailable;
        public int CurrentReads;
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(Allowed);
        public Task<Policy> LoadCurrentAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            CurrentReads++;
            if (Unavailable) throw new HttpRequestException("Synthetic policy origin unavailable");
            return Task.FromResult(Current);
        }
    }
    private sealed class Audit : IAuditSink
    {
        public int Writes;
        public Action? OnWrite;
        public Task RecordOverrideAsync(string eventId, string justification, CancellationToken token)
        { Writes++; OnWrite?.Invoke(); return Task.CompletedTask; }
        public Task WriteAsync(AuditEvent audit, CancellationToken token) => throw new NotSupportedException();
        public Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int count, CancellationToken token) => throw new NotSupportedException();
        public Task<IReadOnlyList<AuditEvent>> ReadPendingAsync(int count, CancellationToken token) => throw new NotSupportedException();
        public Task MarkDispatchedAsync(IReadOnlyCollection<Guid> ids, CancellationToken token) => throw new NotSupportedException();
    }
}
