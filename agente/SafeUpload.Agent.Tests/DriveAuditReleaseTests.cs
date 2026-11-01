using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Drive;

namespace SafeUpload.Agent.Tests;

public sealed class DriveAuditReleaseTests : IDisposable
{
    private readonly TestWorkspace _work = new();
    private static Policy Auditing => LocalPolicyStore.CreateDefault() with
    {
        AuditOnly = true,
        MonitoredScopes = new(new HashSet<string> { ".txt", ".pdf" }, [@"C:\Synthetic"], false, false)
    };

    private async Task<(FileOperation Operation, InspectionResult Result)> Inspect(Policy policy, bool broken = false)
    {
        var path = _work.WriteText(broken ? "broken.pdf" : "cpf.txt", broken ? "%PDF-invalid" : "CPF: 529.982.247-25");
        var operation = TestWorkspace.Operation(path, DestinationKind.Cloud, destinationPath: @"C:\Synthetic\output.txt");
        var engine = new InspectionService(new Policies(policy), new LocalQueueAuditSink(_work.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache());
        return (operation, await engine.InspectStagedAsync(operation, default));
    }

    [Fact]
    public async Task Completed_sensitive_inspection_can_be_released_under_the_same_current_audit_policy()
    {
        var (operation, result) = await Inspect(Auditing);
        Assert.True(result.IsBlocked); Assert.NotEmpty(result.Findings); Assert.Null(result.Reason);
        var current = new Policies(Auditing);
        int called = 0;
        Assert.True(await DriveAuditRelease.TryApproveAsync(current, operation, result, () => { called++; return true; }, default));
        Assert.Equal(1, called); Assert.Equal(1, current.Reads);
    }

    [Theory]
    [InlineData("disabled")]
    [InlineData("revision")]
    [InlineData("content")]
    public async Task Changed_policy_does_not_release_a_previous_audit_decision(string change)
    {
        var (operation, result) = await Inspect(Auditing);
        var current = change switch
        {
            "disabled" => Auditing with { AuditOnly = false },
            "revision" => Auditing with { Version = Auditing.Version + 1 },
            _ => Auditing with { MaxFileSizeMb = Auditing.MaxFileSizeMb + 1 }
        };
        Assert.False(await DriveAuditRelease.TryApproveAsync(new Policies(current), operation, result,
            () => throw new InvalidOperationException("Must not publish"), default));
    }

    [Fact]
    public async Task Real_parser_failure_remains_retained_even_with_audit_mode_enabled()
    {
        var (operation, result) = await Inspect(Auditing, broken: true);
        Assert.True(result.IsBlocked); Assert.NotNull(result.Reason);
        var policies = new Policies(Auditing);
        Assert.False(await DriveAuditRelease.TryApproveAsync(policies, operation, result,
            () => throw new InvalidOperationException("Must not publish"), default));
        Assert.Equal(0, policies.Reads);
    }

    [Theory]
    [InlineData("inspection_timeout")]
    [InlineData("file_too_large")]
    [InlineData("unsupported_format")]
    [InlineData("inspection_limit")]
    public async Task Incomplete_inspection_is_never_turned_into_an_audit_release(string reason)
    {
        var (operation, result) = await Inspect(Auditing);
        Assert.False(await DriveAuditRelease.TryApproveAsync(new Policies(Auditing), operation, result with { Reason = reason },
            () => throw new InvalidOperationException("Must not publish"), default));
    }

    [Fact]
    public async Task Current_origin_failure_cannot_be_replaced_with_a_cached_audit_policy()
    {
        var (operation, result) = await Inspect(Auditing);
        await Assert.ThrowsAsync<HttpRequestException>(() => DriveAuditRelease.TryApproveAsync(new Policies(Auditing) { Fail = true },
            operation, result, () => throw new InvalidOperationException("Must not publish"), default));
    }

    [Fact]
    public async Task Cancellation_before_publication_does_not_call_the_publisher()
    {
        var (operation, result) = await Inspect(Auditing);
        using var stop = new CancellationTokenSource();
        var policies = new Policies(Auditing) { OnRead = stop.Cancel };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => DriveAuditRelease.TryApproveAsync(policies, operation, result,
            () => throw new InvalidOperationException("Must not publish"), stop.Token));
    }

    [Fact]
    public async Task Missing_decision_binding_does_not_authorize_publication()
    {
        var (operation, result) = await Inspect(Auditing);
        Assert.False(await DriveAuditRelease.TryApproveAsync(new Policies(Auditing), operation,
            result with { PolicyContentFingerprint = null }, () => throw new InvalidOperationException("Must not publish"), default));
    }

    [Fact]
    public async Task Publisher_refusal_is_not_reported_as_release()
    {
        var (operation, result) = await Inspect(Auditing);
        Assert.False(await DriveAuditRelease.TryApproveAsync(new Policies(Auditing), operation, result, () => false, default));
    }
    private sealed class Policies(Policy policy) : IPolicyStore
    {
        public bool Fail; public int Reads; public Action? OnRead;
        public Task<Policy> LoadAsync(CancellationToken token) => throw new InvalidOperationException("Legacy snapshot is not authority");
        public Task<Policy> LoadCurrentAsync(CancellationToken token)
        {
            Reads++; OnRead?.Invoke();
            if (Fail) throw new HttpRequestException("Synthetic current origin failure");
            return Task.FromResult(policy);
        }
    }
    public void Dispose() => _work.Dispose();
}
