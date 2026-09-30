using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

public sealed class StagedTransferPublisherTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private readonly string _stagingRoot;
    private readonly NotificationHub _notifications = new();
    private readonly StagedTransferPublisher _publisher;

    public StagedTransferPublisherTests()
    {
        _stagingRoot = Path.Combine(_workspace.Root, "staging");
        Directory.CreateDirectory(_stagingRoot);

        var inspector = new InspectionService(
            new LocalPolicyStore(_workspace.PolicyFile),
            new LocalQueueAuditSink(_workspace.QueueFile),
            ExtractorRegistry.CreateDefault(),
            new VerdictCache());

        _publisher = new StagedTransferPublisher(inspector, _notifications, _stagingRoot);
    }

    public void Dispose() => _workspace.Dispose();

    private StagedTransfer Transfer(string name, string content)
    {
        string stage = Path.Combine(_stagingRoot, name);
        File.WriteAllText(stage, content);
        string destination = Path.Combine(_workspace.Root, "destination", name);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);

        return new StagedTransfer(
            Guid.NewGuid(), stage, destination,
            DestinationKind.RemovableDrive,
            "explorer.exe", 4242, null);
    }

    [Fact]
    public async Task Sensitive_content_never_reaches_the_destination()
    {
        var transfer = Transfer("sensitive.txt", "CPF: 529.982.247-25");

        var outcome = await _publisher.PublishAsync(transfer, CancellationToken.None);

        Assert.Equal(StagedTransferOutcome.Blocked, outcome);
        Assert.False(File.Exists(transfer.DestinationPath));
        Assert.True(File.Exists(transfer.StagePath));
    }

    [Fact]
    public async Task Inspected_clean_content_is_released()
    {
        var transfer = Transfer("clean.txt", "Relatorio sem dados pessoais.");

        var outcome = await _publisher.PublishAsync(transfer, CancellationToken.None);

        Assert.Equal(StagedTransferOutcome.Released, outcome);
        Assert.Equal("Relatorio sem dados pessoais.",
            await File.ReadAllTextAsync(transfer.DestinationPath));
    }

    [Fact]
    public async Task Destination_stays_empty_and_stage_stays_locked_during_analysis()
    {
        var extractor = new PausingExtractor();
        var inspector = new InspectionService(
            new LocalPolicyStore(_workspace.PolicyFile),
            new LocalQueueAuditSink(_workspace.QueueFile),
            new ExtractorRegistry([extractor]),
            new VerdictCache());
        var publisher = new StagedTransferPublisher(inspector, _notifications, _stagingRoot);
        var transfer = Transfer("waiting.txt", "Clean text.");

        Task<StagedTransferOutcome> publication =
            publisher.PublishAsync(transfer, CancellationToken.None);
        await extractor.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(File.Exists(transfer.DestinationPath));
        Assert.Throws<IOException>(() => new FileStream(
            transfer.StagePath, FileMode.Open, FileAccess.Write, FileShare.None));

        extractor.Continue.SetResult();
        Assert.Equal(StagedTransferOutcome.Released, await publication);
        Assert.Equal("Clean text.", await File.ReadAllTextAsync(transfer.DestinationPath));
    }

    [Fact]
    public async Task Uninspectable_content_remains_local()
    {
        var transfer = Transfer("unknown.md", "CPF: 529.982.247-25");

        var outcome = await _publisher.PublishAsync(transfer, CancellationToken.None);

        Assert.Equal(StagedTransferOutcome.Retained, outcome);
        Assert.False(File.Exists(transfer.DestinationPath));
        Assert.True(File.Exists(transfer.StagePath));
    }

    [Fact]
    public async Task A_stage_outside_the_private_root_is_rejected()
    {
        var transfer = Transfer("clean.txt", "safe");
        transfer = transfer with { StagePath = _workspace.WriteText("outside.txt", "safe") };

        await Assert.ThrowsAsync<ArgumentException>(() =>
            _publisher.PublishAsync(transfer, CancellationToken.None));
        Assert.False(File.Exists(transfer.DestinationPath));
    }

    private sealed class PausingExtractor : ITextExtractor
    {
        public IReadOnlySet<string> SupportedExtensions { get; } = new HashSet<string> { ".txt" };
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Continue { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
        {
            Entered.SetResult();
            await Continue.Task.WaitAsync(cancellationToken);
            using var reader = new StreamReader(content);
            return await reader.ReadToEndAsync(cancellationToken);
        }
    }
}
