using System.ComponentModel;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

// Parameterless fixture, existing InternalsVisibleTo entries; unconditional in
// normal and SAFEUPLOAD_ADMISSION_EVIDENCE. Native branch runs on Windows.
public sealed class StagedJournalReplacementTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();
    private static IOException Native(int code) => new("rename failed", new Win32Exception(code));

    [Theory]
    [InlineData(5)] [InlineData(32)] [InlineData(33)]
    public async Task Transient_native_rename_failure_retries_the_same_action_then_stops_at_success(int code)
    {
        int calls = 0; var delays = new List<TimeSpan>();
        await StagedJournalReplacement.ReplaceAsync(() => { if (++calls < 4) throw Native(code); },
            (delay, _) => { delays.Add(delay); return Task.CompletedTask; }, default);
        Assert.Equal(4, calls);
        Assert.Equal(new[] { 20d, 40d, 80d }, delays.Select(d => d.TotalMilliseconds));
    }

    [Theory]
    [InlineData(2)] [InlineData(87)] [InlineData(112)]
    public async Task Nontransient_native_failure_is_preserved_without_retry(int code)
    {
        int calls = 0; var error = Native(code);
        Assert.Same(error, await Assert.ThrowsAsync<IOException>(() => StagedJournalReplacement.ReplaceAsync(
            () => { calls++; throw error; }, (_, _) => throw new Exception("No wait"), default)));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Unclassified_io_and_structural_failure_never_acquire_a_rename_retry()
    {
        foreach (Exception error in new Exception[] { new IOException("unknown"), new InvalidDataException("corrupt"),
                     new UnauthorizedAccessException("not a native rename observation") })
        {
            int calls = 0;
            var observed = await Record.ExceptionAsync(() => StagedJournalReplacement.ReplaceAsync(
                () => { calls++; throw error; }, (_, _) => throw new Exception("No wait"), default));
            Assert.Same(error, observed); Assert.Equal(1, calls);
        }
    }

    [Fact]
    public async Task Exhaustion_has_six_attempts_and_a_620_ms_total_wait_budget()
    {
        int calls = 0; var delays = new List<TimeSpan>(); var error = Native(5);
        Assert.Same(error, await Assert.ThrowsAsync<IOException>(() => StagedJournalReplacement.ReplaceAsync(
            () => { calls++; throw error; }, (delay, _) => { delays.Add(delay); return Task.CompletedTask; }, default)));
        Assert.Equal(6, calls); Assert.Equal(5, delays.Count);
        Assert.Equal(620d, delays.Sum(d => d.TotalMilliseconds));
    }

    [Fact]
    public async Task Cancellation_during_backoff_stops_before_another_rename()
    {
        using var cancellation = new CancellationTokenSource(); int calls = 0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => StagedJournalReplacement.ReplaceAsync(
            () => { calls++; throw Native(5); }, (_, token) =>
            { Assert.Equal(cancellation.Token, token); cancellation.Cancel(); return Task.CompletedTask; }, cancellation.Token));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Cancellation_after_success_does_not_repeat_or_report_an_uncertain_commit()
    {
        using var cancellation = new CancellationTokenSource(); int calls = 0;
        await StagedJournalReplacement.ReplaceAsync(() => { calls++; cancellation.Cancel(); },
            (_, _) => throw new Exception("No wait after success"), cancellation.Token);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Held_manifest_reader_shares_write_and_delete_and_keeps_its_old_object_after_replace()
    {
        string manifest = _workspace.WriteText("manifest.json", "old committed manifest");
        using var reader = StagedJournalFile.Open(manifest);
        // Keep this test's historical name. Readers permit atomic DELETE/rename
        // replacement, but must deny in-place writes to the validated object.
        if (OperatingSystem.IsWindows())
            Assert.Throws<IOException>(() => new FileStream(manifest, FileMode.Open, FileAccess.Write,
                FileShare.ReadWrite | FileShare.Delete));
        string temporary = manifest + ".tmp";
        await using (var output = StagedDestinationFile.Create(temporary))
        {
            await output.WriteAsync(System.Text.Encoding.UTF8.GetBytes("new committed manifest"));
            await StagedJournalReplacement.CommitAsync(output, temporary, manifest, default);
        }
        using var old = new StreamReader(reader, leaveOpen: true);
        Assert.Equal("old committed manifest", await old.ReadToEndAsync());
        Assert.Equal("new committed manifest", await File.ReadAllTextAsync(manifest));
        Assert.False(File.Exists(temporary));
    }
}
