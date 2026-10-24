using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class FileQuarantineTests
{
    [Fact]
    public void Reports_success_only_after_moving_and_preserves_existing_files()
    {
        using var workspace = new TestWorkspace();
        string target = Path.Combine(workspace.Root, "quarantine");
        Directory.CreateDirectory(target);
        string source = workspace.WriteText("synthetic.txt", "first synthetic content");
        Assert.True(FileQuarantine.TryMove(source, target, NullLogger.Instance));
        Assert.False(File.Exists(source));
        workspace.WriteText("synthetic.txt", "second synthetic content");
        Assert.True(FileQuarantine.TryMove(source, target, NullLogger.Instance));
        Assert.False(File.Exists(source));
        Assert.Equal(new[] { "first synthetic content", "second synthetic content" },
            Directory.GetFiles(target).Select(File.ReadAllText).OrderBy(text => text));
    }

    [Fact]
    public void Locked_file_is_not_reported_as_quarantined_and_remains_intact()
    {
        using var workspace = new TestWorkspace();
        string target = Path.Combine(workspace.Root, "quarantine");
        Directory.CreateDirectory(target);
        string source = workspace.WriteText("synthetic.txt", "synthetic content");
        using (File.Open(source, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            Assert.False(FileQuarantine.TryMove(source, target, NullLogger.Instance));
            Assert.Equal("synthetic content", File.ReadAllText(source));
            Assert.Empty(Directory.GetFiles(target));
        }
    }
}
