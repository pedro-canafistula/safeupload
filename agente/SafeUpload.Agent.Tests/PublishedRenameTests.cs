using System.Reflection;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Tests;

public sealed class PublishedRenameTests
{
    [Fact]
    public void A_backing_file_keeps_its_old_destination_until_the_new_name_is_inspected()
    {
        using var f = new DriveRecoveryTests.Fixture();
        Rename(f, @"\report.txt", @"\final.txt");
        Invoke(f.Fs, "Reconcile");
        Assert.False(File.Exists(Path.Combine(f.Backing, "final.txt")));
        Assert.Equal("Published old version", File.ReadAllText(f.Target));
        var pending = f.Read(@"\final.txt", "Published old version");
        Assert.True(pending.IsStage);
        Invoke(f.Fs, "InspectOne", pending);
        Invoke(f.Fs, "Reconcile");
        Assert.Equal("Published old version", File.ReadAllText(Path.Combine(f.Backing, "final.txt")));
        Assert.False(File.Exists(f.Target));
        Assert.True(Assert.Single(f.Observer.Publications).Succeeded);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void A_new_policy_blocks_renamed_sensitive_bytes_including_after_restart(bool restart)
    {
        using var f = new DriveRecoveryTests.Fixture();
        File.WriteAllText(f.Target, "CPF: 529.982.247-25");
        Rename(f, @"\report.txt", @"\final.txt");
        f.Policies.Current = f.Policies.Current with { ActiveCategories = new HashSet<Category> { Category.Cpf }, Version = 2 };
        if (restart) f.Restart();
        var pending = f.Read(@"\final.txt", "CPF: 529.982.247-25");
        Invoke(f.Fs, "InspectOne", pending);
        Invoke(f.Fs, "Reconcile");
        Assert.False(Assert.Single(f.Observer.Decisions).Approved);
        Assert.False(File.Exists(Path.Combine(f.Backing, "final.txt")));
        Assert.Equal("CPF: 529.982.247-25", File.ReadAllText(f.Target));
        Assert.Empty(f.Observer.Publications);
    }

    [Fact]
    public void Renaming_a_blocked_stage_revokes_the_old_justification_and_requires_a_new_decision()
    {
        using var f = new DriveRecoveryTests.Fixture();
        var content = f.Write(@"\report.txt", "CPF: 529.982.247-25");
        Invoke(f.Fs, "InspectOne", content);
        var oldId = Assert.Single(f.Observer.Decisions).VersionId;
        Rename(f, @"\report.txt", @"\final.txt");
        Assert.False(f.Fs.Approve(oldId));
        Invoke(f.Fs, "Reconcile");
        Assert.Empty(f.Observer.Publications);
        Assert.Equal("Published old version", File.ReadAllText(f.Target));
        Invoke(f.Fs, "InspectOne", content);
        var current = f.Observer.Decisions[1];
        Assert.NotEqual(oldId, current.VersionId);
        Assert.True(f.Fs.Approve(current.VersionId));
        Invoke(f.Fs, "Reconcile");
        Assert.Equal("CPF: 529.982.247-25", File.ReadAllText(Path.Combine(f.Backing, "final.txt")));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void An_approved_or_published_stage_is_reinspected_for_a_new_name(bool published)
    {
        using var f = new DriveRecoveryTests.Fixture();
        var content = f.Write(@"\report.txt", "Approved private bytes");
        Invoke(f.Fs, "InspectOne", content);
        if (published) Invoke(f.Fs, "Reconcile");
        int attempts = f.Observer.Publications.Count;
        Rename(f, @"\report.txt", @"\final.txt");
        Invoke(f.Fs, "Reconcile");
        Assert.Equal(attempts, f.Observer.Publications.Count);
        Assert.False(File.Exists(Path.Combine(f.Backing, "final.txt")));
        Assert.Null(content.ApprovedSnapshot);
        Invoke(f.Fs, "InspectOne", content);
        Invoke(f.Fs, "Reconcile");
        Assert.Equal(attempts + 1, f.Observer.Publications.Count);
        Assert.Equal("Approved private bytes", File.ReadAllText(Path.Combine(f.Backing, "final.txt")));
    }

    [Fact]
    public void Renaming_an_explicitly_unmonitored_binary_to_text_cannot_reuse_its_previous_exemption()
    {
        using var f = new DriveRecoveryTests.Fixture();
        f.Create(@"\payload.bin");
        var content = f.Write(@"\payload.bin", "CPF: 529.982.247-25\0");
        Invoke(f.Fs, "InspectOne", content);
        Assert.True(Assert.Single(f.Observer.Decisions).Approved);
        Invoke(f.Fs, "Reconcile");
        Rename(f, @"\payload.bin", @"\final.txt");
        Invoke(f.Fs, "Reconcile");
        Assert.Single(f.Observer.Publications);
        Invoke(f.Fs, "InspectOne", content);
        Assert.False(f.Observer.Decisions[1].Approved);
        Invoke(f.Fs, "Reconcile");
        Assert.Single(f.Observer.Publications);
        Assert.False(File.Exists(Path.Combine(f.Backing, "final.txt")));
        Assert.True(File.Exists(Path.Combine(f.Backing, "payload.bin")));
    }

    [Fact]
    public async Task An_inspection_started_under_the_old_name_cannot_authorize_the_renamed_version()
    {
        using var f = new DriveRecoveryTests.Fixture();
        f.Create(@"\payload.bin");
        var content = f.Write(@"\payload.bin", "CPF: 529.982.247-25\0");
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Policies.BeforeLoad = async token => { entered.TrySetResult(); await release.Task.WaitAsync(token); };
        var inspecting = Task.Run(() => Invoke(f.Fs, "InspectOne", content));
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            f.Policies.BeforeLoad = null;
            Rename(f, @"\payload.bin", @"\final.txt");
        }
        finally { release.TrySetResult(); await inspecting.WaitAsync(TimeSpan.FromSeconds(5)); }
        Assert.Empty(f.Observer.Decisions);
        Invoke(f.Fs, "Reconcile");
        Assert.Empty(f.Observer.Publications);
        Invoke(f.Fs, "InspectOne", content);
        Assert.False(Assert.Single(f.Observer.Decisions).Approved);
    }

    private static void Rename(DriveRecoveryTests.Fixture f, string from, string to) =>
        f.Open(from, (node, handle) => Assert.Equal(0, f.Fs.Rename(node, handle, from, to, true)));
    private static void Invoke(object target, string method, params object[] arguments) =>
        target.GetType().GetMethod(method, BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(target, arguments);
}
