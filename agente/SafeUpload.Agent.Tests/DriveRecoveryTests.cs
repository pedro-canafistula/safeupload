using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Drive;

namespace SafeUpload.Agent.Tests;

public sealed class DriveRecoveryTests
{
    [Theory]
    [InlineData("pending")]
    [InlineData("approved")]
    [InlineData("blocked")]
    public void Retained_version_returns_under_its_name_without_restoring_old_authority(string state)
    {
        using var f = new Fixture();
        string bytes = state == "blocked" ? "CPF: 529.982.247-25" : "Private new version";
        var content = f.Write(@"\report.txt", bytes);
        if (state != "pending") Invoke(f.Fs, "InspectOne", content);
        Guid? blocked = content.BlockedId;
        f.Restart();
        var recovered = f.Read(@"\report.txt", bytes);
        Assert.True(recovered.IsStage);
        Assert.Null(recovered.ApprovedSnapshot);
        Assert.Null(recovered.ApprovedDecision);
        Assert.Null(recovered.BlockedId);
        Assert.Equal(-1, recovered.PublishedVersion);
        Assert.True(recovered.Version > recovered.InspectedVersion);
        Assert.Equal(Fixture.Sid, recovered.Writer?.UserSid);
        Assert.Null(recovered.Writer?.SessionId);
        Assert.Equal(0, recovered.Writer?.ProcessId);
        Assert.True(string.IsNullOrEmpty(recovered.Writer?.ProcessName));
        if (blocked is { } id) Assert.False(f.Fs.Approve(id));
        Invoke(f.Fs, "Reconcile");
        Assert.Equal("Published old version", File.ReadAllText(f.Target));
        Assert.Empty(f.Observer.Publications);
        Invoke(f.Fs, "InspectOne", recovered);
        Assert.Equal(state != "blocked", Assert.Single(f.Observer.Decisions).Approved);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void File_or_directory_rename_recovers_the_final_relative_name(bool directory)
    {
        using var f = new Fixture(directory);
        f.Write(directory ? @"\folder\report.txt" : @"\report.txt", "Renamed private version");
        string old = directory ? @"\folder" : @"\report.txt";
        string renamed = directory ? @"\final" : @"\final.txt";
        f.Open(old, (node, handle) => Assert.Equal(0, f.Fs.Rename(node, handle, old, renamed, true)));
        f.Restart();
        f.Read(directory ? @"\final\report.txt" : renamed, "Renamed private version");
        if (!directory) Assert.NotEqual(0, f.Fs.Open(old, 0, 0, out _, out _, out _, out _));
        Assert.Empty(f.Observer.Publications);
    }

    [Fact]
    public void Deleted_private_version_is_not_resurrected()
    {
        using var f = new Fixture();
        f.Write(@"\report.txt", "Deleted private version");
        f.Open(@"\report.txt", (node, handle) =>
        {
            Assert.Equal(0, f.Fs.Rename(node, handle, @"\report.txt", @"\new.txt", true));
            Invoke(f.Fs, "Delete", ((Handle)handle).Node);
        });
        f.Restart();
        Assert.NotEqual(0, f.Fs.Open(@"\new.txt", 0, 0, out _, out _, out _, out _));
        f.Read(@"\report.txt", "Published old version");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Publication_retires_only_the_published_version_and_next_edit_is_recoverable(bool newerBeforePublication)
    {
        using var f = new Fixture();
        var content = f.Write(@"\report.txt", "First approved version");
        Invoke(f.Fs, "InspectOne", content);
        if (newerBeforePublication) f.Write(@"\report.txt", "Uninspected next version");
        Invoke(f.Fs, "Reconcile");
        Assert.Equal("First approved version", File.ReadAllText(f.Target));
        if (!newerBeforePublication)
        {
            Assert.Empty(JsonNode.Parse(File.ReadAllText(f.Map))!["Entries"]!.AsArray());
            f.Write(@"\report.txt", "Uninspected next version");
        }
        f.Restart();
        f.Read(@"\report.txt", "Uninspected next version");
        Assert.Empty(f.Observer.Publications);
    }

    [Fact]
    public void Rename_after_publication_registers_the_stage_again()
    {
        using var f = new Fixture();
        var content = f.Write(@"\report.txt", "Already published version");
        Invoke(f.Fs, "InspectOne", content);
        Invoke(f.Fs, "Reconcile");
        f.Open(@"\report.txt", (node, handle) => Assert.Equal(0, f.Fs.Rename(node, handle, @"\report.txt", @"\final.txt", true)));
        f.Restart();
        f.Read(@"\final.txt", "Already published version");
        Assert.NotEqual(0, f.Fs.Open(@"\report.txt", 0, 0, out _, out _, out _, out _));
        Assert.Empty(f.Observer.Publications);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void New_empty_file_or_office_replacement_is_recovered(bool office)
    {
        using var f = new Fixture();
        string name = office ? @"\~WRL0001.tmp" : @"\empty.txt";
        f.Create(name);
        if (office)
        {
            f.Write(name, "Office private replacement");
            f.Open(name, (node, handle) => Assert.Equal(0, f.Fs.Rename(node, handle, name, @"\report.txt", true)));
        }
        f.Restart();
        f.Read(office ? @"\report.txt" : name, office ? "Office private replacement" : "");
        Assert.Equal("Published old version", File.ReadAllText(f.Target));
    }

    [Theory]
    [InlineData("policy")]
    [InlineData("process")]
    [InlineData("justification")]
    public void Old_policy_process_exemption_or_justification_does_not_release_the_recovered_version(string mode)
    {
        using var f = new Fixture();
        if (mode == "policy") f.Policies.Current = f.Policies.Current with { ActiveCategories = new HashSet<Category> { Category.Cnpj } };
        var content = f.Write(@"\report.txt", "CPF: 529.982.247-25", process: mode == "process" ? "System" : "explorer");
        Invoke(f.Fs, "InspectOne", content);
        Guid oldId = Assert.Single(f.Observer.Decisions).VersionId;
        if (mode == "justification") Assert.True(f.Fs.Approve(oldId));
        else Assert.NotNull(content.ApprovedSnapshot);
        f.Policies.Current = f.Policies.Current with { ActiveCategories = new HashSet<Category> { Category.Cpf } };
        f.Restart();
        var recovered = f.Read(@"\report.txt", "CPF: 529.982.247-25");
        Assert.False(f.Fs.Approve(oldId));
        Invoke(f.Fs, "InspectOne", recovered);
        var blocked = Assert.Single(f.Observer.Decisions);
        Assert.False(blocked.Approved);
        Assert.Equal(Fixture.Sid, blocked.Operation?.AuditOwnerSid);
        Assert.Null(blocked.Writer?.SessionId);
        Invoke(f.Fs, "Reconcile");
        Assert.Equal("Published old version", File.ReadAllText(f.Target));
        Assert.Empty(f.Observer.Publications);
    }

    [Theory]
    [InlineData("truncated")]
    [InlineData("format")]
    [InlineData("identity")]
    [InlineData("backing")]
    [InlineData("escape")]
    [InlineData("source_escape")]
    [InlineData("stage_escape")]
    [InlineData("duplicate_name")]
    [InlineData("missing_stage")]
    [InlineData("directory_conflict")]
    [InlineData("oversize")]
    [InlineData("duplicate_fields")]
    [InlineData("absolute")]
    [InlineData("alternate_stream")]
    [InlineData("reserved_name")]
    [InlineData("entry_limit")]
    public void Invalid_catalog_refuses_recovery_preserves_bytes_and_releases_ownership_for_repair(string mode)
    {
        using var f = new Fixture();
        var retained = f.Write(@"\report.txt", "Preserved private version");
        f.Fs.Stop();
        byte[] original = File.ReadAllBytes(f.Map);
        var map = JsonNode.Parse(original)!;
        var entry = map["Entries"]![0]!;
        switch (mode)
        {
            case "format": map["Format"] = 2; break;
            case "identity": map["DestinationIdentity"] = "another-volume"; break;
            case "backing": map["Backing"] = Path.Combine(f.Work.Root, "elsewhere"); break;
            case "escape": entry["RelativePath"] = @"..\escaped.txt"; break;
            case "source_escape": entry["PreviousRelativePath"] = @"..\escaped.txt"; break;
            case "stage_escape": entry["StageName"] = @"..\outside"; break;
            case "duplicate_name": map["Entries"]!.AsArray().Add(entry.DeepClone()); break;
            case "missing_stage": entry["StageName"] = Guid.NewGuid().ToString("N"); break;
            case "directory_conflict": entry["RelativePath"] = @"report.txt\child.txt"; break;
            case "absolute": entry["RelativePath"] = @"C:\escaped.txt"; break;
            case "alternate_stream": entry["RelativePath"] = "report.txt:stream"; break;
            case "reserved_name": entry["RelativePath"] = "NUL.txt"; break;
            case "entry_limit":
                for (int i = 0; i < 4096; i++) map["Entries"]!.AsArray().Add(entry.DeepClone());
                break;
        }
        string damaged = mode == "truncated" ? "{" : mode == "oversize" ? new string(' ', 1024 * 1024 + 1) : map.ToJsonString();
        if (mode == "duplicate_fields") damaged = damaged.Replace("\"Format\":1", "\"Format\":1,\"Format\":1");
        File.WriteAllText(f.Map, damaged);
        var error = Record.Exception(f.Mount);
        Assert.True(error is IOException or System.Text.Json.JsonException, error?.ToString());
        Assert.Equal(damaged, File.ReadAllText(f.Map));
        Assert.Equal("Preserved private version", File.ReadAllText(retained.Path));
        Assert.Equal("Published old version", File.ReadAllText(f.Target));
        File.WriteAllBytes(f.Map, original);
        f.Mount();
        f.Read(@"\report.txt", "Preserved private version");
    }

    [Fact]
    public void A_different_directory_at_the_same_path_cannot_claim_retained_files()
    {
        using var f = new Fixture();
        var retained = f.Write(@"\report.txt", "Original destination version");
        f.Fs.Stop();
        var previous = Path.Combine(f.Work.Root, "original-backing");
        Directory.Move(f.Backing, previous);
        Directory.CreateDirectory(f.Backing);
        Assert.Throws<IOException>(f.Mount);
        Assert.Equal("Original destination version", File.ReadAllText(retained.Path));
        Assert.Empty(Directory.GetFileSystemEntries(f.Backing));
        Directory.Delete(f.Backing);
        Directory.Move(previous, f.Backing);
        f.Mount();
        f.Read(@"\report.txt", "Original destination version");
    }

    [Fact]
    public void A_live_owner_prevents_a_second_filesystem_from_recovering_the_same_stage()
    {
        using var f = new Fixture();
        f.Write(@"\report.txt", "Owned private version");
        Assert.Throws<IOException>(f.Mount);
        f.Restart();
        f.Read(@"\report.txt", "Owned private version");
    }

    [Fact]
    public void Failed_catalog_commit_precedes_rename_and_leaves_the_previous_mapping_usable()
    {
        using var f = new Fixture();
        f.Write(@"\report.txt", "Unrenamed private version");
        byte[] before = File.ReadAllBytes(f.Map);
        using (var locked = new FileStream(f.Map, FileMode.Open, FileAccess.Read, FileShare.Read))
            f.Open(@"\report.txt", (node, handle) =>
                AssertIoFailure(() => f.Fs.Rename(node, handle, @"\report.txt", @"\final.txt", true)));
        Assert.Equal(before, File.ReadAllBytes(f.Map));
        Assert.Empty(Directory.GetFiles(f.Private, "*.tmp"));
        f.Restart();
        f.Read(@"\report.txt", "Unrenamed private version");
        Assert.NotEqual(0, f.Fs.Open(@"\final.txt", 0, 0, out _, out _, out _, out _));
    }

    [Fact]
    public void Failed_first_catalog_commit_does_not_accept_new_bytes_and_a_retry_can_recover()
    {
        using var f = new Fixture();
        Directory.CreateDirectory(f.Map);
        AssertIoFailure(() => f.Write(@"\report.txt", "Not accepted"));
        Assert.Equal("Published old version", File.ReadAllText(f.Target));
        Directory.Delete(f.Map);
        f.Write(@"\report.txt", "Accepted retry");
        f.Restart();
        f.Read(@"\report.txt", "Accepted retry");
    }

    [Fact]
    public void Failed_catalog_delete_does_not_remove_a_retained_version()
    {
        using var f = new Fixture();
        var content = f.Write(@"\report.txt", "Retained despite failed delete");
        using (var held = new FileStream(f.Map, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            var wrapped = Assert.Throws<TargetInvocationException>(() => Invoke(f.Fs, "Delete", content.Node!));
            Assert.True(wrapped.InnerException is IOException or UnauthorizedAccessException);
        }
        f.Restart();
        f.Read(@"\report.txt", "Retained despite failed delete");
    }

    [Fact]
    public void Committed_rename_intent_recovers_private_names_when_the_backing_move_did_not_finish()
    {
        using var f = new Fixture(directory: true);
        f.Write(@"\folder\report.txt", "Interrupted rename version");
        using (var held = new FileStream(f.Target, FileMode.Open, FileAccess.Read, FileShare.Read))
            f.Open(@"\folder", (node, handle) =>
                AssertIoFailure(() => f.Fs.Rename(node, handle, @"\folder", @"\final", true)));
        f.Restart();
        f.Read(@"\final\report.txt", "Interrupted rename version");
        Assert.Empty(f.Observer.Publications);
        Assert.Equal("Published old version", File.ReadAllText(f.Target));
    }

    [Fact]
    public async Task Background_worker_reinspects_and_publishes_a_recovered_clean_version()
    {
        using var f = new Fixture();
        f.Write(@"\report.txt", "Recovered clean version");
        f.Restart();
        f.Fs.StartBackgroundWork();
        var publication = await f.Observer.Published.Task.WaitAsync(TimeSpan.FromSeconds(10));
        f.Fs.Stop();
        Assert.True(publication.Succeeded);
        Assert.Equal("Recovered clean version", File.ReadAllText(f.Target));
        Assert.Single(f.Observer.Decisions);
    }

    [Fact]
    public void A_stage_with_a_hard_link_is_preserved_but_not_recovered_as_private_writable_content()
    {
        using var f = new Fixture();
        var retained = f.Write(@"\report.txt", "Linked private bytes");
        f.Fs.Stop();
        var alias = Path.Combine(f.Work.Root, "linked-alias.txt");
        Assert.True(CreateHardLink(alias, retained.Path, IntPtr.Zero), Marshal.GetLastWin32Error().ToString());
        Assert.Throws<IOException>(f.Mount);
        Assert.Equal("Linked private bytes", File.ReadAllText(alias));
        File.Delete(alias);
        f.Mount();
        f.Read(@"\report.txt", "Linked private bytes");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Recovery_rejects_junctions_in_stage_or_destination_paths(bool stage)
    {
        using var f = new Fixture();
        var retained = f.Write(@"\report.txt", "Junction private bytes");
        f.Fs.Stop();
        string link;
        var target = Path.Combine(f.Work.Root, "junction-target");
        if (stage)
        {
            link = Path.Combine(f.Private, "stage");
            Directory.Move(link, target);
        }
        else
        {
            link = Path.Combine(f.Backing, "linked");
            Directory.CreateDirectory(target);
            var map = JsonNode.Parse(File.ReadAllText(f.Map))!;
            map["Entries"]![0]!["RelativePath"] = @"linked\report.txt";
            File.WriteAllText(f.Map, map.ToJsonString());
        }
        var start = new System.Diagnostics.ProcessStartInfo("cmd.exe") { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string arg in new[] { "/c", "mklink", "/J", link, target }) start.ArgumentList.Add(arg);
        using var process = System.Diagnostics.Process.Start(start)!;
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
        try
        {
            Assert.Throws<IOException>(f.Mount);
            string preserved = stage ? Path.Combine(target, Path.GetFileName(retained.Path)) : retained.Path;
            Assert.Equal("Junction private bytes", File.ReadAllText(preserved));
            if (!stage) Assert.Empty(Directory.GetFileSystemEntries(target));
        }
        finally
        {
            Directory.Delete(link); // Remove the junction itself, never recurse into its target.
            if (stage) Directory.Move(target, link);
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string fileName, string existing, IntPtr security);

    private static void Invoke(object target, string name, params object[] arguments) =>
        target.GetType().GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(target, arguments);

    private static void AssertIoFailure(Action action)
    {
        var error = Record.Exception(action);
        Assert.True(error is IOException or UnauthorizedAccessException, error?.ToString());
    }

    internal sealed class Fixture : IDisposable
    {
        public const string Sid = "S-1-5-21-111-222-333-1001";
        public TestWorkspace Work { get; } = new();
        public DriveFileSystem Fs { get; private set; } = null!;
        public Observer Observer { get; private set; } = null!;
        public string Backing { get; }
        public string Private { get; }
        public string Target { get; }
        public string Map => Path.Combine(Private, DriveRecoveryStore.MapName);
        public Source Policies { get; } = new();
        public Fixture(bool directory = false)
        {
            Backing = Path.Combine(Work.Root, "backing");
            Private = Path.Combine(Work.Root, "private");
            Directory.CreateDirectory(directory ? Path.Combine(Backing, "folder") : Backing);
            Target = Path.Combine(Backing, directory ? @"folder\report.txt" : "report.txt");
            File.WriteAllText(Target, "Published old version");
            Policies.Current = LocalPolicyStore.CreateDefault() with
            {
                MonitoredScopes = new(new HashSet<string> { ".txt" }, [Backing], false, false), OverrideAllowed = true
            };
            Mount();
        }
        public void Mount()
        {
            Observer = new Observer();
            var engine = new InspectionService(Policies, new LocalQueueAuditSink(Work.QueueFile),
                ExtractorRegistry.CreateDefault(), new VerdictCache());
            Fs = new DriveFileSystem(Backing, Private, "S:", new ContentInspector(engine, Policies),
                Observer, DestinationKind.Cloud, "Synthetic", () => 123);
        }
        public void Restart() { Fs.Stop(); Mount(); }
        public void Open(string path, Action<object, object> action)
        {
            Assert.Equal(0, Fs.Open(path, 0, 0, out var node, out var handle, out _, out _));
            try { action(node, handle); }
            finally { Fs.Close(node, handle); }
        }
        public void Create(string path)
        {
            Assert.Equal(0, Fs.Create(path, 0, 0, 0, [], 0, out var node, out var handle, out _, out _));
            Fs.Close(node, handle);
        }
        public Content Write(string path, string bytes, string process = "explorer")
        {
            Content? content = null;
            Open(path, (node, handle) =>
            {
                content = ((Handle)handle).Node.Content!;
                content.Writer = new DriveWriter(123, process, 7, Sid, "synthetic-writer");
                Assert.Equal(0, Fs.SetFileSize(node, handle, 0, false, out _));
                var data = System.Text.Encoding.UTF8.GetBytes(bytes);
                var pointer = Marshal.AllocHGlobal(data.Length);
                try
                {
                    Marshal.Copy(data, 0, pointer, data.Length);
                    Assert.Equal(0, Fs.Write(node, handle, pointer, 0, (uint)data.Length, false, false, out var written, out _));
                    Assert.Equal((uint)data.Length, written);
                    Assert.Equal(0, Fs.Flush(node, handle, out _));
                }
                finally { Marshal.FreeHGlobal(pointer); }
            });
            return content!;
        }
        public Content Read(string path, string expected)
        {
            Content? content = null;
            Open(path, (_, handle) =>
            {
                content = ((Handle)handle).Node.Content!;
                Assert.Equal(expected, File.ReadAllText(content.Path));
                Assert.Equal(new FileInfo(content.Path).Length, content.Size);
            });
            return content!;
        }
        public void Dispose() { Fs?.Stop(); Work.Dispose(); }
    }
    internal sealed class Source : IPolicyStore
    {
        public Policy Current { get; set; } = null!;
        public Task<Policy> LoadAsync(CancellationToken token) { token.ThrowIfCancellationRequested(); return Task.FromResult(Current); }
    }
    internal sealed class Observer : IDriveObserver
    {
        public List<DriveDecision> Decisions { get; } = [];
        public List<DrivePublication> Publications { get; } = [];
        public TaskCompletionSource<DrivePublication> Published { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public DriveWriter? IdentifyWriter(int pid) => new(123, "explorer", 7, Fixture.Sid, "synthetic-writer");
        public void OnDecision(DriveDecision decision) => Decisions.Add(decision);
        public void OnPublication(DrivePublication publication) { Publications.Add(publication); Published.TrySetResult(publication); }
    }
}
