using System.Buffers.Binary;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class BootPolicySeederTests
{
    private const string Prefix = @"\Device\HarddiskVolume7\SafeUpload\Protected";

    [Fact]
    public async Task Seed_refuses_policy_when_protected_acl_check_rejects_it()
    {
        using var workspace = new TestWorkspace();
        workspace.WritePolicy(PolicyJson);
        var store = new LocalPolicyStore(workspace.PolicyFile, _ => false);
        var backend = new RecordingBackend();
        var writer = new BootPolicyRegistryWriter(backend);

        await Assert.ThrowsAsync<PolicyFileAclRejectedException>(() =>
            BootPolicySeeder.SeedAsync(store, writer, CancellationToken.None));

        Assert.Empty(backend.Operations);
    }

    [Fact]
    public async Task Seed_commits_the_exact_driver_scope_record_and_removes_pending()
    {
        using var workspace = new TestWorkspace();
        workspace.WritePolicy(PolicyJson);
        var store = new LocalPolicyStore(workspace.PolicyFile, _ => true);
        var backend = new RecordingBackend();
        var writer = new BootPolicyRegistryWriter(backend);

        await BootPolicySeeder.SeedAsync(store, writer, CancellationToken.None);

        Assert.Equal(ExpectedRecord(), backend.Committed);
        Assert.Null(backend.Pending);
        Assert.Equal(new[] { "read", "pending", "committed", "clear", "verify-seeded" }, backend.Operations);
    }

    [Fact]
    public async Task Seed_is_idempotent_and_never_leaves_pending_scopes()
    {
        using var workspace = new TestWorkspace();
        workspace.WritePolicy(PolicyJson);
        var store = new LocalPolicyStore(workspace.PolicyFile, _ => true);
        var backend = new RecordingBackend();
        var writer = new BootPolicyRegistryWriter(backend);

        await BootPolicySeeder.SeedAsync(store, writer, CancellationToken.None);
        byte[] firstCommit = Assert.IsType<byte[]>(backend.Committed).ToArray();
        await BootPolicySeeder.SeedAsync(store, writer, CancellationToken.None);

        Assert.Equal(firstCommit, backend.Committed);
        Assert.Null(backend.Pending);
        BootPolicyScopes committed = BootPolicyCodec.DecodeKnown(backend.Committed);
        Assert.Equal(new[] { Prefix }, committed.Prefixes);
        Assert.Equal(3u, committed.Flags);
        Assert.Equal(2, backend.Operations.Count(operation => operation == "verify-seeded"));
    }

    private static byte[] ExpectedRecord()
    {
        byte[] expected = new byte[BootPolicyCodec.PayloadBytes];
        BinaryPrimitives.WriteUInt32LittleEndian(expected.AsSpan(0, 4), BootPolicyCodec.Version);
        BinaryPrimitives.WriteUInt32LittleEndian(expected.AsSpan(4, 4), (uint)BootPolicyCodec.PayloadBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(expected.AsSpan(8, 4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(expected.AsSpan(12, 4), 3);

        int offset = BootPolicyCodec.HeaderBytes;
        for (int index = 0; index < Prefix.Length; index++)
            BinaryPrimitives.WriteUInt16LittleEndian(expected.AsSpan(offset + index * 2, 2), Prefix[index]);
        return expected;
    }

    private const string PolicyJson = """
        {
          "version": 1,
          "activeCategories": ["Cpf"],
          "monitoredScopes": {
            "extensions": [".txt"],
            "destinationPaths": ["\\Device\\HarddiskVolume7\\SafeUpload\\Protected"],
            "removableDrives": true,
            "networkPaths": true
          },
          "maxFileSizeMb": 20,
          "inspectionTimeoutSeconds": 5
        }
        """;

    private sealed class RecordingBackend : IBootPolicyRegistryBackend
    {
        public List<string> Operations { get; } = [];
        public byte[]? Pending { get; private set; }
        public byte[]? Committed { get; private set; }

        public BootPolicyScopes ReadKnownScopes()
        {
            Operations.Add("read");
            return BootPolicyCodec.Union(
                BootPolicyCodec.DecodeKnown(Committed),
                BootPolicyCodec.DecodeKnown(Pending));
        }

        public void WritePending(byte[] value)
        {
            Pending = value.ToArray();
            Operations.Add("pending");
        }

        public void WriteCommitted(byte[] value)
        {
            Committed = value.ToArray();
            Operations.Add("committed");
        }

        public void ClearPending()
        {
            Pending = null;
            Operations.Add("clear");
        }

        public void VerifySeeded(byte[] expectedCommitted)
        {
            Operations.Add("verify-seeded");
            if (Committed is null || !Committed.AsSpan().SequenceEqual(expectedCommitted) || Pending is not null)
                throw new IOException("Fake registry read-back failed.");
        }
    }
}
