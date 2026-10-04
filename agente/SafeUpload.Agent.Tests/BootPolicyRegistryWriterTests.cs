using System.Buffers.Binary;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class BootPolicyRegistryWriterTests
{
    [Fact]
    public void Boot_record_is_bounded_and_contains_only_destination_scope_fields()
    {
        SafeUploadPolicyMessage candidate = BuildPolicy(@"C:\SafeUploadBootTests\Protected", removable: true);

        byte[] encoded = BootPolicyCodec.Encode(candidate);

        Assert.Equal(16656, encoded.Length);
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(encoded.AsSpan(0, 4)));
        Assert.Equal(16656u, BinaryPrimitives.ReadUInt32LittleEndian(encoded.AsSpan(4, 4)));
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(encoded.AsSpan(8, 4)));
        Assert.Equal((uint)PolicyFlags.Removable,
            BinaryPrimitives.ReadUInt32LittleEndian(encoded.AsSpan(12, 4)));
        BootPolicyScopes decoded = BootPolicyCodec.DecodeKnown(encoded);
        Assert.Single(decoded.Prefixes);
        Assert.Equal((uint)PolicyFlags.Removable, decoded.Flags);
        Assert.Contains("Protected", decoded.Prefixes[0], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Apply_persists_the_union_before_live_push_then_commits_and_clears_pending()
    {
        var backend = new FakeBackend(new BootPolicyScopes(
            [@"\Device\HarddiskVolume991\Previous"], (uint)PolicyFlags.Network));
        SafeUploadPolicyMessage candidate = BuildPolicy(@"C:\SafeUploadBootTests\Protected", removable: true);
        string candidatePrefix = BootPolicyCodec.DecodeKnown(BootPolicyCodec.Encode(candidate)).Prefixes[0];
        var writer = new BootPolicyRegistryWriter(backend);

        writer.Apply(candidate, () =>
        {
            backend.Operations.Add("authenticated-policy");
            BootPolicyScopes pending = BootPolicyCodec.DecodeKnown(Assert.IsType<byte[]>(backend.Pending));
            Assert.Contains(@"\Device\HarddiskVolume991\Previous", pending.Prefixes);
            Assert.Contains(candidatePrefix, pending.Prefixes);
            Assert.Equal((uint)(PolicyFlags.Network | PolicyFlags.Removable), pending.Flags);
        }, () => backend.Operations.Add("finalize"));

        Assert.Equal(new[] { "read", "pending", "authenticated-policy", "committed", "clear", "finalize" }, backend.Operations);
        Assert.Null(backend.Pending);
        BootPolicyScopes committed = BootPolicyCodec.DecodeKnown(Assert.IsType<byte[]>(backend.Committed));
        Assert.Equal(new[] { candidatePrefix }, committed.Prefixes);
        Assert.Equal((uint)PolicyFlags.Removable, committed.Flags);
    }

    [Fact]
    public void Failed_live_push_leaves_the_pending_union_for_a_stricter_next_boot()
    {
        var backend = new FakeBackend(new BootPolicyScopes(
            [@"\Device\HarddiskVolume991\Previous"], 0));
        SafeUploadPolicyMessage candidate = BuildPolicy(@"C:\SafeUploadBootTests\Protected");
        var writer = new BootPolicyRegistryWriter(backend);

        Assert.Throws<InvalidOperationException>(() => writer.Apply(candidate,
            () => throw new InvalidOperationException("port rejected policy"),
            () => backend.Operations.Add("finalize")));

        Assert.Equal(new[] { "read", "pending" }, backend.Operations);
        Assert.NotNull(backend.Pending);
        BootPolicyScopes pending = BootPolicyCodec.DecodeKnown(backend.Pending);
        Assert.Equal(2, pending.Prefixes.Count);
        Assert.Contains(@"\Device\HarddiskVolume991\Previous", pending.Prefixes);
        Assert.NotNull(backend.Committed);
    }

    [Fact]
    public void Failed_durable_finalization_keeps_committed_candidate_and_pending_union_ordered()
    {
        var backend = new FakeBackend(new BootPolicyScopes(
            [@"\Device\HarddiskVolume991\Previous"], 0));
        SafeUploadPolicyMessage candidate = BuildPolicy(@"C:\SafeUploadBootTests\Protected");
        var writer = new BootPolicyRegistryWriter(backend);

        Assert.Throws<IOException>(() => writer.Apply(candidate,
            () => backend.Operations.Add("authenticated-policy"),
            () => throw new IOException("driver did not finalize")));

        Assert.Equal(new[] { "read", "pending", "authenticated-policy", "committed", "clear" }, backend.Operations);
        Assert.Null(backend.Pending);
        Assert.NotNull(backend.Committed);
    }

    [Fact]
    public void Corrupt_v1_count_salvages_only_complete_bounded_valid_prefixes()
    {
        byte[] encoded = BootPolicyCodec.Encode(new BootPolicyScopes(
            [@"\Device\HarddiskVolume991\Protected"], 0));
        BinaryPrimitives.WriteUInt32LittleEndian(encoded.AsSpan(8, 4), uint.MaxValue);

        BootPolicyScopes salvaged = BootPolicyCodec.DecodeKnown(encoded);

        Assert.Equal(new[] { @"\Device\HarddiskVolume991\Protected" }, salvaged.Prefixes);
        Assert.Equal(0u, salvaged.Flags);
        BinaryPrimitives.WriteUInt32LittleEndian(encoded.AsSpan(0, 4), 99);
        Assert.Empty(BootPolicyCodec.DecodeKnown(encoded).Prefixes);
        Assert.Empty(BootPolicyCodec.DecodeKnown([1, 2, 3]).Prefixes);
    }

    [Fact]
    public void Union_refuses_more_than_the_registry_record_bound()
    {
        var left = new BootPolicyScopes(
            Enumerable.Range(0, 16).Select(index => $@"\Device\HarddiskVolume{index}\Old").ToArray(), 0);
        var right = new BootPolicyScopes(
            Enumerable.Range(16, 17).Select(index => $@"\Device\HarddiskVolume{index}\New").ToArray(), 0);

        Assert.Throws<InvalidDataException>(() => BootPolicyCodec.Union(left, right));
    }

    [Fact]
    public void Registry_path_and_dacl_are_the_declared_protected_location()
    {
        Assert.Equal(
            @"SYSTEM\CurrentControlSet\Services\SafeUpload\Parameters\BootPolicy",
            BootPolicyRegistryWriter.RegistryPath);
        Assert.Equal("O:SYD:P(A;;KA;;;SY)(A;;KA;;;TI)", BootPolicyRegistryWriter.SecurityDescriptorSddl);
    }

    private static SafeUploadPolicyMessage BuildPolicy(string destination, bool removable = false)
    {
        var builder = new PolicyBuilder().WithDestination(destination)
            .WithSource(@"C:\SafeUploadBootTests\Source")
            .WithAllSources()
            .WithVolumeKinds(removable, network: false);
        return builder.Build();
    }

    private sealed class FakeBackend(BootPolicyScopes initial) : IBootPolicyRegistryBackend
    {
        public List<string> Operations { get; } = ["read"];
        public byte[]? Pending { get; private set; }
        public byte[]? Committed { get; private set; } = BootPolicyCodec.Encode(initial);

        public BootPolicyScopes ReadKnownScopes() => initial;

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
    }
}
