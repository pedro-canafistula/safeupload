using Microsoft.Extensions.Logging.Abstractions;
using System.Text;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Gate;

namespace SafeUpload.Agent.Tests;

public sealed class GatePolicyMessageTests
{
    [Theory]
    [InlineData(false, false, 0u)]
    [InlineData(true, false, 1u)]
    [InlineData(false, true, 2u)]
    [InlineData(true, true, 3u)]
    public void Existing_v1_layout_preserves_every_path_flags_and_terminator(bool removable, bool network, uint flags)
    {
        string[] paths = [@"\Device\HarddiskVolume3\Protected", @"\Device\Mup\server\share\Dados" ];
        var policy = GatePolicyMessage.Create(paths, removable, network, path => path);
        Assert.Equal(16 + 16 * 512 * 2, policy.Bytes.Length);
        Assert.Equal(1u, BitConverter.ToUInt32(policy.Bytes, 0));
        Assert.Equal(1u, BitConverter.ToUInt32(policy.Bytes, 4));
        Assert.Equal(flags, BitConverter.ToUInt32(policy.Bytes, 8));
        Assert.Equal(2u, BitConverter.ToUInt32(policy.Bytes, 12));
        for (int i = 0; i < paths.Length; i++)
        {
            int offset = 16 + i * 512 * 2;
            var expected = Encoding.Unicode.GetBytes(paths[i]);
            Assert.Equal(expected, policy.Bytes.AsSpan(offset, expected.Length).ToArray());
            Assert.All(policy.Bytes.Skip(offset + expected.Length).Take(512 * 2 - expected.Length), value => Assert.Equal((byte)0, value));
        }
        Assert.All(policy.Bytes.Skip(16 + paths.Length * 512 * 2), value => Assert.Equal((byte)0, value));
    }

    [Fact]
    public void Exact_count_and_path_length_limits_are_represented_without_truncation()
    {
        var paths = Enumerable.Range(0, 16).Select(i => i.ToString().PadRight(511, 'x')).ToArray();
        var policy = GatePolicyMessage.Create(paths, false, false, path => path);
        Assert.Equal(16, policy.PathCount);
        Assert.Equal(16u, BitConverter.ToUInt32(policy.Bytes, 12));
        for (int i = 0; i < paths.Length; i++)
            Assert.Equal(paths[i], Encoding.Unicode.GetString(policy.Bytes, 16 + i * 1024, 1022));
    }

    [Fact]
    public void Excess_count_is_rejected_before_resolving_any_path()
    {
        int calls = 0;
        Assert.Throws<InvalidPolicyException>(() => GatePolicyMessage.Create(new string[17], false, false,
            path => { calls++; return path; }));
        Assert.Equal(0, calls);
    }

    [Fact]
    public void Client_rejects_excess_scope_without_opening_a_driver_connection()
    {
        using var client = new GateClient(NullLogger<GateClient>.Instance);
        var folders = Enumerable.Range(0, 17).Select(i => @"C:\Synthetic\Folder" + i).ToArray();
        Assert.Throws<InvalidPolicyException>(() => client.Apply(folders, false, false));
        Assert.False(client.IsConnected);
    }

    [Theory]
    [InlineData("unresolved")]
    [InlineData("empty")]
    [InlineData("long")]
    [InlineData("nul")]
    [InlineData("encoding")]
    public void Unrepresentable_member_rejects_the_whole_policy(string invalid)
    {
        string? bad = invalid switch
        {
            "unresolved" => null, "empty" => "", "long" => new string('x', 512),
            "nul" => "synthetic\0tail", _ => "synthetic" + (char)0xd800
        };
        Assert.Throws<InvalidPolicyException>(() => GatePolicyMessage.Create(["first", "bad", "last"], true, true,
            path => path == "bad" ? bad : path));
    }

    [Fact]
    public void Key_changes_with_any_transmitted_scope_or_flag()
    {
        var first = GatePolicyMessage.Create(["path"], false, false, path => path);
        Assert.Equal(first.Key, GatePolicyMessage.Create(["path"], false, false, path => path).Key);
        Assert.NotEqual(first.Key, GatePolicyMessage.Create(["different"], false, false, path => path).Key);
        Assert.NotEqual(first.Key, GatePolicyMessage.Create(["path"], true, false, path => path).Key);
        Assert.NotEqual(first.Key, GatePolicyMessage.Create(["path"], false, true, path => path).Key);
    }

    [Fact]
    public void Empty_folder_scope_preserves_volume_flags()
    {
        var policy = GatePolicyMessage.Create([], true, true, _ => throw new InvalidOperationException());
        Assert.Equal(0u, BitConverter.ToUInt32(policy.Bytes, 12));
        Assert.Equal(3u, BitConverter.ToUInt32(policy.Bytes, 8));
    }
}
