#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Collections.Immutable;
using System.Text;
using System.Text.Json.Nodes;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class PublicationApprovalCodecV1Tests
{
    [Fact]
    public void Explicit_capture_keeps_the_JsonIgnored_fingerprint_and_exact_round_trip()
    {
        var live = new InspectionResult(Verdict.Blocked, [new(Category.Cpf, "***.***.***-25") { MemberName = "é.txt" }],
            null, 1, false, 7, true) { PolicyContentFingerprint = ResourceSerializationLimitsV3Tests.Hash };
        var a = ResourceSerializationLimitsV3Tests.Approval() with { Inspection = PublicationApprovalInspectionV1.Capture(live) };
        byte[] bytes = PublicationApprovalCodecV1.Serialize(a);
        Assert.Equal(bytes, PublicationApprovalCodecV1.Serialize(PublicationApprovalCodecV1.Deserialize(bytes)));
        var b = a with { Inspection = a.Inspection with { PolicyContentFingerprint = new('B', 64) },
            PolicyCheck = a.PolicyCheck with { PolicyContentFingerprint = new('B', 64) },
            Justification = a.Justification! with { PolicyContentFingerprint = new('B', 64), BlockedPolicyFingerprint = new('B', 64) } };
        Assert.NotEqual(bytes, PublicationApprovalCodecV1.Serialize(b));
    }

    [Theory]
    [MemberData(nameof(SchemaMutations))]
    public void Missing_unknown_and_duplicate_properties_at_every_occupied_depth_refuse(string label, string json)
    {
        Assert.NotEmpty(label);
        Assert.Throws<InvalidDataException>(() => PublicationApprovalCodecV1.Deserialize(Encoding.UTF8.GetBytes(json)));
    }

    public static IEnumerable<object[]> SchemaMutations()
    {
        var approval = ResourceSerializationLimitsV3Tests.Approval();
        approval = approval with { Inspection = approval.Inspection with { Findings = [new(0, "***", "member.txt")] } };
        var root = JsonNode.Parse(PublicationApprovalCodecV1.Serialize(approval))!;
        foreach (var (path, obj) in Objects(root, ""))
        {
            foreach (var property in obj.ToArray())
            {
                var clone = root.DeepClone();
                ObjectAt(clone, path).Remove(property.Key);
                yield return [$"missing:{path}/{property.Key}", clone.ToJsonString()];
            }
            {
                var clone = root.DeepClone(); ObjectAt(clone, path).Add("Unknown", 1);
                yield return [$"unknown:{path}", clone.ToJsonString()];
            }
            // Duplicate every occupied object, including escaped aliases.
            string text = obj.ToJsonString();
            var first = obj.First();
            string duplicate = "{\"" + first.Key + "\":" + (first.Value?.ToJsonString() ?? "null") + "," + text[1..];
            yield return [$"duplicate:{path}", root.ToJsonString().Replace(text, duplicate, StringComparison.Ordinal)];
        }
    }

    [Theory]
    [InlineData("fraction")]
    [InlineData("exponent")]
    [InlineData("negative-zero")]
    [InlineData("numeric-string")]
    [InlineData("overflow")]
    [InlineData("uppercase-guid")]
    [InlineData("no-fingerprint")]
    [InlineData("mismatched-fingerprint")]
    [InlineData("not-consumed")]
    [InlineData("wrong-user")]
    [InlineData("wrong-operation")]
    [InlineData("not-in-scope")]
    [InlineData("unknown-verdict")]
    [InlineData("unknown-category")]
    [InlineData("trailing-root")]
    [InlineData("bom")]
    [InlineData("surrogate")]
    public void Hostile_encoding_and_policy_bindings_refuse(string mutation)
    {
        var approval = ResourceSerializationLimitsV3Tests.Approval();
        var root = JsonNode.Parse(PublicationApprovalCodecV1.Serialize(approval))!;
        string? raw = null;
        switch (mutation)
        {
            case "fraction": raw = root.ToJsonString().Replace("\"Version\":1", "\"Version\":1.0", StringComparison.Ordinal); break;
            case "exponent": raw = root.ToJsonString().Replace("\"Version\":1", "\"Version\":1e0", StringComparison.Ordinal); break;
            case "negative-zero": raw = root.ToJsonString().Replace("\"Version\":1", "\"Version\":-0", StringComparison.Ordinal); break;
            case "numeric-string": root["Version"] = "1"; break;
            case "overflow": root["Binding"]!["AllocationGeneration"] = ulong.MaxValue; break;
            case "uppercase-guid": root["Binding"]!["TransferId"] = ResourceSerializationLimitsV3Tests.Transfer.ToString().ToUpperInvariant(); break;
            case "no-fingerprint": root["Inspection"]!.AsObject().Remove("PolicyContentFingerprint"); break;
            case "mismatched-fingerprint": root["Inspection"]!["PolicyContentFingerprint"] = new string('B', 64); break;
            case "not-consumed": root["Justification"]!["ConsumedAtUtcTicks"] = 2; break;
            case "wrong-user": root["Justification"]!["Binding"]!["RequestorSid"] = "S-1-5-18"; break;
            case "wrong-operation": root["PolicyCheck"]!["Operation"]!["ProcessId"] = 43; break;
            case "not-in-scope": root["Inspection"]!["InScope"] = false; break;
            case "unknown-verdict": root["Inspection"]!["Verdict"] = 3; break;
            case "unknown-category": root["Inspection"]!["Findings"] = new JsonArray(new JsonObject { ["Category"] = 9, ["MaskedSnippet"] = "***", ["MemberName"] = null }); break;
            case "trailing-root": raw = root.ToJsonString() + "{}"; break;
            case "bom": raw = "\ufeff" + root.ToJsonString(); break;
            case "surrogate": raw = root.ToJsonString().Replace("notepad.exe", "\\uD800", StringComparison.Ordinal); break;
            default: throw new ArgumentOutOfRangeException(nameof(mutation));
        }
        Assert.Throws<InvalidDataException>(() => PublicationApprovalCodecV1.Deserialize(Encoding.UTF8.GetBytes(raw ?? root.ToJsonString())));
    }

    [Fact]
    public void Invalid_managed_surrogate_is_refused_before_writer_replacement()
    {
        var approval = ResourceSerializationLimitsV3Tests.Approval();
        Assert.Throws<InvalidDataException>(() => PublicationApprovalCodecV1.Serialize(approval with
        { Operation = approval.Operation with { FileName = "\ud800" } }));
    }

    private static IEnumerable<(string Path, JsonObject Object)> Objects(JsonNode node, string path)
    {
        if (node is JsonObject obj)
        {
            yield return (path, obj);
            foreach (var property in obj)
                if (property.Value is not null) foreach (var nested in Objects(property.Value, path + "/" + property.Key)) yield return nested;
        }
        else if (node is JsonArray array)
            for (int index = 0; index < array.Count; index++)
                if (array[index] is { } item) foreach (var nested in Objects(item, path + "/" + index)) yield return nested;
    }
    private static JsonObject ObjectAt(JsonNode node, string path)
    {
        foreach (var part in path.Split('/', StringSplitOptions.RemoveEmptyEntries)) node = node is JsonArray ? node[int.Parse(part)]! : node[part]!;
        return node.AsObject();
    }
}
#endif
