using System.Text;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

/// <summary>Regras personalizadas do console (docs/console-agente.md, "Regras personalizadas").</summary>
public sealed class CustomRulesTests
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };

    /// <summary>Mesmo arquivo do backend (RulesContractTest.java): o "when" é exatamente o que o servidor publica.</summary>
    public static IEnumerable<object[]> SharedCases()
    {
        string? directory = AppContext.BaseDirectory;
        while (directory is not null && !File.Exists(Path.Combine(directory, "AGENTS.md")))
            directory = Path.GetDirectoryName(directory);
        string file = Path.Combine(directory ?? throw new DirectoryNotFoundException("Raiz do repositório"),
            "web", "back", "src", "test", "resources", "regras-personalizadas-casos.json");
        using var document = JsonDocument.Parse(File.ReadAllText(file));
        foreach (var item in document.RootElement.EnumerateArray())
            foreach (var text in item.GetProperty("textos").EnumerateArray())
                yield return [item.GetProperty("nome").GetString()!, item.GetProperty("when").GetRawText(),
                    text.GetProperty("texto").GetString()!, text.GetProperty("esperado").GetBoolean()];
    }

    [Theory]
    [MemberData(nameof(SharedCases))]
    public void Agent_evaluates_the_shared_cases_like_the_server(string name, string when, string text, bool expected)
    {
        var rules = Compile(when);
        Assert.True(expected == rules.Scan(text).Count > 0, name + " / " + text);
        // A leitura em blocos de 1 caractere chega ao mesmo resultado.
        var scan = rules.Start();
        foreach (char c in text) scan.Feed([c]);
        Assert.True(expected == scan.Complete().Count > 0, name + " (em blocos) / " + text);
    }

    [Fact]
    public void Large_text_counts_each_occurrence_once_across_windows()
    {
        var rules = Compile("""{ "pattern": "CT\\-[0-9]{4}\\/[0-9]{2}", "min": 40 }""");
        var text = new StringBuilder();
        // 40 ocorrências espalhadas por ~700 KB, várias cruzando a fronteira das janelas de 64 KB.
        for (int i = 0; i < 40; i++)
        {
            text.Append('x', CustomRuleScan.Window - 5 + (i % 7));
            text.Append($"CT-{1000 + i}/26 ");
        }
        Assert.Single(rules.Scan(text.ToString()));
        var tooFew = Compile("""{ "pattern": "CT\\-[0-9]{4}\\/[0-9]{2}", "min": 41 }""");
        Assert.Empty(tooFew.Scan(text.ToString()));

        var scan = rules.Start();
        string all = text.ToString();
        for (int offset = 0; offset < all.Length; offset += 8192)
            scan.Feed(all.AsSpan(offset, Math.Min(8192, all.Length - offset)));
        Assert.Single(scan.Complete());
    }

    [Fact]
    public void Finding_carries_category_by_action_rule_name_and_masked_snippet()
    {
        var set = CustomRuleSet.Compile([
            Rule(1, "Contratos Atlas", alert: true, """{ "words": ["projeto atlas"] }"""),
            Rule(2, "Matrícula", alert: false, """{ "pattern": "MAT\\-([0-9]{8})", "validator": "mod11", "group": 1 }""")]);
        var findings = set.Scan("PROJETO ATLAS, matrícula MAT-12345679");
        Assert.Equal(2, findings.Count);
        Assert.Equal(Category.CustomRuleAlert, findings[0].Category);
        Assert.Equal("Contratos Atlas", findings[0].RuleName);
        Assert.Equal(Category.CustomRule, findings[1].Category);
        Assert.Equal("Matrícula", findings[1].RuleName);
        Assert.DoesNotContain("12345679", findings[1].MaskedSnippet);
    }

    [Fact]
    public void Policy_document_applies_rules_and_alert_only_releases_alert_rules()
    {
        var document = JsonSerializer.Deserialize<PolicyDocument>("""
            { "version": 9, "activeCategories": ["Cpf", "CustomRule", "CustomRuleAlert"], "alertCategories": ["CustomRuleAlert"],
              "customRulesFormat": 1,
              "customRules": [
                { "id": 7, "revision": 2, "name": "Atlas", "alert": true, "when": { "words": ["projeto atlas"] } },
                { "id": 8, "revision": 1, "name": "Segredo", "alert": false, "when": { "words": ["segredo industrial"] } } ] }
            """, Json)!;
        var policy = document.ToPolicy();
        policy.EnsureValid();
        Assert.Equal(2, policy.Rules.Rules.Count);
        var alertOnly = ContentScanner.Scan("Projeto Atlas", policy.ActiveCategories, policy.Rules);
        Assert.True(policy.ReleasesWithAlert(alertOnly.Select(f => f.Category)));
        var blocking = ContentScanner.Scan("Projeto Atlas e o segredo industrial", policy.ActiveCategories, policy.Rules);
        Assert.False(policy.ReleasesWithAlert(blocking.Select(f => f.Category)));
        Assert.Equal(["Atlas", "Segredo"], AuditEvent.RuleNames(blocking));

        var changed = JsonSerializer.Deserialize<PolicyDocument>(JsonSerializer.Serialize(document, Json)
            .Replace("\"revision\":2", "\"revision\":3"), Json)!.ToPolicy();
        Assert.NotEqual(PolicyContentFingerprint.Compute(policy), PolicyContentFingerprint.Compute(changed));
    }

    [Theory]
    [InlineData("""{ "customRulesFormat": 2, "customRules": [ { "id": 1, "revision": 1, "name": "x", "when": { "words": ["a"] } } ] }""")]
    [InlineData("""{ "customRulesFormat": 1, "customRules": [ { "id": 1, "revision": 1, "name": "x", "when": { "pattern": "(?<=a)b" } } ] }""")]
    [InlineData("""{ "customRulesFormat": 1, "customRules": [ { "id": 1, "revision": 1, "name": "x", "when": { "pattern": "a(", "words": ["a"] } } ] }""")]
    [InlineData("""{ "customRulesFormat": 1, "customRules": [ { "id": 1, "revision": 1, "name": "x", "when": { "words": ["Não Normalizado"] } } ] }""")]
    [InlineData("""{ "customRulesFormat": 1, "customRules": [ { "id": 1, "revision": 1, "name": "x", "when": { "pattern": "a", "validator": "rg" } } ] }""")]
    public void Rules_this_agent_cannot_run_make_the_version_invalid(string rules)
    {
        string json = """{ "version": 3, "activeCategories": ["CustomRule"], """ + rules[1..];
        var document = JsonSerializer.Deserialize<PolicyDocument>(json, Json)!;
        Assert.Throws<InvalidPolicyException>(() => document.ToPolicy());
    }

    [Fact]
    public void Folding_matches_the_backend_definition()
    {
        Assert.Equal("divulgacao autorizada e otimo", TextFolder.Fold("Divulgação  AUTORIZADA\n—\tÉ-ótimo"));
        Assert.Equal("a b", TextFolder.Fold("a b"));
        Assert.True(Mod11Validator.IsValid("12345679"));
        Assert.False(Mod11Validator.IsValid("12345670"));
    }

    private static CustomRuleSet Compile(string when) => CustomRuleSet.Compile([Rule(1, "regra", alert: false, when)]);

    private static CustomRule Rule(int id, string name, bool alert, string when) =>
        new(id, 1, name, alert, JsonSerializer.Deserialize<CustomConditionDocument>(when, Json)!.ToCondition());
}
