using System.Text.Json;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

/// <summary>Bloco "web" da política: quem liga a inspeção TLS é o console (docs/console-agente.md).</summary>
public sealed class WebInspectionPolicyTests
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };

    private static Policy Load(string web) => JsonSerializer.Deserialize<PolicyDocument>(
        $$"""{ "version": 3, "activeCategories": ["Cpf"] {{web}} }""", Json)!.ToPolicy();

    [Fact]
    public void Without_the_block_or_with_inspect_false_web_inspection_is_off()
    {
        Assert.Same(WebInspectionPolicy.Off, Load("").Web);
        Assert.False(Load(""", "web": { "inspect": false, "exceptionDomains": ["a.com"] }""").Web.Enabled);
    }

    [Fact]
    public void Inspect_true_carries_the_exception_domains()
    {
        var web = Load(""", "web": { "inspect": true, "exceptionDomains": ["intranet.empresa.com.br", " ", "Parceiro.com"] }""").Web;
        Assert.True(web.Enabled);
        Assert.Equal(["intranet.empresa.com.br", "Parceiro.com"], web.ExceptionDomains);
        // The proxy reloads its exceptions only when this key changes: order and case do not count.
        Assert.Equal(web.ExceptionsKey, new WebInspectionPolicy(true, ["parceiro.com", "INTRANET.empresa.com.br"]).ExceptionsKey);
    }

    [Fact]
    public void Too_many_exception_domains_invalidate_the_policy()
    {
        string domains = string.Join(",", Enumerable.Range(0, WebInspectionPolicy.MaxExceptionDomains + 1).Select(i => $"\"d{i}.com\""));
        Assert.Throws<InvalidPolicyException>(() => Load($$""", "web": { "inspect": true, "exceptionDomains": [{{domains}}] }"""));
    }

    [Fact]
    public void Snapshot_keeps_the_block()
    {
        var policy = Load(""", "web": { "inspect": true, "exceptionDomains": ["a.com"] }""");
        var again = JsonSerializer.Deserialize<PolicyDocument>(JsonSerializer.Serialize(PolicyDocument.FromPolicy(policy)), Json)!.ToPolicy();
        Assert.True(again.Web.Enabled);
        Assert.Equal(["a.com"], again.Web.ExceptionDomains);
    }
}
