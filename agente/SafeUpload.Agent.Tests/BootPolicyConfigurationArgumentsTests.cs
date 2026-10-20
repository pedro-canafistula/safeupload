using Microsoft.Extensions.Configuration;
using SafeUpload.Agent.Service;

namespace SafeUpload.Agent.Tests;

public sealed class BootPolicyConfigurationArgumentsTests
{
    [Theory]
    [InlineData("")]
    [InlineData("https://policy.example.test/agent/")]
    public void Seed_and_service_override_the_same_lower_priority_origin(string origin)
    {
        string[] service = ["--Interception:Mode=Minifilter", "--Interception:StagingPrototype=true",
            "--CentroAdministracao:BaseUrl=" + origin, "--CentroAdministracao:TimeoutSeconds=7"];
        Assert.True(Program.TryGetBootPolicyConfigurationArguments(["--seed-boot-policy", .. service], out var seed));
        Assert.Equal(service, seed);
        var serviceConfig = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["CentroAdministracao:BaseUrl"] = "http://shipped.example.test/agent/" }).AddCommandLine(service).Build();
        var seedConfig = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["CentroAdministracao:BaseUrl"] = "http://shipped.example.test/agent/" }).AddCommandLine(seed).Build();
        Assert.Equal(origin, serviceConfig["CentroAdministracao:BaseUrl"]);
        Assert.Equal(origin, seedConfig["CentroAdministracao:BaseUrl"]);
        Assert.Equal("7", seedConfig["CentroAdministracao:TimeoutSeconds"]);
    }

    [Fact]
    public void Split_values_and_duplicate_override_precedence_are_preserved()
    {
        string[] args = ["--seed-boot-policy", "--CentroAdministracao:BaseUrl=http://old.example.test/agent/",
            "--CentroAdministracao:BaseUrl", "https://current.example.test/agent/"];
        Assert.True(Program.TryGetBootPolicyConfigurationArguments(args, out var configuration));
        var values = new ConfigurationBuilder().AddCommandLine(configuration).Build();
        Assert.Equal("https://current.example.test/agent/", values["CentroAdministracao:BaseUrl"]);
    }

    [Fact]
    public void Standalone_seed_retains_existing_configuration_behavior()
    {
        Assert.True(Program.TryGetBootPolicyConfigurationArguments(["--seed-boot-policy"], out var configuration));
        Assert.Empty(configuration);
    }

    public static TheoryData<string[]> InvalidArguments => new()
    {
        Array.Empty<string>(),
        new[] { "ca", "install", "--seed-boot-policy" },
        new[] { "--seed-boot-policy", "ca", "install" },
        new[] { "--seed-boot-policy", "--seed-boot-policy" },
        new[] { "--seed-boot-policy", "--seed-boot-policy=true" },
        new[] { "--seed-boot-policy", "--CentroAdministracao:BaseUrl" },
        new[] { "--seed-boot-policy", "--CentroAdministracao:BaseUrl", "--other=value" },
        new[] { "--seed-boot-policy", "--" },
        new[] { "--seed-boot-policy", "--=value" },
        new[] { "--seed-boot-policy", "--valid=x", "unexpected-command" }
    };

    [Theory]
    [MemberData(nameof(InvalidArguments))]
    public void Seed_rejects_commands_and_malformed_configuration(string[] args)
    {
        Assert.False(Program.TryGetBootPolicyConfigurationArguments(args, out var configuration));
        Assert.Empty(configuration);
    }
}
