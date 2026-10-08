using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Tests;

public sealed class NtPathTranslatorTests
{
    [Theory]
    [InlineData(@"\Device\Mup\server\share\report.txt", @"\\server\share\report.txt")]
    [InlineData(@"\Device\LanmanRedirector\server\share\report.txt", @"\\server\share\report.txt")]
    [InlineData(@"\Device\Mup\;LanmanRedirector\;Z:000000001\server\share\report.txt", @"\\server\share\report.txt")]
    [InlineData(@"\Device\Mup\server", null)]
    [InlineData(@"\Device\Mup\server\..\report.txt", null)]
    [InlineData(@"\Device\Mup\server\share\..\report.txt", null)]
    [InlineData(@"\Device\Mup\;LanmanRedirector", null)]
    public void Network_paths_translate_without_using_the_service_logon_drive_map(string path, string? expected)
        => Assert.Equal(expected, NtPathTranslator.ToDosPath(path));
}
