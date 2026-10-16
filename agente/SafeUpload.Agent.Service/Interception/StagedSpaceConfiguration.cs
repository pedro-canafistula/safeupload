using Microsoft.Extensions.Configuration;

namespace SafeUpload.Agent.Service.Interception;

internal static class StagedSpaceConfiguration
{
    private const string Prefix = "Interception:StageSpace:";
    internal const long DefaultParserMemoryBytes = 256L * 1024 * 1024;
    internal static bool IsEnabled(IConfiguration configuration) => configuration.GetValue<bool?>(Prefix + "Enabled") ?? true;

    internal static long ParserMemoryBytes(IConfiguration configuration)
    {
        long value = configuration.GetValue<long?>(Prefix + "ParserMemoryBytes") ?? DefaultParserMemoryBytes;
        if (value < 64L * 1024 * 1024 || value > 2L * 1024 * 1024 * 1024)
            throw new IOException("The parser memory budget is outside the supported range.");
        return value;
    }

    internal static StagedSpaceOptions Resolve(IConfiguration configuration, string stagingRoot,
        Func<string, (long Available, long Total)>? readVolume = null)
    {
        var volume = (readVolume ?? ReadVolume)(Path.GetFullPath(stagingRoot));
        if (volume.Available < 0 || volume.Total <= 0 || volume.Available > volume.Total)
            throw new IOException("The staging volume returned invalid space information.");
        var defaults = StagedSpaceOptions.Defaults(volume.Available, volume.Total);
        long total = configuration.GetValue<long?>(Prefix + "TotalBytes") ?? defaults.TotalBytes;
        return new(IsEnabled(configuration), total,
            configuration.GetValue<long?>(Prefix + "PerUserBytes") ?? Math.Min(8 * StagedSpaceOptions.GiB, total / 4),
            configuration.GetValue<long?>(Prefix + "FreeSpaceFloorBytes") ?? defaults.FreeSpaceFloorBytes);
    }

    private static (long Available, long Total) ReadVolume(string stagingRoot)
    {
        var volume = new DriveInfo(Path.GetPathRoot(stagingRoot)!);
        return (volume.AvailableFreeSpace, volume.TotalSize);
    }
}
