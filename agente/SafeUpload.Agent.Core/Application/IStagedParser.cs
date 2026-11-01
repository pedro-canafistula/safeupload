using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Core.Application;

/// <summary>Executes complex parsers outside the service while retaining the exact read lease.</summary>
public interface IStagedParser
{
    Task<IReadOnlyList<Finding>> InspectAsync(string extension, Stream input, Policy policy, CancellationToken token);
}

public sealed class StagedParserFailureException(string reason) : IOException
{
    public string Reason { get; } = reason;
}

/// <summary>Only complete findings or a bounded failure code cross the worker boundary.</summary>
public sealed record StagedParserResult(IReadOnlyList<Finding> Findings, string? Failure);

public static class StagedParserExecution
{
    public static async Task<StagedParserResult> InspectAsync(Stream input, string extension,
        int maximumMiB, IReadOnlySet<Category> categories, CancellationToken token)
    {
        try
        {
            if (maximumMiB <= 0 || categories.Count == 0 || input.Length > (long)maximumMiB * 1024 * 1024)
                return new([], "file_too_large");
            var registry = ExtractorRegistry.CreateDefault();
            var extractor = registry.Resolve(extension);
            IReadOnlyList<Finding> findings;
            if (extractor is ZipArchiveExtractor archive)
            {
                var policy = Infrastructure.LocalPolicyStore.CreateDefault() with
                    { MaxFileSizeMb = maximumMiB, ActiveCategories = categories };
                findings = await archive.InspectAsync(input, registry, policy, token).ConfigureAwait(false);
            }
            else if (extractor is IStreamingTextExtractor streaming)
            {
                findings = await StreamingContentScanner.ScanAsync(() =>
                {
                    input.Position = 0;
                    return streaming.OpenReaderAsync(input, token);
                }, categories, token).ConfigureAwait(false);
            }
            else return new([], "unsupported_format");
            return new(findings, null);
        }
        catch (ArchiveSizeException) { return new([], "file_too_large"); }
        catch (ArchiveRefusalException failure) { return new([], failure.ReasonCode); }
        catch (InspectionLimitException) { return new([], "inspection_limit"); }
        catch (UnsupportedContentException) { return new([], "unsupported_format"); }
        catch (OperationCanceledException) { throw; }
        catch { return new([], "parse_error:worker"); }
    }
}
