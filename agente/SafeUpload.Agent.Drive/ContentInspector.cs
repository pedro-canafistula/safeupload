using System.IO.Compression;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Drive;

/// <summary>Outcome of inspecting one snapshot.</summary>
internal sealed record InspectionOutcome(bool Publish, string Summary, FileOperation? Operation = null, InspectionResult? Result = null);

/// <summary>
/// Inspects a private snapshot with the agent's normal engine. The file type comes from the content, not the name:
/// Word and Excel save through temporary names such as "~WRL0001.tmp" or "1A2B3C4D".
/// Anything that is not clearly approved is held (fail closed).
/// </summary>
public sealed class ContentInspector(InspectionService inspection, IPolicyStore policies)
{
    /// <summary>Rechecks the locally available validated policy; remote composition supplies its background snapshot.</summary>
    internal async Task<bool> IsPublicationAllowedAsync(DriveDecision decision, string destinationPath,
        CancellationToken token)
    {
        if (decision.Operation is not { } operation || decision.Result is not { PolicyContentFingerprint: { } binding } result)
            return false;
        var policy = await policies.LoadCurrentAsync(token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        if (!string.Equals(binding, PolicyContentFingerprint.Compute(policy), StringComparison.Ordinal)) return false;
        operation = operation with { DestinationPath = destinationPath };
        if (!policy.IsMonitoredDestination(operation)) return false;
        return decision.ApprovalKind switch
        {
            DriveApprovalKind.Inspection => result.Verdict == Verdict.Approved ||
                (result.Verdict == Verdict.AllowedWithoutInspection &&
                 ((result.Reason == "excluded_process" && policy.IsExcludedProcess(operation.ProcessName)) ||
                  (result.Reason == "out_of_scope" && !policy.IsMonitoredExtension(operation.Extension)))),
            DriveApprovalKind.Audit => policy.AuditOnly && result.InScope && result.IsBlocked &&
                result.Reason is null && result.Categories.Count > 0,
            DriveApprovalKind.Justification => policy.OverrideAllowed && result.InScope && result.IsBlocked &&
                result.FailureKind != InspectionFailureKind.NotEnoughStagingSpace && policy.IsMonitoredExtension(operation.Extension),
            _ => false
        };
    }

    internal async Task<InspectionOutcome> InspectAsync(string snapshot, string destinationPath, DestinationKind kind,
        string name, DriveWriter? writer, CancellationToken token)
    {
        try
        {
            var info = new System.IO.FileInfo(snapshot);
            var extension = DetectExtension(snapshot, Path.GetExtension(name));
            var effectiveName = Path.GetFileNameWithoutExtension(name) + extension;
            var operation = new FileOperation(snapshot, effectiveName, extension, info.Length, info.LastWriteTimeUtc,
                writer?.ProcessName ?? "unknown", writer?.ProcessId ?? 0, destinationPath, kind);
            var result = await inspection.InspectStagedAsync(operation, token).ConfigureAwait(false);
            var categories = string.Join(",", result.Categories);
            var summary = $"verdict={result.Verdict} type={extension} reason={result.Reason ?? "-"} findings={result.Findings.Count}"
                + (categories.Length > 0 ? $" categories={categories}" : "");
            bool publish = result.Verdict == Verdict.Approved;
            if (result.Verdict == Verdict.AllowedWithoutInspection && result.Reason is "out_of_scope" or "excluded_process")
            {
                // Everything written to a SafeUpload drive goes to a protected place. "Out of scope" may only mean a file
                // type the policy does not inspect; a monitored type means the destination itself was not recognized.
                var policy = await policies.LoadCurrentAsync(token).ConfigureAwait(false);
                publish = result.Reason == "excluded_process" || !policy.IsMonitoredExtension(extension);
                if (!publish) summary += " held=destination_not_monitored";
            }
            return new InspectionOutcome(publish, summary, operation, result);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (Exception error)
        {
            return new InspectionOutcome(false, $"verdict=Error reason={error.GetType().Name}: {error.Message}");
        }
    }

    /// <summary>Content sniffing for the formats the engine understands; falls back to the name's extension.</summary>
    internal static string DetectExtension(string path, string nameExtension)
    {
        Span<byte> head = stackalloc byte[8];
        int read;
        using (var stream = File.OpenRead(path))
            read = stream.Read(head);
        head = head[..read];

        if (head.StartsWith("PK\u0003\u0004"u8))
        {
            try
            {
                using var zip = ZipFile.OpenRead(path);
                if (zip.GetEntry("word/document.xml") is not null) return ".docx";
                if (zip.GetEntry("xl/workbook.xml") is not null) return ".xlsx";
                if (zip.GetEntry("ppt/presentation.xml") is not null) return ".pptx";
            }
            catch (InvalidDataException)
            {
            }
            return ".zip";
        }
        if (head.StartsWith("%PDF"u8)) return ".pdf";
        if (head.StartsWith(new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C })) return ".7z";
        if (nameExtension is ".txt" or ".csv") return nameExtension;
        return LooksLikeText(path) ? ".txt" : nameExtension.ToLowerInvariant();
    }

    private static bool LooksLikeText(string path)
    {
        var buffer = new byte[4096];
        int read;
        using (var stream = File.OpenRead(path))
            read = stream.Read(buffer);
        if (read == 0) return true;
        if (read >= 2 && ((buffer[0] == 0xFF && buffer[1] == 0xFE) || (buffer[0] == 0xFE && buffer[1] == 0xFF))) return true;
        for (int i = 0; i < read; i++)
            if (buffer[i] == 0) return false;
        return true;
    }
}
