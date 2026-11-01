using System.Diagnostics;
using System.IO.Compression;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Drive;

/// <summary>Outcome of inspecting one snapshot.</summary>
internal sealed record InspectionOutcome(bool Publish, string Summary);

/// <summary>
/// Inspects a private snapshot with the agent's normal engine. The file type comes from the content, not the name:
/// Word and Excel save through temporary names such as "~WRL0001.tmp" or "1A2B3C4D".
/// Anything that is not clearly approved is held (fail closed).
/// </summary>
internal sealed class ContentInspector(InspectionService inspection)
{
    public async Task<InspectionOutcome> InspectAsync(string snapshot, string destinationPath, string name, int processId,
        CancellationToken token)
    {
        try
        {
            var info = new System.IO.FileInfo(snapshot);
            var extension = DetectExtension(snapshot, Path.GetExtension(name));
            var effectiveName = Path.GetFileNameWithoutExtension(name) + extension;
            var operation = new FileOperation(snapshot, effectiveName, extension, info.Length, info.LastWriteTimeUtc,
                ProcessName(processId), processId, destinationPath, DestinationKind.Cloud);
            var result = await inspection.InspectStagedAsync(operation, token).ConfigureAwait(false);
            var categories = string.Join(",", result.Categories);
            var summary = $"verdict={result.Verdict} type={extension} reason={result.Reason ?? "-"} findings={result.Findings.Count}"
                + (categories.Length > 0 ? $" categories={categories}" : "");
            bool publish = result.Verdict == Verdict.Approved ||
                (result.Verdict == Verdict.AllowedWithoutInspection && result.Reason is "out_of_scope" or "excluded_process");
            return new InspectionOutcome(publish, summary);
        }
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

    private static string ProcessName(int processId)
    {
        try { return Process.GetProcessById(processId).ProcessName; }
        catch (Exception) { return "unknown"; }
    }
}
