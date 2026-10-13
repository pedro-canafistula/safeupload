using DocumentFormat.OpenXml.Packaging;

namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

internal static class OpenXmlInspectionGuard
{
    // Text extraction cannot inspect these payloads. Walk relationships from the
    // package, not just the body/sheet: headers, notes and drawings can own them.
    // This is a known-content refusal, not proof that every Open XML part is covered.
    public static void RejectUnsupportedPayloads(OpenXmlPackage package, CancellationToken cancellationToken)
    {
        var pending = new Stack<OpenXmlPartContainer>();
        var visited = new HashSet<Uri>();
        pending.Push(package);

        while (pending.TryPop(out var container))
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var relationship in container.Parts)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var part = relationship.OpenXmlPart;
                if (!visited.Add(part.Uri)) continue;

                if (part is ImagePart or ThumbnailPart or EmbeddedObjectPart or EmbeddedPackagePart
                    or AlternativeFormatImportPart or EmbeddedControlPersistencePart
                    or EmbeddedControlPersistenceBinaryDataPart)
                    throw new UnsupportedContentException();

                pending.Push(part);
            }
        }
    }
}
