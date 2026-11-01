using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

/// <summary>Complete-or-refuse ZIP inspection. Plaintext members stream from the held archive; seek-requiring members have a fixed memory budget; names never become paths.</summary>
public sealed class ZipArchiveExtractor : IStreamingTextExtractor
{
    /// <inheritdoc />
    public IReadOnlySet<string> SupportedExtensions { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".zip" };

    /// <inheritdoc />
    public Task<TextReader> OpenReaderAsync(Stream content, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content); cancellationToken.ThrowIfCancellationRequested();
        var budget = new ArchiveInspectionBudget(LocalPolicyStore.CreateDefault().MaxFileSizeBytes);
        return Task.FromResult<TextReader>(new ChunkedTextReader(token => ReadText(content, budget, token)));
    }

    /// <inheritdoc />
    public async Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
    {
        using var reader = await OpenReaderAsync(content, cancellationToken).ConfigureAwait(false);
        return await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
    }

    // Both service modes enter here, inside the original worker/deadline. The
    // legacy outer capture/hash/cache remains unchanged; no child service call.
    internal async Task<IReadOnlyList<Finding>> InspectAsync(Stream content, ExtractorRegistry registry, Policy policy, CancellationToken token)
    {
        var budget = new ArchiveInspectionBudget(policy.MaxFileSizeBytes);
        var findings = new List<Finding>();
        foreach (var member in Walk(content, registry, budget, 1, null, () => token))
        {
            var names = await Scan(() => Task.FromResult<TextReader>(new StringReader(member.Path.Name))).ConfigureAwait(false);
            member.Path.Sensitive = names.Count != 0;
            string? display = null;
            Add(names);
            if (member.Content is not null)
            {
                var streaming = (IStreamingTextExtractor)member.Extractor!;
                Task<TextReader> OpenReader()
                {
                    member.Content.Position = 0;
                    return streaming.OpenReaderAsync(member.Content, token);
                }
                using BoundedTextReplay? replay = member.Extractor is PlainTextExtractor
                    ? new(OpenReader, maximumCharacters: 2 * 1024 * 1024) : null;
                Add(await Scan(replay is null ? OpenReader : replay.OpenAsync).ConfigureAwait(false));
            }

            Task<IReadOnlyList<Finding>> Scan(Func<Task<TextReader>> reader) => StreamingContentScanner.ScanAsync(reader,
                policy.ActiveCategories, token, StreamingContentScanner.MaximumCandidates - findings.Count);
            void Add(IReadOnlyList<Finding> added)
            {
                if (added.Count == 0) return;
                if (display is null)
                {
                    budget.RetainDiagnostic(member.Path.DisplayLength());
                    display = member.Path.Display();
                }
                foreach (var finding in added) findings.Add(finding with { MemberName = display });
            }
        }
        return findings;
    }

    private static IEnumerable<ReadOnlyMemory<char>> ReadText(Stream content, ArchiveInspectionBudget budget, Func<CancellationToken> token)
    {
        var buffer = new char[8192];
        foreach (var member in Walk(content, ExtractorRegistry.CreateDefault(), budget, 1, null, token))
        {
            yield return member.Path.Name.AsMemory(); yield return "\n".AsMemory();
            if (member.Content is null) continue;
            using var reader = ((IStreamingTextExtractor)member.Extractor!).OpenReaderAsync(member.Content, token()).GetAwaiter().GetResult();
            int count;
            while ((count = reader.ReadAsync(buffer.AsMemory(), token()).GetAwaiter().GetResult()) != 0)
                yield return buffer.AsMemory(0, count);
            yield return "\n".AsMemory();
        }
    }

    private sealed class MemberPath(string name, MemberPath? parent)
    {
        internal string Name { get; } = name;
        internal bool Sensitive;
        internal int DisplayLength() => (parent is null ? 0 : parent.DisplayLength() + 2) +
            (Sensitive ? "[sensitive name]".Length : Name.Sum(c => char.IsControl(c) ? 6 : 1));
        internal string Display()
        {
            var own = Sensitive ? "[sensitive name]" : Escape(Name);
            return parent is null ? own : parent.Display() + "!/" + own;
        }
        private static string Escape(string value)
        {
            if (!value.Any(char.IsControl)) return value;
            var result = new StringBuilder();
            foreach (char c in value) if (char.IsControl(c)) result.Append("\\u").Append(((int)c).ToString("X4")); else result.Append(c);
            return result.ToString();
        }
    }
    private sealed record Member(MemberPath Path, Stream? Content, ITextExtractor? Extractor);

    private static IEnumerable<Member> Walk(Stream content, ExtractorRegistry registry, ArchiveInspectionBudget budget,
        int depth, MemberPath? parent, Func<CancellationToken> token)
    {
        token().ThrowIfCancellationRequested();
        var records = ZipInspectionGuard.Inspect(content, budget, depth, token());
        // The strict inventory has already bounded metadata count/size before
        // the BCL ZIP parser loads it. Only this validated held stream is used.
        content.Position = 0;
        using var zip = new ZipArchive(content, ZipArchiveMode.Read, leaveOpen: true);
        if (zip.Entries.Count != records.Count) throw new InvalidDataException("ZIP inventories disagree.");
        for (int index = 0; index < records.Count; index++)
        {
            token().ThrowIfCancellationRequested();
            var record = records[index]; var entry = zip.Entries[index];
            if (entry.FullName != record.Name || entry.Length != record.Length || entry.CompressedLength != record.CompressedLength)
                throw new InvalidDataException("ZIP member metadata disagrees.");
            var path = new MemberPath(record.Name, parent);
            // A ZIP name is data; it is never used as an extraction pathname.
            int slash = Math.Max(record.Name.LastIndexOf('/'), record.Name.LastIndexOf('\\'));
            int dot = record.Name.LastIndexOf('.');
            string extension = dot > slash ? record.Name[dot..] : "";
            var extractor = registry.Resolve(extension);
            if (record.Directory || extractor is PlainTextExtractor)
            {
                budget.Charge(record.Length);
                using var member = ZipInspectionGuard.OpenMember(content, record, token());
                if (record.Directory)
                {
                    if (member.ReadByte() != -1) throw new InvalidDataException("A ZIP directory contains bytes.");
                    yield return new(path, null, null);
                }
                else yield return new(path, member, extractor);
                continue;
            }
            if (extractor is SevenZipRefusingExtractor) throw new ArchiveRefusalException(ArchiveRefusal.SevenZipUnavailable);
            if (extractor is not IStreamingTextExtractor) throw new ArchiveRefusalException(ArchiveRefusal.UnsupportedMember);
            // Office/PDF/nested ZIP parsers require true random access. Refuse
            // large members before allocating; depth and entries are separately bounded.
            const int maximumSeekMemberBytes = 8 * 1024 * 1024;
            if (record.Length > maximumSeekMemberBytes) throw new InspectionLimitException();
            byte[] bytes = ZipInspectionGuard.ReadMember(content, record, budget, token());
            try
            {
                using var member = new MemoryStream(bytes, writable: false);
                if (extractor is ZipArchiveExtractor)
                {
                    yield return new(path, null, null);
                    foreach (var child in Walk(member, registry, budget, depth + 1, path, token)) yield return child;
                }
                else yield return new(path, member, extractor);
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
    }
}

/// <summary>Explicit fail-closed 7z route until header/dictionary admission or an isolated parser is available.</summary>
public sealed class SevenZipRefusingExtractor : ITextExtractor
{
    /// <inheritdoc />
    public IReadOnlySet<string> SupportedExtensions { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".7z" };
    /// <inheritdoc />
    public Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content); cancellationToken.ThrowIfCancellationRequested();
        throw new ArchiveRefusalException(ArchiveRefusal.SevenZipUnavailable);
    }
}
