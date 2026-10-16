# T9 archive inspection increment

Owner scope: 2026-10-16 item 3 and the archive-stage implementation request. ZIP uses
`System.IO.Compression`; `.7z` may remain refused if a managed parser cannot establish bounded admission.
This note extends the existing complete-or-refuse extraction contract; it does not qualify a protected pair.

## Reviewed design

[Independent Sol 6.1 xhigh review](../../driver/evidence/2026-10-16/t9-archives-design-review-sol61.md):
ACCEPT WITH CONDITIONS. Exact interpretation/Deflate completion, cumulative accounting, per-member dispatch and
limited resource claims are implementation conditions; this verdict is not component or protected qualification.

- Add PowerPoint to both agent/backend default extension lists first. After ZIP and explicit 7z refusal are complete,
  add `.zip` and `.7z` to both lists. Existing explicit policies are authoritative; no migration or other default changes.
- Introduce a ZIP extractor with both extraction APIs and a member-inspection operation used by InspectionService
  inside its existing worker slot and queue-plus-work deadline. Legacy retains its captured-byte/hash/cache authority;
  staged retains its exact held source. Other format routes and detector behavior are unchanged.
- Use one request-local budget for the entire archive tree: policy `MaxFileSizeBytes` for compressed input and cumulative
  actual expanded member bytes (nested containers count too), 16,384 total entries (the existing Office part/scanner
  candidate ceiling), and at most three archive levels including the outer archive. Findings across members also share
  the existing 16,384-candidate ceiling. Reject high expansion ratios over 1,000:1 as a ZIP-specific parser guard.
  These guards are new archive admission bounds, not changes to existing format/policy limits.
- Before constructing the BCL ZIP inventory, validate the EOCD and central/local records with bounded reads. Enforce
  counts, sums, offsets, exact local/central name/flags/method/CRC/length agreement, single-disk storage, supported
  compression (store/deflate), no encryption, and no hidden local entries, prefix/suffix, overlaps or duplicate names.
  Refuse ZIP64, unknown extra fields and archive/member comments in this increment. Directory entries must expand
  to zero bytes; symlinks and other special entry types are refused. Recognized timestamp extras may be admitted only
  after structural validation. UTF-8 names are strict; non-UTF-8 names must be ASCII.
- Use System.IO.Compression ZIP inventory and DeflateStream; for deflate, a bounded one-byte input facade prevents
  read-ahead from hiding a compressed suffix and throws on physical EOF before the final marker. Check exact compressed
  consumption, actual expanded length and CRC32 before a member reaches its existing inspector.
- Allocate a seekable in-memory member stream only after length/remaining-budget checks. Parent container bytes and
  one current child per depth remain live; cumulative expansion bounds their sum. Dispose and clear member buffers on
  success, parse/refusal/limit failure, cancellation and late worker completion. No temporary files, pathname extraction,
  network fetch or recursive InspectionService call. Metadata remains separately bounded by the compressed source size
  and entry ceiling. Existing Office/PDF third-party parser allocation limitations remain explicit.
- Resolve member formats using the existing registry, independently of the outer policy's extension list. Scan each
  name as a separate metadata item and each member independently using the existing streaming scanner in both modes.
  Directory/container names are also scanned. Member names are opaque data; never combine them with filesystem paths.
  Add optional `Finding.MemberName` diagnostic provenance (nested names joined with `!/`, no authority). Scan each
  entire entry name, including any slash separators, before redacting sensitive components as `[sensitive name]` and
  escaping control characters. Linked name components avoid repeated prefix copies during walking; charge retained
  diagnostic UTF-16 storage against a separate policy-size quota before materialization. Preserve existing
  two-argument Finding construction and all detection masks/ordering within a member. Separate members cannot assemble
  a match. No findings escape until the entire archive finishes; a later refusal/corruption discards prior findings.
- Archive-specific safe reasons classify encryption, unsupported members/structures and unavailable 7z inspection;
  policy size, timeout, parser limit and parse-error classifications retain their existing meanings. Legacy incomplete
  inspection remains AllowedWithoutInspection; staged remains Blocked. No publication/lifetime gates change.

## 7z parser assessment

Candidate: SharpCompress **0.50.4**, MIT, NuGet publication **2026-08-05** (older than two weeks on 2026-10-16).
[NuGet](https://www.nuget.org/packages/SharpCompress/0.50.4),
[versioned LzmaStream source](https://github.com/adamhathcock/sharpcompress/blob/0.50.4/src/SharpCompress/Compressors/LZMA/LzmaStream.cs).
Its LZMA/LZMA2 constructors derive a dictionary size from untrusted coder properties and allocate the output window
before member-output accounting. Encoded headers and solid/coder graphs also need admission before materialization;
an output-size counter or cancellation token does not supply that proof. The existing in-process inspection worker has
no memory ceiling or forced termination. Do not add this runtime dependency merely to bound returned output.
The versioned [ReaderOptions](https://github.com/adamhathcock/sharpcompress/blob/0.50.4/src/SharpCompress/Readers/ReaderOptions.cs)
exposes buffering/cancellation-related configuration, not this end-to-end admission budget;
[SevenZipArchive](https://github.com/adamhathcock/sharpcompress/blob/0.50.4/src/SharpCompress/Archives/SevenZip/SevenZipArchive.cs)
loads the database before exposing the entry inventory.

Proposed fallback: `.7z` is registered and in default policy scope, but always refuses with `archive_7z_unavailable`,
including encrypted/header-encrypted archives, without invoking a parser. No new NuGet dependency or package hash
exists for this fallback. Any later SharpCompress adoption is a **new untrusted-input parser dependency** requiring
an exact-version/license/nupkg-hash record plus header/dictionary/coder bounds or the separately reviewed isolated worker.

| Dependency record | Result |
|---|---|
| Added third-party runtime packages | None. Existing `System.IO.Compression` in the pinned .NET runtime is used for ZIP inventory/Deflate. |
| Evaluated 7z candidate | SharpCompress 0.50.4, MIT, published 2026-08-05; rejected for this in-process admission contract. |
| NuGet package hash / lock file | Not applicable: no package downloaded, referenced or added; this repository has no NuGet lock files. |
| New input-parser code to review | Owned strict ZIP recognizer plus member dispatch and budget accounting. |
| Future dependency warning | SharpCompress or any other 7z decoder is a new untrusted-input parser dependency, not approved by this fallback. |

ZIP structural layouts follow [PKWARE APPNOTE 6.3.10](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT).

## Required controls

Independent ZIP records and BCL-generated interoperability controls: clean/empty archives; sensitive nested text,
Word/Excel/PowerPoint/PDF; encryption and refused members; exact size/count/depth boundaries; ratios; corrupt local,
central and compressed data/CRC; truncated streams; opaque names and run separation; both extraction APIs and both
inspection modes; cancellation, borrowed ownership and buffer release. No existing test is removed or weakened.

Local compile of all profiles, focused Linux controls, source test preflight against feat/driver-m2, and backend tests
when its toolchain is available precede delivery. Windows matrix and protected qualification remain separate.
