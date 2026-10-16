# Inspection content coverage — T9

Both extraction APIs use the same readers. Word/Excel/PDF round 2 has component matrix evidence in the
[T9 status plan](../../driver/POST-MVP-PLAN.md#t9-large-files-and-complete-inspection).
Each format increment requires its own Windows feature matrix and protected qualification.
Unsupported content yields `unsupported_format`: staged Blocked, legacy AllowedWithoutInspection.
Archive-specific refusal reasons are listed below. No OCR, Office embedded-package inspection or macro execution is provided.

## Word (.docx)

| Payload location | Treatment | Reason |
|---|---|---|
| Main document, headers, footers, footnotes, endnotes, comments | Read | Paragraphs plus remaining text/attributes, including authors. |
| Text boxes, DrawingML groups, AlternateContent Choice/Fallback, drawing alt text | Read | Both XML branches; paragraph runs contiguous; attributes separate. |
| Charts and VML | Read, subject to child refusal | Rich text, caches, references and VML inline text. |
| Charts with embedded workbook | Refused | `EmbeddedPackagePart` remains unsupported; ordinary Word charts often include it. |
| Core and extended properties | Read | All text/attributes, including Company, Manager and property vectors. |
| People, extended comments, comment IDs, extensible comments | Read | All identity/extension text and attributes. |
| Glossary document and its allowlisted children | Read | Building blocks, paragraphs, formatting text and attributes. |
| Styles/effects, fonts, numbering, settings, web settings, theme/override | Read | Formatting XML can carry arbitrary user strings. |
| Custom XML, custom XML properties, custom document properties | Read | Arbitrary well-formed custom XML; all text/attributes, including enterprise labels. |
| Images, thumbnails, OLE/packages, ActiveX, altChunk, VBA, printer settings, ExtendedPart | Refused | Binary/opaque or unsupported content remains uninspected. |
| Any other reachable part type | Refused | Only explicit reader routes are admitted. |

## Excel (.xlsx)

| Payload location | Treatment | Reason |
|---|---|---|
| Workbook sheet/defined names, shared strings, worksheet formulas/values/inline strings | Read | Includes unused stored strings; missing formula caches refused. |
| Remaining worksheet text/attributes; classic/threaded comments and persons | Read | Headers, validation text, authors and identities included. |
| Drawings/groups/text boxes/alt text; charts/titles/series/labels/caches/references; VML | Read | Separate items delimited; inline rich runs remain contiguous. |
| Table definitions, cell metadata, XML mappings | Read | Column names, dynamic-array metadata and schemas can carry strings. |
| Pivot tables, cache definitions and cache records | Read | Labels and independent cached copies of data. |
| Query tables, connections, external workbook parts | Read | Query/connection strings and external cached values; no network fetch. |
| Core/app/custom properties; custom XML and custom XML properties | Read | All text/attributes, including enterprise labels. |
| Styles, theme/override, calculation chain | Read | Formatting/reference XML is also scanned. |
| Images, thumbnails, OLE/packages, ActiveX, VBA, printer settings, ExtendedPart, all other types | Refused | No supported reader route. |
| External relationship Target values (all three Office formats) | Read | Raw XML attribute value emitted as a separate item; targets are not followed. |
| Unreachable ZIP parts; duplicate canonical names (all three formats) | Refused | Orphan content cannot bypass the reader graph. |
| Content-types/relationship structure; empty ZIP directories (all three formats) | Allowlisted-no-text structure | Strict OPC vocabulary; External Targets are separately read. |

The existing 44-type Word/Excel allowlist is unchanged. All admitted parts are read; none is an opaque formatting exemption.
Limits: 16,384 parts (visited set retained), 32,770 ZIP entries, XML depth 256.

## PowerPoint (.pptx, .pptm, .potx, .ppsx)

The template, slide-show and macro-enabled containers use the same presentation part model.
`.pptm` is accepted only without VBA or other uninspected parts. Legacy binary `.ppt` remains unsupported.
As with existing formats, the current policy must include the extension in its inspection scope.
The agent's newly provisioned default and backend policy now include all four extensions; an existing
explicit policy remains authoritative and is not silently migrated.

| Payload location | Treatment | Reason |
|---|---|---|
| Presentation, all reachable slides including hidden slides | Read | All stored XML text and attributes, including text boxes, groups, alternate branches and alt text. |
| Slide layouts/masters, notes slides/masters, handout masters | Read | Stored placeholder and note text is inspected even when not displayed on a slide. |
| Classic comments/authors and modern comments/authors/replies | Read | Text and identity attributes; modern DrawingML rich runs remain contiguous. |
| Charts, rich labels/titles, formulas, cached text/numeric values | Read, subject to child refusal | Every stored value is scanned; linked destinations are never fetched or evaluated. |
| SmartArt data, layout, style, colors and persisted drawing | Read, subject to child refusal | Node text and stored labels/attributes are scanned. |
| Embedded DrawingML tables | Read | Cell paragraphs preserve rich runs; cells and paragraphs remain separate items. |
| Core/app/custom properties, custom XML and custom XML properties | Read | All text/attributes, including enterprise labels. |
| Presentation/view properties, table styles, themes/overrides, VML | Read | Formatting XML is inspected rather than exempted. |
| Hyperlinks and all external relationship targets | Read | Raw Target values scanned separately; no destination fetch. |
| Images/image-only decks, thumbnails, audio/video, OLE/embedded packages, ActiveX, VBA, embedded fonts | Refused | Images remain uninspected by owner decision; all these payloads lack an inspection route. An image-only slide cannot pass as empty text. |
| Charts with embedded workbooks, modern extended chart parts, any other unlisted type | Refused | No recursive embedded-file or additional chart-part reader in this increment. |
| Unknown/unreferenced ZIP payloads and malformed XML | Refused | The same complete inventory, required-root, depth and full-EOF checks apply. No partial approval or partial findings. |

The explicit presentation allowlist has **28 read part types**, restricted to presentation packages:

- Presentation-specific (19): `PresentationPart`, `SlidePart`, `SlideLayoutPart`, `SlideMasterPart`, `NotesSlidePart`,
  `NotesMasterPart`, `HandoutMasterPart`, `SlideCommentsPart`, `CommentAuthorsPart`, `PowerPointCommentPart`,
  `PowerPointAuthorsPart`, `PresentationPropertiesPart`, `ViewPropertiesPart`, `TableStylesPart`, `DiagramDataPart`,
  `DiagramLayoutDefinitionPart`, `DiagramStylePart`, `DiagramColorsPart`, `DiagramPersistLayoutPart`.
- Shared (9): `ChartPart`, `VmlDrawingPart`, `CoreFilePropertiesPart`, `ExtendedFilePropertiesPart`,
  `CustomFilePropertiesPart`, `ThemePart`, `ThemeOverridePart`, `CustomXmlPart`, `CustomXmlPropertiesPart`.

The new presentation-specific routes remain refused in Word/Excel. Spreadsheet and Word primary parts are refused in presentations.
The reader uses the existing 8,192-character chunks and Office part/entry/depth limits, with no part DOMs or complete XML-value copies.
Legacy extraction materializes the completed text as before; staged inspection uses fresh streaming readers.
This bounds reader text state, not SDK/ZIP/XML metadata allocations or total parser peak memory.

Independent raw ZIP/XML fixtures in `PowerPointContentCoverageTests` cover clean/CPF pairs for each admitted route,
hidden slides, image-only decks, unknown/orphan parts, opaque payloads, malformed tails and item boundaries through both inspection paths.
`PowerPointStreamingInspectionTests` covers fragmented/legacy parity, EOF-only CPF, collected live reader state,
cancellation and borrowed-source ownership. These are local component controls, not Windows or protected-pair qualification.

## Archives (.zip; .7z explicitly refused)

ZIP members use the registered text/CSV, Word, Excel, PowerPoint and PDF streaming inspectors, including their existing
complete-or-refuse rules. Both service inspection modes scan each member separately inside one existing worker and
one policy deadline; legacy still captures/hashes the same outer bytes for cache authority. No member is extracted to disk.
The direct ZIP streaming and legacy extraction APIs use the same member walk and insert boundaries between names/bodies/members.

| Archive content/structure | Treatment | Reason |
|---|---|---|
| Stored/Deflate ZIP members, including nested ZIPs | Read | Strict header/inventory reconciliation, exact compressed completion, expanded length and CRC before dispatch. |
| Each complete entry name, directory/container name and member body | Read separately | Names are data; no filesystem extraction, path resolution, fetch or cross-member match. |
| Empty ZIP; empty supported members; zero-payload directories | Read/validate | No payload is silently omitted; ordinary zero-byte-file handling is unchanged. |
| Sensitive members or names | Blocked | Existing categories/masks; `Finding.MemberName` identifies the member, nested names separated by `!/`. Sensitive name components become `[sensitive name]`; controls are escaped. |
| Encrypted ZIP, including strong/masked-header flags | Refused: `archive_encrypted` | Passwords/decryption are not attempted. |
| Images, unknown members, unsupported/opaque payloads inside an Office/PDF member | Refused | `archive_unsupported_member` or the child inspector's existing refusal. One failure discards all prior findings. |
| All nonempty .7z archives, including encrypted/header-encrypted archives | Refused: `archive_7z_unavailable` | No managed 7z parser with pre-admission allocation bounds is qualified in this increment. |
| ZIP64, multi-disk, self-extracting prefix, comments, unknown extras, special/link entries, ambiguous/duplicate names | Refused | Only the documented ZIP subset is admitted; valid unsupported structures use `archive_unsupported_structure`. |
| Missing/hidden/overlapping local records, inconsistent central/local/descriptor metadata, malformed names, bad CRC, truncated/extra compressed frames | Refused | Parse failure; no partial approval or partial findings. |

ZIP-specific admission bounds: **three archive levels including the outer archive**, **16,384 entries cumulatively**
(the existing Office/scanner ceiling), and **1,000:1 maximum per-entry expansion ratio**. The unchanged current policy
size limit applies to the actual held outer source, each member and the **sum of actual expanded member bytes across
the entire tree**, including nested ZIP container bytes. Counts/work are never refunded at disposal or reset at nesting.
The shared finding/candidate ceiling stays 16,384; retained diagnostic-name storage is separately capped at the same
policy byte budget (UTF-16). Refusal uses `inspection_limit` or `file_too_large`, never truncation. The existing policy
inspection deadline covers all archive work, queueing and member scans, with no per-member deadline reset.

The strict recognizer validates EOCD and central/local records before BCL ZIP metadata allocation. It admits only store
and Deflate, explicit version/flag forms, fully reconciled signed/unsigned data descriptors, strict UTF-8 or ASCII names,
and structurally checked extended/NTFS timestamp extras. Deflate's one-byte bounded input facade prevents read-ahead
from hiding a suffix; a nonempty final read must observe the final marker. Member byte arrays are cleared/disposed
on completion, refusal, parse/limit failure and cancellation, including late worker completion after caller timeout.

These bounds cover the added ZIP layer, member storage and scanner state. They do not establish allocation bounds
inside the existing Office/PDF inspectors or total process peak memory. Incomplete staged inspection is Blocked;
legacy retains its established AllowedWithoutInspection error classification and never reports Approved for a partial scan.
Existing explicit policies remain authoritative. Newly provisioned agent and backend defaults include PowerPoint,
ZIP and the explicit 7z refusal route; no other policy default changes.

`ArchiveInspectionTests`/`ArchiveIntegrityTests` use independent raw ZIP headers/CRC, BCL seekable/nonseekable writers,
and independently generated encrypted ZIP/7z fixtures. They cover member provenance and redaction, nested existing
inspectors, exact/over budget boundaries, malformed/late failures, compressed framing, extraction parity and worker/lease lifetime.
The [design and rejected-parser record](T9-ARCHIVE-INSPECTION.md) lists the 7z limitation and independent review conditions.

## PDF

| Payload location | Treatment | Reason |
|---|---|---|
| Page glyph letters | Read | Content order retained; page boundaries inserted. |
| Annotation Contents/T and other strings; URI actions | Read | Direct/indirect dictionaries, arrays and URI chains. |
| Widget/AcroForm V/T/TU, DV, Opt and inherited values | Read, subject to AP refusal | Fields/parents followed; string, hex, name and numeric values supported. |
| Info strings, outline/bookmark titles, catalog XMP text/attributes | Read | Custom Info, child outlines and strict decoded XMP included. |
| Marked-content alternate descriptions/expansion properties | Read | Original glyph inspection retained. |
| AP N/R/D, including every state | Read/validate graphics-only | PdfPig decoding; strict bounded lexer; stored strings, names and comments scanned as separate items. |
| AP text-showing Tj/TJ/'/", XObject Do, inline BI/ID/EI, ActualText | Refused | Appearance text/rendering is not implemented; includes filled text-field widgets. |
| AP missing explicit Resources; nested resource streams; external F/FFilter/FDecodeParms/Ref | Refused | Cannot establish local graphics-only coverage or inspect dependent streams. |
| AP unsupported filters/parameters or malformed content | Refused | Only unfiltered or direct single Flate (absent/null parameters); fallback, framing/checksum and trailing bytes checked. |
| ActualText; RC; other auxiliary streams; page-level Metadata | Refused | Independent replacement/rich/stream content lacks a reader route. |
| Page images; EmbeddedFiles; Filespec/EF/AF; FileAttachment; XFA | Refused | Uninspected image/file/form payloads. |
| JavaScript, non-URI/non-GoTo actions, rich media | Refused | No script execution or multimedia inspection. |
| Incremental revisions, including many signed or Acrobat-edited PDFs | Refused | Previous revisions are not read; staged saves are Blocked as unsupported_format. |

Filled forms whose appearances draw text are also Blocked as `unsupported_format` until appearance text is read.
Graphics-only APs must have explicit Resources and supported filters; some otherwise valid annotations remain unsupported.
PDF limits: 4,096 annotation/field/bookmark visits each; 65,536 auxiliary visits; graph depth 64;
AP cumulative 65,536 tokens and 8 MiB decoded bytes, lexer nesting 64; XMP depth 256 and decoded size 8 MiB.
These bound extraction work, not third-party decoding allocations. PDF orphan objects and unused page resources
are not exhaustively inventoried; arbitrary PDF stored-byte completeness and broader T9 qualification remain open.
