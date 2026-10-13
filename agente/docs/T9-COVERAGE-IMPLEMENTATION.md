# T9 content coverage implementation handoff

Working tree only; no commit, push, Windows build, test execution or VM run was performed.
All changed files are under `agente/`. The starting working tree was clean.
`git diff --check` was used for whitespace review. A local tree-sitter syntax-check attempt could not load the available WASM grammar as a native library; it provides no C# validation.

## Files changed and why

| File under agente/ | Change |
|---|---|
| SafeUpload.Agent.Core/Infrastructure/Extraction/OpenXmlInspectionGuard.cs | Replaces the denylist with 27 explicit part types and strict roots; returns the exact visited graph, rejects orphan/duplicate ZIP entries and validates OPC infrastructure. Existing 16,384-part traversal budget/cancellation retained. |
| SafeUpload.Agent.Core/Infrastructure/Extraction/OpenXmlAuxiliaryText.cs | New streamed text/attribute passes for every admitted part, including drawings/charts/VML, modern comments/persons, core/app properties and formatting strings. Primary-reader containers are excluded from the extra text pass. |
| SafeUpload.Agent.Core/Infrastructure/Extraction/ChunkedTextReader.cs | New reusable pull reader retaining one current chunk; supports fragmented reads, peek, cancellation and iterator disposal. |
| SafeUpload.Agent.Core/Infrastructure/Extraction/WordParagraphTextReader.cs | Reads all reachable Word primary parts, adds nested DrawingML paragraph boundaries, then consumes auxiliary content. |
| SafeUpload.Agent.Core/Infrastructure/Extraction/SpreadsheetTextReader.cs | Reads graph-discovered shared strings/worksheets/comments and the auxiliary stream; validates the single workbook route. |
| SafeUpload.Agent.Core/Infrastructure/Extraction/PdfAuxiliaryText.cs | New bounded token walks for annotations, fields/parents, outlines, Info, URI actions and strict XMP; explicit refusal for unconsumed PDF payloads. |
| SafeUpload.Agent.Core/Infrastructure/Extraction/PdfTextReader.cs | Streams page letters and auxiliary chunks through the same reader, retaining image refusal and explicit strict PdfPig parsing options. |
| SafeUpload.Agent.Core/Infrastructure/Extraction/OpenXmlWordExtractor.cs | Legacy ExtractAsync consumes OpenReaderAsync; removes the independent DOM implementation. |
| SafeUpload.Agent.Core/Infrastructure/Extraction/OpenXmlSheetExtractor.cs | Legacy ExtractAsync consumes OpenReaderAsync, including unused shared strings and all new coverage. |
| SafeUpload.Agent.Core/Infrastructure/Extraction/PdfExtractor.cs | Legacy ExtractAsync consumes OpenReaderAsync, including all new PDF coverage. |
| SafeUpload.Agent.Tests/OfficeContentCoverageTests.cs | Independent raw ZIP/XML fixtures for the requested Office payloads, refusals, limits, boundaries and API parity. |
| SafeUpload.Agent.Tests/PdfContentCoverageTests.cs | Independent raw object/xref PDF fixtures for payloads, refusals, counts, malformed content, inheritance and API parity. |
| SafeUpload.Agent.Tests/SpreadsheetStreamingInspectionTests.cs | Exact-output and character-count assertions now include metadata; legacy unused/shared-string assertions require the same coverage as staged extraction. Existing memory bounds unchanged. |
| docs/INSPECTION-COVERAGE.md | Short format-by-format coverage table, limits and residual scope. |
| docs/T9-COVERAGE-IMPLEMENTATION.md | This requested handoff/output file. |

## Full Office document-part allowlist

All 27 document-part types below are **read**. No document part is silently accepted as opaque formatting.
Each root is checked before extraction; unlisted types, including printer settings, are refused.
Word-primary part types in spreadsheets and spreadsheet-primary part types in Word are refused.

| SDK part type | Justification |
|---|---|
| `MainDocumentPart` | Body, nested text boxes, alternate branches. |
| `HeaderPart` | Header paragraphs and drawings. |
| `FooterPart` | Footer paragraphs and drawings. |
| `FootnotesPart` | Note paragraphs. |
| `EndnotesPart` | Note paragraphs. |
| `WordprocessingCommentsPart` | Comment paragraphs and authors. |
| `WorkbookPart` | Defined names and sheet names. |
| `WorksheetPart` | Formulas, values, inline text and auxiliary strings. |
| `SharedStringTablePart` | All stored strings, even unused ones. |
| `WorksheetCommentsPart` | Classic comment text and authors. |
| `DrawingsPart` | Shapes/groups and alt text. |
| `ChartPart` | Rich text, caches and references. |
| `VmlDrawingPart` | VML text boxes, including legacy HTML text. |
| `WorksheetThreadedCommentsPart` | Modern comment text. |
| `WorkbookPersonPart` | Person names/identifiers. |
| `CoreFilePropertiesPart` | All core property text. |
| `ExtendedFilePropertiesPart` | Company, Manager, vectors and other text. |
| `StyleDefinitionsPart` | Style names and attribute text. |
| `StylesWithEffectsPart` | Extended style names and attribute text. |
| `WorkbookStylesPart` | Number formats and named styles. |
| `FontTablePart` | Font names and alternate names. |
| `NumberingDefinitionsPart` | Numbering labels can be arbitrary strings. |
| `DocumentSettingsPart` | Variables and other string settings. |
| `WebSettingsPart` | String-valued web settings. |
| `ThemePart` | Theme/font/color names and values. |
| `ThemeOverridePart` | Overrides have the same string-bearing structures. |
| `CalculationChainPart` | Normally references only; still parse/read instead of trusting opaque XML. |

The only no-document-text exemptions are validated `[Content_Types].xml`, relationship XML and empty ZIP directory records. Unknown OPC XML vocabulary/attributes and nonempty text nodes in these infrastructure entries are refused. ZIP canonical-name duplicates and unreferenced package parts are refused. The entry inventory has a separate 32,770-entry ceiling.

## New tests by name

OfficeContentCoverageTests (theory parameters cover the individual payload locations):

- `Spreadsheet_drawing_chart_and_modern_comment_payloads_are_inspected`
- `Spreadsheet_metadata_and_other_admitted_strings_are_inspected`
- `Word_alternate_textboxes_descriptions_and_properties_are_inspected`
- `Office_unknown_reachable_and_unreferenced_parts_are_refused`
- `Office_package_inventory_cannot_hide_content_as_infrastructure`
- `Office_allowlisted_clean_packages_are_approved`
- `Rich_runs_remain_contiguous_but_separate_items_cannot_invent_a_cpf`
- `Malformed_auxiliary_xml_never_returns_partial_approval`
- `Drawing_depth_limit_refuses_nested_groups`
- `Auxiliary_streaming_and_legacy_extraction_are_identical`

PdfContentCoverageTests:

- `Pdf_auxiliary_strings_are_inspected_in_legacy_and_staged_paths`
- `Pdf_unconsumed_payloads_are_explicitly_refused`
- `Clean_pdf_with_clean_link_annotation_is_approved`
- `Pdf_auxiliary_counts_over_the_limit_cannot_be_approved`
- `Separate_annotation_items_cannot_assemble_a_cpf`
- `Nested_fields_and_bookmarks_are_inspected`
- `Widget_inherits_values_from_a_parent_even_without_an_acroform_root`
- `Nested_field_depth_is_bounded`
- `Malformed_xmp_and_annotation_entries_fail_the_entire_inspection`
- `Pdf_auxiliary_fragmented_stream_matches_extract_async`

Verdict fixtures invoke both InspectAsync and InspectStagedAsync, assert failure classification/reason or CPF category and exact masked form `•••••••••25`, and compare source bytes after inspection. The duplicate-ZIP fixture accepts the explicit refusal or OPC parse-failure classification because the SDK can reject it before inventory runs. Dedicated fragmented-read cases compare ExtractAsync output against OpenReaderAsync at chunk sizes 1, 7 and 8192.

## API assumptions to verify

No knowingly unconfirmed member names remain. Names were checked against the supplied Open XML 3.3.0 and PdfPig 0.1.16 XML documentation. The threaded-comment/person root/relationship/content-type spellings were also checked against strings in the supplied Open XML assembly.

The exact PdfPig 0.1.16 source confirms DictionaryToken.Data has string keys, MarkedContentElement.Properties is DictionaryToken, and Structure.GetObject returns ObjectToken. References: [DictionaryToken](https://raw.githubusercontent.com/UglyToad/PdfPig/v0.1.16/src/UglyToad.PdfPig.Tokens/DictionaryToken.cs), [MarkedContentElement](https://raw.githubusercontent.com/UglyToad/PdfPig/v0.1.16/src/UglyToad.PdfPig/Content/MarkedContentElement.cs), [Structure](https://raw.githubusercontent.com/UglyToad/PdfPig/v0.1.16/src/UglyToad.PdfPig/Structure.cs).

The builder must still compile every use and validate runtime behavior, especially strict PDF parsing of existing fixtures, raw core-properties enumeration through package.Parts, token string/hex decoding, and SDK handling of independent malformed/duplicate package fixtures. This source/API review is not build or test evidence.

## Limits and known residual gaps

- PDF: 4,096 annotation visits, 4,096 field dictionary/parent visits, 4,096 bookmark dictionary visits, 65,536 auxiliary token visits and graph/reference depth 64. Shared fields visited from annotations and AcroForm can consume more than one visit. XMP XML depth 256; decoded XMP size 8 MiB. Office XML depth 256 and relationship graph 16,384 parts remain.
- Word charts with an EmbeddedPackagePart (their embedded workbook) remain refused. Images/thumbnails, OLE/packages, ActiveX, altChunk, CustomXmlPart, CustomFilePropertiesPart and ExtendedPart remain refused. PowerPoint is unchanged and unregistered.
- PDF AP appearance streams, RC rich content, ActualText replacement spans, page-level metadata, arbitrary auxiliary streams, file specifications/attachments, XFA, rich media and non-URI/non-GoTo actions are refused. These conservative refusals can affect otherwise ordinary annotated/form PDFs. Incremental revision chains with a previous xref offset are also refused.
- PDF orphan/unreferenced objects, unused page resources and arbitrary stored-byte content are not exhaustively inventoried. This component change must not be represented as proof of arbitrary PDF content completeness or closure of T9.
- Page glyph extraction still depends on PdfPig's font/rendering interpretation. The new extraction limits do not bound third-party parser/decompression peak memory; XMP size is checked after decoding. No storage-admission, parser-worker isolation, feature-gate, driver-cap or qualification changes were made.
- Office attributes are scanned conservatively, including identifiers and formatting values. This can produce additional legitimate detector matches compared with the prior text-only behavior; boundaries keep unrelated attribute values separate.
- Independent design review by Sol 6.1 xhigh identified primary-part strings, indirect PDF payloads, inherited fields and replacement-text boundaries; the implementation addresses those with reading or refusal. The reviewer explicitly retained PDF orphan/resource coverage as a limitation. No independent final-code or milestone-pair acceptance is claimed.

## Builder handoff

Run the focused OfficeContentCoverageTests, PdfContentCoverageTests and existing Office/PDF extraction/streaming controls first. Then run the required normal/feature × Debug/Release agent matrix using the orchestrator's authorized delivery mechanism. Do not treat focused tests or this review as protected qualification. No compiler/test success is claimed here.
