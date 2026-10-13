# T9 content coverage implementation handoff — round 2

Changes are uncommitted on `wt/t9-coverage`, on top of `bfeb7103`; all writes are under `agente/`.
The orchestrator reports that **round 1** (`bfeb7103`, matrix `t9-coverage1`) passed all four profiles at zero warnings/errors, with 1,210 normal / 1,580 feature tests per Debug/Release profile and no skips. That result does not cover these changes.
No round-2 compilation, test execution, remote build or VM run was performed here; the host has no .NET SDK.

## Files changed and why (relative to bfeb7103)

| File under agente/ | Change |
|---|---|
| SafeUpload.Agent.Core/Infrastructure/Extraction/OpenXmlInspectionGuard.cs | Adds the 17 requested common XML part types to the 44-type allowlist; every class/root exists in Open XML 3.3.0. CustomXmlPart accepts any well-formed root. Binary/opaque, unknown and orphan refusals remain. |
| SafeUpload.Agent.Core/Infrastructure/Extraction/OpenXmlAuxiliaryText.cs | All added parts use the existing streaming text/attribute passes. Adds a raw relationship XML pass to read External Targets without URI normalization or fetching their destinations. |
| SafeUpload.Agent.Core/Infrastructure/Extraction/WordParagraphTextReader.cs; SpreadsheetTextReader.cs | Pass the held source stream to the shared auxiliary reader. Legacy ExtractAsync already consumes these same readers. |
| SafeUpload.Agent.Core/Infrastructure/Extraction/PdfAuxiliaryText.cs | Replaces blanket AP refusal with all-state traversal, resource inspection, PdfPig decoding and lexer validation; includes inherited field appearances. Adds cumulative token/decoded-byte limits. Retains incremental/page-Metadata refusal. |
| SafeUpload.Agent.Core/Infrastructure/Extraction/PdfAppearanceLexer.cs | New bounded lexer for graphics-only AP streams. Rejects text showing, Do, inline images, ActualText, malformed/unknown operations and unresolved named resources; emits stored literal/hex/name/comment items without whole-text copies. |
| SafeUpload.Agent.Tests/OfficeCommonPartCoverageTests.cs | New independent raw ZIP fixtures for all requested parts, external relationships, clean controls, invalid custom XML and glossary children. |
| SafeUpload.Agent.Tests/OfficeContentCoverageTests.cs | Partial class so new fixtures reuse the existing raw helpers and both-path verdict/byte assertions. |
| SafeUpload.Agent.Tests/OfficeUnsupportedPayloadTests.cs | Six custom XML/properties rows now require clean approval and CPF detection instead of refusal; all binary/opaque refusal assertions retained. |
| SafeUpload.Agent.Tests/PdfAppearanceCoverageTests.cs | New independent raw PDF/xref/stream fixtures; BCL ZLibStream writes compressed fixture bytes, never a PdfPig writer. |
| SafeUpload.Agent.Tests/PdfContentCoverageTests.cs | Partial class; raw PDF helper can write binary stream objects with byte-accurate xref offsets. Existing verdict assertions retained. |
| docs/INSPECTION-COVERAGE.md; docs/T9-COVERAGE-IMPLEMENTATION.md | Updated coverage, complete allowlist, test names, API evidence and user impact. |

## Full Office document-part allowlist

All 44 document-part types below are **read**. No document part is silently accepted as opaque formatting.
Each root is checked before extraction (CustomXmlPart permits any well-formed root); unlisted types, including printer settings, are refused.
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
| `TableDefinitionPart` | Table/column names, formulas and labels. |
| `CellMetadataPart` | Dynamic-array metadata and stored metadata strings. |
| `PivotTablePart` | Pivot labels, captions and formulas. |
| `PivotTableCacheDefinitionPart` | Field names and shared cached values. |
| `PivotTableCacheRecordsPart` | Independent stored copies of source data. |
| `QueryTablePart` | Query and field names. |
| `ConnectionsPart` | Connection strings, commands and descriptions. |
| `ExternalWorkbookPart` | External-workbook cached values; no network fetch. |
| `CustomXmlMappingsPart` | Map names and inline schema text. |
| `WordprocessingPeoplePart` | Comment-author identities. |
| `WordprocessingCommentsExPart` | Extended comment metadata. |
| `WordprocessingCommentsIdsPart` | Comment identity metadata. |
| `WordCommentsExtensiblePart` | Extensible comment metadata. |
| `GlossaryDocumentPart` | Stored building-block paragraphs and attributes. |
| `CustomFilePropertiesPart` | Enterprise labels and arbitrary property values. |
| `CustomXmlPart` | Arbitrary well-formed XML root; all text and attributes are read. |
| `CustomXmlPropertiesPart` | Data-store identity and schema references. |

The only no-document-text exemptions are validated `[Content_Types].xml`, OPC relationship structure and empty ZIP directory records. Every External relationship Target is read separately from that structure. Unknown OPC XML vocabulary/attributes and nonempty text nodes in these infrastructure entries are refused. ZIP canonical-name duplicates and unreferenced package parts are refused. The entry inventory has a separate 32,770-entry ceiling.

## New and changed tests by name

All new verdict fixtures invoke both legacy InspectAsync and staged InspectStagedAsync. They assert verdict, failure kind/reason or CPF category and exact mask `•••••••••25`, and source-byte equality. Clean/sensitive Office pairs cover all 17 additions; custom XML/properties are covered in both formats. Fixtures use raw package XML or raw PDF objects/xrefs, with BCL compression only.

### OfficeContentCoverageTests additions

- `Spreadsheet_common_parts_are_read_including_cached_copies`
- `Word_common_parts_and_glossary_children_are_read`
- `Office_custom_data_and_enterprise_labels_are_read`
- `External_relationship_targets_are_read_as_individual_items`
- `Arbitrary_custom_xml_still_requires_a_complete_root`

### PdfContentCoverageTests additions

- `Highlight_with_graphics_only_appearance_is_inspected`
- `Appearance_text_showing_xobjects_and_inline_images_are_refused`
- `Filled_text_field_with_painted_value_is_still_unsupported`
- `Every_appearance_and_unselected_state_is_inspected`
- `Stored_appearance_strings_and_comments_are_read`
- `Appearance_lexer_preserves_nested_strings_escapes_and_item_boundaries`
- `Appearance_actual_text_direct_encoded_and_named_properties_are_refused`
- `Appearance_indirect_properties_and_resource_names_are_not_backlinks`
- `Appearance_shape_and_local_resource_scope_must_be_complete`
- `Appearance_stream_must_be_a_form_with_numeric_geometry`
- `Appearance_selected_resources_require_the_expected_token_shape`
- `Appearance_nested_resource_streams_are_refused`
- `Appearance_named_resources_must_resolve_in_its_own_dictionary`
- `Appearance_external_stream_sources_and_reference_xobjects_are_refused`
- `Malformed_appearance_streams_are_never_approved`
- `Unsupported_or_failed_appearance_filters_are_refused`
- `Direct_single_flate_filter_forms_are_supported`
- `Indirect_filter_parameters_and_filter_chains_are_refused`
- `Appearance_token_budget_is_cumulative_and_exact`
- `Appearance_decoded_byte_budget_is_cumulative_and_exact`
- `Appearance_container_depth_is_bounded`
- `Page_metadata_and_incremental_revisions_remain_refused`

OfficeUnsupportedPayloadTests changes:

- `Custom_xml_and_properties_are_inspected`: replaces six formerly refused custom-data rows with clean approval and CPF detection through both inspection paths, plus direct ExtractAsync coverage.
- `Clean_text_does_not_approve_uninspected_payloads`: retains all image/thumbnail/OLE/package/ActiveX/altChunk/opaque refusal rows; only inspected custom XML/properties moved to the new test.

Existing round-1 payload, orphan/unknown-part, extraction-parity, annotation/field-count and streaming-memory assertions remain. The PDF builder now accepts binary object bytes; existing string fixtures retain the same object content and byte-accurate offsets.

## PDF appearance admission and limits

Every N/R/D stream and every state is checked. An explicit Resources dictionary is required and all of it is walked, including unused entries; resource keys such as P/S/Parent are not mistaken for backlink skips. The stream must identify a Form XObject with numeric BBox/optional Matrix and supported FormType. Named graphics/font/color/shading/pattern/marked-property operands must resolve locally with the expected token shapes. Nested streams, external stream keys F/FFilter/FDecodeParms and reference-XObject Ref are refused.

Decoded content must pass a bounded lexer: literal escapes/nesting, hex strings, encoded names, numbers, arrays, dictionaries, comments and a closed operator set. Text-showing Tj/TJ/'/", Do, inline BI/ID/EI and ActualText are refused. Stored text/name/comment values are separately emitted; literal/hex property strings support PDFDocEncoding and UTF-16 BOMs. Separate items receive newlines. Unknown operations and malformed/unbalanced syntax cannot imply approval.

Unfiltered streams and direct single FlateDecode/Fl filters (including a one-element direct array) with absent/null DecodeParms are supported. Other filters, chains, indirect filter tokens and non-null DecodeParms remain unsupported. The bytes inspected come from PdfPig's documented Decode helper. PdfPig 0.1.16 can silently return encoded input after a Flate error and can ignore suffixes; the guard rejects fallback and uses a second BCL ZLibStream pass to validate zlib framing/checksum, decoded equality and complete encoded-byte consumption. The second pass supplies one byte at a time to prevent read-ahead masking suffixes and throws on physical EOF to reject truncation. It retains an 8 KiB comparison buffer, not another whole decoded copy. Its per-byte calls add CPU overhead.

Appearance token visits (65,536) and decoded bytes (8 MiB) are cumulative over the document's appearance visits, including repeated references; lexer container/string/graphics/marked nesting is capped at 64. Existing limits remain: 4,096 annotation/field/bookmark visits each, 65,536 auxiliary visits, graph/reference depth 64, XMP depth 256 and decoded size 8 MiB. These are work limits, not third-party allocation bounds; PdfPig decoding occurs before its output-size check.

## API assumptions to verify

No requested Open XML class was skipped: all 17 types exist in the supplied 3.3.0 XML documentation; root properties and serialized root names were checked there. Modern namespaces and relationship/content-type constants were cross-checked against the supplied assembly strings. CustomXmlMappingsPart uses application/xml (not an invented spreadsheetml.xmlMaps MIME type); CustomXmlPart has no fixed root.

New PdfPig 0.1.16 members confirmed in the supplied exact XML documentation: StreamToken.StreamDictionary/Data, ArrayToken.Length/Data, NullToken, Structure.FilterProvider/TokenScanner, PdfExtensions.Decode(StreamToken, ILookupFilterProvider, IPdfTokenScanner), and PdfDocEncoding.TryConvertBytesToString(ReadOnlySpan<byte>, out string). Existing dictionary/reference APIs already built in round 1. No knowingly unconfirmed member names remain.

Pinned source review also checked [Decode](https://raw.githubusercontent.com/UglyToad/PdfPig/v0.1.16/src/UglyToad.PdfPig/PdfExtensions.cs), [Flate fallback](https://raw.githubusercontent.com/UglyToad/PdfPig/v0.1.16/src/UglyToad.PdfPig/Filters/FlateFilter.cs), [parameter handling](https://raw.githubusercontent.com/UglyToad/PdfPig/v0.1.16/src/UglyToad.PdfPig/Filters/DecodeParameterResolver.cs) and [PDFDocEncoding](https://raw.githubusercontent.com/UglyToad/PdfPig/v0.1.16/src/UglyToad.PdfPig.Core/PdfDocEncoding.cs). This does not replace compilation/runtime verification. The Windows builder must verify raw modern-part relationships, compressed fixtures and the BCL zlib endpoint behavior with the clean/corrupt/truncated/trailing/concatenated controls.

## Known residual gaps and user impact

- Incrementally saved PDFs, including many signed PDFs and Acrobat edits, remain staged Blocked as unsupported_format until previous revisions are inspected. Page-level Metadata remains refused.
- Filled text forms whose widget AP draws the value remain staged Blocked as unsupported_format until appearance text is read. Value-only forms without a refused appearance retain field-value inspection.
- Graphics AP support is deliberately limited to explicit local Resources and the supported filter forms. Missing/inherited resources, nested resource streams (soft masks, patterns, ICC profiles, etc.), non-null filter parameters and unknown operators can still refuse otherwise valid annotated files.
- Word charts carrying an embedded workbook remain refused. Images/thumbnails, OLE/packages, ActiveX, altChunk, VBA, printer settings and unknown/opaque Office parts remain refused. PowerPoint is unchanged and unregistered. Custom XML and custom properties are now read, per the round-2 owner direction.
- PDF orphan/unreferenced objects, unused page resources and arbitrary stored-byte content are not exhaustively inventoried. RC, ActualText, attachments/XFA, multimedia and other unsupported auxiliary streams remain refused. Page text still depends on PdfPig's font interpretation.
- Third-party parser/decompression peak memory remains outside these work limits. No storage-admission, worker-isolation, feature-gate, driver-cap or protected-qualification work was added.
- Attribute/metadata inspection is conservative and can detect identifiers or formatting values; unrelated items have boundaries to avoid manufactured CPF matches. External Targets are inspected as stored XML values and are not fetched.

## Verification and builder handoff

Read-only independent Sol 6.1 xhigh security review found the Flate fallback/parameter/resource, trailing-suffix and malformed Form/resource-shape risks. After the fixes, the reviewer reported no unresolved source blocker; the Windows run is still required. Review is not test evidence or acceptance of a protected driver/agent pair. `git diff --check -- agente` passes; the changed-file scope, 44 allowlist entries and new test-name list were checked against source. These static checks do not compile or execute C#.

Run focused OfficeContentCoverageTests, OfficeUnsupportedPayloadTests, PdfContentCoverageTests and existing Office/PDF streaming controls first, then the required normal/feature × Debug/Release agent matrix through the orchestrator's authorized delivery mechanism. No round-2 build or test success is claimed here; no VM action was performed.
