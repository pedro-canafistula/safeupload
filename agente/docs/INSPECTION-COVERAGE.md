# Inspection content coverage — T9

Both extraction APIs use the same readers. Round 2 awaits Windows build/tests and protected qualification.
Unsupported content yields `unsupported_format`: staged Blocked, legacy AllowedWithoutInspection.
No PowerPoint registration, OCR, embedded-file inspection or macro execution is provided.

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
| External relationship Target values (both Office formats) | Read | Raw XML attribute value emitted as a separate item; targets are not followed. |
| Unreachable ZIP parts; duplicate canonical names (both formats) | Refused | Orphan content cannot bypass the reader graph. |
| Content-types/relationship structure; empty ZIP directories (both formats) | Allowlisted-no-text structure | Strict OPC vocabulary; External Targets are separately read. |

All 44 admitted Office part types are read; none is an opaque formatting exemption.
Limits: 16,384 parts (visited set retained), 32,770 ZIP entries, XML depth 256.

## PDF

| Payload location | Treatment | Reason |
|---|---|---|
| Page glyph letters | Read | Content order retained; page boundaries inserted. |
| Annotation Contents/T and other strings; URI actions | Read | Direct/indirect dictionaries, arrays and URI chains. |
| Widget/AcroForm V/T/TU, DV, Opt and inherited values | Read, subject to AP refusal | Fields/parents followed; string, hex, name and numeric values supported. |
| Info strings, outline/bookmark titles, catalog XMP text/attributes | Read | Custom Info, child outlines and strict decoded XMP included. |
| Marked-content alternate descriptions/expansion properties | Read | Original glyph inspection retained. |
| Tagged structure element descriptions/titles | Read | StructTreeRoot child and parent-number-tree traversal distinguishes structure roles from actions; ActualText still refused. |
| AP N/R/D, including every state | Read/validate graphics-only | PdfPig decoding; strict bounded lexer; stored strings, names and comments scanned as separate items. |
| AP text-showing Tj/TJ/'/", XObject Do, inline BI/ID/EI, ActualText | Refused | Appearance text/rendering is not implemented; includes filled text-field widgets. |
| AP missing explicit Resources; nested resource streams; external F/FFilter/FDecodeParms/Ref | Refused | Cannot establish local graphics-only coverage or inspect dependent streams. |
| AP unsupported filters/parameters or malformed content | Refused | Only unfiltered or direct single Flate (absent/null parameters); fallback, framing/checksum and trailing bytes checked. |
| ActualText; RC; other auxiliary streams; page-level Metadata | Refused | Independent replacement/rich/stream content lacks a reader route. |
| Page images; EmbeddedFiles; Filespec/EF/AF; FileAttachment; XFA | Refused | Uninspected image/file/form payloads. |
| JavaScript, non-URI/non-GoTo actions, rich media | Refused | No script execution or multimedia inspection. |
| Multiple cross-reference sections (including Word hybrid exports) | Read when no older definition exists | Unmerged sections must agree on each object number's generation and exact file/object-stream location, and on Root/Info/Encrypt. Identical references to the same bytes are allowed; older definitions or changed trailer graphs remain unsupported_format. |

Filled forms whose appearances draw text are also Blocked as `unsupported_format` until appearance text is read.
Graphics-only APs must have explicit Resources and supported filters; some otherwise valid annotations remain unsupported.
PDF limits: 4,096 annotation/field/bookmark visits each; 65,536 auxiliary and cross-reference visits each; graph depth 64;
AP cumulative 65,536 tokens and 8 MiB decoded bytes, lexer nesting 64; XMP depth 256 and decoded size 8 MiB.
These bound extraction work, not third-party decoding allocations. PDF orphan objects and unused page resources
are not exhaustively inventoried; arbitrary PDF stored-byte completeness and broader T9 qualification remain open.
