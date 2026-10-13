# Inspection content coverage — T9 component change

Source scope, pending Windows build/tests and protected qualification. Both extraction APIs use the same readers.
Unsupported content uses `unsupported_format`: staged Blocked, legacy AllowedWithoutInspection.
No PowerPoint registration is added. No OCR, embedded-file or macro execution is provided.

## Word (.docx)

| Payload location | Treatment | Reason |
|---|---|---|
| Main document, headers, footers, footnotes, endnotes, comments | Read | Paragraph text plus remaining text nodes and attributes; note authors included. |
| Text boxes, nested DrawingML paragraphs, AlternateContent Choice and Fallback | Read | Raw XML visits both branches with paragraph boundaries. |
| Drawing `docPr`/`cNvPr` `descr` and `title` | Read | Attributes inspected separately from paragraph runs. |
| Charts and VML parts | Read, subject to child refusal | Rich paragraphs, caches, references and VML inline text are streamed. |
| Charts with embedded workbook | Refused | The chart's `EmbeddedPackagePart` remains unsupported; ordinary Word charts often have this. |
| Core properties | Read | All property text, including title, subject, creator, keywords, description, lastModifiedBy, category, contentStatus. |
| Extended properties | Read | Company, Manager, TitlesOfParts/HeadingPairs strings and other text/attributes. |
| Styles, effects styles, font table, numbering, settings, web settings, theme/override | Read | Names, numbering labels and settings can carry user strings; no opaque formatting exemption. |
| Images, thumbnails, OLE, embedded packages, ActiveX, altChunk, custom XML/properties, ExtendedPart | Refused | Existing refusals retained. |
| Printer settings and every other part type | Refused | No supported reader route. |

## Excel (.xlsx)

| Payload location | Treatment | Reason |
|---|---|---|
| Workbook defined-name text and attributes; sheet names | Read | Includes names independently of cells. |
| Shared strings, worksheet formulas, cached values, inline strings | Read | Stored strings inspected once, including unused ones; missing formula cache refused. |
| Other worksheet text and attributes | Read | Includes headers/footers, validation prompts/formulas and hyperlink labels. |
| Classic comments, threaded comments and persons | Read | Comment text, authors, display names and other attributes. |
| Drawings, nested group shapes, shape/text-box text and alt text | Read | Rich runs remain contiguous within paragraphs; separate items get newlines. |
| Chart titles, axis titles, series names, labels, strCache/numCache and formula references | Read | All chart XML text/attributes; embedded workbook children still refused. |
| VML drawing text boxes | Read | Inline HTML spans contiguous; text boxes and block items separated. |
| Core and extended properties | Read | Same property coverage as Word. |
| Styles, theme/override and calculation chain | Read | Even formatting/reference XML is parsed and scanned. |
| Images, thumbnails, OLE, embedded packages, ActiveX, custom XML/properties, ExtendedPart | Refused | Existing refusals retained. |
| Every other part type, including printer settings | Refused | Unknown/new SDK part types fail closed. |
| ZIP parts outside the reachable relationship graph (both Office formats) | Refused | Orphan content cannot bypass readers; duplicate canonical names also refused. |
| Content-types and relationship XML (both Office formats) | Allowlisted-no-text infrastructure | Only OPC vocabulary is admitted; these are not document parts. Empty ZIP directory records carry no bytes. |

Office traversal retains its visited set and 16,384-part budget; XML depth is capped at 256.
ZIP inventory is capped at 32,770 entries. No document part is exempted as “formatting with no text”.

## PDF

| Payload location | Treatment | Reason |
|---|---|---|
| Page glyph letters | Read | Content order retained; each page ends with a newline. |
| Annotation Contents/T and other dictionary strings, including URI actions | Read | Direct/indirect tokens, nested arrays/dictionaries and URI action chains are inspected. |
| Widget/AcroForm V/T/TU, DV and Opt | Read | Field trees and widget parents are followed; string/hex, name and numeric V/DV supported. |
| Document Info dictionary and outline/bookmark titles | Read | All stored strings, including custom Info strings and child outlines. |
| Catalog XMP metadata | Read | Strict streaming XML text nodes and attributes after PdfPig decoding. |
| Marked-content alternate descriptions/expansion properties | Read | Original glyph inspection preserved. |
| ActualText replacement spans | Refused | Separate rendering-order coverage is not implemented. |
| Page images; EmbeddedFiles; Filespec/EF/AF; FileAttachment; XFA | Refused | Uninspected image, file or form payload. |
| Annotation/field AP appearances, RC rich content, other auxiliary streams, page metadata | Refused | They can contain independent text outside the page-letter reader. |
| JavaScript, non-URI/non-GoTo actions, rich-media annotations | Refused | No execution or multimedia inspection. |
| Incremental revision chains | Refused | Previous xref offset indicates uninspected historical content. |

PDF limits: 4,096 annotation visits, 4,096 field dictionary/parent visits, 4,096 bookmark dictionary visits;
65,536 auxiliary token visits; graph/reference depth 64; XMP depth 256 and decoded size 8 MiB.
These are extraction-work limits, not bounds on PdfPig/Open XML allocation or decoding peak memory.
Residual: PDF orphan/unreferenced objects and unused resource streams are not exhaustively inventoried.
This change does not establish arbitrary PDF stored-byte completeness or close T9's broader resource/qualification work.
