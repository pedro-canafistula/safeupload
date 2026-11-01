using System.IO.Compression;
using System.Xml.Linq;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Tests;

public sealed partial class OfficeContentCoverageTests
{
    [Theory]
    [InlineData("table")]
    [InlineData("metadata")]
    [InlineData("pivot-table")]
    [InlineData("pivot-definition")]
    [InlineData("pivot-records")]
    [InlineData("query-table")]
    [InlineData("connections")]
    [InlineData("external-workbook")]
    [InlineData("xml-mappings")]
    public async Task Spreadsheet_common_parts_are_read_including_cached_copies(string location)
    {
        await Check(CommonPart(location, Cpf, word: false), sensitive: true);
        await Check(CommonPart(location, "clean", word: false));
    }

    [Theory]
    [InlineData("people")]
    [InlineData("comments-extended")]
    [InlineData("comments-ids")]
    [InlineData("comments-extensible")]
    [InlineData("glossary")]
    [InlineData("glossary-styles")]
    public async Task Word_common_parts_and_glossary_children_are_read(string location)
    {
        await Check(CommonPart(location, Cpf, word: true), sensitive: true);
        await Check(CommonPart(location, "clean", word: true));
    }

    [Theory]
    [InlineData(false, "custom-properties")]
    [InlineData(true, "custom-properties")]
    [InlineData(false, "custom-xml-text")]
    [InlineData(true, "custom-xml-text")]
    [InlineData(false, "custom-xml-attribute")]
    [InlineData(true, "custom-xml-attribute")]
    [InlineData(false, "custom-xml-properties")]
    [InlineData(true, "custom-xml-properties")]
    public async Task Office_custom_data_and_enterprise_labels_are_read(bool word, string location)
    {
        await Check(CommonPart(location, Cpf, word), sensitive: true);
        await Check(CommonPart(location, "clean", word));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task External_relationship_targets_are_read_as_individual_items(bool word)
    {
        foreach (bool sensitive in new[] { false, true })
        {
            string path = word ? Clean(true) : CommonPart("external-workbook", "clean", false);
            using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
            {
                string parent = word ? "word/document.xml" : "xl/externalLinks/externalLink1.xml";
                AddExternal(zip, parent, word ? "hyperlink" : "externalLinkPath", "https://example.test/" + (sensitive ? Cpf : "clean"));
                if (word) Write(zip, parent, Read(zip, parent).Replace("</w:body>",
                    "<w:p><w:hyperlink xmlns:r='" + Rel.TrimEnd('/') + "' r:id='external0'><w:r><w:t>clean link</w:t></w:r></w:hyperlink></w:p></w:body>", StringComparison.Ordinal));
            }
            await Check(path, sensitive);
        }
        string split = Clean(word);
        using (var zip = ZipFile.Open(split, ZipArchiveMode.Update))
        {
            string parent = word ? "word/document.xml" : "xl/worksheets/sheet1.xml";
            AddExternal(zip, parent, "hyperlink", "529.982.");
            AddExternal(zip, parent, "hyperlink", "247-25");
        }
        await Check(split);
    }

    [Theory]
    [InlineData("")]
    [InlineData("<data>")]
    public async Task Arbitrary_custom_xml_still_requires_a_complete_root(string xml)
    {
        string path = CommonPart("custom-xml-text", "clean", true);
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update)) Write(zip, "customXml/item1.xml", xml);
        await Check(path, failure: InspectionFailureKind.ReadOrParse);
    }

    private string CommonPart(string location, string text, bool word)
    {
        string path = Clean(word);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Update);
        string main = word ? "word/document.xml" : "xl/workbook.xml";
        void Sheet(string owner, string name, string relation, string root, string body, string attributes = "") =>
            Add(zip, owner, name, Rel + relation, Ct + "spreadsheetml." + relation + "+xml",
                "<" + root + " xmlns='" + S + "' " + attributes + ">" + body + "</" + root + ">");
        switch (location)
        {
            case "table":
                Sheet("xl/worksheets/sheet1.xml", "xl/tables/table1.xml", "table", "table",
                    "<tableColumns count='1'><tableColumn id='1' name='" + text + "'/></tableColumns>", "id='1' name='Table1' displayName='Table1' ref='A1:A2'");
                break;
            case "metadata":
                Sheet(main, "xl/metadata.xml", "sheetMetadata", "metadata", "<metadataStrings count='1'><s v='" + text + "'/></metadataStrings>");
                break;
            case "pivot-table":
                Sheet("xl/worksheets/sheet1.xml", "xl/pivotTables/pivotTable1.xml", "pivotTable", "pivotTableDefinition", "", "name='" + text + "' cacheId='1' dataCaption='Values'");
                break;
            case "pivot-definition": case "pivot-records":
                Sheet(main, "xl/pivotCache/pivotCacheDefinition1.xml", "pivotCacheDefinition", "pivotCacheDefinition",
                    "<cacheSource type='worksheet'><worksheetSource sheet='Plan1' ref='A1:A2'/></cacheSource><cacheFields count='1'><cacheField name='Field'><sharedItems count='1'><s v='" +
                    (location == "pivot-definition" ? text : "clean") + "'/></sharedItems></cacheField></cacheFields>");
                if (location == "pivot-records") Sheet("xl/pivotCache/pivotCacheDefinition1.xml", "xl/pivotCache/pivotCacheRecords1.xml", "pivotCacheRecords", "pivotCacheRecords", "<r><s v='" + text + "'/></r>", "count='1'");
                break;
            case "query-table":
                Sheet("xl/worksheets/sheet1.xml", "xl/queryTables/queryTable1.xml", "queryTable", "queryTable", "", "name='" + text + "' connectionId='1'");
                break;
            case "connections":
                Sheet(main, "xl/connections.xml", "connections", "connections", "<connection id='1' name='Query' description='" + text + "' type='5'><dbPr connection='clean' command='SELECT 1'/></connection>");
                break;
            case "external-workbook":
                Sheet(main, "xl/externalLinks/externalLink1.xml", "externalLink", "externalLink",
                    "<externalBook><sheetNames><sheetName val='Plan1'/></sheetNames><sheetDataSet><sheetData sheetId='0'><row r='1'><cell r='A1' t='str'><v>" + text + "</v></cell></row></sheetData></sheetDataSet></externalBook>");
                break;
            case "xml-mappings":
                Add(zip, main, "xl/xmlMaps.xml", Rel + "xmlMaps", "application/xml",
                    "<MapInfo xmlns='" + S + "'><Map ID='1' Name='" + text + "' RootElement='data' SchemaID='Schema1'/></MapInfo>");
                break;
            case "people": case "comments-extended": case "comments-ids": case "comments-extensible":
                var (root, ns, relationship, type, body) = location switch
                {
                    "people" => ("people", "http://schemas.microsoft.com/office/word/2012/wordml", "http://schemas.microsoft.com/office/2011/relationships/people", "people",
                        "<w:person w:author='" + text + "'/>") ,
                    "comments-extended" => ("commentsEx", "http://schemas.microsoft.com/office/word/2012/wordml", "http://schemas.microsoft.com/office/2011/relationships/commentsExtended", "commentsExtended",
                        "<w:commentEx w:paraId='12345678' label='" + text + "'/>") ,
                    "comments-ids" => ("commentsIds", "http://schemas.microsoft.com/office/word/2016/wordml/cid", "http://schemas.microsoft.com/office/2016/09/relationships/commentsIds", "commentsIds",
                        "<w:commentId w:paraId='12345678' w:durableId='12345678' label='" + text + "'/>") ,
                    _ => ("commentsExtensible", "http://schemas.microsoft.com/office/word/2018/wordml/cex", "http://schemas.microsoft.com/office/2018/08/relationships/commentsExtensible", "commentsExtensible",
                        "<w:commentExtensible w:durableId='12345678' label='" + text + "'/>")
                };
                // Extended comment identity fields have constrained types. An
                // extension attribute exercises the complete attribute pass.
                Add(zip, main, "word/" + type + ".xml", relationship, Ct + "wordprocessingml." + type + "+xml", "<w:" + root + " xmlns:w='" + ns + "'>" + body + "</w:" + root + ">");
                break;
            case "glossary": case "glossary-styles":
                Add(zip, main, "word/glossary/document.xml", Rel + "glossaryDocument", Ct + "wordprocessingml.document.glossary+xml",
                    "<w:glossaryDocument xmlns:w='" + W + "'><w:docParts><w:docPart><w:docPartBody><w:p><w:r><w:t>" + (location == "glossary" ? text : "clean") + "</w:t></w:r></w:p></w:docPartBody></w:docPart></w:docParts></w:glossaryDocument>");
                if (location == "glossary-styles") Add(zip, "word/glossary/document.xml", "word/glossary/styles.xml", Rel + "styles", Ct + "wordprocessingml.styles+xml",
                    "<w:styles xmlns:w='" + W + "'><w:style w:type='paragraph' w:styleId='Private'><w:name w:val='" + text + "'/></w:style></w:styles>");
                break;
            case "custom-properties":
                Add(zip, "", "docProps/custom.xml", Rel + "custom-properties", Ct + "custom-properties+xml",
                    "<Properties xmlns='http://schemas.openxmlformats.org/officeDocument/2006/custom-properties' xmlns:vt='http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes'><property fmtid='{D5CDD505-2E9C-101B-9397-08002B2CF9AE}' pid='2' name='Sensitivity'><vt:lpwstr>" + text + "</vt:lpwstr></property></Properties>");
                break;
            default:
                Add(zip, main, "customXml/item1.xml", Rel + "customXml", "application/xml",
                    "<private xmlns='urn:enterprise:custom' label='" + (location == "custom-xml-attribute" ? text : "clean") + "'><value>" + (location == "custom-xml-text" ? text : "clean") + "</value></private>");
                if (location == "custom-xml-properties") Add(zip, "customXml/item1.xml", "customXml/itemProps1.xml", Rel + "customXmlProps", Ct + "customXmlProperties+xml",
                    "<ds:datastoreItem xmlns:ds='http://schemas.openxmlformats.org/officeDocument/2006/customXml' ds:itemID='{11111111-1111-1111-1111-111111111111}'><ds:schemaRefs><ds:schemaRef ds:uri='urn:private:" + text + "'/></ds:schemaRefs></ds:datastoreItem>");
                break;
        }
        return path;
    }

    private static void AddExternal(ZipArchive zip, string parent, string kind, string target)
    {
        string name = parent[..(parent.LastIndexOf('/') + 1)] + "_rels/" + parent[(parent.LastIndexOf('/') + 1)..] + ".rels";
        XNamespace ns = "http://schemas.openxmlformats.org/package/2006/relationships";
        var xml = zip.GetEntry(name) is null ? new XDocument(new XElement(ns + "Relationships")) : XDocument.Parse(Read(zip, name));
        xml.Root!.Add(new XElement(ns + "Relationship", new XAttribute("Id", "external" + xml.Root.Elements().Count()),
            new XAttribute("Type", Rel + kind), new XAttribute("TargetMode", "External"), new XAttribute("Target", target)));
        Write(zip, name, xml.ToString());
    }
}
