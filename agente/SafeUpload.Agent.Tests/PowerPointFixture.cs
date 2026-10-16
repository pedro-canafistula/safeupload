using System.IO.Compression;
using System.Text;
using System.Xml.Linq;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

// Independent OPC/XML fixtures: no Open XML SDK writer or extractor constants.
internal static class PowerPointFixture
{
    internal const string P = "http://schemas.openxmlformats.org/presentationml/2006/main";
    internal const string A = "http://schemas.openxmlformats.org/drawingml/2006/main";
    internal const string C = "http://schemas.openxmlformats.org/drawingml/2006/chart";
    internal const string D = "http://schemas.openxmlformats.org/drawingml/2006/diagram";
    internal const string Modern = "http://schemas.microsoft.com/office/powerpoint/2018/8/main";
    internal const string Rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/";
    internal const string Ct = "application/vnd.openxmlformats-officedocument.";
    internal const string Main = "ppt/presentation.xml";
    internal const string Slide = "ppt/slides/slide1.xml";

    internal static LocalPolicyStore InScopePolicy(TestWorkspace workspace)
    {
        // Format coverage is tested with an explicit scope. Product policy
        // defaults, categories, size limits and deadlines remain unchanged.
        workspace.WritePolicy("""
            { "activeCategories": ["Cpf", "Cnpj", "PaymentCard", "Password", "Secret"],
              "monitoredScopes": { "extensions": [".txt", ".csv", ".docx", ".xlsx", ".pdf", ".pptx", ".pptm", ".potx", ".ppsx"],
                "destinationPaths": ["C:\\SafeUpload\\Escopo Monitorado"], "removableDrives": true, "networkPaths": true } }
            """);
        return new LocalPolicyStore(workspace.PolicyFile);
    }

    internal static string Create(string directory, string extension = ".pptx")
    {
        string mainType = extension switch
        {
            ".pptm" => "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml",
            ".potx" => Ct + "presentationml.template.main+xml",
            ".ppsx" => Ct + "presentationml.slideshow.main+xml",
            _ => Ct + "presentationml.presentation.main+xml"
        };
        string path = Path.Combine(directory, Guid.NewGuid() + extension);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        Write(zip, "[Content_Types].xml", "<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'>" +
            "<Default Extension='rels' ContentType='application/vnd.openxmlformats-package.relationships+xml'/>" +
            "<Default Extension='xml' ContentType='application/xml'/>" +
            "<Override PartName='/" + Main + "' ContentType='" + mainType + "'/>" +
            "<Override PartName='/" + Slide + "' ContentType='" + Ct + "presentationml.slide+xml'/></Types>");
        Write(zip, "_rels/.rels", Relationships("officeDocument", Main));
        Write(zip, "ppt/_rels/presentation.xml.rels", Relationships("slide", "slides/slide1.xml"));
        Write(zip, Main, "<p:presentation xmlns:p='" + P + "' xmlns:r='" + Rel.TrimEnd('/') +
            "'><p:sldIdLst><p:sldId id='256' r:id='rId1'/></p:sldIdLst></p:presentation>");
        Write(zip, Slide, SlideXml(Shape(Rich("clean slide"))));
        return path;
    }

    internal static string SlideXml(string shapes, bool hidden = false) => "<p:sld xmlns:p='" + P + "' xmlns:a='" + A +
        "' xmlns:r='" + Rel.TrimEnd('/') + "'" + (hidden ? " show='0'" : "") + "><p:cSld><p:spTree>" + shapes + "</p:spTree></p:cSld></p:sld>";
    internal static string Shape(string paragraphs) => "<p:sp><p:nvSpPr><p:cNvPr id='2' name='TextBox'/><p:cNvSpPr txBox='1'/><p:nvPr/></p:nvSpPr>" +
        "<p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/>" + paragraphs + "</p:txBody></p:sp>";
    internal static string Rich(string text) => "<a:p><a:r><a:t>" + text[..(text.Length / 2)] + "</a:t></a:r>" +
        "<a:r><a:t>" + text[(text.Length / 2)..] + "</a:t></a:r></a:p>";
    internal static string PartXml(string root, string body) => "<p:" + root + " xmlns:p='" + P + "' xmlns:a='" + A + "'>" + body + "</p:" + root + ">";
    internal static string ChartXml(string body) => "<c:chartSpace xmlns:c='" + C + "' xmlns:a='" + A + "'><c:chart>" + body + "</c:chart></c:chartSpace>";

    internal static string Add(ZipArchive zip, string parent, string name, string relation, string contentType, string xml)
    {
        var types = XDocument.Parse(Read(zip, "[Content_Types].xml"));
        types.Root!.Add(new XElement(types.Root.Name.Namespace + "Override", new XAttribute("PartName", "/" + name), new XAttribute("ContentType", contentType)));
        Write(zip, "[Content_Types].xml", types.ToString());
        string id = Relationship(zip, parent, relation, "/" + name);
        Write(zip, name, xml);
        return id;
    }

    internal static string Relationship(ZipArchive zip, string parent, string relation, string target, bool external = false)
    {
        int slash = parent.LastIndexOf('/');
        string name = parent.Length == 0 ? "_rels/.rels" : parent[..(slash + 1)] + "_rels/" + parent[(slash + 1)..] + ".rels";
        XNamespace ns = "http://schemas.openxmlformats.org/package/2006/relationships";
        var relations = zip.GetEntry(name) is null ? new XDocument(new XElement(ns + "Relationships")) : XDocument.Parse(Read(zip, name));
        string id = "rId" + (relations.Root!.Elements().Count() + 1);
        var entry = new XElement(ns + "Relationship", new XAttribute("Id", id), new XAttribute("Type", relation), new XAttribute("Target", target));
        if (external) entry.Add(new XAttribute("TargetMode", "External"));
        relations.Root.Add(entry); Write(zip, name, relations.ToString());
        return id;
    }

    internal static string Read(ZipArchive zip, string name)
    { using var reader = new StreamReader(zip.GetEntry(name)!.Open()); return reader.ReadToEnd(); }
    internal static void Write(ZipArchive zip, string name, string text)
    {
        if (zip.Mode == ZipArchiveMode.Update) zip.GetEntry(name)?.Delete();
        using var writer = new StreamWriter(zip.CreateEntry(name).Open(), new UTF8Encoding(false)); writer.Write(text);
    }
    private static string Relationships(string relation, string target) => "<Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'>" +
        "<Relationship Id='rId1' Type='" + Rel + relation + "' Target='" + target + "'/></Relationships>";
}
