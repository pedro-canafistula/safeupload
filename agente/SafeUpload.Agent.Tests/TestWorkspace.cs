using System.IO.Compression;
using System.Text;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// Pasta temporária isolada por classe de teste, com os utilitários para
/// montar arquivos de exemplo.
///
/// Os .docx e .xlsx são construídos aqui, em código, em vez de entrarem no
/// repositório como binários. Um binário de teste não é revisável — ninguém
/// consegue ver num diff que ele passou a conter um CPF de verdade — e este é
/// justamente um projeto em que o conteúdo dos arquivos de teste é o objeto do
/// exame. Montá-los a partir do XML deixa visível exatamente o que está dentro.
/// </summary>
public sealed class TestWorkspace : IDisposable
{
    /// <summary>Cria a pasta temporária.</summary>
    public TestWorkspace()
    {
        Root = Path.Combine(Path.GetTempPath(), "safeupload-testes", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Root);
    }

    /// <summary>Pasta raiz do teste.</summary>
    public string Root { get; }

    /// <summary>Caminho de um policy.json dentro da pasta do teste.</summary>
    public string PolicyFile => Path.Combine(Root, "policy.json");

    /// <summary>Caminho de um queue.jsonl dentro da pasta do teste.</summary>
    public string QueueFile => Path.Combine(Root, "queue.jsonl");

    /// <inheritdoc />
    public void Dispose()
    {
        try
        {
            Directory.Delete(Root, recursive: true);
        }
        catch (IOException)
        {
            // Limpeza é melhor esforço; o sistema operacional recolhe depois.
        }
    }

    /// <summary>Grava um arquivo de texto e devolve o caminho completo.</summary>
    public string WriteText(string fileName, string content)
    {
        var path = Path.Combine(Root, fileName);
        File.WriteAllText(path, content, Encoding.UTF8);
        return path;
    }

    /// <summary>Grava um policy.json com o conteúdo informado.</summary>
    public string WritePolicy(string json)
    {
        File.WriteAllText(PolicyFile, json, Encoding.UTF8);
        return PolicyFile;
    }

    /// <summary>
    /// Monta uma operação de arquivo para o caminho informado, lendo tamanho e
    /// data de modificação do disco.
    /// </summary>
    public static FileOperation Operation(
        string path,
        DestinationKind destination = DestinationKind.RemovableDrive,
        string processName = "explorer.exe",
        string destinationPath = @"E:\pendrive",
        long? sizeBytes = null)
    {
        var info = new FileInfo(path);

        return new FileOperation(
            path,
            info.Name,
            info.Extension.ToLowerInvariant(),
            sizeBytes ?? info.Length,
            info.LastWriteTimeUtc,
            processName,
            4242,
            destinationPath,
            destination);
    }

    /// <summary>
    /// Monta um .docx mínimo, porém válido, com um parágrafo por item.
    /// </summary>
    public string WriteWordDocument(string fileName, params string[] paragraphs)
    {
        var body = new StringBuilder();
        foreach (var paragraph in paragraphs)
        {
            body.Append("<w:p><w:r><w:t xml:space=\"preserve\">")
                .Append(Escape(paragraph))
                .Append("</w:t></w:r></w:p>");
        }

        var path = Path.Combine(Root, fileName);
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);

        AddEntry(archive, "[Content_Types].xml", """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
              <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
              <Default Extension="xml" ContentType="application/xml"/>
              <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
            </Types>
            """);

        AddEntry(archive, "_rels/.rels", Relationships("word/document.xml", "officeDocument"));

        AddEntry(archive, "word/document.xml",
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
            + "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body>"
            + body
            + "</w:body></w:document>");

        return path;
    }

    /// <summary>
    /// Monta um .xlsx mínimo, porém válido, com uma célula de texto por item,
    /// todas passando pela tabela de strings compartilhadas — que é como o
    /// Excel de verdade grava texto.
    /// </summary>
    public string WriteSpreadsheet(string fileName, params string[] cells)
    {
        var sharedStrings = new StringBuilder();
        var rows = new StringBuilder();

        for (var i = 0; i < cells.Length; i++)
        {
            sharedStrings.Append("<si><t xml:space=\"preserve\">").Append(Escape(cells[i])).Append("</t></si>");
            rows.Append("<row r=\"").Append(i + 1).Append("\"><c r=\"A").Append(i + 1)
                .Append("\" t=\"s\"><v>").Append(i).Append("</v></c></row>");
        }

        var path = Path.Combine(Root, fileName);
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);

        AddEntry(archive, "[Content_Types].xml", """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
              <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
              <Default Extension="xml" ContentType="application/xml"/>
              <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
              <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
              <Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
            </Types>
            """);

        AddEntry(archive, "_rels/.rels", Relationships("xl/workbook.xml", "officeDocument"));

        AddEntry(archive, "xl/_rels/workbook.xml.rels", """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
              <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
              <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>
            </Relationships>
            """);

        AddEntry(archive, "xl/workbook.xml", """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
              <sheets><sheet name="Plan1" sheetId="1" r:id="rId1"/></sheets>
            </workbook>
            """);

        AddEntry(archive, "xl/sharedStrings.xml",
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
            + "<sst xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" count=\""
            + cells.Length + "\" uniqueCount=\"" + cells.Length + "\">"
            + sharedStrings + "</sst>");

        AddEntry(archive, "xl/worksheets/sheet1.xml",
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
            + "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData>"
            + rows + "</sheetData></worksheet>");

        return path;
    }

    private static string Relationships(string target, string kind) =>
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        + "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        + "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
        + kind + "\" Target=\"" + target + "\"/></Relationships>";

    private static void AddEntry(ZipArchive archive, string name, string content)
    {
        var entry = archive.CreateEntry(name);
        using var stream = entry.Open();
        using var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        writer.Write(content);
    }

    private static string Escape(string value) => value
        .Replace("&", "&amp;", StringComparison.Ordinal)
        .Replace("<", "&lt;", StringComparison.Ordinal)
        .Replace(">", "&gt;", StringComparison.Ordinal);
}
