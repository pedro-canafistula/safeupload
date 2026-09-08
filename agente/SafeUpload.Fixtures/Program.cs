// Gera os arquivos de teste que a bateria usa para medir o custo real de
// inspecao.
//
// Existe porque .txt nao mede nada que importe. Um .txt pequeno cabe folgado
// em qualquer prazo, e foi com ele que a cadeia foi dada como funcionando; os
// arquivos que o produto existe para vigiar sao contrato, planilha de
// clientes, relatorio - .docx e .xlsx, que passam pelo Open XML e custam uma
// ordem de grandeza a mais para abrir.
//
// Roda na VM de desenvolvimento, no momento da publicacao, e os arquivos vao
// no pacote. A VM alvo nao tem como gera-los: nao ha Office nem SDK la, e
// montar Open XML a mao em PowerShell seria codigo de teste mais fragil que o
// que ele testa.

using System.Diagnostics;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;
using DocumentFormat.OpenXml.Wordprocessing;

// Os dois formatos declaram Run, Text e Paragraph com o mesmo nome e
// significados diferentes. Os apelidos dizem qual e qual em vez de deixar a
// resolucao depender da ordem dos usings.
using WordRun = DocumentFormat.OpenXml.Wordprocessing.Run;
using WordText = DocumentFormat.OpenXml.Wordprocessing.Text;
using WordParagraph = DocumentFormat.OpenXml.Wordprocessing.Paragraph;
using DomainCategory = SafeUpload.Agent.Core.Domain.Category;

namespace SafeUpload.Fixtures;

public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.Error.WriteLine("uso: SafeUpload.Fixtures <pasta-de-saida> [numero-de-paragrafos]");
            return 1;
        }

        string output = args[0];
        int bulk = args.Length > 1 && int.TryParse(args[1], out int parsed) ? parsed : 400;

        Directory.CreateDirectory(output);

        string cpf = SyntheticCpf("123456789");

        WriteDocx(Path.Combine(output, "contrato-com-cpf.docx"), cpf, bulk);
        WriteDocx(Path.Combine(output, "contrato-sem-nada.docx"), null, bulk);
        WriteXlsx(Path.Combine(output, "planilha-com-cpf.xlsx"), cpf, bulk);
        WriteXlsx(Path.Combine(output, "planilha-sem-nada.xlsx"), null, bulk);

        Console.WriteLine($"  CPF sintetico: {cpf}");
        Console.WriteLine();

        return Measure(output);
    }

    /// <summary>
    /// Mede quanto custa extrair e varrer cada arquivo, aqui, com os mesmos
    /// extratores e o mesmo varredor que o servico usa.
    ///
    /// E o numero que decide o prazo, e ele nao precisa da VM alvo nem do
    /// driver para existir. Medir na maquina de desenvolvimento da o custo
    /// do trabalho; o que ela nao da e a latencia que o usuario sente, que
    /// inclui o caminho ate o kernel e de volta.
    /// </summary>
    private static int Measure(string output)
    {
        ExtractorRegistry extractors = ExtractorRegistry.CreateDefault();
        IReadOnlySet<DomainCategory> categories = new HashSet<DomainCategory>
        {
            DomainCategory.Cpf, DomainCategory.Cnpj, DomainCategory.PaymentCard, DomainCategory.Password,
        };
        bool anyFound = false;

        Console.WriteLine("  arquivo                       bytes   extrair   varrer    total   achados");

        foreach (string file in Directory.GetFiles(output).OrderBy(static f => f))
        {
            var info = new FileInfo(file);
            ITextExtractor? extractor = extractors.Resolve(info.Extension);

            if (extractor is null)
            {
                Console.WriteLine($"  {info.Name,-24} {info.Length,8:N0}   (sem extrator)");
                continue;
            }

            // Uma passagem antes de medir: a primeira toca disco frio e
            // carrega o Open XML, e mediria o arranque do processo em vez do
            // custo por arquivo.
            using (var warm = File.OpenRead(file)) { extractor.ExtractAsync(warm, CancellationToken.None).GetAwaiter().GetResult(); }

            var clock = Stopwatch.StartNew();

            using FileStream stream = File.OpenRead(file);
            string text = extractor.ExtractAsync(stream, CancellationToken.None).GetAwaiter().GetResult();

            long extractMs = clock.ElapsedMilliseconds;
            clock.Restart();

            IReadOnlyList<Finding> findings = ContentScanner.Scan(text, categories);

            long scanMs = clock.ElapsedMilliseconds;

            anyFound |= findings.Count > 0;

            Console.WriteLine(
                $"  {info.Name,-24} {info.Length,8:N0} {extractMs,7} ms {scanMs,6} ms {extractMs + scanMs,6} ms {findings.Count,8}");
        }

        if (!anyFound)
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine("  ERRO: nenhum achado em arquivo nenhum. Os arquivos com CPF nao");
            Console.Error.WriteLine("  serviriam para testar bloqueio - a bateria passaria por engano.");
            return 1;
        }

        return 0;
    }

    /// <summary>
    /// Calcula os digitos verificadores em vez de embutir um numero pronto.
    /// Base 123456789 produz 123.456.789-09, o exemplo canonico - sintetico,
    /// e de pessoa alguma.
    /// </summary>
    private static string SyntheticCpf(string bas)
    {
        int first = 0;

        for (int i = 0; i < 9; i += 1)
        {
            first += (bas[i] - '0') * (10 - i);
        }

        int d1 = first % 11 < 2 ? 0 : 11 - (first % 11);
        string withD1 = bas + d1;
        int second = 0;

        for (int i = 0; i < 10; i += 1)
        {
            second += (withD1[i] - '0') * (11 - i);
        }

        int d2 = second % 11 < 2 ? 0 : 11 - (second % 11);

        return $"{bas[..3]}.{bas[3..6]}.{bas[6..]}-{d1}{d2}";
    }

    /// <summary>
    /// O texto de enchimento existe para o arquivo custar o que um documento
    /// real custa. Um .docx de um paragrafo abre em milissegundos e mediria a
    /// mesma coisa que o .txt ja mede - nada.
    ///
    /// O CPF, quando ha, fica no FIM: se o extrator ou o varredor pararem no
    /// primeiro trecho, o teste tem de reprovar em vez de passar por sorte.
    /// </summary>
    private static void WriteDocx(string path, string? cpf, int bulk)
    {
        using var document = WordprocessingDocument.Create(path, WordprocessingDocumentType.Document);

        MainDocumentPart main = document.AddMainDocumentPart();
        main.Document = new Document();
        Body body = main.Document.AppendChild(new Body());

        body.AppendChild(Paragraph("Contrato de prestacao de servicos"));

        for (int i = 0; i < bulk; i += 1)
        {
            body.AppendChild(Paragraph(
                $"Clausula {i + 1}. As partes acordam os termos descritos neste instrumento, " +
                "que passa a vigorar na data de sua assinatura e permanece valido ate " +
                "manifestacao em contrario de qualquer das partes."));
        }

        if (cpf is not null)
        {
            body.AppendChild(Paragraph($"Responsavel legal, inscrito no CPF {cpf}."));
        }

        main.Document.Save();
    }

    private static WordParagraph Paragraph(string text) =>
        new(new WordRun(new WordText(text) { Space = SpaceProcessingModeValues.Preserve }));

    private static void WriteXlsx(string path, string? cpf, int bulk)
    {
        using var document = SpreadsheetDocument.Create(path, SpreadsheetDocumentType.Workbook);

        WorkbookPart workbook = document.AddWorkbookPart();
        workbook.Workbook = new Workbook();

        WorksheetPart worksheetPart = workbook.AddNewPart<WorksheetPart>();
        var data = new SheetData();
        worksheetPart.Worksheet = new Worksheet(data);

        Sheets sheets = workbook.Workbook.AppendChild(new Sheets());
        sheets.Append(new Sheet
        {
            Id = workbook.GetIdOfPart(worksheetPart),
            SheetId = 1,
            Name = "Clientes",
        });

        data.AppendChild(Row("Codigo", "Cliente", "Observacao"));

        for (int i = 0; i < bulk; i += 1)
        {
            data.AppendChild(Row(
                $"C{i + 1:D5}",
                $"Cliente numero {i + 1}",
                "Cadastro regular, sem pendencias registradas ate a presente data."));
        }

        if (cpf is not null)
        {
            data.AppendChild(Row("C99999", "Cliente final", $"CPF {cpf}"));
        }

        worksheetPart.Worksheet.Save();
        workbook.Workbook.Save();
    }

    private static Row Row(params string[] cells)
    {
        var row = new Row();

        foreach (string cell in cells)
        {
            row.AppendChild(new Cell
            {
                DataType = CellValues.String,
                CellValue = new CellValue(cell),
            });
        }

        return row;
    }
}
