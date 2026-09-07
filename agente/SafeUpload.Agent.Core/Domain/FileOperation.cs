namespace SafeUpload.Agent.Core.Domain;

/// <summary>
/// Natureza do destino para onde o arquivo está indo. É o que a RN-011 usa,
/// junto da extensão, para decidir se a operação entra em escopo.
/// </summary>
public enum DestinationKind
{
    /// <summary>Pen drive, HD externo, cartão de memória.</summary>
    RemovableDrive,

    /// <summary>Compartilhamento de rede (UNC ou unidade mapeada).</summary>
    NetworkShare,

    /// <summary>
    /// Pasta de sincronização de nuvem. Do ponto de vista do endpoint isto é
    /// uma pasta local comum: entra em escopo por casar com um dos caminhos
    /// monitorados da política, não por uma regra própria.
    /// </summary>
    Cloud,

    /// <summary>
    /// Não é destino nenhum: é a <b>leitura de uma origem sensível</b>.
    ///
    /// Entrou quando o gatilho virou o minifiltro. O mock só conhece um tipo
    /// de operação — arquivo chegando a uma pasta vigiada — e para ele todo
    /// caso é destino. Com interceptação de verdade existe o outro lado: abrir
    /// um documento que pode conter dado sensível, que não vai para lugar
    /// algum ainda mas é o que dá início à cadeia de contaminação.
    ///
    /// Sem este valor a operação seria julgada pela regra de destino, não
    /// casaria caminho vigiado nenhum e sairia como fora de escopo — o
    /// arquivo nunca seria aberto, e a cadeia não teria primeiro elo.
    /// </summary>
    SensitiveSource,

    /// <summary>Destino que a política não acompanha.</summary>
    OutOfScope
}

/// <summary>
/// A operação de arquivo que o agente precisa julgar.
///
/// É um retrato imutável do que se sabe antes de abrir o arquivo. O tipo é
/// puro de propósito: não abre, não lê e não conhece FileInfo. Quem monta isto
/// é a borda do sistema — no agente real, o minifiltro; neste mock, o
/// simulador.
/// </summary>
/// <param name="FilePath">Caminho completo do arquivo de origem.</param>
/// <param name="FileName">Nome do arquivo, sem diretório.</param>
/// <param name="Extension">Extensão com ponto, em minúsculas.</param>
/// <param name="SizeBytes">Tamanho em bytes.</param>
/// <param name="LastWriteUtc">Data da última modificação, em UTC.</param>
/// <param name="ProcessName">Processo que iniciou a operação.</param>
/// <param name="ProcessId">PID desse processo.</param>
/// <param name="DestinationPath">Caminho de destino da cópia ou do envio.</param>
/// <param name="Destination">Natureza do destino.</param>
public sealed record FileOperation(
    string FilePath,
    string FileName,
    string Extension,
    long SizeBytes,
    DateTimeOffset LastWriteUtc,
    string ProcessName,
    int ProcessId,
    string DestinationPath,
    DestinationKind Destination);
