// Traducao de caminho em forma de dispositivo para forma DOS.
//
// O Filter Manager entrega nomes como \Device\HarddiskVolume3\pasta\arquivo,
// e nada em modo usuario abre um caminho nesse formato: nem File.Open, nem os
// extratores, nem o log. A conversao inversa - DOS para dispositivo - esta em
// PolicyBuilder, e e usada para empurrar a politica; esta aqui e a que o
// caminho de volta precisa.
//
// O mapa e montado uma vez e mantido em cache porque QueryDosDevice para cada
// letra de unidade, a cada operacao, seria I/O de kernel dentro do orcamento
// de veredito. Ele e reconstruido quando uma traducao falha, que e o sinal de
// que uma unidade apareceu ou sumiu desde a ultima montagem.

using System.Runtime.InteropServices;
using System.Text;

namespace SafeUpload.Agent.Minifilter;

public static class NtPathTranslator
{
    private static readonly Lock Gate = new();

    private static List<(string Device, string Drive)>? _map;

    /// <summary>
    /// Converte \Device\HarddiskVolumeN\resto em X:\resto.
    ///
    /// Devolve null quando nao ha unidade DOS correspondente, o que e
    /// legitimo: volumes montados apenas em pasta, discos sem letra e
    /// dispositivos que nao sao volume nenhum. Quem chama trata a ausencia
    /// como "nao da para inspecionar", nunca como "bloquear".
    /// </summary>
    public static string? ToDosPath(string ntPath)
    {
        if (string.IsNullOrEmpty(ntPath))
        {
            return null;
        }

        // Ja esta em forma DOS: o driver pode reportar assim quando a
        // normalizacao falha e a flag PATH_NOT_NORMALIZED vem ligada.
        if (ntPath.Length >= 2 && ntPath[1] == ':')
        {
            return ntPath;
        }

        string? translated = Translate(ntPath, Map());

        if (translated is not null)
        {
            return translated;
        }

        // Uma falha pode significar mapa velho. Remonta e tenta de novo,
        // uma unica vez - se falhar outra vez, nao ha letra para este
        // dispositivo e insistir so gastaria o orcamento.
        lock (Gate)
        {
            _map = null;
        }

        return Translate(ntPath, Map());
    }

    private static string? Translate(string ntPath, List<(string Device, string Drive)> map)
    {
        foreach ((string device, string drive) in map)
        {
            if (ntPath.StartsWith(device, StringComparison.OrdinalIgnoreCase) &&
                (ntPath.Length == device.Length || ntPath[device.Length] == '\\'))
            {
                return drive + ntPath[device.Length..];
            }
        }

        return null;
    }

    private static List<(string Device, string Drive)> Map()
    {
        lock (Gate)
        {
            if (_map is not null)
            {
                return _map;
            }

            var map = new List<(string, string)>();
            var buffer = new StringBuilder(1024);

            foreach (string drive in Environment.GetLogicalDrives())
            {
                // "C:\" para "C:", que e o que QueryDosDevice aceita.
                string letter = drive.TrimEnd('\\');

                if (QueryDosDeviceW(letter, buffer, buffer.Capacity) != 0)
                {
                    map.Add((buffer.ToString(), letter));
                }
            }

            // Do mais longo para o mais curto: \Device\HarddiskVolume10 tem
            // \Device\HarddiskVolume1 como prefixo, e casar o curto primeiro
            // produziria um caminho de outra unidade que ainda parece valido.
            map.Sort((a, b) => b.Item1.Length.CompareTo(a.Item1.Length));

            _map = map;
            return _map;
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDeviceW(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);
}
