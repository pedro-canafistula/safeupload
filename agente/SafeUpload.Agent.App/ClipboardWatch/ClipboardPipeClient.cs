using System.IO;
using System.IO.Pipes;
using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.App.ClipboardWatch;

/// <summary>
/// A ponta do aplicativo no canal de clipboard.
///
/// Uma conexão por pergunta: conecta, escreve uma linha, lê uma linha e fecha.
/// Não mantém conexão nem estado, então não há o que reconectar quando o serviço
/// reinicia, e uma pergunta que falha não contamina a seguinte.
///
/// <b>A falha sempre libera (RN-013).</b> Serviço parado, pipe ocupado, prazo
/// vencido, resposta malformada: todos viram <c>null</c>, e quem chama trata
/// <c>null</c> como "limpo / pode colar". O cliente nunca lança.
/// </summary>
public sealed class ClipboardPipeClient
{
    /// <summary>
    /// Faz uma pergunta ao serviço.
    /// </summary>
    /// <param name="request">O pedido.</param>
    /// <param name="timeout">
    /// Prazo total, da conexão à resposta. É o do protocolo para o tipo de
    /// pedido: curto na colagem, folgado na classificação.
    /// </param>
    /// <param name="cancellationToken">Cancelamento.</param>
    /// <returns>A resposta, ou <c>null</c> se não veio uma válida do tipo certo.</returns>
    public async Task<ClipboardResponse?> SendAsync(
        ClipboardRequest request,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);

        try
        {
            using var pipe = new NamedPipeClientStream(
                ".",
                ClipboardProtocol.PipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous);

            await pipe.ConnectAsync(deadline.Token).ConfigureAwait(false);

            await using (var writer = new StreamWriter(pipe, ClipboardProtocol.Encoding, 1024, leaveOpen: true))
            {
                await writer.WriteLineAsync(ClipboardProtocol.Serialize(request).AsMemory(), deadline.Token)
                    .ConfigureAwait(false);
                await writer.FlushAsync(deadline.Token).ConfigureAwait(false);
            }

            using var reader = new StreamReader(pipe, ClipboardProtocol.Encoding, false, 4096, leaveOpen: true);

            string? line = await ClipboardProtocol.ReadLineAsync(reader, deadline.Token).ConfigureAwait(false);

            ClipboardResponse? response = ClipboardProtocol.DeserializeResponse(line);

            // Uma resposta de outro tipo não responde a esta pergunta.
            return response is not null && response.Type == request.Type ? response : null;
        }
        catch (Exception)
        {
            // Serviço parado, prazo, acesso negado: nenhum merece tratamento
            // diferente, e nenhum pode atrapalhar o usuário.
            return null;
        }
    }
}
