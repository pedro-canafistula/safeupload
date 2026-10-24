# Cancelamento durante varredura da fila

Ensaio Windows isolado, com o Core real e sem ganchos de produção. Requer SDK
.NET 10 e 2 GiB livres. Nunca usa a fila instalada, instala serviço, chama API,
apaga dados ou termina processos externos. Recusa ProgramData/SafeUpload,
ancestrais reparse e links no arquivo de fila. Somente filhos criados pelo
controlador podem ser encerrados se excederem seu prazo de segurança.

```powershell
dotnet run --project agente/tools/QueueScanCancellationProbe/QueueScanCancellationProbe.csproj -c Release -- C:\Laboratorio\Varredura 3
```

Repetições 1–3 por consulta (integridade/simulação), padrão três. Cria uma pasta
nova, semente de aproximadamente 64 MiB e cópia por cenário, sem limpeza. A
semente repete um par de eventos sintéticos (pendente/confirmado): contagens
são de linhas, não de IDs únicos nem de uma carga representativa de produção.

Cada filho confere a semente e aquece o parser/consulta em outra fila pequena.
Inicia a consulta sobre a fila grande e somente cancela após observar juntos:
tarefa ainda pendente, conflito de compartilhamento indicando leitor aberto
no arquivo e aumento de pelo menos 256 KiB em ReadTransferCount do processo.
Se a consulta terminar antes da observação, o cenário falha; não conta como
cancelamento bem-sucedido. Exige OperationCanceledException/tarefa cancelada,
SHA-256 e tamanho inalterados. A mesma instância precisa voltar a gravar e
consultar; uma reabertura precisa encontrar o ID acrescentado.

O contador é cumulativo do **processo**, não identifica arquivo/offset nem
comprova que uma linha foi completamente parseada. Processo isolado, aquecimento
e conflito do arquivo reforçam a observação, mas não removem essa limitação.
O cancelamento é explícito, após a observação: não exercita o prazo de cinco
segundos do pipe durante uma varredura longa. Não demonstra energia, durabilidade,
memória limitada por linha, justiça do lock ou confirmação por servidor real.

`result.json` agrega os recibos dos filhos. Em falha, `failure.json` registra o
controlador e cenários já concluídos; stdout/stderr ficam no log da execução.
Publicar somente recibos/logs, sem arquivos jsonl grandes.
