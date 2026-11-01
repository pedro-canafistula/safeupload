# Diagnóstico de integridade e acúmulo da fila — 30/10/2026

Extração seletiva do inventário preservado no #49/9680383e, sobre main eaa50a0e. Consulta explícita e somente leitura, sem depender do driver ou backend. Não incorpora retenção, classificação de temporários, reparo ou exclusão.

## Consulta administrativa

Com o serviço atualizado em execução, abrir PowerShell como administrador e executar a ferramenta do repositório:

```powershell
$fila = .\agente\scripts\Get-SafeUploadDiagnostics.ps1 -Query audit-integrity
$fila
if ($null -ne $fila.oldestPendingUtc) {
    [DateTimeOffset]::UtcNow - [DateTimeOffset]$fila.oldestPendingUtc
}
```

O comando usa o canal administrativo existente SafeUpload.Agent.Diagnostics; permissões do canal preservadas. O segundo trecho calcula o tempo desde o registro pendente mais antigo com data conhecida, usando o relógio local atual. Não é tempo garantido em espera no servidor; relógios incorretos ou datas futuras afetam essa diferença. Não foi acrescentada tela no aplicativo.

## Resultado e interpretação

A resposta informa existência do arquivo, bytes observados no início pelo mesmo handle, linhas percorridas, eventos/justificativas reconhecidos, pendentes/confirmados, registros inválidos, tipos desconhecidos e linhas em branco. Contagens são de linhas, inclusive IDs duplicados, não de operações únicas nem prova de persistência central. Os critérios do leitor de eventos permanecem inalterados; este diagnóstico não valida todas as regras de negócio ou a completude de cada campo do evento.

OldestPendingUtc considera eventos e justificativas pendentes com data conhecida e normaliza para UTC. PendingWithoutTimestamp conta pendentes reconhecidos sem data; data nula não significa necessariamente ausência de pendentes. Tipos desconhecidos são separados de inválidos, pois podem pertencer a uma versão futura. RequiresAttention indica linhas inválidas ou tipos desconhecidos; não é atestado geral de saúde, proteção ou entrega.

A amostra de problemas é limitada a 20 pares número da linha/motivo padronizado, com indicação de truncamento; contagens continuam percorrendo o arquivo todo. Não retorna IDs, usuários, caminhos, textos dos eventos/justificativas, trechos inspecionados ou mensagens brutas de exceção. Erros de armazenamento no canal são classificados, sem retornar um inventário saudável fictício.

## Consistência e prazo

O serviço fornece ao diagnóstico a mesma instância de LocalQueueAuditSink usada pelas operações de auditoria. O lock por instância é usado somente para abrir o handle e capturar um limite completo de bytes entre gravações. A varredura ocorre depois de liberar o lock e termina nesse limite: novos appends não entram no resultado, e uma confirmação posterior pode substituir o arquivo sem invalidar o handle capturado. Gravação e confirmação podem prosseguir durante a leitura. Não acrescenta coordenação com escritores externos; alterações arbitrárias por outros processos não têm garantia de snapshot. Truncamento detectado antes de completar a leitura gera erro, não inventário completo. A consulta percorre o conteúdo capturado e ainda exige memória para a maior linha e o JSON, embora retenha apenas contadores e a amostra limitada.

Mantido o prazo de cinco segundos do pedido no canal. Cancelamento ou falha de leitura propagam erro; expiração encerra a conexão sem publicar inventário parcial. A ferramenta informa a ausência de resposta. O teste de prazo controla espera real do lock; não é qualificação de tempo máximo para varrer filas grandes. Não há cache, tarefa periódica, reparo ou alteração de recibos/dispatcher.

O teste concorrente expôs que a promoção anterior por File.Move falhava no Windows enquanto o diagnóstico mantinha o handle aberto. A confirmação passa a promover seu temporário com File.Replace para coexistir com essa leitura compartilhada. Mantidos a seleção do lote, a cópia linha a linha, flush/fechamento/cancelamento e limpeza do temporário próprio. Origem e destino permanecem na mesma pasta/volume; não é criada cópia de backup e erros de mesclagem de metadados continuam sendo propagados. [Contrato da API File.Replace](https://learn.microsoft.com/en-us/dotnet/api/system.io.file.replace?view=net-10.0). Os testes existentes de interrupção e bloqueio continuam exigindo preservação do original e retomada; não há novo aceite de queda de energia ou de outro sistema de arquivos.

## Verificação

140 testes locais Release aprovados, zero falhas/ignorados, incluindo 21 casos de integridade, quatro de concorrência/prazo e regressões de fila, confirmação, recibos, comunicação e diagnóstico de driver já existente. Verificados bytes preservados, linhas mistas/inválidas, duplicatas, datas ausentes/UTC, amostra limitada, erros sanitizados, canal real sem driver, ausência da fila configurada, privacidade, gravação/confirmação concorrentes com reabertura e recuperação após expirar o prazo. Os novos casos verificam gravação e confirmação enquanto o handle capturado continua aberto, exclusão de appends posteriores e erro diante de truncamento externo detectado. Sintaxe da ferramenta conferida em PowerShell 7 e Windows PowerShell 5.1.

O ensaio restrito ao runner Windows descartável do GitHub foi ampliado para executar a ferramenta contra o serviço LocalSystem real no primeiro início e após reinício com backend offline, conferindo contagens e preservação da existência/bytes da fila. O resultado remoto deve ser conferido no HEAD da entrega. Não houve instalação de serviço/driver ou consulta à fila de produção nesta validação local. Política central, autenticação do dispositivo, driver, queda de energia e distribuição conservam aceites próprios.
