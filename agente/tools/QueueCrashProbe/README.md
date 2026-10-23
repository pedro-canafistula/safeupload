# Ensaio de interrupção de processos da fila

Ferramenta de diagnóstico: usa o Core real, filas sintéticas e processos filhos
criados pelo próprio ensaio. Não instala/para serviço, usa rede/driver, acessa a
fila instalada, remove dados ou procura processos pelo nome do executável.

```powershell
dotnet build agente/tools/QueueCrashProbe/QueueCrashProbe.csproj -c Release
dotnet agente/tools/QueueCrashProbe/bin/Release/net10.0/QueueCrashProbe.dll outputs/ensaio-fila 3
```

O último argumento é o número de repetições por cenário (1 a 5, padrão 3).
Exige 2 GiB livres. Cria pasta nova `queue-crash-GUID`, recusa o diretório
ProgramData/SafeUpload e caminhos com ancestrais reparse point. O worker interno
exige marcador da ferramenta e manifesto de operação na pasta sintética.
Usar apenas diretório de laboratório local, sem processos externos modificando-o.

## Cenários e oráculo

Cada repetição recebe cópia da mesma semente de 4.096 eventos e 16 justificativas.
Metadados sintéticos têm padding de 4 KiB por evento para tornar observável a
reescrita; appends usam payload de 8 MiB. São estímulos de I/O, não um perfil real
de documentos, tamanho usual de auditoria, capacidade ou SLA do produto.

Quatro operações: append de evento, append de justificativa, confirmação de 100
eventos e confirmação das 16 justificativas. Worker informa prontidão, espera o
pai, inicia a operação real do Core e informa se a Task ainda estava pendente.
O pai interrompe appends após essa fronteira; confirmações após notificação do
temporário. O worker que concluiu a chamada informa `completed` e espera ser
encerrado pelo pai. Apenas o objeto Process retornado por Process.Start é morto;
finally encerra o filho mesmo se uma asserção falhar.

Após encerrar e aguardar a saída, uma instância nova da fila confere:

- todos os IDs e fingerprints de metadados anteriores, sem perda/duplicação;
- novo append ausente, íntegro ou representado por até uma linha inválida;
- payload completo de qualquer append que sobreviveu como registro válido;
- confirmação de lote inteira ou nenhuma, nunca parcial ou de IDs não selecionados;
- justificativas confirmadas ainda presentes fisicamente na fila;
- toda operação cuja conclusão foi informada deve sobreviver;
- nova escrita e justificativa após reabertura, sem ocultar corrupção anterior;
- repetição de confirmação sem perda/duplicação e sem apagar temporários órfãos.

O recibo `result.json` guarda estado observado, PID do filho, código de saída,
Task pendente na fronteira informada, conclusão recebida, tamanho da fila e dos
temporários **depois** de encerrar, contagens e hashes. Não deduz instrução exata
em execução no momento de Kill: o escalonamento pode concluir o append antes
de o pai interromper. Se `WorkerReportedCompletion=true`, isso é conclusão
antes da interrupção, não prova de uma escrita parcial.

## Limites e retenção dos arquivos do teste

Kill de processo com Windows funcionando não equivale a energia perdida,
interrupção do kernel/SSD, cache físico persistido ou disco cheio. Também não
valida recibos da API nem deduplicação no backend. O ensaio não força nem garante
cauda parcial; o diagnóstico de cauda truncada sintética tem testes separados.

Kill antes da substituição pode deixar `queue.jsonl.GUID.tmp`. A fila publicada
é a autoridade atual; o Core não promove nem remove esse órfão automaticamente.
Tratamento de órfãos exige regra própria, sem promover temporário que possa estar
incompleto ou confirmar registros sem recibo. Nenhuma limpeza automática foi
introduzida. Filas/temporários grandes permanecem no laboratório; o CI publica
somente recibos e log do ensaio. Falha gera `failure.json` e saída não zero.
