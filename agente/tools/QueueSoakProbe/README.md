# Coletor de operação prolongada da fila

Ferramenta do agente para preparar #48. Usa LocalQueueAuditSink real em subpasta
nova e sintética. Não instala componentes, usa serviço/pipe/driver/API, abre a
fila instalada, promove temporários, apaga dados ou altera retenção.

```powershell
dotnet build agente/tools/QueueSoakProbe/QueueSoakProbe.csproj -c Release
dotnet agente/tools/QueueSoakProbe/bin/Release/net10.0/QueueSoakProbe.dll C:\Laboratorio\Fila agente/tools/QueueSoakProbe/pilot.json
pwsh -File agente/tools/QueueSoakProbe/Test-ProbeGuards.ps1 -ProbeDll agente/tools/QueueSoakProbe/bin/Release/net10.0/QueueSoakProbe.dll -OutputParent C:\Laboratorio\Fila
```

O perfil piloto tem três fases de dois segundos: acumular pendentes, confirmar
sem produtor, produzir e confirmar. A taxa é um intervalo mínimo entre operações,
sem rajada para compensar atraso; o total efetivo varia e fica registrado. Não é
o benchmark anterior de 50 mil registros nem ensaio de dias. A execução de 72 h
requer perfil/orçamento acordado e execução efetiva; nenhum perfil de produção
ou agendamento é criado por este piloto.

Test-ProbeGuards.ps1 verifica somente o coletor novo: limite de um evento deve
parar com recibo incomplete e manter a linha; perfil inválido deve falhar antes
de criar saída; destino ProgramData/SafeUpload deve ser recusado. Todos os
arquivos sintéticos, inclusive logs das recusas esperadas, são preservados.

Cada dez eventos há uma justificativa. IDs, instantes e metadados são derivados
da semente e índice, permitindo regeneração sem manter todo o histórico em RAM.
Após cada fase, reabre o sink sem escritor ativo e compara todas as linhas,
metadados, ordem e confirmações com o gerador; confronta diagnóstico de integridade
e hashes antes/depois da consulta. Não é reinício de processo/serviço. Não há
servidor: confirmações são sintéticas e não provam recibo durável ou deduplicação.

samples.jsonl contém UTC, tempo monotônico, intervalo/atraso de coleta, memória,
CPU acumulada, alocações, disco, bytes e contagens. operations.jsonl contém duração
das operações e atraso de produção; result.json registra fases, ambiente, hashes
dos assemblies/perfil/arquivos e status. Memória/CPU incluem o gerador, logs e
verificação; não representam recursos exclusivos do serviço. Verificação e I/O
podem alongar intervalos: ausência de amostra não é zero. O laço é sequencial,
sem deadline de pipe, concorrência ou injeção de falha HTTP/energia/escrita nativa.

Exige 2 GiB livres; valida máximos de duração/eventos/saída, recusa dados instalados,
UNC e ancestrais reparse. Checagens de orçamento ocorrem entre operações, podendo
haver ultrapassagem por uma operação; não são quota rígida. Ctrl+C solicita parada
entre operações; falha/limite/cancelamento produz status incomplete e preserva a
pasta. Kill/queda durante gravação do próprio recibo pode deixá-lo ausente/parcial;
nunca inferir sucesso por sua ausência. Não há proteção contra substituição
concorrente maliciosa dos caminhos. Usar diretório local controlado/descartável.

Para qualquer execução longa futura: guardar perfil aprovado e hashes, limites
de parada e espaço para temporários de regravação; duração real, lacunas e status
devem constar do aceite. Não chamar isso de qualificação instalada, API real,
persistência física ou 72 h antes de obter essas evidências próprias.

## Análise independente, sem executar a carga novamente

Requer PowerShell 7.5+. Measure-ProbeEvidence.ps1 lê o recibo, confere seus hashes,
percorre amostras/operações e compara contagens, ordem temporal e estados. Escreve
somente um relatório novo fora da pasta de evidências; recusa sobrescrita, caminhos
de dados instalados e ancestrais reparse. Usa dados sintéticos estáveis, sem escritor.

```powershell
pwsh -File agente/tools/QueueSoakProbe/Measure-ProbeEvidence.ps1 -EvidenceDirectory C:\Laboratorio\Fila\queue-soak-ID -OutputPath C:\Laboratorio\analise-nova.json
pwsh -File agente/tools/QueueSoakProbe/Test-EvidenceAnalysis.ps1 -PreservedPilotDirectory agente/docs/evidencias/operacao-prolongada-piloto-20261025 -OutputParent C:\Laboratorio\Analise
```

Para o conjunto arquivado no repositório, usar -Prefix pilot- no analisador. O
recibo original mantém os nomes sem prefixo; o parâmetro resolve suas cópias.
Os controles novos analisam cópias do piloto preservado, sem reinstalar ou reexecutar
o gerador. A fonte original é confrontada por hash antes/depois.

O resultado distingue analyzed-completed-run, incomplete-run (recibo ausente ou
de execução incompleta) e invalid-evidence. Inconsistência gera relatório e erro;
incomplete-run não lança erro, por ser um diagnóstico válido de execução incompleta.
Consumidores precisam examinar status; ausência de erro não significa ensaio aprovado.
Nenhum estado concede qualificação de produto, serviço, API ou duração prolongada.

Conta intervalos maiores que o intervalo configurado, incluindo início e fim,
sem inventar quantidade de amostras perdidas nem atribuir falha/SLA. Atraso de
agendamento, logging, operações e verificação também alongam intervalos. Guarda
até 20 detalhes e sinaliza truncamento; máximos de memória/disco são apenas valores
amostrados do processo completo. Sem recibo, a lacuna terminal é desconhecida.
Relógio UTC regressivo é contado separadamente do tempo monotônico.

Limites: 256 MiB por arquivo e 64 Ki caracteres por linha de trace; o analisador
recusa volumes maiores explicitamente. Arquivos de perfil/recibo são lidos inteiros;
traces são percorridos com linha limitada, sem armazenar todas as amostras. Não
revalida conteúdo da fila, autentica manifestos ou protege contra troca maliciosa
concorrente de caminhos. Usa o recibo da verificação do coletor como declaração,
não como nova prova de execução. Limites de análise precisam ser considerados no
perfil futuro antes de iniciar dias de carga.
