# Análise independente dos registros do coletor — #48

25/10/2026. Fonte `eb76de1f29b097419df9ca597a020bd7c5ccb6e0`, base
`80194e404b759c61740233e94607491762789bd6`, PR #49. Continuação exclusiva do
agente e suas integrações. Nenhum componente de produção ou de colegas alterado.

## Lacuna fechada nesta etapa

O [piloto anterior](OPERACAO-PROLONGADA-PILOTO-20261025.md) já preserva amostras,
operações e recibo. Faltava transformar os arquivos em um diagnóstico que mostrasse
intervalos sem coleta e distinguisse execução declarada concluída, execução incompleta
e evidência inconsistente. Não repetimos o piloto para preencher essa lacuna.

Entregue [Measure-ProbeEvidence.ps1](../tools/QueueSoakProbe/Measure-ProbeEvidence.ps1),
PowerShell 7.5+, leitura independente dos arquivos existentes. Confere hashes/tamanhos
contra o recibo, percorre traces com limite por linha, confronta contagens/ordem temporal,
estados pendentes e fases finais. Não reexecuta o gerador nem verifica novamente todos
os metadados da fila: essa prova pertence ao recibo do coletor original.

Saída nova fora da pasta de evidências, com CreateNew; não sobrescreve relatórios ou
escreve nas entradas. Recusa dados instalados e ancestrais reparse nas entradas/saída.
Verifica estabilidade dos hashes durante a análise; não é proteção contra troca
maliciosa concorrente, autenticação de manifesto ou prova de origem externa.

| Status de análise | Significado | Uso pelo chamador |
| --- | --- | --- |
| analyzed-completed-run | Recibo declara conclusão e os controles de consistência implementados passaram | Não concede qualificação ou novo aceite de produto |
| incomplete-run | Recibo ausente ou declara incomplete; traces lidos são coerentes nos controles implementados | Resultado de diagnóstico válido, mas o ensaio não passou; verificar status, não apenas ausência de erro |
| invalid-evidence | Hash, formato, sequência, contagens ou recibo falham em algum controle | Relatório separado preservado e erro devolvido; não qualificar execução |

Sem recibo, o intervalo terminal é desconhecido. Cauda de trace sem LF é recusada,
sem completar, reparar ou apagar bytes. Entradas muito grandes também são recusadas:
256 MiB/arquivo, 64 Ki caracteres/linha. Perfil/recibo são lidos inteiros; traces são
percorridos sem reter todas as amostras. Adequar o perfil longo a esses limites antes
de executá-lo. Uma execução incomplete sem traces suficientes pode resultar em
invalid-evidence: ausência de dados não se converte em diagnóstico de saúde.

## Resultado obtido sobre o piloto preservado

O arquivo original não foi modificado. A análise confirmou 55 amostras, 64 appends,
62 confirmações sintéticas de eventos e seis de justificativas, compatíveis com o
recibo da execução de 6,057133 s. Status analyzed-completed-run, com todas as flags
de qualificação falsas.

| Medida extraída | Valor |
| --- | --- |
| Intervalo configurado | 100 ms |
| Início até a primeira amostra | 43,1775 ms |
| Última amostra até o fim declarado | 113,6403 ms |
| Maior intervalo observado, incluindo extremidades | 125,6838 ms |
| Intervalos acima do configurado | 54; detalhes limitados a 20, truncamento sinalizado |
| Maior working set amostrado | 60.948.480 bytes |
| Maior memória privada amostrada | 29.192.192 bytes |
| Maior fila amostrada | 33.330 bytes; recibo final 34.352 bytes |
| Maior duração de operação registrada | 35,1456 ms |

Intervalo acima de 100 ms não prova amostra perdida ou falha do agente: agendamento,
logging, operação de fila e verificação também consomem tempo. Não foi criada tolerância
arbitrária de SLA nem estimado número de amostras ausentes. A diferença entre maior
fila amostrada e tamanho final mostra por que coleta periódica não é inventário final.
Os valores de memória são máximos entre amostras do processo inteiro, não pico real
ou recursos exclusivos do serviço. Regressões do relógio UTC são contadas separadamente
do tempo monotônico; não se trocou o relógio da máquina para testar.

## Dez controles novos aprovados

[Test-EvidenceAnalysis.ps1](../tools/QueueSoakProbe/Test-EvidenceAnalysis.ps1) cria cópias
sintéticas do conjunto preservado. Não inicia fila, API, serviço ou processo do agente.

1. Piloto íntegro: análise concluída coerente, sem nova qualificação.
2. Recibo omitido: incomplete-run, sem assumir intervalo terminal.
3. Cauda parcial: invalid-evidence, motivo específico de linha sem terminador.
4. Tempo monotônico regressivo: invalid-evidence.
5. Contadores pendentes incoerentes: invalid-evidence.
6. Arquivo alterado sem atualizar manifesto: divergência de hash/tamanho.
7. Lacuna sintética de 10 s: intervalo de 10.113,2783 ms detectado; qualificação falsa.
8. Fase final omitida: invalid-evidence.
9. Nome duplicado no manifesto: invalid-evidence.
10. Saída existente ou dentro das evidências: recusas, sem sobrescrever/criar arquivo.

Nos casos de formato/contadores, somente o manifesto da cópia sintética é recalculado
para alcançar a validação desejada; isso demonstra que manifesto editável não é prova
de autenticidade. Os testes conferem status, motivo esperado e flags falsas, além dos
hashes das seis entradas originais antes/depois. A lacuna é fabricada em timestamps
da cópia, sem esperar dez segundos ou mudar relógios. Não é perda real de coleta.

## Reprodução e preservação

Comandos em [QueueSoakProbe/README](../tools/QueueSoakProbe/README.md). Para ler o conjunto
arquivado, informar -Prefix pilot-. O script de controles regenera as cópias a partir
da evidência já versionada; a pasta de saída deve ser nova ou conter somente arquivos
descartáveis sob controle do operador. Nenhuma remoção automática foi adicionada.

[Manifesto e relatórios brutos](evidencias/analise-coleta-20261025/resumo.json): 11 arquivos
conferidos por tamanho/SHA-256. Resultados negativos são controles aprovados do analisador,
não falhas novas do agente. Código dos controles e hashes das fontes permitem reproduzir
os casos sem reexecutar a carga. Pastas completas das cópias continuam fora do Git.

Somente esses controles novos foram executados em PowerShell 7.6.5. Sem build C#,
suíte de produto, reinstalação, homologação repetida ou VM iniciada. Commits usam
skip ci para evitar repetição das suítes existentes; nenhum workflow foi alterado,
nenhum aceite de CI foi atribuído a esta entrega. A falha anterior de Functional web
continua aberta. #48 permanece pendente de perfil/orçamento e execução real por dias;
energia, escrita nativa, retenção/recuperação e API real continuam aceites próprios.
PR #42 preservado e PR #49 em rascunho, sem merge.
