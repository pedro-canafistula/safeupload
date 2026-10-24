# Custo dos diagnósticos da fila — 24/10/2026

Atividade #56, parte de #48/#43, PR #49 em rascunho. Fonte `6ae2a6f35adc154cc9ae6e9198ee8a152c3a31bd`. Alteração restrita a `agente/tools/QueueProbe`: medições adicionais de integridade e simulação de prazo. Código de produção, formato da fila, serviço, scripts do instalador e retenção permanecem iguais. Nenhum Java, Angular, banco ou driver alterado.

## Método e resultado local

Release, .NET 10.0.13, Windows build 26300, x64, 16 processadores lógicos. Execução em saída nova com dados sintéticos; sem fila instalada, API, driver ou elevação. A ferramenta conserva suas três escalas, três confirmações de cem por escala e concorrência de 120 segundos. Após as confirmações, cinco consultas de cada diagnóstico conferem contagens, bytes e menor ocorrência contra o histórico reaberto. Corte explícito `2030-01-01T00:00:00Z`: os 300 confirmados sintéticos são anteriores ao corte; o restante permanece pendente. SHA-256 antes/depois das dez consultas foi igual nas três escalas.

| Eventos | Fila após confirmações | Integridade: mediana (mín.–máx.) | Simulação: mediana (mín.–máx.) | Alocação média por consulta |
| --- | --- | --- | --- | --- |
| 1.000 | 516.090 bytes | 25,33 ms (24,19–28,37) | 24,51 ms (24,06–28,61) | 2,58 MiB |
| 10.000 | 5.160.090 bytes | 46,32 ms (42,41–73,54) | 45,24 ms (42,48–60,58) | 25,80 / 25,81 MiB |
| 50.000 | 25.840.090 bytes | 227,97 ms (216,56–239,47) | 223,26 ms (216,84–228,00) | 129,04 MiB |

Cinco amostras por operação/escala, cache aquecido e medição incluindo asserções. Alocação acumulada do processo, não memória viva/pico por consulta. Pico de working set de toda a ferramenta **118.812.672 bytes**; não isola consultas, GC ou serviço. Tempos não são SLA, percentil de produção ou comparação controlada entre versões. A ordem fixa pode favorecer operações posteriores pelo aquecimento.

Concorrência existente: **120,438 s**, 594 ciclos, 10.000 iniciais + 461 novos, **10.461 IDs únicos** íntegros após reabertura, **10.460 confirmados / um pendente**, arquivo de **5.439.067 bytes**. Pendência ao fim do intervalo é válida: produtor pode concluir após a última confirmação; a asserção compara o conjunto exato dos pendentes esperados. Soma estimada de tamanhos dos destinos reescritos **2.590.734.966 bytes**, sem medir escrita física. SHA-256 final **11215BA48C0F4595660DC5E34F72EA56003014605D6F1FCA411DCD29712DC194**.

## Implicações para a próxima etapa

As novas contagens não eliminam a leitura completa e a alocação proporcional às linhas. Elas usam o lock da instância do sink: o tempo medido é relevante para avaliar esse custo, mas o ensaio chama o Core diretamente, sem o prazo de cinco segundos do pipe. A fase concorrente exercita gravação, confirmação e histórico; não acrescenta consultas de diagnóstico concorrentes, nem demonstra espera de gravações sob varredura, cancelamento por prazo ou comportamento com fila maior que 50 mil.

Manter consultas administrativas sob demanda. Não introduzir consulta periódica, retenção ou compactação com base nesses números. Antes de substituir o formato por segmentos/checkpoints, medir carga representativa e recuperação de uma migração. A medição não determina orçamento para dias offline, espaço livre mínimo, dados reais maiores ou hosts mais lentos.

Para retenção efetiva, preparar uma especificação separada com: base temporal explícita; prazo sem padrão implícito; confirmação durável/deduplicação alinhadas com o backend; preservação de todos os pendentes e de eventos referenciados por justificativas; tratamento conservador de duplicatas, tipos/metadados futuros e cauda inválida; substituição recuperável com cancelamento, falta de espaço e interrupção. O campo local `dispatched` não comprova armazenamento atual no servidor e a fila não guarda data da confirmação. Até essa definição, **nenhum descarte habilitado**.

## Aceite

- [x] Compilação/execução Release e três escalas completas.
- [x] Cinco integridades e cinco simulações por escala, 300 confirmados e pendentes preservados.
- [x] Bytes/contagens/menor ocorrência e hashes conferidos.
- [x] Concorrência limitada e conjuntos exatos conferidos após reabertura.
- [x] CI da fonte exata aprovado nos três jobs do agente.

[CI 40113824955](https://github.com/pedro-canafistula/safeupload/actions/runs/40113824955) aprovado nos três jobs. Ferramenta compilada em Debug/Release; suíte C# **835 aprovados, zero falhas e quatro skips em 839**, em cada configuração. PS7/PS5.1 **42/42** cada, ambiente **4/4**, controles existentes de interrupção, volume cheio e serviço instalado aprovados. A medição completa acima é local; não é executada por esse workflow. Logs originais preservados, sem herdar resultados de outra fonte.

[Functional web 40113829119](https://github.com/pedro-canafistula/safeupload/actions/runs/40113829119) reprovado nos três jobs: migração sem bean EmpresaRepository, installed-service com backend encerrado antes de iniciar, agent-contract com backend não iniciado (C# 835/839, quatro skips). Trechos identificados dos logs preservados; nenhum componente web alterado e nenhum aceite de integração real. Não declarar PR inteiro aprovado.

[Recibo original, amostras e hashes](evidencias/custo-diagnosticos-20261024/resumo.json). Filas sintéticas grandes permanecem fora do Git; hashes e resultados ficam no recibo. Sem instalação ou nova homologação do instalador nesta atividade; #48 permanece aberta.
