# Simulação de prazo do histórico confirmado — 0.1.14

Registro de 24/10/2026, atividade #55, parte de #43/#48 no PR #49 em rascunho. Fonte `887abf8d`; datas/horas das execuções são as dos recibos originais. Somente agente Windows, testes e ferramentas; nenhum Java, Angular, banco ou driver alterado.

## Entrega e uso

Nova consulta administrativa `audit-retention-preview`, sem modificar a fila. Reutiliza a varredura de integridade sob o mesmo semáforo da instância, com três acumuladores escalares adicionais; não retém lista de IDs nem faz uma segunda leitura. A interface comum do usuário não muda. O serviço e o script mantêm o mesmo pipe administrativo/ACL, sem depender do driver.

Exemplo de requisição: `{"query":"audit-retention-preview","occurredBeforeUtc":"2026-09-24T00:00:00Z"}`. O corte é escolhido pelo operador apenas para a consulta; esse exemplo não estabelece um prazo padrão. Script: `agente/scripts/Get-SafeUploadDiagnostics.ps1 -Query audit-retention-preview -OccurredBeforeUtc '2026-09-24T00:00:00Z'`. Requer administrador. O cliente recusa o parâmetro em outras consultas, evitando ignorá-lo silenciosamente.

Corte obrigatório ISO 8601 UTC: segundos inteiros ou fração de até sete dígitos, com `Z` ou offset zero explícito. Data sem offset, formato de cultura local, valor ausente/nulo, offset diferente de zero e data default são recusados antes de abrir/ler a fila. A API interna C# aceita DateTimeOffset e normaliza UTC; o protocolo externo exige UTC explícito.

| Campo de resposta | Interpretação |
| --- | --- |
| `occurredBeforeUtc` | Corte UTC da consulta, exclusivo: registros exatamente no corte não são contados como anteriores. |
| `confirmedEventsBeforeCutoff` | Linhas válidas de eventos com dispatched verdadeiro e ocorrência estritamente anterior ao corte. Inclui duplicatas. |
| `confirmedOverridesBeforeCutoff` | Mesmo cálculo para justificativas válidas e confirmadas localmente. |
| `confirmedWithoutTimestamp` | Eventos confirmados aceitos pelo parser existente com data default/ausente, excluídos da contagem por prazo. Justificativas sem data continuam inválidas pela regra anterior. |
| `integrity` | Inventário existente: bytes, válidos, pendentes, confirmados, datas pendentes, inválidos, tipos futuros e amostra limitada de problemas. |
| `previewOnly` / `deletionSupported` | Sempre true / false. A contagem não é elegibilidade para remoção. |
| `timestampBasis` | `record-occurrence-time`: não há data de confirmação persistida na fila. |

Retorno não acrescenta IDs, nomes/caminhos, conteúdo, contas ou justificativas. Os acumuladores internos não são serializados na resposta antiga de audit-integrity. Erro de acesso/I/O continua sanitizado; cancelamento/falha não produz inventário parcial bem-sucedido. Fila ausente/vazia não é criada ou reparada. A data mais antiga não é tempo monotônico: relógio incorreto ou futuro afeta interpretações.

## O que falta para retenção efetiva

Um evento ocorrido há 60 dias e confirmado hoje é contado por ocorrência, não por idade da confirmação. A entrega não pode aplicar uma regra de “30 dias depois da confirmação” sem novo dado persistido/contrato. `dispatched` é estado local, não uma consulta ao armazenamento atual do servidor.

Nenhuma linha contada pode ser descartada automaticamente por esse resultado: justificativa pendente pode referenciar evento antigo confirmado; duplicatas, metadados futuros dentro de tipos conhecidos, tipos desconhecidos e cauda inválida exigem tratamento próprio. A simulação não resolve esses relacionamentos, não inspeciona backups/arquivos temporários nem produz lista de candidatos ou bytes recuperáveis. `requiresAttention` mantém a semântica anterior e não vira autorização para compactar quando falso.

Próxima implementação de retenção deve ter política explícita (base temporal, prazo, exceções, preservação local e requisito de confirmação durável), preservar todos os pendentes e referências necessárias, tratar registros desconhecidos/inválidos sem perda, e demonstrar cancelamento/queda/falta de espaço na substituição. Não apagar automaticamente temporários ou histórico para “abrir espaço”. Até essas decisões e testes, comportamento efetivo de retenção permanece desativado.

## Validação e limites

Local Release: **39 aprovados, zero falhas/skips**, incluindo 14 casos novos e regressões de integridade/confirmação. Testados fronteira exclusiva de 100 ns, data normalizada, duplicatas, referência pendente a evento confirmado, justificativas, evento confirmado sem data, inválidos/tipos futuros, BOM/vazio/ausente, cancelamento/arquivo ocupado, bytes preservados e pipe real sem driver. O resultado não concede remoção mesmo quando uma linha antiga é contada.

PowerShell 7 e Windows PowerShell 5.1: **42/42 cada**, ambiente **4/4**. Caso novo executa a validação real extraída do cliente por AST, sem elevá-lo nem abrir pipe: datas UTC aceitas, ausentes/culturais/sem offset/offset não zero/default recusadas. Teste instalado exercita o script cliente real e o pipe administrativo do serviço LocalSystem, consulta após inserir dados sintéticos inválidos/futuros e após reinício. Chamadas Require e sintaxe verificadas antes da publicação.

[CI 40111656699](https://github.com/pedro-canafistula/safeupload/actions/runs/40111656699) aprovado nos três jobs, fonte limpa `887abf8dd85830e554bd4c190562cd380644df47`: **835 aprovados, zero falhas e quatro skips em 839**, Debug e Release; PS7/PS5.1 **42/42** cada, ambiente **4/4**. Ensaios de interrupção e volume NTFS descartável cheio passaram na nova fonte. Interrupções de confirmação observaram temporário criado; append foi observado na fronteira da operação, sem demonstrar corte de append em andamento. Não é ensaio de energia nem durabilidade física.

Serviço instalado LocalSystem: consulta pelo cliente real, **1.143 bytes/dois pendentes**; após linhas inválida/futura, **1.240 bytes/mesmos dois pendentes**, zero confirmados anteriores ao corte 2030-01-01T00:00:00Z. Reinício preservou a resposta, sem alterar hash da fila. previewOnly true e deletionSupported false em todas as consultas. Instalação, inspeção, reinício e remoção aprovados. Cenário offline; contagem positiva de confirmados foi validada nos testes C#/pipe, sem confirmação de servidor real neste ciclo.

EXE **0.1.14**, **84.060.982 bytes**, 724 arquivos, self-contained e sem assinatura. SHA-256 **A8164C0965A03D40A4054D77810C511E192A99E4E083215A8F748800F9D9BACA**; manifesto **CFC4838385AC4E3AB1C1877BE772EEFBB7C828D9656364EFE5CD8D07CE47F757**. Artifact 12567355184, ZIP 83.609.895 bytes, digest **688ABAB95A50D0E19106904A2C695B1E4A5A7D2ADC8DCC0BF2DD7CF9F5267649**, conferidos localmente e no convidado. Instalador não executado no host. Homologação própria do clone em andamento; não herda aceite 0.1.13.

[Functional web 40111659675](https://github.com/pedro-canafistula/safeupload/actions/runs/40111659675) reprovado: migração sem bean EmpresaRepository; installed-service com backend encerrado antes de iniciar; agent-contract sem backend iniciado. C# de agent-contract passou 835/839 e quatro skips. Backend não alterado; logs completos ficam fora do Git, com trechos identificados preservados. Não declarar PR inteiramente verde.

A varredura continua O(tamanho da fila) e ocupa o lock de leitura/escrita da instância; pode atrasar operações ou ultrapassar o prazo existente de cinco segundos do serviço. Escritores externos não compartilham o lock e podem produzir tamanho/contagens de instantes diferentes. Não há consulta periódica, alertas, retenção/limpeza automática, compactação, benchmark novo, ensaio de dias, durabilidade física ou aceitação de queda de energia nesta entrega. API real #44/#47 e par do driver #46 continuam separados. PR #49/#42 em rascunho, sem merge.

[Recibos e hashes](evidencias/simulacao-retencao-20261024/resumo.json).
