# Despacho e latência — investigação de 05/11/2026

Base: [PR #95](https://github.com/pedro-canafistula/safeupload/pull/95),
`3c13b3e7b41bb7a66f276ca2a99eac2766dfde08`.
Branch: `fix/agente-dispatch-latencia-20261105`.

Não foi reproduzido defeito no despachante. A entrega acrescenta quatro testes de recuperação e este registro;
o código de execução permanece igual ao #95. Há evidência de relógios divergentes e demora no próprio ensaio,
mas os registros disponíveis não permitem atribuir todo o atraso exclusivamente à infraestrutura.

## Separação dos tempos

| Etapa | Evidência disponível e limite |
| --- | --- |
| Inspeção | O CPF da tentativa extra (`3f36b219-823a-47e4-972d-43a9c0b4cf6c`) registra `elapsedMs=5`. Esse campo mede o caminho de inspeção, sem publicação, fila ou HTTP. Não mede a espera anterior para iniciar a inspeção. |
| Publicação | Os ensaios aprovados conferem bytes/hash no backing. Não registram duração da cópia. |
| Criação e fila | `OccurredAtUtc` é atribuído ao criar o evento; na publicação, o journal o prepara antes de `File.Move` e o entrega à fila depois. Não é horário de conclusão da cópia, inserção SQL ou confirmação local. |
| Início do despacho | `CommunicationObservation(Audit)` começa depois da leitura dos pendentes. Os avisos guardam amostras do último início/sucesso, sem histórico completo nem duração monotônica. Não permitem separar espera na fila, conexão, cabeçalhos e corpo HTTP. |
| Backend | Consulta SQL somente leitura recuperou `received_at_utc` dos 18 registros preservados. O horário de ocorrência sozinho não indica recebimento. |
| Roteiro/VM | `Wait-Event` de `Test-CentralPolicyDrive.ps1` procura um registro local. A mensagem `Inspection outcome timed out` não é timeout do despachante. O resultado parcial dessa tentativa não foi exportado pelo helper v5; não sabemos qual espera local expirou. |

Dois fatos impedem uma leitura direta dos tempos antigos:

- Evento `ccaff0f0-7b28-4e5f-a81d-c05c9850b8a4`: ocorrência da VM às **13:56:26.182 UTC**, recebimento
  do host às **13:54:09.200 UTC**. Diferença aparente **−136,982 s**; não é latência de transporte.
  O DOCX da mesma fase apresenta **−135,508 s**. Datas SQL foram normalizadas da configuração −03:00 do Java/JDBC.
- No relógio do host, o resultado completo do reinício offline chegou às **14:24:35.226**; os avisos desse
  cenário só foram exportados às **14:29:44.483**: **309,257 s depois de o resultado já estar disponível**.
  Essa espera do auxiliar não mede inspeção/publicação. O auxiliar aguardava um job de leitura do pipe,
  com janela nominal baseada em `UtcNow`, antes de exportar os avisos e aceitar outro comando.

O Java ficou pronto às **14:27:09.075 UTC**; o lote pendente entrou no SQL às **14:29:45.477**.
Houve pausa/retomada breve da cópia às **14:29:42.969**, cerca de **2,508 s antes da persistência**.
É correlação com uma intervenção no ambiente, não prova de causa. Faltam instantes monotônicos do início
e fim de cada tentativa HTTP nesse intervalo. Permanecem hipóteses de agendamento/relógio da VM,
espera do auxiliar, transporte e I/O local; não foi demonstrada espera de minutos programada no despachante.

## Concorrência, timeout e recuperação

O #94 já mantém dois laços independentes, cada um serial. Não há backoff exponencial:
cada operação termina e espera o intervalo configurado; no ensaio eram 2 s, com timeout HTTP de 3 s.
O envio usa o mesmo orçamento para cabeçalhos e corpo do recibo. Confirmação exige recibo completo;
falha, timeout ou cancelamento preservam os registros para nova tentativa com os IDs originais.

**Antes:** 84 testes direcionados do #95 aprovados. **Depois:** os mesmos 84 e quatro casos novos,
**88 aprovados, zero falhas/ignorados** em Windows Release. Único aviso restante: CA2022 preexistente,
fora deste recorte. Sem alteração do comportamento de execução.

Os casos novos exercitam o serviço de fundo com HTTP controlado: persistência anterior à perda de resposta,
timeout antes dos cabeçalhos ou durante o corpo, continuidade dos heartbeats, ausência de lotes sobrepostos,
cancelamento na parada, reabertura da fila, backend 503 e recuperação automática. Conferem payloads idênticos,
uma confirmação local e um registro por ID no modelo idempotente. Esse modelo não é nova homologação Java;
a persistência nativa do #95 continua sendo evidência separada. Nenhuma VM foi retomada nesta investigação.

## Composição para o Agente 4

Este commit pode ser aplicado sobre `3c13b3e7`; contém somente testes/documentação. Não exige trocar os
binários funcionais do #95. Reutilizar `AdministrationSchedulingTests`, `DispatcherRecoverySchedulingTests`,
`DispatcherReliabilityTests`, `AuditReceiptBoundsTests`, `AgentAuditDispatchTests`, `CommunicationHealthTests`
e `CommunicationLoggingTests` na composição final.

Autenticação/identidade do Agente 5 e WPF do Agente 3 permanecem intactas. A interface existente é
`IAgentHeartbeat.SendAsync(CancellationToken)`: a implementação deve respeitar o cancelamento e o orçamento
HTTP de sua composição. Não foi encontrado defeito que exija mudança nessa interface ou no cliente de identidade.

Para esclarecer o atraso histórico, obter uma reprodução curta em ambiente independente: manter `Stopwatch`
para durações e UTC para correlação; registrar separadamente fila, início HTTP, cabeçalhos, fim do recibo,
confirmação local e exportação do auxiliar. Capturar `communication-health`, `audit-health` e `audit-integrity`
antes/depois. Não elevar timeouts, afrouxar recibos ou trocar filas como suposta correção.
