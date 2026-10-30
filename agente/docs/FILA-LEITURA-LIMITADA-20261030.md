# Fila e histórico — leitura limitada — 30/10/2026

Recorte seletivo da implementação preservada no #49/9680383e, adaptado à main 71686854. Não importa confirmação em fluxo, retenção, compactação, diagnósticos ou a consolidação inteira.

## Comportamento

ReadPendingAsync com limite positivo conserva apenas o lote pedido e encerra a varredura ao encontrar essa quantidade de eventos elegíveis. Eventos já confirmados, justificativas, tipos desconhecidos e linhas inválidas não consomem o limite. Continua retornando os primeiros pendentes na ordem do arquivo, inclusive duplicatas existentes.

ReadRecentAsync com limite positivo percorre a fila e mantém somente os últimos N eventos, retornados na ordem inversa de gravação. Não ordena por horário. O histórico ainda exige percorrer o arquivo inteiro; o ganho é limitar os registros retidos em memória, e não tornar a consulta independente do tamanho do arquivo.

Limites zero ou negativos mantêm a consulta completa legada. O limite é de registros, não de bytes: uma linha muito grande ainda pode exigir memória proporcional ao seu tamanho, e a desserialização gera alocações temporárias durante a varredura. Não há novo cursor, índice persistido ou limite geral de memória.

## Preservação e verificação

As leituras não reescrevem a fila. Formato JSONL, BOM legado, metadados, IDs, registros inválidos e horários permanecem preservados em disco. Mantidos o lock local, compartilhamento entre serviço/interface e cancelamento. Gravação, confirmação de eventos/justificativas, dispatcher e recibos não mudam neste recorte.

Os casos de QueueBoundedReadTests preservados no #49 verificam limites 1/2/7/0/-1/int.MaxValue, BOM, filas mistas, metadados, duplicatas, ordem de gravação diferente da ordem dos horários, hash dos bytes, reabertura, ausência de arquivo, cancelamento e arquivo ocupado. Acrescentado cenário de confirmação de dois lotes, escrita após a leitura e reabertura, preservando os demais pendentes e a justificativa.

O recorte local de persistência, justificativas, codificação, projeção HTTP e recibos teve 73 testes aprovados, zero falhas/ignorados, incluindo 16 casos de leitura limitada. O workflow de recibos passa a executar e exigir esse grupo. Os checks remotos devem ser conferidos no HEAD da entrega correspondente. Este incremento não qualifica retenção, confirmação em fluxo, política central, driver ou atualização de instalação.
