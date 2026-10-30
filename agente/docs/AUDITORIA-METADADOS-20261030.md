# Auditoria: contrato de saída separado da fila — 30/10/2026

Recorte independente de desenvolvimento sobre main 459fce48, com origem na proposta AgentAuditPayload preservada em #42/#49. Não importa a consolidação inteira e não altera Java, banco, Angular, protocolo de heartbeat ou driver.

## Comportamento

POST /agent/events passa a usar um DTO explícito, em vez de serializar diretamente o registro local. O envelope informa schemaVersion=1, hostname e versão real do serviço. Eventos e justificativas conservam IDs, horário equivalente em UTC, origem e os demais metadados do contrato. O campo maskedSnippets é enviado vazio; arquivos e trechos inspecionados não são anexados. Novos campos adicionados futuramente ao domínio local não passam automaticamente para a rede.

O registro local mantém seus trechos mascarados, nome/destino e horário original. O recibo precisa continuar confirmando ambas as contagens completas. Falha de rede ou recibo inválido preserva os pendentes, e somente os IDs do lote efetivamente transmitido são confirmados. Nenhuma fila é reescrita ou migrada para aplicar essa projeção.

Justificativas e outros campos textuais de metadados continuam previstos no contrato; este recorte não afirma anonimização geral nem sanitização de todo texto enviado.

## Compatibilidade com dados já aceitos

O backend compara o payload canônico de um eventId já persistido e responde conflito se os metadados mudarem. Um agente pode continuar com o evento pendente depois que o servidor o aceitou, por perda da resposta. Por isso não foi transportada a transformação de nome de arquivo/destino Web do protótipo antigo: reescrever esses valores somente no emissor bloquearia o reenvio de registros existentes.

A projeção mantém fileName e destinationPath como gravados na fila. Omissão dos trechos e horário UTC são compatíveis com o backend atual, que já descarta esses trechos e normaliza horários antes de persistir/comparar. Os novos campos do envelope não alteram a identidade de evento/justificativa. Dados de envelope de registros antigos não são retroativamente atualizados por um reenvio.

Sanitização adicional de nomes/URLs permanece pendente de uma solução que respeite a identidade dos registros já aceitos, por exemplo no nascimento de novos eventos ou mediante contrato de migração alinhado com o backend. Não se faz fallback para outro ID nem se confirma um conflito como entrega.

## Verificação

Dez casos novos exercitam a projeção sem trechos, preservação local, campos/canais/vereditos/hash, horários, justificativa isolada, recibos incompletos, retomada depois de resposta perdida e limite do lote. Recorte local com os controles existentes de comunicação/recibos: 53 aprovados, zero falhas/ignorados. Build Release do utilitário de contrato: zero erros/avisos.

O ensaio C#/Java/MySQL atual foi ampliado: primeiro aceita o formato do emissor anterior e mantém a fila local pendente; depois executa o dispatcher atual e confere confirmação/deduplicação e preservação dos metadados antigos. O resultado remoto deve ser conferido no HEAD do PR correspondente. Esse ensaio usa bancos novos e descartáveis e não qualifica autenticação de dispositivo, política central aplicada, driver ou upgrade de uma instalação existente.

O workflow de recibos inclui a nova classe e exige que todos os resultados encontrados nela sejam Passed. Os controles existentes e os limites do recibo permanecem ativos. A política da console/Pedro e a composição do par com Vitor conservam seus aceites próprios.
