# Detalhes dos eventos de auditoria

Esta entrega complementa a apresentação dos metadados da HU-04 no painel e na auditoria. Usa os eventos já retornados por `/api/painel` e `/api/auditoria`, sem novas rotas ou alterações no servidor, banco, agente ou driver.

O botão de detalhes expande um evento por vez e pode ser acionado por teclado. São apresentados identificador, horário local com deslocamento UTC, endpoint, usuário, extensão, processo, PID, destino, versão da política aplicada e duração. Campos ausentes são identificados como não informados; zero continua sendo um valor válido para PID e duração. Abrir detalhes não altera os filtros da consulta.

Os resultados recebem explicações diferentes: aprovação não garante ausência de risco; bloqueio orienta a revisão do arquivo; liberação sem inspeção não equivale à aprovação. O motivo técnico é apresentado como recebido, sem inventar a causa quando ausente.

Não são exibidos conteúdo do arquivo nem `maskedSnippets`. Os valores são interpolados como texto, nunca como HTML. Isso não substitui a responsabilidade do servidor e do agente de minimizar e mascarar dados: os demais metadados são apresentados como recebidos.

## Testes

`npm test -- detalhes-auditoria.spec.ts` cobre metadados, teclado, filtros, dados ausentes, zero, textos dos resultados, ausência de trechos detectados, escape de HTML e largura em tela pequena, com respostas simuladas.

`migration.spec.ts` também verifica os detalhes de um evento enviado ao backend local de testes. A suíte completa exige esse ambiente isolado, conforme o README. `npm run build` valida a compilação de produção.
