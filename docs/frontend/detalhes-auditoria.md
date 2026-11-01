# Detalhes dos eventos de auditoria

Esta entrega complementa a apresentação dos metadados da HU-04 no painel e na auditoria. Usa os eventos já retornados por `/api/painel` e `/api/auditoria`, sem novas rotas ou alterações no servidor, banco, agente ou driver.

O botão de detalhes expande um evento por vez e pode ser acionado por teclado. São apresentados identificador, horário local com deslocamento UTC, endpoint, usuário, extensão, processo, PID, destino, versão da política aplicada e duração. Campos ausentes são identificados como não informados; zero continua sendo um valor válido para PID e duração. Abrir detalhes não altera os filtros da consulta.

Os resultados recebem explicações diferentes: aprovação não garante ausência de risco; bloqueio orienta a revisão do arquivo; liberação sem inspeção não equivale à aprovação. O motivo técnico é apresentado como recebido, sem inventar a causa quando ausente.

Não são exibidos conteúdo do arquivo nem `maskedSnippets`. Os valores são interpolados como texto, nunca como HTML. Isso não substitui a responsabilidade do servidor e do agente de minimizar e mascarar dados: os demais metadados são apresentados como recebidos.

## Testes

A tabela distingue os canais Arquivo e Área de transferência. Eventos antigos sem `channel` continuam apresentados como arquivos. Clipboard aparece como “Colagem”, com processo de origem e processo de destino; não apresenta extensão nem trata o destino como caminho de arquivo. A orientação de bloqueio e o aviso de privacidade também se adaptam ao canal. Texto copiado e trechos detectados não são exibidos.

`npm test -- detalhes-auditoria.spec.ts` cobre metadados, teclado, filtros, dados ausentes, zero, textos dos resultados, ausência de trechos detectados, escape de HTML e largura em tela pequena, com respostas simuladas.

`migration.spec.ts` também verifica os detalhes de um evento enviado ao backend local de testes. A suíte completa exige esse ambiente isolado, conforme o README. `npm run build` valida a compilação de produção.

Os testes de detalhes cobrem listas mistas (arquivo legado, File explícito e Clipboard), teclado, privacidade, escape de HTML e tela pequena em Auditoria e Painel. O teste de migração envia e reenvia um evento Clipboard ao Java e verifica no navegador que ele aparece uma única vez, com UUID e processos preservados.

Validação inicial em 10/10/2026 na branch `feat/integracao-contratos-atuais`: build Angular aprovado, 17 testes Playwright aprovados e 17 testes Java aprovados. Os testes de navegador usaram backend local temporário e H2 em memória, encerrados ao final. Os eventos de clipboard foram sintéticos: esta validação não demonstra captura de uma colagem real.

A integração posterior do serviço com `IAuditSink` registra sondas de foco com `clipboard_focus_observed`. A interface distingue essas observações de colagens, usando “Monitoramento” e um aviso de que não confirmam colagem ou bloqueio. PID e duração não medidos são exibidos como não informados. O build e os seis testes de detalhes passaram após essa mudança. Consulte `docs/clipboard/INTEGRACAO-AUDITORIA.md` para o fluxo completo e suas limitações.
