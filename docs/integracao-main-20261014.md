# Integração da main em 14/10/2026

## Base e preservação

Branch: `feat/integracao-contratos-atuais`. A base avançou de `e856347c` para `612498f9` por fast-forward, sem rebase, commit novo ou push. As alterações locais continuam não commitadas.

O stash `safeupload-pre-main-20261014` e o backup externo `outputs/pre-main-20261014` foram preservados. A exclusão preexistente de `driver/scripts/Test-StagedW01Parent.ps1` não foi resolvida, restaurada nem incluída como alteração intencional nesta integração.

## Resolução

- Mantida a arquitetura do PR #32: `ClipboardInspectionService`, cache da política, estado do canal e regra global `AuditOnly` no Core.
- O estado de cópia e `ClipboardObservation` transportam categorias, tamanho e versão, sem texto copiado ou trechos detectados.
- `ClipboardAudit` fica no serviço e grava observações de foco na fila com `AllowedWithoutInspection` e `clipboard_focus_observed`. Não afirma colagem ou bloqueio real. A identidade continua vindo do cliente do pipe, não de LocalSystem.
- O pipe, testes e ContractSmoke usam a nova arquitetura; `ClipboardService` não foi ressuscitado.
- Painel e auditoria mantêm a estrutura visual nova, mas consultam a API existente, não o JSON estático nem os incidentes de exemplo.
- Indicadores sem suporte no contrato (pontuação de risco, críticos sem tratamento, percentual de agentes protegidos) não são inventados. São mostrados os indicadores efetivamente fornecidos pelo backend.
- Restabelecidos detalhes de eventos, filtro por endpoint, estado vazio, erros e atualização. Busca, filtros por canal/resultado e exportação CSV usam eventos retornados pela API; o CSV protege células que poderiam ser interpretadas como fórmulas e não exporta trechos sensíveis.
- Seletores dos testes acompanham os nomes novos da navegação, preservando verificações de sessão, perfil e privacidade.

## Verificação local

- Agente/testes C# e ContractSmoke compilaram sem erros nem avisos com SDK portátil 10.0.401.
- 133 testes de clipboard/cache passaram inicialmente. Após reforçar a asserção da versão da política, a recompilação passou, mas o Windows bloqueou a execução do assembly de testes com `0x800711C7`. Não se alterou Controle de Aplicativo nem se removeu o teste. A execução final desse conjunto e a suíte completa ficam pendentes na VM.
- Build Angular aprovado.
- 20 testes Playwright aprovados, incluindo autenticação, autorização, privacidade, filtros, CSV, dados Java reais, heartbeat e deduplicação de eventos.
- Java: 18 testes aprovados. O empacotamento local falhou por classes ausentes no cache dos plugins Maven (jar/surefire). Não se alteraram versões ou dependências do projeto para contornar esse problema.
- Para os testes de navegador, o backend iniciou pelas classes compiladas e dependências do classpath registrado pelo Surefire, sem reutilizar JAR antigo, com H2 em memória e bind em `127.0.0.1:8080`. O processo foi encerrado ao final.
- ContractSmoke foi adaptado e compilado, mas não executado novamente nesta rodada. A execução bem-sucedida da VM em 13/10 pertence à base anterior e não certifica esta integração.

## Próxima etapa

A revalidação elevada na VM foi concluída em 14/10/2026, na base `612498f9569264d1b2f90bbe522a5340e8cb1af0` com alterações locais: 18 testes Java aprovados, JAR empacotado, 661 testes C# aprovados, quatro ignorados e ContractSmoke aprovado (quatro File, um Clipboard, um Web, heartbeat, fila e reenvio idempotente). Isso encerra as pendências de execução na VM descritas na seção de verificação local; não corrige o cache Maven nem o bloqueio de Controle de Aplicativo do host.

Evidência: `validation-612498f9-collected-d21e3251d16440eba6ca73f047b57ec1.zip`, SHA256 `566A7AFE52CE06FF68D7FB46A3BF6D0FB22771205D2E72E5541F39F3E6AA34B7`. Contagens conferidas no TRX e nos XMLs Surefire. Ambiente: Windows 19045.3803, elevado, nenhum adaptador ativo no preflight. O executor não instalou driver. Os quatro ignorados cobrem políticas de navegador, filtro de saída e CA da máquina; não contam como aprovados.

Preparar agora a [validação operacional](VALIDACAO-OPERACIONAL-VM.md). O pacote não comprova execução como serviço instalado, driver carregado, frontend na VM ou comunicação entre duas VMs.

A página de políticas e o fluxo de publicação de política ainda precisam de integração própria. Não foi incorporada a branch divergente `api-web-heartbeat`. O pacote de driver e a compatibilidade com a build da VM continuam dependentes de alinhamento com o responsável.
