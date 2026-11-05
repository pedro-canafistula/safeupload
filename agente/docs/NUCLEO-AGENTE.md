# Núcleo do agente — ponto de integração

O [PR #90](https://github.com/pedro-canafistula/safeupload/pull/90) é o ponto único de revisão da sequência #82–#90.
Os commits intermediários permanecem no histórico dessa branch. A main de referência é `7dcf139f` (#81).
Build/testes e checks aprovados são evidência de implementação; o critério do AGENTS.md também exige funcionamento
na VM antes de concluir o aceite. A integração continua draft enquanto esse ensaio estiver pendente.

## Implementado nesta sequência

- Publicação de snapshots separada da aprovação; resultado de cópia e falha/repetição têm auditoria própria.
- Publicação/justificativa vinculadas ao conteúdo da política, com snapshot remoto atualizado em segundo plano.
- Estado de proteção considera aceitação do escopo pelo gate e disponibilidade das unidades esperadas.
- Tamanho real, cancelamento, campos de política repetidos, prazo/limite de recibos e validade dos caches revisados.
- Catálogo privado recupera a versão atual do stage com nova inspeção, sem restaurar autoridade anterior.
- Journal de publicação retoma eventos com o mesmo ID; intenção sem resultado durável aparece como não confirmada.
- Renomeação de arquivo exige nova inspeção; decisões em andamento e justificativas do nome anterior são invalidadas.
  O destino anterior fica preservado até a nova publicação. A janela da justificativa usa tempo decorrido.

## Referência histórica do #79

O [PR #79](https://github.com/pedro-canafistula/safeupload/pull/79) não deve ser mesclado em bloco: a main #81 alterou
a composição remota e ampliou as categorias. Correções compatíveis foram selecionadas na sequência atual.
A branch `feat/agente-politica-central-20261101`, commit `3a685674caf182d2f4e93dc2c539e8cfa464e443`, permanece preservada.

O diagnóstico `policy-status` ainda existe apenas nessa referência: `RemotePolicyStatus`, `PolicyDiagnosticsStore`,
`GatePolicyStatus`, cliente PowerShell e seus testes. Uma eventual retomada precisa usar a composição atual, sem
reintroduzir HTTP por arquivo ou apresentar observações antigas como prova de proteção. Os documentos datados de
01/11 e os helpers/testes de liberação antigos também permanecem nessa branch; o fluxo atual cobre liberação por
política em outro desenho. Validação inicial de configuração, mensagens v1 do gate e ensaios ConsoleByIp já estão
presentes na base; não são trabalho perdido por encerrar o PR histórico.

## Aceite e pendências

- VM: validar o par WinFsp/gate, Office/USB/SMB, política offline, renomeações, justificativa, parada e encerramento
  abrupto nos pontos de publicação/auditoria. Medir também custo de cópia/hash/flush em arquivos grandes.
- O journal cobre snapshots publicados; movimentação de diretórios, exclusões de backing e auditoria de bloqueios
  legados conservam seus contratos próprios. Não é journal completo do filesystem ou aceite de queda de energia.
- Arquivos legados/snapshots isolados sem catálogo continuam privados, sem nomes inferidos automaticamente.
- O painel deve apresentar `publication_outcome_unknown` como resultado indeterminado. O enum existente não mudou.
- Thiago/equipe: autenticação, provisionamento, renovação/revogação, mudança de IP e confirmação de aplicação.
- Vitor/equipe: laboratório e aceite do par atual. Distribuição Windows 10/11, assinatura e upgrade/rollback mantêm
  validação própria. Retenção destrutiva e entrega única ao backend não foram qualificadas por esta sequência.

Evidências por SHA, resultados de testes e limites adicionais ficam na descrição do PR consolidado. O fechamento
dos PRs intermediários organiza a revisão e não substitui merge ou aceite na VM.

## Continuação do Agente 1 — 04/11

A branch `fix/agente-stage-io-preventivo-20261104` parte do PR #90 em `88c5f751`, ainda sem merge.
Corrige buffers por handle que escondiam bytes já aceitos do leitor de snapshot e dos demais handles.
Cinco regressões falharam antes da correção; os 150 testes relevantes de núcleo passaram depois dela.
O cache do Windows permanece ativo; isso não qualifica durabilidade em queda de energia.

O [ensaio mínimo](ENSAIO-PREVENTIVO-MINIMO.md) exige WinFsp/gate reais e cobre arquivo limpo, CPF bloqueado,
recusa de escrita direta, notificação e auditoria local. Continua sem execução com driver: falta o SYS atual
compilado/assinado, sob responsabilidade de Victor/equipe. O pacote antigo v18 não substitui o gate v1.

Em 05/11, o gate v1 foi compilado sem alterar C/projeto e assinado com certificado próprio de laboratório.
Na cópia isolada da VM, a assinatura foi validada nativamente; o serviço iniciou como SYSTEM, conectou ao gate,
teve um escopo aceito e montou S:. O ensaio revelou que `Path.TrimEndingDirectorySeparator` preserva `S:\`,
enquanto o host guarda `S:`: o indicador permanecia incompleto. A comparação foi corrigida, com regressão que
também exige manter incompletos os casos de unidade ausente ou gate indisponível. O ensaio de publicação/bloqueio
precisa ser repetido com esse binário; a montagem sozinha não comprova o fluxo completo.
