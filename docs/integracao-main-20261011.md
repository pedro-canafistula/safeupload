# Integração com a main em 11/10/2026

## Base e preservação

A branch `feat/integracao-contratos-atuais` avançou de `8938f9d7` para `e856347c` por merge fast-forward de `origin/main`, sem reescrita de histórico. O trabalho local foi salvo, retirado temporariamente e reaplicado sem conflitos. Nenhum commit de implementação ou push foi feito.

O stash `safeupload-pre-main-20261011` foi mantido após a reaplicação, como cópia de segurança. Não reaplicá-lo novamente sobre o trabalho atual. Há também backup dos arquivos modificados/não rastreados, patch e identificadores Git em `C:\Users\lucas\.codex\.chatgpt-projects\g-p-6ac0482198d08191ade96dd8d5731b2b\outputs\pre-main-20261011`.

A main integrada inclui o PR #26 de estabilização do driver e os PRs #27, #28, #30 e #31 da inspeção TLS. O registro da equipe com 69/69 cenários está no histórico do commit `73e9e5ff`. Isso não é resultado de testes executados nesta máquina. A branch remota `feat/driver-m2` não foi incorporada separadamente.

## Compatibilidade ajustada

- `AuditEvent` C# ganhou `PublishedSha256Hex` antes de `Channel`. A criação da observação de clipboard agora usa o argumento nomeado `Channel`.
- Java aceita `Web` e `Retained`, preserva o hash opcional e valida seu formato hexadecimal de 64 caracteres.
- Eventos Web podem ter nome/extensão vazios quando representam texto enviado. Eventos File continuam exigindo nome.
- Os resumos incluem `retidos`, separado de bloqueados, aprovados e liberados sem inspeção. O painel apresenta o novo resultado e explica que nenhum conteúdo foi liberado ao destino protegido.
- O canal Web exibe endereço de destino, e o hash publicado fica disponível nos detalhes.
- Hash ausente não é acrescentado ao JSON persistido, preservando a comparação de reenvios de eventos antigos sem esse campo.
- O smoke foi ampliado para seis eventos: quatro File, um Clipboard e um Web; cobre retenção e hash de publicação.

A main também removeu `sourcePaths` do domínio de política C#: a leitura de origem passou a ser classificada por conteúdo. O campo legado ainda enviado pelo Java é ignorado pelo leitor novo; não deve ser apresentado como controle efetivo de escopo nessa versão.

## Validação e impedimentos

- Backend: 18 testes aprovados e pacote gerado, incluindo Web, Retained, hash e reenvio sem duplicação.
- Frontend: build aprovado e sete testes de detalhes aprovados, incluindo retenção e Web.
- C#: compilação dos projetos e do smoke concluída, mas a execução foi bloqueada pelo Controle de Aplicativo do Windows, código `0x800711C7`. Na suíte, o arquivo bloqueado foi `SafeUpload.Agent.Tests.dll`; no smoke, `SafeUpload.Agent.Service.dll`. Não houve aprovação dos testes C# nesta base atualizada.
- `driver/scripts/Test-StagedW01Parent.ps1` ficou inacessível e depois ausente durante o checkout, aparecendo como excluído no Git. A causa dessa ausência não foi confirmada pelos registros consultados. Não foi excluído intencionalmente nem incluído em commit. Deve ser verificado antes de preparar o PR.

Nenhuma proteção do Windows foi desativada ou contornada. Não foram instalados agente/driver, certificados ou proxy nesta etapa. O backend temporário do smoke foi encerrado ao final.

Os logs estão em `outputs/main-backend-validation.log`, `outputs/main-agent-validation.log` e `outputs/main-contract-validation.log` no workspace Codex. O próximo passo é validar os binários em uma VM de homologação ou runner autorizado pela equipe, após conferir a política de execução aplicável. A homologação deve incluir recuperação de fila com backend indisponível e reinício do agente, além de uso real de aplicativos.
