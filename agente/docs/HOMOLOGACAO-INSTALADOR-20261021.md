# Homologação operacional do agente Windows — 21/10/2026

## Resultado e escopo

Status de integração do PR: [o workflow Functional web continua falhando, com as mesmas etapas já reprovadas na main](DIAGNOSTICO-FUNCTIONAL-WEB-20261021.md). A aprovação abaixo pertence ao ensaio isolado do agente e não significa que todos os checks do PR passaram.

**Aprovada a instalação inicial, inspeção sintética, reinício do serviço e remoção do candidato 0.1.4 em Windows Server 2025 descartável, sem driver.** A execução também aprovou a suíte C# completa em Debug e Release no runner, sem falhas. Windows 10/11, UI interativa e o par protegido agente/driver continuam pendentes; esta é a primeira etapa operacional da macro, não liberação geral de produção.

Execução: [39710172814](https://github.com/pedro-canafistula/safeupload/actions/runs/39710172814), conclusão `success`. Fonte exata testada: `24f39c2818bb48a908ef4dfa26789519db9e1bc0`, branch `tarefa/consolidar-base-agente-windows`.

O workflow `agent-homologacao.yml` roda dois jobs independentes de componentes e um de instalação, em runners diferentes. Usa apenas permissões de leitura do repositório; nenhuma etapa executa merge. A única mudança fora de `agente/` é esse CI exclusivo do agente. Java, Angular, banco e driver não foram alterados.

## Artefato efetivamente instalado

| Campo | Valor |
|---|---|
| EXE | `SafeUploadAgent-0.1.4-win-x64-setup.exe` |
| Fonte | `24f39c2818bb48a908ef4dfa26789519db9e1bc0` |
| Fonte limpa no build | `sourceDirty=false` |
| SHA-256 | `EAD34947B0AB8AAF60DD4AB9757BA5D1F5FA28E57736D9B4ECB360AA2AC5E099` |
| Tamanho | 84.042.943 bytes |
| Payload | 724 arquivos, runtime próprio de serviço/UI |
| Assinatura da equipe | Ausente, candidato de desenvolvimento |
| Ambiente | Microsoft Windows Server 2025 Datacenter, build 26100, x64 |
| Modo instalado | FileSystemWatcher, sem driver e sem URL de API |

Esse EXE foi gerado e instalado no runner. O candidato 0.1.3 anterior foi apenas compilado/verificado localmente e não é o artefato homologado aqui. Não atribuir a aprovação a outro hash, versão ou commit.

O pacote baixado foi confrontado com o digest do artifact no GitHub e o hash do EXE com `build-result.json`. Digests dos ZIPs de evidência:

- Instalador: `13c6f0aa8108056e7499819bd73dd5002959d75c9edb44b0c3540b09945dc9ad`.
- Debug: `d843e9f02dccc7c7fd23c8a1a2e3ce36080043a107582ffe2a1eb42c65afc007`.
- Release: `0cd4654216b6d6b836323a4f3f75df8f1daf2a688521edcd7737707485f612d7`.

## Instalação real

| Controle no runner descartável | Resultado |
|---|---|
| Recusar URL HTTP remota antes de criar serviço | Aprovado |
| Recusar modo minifiltro sem driver registrado | Aprovado |
| Instalar serviço/UI com runtime próprio | Aprovado |
| Conferir LocalSystem, SID do serviço, aspas, argumentos e startup da UI | Aprovado |
| Inicializar política protegida e pasta monitorada | Aprovado |
| Classificar arquivo sintético com CPF e persistir evento pendente | Aprovado |
| Reiniciar serviço preservando ID, horário, pendência e política | Aprovado |
| Recusar instalação sobre a existente sem modificar serviço/política | Aprovado |
| Remover serviço e startup preservando política, fila e dados | Aprovado, incluindo checksum da fila |

Evento sintético observado: `1f17f061-a83b-44fb-ba05-992c05d8c8ad`, `occurredAtUtc=2026-10-22T02:16:36.3735612+00:00` (21/10/2026 às 23:16:36 em São Paulo), política 1, decisão `Blocked`, host `runnervm0xl3a`. O usuário registrado é a identidade observada pelo serviço (`runnervm0xl3a$`), não prova do usuário interativo que originou a operação.

FileSystemWatcher observa após a gravação. Esse resultado comprova classificação/auditoria no modo de teste, não bloqueio preventivo de bytes pelo kernel. O driver não foi instalado ou carregado. O teste de reinstalação comprova recusa de sobrescrita, não suporte a upgrade/repair.

## Testes de componentes e PowerShell

| Ensaio | Total | Aprovados | Falhos | Ignorados |
|---|---:|---:|---:|---:|
| C# Debug completo, sem filtro | 742 | 738 | 0 | 4 |
| C# Release completo, sem filtro | 742 | 738 | 0 | 4 |
| Contratos PowerShell 7 | 39 | 39 | 0 | 0 |
| Contratos Windows PowerShell 5.1 | 39 | 39 | 0 | 0 |
| Ambiente de módulos/ACL e leitor de auditoria | 4 | 4 | 0 | 0 |

O validador estático também aprovou hash, manifesto, runtime, inventário e versões do EXE antes da instalação. O smoke manteve as proteções originais: exige runner Windows hospedado e descartável, privilégios administrativos e ausência de estado SafeUpload anterior. Nenhuma dessas condições foi simulada no host local.

Os sete testes que falhavam localmente foram localizados nominalmente nos dois TRX do runner e todos constam como `Passed`. Não houve correção artificial de asserções, filtro da suíte completa ou adição de skips. Isso resolve a pendência de execução desses controles neste ambiente preparado; não altera o resultado histórico local nem comprova paridade com Windows 10/11.

Os quatro skips já existentes abrangem o teste da CA de máquina e três controles de desvio/políticas de navegadores. Permanecem fora da cobertura executada. Os testes C# rodam como usuário administrador do runner, enquanto o serviço do smoke roda como LocalSystem; não chamar a suíte inteira de uma execução SYSTEM.

Os TRX possuem total 742 e 738 passados. O atributo agregado `notExecuted` aparece como zero, mas há quatro resultados individuais `NotExecuted`, também relatados como `Skipped: 4` pelo executor. O resumo considera os resultados individuais para não omitir esses quatro casos.

## Publicação e atividades

- [PR #49 — Consolidar a base do agente Windows e homologar o instalador](https://github.com/pedro-canafistula/safeupload/pull/49), em rascunho.
- [#43 — Macro do agente Windows](https://github.com/pedro-canafistula/safeupload/issues/43).
- [#44 — Dependência da API de políticas](https://github.com/pedro-canafistula/safeupload/issues/44).
- [#45 — Homologação do instalador](https://github.com/pedro-canafistula/safeupload/issues/45).
- [#46 — Integração M2 apenas no agente](https://github.com/pedro-canafistula/safeupload/issues/46).
- [#47 — Auditoria ponta a ponta com a API](https://github.com/pedro-canafistula/safeupload/issues/47).
- [#48 — Operação prolongada e proteção da fila](https://github.com/pedro-canafistula/safeupload/issues/48).

A restrição de escrita anterior pertencia ao conector. A autenticação Git já configurada para o repositório foi verificada e permite publicação; ela foi usada sem imprimir ou persistir credenciais. O PR #42 continua aberto e em rascunho, sem alteração de sua branch. Não houve merge na main ou em qualquer outra branch.

## Pendências de aceite

- [x] Instalação inicial, inspeção sintética, reinício e remoção no Windows Server 2025 descartável, sem driver.
- [x] Suítes completas Debug/Release, com os sete controles anteriormente falhos aprovados no runner.
- [x] Publicar branch, PR em rascunho, atividades e resultados verificáveis.
- [ ] Windows 10/11, UI em sessão comum, autostart/clipboard e máquina sem runtime global instalado.
- [ ] Par agente/driver, semeadura/reinício do Windows e enforcement M2 com artefatos correspondentes e gates preservados.
- [ ] Consulta de políticas, identidade/autenticação e API real, persistência/deduplicação e painel; dependências da equipe, sem novas perguntas sobre existência do GET.
- [ ] Quatro controles opcionais de CA/desvio de navegador em ambiente próprio, se fizerem parte do escopo de liberação.
- [ ] Upgrade/repair/rollback, proteção/retenção da fila e assinatura Authenticode antes de distribuição de produção.
- [ ] Revisão e aprovação explícita antes de merge. Macro e issue #45 continuam abertas porque a homologação de cliente ainda falta.

O computador de trabalho não recebeu instalação, serviço ou driver. A VM `SafeUpload-Win10-Lab` permaneceu desligada e seus snapshots foram preservados. A validação de Windows 10/11 deve ocorrer em ambiente descartável próprio; não se deve tratar a execução Server 2025 como prova desses clientes.

O commit posterior deste relatório não modifica o produto ou o workflow, portanto não constitui novo EXE homologado. Usar sempre o commit e o hash acima para identificar o candidato aprovado nesta etapa.
