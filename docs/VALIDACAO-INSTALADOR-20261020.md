# Validação operacional do instalador Windows

Branch: `feat/agente-instalador`. Candidato corrigido: **0.1.2**. Esta rodada substitui o estado anterior de “compilado, instalação ainda não executada” registrado nos relatórios de 0.1.0/0.1.1.

## Ambiente e resultado

A instalação real foi executada no Windows Server 2025 x64 descartável do GitHub Actions, como administrador, com o serviço rodando em LocalSystem e **sem driver**. Não houve instalação no computador de trabalho, alteração da VM `SafeUpload-Win10-Lab`, carregamento de driver ou merge na main.

Execução final aprovada: [39517471073](https://github.com/pedro-canafistula/safeupload/actions/runs/39517471073), commit `d7416d9caccaf72cc2d9ee5da9a54a7be88dcfe2`. Todos os passos passaram, incluindo instalação, inspeção, reinício e remoção. Os logs, instalador e `installer-smoke/result.json` estão no artifact `safeupload-agent-installer` dessa execução. A primeira execução aprovada foi [39517083994](https://github.com/pedro-canafistula/safeupload/actions/runs/39517083994), commit `da7334121020fba9bd10aa36296329813be73e3f`; a revisão final repetiu o fluxo com os ajustes de leitura do horário.

SHA-256 do `.exe` final: `06B5222893993CE598495159F8BCEA094459AAE8F3DFF711046BA730C57B4A99`. O build registra `sourceDirty=false`, 724 arquivos no payload e assinatura de distribuição ausente.

| Cenário real no runner | Resultado final |
| --- | --- |
| Recusar URL HTTP remota e modo minifiltro sem driver | Aprovado antes da criação do serviço |
| Instalar silenciosamente serviço e UI com runtime incluído | Aprovado |
| Conferir LocalSystem, SID, aspas no executável, argumentos e startup | Aprovado |
| Criar política local protegida e iniciar escopo do watcher | Aprovado |
| Inspecionar arquivo sintético com CPF de teste | Aprovado, evento `Blocked` na fila |
| Registrar ID, horário, host, identidade do serviço e política | Aprovado |
| Reiniciar serviço e preservar evento pendente, ID, horário e política | Aprovado |
| Recusar instalação sobre a existente sem alterar serviço/política | Aprovado |
| Desinstalar e remover serviço/startup | Aprovado |
| Preservar política, fila de auditoria e dados de teste após remoção | Aprovado, inclusive checksum da fila |

Também passaram 39 contratos em PowerShell 7, 39 no Windows PowerShell 5.1 e 41 testes xUnit focados. O novo teste de ambiente passou localmente e no runner com quatro verificações: controle reproduzindo carregamento de módulo indevido, bootstrap real carregando `Get-Acl` nativo, leitura da fila com final truncado e preservação literal do horário. O smoke e esse teste de ambiente exigem PowerShell 7.5+; o helper do instalador continua usando Windows PowerShell 5.1.

O evento observado na primeira execução aprovada tem ID `932f6334-5df8-4f16-b7f6-adc477922a59`, horário `2026-10-20T23:48:40.0145854+00:00`, política 1 e canal File. O arquivo é exclusivamente sintético. O campo de usuário reflete a identidade observada pelo serviço no modo watcher, **não comprova identificação do usuário interativo que copiou o arquivo**. Processo e usuário reais da operação exigem validação do canal apropriado com o driver.

## Falha encontrada e correção

As duas primeiras execuções falharam na instalação, apesar de contratos e compilação aprovados:

- [39516632990](https://github.com/pedro-canafistula/safeupload/actions/runs/39516632990), commit `ace66900`.
- [39516851167](https://github.com/pedro-canafistula/safeupload/actions/runs/39516851167), commit `890b5892`.

O log de preflight informa que `Get-Acl` foi encontrado em `Microsoft.PowerShell.Security`, mas o módulo não pôde ser carregado. O instalador é chamado por PowerShell 7 no runner e executa seu helper em Windows PowerShell 5.1; o ambiente herdado de módulos não era isolado. Esse problema não havia aparecido na validação estática nem nos testes de funções isoladas.

A correção restringe `PSModulePath` do processo de setup a `$PSHOME\Modules` **antes** de importar o suporte de instalação. Isso seleciona os cmdlets nativos da versão executada e evita autoload de módulos do usuário em processo elevado. Não altera variável global da máquina. A verificação funcional usa um módulo sintético que se apresenta como `Microsoft.PowerShell.Security`: o controle falha ao selecioná-lo, enquanto o bootstrap real o ignora e carrega o módulo nativo. A instalação real passou após essa correção.

O leitor de auditoria do smoke também passou a usar `ConvertFrom-Json -DateKind String`. PowerShell recente converte datas automaticamente; preservar a string evita que uma conversão implícita dependa do idioma/fuso da máquina e prejudique a comparação do horário original.

## Limites e próximos passos

1. Esta evidência qualifica a instalação inicial, reinício e remoção **no modo FileSystemWatcher**, em Windows Server 2025. Não equivale a teste em Windows 10/11 nem bloqueio preventivo do kernel. O watcher observa após gravação e pode mover o arquivo para quarentena.
2. Os runtimes privados foram empacotados e conferidos; ainda falta uma VM de cliente sem SDK/runtime global para validar a instalação nesse perfil.
3. A UI foi empacotada e seu startup registrado, mas abertura da bandeja, notificações, clipboard e uso em sessão comum ainda exigem teste interativo com usuário sem privilégio.
4. Instalação com driver, semeadura, reinício do Windows e enforcement M2 dependem do pacote/roteiro do responsável pelo driver. A VM existente não foi alterada.
5. API Java, persistência MySQL e painel continuam para o teste conjunto com Thiago, usando o contrato de auditoria. O smoke desta rodada é local ao runner, com BaseUrl vazia.
6. O pacote continua sem assinatura de distribuição e recusa upgrade/repair. Autenticação de máquina, identidade persistente, proteção/retenção da fila e cenários de disco cheio permanecem no backlog.

O workflow agora executa os testes na própria branch publicada. Artefatos e logs ficam associados ao commit efetivamente compilado; usar o `build-result.json` e o checksum desse artifact para identificar o candidato, pois dois builds com a mesma versão podem ter hashes distintos. O merge na main continua dependendo de nova aprovação do usuário.
