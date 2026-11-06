# Auditoria, interface e retomada — Agente 3

Base obrigatória: PR #92, `feat/agente-integracao-central-20261104`, `8ab8e6d8`.
Incremento em `feat/agente-auditoria-offline-20261104`, sem merge dos PRs #90–92.
Foram lidos [Integração central](INTEGRACAO-CENTRAL.md) e [Ensaio preventivo mínimo](ENSAIO-PREVENTIVO-MINIMO.md).

O Drive persistia o resultado de publicação, mas o serviço retornava imediatamente quando
`AuditJournaled=true`. A interface ficava sem conclusão/pendência e sem histórico ao vivo.
Agora o callback carrega o evento imutável do diário; o serviço o encaminha à sessão e SID do autor.
Não há segunda gravação nem novo horário/ID/hash. Bloqueios também levam o evento efetivamente gravado.
A WPF atualiza atividade/histórico pela mensagem de transferência e ignora repetição do mesmo evento.
Liberação com achados mostra alerta; classificação sozinha nunca mostra envio concluído.
Falha de publicação mostra pendência sem afirmar que o arquivo foi enviado nem presumir a causa.

## O que foi executado em 04/11/2026

- Aplicativo WPF e ContractSmoke Release compilados sem erros/avisos.
- Quatro regressões novas aprovadas: publicação limpa/Alertar, retenção seguida de liberação,
  histórico/protocolo e isolamento entre sessões/SIDs. São callbacks C# e arquivos reais.
- Suíte relacionada: 602 aprovados, quatro falhas por falta de privilégio Windows para links simbólicos
  e dois testes SYSTEM ignorados. As quatro falhas foram reproduzidas no binário inalterado do #92;
  não foram ocultadas nem convertidas em testes aprovados. CA2022 preexistente no teste de leitura da fila.
- Java sem alteração, JAR SHA256 `DCC472B082F84116EEFDC33DBC55EEAC2BDA8A41F9D45DA1149FFFC94E6A4167`,
  MySQL **8.4.13** exclusivo: **119 verificações aprovadas**. SQL independente confirmou dois hosts,
  cinco publicações do host 1 e 14 eventos distintos (oito do contrato existente + seis desta integração).
  Heartbeat atualizou o host correto sem recadastro; host de controle permaneceu intacto.
- Java realmente encerrado: outro processo restaurou identidade e revisão 5 do disco, inspecionou/publicou
  dois arquivos offline pelos callbacks e deixou seus eventos pendentes. Envio falho preservou fila e cache
  byte a byte. Java reiniciado e terceiro processo C# enviou os mesmos IDs; consulta administrativa e SQL
  conferiram horários, revisão, categorias, decisões e hashes. Replay após confirmação não duplicou eventos.

| Arquivo sintético | Revisão central | Resultado persistido |
| --- | --- | --- |
| online-clean.txt | 4, CPF/Bloquear | Approved, hash de publicação |
| online-cpf.txt | 4, CPF/Bloquear | Blocked, Cpf, destino sem arquivo |
| online-alert.txt | 5, CPF/Alertar | Approved, Cpf, hash e bytes conferidos |
| online-broken.docx | 5, CPF/Alertar | Blocked, erro de inspeção; conteúdo ZIP inválido identificado como `.zip` |
| offline-clean.txt / offline-alert.txt | 5 recuperada | Approved; segundo preserva Cpf; ambos reenviados após reconexão |

Não houve montagem WinFsp, conexão com gate, serviço instalado/SYSTEM, reinício do Windows,
entrega visual da janela/balão ou operação pelo Angular neste ensaio. O hub/protocolo e a apresentação
foram exercitados como componentes; a persistência central foi exercitada com Java/MySQL reais.
Nenhuma dessas evidências substitui o aceite preventivo nativo.

## Repetição com componentes reais

Em Windows, PowerShell 7, .NET 10, Java compatível e MySQL 8.4 disponível localmente:

```powershell
dotnet build agente/SafeUpload.Agent.ContractSmoke -c Release
dotnet build agente/SafeUpload.Agent.App -c Release
dotnet test agente/SafeUpload.Agent.Tests -c Release --filter FullyQualifiedName~DriveOutcomeNotificationTests
# Compilar o backend desta composição, sem modificar fontes/configuração:
mvn -f web/back/pom.xml -DskipTests package
./agente/scripts/Test-FunctionalAudit.ps1 -MySqlBasePath C:\tools\mysql-8.4 -OutputDirectory C:\Teste\agente3-novo
```

As portas locais 13326 e 18080 devem estar livres. O roteiro recusa diretório de saída existente,
cria banco descartável em loopback, encerra apenas os processos que criou e preserva `result.json` e logs.
`functionalWorkspace` aponta para a fila/cache/stage de componente preservados. Também aceita
`-DotNetPath` e `-BackendJarPath` para binários já compilados desta mesma composição.
O modo antigo `--current-api` permanece inalterado; o roteiro usa `--current-api-functional` e
`--functional-audit offline|resume <pasta>` em processos separados.

## Continuidade exata para o Agente 4 — meta 07/11/2026

1. Partir do HEAD deste PR incremental sobre #92, mantendo a sequência sem merge até o aceite.
   Repetir o comando acima em ambiente que permita links simbólicos; executar também os dois testes SYSTEM
   conforme seu provisionamento existente. Não modificar a segurança global do Windows para mascarar falhas.
2. Obter de Victor/equipe o gate v1 x64 Release assinado, commit, SHA256 e certificado público de teste.
   Na VM descartável, publicar serviço **e aplicativo WPF da mesma revisão**. Executar primeiro
   `Test-PreventiveCore.ps1` conforme o [roteiro do #91](ENSAIO-PREVENTIVO-MINIMO.md).
   Confirmar escrita direta recusada e contador real do gate, além de bytes retidos/publicados.
3. Com Java/MySQL e Angular desta composição, cadastrar uma vez um endpoint com hostname e IP exclusivos.
   Configurar `HeartbeatProtocol=AgentApi`, `RegisteredHostId`, `PolicyProtocol=ConsoleByIp`,
   `PolicyHostIp` e `Interception:Mode=Drive` conforme [#92](INTEGRACAO-CENTRAL.md).
   Não criar novo cadastro a cada reinício e não escolher arbitrariamente hosts com IP/hostname duplicado.
4. Pelo Angular, publicar CPF/Bloquear e depois CPF/Alertar. Em cada fase, anotar `idPolitica` e executar
   `Test-CentralPolicyDrive.ps1` com `-Action Bloquear|Alertar`, revisão real e caminho/hash do gate.
   Conferir na WPF aberta: um bloqueio por evento, histórico imediato, conclusão limpa, alerta na liberação
   sensível e ausência de sucesso em DOCX inválido. Não reiniciar o serviço entre publicações.
5. Encerrar apenas o Java de teste. Repetir a última fase com `-Offline`, reiniciar o serviço offline e repetir
   com outro nome/JSON. Preservar identidade, política, fila e stage. Reiniciar Java, aguardar envio e conferir
   os mesmos IDs/horários/revisões no MySQL e em `/auditoria`; comparar o host de controle e total de cadastros.
   Reabrir a WPF para conferir recuperação do histórico autorizado sem repetir alertas antigos.
6. Validar no painel `/auditoria`, `/endpoints` e `/painel` com sessão administrativa. Usar a correlação abaixo
   e demonstrar o conjunto até sábado, **07/11/2026**. Se o gate continuar ausente, demonstrar o ensaio de
   componentes e informar explicitamente a pendência nativa; não substituir o Drive por watcher.

| Correlação para painel/backend | Campo existente |
| --- | --- |
| Identidade imutável de um resultado, chave de reenvio | `eventId` |
| Máquina e cadastro | `endpointId` = hostname único; `hostId` do cadastro/heartbeat |
| Publicação central aplicada à decisão | `policyVersion` = `idPolitica` em ConsoleByIp; `versao="1.0"` é formato |
| Decisão e motivo | `verdict`, `categories`, `notInspectedReason`, `occurredAtUtc` |
| Conteúdo efetivamente publicado | `publishedSha256Hex` e bytes no destino |
| Aviso local e evento central | `TransferNotification.event.eventId`; `transferId` identifica a versão do Drive |

Uma versão bloqueada usa seu ID como evento inicial; publicação posterior tem outro `eventId` imutável.
Não usar `transferId` como chave de uma publicação posterior nem inferir sucesso pela classificação ou cache.
O inventário deriva a revisão do último evento; não comprova aplicação ao gate.
Java, Angular, driver, esquema de banco e autenticação não foram alterados. Autenticação individual do agente,
HTTPS de produção e tratamento de cadastros ambíguos continuam dependências a alinhar com backend/painel.
