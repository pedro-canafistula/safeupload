# Integrações do agente Windows na M2

Atualizado em 19/10/2026. Escopo desta entrega: código do agente e seus contratos de integração. Java/backend pertence ao Luiz; alterações de backend, Angular e driver não fazem parte destes commits.

## Base e fluxo Git

- Base: `feat/driver-m2`, commit `407eb5a9559fe7fee53edcd02005efeb1f65000a`.
- Branch de desenvolvimento: `feat/agent-m2-integration`.
- Destino proposto do PR: `feat/driver-m2`, para revisar somente as adaptações do agente sobre a M2. Não integrar a branch inteira diretamente na main sem a revisão conjunta da equipe.
- O desenvolvimento inicial ocorreu em checkout isolado com HEAD destacado. Estas alterações foram então organizadas em branch e commits próprios. A main e a branch remota da equipe não foram alteradas por esse desenvolvimento local.

## Comportamento implementado

1. Origem da política compartilhada entre startup, serviço e seed de boot. URL administrativa vazia seleciona política local; URL configurada seleciona provedores remotos. O instalador encaminha os mesmos argumentos ao serviço e ao seed, preservando bandeja/autostart e gates existentes.
2. Snapshot/cache persistido para consumidores legados; decisões staged e seed exigem leitura atual estrita, sem usar cache como autorização quando essa consulta falha. Limites explícitos são preservados; campos omitidos mantêm defaults diferentes entre legado e staged da M2.
3. Eventos e justificativas persistem localmente e são enviados pelo dispatcher. Falha de heartbeat não impede tentativa de envio; recibos incompatíveis não confirmam a fila. Preserva-se a identidade fornecida pelo serviço e a ordem auditoria antes de publicação/concessão.
4. Leitura limitada de auditoria recente da equipe preservada, com distinção entre eventos, justificativas e registros desconhecidos.
5. Diagnóstico local `PolicyIntegration`: snapshot disponível/origem, última leitura estrita e histórico do último aceite de escopo pelo caminho driver/BootPolicy. Falha de aplicação e encerramento invalidam o recibo atual, preservando histórico. Fingerprint distingue conteúdos sob mesma versão.

Aceite de escopo, heartbeat, pedido de justificativa e readiness são fatos distintos. O diagnóstico não concede autoridade nem comprova proteção ativa. Não há novo mecanismo de atualização dinâmica do driver nem novo contrato HTTP ou do driver. A extensão opcional da mensagem interna de status, descrita abaixo, pertence exclusivamente ao agente. Consulte o [README do agente](../README.md) para os campos de diagnóstico e uso das ferramentas.

## Divisão de responsabilidades e dependências

| Frente | Dependência ou pendência |
|---|---|
| Agente | Apresentação local do diagnóstico, identidade estável/autenticação acordada com backend, proteção da fila e operação instalada |
| Luiz / backend Java | Confirmar formatos monitorados e defaults da política central; distinguir versão publicada/recebida/aplicada em eventual evolução acordada do contrato; durabilidade no banco escolhido |
| Responsável Angular | Apresentar esses estados apenas quando houver contrato acordado, sem chamar heartbeat de aplicação no driver |
| Vitor/Pedro / driver e integração | Confirmar o par exato de artefatos e o fluxo de aplicação/atualização; preservar gates e boot policy da M2 |

O agente respeita a lista explícita de extensões recebida; não acrescenta silenciosamente extensões locais. A cópia Java usada como referência ainda tem cinco formatos no default, enquanto o agente M2 inclui PowerPoint e ZIP. Essa diferença deve ser resolvida com o backend, sem migrar políticas publicadas automaticamente. Monitorar `.7z` não anuncia inspeção disponível: a recusa `archive_7z_unavailable` permanece.

USB/removíveis, SMB/UNC e cloud-sync dependem dos próprios planos de suporte e qualificação. Não habilitá-los como parte desta integração. O contrato entre orçamento de inspeção e prazo do kernel continua sendo condição a conferir no par de homologação.

## Validação registrada

| Ensaio | Resultado e limite |
|---|---|
| Checkpoint anterior de integração feature | 374/374 Debug e 374/374 Release, sem falhas/ignorados; preserva os 362 casos anteriores |
| Novos diagnósticos sem flag de evidência | 12/12 Debug; recorte, não matriz completa normal/SYSTEM |
| Auditoria com Java real | 49 verificações: online, indisponibilidade, retomada, reenvio idempotente no cenário e reinício; dois eventos e duas justificativas |
| Publicação/leitura com Java real | 44 verificações nas revisões 1/2/3; categorias, cache, refresh e heartbeat; sem transferência real pelo driver |
| Angular real do ensaio anterior | Consulta dos dois eventos/justificativas e distinção entre CPF e política indisponível |

Os ensaios Java/Angular usaram cópias locais e fixtures, incluindo ajustes históricos de backend/UI que **não estão nesta branch**. Não comprovam compatibilidade com qualquer backend remoto. O H2 foi configurado com WRITE_DELAY=0; a durabilidade no banco de homologação continua pendente. Não há garantia geral de exactly-once.

Os hooks de diagnóstico no interceptor foram compilados e conferidos na fonte; os controles de aceite/desconexão são de componente, sem porta real. Serviço instalado, SYSTEM, identidade real no pipe, driver e VM não foram executados nesta entrega. Homologação prevista: Windows 10 22H2 build 19045.2965, com par exato aprovado e observação independente dos bytes.

Para feedback local, executar a suíte de testes de acordo com o ambiente Windows preparado:

```powershell
dotnet test agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj -c Debug -p:SafeUploadAdmissionEvidence=true --filter FullyQualifiedName~PolicyIntegrationDiagnosticsTests
dotnet test agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj -c Release -p:SafeUploadAdmissionEvidence=true --filter FullyQualifiedName~PolicyIntegrationDiagnosticsTests
```

Esses comandos reproduzem os 12 novos controles, não o recorte completo de 374. Não definir SAFEUPLOAD_MACHINE_TESTS=1 nem executar a matriz SYSTEM/VM sem preparar e validar o ambiente apropriado.

## Evidências e entrega

### Apresentação local do diagnóstico — incremento de 19/10

A tela de status da bandeja passa a mostrar Sincronização da política: versão disponível/origem, última consulta bem-sucedida e último aceite de escopo. O resumo `policyIntegration` é opcional na mensagem `status` do canal de notificação já existente, sem alterar seu nome, ACLs ou roteamento. Não contém fingerprints, mensagens de exceção, caminhos ou corpo da política. Um serviço publicador separado verifica mudanças a cada dois segundos; observações idênticas não repetem registros. A gravação durável continua precedendo a entrega; uma falha preserva o status anterior e permite nova tentativa.

O publicador não cria status de proteção antes do interceptador. Seus metadados não mudam ProtectionActive, AuditOnly, cobertura ou geração nativa. Status posteriores preservam o resumo corrente; reconexão recebe o último status registrado. Na interface, desconexão limpa as informações; serviços antigos sem o campo opcional exibem diagnóstico indisponível. A indicação de proteção continua usando os campos anteriores.

Validação deste incremento: 16 controles novos aprovados em Debug normal e no recorte Release feature de 68 controles. Incluem compatibilidade da forma antiga, projeção sem dados internos, preservação dos campos reais de proteção, falha de registro com retentativa, ciclo do publicador e pipe privado real com reconexão. O recorte Debug ampliado inicial executou 477 casos: 473 passaram, incluindo os 374 anteriores e os 15 novos iniciais; quatro testes existentes de NotificationRecordTests falharam ao criar links simbólicos por falta de privilégio do Windows. Não houve alteração dessas asserções, skips, concessão de privilégio ou repetição da mesma falha. A validação privilegiada permanece pendente; os recortes focados aprovados não substituem esse gate.

WPF Release compilado com zero avisos/erros. Renderização isolada do StatusView e seu StatusViewModel reais verificou os estados pendente, desconectado e serviço antigo com dados sintéticos, sem iniciar App.OnStartup, bandeja, clipboard, serviço ou driver. As imagens não são homologação do aplicativo instalado. Os recibos e primeiras tentativas estão no checkpoint bandeja-politica-agente-20261019.

Driver, biblioteca SafeUpload.Agent.Minifilter, backend e Angular continuam sem alterações. Mudança necessária no driver exige comunicação prévia ao Vitor; alteração em outra frente exige alinhamento prévio com o usuário e responsáveis.

Relatórios, TRX, recibos e patches originais permanecem preservados no workspace de desenvolvimento, fora do código versionado. Checkpoints: auditoria-m2-atual-20261018, java-m2-atual-20261018, angular-m2-atual-20261018, contratos-restantes-m2-20261018 e diagnostico-politica-agente-20261019. O registro de entrega Git relaciona commits e hashes aos checkpoints. Dados de ensaio, bancos, runtimes, node_modules e builds locais não devem entrar no PR.

Mudanças antigas em cópia Java/Angular permanecem separadas para referência; não foram incluídas nos commits do agente. Organização para commit normalizou somente linhas vazias finais em 11 arquivos, sem mudança funcional.

Antes de merge/cutover: revisão da equipe, CI, matriz exigida de entrega e homologação do par. Atualizações de progresso devem comentar subtarefas existentes do ClickUp e registrar dependências; não concluir homologação com base nos recortes locais.

### Atribuição do usuário na auditoria staged — 19/10

O identificador do endpoint continua sendo o nome da máquina, compartilhado por consulta de políticas, heartbeat, eventos e justificativas na composição atual. Não foi introduzido outro cadastro ou identificador persistente.

Os resultados staged usavam o usuário do processo do serviço, que pode ser SYSTEM. Agora StagedTransferAudit encaminha para o campo existente userName o RequestorSid já capturado do token do solicitante na alocação e persistido na transferência. A recuperação do registro de uma publicação confirmada usa a mesma identidade persistida. SID ausente, inválido ou acima do limite produz Não identificado; o usuário atual da sessão não é consultado. Um SID SYSTEM efetivamente registrado como solicitante é preservado. Chamadas antigas que não passam atribuição explícita mantêm o comportamento anterior.

Essa informação serve apenas à auditoria. Não muda autorização, veredito, grants, política, sessão de notificação, arquivo do journal ou contrato HTTP. Não resolve nomes de contas e não reescreve eventos antigos na fila ou no servidor. Durante atualização, conservar filas e journals; um conflito de replay de evento previamente aceito deve ser investigado, nunca corrigido apagando registros.

Recortes locais finais: Release feature 146/146, Debug normal 103/103 e Release normal 103/103, sem skips. Incluem seis novos casos de atribuição com reabertura da fila e envio HTTP simulado, além de assertivas nos caminhos reais de publicação, retenção, bloqueio e recuperação em componente. A primeira execução Debug feature passou 146/146; depois de acrescentar assertivas de recuperação e compatibilidade, o Windows bloqueou o carregamento do assembly de testes por Controle de Aplicativo (0x800711C7), inclusive na única repetição sem recompilar. O perfil final Debug feature permanece pendente; nenhuma proteção do Windows foi alterada. Esse bloqueio é distinto das quatro falhas históricas de privilégio para links simbólicos.

Evidências: checkpoint local auditoria-identidade-agente-20261019, com logs/TRX, fontes e hashes. Esses recortes sob o usuário local não substituem a matriz user/SYSTEM nem homologação com o driver. Driver, biblioteca de transporte, Java e Angular não receberam alterações. Comunicação futura: comentar a subtarefa existente de integração/auditoria no ClickUp e alinhar com Luiz apenas se o painel precisar exibir nome amigável em vez de SID; não criar tarefa ou anunciar homologação concluída. Nenhuma mensagem foi enviada automaticamente.
