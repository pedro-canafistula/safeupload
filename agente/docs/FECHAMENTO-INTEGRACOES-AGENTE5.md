# Fechamento funcional das integrações — Agente 5

05/11/2026, Brasília. Base confirmada no GitHub: PR #93 aberto/draft,
`3bb9f6f143b613950e14cca283d95ad73d59d16b`. Checkout próprio
`agente5-integracoes-20261105`, branch `fix/agente5-integracoes-20261105`.
Guia dos Agentes, Trilha, Arquitetura 3.1 e Requisitos 2.1 consultados.

## Defeito corrigido

`HttpAgentDispatcher.ExecuteAsync` executava heartbeat, auditoria e espera no mesmo
laço. Capturar a exceção do heartbeat permitia enviar o lote **depois** da falha,
mas não durante uma resposta lenta. Uma auditoria pendente também suspendia os
heartbeats seguintes. A independência de resultados não era independência de execução.

Dois testes novos falharam na base: heartbeat bloqueado impediu a confirmação do
primeiro lote; auditoria bloqueada impediu os heartbeats seguintes. A espera excedeu
o limite de 5 s dos testes, embora o intervalo configurado fosse 30 ms.

A correção mantém dois laços assíncronos no mesmo serviço hospedado, com intervalo
e cancelamento existentes. Cada operação permanece serial, sem retentativa
sobreposta. `RunCycleAsync`, usado pelos ensaios de componente, também inicia as
duas operações sem espera entre elas. Rotas, JSON, recibos e configuração não mudam.

Após a correção:

- Heartbeat permanece em espera enquanto dois lotes consecutivos são confirmados.
- Auditoria permanece em espera enquanto ao menos três heartbeats são executados;
  existe somente uma requisição do lote em andamento.
- A parada cancela as operações e conclui os dois laços. Sem recibo, os bytes da
  fila permanecem idênticos; reabertura preserva ID e instante. Novo despachante
  reenvia o mesmo payload e só então confirma o lote.

## Revisão dos demais contratos

| Área | Resultado da revisão |
| --- | --- |
| Identidade | `RegisteredHostIdentityStore` vincula servidor + `id_host`, persiste sem sobrescrever vínculo divergente e recupera o ID sem bootstrap. O serviço não repete `synchronize`. |
| Heartbeat | `HeartbeatProtocol=AgentApi` usa `POST /agent/heartbeat`, `{"id_host":n}`. Cliente nomeado inicializado quando há identidade. Legacy permanece opt-in compatível; não equivale ao contrato Java atual. |
| Política central | `PolicyProtocol=ConsoleByIp` usa `GET /agent/api/policy?ip=` e confere IP/ID do destino, revisão positiva, formato `1.0`, ação e regras suportadas. `idPolitica` é a revisão da publicação. |
| Categorias | CPF, CNPJ, cartão, credenciais, RG, dados bancários/saúde, documentos confidenciais e dados pessoais têm tradução explícita. Regra desconhecida rejeita o documento inteiro. |
| Atualização/cache | `RefreshingPolicyStore` publica snapshot validado em fundo; inspeções leem memória. Cache protegido por vínculo e última política válida sustentam recuperação offline. Não há HTTP por arquivo. Os escopos/limites/justificativa continuam locais. |
| Auditoria | Fila durável antes do envio; `POST /agent/events`; somente recibo integral com `acceptedEvents` e `acceptedOverrides` confirma o lote. Resposta inválida, timeout e erro mantêm pendência. |
| URLs/protocolos | Base HTTP(S) configurável terminada em `/agent/`; prazos positivos validados; protocolo escolhido explicitamente. Nenhuma detecção automática por tentativa de cadastro. |
| WPF/serviço | Conectividade administrativa distingue última tentativa/última confirmação da proteção local. Desconexão remove o indicador ativo; reconexão recebe status e histórico autorizado. Eventos de bloqueio/liberação preservam ID e autoria; histórico não recria alertas antigos. |
| Achados/falhas | Liberação com achados é destacada; falha de inspeção não autoriza publicação Drive. Resultado de publicação não confirmado é pendência, sem inferir sucesso. Fluxos existentes do #93 preservados. |

Não foi encontrado outro defeito novo que justificasse alteração neste recorte.
A WPF não foi redesenhada nem alterada. A lógica foi revisada e seus testes
existentes executados; entrega visual, reconexão autenticada ao serviço instalado
e gate real continuam no aceite nativo do Agente 1.

## Validação direcionada

Windows, .NET SDK 10.0.402/runtime 10.0.13, Release:

- **275 testes aprovados, zero falhas/ignorados**, incluindo os dois novos.
  Recorte: AdministrationScheduling, DispatcherReliability, AgentApiCommunication,
  AgentAuditDispatch, AuditReceiptBounds, AdministrationConfiguration,
  RegisteredHostIdentity, ConsolePolicy, RefreshingPolicyStore,
  CommunicationLogging/Health/Presentation, DriveOutcomeNotification,
  DriveProtectionStatus, AuditHistory e ServicePipePeer.
- WPF Release compilada com **zero erros/avisos**; serviço e dependências
  compilados pela execução dos testes. `git diff --check` aprovado.
- Na compilação inicial dos testes: CA2022 preexistente em
  `AuditQueueDiagnosticConcurrencyTests`; NU1900 por indisponibilidade da consulta
  de vulnerabilidades do NuGet. Pacotes disponíveis no cache; nenhum pacote alterado.
- O primeiro lançamento restrito do testhost não conectou ao runner e foi abortado;
  os resultados antes/depois e os 275 testes vieram da execução local autorizada.

Reprodução mínima da regressão corrigida:

```powershell
dotnet test agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj -c Release -m:1 --filter FullyQualifiedName~AdministrationSchedulingTests
dotnet build agente/SafeUpload.Agent.App/SafeUpload.Agent.App.csproj -c Release -m:1
```

Os ensaios novos usam clientes C# reais, transporte HTTP controlado e arquivos
locais reais; não usam Java/MySQL, WinFsp montado ou serviço instalado. A integração
Java/MySQL do #93 (119 verificações) continua evidência daquela revisão e não foi
repetida: esta correção altera agendamento, sem mudança de contrato HTTP.
Não representa qualificação de produção ou aceite ponta a ponta.

## Dependências externas e composição com o Agente 1

Na consulta inicial, #90/#91/#92/#93 estavam abertos/draft e sem merge. #90:
`88c5f751`; #92: `8ab8e6d8`; #93: `3bb9f6f1`. **#91 avançou para `f95f970c`**:
o Agente 1 já corrigiu a comparação `S:\` do Windows com `S:` do host WinFsp.
Esse commit registra início SYSTEM, conexão/escopo aceito pelo gate e montagem;
o ensaio preventivo precisa ser repetido com seu binário. Não duplicar sua correção.
Ela não está na base fixa #93 deste trabalho. O GitHub indicou #92 com conflito
contra o #91 atualizado; a integração da sequência deve preservar ambas as mudanças.

1. Usar a composição final identificada pelo Agente 1, preservando `f95f970c`
   (ou sua sucessora validada), #92 e #93. Incorporar apenas o commit desta branch
   para a independência heartbeat/auditoria; este incremento não altera DriveService.
   Revisar conflitos da sequência antes de construir; não há merge autorizado.
2. Compilar serviço e WPF da mesma revisão. Manter o gate/pacote/configuração do
   Agente 1. Executar seu `Test-PreventiveCore.ps1`, sem trocar por watcher.
3. Com cadastro/IP exclusivos e a configuração de [INTEGRACAO-CENTRAL.md](INTEGRACAO-CENTRAL.md),
   publicar pelo Angular CPF/Bloquear e CPF/Alertar e executar o roteiro
   `Test-CentralPolicyDrive.ps1`. Sem reinstalação entre publicações. Conferir na
   WPF bloqueio, liberação com achados e falha de DOCX; relacionar evento e revisão
   com Java/MySQL e painel, conforme [AUDITORIA-OFFLINE-AGENTE3.md](AUDITORIA-OFFLINE-AGENTE3.md).
4. Desconectar somente o backend de teste, reiniciar serviço e reabrir WPF:
   identidade/política preservadas, proteção coerente com gate/unidades e histórico
   autorizado recuperado. Reconectar e conferir os mesmos IDs/instantes na auditoria.
   Para publicação não confirmada, usar o cenário de recuperação já preparado pelo
   Agente 1; não provocar corrupção nem limpar stage/fila para forçar o resultado.
5. Em dependência HTTP lenta do ensaio, observar diagnósticos: auditoria em andamento
   não impede avanço do contador de heartbeat; heartbeat em andamento não impede
   envio de lote. Não iniciar um segundo despachante sobre a fila do serviço.

Thiago/backend: provisionamento repetível, credencial individual e ciclo de
renovação/revogação dependem de contrato; HTTPS publicado depende do ambiente.
Luiz/painel e Thiago: confirmar exibição dos mesmos IDs e cadastros/IP não ambíguos;
a revisão exibida no inventário vem do último evento, sem confirmar aplicação no gate.
Victor/Agente 1: aceite nativo do pacote e cenários preventivos/recuperação.

Nenhuma alteração em `driver/`, `web/back/`, `web/front/`, `db/`, instaladores ou
scripts compartilhados. Nenhum acesso à VM do Agente 1. Publicação desta branch/PR
draft aguarda autorização específica; implementação e validação locais concluídas.
