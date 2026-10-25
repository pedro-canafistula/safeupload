# Logs da comunicação do agente — 25/10/2026

O novo snapshot `communication-health` já restringia os dados expostos, mas os registros preexistentes de integração ainda incluíam a URL/identidade de inicialização do dispatcher e objetos de exceção completos. Uma exceção de transporte pode carregar URI, caminho ou outros dados na mensagem, exceção interna e propriedades. Não há evidência de credencial real exposta nesta investigação: a reprodução usa somente marcadores sintéticos.

## Correção

O dispatcher registra apenas o intervalo ao iniciar. Os avisos das quatro etapas (`DispatchCycle`, `Heartbeat`, `InitialPolicy`, `PolicyRefresh`) usam evento 3201/`CommunicationFailure`, etapa fechada, categoria fechada, HResult numérico e status HTTP quando disponível. Nenhum objeto de exceção é passado ao logger nesses caminhos. `IoError` não presume rede, pois o ciclo também acessa a fila local; `AccessDenied` mantém distinção de acesso negado. As demais categorias seguem as já usadas no diagnóstico de comunicação.

O cliente nomeado `CentroAdministracao` remove seus loggers HTTP automáticos na composição real do serviço. [RemoveAllLoggers, Microsoft](https://learn.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.httpclientbuilderextensions.removeallloggers) remove os loggers anteriores, inclusive os padrões, apenas daquele cliente. Os logs aplicativos sanitizados e o snapshot permanecem disponíveis. Outros clientes HTTP não recebem essa mudança. Não é uma mudança no conteúdo efetivamente transmitido ou no endereço utilizado.

Rotas, payloads, timeout, política de nova tentativa, cache, confirmação e formato da fila continuam iguais. O custo operacional é intencional: os avisos deixam de fornecer stack trace/mensagem bruta. Diagnóstico deve usar etapa/categoria/status e `communication-health`/`audit-health`/`audit-integrity`. Não é uma revisão geral de todos os logs do produto, EventSource, tracing externo, dumps ou registros do servidor. Os Trace warnings do armazenamento de política já registram apenas tipo de exceção; não recebem payload ou mensagem nesta alteração.

## Prova e reprodução

Três testes novos no código anterior falharam ao detectar URL/identidade ou exceção bruta nos registros. As falhas originais foram preservadas. Com a correção, o recorte Release tem **111 aprovados, zero falhas e zero ignorados**, incluindo **cinco casos novos**:

* Inicialização e falhas de heartbeat/envio não expõem marcador na mensagem, propriedades estruturadas ou exceção do logger. A fila em disco permanece idêntica e reabre com o evento pendente.
* Heartbeat com exceção é registrado com etapa/categoria/código e auditoria independente confirma o evento com recibo válido.
* Falhas inicial e periódica de política não substituem o snapshot nem expõem exceções. Sinais de conclusão coordenam o teste, sem depender de medir tempo de execução.
* Dois casos exercitam o cliente nomeado real via DI, com sucesso e exceção: nenhuma entrada automática mesmo em nível Trace, URI e timeout preservados, outro cliente continua produzindo logs. Transporte é simulado; não há acesso à rede real.

```powershell
dotnet build agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj -c Release
dotnet vstest agente/SafeUpload.Agent.Tests/bin/Release/net10.0-windows/SafeUpload.Agent.Tests.dll '--TestCaseFilter:FullyQualifiedName~CommunicationLoggingTests|FullyQualifiedName~CommunicationHealthTests|FullyQualifiedName~DurableHttpPolicyStoreTests|FullyQualifiedName~DispatcherReliabilityTests|FullyQualifiedName~AgentAuditDispatchTests|FullyQualifiedName~AgentHttpLoopbackTests|FullyQualifiedName~RefreshingPolicyStoreTests|FullyQualifiedName~DriverDiagnosticsTests' '--logger:trx;LogFileName=logs.trx'
```

Build local aprovado, com aviso NU1900 da consulta de vulnerabilidades indisponível.

Fonte `c3ba5a0aa5e928127c5285e773e8987f2686b187`. [CI do agente 40239657012](https://github.com/pedro-canafistula/safeupload/actions/runs/40239657012) aprovado nos três jobs: **959 aprovados, zero falhas e quatro ignorados em 963 por configuração Debug/Release**. Os cinco novos casos estão Passed nos dois TRX; os quatro skips são resultados individuais NotExecuted e aparecem nos logs, embora `Counters.notExecuted=0`. O ciclo automático de instalação, inspeção, reinício e remoção no Windows descartável passou; não foi repetido na VM preservada.

[Functional web 40239662246](https://github.com/pedro-canafistula/safeupload/actions/runs/40239662246) reprovado nos três jobs: migração sem EmpresaRepository, agent-contract sem backend iniciado e installed-service com backend encerrado antes de iniciar. Não afirmar PR inteiramente verde ou API real validada.

[Manifesto e arquivos preservados](evidencias/logs-comunicacao-20261025/resumo.json): TRX/logs brutos locais antes/depois e Debug/Release do CI. Os dois ZIPs C# foram conferidos por tamanho/digest e SHA de origem; não foi baixado/extraído/executado novo instalador no computador de trabalho. O aceite do smoke é o estado do job, não uma nova inspeção local do recibo instalado. Excertos web são texto decodificado pelo conector e normalizado ao salvar. A verificação de integridade pode ser reproduzida com `agente/docs/evidence-tools/Test-PreservedEvidence.ps1 -ManifestPath agente/docs/evidencias/logs-comunicacao-20261025/resumo.json`; matching não concede autenticidade nem qualificação adicional.

API real (#44/#47), par M2 (#46), distribuição Windows (#45) e lacunas físicas da fila (#48) conservam seus aceites próprios; não alterar autenticação, promoção/exclusão de temporários ou retenção sem alinhamento. Ensaio futuro de 12 h continua adiado; nenhuma carga/automação iniciada. Foco exclusivo no agente e integrações, sem Java/Angular/banco/driver alterados; PR #42 preservado, sem merge. Esta entrega complementa o diagnóstico no mesmo PR #49; o pacote Win10 0.1.14 anteriormente homologado mantém sua identidade e seu aceite próprios.
