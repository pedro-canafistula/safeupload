# Diagnóstico da comunicação do agente — 25/10/2026

O comando administrativo `communication-health` permite distinguir tentativas, resultados e falhas de política, heartbeat e auditoria sem provocar uma requisição à API. O agente mantém três posições em memória, sem histórico crescente; reiniciar o serviço reinicia contadores e `sinceUtc`.

## Consulta

Em PowerShell elevado, no diretório do agente instalado ou da árvore de desenvolvimento:

```powershell
.\scripts\Get-SafeUploadDiagnostics.ps1 -Query communication-health | ConvertTo-Json -Depth 10
```

A consulta usa o pipe administrativo existente. Sua leitura não acessa rede, driver ou arquivo de fila. Não introduz outro listener nem altera a DACL do pipe. No serviço, o acesso continua reservado a SYSTEM e Administrators; testes em processo usam o usuário do processo conforme a configuração preexistente.

## Interpretação

* `not_configured`: agente sem URL de administração; não significa conexão bem-sucedida.
* `not_attempted`: URL configurada, nenhuma tentativa daquela operação neste processo.
* `in_progress`: pelo menos uma tentativa ainda em andamento.
* `Success`, `Failure`, `Cancelled`: resultado da tentativa concluída de sequência mais recente. Cancelamento solicitado pelo chamador é separado de timeout.

Cada operação inclui contadores, tentativas em andamento, horários UTC e último status HTTP conhecido. `lastFailureKind` e seu horário preservam a falha mais recentemente concluída mesmo após recuperação; portanto podem coexistir com `Success`. Resultado, status HTTP, origem de política e persistência de cache pertencem à tentativa concluída de sequência mais recente. Uma conclusão antiga não substitui esses campos. Os horários de sucesso/falha/cancelamento são horários de conclusão.

Falhas usam categorias fechadas: `HttpRejected`, `TransportError`, `Timeout`, `InvalidResponse`, `UnexpectedError`. O novo snapshot não inclui URL, identificador de máquina, token, corpo HTTP, caminho, mensagem de exceção ou conteúdo de eventos. Isso não altera nem constitui revisão geral dos logs preexistentes.

Política registra `Remote`, `Memory`, `Disk` ou `Default`; `lastRemoteCachePersisted` só tem valor para carga remota válida concluída. Política remota válida com erro ao salvar cache continua sendo sucesso remoto, com persistência falsa. Consultas ao cache não contam como tentativa HTTP.

Heartbeat com HTTP 2xx é sucesso de comunicação. Auditoria só registra sucesso após recibo completo válido; recibo ambíguo/incompleto ou JSON inválido mantém pendentes. Uma falha posterior ao atualizar a fila local não converte recibo válido em falha de comunicação: os diagnósticos da fila continuam responsáveis por essa etapa. Fila vazia não cria tentativa fictícia.

`protectionQualified`, `apiPersistenceQualified` e `policyAppliedToDriverQualified` permanecem falsos. Este diagnóstico não comprova persistência real no servidor, aplicação no driver ou proteção ponta a ponta. Nenhuma rota, payload, autenticação, regra de aceitação de política ou recibo foi alterada.

## Aceite e reprodução

Os testes `CommunicationHealthTests` cobrem estados iniciais, leitura sem mutação, concorrência, conclusão fora de ordem, recuperação, falhas HTTP/timeout/transporte, cancelamento, cache, recibos inválidos, falha de confirmação local, observador defeituoso e consulta sem driver. Os contratos PowerShell verificam roteamento e preservação da exigência administrativa.

```powershell
dotnet build agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj -c Release
dotnet vstest agente/SafeUpload.Agent.Tests/bin/Release/net10.0-windows/SafeUpload.Agent.Tests.dll '--TestCaseFilter:FullyQualifiedName~CommunicationHealthTests|FullyQualifiedName~DurableHttpPolicyStoreTests|FullyQualifiedName~DispatcherReliabilityTests|FullyQualifiedName~AgentAuditDispatchTests|FullyQualifiedName~AgentHttpLoopbackTests|FullyQualifiedName~RefreshingPolicyStoreTests|FullyQualifiedName~DriverDiagnosticsTests' '--logger:trx;LogFileName=release.trx'
pwsh -NoProfile -File agente/installer/tests/Test-InstallerContracts.ps1
```

O smoke existente foi ampliado para consultar o serviço SYSTEM instalado no runner Windows descartável, verificar o estado sem API e o reinício. Não executar esse instalador no computador de trabalho ou na VM preservada para reproduzir os testes unitários.

Validação local final: **106 aprovados, zero falhas**, incluindo **23 casos novos**; contratos **45/45** em PowerShell 7 e Windows PowerShell 5.1. Uma primeira execução teve um oráculo excessivamente estreito (`IOException`): Windows retornou `UnauthorizedAccessException` ao arquivo bloqueado. O teste passou a aceitar ambas as exceções esperadas; os bytes continuaram preservados. A primeira tentativa de PS 5.1 não executou devido à política local; a execução validada usou Bypass somente no processo, sem mudar política persistente.

Evidências finais de CI e arquivos preservados serão vinculados após a execução automática do commit de implementação. Homologação Win10 0.1.14 e preparação M2 anteriores mantêm seu escopo original. O ensaio prolongado fica adiado para depois da integração e homologação, com duração futura de 12 horas; nenhuma execução foi iniciada.
