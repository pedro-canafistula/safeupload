# Diagnóstico da comunicação do agente — 25/10/2026

O comando administrativo `communication-health` permite distinguir tentativas, resultados e falhas de política, heartbeat e auditoria sem provocar uma requisição à API. O agente mantém três posições em memória, sem histórico crescente; reiniciar o serviço reinicia contadores e `sinceUtc`.

## Consulta

Em PowerShell elevado, na raiz `agente/` da árvore de desenvolvimento, com o serviço desta fonte em execução. O script é uma ferramenta da árvore de desenvolvimento; não pressupor sua inclusão no payload do instalador:

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

Build local Release aprovado, zero erros e um aviso NU1900 porque a consulta de vulnerabilidades ao NuGet estava indisponível.

Fonte de implementação: `51f15f9565f87d127ed602cb89b0c00a864ad3a7`. [CI do agente 40238780761](https://github.com/pedro-canafistula/safeupload/actions/runs/40238780761) aprovado nos três jobs. Debug e Release: **954 aprovados, zero falhas e quatro ignorados em 958** por configuração; os 23 casos novos estão Passed nos dois TRX. O campo `Counters.notExecuted=0` do TRX não conta esses quatro skips: eles aparecem nos resultados individuais e no log. Contratos do runner: 45/45 em PS7 e PS5.1, ambiente 4/4, M2 9/9 em cada versão.

O recibo do smoke instalado está `passed`. A consulta foi vinculada ao PID do SCM e ao SID SYSTEM S-1-5-18: **5696 antes / 2356 depois do reinício**. Sem URL de API, as três operações permaneceram `not_configured` com zero tentativas; `sinceUtc` mudou de `22:12:12.8497446Z` para `22:12:21.966497Z`. Isso comprova leitura e reinício no serviço instalado do runner Windows descartável, sem driver; falhas/sucessos HTTP configurados foram exercitados pelos testes sintéticos, não contra API real instalada. Os flags de qualificação permaneceram falsos.

[Functional web 40238784095](https://github.com/pedro-canafistula/safeupload/actions/runs/40238784095) reprovado nos três jobs: migração sem `EmpresaRepository`, agent-contract sem backend iniciado, installed-service com backend encerrado antes de iniciar. Não atribuir aceite ponta a ponta ou PR inteiramente verde.

[Evidências e manifesto](evidencias/communication-health-20261025/resumo.json): TRX/logs locais originais, inclusive a falha inicial do oráculo; TRX/logs Debug/Release e recibos JSON do runner preservados sem reserialização. Os três ZIPs de origem foram conferidos por tamanho/digest e associados ao SHA de implementação. Apenas os recibos selecionados foram extraídos; o instalador não foi executado nem extraído no computador de trabalho. Excertos dos jobs web são texto decodificado pelo conector e normalizado ao salvar, não cópias binárias dos logs. O manifesto é verificável por `agente/docs/evidence-tools/Test-PreservedEvidence.ps1`; não concede autenticidade nem qualificação adicional.

## Dependências e coleta presencial ainda pendente

* Par exato M2: pacote do driver compatível identificado por fonte/hash/arquitetura, assinatura e instruções da equipe; só então coletar as respostas reais e qualificar aplicação/enforcement (#46). A preparação de 24/10 não equivale à coleta contra driver real.
* API real: contrato consultável de política, identidade/autenticação e teste conjunto de persistência/deduplicação (#44/#47). O novo snapshot ajuda a investigar essa etapa, sem concluí-la.
* Windows 11 e cenários de distribuição/upgrade/repair/rollback/assinatura ainda exigem ambiente e pacote identificados (#45).
* Queda de energia e interrupção de escrita nativa sem instrumentação continuam distintas do append controlado aprovado. Retenção e promoção/exclusão de temporários exigem regras alinhadas antes de implementação (#48).
* Ensaio prolongado adiado para depois do desenvolvimento, integração e homologação, com duração futura de 12 horas. Nenhuma carga ou automação foi iniciada.

Homologação Win10 0.1.14 e preparação M2 anteriores mantêm seu escopo original. Não ligar a VM nem reinstalar para repetir esses aceites; o candidato reconstruído pelo CI não herda a homologação do pacote anterior. Sem alterações Java/Angular/banco/driver. PR #42 preservado, PR #49 em rascunho, sem merge.
