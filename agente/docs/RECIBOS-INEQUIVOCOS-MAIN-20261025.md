# Recibos inequívocos — recorte independente sobre a main

Base `efe93cf75aa668f2870c0951b48b3ef2c6332226`. Esta mudança extrai do PR #49 somente a validação do recibo HTTP de auditoria. Não incorpora o restante da consolidação, o instalador, M2, diagnósticos, projeção de payload ou mudanças de armazenamento. O PR #49 permanece preservado para revisão por partes; não deve ser integrado em bloco.

## Problema e comportamento

O leitor tipado da main aceita a última ocorrência de contagens repetidas e pode tratar uma contagem ausente como zero. Um lote apenas com justificativas pode ser confirmado indevidamente com `{"acceptedOverrides":1}`.

O agente passa a exigir objeto JSON com `acceptedEvents` e `acceptedOverrides`, ambas presentes uma única vez, numéricas inteiras e iguais às quantidades enviadas. Nomes são comparados após decodificar escapes, sem distinção de caixa. Campos adicionais continuam ignorados. Contagens ausentes, textuais, repetidas ou incompatíveis não confirmam o lote. HTTP/JSON inválidos continuam deixando os registros pendentes.

Fila, payload, rotas, identidade e política de reenvio não mudam. Depois de reabrir, recibo válido confirma os mesmos registros. A alteração não prova persistência ou deduplicação reais no backend.

## Validação deste recorte

Sobre a main, apenas com os testes novos: **oito falhas e 15 aprovados em 23**. São seis casos de repetição e dois de ausência/coerção de contagem; as falhas foram preservadas localmente. Com a correção: **41 testes relacionados aprovados, zero falhas e zero ignorados**, incluindo 23 de DispatcherReliabilityTests (16 casos adicionais sobre a main).

```powershell
dotnet build agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj -c Release
dotnet vstest agente/SafeUpload.Agent.Tests/bin/Release/net10.0-windows/SafeUpload.Agent.Tests.dll '--TestCaseFilter:FullyQualifiedName~DispatcherReliabilityTests|FullyQualifiedName~DurableHttpPolicyStoreTests|FullyQualifiedName~RefreshingPolicyStoreTests' '--logger:trx;LogFileName=recibos.trx'
```

Build local com zero avisos/erros. Restore local reutilizou pacotes disponíveis com NuGetAudit=false apenas no processo; não constitui consulta atual de vulnerabilidades. Nenhuma dependência ou configuração persistente foi alterada. Evidências locais antes/depois têm hashes em manifesto separado da árvore do produto; os artefatos do CI deste PR devem fornecer os resultados remotos próprios.

O [Functional web 40240535973](https://github.com/pedro-canafistula/safeupload/actions/runs/40240535973) terminou reprovado nos três jobs de integração. A etapa `Agent tests` passou: **735 aprovados, zero falhas e quatro ignorados em 739**, incluindo os 23 casos de DispatcherReliabilityTests Passed. Artefato 12616637877 (`agent-test-diagnostics`), 186.031 bytes, digest `sha256:f4db6adb303abc8d7379ebb72b74f2392868dd217ae48d680f6a72692b10b311`: ZIP conferido e TRX original preservado. O aceite é dos testes C#, não do workflow ou da API real.

O CI acima pertence à fonte `1881e31d535904f0019a5a4c2c12030c956b65f0`. A revisão posterior apenas remove um `using System.Text.Json` duplicado e atualiza documentação: sem mudança de corpo/método/contrato, sem repetir os testes aprovados; o commit documental/limpeza usa skip ci e não tem uma nova execução própria. A revisão não encontrou outro impedimento no recorte, mas não substitui revisão independente/aprovação.

Os resultados anteriores do #49 não concedem aceite automático a este recorte. A main já tem falhas de backend no Functional web; não ocultar falhas nem dispensar checks implicitamente. O merge aguarda revisão, aprovação explícita do usuário e decisão alinhada sobre o CI funcional reprovado. Sem alteração Java/Angular/banco/driver, instalação, VM ou homologação repetida. Não executar merge nesta tarefa de organização.

## Revisão e tratamento de CI

A revisão adicional conferiu o diff contra main, nomes escapados/comparação sem caixa, duplicatas, contagens ausentes/textuais, objeto principal, confirmação após HTTP válido e preservação de bytes/reenvio. Nenhum outro defeito bloqueante foi identificado nesse recorte. Isso é revisão técnica local, não aprovação independente ou autorização de merge.

O PR acrescenta `.github/workflows/agent-receipts.yml`, exclusivo do agente: check `Recibos e cache (Release)` em Windows, limitado aos três grupos de testes reproduzidos acima. Exige ao menos os 23 casos de recibo com resultado Passed, evitando um filtro vazio/skip silencioso, e preserva TRX/log inclusive em falha. Não instala serviço, usa API/Java/banco, driver ou VM preservada. São quatro arquivos no PR após esse acréscimo; produto e testes permanecem iguais.

O objetivo é fornecer resultado independente e explícito ao recorte; não substituir o Functional web, alterar regras de proteção ou dispensar falhas. A primeira execução deste check ainda precisa ser conferida antes de propor integração. A execução automática valida a própria configuração de CI nova; não foi feita nova rodada local ou repetida homologação aprovada.
