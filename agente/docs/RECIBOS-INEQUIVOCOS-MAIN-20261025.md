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

O CI e a revisão deste PR ainda precisam ser avaliados. Os resultados anteriores do #49 não concedem aceite automático a este recorte. A main já tem falhas de backend no Functional web; não ocultar falhas nem dispensar checks implicitamente. Sem alteração Java/Angular/banco/driver, instalação, VM ou homologação repetida. Não executar merge sem revisão e aprovação explícita do usuário.
