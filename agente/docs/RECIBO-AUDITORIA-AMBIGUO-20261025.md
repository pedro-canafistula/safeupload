# Recibo de auditoria ambíguo — correção no agente

25/10/2026. Fonte `f5d7b7845603bad23afae8beaea56c1aa3a16778`, base
`9dafcef38f75a4d1b50e3f64930c718cf7457089`, PR #49. Frente #47, parte de #43.
Desenvolvimento exclusivo do agente: nenhuma edição de Java, Angular, banco ou driver.

## Problema reproduzido

O dispatcher convertia o recibo diretamente para um objeto com duas contagens.
Quando o JSON repetia uma delas, a última ocorrência substituía a anterior.
Por exemplo, um lote de um evento e uma justificativa podia ser confirmado com:

```json
{"acceptedEvents":0,"acceptedEvents":1,"acceptedOverrides":1}
```

Os seis novos casos falharam contra o código anterior: a fila foi regravada em
resposta ao recibo ambíguo, contrariando a condição de preservação. Isso é uma
reprodução sintética de defeito do leitor C#, não evidência de que a API real já
tenha enviado tal resposta. TRX e log anteriores preservados, sem apagar a falha.

## Comportamento implementado

O [HttpAgentDispatcher](../SafeUpload.Agent.Service/Dispatch/HttpAgentDispatcher.cs)
agora percorre as propriedades do objeto JSON principal. Confirma apenas quando
acceptedEvents e acceptedOverrides aparecem exatamente uma vez, são números JSON
inteiros de 32 bits e correspondem ao lote enviado, inclusive quando uma lista é vazia.
Contagem ausente, repetida ou incompatível mantém o lote pendente.

A comparação dos nomes continua sem distinguir caixa. Nomes escapados são comparados
depois de decodificados; acceptedEvents e accepted\u0045vents são a mesma propriedade
para detectar repetição. Repetição com o mesmo valor também é ambígua e recusada.
Campos futuros continuam ignorados; contagens dentro de metadados aninhados não
confirmam o lote. Valores representados como texto não são contagens numéricas JSON.
Parsing continua pelo leitor HTTP/JSON existente; não houve mudança de endpoint,
payload enviado, credencial, recibo por IDs ou requisito de implementação Java.

Nenhuma confirmação ocorre antes dessa validação completa. Em resposta ambígua,
os testes verificam bytes da fila inalterados; ao reabrir, evento e justificativa
seguem pendentes. Depois de recibo válido, são confirmados. O payload da nova
tentativa é idêntico ao anterior, preservando IDs, instantes e demais metadados.
Não é prova de persistência/deduplicação no servidor: #47 permanece aberta.

## Validação pertinente à alteração

Doze casos novos em [DispatcherReliabilityTests](../SafeUpload.Agent.Tests/DispatcherReliabilityTests.cs):
seis recibos ambíguos (evento, justificativa, caixa diferente, valor repetido e nome
escapado) e seis recibos válidos/compatíveis (nomes, ordem e campos futuros).
O teste de compatibilidade também conserva os dois registros na trilha local após confirmação.

Local Release: **38 aprovados, zero falhas/skips**, incluindo os doze novos e as
regressões afetadas de DispatcherReliabilityTests, AgentAuditDispatchTests e
AgentHttpLoopbackTests. Os 12 resultados Passed foram conferidos no TRX; antes da
correção, os seis casos de ambiguidade tiveram resultado Failed, como esperado
na reprodução. Build aprovado com um aviso NU1900 de consulta NuGet indisponível,
sem atualização de dependências. Não houve suíte completa local ou repetição de
homologações; o recorte foi reexecutado porque o código de produção mudou.

Reprodução do recorte atual, com SDK e dependências já disponíveis:

```powershell
dotnet build agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj -c Release --no-restore -m:1 -nr:false -p:UseSharedCompilation=false
dotnet vstest agente/SafeUpload.Agent.Tests/bin/Release/net10.0-windows/SafeUpload.Agent.Tests.dll '--TestCaseFilter:FullyQualifiedName~DispatcherReliabilityTests|FullyQualifiedName~AgentAuditDispatchTests|FullyQualifiedName~AgentHttpLoopbackTests' '--logger:trx;LogFileName=receipt.trx' --ResultsDirectory:artifacts/receipt
```

Para reproduzir a falha anterior em checkout descartável: usar o arquivo de testes
de f5d7b784 com o dispatcher da base 9dafcef3 e executar apenas o método
Recibo_ambiguo_preserva_bytes_e_reabertura_reenvia_o_mesmo_payload. Não substituir
arquivos na fila instalada ou no checkout de trabalho para essa reprodução histórica.

## Resultados automáticos da fonte corrigida

[CI do agente 40211375512](https://github.com/pedro-canafistula/safeupload/actions/runs/40211375512)
concluído com os três jobs aprovados. Suíte C# Debug e Release: **931 aprovados,
zero falhas e quatro ignorados em 935**, por configuração. Os doze casos novos
Passed foram verificados nos dois TRX originais. ZIPs C# baixados e conferidos
contra tamanho/digest do GitHub e SHA da fonte; logs/TRX copiados sem reserialização.
O contador notExecuted do resumo TRX é zero, mas os quatro UnitTestResult têm
outcome=NotExecuted e o log registra Skipped=4; a contagem acima usa esses registros.

O job de instalação em runner Windows descartável também passou, conforme seus
metadados. Não baixamos/executamos outro instalador no host ou na VM homologada,
nem transferimos o aceite do EXE 0.1.14 antigo ao rebuild dessa fonte. A validação
de recibos ocorre nos testes C# do dispatcher; o smoke não qualifica a API real.
Workflows normais rodaram por haver mudança real em produção; nenhum redisparo
manual ou edição de workflow foi necessário.

[Functional web 40211378229](https://github.com/pedro-canafistula/safeupload/actions/runs/40211378229)
segue reprovado nos três jobs: migration sem bean EmpresaRepository; agent-contract
aprovou os testes C# mas backend não iniciou; installed-service registrou backend
encerrado antes de iniciar. Excertos decodificados/normalizados e metadados preservados,
identificados como tal; não são cópias binárias dos ZIPs de logs. Backend não alterado.
Não declarar PR inteiro aprovado ou integração ponta a ponta.

[Manifesto, reprodução anterior, resultados e hashes](evidencias/recibo-ambiguo-20261025/resumo.json).

## Prioridade atual e dependências

Por orientação explícita do usuário, ensaio prolongado fica para depois de concluir
desenvolvimento, integração e homologação, considerando 12 h futuramente. O perfil de
72 h e seus recibos são históricos; não foram executados e não são prioridade atual.
README do coletor e relatório do perfil receberam essa orientação sem reescrever recibos.

#44 ainda aguarda API consultável compatível; #46 depende do par M2 identificado;
#47 requer API/persistência reais. A correção acima independe desses ambientes e
implementa somente a parte do agente. Não foram abertos listeners ou inventadas rotas.
Nenhuma VM iniciada, pacote reinstalado no host/VM homologada ou merge realizado.
PR #42 preservado; PR #49 continua em rascunho.
