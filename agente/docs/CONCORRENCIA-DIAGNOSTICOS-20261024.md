# Concorrência e prazo dos diagnósticos — 24/10/2026

Atividade #57, parte de #48/#43 no PR #49 em rascunho. Fonte dos testes `3ab7fd7426478e6b00b4385d4261a917a7b97a39`. Alterado somente `AuditQueueDiagnosticConcurrencyTests.cs`. Produção, prazo de cinco segundos, DACL, serviço, contratos, formato e retenção inalterados. Nenhum Java, Angular, banco ou driver modificado; sem merge.

## Cenários exercitados

**Concorrência na mesma instância:** 200 eventos sintéticos iniciais, produtor de mais cem, consumidor de 12 lotes de 15 e leitor de vinte integridades/vinte simulações. O produtor precisa publicar o primeiro evento e aguardar uma varredura real antes de completar sua carga. As tarefas compartilham o sink do mesmo modo que operações do serviço; não é concorrência entre processos. Cada inventário deve estar íntegro e ter pendentes + confirmados iguais aos válidos naquele instante. Consultas separadas não são comparadas como se fossem o mesmo snapshot.

Corte explícito 2030-01-01T00:00:00Z, posterior a todas as ocorrências sintéticas de 2026: cada simulação deve contar exatamente os confirmados de seu próprio inventário e manter `previewOnly=true` / `deletionSupported=false`. Após todas as tarefas, a fila é reaberta: **300 IDs exatos, 180 confirmados e 120 pendentes**, sem perda/duplicação. O conjunto pendente é confrontado com o esperado, não apenas seu tamanho. Consulta final preserva os bytes.

**Prazo real do pipe:** dois casos, `audit-integrity` e `audit-retention-preview`, usam `DiagnosticsPipeServer` real, nome de pipe exclusivo e fila temporária. O semáforo privado da fila é mantido ocupado pelo teste, via reflexão, sem gancho ou alteração em produção. Um pedido válido espera até o prazo do servidor e a conexão termina sem resposta de inventário; timeout do próprio teste não conta como sucesso. Não se exige um texto de erro após o prazo, pois o mesmo token já expirou para escrita da resposta.

Enquanto o bloqueio continua retido, bytes da fila devem ser iguais aos originais. Uma nova escrita é iniciada e confirmada como ainda incompleta; depois da liberação deve concluir. O mesmo servidor deve atender uma nova consulta do mesmo tipo, com dois pendentes e os dois IDs esperados após reabertura. Recursos e bloqueio são liberados em `finally`.

## Validação

Release local: **36 aprovados, zero falhas ou skips**, com três novos casos e regressões de integridade/simulação. Na execução final registrada, o cenário concorrente levou cerca de 0,34 s; os dois casos de prazo/retomada, aproximadamente 6,08 s e 6,03 s, incluindo conexão, expiração e retomada. São durações do teste nesta máquina, não garantias de latência do serviço.

Os cinco segundos limitam o trabalho do pedido, não garantem fechamento da conexão nesse instante. No fluxo atual, o cancelamento não relacionado à parada do serviço passa pelo tratamento de falha, que aguarda um segundo antes do descarte do pipe em `finally`; isso explica a duração próxima de seis segundos observada. Esse comportamento existente foi exercitado sem mudar o prazo ou o tratamento de falhas.

[CI 40114562559](https://github.com/pedro-canafistula/safeupload/actions/runs/40114562559) da fonte exata **aprovado nos três jobs**. Debug e Release: **838 aprovados, zero falhas e quatro skips em 842**, em cada configuração. Os três casos novos constam como Passed nos dois TRX originais, sem herdar o resultado de outra fonte. ZIPs dos artefatos C# conferidos por tamanho/digest publicados pelo GitHub; TRX extraídos preservados por SHA-256. Tempos dos casos de prazo/retomada ficaram próximos de seis segundos também no CI.

PS7/PS5.1 **42/42 cada**, ambiente **4/4**; controles existentes de interrupção, volume cheio e instalação real aprovados. Esses controles complementam os testes, sem transformar o ensaio de lock em teste de varredura longa ou durabilidade física.

[Functional web 40114566481](https://github.com/pedro-canafistula/safeupload/actions/runs/40114566481) ainda em andamento no recibo de estado recolhido. Sem aceite de API/backend, sem presumir sucesso ou repetir a falha de outra execução como resultado desta. Não declarar o PR inteiro aprovado. A atividade #57 limita-se aos testes do agente e está concluída; #43/#48 permanecem abertas.

## Limites e próximos aceites

O ensaio controlado prova espera cancelável pelo prazo real do pipe e retomada após liberar o lock; **não prova cancelamento no meio de uma varredura longa real**. Não mede atraso máximo de gravação, justiça/starvation do semáforo, carga por dias, fila grande com diagnósticos concorrentes, consulta por cliente remoto, API/recibo durável, energia ou durabilidade física. O caso concorrente não usa um servidor de confirmação: marcações são locais e deliberadas.

O controle privado por reflexão é restrito ao teste e deve falhar se o mecanismo de coordenação mudar, para exigir revisão do cenário. As tarefas têm prazo de segurança próprio; os números pequenos tornam o teste de integridade reproduzível sem transformá-lo em benchmark. As [medições anteriores](CUSTO-DIAGNOSTICOS-20261024.md) continuam separadas: 50 mil registros foram medidos em chamadas diretas sem prazo do pipe.

Manter #48 aberta. Nenhuma execução periódica de diagnóstico, alteração de prazo, exclusão, compactação ou regra de retenção foi habilitada. Nenhum novo instalador homologado no clone nesta atividade, pois não houve mudança de produção; o aceite próprio do pacote 0.1.14 segue documentado em seu relatório.

[TRX final, logs, identidade da fonte e hashes](evidencias/concorrencia-diagnosticos-20261024/resumo.json).
