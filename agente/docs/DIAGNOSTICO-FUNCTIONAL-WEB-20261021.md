# Falha do Functional web no PR #49 — 21/10/2026

## Decisão

Podemos continuar o desenvolvimento e a homologação independente do agente. **A falha não está corrigida e a integração ponta a ponta continua pendente com check reprovado; não tratar o PR inteiro como verde nem aprovar merge por causa da homologação isolada.** Nenhuma alteração de Java, Angular, banco ou do workflow funcional foi feita para ocultar ou corrigir esse problema fora do escopo.

Execução da imagem: [Functional web #77, run 39710435094](https://github.com/pedro-canafistula/safeupload/actions/runs/39710435094), associada ao PR #49 e fonte `24f39c2818bb48a908ef4dfa26789519db9e1bc0`.

Referência independente: [Functional web da main, run 39544965948](https://github.com/pedro-canafistula/safeupload/actions/runs/39544965948), fonte `efe93cf75aa668f2870c0951b48b3ef2c6332226`. Os mesmos três jobs já falharam nas mesmas etapas nessa execução da main.

## Logs verificados

| Job | Evidência e limite |
|---|---|
| migration | Os sete testes Java de AgentEventsIntakeTest falham ao carregar o contexto Spring. O controller exige EmpresaRepository, mas o contexto de teste não fornece esse bean. A mesma assinatura aparece no log da main. Frontend/build/testes de navegador não chegaram a executar. |
| agent-contract | A etapa Agent tests passa: 738 aprovados, zero falhas e quatro skips. O backend compila, mas a espera por `/agent/policy` falha e o script lança “Backend não iniciou.” O smoke C#→Java não chegou a executar. Esse job não preserva a causa específica do processo Java; não atribuir seu erro exclusivamente a uma rota 404 ou ao banco sem log correspondente. A mesma etapa já falha na main. |
| installed-service | O serviço C# é publicado, mas o backend encerra antes de iniciar. O artifact contém conexão MySQL recusada e falha de acessoEntityManagerFactory ao obter metadados JDBC. result.json tem status failed e steps vazio. O script tenta iniciar o backend antes de New-Service; portanto, esse job não chegou a instalar o agente. A mesma mensagem terminal aparece na execução da main. |

No cenário installed-service, o runner passa `spring.datasource.url=jdbc:h2:...`, mas a configuração atual do backend usa propriedades próprias `acesso.datasource` e `app.datasource`, com URLs MySQL locais. A substituição genérica não isola essas conexões. Essa constatação é uma dependência de preparação do backend/ensaio, não autorização para editar Java, banco ou o workflow da equipe nesta tarefa.

Foi conferido que `web/back`, o restante de `web/` e `.github/workflows/functional-web.yml` são idênticos entre main `efe93cf7` e o candidato do agente. Comparações Git para esses caminhos retornaram diff vazio. Assim, não há mudança nesses componentes introduzida pelo PR do agente para explicar as falhas observadas.

## O que continua válido

A [homologação do agente, run 39710172814](https://github.com/pedro-canafistula/safeupload/actions/runs/39710172814), é um workflow diferente e foi aprovada. Ele instalou o candidato 0.1.4 em Windows Server 2025 descartável, sem driver e sem backend, classificou arquivo sintético, reiniciou e removeu preservando auditoria/política. Também executou os 742 testes C# em cada configuração: 738 aprovados, zero falhas e quatro skips existentes.

Esse resultado não substitui os três jobs falhos nem comprova comunicação com Java, MySQL, painel ou driver. A síntese anterior da homologação descrevia esse ensaio isolado; o status geral do PR precisa manter a ressalva explícita deste workflow vermelho.

## Encaminhamento

- Registrar a dependência no PR #49 e na atividade #47, sem enviar pergunta repetida sobre existência da API.
- Preservar logs e primeiras falhas; não reexecutar repetidamente sem uma mudança ou hipótese nova.
- Não alterar filtros, asserções, critérios ou gates para tornar o check verde.
- Seguir em atividades independentes do agente, com próxima frente de homologação em Windows 10/11 e UI em sessão comum.
- Retomar a integração real após a equipe disponibilizar backend e ambiente compatíveis. O merge continua dependente de revisão e aprovação explícita, com esses checks considerados.

A homologação de cliente ainda requer ambiente descartável e acesso à conta do convidado. Os scripts existentes para a VM local solicitam a senha localmente com Read-Host -AsSecureString; nenhuma credencial foi solicitada em texto, lida de arquivos alheios, salva ou exposta. A VM original permanece preservada.
