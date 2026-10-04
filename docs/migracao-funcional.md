# Migração funcional Java/Angular

## Escopo

Recupera a integração web removida com `app/`, preservando os contratos HTTP do agente e os comportamentos da Auditoria, Endpoints e Dashboard. As regras foram recuperadas do histórico Git anterior à remoção e dos testes Python. Cadastro e sessão existentes foram mantidos; `/auth/me` passou a devolver o mesmo DTO de usuário do login.

## Contratos do agente

| Método e rota | Dados e comportamento |
|---|---|
| POST `/agent/heartbeat` | `endpointId`, `hostname`, `os`, `agentVersion`, `policyVersion`; upsert da máquina e horário do servidor. Retorna `endpointId`, `serverTimeUtc`, `policyVersion` |
| GET `/agent/policy` | Política global v1; aceita o parâmetro `endpointId` sem individualizar a política |
| POST `/agent/events` | Envelope com listas `events` e `overrides`, opcionais/vazias; até 100 elementos em cada lista |

Eventos preservam os nomes camelCase do record C# `AuditEvent`. Datas exigem offset e são normalizadas para UTC. Categorias: `Cpf`, `Cnpj`, `PaymentCard`, `Password`, `Secret`. Vereditos: `Approved`, `Blocked`, `AllowedWithoutInspection`. Dados inválidos recebem 422; dados conflitantes recebem 409.

Todo o lote é validado antes da gravação e persistido numa transação. Só há 2xx depois do commit, pois o C# marca todos os eventos do lote como entregues ao receber sucesso HTTP. `acceptedEvents`/`acceptedOverrides` indicam quantos itens podem ser considerados confirmados, incluindo reenvios já persistidos. Não são a quantidade de novas linhas.

O identificador persistido combina tipo (audit/override) e UUID. Isso permite registrar uma justificativa relacionada ao UUID de um evento sem conflito entre os tipos. Reenvio com o mesmo conteúdo é idempotente, inclusive dentro do mesmo lote. Alterar conteúdo para o mesmo identificador retorna 409 e desfaz o lote inteiro. O campo `dispatched` é ignorado na comparação e persistência, pois é estado de transporte do agente. Em concorrência, a chave primária impede duplicação; um conflito de inserção retorna 409 e o agente pode reenviar. Não há confirmação parcial.

## Persistência

JPA/H2 armazena máquinas em `agent_endpoints` e eventos/overrides em `agent_events`. O payload validado é serializado em JSON, preservando todos os campos do contrato; tipo e instante têm colunas próprias para ordenação. Não há migração do antigo armazenamento em memória: seus registros não sobreviviam a reinício. Não são utilizados o schema MySQL antigo nem arquivos de banco fornecidos no ZIP.

As consultas de eventos retornam todos os registros e agregam na aplicação, adequado ao recorte atual do protótipo. Para escala, migrar para consultas agregadas/paginadas e definir retenção. A política padrão continua em código, assim como no backend anterior; seu versionamento persistido é outro recorte.

## Consultas administrativas

Todas exigem sessão HTTP de usuário existente e não bloqueado. O papel de usuário é devolvido no DTO, mas esta entrega não define autorização administrativa granular.

- `GET /api/painel`: `periodo`, `resumo`, `tendencia`, `categoriasBloqueadas`, `recentes`, `categoriasAtivas`.
- `GET /api/auditoria?endpoint=...`: `resumo`, `eventos`, `endpoint`. Totais calculados da mesma lista filtrada; comparação exata por identificador.
- `GET /api/endpoints?status=online&os=win11&q=financeiro`: `resumo` global, `itens` filtrados e `onlineThresholdSeconds`. Sistemas aceitos: `win11`, `win10`, `other`; filtros desconhecidos funcionam como `all`.

O resumo de inspeções contém `total`, `bloqueados`, `aprovados`, `liberadosSemInspecao`. Datas e números permanecem tipados no JSON; o Angular formata para exibição.

### Regras temporais

- Painel: hoje e seis dias anteriores em UTC, a partir de 00:00 do primeiro dia até o instante atual. Eventos futuros não entram nos indicadores nem no ranking.
- Últimos seis eventos: os seis recebidos mais recentes por instante do evento, independentemente da janela, preservando o comportamento anterior. Datas futuras permanecem visíveis na auditoria para diagnóstico do relógio do agente.
- Endpoint: online quando o último heartbeat tem no máximo 90 segundos; offline a partir de mais de 90 segundos.
- Inspeções por endpoint: janela móvel de sete dias até agora. O limite superior exclui datas futuras, corrigindo a contagem indevida permitida no legado.
- Ranking: somente eventos bloqueados; uma categoria é contada uma vez por evento mesmo que o payload repita o código.

## Telas

Modelos TypeScript substituem `any`; estados de carregamento, erro e vazio são distintos. O botão Atualizar busca novos dados. Os filtros de Endpoints e o filtro de Auditoria ficam na URL. As assinaturas de consulta usam `switchMap` e `AsyncPipe`, descartando respostas antigas quando o filtro muda e cancelando a assinatura ao sair da tela.

O painel remove os totais fixos. A Auditoria troca o rótulo incorreto “Rejeitados” por “Liberados sem inspeção” e mostra seu motivo. Endpoints remove IP e contagem de desatualizados sem fonte real. Relatórios informa indisponibilidade, sem chamar uma API inexistente ou mostrar registros inventados.

## Validação e operação

`FunctionalMigrationTest` verifica os contratos, sessão, CORS, três vereditos, filtros, limite de 90 segundos, sete dias, ordenação por offset, duplicatas, rollback e erros de validação. `PersistenceRestartTest` fecha e reabre a aplicação usando um banco temporário em arquivo e confirma os registros. `web/front/e2e/migration.spec.ts` exercita cadastro, login, reload, ingestão HTTP, telas, filtros, erro de API, logout, escape de HTML e largura móvel em navegador real.

Os testes de navegador requerem backend exclusivo com banco vazio; não têm rotina destrutiva de limpeza de banco. Consulte o README para os comandos. Ainda é necessário validar o serviço C# e o driver instalado em uma máquina Windows de teste; a suíte web simula o mesmo contrato HTTP, mas não instala ou carrega o driver.

O projeto `SafeUpload.Agent.ContractSmoke` permite uma verificação adicional com o produtor C# real: fila local temporária, carregamento de política, execução do despachante, confirmação dos pendentes e leitura autenticada dos totais Java. Ele exige uma instância Spring exclusiva e vazia na porta 18080; não instala serviço/driver. Esse teste foi compilado e executado com sucesso nesta máquina. Separadamente, a execução da suíte xUnit existente foi bloqueada pelo Controle de Aplicativos do Windows (`0x800711C7` ao carregar `SafeUpload.Agent.Tests.dll`). Esse bloqueio não é uma falha de asserção nem comprovação de aprovação da suíte xUnit; nenhuma proteção do sistema foi alterada. O CI inclui a suíte e o smoke test em um runner Windows.

Para publicação, servir o Angular e `/api` na mesma origem via proxy reverso, configurar HTTPS e cookies adequados, autenticação de dispositivos, autorização, migrations e estratégia de retenção. Esses itens não são substituídos pelo proxy de desenvolvimento.
