# Recorte para alinhamento com Thiago — 30/10/2026

Branch: preparo/ponte-agent-api-20261026, PR #64. Lucas autorizou primeiro os ajustes de testes/CI e depois os reparos mínimos de backend/banco. A política do Pedro permanece separada. Nenhuma mensagem foi enviada em nome de Lucas.

## Arquivos de produção

- db/initdb/05_agent_audit_ingest.sql: restaura o DDL original de e9d7f144, removido da main embora AgentEventsStore continue dependendo da tabela. CREATE TABLE IF NOT EXISTS; não altera tabelas de acesso, hosts ou políticas. Volumes existentes não reaplicam initdb automaticamente: a migração precisa ser executada pelo responsável no banco apropriado antes de usar a ingestão/consulta. Nenhum banco existente foi migrado nesta sessão.
- web/back/src/main/java/com/safeupload/audit/AgentAdminController.java: GET /painel, /auditoria?endpoint=... e /endpoints?status=...&os=...&q=..., correspondentes às chamadas atuais do Angular depois do proxy /api.
- web/back/src/main/java/com/safeupload/audit/AgentAdminQueries.java: consultas somente leitura sobre agent_audit_ingest e hosts, com snapshot SQL, estatísticas de sete dias, limites de resposta e filtros parametrizados. Retorna eventos, justificativas e metadados persistidos, sem recriar arquivos/snippets descartados pela ingestão. Erro SQL continua sendo erro, nunca lista vazia de sucesso.
- web/back/src/main/java/com/safeupload/presentation/config/SecurityConfig.java: exige sessão com ROLE_ADMIN ou ROLE_ROOT para as três novas consultas. Mantém as regras existentes das outras rotas. O arquivo teve normalização de quebras de linha/espaços; a alteração lógica é essa autorização.

Não alterados os controllers/serviços de cadastro, heartbeat e publicação de políticas, seus DTOs ou tabelas de identidade. O Angular de produção e o driver também não mudam neste recorte.

## Semântica das consultas

O inventário usa hosts cadastrados e o timestamp/flag ativo do heartbeat: online significa até 120 segundos, com tolerância de cinco segundos para horário futuro. Não equivale a dispositivo autenticado. Versão de agente/política, quando disponível, vem do último evento; não confirma política efetiva no driver. Sem evento, a versão da política é nula.

A associação entre endpointId da auditoria e hostname só é feita para nome único. Nomes duplicados recebem chave host:id e identityAmbiguous=true; não se atribuem eventos de uma máquina arbitrariamente a outra. Isso não substitui o contrato futuro de identidade/autenticação.

As listas retornam no máximo mil registros e informam limit/truncated. Os filtros do inventário são aplicados antes do limite; o resumo mantém os totais globais. Estatísticas completas da janela são calculadas por páginas de 500 metadados, sem carregar todos os eventos de uma vez. Não há exclusão, retenção automática ou reconhecimento de fila nessas consultas. A UI ainda não oferece paginação dessas listas.

O painel apresenta sete dias de calendário UTC, seis eventos recentes e as categorias observadas nos bloqueios. Não infere a política vigente a partir de eventos: categoriasAtivas permanece vazia e politicaEfetivaConfirmada=false até existir esse contrato. Esse limite evita apresentar uma publicação ou detecção antiga como aplicação atual.

## Testes e CI

AgentEventsIntakeTest passa a fornecer os dois colaboradores exigidos pelo controller (EmpresaRepository e AdminService), preservando persistência/recibos reais e os sete testes. O teste de rotas agora usa /agent/synchronize e /agent/heartbeat, conforme o controller atual; não foram adicionados aliases falsos de /agent/api/heartbeat.

AgentAdminQueriesTest acrescenta oito controles de sessão/perfil, indicadores vazios, vereditos/canais/deduplicação, filtros/justificativas, nomes ambíguos, falha SQL, paginação estatística e filtro antes do limite. Resultado local: 15 testes Java aprovados, sem falhas ou skips.

ContractSmoke --current-api exercita a API atual com o cliente/dispatcher/fila C# reais, sessão, dois cadastros explícitos, heartbeat por id_host, seis eventos em três canais, justificativa e reenvio, consultas SQL e publicação de duas políticas por IP. Em MySQL/Java descartáveis locais: 32 verificações aprovadas; conferência SQL independente 2 hosts / 6 eventos / 1 justificativa / 2 políticas. JVM/MySQL encerrados e portas fechadas. Essa prova usou a árvore de desenvolvimento antes do commit, com hashes dos binários no recibo local.

O ensaio usa política local controlada para o componente de clipboard. Declara expressamente ConsolePolicyAppliedByAgent=Pending e RemotePolicyCacheQualification=Pending. Os roteiros legados são preservados, mas o CI atual não pode afirmar consumo/cache central de um formato que o backend não oferece. A candidata local fac86227 e a entrega do Pedro precisam ser reconciliadas antes desse aceite.

Functional web passa a iniciar os dois schemas MySQL efetivos, usa /auth/decision para prontidão e mantém os testes de navegador. Os testes do navegador foram adaptados aos campos obrigatórios atuais de cadastro e às rotas/payloads reais, preservando os controles de persistência, deduplicação, segurança de apresentação e destino da política. Os dois jobs Windows usam o mesmo ambiente descartável: um executa o contrato atual e a suíte do agente; o outro preserva o aceite SCM/LocalSystem de identidade e reinício offline. Nenhum job usa um 404 como prontidão ou desativa verificações para obter aprovação.

O resultado final deve ser conferido nos checks do HEAD do PR. A aprovação local não substitui o navegador/Windows no runner, o merge ou a homologação do novo par com driver.
