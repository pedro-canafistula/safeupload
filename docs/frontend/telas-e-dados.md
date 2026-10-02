# Telas e dados do frontend

Inventário atualizado em 01/10/2026, incluindo Painel baseado em eventos reais, Auditoria somente para leitura e Endpoints baseado em heartbeats reais. Descreve o comportamento desta versão; não representa funcionalidades planejadas como concluídas.

## Resumo das oito telas

“Demonstrativa” significa que os dados são fixos ou que a ação não possui execução de negócio. “Integração parcial” significa que a tela também apresenta dados recebidos pela API do agente, mantidos apenas na memória do processo.

| Tela | Fonte atual | Funciona hoje | Lacuna principal |
|---|---|---|---|
| Login | Sem contexto de negócio | Renderização e redirecionamento do POST | Autenticação, sessão e autorização ausentes |
| Painel | Eventos recebidos + política vigente | KPIs, tendência de 7 dias, categorias bloqueadas, eventos recentes e categorias ativas | Sem persistência, seleção de período ou atualização automática |
| Auditoria | Somente eventos recebidos, consultados pelo serviço | Lista, totais, estado vazio e filtro por `endpointId` | Sem persistência, filtros adicionais, detalhes, exportação ou paginação |
| Endpoints | Somente heartbeats recebidos, consultados pelo serviço | Inventário, online/offline, filtros e acesso à auditoria por endpoint | Sem persistência ou ações administrativas remotas |
| Relatórios | Catálogo fixo | Links para Auditoria e Painel | Nenhum relatório gerado |
| Categorias | Quatro categorias fixas | Alternância local dos checkboxes | Sem gravação ou ligação com a política do agente |
| Exceções | Sete exemplos fixos | Renderização e navegação de Limpar | Sem cadastro, remoção, filtro ou HMAC implementado |
| Usuários | Seis contas fixas | Renderização e navegação de Limpar | Sem cadastro, edição ou controle de acesso |

Rotas e templates: [admin.py](../../app/presentation/routes/admin.py) e [templates administrativos](../../app/presentation/templates/admin). Contextos integrados: [dashboard.py](../../app/presentation/dashboard.py), [audit.py](../../app/presentation/audit.py) e [endpoints.py](../../app/presentation/endpoints.py); telas demonstrativas: [admin_data.py](../../app/presentation/demo/admin_data.py). Consultas passam por [agent_service.py](../../app/application/agent_service.py), usando [memory_store.py](../../app/infrastructure/memory_store.py).

## Entradas e navegação

| Entrada | Comportamento atual |
|---|---|
| `GET /` | Redireciona para `/admin/login` |
| `GET /admin` | Redireciona para `/admin/dashboard` |
| `GET /admin/login` | Renderiza o login |
| `POST /admin/login` | Redireciona com HTTP 303 para `/admin/dashboard`, independentemente das credenciais |
| Sidebar | Links diretos para Painel, Auditoria, Endpoints, Relatórios, Categorias, Exceções e Usuários |
| Sair | Link para `/admin/login`; não invalida sessão, pois sessão não existe |

As rotas internas não têm controle de acesso. O destaque da sidebar depende do valor `active_page`, enviado por cada rota; não é um estado mantido no navegador. O nome de administrador, e-mail e indicação de servidor operacional no topo são textos fixos.

## Catálogo das oito páginas

### 1. Login

- **Rota e arquivo:** `/admin/login` → `admin/login.html`.
- **Estrutura:** marca, formulário de e-mail/senha, botão Entrar e rodapé.
- **Dados:** não há contexto de negócio específico; o formulário envia `email` e `senha` por POST.
- **Comportamento:** o envio navega para o painel. O handler não lê nem valida credenciais. O formulário possui `novalidate`, apesar dos atributos `required` dos inputs.
- **Limitação:** não existem mensagens de credencial inválida, sessão ou recuperação de acesso.

### 2. Painel

- **Rota e arquivo:** `/admin/dashboard` → `admin/dashboard.html`; `active_page=dashboard`.
- **Contexto:** `kpis`, `trend`, `categories_top`, `categories_status`, `recent_events`.
- **Fonte:** a rota consulta `agent_service.list_audit_events()`, `agent_service.get_current_policy()` e `agent_service.get_server_time_utc()`. O builder em `presentation/dashboard.py` recebe esses dados e não acessa `memory_store` diretamente.
- **Período:** os KPIs, a tendência diária e o ranking de categorias consideram os últimos sete dias, incluindo o dia corrente e ignorando eventos futuros. Não há seletor de período nesta versão.
- **KPIs:** total, bloqueados, aprovados e liberados sem inspeção são calculados a partir dos eventos do período. Os três resultados exibem também sua participação percentual no total.
- **Tendência:** sete barras representam a quantidade de inspeções por dia. A maior contagem do período recebe 100% de altura; em período vazio todas permanecem em zero.
- **Categorias mais detectadas:** considera somente categorias presentes em eventos `Blocked` dos últimos sete dias e ordena por quantidade decrescente.
- **Inspeções recentes:** mostra no máximo os seis eventos mais recentes recebidos, independentemente do período dos KPIs, com horário, arquivo, tamanho, resultado e categorias.
- **Categorias ativas:** lê `activeCategories` da política vigente e apresenta as cinco categorias do contrato quando estiverem habilitadas, incluindo `Secret`.
- **Vazio:** sem eventos, os KPIs ficam zerados, tendência e ranking não inventam ocorrências e a tabela informa explicitamente que nenhuma inspeção foi recebida. As categorias ativas continuam disponíveis porque vêm da política.
- **Detalhe de implementação:** gráficos são elementos HTML com altura/largura inline derivadas de `percentage`. Não usam biblioteca de gráficos.

### 3. Auditoria

- **Rota e arquivo:** `/admin/auditoria` → `admin/audit.html`; `active_page=audit`.
- **Contexto:** `stats` e `events`, montados por `presentation/audit.py`.
- **Fonte:** a rota consulta `agent_service.list_audit_events()`, que usa `memory_store`. O builder recebe essa lista e monta somente a apresentação; nenhum exemplo é acrescentado.
- **Estrutura:** aviso de consulta geral e armazenamento temporário, totais por resultado, tabela e resumo da quantidade exibida. Lista e total representam os mesmos registros, sem corte em vinte linhas ou paginação fictícia.
- **Campos:** data/hora conforme o timestamp recebido, endpoint, arquivo, tamanho, resultado, categorias e motivo de não inspeção quando informado. Não são exibidos usuário, processo, destino ou trechos mascarados.
- **Resultados:** `Approved` → Aprovado; `Blocked` → Bloqueado; `AllowedWithoutInspection` → Liberado sem inspeção. O último tem contagem própria e sinalização de atenção. As cinco categorias do contrato, incluindo `Secret`, têm rótulos de apresentação.
- **Vazio:** sem eventos, todos os totais são zero e a tabela informa que nenhum evento foi recebido.
- **Escopo:** consulta somente para leitura. A rota aceita `endpoint` para exibir apenas os eventos de um `endpointId`; esse filtro é usado pelo inventário de Endpoints. Exportação, detalhes, filtros adicionais e navegação de páginas não aparecem como controles disponíveis.
- **Limites:** não há persistência, deduplicação, atualização automática nem recuperação específica de falha de consulta. As datas preservam o deslocamento presente no timestamp recebido. A API rejeita eventos de auditoria e overrides cujo `occurredAtUtc` não contenha informação de fuso.
- **Verificação:** `tests/test_audit_page.py` cobre ausência de exemplos, estado vazio, contagem por resultado, ordenação entre timestamps com offsets distintos, mais de vinte registros, escape de textos e renderização das demais páginas. A integração com o filtro por endpoint também é exercitada pelos testes de Endpoints.

### 4. Endpoints

- **Rota e arquivo:** `/admin/endpoints` → `admin/endpoints.html`; `active_page=endpoints`.
- **Contexto:** `stats`, `endpoints`, `filters`, `filter_options` e `online_threshold_seconds`, montados por `presentation/endpoints.py`.
- **Fonte:** a rota consulta `agent_service.list_endpoints()` e `agent_service.list_audit_events()`. O builder recebe essas listas e não acessa `memory_store` diretamente. Nenhum endpoint fictício é acrescentado.
- **Estrutura:** totais reais, aviso sobre armazenamento temporário, filtros funcionais, tabela e estado vazio. Os controles de atualização de política, exportação e desativação foram removidos porque não possuem execução de negócio nesta versão.
- **Campos exibidos:** hostname, `endpointId`, sistema, versão informada pelo agente, versão de política, último contato, status e quantidade de inspeções nos últimos sete dias. O contrato de heartbeat não fornece endereço IP.
- **Status:** Online significa heartbeat recebido há no máximo 90 segundos; o intervalo atual do agente é 30 segundos, portanto a tolerância cobre três ciclos. Os demais registros são Offline. Não há classificação de versão desatualizada enquanto não existir uma fonte confiável para a versão de referência.
- **Filtros:** `status`, `os` e `q` são aplicados no servidor. `q` busca por hostname ou `endpointId`, e os valores selecionados permanecem no formulário após a consulta.
- **Auditoria:** Ver auditoria navega para `/admin/auditoria?endpoint=<endpointId>`, e a tela de Auditoria retorna apenas os eventos daquele endpoint.
- **Inspeções (7d):** a contagem é calculada a partir dos eventos recebidos nos últimos sete dias associados ao mesmo `endpointId`.
- **Limites:** os registros ainda vivem apenas em memória, não há atualização automática da página e as ações administrativas remotas continuam fora deste recorte.
- **Verificação:** `tests/test_endpoints_page.py` cobre estado vazio, heartbeat real, transição online/offline, filtros preservados, contagem de inspeções e navegação filtrada para Auditoria.

### 5. Relatórios

- **Rota e arquivo:** `/admin/relatorios` → `admin/reports.html`; `active_page=reports`.
- **Contexto:** `recent_reports`, com oito itens (`num`, `name`, `kind`, `href`).
- **Estrutura:** introdução, catálogo, lista de relatórios recentes e aviso sobre agregação.
- **Comportamento:** os dois primeiros itens navegam para auditoria e o terceiro para o dashboard, sem parâmetros de período. Os cinco restantes e Ver catálogo usam `href="#"`; não abrem relatórios específicos.
- **Limitação:** não há geração de relatório; o título do link não significa aplicação de um filtro.

### 6. Categorias

- **Rota e arquivo:** `/admin/categorias` → `admin/categories.html`; `active_page=categories`.
- **Contexto:** `summary` e `categories`.
- **Estrutura:** resumo e quatro categorias — CPF, CNPJ, cartão e senha — com descrição, regra, ícone, ocorrências e checkbox.
- **Comportamento:** o checkbox alterna pelo comportamento nativo do navegador. O texto Ativa/Inativa e os totais são renderizados pelo servidor e não acompanham a alteração local. Salvar alterações e Descartar não executam ações.
- **Limitação:** não há formulário de gravação nem validação da categoria mínima. Recarregar a rota volta aos mocks originais.
- **Dependência:** a política devolvida por `/agent/policy` contém cinco categorias, incluindo `Secret`. Os quatro checkboxes desta tela não leem nem alteram essa política.
- **Apresentação do ícone:** `cat.icon` contém uma chave conhecida (`shield`, `building`, `card` ou `key`). O SVG correspondente é resolvido por `components/icons.html`; o contexto não transporta HTML e `|safe` não é necessário.

### 7. Lista de exceções

- **Rota e arquivo:** `/admin/excecoes` → `admin/allowlist.html`; `active_page=allowlist`.
- **Contexto:** `stats`, `exceptions`, `filter_options`.
- **Estrutura:** aviso de evolução planejada, resumo por categoria, filtros e sete exceções fictícias com valor mascarado, categoria, justificativa, autor e data.
- **Comportamento:** Aplicar envia GET, mas não filtra; Limpar volta à URL limpa. Nova exceção e Remover exceção não têm ação implementada.
- **Limitação:** a indicação HMAC faz parte da demonstração visual; não há armazenamento protegido implementado.

### 8. Usuários

- **Rota e arquivo:** `/admin/usuarios` → `admin/users.html`; `active_page=users`.
- **Contexto:** `stats`, `users`, `filter_options`.
- **Estrutura:** resumo, filtros e seis contas fictícias; cada linha mostra iniciais, nome, e-mail, perfil, situação e último acesso.
- **Comportamento:** Aplicar envia GET sem alterar os dados; Limpar volta à URL limpa. Novo usuário e Editar usuário não têm execução implementada.
- **Limitação:** Administrador/Auditor são rótulos nos mocks, sem autorização associada. A menção a PBKDF2 na tela não corresponde a armazenamento de credenciais existente.

## Formulários e parâmetros atuais

| Página | Método | Parâmetros enviados | Tratamento atual |
|---|---|---|---|
| Login | POST | `email`, `senha` | Ignorados; redirecionamento 303 |
| Auditoria | GET | `endpoint` opcional | Filtra eventos por `endpointId`; demais parâmetros antigos são ignorados |
| Endpoints | GET | `status`, `os`, `q` | Aplicados no servidor e preservados no formulário |
| Exceções | GET | `categoria`, `q` | Ignorados; contexto padrão |
| Usuários | GET | `perfil`, `status`, `q` | Ignorados; contexto padrão |

As opções selecionadas nos filtros são reconstruídas a partir de `filter_options`, não da consulta recebida. Valores digitados não são repassados às páginas para preservação. Os checkboxes de categorias possuem nomes `cat_...`, mas não integram um envio implementado.

## Formato dos contextos e dependências de apresentação

Os contratos de apresentação são dicionários: Painel usa `presentation/dashboard.py`, Auditoria usa `presentation/audit.py`, Endpoints usa `presentation/endpoints.py`, e as demais páginas com contexto usam `presentation/demo/admin_data.py`. Não há esquema tipado específico para as páginas. As rotas consultam a camada de aplicação, entregam os dados aos builders e repassam o contexto resultante ao Jinja2. A documentação deve descrevê-los como contratos internos existentes, não como API JSON.

| Página | Builder do contexto |
|---|---|
| Painel | `build_dashboard_context(events, policy, now=...)` em `presentation/dashboard.py` |
| Auditoria | `build_audit_context(events)` em `presentation/audit.py` |
| Relatórios | `build_reports_context()` |
| Categorias | `build_categories_context()` |
| Exceções | `build_allowlist_context()` |
| Endpoints | `build_endpoints_context(endpoints, audit_events, ...)` em `presentation/endpoints.py` |
| Usuários | `build_users_context()` |

O login não possui builder porque não recebe contexto de negócio. Cada builder retorna uma nova estrutura. Os builders de Painel, Auditoria e Endpoints recebem dados da camada de aplicação; os demais contextos continuam fixos.

| Estrutura | Campos que sustentam a apresentação |
|---|---|
| KPI do painel | `value`, `trend`, `trend_kind` |
| Barra de tendência | `label`, `value`, `percentage` |
| Categoria mais detectada | `name`, `value`, `percentage` |
| Evento recente | `time`, `filename`, `size`, `result_kind`, `result_label`, `categories` |
| Evento de auditoria | `datetime`, `source`, `filename`, `size`, `result_kind`, `result_label`, `categories`, `not_inspected_reason` |
| Totais de auditoria | `total`, `blocked`, `approved`, `not_inspected`; inteiros calculados a partir da mesma lista exibida |
| Opção de filtro | `value`, `label`, `default` opcional |
| Categoria configurável | `code`, `label`, `rule`, `tone`, `icon`, `enabled`, `heuristic`, `occurrences`, `description`; `icon` é uma chave de apresentação conhecida |
| Endpoint | `endpoint_id`, `hostname`, `os`, `os_kind`, `os_short`, `agent_version`, `policy_version`, `last_seen`, `status`, `status_label`, `inspections_7d` |
| Exceção | `masked`, `category`, `reason`, `added_by`, `added_at` |
| Usuário | `name`, `initials`, `email`, `role`, `role_kind`, `active`, `last_access` |

Datas, tamanhos e vários totais já chegam formatados como texto. `result_kind`, `tone`, `role_kind` e `status` participam da composição de classes CSS. Alterar esses valores pode mudar a aparência. As URLs aparecem como literais nos templates e também em itens de `recent_reports`.

## Limites da integração atual

O fluxo existente é `routes/agent.py` → `application/agent_service.py` → `infrastructure/memory_store.py`. Para Painel, Auditoria e Endpoints, `routes/admin.py` consulta a aplicação e entrega os dados aos builders de apresentação; esses builders não acessam o armazenamento diretamente. A rota renderiza os templates. Os formatos recebidos estão em [domain/schemas.py](../../app/domain/schemas.py). Os dicionários das páginas são contratos de apresentação, distintos desses schemas.

- Reiniciar o processo perde endpoints e eventos recebidos. O banco em `db/` não participa desse fluxo.
- Reenviar um `eventId` acrescenta outra entrada; não há deduplicação no armazenamento.
- `AuditEventSchema` e `OverrideEventSchema` exigem informação de fuso em `occurredAtUtc`, evitando comparações ambíguas na ordenação da Auditoria e nas contagens de Endpoints.
- Não há autenticação na API do agente. Registros recebidos não equivalem a identidade autenticada.
- A API aceita overrides, mas o despachante atual envia essa lista vazia; as telas não apresentam um fluxo de justificativas.
- Painel, Auditoria e Endpoints têm estados vazios reais e não contêm exemplos. As demais listas preservam dados demonstrativos. Não há tratamento específico de falha de consulta nem mensagens de sucesso/erro das ações ainda sem execução.

## Responsabilidades e próximos recortes

As responsabilidades abaixo são por camada; responsáveis nominais e prioridades precisam ser acordados pela equipe. As referências HU/RN dos templates não substituem critérios de aceite. Os contratos de recepção do agente não foram alterados por esse recorte de apresentação.

| Tela | Recorte pequeno sugerido para a web | Dependência para comportamento real |
|---|---|---|
| Login | Distinguir entrada demonstrativa de sessão autenticada na apresentação | Backend/segurança: autenticação, sessão, logout e autorização |
| Painel | Próximo recorte possível: seleção de período ou atualização automática | Aplicação/apresentação: contrato de período e estratégia de atualização |
| Auditoria | Próximo recorte possível: filtros adicionais ou detalhes | Aplicação: contrato de consulta e campos necessários; API: validação de datas |
| Endpoints | Próximo recorte possível: persistência ou ações remotas | Infraestrutura/aplicação: repositório persistente e contratos para comandos administrativos |
| Relatórios | Diferenciar navegação existente de relatórios indisponíveis | Aplicação: definição das consultas, períodos e formatos |
| Categorias | Explicitar que a alteração local não salva política | Aplicação/domínio: catálogo, validação, gravação, versão e auditoria de política |
| Exceções | Explicitar o caráter experimental e as ações indisponíveis | Domínio/segurança/infraestrutura: contrato da exceção, HMAC, autorização e persistência |
| Usuários | Explicitar contas e perfis demonstrativos | Backend/segurança: gestão de contas, credenciais e permissões |

Os recortes de Painel baseado em eventos reais, Auditoria somente para leitura e Endpoints baseado em heartbeats estão implementados nesta versão. Os três usam fontes explícitas, sem exemplos fictícios; o Painel agrega os últimos sete dias e lê a política vigente, enquanto Endpoints acrescenta filtros reais e navegação para a Auditoria por `endpointId`. Persistência, seleção de período, detalhes, paginação, exportação e comandos administrativos permanecem recortes posteriores.

## Critérios de manutenção do inventário

- Conferir rota, template, builder, parâmetros e origem dos dados antes de atualizar a situação de uma tela.
- Diferenciar navegação, alteração local e operação persistida; renderizar HTTP 200 não comprova um fluxo completo.
- Ao integrar um comportamento, registrar estados vazio, sucesso e falha e verificar a regressão das páginas afetadas.
- Preservar templates, componentes, tokens e divisão de camadas existentes; evitar regras de negócio no HTML.
- Tratar os arquivos `validacao-*.json` como registros históricos da refatoração. Eles não certificam as integrações posteriores nem acessibilidade e responsividade.
