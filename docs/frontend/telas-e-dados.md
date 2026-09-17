# Telas e dados do frontend

Referência do comportamento existente em 16/09/2026. A refatoração de layouts e componentes preserva as oito páginas, suas rotas, contextos e ações descritos abaixo.

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
- **Limitação:** não existem mensagens de credencial inválida, sessão ou recuperação de acesso. Documentar essa condição; não implementar autenticação.

### 2. Painel

- **Rota e arquivo:** `/admin/dashboard` → `admin/dashboard.html`; `active_page=dashboard`.
- **Contexto:** `kpis`, `trend`, `categories_top`, `categories_status`, `recent_events`.
- **Estrutura:** quatro KPIs, sete barras de tendência, quatro categorias mais detectadas, seis eventos recentes, quatro categorias ativas e aviso de privacidade.
- **Comportamento:** links para auditoria e categorias navegam. Botões 24h, 7 dias e 30 dias não alteram o período; 7 dias recebe destaque fixo.
- **Detalhe de implementação:** gráficos são elementos HTML com altura/largura inline derivadas de `percentage`. Não usam biblioteca de gráficos.

### 3. Auditoria

- **Rota e arquivo:** `/admin/auditoria` → `admin/audit.html`; `active_page=audit`.
- **Contexto:** `stats`, `events`, `pagination`, `filter_options`.
- **Estrutura:** resumo, filtros, tabela com vinte eventos, exportação e paginação visual. O total demonstrativo é 1.247 eventos, com 63 páginas indicadas.
- **Campos da tabela:** data/hora, origem, arquivo, tamanho, resultado, categorias e ação de detalhes. Origem usa textos de sessão fictícios. Alguns eventos têm `reject_reason`, exibido quando não há categorias.
- **Comportamento:** Aplicar envia GET; Limpar volta à URL sem parâmetros. A rota ignora os filtros, incluindo `hostname` recebido de Endpoints. Exportar CSV, detalhes e botões de paginação não executam essas ações.
- **Limitação:** os números de página são apresentação estática; a consulta não seleciona outros eventos.

### 4. Endpoints

- **Rota e arquivo:** `/admin/endpoints` → `admin/endpoints.html`; `active_page=endpoints`.
- **Contexto:** `stats`, `current_agent_version`, `endpoints`, `filter_options`.
- **Estrutura:** resumo de 24 endpoints, dez linhas demonstrativas, filtros e ações; versão de referência fictícia `2.3.1`.
- **Campos exibidos:** hostname/IP, sistema, versão do agente, versão de política, último contato, status e inspeções em sete dias. `agent_outdated` também controla a indicação de versão desatualizada.
- **Comportamento:** Ver auditoria navega para `/admin/auditoria?hostname=...`, sem aplicar o filtro no destino. Aplicar envia GET e Limpar remove parâmetros. Extrair relatório, Atualizar política em todos, atualizar por máquina e desativar não têm execução implementada.
- **Limitação:** os status `online`, `offline` e `outdated` são dados fictícios; não há monitoramento ou sincronização.

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
| Auditoria | GET | `periodo`, `resultado`, `categoria`, `q` | Ignorados; contexto padrão |
| Endpoints | GET | `status`, `os`, `q` | Ignorados; contexto padrão |
| Exceções | GET | `categoria`, `q` | Ignorados; contexto padrão |
| Usuários | GET | `perfil`, `status`, `q` | Ignorados; contexto padrão |

As opções selecionadas nos filtros são reconstruídas a partir de `filter_options`, não da consulta recebida. Valores digitados não são repassados às páginas para preservação. Os checkboxes de categorias possuem nomes `cat_...`, mas não integram um envio implementado.

## Formato dos contextos e dependências de apresentação

Os contratos atuais são dicionários montados por funções em `presentation/demo/admin_data.py`; não há esquema tipado específico para as páginas. As rotas chamam esses builders e repassam o resultado ao Jinja2. A documentação deve descrevê-los como contratos internos existentes, não como API JSON.

| Página | Builder do contexto |
|---|---|
| Painel | `build_dashboard_context()` |
| Auditoria | `build_audit_context()` |
| Relatórios | `build_reports_context()` |
| Categorias | `build_categories_context()` |
| Exceções | `build_allowlist_context()` |
| Endpoints | `build_endpoints_context()` |
| Usuários | `build_users_context()` |

O login não possui builder porque não recebe contexto de negócio. Cada builder retorna uma nova estrutura; os dados continuam estáticos e demonstrativos.

| Estrutura | Campos que sustentam a apresentação |
|---|---|
| KPI do painel | `value`, `trend`, `trend_kind` |
| Barra de tendência | `label`, `value`, `percentage` |
| Categoria mais detectada | `name`, `value`, `percentage` |
| Evento recente | `time`, `filename`, `size`, `result_kind`, `result_label`, `categories` |
| Evento de auditoria | `datetime`, `source`, `filename`, `size`, `result_kind`, `result_label`, `categories`; `reject_reason` opcional |
| Paginação de auditoria | `showing_from`, `showing_to`, `total`, `current`, `total_pages`; os botões iniciais são fixos no template |
| Opção de filtro | `value`, `label`, `default` opcional |
| Categoria configurável | `code`, `label`, `rule`, `tone`, `icon`, `enabled`, `heuristic`, `occurrences`, `description`; `icon` é uma chave de apresentação conhecida |
| Endpoint | `hostname`, `ip`, `os`, `os_short`, `agent_version`, `agent_outdated`, `policy_version`, `last_seen`, `status`, `status_label`, `inspections_7d` |
| Exceção | `masked`, `category`, `reason`, `added_by`, `added_at` |
| Usuário | `name`, `initials`, `email`, `role`, `role_kind`, `active`, `last_access` |

Datas, tamanhos e vários totais já chegam formatados como texto. `result_kind`, `tone`, `role_kind` e `status` participam da composição de classes CSS. Alterar esses valores pode mudar a aparência. As URLs aparecem como literais nos templates e também em itens de `recent_reports`.
