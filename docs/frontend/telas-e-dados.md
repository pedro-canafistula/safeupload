# Telas e dados do frontend

Inventário consolidado em 01/10/2026, conferido com o código da `main` em `a0b1918960598d9f338a5968ee1a88189c396ffe`. Descreve o comportamento implementado, incluindo a integração parcial da HU-10; não representa funcionalidades planejadas como concluídas.

## Resumo das oito telas

“Demonstrativa” significa que os dados são fixos ou que a ação não possui execução de negócio. “Integração parcial” significa que a tela também apresenta dados recebidos pela API do agente, mantidos apenas na memória do processo.

| Tela | Fonte atual | Funciona hoje | Lacuna principal |
|---|---|---|---|
| Login | Sem contexto de negócio | Renderização e redirecionamento do POST | Autenticação, sessão e autorização ausentes |
| Painel | Dados fixos | Renderização e links internos | Indicadores não refletem os eventos recebidos |
| Auditoria | Exemplos + eventos de `memory_store` | Recepção refletida na lista e em parte dos totais | Mistura de fontes; filtros, detalhes e paginação sem execução |
| Endpoints | Exemplos + heartbeats de `memory_store` | Recepção refletida no inventário e cálculo de status | Versão de referência fixa e ações administrativas sem execução |
| Relatórios | Catálogo fixo | Links para Auditoria e Painel | Nenhum relatório gerado |
| Categorias | Quatro categorias fixas | Alternância local dos checkboxes | Sem gravação ou ligação com a política do agente |
| Exceções | Sete exemplos fixos | Renderização e navegação de Limpar | Sem cadastro, remoção, filtro ou HMAC implementado |
| Usuários | Seis contas fixas | Renderização e navegação de Limpar | Sem cadastro, edição ou controle de acesso |

Rotas e templates: [admin.py](../../app/presentation/routes/admin.py) e [templates administrativos](../../app/presentation/templates/admin). Fontes dos contextos: [admin_data.py](../../app/presentation/demo/admin_data.py) e [memory_store.py](../../app/infrastructure/memory_store.py).

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
- **Estrutura:** quatro KPIs, sete barras de tendência, quatro categorias mais detectadas, seis eventos recentes, quatro categorias ativas e aviso de privacidade.
- **Comportamento:** links para auditoria e categorias navegam. Botões 24h, 7 dias e 30 dias não alteram o período; 7 dias recebe destaque fixo.
- **Detalhe de implementação:** gráficos são elementos HTML com altura/largura inline derivadas de `percentage`. Não usam biblioteca de gráficos.

### 3. Auditoria

- **Rota e arquivo:** `/admin/auditoria` → `admin/audit.html`; `active_page=audit`.
- **Contexto:** `stats`, `events`, `pagination`, `filter_options`.
- **Estrutura:** resumo, filtros, vinte eventos demonstrativos acrescidos dos eventos recebidos, exportação e paginação visual. A paginação permanece fixa em 1.247 eventos e 63 páginas; não limita as linhas renderizadas.
- **Fonte:** `build_audit_context()` antepõe os eventos de `memory_store.list_audit_events()` aos exemplos e acrescenta as quantidades recebidas aos totais fictícios de eventos, bloqueados e aprovados. O Painel não acompanha esses acréscimos.
- **Campos da tabela:** data/hora, origem, arquivo, tamanho, resultado, categorias e ação de detalhes. Origem usa textos fictícios nos exemplos e `endpoint_id` nos eventos recebidos. Alguns eventos têm `reject_reason`, exibido quando não há categorias.
- **Comportamento:** Aplicar envia GET; Limpar volta à URL sem parâmetros. A rota ignora os filtros, incluindo `hostname` recebido de Endpoints. Exportar CSV, detalhes e botões de paginação não executam essas ações.
- **Limitação:** os números de página são apresentação estática; a consulta não seleciona outros eventos.
- **Mapeamento:** `Approved` e `Blocked` viram Aprovado e Bloqueado. `AllowedWithoutInspection` aparece como Aprovado (sem inspeção), mas usa a classe e a contagem de aprovação. `Secret` já recebe o rótulo Segredo/credencial na linha; não aparece nas opções de filtro. Datas são formatadas sem conversão explícita de fuso. `event_id`, usuário, processo, destino e trechos mascarados não são repassados à linha pelo builder; o botão de detalhes não os apresenta.

### 4. Endpoints

- **Rota e arquivo:** `/admin/endpoints` → `admin/endpoints.html`; `active_page=endpoints`.
- **Contexto:** `stats`, `current_agent_version`, `endpoints`, `filter_options`.
- **Estrutura:** resumo inicial de 24 endpoints e dez linhas demonstrativas, acrescidos dos endpoints registrados em memória; filtros, ações e versão de referência fixa `2.3.1`.
- **Campos exibidos:** hostname/IP, sistema, versão do agente, versão de política, último contato, status e inspeções em sete dias. `agent_outdated` também controla a indicação de versão desatualizada.
- **Comportamento:** Ver auditoria navega para `/admin/auditoria?hostname=...`, sem aplicar o filtro no destino. Aplicar envia GET e Limpar remove parâmetros. Extrair relatório, Atualizar política em todos, atualizar por máquina e desativar não têm execução implementada.
- **Fonte e status:** `build_endpoints_context()` antepõe os registros de `memory_store.list_endpoints()` aos exemplos. Nos registros recebidos, versão diferente de `2.3.1` resulta em `outdated`; caso contrário, contato há menos de 15 minutos resulta em `online`, e os demais em `offline`. Não há atualização automática da página: o cálculo ocorre na requisição.
- **Limitação:** o agente informa `1.0.0` em `HttpAgentDispatcher.cs`, portanto é marcado como desatualizado por essa comparação. A condição de versão tem precedência sobre a conectividade. O IP dos registros recebidos é apresentado como `—`, pois não existe no contrato de heartbeat. As inspeções em sete dias contam os eventos em memória associados ao `endpoint_id`.

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

O login não possui builder porque não recebe contexto de negócio. Cada builder retorna uma nova estrutura. Auditoria e Endpoints também leem o armazenamento compartilhado em memória; os demais contextos continuam fixos.

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

## Limites da integração atual

O fluxo existente é `routes/agent.py` → `application/agent_service.py` → `infrastructure/memory_store.py`. Depois, os builders de Auditoria e Endpoints leem essa memória e `routes/admin.py` renderiza os templates. Os formatos recebidos estão em [domain/schemas.py](../../app/domain/schemas.py). Os dicionários das páginas são contratos de apresentação, distintos desses schemas.

- Reiniciar o processo perde endpoints e eventos recebidos. O banco em `db/` não participa desse fluxo.
- Reenviar um `eventId` acrescenta outra entrada; não há deduplicação no armazenamento.
- Os schemas aceitam datas sem fuso. Elas podem falhar na ordenação com datas com fuso ou na comparação usada pelas contagens de Endpoints.
- Não há autenticação na API do agente. Registros recebidos não equivalem a identidade autenticada.
- A API aceita overrides, mas o despachante atual envia essa lista vazia; as telas não apresentam um fluxo de justificativas.
- Listas sempre contêm exemplos. Não há tratamento específico de ausência de dados recebidos, lista realmente vazia ou falha de consulta. Também não há mensagens de sucesso/erro das ações ainda sem execução.

## Responsabilidades e próximos recortes

As responsabilidades abaixo são por camada; responsáveis nominais e prioridades precisam ser acordados pela equipe. As referências HU/RN dos templates não substituem critérios de aceite. Este inventário não altera contratos, regras ou comportamento da aplicação.

| Tela | Recorte pequeno sugerido para a web | Dependência para comportamento real |
|---|---|---|
| Login | Distinguir entrada demonstrativa de sessão autenticada na apresentação | Backend/segurança: autenticação, sessão, logout e autorização |
| Painel | Identificar a origem demonstrativa dos indicadores | Aplicação: agregações com período e fonte definidos |
| Auditoria | Separar exemplos de registros recebidos e representar ausência de eventos | Aplicação/infraestrutura: fonte de leitura; acordo sobre IDs, vereditos e fuso |
| Endpoints | Distinguir conectividade de versão e explicitar ações indisponíveis | Agente/aplicação: versão de referência, identidade e critérios de status |
| Relatórios | Diferenciar navegação existente de relatórios indisponíveis | Aplicação: definição das consultas, períodos e formatos |
| Categorias | Explicitar que a alteração local não salva política | Aplicação/domínio: catálogo, validação, gravação, versão e auditoria de política |
| Exceções | Explicitar o caráter experimental e as ações indisponíveis | Domínio/segurança/infraestrutura: contrato da exceção, HMAC, autorização e persistência |
| Usuários | Explicitar contas e perfis demonstrativos | Backend/segurança: gestão de contas, credenciais e permissões |

O primeiro recorte funcional proposto é Auditoria somente para leitura, a ser feito em outra entrega: fonte explícita, sem somar exemplos aos registros recebidos, lista e total coerentes, estado vazio e mapeamento acordado de categorias/vereditos/datas. Filtros, detalhes, paginação e gravações administrativas permanecem recortes posteriores.

## Critérios de manutenção do inventário

- Conferir rota, template, builder, parâmetros e origem dos dados antes de atualizar a situação de uma tela.
- Diferenciar navegação, alteração local e operação persistida; renderizar HTTP 200 não comprova um fluxo completo.
- Ao integrar um comportamento, registrar estados vazio, sucesso e falha e verificar a regressão das páginas afetadas.
- Preservar templates, componentes, tokens e divisão de camadas existentes; evitar regras de negócio no HTML.
- Tratar os arquivos `validacao-*.json` como registros históricos da refatoração. Eles não certificam as integrações posteriores nem acessibilidade e responsividade.
