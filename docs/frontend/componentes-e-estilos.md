# Componentes e estilos existentes

## Composição dos templates

A estrutura compartilhada usa três níveis simples:

- `admin/partials/sidebar.html` é incluído pelo layout administrativo.
- `components/icons.html` expõe `icon(name)` para SVGs conhecidos. Foram centralizados os quatro ícones de categorias e os desenhos efetivamente repetidos nas páginas, como busca, informação, alerta, gráfico, download e atualização. Ícones únicos permanecem junto do template que os utiliza.
- `components/notice.html` expõe `notice(icon_name, modifier="")`. A macro contém apenas a moldura `notice`/`notice-icon`/`notice-body`; cada página mantém seu texto no próprio arquivo usando `call`, evitando esconder conteúdo específico em um componente genérico.

Os ícones de categoria não são mais HTML vindo de Python. `demo/admin_data.py` entrega apenas `shield`, `building`, `card` ou `key` no contexto usado pela rota, e `categories.html` chama `icon(cat.icon)`. Isso remove o uso de `|safe` e mantém a lista de SVGs aceita sob controle da camada de apresentação.

Não foram criados componentes genéricos para tabela, formulário, card ou botão. As classes CSS já fazem a reutilização visual desses elementos, e uma macro com muitas opções aumentaria o acoplamento para a escala atual.

Os padrões visuais recorrentes são usados por classes CSS:

| Elemento | Classes representativas |
|---|---|
| Estrutura administrativa | `sidebar`, `topbar`, `admin-main`, `admin-content` |
| Cabeçalho e ações | `page-header`, `page-title`, `page-actions` |
| Botões | `btn`, `btn-primary`, `btn-outline`, `icon-btn` |
| Cards | `card`, `card-header`, `card-body`, `card-footer` |
| Indicadores | `kpi-grid`, `kpi-card`, `stat-strip` |
| Filtros | `filter-bar`, `filter-group`, `filter-select`, `filter-input` |
| Tabelas | `data-table`, `data-table-dense`, classes `cell-*` |
| Estados | `badge`, `tag`, `status-dot`, `status-pill` |
| Avisos | `notice`, `notice-icon`, `notice-body` |
| Paginação visual | `pagination`, `pagination-btn` |
| Categorias | `config-list`, `toggle-input`, `toggle-track` |

## CSS

`static/css/styles.css` permanece como o único endereço carregado pelos templates: `/static/css/styles.css`. Depois da F04, esse arquivo funciona apenas como ponto de entrada e importa, nesta ordem fixa:

| Ordem | Arquivo | Responsabilidade | Linhas na origem anterior |
|---|---|---|---|
| 1 | `tokens.css` | Tokens de cores, dimensões, espaços, fontes, raios, sombras e transição | 1–69 |
| 2 | `base.css` | Reset e regras básicas do documento | 70–96 |
| 3 | `auth.css` | Estrutura própria da tela de login | 97–162 |
| 4 | `controls.css` | Formulários e botões; mantém também o rodapé de autenticação no mesmo trecho histórico | 163–246 |
| 5 | `layout.css` | Layout administrativo, sidebar, topbar e área de conteúdo | 247–446 |
| 6 | `components.css` | Cabeçalhos, KPIs, cards, gráficos, tabelas, badges, avisos, filtros e paginação | 447–1192 |
| 7 | `pages.css` | Regras específicas de categorias, exceções, usuários, relatórios e endpoints | 1193–1500 |

A divisão foi feita por intervalos contíguos, sem reordenar, renomear ou reescrever seletores e declarações. A concatenação dos sete arquivos, na ordem acima, reconstrói byte a byte os 40.783 bytes do stylesheet anterior. Isso permite organizar responsabilidades sem mudar a cascata existente.

`:root`, agora em `tokens.css`, reúne os tokens globais. O layout utiliza Flexbox/Grid e fontes do sistema. Os gráficos continuam usando barras HTML com altura ou largura recebida do contexto e aplicada inline.

Campos como `result_kind`, `tone`, `role_kind` e `status` compõem nomes de classes. A relação entre esses campos e os seletores faz parte do contrato atual de apresentação. Não renomeie um lado sem conferir o outro.

Não há JavaScript nem media queries. A sidebar de 260px e as colunas do dashboard limitam a adaptação a janelas estreitas. A comparação em telas menores verifica preservação do resultado, não aprovação de responsividade.

Os `@import` de `styles.css` devem permanecer antes de qualquer outra regra e na ordem documentada. Os sete arquivos não devem ser carregados diretamente pelos templates; `styles.css` continua sendo o contrato público do frontend.
