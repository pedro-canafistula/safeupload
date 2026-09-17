# Estrutura e layouts

## Arquivos atuais

```text
app/
├── main.py
└── presentation/
    ├── __init__.py
    ├── routes/
    │   ├── admin.py
    │   └── agent.py
    ├── demo/
    │   ├── __init__.py
    │   └── admin_data.py
    ├── templates/
    │   ├── base.html
    │   ├── components/
    │   │   ├── icons.html
    │   │   └── notice.html
    │   └── admin/
    │       ├── base_admin.html
    │       ├── partials/sidebar.html
    │       ├── login.html
    │       ├── dashboard.html
    │       ├── audit.html
    │       ├── endpoints.html
    │       ├── reports.html
    │       ├── categories.html
    │       ├── allowlist.html
    │       └── users.html
    └── static/css/
        ├── styles.css
        ├── tokens.css
        ├── base.css
        ├── auth.css
        ├── controls.css
        ├── layout.css
        ├── components.css
        └── pages.css
```

`main.py` cria a aplicação, monta `/static` e registra as rotas. `presentation/__init__.py` configura os templates Jinja2. `routes/admin.py` concentra as declarações HTTP e a seleção de templates. `demo/admin_data.py` concentra os dados fictícios e a montagem dos sete contextos demonstrativos. O router do agente está vazio.

Cada função `build_*_context()` cria uma nova estrutura em memória e não mantém cache ou estado global mutável. O login não possui builder próprio porque não recebe contexto de negócio. Essa separação é interna à camada de apresentação: `demo/` não é serviço de aplicação, repositório nem fonte persistente.

## Herança de templates

`base.html` contém o documento completo: doctype, idioma, metadados, stylesheet e fechamentos de HTML/body. Expõe três blocos:

| Bloco | Uso |
|---|---|
| `title` | Título da página no navegador |
| `body_class` | Classe do corpo; vazio no login, `admin-body` no painel |
| `body` | Estrutura interna da página |

A classe do corpo é capturada em uma variável Jinja2; o atributo `class` só é emitido quando há valor. Isso preserva o HTML do login sem classe e o layout Flexbox das páginas administrativas.

`login.html` herda diretamente de `base.html` e preenche `title` e `body`.

`admin/base_admin.html` também herda de `base.html`. Define `body_class`, inclui a sidebar e monta a topbar e a área principal. Dentro dessa estrutura, disponibiliza `page_title` e `content` para as sete páginas internas. Essas páginas continuam usando os mesmos blocos e os mesmos nomes de arquivo.

`partials/sidebar.html` contém marca, navegação e Sair. O include recebe o contexto atual automaticamente. O campo `active_page` determina o destaque visual de cada link; os valores atuais são `dashboard`, `audit`, `endpoints`, `reports`, `categories`, `allowlist` e `users`.

A topbar permanece no layout administrativo para manter o bloco `page_title` na cadeia de herança. Textos fixos de usuário e servidor continuam demonstrativos.

## Mudanças aplicadas

A primeira parte alterou `base.html`, `admin/base_admin.html` e o bloco externo de `admin/login.html`, adicionando `admin/partials/sidebar.html`. O trecho incompleto `</` no final do layout administrativo foi eliminado pela herança da base, deixando os fechamentos do documento em um único lugar.

A segunda parte adicionou `components/icons.html` e `components/notice.html`. `icons.html` expõe a macro `icon(name)` apenas para desenhos conhecidos e reutilizados. `notice.html` expõe a macro `notice(icon_name, modifier="")`, mantendo o conteúdo textual de cada aviso no arquivo da própria página por meio de `caller()`.

Os quatro SVGs de categorias deixaram de ser constantes em `routes/admin.py`. O contexto continua usando o campo `icon`, mas agora com as chaves `shield`, `building`, `card` e `key`; `categories.html` resolve a chave pela macro de apresentação. Essa mudança remove a necessidade de `|safe` sem alterar os desenhos renderizados.

A terceira parte reorganizou o stylesheet monolítico. `styles.css` permanece como o único arquivo referenciado pelo HTML, mas agora contém somente sete `@import` em ordem fixa. Os trechos originais foram movidos sem alteração para `tokens.css`, `base.css`, `auth.css`, `controls.css`, `layout.css`, `components.css` e `pages.css`. A concatenação desses arquivos na ordem dos imports reproduz byte a byte o CSS anterior.

A quarta parte separou os dados demonstrativos das declarações de rota. `routes/admin.py` importa os builders de `demo/admin_data.py`, obtém o contexto e renderiza o mesmo template de antes. Foram criados `build_dashboard_context()`, `build_audit_context()`, `build_reports_context()`, `build_categories_context()`, `build_allowlist_context()`, `build_endpoints_context()` e `build_users_context()`. Os valores, URLs internas, filtros demonstrativos e campos consumidos pelos templates foram preservados.

## Convenções de manutenção

- Mantenha metadados e a referência única a `/static/css/styles.css` em `base.html`.
- Mantenha o shell administrativo em `base_admin.html` e a navegação na sidebar.
- Mantenha conteúdo específico em cada página, sem duplicar doctype, head ou body.
- Use `components/icons.html` somente para SVGs conhecidos e reutilizados; não passe HTML arbitrário pelo contexto.
- Use a macro de aviso apenas para a moldura compartilhada; o texto do aviso deve permanecer no template da página.
- Preserve a ordem dos `@import` de `styles.css`; alterações na ordem podem mudar a cascata visual.
- Não carregue os arquivos CSS especializados diretamente pelos templates.
- Não acrescente comportamento a controles demonstrativos durante uma refatoração.
- Mantenha dados demonstrativos e montagem dos contextos em `demo/admin_data.py`; `routes/admin.py` deve continuar focado no fluxo HTTP.
- Builders de contexto devem retornar novas estruturas e não introduzir cache, persistência ou estado global mutável.
- Alterações de contexto devem ser conferidas em todas as páginas consumidoras e registradas no guia de telas.
