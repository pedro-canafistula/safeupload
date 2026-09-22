# SafeUpload

Protótipo acadêmico de sistema de **prevenção de vazamento acidental de dados** (DLP), desenvolvido na disciplina de Análise e Projeto de Software da Universidade Católica de Brasília.

> Versão atual: **0.1.0** — protótipo acadêmico com Centro de Administração web e protótipo desktop WPF. O frontend web possui navegação, renderização e dados demonstrativos, mas ainda não possui autenticação real, persistência, inspeção integrada nem execução efetiva das ações administrativas.

---

## Sumário

- [Visão geral](#visão-geral)
- [Arquitetura do produto](#arquitetura-do-produto)
- [Tecnologias](#tecnologias)
- [Pré-requisitos](#pré-requisitos)
- [Instalação e execução](#instalação-e-execução)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Rotas disponíveis](#rotas-disponíveis)
- [Convenções e arquitetura de código](#convenções-e-arquitetura-de-código)
- [Frontend web](#frontend-web)
- [Documentação do frontend](#documentação-do-frontend)
- [Limitações conhecidas](#limitações-conhecidas)
- [Equipe](#equipe)

---

## Visão geral

O SafeUpload é um projeto acadêmico voltado à prevenção de vazamento acidental de informações sensíveis.

A proposta do produto prevê a identificação de categorias como:

- CPF;
- CNPJ;
- cartão de pagamento;
- indícios de senha em texto claro.

O repositório atual contém duas interfaces principais:

1. um **Centro de Administração web**, desenvolvido com FastAPI, Jinja2, HTML e CSS;
2. um **protótipo de agente desktop**, desenvolvido em WPF com .NET 8 e C#.

Nesta versão, o Centro de Administração utiliza dados demonstrativos para representar informações de auditoria, endpoints, categorias de detecção, exceções, usuários e relatórios.

A existência dessas representações visuais não significa que todos os fluxos de inspeção, autenticação, persistência ou administração estejam implementados.

---

## Arquitetura do produto

### 1. Agente desktop

O agente vive em `agente/` e tem seu próprio README, com a arquitetura
completa, como rodar e a integração com o Centro de Administração:

```text
agente/README.md
```

Resumo: além do protótipo visual (`agente/SafeUploadAgent/`), o
repositório contém uma implementação real em .NET 10 — `SafeUpload.Agent.Core`
(validadores CPF/CNPJ/cartão/senha, motor de inspeção), `SafeUpload.Agent.Service`
(serviço Windows que intercepta arquivos e decide) e `SafeUpload.Agent.App`
(interface WPF que só exibe). Opcionalmente, um driver de kernel
(`driver/`) permite interceptação antes da escrita, em vez de reagir depois.

Desde a HU-10, o agente pode buscar política e enviar auditoria para o
Centro de Administração via API (ver seção
[API do agente](#api-do-agente) abaixo) — configuração opcional, desligada
por padrão.

Este README (do frontend web) não detalha o agente — os detalhes vivem em
`agente/README.md` para não duplicar documentação em dois lugares.

### 2. Centro de Administração

O Centro de Administração é uma aplicação web destinada à visualização e administração do ambiente SafeUpload.

Atualmente são apresentadas as seguintes áreas:

- login;
- painel;
- auditoria;
- endpoints;
- relatórios;
- categorias de detecção;
- lista de exceções;
- usuários.

As páginas são renderizadas no servidor por Jinja2 e utilizam dados demonstrativos definidos na camada de apresentação.

Não há aplicação SPA, framework JavaScript ou processo de build do frontend.

---

## Tecnologias

| Camada | Tecnologia |
|---|---|
| Linguagem do servidor web | Python 3.11+ |
| Servidor web | FastAPI + Uvicorn |
| Renderização HTML | Jinja2 |
| Frontend web | HTML5 + CSS3 |
| Dados atuais do painel | Estruturas demonstrativas em Python |
| Persistência | Não implementada nesta versão |
| Agente desktop | WPF / .NET 8 / C# |
| Interface desktop | XAML |

O frontend web não possui dependências JavaScript nem etapa de compilação.

---

## Pré-requisitos

### Centro de Administração web

- Windows com WSL2+ ou Linux;
- Docker
- Python 3.11 ou superior;
- pip;
- navegador moderno.

### Agente desktop

- Windows;
- .NET 8 SDK.

As instruções específicas do agente desktop estão disponíveis em:

```text
agente/README.md
```

---

## Instalação e execução

### Centro de Administração web

### 1. Executar Banco de Dados (Container Docker)

#### 1.1 Verificar dependências:
No windows:

```powershell
wsl --status
```
```powershell
docker version
```
Verificar, no Docker Desktop, se o Docker está integrado à distro do WSL.

No Linux:
```bash
docker version
```

#### 1.2 Entrar na raiz de criação do container Docker:
Em Windows:
```powershell
wsl
```
```bash
cd /<caminho>/safeupload/db
```

Em Linux:
```bash
cd /<caminho>/safeupload/db
```
#### 1.3 Executar:
Em Windows (ainda dentro do ambiente WSL) ou em Linux:
```bash
./install.sh
```

#### 1.4 Verificar logs:
```bash
docker logs safeupload-db
```
A última mensagem deve indicar a aceitação de conexões TCP/IP e não deve conter mensagens de erros no log.

### 2. Executar Aplicação

#### 2.1 Criar um ambiente virtual
```powershell
python -m venv .venv
```

#### 2.2 Instalar as dependências

Sem necessidade de ativar o ambiente:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Ou, caso prefira ativá-lo:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

#### 2.3 Iniciar o servidor

Com o ambiente virtual ativado:

```powershell
uvicorn app.main:app --reload
```

Ou diretamente pelo interpretador do ambiente:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

A aplicação ficará disponível em:

```text
http://127.0.0.1:8000
```

A rota raiz redireciona para:

```text
/admin/login
```

O formulário de login é demonstrativo. Nesta versão, as credenciais não são validadas e o envio redireciona para o painel administrativo.

Não utilize credenciais reais durante a demonstração.

#### 2.4 Encerrar o servidor

No terminal onde o Uvicorn está em execução:

```text
Ctrl + C
```

---

## Estrutura do projeto

A estrutura relevante para as interfaces atuais é:

```text
SafeUpload/
├── app/
│   ├── __init__.py
│   ├── main.py
│   │
│   ├── presentation/
│   │   ├── __init__.py
│   │   │
│   │   ├── routes/
│   │   │   ├── __init__.py
│   │   │   ├── admin.py
│   │   │   └── agent.py
│   │   │
│   │   ├── demo/
│   │   │   ├── __init__.py
│   │   │   └── admin_data.py
│   │   │
│   │   ├── templates/
│   │   │   ├── base.html
│   │   │   │
│   │   │   ├── components/
│   │   │   │   ├── icons.html
│   │   │   │   └── notice.html
│   │   │   │
│   │   │   └── admin/
│   │   │       ├── base_admin.html
│   │   │       │
│   │   │       ├── partials/
│   │   │       │   └── sidebar.html
│   │   │       │
│   │   │       ├── login.html
│   │   │       ├── dashboard.html
│   │   │       ├── audit.html
│   │   │       ├── endpoints.html
│   │   │       ├── reports.html
│   │   │       ├── categories.html
│   │   │       ├── allowlist.html
│   │   │       └── users.html
│   │   │
│   │   └── static/
│   │       └── css/
│   │           ├── styles.css
│   │           ├── tokens.css
│   │           ├── base.css
│   │           ├── auth.css
│   │           ├── controls.css
│   │           ├── layout.css
│   │           ├── components.css
│   │           └── pages.css
│   │
│   ├── application/
│   │   └── __init__.py
│   │
│   ├── domain/
│   │   └── __init__.py
│   │
│   ├── infrastructure/
│   │   └── __init__.py
│   │
│   └── security/
│       └── __init__.py
│
├── agente/                    # Ver agente/README.md — Core, Service, App, Tests, driver
│
├── docs/
│   └── frontend/
│       ├── README.md
│       ├── estrutura.md
│       ├── telas-e-dados.md
│       ├── componentes-e-estilos.md
│       ├── verificacao-e-limitacoes.md
│       └── registros de validação
│
├── .gitignore
├── README.md
└── requirements.txt
```

As pastas:

```text
application/
domain/
infrastructure/
security/
```

estão reservadas na estrutura atual e contêm apenas seus arquivos `__init__.py`.

---

## Rotas disponíveis

### Centro de Administração

| Rota | Método | Comportamento atual |
|---|---|---|
| `/` | GET | Redireciona para `/admin/login` |
| `/admin` | GET | Redireciona para `/admin/dashboard` |
| `/admin/login` | GET | Renderiza a página de login |
| `/admin/login` | POST | Redireciona para o painel sem validar as credenciais |
| `/admin/dashboard` | GET | Renderiza o painel administrativo |
| `/admin/auditoria` | GET | Renderiza a tela de auditoria |
| `/admin/endpoints` | GET | Renderiza o inventário demonstrativo de endpoints |
| `/admin/relatorios` | GET | Renderiza a central demonstrativa de relatórios |
| `/admin/categorias` | GET | Renderiza as categorias de detecção |
| `/admin/excecoes` | GET | Renderiza a lista demonstrativa de exceções |
| `/admin/usuarios` | GET | Renderiza a gestão demonstrativa de usuários |

As páginas administrativas recebem dados demonstrativos provenientes de:

```text
app/presentation/demo/admin_data.py
```

As funções desse módulo montam os contextos utilizados pelos templates Jinja2.

Os formulários de filtro existentes enviam parâmetros HTTP, porém as rotas atuais não utilizam esses valores para alterar os dados exibidos.

Da mesma forma, diversos botões representam ações previstas visualmente, mas não executam operações reais nesta versão.

### API do agente

Desde a HU-10, `app/presentation/routes/agent.py` expõe três rotas que o
agente desktop consome (prefixo `/agent`):

| Rota | Método | Uso |
|---|---|---|
| `/agent/heartbeat` | POST | Registro/heartbeat do endpoint — alimenta `/admin/endpoints` |
| `/agent/policy` | GET | Política vigente, mesmo formato que o agente já lia localmente |
| `/agent/events` | POST | Recebe eventos de auditoria — alimenta `/admin/auditoria` |

Persistência em memória (`app/infrastructure/memory_store.py`), sem
autenticação — decisões de escopo documentadas no próprio módulo. Detalhes
do lado agente (quando ele chama essas rotas, o que acontece se o servidor
cair) estão em `agente/README.md`.

---

## Convenções e arquitetura de código

O projeto mantém uma estrutura em camadas:

```text
presentation
application
domain
infrastructure
security
```

Na implementação atualmente disponível, a maior parte do código funcional está concentrada na camada:

```text
presentation
```

### Responsabilidades atuais

| Pacote | Responsabilidade atual |
|---|---|
| `app.presentation` | Rotas FastAPI, templates Jinja2, CSS e dados demonstrativos do frontend web |
| `app.application` | Estrutura reservada para casos de uso |
| `app.domain` | Estrutura reservada para regras e modelos do domínio |
| `app.infrastructure` | Estrutura reservada para infraestrutura e persistência |
| `app.security` | Estrutura reservada para mecanismos de segurança |

Funcionalidades ainda não implementadas não devem ser consideradas existentes apenas pela presença dessas pastas.

---

## Frontend web

O frontend do Centro de Administração foi reorganizado para facilitar manutenção e documentação sem alterar os fluxos demonstrativos já existentes.

### Templates

O documento HTML base está em:

```text
app/presentation/templates/base.html
```

As páginas administrativas utilizam:

```text
app/presentation/templates/admin/base_admin.html
```

A navegação lateral foi extraída para:

```text
app/presentation/templates/admin/partials/sidebar.html
```

Elementos compartilhados de apresentação estão em:

```text
app/presentation/templates/components/
```

Atualmente existem:

```text
icons.html
notice.html
```

Os SVGs reutilizados são centralizados em macros Jinja2.

Os ícones das categorias são selecionados por uma chave conhecida no contexto, evitando transportar strings SVG ou HTML diretamente pelas rotas.

### Dados demonstrativos

Os dados anteriormente misturados às rotas administrativas foram separados para:

```text
app/presentation/demo/admin_data.py
```

Esse módulo contém funções de construção de contexto para:

- dashboard;
- auditoria;
- relatórios;
- categorias;
- exceções;
- endpoints;
- usuários.

Cada função produz uma nova estrutura de dados demonstrativa por chamada.

Não há banco de dados, cache ou estado global criado por essa separação.

### CSS

O frontend mantém:

```text
/static/css/styles.css
```

como ponto único de entrada.

Esse arquivo importa, nesta ordem:

```text
tokens.css
base.css
auth.css
controls.css
layout.css
components.css
pages.css
```

Responsabilidades:

| Arquivo | Responsabilidade |
|---|---|
| `tokens.css` | Variáveis de cores, tipografia, espaços, dimensões, raios, sombras e transições |
| `base.css` | Reset e regras básicas |
| `auth.css` | Estrutura específica da autenticação |
| `controls.css` | Controles de formulário e botões |
| `layout.css` | Sidebar, topbar e estrutura administrativa |
| `components.css` | Cards, indicadores, tabelas, badges, filtros, avisos, paginação e outros componentes visuais |
| `pages.css` | Regras específicas de determinadas páginas |

A divisão do CSS foi realizada preservando:

- seletores;
- valores;
- ordem da cascata;
- classes existentes.

Não houve redesign da interface durante essa reorganização.

### Design tokens

Os principais tokens visuais ficam em:

```text
app/presentation/static/css/tokens.css
```

Exemplos:

| Token | Uso |
|---|---|
| `--color-primary` | Cor principal da interface |
| `--color-accent` | Links, foco e destaques |
| `--color-success` | Sinalização positiva |
| `--color-danger` | Sinalização de bloqueio ou erro |
| `--color-warning` | Alertas |
| `--color-bg` | Fundo da aplicação |
| `--color-surface` | Cards e superfícies |
| `--color-text` | Texto principal |
| `--color-text-muted` | Texto secundário |
| `--color-border` | Bordas e divisores |

Novos estilos devem preferencialmente reutilizar os tokens existentes em vez de introduzir valores visuais duplicados.

---

## Documentação do frontend

A documentação técnica específica do frontend web está disponível em:

```text
docs/frontend/
```

O conjunto inclui:

### `README.md`

Entrada para o guia do frontend, escopo e instruções de execução.

### `estrutura.md`

Documenta:

- organização dos arquivos;
- responsabilidade das pastas;
- fluxo de renderização;
- layouts;
- componentes;
- dados demonstrativos.

### `telas-e-dados.md`

Documenta as oito páginas existentes, incluindo:

- rotas;
- contextos;
- formulários;
- campos apresentados;
- navegação;
- comportamento real;
- elementos exclusivamente demonstrativos.

### `componentes-e-estilos.md`

Documenta:

- macros e includes;
- SVGs compartilhados;
- componentes visuais;
- design tokens;
- divisão do CSS;
- ordem da cascata.

### `verificacao-e-limitacoes.md`

Registra:

- verificações realizadas;
- comportamentos preservados;
- limitações;
- funcionalidades não implementadas.

Também existem arquivos JSON utilizados como registros das etapas de validação da refatoração.

---

## Limitações conhecidas

### Frontend web demonstrativo

O painel possui navegação e renderização funcional, mas diversos fluxos permanecem demonstrativos.

Não estão implementados nesta entrega:

- autenticação real;
- sessão de usuário;
- autorização por perfil;
- persistência em banco;
- filtros aplicados sobre dados reais;
- paginação real;
- exportação CSV;
- cadastro e edição de usuários;
- cadastro e remoção de exceções;
- persistência da configuração de categorias;
- atualização de política dos endpoints;
- desativação de endpoints;
- geração real de relatórios.

### Dados demonstrativos

Os dados apresentados no Centro de Administração são fictícios e existem apenas para sustentar a interface atual.

### Agente desktop

Fora do escopo desta entrega (frontend web) — ver `agente/README.md` para o
estado real do agente, que já tem interceptação de arquivos, motor de
inspeção e sincronização opcional com o Centro de Administração (HU-10)
implementados e testados de ponta a ponta.

### Camadas reservadas

As pastas:

```text
application/
domain/
infrastructure/
security/
```

ainda não possuem implementação funcional além da estrutura inicial.

### Responsividade

O frontend atual não foi reconstruído como projeto responsivo.

A refatoração realizada preservou a aparência existente em vez de introduzir novos breakpoints ou um novo layout mobile.

### Compatibilidade

O frontend utiliza HTML e CSS convencionais e foi projetado para execução em navegadores modernos.

Uma declaração formal de compatibilidade deve considerar as versões efetivamente verificadas no registro final de validação.

---

## Equipe

**Grupo Prevenção de vazamento de dados — UCB, 2026**

- Victor Nogueira da Nova Bonato
- Pedro Campos Canafístula
- Luiz Henrique Alves Rodrigues
- Lucas Ferreira Coelho
