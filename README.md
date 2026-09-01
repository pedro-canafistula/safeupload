# SafeUpload

Protótipo acadêmico de sistema de **prevenção de vazamento acidental de dados** (DLP). Desenvolvido na disciplina de Análise e Projeto de Software da Universidade Católica de Brasília.

> Versão atual: **0.1.0** — protótipo visual. O Centro de Administração está construído em todas as suas telas, mas ainda sem autenticação, inspeção ou banco de dados. Todos os dados exibidos são fictícios.

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
- [Documentos de referência](#documentos-de-referência)
- [Limitações conhecidas](#limitações-conhecidas)
- [Equipe](#equipe)

---

## Visão geral

O SafeUpload inspeciona o conteúdo textual de arquivos em busca de dados sensíveis — CPF, CNPJ, cartão de pagamento e indícios de senha em texto claro — e classifica cada inspeção em três estados:

| Resultado     | Significado                                                                  |
|---------------|------------------------------------------------------------------------------|
| **Aprovado**  | As regras ativas não encontraram ocorrências no conteúdo textual extraível.   |
| **Bloqueado** | Pelo menos uma ocorrência válida foi identificada.                            |
| **Rejeitado** | Formato inválido, tamanho acima do limite ou falha na análise.                |

O sistema **nunca encaminha arquivos para serviços externos** e descarta o conteúdo do arquivo após a análise.

---

## Arquitetura do produto

O SafeUpload é um sistema de **dois componentes**, seguindo o modelo de soluções DLP corporativas (Forcepoint, Symantec):

**1. Agente desktop** *(ainda não implementado)*
Aplicação Windows instalada nos endpoints dos usuários. Intercepta operações de arquivo (salvar, compartilhar, enviar), submete o conteúdo ao servidor central para inspeção via API (`POST /api/inspect`) e então bloqueia ou libera a operação conforme a resposta. O usuário final não faz upload manual e não se autentica.

**2. Centro de Administração** *(implementado como protótipo visual)*
Aplicação web usada pelos administradores para gestão de endpoints, auditoria de inspeções, configuração de categorias de detecção, lista de exceções e usuários. Exige login.

> O modelo original descrito nos documentos — usuário acessa uma página web e carrega o arquivo manualmente — **foi descartado**. Decisão registrada em [`DOC_CHANGES.md`](./DOC_CHANGES.md) (item 2).

---

## Tecnologias

| Camada                     | Tecnologia                     |
|----------------------------|--------------------------------|
| Linguagem                  | Python 3.11+                   |
| Servidor web               | FastAPI + Uvicorn              |
| Renderização HTML          | Jinja2                         |
| Frontend                   | HTML5 + CSS3 puro              |
| Persistência (futura)      | SQLite                         |
| Agente desktop (futuro)    | a definir                      |

Não há frameworks JavaScript nem etapa de build. Toda a interface é renderizada no servidor com templates Jinja2.

---

## Pré-requisitos

- **Python 3.11** ou superior (o projeto roda em 3.13)
- **pip**
- Navegador moderno (Chrome, Firefox ou Edge)

---

## Instalação e execução

### 1. Criar o ambiente virtual

A partir da raiz do projeto:

```powershell
python -m venv venv
```

> **Nota:** o ambiente da máquina de desenvolvimento atual está em `app/venv/` — fora da convenção. Se você usa esse ambiente, ative com `.\app\venv\Scripts\Activate.ps1`. Ambos os caminhos estão no `.gitignore`.

### 2. Ativar o ambiente virtual

**PowerShell (Windows):**
```powershell
.\venv\Scripts\Activate.ps1
```

**CMD (Windows):**
```cmd
.\venv\Scripts\activate.bat
```

**Bash (Linux/macOS):**
```bash
source venv/bin/activate
```

### 3. Instalar as dependências

```powershell
pip install -r requirements.txt
```

### 4. Iniciar o servidor

```powershell
uvicorn app.main:app --reload
```

A aplicação fica disponível em **http://localhost:8000**, que redireciona para a tela de login. Como não há autenticação real, qualquer entrada no formulário leva ao painel. O parâmetro `--reload` reinicia o servidor a cada alteração em arquivo Python ou template.

### 5. Encerrar o servidor

`Ctrl + C` no terminal onde o Uvicorn está rodando.

---

## Estrutura do projeto

```
SafeUpload/
├── app/                          # Pacote principal da aplicação
│   ├── __init__.py
│   ├── main.py                   # Ponto de entrada do FastAPI
│   ├── presentation/             # Camada de apresentação (UI + rotas)
│   │   ├── __init__.py           # Configuração compartilhada do Jinja2
│   │   ├── routes/
│   │   │   ├── admin.py          # Rotas do Centro de Administração
│   │   │   └── agent.py          # API do agente desktop (vazia por enquanto)
│   │   ├── templates/
│   │   │   ├── base.html            # Layout base genérico
│   │   │   └── admin/
│   │   │       ├── base_admin.html  # Layout com sidebar e topbar
│   │   │       ├── login.html       # Login
│   │   │       ├── dashboard.html   # Painel principal
│   │   │       ├── audit.html       # Histórico de auditoria
│   │   │       ├── endpoints.html   # Inventário de endpoints
│   │   │       ├── reports.html     # Central de relatórios
│   │   │       ├── categories.html  # Categorias de detecção
│   │   │       ├── allowlist.html   # Lista de exceções
│   │   │       └── users.html       # Usuários e perfis
│   │   └── static/
│   │       └── css/
│   │           └── styles.css    # Design tokens + estilos globais
│   ├── application/              # (Reservada) orquestração de casos de uso
│   ├── domain/                   # (Reservada) modelos e validadores de negócio
│   ├── infrastructure/           # (Reservada) extratores e persistência
│   └── security/                 # (Reservada) sessão, hash, CSRF, HMAC
├── Documentos/                   # Documentos oficiais (.docx), diagramas e capturas de tela
├── CLAUDE.md                     # Guia para o assistente Claude Code
├── DOC_CHANGES.md                # Mudanças pendentes na documentação oficial
├── README.md                     # Este arquivo
└── requirements.txt              # Dependências Python
```

As pastas marcadas como **(Reservada)** contêm apenas `__init__.py` — serão preenchidas conforme a implementação avançar.

---

## Rotas disponíveis

### Centro de Administração (`/admin`)

| Rota                  | Método | Descrição                                                        | HU     |
|-----------------------|--------|------------------------------------------------------------------|--------|
| `/admin`              | GET    | Redireciona para `/admin/dashboard`                              | —      |
| `/admin/login`        | GET    | Página de login                                                  | HU-06  |
| `/admin/login`        | POST   | Stub — redireciona ao painel independentemente da entrada        | HU-06  |
| `/admin/dashboard`    | GET    | Painel com indicadores, tendência e inspeções recentes           | —      |
| `/admin/auditoria`    | GET    | Histórico completo de inspeções                                  | HU-04  |
| `/admin/endpoints`    | GET    | Inventário dos endpoints com agente instalado                    | —      |
| `/admin/relatorios`   | GET    | Central de relatórios                                            | HU-09  |
| `/admin/categorias`   | GET    | Configuração das categorias de detecção                          | HU-07  |
| `/admin/excecoes`     | GET    | Lista de exceções controladas (allowlist)                        | HU-08  |
| `/admin/usuarios`     | GET    | Gestão de usuários e perfis de acesso                            | HU-06  |

Todas as telas exibem dados fictícios definidos em `routes/admin.py`. Formulários e filtros são visuais — não submetem para lugar nenhum.

### API do agente

| Rota | Método | Descrição |
|------|--------|-----------|
| `/`  | GET    | Redireciona para `/admin/login` (temporário) |

> `POST /api/inspect` — contrato de inspeção entre o agente desktop e o servidor. **Ainda não implementado**; `agent.py` contém apenas o router vazio.

---

## Convenções e arquitetura de código

O código segue a **arquitetura em camadas** definida na Seção 4.3 do Documento de Arquitetura. A dependência principal é unidirecional:

```
presentation  →  application  →  domain  ←  infrastructure
                     ↑
                  security (suporte transversal)
```

| Pacote               | Responsabilidade                                                                                    |
|----------------------|-----------------------------------------------------------------------------------------------------|
| `app.presentation`   | Rotas HTTP (FastAPI), templates Jinja2, páginas do Centro de Administração e API do agente.         |
| `app.application`    | Coordenação dos casos de uso: receber conteúdo, orquestrar extração e validação, gravar auditoria.   |
| `app.domain`         | Modelos do negócio, validadores (CPF, CNPJ, cartão, senha), enumerações de resultado, mascaramento.  |
| `app.infrastructure` | Extratores por formato (PDF, DOCX, XLSX...), repositório SQLite, operações de persistência.          |
| `app.security`       | Hash de senha (PBKDF2), HMAC para allowlist, token CSRF, controle de sessão.                         |

### Perfis de acesso

| Perfil            | Acesso                                                                     |
|-------------------|----------------------------------------------------------------------------|
| **Administrador** | Todas as telas, incluindo configuração de categorias, exceções e usuários.  |
| **Auditor**       | Somente leitura de Painel, Auditoria e Relatórios.                          |

Registrado em [`DOC_CHANGES.md`](./DOC_CHANGES.md) (item 3) — ainda não consta nos documentos oficiais.

### Design tokens (CSS)

Todas as cores, espaçamentos, raios e sombras estão definidos como variáveis CSS em `:root` no arquivo `styles.css`. Para criar novas páginas com aparência consistente, use sempre as variáveis (`var(--color-primary)`, `var(--space-md)`) em vez de valores fixos.

| Token                | Hex       | Uso                                  |
|----------------------|-----------|--------------------------------------|
| `--color-primary`    | `#1e3a5f` | Marca, cabeçalhos, botões primários  |
| `--color-accent`     | `#3b82f6` | Links, foco, destaques               |
| `--color-success`    | `#10b981` | Resultado **Aprovado**               |
| `--color-danger`     | `#ef4444` | Resultado **Bloqueado**              |
| `--color-warning`    | `#f59e0b` | Resultado **Rejeitado**              |
| `--color-bg`         | `#f8fafc` | Fundo das páginas                    |
| `--color-surface`    | `#ffffff` | Cartões, painéis                     |
| `--color-text`       | `#1e293b` | Texto principal                      |
| `--color-text-muted` | `#64748b` | Texto secundário                     |
| `--color-border`     | `#e2e8f0` | Bordas e divisores                   |

Os ícones são SVGs inline no estilo Lucide (24×24, contorno). Não há fonte de ícones nem dependência externa.

---

## Documentos de referência

A pasta `Documentos/` contém os artefatos acadêmicos oficiais, em `.docx`:

- **Documento de Visão** — escopo, partes interessadas, necessidades e funcionalidades.
- **Documento de Requisitos** — histórias de usuário (HU-01 a HU-10), regras de negócio (RN-001 a RN-010), requisitos não funcionais (RNF-01 a RNF-11).
- **Documento de Arquitetura** — visões 4+1, decisões arquiteturais, diagramas UML, modelo de dados.

Também estão na pasta a apresentação (`dlp-apresentacao.pdf`), os diagramas UML em PNG e a subpasta `imagens/` com capturas de todas as telas implementadas.

Mudanças no escopo ou em decisões já documentadas devem ser registradas em [`DOC_CHANGES.md`](./DOC_CHANGES.md) **antes** de serem aplicadas aos documentos.

---

## Limitações conhecidas

- **Protótipo visual:** nenhuma tela tem funcionalidade. Não há autenticação, inspeção nem persistência — os dados exibidos são fictícios.
- **Agente desktop inexistente:** o componente que efetivamente intercepta arquivos ainda não foi desenvolvido.
- **Camadas vazias:** `application`, `domain`, `infrastructure` e `security` contêm apenas `__init__.py`.
- **OCR fora do escopo:** o MVP não interpreta texto em imagens.
- **Sem integrações externas:** o SafeUpload não encaminha arquivos para nuvem, e-mail ou outros sistemas.
- **Heurística de senha:** a detecção de senha em texto claro pode produzir falsos positivos e falsos negativos.

---

## Equipe

**Grupo Prevenção de vazamento de dados** — UCB, 2026

- Victor Nogueira da Nova Bonato
- Pedro Campos Canafístula
- Luiz Henrique Alves Rodrigues
- Lucas Ferreira Coelho
