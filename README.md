# SafeUpload

Protótipo acadêmico de aplicação web para **prevenção de vazamento acidental de dados** (DLP) em arquivos digitais. Desenvolvido na disciplina de Análise e Projeto de Software da Universidade Católica de Brasília.

> Versão atual: **0.1.0** (protótipo visual — UI sem funcionalidades de inspeção).

---

## Sumário

- [Visão geral](#visão-geral)
- [Tecnologias](#tecnologias)
- [Pré-requisitos](#pré-requisitos)
- [Instalação e execução](#instalação-e-execução)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Rotas disponíveis](#rotas-disponíveis)
- [Convenções e arquitetura](#convenções-e-arquitetura)
- [Documentos de referência](#documentos-de-referência)
- [Limitações conhecidas](#limitações-conhecidas)

---

## Visão geral

O SafeUpload permite que um usuário envie um arquivo pela interface web, recebe o arquivo no servidor central, extrai o texto e aplica regras de detecção para identificar dados sensíveis (CPF, CNPJ, cartão de pagamento e indícios de senha em texto claro). O resultado é classificado em três estados:

| Resultado    | Significado                                                                 |
|--------------|------------------------------------------------------------------------------|
| **Aprovado** | As regras ativas não encontraram ocorrências no conteúdo textual extraível.  |
| **Bloqueado**| Pelo menos uma ocorrência válida foi identificada.                           |
| **Rejeitado**| Formato inválido, tamanho acima do limite ou falha na análise.               |

O sistema **nunca encaminha arquivos automaticamente** para serviços externos. O upload significa apenas envio ao SafeUpload para inspeção.

---

## Tecnologias

| Camada                | Tecnologia                                |
|-----------------------|-------------------------------------------|
| Linguagem             | Python 3.11+                              |
| Servidor web          | FastAPI + Uvicorn                         |
| Renderização HTML     | Jinja2                                    |
| Persistência (futura) | SQLite                                    |
| Frontend              | HTML5, CSS3 puro, JavaScript vanilla      |

Não há frameworks JavaScript (React, Vue etc.). Toda a interface é renderizada no servidor com templates Jinja2.

---

## Pré-requisitos

- **Python 3.11** ou superior
- **pip** (gerenciador de pacotes Python)
- Navegador moderno (Chrome, Firefox ou Edge)

---

## Instalação e execução

### 1. Criar o ambiente virtual

A partir da raiz do projeto:

```powershell
python -m venv venv
```

> O ambiente foi criado em `./venv/` (recomendado). Caso prefira outro local, ajuste os comandos abaixo conforme necessário.

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

A aplicação ficará disponível em **http://localhost:8000**. O parâmetro `--reload` faz o servidor reiniciar automaticamente sempre que um arquivo Python ou template for alterado.

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
│   │   ├── routes/               # Rotas HTTP organizadas por área
│   │   │   ├── admin.py          # Rotas do Centro de Administração
│   │   │   └── agent.py          # Rotas da interface pública (agente DLP)
│   │   ├── templates/            # Templates Jinja2
│   │   │   ├── base.html         # Layout base (genérico)
│   │   │   └── admin/            # Templates do Centro de Administração
│   │   │       ├── base_admin.html  # Layout com sidebar e topbar
│   │   │       ├── login.html       # Página de login
│   │   │       ├── dashboard.html   # Painel principal
│   │   │       └── audit.html       # Histórico de auditoria
│   │   └── static/               # Arquivos estáticos servidos em /static
│   │       └── css/
│   │           └── styles.css    # Design tokens + estilos globais
│   ├── application/              # (Reservada) orquestração de casos de uso
│   ├── domain/                   # (Reservada) modelos e validadores de negócio
│   ├── infrastructure/           # (Reservada) extratores e persistência
│   └── security/                 # (Reservada) sessão, hash, CSRF, HMAC
├── Documentos/                   # PDFs oficiais (Visão, Requisitos, Arquitetura)
├── CLAUDE.md                     # Guia para o assistente Claude Code
├── DOC_CHANGES.md                # Mudanças pendentes na documentação oficial
├── README.md                     # Este arquivo
└── requirements.txt              # Dependências Python
```

As pastas marcadas como **(Reservada)** estão vazias no protótipo visual atual e serão preenchidas conforme a implementação avançar.

---

## Rotas disponíveis

### Centro de Administração (`/admin`)

| Rota                  | Método | Descrição                                              |
|-----------------------|--------|--------------------------------------------------------|
| `/admin`              | GET    | Redireciona para `/admin/dashboard`                    |
| `/admin/login`        | GET    | Página de login do administrador                       |
| `/admin/login`        | POST   | Envio do formulário (stub — redireciona ao painel)     |
| `/admin/dashboard`    | GET    | Painel principal com indicadores e inspeções recentes  |
| `/admin/auditoria`    | GET    | Histórico completo de inspeções (HU-04)                |

### Interface do agente (público)

> A interface do agente (upload + resultado) **não exige autenticação**. Decisão registrada em [`DOC_CHANGES.md`](./DOC_CHANGES.md).

| Rota | Método | Descrição          |
|------|--------|--------------------|
| `/`  | GET    | Redireciona para `/admin/login` (temporário, até a UI do agente existir) |

---

## Convenções e arquitetura

O código segue a **arquitetura em camadas** definida na Seção 4.3 do Documento de Arquitetura. A dependência principal é unidirecional:

```
presentation  →  application  →  domain  ←  infrastructure
                     ↑
                  security (suporte transversal)
```

| Pacote              | Responsabilidade                                                                                   |
|---------------------|----------------------------------------------------------------------------------------------------|
| `app.presentation`  | Rotas HTTP (FastAPI), templates Jinja2, formulários, páginas acessadas pelo navegador.             |
| `app.application`   | Coordenação dos casos de uso: receber arquivo, orquestrar extração e validação, gravar auditoria. |
| `app.domain`        | Modelos do negócio, validadores (CPF, CNPJ, cartão, senha), enumerações de resultado, mascaramento. |
| `app.infrastructure`| Extratores por formato (PDF, DOCX, XLSX...), repositório SQLite, operações de persistência.        |
| `app.security`      | Hash de senha (PBKDF2), HMAC para allowlist, token CSRF, controle de sessão.                       |

### Design tokens (CSS)

Todas as cores, espaçamentos, raios e sombras estão definidos como variáveis CSS em `:root` no arquivo `styles.css`. Para criar novas páginas com aparência consistente, use sempre as variáveis (`var(--color-primary)`, `var(--space-md)`, etc.) em vez de valores fixos.

**Paleta:**

| Token                | Hex      | Uso                                         |
|----------------------|----------|---------------------------------------------|
| `--color-primary`    | `#1e3a5f`| Marca, cabeçalhos, botões primários         |
| `--color-accent`     | `#3b82f6`| Links, foco, destaques                      |
| `--color-success`    | `#10b981`| Resultado **Aprovado**                      |
| `--color-danger`     | `#ef4444`| Resultado **Bloqueado**                     |
| `--color-warning`    | `#f59e0b`| Resultado **Rejeitado**                     |
| `--color-bg`         | `#f8fafc`| Fundo das páginas                           |
| `--color-surface`    | `#ffffff`| Cartões, painéis                            |
| `--color-text`       | `#1e293b`| Texto principal                             |
| `--color-text-muted` | `#64748b`| Texto secundário                            |
| `--color-border`     | `#e2e8f0`| Bordas e divisores                          |

---

## Documentos de referência

A pasta `Documentos/` contém os artefatos acadêmicos oficiais:

- **Documento de Visão (v2.0)** — escopo, partes interessadas, necessidades e funcionalidades.
- **Documento de Requisitos (v2.0)** — histórias de usuário (HU-01 a HU-10), regras de negócio (RN-001 a RN-010), requisitos não funcionais (RNF-01 a RNF-11).
- **Documento de Arquitetura (v2.0)** — visões 4+1, decisões arquiteturais, diagramas UML, modelo de dados.

Mudanças no escopo ou em decisões já documentadas devem ser registradas em [`DOC_CHANGES.md`](./DOC_CHANGES.md) **antes** de serem aplicadas aos PDFs.

---

## Limitações conhecidas

- **Protótipo visual:** as páginas atuais não possuem funcionalidade — formulários não autenticam, dados exibidos no painel são fictícios.
- **OCR fora do escopo:** o MVP não interpreta texto em imagens nem realiza reconhecimento óptico de caracteres.
- **Sem integrações externas:** o SafeUpload não encaminha arquivos para nuvem, e-mail ou outros sistemas.
- **Heurística de senha:** a detecção de senha em texto claro pode produzir falsos positivos e falsos negativos.

---

## Equipe

**Grupo Prevenção de vazamento de dados** — UCB, 2026
- Victor Nogueira da Nova Bonato
- Pedro Campos Canafístula
- Luiz Henrique Alves Rodrigues
- Lucas Ferreira Coelho
