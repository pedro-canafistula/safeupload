# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SafeUpload is an academic MVP prototype for accidental data leak prevention (DLP), built for the Software Analysis and Design course at Universidade Católica de Brasília.

The system inspects the text content of files looking for sensitive data (CPF, CNPJ, payment card, plaintext password) and returns one of three verdicts: **Aprovado**, **Bloqueado**, or **Rejeitado** (invalid format, size over limit, or analysis failure). It never forwards files to third parties and discards file contents after analysis.

**Two-component architecture** (decision #2 in `DOC_CHANGES.md`, mirroring Forcepoint/Symantec DLP):

1. **Desktop agent** — Windows app on user endpoints. Intercepts file operations, posts the content to the central server (`POST /api/inspect`), then blocks or releases the operation based on the response. **Not implemented** — `routes/agent.py` is an empty router.
2. **Admin center** — FastAPI + Jinja2 web app for administrators. **This is what exists today.**

The original "user uploads a file through a web page" model was abandoned and will not be implemented.

**Current state:** the admin center is complete as a **visual prototype** — every sidebar page is built and styled. There is no real authentication, no real inspection, and no database. All displayed data is mocked inside the route handlers. The app's text content is in **Portuguese (pt-BR)**.

## Running the App

```powershell
.\app\venv\Scripts\Activate.ps1     # venv is at app/venv (suboptimal — see "venv location" below)
uvicorn app.main:app --reload
```

Then visit http://localhost:8000 (redirects to `/admin/login`). Type anything in the form and click "Entrar" — it redirects to the dashboard without auth.

## What's Implemented

### Routes (all in `presentation/routes/admin.py`)

| Route | Method | Page | HU |
|---|---|---|---|
| `/` | GET | redirects to `/admin/login` | — |
| `/admin` | GET | redirects to `/admin/dashboard` | — |
| `/admin/login` | GET | login page | HU-06 |
| `/admin/login` | POST | stub: `303 See Other` → dashboard regardless of input | HU-06 |
| `/admin/dashboard` | GET | KPI cards, 7-day trend chart, top categories, recent inspections, category status, privacy notice | — |
| `/admin/auditoria` | GET | full inspection history — stat strip, filter bar, dense table, pagination | HU-04 |
| `/admin/endpoints` | GET | inventory of endpoints running the agent | — |
| `/admin/relatorios` | GET | report center | HU-09 |
| `/admin/categorias` | GET | detection category config with toggles | HU-07 |
| `/admin/excecoes` | GET | controlled allowlist | HU-08 |
| `/admin/usuarios` | GET | user and access-profile management (Administrador / Auditor) | HU-06 |

Every admin page is fully built — there are no `#` placeholders left in the sidebar.

### Tech Stack
- Python 3.11+ (running on 3.13)
- FastAPI + Uvicorn
- Jinja2 templates
- Pure HTML + CSS — no JS framework, no build step

### Sidebar nav (`base_admin.html`)
- **Operação:** Painel, Auditoria, Endpoints, Relatórios
- **Configuração:** Categorias de detecção, Lista de exceções, Usuários
- **Footer:** "Sair" → `/admin/login`

## Architecture (in code, not just docs)

The 5-package layered architecture is scaffolded, but only `presentation` has content:

```
app/
├── main.py                       # FastAPI entry point, static mount, router registration
├── presentation/                 # ✅ Has content
│   ├── __init__.py               # Shared Jinja2Templates instance
│   ├── routes/
│   │   ├── admin.py              # All admin routes (~570 lines) — holds mocked data dicts
│   │   └── agent.py              # Desktop-agent API (empty router — will hold POST /api/inspect)
│   ├── templates/
│   │   ├── base.html             # Generic minimal layout
│   │   └── admin/
│   │       ├── base_admin.html   # Sidebar + topbar layout (extended by every admin page)
│   │       ├── login.html
│   │       ├── dashboard.html
│   │       ├── audit.html
│   │       ├── endpoints.html
│   │       ├── reports.html
│   │       ├── categories.html
│   │       ├── allowlist.html
│   │       └── users.html
│   └── static/css/styles.css     # ALL styles, ~1500 lines — see "Design System" below
├── application/                  # Empty — will hold use case orchestration
├── domain/                       # Empty — will hold validators (CPF, CNPJ, card, password)
├── infrastructure/               # Empty — will hold extractors + SQLite repository
└── security/                     # Empty — will hold session, hash, CSRF, HMAC
```

## Design System (important)

All visual design lives as CSS variables in `:root` at the top of `styles.css`. When building a new page, **always reuse these tokens** instead of hardcoding values.

**Key tokens:**
- Brand: `--color-primary` `#1e3a5f` (plus `-dark`/`-light`), `--color-accent` `#3b82f6` (plus `-dark`)
- Status (DLP semantics): `--color-success` (Aprovado), `--color-danger` (Bloqueado), `--color-warning` (Rejeitado), each with `-bg` and `-text` variants
- Neutrals: `--color-bg` `#f8fafc`, `--color-surface` `#ffffff`, `--color-text`, `--color-text-muted`, `--color-text-soft`, `--color-border`, `--color-border-soft`
- Sidebar: dark navy `#0f172a` with custom `--sidebar-*` tokens, `--sidebar-width` `260px`
- Spacing scale: `--space-xs` through `--space-2xl`
- Radii: `--radius-sm`, `--radius-md`, `--radius-lg`, `--radius-full`
- Shadows: `--shadow-sm`, `--shadow-md`, `--shadow-lg`
- Type: `--font-sans`, `--font-mono`; transitions: `--transition-fast`

**Shared components (used across pages):**
- `.btn`, `.btn-primary`, `.btn-outline`, `.btn-block` with `.btn-icon` for SVG prefixes
- `.kpi-card` with `.kpi-icon-{primary,success,danger,warning}` variants
- `.card`, `.card-header`, `.card-body`, `.card-body-flush`, `.card-footer`, `.card-link`
- `.bar-chart` (CSS-only vertical) and `.hbar-list` (horizontal bars)
- `.data-table` with `.data-table-dense` variant
- `.badge-{approved,blocked,rejected}` and `.tag` (small neutral chip)
- `.stat-strip` (compact horizontal KPI bar)
- `.filter-bar` with `.filter-select`, `.filter-input`, `.filter-search`
- `.pagination` with `.pagination-btn`, `.pagination-ellipsis`
- `.source-chip` (audit table session ID display)
- `.icon-btn` (square ghost button for table actions)
- `.notice` (informational callout)
- `.segmented` (segmented control like the dashboard's "24h / 7 dias / 30 dias")
- `.status-list` / `.status-item` / `.status-tag-{on,off}`

**Page-specific component blocks** — each has its own labeled section at the bottom of `styles.css`: distribution bar + legend (reports), category config list + toggle (categories), allowlist (exceptions), role badge + status pill (users), report center (reports), endpoints table.

**Icons:** all inline SVGs, Lucide-style 24×24 outline. No icon font, no external dependency. Category icons are defined as `_ICON_*` string constants in `admin.py` and rendered with `| safe`.

## Mocked Data Pattern

In `routes/admin.py`, each route builds a `context` dict with mocked data and passes it to the template. When real persistence exists, replace these dicts with calls to application services. **Keep template variable names stable:**

| Route | Context keys (besides `active_page`) |
|---|---|
| `dashboard` | `kpis`, `trend`, `categories_top`, `categories_status`, `recent_events` |
| `audit_page` | `stats`, `events`, `pagination`, `filter_options` |
| `reports_page` | `recent_reports` |
| `categories_page` | `summary`, `categories` |
| `allowlist_page` | `stats`, `exceptions`, `filter_options` |
| `endpoints_page` | `stats`, `current_agent_version`, `endpoints`, `filter_options` |
| `users_page` | `stats`, `users`, `filter_options` |

## Conventions

- **URLs are in Portuguese** (`/admin/auditoria`, `/admin/categorias`) — matches the app language. Exception: `/admin/endpoints`, the accepted term in the domain.
- **Source code is in English** (Python identifiers, comments inside CSS), but **docstrings and user-facing strings are in Portuguese**
- **Active sidebar item** is controlled by the `active_page` context variable in each route (`"dashboard"`, `"audit"`, `"endpoints"`, `"reports"`, `"categories"`, `"allowlist"`, `"users"`)
- **`TemplateResponse` signature:** must use the modern form `templates.TemplateResponse(request, "path/template.html", context)` — Starlette ≥ 0.29 breaks the old `(name, {"request": request})` form
- **POST → GET redirects** use `status.HTTP_303_SEE_OTHER` (not `307`) so refreshing the destination page doesn't re-POST
- **Docstrings cross-reference the HU** they implement (see `audit_page`, `categories_page`)

## Key Design Decisions (already made — don't relitigate)

- **Desktop agent, not browser upload** — inspection happens transparently through a Windows agent that intercepts file operations. The admin center stays a web app. This contradicts the original documents; tracked as item 2 in `DOC_CHANGES.md`.
- **No login on the agent side** — only the admin center requires authentication, mirroring how Forcepoint/Symantec DLP agents work. Contradicts the original HU-06; tracked as item 1 in `DOC_CHANGES.md`.
- **Two access profiles** — Administrador (full access) and Auditor (read-only: Painel, Auditoria, Relatórios). Not in the original requirements; tracked as item 3 in `DOC_CHANGES.md`.
- **Color scheme** chosen: navy `#1e3a5f` primary + blue `#3b82f6` accent + semantic status colors. User approved.
- **Stack** is pure HTML/CSS/Jinja — no React, no Tailwind, no build step.
- **venv location** is `app/venv/` (not ideal — convention is project root). The user knows; will move when convenient.

## Pending Doc Updates

See `DOC_CHANGES.md` for the running list (4 open items). Update that file (don't edit the .docx files) whenever a design decision contradicts the official documents.

## Documents of Record

`Documentos/` contains the official artifacts in Portuguese, as `.docx`:
- **SafeUpload - Documento de Visao.docx** — scope, stakeholders, needs
- **SafeUpload - Documento de Requisitos de Software.docx** — HU-01 to HU-10, RN-001 to RN-010, RNF-01 to RNF-11
- **SafeUpload - Documento de Arquitetura de Software.docx** — 4+1 views, decisions, UML, data model

Also in the folder: `dlp-apresentacao.pdf` (slide deck), the UML diagrams (`SafeUpload - Diagrama.png`, `SafeUpload - Diagrama - Endpoint.png`), and `imagens/` with screenshots of every implemented page.

When implementing a feature, cross-reference the relevant HU and RN.

## What's NOT Implemented Yet (high level)

- The entire desktop agent (Windows app, file interception, tray notifications)
- The inspection API (`POST /api/inspect` — `agent.py` is an empty router)
- Real authentication and session handling
- File content extraction + detection rules (`domain`, `application`, `infrastructure`, `security` are all empty)
- Persistence (SQLite tables: USERS, CATEGORIES, AUDIT_EVENTS, ALLOWLIST)
- Every form action and filter on the admin pages — they render, but submit nowhere
