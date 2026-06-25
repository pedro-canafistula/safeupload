# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SafeUpload is an academic MVP prototype (Python web app) for accidental data leak prevention. Users submit files via a browser, the server inspects the text content for sensitive data patterns, and returns **approved**, **blocked**, or **rejected**. The system never forwards files to third parties and discards file contents after analysis.

**Current state:** Visual prototype in progress. The application runs and the admin login + dashboard + audit pages are implemented as UI-only (no real authentication, no real inspection, no database). All displayed data is mocked in route handlers. The text content of the app is in **Portuguese (pt-BR)**.

## Running the App

```powershell
.\app\venv\Scripts\Activate.ps1     # venv is at app/venv (suboptimal — see README "venv location")
uvicorn app.main:app --reload
```

Then visit http://localhost:8000 (redirects to `/admin/login`). Type anything in the form and click "Entrar" — it redirects to the dashboard without auth.

## What's Implemented

### Routes
- `GET /` → redirects to `/admin/login`
- `GET /admin` → redirects to `/admin/dashboard`
- `GET /admin/login` — login page
- `POST /admin/login` — stub: returns `303 See Other` redirect to `/admin/dashboard` regardless of input
- `GET /admin/dashboard` — main panel with KPI cards, 7-day trend chart, top categories, recent inspections, active categories status, privacy notice
- `GET /admin/auditoria` — full inspection history with stat strip, filter bar, dense data table, pagination

### Tech Stack (matches docs)
- Python 3.11+ (running on 3.13)
- FastAPI + Uvicorn
- Jinja2 templates
- Pure HTML + CSS (no JS framework, no build step)

### Sidebar nav items (most are placeholders linking to `#`)
- **Operação:** Painel ✅, Auditoria ✅, Relatórios ⏳
- **Configuração:** Categorias de detecção ⏳, Lista de exceções ⏳, Usuários ⏳

## Architecture (in code, not just docs)

The 5-package layered architecture is now scaffolded:

```
app/
├── main.py                       # FastAPI entry point
├── presentation/                 # ✅ Has content
│   ├── __init__.py               # Shared Jinja2Templates instance
│   ├── routes/
│   │   ├── admin.py              # All admin routes — currently holds mocked data dicts
│   │   └── agent.py              # Public DLP UI routes (empty for now)
│   ├── templates/
│   │   ├── base.html             # Generic minimal layout
│   │   └── admin/
│   │       ├── base_admin.html   # Sidebar + topbar layout (extended by every admin page)
│   │       ├── login.html
│   │       ├── dashboard.html
│   │       └── audit.html
│   └── static/css/styles.css     # ALL styles — see "Design System" below
├── application/                  # Empty — will hold use case orchestration
├── domain/                       # Empty — will hold validators (CPF, CNPJ, card, password)
├── infrastructure/               # Empty — will hold extractors + SQLite repository
└── security/                     # Empty — will hold session, hash, CSRF, HMAC
```

## Design System (important)

All visual design lives as CSS variables in `:root` at the top of `styles.css`. When building a new page, **always reuse these tokens** instead of hardcoding values.

**Key tokens:**
- Brand: `--color-primary` `#1e3a5f`, `--color-accent` `#3b82f6`
- Status (DLP semantics): `--color-success` (Aprovado), `--color-danger` (Bloqueado), `--color-warning` (Rejeitado), each with `-bg` and `-text` variants
- Neutrals: `--color-bg` `#f8fafc`, `--color-surface` `#ffffff`, `--color-text`, `--color-text-muted`, `--color-text-soft`, `--color-border`, `--color-border-soft`
- Sidebar: dark navy `#0f172a` with custom `--sidebar-*` tokens
- Spacing scale: `--space-xs` through `--space-2xl`
- Radii: `--radius-sm`, `--radius-md`, `--radius-lg`, `--radius-full`
- Shadows: `--shadow-sm`, `--shadow-md`, `--shadow-lg`

**Reusable components already styled:**
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

**Icons:** all inline SVGs, Lucide-style 24×24 outline. No icon font, no external dependency.

## Mocked Data Pattern

In `routes/admin.py`, each route builds a `context` dict with mocked data and passes it to the template. When real persistence exists, replace these dicts with calls to application services. Keep template variable names stable.

## Conventions

- **URLs are in Portuguese** (`/admin/auditoria`, `/admin/categorias`) — matches the app language
- **Source code is in English** (Python identifiers, comments inside CSS), but **docstrings and user-facing strings are in Portuguese**
- **Active sidebar item** is controlled by the `active_page` context variable in each route (e.g. `"dashboard"`, `"audit"`)
- **`TemplateResponse` signature:** must use the modern form `templates.TemplateResponse(request, "path/template.html", context)` — Starlette ≥ 0.29 breaks the old `(name, {"request": request})` form
- **POST → GET redirects** use `status.HTTP_303_SEE_OTHER` (not `307`) so refreshing the destination page doesn't re-POST

## Key Design Decisions (already made — don't relitigate)

- **No login on the agent UI** — the public file-upload interface is open, mirroring how Forcepoint/Symantec DLP agents work. Only the admin center requires login. This contradicts the original HU-06 in the requirements doc and is tracked in `DOC_CHANGES.md`.
- **Color scheme** chosen: navy `#1e3a5f` primary + blue `#3b82f6` accent + semantic status colors. User approved.
- **Stack** is pure HTML/CSS/Jinja — no React, no Tailwind, no build step.
- **venv location** is `app/venv/` (not ideal — convention is project root). The user knows; will move when convenient.

## Pending Doc Updates

See `DOC_CHANGES.md` for the running list. Update this file (don't edit the PDFs) whenever a design decision contradicts the official documents.

## Documents of Record

`Documentos/` contains the official artifacts in Portuguese:
- **Documento de Visão** (v2.0) — scope, stakeholders, needs
- **Documento de Requisitos** (v2.0) — HU-01 to HU-10, RN-001 to RN-010, RNF-01 to RNF-11
- **Documento de Arquitetura** (v2.0) — 4+1 views, decisions, UML, data model

When implementing a feature, cross-reference the relevant HU and RN — the docstrings in `admin.py` already do this for `audit_page`.

## What's NOT Implemented Yet (high level)

- Real authentication
- File upload + inspection (entire `domain`, `application`, `infrastructure`, `security` packages are empty)
- Persistence (SQLite tables: USERS, CATEGORIES, AUDIT_EVENTS, ALLOWLIST)
- Admin pages: Categorias, Lista de exceções, Usuários, Relatórios
- The entire agent UI (public file submission interface)
