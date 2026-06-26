"""
Rotas do Centro de Administração.

Todas as rotas deste módulo são prefixadas com ``/admin`` e devem ser
restritas ao perfil administrador (controle de acesso será adicionado
quando a camada de segurança for implementada).

Durante a fase de protótipo visual, as páginas exibem **dados fictícios**
gerados aqui mesmo. Esses dados serão substituídos por consultas reais ao
banco quando os repositórios da camada de infraestrutura existirem.
"""

from fastapi import APIRouter, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from app.presentation import templates

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("", include_in_schema=False)
async def admin_root():
    """Redireciona ``/admin`` para o painel principal."""
    return RedirectResponse(url="/admin/dashboard")


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Exibe a tela de login do Centro de Administração."""
    return templates.TemplateResponse(request, "admin/login.html")


@router.post("/login", include_in_schema=False)
async def login_submit():
    """Stub do envio do formulário de login.

    No protótipo visual ainda não há validação de credenciais — qualquer
    envio redireciona para o painel. Quando a camada de segurança existir,
    este handler passará a validar e-mail/senha, abrir sessão e definir
    o cookie correspondente.

    Usa o código HTTP 303 (See Other) para converter o POST em GET,
    evitando que o navegador reenvie o formulário ao recarregar a página
    de destino.
    """
    return RedirectResponse(
        url="/admin/dashboard",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# ---------------------------------------------------------------------------
# Painel
# ---------------------------------------------------------------------------

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Exibe o painel principal com indicadores e inspeções recentes.

    Os dados retornados aqui são fictícios e existem apenas para demonstrar
    o layout. Quando a camada de infraestrutura existir, este endpoint
    passará a consultar o banco e o serviço de aplicação.
    """
    context = {
        "active_page": "dashboard",
        "kpis": {
            "total":    {"value": "1.247", "trend": "+12% vs. semana anterior", "trend_kind": "up"},
            "blocked":  {"value": "89",    "trend": "7,1% do total",            "trend_kind": "neutral"},
            "approved": {"value": "1.135", "trend": "91,0% do total",           "trend_kind": "neutral"},
            "rejected": {"value": "23",    "trend": "1,8% do total",            "trend_kind": "neutral"},
        },
        "trend": [
            {"label": "Seg", "value": 152, "percentage": 69},
            {"label": "Ter", "value": 178, "percentage": 81},
            {"label": "Qua", "value": 198, "percentage": 90},
            {"label": "Qui", "value": 187, "percentage": 85},
            {"label": "Sex", "value": 220, "percentage": 100},
            {"label": "Sáb", "value": 145, "percentage": 66},
            {"label": "Dom", "value": 167, "percentage": 76},
        ],
        "categories_top": [
            {"name": "CPF",                  "value": 62, "percentage": 100},
            {"name": "Senha em texto claro", "value": 41, "percentage": 66},
            {"name": "CNPJ",                 "value": 28, "percentage": 45},
            {"name": "Cartão de pagamento",  "value": 14, "percentage": 23},
        ],
        "categories_status": [
            {"code": "CPF",      "label": "CPF",                  "enabled": True},
            {"code": "CNPJ",     "label": "CNPJ",                 "enabled": True},
            {"code": "CARD",     "label": "Cartão de pagamento",  "enabled": True},
            {"code": "PASSWORD", "label": "Senha em texto claro", "enabled": True},
        ],
        "recent_events": [
            {"time": "13:42", "filename": "relatorio_clientes_q2.xlsx", "size": "2,3 MB",
             "result_kind": "blocked",  "result_label": "Bloqueado",
             "categories": ["CPF", "CNPJ"]},
            {"time": "13:38", "filename": "proposta_comercial.pdf",     "size": "1,1 MB",
             "result_kind": "approved", "result_label": "Aprovado",
             "categories": []},
            {"time": "13:35", "filename": "dados_funcionarios.csv",     "size": "856 KB",
             "result_kind": "blocked",  "result_label": "Bloqueado",
             "categories": ["CPF"]},
            {"time": "13:30", "filename": "apresentacao_resultados.pdf","size": "4,2 MB",
             "result_kind": "approved", "result_label": "Aprovado",
             "categories": []},
            {"time": "13:24", "filename": "backup_credenciais.txt",     "size": "12 KB",
             "result_kind": "blocked",  "result_label": "Bloqueado",
             "categories": ["Senha em texto claro"]},
            {"time": "13:18", "filename": "imagem_logo.png",            "size": "—",
             "result_kind": "rejected", "result_label": "Rejeitado",
             "categories": []},
        ],
    }
    return templates.TemplateResponse(request, "admin/dashboard.html", context)


# ---------------------------------------------------------------------------
# Auditoria (HU-04)
# ---------------------------------------------------------------------------

@router.get("/auditoria", response_class=HTMLResponse)
async def audit_page(request: Request):
    """Exibe o histórico completo de inspeções (HU-04).

    Conforme as regras de negócio (RN-006, RN-007), o log contém apenas
    metadados, resultado, categorias detectadas e — quando necessário —
    trechos mascarados. **Valores reais nunca aparecem nesta página**.

    Os dados aqui são fictícios; serão substituídos por uma consulta ao
    repositório de auditoria quando a camada de infraestrutura existir.
    """
    context = {
        "active_page": "audit",
        "stats": {
            "total":    "1.247",
            "blocked":  "89",
            "approved": "1.135",
            "rejected": "23",
        },
        "events": [
            {"datetime": "23/06/2026 13:42:15", "source": "Sessão a3f9-4c2e",
             "filename": "relatorio_clientes_q2.xlsx", "size": "2,3 MB",
             "result_kind": "blocked",  "result_label": "Bloqueado",
             "categories": ["CPF", "CNPJ"]},
            {"datetime": "23/06/2026 13:38:02", "source": "Sessão a3f9-4c2e",
             "filename": "proposta_comercial.pdf", "size": "1,1 MB",
             "result_kind": "approved", "result_label": "Aprovado",
             "categories": []},
            {"datetime": "23/06/2026 13:35:48", "source": "Sessão 7c2a-8e1d",
             "filename": "dados_funcionarios.csv", "size": "856 KB",
             "result_kind": "blocked",  "result_label": "Bloqueado",
             "categories": ["CPF"]},
            {"datetime": "23/06/2026 13:30:11", "source": "Sessão 7c2a-8e1d",
             "filename": "apresentacao_resultados.pdf", "size": "4,2 MB",
             "result_kind": "approved", "result_label": "Aprovado",
             "categories": []},
            {"datetime": "23/06/2026 13:24:55", "source": "Sessão e1d7-9f3b",
             "filename": "backup_credenciais.txt", "size": "12 KB",
             "result_kind": "blocked",  "result_label": "Bloqueado",
             "categories": ["Senha em texto claro"]},
            {"datetime": "23/06/2026 13:18:30", "source": "Sessão e1d7-9f3b",
             "filename": "imagem_logo.png", "size": "—",
             "result_kind": "rejected", "result_label": "Rejeitado",
             "categories": [], "reject_reason": "Formato não suportado"},
            {"datetime": "23/06/2026 13:12:18", "source": "Sessão 2b8f-6a4c",
             "filename": "contratos_fornecedores.docx", "size": "567 KB",
             "result_kind": "blocked",  "result_label": "Bloqueado",
             "categories": ["CNPJ"]},
            {"datetime": "23/06/2026 13:05:44", "source": "Sessão 2b8f-6a4c",
             "filename": "manual_produto.pdf", "size": "8,7 MB",
             "result_kind": "approved", "result_label": "Aprovado",
             "categories": []},
            {"datetime": "23/06/2026 12:58:21", "source": "Sessão 9d4e-3c7a",
             "filename": "cadastro_clientes.xlsx", "size": "3,1 MB",
             "result_kind": "blocked",  "result_label": "Bloqueado",
             "categories": ["CPF", "Cartão de pagamento"]},
            {"datetime": "23/06/2026 12:52:09", "source": "Sessão 9d4e-3c7a",
             "filename": "arquivo_grande.pdf", "size": "22,4 MB",
             "result_kind": "rejected", "result_label": "Rejeitado",
             "categories": [], "reject_reason": "Tamanho excedido"},
            {"datetime": "23/06/2026 12:47:33", "source": "Sessão 6f1c-2d8b",
             "filename": "extrato_bancario.pdf", "size": "234 KB",
             "result_kind": "blocked",  "result_label": "Bloqueado",
             "categories": ["Cartão de pagamento"]},
            {"datetime": "23/06/2026 12:41:18", "source": "Sessão 6f1c-2d8b",
             "filename": "apresentacao_marketing.pdf", "size": "5,4 MB",
             "result_kind": "approved", "result_label": "Aprovado",
             "categories": []},
            {"datetime": "23/06/2026 12:35:02", "source": "Sessão 4e8b-7f1a",
             "filename": "lista_emails.csv", "size": "89 KB",
             "result_kind": "approved", "result_label": "Aprovado",
             "categories": []},
            {"datetime": "23/06/2026 12:28:46", "source": "Sessão 4e8b-7f1a",
             "filename": "folha_pagamento.xlsx", "size": "1,8 MB",
             "result_kind": "blocked",  "result_label": "Bloqueado",
             "categories": ["CPF"]},
            {"datetime": "23/06/2026 12:20:11", "source": "Sessão 8a5d-3e9f",
             "filename": "rascunho_email.txt", "size": "4 KB",
             "result_kind": "approved", "result_label": "Aprovado",
             "categories": []},
            {"datetime": "23/06/2026 12:14:35", "source": "Sessão 8a5d-3e9f",
             "filename": "dados_pix.txt", "size": "18 KB",
             "result_kind": "blocked",  "result_label": "Bloqueado",
             "categories": ["CPF", "Senha em texto claro"]},
            {"datetime": "23/06/2026 12:08:22", "source": "Sessão 1f3a-5c2b",
             "filename": "apresentacao_2026.pdf", "size": "6,7 MB",
             "result_kind": "approved", "result_label": "Aprovado",
             "categories": []},
            {"datetime": "23/06/2026 12:01:47", "source": "Sessão 1f3a-5c2b",
             "filename": "termos_servico.docx", "size": "245 KB",
             "result_kind": "approved", "result_label": "Aprovado",
             "categories": []},
            {"datetime": "23/06/2026 11:55:14", "source": "Sessão 5b9c-8d4e",
             "filename": "cadastro_v2.xlsx", "size": "4,2 MB",
             "result_kind": "blocked",  "result_label": "Bloqueado",
             "categories": ["CPF", "CNPJ", "Cartão de pagamento"]},
            {"datetime": "23/06/2026 11:48:03", "source": "Sessão 5b9c-8d4e",
             "filename": "nota_fiscal.pdf", "size": "178 KB",
             "result_kind": "blocked",  "result_label": "Bloqueado",
             "categories": ["CNPJ"]},
        ],
        "pagination": {
            "showing_from": 1,
            "showing_to":   20,
            "total":        1247,
            "current":      1,
            "total_pages":  63,
        },
        # Opções dos filtros (não persistem; apenas para alimentar os <select>)
        "filter_options": {
            "periods": [
                {"value": "24h",   "label": "Últimas 24 horas"},
                {"value": "7d",    "label": "Últimos 7 dias",   "default": True},
                {"value": "30d",   "label": "Últimos 30 dias"},
                {"value": "90d",   "label": "Últimos 90 dias"},
                {"value": "all",   "label": "Todo o período"},
            ],
            "results": [
                {"value": "all",      "label": "Todos os resultados", "default": True},
                {"value": "blocked",  "label": "Apenas bloqueados"},
                {"value": "approved", "label": "Apenas aprovados"},
                {"value": "rejected", "label": "Apenas rejeitados"},
            ],
            "categories": [
                {"value": "all",      "label": "Todas as categorias", "default": True},
                {"value": "CPF",      "label": "CPF"},
                {"value": "CNPJ",     "label": "CNPJ"},
                {"value": "CARD",     "label": "Cartão de pagamento"},
                {"value": "PASSWORD", "label": "Senha em texto claro"},
            ],
        },
    }
    return templates.TemplateResponse(request, "admin/audit.html", context)


# ---------------------------------------------------------------------------
# Relatórios (HU-09)
# ---------------------------------------------------------------------------

@router.get("/relatorios", response_class=HTMLResponse)
async def reports_page(request: Request):
    """Exibe o relatório consolidado de inspeções (HU-09).

    Conforme HU-09 e RN-007, o relatório usa **apenas contagens e
    categorias** — nunca valores reais detectados. Os totais são agregados
    por resultado e por categoria para o período selecionado.

    Os dados aqui são fictícios; serão substituídos por consultas agregadas
    ao repositório de auditoria quando a camada de infraestrutura existir.
    """
    context = {
        "active_page": "reports",
        "period_label": "Últimos 30 dias",
        "generated_at": "25/06/2026 14:05",
        "kpis": {
            "total":      {"value": "5.842", "trend": "+8,4% vs. período anterior", "trend_kind": "up"},
            "block_rate": {"value": "7,3%",  "trend": "426 de 5.842 inspeções",      "trend_kind": "neutral"},
            "approved":   {"value": "5.301", "trend": "90,7% do total",              "trend_kind": "neutral"},
            "rejected":   {"value": "115",   "trend": "2,0% do total",               "trend_kind": "neutral"},
        },
        "distribution": [
            {"kind": "approved", "label": "Aprovados",  "value": 5301, "percentage": 90.7},
            {"kind": "blocked",  "label": "Bloqueados", "value": 426,  "percentage": 7.3},
            {"kind": "rejected", "label": "Rejeitados", "value": 115,  "percentage": 2.0},
        ],
        "categories": [
            {"name": "CPF",                  "value": 289, "percentage": 100, "share": "47,9%"},
            {"name": "Senha em texto claro", "value": 168, "percentage": 58,  "share": "27,9%"},
            {"name": "CNPJ",                 "value": 102, "percentage": 35,  "share": "16,9%"},
            {"name": "Cartão de pagamento",  "value": 44,  "percentage": 15,  "share": "7,3%"},
        ],
        "volume": [
            {"label": "19/06", "value": 198, "percentage": 78},
            {"label": "20/06", "value": 215, "percentage": 85},
            {"label": "21/06", "value": 142, "percentage": 56},
            {"label": "22/06", "value": 167, "percentage": 66},
            {"label": "23/06", "value": 254, "percentage": 100},
            {"label": "24/06", "value": 231, "percentage": 91},
            {"label": "25/06", "value": 176, "percentage": 69},
        ],
        "summary_rows": [
            {"category": "CPF",                  "occurrences": 289, "files": 174, "share": "47,9%"},
            {"category": "Senha em texto claro", "occurrences": 168, "files": 121, "share": "27,9%"},
            {"category": "CNPJ",                 "occurrences": 102, "files": 88,  "share": "16,9%"},
            {"category": "Cartão de pagamento",  "occurrences": 44,  "files": 39,  "share": "7,3%"},
        ],
        "periods": [
            {"value": "7d",  "label": "7 dias"},
            {"value": "30d", "label": "30 dias", "default": True},
            {"value": "90d", "label": "90 dias"},
        ],
    }
    return templates.TemplateResponse(request, "admin/reports.html", context)


# ---------------------------------------------------------------------------
# Categorias de detecção (HU-07)
# ---------------------------------------------------------------------------

_ICON_SHIELD = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
    'stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>'
)
_ICON_BUILDING = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
    'stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="2" width="16" height="20" rx="2"/>'
    '<line x1="9" y1="6" x2="9" y2="6"/><line x1="15" y1="6" x2="15" y2="6"/>'
    '<line x1="9" y1="10" x2="9" y2="10"/><line x1="15" y1="10" x2="15" y2="10"/>'
    '<path d="M9 22v-4h6v4"/></svg>'
)
_ICON_CARD = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
    'stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="5" width="20" height="14" rx="2"/>'
    '<line x1="2" y1="10" x2="22" y2="10"/></svg>'
)
_ICON_KEY = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
    'stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 '
    '5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3"/></svg>'
)


@router.get("/categorias", response_class=HTMLResponse)
async def categories_page(request: Request):
    """Exibe a configuração das categorias de detecção (HU-07).

    Permite ativar ou desativar cada regra de detecção. Conforme RN-009, o
    sistema não pode permitir desativar todas as categorias ao mesmo tempo.
    Toda alteração administrativa deve ser registrada em auditoria.

    Os dados aqui são fictícios; serão substituídos pela leitura da tabela
    CATEGORIES quando a camada de infraestrutura existir.
    """
    context = {
        "active_page": "categories",
        "summary": {"active": 4, "total": 4, "occurrences": "603"},
        "categories": [
            {"code": "CPF", "label": "CPF", "rule": "RN-001", "tone": "primary",
             "icon": _ICON_SHIELD, "enabled": True, "heuristic": False,
             "occurrences": 289,
             "description": "Classifica como CPF sequências de 11 dígitos que passam pela "
                            "verificação matemática dos dígitos verificadores."},
            {"code": "CNPJ", "label": "CNPJ", "rule": "RN-002", "tone": "primary",
             "icon": _ICON_BUILDING, "enabled": True, "heuristic": False,
             "occurrences": 102,
             "description": "Classifica como CNPJ sequências de 14 dígitos que passam pela "
                            "verificação matemática dos dígitos verificadores."},
            {"code": "CARD", "label": "Cartão de pagamento", "rule": "RN-003", "tone": "warning",
             "icon": _ICON_CARD, "enabled": True, "heuristic": False,
             "occurrences": 44,
             "description": "Classifica como cartão sequências de 16 dígitos com validação "
                            "positiva pelo algoritmo de Luhn."},
            {"code": "PASSWORD", "label": "Senha em texto claro", "rule": "RN-004", "tone": "danger",
             "icon": _ICON_KEY, "enabled": True, "heuristic": True,
             "occurrences": 168,
             "description": "Identifica indícios de senha por padrões chave-valor como "
                            "\"senha:\" ou \"password=\" com valor preenchido. Pode gerar falsos positivos."},
        ],
    }
    return templates.TemplateResponse(request, "admin/categories.html", context)


# ---------------------------------------------------------------------------
# Lista de exceções / allowlist (HU-08)
# ---------------------------------------------------------------------------

@router.get("/excecoes", response_class=HTMLResponse)
async def allowlist_page(request: Request):
    """Exibe a lista de exceções controladas — allowlist (HU-08).

    Tratada como evolução planejada/apoio experimental. Conforme RN-007,
    o valor real é protegido por HMAC e apenas a forma mascarada é exibida.
    Uma exceção afeta somente o valor específico, sem desativar a categoria.

    Os dados aqui são fictícios; serão substituídos pela leitura da tabela
    ALLOWLIST quando a camada de infraestrutura existir.
    """
    context = {
        "active_page": "allowlist",
        "stats": {
            "total": "7",
            "by_category": [
                {"label": "CPF",  "count": 3},
                {"label": "CNPJ", "count": 2},
                {"label": "Cartão", "count": 1},
                {"label": "Senha", "count": 1},
            ],
        },
        "exceptions": [
            {"masked": "***.456.789-**", "category": "CPF",
             "reason": "CPF fictício usado em material de treinamento",
             "added_by": "admin@safeupload.local", "added_at": "20/06/2026"},
            {"masked": "12.***.***/0001-**", "category": "CNPJ",
             "reason": "CNPJ público da própria organização",
             "added_by": "admin@safeupload.local", "added_at": "18/06/2026"},
            {"masked": "***.222.333-**", "category": "CPF",
             "reason": "Documento de exemplo da base de testes",
             "added_by": "joana.silva@safeupload.local", "added_at": "17/06/2026"},
            {"masked": "**** **** **** 1234", "category": "Cartão",
             "reason": "Cartão de teste do gateway (sandbox)",
             "added_by": "admin@safeupload.local", "added_at": "15/06/2026"},
            {"masked": "98.***.***/0001-**", "category": "CNPJ",
             "reason": "Fornecedor recorrente — documento público",
             "added_by": "carlos.lima@safeupload.local", "added_at": "12/06/2026"},
            {"masked": "***.888.999-**", "category": "CPF",
             "reason": "Cadastro de demonstração aprovado pela coordenação",
             "added_by": "joana.silva@safeupload.local", "added_at": "10/06/2026"},
            {"masked": "senha=demo********", "category": "Senha",
             "reason": "Credencial fictícia em manual de instalação",
             "added_by": "admin@safeupload.local", "added_at": "08/06/2026"},
        ],
        "filter_options": {
            "categories": [
                {"value": "all",      "label": "Todas as categorias", "default": True},
                {"value": "CPF",      "label": "CPF"},
                {"value": "CNPJ",     "label": "CNPJ"},
                {"value": "CARD",     "label": "Cartão de pagamento"},
                {"value": "PASSWORD", "label": "Senha em texto claro"},
            ],
        },
    }
    return templates.TemplateResponse(request, "admin/allowlist.html", context)
