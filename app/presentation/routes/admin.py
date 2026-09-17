"""
Rotas do Centro de Administração.

Todas as rotas deste módulo são prefixadas com ``/admin`` e devem ser
restritas ao perfil administrador (controle de acesso será adicionado
quando a camada de segurança for implementada).

Durante a fase de protótipo visual, as páginas exibem **dados fictícios**
fornecidos pelo módulo ``app.presentation.demo.admin_data``. Esses dados
serão substituídos por consultas reais ao banco quando os repositórios da
camada de infraestrutura existirem.
"""

from fastapi import APIRouter, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from app.presentation import templates
from app.presentation.demo.admin_data import (
    build_allowlist_context,
    build_audit_context,
    build_categories_context,
    build_dashboard_context,
    build_endpoints_context,
    build_reports_context,
    build_users_context,
)

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
    context = build_dashboard_context()
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
    context = build_audit_context()
    return templates.TemplateResponse(request, "admin/audit.html", context)


# ---------------------------------------------------------------------------
# Relatórios (HU-09)
# ---------------------------------------------------------------------------

@router.get("/relatorios", response_class=HTMLResponse)
async def reports_page(request: Request):
    """Exibe a central de relatórios de prevenção de vazamento (HU-09).

    Apresenta o catálogo de relatórios e os relatórios recentes. Cada
    relatório é uma visão sobre a base de auditoria com filtros específicos,
    usando apenas contagens e categorias — nunca valores reais (RN-007).

    Os dados aqui são fictícios; serão substituídos por relatórios reais
    quando a camada de infraestrutura existir.
    """
    context = build_reports_context()
    return templates.TemplateResponse(request, "admin/reports.html", context)

# ---------------------------------------------------------------------------
# Categorias de detecção (HU-07)
# ---------------------------------------------------------------------------

@router.get("/categorias", response_class=HTMLResponse)
async def categories_page(request: Request):
    """Exibe a configuração das categorias de detecção (HU-07).

    Permite ativar ou desativar cada regra de detecção. Conforme RN-009, o
    sistema não pode permitir desativar todas as categorias ao mesmo tempo.
    Toda alteração administrativa deve ser registrada em auditoria.

    Os dados aqui são fictícios; serão substituídos pela leitura da tabela
    CATEGORIES quando a camada de infraestrutura existir.
    """
    context = build_categories_context()
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
    context = build_allowlist_context()
    return templates.TemplateResponse(request, "admin/allowlist.html", context)


# ---------------------------------------------------------------------------
# Endpoints (inventário de agentes)
# ---------------------------------------------------------------------------

@router.get("/endpoints", response_class=HTMLResponse)
async def endpoints_page(request: Request):
    """Exibe o inventário de endpoints com o agente SafeUpload instalado.

    Permite monitorar o status de cada máquina (online, offline, agente
    desatualizado), visualizar a versão da política aplicada e executar
    ações administrativas: forçar atualização de política, extrair
    relatório individual ou desativar o endpoint.

    Os dados aqui são fictícios; serão substituídos pela leitura do
    registro de endpoints quando a camada de infraestrutura existir.
    """
    context = build_endpoints_context()
    return templates.TemplateResponse(request, "admin/endpoints.html", context)


# ---------------------------------------------------------------------------
# Usuários (HU-06)
# ---------------------------------------------------------------------------

@router.get("/usuarios", response_class=HTMLResponse)
async def users_page(request: Request):
    """Exibe a gestão de usuários e perfis de acesso (HU-06).

    Conforme RN-008, as funções administrativas são restritas ao perfil
    administrador. As senhas são armazenadas apenas como hash seguro
    (PBKDF2), nunca em texto claro.

    Os dados aqui são fictícios; serão substituídos pela leitura da tabela
    USERS quando a camada de infraestrutura existir.
    """
    context = build_users_context()
    return templates.TemplateResponse(request, "admin/users.html", context)
