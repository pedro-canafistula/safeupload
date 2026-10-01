"""Contextos demonstrativos; Endpoints também inclui heartbeats recebidos."""

from datetime import datetime, timedelta, timezone

from app.domain.schemas import EndpointRecord
from app.infrastructure import memory_store

# Mesmo valor já usado como "current_agent_version" na tela de Endpoints —
# ver build_endpoints_context(). Comparado contra o agentVersion que o
# heartbeat manda para decidir se um endpoint está desatualizado.
_CURRENT_AGENT_VERSION = "2.3.1"

def _format_datetime(value: datetime, *, with_seconds: bool = False) -> str:
    fmt = "%d/%m/%Y %H:%M:%S" if with_seconds else "%d/%m/%Y %H:%M"
    return value.strftime(fmt)


def _os_short(os_name: str) -> str:
    if "11" in os_name:
        return "Win 11"
    if "10" in os_name:
        return "Win 10"
    return os_name


def _endpoint_record_to_row(record: EndpointRecord, *, now: datetime) -> dict:
    outdated = record.agent_version != _CURRENT_AGENT_VERSION
    recently_seen = (now - record.last_seen_utc) < timedelta(minutes=15)

    if outdated:
        status, status_label = "outdated", "Desatualizado"
    elif recently_seen:
        status, status_label = "online", "Online"
    else:
        status, status_label = "offline", "Offline"

    since_7d = now - timedelta(days=7)

    return {
        "hostname": record.hostname,
        "ip": "—",
        "os": record.os,
        "os_short": _os_short(record.os),
        "agent_version": record.agent_version,
        "agent_outdated": outdated,
        "policy_version": f"v{record.policy_version}",
        "last_seen": _format_datetime(record.last_seen_utc),
        "status": status,
        "status_label": status_label,
        "inspections_7d": memory_store.count_recent_events_for_endpoint(
            record.endpoint_id, since_7d
        ),
    }


def build_dashboard_context():
    """Cria o contexto demonstrativo do painel principal."""
    return {
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


def build_reports_context():
    """Cria o contexto demonstrativo da página de relatórios."""
    return {
        "active_page": "reports",
        "recent_reports": [
            {"num": 1, "name": "Inspeções (últimos 3 dias)", "kind": "table",
             "href": "/admin/auditoria"},
            {"num": 2, "name": "Inspeções (últimos 7 dias)", "kind": "table",
             "href": "/admin/auditoria"},
            {"num": 3, "name": "Painel DLP (últimos 7 dias)", "kind": "chart",
             "href": "/admin/dashboard"},
            {"num": 4, "name": "Categorias mais detectadas (últimos 7 dias)", "kind": "chart",
             "href": "#"},
            {"num": 5, "name": "Ocorrências por categoria e resultado (últimos 7 dias)", "kind": "chart",
             "href": "#"},
            {"num": 6, "name": "Principais origens de envio (últimos 7 dias)", "kind": "chart",
             "href": "#"},
            {"num": 7, "name": "Tendência de inspeções (trimestre atual)", "kind": "chart",
             "href": "#"},
            {"num": 8, "name": "Situação das inspeções (últimos 7 dias)", "kind": "chart",
             "href": "#"},
        ],
    }


def build_categories_context():
    """Cria o contexto demonstrativo da página de categorias."""
    return {
        "active_page": "categories",
        "summary": {"active": 4, "total": 4, "occurrences": "603"},
        "categories": [
            {"code": "CPF", "label": "CPF", "rule": "RN-001", "tone": "primary",
             "icon": "shield", "enabled": True, "heuristic": False,
             "occurrences": 289,
             "description": "Classifica como CPF sequências de 11 dígitos que passam pela "
                            "verificação matemática dos dígitos verificadores."},
            {"code": "CNPJ", "label": "CNPJ", "rule": "RN-002", "tone": "primary",
             "icon": "building", "enabled": True, "heuristic": False,
             "occurrences": 102,
             "description": "Classifica como CNPJ sequências de 14 dígitos que passam pela "
                            "verificação matemática dos dígitos verificadores."},
            {"code": "CARD", "label": "Cartão de pagamento", "rule": "RN-003", "tone": "warning",
             "icon": "card", "enabled": True, "heuristic": False,
             "occurrences": 44,
             "description": "Classifica como cartão sequências de 16 dígitos com validação "
                            "positiva pelo algoritmo de Luhn."},
            {"code": "PASSWORD", "label": "Senha em texto claro", "rule": "RN-004", "tone": "danger",
             "icon": "key", "enabled": True, "heuristic": True,
             "occurrences": 168,
             "description": "Identifica indícios de senha por padrões chave-valor como "
                            "\"senha:\" ou \"password=\" com valor preenchido. Pode gerar falsos positivos."},
        ],
    }


def build_allowlist_context():
    """Cria o contexto demonstrativo da página de exceções."""
    return {
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


def build_endpoints_context():
    """Cria o contexto da página de endpoints: lista mockada + o que o
    agente desktop já registrou de verdade via ``POST /agent/heartbeat``."""
    context = {
        "active_page": "endpoints",
        "stats": {
            "total": "24",
            "online": "18",
            "offline": "4",
            "outdated": "2",
        },
        "current_agent_version": _CURRENT_AGENT_VERSION,
        "endpoints": [
            {"hostname": "DESKTOP-FINANC01",    "ip": "192.168.10.101",
             "os": "Windows 11 Pro", "os_short": "Win 11",
             "agent_version": "2.3.1", "agent_outdated": False,
             "policy_version": "v4", "last_seen": "26/06/2026 14:12",
             "status": "online",   "status_label": "Online",        "inspections_7d": 47},
            {"hostname": "DESKTOP-RH003",        "ip": "192.168.10.45",
             "os": "Windows 10 Pro", "os_short": "Win 10",
             "agent_version": "2.3.1", "agent_outdated": False,
             "policy_version": "v4", "last_seen": "26/06/2026 13:58",
             "status": "online",   "status_label": "Online",        "inspections_7d": 32},
            {"hostname": "NOTEBOOK-TI001",       "ip": "192.168.20.12",
             "os": "Windows 11 Pro", "os_short": "Win 11",
             "agent_version": "2.3.1", "agent_outdated": False,
             "policy_version": "v4", "last_seen": "26/06/2026 14:05",
             "status": "online",   "status_label": "Online",        "inspections_7d": 91},
            {"hostname": "DESKTOP-JURIDICO02",   "ip": "192.168.10.77",
             "os": "Windows 11 Pro", "os_short": "Win 11",
             "agent_version": "2.3.1", "agent_outdated": False,
             "policy_version": "v4", "last_seen": "26/06/2026 13:44",
             "status": "online",   "status_label": "Online",        "inspections_7d": 18},
            {"hostname": "DESKTOP-DIRETORIA01",  "ip": "192.168.10.10",
             "os": "Windows 11 Pro", "os_short": "Win 11",
             "agent_version": "2.3.1", "agent_outdated": False,
             "policy_version": "v4", "last_seen": "26/06/2026 14:01",
             "status": "online",   "status_label": "Online",        "inspections_7d": 9},
            {"hostname": "DESKTOP-CONTABIL02",   "ip": "192.168.10.133",
             "os": "Windows 10 Pro", "os_short": "Win 10",
             "agent_version": "2.3.1", "agent_outdated": False,
             "policy_version": "v4", "last_seen": "26/06/2026 11:30",
             "status": "online",   "status_label": "Online",        "inspections_7d": 26},
            {"hostname": "DESKTOP-RH007",        "ip": "192.168.10.51",
             "os": "Windows 10 Pro", "os_short": "Win 10",
             "agent_version": "2.1.0", "agent_outdated": True,
             "policy_version": "v3", "last_seen": "26/06/2026 09:15",
             "status": "outdated", "status_label": "Desatualizado", "inspections_7d": 14},
            {"hostname": "NOTEBOOK-CONTABIL03",  "ip": "192.168.20.34",
             "os": "Windows 11 Pro", "os_short": "Win 11",
             "agent_version": "2.2.0", "agent_outdated": True,
             "policy_version": "v4", "last_seen": "25/06/2026 17:48",
             "status": "outdated", "status_label": "Desatualizado", "inspections_7d": 7},
            {"hostname": "DESKTOP-FINANC03",     "ip": "192.168.10.103",
             "os": "Windows 10 Pro", "os_short": "Win 10",
             "agent_version": "2.3.1", "agent_outdated": False,
             "policy_version": "v4", "last_seen": "24/06/2026 18:22",
             "status": "offline",  "status_label": "Offline",       "inspections_7d": 0},
            {"hostname": "DESKTOP-JURIDICO01",   "ip": "192.168.10.75",
             "os": "Windows 11 Pro", "os_short": "Win 11",
             "agent_version": "2.3.1", "agent_outdated": False,
             "policy_version": "v4", "last_seen": "23/06/2026 08:05",
             "status": "offline",  "status_label": "Offline",       "inspections_7d": 0},
        ],
        "filter_options": {
            "statuses": [
                {"value": "all",      "label": "Todos os status",  "default": True},
                {"value": "online",   "label": "Online"},
                {"value": "offline",  "label": "Offline"},
                {"value": "outdated", "label": "Desatualizado"},
            ],
            "os_list": [
                {"value": "all",   "label": "Todos os sistemas", "default": True},
                {"value": "win11", "label": "Windows 11"},
                {"value": "win10", "label": "Windows 10"},
            ],
        },
    }

    now = memory_store.utc_now()
    real_endpoints = [
        _endpoint_record_to_row(record, now=now) for record in memory_store.list_endpoints()
    ]
    context["endpoints"] = real_endpoints + context["endpoints"]

    for row in real_endpoints:
        context["stats"]["total"] = str(int(context["stats"]["total"]) + 1)
        key = row["status"] if row["status"] in ("online", "offline", "outdated") else "offline"
        context["stats"][key] = str(int(context["stats"][key]) + 1)

    return context


def build_users_context():
    """Cria o contexto demonstrativo da página de usuários."""
    return {
        "active_page": "users",
        "stats": {"total": "6", "admins": "3", "auditors": "3", "active": "5"},
        "users": [
            {"name": "Victor Nogueira da Nova Bonato", "initials": "VB",
             "email": "victor.bonato@safeupload.local", "role": "Administrador",
             "role_kind": "admin", "active": True, "last_access": "25/06/2026 13:58"},
            {"name": "Joana Silva", "initials": "JS",
             "email": "joana.silva@safeupload.local", "role": "Administrador",
             "role_kind": "admin", "active": True, "last_access": "25/06/2026 11:20"},
            {"name": "Pedro Campos Canafístula", "initials": "PC",
             "email": "pedro.campos@safeupload.local", "role": "Auditor",
             "role_kind": "auditor", "active": True, "last_access": "24/06/2026 17:04"},
            {"name": "Luiz Henrique Alves Rodrigues", "initials": "LR",
             "email": "luiz.alves@safeupload.local", "role": "Auditor",
             "role_kind": "auditor", "active": True, "last_access": "23/06/2026 09:42"},
            {"name": "Lucas Ferreira Coelho", "initials": "LC",
             "email": "lucas.coelho@safeupload.local", "role": "Administrador",
             "role_kind": "admin", "active": True, "last_access": "22/06/2026 15:11"},
            {"name": "Carlos Lima", "initials": "CL",
             "email": "carlos.lima@safeupload.local", "role": "Auditor",
             "role_kind": "auditor", "active": False, "last_access": "02/06/2026 08:30"},
        ],
        "filter_options": {
            "roles": [
                {"value": "all",     "label": "Todos os perfis", "default": True},
                {"value": "admin",   "label": "Administrador"},
                {"value": "auditor", "label": "Auditor"},
            ],
            "statuses": [
                {"value": "all",      "label": "Todos os status", "default": True},
                {"value": "active",   "label": "Apenas ativos"},
                {"value": "inactive", "label": "Apenas inativos"},
            ],
        },
    }
