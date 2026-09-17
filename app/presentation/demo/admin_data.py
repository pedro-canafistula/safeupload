"""Contextos demonstrativos do Centro de Administração.

Os dados deste módulo existem apenas para sustentar o protótipo visual.
Cada função cria e retorna uma nova estrutura, sem cache, persistência ou
estado global mutável. As rotas permanecem responsáveis apenas pelo fluxo
HTTP e pela seleção do template correspondente.
"""

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


def build_audit_context():
    """Cria o contexto demonstrativo da página de auditoria."""
    return {
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
    """Cria o contexto demonstrativo da página de endpoints."""
    return {
        "active_page": "endpoints",
        "stats": {
            "total": "24",
            "online": "18",
            "offline": "4",
            "outdated": "2",
        },
        "current_agent_version": "2.3.1",
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
