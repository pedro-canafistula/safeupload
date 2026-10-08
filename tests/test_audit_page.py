from uuid import uuid4

import pytest


def event_payload(**changes):
    event = {
        "eventId": str(uuid4()),
        "occurredAtUtc": "2026-10-01T12:00:00Z",
        "endpointId": "ENDPOINT-TESTE",
        "userName": "teste",
        "fileName": "arquivo-recebido.txt",
        "extension": ".txt",
        "sizeBytes": 2048,
        "verdict": "Approved",
        "categories": [],
        "processName": "editor",
        "processId": 1,
        "destinationPath": "C:\\destino",
        "policyVersion": 1,
        "elapsedMs": 10,
    }
    return event | changes


def test_auditoria_vazia_nao_exibe_exemplos_ou_acoes_sem_execucao(client):
    page = client.get("/admin/auditoria")

    assert page.status_code == 200
    assert page.context["events"] == []
    assert page.context["stats"] == {
        "total": 0, "blocked": 0, "approved": 0, "not_inspected": 0,
    }
    assert "Nenhum evento recebido" in page.text
    assert "relatorio_clientes_q2.xlsx" not in page.text
    assert '<form' not in page.text
    assert '<button' not in page.text
    assert "1.247" not in page.text


def test_auditoria_conta_somente_recebidos_e_separa_sem_inspecao(client):
    events = [
        event_payload(fileName="aprovado.txt"),
        event_payload(fileName="bloqueado.txt", verdict="Blocked", categories=["Cpf", "Secret"]),
        event_payload(fileName="liberado.txt", verdict="AllowedWithoutInspection", notInspectedReason="Tempo limite", categories=["Cnpj"]),
    ]
    assert client.post("/agent/events", json={"events": events}).status_code == 200
    page = client.get("/admin/auditoria")

    assert page.context["stats"] == {
        "total": 3, "blocked": 1, "approved": 1, "not_inspected": 1,
    }
    assert {row["filename"] for row in page.context["events"]} == {
        "aprovado.txt", "bloqueado.txt", "liberado.txt",
    }
    assert "Segredo/credencial" in page.text
    assert "Liberado sem inspeção" in page.text
    assert 'badge-not-inspected' in page.text
    assert "Tempo limite" in page.text
    assert "Nenhum evento recebido" not in page.text


def test_auditoria_ordena_corretamente_instantes_com_offsets_distintos(client):
    events = [
        event_payload(fileName="antigo.txt", occurredAtUtc="2026-10-01T10:00:00Z"),
        event_payload(fileName="recente.txt", occurredAtUtc="2026-10-01T08:00:00-03:00"),
    ]
    client.post("/agent/events", json={"events": events})
    page = client.get("/admin/auditoria")

    assert [row["filename"] for row in page.context["events"]] == ["recente.txt", "antigo.txt"]
    assert "01/10/2026 08:00:00 -0300" in page.text
    assert "01/10/2026 10:00:00 +0000" in page.text


def test_auditoria_exibe_todos_sem_paginacao_ficticia(client):
    events = [event_payload(fileName=f"recebido-{i}.txt") for i in range(25)]
    client.post("/agent/events", json={"events": events})
    page = client.get("/admin/auditoria")

    assert len(page.context["events"]) == page.context["stats"]["total"] == 25
    assert 'Exibindo <strong>25</strong> de <strong>25</strong>' in page.text
    assert 'aria-label="Paginação' not in page.text


def test_auditoria_escapa_textos_recebidos(client):
    event = event_payload(
        fileName='<script>alert("arquivo")</script>',
        endpointId='<img src=x onerror=alert(1)>',
        verdict="AllowedWithoutInspection",
        notInspectedReason='<script>alert("motivo")</script>',
    )
    client.post("/agent/events", json={"events": [event]})
    page = client.get("/admin/auditoria")

    assert '<script>' not in page.text
    assert '<img src=x' not in page.text
    assert '&lt;script&gt;' in page.text
    assert '&lt;img src=x' in page.text


def test_parametros_antigos_nao_sugerem_filtro_aplicado(client):
    client.post("/agent/events", json={"events": [event_payload()]})
    page = client.get("/admin/auditoria?hostname=OUTRO&periodo=24h&resultado=blocked")

    assert page.context["stats"]["total"] == 1
    assert "Consulta geral, somente leitura." in page.text
    assert "Filtros adicionais, detalhes e exportação ainda não estão disponíveis." in page.text


@pytest.mark.parametrize("path", ["login", "dashboard", "endpoints", "relatorios", "categorias", "excecoes", "usuarios"])
def test_demais_telas_continuam_renderizando(client, path):
    assert client.get(f"/admin/{path}").status_code == 200
