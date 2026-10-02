from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.infrastructure import memory_store


def heartbeat_payload(endpoint_id: str, *, os_name: str = "Windows 11 Pro") -> dict:
    return {
        "endpointId": endpoint_id,
        "hostname": endpoint_id,
        "os": os_name,
        "agentVersion": "1.0.0",
        "policyVersion": 1,
    }


def event_payload(endpoint_id: str, *, file_name: str) -> dict:
    return {
        "eventId": str(uuid4()),
        "occurredAtUtc": "2026-10-01T12:00:00Z",
        "endpointId": endpoint_id,
        "userName": "teste",
        "fileName": file_name,
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


def test_endpoints_vazio_nao_exibe_maquinas_ficticias(client):
    page = client.get("/admin/endpoints")

    assert page.status_code == 200
    assert page.context["stats"] == {"total": 0, "online": 0, "offline": 0}
    assert page.context["endpoints"] == []
    assert "Nenhum endpoint registrou heartbeat" in page.text
    assert "DESKTOP-FINANC01" not in page.text
    assert "Versão atual do agente" not in page.text
    assert "Atualizar política em todos" not in page.text
    assert "Extrair relatório" not in page.text


def test_heartbeat_aparece_no_inventario_com_dados_reais(client, monkeypatch):
    now = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(memory_store, "utc_now", lambda: now)

    response = client.post("/agent/heartbeat", json=heartbeat_payload("ENDPOINT-01"))
    assert response.status_code == 200

    page = client.get("/admin/endpoints")
    assert page.context["stats"] == {"total": 1, "online": 1, "offline": 0}
    assert len(page.context["endpoints"]) == 1

    endpoint = page.context["endpoints"][0]
    assert endpoint["endpoint_id"] == "ENDPOINT-01"
    assert endpoint["hostname"] == "ENDPOINT-01"
    assert endpoint["agent_version"] == "1.0.0"
    assert endpoint["policy_version"] == "v1"
    assert endpoint["status"] == "online"
    assert endpoint["inspections_7d"] == 0
    assert "/admin/auditoria?endpoint=ENDPOINT-01" in page.text


def test_endpoint_fica_offline_apos_limite_sem_heartbeat(client, monkeypatch):
    clock = {"now": datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)}
    monkeypatch.setattr(memory_store, "utc_now", lambda: clock["now"])

    client.post("/agent/heartbeat", json=heartbeat_payload("ENDPOINT-OFFLINE"))
    clock["now"] += timedelta(seconds=91)

    page = client.get("/admin/endpoints")
    assert page.context["stats"] == {"total": 1, "online": 0, "offline": 1}
    assert page.context["endpoints"][0]["status"] == "offline"
    assert "há no máximo 90 segundos" in page.text


def test_filtros_de_endpoints_sao_aplicados_e_preservados(client, monkeypatch):
    now = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(memory_store, "utc_now", lambda: now)

    client.post("/agent/heartbeat", json=heartbeat_payload("FINANCEIRO-01", os_name="Windows 11 Pro"))
    client.post("/agent/heartbeat", json=heartbeat_payload("RH-01", os_name="Windows 10 Pro"))
    client.post("/agent/heartbeat", json=heartbeat_payload("LINUX-01", os_name="Ubuntu 24.04"))

    page = client.get("/admin/endpoints?status=online&os=win11&q=financeiro")

    assert page.status_code == 200
    assert [ep["endpoint_id"] for ep in page.context["endpoints"]] == ["FINANCEIRO-01"]
    assert page.context["stats"] == {"total": 3, "online": 3, "offline": 0}
    assert page.context["filters"] == {
        "status": "online",
        "os": "win11",
        "q": "financeiro",
    }
    assert 'value="financeiro"' in page.text
    assert 'value="online" selected' in page.text
    assert 'value="win11" selected' in page.text
    assert "RH-01" not in page.text
    assert "LINUX-01" not in page.text


def test_inspecoes_7d_e_link_de_auditoria_usam_endpoint_id(client, monkeypatch):
    now = datetime(2026, 10, 1, 12, 5, tzinfo=timezone.utc)
    monkeypatch.setattr(memory_store, "utc_now", lambda: now)

    client.post("/agent/heartbeat", json=heartbeat_payload("ENDPOINT-A"))
    client.post("/agent/heartbeat", json=heartbeat_payload("ENDPOINT-B"))
    client.post(
        "/agent/events",
        json={
            "events": [
                event_payload("ENDPOINT-A", file_name="arquivo-a.txt"),
                event_payload("ENDPOINT-B", file_name="arquivo-b.txt"),
            ]
        },
    )

    endpoints_page = client.get("/admin/endpoints?q=ENDPOINT-A")
    assert endpoints_page.context["endpoints"][0]["inspections_7d"] == 1
    assert "/admin/auditoria?endpoint=ENDPOINT-A" in endpoints_page.text

    audit_page = client.get("/admin/auditoria?endpoint=ENDPOINT-A")
    assert audit_page.status_code == 200
    assert [row["filename"] for row in audit_page.context["events"]] == ["arquivo-a.txt"]
    assert audit_page.context["endpoint_filter"] == "ENDPOINT-A"
    assert "Auditoria do endpoint ENDPOINT-A" in audit_page.text
    assert "arquivo-b.txt" not in audit_page.text

def test_api_rejeita_datas_sem_fuso_antes_de_afetar_inventario(client):
    event = event_payload("ENDPOINT-A", file_name="sem-fuso.txt")
    event["occurredAtUtc"] = "2026-10-01T12:00:00"

    override = {
        "eventId": str(uuid4()),
        "justification": "Teste sem fuso",
        "occurredAtUtc": "2026-10-01T12:00:00",
        "userName": "teste",
        "endpointId": "ENDPOINT-A",
    }

    response = client.post(
        "/agent/events",
        json={
            "events": [event],
            "overrides": [override],
        },
    )

    assert response.status_code == 422
    assert memory_store.list_audit_events() == []