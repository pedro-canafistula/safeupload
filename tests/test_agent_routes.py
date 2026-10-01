"""Testes de fumaça para a API do agente desktop (HU-10)."""

from app.infrastructure import memory_store


def test_heartbeat_upsert_nao_duplica(client):
    payload = {
        "endpointId": "DESKTOP-TESTE01",
        "hostname": "DESKTOP-TESTE01",
        "os": "Windows 11 Pro",
        "agentVersion": "2.3.1",
        "policyVersion": 1,
    }

    first = client.post("/agent/heartbeat", json=payload)
    second = client.post("/agent/heartbeat", json=payload)

    assert first.status_code == 200
    assert second.status_code == 200
    assert len(memory_store._endpoints) == 1
    assert first.json()["endpointId"] == "DESKTOP-TESTE01"


def test_get_policy_formato_esperado(client):
    response = client.get("/agent/policy")

    assert response.status_code == 200
    body = response.json()

    assert body["version"] == 1
    assert set(body["activeCategories"]) == {"Cpf", "Cnpj", "PaymentCard", "Password", "Secret"}
    assert body["monitoredScopes"]["extensions"] == [".txt", ".csv", ".docx", ".xlsx", ".pdf"]
    assert body["maxFileSizeMb"] == 20
    assert body["inspectionTimeoutSeconds"] == 5
    assert body["failOpen"] is True


def test_submit_events_aceita_lote_e_aparece_na_auditoria(client):
    payload = {
        "events": [
            {
                "eventId": "b1f3c2a0-1111-4a2b-8c3d-000000000001",
                "occurredAtUtc": "2026-09-17T13:42:15Z",
                "endpointId": "DESKTOP-TESTE01",
                "userName": "pedro",
                "fileName": "relatorio.xlsx",
                "extension": ".xlsx",
                "sizeBytes": 204800,
                "verdict": "Blocked",
                "categories": ["Cpf", "Cnpj"],
                "maskedSnippets": ["***.***.***-**"],
                "processName": "EXCEL.EXE",
                "processId": 4321,
                "destinationPath": "C:\\SafeUpload\\Escopo Monitorado\\relatorio.xlsx",
                "notInspectedReason": None,
                "policyVersion": 1,
                "elapsedMs": 120,
                "dispatched": False,
            }
        ],
        "overrides": [
            {
                "eventId": "b1f3c2a0-1111-4a2b-8c3d-000000000002",
                "justification": "Falso positivo confirmado",
                "occurredAtUtc": "2026-09-17T13:45:00Z",
                "userName": "pedro",
                "endpointId": "DESKTOP-TESTE01",
            }
        ],
    }

    response = client.post("/agent/events", json=payload)

    assert response.status_code == 200
    assert response.json() == {"acceptedEvents": 1, "acceptedOverrides": 1}

    page = client.get("/admin/auditoria")
    assert page.status_code == 200
    context = page.context
    real_row = next(row for row in context["events"] if row["filename"] == "relatorio.xlsx")

    assert real_row["result_kind"] == "blocked"
    assert real_row["source"] == "DESKTOP-TESTE01"
    assert "CPF" in real_row["categories"]
    assert "CNPJ" in real_row["categories"]
