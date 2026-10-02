from datetime import datetime, timezone
from uuid import uuid4

from app.infrastructure import memory_store


def event_payload(
    *,
    occurred_at: str,
    file_name: str,
    verdict: str = "Approved",
    categories: list[str] | None = None,
) -> dict:
    return {
        "eventId": str(uuid4()),
        "occurredAtUtc": occurred_at,
        "endpointId": "ENDPOINT-DASHBOARD",
        "userName": "teste",
        "fileName": file_name,
        "extension": ".txt",
        "sizeBytes": 2048,
        "verdict": verdict,
        "categories": categories or [],
        "processName": "editor",
        "processId": 1,
        "destinationPath": "C:\\destino",
        "policyVersion": 1,
        "elapsedMs": 10,
    }


def test_dashboard_vazio_usa_estado_real_e_politica_vigente(client, monkeypatch):
    now = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(memory_store, "utc_now", lambda: now)

    page = client.get("/admin/dashboard")

    assert page.status_code == 200
    assert page.context["kpis"]["total"]["value"] == 0
    assert page.context["kpis"]["blocked"]["value"] == 0
    assert page.context["kpis"]["approved"]["value"] == 0
    assert page.context["kpis"]["not_inspected"]["value"] == 0
    assert page.context["recent_events"] == []
    assert [item["code"] for item in page.context["categories_status"]] == [
        "Cpf", "Cnpj", "PaymentCard", "Password", "Secret",
    ]
    assert "Nenhuma inspeção recebida" in page.text
    assert "1.247" not in page.text
    assert "24h" not in page.text
    assert "30 dias" not in page.text
    assert "Segredo/credencial" in page.text


def test_dashboard_calcula_kpis_reais_dos_ultimos_sete_dias(client, monkeypatch):
    now = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(memory_store, "utc_now", lambda: now)

    events = [
        event_payload(occurred_at="2026-10-01T11:00:00Z", file_name="aprovado.txt"),
        event_payload(occurred_at="2026-09-30T11:00:00Z", file_name="bloqueado.txt", verdict="Blocked", categories=["Cpf"]),
        event_payload(occurred_at="2026-09-29T11:00:00Z", file_name="sem-inspecao.txt", verdict="AllowedWithoutInspection"),
        event_payload(occurred_at="2026-09-24T11:00:00Z", file_name="fora-periodo.txt", verdict="Blocked", categories=["Cnpj"]),
        event_payload(occurred_at="2026-10-01T13:00:00Z", file_name="futuro.txt", verdict="Blocked", categories=["Secret"]),
    ]
    assert client.post("/agent/events", json={"events": events}).status_code == 200

    page = client.get("/admin/dashboard")
    kpis = page.context["kpis"]

    assert kpis["total"]["value"] == 3
    assert kpis["blocked"]["value"] == 1
    assert kpis["approved"]["value"] == 1
    assert kpis["not_inspected"]["value"] == 1
    assert kpis["blocked"]["trend"] == "33,3% do total"
    assert "Liberados sem inspeção" in page.text


def test_dashboard_agrega_tendencia_e_categorias_bloqueadas(client, monkeypatch):
    now = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(memory_store, "utc_now", lambda: now)

    events = [
        event_payload(occurred_at="2026-09-29T08:00:00Z", file_name="a.txt", verdict="Blocked", categories=["Cpf", "Cnpj"]),
        event_payload(occurred_at="2026-09-29T09:00:00Z", file_name="b.txt", verdict="Blocked", categories=["Cpf"]),
        event_payload(occurred_at="2026-09-30T10:00:00Z", file_name="c.txt", categories=["Secret"]),
        event_payload(occurred_at="2026-10-01T11:00:00Z", file_name="d.txt", verdict="Blocked", categories=["Password"]),
    ]
    client.post("/agent/events", json={"events": events})

    page = client.get("/admin/dashboard")

    trend_by_date = {item["date"]: item for item in page.context["trend"]}
    assert trend_by_date["29/09"]["value"] == 2
    assert trend_by_date["29/09"]["percentage"] == 100
    assert trend_by_date["30/09"]["value"] == 1
    assert trend_by_date["30/09"]["percentage"] == 50

    categories = [(item["name"], item["value"]) for item in page.context["categories_top"]]
    assert categories == [
        ("CPF", 2),
        ("CNPJ", 1),
        ("Senha em texto claro", 1),
    ]
    assert "Segredo/credencial" in page.text  # política ativa, não ranking de bloqueios


def test_dashboard_exibe_somente_seis_eventos_mais_recentes(client, monkeypatch):
    now = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(memory_store, "utc_now", lambda: now)

    events = [
        event_payload(
            occurred_at=f"2026-10-01T{hour:02d}:00:00Z",
            file_name=f"arquivo-{hour}.txt",
            verdict="AllowedWithoutInspection" if hour == 11 else "Approved",
        )
        for hour in range(5, 12)
    ]
    client.post("/agent/events", json={"events": events})

    page = client.get("/admin/dashboard")
    names = [item["filename"] for item in page.context["recent_events"]]

    assert len(names) == 6
    assert names == [
        "arquivo-11.txt",
        "arquivo-10.txt",
        "arquivo-9.txt",
        "arquivo-8.txt",
        "arquivo-7.txt",
        "arquivo-6.txt",
    ]
    assert "arquivo-5.txt" not in page.text
    assert "Liberado sem inspeção" in page.text


def test_dashboard_escapa_textos_recebidos(client, monkeypatch):
    now = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(memory_store, "utc_now", lambda: now)

    event = event_payload(
        occurred_at="2026-10-01T11:00:00Z",
        file_name='<script>alert("dashboard")</script>',
    )
    client.post("/agent/events", json={"events": [event]})

    page = client.get("/admin/dashboard")

    assert '<script>' not in page.text
    assert '&lt;script&gt;' in page.text
