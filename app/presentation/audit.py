"""Contexto de apresentação dos eventos recebidos dos agentes."""

from collections.abc import Sequence

from app.domain.schemas import AuditEventSchema

_CATEGORY_LABELS = {
    "Cpf": "CPF",
    "Cnpj": "CNPJ",
    "PaymentCard": "Cartão de pagamento",
    "Password": "Senha em texto claro",
    "Secret": "Segredo/credencial",
}

_VERDICT_TO_RESULT = {
    "Approved": ("approved", "Aprovado"),
    "Blocked": ("blocked", "Bloqueado"),
    "AllowedWithoutInspection": ("not-inspected", "Liberado sem inspeção"),
}


def _format_size(size_bytes: int) -> str:
    if size_bytes >= 1024 * 1024:
        text = f"{size_bytes / (1024 * 1024):.1f}".replace(".", ",")
        return f"{text} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.0f} KB"
    return f"{size_bytes} B"


def build_audit_context(
    events: Sequence[AuditEventSchema],
    *,
    endpoint_id: str | None = None,
) -> dict:
    rows = []
    stats = {"total": len(events), "blocked": 0, "approved": 0, "not_inspected": 0}

    for event in events:
        result_kind, result_label = _VERDICT_TO_RESULT[event.verdict]
        stats[result_kind.replace("-", "_")] += 1
        rows.append({
            "datetime": event.occurred_at_utc.strftime("%d/%m/%Y %H:%M:%S %z").strip(),
            "source": event.endpoint_id,
            "filename": event.file_name,
            "size": _format_size(event.size_bytes),
            "result_kind": result_kind,
            "result_label": result_label,
            "categories": [_CATEGORY_LABELS[category] for category in event.categories],
            "not_inspected_reason": event.not_inspected_reason,
        })

    return {
        "active_page": "audit",
        "stats": stats,
        "events": rows,
        "endpoint_filter": endpoint_id,
    }
