"""Contexto do painel administrativo baseado nos eventos recebidos."""

from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

from app.domain.schemas import AuditEventSchema, PolicySchema

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

_WEEKDAY_LABELS = ["Seg", "Ter", "Qua", "Qui", "Sex", "Sáb", "Dom"]


def _as_utc(value: datetime) -> datetime:
    return value.astimezone(timezone.utc)


def _format_size(size_bytes: int) -> str:
    if size_bytes >= 1024 * 1024:
        text = f"{size_bytes / (1024 * 1024):.1f}".replace(".", ",")
        return f"{text} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.0f} KB"
    return f"{size_bytes} B"


def _percentage_text(value: int, total: int) -> str:
    if total == 0:
        return "0,0% do total"
    percentage = f"{value / total * 100:.1f}".replace(".", ",")
    return f"{percentage}% do total"


def build_dashboard_context(
    events: Sequence[AuditEventSchema],
    policy: PolicySchema,
    *,
    now: datetime,
) -> dict:
    """Monta indicadores reais do painel para os últimos sete dias."""
    now_utc = _as_utc(now)
    first_day = now_utc.date() - timedelta(days=6)

    period_events = [
        event
        for event in events
        if first_day <= _as_utc(event.occurred_at_utc).date() <= now_utc.date()
        and _as_utc(event.occurred_at_utc) <= now_utc
    ]

    counts = Counter(event.verdict for event in period_events)
    total = len(period_events)
    blocked = counts["Blocked"]
    approved = counts["Approved"]
    not_inspected = counts["AllowedWithoutInspection"]

    daily_counts = Counter(_as_utc(event.occurred_at_utc).date() for event in period_events)
    days = [first_day + timedelta(days=offset) for offset in range(7)]
    max_daily = max((daily_counts[day] for day in days), default=0)
    trend = [
        {
            "label": _WEEKDAY_LABELS[day.weekday()],
            "date": day.strftime("%d/%m"),
            "value": daily_counts[day],
            "percentage": round(daily_counts[day] / max_daily * 100) if max_daily else 0,
        }
        for day in days
    ]

    category_counts: Counter[str] = Counter()
    for event in period_events:
        if event.verdict == "Blocked":
            category_counts.update(event.categories)

    max_category = max(category_counts.values(), default=0)
    categories_top = [
        {
            "code": code,
            "name": _CATEGORY_LABELS[code],
            "value": count,
            "percentage": round(count / max_category * 100) if max_category else 0,
        }
        for code, count in sorted(
            category_counts.items(),
            key=lambda item: (-item[1], _CATEGORY_LABELS[item[0]]),
        )
    ]

    recent_events = []
    for event in sorted(events, key=lambda item: item.occurred_at_utc, reverse=True)[:6]:
        result_kind, result_label = _VERDICT_TO_RESULT[event.verdict]
        recent_events.append(
            {
                "datetime": event.occurred_at_utc.strftime("%d/%m %H:%M"),
                "filename": event.file_name,
                "size": _format_size(event.size_bytes),
                "result_kind": result_kind,
                "result_label": result_label,
                "categories": [_CATEGORY_LABELS[category] for category in event.categories],
            }
        )

    categories_status = [
        {"code": code, "label": _CATEGORY_LABELS[code], "enabled": True}
        for code in policy.active_categories
    ]

    return {
        "active_page": "dashboard",
        "period_label": "Últimos 7 dias",
        "kpis": {
            "total": {
                "value": total,
                "trend": "Últimos 7 dias",
                "trend_kind": "neutral",
            },
            "blocked": {
                "value": blocked,
                "trend": _percentage_text(blocked, total),
                "trend_kind": "neutral",
            },
            "approved": {
                "value": approved,
                "trend": _percentage_text(approved, total),
                "trend_kind": "neutral",
            },
            "not_inspected": {
                "value": not_inspected,
                "trend": _percentage_text(not_inspected, total),
                "trend_kind": "neutral",
            },
        },
        "trend": trend,
        "categories_top": categories_top,
        "categories_status": categories_status,
        "recent_events": recent_events,
    }
