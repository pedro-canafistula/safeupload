"""Contexto de apresentação do inventário de endpoints registrados."""

from collections.abc import Sequence
from datetime import datetime, timedelta

from app.domain.schemas import AuditEventSchema, EndpointRecord

ONLINE_THRESHOLD = timedelta(seconds=90)


def _format_datetime(value: datetime) -> str:
    return value.strftime("%d/%m/%Y %H:%M:%S %z").strip()


def _os_kind(os_name: str) -> str:
    normalized = os_name.casefold()
    if "windows 11" in normalized:
        return "win11"
    if "windows 10" in normalized:
        return "win10"
    return "other"


def _os_short(os_name: str) -> str:
    kind = _os_kind(os_name)
    if kind == "win11":
        return "Win 11"
    if kind == "win10":
        return "Win 10"
    return os_name


def _normalize_status(value: str) -> str:
    return value if value in {"all", "online", "offline"} else "all"


def _normalize_os(value: str) -> str:
    return value if value in {"all", "win11", "win10", "other"} else "all"


def build_endpoints_context(
    endpoints: Sequence[EndpointRecord],
    audit_events: Sequence[AuditEventSchema],
    *,
    now: datetime,
    status_filter: str = "all",
    os_filter: str = "all",
    query: str = "",
) -> dict:
    """Monta o inventário real, os totais e os filtros da página de Endpoints."""
    status_filter = _normalize_status(status_filter)
    os_filter = _normalize_os(os_filter)
    query = query.strip()
    query_normalized = query.casefold()
    since_7d = now - timedelta(days=7)

    inspections_by_endpoint: dict[str, int] = {}
    for event in audit_events:
        if event.occurred_at_utc >= since_7d:
            inspections_by_endpoint[event.endpoint_id] = (
                inspections_by_endpoint.get(event.endpoint_id, 0) + 1
            )

    rows = []
    stats = {"total": len(endpoints), "online": 0, "offline": 0}

    for record in endpoints:
        online = now - record.last_seen_utc <= ONLINE_THRESHOLD
        status = "online" if online else "offline"
        stats[status] += 1
        os_kind = _os_kind(record.os)

        row = {
            "endpoint_id": record.endpoint_id,
            "hostname": record.hostname,
            "os": record.os,
            "os_kind": os_kind,
            "os_short": _os_short(record.os),
            "agent_version": record.agent_version,
            "policy_version": f"v{record.policy_version}",
            "last_seen": _format_datetime(record.last_seen_utc),
            "status": status,
            "status_label": "Online" if online else "Offline",
            "inspections_7d": inspections_by_endpoint.get(record.endpoint_id, 0),
        }

        if status_filter != "all" and row["status"] != status_filter:
            continue
        if os_filter != "all" and row["os_kind"] != os_filter:
            continue
        if query_normalized and query_normalized not in (
            f"{record.hostname} {record.endpoint_id}".casefold()
        ):
            continue

        rows.append(row)

    return {
        "active_page": "endpoints",
        "stats": stats,
        "endpoints": rows,
        "filters": {
            "status": status_filter,
            "os": os_filter,
            "q": query,
        },
        "filter_options": {
            "statuses": [
                {"value": "all", "label": "Todos os status"},
                {"value": "online", "label": "Online"},
                {"value": "offline", "label": "Offline"},
            ],
            "os_list": [
                {"value": "all", "label": "Todos os sistemas"},
                {"value": "win11", "label": "Windows 11"},
                {"value": "win10", "label": "Windows 10"},
                {"value": "other", "label": "Outros"},
            ],
        },
        "online_threshold_seconds": int(ONLINE_THRESHOLD.total_seconds()),
    }
