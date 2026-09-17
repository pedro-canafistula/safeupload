"""Casos de uso da API do agente desktop.

Cada função recebe um schema de :mod:`app.domain.schemas`, fala com
:mod:`app.infrastructure.memory_store`, e devolve outro schema. Sem
classes/interfaces — são três operações, uma abstração maior não se paga
no prazo desta entrega.
"""

from app.domain.schemas import (
    AuditEventSchema,
    EndpointRecord,
    HeartbeatRequest,
    HeartbeatResponse,
    OverrideEventSchema,
    PolicySchema,
    SubmitEventsResponse,
)
from app.infrastructure import memory_store


def register_heartbeat(request: HeartbeatRequest) -> HeartbeatResponse:
    """Upsert do endpoint — primeira execução e heartbeats seguintes usam a mesma rota."""
    now = memory_store.utc_now()

    memory_store.upsert_endpoint(
        EndpointRecord(
            endpoint_id=request.endpoint_id,
            hostname=request.hostname,
            os=request.os,
            agent_version=request.agent_version,
            policy_version=request.policy_version,
            last_seen_utc=now,
        )
    )

    current_policy = memory_store.get_current_policy()

    return HeartbeatResponse(
        endpoint_id=request.endpoint_id,
        server_time_utc=now,
        policy_version=current_policy.version,
    )


def get_current_policy(endpoint_id: str | None = None) -> PolicySchema:
    """Política vigente. ``endpoint_id`` é aceito mas ignorado por ora — a
    política é única e global nesta entrega; o parâmetro mantém a porta
    aberta para política por-endpoint sem quebrar o contrato depois."""
    del endpoint_id
    return memory_store.get_current_policy()


def submit_events(
    events: list[AuditEventSchema],
    overrides: list[OverrideEventSchema],
) -> SubmitEventsResponse:
    memory_store.add_events(events, overrides)

    return SubmitEventsResponse(
        accepted_events=len(events),
        accepted_overrides=len(overrides),
    )
