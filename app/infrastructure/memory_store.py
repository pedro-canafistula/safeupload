"""Armazenamento em memória para o que o agente desktop envia pela API.

Decisão de escopo: dict em memória, não banco de dados. Zero dependência
nova, testável em segundos, e evita duas fontes de verdade enquanto o resto
do Centro de Administração (``app/presentation/demo``) continua mockado.
O estado se perde a cada restart do processo — trade-off aceito para esta
entrega. Trocar por um `SqliteStore` depois é mudança isolada neste módulo;
nenhuma outra camada precisa mudar, porque `app.application.agent_service`
só conhece as funções abaixo, não a estrutura interna.

Os objetos de módulo (``_endpoints``, ``_audit_events``, ``_overrides``) já
são singletons de fato em Python — não há necessidade de uma classe ou
padrão de instância única por cima disso.
"""

from datetime import datetime, timezone

from app.domain.schemas import (
    AuditEventSchema,
    EndpointRecord,
    MonitoredScopesSchema,
    OverrideEventSchema,
    PolicySchema,
)

# Mesmos valores do policy.json padrão que `PolicyDocument.Default` (C#) usa
# quando o arquivo não existe — ver LocalPolicyStore.cs.
DEFAULT_POLICY = PolicySchema(
    version=1,
    active_categories=["Cpf", "Cnpj", "PaymentCard", "Password", "Secret"],
    monitored_scopes=MonitoredScopesSchema(
        extensions=[".txt", ".csv", ".docx", ".xlsx", ".pdf"],
        destination_paths=["C:\\SafeUpload\\Escopo Monitorado"],
        source_paths=[],
        removable_drives=True,
        network_paths=True,
    ),
    max_file_size_mb=20,
    inspection_timeout_seconds=5,
    audit_only=False,
    override_allowed=False,
    fail_open=True,
    excluded_processes=["System", "SafeUpload.Agent.App"],
)

_endpoints: dict[str, EndpointRecord] = {}
_audit_events: list[AuditEventSchema] = []
_overrides: list[OverrideEventSchema] = []


def get_current_policy() -> PolicySchema:
    """Política vigente. Única e global nesta entrega — sem política por-endpoint ainda."""
    return DEFAULT_POLICY


def upsert_endpoint(record: EndpointRecord) -> None:
    """Registra ou atualiza um endpoint. Primeira execução e heartbeats seguintes
    passam pela mesma função — não há distinção de payload entre os dois casos."""
    _endpoints[record.endpoint_id] = record


def list_endpoints() -> list[EndpointRecord]:
    """Mais recentes primeiro, para aparecerem no topo da tela de Endpoints."""
    return sorted(_endpoints.values(), key=lambda e: e.last_seen_utc, reverse=True)


def add_events(events: list[AuditEventSchema], overrides: list[OverrideEventSchema]) -> None:
    _audit_events.extend(events)
    _overrides.extend(overrides)


def list_audit_events() -> list[AuditEventSchema]:
    """Mais recentes primeiro, para aparecerem no topo da tela de Auditoria."""
    return sorted(_audit_events, key=lambda e: e.occurred_at_utc, reverse=True)


def count_recent_events_for_endpoint(endpoint_id: str, since_utc: datetime) -> int:
    return sum(
        1
        for event in _audit_events
        if event.endpoint_id == endpoint_id and event.occurred_at_utc >= since_utc
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
