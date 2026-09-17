"""Contratos de dados trocados entre o agente desktop e o Centro de Administração.

Os nomes de campo (via ``alias``) e os valores de enum espelham exatamente o
que o domínio C# do agente (``SafeUpload.Agent.Core``) já produz e consome:

- :class:`PolicySchema` tem o mesmo formato JSON que ``LocalPolicyStore`` lê
  de ``policy.json`` (``PolicyDocument``/``MonitoredScopesDocument``).
- :class:`AuditEventSchema` tem os mesmos 17 campos que ``AuditEvent``
  (record C#) e que ``LocalQueueAuditSink`` grava em ``queue.jsonl``.
- :class:`OverrideEventSchema` espelha a linha de override da mesma fila.

Os valores de enum (``verdict``, itens de ``categories``) trafegam pelo nome
do membro C# (``"Blocked"``, ``"Cpf"``...), porque é assim que o
``JsonStringEnumConverter`` do .NET já serializa — não em minúsculo.

``populate_by_name=True`` em cada model aceita tanto o alias camelCase
(o que o agente manda) quanto o nome do campo em snake_case (conveniente
para montar objetos a partir de código Python), sem duplicar schemas.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

Verdict = Literal["Approved", "Blocked", "AllowedWithoutInspection"]
CategoryCode = Literal["Cpf", "Cnpj", "PaymentCard", "Password", "Secret"]


class MonitoredScopesSchema(BaseModel):
    """Espelha ``MonitoredScopesDocument`` (C#)."""

    model_config = ConfigDict(populate_by_name=True)

    extensions: list[str]
    destination_paths: list[str] = Field(alias="destinationPaths")
    source_paths: list[str] = Field(alias="sourcePaths", default_factory=list)
    removable_drives: bool = Field(alias="removableDrives")
    network_paths: bool = Field(alias="networkPaths")


class PolicySchema(BaseModel):
    """Espelha ``PolicyDocument`` (C#) — o mesmo formato de ``policy.json``."""

    model_config = ConfigDict(populate_by_name=True)

    version: int
    active_categories: list[CategoryCode] = Field(alias="activeCategories")
    monitored_scopes: MonitoredScopesSchema = Field(alias="monitoredScopes")
    max_file_size_mb: int = Field(alias="maxFileSizeMb")
    inspection_timeout_seconds: int = Field(alias="inspectionTimeoutSeconds")
    audit_only: bool = Field(alias="auditOnly")
    override_allowed: bool = Field(alias="overrideAllowed")
    fail_open: bool = Field(alias="failOpen")
    excluded_processes: list[str] = Field(alias="excludedProcesses")


class HeartbeatRequest(BaseModel):
    """Upsert de endpoint — primeira execução e heartbeats seguintes usam a mesma forma."""

    model_config = ConfigDict(populate_by_name=True)

    endpoint_id: str = Field(alias="endpointId")
    hostname: str
    os: str
    agent_version: str = Field(alias="agentVersion")
    policy_version: int = Field(alias="policyVersion")


class HeartbeatResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    endpoint_id: str = Field(alias="endpointId")
    server_time_utc: datetime = Field(alias="serverTimeUtc")
    policy_version: int = Field(alias="policyVersion")


class EndpointRecord(BaseModel):
    """Estado de um endpoint conhecido, guardado em :mod:`app.infrastructure.memory_store`."""

    model_config = ConfigDict(populate_by_name=True)

    endpoint_id: str = Field(alias="endpointId")
    hostname: str
    os: str
    agent_version: str = Field(alias="agentVersion")
    policy_version: int = Field(alias="policyVersion")
    last_seen_utc: datetime = Field(alias="lastSeenUtc")


class AuditEventSchema(BaseModel):
    """Espelha o record ``AuditEvent`` (C#) — os mesmos 17 campos."""

    model_config = ConfigDict(populate_by_name=True)

    event_id: UUID = Field(alias="eventId")
    occurred_at_utc: datetime = Field(alias="occurredAtUtc")
    endpoint_id: str = Field(alias="endpointId")
    user_name: str = Field(alias="userName")
    file_name: str = Field(alias="fileName")
    extension: str
    size_bytes: int = Field(alias="sizeBytes")
    verdict: Verdict
    categories: list[CategoryCode] = Field(default_factory=list)
    masked_snippets: list[str] = Field(alias="maskedSnippets", default_factory=list)
    process_name: str = Field(alias="processName")
    process_id: int = Field(alias="processId")
    destination_path: str = Field(alias="destinationPath")
    not_inspected_reason: str | None = Field(alias="notInspectedReason", default=None)
    policy_version: int = Field(alias="policyVersion")
    elapsed_ms: int = Field(alias="elapsedMs")
    dispatched: bool = False


class OverrideEventSchema(BaseModel):
    """Espelha a linha ``{"type":"override", ...}`` do ``queue.jsonl``."""

    model_config = ConfigDict(populate_by_name=True)

    event_id: UUID = Field(alias="eventId")
    justification: str
    occurred_at_utc: datetime = Field(alias="occurredAtUtc")
    user_name: str = Field(alias="userName")
    endpoint_id: str = Field(alias="endpointId")


class SubmitEventsRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    events: list[AuditEventSchema] = Field(default_factory=list)
    overrides: list[OverrideEventSchema] = Field(default_factory=list)


class SubmitEventsResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    accepted_events: int = Field(alias="acceptedEvents")
    accepted_overrides: int = Field(alias="acceptedOverrides")
