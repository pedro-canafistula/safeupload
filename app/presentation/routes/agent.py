"""Rotas chamadas pelo agente desktop instalado nos endpoints (HU-10).

Fecha o ciclo entre o agente (C#, ``agente/SafeUpload.Agent.Service``) e o
Centro de Administração pela primeira vez: registro/heartbeat de endpoint,
distribuição de política, e envio de eventos de auditoria. Antes desta
rota, os dois lados nunca trocavam dado — o agente lia política só de
``policy.json`` local e gravava auditoria só em ``queue.jsonl`` em disco.

Os formatos de request/response (:mod:`app.domain.schemas`) espelham
exatamente o que o domínio C# já usa (``Policy``, ``AuditEvent`` em
``SafeUpload.Agent.Core``), para que ``HttpPolicyStore``/o despachante de
auditoria — os pontos de extensão que ``IPolicyStore``/``IAuditSink`` já
anticipam em comentário, citando esta mesma HU-10 — só troquem a fonte do
dado quando forem implementados, sem tocar no domínio C#.

Limitações conhecidas desta entrega, deliberadas:

- **Sem autenticação.** Nada no projeto tem autenticação real hoje (nem
  ``/admin/login``, que é stub). Uma chave fixa só nesta rota seria
  segurança de fachada — prova que quem chamou conhece uma string, não
  quem é o endpoint. Fica como TODO explícito para uma HU futura de
  enrollment/token, não como omissão silenciosa.
- **Persistência em memória**, não banco — ver
  :mod:`app.infrastructure.memory_store`. Estado se perde a cada restart.
- **Identidade do endpoint é uma string opaca** (``endpointId``). O agente
  C# hoje só tem ``Environment.MachineName``; o contrato aceita qualquer
  string, então isso já funciona sem alteração quando o agente real for
  ligado. Recomendação para quando o C# for atualizado: gerar um GUID na
  primeira execução e persistir ao lado de ``policy.json``, em vez de
  depender do hostname (que muda se a máquina for renomeada).
- **Política é única e global** — sem política por-endpoint ainda, embora
  o parâmetro ``endpointId`` já seja aceito em ``GET /agent/policy`` para
  não quebrar o contrato quando isso existir.
"""

from fastapi import APIRouter

from app.application import agent_service
from app.domain.schemas import (
    HeartbeatRequest,
    HeartbeatResponse,
    PolicySchema,
    SubmitEventsRequest,
    SubmitEventsResponse,
)

router = APIRouter(prefix="/agent", tags=["agent"])


@router.post("/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(request: HeartbeatRequest) -> HeartbeatResponse:
    """Upsert do endpoint. Primeira execução e heartbeats seguintes usam esta
    mesma rota — não há diferença de payload entre "novo" e "já conhecido"."""
    return agent_service.register_heartbeat(request)


@router.get("/policy", response_model=PolicySchema)
async def policy(endpoint_id: str | None = None) -> PolicySchema:
    """Política vigente, no mesmo formato de ``policy.json``."""
    return agent_service.get_current_policy(endpoint_id)


@router.post("/events", response_model=SubmitEventsResponse)
async def events(request: SubmitEventsRequest) -> SubmitEventsResponse:
    """Recebe o lote que um despachante leria de ``queue.jsonl``: eventos de
    auditoria e registros de justificativa/override, em arrays separados."""
    return agent_service.submit_events(request.events, request.overrides)
