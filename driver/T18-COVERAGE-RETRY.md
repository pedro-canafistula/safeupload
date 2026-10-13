# T18 — coverage snapshot retry before Degraded

Owner direction 2026-10-13 ([POST-MVP-PLAN.md](POST-MVP-PLAN.md#owner-decisions)): retry an `ERROR_RETRY` coverage
answer briefly before reporting Degraded, with admission authority unchanged. This note is the design for review.

## Current behavior

`MinifilterInterceptor.PublishAdmissionCoverageLoopAsync` polls `FilterPort.GetAdmissionCoverageStatus()` every 500 ms.
The driver builds the receipt from a complete writer-registry walk and returns `STATUS_RETRY` when the registry change
sequence or global uncertainty changed during that walk (`StageWriters.c`, [analysis](evidence/2026-10-12/t4-coverage-retry-analysis.md)).
`FilterSendMessage` reports that as HRESULT `0x800704D5` (`ERROR_RETRY`); the port throws `Win32Exception`, and the loop
publishes `Degraded / CoverageQueryFailed` for that poll. Under ordinary saving the next poll is usually Ready again.
T4 short rows logged 12–21 such Degraded notices per run; users would see false "protection degraded" transitions.

## What the status controls

The published status reaches the tray (`StatusViewModel`), the service event log and the one-time `ReadySignal`. It does
not authorize any operation: the driver admits or refuses each operation from its own state, and a staged version is
approved only by complete inspection. A failed query never authorizes publication today, and nothing below changes that.

## Change

1. Within one poll, when the coverage query fails with a `Win32Exception` whose **`NativeErrorCode`** is exactly
   `unchecked((int)0x800704D5)` (the port stores the HRESULT there; `Exception.HResult` stays `E_FAIL`), query again after
   10, 20 and 40 ms: at most three retries, sequential, each send lease released before the delay, delays cancellable.
   The first successful receipt is evaluated exactly as today. Match only this coverage query; do not generalize the rule
   to other controls (several also return `STATUS_RETRY`). The HRESULT carries no return-edge provenance, so retrying is
   a reporting choice, not proof that the churn was harmless.
2. If every retry still answers `ERROR_RETRY`, publish `Degraded / CoverageQueryFailed` exactly as today.
3. Any other exception, a malformed receipt, cancellation or a non-retry HRESULT behaves exactly as today: no retry.
4. The published status is never held or synthesized; nothing is published until a real receipt or the final failure.
   Reporting latency: a retrying poll adds the 70 ms delay budget **plus up to three more query durations** (each waits on
   the uncancellable send gate and a synchronous `FilterSendMessage`), on top of the existing poll interval. Cancellation
   bounds the delays, not an in-flight native query. The previously published status stays displayed meanwhile.
5. Count retries and exhausted retries in the existing diagnostics/log path (one warning per exhausted sequence, the
   existing duplicate-suppression rule applies), so persistent churn remains visible to administrators.
6. Startup readiness flags are sampled after the retries, so a startup failure arising during a retry delay is applied
   to the final decision. Existing precedence remains: a changing snapshot evaluates Pending before Unknown/policy/identity
   checks, and `ApplyStageStartupReadiness` preserves Pending/Degraded even when startup failed (tested today); this design
   does not change it, and persistent failures can never become Ready.

The retry logic is a small static helper taking the query and delay functions, so tests drive it without a driver port.
Each query walks the writer registry under a shared lock at PASSIVE_LEVEL; four sequential walks add contention but no
new lock order, IRQL transition or mutation. Record the actual latency during the eventual authorized qualification.

## Not changed

Kernel code and protocol, the evaluator, Ready/Pending/Degraded semantics, sticky Unknown, the startup readiness gate,
admission/inspection/publication authority, and the 500 ms poll.

## Tests

- Production-shaped exceptions: `new Win32Exception(unchecked((int)0x800704D5), ...)` retries; the same value only in
  `HResult`, another `NativeErrorCode`, `InvalidDataException` and a generic exception do not retry (one query, Degraded).
- `ERROR_RETRY` then success on attempt 2, 3 and 4: one evaluation each, no Degraded published, retries counted.
- `ERROR_RETRY` on every attempt: exactly four queries with delays exactly 10/20/40 ms, then `Degraded /
  CoverageQueryFailed`; exhaustion counted. Repeated exhausted sequences increment the counter even while the duplicate
  warning is suppressed.
- Retry followed by a terminal non-retry error or a malformed receipt: Degraded, no further query.
- Cancellation during a retry delay stops without another query and without publishing.
- Retry followed by an Unknown, policy-failure, identity-failure or generation-mismatch receipt: published as evaluated,
  never upgraded. Retry followed by Ready while the current startup flags reject staging: the startup rejection wins.

Review: [Sol 6.1 xhigh, ACCEPT WITH CONDITIONS](evidence/2026-10-13/t18-coverage-retry-review-sol61.md); the conditions
are incorporated above.

## Qualification

Agent matrix (normal/feature × Debug/Release). The T4 short row on the final pair should show `CoverageQueryFailed`
notices only for exhausted sequences; the post-idle Ready assertion stays as is. That row is not authorized by this
design; it runs only when product VM rows resume.
