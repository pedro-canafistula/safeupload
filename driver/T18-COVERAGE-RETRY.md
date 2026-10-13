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

1. Within one poll, when the query fails with exactly HRESULT `0x800704D5`, query again after 10, 20 and 40 ms (at most
   three retries, about 70 ms in total, cancellable). The first successful receipt is evaluated exactly as today.
2. If every retry still answers `ERROR_RETRY`, publish `Degraded / CoverageQueryFailed` exactly as today.
3. Any other exception, a malformed receipt, cancellation or a non-retry HRESULT behaves exactly as today: no retry.
4. The published status is never held or synthesized. Between polls the displayed status is already up to 500 ms old;
   the retries extend one poll by at most about 70 ms and publish nothing until a real receipt or the final failure.
5. Count retries and exhausted retries in the existing diagnostics/log path (one warning per exhausted sequence, the
   existing duplicate-suppression rule applies), so persistent churn remains visible to administrators.

The retry logic is a small static helper taking the query and delay functions, so tests drive it without a driver port.

## Not changed

Kernel code and protocol, the evaluator, Ready/Pending/Degraded semantics, sticky Unknown, the startup readiness gate,
admission/inspection/publication authority, and the 500 ms poll.

## Tests

- `ERROR_RETRY` once then a Ready receipt: one Ready evaluation, no Degraded published, one retry counted.
- `ERROR_RETRY` on every attempt: exactly four queries, then `Degraded / CoverageQueryFailed`; exhaustion counted.
- Another `Win32Exception` HRESULT, `InvalidDataException` and a generic exception: one query, immediate Degraded.
- Cancellation during a retry delay stops without publishing.
- A Pending or Degraded receipt after a retry is published as evaluated, never upgraded.

## Qualification

Agent matrix (normal/feature × Debug/Release). The T4 short row on the final pair should show `CoverageQueryFailed`
notices only for exhausted sequences; the post-idle Ready assertion stays as is.
