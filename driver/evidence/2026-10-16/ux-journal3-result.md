# T4 outcome audit-history scaling

Base: `2121f24ee568b41c9da4175328df7fc017a0b98b`. Delivery: `ux/journal`,
`.scratch/ux-journal3.bundle`; the source worktree's Git stays unchanged.

## Finding and change

A legacy public-file open that misses the driver's stream cache still goes through
`SafeUploadEvaluate` → `MinifilterInterceptor.Judge` → `Announce`.
`Announce` requested five recent audit events, but `LocalQueueAuditSink.ReadRecentAsync`
read and deserialized **every** retained `queue.jsonl` record before selecting five.
It held the same semaphore as staged publication's outcome append. The T4 coordinator's
`Read-Public` byte observation is inside `OutcomeMs`, after the save ACK; therefore
this is both an outcome-observation cost and a possible publication-audit convoy.
This explains how an O(history) operation can coexist with flat allocation/seal ACKs.
A Windows phase trace is still required to quantify its share of the reported slope.

Positive recent-event requests now scan complete UTF-8 lines backwards from a captured
file end, stopping at the requested count. Newest-first ordering, malformed/empty-line
handling, BOM handling, cancellation and concurrent writer sharing are preserved.
The queue is untouched. Explicit full-history requests and legacy UTF-16/32 queues
retain their full-reader semantics. Added `audit-recent` request timing isolates the
operation in the next Windows run.

No destination-head, transfer archive, authority, retention, generation barrier,
receipt, notification-record or readiness rule changes. No V30 path is imported.
The bounded archive inventory and per-path archived maximum are not rewritten with
all historical transfers on each save. The existing notification record is bounded;
hand-back creation uses a direct GUID leaf rather than enumerating old hand-backs.

## Local evidence

The owner-supplied live input contains 4,659 successful cycles and 1,171 distinct
public names: the `new` pattern creates unique names; the others reuse two each.
The local repro deliberately uses eight fixed destination names.

The added 10k audit-outcome control writes 10,000 records for eight names, recreates
the sink, then measures eight five-event requests. It asserts exact event IDs/order,
unchanged history bytes, all 10k records still readable, a **2 MiB** allocation bound
and a **1,000 ms** elapsed bound for the eight requests. The same control on the base
fails: **1,948.200 ms / 193,736,408 B**. After the fix:

| Feature configuration | Eight reads | Per read/save | Allocation, eight reads |
|---|---:|---:|---:|
| Debug | 3.369 ms | 0.421 ms | 258,352 B |
| Release | 3.577 ms | 0.447 ms | 254,600 B |

The separate 10k journal lifecycle repro creates/seals/transitions/commits/completes,
appends real durable audit/notification records, disposes and archives each transfer.
The native rename callback is a no-op fixture; it does not qualify public NTFS bytes.
Before adding the legacy recent-event read, its final-100 mean was **14.481 ms/save**
(14.394 ms at cycle 500), with **0 hot manifests / 10,000 archived transfers**.
The recent-read variant exercises the same audit operation as `Announce` after each
save. Phase data and source are retained in [the repro evidence](ux-journal3/controls.json).
Write-phase latency bursts on the shared host are retained in those measurements;
they are not deleted as outliers.

At cycle 10,000, the recent-read variant's final-100 mean was
**156.958 → 16.439 ms per metadata/audit lifecycle**;
its observer audit/recent phase was **136.541 → 0.216 ms/save**.
Both runs finished with 0 hot manifests and all 10,000 exact transfers archived.

Focused Linux feature Debug and Release: **84/84 each**, zero skipped cases,
zero build warnings/errors. Includes the nine new audit cases, existing audit
encoding/privacy/dispatch controls, all 61 previous archive/receipt/barrier/restart,
terminal-read-free, maintenance-retry and timing controls. Existing tests and their
thresholds are unchanged, including the native ACK/last-close invariant.
The serial in-process xUnit runner uses the real assertions; the sandbox's standard
test host cannot open its local socket. Raw logs remain under `.scratch/ux-journal3/`.
Hashes, exact counts and full phase samples are in [controls](ux-journal3/controls.json).

## Remaining qualification

These are local component results, not a native Windows matrix or protected T4
verdict. No builder job or VM state change was performed. A read-only live inventory
attempt was refused by the sandbox's socket restriction; live hot-state counts were
not available. The full Windows Debug/Release user+SYSTEM matrix and matched T4 run
remain required. The new phase can confirm any residual Windows outcome delay.
The T4 coordinator still enumerates/sorts accumulated hand-backs on blocked
observations; that harness cost cannot explain the approved-save slope and is
not changed here. Its assertions and timing definitions remain intact.

Tail work is proportional to bytes through the requested valid records: unusually
large records or a long malformed suffix still cost their own bytes. Explicit full
history, pending audit dispatch and legacy UTF-16/32 compatibility still scan history.
This fix does not impose a new audit-retention cap or discard records to meet a bound.
