# Independent design review: proved resource refusal

2026-10-19 — **gpt-6.1-sol, high**. Reviewed First repair in
[t4-smoke-diagnosis.md](t4-smoke-diagnosis.md) against source
`a9f292b8e00586521f540a971adef4dade7dbaff` and current contributor/owner rules.
**ACCEPT WITH CONDITIONS for the narrow agent-only design below.** This is not
implementation acceptance, T4 qualification, or approval of capacity/sharing
changes. No product/harness edits, builds, tests, VMs or builder jobs performed.
The failed smoke and successful separate restoration remain separate results.

## Source findings

- `StagedAllocationResolution.cs:38` holds `_v19AllocationGate` across manifest
  lookup, `prepare` (`:83`) and the existing null-result absence proof (`:87`).
  Stable-ID allocation (`StagedTransferAllocator.cs:361`) and failed-allocation
  recovery (`StagedAllocationRecovery.cs:16`) use the same allocator gate.
  Production staging dispatch uses this resolver and refuses the legacy route
  (`MinifilterInterceptor.cs:415`). Thus extending the proof **inside that same
  critical section**, after the awaited prepare has fully unwound, cannot race
  another supported allocation/recovery producer for this reservation.
- A resource exception is not absence evidence. Allocation commits the manifest
  before binding its grant (`StagedTransferAllocator.cs:291`–`:294`). Its catch
  rereads durable state and preserves a committed backing (`:299`–`:303`).
  Journal replacement can commit and then throw (`StagedTransferJournal.cs:460`–
  `:467`); metadata admission can independently throw `StagedSpaceException`
  (`StagedSpaceBudget.cs:391`, `:410`). The new proof must reread the exact
  manifest again, including archived state, and refuse terminal classification
  on **any** present manifest, malformed data, inaccessible state or read error.
  Journal `ReadAsync` takes its gate and reads actual state (`:1502`–`:1552`),
  rather than trusting the stale pre-prepare result.
- `RequireFailedAllocationAbsent` already rejects issued/legacy grants, changed
  locators, snapshots, unknown present backing and unsuccessful exact cleanup
  (`StagedSpaceBudget.cs:442`–`:459`). `RetireFailedAllocation` also checks live
  snapshot ownership and deletes only its recorded identity (`:432`–`:438`).
  **It does not check the `.space` companion when no reservation record exists.**
  Explicit companion absence is required in every successful new proof branch;
  copying the current null-result block alone is insufficient.
- Ambiguous ledger persistence latches `_faulted` (`StagedSpaceBudget.cs:670`–
  `:683`); `RequireHealthy` must remain a fatal proof failure (`:665`). A missing
  in-memory dictionary entry must not override that latch or unresolved disk
  ledger residue. Constructor inventory rejects malformed/partial ledger files
  (`:84`–`:104`). Keep that startup behavior. Unknown backing identity, a changed
  object, sharing/access failure, companion residue and any unresolved snapshot
  or ledger remain held; do not delete them by newly observed path identity.

## Minimal safe implementation and conditions

1. Catch **only the direct `StagedSpaceException` thrown by the awaited prepare**
   inside `ResolveAllocationRequestV20Async`. Do not wrap the existing committed
   replay/Bind branch in this catch and do not broaden it to `IsSpace`, generic
   IOException, native disk errors, AggregateException or nested space causes.
   Conservatively leaving wrapped/post-commit failures uncertain is correct.
2. Reuse a shared terminal-proof helper while retaining allocator serialization:
   re-read manifest; validate the reservation-derived stage locator; run existing
   healthy-budget/unissued exact cleanup; confirm both stage and `.space` absent.
   Preserve the exact ledger's no-grant/no-snapshot obligations and all cleanup
   failures. Do not turn `TryDeleteUnjournaled` into authority to delete unknown
   resource-failure residue. The new space-exception route should require its
   real budget proof; a missing budget is not permission to infer no grant. A
   shared helper may preserve the existing legacy null-prepare behavior without
   silently widening this new route. No new negative receipt/protocol state.
3. Construct an internal, sealed proof-result exception only **after the helper
   succeeds**. Its original space exception remains InnerException. The
   interceptor may classify that direct proof-marker as the existing exact
   `NoAllocationCommitted`, using the existing request-echo reply; it must never
   infer the marker from an error message, generic permanent refusal or nested
   cause. Existing replay, request/owner/driver/parent binding and kernel late
   kind-5 cleanup remain unchanged.
4. Preserve notification on both proved refusals and failed proofs. Current
   `StagedSpaceFailure.IsSpace` follows only the InnerException chain, and the
   existing interceptor emits the space alert before failure classification
   (`MinifilterInterceptor.cs:855`–`:871`). If proof fails, retain its diagnostics
   while wrapping the **original space exception directly in that chain**;
   neither throw only the cleanup error nor bury the resource cause solely in an
   AggregateException collection. Failed proof stays uncertain, never terminal.
   Logging should distinguish proved no-allocation from unresolved allocation.
5. Keep journal→budget lock order (`StagedSpaceBudget.cs:289`). Do not await a
   journal read while holding the budget's monitor; allocator→journal and then
   allocator→budget in separate calls is the existing pattern. Keep one live
   allocator per private root. Its semaphore is not a cross-process/root-wide
   lock. Initialization replaces the pre-budget allocator before admission and
   gates readiness on recovery (`MinifilterInterceptor.cs:1686`–`:1718`, `:1733`);
   do not introduce overlapping allocator instances or startup admission.

This remains the existing **stateless** refusal contract: another queued exact
request may allocate after the proof releases its gate and before the refusal
reply arrives. Do not claim permanent absence or ban that replay with a new
tombstone. Preserve exact late-allocation kind-5 cleanup and no caller exposure;
the existing concurrency control is
`StagedAllocationResolutionTests.Stateless_refusal_and_late_allocation_serialize_for_exact_kind5_cleanup`.

Required focused controls: actual pre-backing budget exhaustion produces terminal
no-allocation plus the resource alert; restart/retry and simultaneous exact
requests retain serialization and late cleanup; an actual AfterReplacement
resource failure, existing/corrupt/inaccessible manifest, unknown/replaced/locked
backing, orphan companion with no ledger, issued grant, snapshot/live lease,
faulted/partial ledger and failed cleanup never produce terminal authority.
Include proof-failure notification preservation and direct-marker classification.
Do not alter the single-winner capacity expectation, sharing probes, thresholds
or existing generic-I/O/owner/replay/exact-envelope assertions. Run relevant
component feedback and the required feature delivery matrix on the implemented
change; those results and eventual product VM qualification remain outstanding.
