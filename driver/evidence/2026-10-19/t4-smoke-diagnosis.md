# T4 reopen smoke: diagnosis and narrow repair proposal

2026-10-19, source `a9f292b8`; product kernel `f8e99d25`, agent `a3ea2a48`.
This is source/evidence analysis, not a passing run or implementation acceptance.
Owner authorized focused diagnosis after the repeated-failure stop.

- [x] T4: [smoke verdict](m2t4smoke1019a-verdict.txt) fails after nine attempts;
  [separate restoration](m2t4smoke1019arestore-restoration.txt) passes. No 10k started.
- [x] T4: [reopen receipts](m2t4smoke1019a-reopens.jsonl) show all four read probes
  succeed with exact bytes. Original-owner read/write returns 32 in all four;
  child read/write succeeds once, then returns 170 three times. These are
  distinct observations, not proof of a single kernel cause.
- [x] T9: retained `m2t4smoke1019a-service-events.txt` records 11 allocation
  exceptions `Not enough staging space for this user`, beginning at request 365.
  `StagedSpaceBudget.cs:206`–`:226` grants nearly all remaining SID allowance to
  one version and refuses another below 16 MiB. Existing
  `StagedLargeFileTests.cs:49` explicitly requires a single concurrent winner;
  `UX-LARGE.md:160` documents this limitation. Increasing the total does not fix
  its shape. The retained last journal is an allocated child-owned generation
  for `map-4.txt`, not an inspected/publication failure.
- [ ] T4: owner error 32 still needs exact-site attribution. Independent owners'
  attached private views conflict in `StageReserveAllocationName`
  (`StageStream.c:2030`). The probes run simultaneously; this is a supported
  candidate explanation, not a recorded gate for these particular requests.
  The final deny ring has no matching sharing entry; pending CREATE completion
  does not preserve that attribution. Do not substitute Word's gate-6 diagnosis.

## First repair: prove a refused allocation is absent before releasing its hold

Today `ResolveAllocationRequestV20Async` calls `prepare` at
`StagedAllocationResolution.cs:83`. A resource exception bypasses its existing
no-allocation proof. `MinifilterInterceptor.cs:888` labels it RetryableFailure,
so the exact request/name can remain reserved even when nothing was created.
An exception alone must never authorize terminal release: metadata growth can
also fail after manifest replacement has committed.

Proposed coherent agent-only repair, before changing capacity policy:

1. Catch only `StagedSpaceException` from the serialized `prepare` call.
   Re-read the exact manifest under the existing allocation gate. If present,
   corrupt or inaccessible, preserve the original uncertainty/replay behavior.
2. Reuse the existing terminal-refusal cleanup proof: validate the stage locator;
   require exact recorded unissued cleanup or confirmed absence, no issued grant,
   no snapshot obligation, and confirmed absence of stage and `.space` companion.
   Unknown/replacement/locked objects and unresolved ledgers remain held.
3. Only after that proof, carry an internal typed "no allocation committed"
   exception to the existing interceptor catch. Keep its resource notification
   (inner cause still identifies staging exhaustion), and return the existing
   exact request-echo `NoAllocationCommitted` reply. Add no protocol state or
   negative receipt. Never repeat a completed public mutation.
4. Add positive before-CREATE exhaustion/restart/retry controls and negatives
   for actual post-commit exhaustion, unknown backing, companion residue,
   outstanding ledger/issued grant and cleanup failure. Existing generic I/O,
   identity mismatch, owner, replay and exact-envelope tests remain unchanged.

This prevents false uncertainty from a proved refusal. It does **not** make
concurrent allocations succeed, solve sharing errors or qualify T4.

## Capacity and sharing follow-up: unresolved design, no code yet

A larger budget or a new fixed per-file cap cannot satisfy the approved
ordinary multi-file workflows. Candidate direction is bounded initial
reservations that grow before additional writes, under the same approved
SID/total/free-space budgets and four-copy accounting. Growth must bind the
exact live version, persist before authority increases, avoid kernel resource
wait cycles and account for lost replies/restart. Existing whole-SID immutable
grants remain fully charged; no live grant can silently be reduced or reused.
This needs its own concrete security/lifetime design and independent review.
The single-winner test encodes the old allocation strategy; changing that
expectation requires the owner's test-contract approval first. No assertion,
budget, cap, refusal policy or supported Windows sharing contract is changed
by this note. Simultaneous owner/child probes remain intact, with no retries.
