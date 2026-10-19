# T4/T9: growing reservations for ordinary overlapping saves

2026-10-19. **Proposed security/lifetime design; do not implement until independent review.**
Owner approved growing reservations, unchanged approved budgets, and replacing the
single-concurrent-winner test with concurrent no-overspend controls. This approves
neither a qualified pair nor different Windows sharing, failure or cutover policy.
Background: [smoke diagnosis](evidence/2026-10-19/t4-smoke-diagnosis.md),
[existing accounting](UX-LARGE.md), [recovery](UX-LARGE-RECOVERY.md).

## Problem and user result

Today one tiny file reserves nearly the entire user's allowance. Word temporary
files and an overlapping save can be refused despite ample real space. Raising
the budget preserves that defect. Splitting it into immutable small grants creates
an unapproved per-file cap. Removing accounting violates the approved bounds.

Use small initial grants and reserve more before growth. Keep total/per-SID/floor
formulas, four overlapping copies, metadata debits, original user ownership,
exact cleanup/refund and fail-closed inspection. A file may grow to the remaining
approved budget; multiple small files can coexist. Actual exhaustion still refuses
the affected save with its existing space alert. This does not by itself solve the
separate same-name/cross-owner sharing conflict.

## Agent accounting

1. Initial capacity is at least the existing 16-MiB minimum, rounded to both stage
   and destination allocation units. For a seeded file reserve its checked seed
   requirement first; source size is a sizing input, never authorization. Retain
   the existing held source/identity and seed-length checks. A size race refuses
   allocation without granting uncharged bytes. Do not reopen/seed unreadable
   source data under newly invented service authority.
2. An existing ledger's `Capacity` increases monotonically. Charge four times the
   increment before acknowledging it, under the existing budget monitor. Metadata
   remains charged once, not once per growth. Available bytes above the unchanged
   floor still subtract all outstanding reservations conservatively.
3. Prefer geometric growth, capped by the remaining charged allowance, but grant
   any aligned capacity sufficient for the requested extent when that fits. A
   doubling preference must not refuse a write that fits. Checked arithmetic and
   allocation-unit rounding precede accounting; capacity cannot overflow.
4. Exact replay returns the already-persisted sufficient capacity without another
   debit. Same-version concurrent requests serialize in the budget. Different
   versions/SIDs cannot spend the same bytes. No timer returns unused capacity,
   no active grant shrinks, and version cleanup remains the only full refund.
5. Persist ledger growth before updating the exact service-only `.space` grant,
   then reply. Replace the companion atomically only after checking its exact
   original object, owner/security, fixed length, transfer and complete stage
   identity. An inaccessible/unknown/changed companion is a hold, never a path
   overwrite. The existing immutable `WriteGrant` comparator must be replaced
   deliberately, not bypassed with `File.WriteAllBytes`.
6. A crash after ledger growth but before companion/reply overcharges safely.
   Recovery validates the same tuple and monotonically repairs the companion;
   ambiguous ledger writes retain the existing fault latch. A lost reply retries
   bookkeeping, never allocation, seeding or publication. Old immutable grants
   keep their full debit; startup must not shrink them to the new initial window.

## Negotiation and exact growth request

Use a new size-checked feature capability and request/reply extension; do not
reinterpret the existing v31 receipt or the 64-byte companion. Old pairs remain
closed to the new mode. Define fixed-width C/C# layouts and contract mutation
controls before implementation. No persisted enum is renumbered.

The driver supplies request ID, driver instance, transfer, destination generation,
full volume/file identity, old observed capacity and required aligned extent. The
authenticated service checks these against its exact live unbound journal/ledger
and original SID. A growth request is capacity authority only: no content verdict,
destination permit, read/export grant or native mutation. Reject bound allocations,
discarded/terminal/retiring versions, wrong identity/epoch/generation and unknown
accounting. A duplicate/late smaller request can receive the current greater grant;
it cannot reduce capacity or revive a retired version.

Journal checks precede budget locking; do not await a journal operation under its
monitor. Growth must not wait for publication, policy epoch drain, inspection,
application close or the stage worker. Review whether the journal's own growth
admission callbacks create an indirect cycle. Cleanup and growth serialize their
ledger transition; a stale pre-lock journal read is insufficient to issue a grant
after retirement. Specify a final journal→budget linearization, with no inverse
budget→journal call. The current cleanup/reconcile call sites must be audited as
part of this change.

## Kernel growth fence

Only increase the in-memory capacity after an authenticated exact reply and
revalidation of the still-live tuple. Copy identity values; retain a local stream
pin through asynchronous work. A stale smaller reply never reduces a newer grant.
Cancellation, disconnect and mandatory teardown locally drain pins without needing
the service. An increased service debit with no adopted reply remains charged.

**No RPC while holding namespace, stream, paging, writer-registry or spin
resources.** Existing `StageResize` is called with `Stream->Resource` held
(`StageStream.c:4726`); putting a send there is invalid. Compute the required
extent, release resources, reserve through a bounded PASSIVE worker, reacquire
and revalidate, then perform the existing write/resize. Append/file-pointer
operations recompute their actual extent after reacquisition. Recheck cancellation,
read-only/sealing/rename and exact backing before mutation. A bounded recheck
cannot turn timeout/conflict into capacity approval.

Cover ordinary and noncached writes, EOF/VDL/allocation, append, MDL preparation,
cached writes and section extension. Paging writes must fit a capacity reserved
before EOF/cache/section exposure; never grow by RPC from a paging callback.
Reject fast I/O to obtain its IRP fallback where required. Never return a status
that makes section creation retry forever. For top-level MM resize, use the
existing worker separation only if no service/stream/cache cycle remains.
`StagePostResizeBacking` currently waits while the caller holds a stream resource;
it cannot be reused unchanged for a service growth request. If a supported MM
path cannot reserve before exposure without such a cycle, revise this design
before code; do not silently narrow the mapped-file assertions.

An unsuccessful required growth cannot publish a successful prefix. Preserve the
existing sticky failed-space/nonpublishable behavior and owner diagnostics. An
uncertain growth retains its debit and cannot authorize additional bytes. Any
different recovery/failure behavior needs an explicit owner decision first.

## Controls and delivery

- [x] T4/T9: owner approved growing reservations and replacement of the
  single-winner strategy assertion with stronger concurrent accounting controls.
- [ ] T4/T9: independent security/lifetime review, including exact journal/budget
  linearization, every growth entry point and shutdown/cancellation drain.
- [ ] T9: real tiny-file overlap plus seeded/large growth; exact budget/floor
  boundaries, same/different SID races and geometric fallback; no double spending.
- [ ] T9: crash at ledger/companion/reply boundaries, late/reordered/forged replies,
  identity substitution, retirement races, locked/corrupt metadata, restart and
  old-grant compatibility. Keep original no-overspend and exact refund assertions.
- [ ] T4: unchanged immediate owner/child read/read-write probes and 256-cycle
  boot-Verifier smoke; then the full 10k/resource/raw-byte gates and separate
  restoration. No open retries or threshold changes.
- [ ] T4/T8: real standard-user Word save/edit/reopen and multiple temporary files;
  no false alert/read-only fallback, exact independent public bytes.

Required feature WDK Debug/Release PREfast/ApiValidator/import gates, four-leg
agent matrix and matched-pair ordinary/runtime-/boot-Verifier qualification remain.
