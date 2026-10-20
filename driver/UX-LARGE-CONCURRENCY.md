# T4/T9: growing reservations for ordinary overlapping saves

2026-10-19. **Revised security/lifetime design; implementation remains gated on independent review.**
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

The fixed request contains version/size, request ID, connection cookie, driver
instance, transfer, **immutable allocation generation**, full volume/file identity,
old observed capacity and required aligned extent. The reply echoes that complete
tuple, required extent and request ID, and carries status/current capacity; all
reserved bytes are zero. C/C# size/offset and mutation controls are required.
Current destination generation is deliberately separate: private rename changes
namespace authority, never the immutable allocation binding used for capacity.
Bind persists this tuple, original SID, alignment and an open-growth flag in a
new ledger format before exposing the grant. The authenticated service validates
against that ledger, not a foreground journal read. A growth request is capacity
authority only: no content verdict,
destination permit, read/export grant or native mutation. Reject bound allocations,
discarded/terminal/retiring versions, wrong identity/epoch/generation and unknown
accounting. A duplicate/late smaller request can receive the current greater grant;
it cannot reduce capacity or revive a retired version.

Before enabling growth after restart, existing startup recovery validates the
binding against exact journal custody. Old v1 ledgers/grants keep their full debit
and immutable behavior. Missing or ambiguous modern binding stays held.

Growth reads only connection state and the ledger under the budget monitor. It
never acquires the journal, allocator, publisher or policy loader. Terminal,
sealing, discard, cancellation, epoch retirement and hand-back transitions take
the existing journal serialization and durably close growth under the budget
monitor **before** making that transition usable. Close is monotonic and refunds
nothing. If journal persistence subsequently fails, retain closed custody and
the full charge; recovery finishes from exact evidence. Cleanup refunds only a
closed record's **current** capacity, with exact deletion evidence and no snapshot
lease. A stale request cannot recreate a deleted record. Lock order is
journal→budget; there is no budget→journal call.

The receive loop must remain available while other lifecycle operations run.
Give capacity requests a separate bounded continuation lane whose workers call
only this ledger operation. Do not reuse `boundContinuations`, allocation workers,
or the stage worker: those can wait for journal/publication. A saturated lane
returns the existing resource failure; it cannot queue unbounded work or drop a
request as approval. Connection cancellation/drain does not wait on application
handles or public mutations.

## Accounting I/O dependency fence

The [independent review](evidence/2026-10-19/t9-growing-reservations-design-review-sol-high.md)
found a real possible cycle: MM upper stream→growth→ledger rename→namespace→upper
stream. Moving the RPC to a worker alone does not break it. The design uses a
small, separate **connection-local private metadata capability map**. It does not
reject policies covering the private root, introduce a SYSTEM/path-prefix bypass,
or reuse publication records whose source-current checks take namespace locks.

Before admitting growth, register held no-follow directory anchors for the exact
existing product roots needed here: staging, its `.space-reservations` child,
`staging-journal` and its `completed` child. Bootstrap independently checks the
installed private-root contract, complete volume/directory IDs, fixed NTFS,
trusted owner/protected security and no untrusted writers/reparse traversal.
An arbitrary SYSTEM-owned directory submitted by the service is insufficient.
Driver-held anchors exclude rename/delete/security substitution; uncertainty
revokes admission. Root discovery, creation and ACL repair happen before growth.
Bind anchors to the authenticated connection, original process object/token and
instance, and retain those references through local rundown.

Metadata opens use existing relative `NtCreateFile` mechanics, one validated leaf
and the registered RelatedFileObject. Exact roles distinguish bounded ledger
JSON (64 KiB), its replacement, companion/current replacement and the bounded
journal inventory/query objects needed by budget callbacks. Reject ADS, traversal,
links, reparse/TxF/by-ID/target-directory escapes and unsupported access/options.
Existing objects require their expected full identity; new roles require
FILE_CREATE, post-CREATE FILE_CREATED, regular/single-link/no-reparse type and
trusted stored security before exposing a child capability. Native access checks
still apply. The map tags only currently open original FILE_OBJECTs, not paths.

Route recognized anchor-relative opens and tagged objects **before** epoch, BP,
namespace and writer routing. Invalid operations on a matched capability fail
there; they do not fall through to generic dispatch. Permit only role-specific
query/read, bounded write/flush/EOF/allocation, exact delete and same-anchor
relative replacement. Root handles admit only bounded directory/volume/security
queries needed for that inventory. Mutations require the exact registered
unimpersonated process/token/connection. Deny mapping, MDL/fast I/O, EA/FSCTL,
security mutation and outgoing/absolute rename. Native post-validation uses
lower-instance queries and short private map locks; no namespace, upper stream,
epoch-drain, source-current check or stage-worker dependency is allowed.

Metadata mutation handles are synchronous **noncached**. Sector-pad bounded
writes, flush, then set exact logical EOF within the charged envelope. WriteThrough
alone is insufficient: cached writes could later use an untagged system object.
No helper may silently fall back to cached or absolute-path I/O. Reuse
`StagedDestinationDirectory.OpenRelative` and the native relative-rename mechanics
in `StagedHandbackCopier.RenameRelativeNoReplace`; preserve hand-back's no-replace
contract. Replacement validates its held exact target/exclusion, not just its
name. Native mutation success is final even if later bookkeeping fails.

Remove nonowning FILE_OBJECT map keys before CLOSE/address reuse. Disconnect
revokes mutations; cleanup/CLOSE and instance/unload rundown finish locally, with
no service ACK. Map locks span neither lower I/O nor object dereference. Storage
is bounded by registered roots and independently progressing open metadata
transactions, with no durable kernel receipts or per-transfer history.

Every current budget-monitor I/O holder must change before MM growth is enabled:

| Current methods (`StagedSpaceBudget.cs`) | Required route |
|---|---|
| `Reserve`, `RecordStage`, `Bind`, `Persist`, `WriteGrant`, metadata retirement | Anchored exact metadata operations; no generic rename/query/open under `_gate`. |
| `VerifyInventory`, `RefreshNegativeReceiptStorage`, `VerifyJournalInventory`, `RequireArchiveAdmission`, `RefreshArchiveStorage`, `RequireMetadataAdmission` | Anchored bounded directory/identity/length/security queries; startup-only legacy scans finish before enabling growth. Audit transitive `MetadataFiles`/archive callbacks too. |
| `RetireFailedAllocation`, `RequireFailedAllocationAbsent`, `RetireUnissuedMetadata`, `BeginSnapshot`, `ReconcileAsync`, `RetireCompletedMetadata` | Move stage/snapshot identity/query/delete I/O outside `_gate` under exact cleanup/snapshot leases, retaining the full debit. Companion/ledger I/O uses metadata capabilities. |
| `ContentReservationPending`, `EndSnapshot`, cursor/equality/accounting reads | Memory-only; never add an I/O or journal dependency. |

For content cleanup, claim a per-reservation lease under `_gate`, copy exact
custody, release the monitor, do existing exact-object work, then reacquire and
update only still-matching custody. Reserve/RecordStage/Bind/BeginSnapshot must
respect that lease, preventing a new seed/snapshot during cleanup. Do not merely
check equality after deletion. Capacity may have grown: retain/refund the latest
record, not stale capacity. Failure retains debit and evidence. Reuse current
allocator serialization where present. Content objects gain no writable metadata
capability and no new publication/read/export authority.

Keep one bounded atomic companion replacement, rather than unbounded revision
files. Under the ledger monitor persist a pending tuple with exact predecessor
identity/capacity, target capacity and held replacement identity before making
the replacement current. Use one current/replacement pair, charged inside the
existing metadata envelope; unresolved residue holds further growth. Recovery
accepts only those exact predecessor/replacement states at the charged capacity.
An unknown or ahead-of-ledger companion is held. A smaller proven predecessor
can be repaired, never refunded. Replay completes successful replacement's
bookkeeping rather than repeating that public/native mutation. Repeated exact-fit
growth must not hit a made-up revision-count/file-size cap.

## Kernel growth fence

Only increase the in-memory capacity after an authenticated exact reply and
revalidation of the still-live tuple. Copy identity values; retain callback
ownership and a reference to the **upper FILE_OBJECT** through reply adoption.
A backing-object reference alone does not pin the upper stream's FileObjects
release fence. A stale smaller reply never reduces a newer grant.
Cancellation, disconnect and mandatory teardown locally drain pins without needing
the service. An increased service debit with no adopted reply remains charged.

Normal operations compute the required extent, drop only resources they own,
reserve through bounded PASSIVE work, reacquire and revalidate, then perform the
existing write/resize. Append/file-pointer operations recompute the actual extent
after reacquisition. Recheck cancellation, read-only/sealing/rename and exact
backing before mutation. A bounded recheck cannot imply capacity approval.

**Narrow MM exception:** MM may already own the upper stream resource when it
recursively enters EOF/section extension. Never release an unknown recursion
count or transfer its upper-cache flush to another thread. That caller may retain
only this upper resource while waiting for the copied-tuple capacity worker;
namespace, paging, writer-registry and spin resources never span the wait. This
exception is safe only after the accounting I/O fence above is implemented and
audited. Assert actual IRQL/top-level/resource preconditions at each entry point.

Worker storage is bounded nonpaged heap work with separate waiter/worker
references. The worker uses only copied inputs, writes status/reply and signals
the event **before** dropping its upper-file reference; final CLOSE can need
namespace. The waiter depends only on the result event, not worker exit or pin
cleanup. Do not reuse namespace-taking `RpcReferences`/publication-source release
or the shared stage worker. A timeout cannot abandon stack storage a late worker
can touch. Cancellation/disconnect/mandatory teardown complete locally, with
exactly-once pin release, independently of service ACK or upper-resource cleanup.

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
- [x] T4/T9: initial independent review identified MM recursion, ledger retirement
  and reentrant metadata dependencies; concrete mechanism addendum retained.
- [ ] T4/T9: accept this revision before implementation; review coherent changed
  kernel against the conditions before its first VM boot.
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
