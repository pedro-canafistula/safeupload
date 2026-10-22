# T4/T9: growing reservations for ordinary overlapping saves

2026-10-19; revisions 3, 4 and 5 2026-10-22. **Revised security/lifetime design; implementation remains gated on independent review.**
Revision 5 answers the [fourth review](../../../evidence/2026-10-22/t9-growing-rev4-review-sol-high.md) (REVISE; R4.4 ordering and R4.5 startup accepted with conditions) and supersedes R4.1-R4.3
where they conflict. Revision 4 answers the [third review](../../../evidence/2026-10-22/t9-growing-rev3-review-sol-high.md) (REVISE; R3.1 and the R3.4 matrix accepted) and supersedes R3.2, R3.3(c),
R3.5 and R3.6 where they conflict. Revision 3 answered the [second independent review](../../../evidence/2026-10-22/t9-growing-rev2-review-sol-high.md) (REVISE) and the product evidence
[discovery 1 F5](../../../evidence/2026-10-22/t8-discovery-1.md): see "Revision 3" before "Controls and delivery".
Owner approved growing reservations, unchanged approved budgets, and replacing the
single-concurrent-winner test with concurrent no-overspend controls. This approves
neither a qualified pair nor different Windows sharing, failure or cutover policy.
Background: [smoke diagnosis](../../../evidence/2026-10-19/t4-smoke-diagnosis.md),
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

The [independent review](../../../evidence/2026-10-19/t9-growing-reservations-design-review-sol-high.md)
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

## Revision 3 (2026-10-22)

Evidence: with the budget on and a clean state, every `StageAllocate` takes 1.51–1.59 s, Word/Excel saves fail, and one-line text files can fail. The 1.5 s is
`StagedSpaceBudget.RefundGrace`: the grant is the whole remaining allowance, so the second allocation of an overlapping save waits the grace and fails.

### R3.1 Initial grant and admission (review finding 1)

For a newly negotiated growable allocation: `initial = AlignUp(max(16 MiB, checked seed requirement), max(stage granularity, destination allocation unit))`, never
the remaining allowance. An unseeded file gets 16 MiB; a seeded file gets its checked requirement before copying; every later byte needs growth. This creates no
per-file cap: a file may grow to the remaining approved budget. Admission is **immediate** when the small reservation fits the unchanged total/per-SID/floor
formulas: no grace delay and no full-history reconciliation pass in the foreground. `ReserveAfterPendingRefundsAsync` and its 1500 ms grace are removed for growable
allocations; a refused reservation keeps today's refusal and diagnostics, and any refund retry is bounded work off the receive path. One active small version costs
four copies of 16 MiB plus metadata, about 65 MiB; concurrency stays budget-limited (a guest with 0.7 GiB per user holds about ten overlapping versions).

### R3.2 Retained and held custody (finding 2)

Capacity stays monotonic while a version can still write. Add one durable transition **Retired-proven** after the driver has proved write authority ended (no handle,
no writable section, no outstanding growth grant, paging rundown released; a file-length query is never proof). The record then keeps two numbers: `AuthorizedCapacity`
(history, never reduced) and `RetainedCharge = CopyCount × AlignUp(sealed length, granularity) + metadata`, which conservatively covers rounding, every retained object
and the permitted snapshot, publication and hand-back copies, preserving the approved four-copy envelope. Every consumer respects the reduced envelope or reserves
more first. Ambiguous or still-live custody keeps its full charge; v1 immutable grants keep their original accounting. Crash contract: the ledger write of the
transition precedes any use of the reduced charge; replay of a finished transition changes nothing; a failed transition keeps the full charge.

### R3.3 Dependencies of the F5 fix (finding 3)

Delivery order inside T9, each a separate coherent change that must land before any claim that default-budget saving works: (a) completed ordinary saves must not keep
their per-SID metadata charge (retirement covers only selected discard kinds today, `StagedSpaceBudget.cs:655`); (b) a lost **initial allocation reply** must self-heal
(growth replay does not cover it); (c) allocation latency: no work proportional to history in the foreground; (d) growth as designed above.

### R3.4 Smallest increment and compatibility (finding 4)

Increment 1: exact initial-window allocation with the existing kernel fast path below the window and the growth exchange only past it. Mapped, EOF and allocation
boundary crossings need the full growth protocol; until it is complete growable admission stays NotReady (it cannot qualify with a 16 MiB ceiling). One monotonic
reservation per version; no shared SID pool.

| Driver / agent | Behaviour |
|---|---|
| new / new | small initial grants only after exact growth negotiation and recovery readiness |
| old / new | immutable v1 behaviour, including its limit, or growable admission NotReady; never a new 16 MiB immutable grant |
| new / old | immutable v1 behaviour; growth authority is never inferred from driver capability alone |
| old agent, modern persisted accounting | refuse the downgrade safely; no reinterpretation, deletion or accounting-disabled fallback |

Existing v1 grants are never converted to small windows or refunded as growable records (`StageStream.c:1762` reads the companion once into an immutable capacity).

### R3.5 Receive and completion progress (finding 5)

The receive loop (`MinifilterInterceptor.cs:418`, `:458`) currently runs allocation, lifecycle, rename and epoch-drain handlers inline, so a separate growth lane would
not help a request that has not been received. Change: the receive loop only dequeues, validates the header and hands the message to a bounded lane; it never runs a
handler inline. Lanes: **growth** (workers call only the ledger operation; own bounded queue and reply path), **allocation**, **lifecycle/rename/drain**. A saturated lane
returns the existing resource failure. Connection cancellation and revocation release growth waiters **before** any drain that could depend on them; shutdown orders
growth lane, then the rest. Audit of every budget-held metadata operation includes transitive free-space, alignment and security queries and error cleanup.

### R3.6 Startup recovery state table (finding 6)

| Observed at start | Action |
|---|---|
| ledger current, companion at ledger capacity | normal |
| ledger ahead, companion smaller proven predecessor | repair companion monotonically; no refund |
| companion ahead of ledger, or unknown object | hold; reject; diagnose |
| pending tuple with exact predecessor still current | finish replacement bookkeeping, never repeat a successful native replace |
| exact replacement already current, predecessor residue | delete residue after identity proof; finish ledger |
| `.new` ledger residue / torn pending write | classify by pending tuple before the blanket "unknown residue" rejection; hold if ambiguous |
| initial bind/companion missing or created before identity capture | separate path from replacement; hold unless exact evidence |
| repair interrupted again | same table again, idempotent |
| reconnect vs driver restart | durable: ledger, companion, immutable allocation tuple; per-connection: cookie, anchors, pins; old-cookie work fails; reconnect never reopens closed growth |
| closure racing growth, then journal persistence failure | closed custody stays charged; replay cannot revive it; late success cannot clear sticky failed-space/nonpublishable state |

## Revision 4 (2026-10-22)

Preserved from revision 3: the initial-grant formula (R3.1) and the compatibility matrix (R3.4), including NotReady for old/new mixes and v1 immutable behaviour. The
legacy/v1 path keeps its reconciliation and refund-grace branch behind an explicit mode; an exact replay of a committed allocation bypasses fresh sizing and admission and
returns the persisted object, generation and capacity even if free space has since fallen (it completes pending companion bookkeeping, never resets capacity to the initial
window, never reseeds or double-charges, never reopens closed growth, and never retries attachment of a CREATE already returned as failed).

### R4.1 Retained charge bounds physical storage (review finding 2)

`RetainedCharge` is not computed from the sealed length. The retirement receipt (R4.2) carries, for the version and for every retained object of the transfer (stage, snapshot,
hand-back copy, reader-pinned deletion-pending object), the **measured** `AllocationSize` and `EndOfFile`. `RetainedCharge = metadata + CopyCount × max over retained objects of
AlignUp(AllocationSize, granularity)` — four simultaneous copy slots, each at the largest retained allocation, so a tiny EOF with a large preallocation cannot undercharge. Seal
normalizes allocation to EOF where the filesystem allows it, *before* the receipt is produced; if normalization fails the receipt reports the real allocation and the charge stays
high (or the full debit is retained). Consumers (snapshot, publication, hand-back) must reserve beyond the reduced envelope before use; they never take `AuthorizedCapacity` as their
ceiling after the reduction. Empty sealed files report their residual allocation. A reader that keeps a deletion-pending object alive keeps its allocation in the inventory until the
object is observed deleted.

### R4.2 The retirement receipt (finding 3)

The driver proof is the existing boundary, extended: successful `StageDrain` plus, under the stream exclusion, closing the writable backing and setting irreversible `ReadOnly` in
`StageDrainAndSeal` (`StageStream.c:6276`, `:6419`), preceded by: fresh writable opens, section creation and growth adoption excluded; zero upper handle/share and FILE_OBJECT custody;
cache and sections drained and purged; paging rundown complete; flush results checked; queued and in-flight growth requests and their reply adoption resolved so no late grant can
restore mutation authority. "No outstanding grant" means no remaining ability to consume or adopt authority (historical grants exist). The driver then sends an authenticated,
exact-tuple (transfer, driver instance, allocation generation, destination generation) **WriteRetirementReceipt** with the measurements of R4.1. The agent persists the accepted
transition in the ledger **before** reducing any charge. Delivery or persistence failure, a stale or duplicated receipt, or any uncertainty retains the full debit; replay of an accepted
receipt changes nothing. Accounting *Retired-proven* is a different state from the driver's `Retired` (deleted backing custody); a later read-only reader may retain storage without
undoing a proved write retirement. `CLEANUP`, zero user handles, "growth closed", a length query or a queued seal request are each insufficient.

### R4.3 Allocation deadline, history-independent admission, failure contract (finding 4)

- **Deadline.** The roughly 3 s the driver waits is `SafeUploadPolicyVerdictTimeout` of the shared exchange (`Communication.c:1731`), not an allocation constant; seeding has its own 120 s
  (`StagedSpaceBudget.SeedTimeout`). A small initial window completes in milliseconds, but a seed of a large existing file cannot. Staged allocation gets its own **monotonic overall
  deadline** (queueing + preparation + seeding + persistence), not restarted by retries and separate from the inspection timeout. A seed larger than the fast path uses a bounded
  pending/completion exchange; the opener waits up to the declared bound. **Owner decision needed (below)** on that bound and the user-visible failure.
- **On expiry** the save/create fails after the declared bound with a diagnostic that distinguishes *timeout* from *space exhausted*; the destination stays protected; a late committed
  allocation stays charged until exact resolution and cleanup; recovery releases the stranded name automatically when proved safe, without attaching the failed CREATE or requiring the
  original process to exit; the reply never claims `NoAllocationCommitted` while a duplicate may still commit elsewhere.
- **History-independent admission.** `Reserve` currently sums every reservation (`StagedSpaceBudget.cs:206`). Keep maintained running totals (global and per SID) updated under `_gate` on
  every charge, growth, retirement and refund, rebuilt at startup from the ledger and checked against inventory; admission reads totals, never the history. Completed ordinary saves move
  to reconstructible shared accounting that preserves their storage debit, replay evidence and generation barriers (R3.3 (a)).

### R4.4 Ordering across lanes (finding 5)

Dispatch-only receive does not give request-order processing, so ordering is by state, not arrival: (1) allocation: duplicate preparation/resolution of one intent serializes; binding and
grant persistence precede any dependent growth or lifecycle use. (2) growth versus closure linearizes through the ledger: growth committed first stays charged, closure committed first
rejects growth, a late reply cannot undo closure, retirement or sticky failure. (3) lifecycle and namespace keep their attachment/cleanup/seal/discard ordering and destination-generation and
rename barriers; worker scheduling never decides semantic order. (4) connection identity is captured at dispatch and revalidated before authority-changing work; a drain revokes admission
before draining dependent work; an old worker cannot publish readiness or mutate through a replacement connection. (5) replies correlate exactly; reply completion may reorder where the state
machine permits. Short state transitions only: a per-transfer lock across lifecycle I/O would recreate the MM→growth dependency. A negotiated mode stays attached to each allocation
(reconnect or capability loss never converts growable custody into a v1 window). A saturated lane returns a valid failure and does not claim non-commitment while a duplicate may commit.

### R4.5 Startup algorithm (finding 6)

Order: (1) validate trusted storage; (2) classify supported schemas and **recognized** residue (replacement companion, `.new` ledger, pending tuple) before the blanket rejection of unknown
objects; (3) reconstruct conservative charges and exact bindings; (4) resolve permitted transactions; (5) verify inventory; (6) enable admission. Added states: replacement current without
predecessor residue (finish bookkeeping); predecessor current with replacement absent, incomplete or fully prepared (an unperformed replacement needs the native step, a performed one only
bookkeeping); committed Retired-proven records, interrupted reduction and retained snapshot/reader/copy custody; missing ledger with a modern companion or content (hold, never reinterpret as
legacy); v1 `LegacyGuard`, `ContentReleased`, legacy upgrade and shared completed-history accounting preserved. "Ledger current, companion at ledger capacity" requires no unresolved
transaction and matching format, identity and binding, not numerical equality alone. Modern records use a **new schema version that old readers reject**; adding fields to version 1 would
not enforce downgrade refusal.

### R4.6 Added controls (finding 7)

Tiny EOF with large preallocation and zero-length retained custody, with physical allocation observed across reduction and restart; retirement receipt lost, duplicated, stale, or racing the
irreversible boundary; read-only readers retaining objects afterwards; deliberately reordered allocation/growth/lifecycle work and epoch drain with queued work in every lane; allocation
deadline expiry during queueing, seeding and post-commit reply delivery, with late completion, automatic name recovery and the application-visible diagnostic; exact replay after capacity
growth with available budget fallen; admission measured against increasing completed history (queue time and end-to-end); v1 grace/replay preservation and unsupported downgrade with modern
retained accounting; concurrent policy/namespace/publication stress; the budget-on T5 reruns carried by the status plan. F3/F4 publication-window failures stay separate from F5 results.

### Owner decision needed

Opening a large existing file for editing needs its seed copy: should the opener **wait up to 120 s** (the existing `SeedTimeout`) with the application showing its normal "opening" state and then fail
with a clear "not enough time / space" message, or fail sooner? Recommendation: wait up to 120 s (a 200 MB document copies in seconds on SSD; 120 s covers a slow disk), diagnostic distinguishes
timeout from space. Small saves are unaffected (initial window, milliseconds).

## Revision 5 (2026-10-22)

Accepted and unchanged: R3.1 initial window, R3.4 compatibility matrix, R4.4 ordering guarantees (implement as claim → capture exact state and generation → release serialization for lifecycle
I/O → complete only the still-matching transition; journal→budget order preserved; growth never takes lifecycle/journal serialization nor waits for content-I/O leases; revocation releases growth
waiters before dependent drains) and R4.5 startup algorithm (it changes the startup entry path: the budget constructor today rejects non-JSON residue and every version but 1 before any recovery
runs, `StagedSpaceBudget.cs:84`, constructed in `MinifilterInterceptor.cs:1714`; classification and the new schema version must precede that rejection, and an old reader must still meet a
rejected format or marker wherever modern semantics remain; tests cover budget-enabled and accounting-disabled startup).

### R5.1 Custody and lease protocol for service-owned storage (finding 1)

The ledger record of a transfer carries a **custody inventory**: one slot per charged content object (stage, inspection snapshot, hand-back temporary, reader-pinned deletion-pending object),
at most four occupied simultaneously, each with its exact identity (volume serial, file ID, generation), role, and `ReservedMax` allocation. Rules:

- **Mutable copy lease.** A snapshot or hand-back temporary is registered with a lease holding `ReservedMax = AlignUp(expected length, granularity)` (or the full slot until its length is known).
  While a lease is open its slot keeps `ReservedMax`, never its momentary allocation. A snapshot registered at zero allocation and still being copied therefore cannot lower the envelope.
  Closing the lease (copy complete, flushed, identity re-read) records the measured allocation; abandonment keeps `ReservedMax` until the object's exact deletion is proved.
- **Reduction waits for or retains leases.** Reduction of a transfer's charge is computed from the inventory only when no mutable lease is open; otherwise the open slots count at `ReservedMax` or the
  transfer keeps its full debit. No lease is ever opened above the reduced envelope: opening one is an admission (reserve first, then create).
- **Deletion-pending readers.** A slot is released only on **exact storage-release evidence** (the object's final close observed by the owner of the handle, or an exact-identity absence
  confirmed after the last handle closed); a path or directory entry disappearing alone never frees a slot. Without that proof the slot stays charged conservatively.
- **All content gone.** When every slot is released and no lease is open, the transfer is metadata-only accounting (`metadata` debit only); this is an explicit state, not a zero-slot special case.
- Persisted with every transition: object identities, occupied slots, open leases and pending obligations.

### R5.2 Separated proofs and the reduction transaction (finding 2)

Three pieces, accepted together only against still-current accounting state:

1. **Driver receipt (stage write retirement).** The R4.2 boundary (successful `StageDrain`, writable backing closed, irreversible `ReadOnly`, growth adoption excluded and drained, queued growth
   resolved). The receipt binds: transfer id, driver instance id, allocation generation, destination generation, **complete stage volume serial and file ID**, the authenticated connection
   identity/cookie current at send, and a monotonic receipt sequence. It carries stage `EndOfFile` and measured `AllocationSize`. Replay rule: an exact duplicate of an accepted receipt is a
   no-op, including after restart (no second refund, no restoration of the full debit); a receipt for another connection, tuple or identity, or one that conflicts with an accepted
   measurement, grants nothing.
2. **Agent custody evidence (R5.1)** for every other slot.
3. **Reduction transaction.** The agent validates the receipt against the current ledger state and the custody inventory, then writes **one durable transition** holding the accepted
   receipt, the inventory, the closed-growth state and the resulting debit, then updates memory. Before durable acceptance the old charge stays; after acceptance but before memory is updated,
   restart reconstructs the committed debit; an ambiguous persistence fault faults admission instead of allowing competing accounting.

### R5.3 Maintained accounting covers the metadata callbacks; allocation deadline contract (finding 3)

Maintained running totals replace more than `Reserve`'s summation. Metadata admission also enumerates the journal directory (`StagedSpaceBudget.cs:419`) and journal-growth admission rebuilds
hot allocation bytes through `MetadataFiles` (`:346`); routing them through anchored capabilities fixes routing but not their duration under `_gate`. Rule: maintained **hot** and **shared**
physical totals plus bounded per-transfer metadata lookup; full reconstruction only at startup or maintenance; debit before write and conservative failure handling preserved; the whole
allocation path (not only `Reserve`) is measured against growing retained history, with queue time and end-to-end time recorded.

The monotonic **allocation deadline** originates when the driver issues the allocation request (carried in the request, remaining time preserved across retries) and ends when the driver
adopts the reply (queueing, preparation, seeding, persistence and reply delivery included). Pending-operation bound: at most a fixed number of in-flight pending allocations per
connection and per SID; cancellation or connection loss abandons the driver side only. Abandonment/resolution evidence for automatic name recovery: the exact allocation intent and
identity from the ledger plus a proof that no CREATE can still adopt it; expiry may end the CREATE promptly while the cleanup stays charged, and it never releases a possibly committed name.
"Small saves finish in milliseconds" is a measurement to record, not an assumption. The **120 s bound is an owner decision** (see revision 4), not implied by the seed timeout.

### R5.4 Added controls (finding 6)

Snapshot/hand-back creation and copying racing reduction (including an object registered at zero allocation before its first write); four occupied slots plus an attempted fifth, a
deletion-pending reader preventing premature slot reuse; allocation-normalization failure, empty files with residual allocation, differing allocation units; crashes before acceptance
persistence, after durable acceptance and before in-memory totals change, duplicate delivery and conflicting same-version measurements; forged or substituted object identities and
stale-connection receipts; completed-history latency through the metadata callbacks; downgrade attempts after modern accounting moved to shared/completed storage, with budget-enabled and
accounting-disabled startup.

## Controls and delivery

- [x] T4/T9: owner approved growing reservations and replacement of the
  single-winner strategy assertion with stronger concurrent accounting controls.
- [x] T4/T9: initial independent review identified MM recursion, ledger retirement
  and reentrant metadata dependencies; concrete mechanism addendum retained.
- [x] T4/T9: design accepted with conditions at revision 5 ([review](../../../evidence/2026-10-22/t9-growing-rev5-review-sol-high.md), four reviews 2026-10-22).
  Before implementation: fixed-width wire layouts, schema and state transitions, slot incarnation and pending-creation representation, exact release/adoption evidence,
  maintained-total update rules, concrete pending bounds and the monotonic clock representation; the owner's seed-wait decision for that dependent behaviour.
  Review the coherent changed kernel against the conditions before its first VM boot.
- [ ] T9 F5 regression: fresh budget-on state; overlapping distinct-name one-line files, Word temp/target saves, Excel SaveAs/edit/reopen, repetition with retained state;
  successful exact reservations without the 1500 ms grace; record backend cause and application result.
- [ ] T9 held/completed accounting: charge before and after proven retirement, retained oversized grants, shrink/truncate, live mappings and readers, copying hand-back,
  repeated restart, enough completed saves to expose cumulative metadata debt.
- [ ] T9 progress: cached/noncached/append/MDL/EOF/allocation/section crossings; all lane slots occupied; timeout, disconnect, mandatory teardown; exact pin release.
- [ ] T9 capability confinement: private roots covered by policy, wrong process/token/connection, impersonation, root/target substitution, links/reparse/ADS/by-ID,
  unsupported operations, noncached alignment, revocation, FILE_OBJECT address reuse.
- [ ] T9 crash/replay: every row of R3.6, lost initial-allocation replies separate from growth replies, mixed versions, exact-fit growth by many small increments, no
  duplicate debit or refund, no successful-prefix publication.
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
