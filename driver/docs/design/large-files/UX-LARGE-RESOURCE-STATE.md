# T9 modern reservation state and custody schema

2026-10-28. Concrete next increment of accepted
[growing reservations, revision 5](UX-LARGE-CONCURRENCY.md), following the passive
[v32 wire contract](UX-LARGE-RESOURCE-WIRE.md). Independent review accepted the
passive increment with the representation/charge conditions incorporated below.
Scope is a bounded schema codec and pure state/charge validation. No native I/O,
budget adoption, active negotiation or claim that a stored numeric value proves
object lifetime. The current v1 ledger remains unchanged. Integration with the
anchored metadata store, shared completed history and real custody proofs follows
separately before any growable admission.

## Representation

One immutable record per transfer, maximum 64 KiB UTF-8 JSON, depth at most 16.
Use exact property names, required properties, no duplicate properties at any
depth, no unknown properties, no numeric strings, and no unknown enum values.
Nullable fields are explicitly present as null. Serialization validates first;
deserialization validates the entire record before returning it. Invalid input
returns no partially usable record. Integers are signed 64-bit unless noted.
Connection cookies, wire/receipt sequences, volume serials and both file-ID
halves are unsigned 64-bit and preserve all bits; they are not JSON floating
point values. Revision, grant revision, incarnation and generation counters are
positive signed 64-bit values and never wrap.

| Field | Meaning / bound |
|---|---|
| Version | Exactly 2 |
| TransferId / DriverInstanceId | Nonempty GUIDs; never inferred from a path |
| Sid | Original SID string from the Windows token/journal, ordinal comparison, 1–184 characters; codec checks bounded nonempty data, not token authority |
| OriginalRequest | Canonical Base64 string (1592 characters) decoding to the complete 1192-byte original v32 allocation request; no whitespace, alternate encoding or reduced-tuple substitution |
| Alignment | Positive power of two, at least 64 KiB |
| MetadataGranularity | Actual metadata allocation unit, power of two at least 512; validated against a trusted caller-supplied unit, separately from content Alignment |
| AuthorizedCapacity | At least 16 MiB, aligned; historical monotonic maximum |
| MetadataDebit | Exactly max(1 MiB, 16 * MetadataGranularity), checked; no alignment to a larger content/destination unit and no new resource default |
| Revision | Positive, increases exactly once per durable state transition; exhaustion refuses |
| GrantRevision | 0 before binding; thereafter the last committed capacity revision, positive and at most Revision, matching the companion's capacity revision |
| GrowthClosed | Irreversible; no clock or reconnect reopens it |
| GrantMayHaveEscaped | Persisted true before the first positive reply can be attempted; irreversible |
| Binding | Null before binding; otherwise exact stage identity, immutable allocation generation and initial destination generation |
| CurrentDestinationGeneration | Null before binding; otherwise positive, at least the immutable initial generation; updated by exact journal→budget namespace transitions |
| Phase | Preparing, Writable, Closing, ClosedUnissued, WriteRetired, MetadataOnly |
| ClosureKind | None, UnissuedClosed or DriverWriteRetired; retained across MetadataOnly |
| Slots | Exactly four indexed positions; no unbounded per-slot history |
| AcceptedRetirement | Null or full semantic driver receipt: original cookie, sequence, driver/transfer/allocation/destination generations, stage identity, authorized capacity, EOF/allocation |
| StageRelease | Null or retained exact original-stage release evidence, including slot incarnation; remains if that slot is reused |
| PendingCompanion | Null or the single replacement transaction below |
| Companion | Null before initial commitment, or exact current companion identity/capacity/grant revision; not an authority derived from its pathname |
| FullDebitHeld | True while custody/reduction is uncertain; conservative hold, never authority to approve |
| ChargeBytes | Persisted checked derived charge; must agree with state and envelope |

Binding also records the original Stage slot index and incarnation. Identity is
the complete `(volume serial, file ID high, file ID low)`; either file-ID half may
be zero, but both cannot. All non-null generations
are positive. Current destination generation is retained separately in the
accepted retirement proof and current journal; rename never rewrites the
immutable initial binding. OriginalRequest is immutable across all revisions.
Its outer and complete inner intent must validate and match the record's
transfer/driver and original requestor; its deadline never changes on replay.
Historical deadline expiry is not corruption: validate original wire shape and
intent statically, without a current-time adoption check. The codec validates
correspondence, not current Windows grants or identity.

## Slot representation and conservation

A slot is Empty or has Index (0–3), positive Incarnation, Role (Stage, Snapshot,
PublicationTemporary, Handback), State, ReservedMax, optional full object identity,
optional locator, optional measured EOF/allocation and optional release evidence.
Locators are bounded to the existing 512-character path carrier and never object
authority. Empty slots have incarnation zero and no other data. Released slots
keep their last positive incarnation; reuse checked-increments it, never resets
or wraps it. At most one live Stage slot exists and matches Binding when bound.

| Slot state | Required facts / charged extent |
|---|---|
| ReservedNotIssued | Creation obligation persisted; no native creation may have started; identity/measurements absent; ReservedMax charged |
| CreationMayHaveStarted | Persisted before invoking native creation; identity absent until captured; ReservedMax charged; crash/timeout is not absence |
| Mutable | Exact identity persisted; writes enforce ReservedMax; no final measurements; ReservedMax charged |
| Immutable | All mutation rights ended and writes drained; exact identity and measured EOF/allocation; measured allocation rounded to alignment |
| ReleasePending | Unfinished/abandoned mutable custody; identity may be absent only for unresolved creation; measurements absent; retain ReservedMax until exact deletion/non-creation proof |
| ImmutableReleasePending | Previously Immutable, all measurements unchanged; retain rounded measured allocation until exact release; closing a reader does not re-inflate the old mutable envelope |
| Released | Exact release evidence, or proved never-created result; zero content charge, last incarnation retained |

ReservedMax is aligned, nonnegative and at most AuthorizedCapacity; a live
creation/copy reserves at least aligned expected length before any native create.
Zero expected length still has an explicit obligation; it is not a free slot.
An uncertain pre-identity creation cannot be retired from pathname absence.
Mutable requires identity and no measurements. Immutable and
ImmutableReleasePending require identity and both nonnegative measurements,
each at most ReservedMax/AuthorizedCapacity; copy EOF equals its admitted
expected length. ReservedNotIssued/CreationMayHaveStarted have no identity or
measurements. ReleasePending never substitutes partial-copy measurements for
ReservedMax. Released retains both measurements or neither and requires its
typed proof. All rounding and four-copy arithmetic is checked for overflow.
Every native start, identity capture, copy completion and release matches the
same transfer, slot, incarnation and claimed revision before committing state.
No old completion can affect a reused slot. Closing one reader is not a release
proof when another handle, section or operation may retain storage.

Release evidence is a typed immutable claim about the same identity/incarnation:
NeverCreated (native call never issued or definitive non-creation after the claim
was closed), or StorageReleased (all admitted handles/sections/operations drained
and final storage release or exact-identity absence established). The live native
adapter must establish the claim; the codec cannot manufacture proof from a
boolean, timeout, digest or locator. Missing/uncertain evidence keeps charge.
Original-stage StorageReleased evidence is copied into StageRelease before its
slot is reused, so later retirement replay cannot mistake a new object for it.
Every bound original-stage release records StageRelease in the same transition.
StageRelease matches binding identity, original slot/incarnation and the slot's
exact release witness. A live original Stage and StageRelease cannot coexist.

## Legal phases and derived debit

- Preparing: Binding may be null, no accepted retirement; full content debit.
  Stage creation/seed is an explicitly charged slot obligation. Binding and
  companion commitment precede any usable positive reply.
  GrowthClosed=false, GrantMayHaveEscaped=false and ClosureKind=None.
- Writable: Binding required, original Stage slot Mutable, GrowthClosed=false,
  no accepted retirement and full content debit. Growth persistence and slot
  ReservedMax update precede companion replacement and reply.
- Closing: GrowthClosed=true, Binding required, no accepted retirement yet,
  ClosureKind=None and full content debit. Already-granted writes/custody may
  still exist. This represents the durable growth closure before journal/seal
  completion, including failure of that later bookkeeping.
- ClosedUnissued: GrowthClosed=true, GrantMayHaveEscaped=false, no driver receipt
  required, ClosureKind=UnissuedClosed. The serialized intent is permanently closed before exact cleanup;
  no duplicate can bind or produce a later positive reply. Full debit until all
  pending creations and exact objects are resolved.
- WriteRetired: GrowthClosed=true, Binding and accepted retirement required.
  ClosureKind=DriverWriteRetired.
  Stage is immutable, release-pending or has its exact StageRelease proof. The
  accepted receipt matches the immutable binding and the current custody
  revision; a stale connection never creates a new accepted transition.
- MetadataOnly: GrowthClosed=true, all slots Empty/Released, no pending creation,
  copy or replacement. Requires accepted write retirement or the ClosedUnissued
  non-exposure closure, retained by ClosureKind. Entering this phase is explicit; zero measured EOF alone
  cannot imply it. Later content creation requires a new charged admission.
  FullDebitHeld=false and PendingCompanion=null are required; uncertainty stays
  in the preceding charged phase rather than claiming MetadataOnly.

AcceptedRetirement preserves its acceptance Revision separately from later
custody revisions, and matches driver/transfer/allocation generation and stage
identity. Its destination generation was current at acceptance; later authorized
rename may advance CurrentDestinationGeneration without invalidating the already
accepted storage proof. Receipt AuthorizedCapacity may be smaller than the
ledger's historical AuthorizedCapacity after a lost growth reply, but never
larger; measurements fit its declared capacity. While the original Stage is
Immutable/ImmutableReleasePending, both measurements equal the accepted receipt
exactly. A released/reused Stage slot instead requires the matching StageRelease.
This prevents a large-allocation receipt being paired with a zero-allocation slot.
Preparing/Writable/Closing have ClosureKind=None and no accepted receipt;
ClosedUnissued has no receipt, and WriteRetired has DriverWriteRetired closure.
Binding-null records have GrantRevision=0 and no current destination generation.
GrantRevision cannot be later than the accepted retirement revision. Allocation/
growth replies report this capacity-commit revision; retirement acknowledgment
reports its saved acceptance revision. Later custody revisions change neither.

Full content debit is `4 * AuthorizedCapacity + MetadataDebit`, checked for
overflow. Preparing, Writable, Closing and ClosedUnissued always retain it until
an explicit next phase; any pending companion or FullDebitHeld also forces it.
Only WriteRetired with a validated receipt
and still-current inventory can use `4 * max(charged slot extents) + MetadataDebit`.
The max includes ReservedMax for every pending/mutable slot; a copy at zero
allocation cannot lower debit. MetadataOnly has MetadataDebit only. Persisted
ChargeBytes must equal the applicable formula, never merely be below a ceiling.
This increment keeps the metadata debit; it does not implement or close the
shared completed-history handoff or remove its old cumulative charge.

## Single companion transaction

PendingCompanion stores operation GUID, predecessor exact identity/capacity,
target capacity/revision, replacement incarnation and optional exact replacement
identity, and phase ReservedNotIssued / CreationMayHaveStarted / Prepared /
NativeReplacementCommitted. A captured replacement identity is required for
Prepared/NativeReplacementCommitted; it is absent in the two pre-capture phases.
Predecessor identity/capacity is both absent/zero for initial creation only,
otherwise matches Companion and has positive aligned capacity. Target capacity
is positive/aligned, at least predecessor capacity and exactly AuthorizedCapacity;
target revision equals GrantRevision with 0 < target revision <= Revision.
Writable records retain a current Companion; pending growth may leave its older
capacity/revision until exact replacement bookkeeping completes. Without pending
state the current companion matches AuthorizedCapacity/GrantRevision.
One current/replacement pair only. Unknown identity
after native start retains the old conservative debit and blocks another growth.
Target capacity never decreases; replacement matches the exact binding and
persisted target revision (which can precede the current revision after closure).
No further growth starts until this transaction is resolved. Native success is final: restart completes bookkeeping from
exact current/predecessor/replacement evidence, never repeats a successful rename.
The codec checks representation and bounds; recovery decides no native action
from a serialized phase flag alone.

## Persistence and integration gates

Pure candidate transitions carry expected current Revision and complete next
record. Under the single budget gate, validate current revision/custody, check
the combined v1/v2 global and original-SID totals, persist through the anchored
noncached metadata capability, then adopt memory/totals before another admission.
An ambiguous write faults admission and retains conservative custody. No journal
or content I/O is introduced under this gate. Content work uses short claim →
release serialization → exact native work → complete matching claim transitions,
preserving journal→budget ordering and the separate growth lane.

Growth replay persistence is intentionally not complete in this schema increment.
Before any growth consumer, add a bounded sequence high-water/latest semantic
operation representation and explicit handling of older sequences. Clearing
PendingCompanion must not erase evidence needed to reject changed sequence reuse.
The passive codec cannot be enabled as the active growth ledger without that work.

Before runtime use: full initial/pre-binding and companion crash tables, exact
release adapters, combined v1/v2 totals, shared completed physical accounting,
marker transactions and enabled/disabled downgrade controls, all worker bounds,
deadline and original-intent resolution consumers. A successful schema round-trip
is not any of those results. Growable admission stays NotReady until all are
implemented, independently reviewed and qualified on the matched pair.
