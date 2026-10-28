# T9 growable resources: concrete wire and accounting identity

2026-10-28. Implementation detail of revision 5 of
[growing reservations](UX-LARGE-CONCURRENCY.md); independent review accepted the
passive increment with the parser/replay conditions incorporated below.
This specifies the first passive contract increment, not readiness, activation,
an implemented producer or qualification. The accepted metadata capability fence,
custody leases, startup recovery and all mapped/EOF paths remain prerequisites
before the mode can admit a file. Existing v1 behavior stays unchanged.

## Carrier and compatibility

Keep the v18 ordinary request/response and v20 lifecycle layouts unchanged.
Resource messages use extension **32**, distinct from the v31 failure-only seal.
Allocate keeps operation 3; new operations **23** (grow) and **24** (write-retirement
receipt) have no ordinary-verdict interpretation. Control **36** is reserved for
resource negotiation. These numbers are unused in the current headers; do not
renumber existing enums or reuse bound-head readiness.

All fields below are little endian, fixed width, packed at four bytes in C and
C#. GUIDs use the existing native GUID byte layout; stage identity remains the
24-byte volume serial plus complete 128-bit file ID. Every reserved byte and
unused carrier byte is zero. A reader validates exact native buffer length,
outer and inner version/size, kind, known result, correlation and tuple before
using any field. It rejects truncation, trailing bytes and unexpected flags.

The outer request remains 1192 bytes. `Reserved=32`, `Flags=StageV19ReplyFlag`,
nonzero RequestId. For growth/retirement, ImageName and its length are zero;
Path carries exactly the binary request, with PathLength its byte count and
the remaining Path bytes zero. These fields are never decoded or logged as text.
For allocation, ImageNameLength=104 and ImageName carries that intent; Path retains the
original destination under existing strict pathname validation.

The new reply is **376 bytes**, excluding FILTER_REPLY_HEADER: the unchanged
first 24 bytes of the v18 response header followed by the 352-byte resource
result below. Outer Version=18, StructSize=376, matching RequestId,
Verdict=DENY, StageNameLength=0. The ordinary verdict field is never resource
authority. The negotiated new driver supplies a 376-byte reply buffer and
requires exactly that length; an old 152-byte reply grants nothing. A new
agent never sends this frame for an old-mode allocation.

The resource parser must be selected before all ordinary and older stage
dispatch. An operation 23/24, Reserved=32, or recognized resource reply with a
mismatched envelope is a typed refusal, never ordinary ALLOW. Unknown pairs
remain immutable v1 or NotReady as specified by revision 3; no small immutable
grant is emitted in lieu of the negotiated protocol.

## Common binding, 112 bytes

| Offset | Width | Field |
|---|---|---|
| 0 | u32 | Version = 32 |
| 4 | u32 | StructSize of the containing request |
| 8 | u32 | Kind: 1 growth, 2 write retirement |
| 12 | u32 | Reserved = 0 |
| 16 | u64 | RequestId, equal to outer RequestId |
| 24 | u64 | Authenticated connection cookie |
| 32 | GUID | Driver instance |
| 48 | GUID | Transfer/reservation ID |
| 64 | u64 | Immutable allocation generation |
| 72 | 24 bytes | Complete stage identity |
| 96 | u64 | Current destination generation |
| 104 | u64 | Operation sequence |

IDs, cookie and sequence are nonzero; generations fit positive signed 64-bit
values. Allocation generation is persisted at first binding and never changes
on private rename. Destination generation is checked independently. A growth
operation captures its destination generation before dispatch; rename can make
that request stale but cannot change the allocation identity. A stale request
does not acquire capacity through a new name.

Operation sequence is per allocation, monotonically assigned by the driver,
and preserved across retransmission of that operation. Exhaustion closes/refuses
further operations; it never wraps. It is not the journal revision. Durable
operation identity is binding + kind + sequence + complete semantic request
(including extent/deadline or retirement measurements), excluding transport
RequestId. A retry may have a new transport RequestId, which its reply must echo;
reusing a sequence with different semantic fields refuses. Growth replay may return a later sufficient grant without another
debit only while the same binding is open. A closed binding never reopens.
Write-retirement sequence and its complete measurements are persisted so an
exact duplicate remains a no-op after restart; a conflicting tuple/measurement
does not refund. Reconnect uses a new cookie; it does not create a new allocation
generation or restore growth. Previously accepted retirement duplicates can be
recognized from durable evidence without treating an old cookie as live authority.
Such an acknowledgment reports historical acceptance only: it authenticates no
live connection, reopens no growth and never repeats a reduction.

## Allocation intent, 104 bytes

The first 72 bytes mirror the field order of StageAllocateV20, with Version=32
and StructSize=104. They retain allocation reservation ID, optional predecessor,
disposition/reference kind, driver instance and original process creation time.
Append: ConnectionCookie u64 at 72, IssuedInterruptTime u64 at 80,
DeadlineInterruptTime u64 at 88, Mode u32=1 at 96, Reserved u32=0 at 100.
Transfer ID remains the allocation reservation ID as on the existing allocator.
The first successful binding records its immutable allocation generation before
the companion or reply is usable.

Only fresh negotiated growable allocations use this intent. Exact replay first
resolves the original intent and returns its committed object/generations/capacity;
it does not size another window, reseed, reattach a failed CREATE or double-debit.
The initial capacity is the approved aligned max(16 MiB, checked held-source seed
requirement), with unchanged caller grants and read/export proof. V1 records and
companions retain their original capacity/accounting and parser.

## Growth and retirement requests, 160 bytes each

Growth: common binding at 0, ObservedCapacity u64 at 112, RequiredExtent u64 at
120, IssuedInterruptTime u64 at 128, DeadlineInterruptTime u64 at 136, then
16 reserved zero bytes. Capacity and extent are positive signed-64-bit aligned
values. RequiredExtent is greater than ObservedCapacity; it includes allocation
as well as EOF/write extent. Ledger capacity may already be greater after another
committed growth. The immutable alignment is loaded from the ledger, not supplied
as authority by the requester. No capacity is reduced by replay.

Retirement: common binding at 0, EndOfFile u64 at 112, AllocationSize u64 at 120,
AuthorizedCapacity u64 at 128, then 24 reserved zero bytes. Measurements are
nonnegative signed-64-bit values, individually no greater than the authorized
capacity. The sender produces this only after the accepted irreversible drain/
seal boundary and all growth adoption is resolved; these numeric checks alone
prove no retirement. The agent joins it to the same current custody revision,
including pending creations and mutable leases, in one durable reduction.

## Resource result, 352 bytes

| Offset | Width | Field |
|---|---|---|
| 0 | u32 | Version = 32 |
| 4 | u32 | StructSize = 352 |
| 8 | u32 | Kind: 0 allocation, 1 growth, 2 write retirement |
| 12 | u32 | Result |
| 16 | u64 | RequestId |
| 24 | u64 | ConnectionCookie |
| 32 | GUID | Driver instance |
| 48 | GUID | Transfer/reservation ID |
| 64 | u64 | Allocation generation |
| 72 | 24 bytes | Complete stage identity |
| 96 | u64 | Destination generation |
| 104 | u64 | Operation sequence (0 for initial allocation) |
| 112 | u64 | Observed/previous authorized capacity |
| 120 | u64 | RequiredExtent (0 except growth) |
| 128 | u64 | IssuedInterruptTime (0 for retirement) |
| 136 | u64 | DeadlineInterruptTime (0 for retirement) |
| 144 | u64 | Committed current capacity (allocation/growth success only) |
| 152 | u64 | Committed ledger revision (successful transition/replay only) |
| 160 | u64 | Retirement EndOfFile (0 except retirement) |
| 168 | u64 | Retirement AllocationSize (0 except retirement) |
| 176 | u32 | Flags = 0 |
| 180 | u32 | Reserved = 0 |
| 184 | u32 | StageNameBytes (allocation success only) |
| 188 | u32 | Reserved = 0 |
| 192 | WCHAR[64] | Stage basename; unused characters zero |
| 320 | byte[32] | Reserved = 0 |

Results: 1 Allocated, 2 CapacityCommitted, 3 RetirementAccepted,
4 NoAllocationCommitted, 5 RetryableBusy, 6 NotEnoughSpace,
7 DeadlineExpired, 8 Closed, 9 InvalidBinding, 10 Unresolved.
Only the matching success kind is valid: allocation/1, growth/2, retirement/3.
DeadlineExpired is allocation/growth only; retirement has no deadline.
Success needs a positive committed revision. Growth capacity must cover both
observed capacity and required extent. No failure returns usable capacity or
revision. Failures still echo the request's identifying fields; initial
allocation failures have zero unknown stage identity/generations/name.
NoAllocationCommitted is allocation-only and requires the existing durable
exact-resolution proof; busy/deadline/transport failure cannot imply it.

An allocated basename obeys the existing extension and transfer-ID checks and
contains no separator, ADS syntax, embedded NUL or unvalidated suffix. Its length
is even, positive and less than the 128-byte field, leaving a terminator. Allocation
reply authority is rechecked against the exact opened stage and companion.
Growth and retirement carry zero name fields. The result echoes request fields
exactly except newly assigned allocation identity/generations and a successful
current capacity/revision. It cannot authorize content, publication or export.
Offset 112 is zero for allocation, the exact ObservedCapacity for growth and
the exact AuthorizedCapacity for retirement. Every inapplicable field is zero.
Allocation/growth success capacity is positive, signed-64-bit representable,
aligned to the validated immutable granularity and at least 16 MiB. Before live
adoption it must equal the exact companion/ledger binding's committed capacity;
a valid wire shape alone supplies no authority. Retirement success has capacity
zero and echoes the complete measurements, not a second grant.

V20 allocation-resolution helpers retain their existing larger reply/ALLOW/
byte-identical original-request contract. No v32 result substitutes for that
proof. Future v32 NoAllocationCommitted consumption must retain/correlate the
complete original allocation intent and exact absence/non-adoption proof,
including exclusion of another duplicate committing. This passive enum value
supplies no runtime cleanup, release or name-recovery authority.

## Clock, bounded work and abandonment

Use the guest's interrupt-time count in 100-nanosecond units: existing
KeQueryInterruptTime on the driver side and QueryInterruptTime in the service.
Both use the same boot domain; driver instance/connection fencing rejects
cross-boot values. Subtraction/comparison is checked; no UTC/FILETIME deadline
or restarted retry timer. Allocation Deadline-Issued is exactly 1,200,000,000
ticks (120 seconds). At receive and before any authority-changing adoption,
expired work refuses; a late committed result remains charged and is resolved.
Validity is checked Issued <= now < Deadline; equality at Deadline is expired.
Resolving a committed allocation after expiry may finish bookkeeping or exact
cleanup, but cannot revive/attach the failed CREATE or renew its deadline.
The driver checks expiry immediately before reply adoption. Retirement has no
deadline and cannot be interpreted as a growth acknowledgment.
The service preserves the original pair through queue, seeding and persistence.
Growth uses a separate bounded short request budget and retains uncertain debit;
its exact duration is not inferred from the allocation or inspection timeout.

[Microsoft interrupt-time contract](https://learn.microsoft.com/en-us/windows/win32/sysinfo/interrupt-time):
interrupt time is not changed by user/Windows time-service clock adjustments.
Sleep contributes to the biased count. Admission rechecks after resume; a timer
callback arriving late does not extend the absolute deadline.

Proposed pending bounds: eight unresolved initial allocations per connection,
four per SID, counting queued, active and abandoned work until exact resolution.
Per-SID unresolved records survive reconnect/restart. A stopped waiter does not
release a slot; only an exact non-adoption/cleanup transition does. Growth lane:
eight workers, 32 queued requests per connection, independent of allocation and
lifecycle lanes. Saturation produces correlated RetryableBusy, never a positive
reply or an unbounded continuation. These are in-flight work bounds, not caps on
files or their admitted size. Ordinary paths below the current grant do not wait
on this lane. No mode activation until all lane/rundown controls pass.

## Durable schema and delivery boundaries

Modern reservation Version=2 distinguishes Mode, AllocationGeneration,
DriverInstance, stage identity, original SID, alignment, AuthorizedCapacity,
GrowthClosed, LedgerRevision, pending companion replacement, accepted retirement,
and four custody slots. Each slot has a monotonically increasing incarnation,
role, PendingCreate/Mutable/Immutable/ReleasePending/Released state, optional
identity (absent only for charged PendingCreate), ReservedMax and measurements.
Every completion matches transfer + slot + incarnation + exact identity +
current ledger revision; an old completion cannot act on a reused slot.

Before the first modern record, persist a non-JSON format marker under
`.space-reservations` and retain it while modern/shared accounting remains.
The current old enabled reader rejects non-JSON residue; the current old disabled
startup rejects any remaining reservation-directory entry
(`MinifilterInterceptor.InitializeStagingSubsystem`). Thus shared/completed
records cannot remove the downgrade guard. New startup classifies the marker,
modern records and recognized pending replacements before legacy blanket checks.
Marker validity/identity/security and all shared charges are startup admission
requirements; malformed/missing evidence stays held.

The concrete metadata-capability registration/control layouts, completed-history
storage transitions, noncached I/O operations, short claim/complete transitions
and storage-release proofs will be specified with their implementing increments.
No capacity consumer, mode negotiation success or small-window admission can be
enabled from these passive wire types alone. Before that boundary, all revision-5
conditions must have concrete implementation and independent review, followed by
WDK/static/import gates, four-leg agent matrix and matched-pair qualification.
