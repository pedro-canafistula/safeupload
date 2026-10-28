# T9 growing reservations: revision 6 implementation contracts

2026-10-28. **Proposed addendum for independent review; documents only.**
Second revision after the independent REVISE re-review; not yet accepted.
The [re-review](../../../evidence/2026-10-28/t9-growth-protocol-rereview-sol-high.md)
closed F1/F2/F3/F5/F7 as design corrections, with native/source/runtime proof
still distinct; its three residual findings are addressed below.
Source anchors below refer to `feat/driver-m2` at `7867cf37`; proposed types and
modules are identified as proposed. This is increment 1's contract proposal,
not completion of its executable transitions, review acceptance, activation or
qualification. The decomposition is the read-only planner output
`~/Work/safeupload-tools/workers/t9-growth-plan-final.md` (seven increments,
design gaps/owner boundaries and five-hazard table).

Read with [revisions 1–5](UX-LARGE-CONCURRENCY.md), the passive
[wire](UX-LARGE-RESOURCE-WIRE.md) and [custody schema](UX-LARGE-RESOURCE-STATE.md),
[defaults](UX-LARGE.md), [recovery](UX-LARGE-RECOVERY.md) and
[qualification rows](UX-LARGE-VM.md). Review provenance:
[wire](../../../evidence/2026-10-28/t9-resource-wire-review-sol-high.md),
[state](../../../evidence/2026-10-28/t9-resource-state-review-sol-high.md),
[revision 5](../../../evidence/2026-10-22/t9-growing-rev5-review-sol-high.md).
The [revision-6 review](../../../evidence/2026-10-28/t9-growth-protocol-review-sol-high.md)
requires the corrections and implementation gates below. The revision-5
review's pending allocation duration was subsequently settled by the owner:
120 s, as recorded in revision 4's owner decision. Growth duration remains open.

## 1. Scope, precedence and authority

Revision 6 makes the remaining revision-5 integration contracts concrete. Its
new formats, controls and bounds are proposals until independently reviewed.
It does not change the approved budget formulas, four-copy envelope, 120 s
issuance-to-adoption allocation wait, absence of a modern per-file cap, Windows
grants/sharing/security, or publication/read/export authority. It does not change
any test threshold, assertion, scope or cutover gate. Preserve shipped unbound
v1/v20 behavior and the bound-head NotReady gates. No resource message means
ordinary ALLOW; no timeout means non-commitment or storage release.

The passive ABI is real; the active mechanisms below are not. In particular,
`driver/SafeUpload.Minifilter/StageResourceWire.h:4` declares no producer or
negotiation success; `agente/SafeUpload.Agent.Minifilter/ResourceWireV32.cs:46`
only parses growth. The budget constructor at
`agente/SafeUpload.Agent.Service/Interception/StagedSpaceBudget.cs:89` still
accepts only the legacy startup shape. Modern readiness is the conjunction of
metadata confinement, bounded dispatch/replies, reconstructed accounting,
native custody adapters, initial-allocation fencing, growth/MM consumers and
the existing runtime gates. Negotiation cannot assert readiness from parser
support. Keep ordinary metadata/content work off the growth dependency chain.

Notation: `K = (DriverInstance, TransferId, immutable AllocationGeneration,
complete StageIdentity)`. Identity is `(volume serial u64, file-ID low u64,
file-ID high u64)` in existing native order; neither a path nor a hash is K.
`D` is the separately checked current destination generation. `C` is authorized
capacity; `G` is the capacity-commit revision; `R` is the custody revision.
All integers are little endian, pack 4; GUID bytes use the existing native
layout. Signed-positive counters never wrap. Unsigned cookies/sequences/identity
words preserve every bit. Unknown bits, reserved nonzero bytes, incorrect native
lengths, inapplicable fields, overflow and trailing bytes refuse before use.

## 2. Negotiation and resource control ABI

### 2.1 Control 36 and negotiation success

Extend `StageResourceWire.h:9` and `ResourceWireV32.cs:11`; add an explicit
resource-control branch before ordinary controls in
`driver/SafeUpload.Minifilter/Communication.c:2075`. Existing control 35 at
`Communication.c:2096` remains the exact four-byte v31 failure-seal receipt; it
does not negotiate growth. Port-process binding at `Communication.c:1988` and
service-SID checks both apply to **every** control-36 opcode. No pointer value
is exported as a cookie.

All control-36 requests/replies have this 64-byte header. Total native length
equals `64 + PayloadBytes`, with no optional tail. Reply echoes opcode and
ControlRequestId, including failures. Except negotiation's cookie assignment,
it echoes cookie/instance exactly. Request IDs are nonzero, per connection,
never reused while unresolved; exhaustion revokes this session.

| Offset | Type | Field |
|---|---|---|
| 0, 4, 8, 12 | four u32 | outer Version=18, total StructSize, Command=36, Reserved=0 |
| 16, 20 | two u32 | ResourceVersion=32, Opcode |
| 24, 32 | two u64 | ControlRequestId, numeric ConnectionCookie |
| 40 | GUID | DriverInstance |
| 56, 60 | two u32 | PayloadBytes, Flags=0 |

Opcodes: 1 Negotiate, 2 Revoke, 3 RegisterRoot, 4 RegisterChildIntent,
5 FenceAllocation, 6 ResolveAllocationAck, 7 ShellSnapshot (section 5.4.1). These are proposed subcommands of
36, not new ordinary operation numbers. No opcode silently succeeds on an
older peer. NoControl/short/malformed/unsupported result means no modern mode.

Negotiate request payload is 96 bytes:

| Offset | Type | Field |
|---|---|---|
| 0 | GUID | AgentInstance (fresh service lifetime) |
| 16, 24 | two u64 | OfferedCapabilities, RequiredCapabilities |
| 32 | u64 | proposed GrowthWaitTicks (zero until an owner-approved duration exists) |
| 40, 44, 48, 52, 56, 60 | six u32 | unresolved allocation limit=8, SID limit=4, growth workers=8, growth queue=32, lifecycle workers=2, lifecycle queue=32 |
| 64 | GUID | ReadinessEpoch, nonempty only after agent recovery prerequisites |
| 80, 84 | u32 + byte[12] | Phase (1 Probe, 2 Commit), reserved zero |

Probe has header cookie/DriverInstance zero and ReadinessEpoch zero, always
returns NotReady, and obtains the provisional cookie/actual instance. An exact
Probe retry on that port returns the same provisional identity. Register roots
using that authenticated identity before Commit. Commit has the returned header
cookie/instance and nonempty ReadinessEpoch; it freezes the complete offered
contract/epoch. Exact Commit retry is idempotent; a changed committed tuple
requires Revoke and a new connection. Probe does not freeze Commit's readiness
epoch. Only Commit can return Ready; it cannot return Ready with GrowthWaitTicks
zero. Provisional registration/Probe is not negotiation success.

Reply payload is 112 bytes:

| Offset | Type | Field |
|---|---|---|
| 0, 4 | two u32 | Result (1 Ready, 2 NotReady, 3 Unsupported, 4 Invalid), Mode (1 growable only on Ready; otherwise 0) |
| 8 | u64 | AcceptedCapabilities (0 on failure/Probe) |
| 16, 32, 48 | three GUIDs | AgentInstance echo, ReadinessEpoch echo, BootDomain |
| 64 | u64 | GrowthWaitTicks (exact accepted value; zero on failure) |
| 72…92 | six u32 | exact accepted bounds in request order; zero on failure |
| 96 | byte[16] | zero |

Header returns the actual DriverInstance and nonzero provisional/current cookie
for an authenticated well-formed negotiation, even on NotReady. Cookie is a
monotonically allocated u64 session number within the driver instance, never
reused there; exhaustion refuses a connection. BootDomain is an independently
validated OS-boot identity, not the service instance or a wall clock (native
source is unresolved in section 13). Capabilities are u64 bits:

| Bit | Capability / required proof before advertising |
|---|---|
| 0 | exact v32 allocation/result, companion-v2, 120 s adoption deadline |
| 1 | durable monotonic growth, bounded semantic replay, selected growth deadline |
| 2 | driver stage-write retirement and exact acknowledgment replay |
| 3 | metadata capabilities, noncached operations and transitive-query fence |
| 4 | bounded dispatch, independent growth/reply progress and local rundown |
| 5 | complete-intent abandonment/CREATE adoption fence |
| 6 | modern schema-3 custody/recovery/shared accounting/downgrade guard |
| 7 | all supported MM/MDL/cache/EOF/allocation capacity crossings |

RequiredCapabilities is exactly `0xff` for modern admission; Offered must contain
all required bits and no unknown bits. Success requires the driver and agent
each meet every bit and all runtime readiness gates, trusted roots on this
connection and the same ReadinessEpoch; the driver returns exactly `0xff`.
No subset success, no implicit 3 s selection, no bound allocation. A provisional
cookie alone grants neither capacity nor a policy bypass. Revoke payload is
`Reason u32` (1 disconnect, 2 readiness loss, 3 shutdown), `Reserved u32=0`;
reply is `Result u32` (1 revoked), `Reserved u32=0`. Revocation is monotonic,
locally cancels adoption and growth waits before dependent lifecycle drains,
and does not wait for a service ACK or erase durable unresolved obligations.

| Connection state / interruption | Allowed next state / authority | Control |
|---|---|---|
| Authenticated, before Probe | Provisional only; no modern admission; crash retains durable accounting | R3-N01 |
| Provisional after Probe/root registration; Commit lost before processing | exact retry Commit; no Ready inferred from local roots or cookie | R3-N01 |
| Ready committed, reply lost | exact Commit retry returns same cookie/epoch; changed tuple refuses; driver still applies all live adoption checks | R3-N01 |
| Ready → revoke/disconnect/readiness loss | Revoked irreversibly for that session; cancel adoption, preserve charged uncertain results and unresolved counts | R3-N02 |
| Service restart/new connection | new provisional cookie/AgentInstance, reconstruct then register/Commit; never restore old-cookie authority | R3-A04 |

### 2.2 Driver-to-agent allocation, growth and retirement

Retain the passive layouts without reinterpretation:

| Exchange | Exact layout / adoption contract |
|---|---|
| Allocate, operation 3 | 1192-byte outer v18 request, Reserved=32, StageV19ReplyFlag, ImageNameLength=104; ImageName[0:104] is AllocationV32, remaining 24 bytes zero; Path is the original strict destination, unused bytes zero. Intent[0:72] is existing v20 field order with version 32/size 104; cookie@72, issued@80, deadline@88 (u64), mode=1@96, zero@100. Complete original bytes remain immutable. |
| Grow, operation 23 | Same outer size/version/flag/Reserved; ImageName empty, PathLength=160 binary bytes, remaining carrier zero. Common binding: version/size/kind/zero@0/4/8/12; requestId@16, cookie@24, driver@32, transfer@48, allocation generation@64, stage identity@72, D@96, sequence@104. Then observed C@112, required aligned extent@120, issued@128, deadline@136, zero[16]@144. |
| Write retirement, operation 24 | Same 160-byte framing/common binding, kind=2. EOF@112, measured allocation@120, driver's adopted authorized C@128, zero[24]@136. No deadline. |
| Reply to each | Exactly 376 bytes excluding FILTER_REPLY_HEADER: outer 24-byte v18 header, Verdict=DENY and StageNameLength=0, then ResultV32[352]. Kind/result@8/12; requestId/cookie@16/24; driver/transfer@32/48; allocation generation/identity/D/sequence@64/72/96/104; observed/required/issued/deadline@112/120/128/136; committed C/G@144/152; retirement EOF/allocation@160/168; flags/zero/nameBytes/zero@176/180/184/188; WCHAR[64] basename@192; zero[32]@320. Offsets in this row are relative to ResultV32. |

Kinds 0/1/2 pair only with results 1 Allocated / 2 CapacityCommitted /
3 RetirementAccepted. Results 4 NoAllocationCommitted, 5 RetryableBusy,
6 NotEnoughSpace, 7 DeadlineExpired, 8 Closed, 9 InvalidBinding, 10 Unresolved
carry zero usable capacity/revision. All identifying request fields echo exactly;
allocation failure has zero unknown identity/generations/name. Initial allocation
sequence is zero. Growth/retirement sequence is nonzero and monotonic per K.
Retirement has zero grant capacity, extent and clock fields. Only allocation
success carries a basename, subject to the existing transfer/extension grammar.
The successful revision is G for allocation/growth and accepted R for retirement.
Compare against the held exact companion/ledger before adoption, not just a
number or wire shape (`ResourceWireV32.cs:141`–`:148`, `:181`–`:184`;
these compare supplied committed values and do not establish native custody).

Transport RequestId can change on growth retransmission; semantic sequence,
cookie, K, D, extent, observed capacity and deadline cannot. Initial resolution
retains **all 1192 original bytes**, including its original RequestId. A new
transport control wraps those bytes; it does not edit the saved request. Select
resource parsing before all ordinary dispatch. A recognized resource marker in
an invalid envelope refuses; it never falls back to an ordinary verdict.
`Communication.c:1715` needs a separate 376-byte reply buffer branch and a
remaining-resource-deadline timeout, replacing the inspection-timeout dependency
at `Communication.c:1731` only for modern resource requests.

### 2.3 Mixed-version matrix (R3.4)

| Driver / agent / persisted state | Peer-visible result |
|---|---|
| New / new, all prerequisites Ready | v32 exact negotiation; small initial window then monotonic growth; immutable mode stored per allocation |
| Old / new, v1 only | old controls/v20 replies and original immutable allowance/limit, or NotReady if the requested profile requires modern readiness; no small immutable substitute |
| New / old, v1 only | old negotiation sees unchanged v31 control-35 receipt, v20 allocation and legacy companion; no v32 frame sent |
| Either loses modern capability with live modern custody | revoke modern admission and fail required growth privately; never reinterpret that allocation as v1; reconstruct custody before another modern session |
| Old agent, modern hot or shared history; new agent accounting disabled | startup refuses because the persistent non-JSON marker remains; no deleting, ignoring or converting modern accounting |

Controls: R3-N01 and R3-N02 in section 12. Existing v20 larger ALLOW/
byte-identical original-request resolution remains unchanged at
`agente/SafeUpload.Agent.Service/Interception/StagedAllocationResolution.cs:35`;
no reduced v32 tuple replaces that proof.

## 3. Modern companion and startup bytes

### 3.1 Fixed 192-byte companion-v2

The growable `.space` is a different format; never reinterpret the 64-byte v1
grant (`StagedSpaceBudget.cs:764`, `StageStream.c:1735`). One current object and
at most one replacement, no revision-file series. New basename is still the
stage basename plus `.space`; the sole replacement is `.space.new`.

| Offset | Type | Field |
|---|---|---|
| 0 | byte[8] | ASCII `SAFGRW02` |
| 8, 12 | two u32 | Version=2, StructSize=192 |
| 16, 32 | two GUIDs | DriverInstance, TransferId |
| 48, 56 | two u64 | immutable allocation generation, initial destination generation |
| 64 | identity[24] | exact stage identity |
| 88, 96, 104 | three u64 | immutable Alignment, InitialCapacity, AuthorizedCapacity |
| 112, 120 | two u64 | GrantRevision, GrowthSequence (0 at initial commitment) |
| 128 | GUID | companion transaction OperationId |
| 144 | identity[24] | this companion's captured identity |
| 168 | byte[24] | zero |

InitialCapacity is immutable approved aligned `max(16 MiB, checked held-source
seed requirement)`. Capacity is aligned, at least InitialCapacity and never
decreases; G increases on each new capacity commitment. The ledger supplies
the complete pending predecessor identity/C/G, target C/G, operation ID and
replacement incarnation/identity, not an unbounded list in the companion.
GrowthSequence references the durable replay entry in section 4. The companion
does not bind the current rename generation: initial D is historical, current D
is checked in each live request. It has no mutable connection cookie. Its own
identity is captured after FILE_CREATE and before writing/flush; it is not known
before creation. ACL/link/no-reparse checks authenticate storage; the magic and
numeric fields alone do not. No checksum is treated as object authority.

`StageStream.c:1762` currently reads capacity once and skips later reads;
`:1780` falls back to the legacy capacity on missing grant. Preserve that v1
behavior **only for v1**. Modern first adoption requires exact format/length,
identity, driver/transfer/generations/alignment/C/G and trusted security from
the held companion matching the result. Missing modern companion refuses,
never falls back. Cache InitialCapacity, C, G and K once in the stream. Growth
does not poll/reopen the companion in an MM wait: the agent commits it through
metadata capabilities, and the authenticated reply advances the cached C/G
under the stream's adoption fence. A lower/stale reply cannot shrink C; an
equal-C reply needs the matching G. On reconnect no new write authority is
derived from disk alone. Repair is an accounting transaction, not a kernel grant.

### 3.2 Durable transaction and R3.6/R4.5 startup table

Persist charged target and PendingCompanion before native create. Persist
CreationMayHaveStarted before invoking it; capture/persist exact replacement
identity, write padded noncached bytes, flush, set exact EOF, then flush again
(section 8.4) before persisting Prepared. Exact relative replacement validates the held predecessor and its
exclusion/security. Native success is final. Persist current Companion + replay
commit before reply. Updating memory/totals follows persistence. Retain the full
debit throughout a pending transaction. Any ambiguous ledger write faults
admission; any unresolved replacement blocks further growth of this K.
Schema 3 adds PendingCompanion phase **IdentityCaptured=5**, without renumbering
the existing 1–4 values: CreationMayHaveStarted → IdentityCaptured persists the
captured replacement identity **before writing it**; IdentityCaptured → Prepared
requires complete bytes/flush/EOF/post-EOF flush. IdentityCaptured/Prepared/
NativeReplacementCommitted require identity; the two pre-capture phases forbid
it. This closes the passive v2 representation gap between capture and Prepared;
do not persist a captured identity in v2's CreationMayHaveStarted shape.

| Durable ledger / observed bytes | Startup action, no inference from equal capacity alone | Control |
|---|---|---|
| No pending; current identity, all 192 bytes, C/G match | normal inventory; no rewrite | R3-C01 |
| Pending with exact predecessor current, replacement absent, ReservedNotIssued | create the recorded replacement after claim; keep target charge | R3-C02 |
| CreationMayHaveStarted, identity absent, possible `.space.new` | hold if object exists/identity unknown; absence only resolves after creation claim fenced; no path adoption | R3-C02 |
| Exact incomplete replacement plus predecessor current | exact delete/recreate only after closing its creation claim; never expose partial bytes | R3-C02 |
| Prepared exact replacement; predecessor current at smaller proven C/G | perform the **unperformed** exact native replacement, then bookkeeping; no refund | R3-C03 |
| Exact target is current, predecessor present or absent | verify complete target bytes/K/op/C/G; finish bookkeeping, delete only exact proven residue; do not repeat rename | R3-C03 |
| Ledger ahead, smaller current proven predecessor | monotonic repair using pending identity and target; no shrink of debit | R3-C03 |
| Companion ahead of ledger, changed identity/binding, or unknown current/replacement | hold and diagnose; no grant, overwrite or legacy conversion | R3-C04 |
| `.json.new` ledger residue | read strict bounded candidate and predecessor by exact handles; match expected R/transaction. If uniquely committed current, finish; if ambiguous, fault admission and preserve both | R3-C04 |
| Initial bind/current missing, or create before identity capture | resolve initial creation claim separately; pending initial has predecessor=null/zero, never an invented predecessor | R3-C02 |
| Interrupted repair | re-enter the same table, without another debit or repeated committed mutation | R3-C03 |
| Closed growth, journal completion failed | closure is irreversible; finish journal later; target charge and replay retained | R4-O01 |
| Reconnect / driver restart | preserve durable K, C/G, intent, replay and unresolved counts; recreate cookie/anchors/pins. Old-cookie work gains no new authority; restart alone gives no absence/adoption proof | R3-A04 |
| Retired proof/reduction pending; mutable snapshot/reader/copy | restore four exact slots and retained maxima/measurements; section 9's transaction; no EOF-only refund | R5-S01 |
| Missing ledger with modern companion/content | hold; no LegacyGuard import | R3-C04 |
| LegacyGuard, ContentReleased, legacy upgrade or shared completed entry | separate supported classifier, original immutable debit or exact shared debit; no modern window conversion | R4-H01 |

Startup order is trusted-root validation → schema/residue classification →
conservative combined totals and pending counts → permitted exact recovery →
inventory validation → readiness. This replaces the early legacy-only rejection
at `StagedSpaceBudget.cs:89`, not its conservative failure behavior. No live
admission runs during startup reconstruction. R3.6's table is not a sweep license.

## 4. Bounded semantic growth replay and executable transitions

The strict passive v2 record (`ResourceStateV2.cs:8`,
`ResourceStateCodecV2.cs:64`) rejects unknown fields. Propose **reservation
Version=3**, keeping all v2 fields/semantics and adding required replay,
intent-resolution and history-handoff fields below. A new strict codec must
reject missing/duplicate/unknown fields, enum values, numeric strings and depth
over 16, and retain the **64 KiB** total record bound. Do not append permissive
fields to Version=2. Pre-runtime v2 import is allowed only by explicit validated
migration with no live negotiation; future old v2 readers must reject v3. Also
require nonempty InstallationId and required-null `RetirementWitnessId`
(nonempty GUID exactly when AcceptedRetirement exists), created/persisted with
receipt acceptance; this local witness ID is not new wire authority.
Require positive aligned immutable `InitialCapacity`, at least 16 MiB and at
most AuthorizedCapacity, matching the initial companion/held seed admission.
The v2→v3 migration cannot infer a smaller initial capacity from current EOF.

Required `GrowthReplay` has `HighWater u64`, `Latest` null or exactly one
`{Sequence u64, CanonicalRequest Base64[216], State, Result (nullable resource
result code), CommittedCapacity (nullable i64), GrantRevision (nullable i64),
AcceptedRevision (nullable i64)}`. CanonicalRequest decodes to all
160 growth bytes with **only RequestId@16 zeroed**. It includes cookie, K, D,
observed/required extent and issued/deadline. No digest substitutes for bytes.
State is Claimed=1, Charged=2, CompanionCommitted=3, Refused=4. Initial value is
HighWater=0/Latest=null; otherwise Latest.Sequence equals HighWater and its
canonical bytes match the stored K and sequence. Claimed/Charged have null
Result/AcceptedRevision; Claimed has null capacity/G, Charged has target C/G
equal to the charged pending transaction. CompanionCommitted has result=2,
positive sufficient C/G and positive accepted R; Refused has a typed failure,
null capacity/G and positive accepted R. No nullable field may be omitted.
Retirement has its separately retained full accepted
receipt; driver serializes its sequence assignment with growth, and permanently
closes growth before assigning retirement. Retirement sequence must exceed
GrowthReplay.HighWater; it does not displace growth replay.

Only **one unresolved semantic growth operation per K** is issued. Concurrent
crossings join its bounded shared operation (section 11.1). Each application I/O
retains its own first-crossing deadline; a higher-extent waiter may issue a later
semantic sequence only within that original remaining interval (section 7).
No join, subsequent sequence or append recomputation renews its I/O deadline.
A waiter does not edit an in-flight semantic extent/deadline.
No later operation is issued until the earlier one is terminal. Therefore latest
semantic equality plus a durable stale-rejection floor is sufficient; no sliding
unbounded replay log or revision-count cap is necessary.

| Input under `_gate` | Required candidate transition / result |
|---|---|
| New sequence > HighWater, same live K/current cookie/D, previous latest terminal | persist complete Claimed semantic entry before any capacity effect; advance HighWater atomically. Gaps are permitted (driver may have refused locally), never wrap. |
| Sequence = HighWater, equal complete canonical bytes | resume the recorded transaction or return its recorded refusal; successful replay can report current sufficient C/G while still live/open and unexpired; never another debit |
| Sequence = HighWater, changed byte other than transport RequestId | InvalidBinding, no mutation, capacity or renewal |
| Sequence < HighWater | InvalidBinding/stale, no success, even if requested extent now fits; equality can no longer be established after compaction |
| New/duplicate on closed, wrong D/cookie/K, or expired | correlated Closed/InvalidBinding/DeadlineExpired; no grant. Previously committed charge remains; accepted retirement replay is historical acknowledgment only. |
| Sufficient current capacity, new valid sequence | persist terminal success semantic entry referencing current G, no capacity charge; exact request still retained |
| Insufficient capacity | checked geometric preference then aligned sufficient exact-fit; if fits, persist C, four-copy increment, stage ReservedMax, new G and Charged replay together; otherwise persist Refused with NotEnoughSpace |
| Charged | finish sole PendingCompanion; commit current companion + CompanionCommitted + G in one ledger transition before reply |

New sequences are not allowed to replace Claimed/Charged entries, even if another
transport call supplies a higher number. Return Unresolved, with no grant. A
busy queue rejection does not advance HighWater or allocate a file. Retrying
Busy uses the same semantic operation/deadline. Refused is terminal; required
growth failure makes this save permanently nonpublishable on the driver side.

Compaction replaces the previous **terminal** Latest with the next Claimed entry
in one durable transition. HighWater never decreases. Older sequences always
refuse, so changed reuse cannot acquire authority even though old semantic
bytes are gone. Keep latest until transfer closure; move HighWater/latest and
accepted retirement into shared completed history before deleting the ledger.
Shared historical replay never returns capacity. Clearing PendingCompanion
alone does not clear Latest, HighWater or conflict evidence. The representation
is constant size per transfer and remains inside the existing metadata envelope;
repeated exact-fit growth does not exhaust a revision-file quota.
Before MetadataOnly/shared handoff, any Claimed/Charged replay is settled to a
terminal success/failure with all native obligations resolved. Closing it cannot
erase a charged target: authorized capacity remains historical and exact release
still controls the debit.

| Crash point | Reconstructed effect |
|---|---|
| Before Claimed persistence | no capacity effect; exact retry may claim |
| Claimed, before charge | resume same semantic admission or close/refuse; no debit yet for growth |
| Charged, before companion | target full debit retained; recover section 3 |
| Companion current, before terminal replay persistence | exact pending evidence proves native result; finish bookkeeping, no repeat rename |
| Terminal persisted, before reply/memory adoption | restore terminal replay and maintained charge; exact retry no-op |
| Next Latest persisted, old duplicate arrives | old sequence refuses from durable HighWater, not guessed equality |
| Closure persisted during any step | keep charged state/pending evidence and close; late success cannot restore mutation or clear sticky failure |

Proposed pure transition/replay module consumes `(current record, expected R,
typed event)` and returns a fully validated candidate or typed refusal; it does
no I/O. Store validates current R and combined v1/v3 totals, persists, then adopts
memory/totals under `_gate`. Ambiguity faults admission. Controls R3-G01/G02
exercise each row plus clearing PendingCompanion, compaction, reordered sequences,
changed deadlines and unsigned high-bit sequence/cookie values.

## 5. Lost initial reply: intent, abandonment and CREATE fence

### 5.1 Intent record and service closure

Reservation-v3 adds required `InitialResolution`:
`{OriginalRequest (same canonical 1192 bytes as the immutable record field),
OriginCookie u64, BootDomain GUID, Sid, IntentRevision i64, State,
FenceId GUID?, ControlReason u32?, FenceReceipt Base64?, CleanupWitness GUID?, ResolutionRevision
i64?}`. The duplicate OriginalRequest field must byte-equal the record field;
an implementation may store it once and reference it in memory, but persisted
validation must have one canonical authority. States: Open=1, Closing=2,
Fenced=3, Attached=4 (provisional successful attachment awaiting final-success
receipt), CleanupComplete=5, ResolutionAcknowledged=6, InitialResolved=7
(durably proved final CREATE success). Sid must
equal the ledger's original requester SID, not the reconnecting service token.
Driver's intent key is `(DriverInstance, AllocationReservationId)` plus exact
original bytes; changed bytes with that key refuse. Driver also retains original
parent-directory identity/name-reservation/view-generation evidence, never a
pathname-only name-release claim.

Persist Open plus reserved Stage slot before **any** native creation/seed. One
service allocation claim owns the intent; duplicate preparation, replay and
closure serialize through that intent, without holding a lock across content
I/O needed by growth. Closing is durable and irreversible and excludes future
creation/positive reply claims; already executing preparation must settle its
creation obligation and report its exact object. Persist GrantMayHaveEscaped
before attempting any positive reply. If closure wins, that worker cannot send
a positive result or bind a different object. Claim completion checks the same
intent revision and closure; a late native commit is recorded as cleanup custody,
not adopted as fresh allocation. Expiry/cancellation merely requests Closing.

### 5.2 Driver fence and concrete control messages

FenceAllocation (opcode 5) payload is **1224 bytes**: original request[1192]@0,
FenceId GUID@1192, Reason u32@1208 (1 expiry, 2 cancelled, 3 disconnected,
4 service abandonment, 5 initial-resolution query), reserved zero[12]@1212. The outer header uses the
**current** authenticated cookie; original bytes carry the origin cookie.
No stage identity is required to ask for a fence: the lost reply may have hidden
it. For reasons 1–4 service persists Closing/FenceId/ControlReason before
sending; reason 5 persists the query ID/reason while retaining Open/Attached,
not Closing or GrowthClosed. Driver validates the
full retained original request; reasons 1–4 latch permanent Closing unless final
Attached already won, while reason 5 only queries success. Callback returns
Busy rather than waiting for tickets/rundown/service-dependent progress (section
8.3). Query/retry uses the same FenceId.

Reply payload is **128 bytes**:

| Offset | Type | Field |
|---|---|---|
| 0, 4 | two u32 | Result (1 FencedNeverAdoptable, 2 Attached, 3 Busy, 4 Unknown), Reserved=0 |
| 8, 24 | two GUIDs | FenceId echo, BootDomain |
| 40, 48 | two u64 | origin cookie, monotonic per-instance FenceSequence |
| 56, 64 | two u64 | allocation generation, current D (zero if unknown) |
| 72 | identity[24] | stage identity, zero if unknown |
| 96, 104, 112 | three u64 | active CREATE/adoption tickets, reply-delivery tickets, attach-completion tickets |
| 120 | byte[8] | zero |

FencedNeverAdoptable and final Attached carry a nonzero FenceSequence
(receipt sequence) and three zero **initial-adoption** counters; final Attached
also requires callback completion and exact known binding (section 5.4). A known K echoes exact committed K; unknown tuple fields are all zero
and do not claim no service commitment. The authenticated kernel callback produces this receipt; the agent may accept
it only from the exact native result correlated to its outstanding current
control RequestId/cookie, retained original request and FenceId. It cannot fill
receipt fields from a ledger, caller object, ordinary reply or echoed sequence.
Cross-process/duplicated-port handles still fail the original process/token/
service checks. Agent persists full header+payload plus the original request
and FenceId. Result 1 alone is non-adoption evidence; result 2 proves only
final-success initial resolution. Neither is deletion evidence. FenceReceipt
is the canonical 192-byte header+payload (256 Base64 characters); required-null
fields remain present and receipt reason/ID must match InitialResolution. Busy/Unknown supplies no cleanup authority. Attached requires the
ordinary attached lifecycle, never unattached cleanup. Sequence never wraps;
exact repeated fence returns the same receipt until resolution ACK.

Proposed bounded driver intent registry has one entry per unresolved allocation;
all original/duplicate CREATE continuations take tickets **before** dispatch,
and all reply/attach paths consult its irreversible gate. Lock order is existing
namespace → short intent state lock; no intent lock spans lower I/O or RPC.
Never take namespace from an intent lock. The entry survives waiter cancellation
and connection loss and cannot be evicted for age or capacity pressure.

| Possible adopter | Required fence integration / linearization |
|---|---|
| Queued CREATE or duplicate | ticket before enqueue; Closing cancels admission; late dequeue rechecks gate and deadline before preparation |
| Executing allocation/backing open | copied original intent/ticket remains owned outside namespace; recheck Closing/current cookie/deadline on return before binding/adopting |
| Reply in delivery or copied but not adopted | reply ticket covers send through adoption decision, including a transport timeout; Closing makes late success cleanup-only |
| Local FILE_OBJECT/share/FsContext binding | provisional adoption ticket covers `StageStream.c:2961` general binding, `:2937` temporary overwrite-resize binding and `:2969` FileObjects increment; Closing rolls back unpublished upper binding under existing ownership before ticket release |
| Attach PREPARE/COMPLETE may have escaped | track exact v20 attach state, including `AttachCompletionMayExist/Known/Fence`, terminal/retire and in-flight flags; obtain exact ABORT/retirement evidence and undo provisional binding, or report Attached/Busy |
| Final upper CREATE success | one gate transition commits Attached immediately before successful completion, with deadline/current connection rechecked. If Attached wins, no FencedNeverAdoptable; if Closing wins, no CREATE success. |

The final success transition cannot leave a scheduler gap in which the fence
reports non-adoption but a prepared success still completes. Receipt issuance
requires every locally admitted ticket retired, reply adoption excluded and
all attach-completion possibilities resolved. Until then the callback returns
Busy; it does not synchronously wait, under any lock or outside one, for
service-dependent completion. An unresolved attach permission is Busy even at zero
ordinary handles. `StageStream.c:2912` already distinguishes provisional binding
from completion; `:6815` retains original allocation recovery requests, and
`:6868` checks attach/handle/section state before legacy non-commitment.
Extend those paths; service serialization alone cannot establish this fence.
Every failure completion (including deadline expiry before a service fence
arrives) first closes the same driver adoption gate. A reply cannot win adoption
after that failed completion. Service Closing and driver Closing are separate
facts; both must be joined before cleanup authority exists.

Driver retains a fenced receipt/name reservation until ResolveAllocationAck
(opcode 6). Payload **1208 bytes** = original request[1192] + FenceId[16]. For abandoned allocation the agent
may send it only after persisting CleanupComplete with exact stage/companion/
pending-creation disposal and its durable closed-intent tombstone in hot/shared
history. For successful allocation it acknowledges InitialResolved under section
5.4 and performs no namespace release. Reply payload is `Result u32` (1 name released, 2 unresolved), zero u32.
Driver revalidates the same fenced shell and absence of all tickets, releases
only that exact name reservation/parent reference, then marks ACK idempotently.
It does not retry attachment or alter another name's generation barrier.
After ACK, any driver replay of this old intent still refuses: closed semantic
state is retained by the service, and no new CREATE can supply an old key through
the driver's fresh-intent issuance path. Transport retries query the tombstone.
Driver registry storage is unresolved-work storage, not durable per-transfer
kernel history. Lost ACK reply replays bookkeeping/name release only. If that
exact shell is already absent after ACK, return name-released with no mutation;
never remove another shell or create a receipt of storage absence. All tickets
were drained before eviction, the service retains the closed original intent,
and a fresh CREATE always issues a fresh reservation ID.

### 5.3 Cleanup authority and crash/reconnect table

Add reservation phase `AbandonedFenced=7` and closure kind `IntentFenced=3` to
schema 3. Unlike ClosedUnissued, it permits GrantMayHaveEscaped=true and requires
the accepted non-adoption fence. GrowthClosed=true; full debit until every
creation obligation/object/reader/copy is exactly resolved. MetadataOnly may
retain this closure proof. Do not weaken passive v2's ClosedUnissued invariant.
AbandonedFenced has no AcceptedRetirement; Binding may be null only while all
stage creation obligations remain explicitly unresolved or proved never-created.
MetadataOnly with IntentFenced retains the full original intent/fence and every
release witness, even if no stage was ever bound. No full-debit reduction before
that explicit all-obligations-resolved transition.

| Durable situation | Permitted action / charge |
|---|---|
| No native start, definitive stateless refusal | no persistent negative receipt; exact serialized non-creation plus driver non-adoption permits NoAllocationCommitted |
| Open with lost reply; object may be committed | replay same object to resolve custody, never size/reseed; retain name/debit until fence |
| Closing before driver fence | stop service creation/reply claims; keep debit/name; retry fence |
| Fence reply lost, driver Closing/Fenced | query same FenceId/full request; no new allocation; retain debit |
| Fenced persisted, native creation still settling | close/join service claim, capture exact result; no path absence inference while create may commit |
| Fenced + exact deletion/never-created proof, before CleanupComplete persistence | keep old debit; repeat proof/bookkeeping only; do not repeat a successful native mutation |
| CleanupComplete persisted before ACK | startup reconstructs closed tombstone, safe charge/class handoff; retry ACK to release exact name |
| ACK acted, reply lost | exact repeated ACK succeeds without another release/refund; fresh save uses a new intent |
| Service restart or new connection, same driver instance | resume Closing/FenceId with current control cookie, original request unchanged; reconstruct SID slots; no attachment revival |
| Driver unload/reload or reboot | new instance alone is **not** a receipt. Require verified old-instance rundown/boot-domain boundary plus exact service claim closure and native custody release. Without that adapter/evidence, hold. |
| Attached/ambiguous attach state | ordinary attached lifecycle/retirement; never infer unattached cleanup from failed transport or owner exit |

NoAllocationCommitted is sent only after service claims are fenced, exact
non-creation/cleanup is durable, and the driver non-adoption receipt excludes
every duplicate. Expiry alone never releases a possibly committed name. Automatic
name recovery must work without the original process exiting, including when
the driver never learned the object identity. Controls R3-A01–A04 separately
observe failed CREATE, exact eventual cleanup and a fresh successful same-name
save; a safe held allocation is not successful automatic recovery.

### 5.4 Successful intents, resource-only closure and ACK persistence (finding 4)

The bounded initial-intent registry has two terminal outcomes; active content
custody and initial-request debt are distinct. Successful saves do not keep
consuming one of 8/4 unresolved initial slots until content disposal.

**Successful path:** after final kernel success, the service sends opcode 5
reason **5 InitialResolutionQuery**, using the same 1224-byte layout with a fresh
nonempty query FenceId and complete original request. This reason neither
abandons a live CREATE nor closes growth. Result Attached is issued only when
the driver has observed final `ExposeClaimed`/successful callback completion,
resolved every provisional/retire path and retained the exact original request,
K/D and receipt sequence; otherwise Busy/Unknown. This adds a reason/result
meaning, not a byte-layout change. It must not use an agent-populated claim that
a positive allocation reply was adopted.

Persist `InitialResolution.State=InitialResolved`, full authenticated query
receipt and ResolutionRevision in one ledger transition, then decrement the
initial pending/SID/family count exactly once. The ledger stays charged for
content and can remain Writable. After that persistence opcode 6 with original
request + query FenceId acknowledges the **success receipt**: clear only the
initial registry/ticket debt, no content deletion, name mutation or growth close.
The kernel must retain the final-success receipt until ACK even if the writer
closes immediately. An exact ACK retry uses that receipt or the already-removed
shell no-op rule; it supplies no storage-release evidence. Successful handoff
retains InitialResolved, so no later ACK delta is needed to stop initial counts. **Eligibility is mandatory:** a successful transfer cannot prepare a closure
candidate, select a shared base or delete its ledger until InitialResolved is
durably committed there. MetadataOnly/terminal Entry alone is insufficient.
Immediate close/retirement may reduce content custody while the delayed success
query is pending, but the ledger and its metadata debit remain; retry the exact
query then InitialResolved before handoff. No success-resolution history delta
is introduced. CleanupComplete abandonment follows its separate ACK-delta path.
Native success→service query/commit, ACK loss and immediate writer-close races
are R3-A05.

**Abandoned without a manifest:** persist a **ResourceOnlyClosure** record
(section 10.2), with full original intent/SID/origin cookie, authenticated
FencedNeverAdoptable receipt, closed creation claims, exact released slot
incarnations and MetadataOnly state. Entry is explicitly null. Binding, allocation
generation, stage identity and destination generation remain null/absent if never
assigned; never invent K or an ordinary Discarded namespace event. A pre-manifest
created stage may retain its exact slot/release identity without a bound K.
This resource tombstone cannot enter journal namespace/generation indexes,
publication, delete or export paths. It participates only in closed-intent replay,
physical shared accounting and initial pending-count reconstruction. It allows
SID metadata retirement after exact creation/deletion resolution without
manufacturing a manifest or indefinitely retaining that envelope.

**ACK after ledger deletion:** base closure stays CleanupComplete (pending count
1) until the kernel's exact ResolveAllocationAck returns name-released for the
accepted outstanding original/FenceId. Persist a unique **InitialResolutionDelta**
record linked to that base (section 10.2) with ResolutionAcknowledged, exact ACK
request/result bytes, acceptance revision and previous record ID. Only after its
frontier is durable decrement the count. Replay selects the validated monotonic
chain, not duplicate changed TransferId frames. If native ACK acted but reply or
delta was lost, reissue the same ACK; it cannot repeat deletion or release another
name. ACK correlation from the authenticated native control is required even
when the kernel reports the already-absent shell no-op. The original accepted
non-adoption receipt remains the authority; the ACK is not a replacement for it.

| Durable state / crash | Initial count on restart / recovery |
|---|---|
| Positive allocation reply only, final adoption unknown | 1; query/fence exact original, no guessed success or cleanup |
| Kernel final success, immediate close/disposal, delayed query/InitialResolved missing | 1; keep exact ledger/metadata, handoff forbidden even if MetadataOnly; authenticated query → durable InitialResolved → handoff, including crash between each step |
| InitialResolved committed, memory decrement/ACK lost | 0; reconstruct once, retry success ACK only; content debit unchanged |
| Binding-null ResourceOnlyClosure committed, cleanup complete, no ACK delta | 1; shared tombstone replaces ledger authority and SID metadata; retry exact ACK |
| ACK native success, delta append outside committed frontier | 1 until section 10.3 resolves exact append/frontier; no duplicate frame or inferred ACK persistence |
| ResolutionAcknowledged delta durable, memory decrement lost | 0; latest validated projection reconstructs once |
| Changed FenceId/original/sequence or unauthenticated supplied record | no transition or decrement; hold the exact outstanding intent |

Stored receipts rely on the existing trusted-service/private-storage boundary;
they are not independently unforgeable certificates. No non-driver peer can
originate their acceptance through duplicated handles or an arbitrary serialized
record. ACK still validates the retained kernel shell/current authenticated
request. U1/U2 must prove old-instance and all adoption boundaries; until then
the proposed fence remains a contract, not a verified complete mechanism.

### 5.4.1 Separate initial debt and retained kernel-shell credit (residual 2)

Service debt is the durable 8/family and 4/SID unresolved-initial count. Exactly
one InitialResolved transition releases successful debt; a repeated query/receipt
cannot decrement it again. **Kernel registry occupancy is a separate credit:**
propose exactly **8 shell credits per live driver instance globally**, including
pending, fenced and retained-success entries across every connection/SID. Reserve
one before StageAttachReserveCapture/queue visibility, extra retained object
allocation or original-intent capture. A capture failure with proved no shell
releases that reservation locally; otherwise only actual kernel ACK eviction
(or proved complete old-instance rundown under U1) releases it. InitialResolved,
service memory adoption, ACK enqueue/send/timeout and disconnect do not release
kernel occupancy. The kernel owns its count; a service report cannot refund it.

| Event | Service initial debt / kernel occupied credit |
|---|---|
| Reserve/capture succeeds | increment debt when admitted; occupied +1 already reserved before capture |
| InitialResolved durable | debt -1 once; occupied unchanged, successful shell retained |
| Success ACK native result says evicted | occupied -1 once in kernel; debt stays 0; reply loss retries eviction bookkeeping only |
| Abandonment CleanupComplete/handoff | debt 1 until durable ResolutionAcknowledged; occupied remains until actual ACK eviction |
| Reconnect/service restart | rebuild debt from ledger/base/delta projection; occupied credits come from surviving kernel registry snapshot, never reconstructed as zero from debt=0 |
| All 8 occupied, service debt=0 | fresh modern CREATE gets correlated resource Busy before capture/heap retention, no new ledger/seed; diagnose retained receipt ACK backlog and retry recovery, not space exhaustion or global Unknown |

Add control-36 **opcode 7 ShellSnapshot**, authenticated like the other resource
controls; existing confirmed ABI sizes do not change. Empty request payload;
reply payload **9888 bytes** = header `{BootDomain GUID@0, SnapshotSequence
u64@16, Count u32@24, Reserved=0 u32@28}` + exactly 8 entries of **1232 bytes**:
original allocation request[1192]@0, State u32@1192 (1 pending,2 success-retained,
3 fenced), zero u32@1196, ReceiptId GUID@1200, ReceiptSequence u64@1216,
OriginCookie u64@1224. Unused entries zero; Count<=8. Pending may have zero
receipt fields; no tuple or identity is invented. Snapshot is copied under a
short registry lock and returned without waiting on service. It is occupancy
and recovery input, not final-success/non-adoption proof. Use opcode 5 for that
proof, opcode 6 for eviction. Reject changed original/driver/domain/correlation.

On reconnect new CREATE admission stays closed until a coherent snapshot is
joined to exact durable intents and old-origin cookies. Unknown unmatched slots
remain occupied/held; they cannot be silently erased. A queued pre-service intent
with no ledger needs exact serialized non-creation/fence resolution. A retained
success with debt 0 is prioritized for ACK from its exact InitialResolved ledger
or base. New instance/boot is U1, not an inferred empty old registry. The bounded
snapshot covers every occupied slot, including streams already closed.

ACK scheduling: one unique work item per occupied shell, **at most 8**, FIFO with
retained-success ACKs before new initial work; at most 2 native resolution sends
active, within section 8.3's class. No per-retry Tasks or duplicate queue items;
retry keeps original/FenceId and uses bounded existing monotonic backoff. Busy,
disconnect and cancelled sends retain both the item and shell credit until exact
native eviction is observed/reconciled. Snapshot reconciliation precedes fresh
admission after reconnect; it does not reset SID debt. Saturation may stall fresh
opens while ACKs recover, even with free storage; report that explicit cause.
The pure model tests durable count reconstruction and repeated crash-after-
InitialResolved-before-ACK cycles against this independent eight-slot limit.

### 5.5 Whole-CREATE audit required by U2

The adoption ticket must be reserved **before queue visibility**, including
capture reservations at `StageStream.c:3363`/`:3421`, and retained through
cancellation, provisional overwrite/general FILE_OBJECT binding (`:2937`,
`:2961`, `:2969`), every v20 PREPARE/ATTACH/COMPLETE/ABORT/terminal/retire exchange,
`ExposeClaimed` (`:4559`), and `StageAttachFinishCallback` / actual
`FltCompletePendedPreOperation` (`:4408`). Audit the single serial attach worker
(`:4634`) and pre-completion retire-unexposed (`:4606`): neither queue time nor
a failed service-dependent retirement may defer expiry of the original opener.

Carry original Issued/Deadline through **later lifecycle calls**, not just the
allocation exchange. At every wait compute remaining time; immediately before
ExposeClaimed and callback success revalidate deadline/cancel/teardown and the
same adoption gate. Expiry promptly closes adoption/completes caller failure;
unfinished cleanup/retirement must continue with separately owned bounded
storage rather than blocking callback completion past its interval. If current
serial-worker or cancellation ownership cannot provide that separation, U2
requires a concrete reviewed change before increment 5. Audit exposes/rollbacks
that already won, callback-key retirement before address reuse, producer pre-op
handoff and all ticket releases. Busy is required whenever final success or
retirement is ambiguous. R3-A01/A02/A05 must fault each of these exact boundaries;
changing only `Communication.c:1731` is not the 120 s protocol.

## 6. Allocation deadline, bounded pending work and saturation

### 6.1 Approved 120 s allocation interval

Driver stamps Issued at original issuance and Deadline=Issued+1,200,000,000
interrupt-time ticks before enqueue; checked addition refuses overflow.
`KeQueryInterruptTime` and service `QueryInterruptTime` use the same verified
BootDomain, biased 100 ns count (sleep consumes the interval). Validate
`Issued <= now < Deadline`; equality is expired. Carry unchanged bytes through
queue, held-source sizing, preparation, seed, persistence, reply and adoption.
Native wait durations are recomputed remaining time; no wall-clock subtraction,
fresh retry timer or independent 120 s after dequeue. A per-seed cancellation
can end earlier, never later. Current `StagedTransferAllocator.cs:229` starts
reconciliation/grace before its seed timer creation/arming at `:238`–`:239`; modern admission replaces
that path with immediate small-window admission and the carried deadline.
Legacy grace/seed behavior stays under legacy mode.

Every authority-changing boundary checks remaining time, particularly before
native create/seed work and the final upper CREATE success in section 5. On
expiry the opener fails with allocation-timeout diagnostics distinct from
space exhaustion; its destination stays protected. Background resolution may
continue charged after expiry. It cannot attach, reseed or renew the failed
CREATE. Same-connection retries keep the original pair; reconnect uses current
control authentication wrapping the original intent, **resolution only** for
an abandoned/closed initial request. Cross-boot historical bytes validate as
history, never as a new live deadline (`ResourceStateCodecV2.cs:284`).

### 6.2 Current dispatch shell and remaining modern bounds

Increment 2 landed in `272a33d1`; its current code is
`StagedRequestDispatcher.cs:5`–`:50`, `StagedRequestLane.cs:14`–`:60` and
`MinifilterRequestDispatch.cs:7`–`:31`. It preserves legacy v1/v20 FIFO through
Ordered and separates previously asynchronous continuations. It has **no growth
handler**. These facts replace the earlier speculative allocation/lifecycle/
ordinary reply-pump description; no reordering of legacy handlers is proposed.

| Population | Current code / proposed modern contract / saturation |
|---|---|
| Kernel initial shells | Proposed 8 globally per driver instance across reconnect/SIDs, reserved before CREATE capture; independent of durable debt, retained until actual native ACK eviction (section 5.4.1). |
| Initial modern intents | Proposed 8 unresolved per authenticated connection family across reconnect, 8 current-connection and 4/original SID across all cookies/restart. Queued/executing/fenced/unacknowledged abandonment counts; attached saves stop counting only on section 5.4's durable InitialResolved success transition. |
| Ordered | Current 1 worker + 32 queued; legacy allocation/discard/lifecycle/rename/reconcile/epoch-drain/Judge keep FIFO including their existing replies. |
| Allocation | Current 2 workers + 6 queued for existing bound allocation only. Modern initial allocation placement must preserve legacy ordering and independent growth progress; its admitted unique intents fit the above 8, not an additional queue. Bound-head resource admission stays NotReady. |
| Continuation | Current 8 workers + 32 queued for existing overlapping seal/public-open/native-lifecycle/private-cancellation work. They capture the preceding Ordered completion's driver identity. |
| Growth | Current passive 8 workers + 32 queued, independent worker/failure lane; proposed v32 consumer one semantic operation/K. Extra duplicates need a bounded reply credit or Busy, never unlimited Tasks. |
| Failure replies | Current 1 worker + 64 queued ordinary failures, separate 1 worker + 40 queued growth failures; credit reserved **before dequeue**, transferred to rejected work and released exactly once. Accepted handlers deliver their existing replies; this is not two pumps owning every success reply. |
| Kernel waiters/pins | Not bounded by service messages. Section 11.1 proposes 32 waiters/K, 256 global and 64 shared operations, admission before allocation/pinning. |
| Service-to-driver controls | Still serialized by FilterPort._sendGate today. Section 8.3 is a required new bounded progress path, not a result of increment 2. |

The current receiver reserves an ordinary reply credit before TryGetMessage
(`MinifilterInterceptor.cs:365`–`:366`), which can block growth before classification.
**Choose separate physical growth intake**, not a priority queue behind that
receiver. Proposed port `\SafeUploadResourcePort` admits one authenticated
resource client paired to the existing control/ordinary connection; its connect
context is `{DriverInstance GUID (16 bytes), main ConnectionCookie u64}`
(24 bytes, a new side-port context, no confirmed ABI size changes). Validate the
same original service process/token/service SID, live main cookie and instance;
never accept an independently authenticated replacement service as this group.
One driver-issued group cookie remains the u64 wire cookie on both ports. A
second FilterPort object owns the resource handle/lifetimes; provisional side
connection/root registration precedes main Commit Ready. Capability bit 4 now
requires this physical intake separation on both peers. Shipped v1/main port and
Ordered ordering remain unchanged; old peers never receive side-port traffic.

Only grow operation 23 uses resource FilterGetMessage and Growth workers/failure
credits (8+32, 40 failure credits). Retirement 24 and initial allocation/lifecycle
stay on main Ordered/Continuation as semantically assigned. The dedicated
resource receive loop reserves **growth** credit before dequeue and can never
consume or await one of the 64 ordinary credits. Ordinary backpressure cannot
prevent receiving growth. Within the resource class, a stalled reply can still
exhaust 40 credits: no further receive/work is retained, driver I/O deadline
expires and fails privately; it is not a promise of service from a stuck native
API. Reject wrong-channel operations without ordinary fallback; no allocation,
journal/publication or policy handler may run on the resource loop. Each receive
has its own owned OVERLAPPED/event as existing FilterPort.TryGetMessage requires.

Existing StagedRequestDispatcher queues/reply pools are retained, but modern
Dispatch must consume the matching pool selected by the physical channel; no
ordinary-credit reservation followed by transfer into Growth. Preserve main
FIFO and captured preceding driver for old handlers. Resource group revocation
is synchronous local state **before** stopping either receive: close admission,
wake growth waiters, stop producers, cancel both receives, cancel queued sends,
then drain native callbacks/send/reply/receive leases and finally close handles.
Disconnect of either port revokes the whole group; neither replacement port is
published until old ownership drains. A cancelled caller does not free native
storage still in use. U5 must prove the chosen two-port pairing/intake/native
lifetime mechanism on implemented source/real ports; models are not that proof.
Dispatcher GUID Cookie (`StagedRequestDispatcher.cs:58`) is still only local
scheduling identity, not the group u64 authenticated cookie.

Reconnect adopts old unresolved intent debt into its connection family before
fresh admission. Origin cookie and SID persist; new AgentInstance does not reset
them. Startup reconstructs counts from latest durable InitialResolution, including
resource-only tombstones and successful InitialResolved records (section 5.4).
Timeout/disconnect does not decrement; abandonment decrements only after durable
ResolutionAcknowledged, successful attachment after durable InitialResolved.
Migration with unassignable debt refuses modern readiness.

Saturation returns correlated RetryableBusy or the existing typed legacy failure;
no metadata/negative receipt, positive grant or inferred NoAllocationCommitted.
A possibly committed duplicate remains unresolved. Retries preserve both semantic
and per-I/O deadlines. Current `Revoke` stops growth before dependent lanes
(`StagedRequestDispatcher.cs:148`–`:184`); native waiters/control sends need their
own local ownership proof. Old workers cannot publish readiness on a replacement
connection. R3-Q01/R4-O02 include stalled native replies and pre-dequeue credit
exhaustion, not merely operation-queue saturation. Increment 2's component gate
is not native progress or protected-pair qualification.

## 7. Growth deadline: per application I/O, owner duration unselected

**Proposed composition: one growth-wait bound per application I/O**, measured
from that I/O's first observed capacity crossing through its final sufficient
capacity adoption/revalidation. Recommend **3 s = 30,000,000 interrupt-time
ticks**; this duration is not approved here. A long save can issue many I/Os and
therefore encounter several such pauses. This is not a bound on the whole save,
inspection or the later native data-write duration. No modern producer/consumer
until the owner selects the duration and the per-I/O interpretation.

Driver stores in each admitted waiter `IoIssued`, checked
`IoDeadline=IoIssued+SelectedGrowthTicks`, immutable across joins/retries/extent
recomputation. Semantic RPC stores its own immutable Issued/Deadline on the
existing wire: when creating a shared operation, stamp RPC Issued=now and
Deadline=min(creator.IoDeadline, now+SelectedGrowthTicks). The duration can be
shorter than the configured maximum; no ABI size changes. Joined waiters retain
their **own** IoDeadline and wait only until min(their deadline, current RPC
completion/closure). They never extend the RPC deadline or inherit a fresh I/O
interval. The creator leaving does not transfer authority to renew that RPC.

| Situation | Required deadline/extent action |
|---|---|
| B joins A's operation for a larger extent | B's deadline starts at B's first crossing, not when A finishes. If A's grant is insufficient, B may become a later operation's creator only with B's remaining time; zero remaining means permanent required-growth failure. |
| Shared operation completes, sufficient C available | Before adoption, resource reacquisition and final extent check, recheck each waiter's I/O deadline, live K/D, cancellation and sticky failure. A timely RPC alone does not authorize a late I/O. |
| Append/file pointer changes while resource released | Recompute actual extent under reacquired ownership; any additional sequence inherits that I/O's original deadline, never now+duration. |
| Busy/reordered reply/reconnect | Retransmit the same semantic fields/deadline only if both its RPC deadline and caller I/O deadline permit. Disconnection closes modern authority as specified; no renewed interval. |
| Any required waiter expires or saturation refuses required growth | Sticky SpaceFailed/nonpublishable for that version; close shared operation/adoption. Other waiters also fail, even if their own later deadline has time. All uncertain service debit remains charged. |

Ordinary resource reacquisition must use an owned, bounded acquisition strategy
(e.g. nonwaiting resource acquire and deadline-bounded retry outside forbidden
locks), not an indefinite acquire after a timely reply. The MM exception may
already hold the known upper resource; no unknown recursion release. Prove these
entry-specific waits in U6; if total growth wait cannot honor the I/O window,
stop for a reviewed design delta. A delayed scheduler/timer callback does not
renew authority: at the next execution after deadline it must fail before
mutation. This is a monotonic authority/wait contract, not hard real-time Windows
scheduling.

User effect: a crossing I/O pauses within this interval; expiry permanently
fails that save privately. A clean/empty prefix cannot publish; late capacity
cannot clear failure or reopen the version. Existing charged custody/disposal/
hand-back policy remains. Writes below C do not enter growth waiting. Diagnose
**growth timeout**, separately from exhausted storage and allocation timeout.
Preserve sticky failure at `StageStream.c:4780` and failure-only v31 semantics;
new diagnostic plumbing must not turn timeout into approval.

| Owner alternative | Per-I/O effect / trade-off (several pauses per long save possible) |
|---|---|
| 1 s | shorter crossing pause, more save failures under durable-storage contention |
| **3 s recommended** | short bounded crossing pause with room for normal durable metadata operations; requires measurements under joined/append/lane load |
| 10 s | more storage tolerance, longer visible pause for each affected I/O |

R4-D02 includes B needing 64 MiB joining A's 32 MiB RPC just after issuance,
A completing near its deadline, B requiring another sequence, and repeated append
recomputation. Assert B never gets two full intervals, nor extra time after
reacquisition, and no late successful prefix publication. No duration is selected
by model tests or this revision.

## 8. Metadata capability map and accounting I/O fence (increment 3)

### 8.1 Registration and object routing

Proposed `StageResourceMetadata` recognition runs at the **entry of
StageDispatchEpoch** (`StageStream.c:11296`), before slot/directory-sequence
capture, public-disposition classification, StageEpochOperation and
SafeUploadPolicyAdmissionAcquire (`:11333`, `:11348`). This is outside
StageDispatchCore: its SafeUploadBoundPublicationPre (`:10908`–`:10917`) and
owned-stream branch (`:10927`) are already too late. The caller at `:11425`
retains startup/mandatory-teardown CREATE gates; the capability hook does not
bypass an unloaded/uninitialized filter. Already-owned CLEANUP/CLOSE still drain
locally. Revoke hooks bind the authenticated connection at
`Communication.c:1980` and instance/unload rundown (`StageStream.c:8234`).
A SYSTEM-owned arbitrary path is insufficient.
Bootstrap outside `_gate` validates installed roots, fixed NTFS, full directory
IDs, trusted owner/protected DACL/no untrusted writers and no reparse ancestors.
Root anchors open with FILE_SHARE_READ|FILE_SHARE_WRITE, **without**
FILE_SHARE_DELETE, excluding native rename/delete while held. Share modes do
not exclude WRITE_DAC/WRITE_OWNER: protected security must deny untrusted
security mutation, trusted repair requires prior group revocation, and every
commit revalidates held security. No claim of excluding hostile local SYSTEM/
administrator beyond the selected trusted-storage boundary (O2).

RegisterRoot opcode 3 request payload **64 bytes**:
RootRole u32@0 (1 StageRoot, 2 Reservations, 3 JournalHot, 4 Completed),
Flags=0@4, user Handle u64@8, expected directory identity[24]@16,
ParentRootId u64@40 (0 for installed StageRoot/JournalHot),
SecurityContractVersion=1 u32@48, zero[12]@52. Validate handle in the registered
original process, object/token and installed root ancestry; reference original
FILE_OBJECT and instance, do not trust the integer after return. Reply **40
bytes**: Result u32@0 (1 registered, 2 refused), zero u32@4, RootId u64@8,
verified identity[24]@16 (all authority fields zero on refusal). IDs are
connection-local nonzero monotonic integers, never FILE_OBJECT addresses.

RegisterChildIntent opcode 4 request payload **640 bytes**:
RootId u64@0, TransactionId GUID@8, Role u32@24, AccessMask u32@28,
MaximumLogicalBytes u64@32, ExpectedIdentity[24]@40 (zero only for FILE_CREATE),
ReplaceTargetIdentity[24]@64 (zero unless replacement), LeafBytes u32@88,
CreateDisposition u32@92 (FILE_OPEN=1 or FILE_CREATE=2 only),
WCHAR Leaf[256]@96 (one component, <=510 bytes, terminator/unused zero),
zero[32]@608. Reply **16 bytes**: Result u32, zero u32, ChildIntentId u64.
Exactly one claimed relative open matches each child intent; recognize by
RelatedFileObject/root, exact leaf, original process/token and connection.
The intent is consumed by post-CREATE validation; it never authorizes another
same-name object. Existing replacement targets use FILE_SHARE_READ|WRITE|DELETE
so native replacement is possible, plus an exclusive **store namespace claim**
for the exact anchor/leaf/current identity across validation and rename. Every
registered writer respects that claim; untrusted writers lack native access.
A no-SHARE_DELETE target cannot be replaced and is not the chosen mechanism.
Native sharing alone cannot exclude another privileged DELETE or security
writer; that remains outside trusted private-storage authority, not a fictitious
OS exclusion. Recheck exact held target/security before the native step; any
conflict/changed identity revokes/holds rather than path overwrite.

Role numbers are fixed: 1 LedgerCurrent, 2 LedgerNew, 3 CompanionCurrent,
4 CompanionNew, 5 ManifestCurrent, 6 ManifestNew, 7 Segment, 8 InventoryCurrent,
9 InventoryNew, 10 MarkerCurrent, 11 MarkerNew, 12 LegacyNegative,
13 LegacySecurity, 14 EpochCurrent, 15 EpochNew, 16 HistoryCandidate,
17 AppendIntentCurrent, 18 AppendIntentNew, 19 CompactionIntentCurrent,
20 CompactionIntentNew. Result is 1 registered or
2 refused, with ChildIntentId zero on refusal. Current roles are read/query/
exact-delete only, except Segment's admitted offset writes; only New roles
receive bounded output/replace rights. Segment additionally receives bounded
offset-write/flush and **monotonic aligned EOF/allocation extension** under its
recorded append claim (section 10.3); no shrink, arbitrary EOF or rename. A new
compaction segment uses a separately created Segment intent, not replacement
permission on an existing Segment. MarkerCurrent never receives
automatic delete. LegacySecurity is query/read only. LegacyNegative delete
requires its serialized legacy non-commitment proof, not its role number.
Names are the exact pre-admitted ledger/transfer/transaction leaves; epoch is
`driver-epoch.state`, inventory `segments.state`, marker `resource-format.marker`; global intents `append.intent`/`compaction.intent` and candidate
`<RecordId:N>.resource` are typed exact names, never ordinary Entry lookup.
HistoryCandidate permits FILE_CREATE, bounded write/flush/EOF only until
its immutable candidate commit (<=128 KiB), then read/query/exact delete.
AppendIntentCurrent/New and CompactionIntentCurrent/New use <=64 KiB
current/read + new/replace semantics.
New roles use their respective recorded `.new` or GUID `.tmp` leaf, never a
wildcard name capability. Directory enumeration itself remains root-only.

Mutation handles require unimpersonated original process/token and synchronous
`FILE_NO_INTERMEDIATE_BUFFERING | FILE_SYNCHRONOUS_IO_NONALERT |
FILE_OPEN_REPARSE_POINT`. FILE_CREATE needs post result FILE_CREATED, regular
single-link/no-reparse, trusted protected security and captured identity before
any child capability becomes usable. Existing opens match exact identity before
data I/O. No ADS, separators, dot components, by-ID, TxF, target-directory,
links, mapping, MDL, fast-I/O, EA, arbitrary FSCTL, security mutation or absolute/
cross-anchor outgoing rename. A matched invalid capability operation fails in
this routing branch; it does not fall through to generic policy dispatch.

Desired access is an exact role subset: READ_CONTROL (0x20000), SYNCHRONIZE
(0x100000), FILE_READ_ATTRIBUTES (0x80), FILE_READ_DATA (0x1); add FILE_WRITE_DATA
(0x2) only to admitted new-output/segment-control roles, and DELETE (0x10000)
only to exact delete/replacement roles. No GENERIC_ALL, WRITE_DAC, WRITE_OWNER,
append-only authority or write-attributes/security mutation. Anchor access is
READ_CONTROL|SYNCHRONIZE|FILE_READ_ATTRIBUTES|FILE_LIST_DIRECTORY; no directory
creation/rename through a root capability. Data writes are offset+length bounded
by the admitted padded extent; EOF/allocation changes stay within that extent,
and final logical EOF within MaximumLogicalBytes. Query-directory responses are
bounded pages, never retained unbounded output under `_gate`.

Root and child entries reference connection/process/token/instance and have
short map-lock lookup pins; release the map lock before lower I/O or dereference.
Tag only original FILE_OBJECTs (Opening at pre-CREATE, Active only after validation), remove nonowning keys before CLOSE/address
reuse. Revoke denies new mutations/opens immediately; already claimed operations
settle conservatively with map rundown pins. Cleanup/CLOSE always progress;
disconnect/instance teardown/unload finish locally without service ACK. A stale
object pointer cannot match a new incarnation. Bound registration: four roots,
at most one child intent + **four** live metadata child objects per active metadata
worker; proposed **16 metadata transactions**, otherwise Busy before allocation.
Growth uses at most 8 of these; reserve 8 for non-growth work so neither exhausts
the other's progress. Four child handles replaces the earlier proposed two:
an excluded companion target can remain held while a ledger current/new pair
is durably committed, and archive candidate/segment/intent replacement needs
up to four. This is bounded map storage, not a cap on durable history.

| Capability state / interruption | State transition / recovery action | Control |
|---|---|---|
| Child intent registered, open not issued | PendingOpen=1; consumes one bounded transaction slot; revoke removes unclaimed intent locally | R3-M02 |
| Pre-CREATE claimed, lower create executing | Opening=2 with local rundown pin; revoke excludes subsequent mutation/exposure; settle native result against the durable creation claim | R3-M02 |
| Post-CREATE exact validation succeeds | Active=3; publish original FILE_OBJECT tag only after identity/type/security checks; invalid result closes capability and retains uncertain native custody | R3-M01 |
| Data/native replacement committed, service loses completion | capability is no durable receipt; recover from the ledger's pending exact identity/bytes, retain physical/debit charge; never repeat known-success replacement | R3-C03 |
| Active → disconnect/instance revoke | Revoked=4; deny new I/O, locally finish pinned operations and permit cleanup/CLOSE; no service ACK | R3-M02 |
| CLOSE/rundown | Removed=5; remove key before address reuse, then dereference outside map lock; next connection rebuilds map from trusted anchors, never serialized pointers | R3-M02 |

These states are proposed in-memory enum values, not persisted kernel history.
Driver/service crash reconstructs durable transactions conservatively, not the
old map; permission to finish accounting is not permission to reactivate an old
capability. Map/rundown locks never span lower I/O.

### 8.1.1 Outer pre/post ownership (finding 1)

Recognition uses only the connection-private root/child-intent map, original
FILE_OBJECT/RelatedFileObject, captured process/token and one relative component.
It does not call generic name normalization, policy/union classification,
publication/namespace/writer routing or epoch acquisition first. Untagged,
unmatched requests continue through StageDispatchEpoch unchanged. Matched-invalid
requests fail in the metadata branch; they never fall through.
Carry a metadata-handled discriminator back to SafeUploadStageDispatch
(`StageStream.c:11425`) so its final generic SafeUploadDenyNote path cannot
re-enter name/policy/namespace work on a metadata refusal. Emit only bounded
captured metadata failure telemetry there. Ordinary deny reporting is unchanged;
this is an internal pre-dispatch result/ownership field, not a wire ABI change.

Reserve one bounded nonpaged completion context before forwarding lower I/O.
It contains signature, operation, captured role/connection/root/object incarnation,
expected identities, map/rundown pins and completion-owner state; it owns no epoch
or ordinary inner context. Proposed system-address tag low bits **3**, 16-byte
aligned allocation, is distinct from existing epoch tags 1/2. Add its classifier
**first** in SafeUploadStagePostOperation (`StageStream.c:11538`), before generic
draining coverage-loss/writer callbacks and epoch-tag decoding. Only a validated
context owned by this branch reaches metadata post; an ordinary context cannot
be reclassified from pathname or status. Check actual tag availability at
integration (U4). Do not call StagePostOperationCore for metadata operations.

| Operation/result | Pre ownership / matching post disposition |
|---|---|
| Matched invalid request; allocation failure before forwarding | Complete refusal, no completion context; return every reserved credit/pin exactly once. |
| Relative CREATE | Opening map entry keyed to original target FILE_OBJECT before lower dispatch; forwarding owns the context. Request synchronized CREATE post for exact lower result/type/identity/security validation at supported IRQL; Active only after that validation. |
| Failed lower CREATE | Post removes Opening key/intent, records definitive failure or ambiguity to native caller, releases context/pins; no Active tag, epoch or generic CREATE post. |
| Successful CREATE, normal post | Validate captured expected tuple using lower-instance queries; publish Active tag or deny usable capability. Actual created object/identity remains a charged obligation until exact cleanup even if validation fails. |
| Metadata read/write/query/flush/EOF/replacement | One context owns native completion status/length and rundown; no epoch token. At normal post, settle only exact transaction incarnation, release ownership; native success is final. |
| POST_OPERATION_DRAINING | Do not use paged pre-input or perform lower I/O at DISPATCH. Never activate a child or assert mutation failure/success from an unavailable outcome; mark Opening/transaction Revoked/uncertain, retain durable charge. Release/defer only through a preallocated local rundown owner, no service or generic callback. |
| CLEANUP | Recognize tagged/Opening/Revoked object before epoch routing, permit only local native cleanup, release open-operation custody in matching metadata post; no writer or public-name side effects. |
| CLOSE | Remove object-map key before address reuse; use locally owned preallocated rundown storage for remaining pins, no new admission allocation. Release metadata-only context exactly once; never invoke generic native/public CLOSE hooks. |

If draining CREATE can leave a native handle, its Opening entry stays Revoked so
no subsequent bytes/mutations use an Active capability; cleanup/CLOSE are allowed.
The exact supported CREATE validation/cancel/close IRQL and local deferral owner
must be established in U4, not guessed. Failed CREATE, drain, cancellation and
post-context allocation failures must conserve pins/credits without an epoch.
R3-M01 explicitly closes epoch admission while an application-held epoch waits
for growth and forces ledger/companion/registration operations: metadata still
routes here, not union denial/BP/namespace callbacks. R3-M02 covers failed CREATE,
draining posts and CLEANUP/CLOSE with address reuse. First-boot review includes
both outer wrappers and context lifetime, not only the metadata module.

### 8.2 Exact operation-to-capability map

Allowed queries `Q` mean FileIdInformation, FileStandardInformation (EOF,
AllocationSize, links, delete-pending), FileAttributeTagInformation, and held
owner/DACL/security-descriptor query; volume queries are FileFsSizeInformation,
FileFsFullSizeInformation and FileFsSectorSizeInformation on verified anchors.
Validate returned lengths/units and cached immutable alignment. Destination
alignment/security/caller-grant evaluation occurs outside `_gate` through its
existing held destination authority; it gains **no** metadata bypass.

| Budget holder / code anchor | Root + exact role / permitted native operation | Transitive dependencies / disposition |
|---|---|---|
| Reserve (`StagedSpaceBudget.cs:197`), RecordStage (`:443`), Bind (`:523`), Persist (`:749`) | Reservations; LedgerCurrent/LedgerNew, each <=64 KiB. Q/read; new bounded padded write/flush/EOF/allocation; exact same-anchor replacement/delete. | StageRoot volume free space query through anchor; immutable stage/destination units passed from validated capture. No DriveInfo, absolute GetDiskFreeSpaceW or ACL repair under gate. |
| WriteGrant (`:776`), DeleteGrant (`:684`), PendingCompanion | StageRoot; CompanionCurrent/CompanionNew, 192 bytes modern or 64 legacy. Q/read, new write/flush/exact EOF, exact replacement/delete. | Full stage identity is captured outside gate; no stage content read/open/delete on capability. Ledger pending tuple provides exact target exclusion. |
| RequireMetadataAdmission (`:409`), journal.PrivateTemporaryAdmission (`StagedSpaceUpgrade.cs:18`) | JournalHot; ManifestCurrent/ManifestNew <=128 KiB; only pre-admitted exact IDs and bounded suffixes. Q/read, new write/flush/EOF/replace/delete. | Maintained per-transfer physical map, not directory scan; security query via Q. No journal callback/reentry under budget gate. |
| Global driver-epoch journal (`StagedTransferJournal.cs:180`, `:208`) through PrivateTemporaryAdmission | JournalHot; EpochCurrent/EpochNew <=4096 bytes, exact `driver-epoch.state` and recorded replacement. Q/read, new write/flush/EOF/exact relative replacement. | Existing global metadata quarter-envelope; no epoch-drain RPC or policy call in the budget callback. Epoch acceptance/drain semantics are unchanged. |
| RequireArchiveAdmission / RequireJournalGrowthAdmission (`:326`, `:340`), ArchiveGrowthAdmission (`StagedTerminalArchive.cs:136`) | Completed; Segment <=4 MiB including two aligned frontier slots (section 10.3); InventoryCurrent/InventoryNew 128 bytes modern (section 10). Q/read, bounded aligned offset write/flush and monotonic claimed EOF/allocation extension; no Segment rename/shrink. InventoryNew alone permits exact relative inventory replacement. | Include padding, control/frontier write, replacement overlap and failed residue in maintained shared physical total before write. No hot MetadataFiles rebuild. |
| Shared append/recovery (section 10.2) | JournalHot HistoryCandidate <=128 KiB; Completed AppendIntentCurrent/New and CompactionIntentCurrent/New <=64 KiB. Q/read; charged create/write/flush/EOF, exact intent replacement/delete and candidate immutability. | Global archive serialization outside budget; bounded physical admission under budget, no growth→archive dependency. |
| VerifyInventory / RefreshNegativeReceiptStorage (`:171`, `:275`) | StageRoot/Reservations; directory inventory + exact legacy negative metadata role <=1192 bytes; Q/read/delete after legacy proof | Full enumeration outside gate at startup/maintenance; steady-state bounded lookup only. Negative file count never a refusal quota; unknown content has no delete capability. |
| VerifyJournalInventory / RefreshArchiveStorage (`:305`, `:381`), MetadataFiles (`:368`) | JournalHot/Completed anchors; bounded directory-page enumeration and Q on exact metadata roles | Reconstruct outside admission at startup; maintenance claims stable frontier then applies deltas under gate. No whole directory walk under gate or admission. |
| RetireCompletedMetadata / DeleteReservationMetadata (`:662`, `:501`), shared marker/handoff | Reservations + JournalHot/Completed; exact ledger/marker/handoff and bounded completed proof roles | Durable shared debit/handoff precedes ledger delete; exact delete completion updates totals. No content absence or archive traversal under gate. |
| RetireFailedAllocation / RequireFailedAllocationAbsent / RetireUnissuedMetadata (`:455`, `:470`, `:492`), BeginSnapshot (`:546`), ReconcileAsync (`:590`) | Only ledger/companion parts use above roles | **Content** identity/query/create/delete/reader drain runs outside gate under persisted slot/incarnation/claim lease. Then reacquire same R/claim and commit. Paths cannot become capabilities. |
| ContentReservationPending / EndSnapshot / cursors/equality (`:400`, `:578`) | none, memory only | Never add native/journal/policy work. |

Legacy immutable `.security` inventory keeps its existing schema size limit
(`StagedJournalFile.cs:24`) and **read/query only** under shared accounting; no
new bound allocation or writable security capability. Legacy `segments.state`
is the exact Version/SegmentCount JSON at `StagedTerminalArchive.cs:28`, bounded
by the existing 4 MiB archive reader at `:249`; modern writes replace it with
section 10's bounded inventory before modern history handoff. Archive indexes
`_archived`, `_archivedClaims` and `_archivedEffectiveClaims` at `:21` are
reconstructed memory, not permission to invent writable index files. Audit
compaction/control writers for any additional actual roles beyond those explicitly specified (section 13); a generic
unlimited “journal file” role is forbidden.

Sector-pad each noncached write within precharged allocation, flush, set exact
logical EOF, **flush again**, and verify allocation (section 8.4); handle zero/tiny records and large allocation
units. Never silently fall back to cached or absolute I/O. Reuse the mechanics,
not the authority, of `StagedDestinationDirectory.cs:89` relative open and
`StagedHandbackCopier.cs:884` relative rename; hand-back no-replace stays intact.
Current `StagedJournalFile.cs:50`/`StagedJournalReplacement.cs:12` generic
overlapped/path helpers cannot run under the modern budget gate unchanged.

Native metadata transactions may hold `_gate` only across their bounded,
dependency-confined metadata operations and durable adoption. Journal → budget
order remains; growth never acquires journal/allocator/publisher/policy or waits
on content leases. Content claim → persist → unlock → native work → validate
same claim/incarnation/R → persist completion; conflicting creation/copy/reuse
is excluded while claimed. Unknown results retain charge. Maintained hot/shared
physical totals update for creation, padding, replacement overlap, failures,
delete, archive move and handoff; current maintained reservation totals at
`StagedSpaceBudget.cs:706` are necessary but insufficient. Reconstruction only
at startup/maintenance. A completed mutation with failed bookkeeping is resolved
from its exact receipt, never retried as a new mutation. Controls R3-M01–M03,
R5-H01 exercise the lock-order, confinement and history-cost hazards.

### 8.3 Service-to-driver control admission and send ownership (finding 2)

Current `FilterPort.cs:89`–`:123` counts accepted senders then serializes them
on `_sendGate`; `SetPolicy` at `:568` uses that lease. Kernel policy transition
closes/replaces the epoch (`Policy.c:1155`) then drains (`:1169`). The prohibited
cycle is SetPolicy/_sendGate → epoch drain → application growth → budget ledger
→ RegisterChildIntent → _sendGate. Independent **driver-to-service** lanes do
not remove this **service-to-driver** cycle.

Propose three normal send classes plus bootstrap/revoke slots within the
**same authenticated two-port connection group**, retaining
one common send-lifetime owner, with private per-call buffers and native handle
references. This is an intended FilterPort change, not current behavior:

| Class | Bounded admission / ownership / kernel callback rule |
|---|---|
| Legacy/policy (main port) | Existing single `_sendGate` stays for all old controls. Proposed modern wrapper admits 1 active + 8 queued; excess gets local Busy before retention. No metadata or resource-fence callback ever waits for this gate. |
| Metadata progress (resource port) | 8 active, **0 queued** native sends; TryAcquire before constructing/retaining a control. RegisterRoot/ChildIntent use a send-lifetime lease but **bypass `_sendGate`**. A full class returns local Busy; same original growth/I/O deadline applies. Separate reserved capacity cannot be consumed by SetPolicy or fencing. |
| Resource resolution (resource port; includes ShellSnapshot) | 2 active, 8 queued, separate from both above. FenceAllocation/ResolveAllocationAck use send-lifetime leases; queue cancellation removes the exact pending item. Callback returns a snapshot/Busy, never waits on application tickets, service replies, journal, namespace drain, epoch or another control. |

Complete assignment: Negotiate Probe/Commit uses main port, one active/no
queue bootstrap send; it may proceed only with initial admission closed and
no policy send active (TryAcquire legacy gate, otherwise Busy). RegisterRoot/
ChildIntent uses resource metadata class. Fence/ACK/ShellSnapshot uses resource
resolution class. Revoke has one dedicated resource send slot/no queue, but
**local** revoke is published first; failure/Busy never waits for a remote ACK.
All other existing controls stay legacy/main and cannot occupy metadata slots.
Before disposal, reject admission in all classes under group lifecycle state,
wake waiters/stop producers, cancel queued sends/receives, then join accepted
native leases without holding lifecycle or policy/map locks. No new negotiation
or port-handle publication while the old group drains. These are complete
class assignments, not permission to remove legacy send protection.

A metadata transaction does not retain the budget gate while waiting to enter a
control queue: metadata admission is nonwaiting. Once admitted, its synchronous
native callback may take only short connection/metadata-map locks; it never waits
for an epoch, policy-update lock, upper stream, namespace or service operation.
RegisterChildIntent fails Busy on bounded map/intent exhaustion, not a wait for
cleanup that requires that registration. On local Busy the accounting transaction
keeps its durable charge and releases owned serialization before a bounded retry.
No indefinite queue is hidden in a helper or synchronous Task.GetResult.

FenceAllocation is **snapshot-only after its short Closing latch**. QueryReason
5 (section 5.4) does not latch Closing; reasons 1–4 do. If tickets, ExposeClaimed,
attach retirement or any prerequisite needs external/service progress, return
Busy immediately after releasing the state lock. Independent local workers may
finish rundown, but the synchronous callback does not join them. ACK similarly
returns unresolved/Busy unless its retained shell is already locally releasable.
A fence must not acquire namespace blocking behind a growth waiter: use short
nonblocking claim/snapshot, return Busy when unavailable, and revalidate on the
next request. Service retry performs no cleanup until the exact authenticated
FencedNeverAdoptable result exists.

Refactor **lifetime**, not just gate selection: under `_sendLifecycle`, reject
new senders after disposal/revoke and count every admitted/queued sender in every
class. Each native invocation owns a safe-handle reference, exact connection,
input/output buffers and its class token until native return, even if its caller
cancels/times out. Cancellation can stop adoption; it cannot free a buffer or
close a handle still used by FilterSendMessage. Dispose closes admission,
cancels queued work, revokes authority, drains accepted native send leases then
closes the port; no `_sendLifecycle` monitor is held while waiting on gates or
native completion. Keep reply buffers/connection ownership through the native
reply return as well: `FilterPort.cs:294` calls FilterReplyMessage directly, so
its lifetime is owned by the surrounding dispatcher drain, not `_sendGate`.
Concurrent sends on this port and finite native teardown/cancellation must be
proved in U5; a timeout cannot be used as permission to dispose a running send.

Required edges: journal → budget → **nonwaiting** metadata-control admission →
short metadata-map lock; policy-control gate → policy update/epoch drain; resource
resolution class → short intent snapshot only. Forbidden reverse/dependent edges:
metadata-control → legacy gate/epoch/policy/namespace/service; fence-control →
service completion; map lock → lower I/O/dereference; growth → archive/journal.
Shared lifetime counting is not a serialization gate. Include both directions
in metadata and CREATE first-boot lock-order reviews.

R3-M04 saturates legacy sends with SetPolicy blocked in epoch drain while the
counted application waits for growth; RegisterChildIntent, ledger/companion I/O
and growth reply must progress. Independently fill metadata and fence classes,
queue fences whose tickets need service progress and require prompt Busy,
correlated refusals, bounded population and cancellation/dispose with no freed
send buffer. An unrelated typed Busy is not proof of no allocation commitment.

### 8.4 Settled native sequence and documented guarantee boundary

This is a selected sequence, replacing the unnamed future replacement barrier.
References are offline Microsoft API/documentation links; this task performs no
network retrieval. No quotations or power-loss guarantee beyond those API
contracts is asserted.

Use relative NtCreateFile/FILE_CREATE for a new output, with
FILE_NO_INTERMEDIATE_BUFFERING|FILE_WRITE_THROUGH|FILE_SYNCHRONOUS_IO_NONALERT|
FILE_OPEN_REPARSE_POINT; verify FILE_CREATED, identity/security/link/type through
that held handle. Sector-aligned buffers, offsets and lengths are required;
noncached I/O bypasses system data buffering, not every metadata cache.
[Microsoft file buffering](https://learn.microsoft.com/en-us/windows/win32/fileio/file-buffering)
and [CreateFile flags/sharing](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
separate NO_BUFFERING, WRITE_THROUGH and sharing semantics. WRITE_THROUGH requests
write-through behavior; it is not an application-wide atomic transaction or a
guarantee that arbitrary hardware honors cache flushes.

| Ordered step | Concrete primitive / acceptance rule |
|---|---|
| Create/claim | Relative NtCreateFile using registered anchor and exact one-component name; record may-start before call, captured identity before data. Root/target shares and exclusive store claim are section 8.1, not invented share exclusion of security updates. |
| Write padded bytes | NtWriteFile (synchronous, noncached/write-through) at aligned offsets, bounded by precharged physical extent; no cached fallback or reopening by path. |
| F1 | FlushFileBuffers on the same held output handle (native adapter NtFlushBuffersFile); require success before exact logical EOF. |
| EOF/allocation | NtSetInformationFile(FileEndOfFileInformation), and FileAllocationInformation only within precharged extent; requery actual EOF/allocation. |
| F2 after EOF | FlushFileBuffers on that same handle again, then verify complete expected bytes/identity/security/EOF. No durable candidate from a pre-EOF flush alone. |
| Replace | Under exact store namespace claim, NtSetInformationFile(FileRenameInformation) on held source, RootDirectory=held same anchor, exact target leaf, ReplaceIfExists only for prevalidated expected current object. No absolute MoveFileEx, target path reopen or cross-anchor rename. |
| F3 after replacement | FlushFileBuffers on the renamed source handle, then lower-query exact new current identity/bytes/EOF and held parent identity. On any failed/uncertain call keep predecessor/candidate/intent evidence and all conservative charge; native rename success is final, never issue it again. |

[Microsoft NtSetInformationFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile)
documents the information-class operation and native completion, and
[FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
documents flushing buffered file information. This sequence requests data and
file-metadata flushes and establishes tested **process-crash/native-completion**
ordering on supported local fixed NTFS. None of these links specifies an atomic,
application-level durable transaction across ledger, companion, directory entry
and another file, nor makes a failed/uncertain rename equivalent to no rename.
There is no undocumented directory-FSYNC or atomic-sector assumption here.

Where that stronger crash/power-loss guarantee is undocumented, **do not grant
it**: keep full charge until exact current/predecessor/candidate/receipt and
physical inventory reconstruct a unique conservative state; missing, rolled-
back, conflicting or torn evidence holds admission. F3 success alone never
releases content, certifies complete storage lifetime, or overrides marker/
identity/sequence checks. An implementation unable to retain enough predecessor/
transaction evidence for this conservative outcome must stop for a design delta;
it cannot invent a stronger rename barrier. Independent power-loss/target
qualification remains separate from these supported API requests and builder
fault injection. No volume-wide flush is inserted under the growth budget gate
(it could wait for the very application stream that needs growth).

Archive: create a new exact segment, aligned-write its two initial frontier
slots, F1, set aligned EOF=2*A, F2; then record exact segment identity. Each
append is aligned frame write → F1 → monotonic aligned EOF → F2 → inactive
frontier-slot write → F3, as section 10.3. New inventory/candidate/append-intent/
compaction-intent replacement uses the above F1/EOF/F2/rename/F3 sequence.
Uncertain F1/F2/F3 retains every affected physical object and full debit; startup
classifies the exact append location **before** any legacy tail truncation.
All metadata operations/query/flushes route through the capability branch;
no epoch, policy, namespace or service dependency is acquired there.

IRQL contract: registration and relative CREATE, identity/security/type validation,
read/write/EOF/flush/rename/disposition run PASSIVE. Forwarded CREATE requests
synchronized post and captures all inputs in nonpaged context. Draining post at
DISPATCH does no pageable validation/lower I/O: leave entry Revoked/uncertain,
queue its pre-reserved local PASSIVE rundown owner. CLEANUP/CLOSE can only retire
local keys/pins at their allowed callback IRQL, with final lower/dereference work
deferred through that owner; no new allocation or service ACK. U4 first-boot
review must establish actual callback registrations and cleanup/cancel paths.

### 8.5 Builder-native mechanism experiments (specification only)

These are component controls on an approved builder OS, **no proposed kernel
boot**, mechanism evidence only, not target 19045.2965 or power-loss qualification.
Implement later as native tests; none is implemented/run in this increment.

| Control | Exact experiment / PASS (otherwise FAIL or conservative hold) |
|---|---|
| N-U4-01 relative confinement | Held NTFS parent + NtCreateFile relative leaf, FILE_CREATE/no-follow; verify full IDs, one link, regular/protected security; traversal/ADS/reparse/wrong parent/wrong target substitutions refuse without altering substitute. |
| N-U4-02 aligned noncached | Sector/buffer/offset queries then selected flags; 64/128/192/1192/65536/131072-byte logical records, A=4096..65536 model, aligned native buffer. Verify exact bytes, zero padding and measured AllocationSize; deliberate wrong offset/length/buffer alignment must refuse, never cached fallback. Unsupported actual units are reported, not passed through synthetic fixture arithmetic. |
| N-U4-03 EOF and barriers | Instrument exact write,F1,EOF,F2,rename,F3 order; inject each failure/kill worker between steps, reopen exact handles after process exit, require only uniquely proven complete output be committed and all uncertain objects charged/held. F1 without post-EOF F2 must never produce Prepared. This is not physical power interruption. |
| N-U4-04 sharing/security | Root handle omits SHARE_DELETE: competing rename/delete must fail. Replace target uses SHARE_DELETE + exclusive store claim: second authorized store writer cannot enter, exact replacement succeeds. Show WRITE_DAC is not excluded by share flags; untrusted token denied by native security, trusted repair requires revoke. Wrong-owner/DACL/link/reparse never normalized. |
| N-U4-05 exact replacement | Relative FileRenameInformation on held original/new, target exclusion claim and F3; alternate target substitution/failure injection must hold, exact renamed identity survives no-reopen comparison; native success with lost bookkeeping never triggers a second rename. |
| N-U8-01 physical fit | Compare pure model rounded outputs, current/new overlap, candidate/intent/inventory/padding/frontier allocation to native AllocationSize at actual units; every measured allocation <= precharge, all failed residue remains counted. Higher/unusual actual allocation holds instead of weakening model. |
| N-U8-02 archive recovery | Unaligned logical payload ends, A-strides, dual slots, full append outside frontier and torn inactive frontier; no committed frame sector changes, classifier finishes exact frontier only, partial/unknown tail holds, no modern truncation. |
| N-U8-03 migration/selection | Mixed legacy contiguous and modern aligned segments; legacy never modern-appended, selected-prefix copy/suffix/target ranges remain consecutive, every base/ACK/witness reconstructs once; injected selection/copy/delete faults preserve old+new physical debt, no lost selected segment or duplicate changed base. |

Outer-hook cases R3-M01/M02 and real paired resource-port/epoch-drain progress R3-M04
require the increment-3 implementation and protected execution **after** its
first-boot review. They are coverage obligations before implementation, not
experiments that can already pass against an unimplemented metadata driver.

## 9. Custody, ordinary Discarded receipt and reduction

### 9.1 Wording and transaction (R5 precedence)

Call the driver message **stage-write retirement**, not all-object retirement.
Extend `StageStream.c:6278` drain and `:6419` drain/seal: exclude fresh writable
opens/sections/adoption; resolve queued/in-flight growth; prove zero handles and
upper FILE_OBJECT custody, cache/sections purged, paging rundown drained, flush
checked, writable backing closed and irreversible ReadOnly set. Measure exact
stage EOF/allocation (normalize if possible before receipt; failed normalization
reports actual allocation or keeps full debit). A mere CLEANUP, length query,
growth closure or queued seal is not proof. A read-only/deletion-pending object
can retain physical storage after write retirement (`StageStream.c:6310`).
Capture measurements and the immutable receipt tuple at successful drain,
before closing the writable backing, and retain the pending receipt across
notification failure. This also applies to never-sealed ordinary discard:
stage-write retirement is separate from an inspection seal and does not make
Discarded inspectable or publishable.

The **agent**, not the driver, proves snapshot/publication/hand-back custody:
reserve slot/incarnation/ReservedMax before native create; persist
CreationMayHaveStarted; capture exact identity; enforce copy ceiling; end every
mutation right and drain operations before immutable measurements. Closing one
reader is not final storage release. A fifth occupied slot refuses before create.
Keep ReservedMax on abandoned mutable copies; keep measured allocation on
immutable deletion-pending readers. Bind each completion to K/slot/incarnation/
claim revision. Original-stage release remains retained if its slot is reused
(`ResourceStateV2.cs:29`, `ResourceStateCodecV2.cs:153`).

Persist accepted stage receipt, current four-slot inventory, GrowthClosed and
derived debit **together**, before memory/totals adoption. Full charge is
`4*C + metadata`; after valid write retirement, use
`4*max(each charged slot extent) + metadata`, never EOF alone; pending/full-hold
keeps the full debit. MetadataOnly requires all slots released and no pending
creation/copy/replacement. Lost receipt retains full debit; duplicate accepted
receipt returns saved acceptance R with no second reduction; conflicting/stale
receipt grants nothing. Later exact object release is a new custody transition,
not another receipt-triggered refund. Crash before durable reduction keeps old
debit; crash after it reconstructs committed debit; ambiguous write faults
admission. Controls R5-S01–S03 cover all three boundaries and custody races.

### 9.2 Minimal ordinary Discarded disposal receipt

`StagedTransferJournal.cs:2463` records Discarded without disposal proof;
`StagedTransferJournal.cs:1922`–`:1929` rejects StageDeleted for that state. `StagedSpaceBudget.cs:624` requires
a durable release receipt, so a successful ordinary delete currently cannot
retire its four-copy reservation by that route. Do **not** set StageDeleted or
broaden its validator. Propose a distinct required-null-or-value field
`OrdinaryDiscardDisposal` in a versioned modern manifest envelope:

`{Version:1, WitnessId GUID, TransferId GUID, DriverInstance GUID,
AllocationGeneration i64, DestinationGeneration i64, StageIdentity,
StageSlot u32, StageIncarnation i64, ClaimRevision i64,
ReleaseKind (FinalStorageRelease=3 or ExactAbsenceAfterDrain=4),
FenceOrRetirementWitness GUID, AcceptedRevision i64}`.

ClaimRevision is the budget claim revision; AcceptedRevision is the positive
modern manifest RecordRevision committing this receipt. FenceOrRetirementWitness
names the accepted FenceId or local RetirementWitnessId, and validation loads
that exact retained proof. It is not a free-standing assertion by GUID.

It is valid only on exact never-sealed Discarded, no pending rename/copying
hand-back, matching current driver/generation/stage/slot/incarnation, with
growth/adoption permanently closed and the named retirement/fence evidence.
Witness contains no content verdict, digest authority or publication permit.
State Discarded is the writer's terminal namespace barrier even **before** this
receipt; proof only changes storage accounting. This does not cancel a prior
public delete or revive earlier versions.

Sequence: journal Discarded + close growth → persist cleanup claim → release
journal/budget locks → exact native disposal → prove all relevant handles/
sections/operations drained and storage released → persist receipt under journal
serialization → matching budget StageRelease/slot transition → metadata-only/
shared handoff when every slot is gone. Current helper
`StagedDiscardCleanup.cs:11` delegates exact identity deletion to
`StagedStageFile.cs:162`; its exclusive open at `:186` and path-absence result
at `:220` are useful mechanisms, **not yet the complete modern lifetime proof**.
No receipt from pathname absence alone, especially unknown legacy identity.

| Crash/result | Accounting / retry |
|---|---|
| Discarded before native delete | retain full content charge, retry exact cleanup |
| Native delete failed, pending reader, replacement at name | retain charge; never receipt/delete replacement |
| Native delete succeeded, receipt not persisted | retain charge; complete from exact drained claim + absence witness; if lifetime cannot be proved, hold |
| Receipt persisted, budget transition lost | reconstruct same release exactly once, no new delete |
| Stage gone but another snapshot/copy lives | release only stage slot; retain other slot maxima/physical charge |
| All slots resolved, receipt replay after shared handoff | no second refund; preserve generation barrier and witness |

Schema consequence: propose modern manifest `FormatVersion=2` envelope with
required RecordKind, RecordId, TransferId, PreviousRecordId (nullable),
required `Entry` (existing journal payload, nullable only for resource/delta
records below), `ResourceSchema=3`, InstallationId,
positive i64 RecordRevision (starts at 1, increments on each hot manifest transition; archive ACK deltas use the subsequent history revision),
required-null `OrdinaryDiscardDisposal`, and required-null `ResourceClosure`
(the complete strict schema-3 MetadataOnly record including replay, accepted
proofs, final slots and HistoryHandoff=null as an immutable snapshot). ResourceClosure is non-null on closure bases before shared
commit; InstallationId/TransferId must match ResourceClosure and, when present,
Entry and any disposal witness. Live modern hot manifests keep ResourceClosure
null until exact metadata-only closure; their Kind=1/Entry is still the journal
payload, never a resource-only namespace event.
Keep legacy manifest reader/writer unchanged for v1-only entries. An old reader seeing an envelope
must reject rather than deserialize a partial ordinary entry; marker blocks it
even after packing. Update exact equality/hash, hot/packed validation,
terminal-shape/epoch-drain/compaction and budget consumers, anchored at
`StagedTransferJournal.cs:166`, `:3638`, `:3733` and
`StagedTerminalArchive.cs:88`. No evidence can be discarded during pack. Legacy
Discarded without exact lifetime evidence stays charged; no retroactive boolean
or blanket migration based on an absent path. Controls R3-X01/X02 prove ordinary
discard storage retirement live/restart without weakening StageDeleted grammar.

## 10. Shared completed history and persistent downgrade marker

### 10.1 Marker bytes and installation order

Before first modern ledger/native creation, persist and verify a protected,
non-JSON **`.space-reservations/resource-format.marker`**, retaining it for the
installation lifetime. No automatic removal even when modern content count is
zero. This is the deliberate old-reader barrier, not a resource reservation or
permission to ignore old records. Current enabled startup rejects non-JSON
residue (`StagedSpaceBudget.cs:89`); accounting-disabled startup checks reservation
entries (`MinifilterInterceptor.cs:1705`). Both must keep refusing this marker.

Marker is exactly **128 bytes**: magic ASCII `SAFMT003`@0; u32 FormatVersion=3@8,
Size=128@12; InstallationId GUID@16; identities StageRoot@32,
Reservations@56, JournalHot@80 (24 bytes each); u64 RequiredFeatures=0xff@104;
zero[16]@112. Identity/security verified through held capabilities. Store the
same InstallationId and required format in every modern ledger, modern manifest
and shared control record. First modern creation is forbidden before marker
flush/exact EOF/identity validation completes. Partial marker or failed native
creation is preserved and refuses modern startup; never normalized in place.

### 10.2 Typed completed history and bounded append intent (finding 4)

Modern frames use a strict discriminated envelope, FormatVersion=2,
ResourceSchema=3, InstallationId, RecordKind u32, RecordId GUID, TransferId GUID,
positive RecordRevision i64, PreviousRecordId (required nullable GUID), Entry
(required nullable), ResourceClosure (required nullable), OrdinaryDiscardDisposal
(required nullable), ResolutionDelta (required nullable). No unknown/duplicate
fields. Max envelope remains **128 KiB**; resource-state snapshots remain <=64
KiB. All three record kinds use the same frame grammar in section 10.3.

| RecordKind | Required fields / selection semantics |
|---|---|
| 1 TransferClosure | Entry non-null exact modern terminal journal entry; ResourceClosure non-null MetadataOnly, with HistoryHandoff=null, complete intent, binding, replay/receipts and final release inventory; matching optional OrdinaryDiscardDisposal; ResolutionDelta=null. InitialResolution must be **InitialResolved=7 for successful allocations**, or **CleanupComplete=5 / ResolutionAcknowledged=6 for proved abandonment**; no Open/Attached/Closing/Fenced base even if MetadataOnly. RecordRevision equals the captured hot manifest revision (positive), PreviousRecordId=null. Retain both effective and allocation high-water generation barriers. |
| 2 ResourceOnlyClosure | Entry=null, OrdinaryDiscardDisposal=null, ResolutionDelta=null; ResourceClosure non-null MetadataOnly/IntentFenced/InitialResolution CleanupComplete=5 or already ResolutionAcknowledged=6, complete original request/SID and authenticated fence/releases. RecordRevision=1, PreviousRecordId=null. Binding can be null; no invented stage/generations or namespace claims/index entries. |
| 3 InitialResolutionDelta | Entry/ResourceClosure/OrdinaryDiscardDisposal=null; ResolutionDelta non-null as below. Unique RecordId, same TransferId, RecordRevision=previous+1 and PreviousRecordId=exact prior record. Legal only from a proved CleanupComplete base/projection; no authority to rewrite custody or namespace history. |

ResolutionDelta fields are exactly `{State:6 (ResolutionAcknowledged),
OriginalRequest (canonical 1592-char Base64), FenceId GUID, OriginCookie u64,
KernelAckControlRequest (canonical Base64 of 64+1208 bytes),
KernelAckControlReply (canonical Base64 of 64+8 bytes),
ResolutionRevision i64}`. All correlation/cookie/instance/opcode/length checks
apply, including outstanding-native-send acceptance; OriginalRequest/FenceId
must equal the base's accepted fence. Historical storage validation is static,
not a renewed live deadline. Projection retains the base in full and applies
only the acknowledgment state/revision; zero initial pending count follows.

Modern archive indexing distinguishes **RecordId** from TransferId. Duplicate
RecordId requires byte-identical record or is corruption; multiple closure bases
for a TransferId are corruption. A delta is the only permitted changed record
for that TransferId and must extend its exact chain by one revision. Gaps,
forks, changed-base witnesses, orphan deltas or incompatible hot/shared records
hold startup. Legacy version-1 frame duplicate rules stay unchanged. The current
archive rejects duplicate TransferIds and hot/packed inequality
(`StagedTerminalArchive.cs:315`); replace that logic only for typed modern records
with this chain selector. At most **one** acknowledgment delta is legal for
a CleanupComplete base: its ResolutionAcknowledged projection is terminal.
Retry returns the committed delta or resumes its one append intent with the same
RecordId; it cannot append another already-acknowledged revision. Hot and packed
duplicates compare the **same RecordId
and canonical bytes**; a later valid delta is not a changed duplicate base.
Compaction must retain a validated base+all needed deltas, never prune away ACK
state and restore initial pending debt. InitialResolved success already in a base
has count zero; no delta can turn it back into unresolved.

Before shared transfer ledger deletion, persist `HistoryHandoff` in ledger-v3:
`{TransactionId GUID, RecordId GUID, RecordKind u32, InstallationId GUID,
ExpectedLedgerRevision i64, Phase, CandidateIdentity (nullable full identity),
CandidateLeaf (bounded one component), CandidateBytes i64,
CandidateSha256 (64-char uppercase hex), SegmentNumber u32,
SegmentIdentity (nullable full identity), Alignment u32,
ExpectedFrontier i64, ExpectedFrontierSequence u64, FrameOffset i64,
FrameStride i64, TargetFrontier i64, TargetFrontierSequence u64,
SharedPhysicalBefore i64, ReservedPhysicalGrowth i64}`.
Prepared=1/SharedCommitted=2 retain their earlier proposed enum values; add
ReservedNotIssued=3, CreationMayHaveStarted=4, CandidateCaptured=5,
FrameDurable=6. No shipped persisted enum changes. Prepared and later require
both exact identities, complete immutable candidate, FrameOffset=ExpectedFrontier,
TargetFrontier=FrameOffset+FrameStride, TargetSequence=ExpectedSequence+1,
checked/aligned bounds and recorded physical charge. Preidentity phases cannot
assert candidate/segment completion. Do not hash a payload containing its own
hash/handoff: the closure snapshot has HistoryHandoff=null; its exact **separate
candidate** supplies immutable serialized envelope bytes.

Candidate is one `JournalHot/<RecordId:N>.resource` (<=128 KiB), created under a
charged metadata claim, captured, noncached-written/flush/EOF/flush, then made
immutable before Prepared. It is not an ordinary journal Entry; classifier uses
the exact recorded role/RecordId. It survives until its exact committed frame and
all bookkeeping are durable. A resource-only no-manifest candidate is legal.
Its creation/capture phases conserve storage even before identity is known;
unknown existing candidate is held, never adopted by pathname.

**One global serialized archive append intent**, `Completed/append.intent`
(strict schema Version=3, <=64 KiB JSON) holds the same transaction/record/
candidate/segment/location/frontier/physical fields, plus `ExpectedPreviousRecordId`
(nullable), `ExpectedRecordRevision` and `Phase`. It has one exact `.new`
replacement, no per-growth file history. Its purpose is recovery of **every**
append, including ResolutionAcknowledged after the transfer ledger is gone.
Journal/archive serialization owns this intent; growth never takes it. Persist
it before issuing append; any duplicated ledger HistoryHandoff must agree.
Missing/mismatched copies hold, not guess authority. No new append starts until
the prior intent is committed/cleared. This global intent and bounded candidate
storage fit the existing **shared** physical allowance, with pre-admission and
replacement overlap, rather than inventing a per-SID envelope extension.

Keep the confirmed **128-byte size** of modern `segments.state`: ASCII `SAFHIS03`@0,
u32 Version=3@8, Size=128@12, InstallationId GUID@16,
CompletedDirectoryIdentity[24]@32, u32 CommittedSegmentCount@56, zero u32@60,
u64 InventoryRevision@64, LastHandoffTransactionId GUID@72,
u32 FirstSelectedSegment@88, zero u32@92, CompactionTransactionId GUID@96,
u64 PreviousInventoryRevision@112, zero[8]@120. The earlier 40 reserved bytes
now encode a bounded consecutive **selected range** so compaction can retire
an old prefix without treating missing unselected segments as lost history;
this changes proposed inventory semantics, **not its size**. It is not a change
to any shipped/passive wire ABI.
InventoryRevision starts at 1 and checked-increments; LastHandoffTransactionId is
zero only before first modern handoff. FirstSelectedSegment is 1 on initial
nonempty inventory (0 only when count=0); selected numbers are every integer
in [FirstSelectedSegment, CommittedSegmentCount]. CompactionTransactionId is
zero until first selection change; PreviousInventoryRevision is the exact
predecessor revision (0 only at initial revision 1). Missing selected numbers
still hold; outside-range objects require exact append/compaction residue proof,
never blanket exclusion/deletion. Segment identities/frontiers come from exact append intents,
held validated segment handles and the committed inventory, not a content path.
Replace inventory only with section 8.4 barriers. Initialization/import must
classify legacy segments separately before selecting a modern append segment.

Admit shared candidate/segment/padding/control/intent growth first while the
per-SID envelope remains. Persist Prepared and append.intent, append exact frame,
commit durable frontier and required new-segment inventory, persist
SharedCommitted, then exact ledger deletion and in-memory transfer-debit removal.
Retain shared physical allowance at least the existing
`2 * rounded(hot + completed physical bytes) + 16 MiB`; include rounded physical
padding and **all** retained candidates/intents/replacements/failed residue.
No gap, overlap may conservatively charge both classes. After ledger deletion,
post-handoff ACK uses another globally journaled append intent and a **delta**,
never a replacement base. A native success is final; retry its frontier/index/
ledger bookkeeping, not another append of a completed record.

### 10.2.1 Pure physical-fit admission model (U8)

The executable independent model is
`agente/SafeUpload.Agent.Tests/GrowthArchiveFitModelTests.cs`; it performs no I/O
and consumes no unfinished production code. Model alignment A is 4096..65536
(power of two); metadata allocation unit U is verified independently and may be
larger (vectors include 512, 4096, 65536, 1048576). Round(x,U) is checked
AlignUp; metadata envelope remains max(1 MiB,16*U), journal half unchanged.
No claimed fit substitutes a smaller assumed allocation for actual native size.

**Complete-envelope rule:** E=canonical serialized Entry bytes, S=complete
ResourceClosure bytes, W=all remaining envelope bytes, including separators/
property names/escaped strings/other witnesses, not just fixed field values.
Require E<=128 KiB, S<=64 KiB, W<=8 KiB, **E+S+W<=128 KiB** before any candidate
create/handoff. W=8 KiB is a bounded serialization allowance, not free storage.
At S=64 KiB and W=8 KiB, E can be at most **56 KiB**. Independent maxima
E=128 KiB,S=64 KiB,W=8 KiB total **200 KiB**, so **do not fit**. Preserve exact
ledger/metadata/custody and diagnose handoff metadata too large; never truncate
Entry, omit a receipt or delete the ledger to pass. This is deferred metadata
retirement, not an added content/file-size cap or denial of already inspected
publication. A later format split for full independent maxima needs review;
this model explicitly rejects them instead of calling each component valid.
Exact production serialization/migration must be compared to these bounds
before its consumers; arithmetic alone is not a codec maximum proof.

Model simultaneous transfer overlap: journal current/new (each <=128 KiB) plus
one handoff candidate <=128 KiB consume at most 3*Round(128 KiB,U) of the journal
half. Ledger current/new <=64 KiB and companion current/new 192 bytes consume
2*Round(64 KiB,U)+2*Round(192,U) of the other half. Retained failed residue also
counts; if it no longer fits, refuse another metadata transaction, never forget
it. Shared controls are **additional accounted shared physical bytes**:
append-intent current/new, compaction-intent current/new (each <=64 KiB),
inventory and marker current/new (each 128 bytes), and retained candidate.
Compaction charge includes all old + up to 32 new physical 4 MiB segments,
both frontier slots in each segment, controls/replacements/residue. Selection
alone releases no old physical debt; exact storage release is also required.
Shared debit still uses 2*rounded total physical +16 MiB, no new budget formula.

Tests cover exact stride boundaries/maximum payload, zero-padding/dual slots,
checked overflow/invalid units, aligned-output replacement overlap, combined
maxima refusal/fit boundary, 32-segment source/target selection, old contiguous
format exclusion, delayed-query successful handoff and separate durable debt/
eight kernel credits. Deliberately wrong header/frontier/envelope parameters,
missing padding/second frontier and debt-as-occupancy mutants must fail model
acceptance. This closes only the **pure arithmetic/state-model** portion of U8,
not actual native allocation, power-loss durability or codec/selection correctness.

### 10.3 Aligned append grammar, frontier and durability (finding 3)

Choose **aligned independent frames with two frontier slots**, not read-modify-
write of a committed tail sector. This deliberately changes the earlier proposal's
modern frame version **2 → 3** and frontier version **1 → 3**; passive wire,
negotiation/control/companion/marker/inventory sizes remain unchanged. Legacy
contiguous `60+payload` frames/frontiers keep their old decoder only; never append
modern noncached data to a legacy segment. Current writer at
`StagedTerminalArchive.cs:140`, `:150`, `:397`, `:424`, `:448`, `:553` must change.

Let **A=max(4096, verified native I/O sector/buffer/offset alignment)**, power of
two <=64 KiB, determined from held volume/device requirements before use. Two
frontier slots occupy `[0,A)` and `[A,2*A)`; first frame offset is `2*A`. Segment
EOF and every frame start/end are multiples of A, maximum physical segment 4 MiB.
No new sector/cluster product default: A is a verified physical requirement.
A/identity are persisted in the append intent and both frontier slots; disagreement
holds. Legacy 4096-byte frontier area is not reused for this grammar.

Modern frame header remains **60 bytes**: magic u32@0 (existing ArchiveMagic),
Version=3 u32@4, PayloadLength u32@8 (1..128 KiB), **RecordId** GUID@12,
SHA256(payload)[32]@28. Payload begins at +60. **Stride=AlignUp(60+PayloadLength,A)**;
all bytes through stride end after payload are zero and validated. Next frame
starts exactly at previous+Stride. Issue each frame as one aligned buffer (or
aligned independent full-sector chunks) at its aligned offset, including zero
padding. A frame ending at logical `60+payload` is not the physical EOF.
No append ever rewrites a sector belonging to an earlier committed frame.

Each frontier slot is an A-byte aligned record: magic ASCII `SAFEND03`@0,
u32 Version=3@8, HeaderBytes=128@12, InstallationId GUID@16,
SegmentIdentity[24]@32, u32 A@56, SlotIndex@60 (0/1),
u64 Sequence@64, committed physical End@72, LastAppendTransactionId GUID@80,
SHA256(slot bytes [0,96))[32]@96, zero bytes [128,A). Initialize slot 0 with
sequence 1/end=2*A/transaction zero and slot 1 all zero, then flush/EOF/flush;
record exact created segment identity before any nonzero frame. Subsequent
commits write the **inactive** slot with sequence+1, new end and transaction ID,
then flush; never overwrite the last selected valid slot. Validate length,
identity/alignment, zero padding, hash and sequence. Do not assume atomic sector
writes, that a valid hash authenticates a content object, or that a torn newer
slot means its append did not happen. Recover via append.intent below.

Per append, after Prepared+intent are durable and expected frontier is rechecked:
(1) write frame at ExpectedFrontier without touching preceding sectors;
(2) **F1 flush** frame data; (3) set EOF to TargetFrontier (monotonic, aligned,
within claim); (4) **F2 flush after EOF**; re-read/verify identity/frame/physical
EOF; (5) write inactive frontier slot with recorded target sequence/end/ID;
(6) **F3 flush frontier**; commit any required new-segment inventory via its own
post-EOF/replacement barriers; only then report SharedCommitted and delete
candidate/intent/ledger by exact custody. FrameDurable denotes completed F2,
not merely a successful WriteFile return. Uncertain F1/F2/F3 keeps the intent,
all physical charge and admission hold. Native execution and the documented guarantee limits
are section 8.4/U4; no cached fallback or undocumented atomic-write assumption.

| Crash/read state (before legacy tail repair) | Exact permitted recovery / charge |
|---|---|
| Intent Prepared, old frontier valid, no target bytes | no issued/complete append proven; after closing its native append claim, issue the recorded frame once at the same offset, never allocate another RecordId |
| Full exact frame at recorded offset beyond old committed frontier; append result/FrameDurable update lost | validate candidate/segment/offset/stride/hash/zero padding and all bytes, reestablish F1/EOF/F2 durability, then finish **frontier only**; no second append or truncation |
| Partial/invalid recorded frame in uncommitted tail | close native writer claim; preserve first failed bytes as charged exact residue. Recover into a new exact segment/candidate transaction only after resolving old custody, or hold; do not rewrite/truncate potentially committed history to make it pass |
| Target frontier slot torn/invalid, prior slot valid | join the recorded append intent and exact target frame; repair only inactive slot after F2. Without matching intent, hold, never silently roll back to prior end |
| Target frontier valid, F3 completion or SharedCommitted lost | match sequence/end/transaction and candidate bytes; establish final flush, finish intent/index/ledger bookkeeping; never append again |
| Bytes after selected frontier, no matching append intent | hold/preserve, no automatic tail truncation or interpretation as another transfer |
| Both slots invalid, unexpected sequence/fork/identity or ambiguous native write | hold full accounting, no guessed frontier or frame adoption |
| New segment frame/frontier durable, inventory count update lost | exact global intent identifies segment number/identity and expected inventory; finish inventory only; no duplicate segment append |
| Committed ACK delta but pending count not updated | validated base→delta projection gives zero debt exactly once |

Run this classifier **before** current `StagedTerminalArchive.cs:467` tail
truncation; that legacy repair is prohibited on modern segments. A complete
append outside the frontier is known native work to finish, not disposable
scratch. Any unknown/partial case stays charged, with exact residue retained.

**Bounded compaction transaction:** under the same archive serialization, with
no unresolved append.intent, select at most **32 consecutive source segments
from the current selected prefix**. Preserve all canonical base/delta witnesses
needed for exact replay, counts and generation barriers; this protocol does not
authorize semantic pruning. Copy/pack into at most 32 newly created aligned
segments numbered after the old range end, using the same A/stride/dual-frontier
F1/F2/F3 grammar. Coalesce byte-identical duplicate RecordIds only; changed
records/forks hold. A delta may physically precede its copied base: validate the
full RecordId/revision chain after collecting the selected records, not arrival
order. Native handles are processed in bounded groups, not 32 opens at once.

Persist one <=64 KiB `Completed/compaction.intent` and one `.new` replacement,
strict `{Version:3, TransactionId, InstallationId, ExpectedInventoryIdentity,
ExpectedInventoryBytes (canonical Base64 of 128 bytes), Phase,
Sources[1..32]{Number,Identity,FrontierSequence,End},
Targets[1..32]{Number,CreationPhase,Identity (nullable until captured),
FrontierSequence,End}, NewFirstSelected, NewRangeEnd,
ReservedPhysicalGrowth}`. All numeric ranges/counters checked; source prefix
starts at old FirstSelectedSegment and ends before NewFirstSelected; target
numbers start at old end+1, no gaps. CreationPhase uses reserve/may-start/captured/
committed identity rules. Phase is Prepared=1, Copied=2, Selected=3,
CleanupComplete=4. Source identity/frontier and expected inventory must still
match before issuing copy. Persist preidentity creation claims before native
create; unknown target identity holds. No append runs concurrently.

Charge old + targets + both frontier slots + compaction intent/replacement and
inventory replacement/failed residue **before** creation, inside existing shared
formula. Persist Copied only after all exact target frames/EOF/frontiers are
durable; then atomically replace/durably commit inventory setting
FirstSelectedSegment=first old segment after copied prefix (or first target if
the entire old range was copied), end=last target, exact transaction ID and
previous revision. The remaining old selected suffix plus targets is consecutive;
all old-prefix records survive in targets. Only after exact new inventory is
selected/durable persist Selected and exact-delete the recorded source prefix,
releasing measured physical totals only on storage-release proof. No in-place
sector rewrite or live Segment rename/shrink permission is needed. Persist
CleanupComplete before exact intent removal. Decoder rejects any attempt to skip
unrecorded missing selected segments or select away a needed base/ACK barrier.

| Compaction crash | Recovery before archive admission |
|---|---|
| Target creation/copy before selection | old inventory remains authority; recognize only exact intent targets as charged residue. Resume exact unperformed work; completed copy/frontier is bookkeeping only. Unknown identity/partial native outcome holds, never delete source. |
| New inventory native success/durability completion uncertain | inspect held exact current/replacement identities and recorded expected/new bytes. If selection ambiguous, hold both classes; never repeat a known-success replacement or delete source. |
| New selection durable before Selected persistence | match exact selected range/transaction/previous revision and target frontiers; finish bookkeeping then source cleanup only. |
| Some sources deleted, cleanup record lost | selected range excludes precisely that prefix; retry exact **absence/bookkeeping** for proved deleted identities, never path-delete unknown replacement. Shared measured totals reconstruct without forgetting residue. |

This is the format/transaction choice for compaction; U8 still requires executable
migration/selection/maximum-size conservation models before increment 4, and U4
requires implemented/native confirmation within section 8.4's guarantee boundary. It does not authorize removing old
evidence, pruning live epoch/replay barriers or deferring required checks to
increment 7.

### 10.4 Startup, marker and handoff crash obligations

| Crash point | Startup action / count and debit |
|---|---|
| Marker before first ledger | validate marker and recognized residue; no v1 fallback |
| Candidate created before identity captured | native creation claim unresolved; preserve unknown object and debit; no pathname adoption |
| ResourceOnlyClosure complete with no Entry/K | select resource-only typed base, retain exact fence/release proof, no namespace index insertion |
| Ledger deleted, ACK not yet durable | base retains CleanupComplete; initial pending count=1, shared physical debit; retry authenticated ACK then delta |
| Append before frontier (base or ACK delta) | section 10.3 exact intent/location classifier before any tail repair |
| SharedCommitted before ledger delete/memory update | exact ledger deletion only; shared projection reconstructs receipt/replay/debit |
| Immediate-close successful transfer, query delayed beyond disposal, crash before InitialResolved | successful handoff/candidate/ledger deletion forbidden; retain ledger/metadata and count 1, complete authenticated query then durable InitialResolved; only then base with count 0 |
| Last modern ledger retired, records packed | marker remains; enabled old/disabled startup refuses modern/shared residue |
| Marker corrupted/removed while modern/shared evidence survives | hold, actionable identity/format diagnostic, no recreate/downgrade normalization |
| Marker and every local witness erased/rolled back | no detection guarantee from these stores; O2 asks for the precise external trust boundary and repair/uninstall contract |

Startup classifies marker, typed hot candidates/global append intent, legacy and
modern archive formats and resolution chains **before** blanket constructor
checks. Accounting-disabled startup refuses any modern evidence even without a
transfer ledger. A missing marker never relabels modern history as legacy.
`StagedSpaceBudget.cs:662` and `StagedSpaceUpgrade.cs:12` are existing selected
shared-accounting mechanisms, not these new typed/tail/delta contracts. R4-H01
must test binding-null bases, normal-success count retirement, ACK after ledger
deletion, append outside frontier, interrupted F2/F3, torn alternate slot and
unaligned logical frame lengths. R4-H02/H03 retain downgrade/marker tests.

## 11. Kernel growth/MM feasibility and stop condition

Extend the current immutable `SpaceCapacity` (`StageStream.c:123`) at write/
resize/allocation (`:4780`, `:4841`–`:4863`, `:5990`, `:6009`), paging
bridge (`:5833`) and drain (`:6278`). **Owned** streams route through
`:10927` to StagePreOperation: fast I/O rejects at `:5903`, paging at
`:5931`–`:5942`, nonpaging IRP writes at `:5948`. The `:11044` MDL fallback
is **unowned** and proves no owned-stream growth/MDL coverage. Copy K/D/C/extent/deadline into bounded
nonpaged heap work, with separate waiter/worker references. Pin the **upper
FILE_OBJECT**, callback ownership and stream through reply adoption; a backing
reference alone does not pin FileObjects-based release. Do not use stack-backed
`STAGE_RESIZE_WORK` at `StageStream.c:4755` for asynchronous RPC, existing
namespace-taking RpcReferences release, or the shared stage worker.

Worker writes result and signals its event **before** dropping its upper-file
pin; waiter waits on result, not worker exit/pin cleanup (final CLOSE can need
namespace). Timeout/cancel/disconnect/mandatory teardown drain local ownership
exactly once without service acknowledgment. Any late result sees the permanent
failure/closure fence; extra agent capacity remains charged until exact release.

| Supported crossing | Preconditions before any exposure/mutation / recheck |
|---|---|
| Ordinary cached/noncached write; append/file pointer | PASSIVE growth work; drop only owned resources, never unknown recursion. Reserve required aligned max(write end, EOF/allocation exposure); reacquire/revalidate K/D/current C, cancellation/read-only/seal/rename and recompute append/file-pointer extent. Retry computation within original operation deadline; no guessed extent. |
| Explicit EOF/VDL/allocation, including preallocation | reserve actual allocation as well as logical extent before FltSetInformation/Cc size exposure; validate checked arithmetic and revalidate after waits. VDL cannot expose unmaterialized/uninspected bytes. |
| Cached/section creation/extension, mapped writable access | reserve before cache/section EOF exposure so later paging fits; assert actual IRQL/top-level/resource ownership at each entry. An MM-recursive waiter may retain only the known upper stream resource under the audited metadata dependency fence. It cannot release an unknown recursion count or transfer upper cache flush to another thread. |
| Owned-stream MDL preparation/completion | Trace StagePreOperation (`:5903`/`:5948`), actual IRP minor values and callback/MDL/upper-file ownership, rather than the unowned `:11044` fallback. Reserve before returning writable range. Completion/release never waits for growth/closure; U6 must establish exact owned preparation and completion behavior before implementation. |
| Paging/AdvanceOnly/flush | no growth RPC. Extent must fit pre-reserved capacity; retain paging rundown and failure completion behavior, never skip/approve over-capacity bytes. |

No namespace, paging resource, writer registry lock or spin resource spans a
growth wait. No budget → journal/content dependency. Existing recursive resize
comment `StageStream.c:4747` records NTFS top-level lock-conflict/section retry
livelock; `:4783`–`:4788` keeps upper flush on its caller. This does not establish that
the proposed growth worker is feasible on every supported entry. Do not invent
IRQL, recursion ownership or callback cancellation behavior from that example.

**Stop for a reviewed design delta before implementation/activation** if any
supported cached/noncached/mapped/MDL/EOF/allocation path cannot reserve before
exposure, wait with only the permitted known upper resource, release pins locally
without a service/namespace cycle, or return a finite failure without section
retry livelock. Keep the original mapped-file assertions and support scope;
do not silently narrow them or move growth to paging. Controls R4-MM01/MM02
must cover C02-style section extension, timeout/disconnect/teardown and retirement
at each pin/adoption boundary with Verifier and independent bytes.

### 11.1 Kernel shared operation, waiter and pin bounds (finding 6)

Propose **32 admitted growth waiters per K, 256 globally, 64 shared growth
operation objects globally**, one operation/K. These are kernel retained-work
bounds for independent review, not per-file capacity or budget defaults. Service
8+32 messages do not bound waiting application callbacks.

A shared `STAGE_GROWTH_OPERATION` holds copied K/D, semantic sequence/extent/
Issued/Deadline, immutable connection identity, bounded result/event, waiter list,
worker/adoption state, refcount and exactly one independent upper-FILE_OBJECT
pin. It contains no caller stack pointer. A `STAGE_GROWTH_WAITER` holds callback
ownership, one upper-file pin, original IoIssued/IoDeadline, operation ref, required
extent and atomic terminal state (Waiting/Granted/Failed/Cancelled/TimedOut).
No variable-length buffers; fixed structures use copied bounded protocol data.
Growth-owned upper pins are at most **256+64=320**, callback references at most
256; stream/connection refs are at most the corresponding object populations.
Original incoming callback ownership is distinct from a new retained growth ref.

One short global growth-admission spin lock protects counters, per-stream shared
operation pointer/incarnation and list membership; it is never held across
allocation, wait, dereference, service call or resource acquisition. Reserve a
per-K/global waiter credit and, if needed, operation credit **before allocating
heap work, taking additional callback references or pinning upper files**.
Release lock, allocate fixed storage, then reacquire/revalidate same stream/
connection/incarnation before publication. Reserved-but-unpublished credits count
against limits. Competing creator that finds another operation joins it and
returns its unused operation credit; stale/cancelled/closed attachment returns
all reservations and destroys its unpublished allocations outside the lock.
No unbounded waiter group is allocated first and counted later.

| Event | Ownership / saturation completion |
|---|---|
| Per-K/global/operation credits exhausted, or heap allocation fails | no new retained callback/pin/work; fail required crossing with typed resource status and set version nonpublishable. Complete via its original callback owner, without waiting for a slot. No successful prefix. |
| Join one operation | one admitted waiter ref and node; own IoDeadline unchanged. No duplicate service request or extra worker pin per waiter. Higher extent does not mutate current semantic request. |
| Operation result | worker stores immutable result/signals before dropping independent upper pin; each waiter separately claims terminal transition and revalidates its I/O deadline/current extent before mutation. |
| Waiter cancellation/timeout | atomic terminal winner unlinks exactly once, releases callback/upper pin/operation ref and its credit exactly once outside lock. Late worker cannot touch freed waiter storage. If it wins required-growth failure, close version/adoption and wake remaining waiters. |
| Closure/disconnect/mandatory teardown | mark shared operation closed locally; terminalize/wake all admitted waiters without service ACK. Worker storage/ref survives late service completion; no waiter depends on worker pin cleanup. |
| Last waiter leaves with worker still active | operation worker ref and its credit/pin remain until local cancellation/native ownership ends; do not free from list emptiness alone. No new operation for closed K. |
| Later sufficient sequence for a surviving higher-extent waiter | transfer its node/ref to the next bounded operation only with original IoDeadline; cannot retain two operation credits/pins per waiter by retrying. |

The worker never retains a raw waiter-node pointer: it writes/signals only the
shared operation. Waiters independently observe the shared result plus their
locally owned cancellation/deadline; cancellation registrations are disarmed/
joined before node free, with their own temporary node ref if invoked. List
traversal/closure is under admission lock; pin/credit release is outside it.
Only one **unresolved semantic** operation/K exists. A signalled predecessor can
remain allocated with its worker release ref while a successor starts; that
retiring object still counts toward the global 64. No waiter waits for its pin
cleanup or bypasses the global limit; exhaustion fails closed. Transferring to a
successor drops the old waiter ref and keeps only one growth-owned waiter pin.

Every path has a single terminal owner per waiter and a separate worker terminal
owner for operation credit/pin; delayed result after cancellation changes neither.
Retirement sees all reserved/published/worker adoption owners, not just service
messages. U6 must prove that each owned callback can safely retain/complete at
its actual IRQL/minor function; do not use a generic callback ref as proof that
an MDL completion may be pended. If native completion cannot be owned this way,
stop for a design delta rather than allocating uncounted work.

R4-MM03 drives many threads (well above 32) against one K and many Ks beyond 256/
64 while one service operation stalls. Assert exact admitted node/callback/pin
counts, prompt saturation completion, no extra Task/work objects, cancel/close/
late-reply exactly-once release and no UAF in Verifier. R4-MM01 logs owned-stream
routing, actual Major/Minor and completion owner for every cached/noncached/
MDL/EOF/allocation/section actor; unowned native success is not a passing owned
MDL control. R4-MM02 covers local pin/rundown races at all admission states.

### 11.2 User buffers and MDLs are separate custody (residual 3)

Current `StageReadWrite` locks a caller buffer at `StageStream.c:4824`, maps its
MDL at `:4832`, waits on Resource at `:4835`, and only then computes effective
append/file-pointer extent (`:4841`) and crosses capacity (`:4863`). FILE_OBJECT
pin counts do not bound those page locks. Moving only the later growth test is
insufficient.

Proposed **owned-I/O admission** applies to each new owned nonpaging READ/WRITE
data/preparation operation, after handle checks at :5944 and before the
StageReadWrite call at :5948, **before FltLockUserBuffer, MDL mapping, resource
waiting or growth heap/pins**. Use the same proposed 32/K and 256-global credits
as growth waiters: an I/O already holding one converts that credit into a growth
waiter; it never takes another. Below-C operations hold it through completion
then release. Reads need this too because they can lock pages before waiting
behind an MM growth owner. Paging and completion/release minors do not enter **new** admission or initiate
growth: they find their original counted callback/MDL owner and release that
credit. They cannot be rejected or queued behind a full admission pool; U6
must map the exact owned minor/completion route. Saturated write admission completes resource
failure without buffer lock and marks its save nonpublishable; a rejected read
has no mutation authority. Do not queue rejected callbacks awaiting a credit.

| Buffer/MDL origin | Custody while waiting / completion |
|---|---|
| No MDL, caller user buffer | acquire owned-I/O credit first. Prefer compute/grow before locking pages when safe, but original callback input cannot be touched asynchronously without proved ownership. Any later FltLockUserBuffer occurs under the credit; recheck extent after resource reacquisition. |
| FltLockUserBuffer-created MDL | retain only the MDL attached to that owned original callback, within its one credit and captured length. Filter Manager owns its completion-time free/unlock; do not manually MmUnlockPages/IoFreeMdl it. Complete/release callback ownership once so normal Filter Manager cleanup runs. |
| Incoming caller/I/O-manager/upper-driver MDL | borrowed, not a newly allocated filter MDL; retain only through the proved original IRP/callback lifetime, never free/unlock or repurpose it. Rejection completes promptly via original owner. No claim to bound already locked arrivals before filter admission. |
| Paging bridge partial MDLs | existing StageClonePagingMdls/:5774 and child completion own their exact clone chain under PagingRundown; independent from owned nonpaging buffer credits, no growth wait from paging. |
| Owned MDL preparation/complete minors or mapped/system buffer | U6 must name the actual Major/Minor callback owner, valid buffer lifetime and legal completion/IRQL; no raw mapped address or borrowed MDL survives that owner. Release/completion cannot wait for a growth credit. |

[Microsoft FltLockUserBuffer](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltlockuserbuffer)
is the ownership reference for the Filter Manager-created MDL; never infer its
ownership from a non-null incoming MdlAddress. Native minor/completion ownership
still requires the U6 source audit and routed evidence.

Cancellation/admission failure before lock releases only reserved credits; after
lock, the single terminal callback owner completes/cancels and relinquishes its
reference, allowing the MDL's actual owner to unlock/free. Worker touches only
copied growth inputs, never the user buffer or MDL. A late RPC cannot use freed
buffer memory. Cancel registrations are joined before credit/node free.

These are **count/ownership** bounds, not a claim that 256 callbacks imply small
locked memory. Model/account each retained page span as
AlignUp((virtual page offset)+Length,PAGE_SIZE), with Length checked against its
actual MDL chain/system buffer and ULONG carrier limit; count MDL headers/PFN
arrays/cancel owners separately from 320 upper-file references. U6 must supply
actual structures, supported length extrema and worst-case retained bytes and
saturation measurements before increment 6. No new buffer-size product default
or narrowed MDL support is selected here. Admission is not complete until the
pre-lock owned path and borrowed/created MDL completion audit are implemented.
R4-MM03 now includes many ordinary writers blocked before effective extent,
pre-existing/created MDLs, cancel-before/after-lock and exact credit/page custody.

## 12. Dependency-ordered implementation and control inventory

### 12.1 Seven increments (all T9, no completed checkboxes)

| Order | Coherent implementation / dependencies / exit observable |
|---|---|
| T9 increment 1 | Review this addendum; extend passive C/C# ABI, strict schema-3 codec and pure transition/replay/fence models (sections 2–6, 8–10). No negotiation/admission. Linux ABI/mutation/conservation/crash controls; changed C gets paired WDK/static/import gates; agent gets full four-leg delivery matrix. Growth duration owner decision before its dependent producer. |
| T9 increment 2 | Landed `272a33d1`: StagedRequestDispatcher/StagedRequestLane/MinifilterRequestDispatch preserve Ordered legacy FIFO and bound existing workers/failure replies. No growth handler. Native pre-dequeue credit/control/reply progress is **open U5**, prerequisite to increment 3, not closed by this component delivery. |
| T9 increment 3 | After 1; integrate metadata kernel capability module and agent anchored store, noncached native operations and maintained hot/shared totals; use 2 for dispatch. Sections 8/10 roles complete, no generic budget I/O. Confinement/native controls and pre-boot lifetime/lock-order/security review; growable admission closed. |
| T9 increment 4 | After 1–3; integrate custody/reduction, stage-write retirement producer, modern startup/shared history/marker and ordinary Discarded receipt, all release adapters (sections 3/9/10). R5/R4-H/R3-X controls prove reserve-before-create and exact reduction/release. Still no growable admission. |
| T9 increment 5 | After 1–4; modern initial allocation and 120 s issuance-to-adoption/fence/recovery (sections 5/6), exact replay no reseed/double debit; lost identity/reply self-heals same name. R3-A/R4-D01; pre-boot CREATE/adoption review. Small-window production remains gated pending 6. |
| T9 increment 6 | After 1–5 and approved growth duration; end-to-end ledger→companion→reply/adoption, semantic replay and **every MM path** (sections 3/4/7/11). R3-G/C, R4-D02/MM; coherent growth/MM security/lifetime/lock-order review before first boot. |
| T9 increment 7 | After 1–6; audit modern cap replacement/computed readiness; decouple minimum window from legacy seed-cap symbol (`StagedTransferAllocator.cs:17`, `StagedSpaceBudget.cs:34`). Preserve STAGE_LEGACY_CAPACITY and bound-head gates. Complete harnesses, regressions, matched-pair qualification and final independent adversarial milestone review. Cutover separate. |

Ordinary implementation stays with the primary agent. Independent design review
and changed-kernel lifetime/lock-order/security review precede first boot. Every
agent delivery checkpoint needs full feature Debug/Release × user/SYSTEM
discovery/execution (no skips); every changed kernel needs both WDK builds,
PREfast/ApiValidator zero warnings/errors and both imports PASS, plus required
Verifier. Harness changes need PowerShell **5.1** parse/native signatures,
self-checks and an authorized real run. Committed source/fresh labels/matched
artifact hashes are delivery obligations for the orchestrator; this document-only
increment performs none of them. No new source-freeze/disposition framework.

### 12.1.1 Three separate review/delivery stages

Contract acceptance, implemented first-boot review and runtime evidence are
separate. The re-review closed the original F1/F2/F3/F5/F7 **design defects**;
its residual 1–3 and this revision need independent acceptance. Do not require
R3-M01/M04 protected execution before increment 3 is written. The table lists
coverage now; results follow implemented source and first-boot review.

| Integration | Contract/fact required before implementation | Implemented source required before its first boot | Runtime/component evidence after implementation |
|---|---|---|---|
| T9 increment 3 | U4 selected role/exclusion/IRQL and F1/EOF/F2/rename/F3 sequence with documented guarantee limits; U5 paired growth intake/send classes/lifetimes; U8 pure fit vectors; independently accepted outer pre/post and send-progress text. This revision supplies proposals/model; acceptance remains open. | Both dispatch wrappers and tag-3 classification before existing tags/draining; failed/draining CREATE, CLEANUP/CLOSE/address reuse; connection/instance/unload rundown; authenticated two-port handlers and every actual role/query/import; complete journal→budget→registration→native graph; conservative physical faults. Sol security/lifetime/lock-order review of coherent source. | Builder N-U4-01..05/N-U8-01..03 are mechanism evidence on builder OS; R3-M01 epoch closed, M02 ownership/reuse, M03 dependencies and M04 real port/send progress run on implemented protected pair after review. WDK/static/import and complete agent matrix stay required. |
| T9 increment 4 | Residual 1 successful-handoff eligibility; U3 every-role release owner/crash contract, U7 owner scope, strict U8 grammar/migration/candidate/tail/ACK/selection models and actual serializer limits. | Retirement/capture/paging+growth rundown, receipt/inventory/debit transition, release/custody and teardown, any added metadata permissions reviewed before boot. | R3-X/R4-H/R5-S native/protected crashes, delayed query/immediate close, base/delta state reconstruction and exact physical release. |
| T9 increment 5 | Residual 2 separate eight shell credits; U1 boot/old-instance and U2 complete CREATE/cancellation audit; authenticated receipts, bounded snapshot/ACK eviction scheduling, deadline through later lifecycle calls, fence-specific U5 Busy. | Capture-to-callback/exposure ownership, success/non-adoption evidence, eviction credits and reconnect, deadline/failure vs separately owned cleanup; coherent lifetime/lock-order review. | R3-A01..05/R4-D01, repeated durable-success-before-ACK interruption, pending-vs-shell saturation, exact same-name recovery and no failed-CREATE adoption. |
| T9 increment 6 | Residual 3 pre-buffer-lock owned-I/O credits/MDL ownership; U6 real Major/Minor/IRQL/resource/completion inventory and actual byte/structure maxima; measured 32/256/64 bounds and owner-selected O1. | Full growth/replay/companion/MM/MDL/paging/pin/retirement integration, including user buffers and cancellation ownership, reviewed before boot. | R4-D02/MM01..03 routed actor evidence, many writers before FltLockUserBuffer/resource acquire, borrowed/created MDL release, deadline/teardown/retirement races and Verifier. |

No row is a claim of runtime PASS or permission to boot. Modern admission stays
closed through the integration prerequisites until the complete readiness
conjunction and matched-pair qualification pass. Compaction design is not
approval to expand M2 beyond the required 10k workload or owner deferrals.

### 12.2 Carried qualification rows

All existing T9L and T9R assertions remain. The table maps coverage; Linux models
do not satisfy Windows-native or protected-pair cells. Each VM row requires
ordinary/runtime-Verifier/boot-Verifier, independent destination bytes and
separate restoration through the existing authorized lab workflow.

| Existing rows | Concrete contract coverage retained |
|---|---|
| T9L01–L05 | complete clean/EOF-CPF large files, seeded grants/read authority, old cap crossings; modern initial+growth, exact public bytes |
| T9L06–L09 | failed prefix, all resize/section paths, same/different SID, exact aligned budget/floor boundaries; geometric fallback and no overspend |
| T9L10–L11 | physical failures and crashes at every create/identity/manifest/grant/copy/native-publication point; add sections 3–5 crash points without removing existing ones |
| T9L12–L14 | parser kill/drain/hostile memory/format/extraction bounds remain separate T9 completion requirements |
| T9L15–L17 | retained reader/copy storage, seed failure, corrupt/unsafe accounting; exact release and metadata capabilities |
| T9L18 | mixed versions/downgrade/disabled startup, extended after shared handoff and marker damage |
| T9L19–L21 | owner diagnostics, concurrent ordinary Word/temp saves, completed/discarded metadata and restart history; no intentional modern grace |
| T9R01–R03 | historical failed allocation/refusal recovery and malformed isolation; no receipt-count veto or identity guessing |
| T9R04 | exact cleanup ACK, effective and allocation high-water barriers retained through shared packing/restart |
| T9R05–R06 | owner-only resource/timeout diagnostics and notification recovery; no global Unknown or cleared sticky failure |

Carry budget-on T5 CREATE/sharing/abort/replay/rename/delete/blocked-notification
rows; T4 immediate owner/child read/read-write, 256-cycle smoke, 10k/resource/raw
byte/lost-reply obligations; affected T7/T8/T10/T11 and final matched-pair gates.
T9L15's intermediate metadata retention is observed **before** shared handoff;
completed exact disposal later sheds the SID envelope while shared physical debt
remains (R3.3(a)). T9L20 must prove the approved concurrent no-overspend behavior,
not accept the historical whole-SID concurrency limitation as completion. F3/F4
publication-window failures remain distinct from F5. No test weakening follows.

### 12.3 Added R3–R5 rows (proposed control identifiers)

`L` = Linux-local pure model/codec; `N` = Windows-native mechanism controls;
`V` = protected VM in all three modes. Cells specify obligations, not existing
harness availability or permission to run them in this documents-only task.

| Row | L | N | V / required proof |
|---|---|---|---|
| R3-N01 negotiation | every byte/length/bit/opcode/kind mutation, no ordinary fallback | native C/C# offsets, exact port buffers | prerequisite missing/partial caps never Ready or small immutable grant |
| R3-N02 compatibility | full matrix/model | old/new v20/v31 frames | old/new peers, live modern disconnect/capability loss, bound-head still NotReady |
| R3-C01 companion | exact bytes/K/C/G/own identity | no-follow/link/security/size/substitution | once-only modern read; no missing-companion legacy fallback |
| R3-C02 initial companion | preidentity/native-start crash model | create/pad/flush/EOF failure | missing/current/replacement/residue classification, no unknown adoption |
| R3-C03 replacement | every section-3 crash state, interruption twice | exact replacement vs bookkeeping, large units | lost reply/repair/restart, monotonic charge/capacity, no repeated rename |
| R3-C04 corruption | unknown/ahead/torn schema cases | locked/changed exact handles | hold no shrink/deletion/fallback, preserve bytes and diagnostics |
| R3-G01 replay | HighWater/latest compaction/duplicate/stale/changed semantics | persisted store crash/restart | no double debit, changed reuse never capacity, many exact-fit growth operations |
| R3-G02 accounting | same/different SID, geometric fallback/overflow/closure | durable totals agree with native inventory | insufficient space sticks; capacity committed before closure stays charged |
| R3-A01 lost initial reply | ticket/fence/attach linearization interleavings | exact original bytes and result correlation | drop before/after bind/reply/adopt/attach ACK; failed opener, automatic fresh same-name success |
| R3-A02 abandoned commit | service claim closing/native-start/crash model | partial seed/object exact cleanup | expire in queue/seed/persist/delivery; no prefix, reseed or failed-CREATE attach |
| R3-A03 fence/ACK | duplicated/reordered fence and lost resolution ACK | changed intent/FenceId/identity refusal | no name release while any adopter/attach possibility remains; exactly-once cleanup/release |
| R3-A04 reconnect | durable SID/family debt, origin/new cookie | service restart vs driver/boot proof adapter | churn cannot evade bounds; restart alone no receipt; identity-unknown reply loss recovers |
| R3-Q01 bounds | current Ordered/Allocation/Continuation/Growth lanes and reply credits; bounded duplicates | exhaust ordinary pre-dequeue credits, stall accepted/rejected native replies, reconnect | prove the chosen bounded modern intake strategy permits resource progress; no unconditional claim from separate failure queues alone; local revoke before drains |
| R3-M01 confinement | outer pre/post role/size/access/leaf/context mutations | relative noncached/pad/EOF/post-EOF flush/security/unit checks | **epoch admission closed** while counted I/O waits for growth; ledger/companion and registration progress without BP/union/namespace recursion, roots policy-covered |
| R3-M02 lifetime | metadata tag-3/pre/post context and incarnation/revoke conservation | failed lower CREATE, draining at permitted IRQL, CLEANUP/CLOSE; token/anchor/substitution/link/ADS faults | map key retired before FILE_OBJECT address reuse, generic epoch/BP post never sees metadata context; disconnect/unload, no UAF |
| R3-M03 lock order | transitive callback/claim completion failures | content leases outside gate | saturated growth + namespace/publication/reduction stress, no budget→journal cycle |
| R3-M04 control progress | model legacy/progress/fence/bootstrap/revoke slots, paired channels and exact send leases | main 64 failure credits stalled while separate growth 40 credits/intake works; SetPolicy drain, metadata registration, fence Busy, cancel/dispose | wrong process/token/group/side-port rejects; loss of either revokes both before drains, no new handle publication before native leases end; epoch-closed growth accounting progresses |
| R3-A05 initial success/tombstone | no Entry/K closure, InitialResolved and linked ACK delta count reconstruction | final-success query/ACK origin, cross-request/FenceId/duplicated-handle refusal | delayed final-success query plus immediate close/disposal/crash must keep ledger until InitialResolved; then ledger deletion before ACK, ACK reply/delta loss and restart: no fabricated Entry, duplicate TransferId base or 8/4 debt leak |
| R3-X01 ordinary discard | strict new receipt, old StageDeleted still rejected | exact delete with reader/section/replacement | ordinary discard refunds after proof, snapshot remains charged, fresh name use |
| R3-X02 discard crash | section-9 crash table, duplicate/reuse | receipt persist fault after exact native success | live/restart/hot/packed no lost barrier or duplicate release |
| R4-O01 ordering | forced allocation/growth/close/rename reordering | connection revalidation | journal failure after growth closure, late success cannot reopen |
| R4-O02 drain | lane-full revoke/cancel dependency model | bounded reply teardown | epoch drain queued in every lane, service-independent local pin release |
| R4-D01 allocation deadline | exact 120 s pair, equality/overflow/retry through every lifecycle wait | interrupt-time clock/resume; serial attach worker, pre-completion retirement, ExposeClaimed/callback ownership | capture-before-queue, all attach/retire/ABORT exchanges and final callback expiry; prompt failed opener with cleanup separately owned; timeout vs space UI |
| R4-D02 growth deadline | distinct original I/O/RPC immutable deadlines, joined higher extent and repeated append recomputation | blocked reacquisition and late timer/reply; no second full interval | 32→64 MiB join near deadline and append race: original per-I/O bound, late sufficient grant cannot publish prefix; several I/Os may each pause |
| R4-MM01 crossings | extent/revalidation/append and owned Major/Minor models | trace owned StagePreOperation :5903/:5948, actual MDL minors and completion owner; unowned fallback insufficient | every supported owned crossing above/below C, C02, no paging RPC/livelock; route evidence required per case |
| R4-MM02 pins | waiter/worker timeout/signal/release ownership | allocation/cancel fault seams | timeout/disconnect/teardown/retire at every adoption/pin boundary under Verifier |
| R4-H01 handoff | typed no-Entry/K bases, ACK chain, successful-count and exact append-location crash models | arbitrary unaligned logical payload lengths; A-strides, F1/F2/F3, torn alternate frontier, append before frontier, candidate/intent/ledger delete | classifier before :467 tail repair; no successful base before durable InitialResolved (delayed-query/immediate-close crash); no second append, duplicate changed base, ACK rollback/debt leak or missing physical padding/overlap charge |
| R4-MM03 many waiters | one K >32 and global >256 waiters/>64 operations; owned-I/O credits before :4824 buffer lock/:4835 resource wait, exact terminal owners | instrument user page spans, borrowed/FilterMgr-created MDLs, waiter/operation/upper/callback credits, allocation/cancel/late result | many ordinary writes queued behind upper MM resource; completion minors release existing credit without new admission; no upper-pin-only or service-lane bound substituted for page custody |
| R4-H02 downgrade | enabled/disabled/mixed schema matrix | old binaries see marker/envelope | old/disabled startup refuses after shared handoff/packing |
| R4-H03 marker | corrupt/missing/wrong installation model | exact security/identity and partial-write checks | removal with surviving modern evidence holds, no marker recreation/fallback |
| R5-S01 inventory | zero-allocation mutable copy, four slots/fifth refusal | reserve-before-create; preallocation/zero EOF/normalization failures | snapshot/hand-back race reduction, charged physical allocation independent of EOF |
| R5-S02 storage release | stale completion/incarnation reuse, uncertain drain | multiple readers, deletion-pending section/operations | final-close adapter proven, no slot reuse/refund from one reader closing |
| R5-S03 receipt | full tuple/measurement/revision conflict + three crash points | immutable proof persisted before totals | lost/duplicate/stale receipts, lower adopted C after lost growth, no double reduction |
| R5-H01 history cost | maintained hot/shared delta conservation | reconstruction includes padding/failed residue | growing retained history incl 10k; record queue/metadata callback/end-to-end time and reconstructed physical totals, unchanged resource gates |

## 13. Unresolved before implementation

These are missing implementation facts, not licenses to infer Windows behavior.
Resolve the applicable item before its dependent increment; if it changes a
contract above, obtain a reviewed design delta. No new VM/build access is
authorized by listing a control.

| Item | Selected contract / exact remaining fact / dependent integration |
|---|---|
| U1 BootDomain / old instance | Still open before 5: choose/verify OS boot identity and exclusion of old adopters; existing BootId use at StageStream.c:4369 is not the whole proof. No restart/GUID inference. |
| U2 CREATE / shell ownership | Before 5: section 5.5 whole source audit, prompt final expiry vs separately owned cleanup, authenticated success/fence acceptance and exact eight retained-shell credits/snapshot/ACK eviction. Pure debt/shell model exists; current code clears old receipts (:4461/:4629) and does not implement this registry. |
| U3 Release adapters | Before 4: identify each slot's actual final handle/section/operation owner and each crash/unknown release witness; retained mutable maximum and driver retirement remain separate. Builder handle/section tests may supply mechanism evidence, not stage rundown proof. |
| U4 Metadata/native sequence | Contract selected in 8.1/8.4: root no-SHARE_DELETE, replace-target SHARE_DELETE plus trusted exclusive store claim, no invented share exclusion of WRITE_DAC; PASSIVE native work/local draining owner; exact F1/EOF/F2/relative rename/F3 and conservative undocumented-guarantee outcome. Before 3 **accept text and resolve any unsupported primitive/import**, with listed controls designed. Implemented wrappers/IRQL/cancel/deferral/native exclusions must then pass coherent first-boot review; N-U4 controls and protected R3-M controls follow implementation. No unnamed future persistence barrier remains, and no stronger power-loss guarantee is claimed. |
| U5 Two-direction progress | Physical growth port/group pairing, 40 independent growth credits, legacy/main FIFO/64 ordinary credits, every send class (including negotiation/revoke/snapshot), revoke-before-send and drain-before-handle-publication selected in 6.2/8.3. Before 3 accept mechanism; implemented group/auth/receive/cancel/send buffers require first-boot review. Real concurrent native FilterSendMessage/FilterReplyMessage/teardown and epoch-closed growth progress still need execution; fence Busy proof also before 5 boot. |
| U6 Owned MM/buffers | Before 6: finish owned :10927→:5903/:5948 Major/Minor/IRQL/resource/MDL/completion audit, and pre-FltLockUserBuffer credits at :4824. Supply actual structures/worst-case page/PFN/cancel storage and validate numerical bounds; no pin-only or unowned :11044 proof. R4-MM routing/native evidence follows implemented review. |
| U7 Trust scope | Owner decision before 4 unchanged: existing trusted private-storage boundary or separately reviewed external erasure/rollback architecture with availability/repair/uninstall/reset rules. A builder test cannot settle this boundary. |
| U8 Fit/grammar | GrowthArchiveFitModelTests supplies pure checked arithmetic, maximum combined-envelope refusal/fit, overlap/padding/migration/selection and initial debt/shell state model before 3. Full independent Entry+closure maxima **do not fit** and retain ledger. Before 4 implement/validate actual serialization lengths/strict codecs and typed candidate/tail/delta/prefix selection against model; N-U8 allocation/recovery controls remain builder mechanisms, then required target evidence. No arithmetic result is native durability or qualification. |

## 14. Open questions for the owner

| Decision | User-visible effect / recommendation; still open |
|---|---|
| O1 Per-application-I/O growth wait | Recommend a **per-I/O growth-wait bound of 3 s**, from first crossing through sufficient adoption/reacquisition/recomputation, not 3 s per RPC. A larger joined extent/append race cannot renew it. A long save can encounter several pauses on different I/Os; expiry permanently fails that save privately. Alternatives 1 s/10 s shorten pauses or tolerate slower storage respectively. Owner must select duration and interpretation **before increment 6**; nothing here selects it or reopens the approved 120 s allocation interval. |
| O2 Erasure/rollback boundary | Recommend retaining the existing trusted-service/private-storage scope for M2 unless stronger protection is explicitly required; surviving modern evidence with a missing/corrupt marker still holds. If stronger detection is wanted, identify a separate authority whose anchor local SYSTEM/admin/installer cannot erase **or roll back** (installer-owned on the same machine is insufficient), who can authorize recovery/reset, what happens while unavailable, and how repair/uninstall/reinstall preserves or explicitly discharges retained custody. Normal uninstall cannot silently reset that anchor. A separate reviewed architecture is required before claiming this stronger guarantee. Owner scope decision remains open **before increment 4**. |

Pending/lane/capability work bounds above are concrete engineering proposals for
independent review, not renewed questions about budget defaults or a new file
size cap. No other product decision is requested here. If native evidence makes
the specified cleanup, metadata or MM contract impossible, present the exact
failed precondition and user effect for a design delta; do not silently change
support, failure policy, grants or assertions. Runtime activation and owner
cutover remain separate from review, component gates and pair qualification.
