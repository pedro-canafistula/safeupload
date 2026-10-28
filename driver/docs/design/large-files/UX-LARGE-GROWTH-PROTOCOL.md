# T9 growing reservations: revision 6 implementation contracts

2026-10-28. **Proposed addendum for independent review; documents only.**
Source anchors below refer to `feat/driver-m2` at `b066c30b`; proposed types and
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
The latter's pending allocation duration was subsequently settled by the owner:
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
5 FenceAllocation, 6 ResolveAllocationAck. These are proposed subcommands of
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
number or wire shape (`ResourceWireV32.cs:135`, `:178`).

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
identity, write padded noncached bytes, flush and set exact EOF, then persist
Prepared. Exact relative replacement validates the held predecessor and its
exclusion/security. Native success is final. Persist current Companion + replay
commit before reply. Updating memory/totals follows persistence. Retain the full
debit throughout a pending transaction. Any ambiguous ledger write faults
admission; any unresolved replacement blocks further growth of this K.
Schema 3 adds PendingCompanion phase **IdentityCaptured=5**, without renumbering
the existing 1–4 values: CreationMayHaveStarted → IdentityCaptured persists the
captured replacement identity **before writing it**; IdentityCaptured → Prepared
requires complete bytes/flush/EOF. IdentityCaptured/Prepared/
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
crossings join its heap waiter group with the original deadline; a higher extent
waits for that result, then, if still eligible, starts a new sequence with its
own operation deadline. A waiter does not edit an in-flight extent/deadline.
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
FenceId GUID?, FenceReceipt Base64?, CleanupWitness GUID?, ResolutionRevision
i64?}`. The duplicate OriginalRequest field must byte-equal the record field;
an implementation may store it once and reference it in memory, but persisted
validation must have one canonical authority. States: Open=1, Closing=2,
Fenced=3, Attached=4, CleanupComplete=5, ResolutionAcknowledged=6. Sid must
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
4 service abandonment), reserved zero[12]@1212. The outer header uses the
**current** authenticated cookie; original bytes carry the origin cookie.
No stage identity is required to ask for a fence: the lost reply may have hidden
it. Service persists Closing and FenceId before sending. Driver validates the
full retained original request and marks the intent permanently Closing before
returning Busy or doing local rundown. Query/retry uses the same FenceId.

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

Only FencedNeverAdoptable carries a nonzero FenceSequence and three zero
counters. A known K echoes exact committed K; unknown tuple fields are all zero
and do not claim no service commitment. Agent persists full header+payload plus
the original request and FenceId; this is non-adoption evidence, **not deletion
evidence**. Busy/Unknown supplies no cleanup authority. Attached requires the
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
| Local FILE_OBJECT/share/FsContext binding | provisional adoption ticket covers `StageStream.c:2941` binding/`:2964` FileObjects increment; Closing rolls back unpublished upper binding under existing ownership before ticket release |
| Attach PREPARE/COMPLETE may have escaped | track exact v20 attach state, including `AttachCompletionMayExist/Known/Fence`, terminal/retire and in-flight flags; obtain exact ABORT/retirement evidence and undo provisional binding, or report Attached/Busy |
| Final upper CREATE success | one gate transition commits Attached immediately before successful completion, with deadline/current connection rechecked. If Attached wins, no FencedNeverAdoptable; if Closing wins, no CREATE success. |

The final success transition cannot leave a scheduler gap in which the fence
reports non-adoption but a prepared success still completes. Fencing waits for
all locally admitted tickets to retire, reply adoption to be excluded and any
attach-completion possibility to be resolved. It does not wait under namespace,
stream or spin locks. An unresolved attach permission is Busy even at zero
ordinary handles. `StageStream.c:2912` already distinguishes provisional binding
from completion; `:6815` retains original allocation recovery requests, and
`:6868` checks attach/handle/section state before legacy non-commitment.
Extend those paths; service serialization alone cannot establish this fence.
Every failure completion (including deadline expiry before a service fence
arrives) first closes the same driver adoption gate. A reply cannot win adoption
after that failed completion. Service Closing and driver Closing are separate
facts; both must be joined before cleanup authority exists.

Driver retains a fenced receipt/name reservation until ResolveAllocationAck
(opcode 6). Payload **1208 bytes** = original request[1192] + FenceId[16]. Agent
may send it only after persisting CleanupComplete with exact stage/companion/
pending-creation disposal and its durable closed-intent tombstone in hot/shared
history. Reply payload is `Result u32` (1 name released, 2 unresolved), zero u32.
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
reconciliation/grace before its seed timer at `:237`; modern admission replaces
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

### 6.2 Proposed lane and reply bounds

Confirm the wire proposal's 8 unresolved allocations/connection, 4/SID, 8 growth
workers and 32 queued growth messages. Complete its previously unspecified
allocation/lifecycle/reply bounds below. These are proposed implementation work
bounds, not new storage defaults or limits on admitted files. Acceptance is a
review prerequisite; do not activate them from this document alone.

| Population | Proposed bound / admission / saturation |
|---|---|
| Initial intents | 8 unresolved per connection family (one authenticated agent/driver-instance lineage across reconnects), also 8 on current connection; 4 per original SID across **all** old/new cookies and restart. Count queued/executing/Closing/Fenced/unacknowledged cleanup. |
| Allocation execution | 1 worker + at most 7 waiting unique intents within those 8 slots; duplicates share the intent, no extra native worker. Capture at most one pending transport reply per intent; additional duplicate receives Busy. |
| Growth | 8 workers + 32 queued per connection, one semantic operation/K; duplicates use a bounded reply slot or Busy, never unbounded joining Tasks. |
| Lifecycle/rename/drain | 2 workers + 32 queued per connection; short claim/capture then release serialization for I/O, current-state completion. Semantic ordering stays journal/state based, never arrival order. |
| Ordinary verdict | separate existing bounded inspection worker admission, with proposed dispatch shell 2 workers + 32 queued; handlers do not run on receive or use growth workers. |
| Replies | one preallocated reply record per admitted message (growth 40, allocation 8, lifecycle 34, ordinary 34), two independent completion pumps: growth and non-growth; no handler waits for a reply pump under `_gate`/journal. |
| Rejection | one fixed receive-owned failure buffer, synchronous bounded reply with zero retry queue; transport failure locally abandons that message. Receive never waits for content/lifecycle work. |

Connection **family** counting tightens the literal connection proposal to stop
reconnect churn from multiplying unresolved work. Reconnect adopts old debt into
its family before accepting fresh work; old origin cookie/SID remain in durable
intent records. There is one authenticated service channel; a new AgentInstance
does not reset its family debt. Startup reconstructs unresolved counts before
readiness, including creations without identity. Decrement only on exact
resolution and acknowledged name recovery, never waiter timeout/disconnect.
Migration must refuse modern admission if unresolved debt cannot be attributed.

At saturation send correlated RetryableBusy (v32) or the existing typed legacy
failure; no queued positive reply, no new metadata/negative receipt and no
NoAllocationCommitted unless independently proved. For a duplicate that may
already have committed, Busy means unresolved, never absence. Growth can retry
Busy only within its original deadline; eventual required-growth failure sticks.
Reserve reply storage **before** retaining a message, including duplicates.
An unexpectedly blocked reply syscall cannot consume the growth pump; failed
delivery drops transport ownership and leaves semantic custody charged.
Native cancellation/bounded delivery feasibility is an explicit section-13 gate.

Revoke capture/revalidation occurs before admission and every authority commit.
Growth waiters release locally before dependent lifecycle drains; old workers
cannot publish readiness on replacement connections. No per-transfer mutex
spans content I/O needed by growth. This is the interface for increment 2;
`MinifilterInterceptor.cs:349` and `StagedRequestContinuations.cs:13` are change
anchors only and are owned by the concurrent dispatch worker. Controls R3-Q01,
R4-O01/O02 include occupied lanes, blocked replies and reconnect/SID churn.

## 7. Growth deadline: owner decision, no selected default

Required growth is its own operation, separate from allocation and inspection.
Propose **3 s = 30,000,000 interrupt-time ticks**, from first capacity-crossing
issuance through adoption, never renewed by retransmission, queue saturation,
reconnect or a late reply. This value is **not approved here**. Negotiation stays
NotReady for growth until a value is accepted and represented on both peers.

User-visible contract for any selected duration: a write/EOF/allocation/section
extension crossing capacity pauses for at most the remaining growth wait; if
that wait expires, that save permanently fails, stays private and cannot publish
even a clean/empty successful prefix. Already written private bytes remain in
exact charged custody for ordinary disposal/hand-back policy. A later grant or
recovered service cannot make that version writable/publishable again. Ordinary
writes already within the grant do not enter this wait. Timeout diagnostics say
growth timed out, distinct from exhausted storage and allocation timeout.

| Owner alternative | User effect / trade-off |
|---|---|
| 1 s | shorter application stall, more false save failures under storage/recovery contention |
| **3 s recommended** | short bounded pause while allowing normal durable metadata round trips; needs target measurements under full lane load |
| 10 s | more tolerance for slow durable storage; a capacity crossing may visibly freeze saving longer |

No alternative permits deadline renewal, prefix publication or a changed
failure policy. Required-growth refusal must set the existing sticky
SpaceFailed/nonpublishable path (`StageStream.c:4780`,
`agente/SafeUpload.Agent.Service/Interception/StagedSpaceFailure.cs:1`) with a
distinct timeout cause, preserving v31's failure-only semantics. Control R4-D02
observes application duration, private bytes and late-success refusal with an
injected clock; native/VM controls use the owner-selected value, not a weakened
assertion to suit a slow run.

## 8. Metadata capability map and accounting I/O fence (increment 3)

### 8.1 Registration and object routing

Proposed `StageResourceMetadata` and anchored native-store modules integrate
before epoch/BP/namespace/writer dispatch at `StageStream.c:10928`, with revoke
hooks in `Communication.c:1980` and instance/unload rundown (existing unload
entry `StageStream.c:8234`). A SYSTEM-owned arbitrary path is insufficient.
Bootstrap outside `_gate` validates installed roots, fixed NTFS, full directory
IDs, trusted owner/protected DACL/no untrusted writers and no reparse ancestors.
Anchor handles exclude rename/delete/security substitution for their lifetime;
unsupported native exclusion must stop integration, not become a path bypass.

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
same-name object. Existing target exclusion is held by the store across replace.

Role numbers are fixed: 1 LedgerCurrent, 2 LedgerNew, 3 CompanionCurrent,
4 CompanionNew, 5 ManifestCurrent, 6 ManifestNew, 7 Segment, 8 InventoryCurrent,
9 InventoryNew, 10 MarkerCurrent, 11 MarkerNew, 12 LegacyNegative,
13 LegacySecurity, 14 EpochCurrent, 15 EpochNew. Result is 1 registered or
2 refused, with ChildIntentId zero on refusal. Current roles are read/query/
exact-delete only, except Segment's admitted offset writes; only New roles
receive bounded write/flush/EOF/replace rights. MarkerCurrent never receives
automatic delete. LegacySecurity is query/read only. LegacyNegative delete
requires its serialized legacy non-commitment proof, not its role number.
Names are the exact pre-admitted ledger/transfer/transaction leaves; epoch is
`driver-epoch.state`, inventory `segments.state`, marker `resource-format.marker`.
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
Tag only original open FILE_OBJECTs, remove nonowning keys before CLOSE/address
reuse. Revoke denies new mutations/opens immediately; already claimed operations
settle conservatively with map rundown pins. Cleanup/CLOSE always progress;
disconnect/instance teardown/unload finish locally without service ACK. A stale
object pointer cannot match a new incarnation. Bound registration: four roots,
at most one child intent + two live metadata child objects per active metadata
worker; proposed **16 metadata transactions**, otherwise Busy before allocation.
Growth uses at most 8 of these; reserve 8 for non-growth work so neither exhausts
the other's progress. These bounds do not cap durable history.

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
| RequireArchiveAdmission / RequireJournalGrowthAdmission (`:326`, `:340`), ArchiveGrowthAdmission (`StagedTerminalArchive.cs:136`) | Completed; Segment <=4 MiB including its 4096-byte frontier block; InventoryCurrent/InventoryNew 128 bytes modern (section 10). Q/read and admitted bounded noncached offset write/flush/EOF/relative replacement. | Include padding, control/frontier write, replacement overlap and failed residue in maintained shared physical total before write. No hot MetadataFiles rebuild. |
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
compaction/control writers for additional actual roles (section 13); a generic
unlimited “journal file” role is forbidden.

Sector-pad each noncached write within precharged allocation, flush, set exact
logical EOF and verify allocation; handle zero/tiny records and large allocation
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
`:1919` rejects StageDeleted for that state. `StagedSpaceBudget.cs:624` requires
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
required `Entry` (existing journal payload), `ResourceSchema=3`, InstallationId,
positive i64 RecordRevision (starts at 1, increments on each manifest transition),
required-null `OrdinaryDiscardDisposal`, and required-null `ResourceClosure`
(the complete strict schema-3 MetadataOnly record including replay, accepted
proofs, final slots and the Prepared handoff). ResourceClosure is non-null before shared
commit; InstallationId/transfer and any disposal witness must match Entry.
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

### 10.2 Handoff transaction and shared bytes

Reservation-v3 adds required-null-or-value `HistoryHandoff`:
`{TransactionId GUID, InstallationId GUID, Phase (Prepared=1,
SharedCommitted=2), ExpectedLedgerRevision i64, CompletedRecordId GUID,
CompletedRecordRevision i64, SharedPhysicalBefore i64,
ReservedPhysicalGrowth i64}`. The modern completed entry retains exact original
intent, K, original SID, closure/fence/receipt, replay HighWater/latest, ordinary
discard witness, final slot incarnations/releases and both effective and
allocation high-water generation barriers. History is not compacted into a
hash/path-only proof. Modern `segments.state` is exactly **128 bytes**:
ASCII `SAFHIS03`@0, u32 Version=3@8, Size=128@12, InstallationId GUID@16,
CompletedDirectoryIdentity[24]@32, u32 CommittedSegmentCount@56, zero u32@60,
u64 InventoryRevision@64, LastHandoffTransactionId GUID@72, zero[40]@88.
InventoryRevision starts at 1 and checked-increments for each replacement;
LastHandoffTransactionId is zero only before the first modern handoff. Segment
count preserves existing consecutive-name/missing-segment validation, it is not
a cap on completed saves. Replace through InventoryNew after flush, same anchor.

Keep the existing bounded 4 MiB segments and 4096-byte frontier area
(`StagedTerminalArchive.cs:13`, `:16`). The existing 48-byte frontier at `:410`
has magic@0, version=1@4, committed end i64@8 and SHA256(first 16 bytes)@16;
remaining frontier-area bytes are zero. Its end remains within [4096, 4 MiB].
Modern frames retain the 60-byte frame header (`:399`): magic@0, **version=2**@4,
payload length u32@8, TransferId GUID@12, SHA256(payload)[32]@28, followed by
the strict modern manifest envelope (<=128 KiB). Legacy frames stay version=1.
The modern envelope's ResourceClosure contains Prepared HistoryHandoff with
TransactionId/CompletedRecordId/CompletedRecordRevision; these fields identify
duplicate handoffs without a self-referential payload hash or unbounded index
file. Exact frame locations/digests and both generation indexes are rebuilt in
memory from committed frames at startup. Hashes validate framing, not content
object authority. Capability registration validates each held segment identity;
no path/digest may authorize deletion of a content object.

After all content and companion obligations resolve, durably prepare the
handoff while the per-SID metadata envelope remains charged. Admit **shared**
physical growth and replacement overlap first. Append/flush exact completed
entry and commit the archive frontier/index with transaction ID. Persist
SharedCommitted; only then delete the exact ledger through metadata capability
and remove its per-SID debit. Shared storage debit is at least the existing
`2 * rounded(hot + completed physical bytes) + 16 MiB` recovery/packing
allowance; preserve the approved formula and per-object rounding. No debit gap:
overlap may conservatively charge both classes. The archived ResourceClosure
is the exact Prepared snapshot, not a claim that its old R equals the later
SharedCommitted ledger R; compare its recorded expected R and transaction ID.
Native append/rename success
is final; retry its frontier/handoff bookkeeping, not another completed entry.

| Crash point | Startup reconstruction / permitted action |
|---|---|
| Marker before first ledger | validate marker, inventory empty or recognized residue; no v1 fallback |
| Prepared before shared commit | charge transfer metadata and reserved shared overlap; finish exact append or resolve recorded incomplete transaction |
| Shared commit before ledger SharedCommitted | discover transaction ID/record revision at committed frontier, finish ledger bookkeeping; no duplicate append |
| SharedCommitted before exact ledger delete | retain both conservative classes until exact delete; complete deletion only |
| Ledger deleted before memory totals update | shared record/frontier reconstructs debit and closed replay/generation state; no lost SID debt |
| Packed/moved shared records | charge old + new/residue until exact commit/delete; retained witnesses/barriers survive |
| Last modern transfer retired | marker persists and shared bytes remain accounted; old/disabled startup still refuses |
| Marker corrupted, identity changed or missing while any modern/shared evidence exists | admission hold with actionable format/identity diagnostic; no recreate/delete/downgrade normalization |
| Marker removed together with all recognizable evidence | cannot detect arbitrary privileged erasure from these stores alone; section 13 identifies the trust limit and required install anchor |

All new startups classify shared format and marker **before** the old blanket
constructor checks; accounting-disabled mode refuses marker or any modern
evidence even if the transfer ledger directory is otherwise empty. A missing
marker never makes a modern record legacy. No automatic marker erasure/rebuild
on corruption. Repair requires an explicitly authorized storage recovery path.
`StagedSpaceBudget.cs:662` already moves selected completed cases into shared
accounting but lacks this modern transaction/marker; `StagedSpaceUpgrade.cs:12`
currently reconstructs the old shared allowance. Controls R4-H01–H03 include
enabled and disabled old readers after **last** modern ledger deletion.

## 11. Kernel growth/MM feasibility and stop condition

Extend the current immutable `SpaceCapacity` (`StageStream.c:123`) at write/
resize/allocation (`:4780`, `:4850`, `:6009`), paging bridge (`:5833`), MDL
fallback (`:11044`) and drain (`:6278`). Copy K/D/C/extent/deadline into bounded
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
| PREPARE_MDL_WRITE / IRP_MN_MDL / COMPLETE_MDL | reject fast prepare for IRP fallback where needed, reserve before returning writable range; preserve W/paging ownership through completion. Completion/release path never waits for growth or is blocked by closure. |
| Paging/AdvanceOnly/flush | no growth RPC. Extent must fit pre-reserved capacity; retain paging rundown and failure completion behavior, never skip/approve over-capacity bytes. |

No namespace, paging resource, writer registry lock or spin resource spans a
growth wait. No budget → journal/content dependency. Existing recursive resize
comment `StageStream.c:4747` records NTFS top-level lock-conflict/section retry
livelock; `:4790` keeps upper flush on its caller. This does not establish that
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

## 12. Dependency-ordered implementation and control inventory

### 12.1 Seven increments (all T9, no completed checkboxes)

| Order | Coherent implementation / dependencies / exit observable |
|---|---|
| T9 increment 1 | Review this addendum; extend passive C/C# ABI, strict schema-3 codec and pure transition/replay/fence models (sections 2–6, 8–10). No negotiation/admission. Linux ABI/mutation/conservation/crash controls; changed C gets paired WDK/static/import gates; agent gets full four-leg delivery matrix. Growth duration owner decision before its dependent producer. |
| T9 increment 2 | Concurrent worker's bounded dispatch shell in MinifilterInterceptor/StagedRequestContinuations; freeze control/cookie/lane/reply interface from sections 2/6. Receive validates/captures/dispatches only; blocked allocation/lifecycle/reply cannot trap growth. R3-Q01 and R4-O01/O02. No active growth yet. |
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
| R3-Q01 bounds | all lanes/reply slots full, bounded duplicates/tasks | blocked reply/cancel/port reconnect | growth still received/replied, revocation releases waits before drains |
| R3-M01 confinement | role/size/access/leaf mutations | relative noncached/pad/EOF/security/allocation-unit checks | policy covers all private roots, no epoch/namespace/upper-stream recursion |
| R3-M02 lifetime | map incarnation/revoke/rundown model | impersonation, process/token/anchor/target substitution, links/reparse/ADS/by-ID | FILE_OBJECT address reuse, disconnect, instance/unload; no bypass or UAF |
| R3-M03 lock order | transitive callback/claim completion failures | content leases outside gate | saturated growth + namespace/publication/reduction stress, no budget→journal cycle |
| R3-X01 ordinary discard | strict new receipt, old StageDeleted still rejected | exact delete with reader/section/replacement | ordinary discard refunds after proof, snapshot remains charged, fresh name use |
| R3-X02 discard crash | section-9 crash table, duplicate/reuse | receipt persist fault after exact native success | live/restart/hot/packed no lost barrier or duplicate release |
| R4-O01 ordering | forced allocation/growth/close/rename reordering | connection revalidation | journal failure after growth closure, late success cannot reopen |
| R4-O02 drain | lane-full revoke/cancel dependency model | bounded reply teardown | epoch drain queued in every lane, service-independent local pin release |
| R4-D01 allocation deadline | exact 120 s pair, equality/overflow/retry | interrupt time vs wall-clock jump/resume | issuance through final attach, queue/seed/postcommit expiry, timeout vs space UI |
| R4-D02 growth deadline | owner-selected duration, no renewal | native timer/late delivery | stalled crossing permanently fails privately; late grant cannot publish prefix |
| R4-MM01 crossings | extent/revalidation/append races | cached/noncached/MDL/EOF/allocation/section actors | each supported crossing above/below C, C02 extension, no paging RPC/livelock |
| R4-MM02 pins | waiter/worker timeout/signal/release ownership | allocation/cancel fault seams | timeout/disconnect/teardown/retire at every adoption/pin boundary under Verifier |
| R4-H01 handoff | shared transaction crash table | append/frontier/index/ledger-delete faults | replay/generation/debits after last ledger deletion, no lost charge |
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

| Item | Exact missing fact / affected anchor / dependent increment |
|---|---|
| U1 BootDomain and old-instance fence | Select/verify a supported Windows 19045.2965 source for OS boot identity and exact old-instance unload/rundown evidence. Existing `StageStream.c:6815` replay and `:8234` unload do not provide the proposed persistent cross-instance receipt. Service restart/new DriverInstance is insufficient. Needed for sections 2/5, increments 4–5. |
| U2 Complete adoption audit | Enumerate all queued/executing CREATE exits and v20 attach/terminal/retire callbacks reachable from `StageStream.c:2432`, `:2912`, `:6815`, including final callback completion ownership, and demonstrate the single Attached/Closing linearization with no success-completion gap. The table specifies obligations, not a verified kernel implementation. Increment 5. |
| U3 Native release adapters | Prove final storage release with multiple service readers/sections/operations, including after crash and delete-pending storage. `StagedStageFile.cs:162` exclusive deletion/absence alone has not proved every modern lifetime. Enumerate adapters per slot role and legacy ordinary discard; unknown remains charged. Increment 4. |
| U4 Metadata native exclusions/roles | Verify directory/target handle sharing excludes rename/delete/security substitution without blocking exact replace, and enumerate concrete archive frontier/index/state-file maxima from `StagedTerminalArchive.cs:129` and its control/compaction writers. No unbounded role or cached fallback. Include lower-query identity/security/free-space/alignment routes and native import availability. Increment 3. |
| U5 Reply progress | Prove finite/cancellable native reply delivery and two-pump storage lifetime for the bounded dispatch shell; current passive `ResourceWireV32.cs:94` says nothing about port blocking/rundown. If a blocked native call can consume the independent growth path, redesign before active negotiation. Increment 2 integration. |
| U6 MM entry feasibility | Inventory actual IRQL/top-level/owned resources and callback ownership for each section-11 path; prove no unknown recursion release, no upper flush transfer, no forbidden wait lock or paging growth. `StageStream.c:4753` demonstrates existing resize separation only. Increment 6; stop condition in section 11 applies. |
| U7 Installation erasure boundary | Marker + mirrored InstallationId detects missing marker while any modern evidence survives. Arbitrary privileged deletion of **all** witnesses is not detectable from empty directories. Select an independently checked installer/service format anchor or explicitly retain the existing trusted-private-storage threat boundary; do not claim tamper-proof removal detection. Required before shipping downgrade support, increments 4/7. |
| U8 Format migration/physical fit | Implement strict v2→v3 passive-record migration, modern manifest envelope and archive version discrimination, with maximum serialized witnesses still <=64 KiB ledger /128 KiB manifest and existing metadata envelope under large units. Reject rather than drop fields. Codec success is not native store durability. Increments 1/3/4. |

## 14. Open questions for the owner

| Decision | User-visible effect / recommendation |
|---|---|
| O1 Growth wait duration (required) | A crossing write pauses then permanently fails that save privately on expiry. Recommend **3 s**, never renewed; 1 s reduces stalls but increases failures, 10 s tolerates storage contention with longer visible stalls (section 7). No growth producer/consumer until selected. This does not reopen the approved 120 s allocation wait. |
| O2 Only if U7 exceeds the existing storage trust boundary | If downgrade must also detect complete privileged erasure of marker **and** all modern history, an independently retained installation-format anchor is necessary; absent it protection cannot honestly claim that detection. Recommend an installer-owned, independently checked format anchor, with a concrete repair/upgrade design before expanding that guarantee. Existing surviving-evidence corruption/removal stays a hold without a new owner choice. |

Pending/lane/capability work bounds above are concrete engineering proposals for
independent review, not renewed questions about budget defaults or a new file
size cap. No other product decision is requested here. If native evidence makes
the specified cleanup, metadata or MM contract impossible, present the exact
failed precondition and user effect for a design delta; do not silently change
support, failure policy, grants or assertions. Runtime activation and owner
cutover remain separate from review, component gates and pair qualification.
