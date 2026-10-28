# T9 growing reservations: revision 8 implementation contracts

2026-10-28. **Proposed addendum and pure models for independent review; no product implementation.**
**Revision 8 is proposed, pending independent review.** It adds the increment-4
before-coding audit (12.1.3), release ownership (9.3), strict archive/serializer
contracts (10.5), and legacy migration (10.6), with product-independent models.
O1/O2 reflect the owner decisions of 2026-10-28; no checkbox or execution gate
is closed by this revision. Revision 7 applied the first measured Windows mechanisms from
[native results 2](../../../evidence/2026-10-28/t9-inc3-native-results-2.md),
retaining the [first failures/correction](../../../evidence/2026-10-28/t9-inc3-native-findings.md).
The [section 8.7 review](../../../evidence/2026-10-28/t9-growth-87-review-sol-high.md)
is **ACCEPT WITH CONDITIONS** for dormant registration/pools; revision 6 supplied
its before-coding text. Actor/echo remains deferred to increment 6 separately
from pools. Builder mechanisms, source acceptance, target preflight, delivery
and qualification are distinct; this edit claims none of the latter results.
The [re-review](../../../evidence/2026-10-28/t9-growth-protocol-rereview-sol-high.md)
closed F1/F2/F3/F5/F7 as design corrections, with native/source/runtime proof
still distinct. The [third review](../../../evidence/2026-10-28/t9-growth-protocol-rereview2-sol-high.md)
requires the corrected peak model and explicit increment-3 source/test cut below
before coding; this revision does not self-declare independent acceptance.
Earlier source anchors below refer to `feat/driver-m2` at `8ae881b9`;
section 8.7 also cites the partial kernel delivery `88d7850b` and unchanged root
construction verified in the current tree. Proposed types/modules are identified
as proposed. This is increment 1's contract proposal,
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
120 s, as recorded in revision 4's owner decision. The owner subsequently
selected 3 s per application I/O (O1), retaining that allocation interval.

## 1. Scope, precedence and authority

Revision 6 made the remaining revision-5 integration contracts concrete;
revision 8 supplies the increment-4 additions identified in 12.1.3. Its
new formats, controls and bounds are proposals until independently reviewed.
It does not change the approved budget formulas, four-copy envelope, 120 s
issuance-to-adoption allocation wait, absence of a modern per-file cap, Windows
grants/sharing/security, or publication/read/export authority. It does not change
any test threshold, assertion, scope or cutover gate. Preserve shipped unbound
v1/v20 behavior and the bound-head NotReady gates. No resource message means
ordinary ALLOW; no timeout means non-commitment or storage release.

The passive ABI and dormant increment-3 substrate are real; the complete active
resource consumers below are not. Section 8.7 retains the historical partial
`88d7850b` delivery/anchors. At `7c3ab3e5`, the increment-3 kernel pass-4
[source re-review](../../../evidence/2026-10-28/t9-inc3-preboot-rereview-sol-high.md)
is ACCEPT WITH CONDITIONS: registration/pools/routing source exists, but target
N-U4-06 fault/retention/release and separate real-component N-U5-01 remain before
first protected boot, with their original ordering. Commit stays NotReady. In particular,
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
| 32 | u64 | GrowthWaitTicks (30,000,000 for Commit; zero permitted only on Probe) |
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
No subset success; Commit requires the explicit owner-selected 30,000,000 ticks,
with identical driver/agent acceptance, never a default on missing input.
No bound allocation. A provisional
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
| Service-to-driver controls | Legacy main sends retain FilterPort._sendGate. Dormant resource send classes landed in `01ffb09f` (`FilterPort.ResourceSends.cs:41`); production pairing/registration callers and real-port proof are still absent. Section 8.3 remains the full required contract, not a result of increment 2. |

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
FIFO and captured preceding driver for old handlers. The separate resource
handler validates the captured provisional/authenticated group directly; it must
not call AwaitDispatchDriverAsync on a preceding Ordered handler (the main lane
may be the one blocked). This changes no legacy continuation ordering.

The dispatcher releases a pre-dequeue credit immediately on **accepted** work
(`StagedRequestDispatcher.cs:130`). Thus 40 credits do **not** bound all retained
growth messages. Queue/worker capacity bounds accepted Growth work at 8+32=40;
the credit pool independently bounds rejected work plus the next receive owner
at 40. Combined accepted + rejected + one reserved/dequeued receive is **<=80**,
not 40. Rejected ownership retains its credit through native failure reply.
Main accepted work is <=33 Ordered +8 Allocation +40 Continuation =81; ordinary
rejected/receive owners <=64, combined <=145. A group has at most one receive
owner per port, inside its pool, no unbounded post-dequeue buffer/task list.
Saturation closes intake when its class credits are exhausted; accepted native
reply stalls consume accepted workers, rejected stalls consume failure credits.
These transport/delegate populations are separate from kernel 32/256/64 and
metadata/send/ACK limits; first-boot review must size each actual capture.
 Resource group revocation
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

## 7. Growth deadline: owner-approved 3 s per application I/O

**Owner decision O1, 2026-10-28: one 3 s growth-wait bound per application I/O**, measured
from that I/O's first observed capacity crossing through its final sufficient
capacity adoption/revalidation, reacquisition and recomputation: **3 s =
30,000,000 interrupt-time ticks**. A long save can issue many I/Os and
therefore encounter several such pauses. This is not a bound on the whole save,
inspection or the later native data-write duration. Modern producer/consumer
readiness still requires all dependent implementation,
review and qualification gates; the duration decision alone supplies no authority.

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

R4-D02 includes B needing 64 MiB joining A's 32 MiB RPC just after issuance,
A completing near its deadline, B requiring another sequence, and repeated append
recomputation. Assert B never gets two full intervals, nor extra time after
reacquisition, and no late successful prefix publication. The owner selected the
duration; model tests supply no readiness or qualification result.

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
Section 8.7.1 supplies the proposed signed fixed-path selection authority;
caller identity/security alone never enrolls an installed root. Root anchors
open with FILE_SHARE_READ|FILE_SHARE_WRITE, **without**
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
**together with FileRenameInformationEx class 65/flags 3** (8.4); SHARE_DELETE
alone does not make class-10 replacement possible. Also hold an exclusive
**store namespace claim**
for the exact anchor/leaf/current identity across validation and rename. Every
registered writer respects that claim; untrusted writers lack native access.
The measured class-65/flags-3 operation against a held no-SHARE_DELETE target
returns sharing violation; do not drop the predecessor handle or substitute
another class as an automatic fallback. The metadata capability branch must
validate class 65, flags **exactly 3**, native buffer length and the held source/
root/target tuple; it gains no generic POSIX or public-path rename exemption.
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
at most **four total child credits** per metadata transaction, including at most
one pending intent (8.7.2); **16 metadata transactions**, otherwise Busy before
allocation/lower dispatch. Pending/Opening/Active/retiring records share this bound.
Section 8.7.2 fixes eight Growth and eight NonGrowth slots with immutable
TransactionId class tags; Role alone cannot distinguish shared ledger uses.
Neither pool borrows from the other; exhaustion returns Busy, never a cleanup
wait. Four child handles replaces the earlier proposed two:
an excluded companion target can remain held while a ledger current/new pair
is durably committed, and archive candidate/segment/intent replacement needs
up to four. This is bounded map storage, not a cap on durable history.

| Capability state / interruption | State transition / recovery action | Control |
|---|---|---|
| Child intent registered, open not issued | PendingOpen=1; consumes its transaction slot and one of four child credits; revoke removes locally, releasing only after every referencing owner drains | R3-M02 |
| Pre-CREATE claimed, lower create executing | Opening=2 uses the same reserved child credit, with local rundown/context pin; revoke excludes subsequent mutation/exposure; settle native result against the durable creation claim | R3-M02 |
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
R3-M01 must prove metadata routes here while a real counted epoch is closed,
not through union denial/BP/namespace callbacks. Its increment-3 diagnostic
actor/raw-store subset is deferred to 6 in 8.7.3; early native/legacy-pause
controls in 8.7.4 have narrower explicit coverage; its
application-held growth/ledger/companion case remains increment 6. R3-M02 covers
failed CREATE,
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

Legacy `FilterPort.cs:89`–`:123` counts accepted senders then serializes them
on `_sendGate`; `SetPolicy` at `:568` uses that lease. Kernel policy transition
closes/replaces the epoch (`Policy.c:1155`) then drains (`:1169`). The prohibited
cycle is SetPolicy/_sendGate → epoch drain → application growth → budget ledger
→ RegisterChildIntent → _sendGate. Independent **driver-to-service** lanes do
not remove this **service-to-driver** cycle.

Propose three normal send classes plus bootstrap/revoke slots within the
**same authenticated two-port connection group**, retaining
one common send-lifetime owner, with private per-call buffers and native handle
references. `01ffb09f` adds dormant resource classes in
`FilterPort.ResourceSends.cs:41`/`:75` with no production registration caller;
the table states the full integration contract, not a real-port progress result:

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

R3-M04's retained increment-6 production case saturates legacy sends with
SetPolicy blocked in epoch drain while the counted application waits for growth;
RegisterChildIntent, ledger/companion I/O
and growth reply must progress. Independently fill metadata and fence classes,
queue fences whose tickets need service progress and require prompt Busy,
correlated refusals, bounded population and cancellation/dispose with no freed
send buffer. An unrelated typed Busy is not proof of no allocation commitment.

### 8.4 Measured native sequence and documented guarantee boundary

This selects the measured held-target mechanism and explicit allocation
precondition below; it supersedes the earlier class-10 selection. Results are
from builder2 Windows **19045.6466**, not the **19045.2965** target. N-U4-06 must
reproduce the primitive on that target without the new kernel before any
boot-time reliance on it; availability on a similarly numbered OS is not proof.
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
| Plan/preallocate padded extent | **Before issue**, precharge nominal Q=AlignUp(AlignUp(L,A),U) independently for current/new/predecessor/residue. Production requests FileAllocationInformation (class 19) for P=AlignUp(L,A), then queries identity/EOF/AllocationSize **before writing**. For append extension request the complete claimed TargetFrontier extent first, not merely frame length. Reject a failed preallocation/unknown measurement; raise retained charge before reporting any measured overrun Held. No write begins after a detected preallocation overrun. |
| Write padded bytes | NtWriteFile with aligned offsets/buffers, synchronous noncached/write-through, within the admitted padded extent. Preallocated chunked writes are the production sequence; a **whole padded extent in one call** is only a separately qualified alternative, not an unpreallocated chunking fallback. Query allocation after every native write, including failed/lost-completion boundaries, before F1/EOF normalization. Sector separation is not an allocation-ceiling proof. |
| F1 | FlushFileBuffers on the same held output handle (native adapter NtFlushBuffersFile); require success before exact logical EOF. |
| EOF/allocation | NtSetInformationFile(FileEndOfFileInformation) and any admitted FileAllocationInformation normalization within the claimed extent; query identity/EOF/AllocationSize after **each** call, even failure. Smaller/final allocation does not erase a previously observed peak or authorize a refund. |
| F2 after EOF | FlushFileBuffers on that same handle again, then verify complete expected bytes/identity/security/EOF. No durable candidate from a pre-EOF flush alone. |
| Replace | Under exact store namespace claim, NtSetInformationFile(**FileRenameInformationEx, class 65**) on held source, RootDirectory=held same anchor, exact target leaf, **Flags=REPLACE_IF_EXISTS (1) \| POSIX_SEMANTICS (2)=3** for prevalidated replacement. The exact predecessor stays held with FILE_SHARE_DELETE. No unrelated POSIX flags, absolute MoveFileEx, target-path reopen, cross-anchor rename, release-first fallback or widened public/content authority. Class 10 and class 65/flags 1 are failed held-target alternatives, not selected replacements. |
| F3 after replacement | Require native rename success and exactly one mutation before interpreting predecessor state; FlushFileBuffers on renamed source, then query exact successor and held parent. Query predecessor separately: measured class-65/flags-3 success yields Links=0, DeletePending=True, readable old bytes through held handle; independently openable successor has Links=1. Refusal proves neither unlink nor successful-mutation recovery. Failed/uncertain barriers retain all charges/evidence; known native success is final and is never reissued. |

[Microsoft NtSetInformationFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile)
documents the information-class operation and native completion, and
[FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
documents flushing buffered file information. This sequence requests data and
file-metadata flushes and specifies **native-completion/process-crash recovery**
ordering on supported local fixed NTFS. The recorded discovery calls do not
complete the interrupted-recovery controls or establish that ordering on target. None of these links specifies an atomic,
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

Store outputs carry LogicalLength L, PaddedWriteExtent P=AlignUp(L,A), and
**nominal** geometric precharge Q=AlignUp(P,U); A and U remain independent.
Q is not a universal NTFS physical-allocation ceiling. The builder experiment
recorded unpreallocated chunked-extension overshoot in **3/12** cases, including
L=65537: peak=131072 versus Q=69632, and L=131072: peak=196608 versus Q=131072
(**+50%** in that vector). Final EOF normalization returned allocation to Q;
that does not remove the earlier peak. Neither +50% nor the largest measured
ratio becomes a new bound/default. Single padded writes (12 without and 12 with
preallocation) and preallocated chunked writes (12) stayed within Q on this
builder. These are measured vectors, not universal bounds or target proof.

Production preallocates **P** before initial writes and the full target extent
before append extension; verify preallocation and query every write, F1,
EOF/allocation normalization, F2 and failed native step. The agent round-2
implementation adds this request/measurement at
`StagedMetadataStoreNative.cs:222` and `StagedMetadataStore.cs:155` in the worker
report; these anchors refer to that reported source, not assumed later offsets.
One-call and chunked mechanisms require separate allocation experiments. A
positive completion requires successful native steps and all observed allocations
within the nominally admitted bound. Overrun is Held, never discovery-PASS
promoted to Committed or a larger implicit segment/resource limit.

Call retained physical charge **R_phys**, distinct from custody revision R.
For each exact object, before any explicit supported reduction transition,
`R_phys := max(previous R_phys, Q, AlignUp(observed AllocationSize,U))`.
Thus retain at least max(Q, observed), rounding conservatively and recording the
peak **before** reporting Held/faulting admission if it exceeds Q. Update the
maintained per-object/hot/shared debit, exact identity and boundary receipt;
do not leave only Q charged after observing more. A failed query keeps the
previous conservative charge/creation claim and holds admission with unknown
physical outcome, not a claim that Q covers unknown allocation. Failure, lost
completion, smaller EOF or later normalization cannot lower R_phys. Lowering
needs an exact persisted measurement/release transition after F2 and closed
mutation/operation custody; final close alone is not storage-release proof.
Precharge before issue remains required: after-the-fact overrun accounting is
conservative failure handling, not proof of reserve-before-write. If preallocation
cannot support the nominal admission mechanism on the supported target, stop for
a reviewed allocation-bound/design delta; do not silently inflate a formula.

Retain every current/predecessor/replacement/residue additively. For a **successful
class-65/flags-3 held-target replacement**, the measured predecessor is unlinked
and delete-pending (`Links=0, DeletePending=True`) but still readable through its
held handle. Track `Linked → UnlinkedHeld → UnlinkedDrained → Released` with
exact object/store-operation/handle pins; reacquired pins retain/reenter held
custody. Record link count and DeletePending independently. No such state is
inferred after class-10 or class-65/flags-1 ACCESS_DENIED or an uncertain result. A linked,
unlinked-held, or other delete-pending object stays charged until its owners drain
and exact release is established; zero links, DeletePending or one handle closing
is not a refund receipt. A genuinely measured immutable predecessor can retain
its separately persisted lower charge; every new/failed output retains its own
R_phys. No retry borrows another object's unused envelope or repeats known-success
rename. The accounting worker's reported `StagedMetadataStorePlan.cs:149`/`:187`
implements pin/state and raise-before-fault concepts; it is not target qualification.

Archive initialization now precharges Q(2*A), requests allocation=2*A, measures,
then writes the two initial frontier slots (chunking separately qualified), F1,
EOF=2*A, F2, observing allocation before normalization and after **each** call.
The revised builder raw append remained allocated at 8192 throughout; its later
strict replacement still failed on class 10. Each extension reserves the
increment to max(current R_phys, Q(target extent)) for that same segment, retaining
its old charge until the transition settles; **different** predecessors/residue
remain additive. Do not charge the same segment as two physical objects. Then
preallocate and measure the complete target extent,
then frame write → F1 → monotonic EOF → F2 → inactive slot → F3, with R_phys
updates at every boundary. New inventory/candidate/intents use the selected
class-65/flags-3 F1/EOF/F2/rename/F3 sequence. Uncertain outcomes preserve exact
append location/physical evidence before any legacy tail repair; no cached fallback,
new epoch/policy/namespace/service dependency or undocumented durability guarantee.

IRQL contract: registration and relative CREATE, identity/security/type validation,
read/write/EOF/flush/rename/disposition run PASSIVE. Forwarded CREATE requests
synchronized post and captures all inputs in nonpaged context. Draining post at
DISPATCH does no pageable validation/lower I/O: leave entry Revoked/uncertain,
queue its pre-reserved local PASSIVE rundown owner. CLEANUP/CLOSE can only retire
local keys/pins at their allowed callback IRQL, with final lower/dereference work
deferred through that owner; no new allocation or service ACK. U4 first-boot
review must establish actual callback registrations and cleanup/cancel paths.

### 8.5 Native mechanism controls: builder observations and target preflight

These raw component controls use the native adapter **without the new kernel**.
The [first execution](../../../evidence/2026-10-28/t9-inc3-native-findings.md)
failed 3 of 3407 in the first matrix leg; the four-leg gate did not complete.
The [second diagnostic](../../../evidence/2026-10-28/t9-inc3-native-results-2.md)
(`633f3ffb`, agent identical to `fda55c13`, builder2 **19045.6466**) executed
**97: 94 passed, 3 failed**, including 80 recording-only discovery cases and
three still-failing strict gates N-U4-01/-05 and N-U8-01. Their findings select
the corrected mechanism below; neither successful discovery recording nor this
edit is a green strict gate/full matrix. Builder results are mechanism evidence only,
not target 19045.2965 qualification or physical power-interruption evidence.
Each fault case must have a preregistered expected result: **Committed**,
**RecoverableBookkeeping** (same already-successful mutation, no repeat), or
**Held** (no usable authority, full charge/evidence). Held may pass a preservation
case; it fails any case requiring positive completion or recovery. No choosing
classification after seeing the result. Every positive baseline uses the exact
role masks/shares and native information classes, not FullControl substitutes.

| Control / owning increment / order | Exact experiment and acceptance |
|---|---|
| N-U4-01 / 3 / **before-first-boot** | Exact-role relative create/query/no-follow positive; independent readback uses FILE_SHARE_READ\|WRITE\|DELETE while writable store handles remain held (plain File.ReadAllBytes is not a compatible observer). Traversal/ADS/reparse/wrong-parent/substitution negatives preserve substitute. Measured junction-as-file negative is typed MetadataNativeException/STATUS_FILE_IS_A_DIRECTORY **0xC00000BA**, not required to derive from IOException. Assert exact native refusal/call/identity, not any exception. Strict old assertion still failed in results 2; rerun corrected gate. |
| N-U4-02 / 3 / **before-first-boot** | Actual queried A/U, native aligned buffers/offsets/lengths; include 64/128/192/1192/65536/65537/131072 and A>U, U=512/4096 where available. The 64 KiB experiment quantum is a verified multiple of native alignment, not a fabricated U. Record actual units and adapter-before-issue versus native-issued alignment refusal separately. Earlier builder subset passed; reproduce with selected mechanism/target units; no simulated native PASS. |
| N-U4-03 / 3 / **before-first-boot** | Record L/P/nominal Q/R_phys, identity/EOF/AllocationSize after preallocation, every initial/extension write (including failures), F1, EOF/allocation normalization and F2, before normalization as well as final. Production preallocates P/full target extent and requires observed allocation within Q for positive completion. Any overrun raises retained debit before Held, survives faults and later normalization until explicit persisted reduction/release. Reproduce one-call/preallocated-chunk vectors separately; unpreallocated overshoot is preservation evidence only. |
| N-U4-04 / 3 / **before-first-boot** | Retained root/ancestry no-SHARE_DELETE exclusion is separate from predecessor sharing. Positive **class 65/flags 3** needs held predecessor SHARE_DELETE plus store namespace claim; SHARE_DELETE alone does not make class 10 or class 65/flags 1 work. Negative class-65/flags-3 no-SHARE_DELETE returns **0xC0000043**, no substitution/release-first fallback. Security, competing registered writer and revoke/drain-before-repair cases remain. Record actual Links/DeletePending/pins and additive R_phys; only proved native success permits UnlinkedHeld, and zero links/DeletePending/final handle close alone never release charge. |
| N-U4-05 / 3 / **before-first-boot** | Select **FileRenameInformationEx class 65, flags=3 (REPLACE_IF_EXISTS\|POSIX_SEMANTICS)**, exact relative masks/claim and predecessor SHARE_DELETE. Measured held class 10 and class 65/flags 1 return **0xC0000022**, regardless of predecessor DELETE access; no held target and release-predecessor-first/class-10 are measured successful discovery controls, **not** a release-first fallback. Require native success, SuccessfulRenames +1, old **Links=0/DeletePending=True/readable**, successor independently openable with Links=1. Failed rename cannot enter lost-success bookkeeping. Interrupt recovery twice: exactly one successful mutation with all R_phys retained. Class-10 strict gate remained failed in results 2; corrected strict rerun and N-U4-06 target reproduction pending. F3 is not a power-loss certificate. |
| N-U8-01 / 3 / **before-first-boot** | Raw output/replace/append/frontier compares nominal L/P/Q **and additive retained R_phys** for current/new/predecessor/residue before normalization and at faults. Precharge then preallocate target extent; record each allocation/native result. Builder single-write/preallocated-chunk vectors stayed within Q; unpreallocated chunks overshot in 3/12 and normalization later hid the excess. Require raised debit/Held on that negative, never positive PASS. Revised initial append stayed 8192, but later class-10 replacement and DeletePending=False assertion still failed: corrected class-65/flags-3 old Links=0/DeletePending=True must pass. Cover tiny A>U, failed outputs and retained unlinked predecessor pins; raw geometry is not archive-selector evidence. |
| N-U4-06 target reproduction / 3 / **before-first-boot reliance** | On exact **19045.2965 target OS**, using native component fixtures **without loading/booting the new metadata kernel**, reproduce the N-U4-04/-05 class-65/flags-3 sharing/status/link/readability matrix and N-U4-03/N-U8-01 preallocation/one-call/chunk/fault allocation boundaries. Revalidate exact role/security/relative-handle masks, retained R_phys and release proof. Complete before the first boot that relies on these mechanisms; builder 19045.6466 evidence alone cannot satisfy this gate. Independently review changed source first and use an authorized existing-baseline native preflight; this document authorizes no target run, boot or gate change. A mismatch to the required selected mechanism/sharing/lifetime or preallocated within-Q outcome stops reliance for a design delta, never silently narrows support. Recompute Q from actual target A/U; recording-only unpreallocated discovery outcomes are not assumed to reproduce identical overshoot counts. |
| N-U8-02 / **4**, retained **before-qualification** gate | Actual archive classifier/tail/frontier/base/delta recovery after increment 4 exists: arbitrary logical ends, appended frame outside frontier, torn inactive slot, current/predecessor intents and repeated interrupted recovery; no modern truncation or repeated committed append. Not an increment-3 exit obligation. |
| N-U8-03 / **4**, retained **before-qualification** gate | Actual legacy migration, selected-prefix copy/inventory recovery and preservation of every base/ACK/witness; inject copy/select/delete failures with old+new/residue charge. Numeric range tests are not this control. Not an increment-3 exit obligation. |

Predetermined fault expectations for N-U4/N-U8-01: successful exact sequence
and positive replacement is Committed; explicit write/F1/EOF/F2/rename refusal,
unknown identity, torn bytes or failed final barrier is Held with the exact
retained **R_phys**, including raised measured overrun and all live predecessors/
residue; known native rename/append success with
only completion/bookkeeping lost is RecoverableBookkeeping **only after exact
independent identity/mutation observation and required flush reestablishment**.
Interrupt that bookkeeping recovery a second time: still exactly one native
rename (or one raw append), not a newly successful mutation. A Held result is
never relabelled positive recovery. Before-issue adapter alignment rejection
records zero native calls; native-issued alignment negatives record the actual
API result and preserve any admitted/created custody.

R3-M01/M04's kernel actor/echo seams are **deferred to increment 6** (8.7.3),
separately from the accepted pools. Section 8.7.4 supplies early real-port
N-U5-01 and legacy-reply-pause R3-M04P controls without new kernel authority;
neither is full actor/growth evidence. R3-M03 reduction stress remains increment
4 (growth saturation in 6); fence/ACK/snapshot remains 5. No later assertion is
deleted or closed by raw/fake storage/transport tests.

### 8.6 Increment-3 deliverable and stable test seams (before-coding cut)

Name the deliverable **provisional metadata substrate**. It contains only:
provisional main/resource group pairing and registration; authenticated metadata
control dispatch; outer metadata pre/post/tag/refusal routing; bounded native
store operations; nominal padded precharge/preallocation and measured retained
physical accounting/short claims; common native
handle/buffer/connection and PASSIVE rundown infrastructure. Negotiate Probe can
return provisional identity; **Commit always returns NotReady, Mode=0, no
accepted capability/grant**, independent of raw substrate test success. No modern
initial allocation, schema-3 ledger consumer, capacity adoption/growth producer,
retirement reduction, CREATE registry/fence/ACK/snapshot handler, or archive
selector/recovery is activated by increment 3. Shared control opcodes that belong
to 5 remain typed NotReady/unsupported, never successful stubs.

Choose an **opaque bounded-buffer store** to avoid the unfinished schema-3 codec
as an increment-3 prerequisite. No production source pretends the current strict
ResourceStateCodecV2 (:66) is schema 3. Proposed module/interface contracts:

| Seam | Inputs / bounded result / exclusions |
|---|---|
| Provisional registration | Exact existing control-36 layouts, group identity and role map; native handles referenced before return. Pure header/role/layout validation and paired lifetime types are the only increment-1 wire source dependencies; if absent, implement/review these passive contracts first. No schema-3 transition module dependency. |
| BoundedOutputPlan | Role, exact transaction/object incarnation, L, independent verified A/U, P, nominal Q, expected predecessor identity and maximum logical bytes; checked precharge before preallocation/issue, then per-call measured R_phys and overrun Held. Immutable byte buffer length exactly L, independently owned through native completion. No JSON interpretation, intent/debit authorization or callback into journal/policy. |
| Claim/output store | Short typed claim/current revision → exact relative create/read, aligned opaque write/flush/EOF, exact held-target replace/delete and raw aligned offset append/slot flush. Return exact native result/identity/EOF/allocation/operation receipt plus Committed/RecoverableBookkeeping/Held. Native success is final, not retried because a wrapper failed. Serialization/parsing of resource records is a later caller's responsibility. |
| Physical accounting | Bounded object inventory with nominal Q plus measured retained R_phys (raise before overrun Held), independently charged predecessor/residue and object/store pins; explicit exact measured-closed/release events lower charge. Maintain hot/shared deltas under short state serialization, no directory walk or content/journal callbacks on a foreground admission. |
| Diagnostic fixtures | Inject finite native-call failures vs lost return/bookkeeping separately, observe independent mutation counts and repeat-interrupt recovery. Feed bounded opaque byte patterns and raw frame/frontier buffers, not a fabricated valid schema-3 allocation or archive receipt. |

**Deferred to increment 6:** retain the proposed test-only
**T9MetadataEpochHoldActor** seam below as an unapproved future fixture, not
increment-3 source. The early alternatives are in 8.7.4. In the deferred proposal, the
harness acquires one real counted admission token, closes epoch admission through
the normal policy transition, and releases the token only after a bounded
**raw metadata** transaction completes or the monotonic diagnostic deadline ends.
It is not an application save waiting for growth and issues no grant/reply.
The actor uses a dedicated test-build control/fixture identity and cannot create
resource authority; every actor/echo path must be absent in product builds. The
artifact/host exclusion choice and exact test-only control/layout must
be independently reviewed with implementing source, without changing these
confirmed product ABIs. Section 8.7.3 now proposes the diagnostic layouts and
artifact/host options; **deferral to 6 is recorded**, with future fixture
selection/review required before any actor code. Scope
it to token acquire/release and captured diagnostic
counters, not generic policy bypass or silent Unknown reset. Every timeout/cancel/
teardown releases its token locally and reports failure, not PASS by a hold.

Deferred actor R3-M01 seam: policy covers private roots, diagnostic token holds the
epoch closed, opaque ledger/companion-shaped bytes still create/replace/flush
through metadata branch. R3-M04 seam: SetPolicy occupies main send path and 64
ordinary failure credits are stalled; provisional independent metadata controls/
raw resource-channel **diagnostic echo** complete with exact owner/correlation,
then actor releases token. Echo is separately tagged test-only traffic, never
operation 23 success; no growth handler is needed. Wrong-channel/token/process,
local revoke/cancel and finite drain are part of this seam. Commit remains
NotReady before/during/after actor execution.

R3-M02 is fully an increment-3 map/context lifetime row. R3-M03's increment-3
subset is raw journal-shaped buffer/store claim ordering and fault accounting;
its **real custody reduction** waits for 4 and production growth stress for 6.
N-U8-01's raw append/dual-slot writes are in 3; classification, candidate/tail
recovery, migration and selection are exclusively the increment-4 consumer.
Increment 3's passive preparation must materialize/validate the existing
64-byte ResourceControlHeader, 96/112-byte Negotiate, 64/40-byte RegisterRoot,
640/16-byte RegisterChildIntent, 8/8-byte Revoke and 24-byte PairContext layouts,
role/access enums and local claim/incarnation/result/lifetime types, with C/C#
layout/mutation controls before any handler consumes them. These are its exact
wire/local prerequisites; the existing passive 1192/104/160/352/376-byte
resource types are not a completed schema-3 state machine. No source consumer of
Fence/ACK/ShellSnapshot is added in 3. Before increment 4's resource/archive
consumer, strict source codecs/transitions from increment 1 must exist and pass
their own checks. This explicitly narrows a dependency, not any
carried final-pair assertion. O1/O2 were not prerequisites for this dormant
substrate; both are now decided (2026-10-28), without closing any other gate.

### 8.7 Inputs for completing the increment-3 kernel substrate (revision 6)

The worker report `~/Work/safeupload-tools/workers/t9-inc3-kernel-final.md`
records **partial** delivery at `88d7850b`: pairing/authentication/revocation/
control dispatch exist, but no successful registration, object maps, metadata
pre/post routing or native store ownership. At the section 8.7 review snapshot
`44080deb`, the root stub is `StageResourceMetadata.c:361`–`:387`; child dispatch
at `:588`–`:592` also returns refusal. These are reviewed snapshot anchors, not
acceptance of concurrent implementation work.
The following are proposed contracts for independent review, not evidence that
those stubs can return success. They preserve every confirmed product ABI size
and **Commit NotReady, Mode=0, no grants**. The review accepts the root/pool
architecture conditionally; the predicates, Busy mapping and credit representation
below supply its coding conditions. Actor/echo is **DEFERRED to increment 6**;
no actor parser/helper is part of this kernel pass.

#### 8.7.1 Installed-root authority: signed fixed table, not enrollment

**Conditionally accepted selection:** the signed driver contains the following compile-time
RootRole-to-absolute-NT-path table. RegisterRoot accepts a role and an original
user handle, never a locator, configured prefix, environment expansion or an
installer/service enrollment assertion. This is the recommended root-authority
contract, with the review's separate security predicates below. The table supplies the missing namespace
selection authority; native capture supplies the object authority.

| RootRole | Fixed NT path | Required registered parent |
|---|---|---|
| 1 StageRoot | `\??\C:\ProgramData\SafeUpload\staging` | ParentRootId=0; verified installed ancestor chain |
| 2 Reservations | `\??\C:\ProgramData\SafeUpload\staging\.space-reservations` | live StageRoot RootId from this group |
| 3 JournalHot | `\??\C:\ProgramData\SafeUpload\staging-journal` | ParentRootId=0; verified installed ancestor chain |
| 4 Completed | `\??\C:\ProgramData\SafeUpload\staging-journal\completed` | live JournalHot RootId from this group |

The existing kernel constructs the C: staging path at `StageStream.c:2164` and
`:2889`; `:9247` is a **volume-relative** private-prefix classifier, not an
absolute C: enrollment check. The agent sets `staging` and `staging-journal`
from AgentPaths.RootDirectory at `MinifilterInterceptor.cs:1697`–`:1698`.
`AgentPaths.cs:22`–`:24` uses CommonApplicationData, which need not be C:.
Reservations is under **staging**, not the journal
(`StagedSpaceBudget.cs:71`); Completed is under **staging-journal**, not staging
(`StagedTransferJournal.cs:246`–`:247`). Thus the two top-level roots share
`\??\C:\ProgramData\SafeUpload\`; JournalHot is a sibling of staging.
Calling all four descendants of the existing `staging\` prefix would contradict
these sources. The table is the minimal explicit extension for metadata, not a
change to the shipped private-prefix classifier or arbitrary-prefix support.

RegisterRoot performs the following bounded PASSIVE capture outside `_gate` and
all map/epoch/policy/upper-stream locks; map space is reserved nonwaiting first.

1. Authenticate the original process/primary token/service SID and paired group.
   Reference the supplied handle **in that process with UserMode access checks**
   for READ_CONTROL|SYNCHRONIZE|FILE_READ_ATTRIBUTES|FILE_LIST_DIRECTORY, as the
   partial handler already attempts at `StageResourceMetadata.c:372`–`:377`.
   Reject impersonation, non-directory handles, wrong grants and truncation.
   Retain that original FILE_OBJECT reference and instance, not the handle integer.
2. Resolve the table's C: through the **kernel global DOS-device namespace**,
   never the registered process's per-process drive mapping. Capture/pin its
   volume/device and filter instance, require local fixed NTFS, and require the
   kernel-resolved Windows system volume to be this C: volume. Neither a client
   device-map alias nor an unrelated fixed C: data disk satisfies the contract.
   Use targeted Filter Manager opens/queries below this filter, with kernel
   handles and KernelMode, not a general kernel-I/O bypass. Existing targeted
   open mechanics are at `StageStream.c:1223`–`:1225`; fixed-volume/NTFS checks
   at `:1192`–`:1202` are mechanics, not this new installed-root proof.
3. **Recommended mechanics:** hold the fixed installation ancestry once:
   global C: volume root → `ProgramData` → `SafeUpload`. Open the first by its
   independently resolved kernel NT volume locator, then each signed one-component
   suffix relative to its already held parent, never a caller path. From held
   SafeUpload resolve signed `staging` / `staging-journal` suffixes, then
   `.space-reservations` / `completed` relative to the appropriate held root.
   These are independent resolutions of the table's fixed absolute locations;
   repeating four absolute opens is not extra authority and is not required.
   Use FILE_OPEN, FILE_DIRECTORY_FILE|FILE_OPEN_REPARSE_POINT|
   FILE_SYNCHRONOUS_IO_NONALERT, step-1 root access and
   FILE_SHARE_READ|FILE_SHARE_WRITE **without SHARE_DELETE** on every retained
   directory handle. Capture full identity, volume/instance, type and security
   at each component, following no filesystem reparse point. Share at most seven
   directory anchors. Retain the actual exclusion handles, not just FILE_OBJECT
   references; a reference alone does not exclude replacement. Missing/no-follow/
   share/security uncertainty refuses, with no ACL repair or service wait.
4. Apply **PrivateRoot** to each of the four roots and **AncestorEdge** to the
   volume-root/ProgramData/SafeUpload ancestry, as defined below. These are
   distinct predicates, not a call to one generic trusted-owner helper.
5. Compare the expected identity in the request, the original user FILE_OBJECT
   and the independently opened installed object: full volume serial/128-bit
   file ID, same pinned volume/instance, directory/type/security and exact held
   parent relationship must agree. KernelMode opening does not add to the user's
   checked grant or authorize a child mutation. Publish a connection-local RootId
   only after final live-group revalidation. Never reopen using the user handle
   integer after return. Kernel anchors and original references live through
   group/map rundown; remove keys before releasing them outside the map lock.

**PrivateRoot(SD):** owner must equal LocalSystem (`S-1-5-18`) or Builtin
Administrators (`S-1-5-32-544`), explicitly including Administrators. DACL must
be present, non-null, structurally valid and protected. For directory generic
mapping, mutation includes FILE_WRITE_DATA/ADD_FILE, FILE_APPEND_DATA/ADD_SUBDIRECTORY,
WRITE_EA, WRITE_ATTRIBUTES, DELETE, FILE_DELETE_CHILD, WRITE_DAC and WRITE_OWNER.
Every potentially applicable mutation Allow ACE, explicit or inherited, must
name one of those two exact principals. Inspect inherit-only mutation grants
for future descendants as well; an unsupported form cannot hide a grant.
**TrustedInstaller and a separate SafeUpload service-SID mutation ACE are not
automatically accepted**, even if the connecting token contains that SID.
Neither an arbitrary caller/owner SID nor group membership enlarges this set.
Read-only grants may name other valid SIDs. An ordinary mutation Allow to another
principal refuses conservatively even when a Deny might restrict it; no ACL
rewrite or speculative token-group enumeration converts it to acceptance.

**AncestorEdge(parent SD, held child SD/identity, component):** Windows ancestors
need not have private protected DACLs. Require a valid known owner and present,
non-null valid DACL. Owner itself is security authority through owner-derived
WRITE_DAC; an untrusted owner fails even if no Allow ACE lists mutation rights.
For the Windows volume root and ProgramData only, the allowed security-authority
set is LocalSystem, Builtin Administrators and the **exact Windows TrustedInstaller
service SID**, derived from the fixed Windows service identity, never a friendly
name/caller SID. These may own or receive destructive/security authority on those
Windows ancestors. For the SafeUpload installation ancestor the set is only
LocalSystem/Builtin Administrators, matching its private installation boundary.
This explicit servicing exception does not apply PrivateRoot to Windows ancestors,
and does not add TrustedInstaller to any private root's owner/grant set.

For each edge, expand directory GENERIC masks, account for effective explicit
and inherited ACEs and propagation flags, and reject any possible untrusted
DELETE on the parent, FILE_DELETE_CHILD, WRITE_DAC or WRITE_OWNER. Also examine
inheritable ACEs that actually reach this captured child: CONTAINER_INHERIT,
INHERIT_ONLY and NO_PROPAGATE affect propagation, not trust. Refuse if they can
grant the untrusted principal destructive/security authority on that child or
mutation forbidden by the child's own predicate. An inherit-only ACE does not
authorize the parent; it must still be evaluated for this edge. A verified
protected child DACL blocks inheritance; do not invent inheritance across it,
or rely on protection without capturing that actual child descriptor. Ordinary
create-in-other-names rights on ProgramData do not replace the already held
SafeUpload component and are not alone a refusal. Compare child type/identity/
security again before publication; retain the no-SHARE_DELETE chain throughout.

Both predicates parse bounded valid self-relative descriptors/ACLs and ordinary
ACCESS_ALLOWED/ACCESS_DENIED ACEs with valid SIDs and recognized inheritance flags.
AncestorEdge additionally resolves ordinary OWNER_RIGHTS ACEs to the captured
owner (without using a Deny to excuse an untrusted owner), and inherit-only
CREATOR_OWNER ACEs to the **captured next child's owner** when their inheritance
flags apply. Check the resolved principal and actual resulting child descriptor;
this supports ordinary Windows inheritance without treating every creator as
trusted. Non-inherit-only CREATOR_OWNER, unresolved creator/group/substitution
semantics, object/callback/conditional/resource-attribute ACEs, malformed masks/
lengths/flags or an unproved owner/inheritance case **refuse with a diagnostic**.
PrivateRoot's exact SID/mutation rule is not expanded by these ancestor-only
resolutions; a private mutation grant outside SYSTEM/Admin still refuses.
Do not silently skip them or infer absence of authority from an unknown ACE.
The over-approximation of Allow rights is deliberately conservative; legitimate
but unsupported descriptors require a reviewed predicate extension, not auto-repair.
This specifies a capture rule, not a claim that today's kernel stub implements it.

Source boundaries: `StagedTransferJournal.cs:2083` checks mutation grants;
`:3544` checks the application parent and currently trusts only SYSTEM/Admin;
`:3581` checks private-object owners. Reuse their private trust limits, not
RequireTrustedOwner indiscriminately for Windows servicing-owned ancestors.
Kernel implementation belongs at `StageResourceMetadata.c:361`–`:387`, which
at the review snapshot references then releases a user object and returns unsupported.
**R3-M05** must accept legitimate servicing-owned Windows ancestors with exact
SYSTEM/Admin private roots, and reject an untrusted ancestor owner with an
otherwise innocuous DACL, effective/inheritable destructive grants, unsupported
ACEs, TI-owned private roots and separate service-SID mutation grants there.
Include ordinary ancestor CREATOR_OWNER inheritance resolving to the real trusted
child owner as a positive, and an untrusted/unresolved child-owner case as a negative.
Admin-owned/granted private roots are positive controls. Owner/ACL checks never
replace independently reached identities and retained exclusion handles.

**Legitimate ACL repair:** revoke the whole group and close new admission, then
drain accepted native operations, contexts, claims and exclusion handles **before**
any directory/child security mutation; only then repair outside `_gate` and
recapture all anchors/security on a new provisional group. Journal startup can
write directory and child DACLs at `StagedTransferJournal.cs:307`–`:325`; future
integration must place those writes before registration or behind this complete
revoke/drain/repair/recapture order. No live capability survives a repair, no
normalization of an untrusted object to pass, no release of uncertain charge.
R3-M05/M02 includes a repair attempt with active contexts and proves mutation
waits for real drain and old IDs never reactivate.

The installer/service may establish a **missing** protected leaf through ordinary
trusted setup outside metadata accounting, then retry bootstrap from scratch;
the kernel neither creates it nor enrolls a substitute. The agent's bootstrap
first compares its actual CommonApplicationData-derived roots against these
fixed C: locators (case-insensitive, no alternative drive/alias/reparse mapping);
a mismatch holds startup before registration. That is a compatibility refusal,
not kernel enrollment evidence: the kernel still independently performs the
object checks above and never reads a service environment variable. An exact
repeat for a
live role/identity returns its existing RootId; a different identity for that
role refuses and revokes the group. ParentRootId=0 is legal only for roles 1/3;
roles 2/4 must match the exact role/parent above. All four are required before
any future Commit Ready. Security is rechecked before native commit as in 8.1;
trusted rename/repair/uninstall follows the revoke/drain-before-mutation and
recapture rule above; kernel references alone are not a repair barrier.

| Condition / interruption | Required failure/recovery; no implicit authority | Control |
|---|---|---|
| Windows system volume differs from the captured global C: volume, or CommonApplicationData-derived roots use a non-C: locator | Kernel RegisterRoot refused for the volume mismatch, RootId=0; agent bootstrap refuses the locator mismatch without issuing registration. Modern startup Held with role/installed-path/actual-volume diagnostic. Do not use environment override, alternate drive, junction or a copied C: tree. Supporting it requires a separately reviewed table/path contract delta; no legacy gate change. | R3-M05 |
| Root missing, renamed before capture, wrong parent, reparse ancestor or non-fixed/non-NTFS volume | Refuse with zero authority and precise missing/identity/ancestry/filesystem diagnostic. Preserve all durable charges/evidence. Trusted setup/repair outside admission may retry after full validation; no automatic migration or recursive creation. | R3-M05 |
| Native root/ancestor share exclusion unavailable, security changed, or original handle closed/reused while capturing | Captured original reference must still compare to installed identity; any uncertainty refuses/holds. A later handle with the same integer cannot register the substitute. Never wait for cleanup requiring that registration. | R3-M02/M05 |
| Rename/delete attempted while anchors held; group revoked during capture | Native exclusion must prevent the former; revoke prevents publication and locally releases unpublished capture. A successful substitution or unproved exclusion stops this implementation for a design delta. | R3-M02/M05 |
| Root replaced after previous group drains; marker identities refer to predecessor | New table capture is not migration authority: section 10 startup holds on marker/ledger/inventory identity mismatch. Do not update InstallationId, erase marker or discard old custody. | R4-H03 |

**Consistency with 8.1/8.2/10 and the reviews:** 8.1 already requires installed
ancestry independently of SYSTEM ownership; this table supplies its missing
selection source while retaining the original-handle check and root exclusion.
8.2's root/role map is unchanged, including the sibling JournalHot. Section 10's
marker remains on Reservations and binds the captured identities; it does not
enroll roots or authorize replacing them. There is no authenticated root-enrollment
channel to design because neither peer may choose another namespace. This is
**not** an erasure/rollback-resistant installation anchor: privileged SYSTEM/
admin/installer can replace trusted storage after revoke/reboot. The first
review's erasure/rollback warning remains: O2 now selects that existing boundary
for M2; paths, signed table, ownership and marker do not widen it. U7's owner
scope is settled, while its implementation/security checks remain required. Specific
native C:/system-volume resolution, ancestry exclusion/security capture and
cancel/rundown imports still require source review and N-U4/R3-M05 evidence.

#### 8.7.2 Transaction partition: immutable wire-neutral class tag

The Role field alone cannot classify all transactions. Growth uses only
LedgerCurrent/New and CompanionCurrent/New, but initial allocation, abandonment
and custody/reduction also use those four roles (8.2). A rule putting every
ledger in growth's pool would let growth consume cleanup's reserved capacity.
Use the conditionally accepted wire-neutral rule: reserve **bit 7 of native
GUID byte 15 of TransactionId** as Pool (1 Growth, 0 NonGrowth). The other 127
bits identify a fresh nonzero transaction (all-zero after masking the tag refuses); this is not a TransferId, request ID,
FenceId or durable K. C# uses the native Guid byte layout already specified in
section 1, not text GUID position or a host-endian integer cast. Do not alter the
640-byte child request, reserved bytes, role numbers or capability bits.

| Transaction purpose / Role | Pool tag / admission rule |
|---|---|
| Capacity-growth ledger and companion exchange: roles 1–4 only | Growth=1; one of eight Growth transaction slots. No manifest, archive, epoch or cleanup dependency within this transaction. |
| Initial allocation, recovery, abandonment, retirement/reduction or exact metadata cleanup: roles 1–4 where needed | NonGrowth=0; one of eight NonGrowth slots. These uses explain why Role alone is insufficient. |
| ManifestCurrent/New (5/6), Segment (7), InventoryCurrent/New (8/9), MarkerCurrent/New (10/11), LegacyNegative (12), LegacySecurity (13), EpochCurrent/New (14/15), HistoryCandidate (16), AppendIntentCurrent/New (17/18), CompactionIntentCurrent/New (19/20) | NonGrowth=0 only; Growth tag with any such role refuses before allocation. Existing role/proof/access limits still apply; tag never grants delete or adds LegacyNegative proof. |
| RegisterRoot / bootstrap / revoke / ordinary control | No TransactionId or transaction slot. Existing root/control/send bounds remain separate. |

The trusted service chooses purpose before its first RegisterChildIntent, passes
one exact tagged ID to all children of that transaction, and does not relabel a
growth operation as cleanup to borrow reserved slots. A non-growth caller that
also needs companion/ledger work uses one NonGrowth transaction across those
roles. No operation holds one pool while waiting to acquire the other: publish
its exact charged result, close/drain its transaction, then schedule an independent
consumer. Growth never waits for archive/journal work. A tag is scheduling data
from the already trusted service, **not kernel proof of semantic purpose**;
future growth/cleanup call sites must prove classification in their integration
controls. Hostile authenticated service behavior is not a new isolation claim.

Kernel transaction key is (live group cookie, exact TransactionId), with a
second retained masked-ID lookup to reject tag-flipped aliases. **Choose pending
intents reserving one of the four child credits**, not separate extra storage.
This refines 8.1's earlier "one intent + four live" wording: the total is four,
not five. Existing `StageResourceMetadata.h:23`–`:26` bounds 16 transactions ×4
child records =64 records; at most 16 of those records can be unclaimed intents.
No 65th child record or uncounted Opening owner is implied by pending storage.

For each transaction, `PendingOpen + Opening + Active + Revoked/retiring <= 4`
(each record counted once), `PendingOpen <= 1`, plus operation/context reference
counts. Atomically under the short map lock: validate live group/tag/alias,
join/create exactly one transaction in its encoded 8-slot pool, reserve a vacant
child record **and** its bounded completion/rundown ownership, then publish the
intent. No native I/O/allocation/wait under that lock. Reserve bounded backing
storage before visibility; allocation failure rolls back only unpublished new
ownership and never an existing transaction's owners. A duplicate exact pending
registration returns its existing ID without another credit; changed reuse
refuses. Concurrent first children for the same ID cannot allocate two
transactions or two pending intents: one wins, the other gets exact duplicate
success or Busy. Concurrent opposite-tag aliases cannot both win.

| Child state / event | Credit, slot and completion ownership |
|---|---|
| Register while four records occupied, or a distinct unclaimed intent already pending | Busy **before lower dispatch**; no fifth Opening/Active/retiring child and no new retained ownership. Already-admitted completion/CLEANUP/CLOSE never needs this admission. |
| PendingOpen → pre-CREATE claim → Opening | Atomically consume the intent **in the same reserved record**, acquiring its context/operation pin before lower dispatch. No temporary return/reacquire of a credit. |
| Failed CREATE, invalid successful CREATE or draining post | Remove/disable nonowning key and mark retiring; retain record/transaction until native outcome, any actual object custody and every post/deferred-context pin settles. No Active authority on failure/ambiguity. |
| Active → revoke/cancel/CLEANUP/CLOSE | Deny new use; retire original object key before address reuse. Cancellation is a signal, **not a slot refund** while a callback/completion/rundown context still refers to the record/transaction. |
| Final local retirement | Return the child credit only after intent/object/operation/context owners are zero and deferred local work has finished. Return transaction pool slot only when all four records and transaction pins are zero; exactly one final owner releases it. |

Neither pool borrows; no early refund on service cancellation or disconnect.
Reconnect drains the old maps/contexts before publishing a new group. An empty
transaction has no persistent slot and subsequent operations use fresh IDs;
that is a trusted-service obligation, not permanent kernel replay storage.
Unclaimed-intent cancellation cannot be inferred from a canceled service Task:
absent a kernel-observed claim/completion, local group revoke/rundown retires it.
No new cancel opcode or early agent-side slot refund is implied. These maps are
separate from durable 8/4 initial debt and retained-success shells.

**Both validators:** `MetadataChildShape` (`StageResourceMetadata.c:391`–`:440`)
and `ResourceControlWireV32.TryReadChild` (`ResourceControlWireV32.cs:116`–`:139`)
must examine native GUID bytes, reject all-zero **after masking byte15 bit7**
(including the tag-only GUID), reject unknown roles, and for Growth permit
**only roles 1–4**, independently of all existing size/access/name/identity rules.
NonGrowth may use any known role only with its existing exact role/proof limits;
no LegacyNegative delete proof or LegacySecurity size bound is fabricated.
Both reviewed validators check only ordinary GUID nonzero, which is insufficient. Stateful
retained-alias/concurrent-pool checks belong to the authoritative kernel map;
the agent registration adapter must mirror its active ID discipline, not claim
that a stateless wire parser can detect concurrent aliases. Existing opens as
well as creates must prove unnamed-stream, regular single-link/no-reparse exact
identity before becoming usable; user-native adapter checks alone are insufficient.

**Registration outcomes must survive every layer:**

| Outcome | Handler → kernel control dispatch → agent registration adapter |
|---|---|
| Local metadata send-class full | `ResourceSendStatus.Busy`, before input construction/native send; no native call, ID or retained new ownership. Release owned serialization before bounded retry. |
| Kernel transaction/child/control capacity full | Handler returns STATUS_DEVICE_BUSY; dispatcher returns that status unchanged, ReturnedBytes=0, no output authority, rolls back unpublished reservations. It must not turn it into transport success + Refused. Adapter maps only the exact native Busy transport result to retryable Busy. |
| Malformed header/payload/tag/role | STATUS_INVALID_PARAMETER/length error, no output ID; adapter reports malformed, never Busy and never retries as capacity exhaustion. Authentication failures remain access/refused errors. |
| Well-formed but object/identity/security/role authority refused | Explicit STATUS_SUCCESS with existing Result=2 and zero RootId/ChildIntentId/identity, fully correlated header; permanent refusal/held diagnostic. No automatic retry as Busy or ACL normalization. |
| Successful registration | STATUS_SUCCESS, exact native lengths/correlation and existing Result=1, verified nonzero ID; only this grants the transient capability. |

The working dispatcher must replace `StageResourceMetadata.c:581`–`:592`'s
blanket root-failure conversion and unconditional child success assignment with
these branches. Shape failures do not reach pool mutation; Busy/failed allocation
retains no **new** intent/transaction/context/open, and does not release preexisting
owners. No wire Result=3 is invented; product 64/40 and 640/16 exchanges stay fixed.

`FilterPort.ResourceSends.cs:123`–`:134` preserves HResult/BytesReturned but
currently calls any returned native invocation **Completed**. Completed is
transport completion, not successful registration. The agent adapter first
handles local Busy/Canceled/Revoked, then checks native HResult **before parsing
payload/ID**. For native FilterSendMessage use the exact Busy conversion
`HRESULT_FROM_WIN32(ERROR_BUSY)`; preserve the original HRESULT in diagnostics.
If a native sender explicitly exposes the NT HRESULT form, recognize exactly
`HRESULT_FROM_NT(STATUS_DEVICE_BUSY)` too, not arbitrary HRESULT failures.
R3-M08 must record which real FltLib conversion occurs; any different observed
conversion stops adapter acceptance for an explicit mapping correction, never
falls back to parsing zero/partial output or retrying every error. A failed
native result cannot expose a success payload; BytesReturned must be zero on
the specified kernel Busy path. Reject nonzero/invalid lengths as a protocol
fault, not registration. Concurrent cancellation/revoke may terminate adoption
instead; it still cannot turn Busy into a permanent authority refusal or free
in-flight native buffers. Keep native send leases through actual return.

Busy retries use the original operation deadline, release owned serialization/
admission before bounded retry, preserve durable charges and never await cleanup
requiring the refused registration. Cleanup/CLOSE and admitted completion/rundown
bypass new registration. Shared metadata sends remain 8-active/0-queued; pool
isolation is occupancy isolation, not fairness or a guarantee through stalled
native calls. A registration does not hold a send slot waiting for a pool slot.

**R3-M08 Busy propagation:** exhaust local send class and require zero native
calls/zero buffer construction; separately fill each kernel pool, child records
and control slots with a real connection and require native Busy, zero returned
bytes/no new IDs or owners. Follow with malformed/tag/role and security/identity
refusal cases and require distinct non-Busy classifications. Release the actual
last owner, retry once within the original deadline and require exactly one
registration; existing transactions remain unchanged by refusal. Test the
handler/dispatcher/transport/adapter chain, not just direct handler return or a
fake HRESULT. Counter/mutation models precede implementation; real-port mapping
and native-owner conservation follow source review (8.7.4 gates).

**R3-M06 pool isolation:** hold eight Growth transactions with actual children;
require ninth Growth Busy without allocation, and independent NonGrowth
registration/store/cleanup completion. Reverse the pools, require eight Growth
transactions still usable, and exercise all role rows, mixed ledger/companion
cleanup, the tag-only GUID, **every** disallowed Growth role 5–20, unknown roles,
tag-flipped retained aliases, concurrent first children and the four-total-child/
one-pending-intent bound. Inject failed CREATE, cancellation, revoke/CLOSE and
draining completion at every state, including cancellation while a completion
context still owns the record/transaction: no slot reuse until that pin drains. Prove 8+8 conservation including retiring owners,
no cross-pool borrowing, bounded send Busy, release once and eventual reuse only
after actual local drain. Pure tag/role/admission controls precede handlers;
routed runtime cases follow their implemented first-boot review. Full production
growth/cleanup classification remains an increment-4/5/6 integration gate.

#### 8.7.3 Diagnostic actor: deferred to increment 6, separate from pools

**Disposition: DEFERRED to increment 6.** No actor/echo opcode, parser, timer,
policy helper or diagnostic receive branch is authorized for increment 3. Pool
implementation proceeds independently under 8.7.2; actor deferral is not pool
admission deferral. The options/layouts below remain future design material,
not selected or accepted source contracts. N-U5-01/R3-M04P in 8.7.4 provide
narrower early native/protected checks while full actor/echo evidence stays OPEN.

A debug build or SAFEUPLOAD_ADMISSION_EVIDENCE flag is not enough to exclude an
actor from product delivery. Future selection must exclude all actor surfaces
from product-signed product drivers, irrespective of signing a diagnostic binary.
A remains the smallest future lab-only candidate if its deployment boundary is
explicitly accepted; B additionally needs independent host/permit authority;
C remains rejected. None is selected by this deferral.

| Concrete option | Attack surface / required review disposition |
|---|---|
| A: dedicated `SAFEUPLOAD_T9_METADATA_DIAGNOSTICS=1` artifact; default 0 in every product feature Debug/Release configuration | Compile **all** actor/echo parsers, handlers, state, timers and policy helpers out at 0; product rejects these unknown opcodes with no side effects. Distinct diagnostic artifact/hash delivered only to the authorized disposable lab target, never the product package. Smallest surface and recommended for the current lab. Compile exclusion proves absence in product binaries; delivery control alone cannot prevent someone installing the diagnostic binary on another host. Review must explicitly accept this deployment trust boundary or require B. |
| B: A plus one-boot lab authorization from an independent lab authority | Before exposing the diagnostic handler, require a verified, expiring permit bound to the approved target's independently authenticated machine identity, fresh driver-instance/boot challenge, diagnostic artifact hash and permitted actor/echo operations. Fail closed on missing/stale/replayed/mismatched permit; no registry/env/hostname/port caller assertion suffices. Product still compiles it out. Stronger host restriction but adds permit verification/provisioning/revocation surface. No such independent host-identity/permit source exists in the cited code; exact authority, evidence, verifier/imports and permit ABI need separate acceptance before implementing B. No claim of unforgeable lab identity from a local file or test-signing mode. |
| C: runtime registry/config/test-signing/KD gate in a product binary | Reject for the stated requirement: diagnostic parsers/state remain in product and a privileged local actor could enable them. It supplies neither compile exclusion nor an independent production-host boundary. Not recommended. |

The following is the **deferred proposed actor ABI shared by A/B**, subject to
future choice and source review; no handler is added in increment 3. It adds no product opcode/capability/size. Use the
existing 64-byte control-36 header, resource port only, **diagnostic-only** opcode
`0x80000001` EpochActor and `0x80000002` IssueEcho. At flag 0 these numbers stay
unsupported; no fallback to ordinary requests, growth operation 23 or policy
success. Header cookie/DriverInstance/ControlRequestId and original service
process/token/SID/group checks are identical to real resource controls. No kernel
pointer/token or caller-supplied epoch address crosses the wire.

| Payload | Exact fields / lengths (pack 4, little endian) |
|---|---|
| EpochActor request, **32 bytes** | Action u32@0 (1 Acquire, 2 Query, 3 Release), zero u32@4; ActorId u64@8 (0 on Acquire, returned ID otherwise); HoldTicks u64@16 (Acquire only); zero u64@24. Query/Release require HoldTicks=0. |
| EpochActor reply, **64 bytes** | Result u32@0 (1 acquired, 2 observed, 3 released, 4 expired, 5 refused); State u32@4 (0 none, 1 held, 2 released, 3 expired, 4 revoked); ActorId u64@8; held EpochGeneration u32@16, held Accepting u32@20 (0/1), held ActiveCallbacks u32@24, zero u32@28; RemainingTicks u64@32; MetadataCompletionSequence u64@40; EchoCompletionSequence u64@48; zero[8]@56. No authority fields on refusal. |
| IssueEcho request / reply, **16 / 16 bytes** | Request: ActorId u64@0, nonzero ProbeNonce u64@8. Reply: same pair, meaning queued only; native Busy/refusal emits no successful payload. One outstanding echo/group, no queue. |
| Diagnostic side-port echo request / reply, **32 / 32 bytes** | Magic ASCII `T9MECHO1`@0, ActorId u64@8, ProbeNonce u64@16, driver-issued EchoSequence u64@24. Native Filter Manager message/reply headers are additional, as in the existing transport; exact returned lengths and correlation must match. Identical reply payload, no arbitrary bytes or paths. This is a separate diagnostic message shape, never the 1192-byte resource request parser or an operation-23 result. |

One actor globally per driver instance, bound to this live group; a second
Acquire returns Busy. ActorId is driver-issued nonzero monotonic, never reused
in that instance; retain at most one terminal snapshot until next Acquire or
group drain. Acquire reserves local token/timer/PASSIVE work ownership first,
then calls **real** SafeUploadPolicyAdmissionAcquire (`Policy.c:307`–`:321`),
returning immediately; closed admission returns Retry, not synthetic success.
HoldTicks is a caller-selected finite monotonic interval in 100 ns units, at
most half SAFEUPLOAD_POLICY_DRAIN_TIMEOUT_100NS (`Policy.c:117`, currently
30 s); it is never renewed by Query/echo/retry. This diagnostic maximum does not
change owner-selected O1 or the product drain timeout. The harness separately starts
normal SetPolicy on main; actor never closes/replaces policy itself.

Query snapshots the **held token's epoch** under the epoch's short lock, with
no policy-update wait: its Accepting must be 0 while it still counts an active
callback during normal close/drain (`Policy.c:1155`/`:1169`). Existing status at
`Policy.c:395` observes the **current** epoch and is insufficient proof about
the actor's old draining epoch. Proposed diagnostic-only helpers in Policy.c
must capture that real held generation/Accepting/count without exposing an
address or resetting Unknown/failed-closed state. MetadataCompletionSequence
advances only for successful matched metadata post-completions, not registration
or echoes. Query before/after raw work proves progress while that held epoch
remains closed; normal token release uses `Policy.c:324`–`:335` exactly once.

IssueEcho schedules one independently owned local worker, returns without waiting
for service, and uses FltSendMessage on the paired resource channel with a timeout
no later than actor expiry. A diagnostic receive branch, compiled only in the
diagnostic agent artifact, validates the exact 32-byte magic/group/ID/nonce and
uses the resource receive/reply lifetime and bounded credit ownership of 6.2.
The diagnostic loop may run on the provisional paired group while Commit is
NotReady; this exception is absent from the product receive/parser path.
It neither awaits preceding Ordered work nor uses ordinary credits. Success
increments EchoCompletionSequence only after the driver validates the native
reply/correlation; a queued trigger alone proves no receive/reply progress.
Worker owns its buffer/group/native send until return. Echo uses metadata-send
admission for its short trigger, not the main `_sendGate`; EpochActor has one
separate active/no-queue diagnostic send slot so Release/Query do not depend on
exhausted metadata slots. Neither uses Revoke's dedicated product slot. No lock
spans token acquire/release, native echo send or local rundown waits.

Release, deadline, either-port disconnect, local revoke, instance detach and
unload race to one local terminal owner; that owner releases the real epoch
token even if the service/echo is stuck. Native echo storage still drains through
its own lifetime; no cancellation frees an in-flight buffer. Timer queues
pre-reserved PASSIVE work and holds an image lifetime until actual worker join;
no service ACK, new allocation or policy-update lock is required to release.
No auto-rearm after timeout/revoke. Lost Acquire reply cannot leak an indefinite
hold: timeout/group rundown releases it. Unknown ActorId/nonce, stale group,
wrong channel, flags/nonzero reserved/length mutations refuse. An expiry/revoke
is diagnostic failure, not a passing completion or permission to reopen policy.

**Before any later actor implementation, review must decide:** A's delivery
boundary versus B's independent host permit; accept the diagnostic numbers/layouts, one-actor/echo/send
bounds and half-drain maximum; validate the actual epoch-lock/token/timer/image
lifetime helpers and exact test-only receive branch with implementing source.
ABI/mutation, product-symbol/opcode-absence checks and coherent fixture lifetime
review precede its first boot; routed timeout/cancel/unload tests execute only
after that review, not as impossible pre-implementation prerequisites. Nothing here adds
an actor implementation or silently chooses an option.

**Recorded evidence consequence of deferral:** R3-M01's directly observed
**held-old-epoch raw-metadata progress** and R3-M04's full **SetPolicy + ordinary-
failure saturation + diagnostic side-port echo** subsets stay OPEN to 6.
N-U5-01 can expose real native send serialization early; R3-M04P can expose an
actual legacy CREATE/drain dependency. Neither proves the missing actor-specific
observations. A remaining `_sendGate`/drain integration flaw may still be found
late and require revisiting 3/4/5; report exact early coverage and this residual
risk, not "all progress deferred" or "all progress proved". Real modern growth/
reply remains 6 and real fence/ACK/snapshot 5. Fake sends close none of the native/
protected obligations. Commit activation/qualification needs every retained gate.

#### 8.7.4 Early progress controls without the deferred kernel actor

**N-U5-01 real native gate independence — before-first-boot checkpoint.** After
coherent implemented-source review, run the agent-side
`FilterPort.ResourceSends.cs:152` **HoldLegacySendForTesting** seam against real
connected main/resource handles, the actual FilterSendMessage adapter and actual
RegisterRoot/RegisterChildIntent callbacks. The harness is the authenticated
original service subject; Probe/pair and fixed roots are real, Commit stays
NotReady. Acquire the main EnterSend lease, signal a bounded independent latch
only after `_sendGate` is actually held, then issue valid root registrations,
a child intent and a relative raw metadata open/query/store transaction on the
resource channel. Require exact correlated successful IDs/native results while
the legacy lease remains held; an independent attempted legacy send must remain
blocked until latch release. Reject arbitrary temp-root fixtures, fabricated
handles/native senders and success stubs. Bound the latch and release it in a
finally/independent watchdog on timeout, failure, cancellation or revoke; no
progress being measured can be required to release it.

Repeat with full local metadata admission, kernel transaction/child exhaustion,
malformed/refused tuples, and disconnect during an admitted call (R3-M08/M02).
Assert correct Busy distinction, finite drain and no native buffer/handle release
before return. This demonstrates **real main-send-gate/resource-callback
independence**, including native/adapter lifetime. It does **not** close/drain a
real epoch, prove application-growth progress, prove the actor's held-old-epoch
snapshot, side-port receive/reply echo or stalled ordinary failure-credit proof.
Fake-send `ResourceSendTests.cs:9`–`:49` checks managed admission only and closes
none of these native/protected execution obligations.

This is a real-port kernel component control, **not** the section 8.5 user-native
experiments without a new kernel. It requires the reviewed dormant driver loaded
on a separately authorized native component host; run it after source review
and before the first protected-target VM boot/that delivery checkpoint. No host
load/run is authorized here. If no such reviewed/authorized real host exists,
this obligation remains pending; do not claim a fake transport satisfies it or
perform a kernel load before review to make a pre-boot checkbox green.

**R3-M04P legacy allocation-reply pause — early protected alternative.** Prepare
an agent-only diagnostic fixture for an **existing** legacy/unbound allocation
exchange, without adding any kernel opcode, token owner or modern admission.
StageDispatchEpoch already acquires the CREATE token at
`StageStream.c:11333`–`:11354`; the unbound allocation calls
SafeUploadStageAllocateV19 at `:2752` and the exchange at `StageProtocol.c:965`.
After the allocation result is prepared, pause immediately **before** its actual
reply: `MinifilterInterceptor.cs:657`–`:662` for the typed V19 create reply;
`:666`–`:670` is the separate basename-only legacy branch. Record which branch
and operation is actually routed; do not toggle bound-head NotReady to reach a
branch. Preserve the exact response and normal ownership; no fake allocation,
reply drop, duplicate reply or changed native outcome.

Correlate main cookie/DriverInstance, original RequestId/message ID, CREATE and
prepared result with the pause. Independently start normal SetPolicy and raw
metadata registration/store work through the paired resource path while policy
covers the private roots. Require independent trace/stack observation that the
actual SetPolicy callback **has reached close/drain** (`Policy.c:1155`/`:1169`),
the CREATE exchange remains awaiting this reply, and raw metadata completes in
that interval. A merely outstanding SetPolicy task can be blocked elsewhere and
is not sufficient; missing correlation/blocked-transition observation makes
this case inconclusive/failing, never evidence of a broken cycle. Use reviewed
passive tracing or an independent kernel-debugger observation, not a status RPC
queued behind the held main gate. Existing current-epoch status alone does not
identify the old token's epoch.

The diagnostic-agent pause is one-shot for that exact request, compiled out of
product agent artifacts. Its watchdog/release runs independently of Ordered,
policy send, metadata work and any epoch drain. A source-reviewed finite pause
interval must be **strictly within the remaining minimum of all existing
allocation/exchange, policy drain and caller deadlines**, leaving measured reply/
completion margin; select it in the case configuration, never renew on retry.
The case must identify the actual source timeouts and independently observed
remaining budget/release margin first; an unproved budget is not permission to
insert the pause or lengthen an existing deadline.
Do not substitute the modern 120 s contract for an existing legacy timeout or
change any timeout/threshold. Release on success/failure/cancel/stop and send
exactly the original reply once if the original waiter remains valid; otherwise
follow existing exact lost-reply/cleanup handling and retain uncertainty. An
unexpected deadline expiry fails the positive case and preserves evidence.
After release require the original CREATE/SetPolicy to settle by their existing
contracts, with private bytes/charges and no new readiness grant.

This supplies evidence of **an actual legacy CREATE → allocation reply → epoch
drain dependency plus concurrent raw metadata progress**, stronger than the
synthetic held-send control. It still does **not** furnish the actor's direct
snapshot of its held old epoch, diagnostic side-port echo under all 64 ordinary
failure credits, modern growth/replay or fence/ACK progress. Run only after
review of the actual kernel route/lifetimes and diagnostic-agent pause/release
source, authorized protected/native-host setup and existing delivery gates.
It is an early feedback alternative in increment 3 and retained progress evidence
before qualification, not a prerequisite to writing the substrate. Its exact
coverage cannot be reported as all R3-M01/M04 PASS. The full actor/production
growth cases stay open to increment 6 and fence/ACK/snapshot to increment 5.

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
required-null `ResolutionDelta` and `LegacySource` (both null on a live modern
hot manifest), required-null `OrdinaryDiscardDisposal`, and required-null `ResourceClosure`
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

### 9.3 Every-role owner, durable claim and release contract (U3, revision 8)

The v2 codec validates a claim's representation; it proves no final close.
In the current source, `StagedInspectionSnapshot` owns its writer, read stream
and `ReadLease` duplicates; `StagedTransferPublisher` owns the locked stage and
snapshot lifetime; `StagedHandbackCopier` owns both temporary and duplicated output
handles plus `VerifiedHandbackLease`. `StagedSpaceBudget.EndSnapshot` only drops
a memory lease. These are integration anchors, not already-complete adapters.

**One claim per occupied slot**, included in schema 3's <=64 KiB state, not a
side file or unbounded list: required-null `CustodyClaim` with exact properties
`{ClaimId GUID, OwnerEpoch GUID, Slot u32, Incarnation i64, ClaimRevision i64,
Kind u32, State u32, Identity (nullable identity[24]), RetirementWitnessId
(nullable GUID)}`. Kind=1 CreateCopy, 2 FreezeMeasure, 3 Dispose, 4 Promote;
State=1 Prepared, 2 MayHaveIssued, 3 NativeComplete, 4 Drained. IDs nonempty,
slot 0..3, incarnation/revision positive; owner epoch identifies the actual
service lifetime, never a reusable PID. Identity is null only before capture;
NativeComplete/Drained require it except proved non-creation. Completion carries
the identical claim/slot/incarnation and expected **current** R; an intervening
unrelated R change requires revalidation and a new commit against that R, never
applying an old whole-record snapshot. At most four claims, one exclusive
mutator/closer per slot; each owns a checked refcount of all its issued native
operations, handle duplicates and parser readers. Each content adapter must
pre-admit its readers/operations within the existing qualified extraction/worker
limits; the claim is no authority to spawn unbounded parser work. No bare handle escapes this
owner. No agent-created sections or cross-process duplicate of these content
handles is allowed by this adapter. A path is only a bounded locator.

Persist Prepared and the reservation before issuing anything; persist
MayHaveIssued before create/copy/delete/rename. Capture identity before content
writes. NativeComplete records a known successful mutation and its exact result;
Drained requires all operation completions and handle/reader/section owners
accounted for, including cancellation completion. Cancel/requested shutdown,
a returned Task, Dispose of one wrapper and lease-count zero alone prove neither
native completion nor storage release. FreezeMeasure revokes **all** mutation
rights, drains writers, flushes, queries EOF/allocation on the exact held object,
then closes mutation handles before accepting Immutable. Partial-copy cleanup
keeps ReservedMax; it cannot manufacture that measurement transition.

| Role / sole coordination owner | Owners included before Drained / permitted persisted release |
|---|---|
| Original Stage / kernel stream retirement plus agent cleanup claim | Kernel upper FILE_OBJECT/handles, writable sections/cache, paging rundown, growth workers/waiters/adoption and backing mutation handles; agent publisher stage read, seed/copy source and disposal handles. Stage-write retirement proves only kernel mutation drain and immutable measurements. Storage release additionally requires exact stage disposal, zero remaining agent/native owners and final-close/absence proof; retain original StageRelease across reuse. No agent claim can clear kernel Unknown. |
| Snapshot / `StagedInspectionSnapshot` lifetime owner | Copy writer, primary read stream, every parser `ReadLease` duplicate and active read/copy/hash operation. Await actual parser reader disposal, including a parser ignoring cancellation. After final delete-on-close handle closes, establish final storage release for the captured object; otherwise remain ImmutableReleasePending at measured allocation. Never use EndSnapshot or name absence alone. |
| PublicationTemporary / publisher's exact output transaction | Output writer, metadata/security application, publication permit/driver operation pins, verification and retry handles. Failed uncommitted output: close mutation/operation owners then exact delete with final release proof. Known successful promotion: persist NativeComplete with existing publication receipt and exact output/destination generation, finish bookkeeping once; **no physical-release receipt**. Until O3 is selected retain the slot/charge; never delete the public object for budget cleanup. |
| Handback / copier's exact output transaction | Original temporary handle, duplicated output stream, verifier/reopen handles and every `VerifiedHandbackLease`. Failure: exact private temporary disposal after drain. Successful no-replace rename plus authorized export: NativeComplete and existing journal result once; retained public file is not absent/deleted. O3 controls any accounting transfer. Existing seed read/export policy and caller SID/owner/DACL/SACL/label checks still apply. |
| Any deletion-pending object in one of these roles | The role/slot/incarnation survives unlink. Every owner above remains included; never relabel it as a free fifth slot. Unknown extra handle/section/native outcome retains the conservative charge and diagnostic. |

**Release commit:** after the role's proof, journal serialization (where needed)
precedes budget claim; content work always runs outside both. Persist the typed
NeverIssued/DefinitiveNonCreation or FinalStorageRelease/ExactAbsenceAfterDrain
witness, same K/slot/incarnation/claim revision, StageRelease if applicable,
new inventory and derived debit in one budget transition **before** memory
adoption/reuse. Ordinary Discarded additionally follows 9.2's manifest-first
receipt; restart joins that receipt to the exact budget claim. A known successful
mutation is never issued twice. No schema-3 kind for public custody transfer is
selected here; O3 must settle its accounting meaning before its codec/consumer.
A promoted slot remains occupied/charged and cannot enter MetadataOnly merely
because its private name disappeared. If user activity can change it after
promotion, retain FullDebitHeld; do not claim a bounded immutable allocation or
silently delete/alter that public file. This exposes an O3 integration stop,
not a supported indefinitely bounded public-file accounting mechanism.

| Crash / uncertainty | Recovery and retained charge |
|---|---|
| Prepared; native issue excluded by closed claim | Prove NeverIssued, persist release; no existence scan substitutes for the issue fence. |
| MayHaveIssued, identity not captured | Close/fence all issuers and creation authority; definitive native non-creation may release. Otherwise hold ReservedMax, preserve any residue, no pathname adoption or blind second create. |
| Captured mutable copy, cancellation/crash before freeze | Retain ReservedMax; rejoin exact identity, close mutation owners, dispose exactly or remain held. Service restart alone does not prove other processes/driver owners drained. |
| Freeze/retirement receipt lost | Retain preceding/full debit; recover exact retained receipt or repeat only a safe query/drain proof, never infer it from EOF or a hash. |
| Exact delete native success, release persistence lost | Preserve charge, complete from exact claim plus all-owner drain/final-release witness; do not issue another successful delete against the name. If witness cannot be recovered, hold until a valid lifetime boundary, including reboot where required. |
| Release durable, memory totals/reuse not done | Reconstruct the same transition once. Duplicate completion is no-op; stale incarnation/claim refuses. |
| Public rename succeeded, reply/journal completion lost | Existing exact-object publication/export recovery finishes bookkeeping; no second copy/rename/public mutation. Retain charge until O3's approved transfer or actual release proof. |
| Metadata current/new/predecessor/candidate/segment unlinked | `StagedMetadataStore.Transaction` owns output/predecessor handles, accounting pins and active operation; journal/archive owns candidate/segment readers. Persist exact MetadataStorageTransition only after all drain. Class-65 unlink/selection/F2/normalization alone refunds nothing. Store Dispose only closes owners; it cannot persist a refund. After ledger deletion, shared append/compaction evidence owns these transitions. |

On restart reconstruct every unresolved claim before admission. OS-verified
termination can close only the dead service's exclusive process-local handles;
it is not evidence about kernel stage sections, other live processes or an
uncaptured object. A missing lifetime proof retains charge. Sticky Unknown
remains until reboot; no timer, scan, forced deletion or digest can discharge it.
Reboot permits fresh validated lifetime reconciliation, never invents identity,
publication completion or lost accounting evidence. MarkerCurrent is never an ordinary cleanup target; legacy security/negative
objects retain their existing permissions/proofs. Current/new ledgers, manifests,
companions and intents retain each exact predecessor/replacement until persisted
identity-bound release. Role/native/source coverage
is required by R5-S04/S05; pure release models prove only the transition rules.

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
KiB. Kinds 1–3 below and revision-8 migration-only kind 4 (10.6) use the same
frame grammar in section 10.3. All envelopes also require LegacySource (10.5).

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

Migration-only LegacyHistory kind 4 and compatible legacy-hot duplicates follow
10.6; they never acquire modern custody or initial debt. Modern archive indexing
distinguishes **RecordId** from TransferId. Duplicate
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

For **each** output keep L (logical bytes), P=AlignUp(L,A) (padded extent),
Q=AlignUp(P,U) (**nominal geometric precharge**), and retained physical R_phys
from section 8.4. Precharge Q before issue, then request FileAllocationInformation
for P/full target extent and measure before writes. Current/new/predecessor/
failed residue are additive **R_phys**, not blindly Q; record and raise the debit
to max(previous retained charge, Q, rounded observed allocation) before any
overrun Held. These geometry calculations are conditional on the qualified
preallocated (or separately qualified whole-extent one-call) mechanism keeping
allocation within Q. The builder's unpreallocated chunks disprove a universal
Q ceiling; a geometric proof does not constrain NTFS allocation policy.

Round(logical EOF,U) remains an invalid pre-write charge when A>U, and the
logical-EOF mutant still fails nominal conservation/admission. That mutant's
failure is not a physical-allocation bound proof. Failed/unknown native outcomes
retain max(Q, larger observed peak) for that object plus all exact residue; lower
allocation after EOF normalization does not refund that peak. Only a separately
persisted exact measurement/release transition after required barriers and
closed mutation/operation/handle custody can reduce retained charge. A held
predecessor with measured Links=0/DeletePending=True after class-65/flags-3
success cannot be reduced from one observer closing.

**Nominal** simultaneous base overlap is journal J=3*Q(128 KiB,A,U), other
B=2*Q(64 KiB,A,U)+2*Q(192,A,U). Existing envelope M=max(1 MiB,16*U) and halves
remain unchanged. The independent A/U cross-product (A=4096..65536,
U=512..1048576, powers of two) has **60 pairs**; computed maximum (J+B)/M is
**62.5%**. Within that domain the **nominal geometry** fits each half, subject
to the preallocation/within-Q precondition. It is not a bound on arbitrary native
extensions or measured retained inventory. Actual admission sums R_phys,
predecessor pins and every failed residue; any observed excess is charged before
Held, with no larger implicit budget or physical-segment permission:

| A | U | nominal journal J | nominal other B | nominal sum Q | existing envelope M |
|---|---|---|---|---|---|
| 65536 | 512 or 4096 | 393216 (384 KiB) | 262144 (256 KiB) | 655360 (640 KiB) | 1048576 (1 MiB) |
| 65536 | 65536 | 393216 | 262144 | 655360 | 1048576 |
| 65536 | 1048576 | 3145728 (3 MiB) | 4194304 (4 MiB) | 7340032 (7 MiB) | 16777216 (16 MiB) |

Residue is **additional R_phys**, not included free in the nominal table. At A=65536,
U=4096 a fourth nominal-within-Q 128 KiB journal output fills the 512 KiB half;
another must refuse until exact release, even if aggregate M has space. A
predecessor explicitly measured at 4096 plus a new 192-byte replacement and
failed 128-byte residue **if within their nominal Q** totals
4096+65536+65536=135168 bytes; without that predecessor measurement the nominal
three-object sum is 196608 bytes. Any larger observed allocation increases those
retained totals before Held; these example numbers are not maximum NTFS peaks.
Neither retry nor failed handoff adds another reservation envelope for the same transfer.
Native units outside tested vectors require checked recomputation/experiment,
not a borrowed proof from U=A.

Shared controls separately precharge **nominal** padded Q (with the same
preallocation precondition and later additive R_phys): four 64 KiB intent outputs
(current/new append and compaction), four 128-byte inventory/marker outputs and
one 128 KiB candidate. At A=65536, U=512/4096 their nominal sum is **655360 bytes**; logical-only rounding would incorrectly report 409600 at
U=4096, or 395264 at U=512. At U=1048576 it is nine units =9 MiB.
Compaction counts old + new up to 32 admitted 4 MiB segments each,
including both frontier slots, plus all residue and retained R_phys. Never clamp
an unexpected observation to 4 MiB: charge it and hold, without increasing the
segment/admission limit. Shared debit is still 2*rounded retained physical
inventory +16 MiB. Selecting a replacement never releases old
physical allocation before exact owner/storage release.

The pure fit models exercise **nominal** independent L/P/Q vectors, conservation rejection
of logical-only charge, exact measurement/release transitions, boundary/overflow,
combined-envelope refusal/fit and source/target ranges. ACK tests now execute
bounded 2-active/8-retained scheduling with Busy retry; snapshot reconciliation
uses independent durable/snapshot inputs including unknown, missing-pending,
duplicate and unauthenticated entries. Header/frontier mutants test actual
occupied byte-range overlap/overrun, not constant-equality assertions. These
remain **pure** models: no claim of actual send scheduling, native snapshots,
JSON codec validation, preservation of base/delta witnesses, or migration capacity.
Those are retained increment-4/5 consumer tests. They do not model every NTFS
extension policy or prove preallocation effective. The worker's raise-before-fault
R_phys/pin controls are separate from the fit arithmetic. Only exact native
experiments can verify observed allocation boundaries, and the recorded builder
vectors are not a universal ceiling. No model closes native durability or target
preflight/qualification.

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
EOF and every frame start/end are multiples of A, with the existing **4 MiB
admitted extent/EOF and physical-segment limit unchanged**. Native AllocationSize
is measured independently: retain any excess as R_phys and Hold, never silently
increase that limit or describe a 4 MiB EOF as proof of 4 MiB physical use.
No new sector/cluster product default: A is a verified physical requirement.
A/identity are persisted in the append intent and both frontier slots; disagreement
holds. Legacy 4096-byte frontier area is not reused for this grammar.

Modern frame header remains **60 bytes**: magic u32@0 (existing ArchiveMagic),
Version=3 u32@4, PayloadLength u32@8 (1..128 KiB), **RecordId** GUID@12,
SHA256(payload)[32]@28. Payload begins at +60. **Stride=AlignUp(60+PayloadLength,A)**;
all bytes through stride end after payload are zero and validated. Next frame
starts exactly at previous+Stride. Production **preallocates and measures the
full claimed target extent before initial frame/slot writes or append extension**,
then issues aligned bytes, including zero padding, within that extent. One-call
whole-extent versus preallocated full-sector chunks require separate experiments;
a single frame write at a nonzero offset is not automatically the same allocation
mechanism as a single whole-output write. Unpreallocated chunked extension is
not a permitted equivalent merely because its sectors are disjoint.
A frame ending at logical `60+payload` is not the physical EOF.
No append ever rewrites a sector belonging to an earlier committed frame.

Each frontier slot is an A-byte aligned record: magic ASCII `SAFEND03`@0,
u32 Version=3@8, HeaderBytes=128@12, InstallationId GUID@16,
SegmentIdentity[24]@32, u32 A@56, SlotIndex@60 (0/1),
u64 Sequence@64, committed physical End@72, LastAppendTransactionId GUID@80,
SHA256(slot bytes [0,96))[32]@96, zero bytes [128,A). Initialize slot 0 with
sequence 1/end=2*A/transaction zero and slot 1 all zero **after precharging and
requesting allocation=2*A**. Query before writing and after each initial slot
write/F1/EOF/F2, including failures and before normalization; record exact segment
identity and retained R_phys before any nonzero frame. A builder preallocated
8192-byte initial append stayed at 8192; it is a vector, not a general proof.
Subsequent commits write the **inactive** slot with sequence+1, new end and transaction ID,
then flush; never overwrite the last selected valid slot. Validate length,
identity/alignment, zero padding, hash and sequence. Do not assume atomic sector
writes, that a valid hash authenticates a content object, or that a torn newer
slot means its append did not happen. Recover via append.intent below.

Per append, after Prepared+intent are durable and expected frontier is rechecked:
(0) reserve the delta needed to charge the segment at max(current R_phys,
Q(TargetFrontier)), plus independently retained **different-object** predecessor/
residue inventory; request **FileAllocationInformation for the full
TargetFrontier**, query identity/EOF/allocation, stop before writing on failed/
unknown preallocation or observed overrun, retaining raised R_phys;
(1) write frame at ExpectedFrontier without touching preceding sectors, querying
allocation after each native call (including failed writes);
(2) **F1 flush** frame data; (3) set EOF to TargetFrontier (monotonic, aligned,
within claim); (4) **F2 flush after EOF**; re-read/verify identity/frame/aligned
EOF and independent AllocationSize/R_phys; (5) write inactive frontier slot with
recorded target sequence/end/ID;
(6) **F3 flush frontier**; commit any required new-segment inventory via its own
post-EOF/replacement barriers; only then report SharedCommitted and delete
candidate/intent/ledger by exact custody. FrameDurable denotes completed F2,
not merely a successful WriteFile return. Query allocation at F1/EOF/F2/slot/F3
and every failure boundary; retain each measured high-water charge before Held.
No later EOF normalization hides an earlier overrun. Uncertain F1/F2/F3 keeps
the intent, all retained physical charge and admission hold. Native execution and the documented guarantee limits
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

This is the format/transaction choice for compaction; revision 8 adds the pure
U8 migration/selection/serializer models in 10.5/10.6, pending independent review.
Actual consumers still require matching codec/model controls before use, and U4
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
| Marker and every local witness erased/rolled back | outside M2 under decided O2: SYSTEM/administrators are trusted; no erasure/rollback detection guarantee. Stronger anchoring is separately reviewed post-M2 work |

Startup classifies marker, typed hot candidates/global append intent, legacy and
modern archive formats and resolution chains **before** blanket constructor
checks. Accounting-disabled startup refuses any modern evidence even without a
transfer ledger. A missing marker never relabels modern history as legacy.
`StagedSpaceBudget.cs:662` and `StagedSpaceUpgrade.cs:12` are existing selected
shared-accounting mechanisms, not these new typed/tail/delta contracts. R4-H01
must test binding-null bases, normal-success count retirement, ACK after ledger
deletion, append outside frontier, interrupted F2/F3, torn alternate slot and
unaligned logical frame lengths. R4-H02/H03 retain downgrade/marker tests.

### 10.5 Strict codecs, candidate/frontier selector and byte limits (U8)

This section fills the representation/selection gaps; 10.2/10.3's existing
append and crash rules are not relaxed. `GrowthArchiveContractModelTests.cs`
is a pure reference model using actual .NET UTF-8 JSON serialization and byte
buffers, with no production codec, file/port I/O or native lifetime claims.

**Strict JSON boundary:** reject BOM, invalid UTF-8, comments, trailing commas,
extra root values/non-whitespace bytes, depth >16, duplicate properties at every depth (including
escaped aliases), unknown/missing properties, noncanonical GUID/Base64/hex,
fractional/exponent/string encodings of integers, overflow and unknown enums.
Nullable properties are present explicitly as null; null is not an empty object.
GUID JSON strings use lowercase `D`; leaves use lowercase `N`; SHA256 is uppercase
hex. u64 accepts 0..18446744073709551615, signed-positive revisions never wrap.
Normalize only validated new values when writing, never repair hostile evidence.
Schema-3 identity JSON uses the codec's exact unsigned `VolumeSerialNumber`,
`FileIdHigh`, `FileIdLow` properties (wire identity remains low-before-high).
Historical receipts validate exact saved bytes/correlation without a new clock.

For **new** envelope writes use compact `Utf8JsonWriter`, default escaping
(`JavaScriptEncoder.Default`), no BOM/indentation, the following property order:
`FormatVersion, ResourceSchema, InstallationId, RecordKind, RecordId, TransferId,
RecordRevision, PreviousRecordId, Entry, ResourceClosure, OrdinaryDiscardDisposal,
ResolutionDelta, LegacySource`. The first twelve properties retain 10.2's
semantics; `LegacySource` is required-null on kinds 1–3 and required on the new
migration-only kind 4 below. Readers accept property order variation but check
exact schemas. Identity-bearing duplicate records/candidates compare their saved
**exact canonical writer bytes**, not reserialized object equality. No changed
bytes under one RecordId, even equivalent JSON. Nested Entry retains its existing
strict journal schema; ResourceClosure is complete strict schema 3, <=64 KiB,
HistoryHandoff=null. No v2 passive record is relabelled schema 3. The reference
model isolates envelope byte costs and chain semantics; it is not that full codec.

| Serialized item / measured UTF-8 bytes before native create | Bound / failure |
|---|---|
| OriginalRequest / ACK request / ACK reply | 1192 / 1272 / 72 decoded bytes; canonical Base64 **1592 / 1696 / 96** characters. Exact equality after round-trip, no whitespace or alternate pad bits. |
| Modern ledger / append.intent / compaction.intent | Each <=**65536**, depth <=16, including every property, array, witness, creation/release claim, escape and .NET writer output. Four slots/claims, one companion transaction, one bounded latest replay, <=32 sources/targets; no per-growth list. Serialization exhaustion preserves prior state/charge and holds the transition. |
| Envelope, candidate, frame payload, modern manifest | Each <=**131072** actual bytes; Entry<=131072, closure<=65536, wrapper W<=8192 and **E+S+W<=131072**. E/S are exact encoded nested values (null is four bytes), W is actual remainder, including receipt/delta/LegacySource and keys. At independent E/S/W maxima 204800 bytes, refuse handoff and keep ledger. No truncation/receipt omission. |
| Identity/slot/intent counters and leaves | Three full u64 identity words, positive i64 revision/generation/incarnation, checked arithmetic; candidate leaf exactly `<RecordId:N>.resource` (**41 ASCII bytes**), no separators, ADS, NUL or alternative case/spelling. Segment leaf remains eight uppercase hex digits plus `.pack`; segment numbers positive u32, no overflow when allocating successors. |
| Binary ABI | Header 64; request 1192; result 352/outer reply 376; negotiation 96/112; companion 192; marker/inventory 128; frame header 60; frontier header 128 in each A-byte slot; ShellSnapshot payload 9888. No size changes in revision 8. |

Measure serialized **bytes**, not .NET string.Length or an estimated field sum.
For example a 512-character string of U+0001 takes 3072 bytes of escaped payload
inside JSON quotes. A 1592-character Base64 value can cost extra under default
escaping (notably `+`); measure the actual writer, including request/reply fields.
The 8 KiB W allowance is a rejection bound, never a proof every legal combination
fits. Serialize/validate into bounded scratch first; a crossing writer stops at
limit+1, retains original evidence and creates no candidate. This is a metadata
handoff bound, not a modern content-size cap or new publication verdict.

**Actual serializer limitation:** there is currently no product schema-3
closure/envelope, candidate or migration serializer at HEAD `7c3ab3e5`.
Existing `ResourceStateCodecV2.MaximumBytes=65536` and
`StagedJournalFile.MaximumManifestBytes=131072` validate their own formats only.
The independent model executes real writer boundaries/escaping, full ACK byte
strings and 32-source/32-target control records. The prerequisite actual schema-3 serializer/transition proof remains **OPEN
before coding increment 4** (8.6/12.1.3); the pure model does not defer or close
it. As each new increment-4 record is implemented, before its first use its
**actual production serializer+strict reader** must
pass the same vectors plus complete maximal Entry/closure/claim/replay shapes,
including shared control replacements and rejection-before-create at limit+1.
No assertion of a full schema-3 maximum is made from a surrogate string model.
Depth is measured on the whole envelope: nesting a depth-16 closure can exceed
the envelope depth and must refuse before create as well. A valid record that
cannot be stored stays charged/held; if ordinary worst-case
records cannot progress, stop for a reviewed format split, no cap removal.

**Candidate selector:** classify by persisted role and exact RecordId, then
verify exact captured identity, InstallationId, length, SHA256, canonical bytes,
kind/revision/base eligibility and matching immutable append intent. A path/hash
alone authorizes nothing. ReservedNotIssued and CreationMayHaveStarted cannot
supply Prepared bytes; CandidateCaptured means identity persisted before write,
not immutable bytes. Prepared requires complete F2-verified candidate and exact
segment/old-frontier claim. Duplicate ledger/global intent copies must agree.
Unknown/missing candidate with unfinished intent holds. If SharedCommitted is
proved and the recorded exact candidate deletion already completed, recover only
bookkeeping from the exact committed frame; candidate absence alone is no proof.

**Deterministic slot/tail selection:** validate both A-byte slots completely
before selecting any end. Sequence 1 uses slot 0/end=2*A/zero transaction; sequence
n uses slot `(n-1)%2`. Slot 1 all-zero is legal only with that exact initial slot 0.
Two valid slots must be consecutive sequences, increasing ends, distinct nonzero
append transaction IDs after initialization and the same installation/identity/A;
the higher sequence selects. Same-sequence forks/gaps/parity failures hold.
Any invalid nonzero inactive slot requires the exact append intent; never merely
pick the older valid slot. With one old valid slot + intent, expected sequence/end
must match; with target selected + intent, the other valid slot must match expected.
EOF is aligned, >=selected end, <=4 MiB; no silent EOF normalization of an unknown
tail. Preallocated AllocationSize beyond EOF is retained R_phys, not a frame.

Walk exact strides from 2*A to selected end: version=3, magic=0x414A5553,
payload 1..131072, exact header RecordId=payload RecordId, payload hash, zero
padding and checked aligned end within selected frontier/4 MiB. Never scan for
magic or skip malformed frames. Bytes beyond the selected end require the one
matching intent/identity/offset/target sequence and candidate. Full exact frame
and no extra tail: reestablish F1/EOF/F2 then frontier only. No issued bytes:
issue once after fencing old native work. Partial/mismatched tail: retain charged
residue/Held. Unknown extra tail, both slots invalid or identity mismatch: Held.
A torn target slot with full exact frame permits inactive-slot repair only.
Repeated interruption of recovery does not add an append or replay native success.
This model deliberately does not simulate native allocation policy/durability.

**Chain/selection:** collect selected frames and compatible hot/candidate copies
before projecting. Byte-identical RecordId duplicates coalesce; changed duplicates
hold. Exactly one base (kind 1 or 2) per modern TransferId, optional one kind-3
delta from CleanupComplete only, exact PreviousRecordId, revision+1, original
request/FenceId/cookie and authenticated recorded ACK correlation. An
InitialResolved or already-acknowledged base accepts no delta; no orphan/fork,
gap, changed base, namespace mutation or second ACK revision. Resource-only
bases never enter namespace indexes. Compaction compares the **complete mapping
RecordId -> exact bytes**, plus each reconstructed resolution state/count and
allocation/effective-generation high-water barrier, before and after copying.
Arrival order may differ, including delta before base. Numeric consecutive
segment ranges without that semantic equivalence cannot select away sources.
Retain all witnesses, even count-zero/old-generation records; no semantic pruning.
Persisted selection alone releases no physical allocation; exact old-source
storage-release transitions must follow selection. Failed/unselected outputs
and pinned predecessors stay additional R_phys.

### 10.6 Legacy migration and mixed selected ranges (U8)

The legacy reader keeps its Version=1 inventory, 4096-byte control area,
48-byte frontier (SUAC/version1/end/hash[0,16)), and contiguous
60-byte SUJA/version1/TransferId/payload-hash frames. Under modern startup it
runs **read-only**, before any legacy tail repair. Validate complete committed
prefix, identity/security, inventory count and matching hot entries. Unknown
legacy tail/extra segment/temporary output remains charged and holds migration;
existing v1-only startup behavior outside modern mode is unchanged. No current
modern transfer is invented from legacy identity-unknown absence.

Add **RecordKind=4 LegacyHistory**, migration-only: Entry is the validated
original terminal v1 journal payload, ResourceClosure/OrdinaryDiscardDisposal/
ResolutionDelta/PreviousRecordId are null; revision=1. `LegacySource` is exactly
`{InventoryIdentity, SegmentIdentity, FrameOffset i64, PayloadLength u32,
PayloadSha256 (64 uppercase hex)}`. TransferId equals the original header/Entry.
RecordId is freshly allocated **once in the durable migration intent before
copy**; recovery reuses it. One legacy TransferId base, no ACK delta and no modern
initial debt; preserve original namespace/generation/epoch/security witnesses,
never synthesize modern closure/release authority. If wrapping the full original
Entry exceeds 128 KiB or W exceeds 8 KiB, keep the legacy source selected and
charged with an actionable migration-too-large diagnostic. No lossy conversion.
All frame versions/layouts and binary inventory size stay unchanged.

Use the existing single serialized compaction transaction; no external append or
second migration. An append.intent owned by that compaction is its sole nested
copy subtransaction, never an independent append; CompactionTransactionId must
match before issue/recovery. This is an explicit exception to 10.3's no-unresolved-
append-at-compaction-start rule only after that compaction has started. Extend its proposed strict schema with required
`SourceInventoryFormat` (1 legacy,3 modern), required-null
`ExpectedLegacyInventory` (`{Identity, EndOfFile i64, Sha256 (64 uppercase hex),
Version u32=1, SegmentCount u32}`; count <=2147483647 from the legacy reader),
`ExpectedInventoryBytes` (canonical 128-byte Base64 only for modern), and per
source `Format`=1/3. Required-null `MigrationCursor` is
`{SourceIndex u32, FrameOffset i64, RecordId GUID, TargetIndex u32, Phase u32}`
only during legacy conversion: indices 0..31 into frozen Sources/Targets,
offset at an exact source frame start; nonempty RecordId assigned before candidate
creation; Phase=1 Prepared, 2 FrameCommitted. Append intent also adds required-null
`CompactionTransactionId` and `LegacySource` (same exact 10.6 tuple); these are
null on unrelated appends. No next cursor/candidate until the prior frame is
F3-committed and its assignment is recoverable from that target frame.
Target CreationPhase is exactly 1 ReservedNotIssued, 2 CreationMayHaveStarted,
3 IdentityCaptured, 4 Committed; identity is required only in 3/4. Legacy source
FrontierSequence is null; End is its validated committed
frontier. Mixed modern inventory may select untouched read-only legacy suffix
segments plus newly aligned modern targets. A Source Format must match its
actual held header/frontier; no decoder fallback on parse failure. Classify
before old inventory constructors, as required by 10.4.

Legacy source-to-RecordId assignments must also be bounded: stage **one** converted
candidate at a time using append.intent and the same captured source frame tuple;
the committed target frame becomes the retained assignment when advancing to the
next frame. Compaction Sources/Targets remain <=32 each; do not put every frame
mapping into the <=64 KiB intent. Before any copy, stream a read-only size pass
over the selected prefix; if <=32 targets at <=4 MiB cannot contain every wrapped
record/stride/frontier, refuse that prefix and choose a smaller prefix, or hold
one unrepresentable source. Even one old densely packed source can expand past
32 targets under aligned framing; that case holds with its sources intact.
Do not claim universal legacy migration progress from this bounded proposal;
a reviewed format/streaming migration delta is required if real supported
records hit that stop. Peak old+new+candidate/control/replacement/residue
charge must fit **before create**; selection never anticipates source release.
A complete captured candidate/target frame survives interruption before advancing
its cursor; recovery finds the assignment by exact source tuple, not a fresh GUID.

The four-total-child credit contract in 8.7.2 still applies. Read one source frame
then close its source handle; create/F2-close the candidate; close durable control
replacement handles before opening the next group. Append can hold candidate,
segment, current append intent and its one replacement, at most four; compaction
control is closed during that group. Inventory selection holds only old/new
inventory and compaction control as needed, after segment readers close. Reopen
only against persisted full identity/security and expected bytes; closing a
handle never releases that object's physical debit. No 32-source handle set or
five-handle source+candidate+segment+both-controls sequence is permitted.
All these operations use NonGrowth purpose; no migration work takes Growth pool
credits or acquires journal serialization from the budget gate.

The migration uses compaction Prepared/Copied/Selected/CleanupComplete phases.
Prepared records exact source identities/frontiers and frozen old inventory;
all new targets have persisted preidentity creation claims. Copied requires full
exact target durability plus preservation of every source record and barrier.
For modern sources compare RecordId/exact bytes. For legacy sources compare
the complete injective mapping from the captured source identity/offset/length/
hash to kind-4 LegacySource and exact original Entry bytes, then compare both
namespace generation indexes. Every source has exactly one target assignment;
no unreferenced/changed/duplicate assignment. Compatible v1 hot duplicates may
coalesce only after the existing full Entry validation/equality and the exact
source Entry bytes are proved; a changed legacy hot/packed pair holds. No hot
legacy manifest is relabelled as modern schema-3 custody. A source hash validates bytes only
after the held identity/security and frozen inventory match.
Replace legacy inventory by the 128-byte modern inventory (or replace its modern
predecessor) only after that proof, using 8.4's exact held class-65/flags-3/F3
sequence. First selection has InventoryRevision=1/Previous=0; later selections
increment exactly once. FirstSelected skips precisely the copied old prefix,
and end includes consecutive targets after the old end. Retain old inventory
predecessor until its exact storage-release proof; hash is only byte validation,
never permission to replace an unknown object. Legacy preflight outside budget/admission may bounded-read inventory at its
existing <=4 MiB legacy-reader limit. Modern metadata InventoryCurrent still
allows only 128 bytes: an oversized/non-strict legacy inventory is preserved
and **holds modern migration**, never read/replaced through widened permissions.
Its raw Base64 bytes are **not** embedded into a <=64 KiB intent; retain its
exact identity/EOF/hash and strict Version/SegmentCount. A changed/unknown predecessor holds both classes.

Before selection, old sources remain authoritative; after exact new inventory
selection, targets plus untouched suffix are authoritative. Native replacement
success with lost completion finishes inventory/Selected bookkeeping only.
Source deletion starts only after durable selection and all source readers drain;
repeated recovery cannot delete a same-named replacement or release twice.
Missing selected suffix, missing copied base/ACK/witness, duplicate changed legacy
TransferId or inconsistent hot/packed record holds. Candidate/copy/select/delete
faults retain old+new/residue charge; this is not a rewrite/prune license.
Controls R4-H04/H05, R5-S04 and N-U8-02/03 retain their source/native obligations.

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
behind an MM growth owner. Paging does not enter owned nonpaging admission or initiate growth: the
paging bridge retains/releases its separate PagingRundown and child/partial-MDL
owner. Completion/release minors for already admitted **nonpaging** work do not
enter new admission: they find/release their original counted callback/MDL owner. They cannot be rejected or queued behind a full admission pool; U6
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
| T9 increment 2 | Landed `272a33d1`: bounded lanes/legacy FIFO and failure replies, no growth handler. U5's accepted two-direction progress **contracts** precede dependent substrate coding; implemented native progress does not. Source/lifetime review and subsequent real native/protected execution are separate pending obligations, not closed by fake-send tests. |
| T9 increment 3 | **Provisional metadata substrate** (8.6): authenticated fixed-root capture, 8.7.1 separate security predicates, 8.7.2 Busy-preserving registration and 8+8 pools/four-total-child credits; outer pre/post, opaque bounded native store, nominal precharge + preallocation/measured R_phys accounting and lifetimes, no schema-3 consumer. Commit NotReady. Actor/echo **deferred to 6** independently of pools; prepare early N-U5-01 and R3-M04P under 8.7.4's gates. Partial `88d7850b` pairing/auth/revoke/dispatch is not registration/maps/routing completion. Class-65/flags-3 and preallocation selection follows 8.4 builder evidence; strict corrected reruns/full matrix and target N-U4-06 remain open. No growth/fence/selector consumer or fake-test execution credit. |
| T9 increment 4 | After 1–3; integrate custody/reduction, stage-write retirement producer, modern startup/shared history/marker and ordinary Discarded receipt, all release adapters (sections 3/9/10). R5/R4-H/R3-X controls prove reserve-before-create and exact reduction/release. Still no growable admission. |
| T9 increment 5 | After 1–4; modern initial allocation and 120 s issuance-to-adoption/fence/recovery (sections 5/6), exact replay no reseed/double debit; lost identity/reply self-heals same name. R3-A/R4-D01; pre-boot CREATE/adoption review. Small-window production remains gated pending 6. |
| T9 increment 6 | After 1–5 and implementation of approved O1 (3 s per I/O); end-to-end ledger→companion→reply/adoption, semantic replay and **every MM path** (sections 3/4/7/11). R3-G/C, R4-D02/MM; coherent growth/MM security/lifetime/lock-order review before first boot. |
| T9 increment 7 | After 1–6; audit modern cap replacement/computed readiness; decouple minimum window from legacy seed-cap symbol (`StagedTransferAllocator.cs:17`, `StagedSpaceBudget.cs:34`). Preserve STAGE_LEGACY_CAPACITY and bound-head gates. Complete harnesses, regressions, matched-pair qualification and final independent adversarial milestone review. Cutover separate. |

Ordinary implementation stays with the primary agent. Independent design review
and changed-kernel lifetime/lock-order/security review precede first boot. Every
agent delivery checkpoint needs full feature Debug/Release × user/SYSTEM
discovery/execution (no skips); every changed kernel needs both WDK builds,
PREfast/ApiValidator zero warnings/errors and both imports PASS, plus required
Verifier. Harness changes need PowerShell **5.1** parse/native signatures,
self-checks and an authorized real run. Committed source/fresh labels/matched
artifact hashes are delivery obligations for the orchestrator; this document/pure-model revision
performs no Windows delivery gate or kernel boot. No new source-freeze/disposition framework.

### 12.1.1 Three separate review/delivery stages

Contract acceptance, implemented first-boot review and runtime evidence are
separate. The re-review closed the original F1/F2/F3/F5/F7 **design defects**;
its residual 1–3 and this revision need independent acceptance. Do not require
R3-M01/M04 diagnostic protected execution before increment 3 is written, or
production-growth assertions before increment 6 exists. The table lists
coverage now; results follow implemented source and first-boot review. Accepted
progress contracts permit coding dormant infrastructure; fake/native/protected
results cannot substitute for each other. N-U5-01 is an after-source-review real
component-host control before protected-target first boot, not a test requiring
unreviewed kernel loading. R3-M04P needs its own reviewed protected/native setup.

| Integration | Contract/fact required before implementation | Implemented source required before its first boot | Runtime/component evidence after implementation |
|---|---|---|---|
| T9 increment 3 | **Before-coding:** accepted U4/U5/outer-hook and corrected nominal-geometry contracts with 8.4 preallocation/R_phys and class-65/flags-3 delta; 8.6 opaque/passive prerequisites; 8.7.1 PrivateRoot/AncestorEdge and fixed held installation ancestry; 8.7.2 preserved Busy, both validators and four-total-child credit representation. Actor deferral recorded separately, no O1/O2 prerequisite. | **Implemented source review before load/boot:** both wrappers/tag-3/drain/CLEANUP/CLOSE; actual auth/anchors/security/repair, imports, Busy dispatch+adapter, concurrent pools/context pins and native lifetimes/accounting. Exact-role N-U4/N-U8 corrected strict mechanisms, selected class/flags/masks/pins and raise-before-fault source review, target **19045.2965 N-U4-06 before any boot-time reliance**, WDK/static/import and full agent matrix remain. **N-U5-01 executes after source review on an authorized real component host, before first protected-target boot/checkpoint.** | Builder results 2 remain 94/97, three strict failures, no completed delivery matrix. R3-M05/M06/M08 and M02/M03 raw runtime cases follow their implementations/review. Early R3-M04P is optional feedback after reviewed authorized setup, narrower than actor proof. R3-M01 held-old-epoch and R3-M04 full saturation/echo remain OPEN to 6; real reduction/archive/fence/growth assertions retain 4/5/6 ownership. Fake-send tests close no execution cell. Commit NotReady. |
| T9 increment 4 | Residual 1 already complete in 5.4/10.2/10.4; U7 settled by O2. Proposed revision-8 U3 owner/crash contract (9.3) and U8 strict grammar/migration/candidate/tail/ACK/selection and serializer models (10.5/10.6); independent acceptance and O3 promotion accounting choice remain. The actual serializer/codec prerequisites remain OPEN before dependent increment-4 coding (12.1.3). | Retirement/capture/paging+growth rundown, receipt/inventory/debit transition, release/custody and teardown, any added metadata permissions reviewed before boot. | R3-X/R4-H/R5-S native/protected crashes, **N-U8-02/03 actual selector/recovery/migration**, R3-M03 real reduction stress, delayed query/immediate close, base/delta state reconstruction and exact physical release. |
| T9 increment 5 | Residual 2 separate eight shell credits; U1 boot/old-instance and U2 complete CREATE/cancellation audit; authenticated receipts, bounded snapshot/ACK eviction scheduling, deadline through later lifecycle calls, fence-specific U5 Busy. | Capture-to-callback/exposure ownership, success/non-adoption evidence, eviction credits and reconnect, deadline/failure vs separately owned cleanup; coherent lifetime/lock-order review. | R3-A01..05/R4-D01, R3-M04 **real fence/ACK/snapshot** progress, repeated durable-success-before-ACK interruption, pending-vs-shell saturation, exact same-name recovery and no failed-CREATE adoption. |
| T9 increment 6 | Residual 3 pre-buffer-lock owned-I/O credits/MDL ownership; U6 real Major/Minor/IRQL/resource/completion inventory and actual byte/structure maxima; measured 32/256/64 bounds and implementation of decided O1 (3 s per I/O). | Full growth/replay/companion/MM/MDL/paging/pin/retirement integration, including user buffers and cancellation ownership, reviewed before boot. | R4-D02/MM01..03 and R3-M01/M04 **production growth/reply** plus R3-M03 saturated growth/reduction integration; routed actor evidence, many writers before FltLockUserBuffer/resource acquire, borrowed/created MDL release, deadline/teardown/retirement races and Verifier. |

No row is a claim of runtime PASS or permission to boot. Modern admission stays
closed through the integration prerequisites until the complete readiness
conjunction and matched-pair qualification pass. Compaction design is not
approval to expand M2 beyond the required 10k workload or owner deferrals.

### 12.1.2 Increment-3 readiness conjunction — required order

- [ ] T9 **before-coding remaining increment-3 handlers**: apply the section 8.7 review's accepted architecture with this revision's PrivateRoot/AncestorEdge, fixed ancestry capture, Busy propagation and both validators/four-total-child credits. Retain corrected **nominal** peak models, preallocation/per-call R_phys controls and the opaque 8.6 cut; no schema-3 consumer. Contracts precede implementation, runtime evidence does not. Partial stubs/static gates are not complete registration/routing.
- [ ] T9 **actor disposition recorded — DEFERRED to 6**: no diagnostic kernel actor/echo code in this pass, independent of pools. Keep its full R3-M01/M04/M07 coverage OPEN; prepare 8.7.4 early controls without new kernel authority. Future fixture selection/source review remains required before its own coding/load.
- [ ] T9 **implemented source before any new kernel load/boot**: coherent independent review of both wrappers, actual role/exclusion/security/repair, authentication, pool/tag/alias concurrency, Busy adapter and child/context/rundown conservation. Review measured class-65/flags-3 sharing/lifetime and preallocation/retained-debit paths; pass corrected exact-role N-U4/N-U8 strict user-native mechanisms, both WDK/static/import gates and full agent delivery matrix. No fake-send test closes any native/protected execution obligation.
- [ ] T9 **before any target boot-time reliance on 8.4 mechanisms**: reproduce N-U4-06 on exact 19045.2965 using authorized existing-baseline native component preflight without the new metadata kernel. Require class 65/flags 3 + predecessor SHARE_DELETE, old Links=0/DeletePending=True/readability and successor identity, preallocation/full-extent allocation observations, fault R_phys and exact release. Builder 19045.6466 discovery, a Held result, source compile or nominal-fit arithmetic cannot close this gate. Contradiction stops reliance for a reviewed delta.
- [ ] T9 **before-first-protected-target-boot/checkpoint**: after that review, execute N-U5-01 using real connected handles and working registration callbacks on an authorized native component host. Missing reviewed real-host setup leaves this gate pending, not a reason to load unreviewed code or substitute fake handles. R3-M05/M06/M08 protected cases execute only after their source review/authorized setup.
- [ ] T9 **before-qualification**: execute root/pool/Busy/lifetime and retained native/protected progress obligations; R3-M04P may supply early narrow legacy-drain feedback, but actor/growth proof remains 6. Complete 4's archive/custody/selector/migration, 5's CREATE/fence/ACK and 6's MM/MDL/deadlines, then matched-pair gates. O2/O1 were decided on 2026-10-28; all other prerequisites remain. No admission/cutover gate changes.

The prerequisite is the accepted **contract/fact**, not a runtime control
requiring unimplemented source. Implementing substrate source must not fill
NotReady stubs with partial modern authority merely to run a later row.

No box is self-closed by this edit or its Linux model results. This conjunction
allows remaining increment-3 coding only after its applicable **before-coding**
contracts are accepted, with the actor **deferred to 6 separately from pools**
and early native/protected execution obligations retained. It does not require later production-growth controls
before the substrate is written, nor permit enabling Commit or dropping their final assertions.

### 12.1.3 Increment-4 before-coding audit (revision 8, proposed)

Baseline citations here are **revision 7 at `7c3ab3e5`**, so later insertions do
not change what was assessed. This is an adversarial contract audit, not an
acceptance report; no checkbox is closed.

| Prerequisite / revision-7 evidence | Assessment / revision-8 delta / proof order |
|---|---|
| Residual 1 successful-handoff eligibility: 5.4 **lines 574–597**, 10.2 **2194–2197**, 10.4 **2553**; third review explicitly calls this closed in text | **Complete contract already.** No replacement eligibility wording added. Keep R3-A05/R4-H01 delayed success query, immediate close/disposal and crash, ledger retained until durable InitialResolved. Implement archive side in **4**, actual authenticated query/shell producer in **5**; [before-first-boot] coherent source review; [before-qualification] native/protected race proof. A model does not close those execution cells. |
| U3 every-role release: 9.1 **2055–2090**, 9.2 **2114–2141**; accepted v2 slot/release codec | **Incomplete:** general drain/max rules but no exhaustive native owner set, per-slot issue/completion claim, crash reconstruction or public-promotion accounting distinction. **9.3** supplies private-role and metadata owner/recovery contracts; **O3 remains a product choice** for successful public promotion. **4 [before-coding]** accepted claim/release contracts and schema-3 codec bounds; actual adapters follow with source review; **4 [before-first-boot]** retirement/capture/paging/growth rundown review; **4 [before-qualification]** R5-S04/S05, R3-X/R5-S and native exact final release. Sticky Unknown and uncertain identity remain held. |
| U7 owner scope: 10.4 **2556**, 13 **2892**, 14 **2900** | Revision 7 correctly identifies the trust choice but leaves it open. **Complete by owner O2, 2026-10-28**, independently of a model/native result. Sections 8.7.1/10.4/13/14 now say the selected M2 boundary; stronger anchoring stays post-M2. R4-H02/H03 still required; no review or execution gate changed. |
| U8 grammar/candidate/tail/ACK: 10.2 **2184–2298**, 10.3 **2404–2493** | Core byte layouts, append intent, typed bases/delta and conservative tail recovery already specified. **Incomplete for strict field/encoding boundaries, slot parity/gap/fork selection, candidate identity/phase matching and executable negative cases.** **10.5** supplies these and actual writer byte models; **4 [before-coding acceptance]** independent review of proposal/models; **4 [before-coding]** prerequisite schema-3 codecs/serializer-limit proof; implemented selector differential controls follow before boot; **4 [before-qualification]** N-U8-02/R4-H01/H04 target crash proof. ACK live transport/producer remains **5**, not moved into 4. |
| U8 migration/selection: 10.3 **2495–2541**, 13 **2893** | Compaction range/phase/charge contract exists; no implementable legacy representation/import or preservation model. **10.6** adds migration-only kind 4, bounded source/candidate mapping, mixed read-only legacy suffix and exact inventory replacement/recovery; 10.5 requires semantic byte/witness equivalence before range selection. **4 [before-coding]** reviewed migration/strict-codec contracts and pure copy/selection comparisons; actual copy/selector verification follows implementation; **4 [before-qualification]** N-U8-03/R4-H05, full physical old+new/residue and exact-release evidence. |
| U8 actual serializer limits: 10.2.1 **2309–2324**, 13 **2893** | Arithmetic explicitly admits independent maxima do not fit; it is **not** proof of actual serialization bounds. **10.5** fixes byte limits, writer/escaping/base64/depth and refusal-before-create; pure models measure real .NET output, not character counts. **Actual new product serializers do not yet exist.** Their complete prerequisite schema-3 max-shape/limit+1 proof remains **OPEN [before-coding 4]**, not moved to first use or qualification. This documents an unmet prerequisite rather than declaring increment 4 ready. Existing v2/Entry limits cannot close it. |

Local diagnostic execution (SDK **10.0.400**, Linux, feature Debug/Release):
**117 new contract cases + 70 unchanged fit cases = 187 discovered/executed/passed
per configuration; 374 executions total, zero failures/skips in the final runs**.
VSTest's local socket was denied by the sandbox; a temporary in-process reflection
runner expanded all xUnit Fact/InlineData rows and invoked the same real xUnit
assertions. It is not a Windows matrix runner. Actual serializer prerequisites,
native storage/durability, source acceptance and protected-pair qualification
remain separate; these counts close no checkbox. This revision permits no product source,
network, builder/VM or commit work. All modern readiness/capability/admission and
cap-removal gates remain open. New kind 4 and strict JSON/claim schema additions
are proposals requiring independent review, not changes to shipped/passive ABIs.

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
| R3-C03 replacement | every section-3 crash state, interruption twice | class-65/flags-3 held replacement vs bookkeeping, predecessor Links/DeletePending/readability and R_phys, large units | lost reply/repair/restart, monotonic charge/capacity, no repeated rename |
| R3-C04 corruption | unknown/ahead/torn schema cases | locked/changed exact handles | hold no shrink/deletion/fallback, preserve bytes and diagnostics |
| R3-G01 replay | HighWater/latest compaction/duplicate/stale/changed semantics | persisted store crash/restart | no double debit, changed reuse never capacity, many exact-fit growth operations |
| R3-G02 accounting | same/different SID, geometric fallback/overflow/closure | durable totals agree with native inventory | insufficient space sticks; capacity committed before closure stays charged |
| R3-A01 lost initial reply | ticket/fence/attach linearization interleavings | exact original bytes and result correlation | drop before/after bind/reply/adopt/attach ACK; failed opener, automatic fresh same-name success |
| R3-A02 abandoned commit | service claim closing/native-start/crash model | partial seed/object exact cleanup | expire in queue/seed/persist/delivery; no prefix, reseed or failed-CREATE attach |
| R3-A03 fence/ACK | duplicated/reordered fence and lost resolution ACK | changed intent/FenceId/identity refusal | no name release while any adopter/attach possibility remains; exactly-once cleanup/release |
| R3-A04 reconnect | durable SID/family debt, origin/new cookie | service restart vs driver/boot proof adapter | churn cannot evade bounds; restart alone no receipt; identity-unknown reply loss recovers |
| R3-Q01 bounds | current Ordered/Allocation/Continuation/Growth lanes and reply credits; bounded duplicates | exhaust ordinary pre-dequeue credits, stall accepted/rejected native replies, reconnect | prove the chosen bounded modern intake strategy permits resource progress; no unconditional claim from separate failure queues alone; local revoke before drains |
| R3-M01 confinement | outer pre/post role/size/access/leaf/context mutations | 3: opaque noncached/padded-peak/EOF/F2/security primitives | **Actor held-old-epoch subset deferred to 6**; early R3-M04P has only its observed legacy-drain coverage. **6 production:** actual application waiting for growth, ledger/companion/reply without BP/namespace recursion. Commit NotReady through substrate. |
| R3-M02 lifetime | metadata tag-3/pre/post context and incarnation/revoke conservation | failed lower CREATE, draining at permitted IRQL, CLEANUP/CLOSE; token/anchor/substitution/link/ADS faults | map key retired before FILE_OBJECT address reuse, generic epoch/BP post never sees metadata context; disconnect/unload, no UAF |
| R3-M03 lock order | raw claim/fault model before 3 | 3: opaque store/physical delta callbacks, no content/journal dependency | **4 retained:** actual reduction/content lease stress; **6 retained:** saturated production growth + namespace/publication/reduction, no budget→journal cycle. Neither is a substrate exit. |
| R3-M04 control progress | provisional/bootstrap/metadata/revoke classes and paired lifetime, accepted/rejected transport bounds | **N-U5-01 before-first-protected-boot:** real main-gate/resource callback independence after source review; no epoch claim | **R3-M04P early alternative:** observed legacy allocation/drain plus raw metadata, after reviewed setup. Full actor held-epoch/saturation/side-port echo remains OPEN to 6; real fence/ACK/snapshot in 5 and growth/reply in 6. Fake sends close none of these. |
| R3-M05 installed roots | PrivateRoot versus AncestorEdge: Admin positives; TI/service-SID mutation negatives on roots; Windows-servicing ancestor positive; untrusted owner, effective/inheritable/unsupported ACE negatives | fixed ancestry capture, original handle/identity, exclusion/security and revoke/drain-before-ACL-repair mechanisms | **3:** correct fixed four roots succeed; lookalike/alias/non-C:/missing/reparse/substitute refuse/Held, no root/marker repair by kernel. Actual repair waits for contexts/handles to drain and recapture never revives IDs. |
| R3-M06 transaction pools | tag-only/all-zero GUID; every disallowed Growth role 5–20; unknown roles, tag-flipped aliases/concurrent first children, four total credits | real registration exhaustion; Pending→Opening same credit, failed CREATE/revoke/CLOSE/context drain | **3:** 8+8 isolation, ninth Busy before allocation; never fifth Opening/Active/retiring child. Cancel with referencing completion context cannot free record/slot; release once after final drain. **4/5/6:** real purpose classification. |
| R3-M07 diagnostic boundary | deferred actor/echo ABI and product absence proposal | **DEFERRED to 6**, not an increment-3 actor gate | Future fixture needs selection/host boundary, implementation review and bounded lifetime/teardown tests; no enabled actor in product-signed product driver. N-U5-01/R3-M04P are separately scoped and do not close this row. |
| R3-M08 Busy propagation | local-send Busy/no construction; kernel Busy versus malformed/Refused and exact adapter mapping | real callback→FilterSendMessage HRESULT/ReturnedBytes→adapter; both pool/child and control exhaustion | Native Busy stays retryable without success ID/new ownership; invalid/refused stays distinct, no Result=3. Retry only after actual release/original deadline, no duplicate registration. Real execution follows source review; fake error injection alone is insufficient. |
| R3-A05 initial success/tombstone | no Entry/K closure, InitialResolved and linked ACK delta count reconstruction | final-success query/ACK origin, cross-request/FenceId/duplicated-handle refusal | delayed final-success query plus immediate close/disposal/crash must keep ledger until InitialResolved; then ledger deletion before ACK, ACK reply/delta loss and restart: no fabricated Entry, duplicate TransferId base or 8/4 debt leak |
| R3-X01 ordinary discard | strict new receipt, old StageDeleted still rejected | exact delete with reader/section/replacement | ordinary discard refunds after proof, snapshot remains charged, fresh name use |
| R3-X02 discard crash | section-9 crash table, duplicate/reuse | receipt persist fault after exact native success | live/restart/hot/packed no lost barrier or duplicate release |
| R4-O01 ordering | forced allocation/growth/close/rename reordering | connection revalidation | journal failure after growth closure, late success cannot reopen |
| R4-O02 drain | lane-full revoke/cancel dependency model | bounded reply teardown | epoch drain queued in every lane, service-independent local pin release |
| R4-D01 allocation deadline | exact 120 s pair, equality/overflow/retry through every lifecycle wait | interrupt-time clock/resume; serial attach worker, pre-completion retirement, ExposeClaimed/callback ownership | capture-before-queue, all attach/retire/ABORT exchanges and final callback expiry; prompt failed opener with cleanup separately owned; timeout vs space UI |
| R4-D02 growth deadline | distinct original I/O/RPC immutable deadlines, joined higher extent and repeated append recomputation | blocked reacquisition and late timer/reply; no second full interval | 32→64 MiB join near deadline and append race: original per-I/O bound, late sufficient grant cannot publish prefix; several I/Os may each pause |
| R4-MM01 crossings | extent/revalidation/append and owned Major/Minor models | trace owned StagePreOperation :5903/:5948, actual MDL minors and completion owner; unowned fallback insufficient | every supported owned crossing above/below C, C02, no paging RPC/livelock; route evidence required per case |
| R4-MM02 pins | waiter/worker timeout/signal/release ownership | allocation/cancel fault seams | timeout/disconnect/teardown/retire at every adoption/pin boundary under Verifier |
| R4-H01 handoff | typed no-Entry/K bases, ACK chain, successful-count and exact append-location crash models | arbitrary unaligned logical payload lengths; A-strides, preallocation/per-call R_phys, class-65/flags-3 F1/F2/F3, torn alternate frontier, append before frontier, candidate/intent/ledger delete | classifier before :467 tail repair; no successful base before durable InitialResolved (delayed-query/immediate-close crash); no second append, duplicate changed base, ACK rollback/debt leak or missing physical padding/overlap charge |
| R4-MM03 many waiters | one K >32 and global >256 waiters/>64 operations; owned-I/O credits before :4824 buffer lock/:4835 resource wait, exact terminal owners | instrument user page spans, borrowed/FilterMgr-created MDLs, waiter/operation/upper/callback credits, allocation/cancel/late result | many ordinary writes queued behind upper MM resource; completion minors release existing credit without new admission; no upper-pin-only or service-lane bound substituted for page custody |
| R4-H02 downgrade | enabled/disabled/mixed schema matrix | old binaries see marker/envelope | old/disabled startup refuses after shared handoff/packing |
| R4-H03 marker | corrupt/missing/wrong installation model | exact security/identity and partial-write checks | removal with surviving modern evidence holds, no marker recreation/fallback |
| R5-S01 inventory | zero-allocation mutable copy, four slots/fifth refusal | reserve-before-create; preallocation/zero EOF/normalization failures | snapshot/hand-back race reduction, charged physical allocation independent of EOF |
| R5-S02 storage release | stale completion/incarnation reuse, uncertain drain | multiple readers, deletion-pending section/operations | final-close adapter proven, no slot reuse/refund from one reader closing |
| R5-S03 receipt | full tuple/measurement/revision conflict + three crash points | immutable proof persisted before totals | lost/duplicate/stale receipts, lower adopted C after lost growth, no double reduction |
| R4-H04 strict archive contracts / **4** | **[before-coding acceptance]** GrowthArchiveContractModelTests: strict JSON/actual UTF-8 lengths, byte-frame/frontier mutants, exact candidate/phase/tail and base/delta selection; **[before-coding 4] OPEN** prerequisite schema-3 actual serializer max-shape/limit+1 proof; actual new envelope/intent codecs must pass matching vectors during implementation before any use | **[before-qualification]** N-U8-02 actual classifier before tail repair, two interrupted recoveries, independent append/rename counts | Retain R4-H01 native/protected crashes; no inferred durability from pure models |
| R4-H05 legacy migration / **4** | **[before-coding acceptance]** 10.6 capacity/selection/preservation models; **[before-coding 4]** reviewed kind-4/cursor/v1 contracts and pure models; actual codecs/selector checks follow implementation before use | **[before-qualification]** N-U8-03 copy/select/delete faults, missing selected suffix, oversized legacy wrapper and all witnesses retained | Repeated migration recovery, exact old+new inventory and no second mutation or refund |
| R5-S04 role release / **4** | **[before-coding 4]** 9.3 claim/state/refcount contract, schema-size and pure controls for all roles; identity/incarnation/claim/undrained/persistence mutants | **[before-qualification]** each actual role's extra reader/duplicate, active operation, section where applicable, process death, preidentity and post-delete-before-persist faults | **[before-first-boot]** independent retirement/capture/paging/growth rundown review; R5-S01–03 and R3-X remain required |
| R5-S05 public promotion / **4** | **[before-coding promotion release]** owner O3 then independently reviewed typed accounting contract/codec; until then no release from rename | **[before-qualification]** successful/uncertain publication and authorized hand-back, lost reply and private owners still active | No repeated public mutation/export, no delete-to-refund, exact original grants/security, retained charge on uncertainty |
| R5-H01 history cost | maintained hot/shared delta conservation | reconstruction includes padding/failed residue and retained measured R_phys, never only nominal Q | growing retained history incl 10k; record queue/metadata callback/end-to-end time and reconstructed physical totals, unchanged resource gates |

## 13. Unresolved before implementation

These are missing implementation facts, not licenses to infer Windows behavior.
Resolve the applicable item before its dependent increment; if it changes a
contract above, obtain a reviewed design delta. No new VM/build access is
authorized by listing a control.

| Item | Selected contract / exact remaining fact / dependent integration |
|---|---|
| U1 BootDomain / old instance | Still open before 5: choose/verify OS boot identity and exclusion of old adopters; existing BootId use at StageStream.c:4369 is not the whole proof. No restart/GUID inference. |
| U2 CREATE / shell ownership | Before 5: section 5.5 whole source audit, prompt final expiry vs separately owned cleanup, authenticated success/fence acceptance and exact eight retained-shell credits/snapshot/ACK eviction. Pure debt/shell model exists; current code clears old receipts (:4461/:4629) and does not implement this registry. |
| U3 Release adapters | Proposed 9.3 supplies every role's owner, claims, crash/unknown witnesses and persisted release transition. O3 public promotion accounting remains an owner choice; no release kind is silently added. Before coding 4: review the proposed exact adapters and prove prerequisite schema-3 claim sizes; actual native adapters follow implementation/source review; before first boot review actual kernel retirement/capture/paging/growth rundown. R5-S04/S05 and existing R3-X/R5-S native/protected proof remain. |
| U4 Metadata/native sequence | Accepted dormant architecture with this revision's 8.7.1 PrivateRoot/AncestorEdge, servicing-only ancestor exception, one fixed held ancestry, original UserMode handle proof and revoke/drain-before-ACL-repair. 8.7.2 selects four total child credits including pending intent. Actual capture/query/IRQL/imports, pre/post exclusions, native preallocation/query/F1/EOF/F2/**class-65/flags-3** relative rename/F3 and cancel/rundown remain implementation/source-review/native-mechanism facts before load/boot; partial registration stubs are not proof. Builder results 2 select the mechanism but leave three strict failures; corrected N-U4-01/-05/N-U8-01 and full matrix remain, plus target **19045.2965 N-U4-06 before any boot-time reliance**. Actual old-target Links=0/DeletePending=True/readability, all predecessor SHARE_DELETE handles/operation pins and source review must match; failed class-10 or class-65/flags-1 replacement is not unlink proof. Existing root/lifetime controls remain. No stronger power-loss or O2 guarantee. |
| U5 Two-direction progress | Accepted 6.2/8.3 bounded intake/send/lifetime contracts are coding prerequisites; real execution is not a prerequisite to writing the substrate. Working dispatcher+adapter must preserve local/kernel Busy and validate both tag/role rules (8.7.2/R3-M08); actual FltLib Busy HRESULT conversion needs real N-U5-01/M08 verification before accepting that adapter. Implemented source review precedes any kernel load; N-U5-01 real gate independence follows review before first protected-target boot/checkpoint. R3-M04P is an early reviewed legacy-drain alternative. **Actor/echo deferred to 6 separately from pools**; full held-old-epoch/saturation/echo proof remains OPEN, plus 5's fence Busy and 6's production growth/teardown. Fake-send tests close no native/protected execution obligation; real 4/5/6 purpose classification remains. |
| U6 Owned MM/buffers | Before 6: finish owned :10927→:5903/:5948 Major/Minor/IRQL/resource/MDL/completion audit, and pre-FltLockUserBuffer credits at :4824. Supply actual structures/worst-case page/PFN/cancel storage and validate numerical bounds; no pin-only or unowned :11044 proof. R4-MM routing/native evidence follows implemented review. |
| U7 Trust scope | **Decided O2, 2026-10-28:** existing trusted-service/private-storage boundary; local SYSTEM/administrators trusted, their erasure/rollback outside M2. Surviving modern evidence plus missing/corrupt marker holds. Stronger anchoring is separately reviewed post-M2. No native/security/marker gate is discharged. |
| U8 Fit/grammar | GrowthArchiveFitModelTests supplies **nominal** independent L/P/Q and A/U geometry, explicit measured/released custody, logical-EOF conservation mutant, combined-envelope and corrected overlap/controls. Base transfer **nominal** overlap fits halves in all 60 pairs (worst nominal ratio 640 KiB/1 MiB=62.5%); native fit requires qualified preallocation/within-Q observations. Unpreallocated chunked NTFS overshoot disproves a general Q ceiling; production sums retained R_phys, raises charge before Held, and cannot erase the peak through normalization. Preallocation/per-call accounting/pin proofs, corrected strict N-U8-01 and target N-U4-06 remain open. ACK scheduling and independent snapshot unknown/missing input models are stronger pure controls; they are not real sends or durable/native reconciliation. Full independent Entry+closure maxima **do not fit** and retain ledger. Proposed 10.5/10.6 and GrowthArchiveContractModelTests supply byte/serializer, typed candidate/tail/delta/prefix and migration models. Before coding 4 the prerequisite schema-3 actual serialization/strict-codec proof remains OPEN; new consumer codecs must match the models during implementation before use; N-U8-01 raw peak primitives are before-3-first-boot mechanism controls; N-U8-02/03 actual selector/migration/recovery wait for increment 4, then required target evidence. No arithmetic/builder discovery result is a universal allocation ceiling, native durability or target qualification. |

## 14. Owner decisions and remaining question

| Decision | Status / user-visible consequence |
|---|---|
| O1 Per-application-I/O growth wait | **Decided 2026-10-28:** 3 s from first crossing through sufficient adoption/reacquisition/recomputation, never per RPC. Joined extent/append cannot renew it. Expiry permanently fails that save privately; several I/Os in a long save may each pause. Allocation/seed remains 120 s. |
| O2 Erasure/rollback boundary | **Decided 2026-10-28:** M2 keeps trusted-service/private-storage scope; local SYSTEM/administrators are trusted and their erasure/rollback is outside M2. Surviving modern evidence with missing/corrupt marker holds. Stronger external anchoring requires separately reviewed post-M2 architecture. |
| O3 Accounting after successful public promotion | **Open before implementing promotion release in 4.** Recommend a separately typed, persisted exact-object custody-transfer receipt for a successfully published/authorized hand-back file, after the existing publication/export transaction is proved complete and all private mutation/operation owners drain. This transfers staging-budget responsibility; it must never masquerade as physical deletion or authorize another publication/export. Actual volume free-space admission still sees the retained public bytes. Alternative: retain its slot/charge until actual storage-release proof. With retention, completed user files can consume the staging budget indefinitely and eventually block new saves; the recommendation permits normal continued saving while failed/uncertain promotion stays fully charged. Neither option changes caller grants or permits unreadable seed export. O3 is not settled by O2, which concerns trust in private storage. |

No renewed budget-default, file-size-cap or O1/O2 question is raised. Pending
lane/capability bounds remain engineering proposals requiring review. The 8.7.3
actor/echo remains deferred to 6 with its existing selection/review gates.
If native evidence makes a specified cleanup, metadata or MM contract impossible,
present the failed precondition and user effect for a reviewed design delta;
never silently change support, failure policy, grants or cutover.

## 15. Revision history

| Revision | Scope / status |
|---|---|
| 1–5 | Historical proposal/review corrections in the linked reviews and concurrency design; retain their provenance. |
| 6 | Installed roots/ancestry, immutable transaction pools and actor deferral; 8.7 review ACCEPT WITH CONDITIONS for dormant substrate. |
| 7 | Measured preallocation, retained R_phys and class-65/flags-3 mechanism delta; source acceptance and native/target qualification remain separate. |
| 8 | **Proposed, pending independent review:** 12.1.3 audit; 9.3 role/claim/release crashes; 10.5 strict codecs/frontiers/candidate/ACK/selection models and real serializer byte limits; 10.6 legacy migration. Records decided O1/O2 and exposes O3. No product code, checkbox closure, Windows execution or admission/cutover change. |
