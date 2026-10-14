# T5 recovery and activation holds

**Revised proposal against `7ae168804698ebd01ada4570694abfa88efb985f`, 2026-10-14.** Incorporates findings 1–5 of the independent Sol 6.1 xhigh receipt `t5-designs-review-sol61.md`, which returned REVISE for both designs. This revision has not been independently accepted. Read-only inspection; no edits, builds, tests or VM contact. Checkout clean.

The kernel and agent interception source is unchanged from `1db2d9fe`. This batches [fix7 finding 2](evidence/2026-10-14/t5-fix7-review-sol61.md), [replay2 findings 5–6](evidence/2026-10-14/t5-replay2-review-sol61.md) and [block2 finding 3](evidence/2026-10-14/t5-block2-review-sol61.md), under workflow rules 3–5 and the integrated checkpoint in [POST-MVP-PLAN.md](POST-MVP-PLAN.md). The joint unload contract is also specified in [T5-VOLUNTARY-UNLOAD.md](T5-VOLUNTARY-UNLOAD.md).

References use `K/` for `driver/SafeUpload.Minifilter/` and `A/` for `agente/SafeUpload.Agent.Service/Interception/`. Verified statements describe inspected source; proposed transitions and attestations require implementation, review and qualification.

## 1. Current states and stranding sequences

| Hold | Verified mechanism |
|---|---|
| Lost seal ACK | Drain closes writable backing and irreversibly selects read-only backing; seal collection pins owner/view/transfer/generation/full identity (`K/StageStream.c:5706`, `:5741`, `:6070`). Transport currently assigns a fresh RequestId per attempt (`K/StageProtocol.c:2145`). The journal writes `SealPending` without the original request, then measured `Sealed` (`A/StagedTransferJournal.cs:2143–2182`); startup calls `SealAsync` without that request (`:3116–3121`). A lost reply followed by inspection, publication or cleanup strands replay: `SealAsync` rejects cleanup and rechecks current backing/head (`:2126–2137`), while the handler accepts only exactly `Sealed` (`A/MinifilterInterceptor.cs:1249`). |
| Lost op15 / late fence | Agent attachment is `None → Prepared → Committed → CompletionPermitted`; permission is not handle delivery (`A/StagedTransferJournal.cs:882–972`). Failed CREATE rolls back its binding; only an exact original-owner retry resumes op15 (`K/StageStream.c:1746–1778`, `:3690–3774`). Maintenance parks completion/fence/retirement flags (`:5960`); op19 collection excludes them (`:6285–6288`). V20 has no typed op15 refusal (`K/StageProtocol.c:1590`). Late validation can fail after preliminary attachment bookkeeping but before successful completion; fence clearing is success-only (`K/StageStream.c:4080–4105`, `:4163–4219`). Canceled CREATE can reach CLOSE without CLEANUP (`:5448`), which does not supply op19 evidence. |
| Refusal storage | Under `_v19AllocationGate`, committed manifests resolve before live-owner lookup. Definitive refusal removes unjournaled backing, then flushes and renames the complete 1,192-byte request into `GUID.allocation-refused` (`A/StagedAllocationResolution.cs:28–103`). There is no cumulative budget or retirement path. Epoch drain scans `*.json`, not refusal files, and requires matching manifests terminal and stages absent (`A/StagedTransferJournal.cs:93–124`). Epoch replacement overwrites the single epoch record (`:69`, `A/StagedDriverEpochStartup.cs:75`). |

The stranding interleavings and cumulative-storage inference are source-derived, not new runtime reproductions.

## 2. Wire, validation and durable identity

Preserve existing layouts and enum values. Proposed feature capabilities:

| Capability | Bit |
|---|---:|
| Durable exact seal request/receipt | `0x200` |
| Exact op15 refusal and attachment recovery | `0x400` |
| Charged refusal storage and durable epoch retirement | `0x800` |

Required mask becomes **`0xFBF`**, replacing `0x1BF`; bound-head bit `0x40` remains independently disabled. Normal builds compile staging out.

Reserve extension **29** and operation **23** for attachment recovery; verify availability before implementation. Operations 4, 15 and 17 receive separate extension-29 parsers. An old/incomplete mask cannot activate this family. Reconciliation refuses or returns EpochBusy with accepted mask zero; no legacy acknowledgement fallback. Old-format unresolved requests remain held, never converted into fresh authority.

### Version request: operations 4, 15 and 23

The unchanged 1,192-byte outer request carries this **124-byte, pack-4** payload:

| Offset | Field |
|---:|---|
| 0 / 4 | ExtensionVersion / StructSize, uint32 |
| 8 | TransferId, GUID |
| 24 | DestinationGeneration, uint64 |
| 32 | StageIdentity: volume serial + full FILE_ID_128, 24 bytes |
| 56 | DriverInstanceId, GUID |
| 72 | ParentDirectoryIdentity, 24 bytes |
| 96 | Original owner creation time, int64 |
| 104 | ViewGeneration, uint64 |
| 112 | ReferenceRequestId, uint64 |
| 120 | ProofKind, uint32 |

Outer fields are core version/size, nonzero RequestId, operation, original owner PID, permitted volume flags, extension marker, image/path lengths and path bytes. All unused bytes are zero.

- Op4: original private stage path; reference is genuine durable op19; ProofKind=0.
- Op15: exact destination name; reference is committed op13; ProofKind=0.
- Op23: original op15 destination/authority tuple; reference is original op15. ProofKind is the kernel attestation in section 4. A newer fact uses a new immutable op23 request, never changes an in-flight request.

Validate envelope, sizes/tails/flags, complete raw replay bytes, transfer/full stage identity/generation, original driver epoch, original PID/creation time, parent identity, view and phase reference. Bind view generation on first op15 and preserve its exact rename history. Bound entries additionally require original mount/root/parent/case/leaf, security, ancestry and seed dependencies. Paths/digests cannot reconstruct missing authority.

Validation differs by operation:

| Operation | Required authority |
|---|---|
| Fresh op15 permission | Live original owner and effective caller authority, current admission, exact committed allocation/parent/view, native grant/share/security and seed prerequisites. PID identity alone is insufficient. |
| Op15 outcome replay | Exact saved request/outcome; no fresh grant and no requirement that an exited process become live again. Permission/refusal cannot change. |
| First/resumed seal | Exact historical owner binding, genuine durable op19 and the authenticated driver’s completed T4 drain/irreversible read-only attestation for this object/version; exact backing/length/seed dependencies. **No live-process requirement.** |
| Op23 recovery | Exact original allocation/op15 chain and authenticated immutable kernel attestation; no new caller/file object or filesystem authority. |
| Inspection/publication | Measured exact seal receipt, current policy, current destination/generation/delete floors and existing publication/native authority. Seal acknowledgement is not approval. |
| Op17 | Joint state machine, exact request and kernel/agent quiescence; default terminal-and-absent residue policy. |

The op4 contract attests successful drain before sending; save that attestation with the request. A mere startup scan, owner exit or zero counter does not recreate it.

### Typed reply

Use a separate **1,296-byte, pack-4** buffer:

| Offset | Field |
|---:|---|
| 0 / 4 / 8 | Core Version / StructSize / RequestId |
| 16 / 20 | Verdict / operation-specific Result |
| 24 | Entire original 1,192-byte request echo |
| 1216 / 1224 | Current connection epoch / authority revision |
| 1232 | Durable ReceiptId, GUID |
| 1248 | MeasuredLength, int64 |
| 1256 / 1260 | Recorded op15 outcome / reason code, uint32 |
| 1264 | Reserved zero, 32 bytes |

Define results in this family without renumbering old results. Nonapplicable fields are zero. Durable results require ReceiptId; `EpochReady`, transient and held replies provide no retirement authority. Rebind transport header fields on reconnect without changing immutable receipt facts.

Driver adoption requires exact echo/result/size/zeros, actual successful transport and current authenticated connection/authority, followed by pinned tuple and local-state revalidation. Generic verdicts, timeout, pending/reparse status and malformed replies cannot be typed success.

## 3. Seal request survives every entry point

Before the first send, the kernel retains one immutable request/RequestId. Retries use identical bytes.

The agent atomically persists **`SealIntent` and `SealPending` together, before measurement**. Intent contains the entire request, ReceiptId, original driver/boot and historical owner binding, destination identity, exact object/generation, genuine op19 reference and drain attestation. Reserve its storage before replacement. `SealPending` without intent cannot be newly emitted.

Measurement resumes only from that persisted intent. Successful classification atomically adds measured length and `SealReceipt` while preserving the intent. Inspection cannot consume the version before this replacement. Zero length follows the ordinary path.

All entry points use one helper:

- synchronous/async interceptor seal handlers;
- direct `SealAsync`;
- `TransitionAsync(..., Sealed)` (`A/StagedTransferJournal.cs:1977–1986`);
- startup `RetainInterruptedAsync` (`:3116–3121`);
- legacy-empty migration and its publisher/startup callers (`:2236`, `A/StagedTransferPublisher.cs:117`).

An entry point supplies the authenticated exact request or resumes the identical stored intent. It cannot generate a new request from manifest fields. Missing/mismatched intent leaves the version nonpublishable with `seal_request_unavailable`/`seal_request_mismatch`; historical state/length/digest does not waive this rule. Already-completed publication may finish exact result bookkeeping, never repeat publication.

Startup with intent but no measurement retries only measurement after validating original evidence, exact frozen backing and applicable epoch state. Retirement-only epochs prohibit this continuation. Missing backing, changed identity, coverage/lifetime uncertainty or an unproved drain remains held.

Completed receipt lookup precedes current-head/backing/cleanup checks. Exact replay acknowledges the historical measurement in progressed states and after cleanup without reopening the deleted stage, remeasuring, inspecting or publishing.

| Reply | Driver action |
|---|---|
| `SealRecorded` | Clear matching seal pending/in-flight state; set ordinary local `Sealed`; save receipt and wake disposal/retirement. Release attempt pin once. Keep independent object/section/cleanup/publication obligations. |
| `RetryableFailure` | Keep exact request and obligation; release attempt pin only; bounded EXCHANGE retry of unfinished measurement/bookkeeping. |
| Held/DENY/malformed | Preserve request/lifetimes, park SERVICE with named reason; no refusal polling. |
| Disconnect/stale | Preserve request; retry only after permitted current-channel reconciliation. No replay after retirement begins. |

Compaction pins intent, receipt and dependency closure while valid replay remains. Cleanup/publication cannot erase them. Charge retained journal storage cumulatively.

## 4. Op15 and complete exposure recovery

### Durable outcome

Serialize permission, refusal and recovery closure under the same journal gate. Persist complete original op15 and immutable outcome before reply. Existing exact outcome wins before live-owner checks. Definitive refusal requires proving no permission was committed; uncertainty/invalid authority gives no terminal refusal.

| Op15 reply | Driver action |
|---|---|
| `CompletionPermitted` | Mark permission known/may-exist; continue original CREATE validation/cancellation. Reply alone clears no reservation or lifetime obligation. |
| `CompletionRefused` | Prohibit exposure and queue op23 after actual rollback/completion drains. Keep receipt/reservation/predecessor meanwhile; a sent op15 cannot enter op16/kind-5. |
| Retryable | Preserve ambiguity; complete/roll back original CREATE once; queue evidence recovery, not another CREATE. |
| Held/DENY/malformed/disconnect | Preserve ambiguity and named hold. |

### Kernel attestation and agent transitions

Retain allocation-level monotonic evidence after transaction destruction: exposure claim, original completion classification/return, rollback completion, real per-object CLEANUP/CLOSE, callback/lookup ownership and actual cache/paging rundown. Keep raw status/information locally; success attestation requires a final valid successful staged completion, not `NT_SUCCESS(STATUS_PENDING)`.

Latch `ExposurePossible` under final `StageAttachLock` arbitration **before** successful completion. It means possible exposure, not delivered handle. Never reset it.

Op23 ProofKind values are:

| Value | Kernel attestation and agent action |
|---:|---|
| 1 — `NeverExposed` | All relevant CREATEs returned failure, no exposure claim ever occurred, rollback and complete local drain proved. Agent persists retained-unexposed custody, closing absent op15 outcome with refusal first. |
| 2 — `ExposurePossible` | Claim occurred, completion outcome/return unresolved. Agent records `AttachmentRecoveryState=ExposurePossible`; returns `HandleLifecycleRequired`, but authorizes no pending/fence clear. |
| 3 — `CompletionSuccessReturned` | Claim plus exact original successful completion returned; attach/cancel producer arbitration finished. Agent requires existing exact permitted op15, records this immutable completion attestation, retains `CompletionPermitted`, returns `HandleLifecycleRequired`. |
| 4 — `RealCleanupAfterExposure` | Cumulative success-return attestation plus actual owned-object CLEANUP. Agent records both facts and returns `HandleLifecycleRequired`; **does not write op19**. |
| 5 — `CloseWithoutCleanupUnproved` | Exact owned CLOSE occurred without real CLEANUP after possible exposure/cancellation. Agent retains `attach_canceled_close_lifetime_unproved`; no ordinary-lifetime conversion. |
| 6 — `CoverageLost` | Callback coverage or required tracking lost. Agent retains `attach_lifetime_unproved`; stronger-looking counters/older replies cannot clear it. |
| 7 — `CompletionFailureAfterExposure` | Completion returned failure after a possible exposure claim, or claimed cancellation lacks a proved no-handle route. Agent records failure but retains `attach_exposure_unproved`; it cannot convert this into NeverExposed. |

Reject impossible combinations, altered references and conflict with retained-unexposed or refused op15 evidence. Exposure attestations without an exact durable permission remain `attach_outcome_unproved`; recovery cannot create permission.

Source observations determine transitions:

| Event | Resolving transition |
|---|---|
| Failure/cancellation before exposure claim | After actual rollback/completion and full drain, ProofKind 1. No fabricated CLEANUP, op19 or seal. |
| Successful completion returned | ProofKind 3. After exact durable reply and local revalidation, finish attachment bookkeeping below. Ordinary and recovery paths use the same completion-attestation transition. CREATE is already completed once; no second completion is issued. |
| Real CLEANUP before success bookkeeping finishes | Record genuine cleanup immediately and defer op19 collection. ProofKind 4 permits the same bookkeeping finish; then queue the **real** pending op19. |
| Normal CLOSE after CLEANUP | Release only actual handle/object/lease ownership; preserve sticky cleanup evidence and op19 obligation. CLOSE does not acknowledge op19 or prove deletion. |
| Canceled CREATE reaching CLOSE without CLEANUP | ProofKind 5. The inspected source supplies no proved cancellation-CLOSE no-handle lifetime construction. **Keep the named hold.** Do not mark `AnyHandleCleanupObserved`, manufacture op19, seal or delete. A future resolving route needs its own exact cancellation/object/source-barrier proof and review. |
| Failure after claim, unknown completion or coverage loss | ProofKind 2/6/7 and named hold. Real release callbacks may drain references, but cannot erase the missing evidence. |
| Owner exit | Scheduling event only. Preserve historical owner binding; do not clear an unresolved allocation-owned reservation. |

### Flags, reservations and pins

Recovery and owner-resume claim serialize under `StageNamespaceResource`; rename/other terminal work cannot alter the tuple during recovery. Each RPC owns one stream pin; callback/transaction/lookup owners drain independently.

For a validated ProofKind 3/4 `HandleLifecycleRequired` reply:

- require exact permitted op15 and original completion-return evidence, no active attachment producer, conflicting terminal claim or coverage-loss hold;
- set `AttachCompletionKnown/MayExist` and `AttachAcknowledged`; clear `AttachCompletionPending/Fence` **only for this completed original CREATE**;
- clear its allocation receipt/recovery pending and tuple bookkeeping only after all allocation attempts drain; unlink only its reservation;
- release its one `AllocationReceiptParent` reference and wake that predecessor;
- clear allocation-only `PrivateDeleteReserved` only absent actual discard/delete-on-close; preserve actual delete state;
- preserve `AnyHandleCleanupObserved`; if genuinely set and op19 unacknowledged, set/retain `HandleReceiptPending` and wake collection. Op19’s existing gate becomes reachable because completion flags are now resolved;
- retain handle/object/share/cache/paging/instance/writer-lease ownership until its real release. Do not set `HandleReceiptAcknowledged`, `Sealed`, `Retired` or deletion flags.

ProofKind 2 never performs those clears. ProofKind 5/6/7 keeps unresolved flags and reservations; actual CLOSE may release its own counted object/lease, but is not permission to bulk-clear sharing/cache/lifetime obligations. A late weaker reply cannot clear a newer hold.

Genuine op19 remains `CompletionPermitted → HandleObserved` through its exact durable reply (`A/StagedTransferJournal.cs:1011–1025`; `K/StageStream.c:6309–6359`). Only then may normal T4 drain/read-only seal proceed, including after owner exit. Actual discard retains its separate exact cleanup path. Op16/op18/kind-5 remain unavailable for op15 ambiguity.

For ProofKind 1, require no file objects, shares, cache/sections/paging users, attach producers/lookups or competing RPC/rename/cancellation owner, and close driver-owned holds outside callback-needed locks. Zero samples alone are insufficient.

Agent persistence is `AttachmentRecovery=RetainedUnexposed` plus exact custody receipt, bytes/object/version/ancestry/security/provenance/accounting. If original op15 outcome is absent, persist refusal first against delayed permission. Reply `RetainedUnexposed` permits matching view detachment, pending/fence/allocation reservation release and the single predecessor-pin release. Retire drained kernel stream memory through a separate predicate, never synthetic seal/discard/deletion. Retain the unload obligation described next.

All other replies retain the exact claim; retryable persistence backs off, explicit refusal parks, and disconnect preserves state.

### Retained residue: conservative default and pending option

**Owner-recorded conservative default:** retained never-exposed bytes remain an outstanding private allocated/unsealed obligation and **veto voluntary unload and epoch retirement**. Preserve the existing terminal-and-absent agent predicate. Releasing drained stream memory or the abandoned app name does not satisfy it.

Before freeing the shell, retain a bounded, charged epoch residue ticket naming custody ReceiptId, transfer/generation/full identity and durable dependencies. Reconstruct tickets from validated service custody inventory on restart/reconnect before unload preflight. No ticket may disappear because counters reach zero. Missing inventory/custody evidence vetoes with `retained_unexposed_custody_unproved`; confirmed residue vetoes with `retained_unexposed_blocks_unload`. It is not automatically deleted, sealed, exported, seeded or published.

Users can retry the failed save after exact name release, but operators still cannot voluntarily unload while this residue remains. Full Restart can establish ended Windows lifetimes; **it does not make retained bytes terminal-and-absent or retire their receipts/charges**. Existing new-boot admission/recovery is a separate decision from old-epoch receipt retirement.

**Recommended narrow exception — NOT implemented or enabled until owner approval:** only proved never-exposed, fully drained residue could qualify as service-owned custody rather than an unload obligation, provided:

- exact object/version/original driver/owner/boot and immutable custody receipt survive startup verification;
- complete bytes and metadata are under validated service-private ownership, with no app/native producer, lookup, lease, mapping or callback that can change them;
- storage and all dependency/receipt charges are durable and reconstructed; custody acceptance reserves capacity before kernel ownership is released;
- service compaction retains ancestry/security/provenance and destination generation floors; kernel predecessor release transfers dependency responsibility without erasing it;
- no pending public intent, accepted mutation, uncertain outcome or cleanup obligation is hidden;
- custody is permanently nonpublishable/nonseedable and cannot acquire justification/export authority from unload; only a separately authorized exact cleanup/retention policy can remove it;
- op17 explicitly audits and includes these custody receipts in its durable retirement record; epoch retirement removes replay authority, not custody/accounting.

Users would gain idle voluntary unload while private residue remains charged on disk. Automatic deletion and broader exposure/coverage exceptions are excluded.

## 5. Accounting and the joint op17/unload contract

### Allocation operation 3

Keep the existing 72-byte V20 request: intent version/size, reservation/predecessor GUIDs, disposition/reference kind, driver GUID and original creation time; outer RequestId/PID/flags/destination. Preserve exact validation and committed-manifest/refusal replay.

Reserve a potential refusal slot and worst-case storage **before fresh backing or receipt creation** under allocator/accounting serialization. Replay needs no new slot. Release potential-refusal charge only after verified positive manifest commit; uncertainty stays charged. Include committed allocation units, temporary overlap, crash orphans, bounded metadata and filesystem overhead allowance; also check volume headroom.

The unchanged 1,216-byte full-request-echo reply retains 19/20; capability `0x800` adds 21:

| Reply | Driver action before retirement |
|---|---|
| Exact allocation tuple | Existing adoption/attachment/cleanup route. |
| 20 — no allocation committed | Exact shell reservation and one predecessor-pin release; no predecessor-state change. |
| 19 — transient | Preserve request/reservation/pin; bounded EXCHANGE retry. |
| 21 — capacity unavailable | No backing/generation/refusal committed; preserve request/reservation/pin and park SERVICE as `allocation_refusal_budget_exhausted`. Reconciled reconnect after capacity restoration wakes it; no polling. |
| DENY/malformed/disconnect | Hold; no terminal release. |

Startup validates refusals/temporaries/orphans/retirement records and reconstructs charges, including legacy 1,192-byte receipts. Never reset usage on restart. Invalid/conflicting/unreadable evidence is conservatively charged and blocks fresh admission with `allocation_refusal_accounting_unproved`. Orphan cleanup requires validated ownership and retirement, not age/name.

### Op17 request and reply adoption

Extension 29 uses an **80-byte, pack-4** payload:

| Offset | Field |
|---:|---|
| 0 / 4 / 8 | Version / StructSize / DriverInstanceId |
| 24 | DrainNonce, uint64 |
| 32 / 36 | Original OS boot sequence / proof flags, uint32 |
| 40 / 48 | Private-state revision / last pre-retirement RequestId, uint64 |
| 56 | QuiescenceNonce, GUID |
| 72 | Reserved zero, uint64 |

Outer PID/flags/path are zero. ProofFlags=0 is a **nonterminal preflight audit**, permitted only before retirement, returning `EpochReady` or a named blocker. It does not retire or authorize reclamation. Final ProofFlags=`0xF` attests permanently closed admission, drained producers, drained prior request uses and ended relevant local lifetimes. Private revision changes with relevant state/ownership; it is not lifetime proof.

Preflight includes durable retained-residue inventory under the default above. Recheck all operational/durable obligations before entering retirement; no cleanup requiring future service traffic may remain.

Final request is constructed and frozen before entering R below. Persist agent `Retiring` with the exact request before waiting for continuation drain; uncertain persistence never permits reactivation. Persist `EpochRetired` only after complete audit/quiescence. Preserve this record until reclamation finishes, rather than overwrite the sole epoch file.

Driver accepts only the legal reply for the saved request, correct complete echo/nonce/driver/boot/revision, zero fields, required receipt and current authenticated transport. Old `EPOCH_DRAINED` is not the extension-29 retirement result.

### One state machine, shared with the unload note

| State | Allowed work and transition |
|---|---|
| **P — Reversible preparation** | Close unload-owned admission, drain control bodies and inspect operational/durable obligations; op17 preflight is nonterminal. Veto may restore only unload-owned gates and exact prior work. No Unknown clear. If cleanup may commit, enter Q. If every prerequisite is proved, freeze final op17 and enter R. |
| **Q — Cleanup quarantine** | App admission stays closed. Complete only already-identified exact cleanup/bookkeeping, required service-private bookkeeping CREATE and current-channel reconciliation needed for it. Recheck all obligations, including retained residue. No epoch retirement yet. Then enter R; no rollback to P. |
| **R — Retirement-only** | Permanently fence every ordinary sender/authority path and drain previously admitted uses. Only the saved final op17 request/replay and necessary local draining are allowed. Agent closes epoch admission, drains prior continuations and audits terminal/absent obligations. No return to P/Q. |
| **E — Epoch retired, local commit pending** | Exact `EpochRetired` adopted. Keep all fences. Final operational recheck/fence commit may veto, but leaves E and local-drain-only progress; no ordinary RPC/reconciliation or service bookkeeping CREATE resumes. Once checks pass, enter T without a new epoch request. |
| **T — Committed local teardown** | Common permanent teardown: close ports/owned holds, join workers, drain actual users, release instance pins, unregister and free after source barriers. No veto/rollback/reopen; genuine lifetime waits may be unbounded. |

In R, `Held`/EpochBusy, retryable failure, DENY, malformed or lost reply **all retain R**. Retry only immutable final op17 when applicable; an unexpected unresolved obligation remains named and fail-closed. Local events/operator retry may recheck; timers provide no evidence.

Reconnect in R/E authenticates a **retirement-only transport** without op11, ordinary capability activation, startup recovery or a full stream sweep. It can deliver only the saved final op17/reply; the new peer must support the required family. E may re-fetch that same receipt if needed, never re-create authority.

Replace current post-ACK and shared veto behavior at `K/StageStream.c:7757–7773`, `:7793–7801`: `StageUnloadPrepareWork=TRUE` and general callback reopen must not restore collectors or bookkeeping CREATE in R/E. A narrow local-release gate admits CLEANUP/CLOSE/completion/rundown only. Only P may call reversible rollback; Q’s exact cleanup eligibility is not R/E eligibility.

### Every sender and continuation

Enforce the phase gate at collection **and the common transport/control entry**, including already-collected batches.

Before R, finish/quiesce: allocation/follow-up/create-after and recovery; attach 12–16/18 and op19; seal; rename prepare/commit/abort; discard; op23; private cancellation; native/public-open/disposition preparation and facts; publication/metadata/observation/Facts/ACK controls; epoch reconciliation; legacy/advisory sends and canary/fence/activation/reclaim work that can send, create ownership or touch filesystem state. R/E permit none of these new exchanges. Only exact final op17 can obtain a retirement send pin. Local release work remains resident and counted.

The agent epoch gate covers receive-loop inline handlers, deferred allocation/seal/op23/rename/native/public continuations, startup/private/native recovery, inspection/publication and its native controls, discard/BLOCK/released-stage cleanup, hand-back/justification work that can authorize or mutate, and their queued/destination-turn waiters. Quiesce them **before R**; at retirement entry drain pre-admitted bodies/I/O and unfinished recording without repeating mutations. No new epoch continuation starts. The op17 coordinator must not wait on itself, hold journal/namespace locks, or occupy the receive loop.

Canceling a task is not proof it drained. An accepted mutation with unresolved recording blocks retirement; later reply transmission is not retirement evidence. Status/notification delivery grants no work authority.

Qualified full Restart still requires greater trusted boot, different driver, complete authenticated replay and successful private recovery. Retained residue still blocks retirement under the conservative default. Preserve old active/blocked retirement evidence before recording a new epoch; new-boot admission does not falsely retire old residue or reclaim its charges. GUID change, service restart, Fast Startup, native-map absence and counter rollback/wrap are insufficient.

Reclamation requires durable retirement plus quiescence. Persist reclamation intent, remove only exact validated receipts, confirm removal, then release charges; failures remain charged. Bound/charge retirement metadata and reserve separate recovery headroom. Keep generation/published/delete floors and all custody dependencies.

## 6. Locks, scheduling and mandatory teardown

- New snapshots, attestations, claims and residue tickets are capacity-reserved **nonpaged** ownership. Spin-lock/DPC/elevated-IRQL release bodies remain resident.
- Preserve namespace → stream Resource/StageListLock, exposure arbitration under StageAttachLock and existing native/publication orders. No reverse acquisition.
- Pin exact stream/request at PASSIVE, release resources for RPC/I/O, then revalidate before adoption. One release per attempt; no I/O, allocation, close or wait under spin locks or callback-needed resources.
- Close backing/backend holds outside locks before dependent waits. Completion/rollback, genuine CLEANUP/CLOSE and last reference release wake local/recovery work; owner exit only schedules evaluation.
- Before R, persistent causes/deadlines survive pending→in-flight→reply. Count eligible in-flight obligations; use existing 250 ms–8 s exchange backoff and genuine drain/unmap behavior. SERVICE/refusal/capacity holds do not poll. DPC is wake-only; arm from `KeReadStateTimer`, cancel/reset when no eligible work remains.
- R/E timers/wakes cannot run ordinary collectors, op11 or startup seal. They pace only eligible immutable retirement replay/local checks. Disconnect/reconnect never lowers phase.
- Recovery runs off the receive loop; ordinary startup permits exact pending recovery without fresh admission only in P/Q-compatible active epochs. Durable Retiring/Retired is checked before dispatch.
- Mandatory teardown bypasses voluntary preflight/op17 and uses service-independent permanent local drain. It synthesizes no receipt, seal, deletion or epoch retirement. Sticky Unknown/coverage-loss constraints remain.

## 7. Controls, delivery and decisions

Agent tests use actual handlers, fresh journals and `MemoryMarshal` wire bytes:

| Group | Required cases |
|---|---|
| Harness patterns | Resave/new/replace/mapped × approve/BLOCK; empty; name reuse; occupied-name generation adoption; BLOCK then resave before/after retirement; independent public bytes. |
| Seal | Crashes before/after atomic intent+SealPending and measurement, startup/direct/Transition/migration entry points, missing/tampered intent, exited owner, progressed states and cleanup. Lost replies at inspection/approval/BLOCK/publication/disposal/cleanup boundaries never increase mutation counters. |
| Attachment | Every prepare/commit/op15/op23 reply loss; exit/never retry/PID reuse; owner retry versus recovery; refusal versus permission/delayed op15; success return and cleanup in either order; late failure and coverage loss. |
| Canceled lifetime | Before-claim rollback resolves only with full proof; claim followed by CLOSE without CLEANUP preserves the named hold, flags/reservation and no op19/seal/delete. Duplicate/inherited handles, independent objects, mappings/cache/paging and upper cancellation remain distinct. |
| Custody/accounting | Default residue veto after shell release/restart; unapproved exception cannot activate; custody/dependency corruption; count/byte limits, temporary/orphan overlap, disk full and exact replay during exhaustion. |
| Epoch/unload | P rollback; Q cleanup; R lost request/reply; E post-ACK policy/fence veto; reconnect in each phase; pre-admitted agent continuation; no forbidden send/control/mutation after R; restart versus old-residue retirement; reclamation crashes. |
| Wire/compaction | Every envelope/tuple/owner/view/reference/proof/result/connection/tail mutation; stronger hold cannot be cleared by stale reply; retain receipt/ancestry/floors until exact retirement. |

Extend existing allocation, attachment/journal and publication controls without removing/renaming tests or weakening assertions. Kernel properties/mutations must catch: missing atomic intent, alternate seal entry bypass, live-process seal requirement, fabricated cleanup/op19, early fence/reservation clear, exposure reset, concurrent recovery/resume, wrong tuple adoption, missing/double pins, spin/PAGE violations, in-flight census loss/refusal polling, premature accounting/reclamation, residue ticket loss, and **every R/E reopen/send path**, including current post-ACK veto branches.

Batch coherent contracts/persistence/worker/accounting/compaction/unload integration. Then local four-profile compile and test preflight/all T5 controls; complete agent matrix and four WDK/PREfast/ApiValidator/import gates; fresh independent Sol 6.1 xhigh combined review; authorized matched-pair fault/Verifier/raw-byte/restoration rows. Source acceptance, component results and qualification are separate.

Pending choices:

| Decision | Recommendation and user effect |
|---|---|
| Receipt budgets | Evaluate 4,096 refusal slots and 64 MiB charged refusal storage plus reserved recovery headroom; measured defaults require approval. Exhaustion stops fresh protected allocation with a named explanation while permitted exact replay continues. Charge seal/attachment retention too. |
| Retained residue exception | Recommend only the custody conditions in section 4. **Default veto remains implemented until owner approval.** Exception would permit unload while bytes remain private/charged; automatic deletion remains excluded. |
| Missing evidence | Keep named holds and existing applicable remedies; no expiry, manual unlock, SYSTEM authority or broader restart inference. |

Unreadable-seed option 1, metadata/security, generation/delete invariants, bound-readiness blockers and unsupported destinations remain unchanged. The cancellation-CLOSE hold is explicit; this note does not claim complete recovery qualification.
