# T5 batch 2: recovery holds and released-stage delete receipts

**Proposal against `27f570b78df33e01bc00d45225a40f6a5c6f5c00`, 2026-10-14.** Read-only source/design review; no edits, builds, tests or VM contact. Checkout clean. This revision has not been independently accepted.

The [2026-10-14 scope decision](POST-MVP-PLAN.md) under “Batched recovery holds + voluntary unload” defines batch 2 as:

1. Exact seal request/receipt recovery.
2. Typed op15 refusal, exposure evidence and op23 recovery.
3. Refusal accounting **without reclamation**.
4. Negotiated per-version driver-delete receipts for normally released stages.

The [re-review](evidence/2026-10-14/t5-designs-rereview-sol61.md) resolved the earlier seal, exposure and historical-owner design findings. Its three new retirement findings are deferred as specified in section 8. The delete receipt addresses [agent-loop RCA defect 2](evidence/2026-10-14/m2t5purgeattr1-agent-loop-rca-sol61.md). The completed-BLOCK idle-loop fix belongs to batch 1.

References use `K/` for `driver/SafeUpload.Minifilter/` and `A/` for `agente/SafeUpload.Agent.Service/Interception/`. Verified statements describe source; new contracts, attestations and controls are proposals.

## 1. Verified defects

| Hold | Current mechanism |
|---|---|
| Lost seal ACK | The kernel drains and selects read-only backing, but assigns a fresh RequestId per seal attempt (`K/StageStream.c:5706,5741,6070`; `K/StageProtocol.c:2145`). Journal `SealPending` omits the request; startup resumes without it (`A/StagedTransferJournal.cs:2143–2182,3116–3121`). Replay rejects cleanup/current-object changes, and the handler requires exactly `Sealed` despite possible inspection/publication progress (`:2126–2137`; `A/MinifilterInterceptor.cs:1249`). |
| Lost op15 / late fence | Op15 records permission, not delivery (`A/StagedTransferJournal.cs:882–972`). Failed CREATE rolls back; only exact owner retry resumes. Maintenance parks completion/fence flags, which also exclude op19 collection (`K/StageStream.c:1746–1778,3690–3774,5960,6285–6288`). Late validation can fail after preliminary attachment bookkeeping. Canceled CREATE can reach CLOSE without CLEANUP (`:4080–4219,5448`). |
| Refusal storage | Serialized allocation resolution writes exact 1,192-byte negative receipts after unjournaled-backing cleanup, but has no cumulative budget (`A/StagedAllocationResolution.cs:28–103`). Existing epoch drain scans manifests, not refusal files (`A/StagedTransferJournal.cs:93–124`). |
| Released-stage cleanup after restart | Publisher returns for driver-held disposal, leaving `StageDeleted=false`; startup later retries. The driver verifies identity, applies disposition, closes backing and frees the stream, retaining only counters (`A/StagedTransferPublisher.cs:502`; `K/StageStream.c:5818–5892,1496`). Startup’s leaf `GetAttributes` fails before absence-capable bookkeeping (`A/MinifilterInterceptor.cs:1652`; Publisher `:1007–1011`). `Held=0` merely means no listed stream (`K/StageStream.c:6958`); its eight-byte reply proves no deletion. |

These are verified source mechanisms and source-derived interleavings, not new runtime reproductions. Historical counters, missing paths and digests cannot reconstruct a per-version delete receipt.

## 2. Negotiation, common wire and validation

Preserve existing layouts and numeric values. Proposed batch-2 capabilities:

| Capability | Bit |
|---|---:|
| Exact durable seal request/receipt | `0x200` |
| Op15 refusal/exposure/op23 recovery | `0x400` |
| Refusal accounting, without reclamation | `0x800` |
| Exact released-stage driver-delete receipt | `0x1000` |

Required feature mask becomes **`0x1FBF`**, replacing `0x1BF`. There is **no durable-retirement capability**. These new bits are unshipped proposals; `0x800` denotes accounting only. Bound-head bit `0x40` remains independently disabled. Normal builds compile staging out.

Reserve extension **29**, operation **23** for attachment recovery, operation **24** for driver-delete receipts, and control **35** for exact released-stage disposal/query. These identifiers are unused in inspected source; assert availability before implementation.

Old/incomplete masks cannot activate batch 2. Normal op11 negotiation rejects them or returns EpochBusy with accepted mask zero. No fallback to old seal ACK, generic op15 DENY, or `Held=0` deletion inference. Existing op17 remains **V20/EPOCH_DRAINED**; it receives no extension-29 payload, new result or reclamation meaning.

### Operations 4, 15 and 23

Use the unchanged 1,192-byte outer request with this **124-byte, pack-4** payload:

| Offset | Field |
|---:|---|
| 0 / 4 | ExtensionVersion / StructSize, uint32 |
| 8 | TransferId, GUID |
| 24 | DestinationGeneration, uint64 |
| 32 | StageIdentity: volume serial + FILE_ID_128, 24 bytes |
| 56 | DriverInstanceId, GUID |
| 72 | ParentDirectoryIdentity, 24 bytes |
| 96 | Original owner creation time, int64 |
| 104 | ViewGeneration, uint64 |
| 112 | ReferenceRequestId, uint64 |
| 120 | ProofKind, uint32 |

Outer fields supply version/size, nonzero RequestId, operation, original owner PID, permitted flags, extension marker, lengths and path. Unused bytes are zero.

- Op4: original private stage path; genuine durable op19 reference; ProofKind=0.
- Op15: exact destination; committed op13 reference; ProofKind=0.
- Op23: original op15 destination/authority tuple and RequestId; proof from section 4. A newer attestation gets a new immutable request, never modifies an in-flight one.

Validate every envelope/length/tail/flag, full replay bytes, transfer/full identity/generation, original epoch, historical PID/creation, parent/view and phase reference. Bind view on first op15 and preserve exact rename history. Bound entries additionally require their original mount/root/parent/case/leaf, security, ancestry and seed dependencies.

| Operation | Authority requirement |
|---|---|
| Fresh op15 permission | Live original owner/effective authority, current admission, exact allocation/commit/view/parent, native grant/share/security and seed prerequisites. PID identity alone is insufficient. |
| Op15 replay | Exact immutable saved outcome; no new grant or live-process refresh. |
| First/resumed seal | Historical owner binding, genuine durable op19 and authenticated completed T4 drain/irreversible read-only attestation, exact backing/length/seed evidence. **No live-process requirement.** |
| Op23 | Exact original allocation/op15 chain and authenticated kernel attestation; no new caller/file object. |
| Inspection/publication | Exact measured seal receipt, current policy, current destination/generation/delete floors and existing publication authority. |
| Driver-delete receipt | Exact prior release intent, historical version/object/epoch and actual disposition/lifetime/removal evidence; no new public mutation authority. |

### Typed replies for operations 4, 15, 23 and 24

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

Define operation-specific results without renumbering old enums. Nonapplicable fields are zero. Durable results require ReceiptId; transient/held replies carry no completion authority. Op24’s ReceiptId must equal the driver’s receipt ID.

Adoption requires actual successful transport, complete echo, legal result, exact sizes/zeros, current authenticated connection/authority and pinned local-state revalidation. Timeout, pending/reparse status, malformed reply or generic verdict cannot be typed success. Reconnect changes transport headers, never immutable evidence.

## 3. Exact seal recovery

Retain one kernel request/RequestId before sending; retry identical bytes.

Atomically persist **`SealIntent` together with `SealPending`, before measurement**. Include complete request, ReceiptId, original driver/boot and historical owner binding, destination identity, exact object/generation, genuine op19 reference and drain attestation. Reserve storage before replacement. New `SealPending` without intent is invalid.

Measurement resumes only from that intent. Atomically add measured length and `SealReceipt` on classification, preserving intent. Inspection cannot consume the version before this replacement. Zero length follows the ordinary path.

All entry points use the same helper:

- synchronous/async interceptor handlers and direct `SealAsync`;
- `TransitionAsync(..., Sealed)` (`A/StagedTransferJournal.cs:1977–1986`);
- startup `RetainInterruptedAsync` (`:3116–3121`);
- legacy-empty migration and publisher/startup callers (`:2236`; `A/StagedTransferPublisher.cs:117`).

Supply an authenticated exact request or resume the identical stored intent. Do not construct one from manifest fields. Missing/mismatched intent stays nonpublishable with `seal_request_unavailable`/`seal_request_mismatch`. Historical state/length/digest does not waive this requirement. Exact bookkeeping of an already-completed publication may finish; publication is never repeated.

Startup retries unfinished measurement only with validated original evidence and exact frozen backing. Missing backing, changed identity, missing drain/seed or lifetime uncertainty stays held.

Completed receipt lookup precedes current-head/backing/cleanup checks. Exact replay in progressed states or after cleanup acknowledges historical measurement without reopening, remeasuring, inspecting or publishing.

| Reply | Driver action |
|---|---|
| `SealRecorded` | Clear matching seal pending/in-flight, set ordinary local `Sealed`, save receipt and wake disposal/retirement. Release attempt pin once; keep independent lifetime/cleanup/publication obligations. |
| Retryable | Keep exact request; release attempt pin only; bounded EXCHANGE retry of unfinished work. |
| Held/DENY/malformed | Keep request/lifetimes; park SERVICE with named reason, without refusal polling. |
| Disconnect/lost/stale | Keep request; normal authenticated reconciliation/reconnect retries it. Old-channel ACK cannot apply. |

Compaction retains intent, receipt and dependencies while replay remains possible. Charge storage cumulatively. This batch introduces no epoch-based receipt reclamation.

## 4. Op15 and exposure recovery

### Durable outcome

Serialize permission/refusal/recovery closure under the journal gate. Persist complete original op15 and immutable outcome before reply. Existing exact outcome wins before live-owner checks. Definitive refusal requires proving no permission committed; uncertain storage/query or invalid authority gives no definitive negative.

| Reply | Driver action |
|---|---|
| `CompletionPermitted` | Record known/may-exist permission; continue original validation/cancellation. Reply alone releases no reservation. |
| `CompletionRefused` | Prohibit exposure; queue op23 after actual rollback/completion drains. Keep receipt/reservation/predecessor meanwhile. Sent op15 cannot enter op16/kind-5. |
| Retryable | Preserve ambiguity; complete/roll back original CREATE once; recover evidence, not another CREATE. |
| Held/DENY/malformed/disconnect | Preserve ambiguity and named hold. |

### Monotonic evidence and op23

Retain allocation-level exposure claim, completion classification/return, rollback, real per-object CLEANUP/CLOSE, lookup/callback ownership and cache/paging evidence after transaction destruction. Keep raw status/information locally. Latch `ExposurePossible` under final `StageAttachLock` arbitration **before** successful completion; it means possible exposure, not delivered handle, and never resets.

| ProofKind | Kernel attestation / agent transition |
|---:|---|
| 1 — `NeverExposed` | All relevant CREATEs returned failure, no claim ever occurred, rollback/full local drain proved. Persist retained-unexposed custody; close absent op15 outcome with refusal first. |
| 2 — `ExposurePossible` | Claim occurred, completion/return unresolved. Persist `AttachmentRecoveryState=ExposurePossible`; `HandleLifecycleRequired` authorizes no pending/fence clear. |
| 3 — `CompletionSuccessReturned` | Exact successful original completion returned and attach/cancel arbitration finished. Require durable permitted op15; persist immutable completion attestation, retain `CompletionPermitted`; return `HandleLifecycleRequired`. |
| 4 — `RealCleanupAfterExposure` | Cumulative success-return plus actual owned CLEANUP. Persist both facts; return `HandleLifecycleRequired`, **without writing op19**. |
| 5 — `CloseWithoutCleanupUnproved` | Exact owned CLOSE without real CLEANUP after possible exposure/cancellation. Retain `attach_canceled_close_lifetime_unproved`. |
| 6 — `CoverageLost` | Required callback/tracking evidence lost. Retain `attach_lifetime_unproved`. |
| 7 — `CompletionFailureAfterExposure` | Failure after claim or unproved canceled-before-handle route. Record failure and retain `attach_exposure_unproved`; never convert to NeverExposed. |

Reject impossible combinations, altered references and conflicts with refused op15/retained-unexposed evidence. Exposure without exact durable permission remains `attach_outcome_unproved`; recovery cannot mint permission.

| Event | Resolution |
|---|---|
| Failure/cancellation before claim | ProofKind 1 only after actual rollback/completion and full drain; no synthetic CLEANUP/op19/seal. |
| Success returned | ProofKind 3 and exact durable reply finish bookkeeping below. Normal and recovery paths share this transition; original CREATE completes only once. |
| CLEANUP before success bookkeeping | Record genuine cleanup immediately, defer op19; ProofKind 4 finishes bookkeeping then queues real op19. |
| CLOSE after CLEANUP | Release actual object/lease ownership; retain cleanup/op19 obligation. CLOSE does not prove deletion. |
| Canceled CREATE reaches CLOSE without CLEANUP | The inspected source provides no proved cancellation-CLOSE no-handle construction. **Keep the named hold**, with no fabricated op19, seal or deletion. A resolving route requires separate exact proof/review. |
| Unknown completion/failure after claim/coverage loss | Retain the applicable named hold despite actual reference releases. |
| Owner exit | Scheduling only; preserve historical binding and unresolved allocation-owned reservation. |

### Flags, reservations and pins

Recovery versus owner resume serializes under `StageNamespaceResource`; competing rename/terminal work cannot change the tuple. Each RPC has one stream pin; transaction/callback/lookup owners drain separately.

A validated ProofKind 3/4 reply requires exact permitted op15, completion-return evidence, no active producer/conflicting terminal claim/coverage hold. Then, for this original completed CREATE only:

- set `AttachCompletionKnown/MayExist`, `AttachAcknowledged`; clear `AttachCompletionPending/Fence`;
- clear allocation receipt/recovery/tuple bookkeeping only after its attempts drain; unlink only its reservation;
- release its single predecessor receipt reference and wake that predecessor;
- clear allocation-only `PrivateDeleteReserved` only absent actual discard/delete-on-close;
- preserve genuine `AnyHandleCleanupObserved`; if set and op19 unacknowledged, retain/set `HandleReceiptPending` and wake collection;
- retain actual handle/object/share/cache/paging/instance/lease ownership until release. Do not set op19 ACK, seal, retirement or deletion flags.

ProofKind 2 performs none of those clears. ProofKind 5/6/7 retains unresolved flags/reservations; CLOSE releases only actual ownership. Weaker/stale replies cannot clear stronger holds.

Genuine op19 remains `CompletionPermitted → HandleObserved` through exact durable reply (`A/StagedTransferJournal.cs:1011–1025`; `K/StageStream.c:6309–6359`). Only then may T4 drain/read-only seal proceed, including after owner exit. Discard remains separate; op16/op18/kind-5 cannot resolve op15 ambiguity.

For NeverExposed, prove no app objects/shares/cache/sections/paging users, attach producers/lookups or competing RPC/rename/cancellation; close driver holds outside callback-needed locks. Zero samples alone are insufficient.

Persist `RetainedUnexposed` custody with exact request/object/version, bytes, ancestry/security/provenance/accounting. Its reply permits matching view detachment, pending/fence/allocation reservation and one predecessor-pin release. Free drained shell memory through a distinct predicate, never synthetic seal/discard/deletion.

**Conservative default applied:** retain a bounded charged residue ticket/custody inventory; retained bytes still veto voluntary unload and existing epoch drain. Missing custody is `retained_unexposed_custody_unproved`; confirmed residue is `retained_unexposed_blocks_unload`. Restart/counters/name release do not clear it. Nothing is automatically deleted, seeded, exported or published.

The recommended custody exception remains **unapproved and unimplemented**: only exact fully drained never-exposed service-private custody, reconstructed charges, retained ancestry/security/provenance/floors, no public/cleanup/uncertain obligation and permanent nonpublication/nonseeding could qualify. It would permit unload while bytes remain charged/private. Automatic deletion and exposure/coverage exceptions remain excluded.

## 5. Refusal accounting without reclamation

Keep operation 3’s 72-byte V20 request and full validation: intent version/size, reservation/predecessor, disposition/reference kind, driver and original creation time; outer RequestId/PID/flags/destination.

Reserve a potential refusal slot and worst-case storage **before fresh backing or receipt creation** under allocator/accounting serialization. Exact replay consumes no new slot. Verified positive allocation may release the unused potential-refusal reservation; uncertain commit remains charged.

Charge committed file allocation, temporary overlap/crash orphans, bounded accounting metadata and filesystem overhead allowance; also check volume headroom. A live-stream bound or 1,192-byte payload alone is insufficient.

Keep the 1,216-byte complete-request-echo reply; accounting capability `0x800` adds result 21:

| Reply | Driver action |
|---|---|
| Exact allocation tuple | Existing adoption/attachment/cleanup route. |
| 20 — no allocation committed | Exact shell reservation and one predecessor-pin release; no predecessor-state change. |
| 19 — transient | Keep exact request/reservation/pin; bounded EXCHANGE retry. |
| 21 — capacity unavailable | No backing/generation/refusal committed. Keep exact request/reservation/pin; park SERVICE as `allocation_refusal_budget_exhausted`. Retry after reconciled reconnect following approved capacity restoration; no polling. |
| DENY/malformed/lost/disconnect | Preserve hold; no terminal release. |

Startup validates and reconstructs committed refusal, temporary/orphan and uncertain charges, including legacy receipts. Invalid/conflicting/unreadable evidence stays conservatively charged and blocks fresh admission with `allocation_refusal_accounting_unproved`.

**No committed allocation-refusal receipt is retired, compacted, deleted or uncharged in batch 2.** Service restart, Windows Restart, existing `EPOCH_DRAINED`, reply delivery, elapsed time and apparent absence authorize no reclamation. Failed uncommitted work releases reservations only after actual operation drain and verified absence of its storage; that is not committed-receipt reclamation.

Valid durable refusal files alone need not veto unload once their kernel requests/reservations/pins have resolved and accounting is consistent. They remain charged on disk after unload/restart. Unresolved requests, dirty/uncertain accounting or outstanding storage operations still veto. Increasing an approved budget may restore capacity; restart cannot reset it.

## 6. Exact released-stage driver-delete receipt

This applies to **normally Released**, published versions with `HandbackState=NotAttempted`. Justified/blocked hand-back cleanup retains its separate exact receipt path. No public file is deleted by this protocol.

### Exact release intent: control 35

Before sending, the agent persists an immutable release intent naming the original version, stage path and checked private-directory binding, driver epoch, committed rename count and unique ReleaseNonce. Do not initiate deletion from a mere missing leaf.

Use **128-byte, pack-4** control input:

| Offset | Field |
|---:|---|
| 0 | Existing core Control, 16 bytes: Version=18, StructSize=128, Command=35, Reserved=0 |
| 16 / 20 | ExtensionVersion=29 / Phase, uint32 |
| 24 / 40 | DriverInstanceId / TransferId, GUID |
| 56 | DestinationGeneration, uint64 |
| 64 | StageIdentity, 24 bytes |
| 88 / 92 | CommittedRenames / Outcome, uint32 |
| 96 | ReleaseNonce, GUID |
| 112 | ExpectedReceiptId, GUID |

Phase 1=`Release`: ExpectedReceiptId is zero. Phase 2=`Query`: zero discovers the existing binding; nonzero must match it. Outcome must be existing Released value 1. Other fields must be nonzero/valid as applicable.

Reply is **168 bytes**:

| Offset | Field |
|---:|---|
| 0 | Entire 128-byte input echo |
| 128 | ReceiptId, GUID |
| 144 / 148 | Result / Reserved=0, uint32 |
| 152 / 160 | Current connection epoch / authority revision, uint64 |

Results distinguish `ReleaseAccepted`, `ReceiptPending`, `ReceiptReady`, `ReceiptUnavailable`, `TupleRefused`, `RetryableFailure`, `CapacityUnavailable` and `NotReady`. Query never authorizes deletion or supplies the completion facts by itself.

Kernel validation requires current authenticated service, negotiated mask, exact original driver/transfer/generation/full identity/rename count, Released outcome and immutable nonce. Same-nonce replay is idempotent; changed nonce/tuple refuses. Read mutable state through its proper locks/nonpaged snapshots; no namespace acquisition from a callback needed by a worker RPC.

For Release, reserve record capacity and publish the exact binding **before** setting disposal/queueing work. Capacity/allocation failure changes no disposal state. A replay returns the same ReceiptId without another reservation or delete. Query reads existing stream/receipt ownership and may wake pending delivery; absence from both is `ReceiptUnavailable`, never successful deletion.

The agent checks every echo/header/result and current connection. It durably binds returned ReceiptId to its existing ReleaseNonce. If the initial reply was lost, Query recovers that binding. For negotiated Released traffic, old control-29 `Held` replies are not completion authority; retain old layouts for their existing uses, including the separate CleanedUp path.

### Kernel evidence, lifetime and accounting

Maintain a separate bounded **nonpaged** receipt map, surviving stream release. Reserve factories before allocation and count reserved, waiting, deleting, replay-pending and in-flight records together. Proposed development ceiling: **1,024 slots**, reused only after acknowledged records actually free; it is not a per-boot counter.

A record owns its exact release input, ReceiptId, original boot/driver, stage locator and private-parent anchor, immutable completed facts, full saved operation-24 request, state and reference/work accounting. Bound record payload to 4,096 bytes with compile-time assertions; separately charge bounded RPC scratch and map/factory metadata. All temporarily retained stream/instance/handle owners remain in existing bounded accounting; do not return a stream slot while its memory is retained.

State progression:

`Reserved → WaitingLocalLifetime → DeleteClaimed → DispositionAccepted → LocalLifetimeComplete → CompletionReady → AgentAcknowledged`.

- Claim deletion under namespace serialization against attach/rename/follow-up/discard. Require ordinary seal/op19, Released disposal and exact rename count. Detach only the already-disposed private view.
- Keep stream ownership/count until actual destruction. Perform context/paging drain, identity/security/type checks, opens, disposition and closes outside namespace/spin locks.
- Verify the original backing and DELETE-open object both match recorded volume/FILE_ID_128; require regular, non-reparse, single-link private backing and checked parent.
- Record actual final disposition status immediately. Once accepted, never issue disposition again. Lost replies/storage failures retry evidence delivery/bookkeeping only. Indeterminate outcome stays `driver_stage_delete_outcome_unproved`.
- Close every driver-owned stage handle and release stage-object references after real upper-object/share/cache/section/paging/callback/RPC drain. Preserve actual ordering; counters alone do not attest it.
- Confirm removal through complete stable observation under the checked private-parent/volume binding after close. Exact prior disposition plus lifetime evidence qualifies absence; pathname absence alone does not. Pending original link, replacement, changed/reparse parent, access error or incomplete observation remains held.
- Publish terminal immutable evidence before freeing the stream. No retained terminal record owns a stage FILE_OBJECT or handle that could delay deletion. Release temporary instance/observer pins after their work drains.

Reserve before mutation, so no allocation is needed after disposition to save its result. Publish map ownership before unlinking the stream, closing the current “not listed but teardown unfinished” gap. ACK cannot free a record with factory/work/send/lookup uses; unlink under lock and destroy/release charges outside it after the last use.

Pre-disposition transient preparation and genuine unsignaled drain waits use existing bounded scheduling. Accepted/uncertain disposition is never repeated. Explicit evidence mismatch parks with named diagnostics. Own close/drain/reference events, normal reconnect and exact Query wake the worker; timers merely request fresh qualifying observation.

### Operation 24: retained evidence replay

Send only `CompletionReady` evidence using extension 29 and this **124-byte, pack-4** payload:

| Offset | Field |
|---:|---|
| 0 / 4 | ExtensionVersion=29 / StructSize=124, uint32 |
| 8 | ReceiptId, GUID |
| 24 / 40 | Original DriverInstanceId / TransferId, GUID |
| 56 | DestinationGeneration, uint64 |
| 64 | StageIdentity, 24 bytes |
| 88 / 92 | CommittedRenames / DisposeOutcome=Released(1), uint32 |
| 96 / 100 | DispositionClass=`FileDispositionInformation` / DeleteFile=1, uint32 |
| 104 / 108 | Actual final DispositionStatus / DrainStatus, int32 |
| 112 / 116 | CompletionFacts / OriginalBootSequence, uint32 |
| 120 | Reserved=0, uint32 |

Outer request: core version/size, retained nonzero RequestId, Operation=24, RequestorProcessId=0, Flags=`StageV19ReplyFlag` only, Reserved=29, ImageNameLength=124, original private-stage NT locator in Path and zero tails. No token, pointer or handle is exported.

CompletionFacts bits are:

| Bit | Attested fact |
|---:|---|
| `0x001` | Exact Released disposal intent bound |
| `0x002` | Exact object/type/single-link/parent verified |
| `0x004` | Genuine T4 drain complete |
| `0x008` | Upper application-object/share lifetime ended |
| `0x010` | Cache/section/paging/callback/RPC users drained |
| `0x020` | Original exact disposition accepted |
| `0x040` | All driver-owned stage handles closed |
| `0x080` | Driver-owned stage-object references released |
| `0x100` | Exact qualified removal confirmed |

Terminal replay requires **`0x1FF`**, no higher bits, and strict successful final disposition/drain statuses. Positive-indeterminate status, local close alone or forced coverage loss cannot produce CompletionReady.

Retain identical request bytes/RequestId through every retry. Copy/pin under the receipt-map lock, send at PASSIVE outside locks, then revalidate the record and current channel before adoption.

### Agent validation and absence-tolerant completion

Validate:

- complete envelope, exact payload/flags/PID/path/tails;
- driver/boot against authenticated origin binding and original manifest epoch;
- transfer, positive generation and full stage identity against the exact Released manifest;
- rename count against the same committed chain used by disposal;
- Released outcome, ordinary non-hand-back eligibility, no pending rename/conflicting cleanup;
- ReceiptId against saved release intent, or exact control-35 Query binding after lost initial reply;
- disposition class/flag, actual strict final statuses and complete `0x1FF` facts;
- lexical owned stage locator and saved private-parent identity; fresh anchored observation must not show a replacement, pending original, reparse/access ambiguity or incomplete result.

Do not require a live original owner or current public-name generation: this completes historical private cleanup, not publication. It must not change published/delete floors or remove a newer version.

Replace unconditional leaf `GetAttributes` with lexical containment plus checked parent/ancestor validation and absence-capable observation. **Only a matching complete receipt** permits absent-stage completion. Persist the raw request/receipt, exact release-intent binding and `StageDeleted=true` in one atomic manifest replacement before ACK. Fault after replacement is recovered by exact reread, not a second delete.

A same receipt replays this durable completion. Changed receipt/tuple or conflicting evidence stays `released_stage_delete_receipt_mismatch`/`released_stage_delete_observation_unproved`. Historical driver-owned entries without receipt stay **`released_stage_delete_receipt_unavailable`**; aggregate counters, `Held=0`, missing path, digest or reboot cannot certify them. No agent-only missing-file catch changes this.

| Agent reply | What the driver does |
|---|---|
| `DriverDeleteRecorded` | Require exact full echo, matching ReceiptId, zero nonapplicable fields and current authenticated channel. Mark acknowledged, remove only this record’s map ownership, then free after all local uses drain. No stage/public mutation or successor-state change. |
| `RetryableFailure` | Keep immutable terminal evidence and accounting; release attempt pin only; bounded EXCHANGE retry of recording/delivery, never disposition. |
| Typed Held or generic DENY | Keep record and unload obligation; park SERVICE with named reason. Query/reconciled reconnect can retry; no refusal polling. |
| Malformed/wrong receipt/stale reply | Keep record; release attempt pin once; no ACK adoption. |
| Lost reply/disconnect | Keep record/request; normal authenticated reconnect replays it. Agent returns saved completion if replacement had committed. |

The agent persists completion before replying; reply transmission alone does not release kernel ownership. Durable receipt/dependency storage remains charged and pinned in this batch; kernel ACK-based memory release is not allocation-refusal reclamation.

### Restart and delivery limitations

Use existing normal SET_POLICY/authentication commit/op11 bootstrap and the new required mask. No retirement-only bootstrap is added. Op24 is receipt bookkeeping, not fresh staging authority; its handler must not require inspection/publication recovery readiness once normal authenticated driver binding/compatibility is established. Startup must not block negotiation or the receive loop waiting for a receipt its kernel sender cannot yet deliver: record the per-version hold, finish normal bootstrap and retry through the connected receipt worker.

Service restart with the same loaded driver replays retained nonpaged evidence. If the agent already persisted the receipt, startup finishes/replays bookkeeping without new deletion.

Voluntary unload is vetoed until ACK and local record-use drain. Mandatory teardown/reboot sends no fresh receipt RPC and fabricates no ACK; after local rundown it may destroy volatile memory. If no durable agent receipt survived that loss, the entry remains named and held. A different driver/boot cannot recreate it. This batch does not promise cold-driver recovery of unpersisted delete evidence.

Completed cleanup leaves pending dispatch; genuine unfinished disposal/recording has bounded backoff, while evidence-dependent holds park. Do not reinstate batch 1’s per-entry idle loop.

## 7. Unload, locks and scheduling

Use [T5-VOLUNTARY-UNLOAD.md](T5-VOLUNTARY-UNLOAD.md) **as of `7ae16880`**, narrowed by the current scope decision:

| Phase | Contract |
|---|---|
| Reversible preparation | Close unload-owned admission, drain/check obligations; veto restores the existing permitted listener/worker/recovery routes. |
| Existing quarantine / epoch exchange | Preserve exact cleanup and existing V20 op17 RequestId/nonce replay, service bookkeeping CREATE exception, normal authentication/reconciliation and **EPOCH_DRAINED** semantics. Post-ACK veto keeps existing quarantine/progress behavior. |
| Committed local teardown | Only after exact EPOCH_DRAINED, final operational recheck and fence commit: close ports/owned holds, join workers, drain actual users, unregister/free. No rollback thereafter. Mandatory entry remains service-independent. |

No R/E retirement-only states, extension-29 op17, new preflight, `EpochRetired`, permanent-refusal mode or changed post-ACK reopen behavior belongs to batch 2.

Batch-2 vetoes are: pending/in-flight seal or missing exact seal evidence; unresolved op15/exposure/fence/op23 and associated pins/reservations; genuine op19/drain/cancellation-CLOSE/coverage obligations; unresolved allocation/accounting work; retained-unexposed residue/custody ticket; driver-delete reserved/waiting/deleting/unknown/completion-ready/unacknowledged records, factories or local uses; and incomplete durable released-stage completion. Resolved charged refusal files alone are not a new unload veto or reclaimable storage.

Keep new ownership nonpaged and capacity-reserved. Preserve namespace → stream Resource/StageListLock and existing native/publication orders. Receipt-map operations use bounded nonpaged copies; allocate, query, close, wait and RPC outside spin locks and callback-needed resources. Pin every object used after a lock drop, release once, and include the new deletion/delivery batches in teardown joins.

Before committed teardown, normal reconciled reconnect can wake exact recovery. Causes/deadlines survive pending→in-flight→reply; count in-flight obligations. Use existing 250 ms–8 s exchange and genuine drain retry behavior; SERVICE/refusal/capacity/evidence holds do not poll. DPC stays wake-only; timer state governs arming and idle cancellation.

Mandatory teardown performs local drains only; no seal/op23/op24/cleanup ACK is synthesized. Sticky Unknown, taint, feature gates and unsupported destinations remain unchanged. Late-load hardening is deferred by the scope decision, not silently implemented here.

## 8. Deferred work and owner choices

The [re-review findings 1–3](evidence/2026-10-14/t5-designs-rereview-sol61.md) require a later coherent design:

- **Durable epoch retirement/reclamation:** needs an exact bounded storage route that remains usable for durable writes/audit. Closing service bookkeeping CREATE first strands it.
- **Retirement-only reconnect:** needs complete authentication/bootstrap, cookie/epoch/revision/capability and reply-adoption contracts; existing policy/authentication/op11 cannot simply be forbidden.
- **Permanent refusal after failed retirement:** changes the approved usable-veto recovery policy and requires an explicit owner failure-policy decision and remedy.

None is implemented or advertised by batch 2. Existing EPOCH_DRAINED does not authorize refusal reclamation.

Budget defaults remain pending owner approval: evaluate 4,096 refusal slots/64 MiB charged storage with temporary overlap and separately reserved recovery headroom. Kernel delete-record limits and durable recovery storage also require measured accounting before activation.

The retained-residue custody exception remains an unapproved option; conservative unload veto applies. No automatic deletion, manual unlock, expiry, SYSTEM-created caller authority or broader restart inference is proposed.

## 9. Required controls and delivery

Agent controls use actual handlers/fresh journals and `MemoryMarshal` wire bytes:

| Group | Required cases |
|---|---|
| Harness patterns | Resave/new/replace/mapped × approve/BLOCK; empty; occupied targets; name reuse; rename generation/count adoption; BLOCK→resave before/after cleanup; independent public bytes. |
| Seal | Before/after atomic intent+SealPending and measurement; every entry point/startup/migration; missing/tampered intent; exited owner; progressed/cleaned states; every lost reply/crash boundary; no repeated publication. |
| Exposure | Every prepare/commit/op15/op23 loss; exit/never retry/PID reuse; permission/refusal/delayed request races; success/CLEANUP ordering; late failure/coverage loss; cancellation-CLOSE keeps its named hold with no synthetic op19/seal/delete. |
| Refusal accounting | Count/byte limits, concurrent writers, temporary/orphan overlap, disk full, before/after commit faults, startup reconstruction, invalid evidence and result 21. No receipt deletion/uncharge after restart/EPOCH_DRAINED/time. Exact replay continues at capacity. |
| Driver deletion | Driver-held release→local drain→exact disposition/close/removal→service restart→one durable completion; rename count/epoch/generation/full identity mutations; lost release/query/op24 replies; before/after completion replacement faults; no second disposition/public mutation. |
| Negative deletion | Absent without receipt, historical receiptless entries, replacement/reparse/changed parent, access errors, pending link, incomplete lifetime, failed/indeterminate disposition and driver loss before persistence remain held. |
| Bounds/unload | Reserve before delete; factories and in-flight records included; capacity refuses before mutation; stream/record slots return only after actual free; unacknowledged record and retained residue veto; normal reconnect resolves; existing quarantine/post-ACK behavior preserved; mandatory sends no new RPC. |
| Idle/compaction | Completed cleanup performs no recurring per-entry work; unfinished work backs off; holds park; receipts/ancestry/floors survive compaction. Batch-1 BLOCK/history-name fixes remain intact. |

Extend [publisher disposal tests](../agente/SafeUpload.Agent.Tests/StagedTransferPublisherTests.cs), [hand-back recovery tests](../agente/SafeUpload.Agent.Tests/StagedHandbackTests.cs), [journal/scan tests](../agente/SafeUpload.Agent.Tests/StagedTransferJournalTests.cs) and existing allocation/attachment/native controls. No renamed/removed tests, skips or weakened assertions.

Kernel source/property mutations must catch: seal intent omission/alternate entry bypass/live-owner seal requirement; exposure reset/fabricated cleanup/early flag clear/double pins; refusal budget bypass/reset/reclamation; delete without record reservation; map publication after unlink; wrong tuple/count/nonce; counters or Held=0 used as completion; accepting disposition without close/removal; repeated accepted/uncertain disposition; early ACK/free/slot return; uncounted factory/scratch ownership; PAGE/spin/I/O violations; missing delete-batch join; refusal polling/stale-channel adoption; and introduction of deferred retirement/reconnect/permanent-refusal behavior.

Batch contracts, persistence, worker/accounting and receipt retention coherently. Run local four-profile compile, required-test preflight/all T5 checks, complete agent matrix and four WDK/PREfast/ApiValidator/import 0/0 gates; obtain fresh independent Sol 6.1 xhigh security/lifetime review before revised boot. Then authorized matched-pair loss/restart/unload/Verifier rows, independent bytes and separate restoration. Source acceptance, component results and protected qualification remain distinct.
