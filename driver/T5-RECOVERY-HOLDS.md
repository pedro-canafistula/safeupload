# T5 batch 2: recovery holds and released-stage delete receipts

**Proposal against `ae2d0b3c96d01b1f7a1fe70c3b16adedf471b56a`, 2026-10-14.** Read-only source/design review; no edits, builds, tests or VM contact. Checkout clean. This revision has not been independently accepted.

The [2026-10-14 scope decision](POST-MVP-PLAN.md), updated by the evening owner decisions, defines batch 2 as:

1. Exact seal request/receipt recovery.
2. Typed op15 refusal, exposure evidence and op23 recovery.
3. Stateless allocation refusals and exact cleanup of dead-request allocations.
4. Negotiated per-version driver-delete receipts for normally released stages.

The [design re-review](evidence/2026-10-14/t5-designs-rereview-sol61.md) resolved the earlier seal, exposure and historical-owner design findings. Its retirement proposals remain outside this batch. The subsequent independent `t5-batch2-rereview-sol61.md` receipt at `ae2d0b3c` required rename revocation, retirement-before-Release ownership, complete control-35 replies and replay-before-observation ordering; those contracts remain below.

The evening owner decisions recorded in [POST-MVP-PLAN.md](POST-MVP-PLAN.md) accept the retained-residue exception (`c26584d6`) and **drop durable allocation-refusal receipts** (`49df2e00`). These supersede the earlier conservative residue default and refusal-storage item. They are implementation contracts, not claims that inspected source already implements them.

The delete receipt addresses [agent-loop RCA defect 2](evidence/2026-10-14/m2t5purgeattr1-agent-loop-rca-sol61.md). The completed-BLOCK idle-loop fix belongs to batch 1.

References use `K/` for `driver/SafeUpload.Minifilter/` and `A/` for `agente/SafeUpload.Agent.Service/Interception/`. Verified statements describe source; new contracts, attestations and controls are proposals.

## 1. Verified defects and allocation rationale

| Hold | Current mechanism |
|---|---|
| Lost seal ACK | The kernel drains and selects read-only backing, but assigns a fresh RequestId per seal attempt (`K/StageStream.c:5706,5741,6070`; `K/StageProtocol.c:2145`). Journal `SealPending` omits the request; startup resumes without it (`A/StagedTransferJournal.cs:2143–2182,3116–3121`). Replay rejects cleanup/current-object changes, and the handler requires exactly `Sealed` despite possible inspection/publication progress (`:2126–2137`; `A/MinifilterInterceptor.cs:1249`). |
| Lost op15 / late fence | Op15 records permission, not delivery (`A/StagedTransferJournal.cs:882–972`). Failed CREATE rolls back; only exact owner retry resumes. Maintenance parks completion/fence flags, which also exclude op19 collection (`K/StageStream.c:1746–1778,3690–3774,5960,6285–6288`). Late validation can fail after preliminary attachment bookkeeping. Canceled CREATE can reach CLOSE without CLEANUP (`:4080–4219,5448`). |
| Released-stage cleanup after restart | Publisher returns for driver-held disposal, leaving `StageDeleted=false`; startup later retries. The driver verifies identity, applies disposition, closes backing and frees the stream, retaining only counters (`A/StagedTransferPublisher.cs:502`; `K/StageStream.c:5818–5892,1496`). Startup’s leaf `GetAttributes` fails before absence-capable bookkeeping (`A/MinifilterInterceptor.cs:1652`; Publisher `:1007–1011`). `Held=0` merely means no listed stream (`K/StageStream.c:6958`); its eight-byte reply proves no deletion. |

Two source-verified interleavings qualify the delete contract:

- Committed rename adopts the target generation, increments rename count and clears `Disposed/DisposeDeferred` (`K/StageStream.c:4704–4710`). The journal returns a sealed renamed transfer to `Sealed`, clearing its inspection digest (`A/StagedTransferJournal.cs:2479–2495`). An accepted old Release therefore needs explicit revocation.
- Owner exit detaches the view (`K/StageStream.c:6537`); supersession also permits `StageTryRelease` (`:5905–5944`). Teardown deletes only when `Disposed && Released`, then frees the stream (`:5884–5892`). Retirement before disposal can leave backing on disk without an owner for a later Release.

**The allocation decision’s cleanup-only rationale is verified in source.** Failed CREATE enters `StageRetainAllocationReceipt`, retaining the stable request, closing backing and keeping a detached/unattached receipt stream (`K/StageStream.c:1950–2000,2734`). Recovery either resolves exact result 20 or adopts the returned tuple solely to queue kind-5 cleanup (`:6135–6269`). It does not resume CREATE or attach an application object. Kind-5 ACK removes the allocation reservation and releases its predecessor reference (`:6400–6423`).

Claim neutrality is **not already proved by that routing**: allocation currently commits a destination generation (`A/StagedTransferJournal.cs:351`), and `DestinationVersionsAsync` includes historical allocations in head selection (`:2921–2948`). Existing NO_WAITER retirement deliberately retains an Unsealed manifest and generation (`A/StagedRejectedAllocation.cs:81–116`).

Also verified: `RecoverRejectedAllocationsAsync` processes exact NO_WAITER evidence, but its queue is populated only by the legacy basename reply branch (`A/MinifilterInterceptor.cs:552–566,1393–1416`). Typed allocation replies currently do not enter that queue. Section 5 therefore specifies both claim withdrawal and ordinary typed NO_WAITER capture.

These are source mechanisms and source-derived interleavings, not new runtime reproductions. Historical counters, missing paths and digests cannot reconstruct missing authority or lifetime evidence.

## 2. Negotiation, common wire and validation

Preserve shipped layouts and numeric values. Proposed batch-2 capabilities:

| Capability | Bit |
|---|---:|
| Exact durable seal request/receipt | `0x200` |
| Op15 refusal/exposure/op23 recovery, including qualified never-exposed custody | `0x400` |
| Exact released-stage driver-delete receipt, including pre-delete revocation | `0x800` |

Required feature mask becomes **`0xFBF`**, replacing `0x1BF`. Remove the proposed refusal-accounting capability; move the unshipped driver-delete capability to `0x800`. Existing allocation-resolution bit `0x100` retains exact results 19/20; the complete batch-2 contract additionally requires section 5’s stateless refusal, claim neutrality and late-allocation cleanup.

These assignments are unshipped proposals. Negotiation validates the exact required-contract mask and its echo, not merely a subset test that could accept an older proposal’s different bit meanings. Old/incomplete contracts cannot activate batch 2. Normal op11 rejects them or returns EpochBusy with accepted mask zero. Bound-head bit `0x40` remains independently disabled. Normal builds compile staging out.

Reserve extension **29**, operation **23** for attachment recovery, operation **24** for driver-delete resolution receipts, and control **35** for exact released-stage disposal/query. These identifiers are unused in inspected source; assert availability before implementation.

No fallback to old seal ACK, generic op15 DENY or `Held=0` deletion inference. Existing op17 remains **V20/EPOCH_DRAINED**; it receives no extension-29 payload, new result or reclamation meaning. Ordinary op3 and kind-5 op9 keep their V20 wire layouts, specified in section 5.

The no-durable-refusal decision concerns **allocation op3**. It does not remove hold 2’s exact durable op15 permission/refusal outcome.

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
| Fresh op3 allocation | Current policy, live original PID/creation/effective authority and exact allocation/seed prerequisites. Creates only a private candidate; no attachment, publication or public mutation authority. |
| Positive op3 replay | Exact immutable positive allocation receipt before policy/live-owner/current-head/backing checks. No new generation, seeding, attachment or public mutation. |
| Fresh op15 permission | Live original owner/effective authority, current admission, exact allocation/commit/view/parent, native grant/share/security and seed prerequisites. PID identity alone is insufficient. |
| Op15 replay | Exact immutable saved outcome; no new grant or live-process refresh. |
| First/resumed seal | Historical owner binding, genuine durable op19 and authenticated completed T4 drain/irreversible read-only attestation, exact backing/length/seed evidence. **No live-process requirement.** |
| Op23 | Exact original allocation/op15 chain and authenticated kernel attestation; no new caller/file object. |
| Inspection/publication | Exact measured seal receipt, current policy, current destination/generation/delete floors and existing publication authority. |
| Driver-delete resolution receipt | Exact prior release intent and historical version/object/epoch. Deletion requires actual disposition/lifetime/removal evidence; revocation requires exact committed rename and drained old preparation. Neither grants public mutation authority. |

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

Persist `RetainedUnexposed` custody with exact request/object/version, bytes, ancestry/security/provenance/accounting. Its qualifying reply permits matching view detachment, pending/fence/allocation reservation and one predecessor-pin release. Free drained shell memory through a distinct predicate, never synthetic seal/discard/deletion. Custody atomically withdraws this never-exposed allocation’s private generation/admission claim as specified in section 5; public publication/delete floors and real namespace history remain intact.

### Accepted retained-residue exception

**Batch-2 behavior:** proved service-owned never-exposed residue does **not** veto voluntary unload or existing epoch drain. The bytes remain private, keep their storage charge and are not automatically deleted. Residue without the complete proof below still vetoes.

Use a dedicated terminal journal state **`RetainedUnexposed`**, appended without renumbering existing states, and immutable disposition **`ServiceOwnedCustodyOnly`**. Generic `Retained`, old `RetiredUnexposed` flags, owner exit and counters do not qualify. This terminal state has no route back to ordinary save processing.

The authoritative custody record is part of the same atomic manifest replacement as that terminal state and its committed charge. It contains:

| Proof group | Required durable, exact fields and validation |
|---|---|
| Request/version | Schema version 29; nonzero CustodyReceiptId; complete immutable op23 ProofKind-1 request; original allocation/prepare/commit/op15 requests and outcomes; DriverInstanceId/origin binding; TransferId, destination generation, full stage identity, committed rename count, original PID/creation, view generation and destination parent/name binding. Agent compares the entire historical chain; driver compares the echoed request with its retained tuple and original authority binding. |
| Never exposed | Authenticated kernel attestation: no exposure claim ever occurred, all relevant CREATE completions failed, completion/cancellation/rollback returned, and required local object/share/cache/section/paging/producer/lookup/RPC lifetimes drained. Preserve the exact attestation and attachment closure. No op19, seal or publication evidence is invented. A previously saved permission is historical only; it cannot remain usable to resume this closed attachment. |
| Private custody | Exact stage locator/leaf, volume and full file identity, private root/parent and checked ancestor identities/case bindings; regular non-reparse single-link object; logical length and allocated storage; no delete-pending/delete-on-close; checked service custodian identity and actual protected object/directory security. Agent validates through exact anchored handles. Custody must remain private without the loaded filter; SYSTEM’s ability to open a file is insufficient. Preserve original owner/DACL/SACL/label and caller grant/share provenance separately. |
| Charge | Unique charge ID bound to CustodyReceiptId and object/version; accounting schema/budget identity; committed count charge; stage allocation, custody/manifest/dependency storage, filesystem overhead and temporary/orphan overlap charges. Shared dependency charges retain exact reference accounting. Reserve capacity before custody commit; no ACK can release the kernel slot first. The custody record is authoritative for restart reconstruction, not an independently committed cache ledger. |
| Ancestry | Explicit no-seed/no-parent basis, or exact parent/predecessor version, epoch, object and receipt references; complete retained seed provenance/completion and security/read-export provenance; namespace/rename ancestry and publication/delete floors needed to prevent resurrection. Preserve the referenced closure durably and charge it. Missing, unresolved or conflicting origin evidence fails qualification. No live seed borrower or dependency operation remains. |
| Nonpublication | Immutable `ServiceOwnedCustodyOnly`, `Exposure=Never`, `AttachmentClosed=true`, allocation claim withdrawn; `PublishAllowed=false`, `SeedAllowed=false`, `ExportAllowed=false`, `JustificationAllowed=false`, `AutomaticDeleteAllowed=false`. No seal intent/receipt, measured seal length, inspection approval, publication intent, hand-back/export path or justification authorization. Handback remains NotAttempted and the justification window is closed. `StageDeleted=false`; no discard/delete receipt substitutes for custody. |
| Remaining obligations | No unresolved publication/deletion, pending rename/discard/op19/seal, uncertain completion, coverage loss or competing custody/storage operation. Preserve closure evidence and dependency references; absence of a work flag alone is insufficient. |

Every listed field is mandatory where applicable. “None” must be an explicit validated no-parent/no-seed/no-authority value, not a missing field. A content digest may check integrity but cannot replace object identity, ancestry, lifetime or authority.

The **agent** validates the record under journal/accounting serialization, checks current exact private custody and actual charges, closes its validation handles, then atomically commits terminal custody before replying. A failure after replacement is resolved by exact reread. Exact replay uses the same record/ReceiptId; qualification failure never erases the historical evidence or creates a new authority.

Use op23 result **`RetainedUnexposedCustodyRecorded`** only for ProofKind 1 with the complete qualifying record. The unchanged 1,296-byte reply echoes the entire request, carries CustodyReceiptId at offset 1232, the exact saved op15 outcome at 1256, zero reason/reserved fields and zero unused MeasuredLength. Zero MeasuredLength does not assert an empty file. Capability `0x400` includes this complete custody contract; there is no weaker boolean-only success.

| Reply | Driver action |
|---|---|
| `RetainedUnexposedCustodyRecorded` | Validate exact request/tuple/epoch, ProofKind 1, legal saved outcome, nonzero matching custody receipt binding, current channel and every local NeverExposed/lifetime predicate. Mark custody acknowledged for this original allocation only. Detach/unlink its reservation and release its one predecessor pin as above; drop the attempt pin once. Release shell/ticket/instance ownership only after actual remaining uses drain. Do not set Sealed, Discarded, Deleted or op19 ACK. |
| Retryable | Keep exact request, reservation, ticket and charge ambiguity; release attempt pin only; bounded EXCHANGE retry. |
| Held/DENY, missing proof, malformed/stale reply | Keep custody/lifetime obligation and unresolved reservations/pins; park SERVICE with the applicable named reason. |
| Lost reply/disconnect | Keep original ticket/request; reconnect replays it. Saved agent custody is not proof that the driver adopted ACK or drained its final uses. |

The **driver’s voluntary-unload predicate** exempts only storage already transferred through that exact authenticated typed ACK, with its own monotonic NeverExposed proof still valid and all local shell/transaction/callback/RPC/instance/lease ownership genuinely drained. An opaque GUID or an agent boolean alone is insufficient. The driver validates its own evidence and reply binding; the agent validates journal, storage, security and ancestry facts. The driver does not read the service journal under kernel locks.

Unacknowledged transfer, remaining local uses, exposure/coverage uncertainty or invalid local binding still vetoes. Keep tickets nonpaged and in existing bounded accounting until actual free; do not discount retained kernel memory from StageStreamCount. Once the exact transfer and drain complete, only service-owned bytes and durable service metadata remain; they are not kernel lifetime obligations.

Missing custody/security/object proof is `retained_unexposed_custody_unproved`; invalid charge is `retained_unexposed_accounting_unproved`; missing ancestry is `retained_unexposed_ancestry_unproved`; missing immutable restrictions is `retained_unexposed_nonpublication_unproved`; unfinished local transfer/drain is `retained_unexposed_lifetime_unproved`. Each vetoes. A confirmed but unqualified residue retains `retained_unexposed_blocks_unload` with its specific cause.

### Epoch drain, restart and permanent restrictions

Verified source currently checks pathname absence first in `IsEpochEntryTerminalAndAbsent` (`A/StagedTransferJournal.cs:114–124`), so it cannot accept retained bytes. Replace that predicate with two exclusive branches:

- **Never-exposed/custody entry:** accept only `RetainedUnexposed + ServiceOwnedCustodyOnly` with the complete qualified record, consistent reconstructed charges and no unfinished agent custody work. Validate retained object/private ownership through anchored observation; absence does not qualify this branch. Missing/invalid custody never falls through to ordinary terminal-and-absent handling.
- **Other entry:** preserve existing terminal-and-absent requirements. Do not admit generic Retained, exposure-possible, attached-private, legacy receiptless or merely absent entries through the exception.

`DrainDriverInstanceV20Async` validates custody/accounting inventory under its serialized drain before recording EPOCH_DRAINED. Include retained custody from earlier drained epochs in global inventory/accounting validation; never rewrite their original epochs or tuples. On replay/reconciliation relying on retained custody, missing proof or dirty accounting gives existing **EpochBusy**, preserving the saved drain request/nonce and receipt. A valid exact replay returns existing EPOCH_DRAINED.

EPOCH_DRAINED means each relevant entry is ordinarily terminal and absent or exactly terminal in qualified service custody. It does **not** assert custody bytes are absent, authorize deletion/uncharge or introduce durable epoch-retirement/reclamation semantics. Unfinished positive-allocation/kind-5/NO_WAITER cleanup remains busy. The driver still requires the existing exact epoch exchange and final local operational recheck; custody qualification cannot bypass another veto.

Startup reconstructs all residue and dependency charges, including temporary/orphan/uncertain storage, before qualification or drain. Validate exact custody, security, ancestry and restrictions again; never infer them from elapsed time, reboot, owner exit or file size. Invalid evidence stays conservatively charged and held. Service restart with the loaded driver replays the original op23. No new cold-driver lifetime inference is added.

All transition helpers, startup/migration, inspection/publisher dispatch, hand-back/export/justification, seed selection and automatic cleanup reject custody-only entries **before side effects**. Later policy approval or caller grants cannot turn them into publishable/exportable/justifiable data. Preserve their immutable restrictions, receipt closure, ancestry and charges across compaction and subsequent driver epochs. No expiry, orphan sweep or unload automatically deletes or uncharges them.

The user-visible result is that an operator can voluntarily unload once exact custody and all other obligations resolve, while these bytes remain service-private. Unproved residue still blocks unload. No file recovery, export, justification or automatic deletion is offered by this exception.

## 5. Stateless allocation refusal and dead-request cleanup

### Decision and ordering

Remove allocation-refusal files, negative-receipt accounting/reconstruction and the refusal-storage hold. Do not write durable allocation denials or reserve refusal storage. Keep exact result **20**:

> No allocation committed for this exact request at the time of the answer.

This is a time-local allocation-discovery answer, not immutable rejection or permission to proceed. It is serialized with allocation commit and unjournaled-backing cleanup. Before returning 20:

1. Validate the request and authenticated epoch.
2. Look up a **positive allocation record first**.
3. If none exists, evaluate current policy and original live owner/creation/authority before any fresh allocation.
4. On refusal, remove any unjournaled backing through the existing no-follow, identity-qualified private cleanup and confirm absence.
5. Recheck no allocation committed under the same allocation serialization; then answer 20 without persisting a negative.

Unreadable/conflicting journal, uncertain commit, unproved backing identity or unfinished cleanup gives retryable/held failure, never 20. Directory disappearance or access failure is not proven manifest absence.

A committed positive record atomically retains the complete original request, exact returned tuple, private locator/parent binding, initial seed evidence and claim ownership before replying. Exact replay returns that immutable positive tuple even after cleanup or later manifest progress, without reopening/recreating backing, allocating another generation, reseeding or checking a live process/current policy. Conflicting replay is held as `allocation_positive_request_mismatch`; missing historical request evidence is `allocation_positive_request_unavailable`.

A durable positive cannot become 20 because current policy refuses, the owner exited, PID was reused, backing was removed or the agent restarted. Cleaned positive records remain positive historical evidence and replay their exact cleanup outcome.

### Op3 wire and driver actions

Keep the **72-byte, pack-8 V20** payload:

| Offset | Field |
|---:|---|
| 0 / 4 | ExtensionVersion=20 / StructSize=72, uint32 |
| 8 | AllocationReservationId, GUID |
| 24 | ParentTransferId, GUID |
| 40 / 44 | Disposition / ReferenceKind, uint32 |
| 48 | DriverInstanceId, GUID |
| 64 | Original requester creation time, int64 |

The 1,192-byte outer request carries core version/size, nonzero stable RequestId, Operation=3, original PID, legal destination/volume/reply flags, Reserved=20, ImageNameLength=72, exact destination and zero unused bytes. Validate disposition 0–5, reference kind 0–2 and the exact parent/none relationship. Fresh work validates original PID **and creation time**, session/SID/effective authority and seed prerequisites; historical positive replay uses saved bindings.

Negative/transient reply remains **1,216 bytes**: core Version/StructSize/RequestId at 0/4/8, Verdict at 16, Result at 20, entire original request at 24. Verdict=Allow is the typed carrier, not save permission. Legal results are existing 19 and 20 only. Validate successful transport, full echo and current local channel/authority before adoption.

Positive reply keeps the existing **152-byte, pack-8** layout: Version/Size/RequestId at 0/4/8, Verdict=Allow at 16, basename byte length at 20, 48-WCHAR basename at 24, generation at 120 and full stage identity at 128. Check nonzero generation/full identity, reservation-derived basename, lengths/zeros, current channel and pinned local request.

| Reply/event | Driver action |
|---|---|
| Positive, original live request | Adopt only into the original still-pended, revalidated CREATE transaction. Continue existing prepare/commit/op15/native validation; reply alone exposes nothing. |
| Positive, retained dead request | Save exact tuple and queue kind-5 cleanup. Never open it as a visible view, attach an app object, complete CREATE successfully or send fresh attachment/seal/publication traffic. |
| 20 — no allocation committed now | For original live CREATE, fail it once with no stage. For the exact dead receipt, resolve only its cleanup bookkeeping: clear recovery/receipt state, unlink remaining allocation-only reservation, release its single predecessor pin and actual shell/lease ownership after drain. No predecessor/public-state change. |
| 19 — transient | Keep exact request, receipt ownership and pins; bounded EXCHANGE retry. It may later resolve to 20 or the exact/new private candidate. |
| DENY/malformed/lost/disconnect/stale | Preserve ambiguity; no terminal release. Retry exact bytes on normal authenticated reconciliation; named holds park without refusal polling. |

The retained request is immutable. Once CREATE failure is final and its completion/attempt producers drain, latch **`AllocationUse=CleanupOnly`** irreversibly. No owner retry or successful allocation reply can change that disposition. A later application CREATE gets a new reservation/request.

### Claims a positive answer may make

Because op3 has identical bytes on first send and cleanup replay, the agent cannot infer liveness from arrival time. **Every fresh ordinary op3 allocation starts as a private candidate.** Add durable allocation-claim roles `Candidate`, `ActiveSave` and `Withdrawn`; do not overload transfer State or StageDeleted.

| Claim | Candidate / dead-request rule | Exact release |
|---|---|---|
| Generation | Assign one immutable positive generation for tuple identity. Candidate and withdrawn rows are excluded from active destination-head, reservation, publication and delete-floor selection. | Withdrawal removes this allocation’s semantic generation claim, never decrements/reuses numbers or restores a stale head. Historical positive identity remains. |
| Destination/name/rename | Op3 creates no publication reservation, rename transaction, source tombstone or public-delete claim; it does not consume an existing tombstone. | Withdraw only this candidate’s admission fields. Preserve real predecessor/tombstone/publication history and other saves. |
| Seeding | At most one bounded, authorized copy into this exact private candidate, from the validated public/predecessor identity. Persist provenance. No visibility, export, successor seeding or predecessor disposal follows from allocation. Replay never copies again. | Finish/drain source-copy work and close its handles/temporary borrow tokens; kind-5 removes only the candidate. Preserve historical provenance without a live borrow. |
| Journal | One positive manifest/receipt and its own cleanup intent. No seal, inspection approval, publication, hand-back or justification. | Retain historical positive/cleanup evidence with role Withdrawn; exclude it from active namespace claims. |
| Kernel reservation | Original live allocation may reserve the name during its RPC. A dead receipt retains cleanup identity, not a right to block that name. | After final failed completion and producer drain, remove its `ReservationLinked` and allocation-only private-name barrier. Keep receipt/private-cleanup ownership counted until resolution. Never clear an actual delete/attachment hold. |
| Predecessor pins | One receipt-owned predecessor reference plus separately counted temporary copy/RPC references. No new pin per replay. | Drain temporary users; exact result 20 or kind-5 ACK releases the one receipt reference and wakes the predecessor. No detach, delete, reseal or current-view replacement of the predecessor/successor. |

Generation allocation uses monotonic high-water identity bookkeeping, including positive historical receipts, to prevent reuse. **Active head selection is a separate projection** containing promoted saves and real namespace history, not candidates/withdrawn cleanup rows. Numeric gaps are not name/order/floor authority. A dead candidate cannot mask a later or earlier eligible save, even while physical cleanup waits.

Fresh live **op13 commit** is the sole promotion from Candidate to ActiveSave. Keep existing 112-byte V20 lifecycle request/reply fields and results: operation/RequestId, transfer, generation, full stage identity, driver epoch, parent identity, outer owner/path and exact historical allocation binding. Agent validates the existing live original authority, prepare chain, backing/security/seed facts and captured namespace basis; stale activation is refused. Commit success atomically records promotion with its exact receipt. Replay returns that receipt without another promotion or head change.

Driver adoption remains confined to the original live attachment transaction. Denied commit follows existing abort/failure recovery; lost/uncertain replies retain exact lifetime obligations. Allocation recovery, startup and NO_WAITER work cannot manufacture op12/13. Successful op13 does not replace fresh op15 authority or real exposure evidence. A subsequently proved NeverExposed closure withdraws only its unused private claim.

Existing `DestinationVersionsAsync`, current-head validation, allocation reply validation and startup projections must implement this distinction. Merely marking a dead manifest Unsealed or deleting its file does not release its generation claim. Bound V23 head/publication rules remain separately disabled and unchanged.

### Kind-5 and NO_WAITER cleanup

Use the existing **op9, kind 5**, 64-byte pack-8 V20 payload:

| Offset | Field |
|---:|---|
| 0 / 4 | ExtensionVersion=20 / StructSize=64 |
| 8 | ReservationId, GUID; equals allocation TransferId |
| 24 | Full StageIdentity, 24 bytes |
| 48 | Original DestinationGeneration, uint64 |
| 56 / 60 | Kind=5 / zero padding |

Outer fields carry Operation=9, original PID, current attempt RequestId, Reserved=20, ImageNameLength=64, original private stage locator, flags/unused bytes zero. Authenticated driver epoch must match the positive manifest. Validate exact reservation/version/object and historical owner, allocation-only phase and no successful attachment/op15 ambiguity, pending rename or custody-only disposition. Cleanup needs no live process or current destination head. Parent validation uses preserved exact ancestry; it cannot require a renamed predecessor still to have its old mutable generation.

The existing 152-byte status reply carries RequestId and `DiscardPending`/`DiscardAcknowledged` in the operation-specific result field; unused name/generation/identity bytes are zero. The driver revalidates its pinned kind/tuple/reservation/channel before adoption.

| Kind-5 reply | Driver action |
|---|---|
| `DiscardPending` | Keep exact cleanup tuple, receipt and predecessor ownership; bounded genuine cleanup retry. No name/head restoration or CREATE replay. |
| `DiscardAcknowledged` | Require durable exact cleanup and qualified absence. Clear matching receipt/recovery/tuple/private-cleanup state; release the one predecessor reference and wake it; detach only if this receipt itself is current. Drain/free actual shell/RPC/instance ownership. Existing terminal shell flags are release bookkeeping, not an op19/seal/publication receipt. |
| DENY/malformed/stale/disconnect/lost | Keep cleanup ownership and tuple. SERVICE hold or bounded exchange retry as appropriate; no weaker evidence releases pins. |

Agent kind-5 and NO_WAITER retirement share this sequence:

1. Serialize against allocation/attachment; atomically record exact cleanup basis and `AllocationClaimRole=Withdrawn` before physical deletion. Remove only this allocation’s semantic claims. Never roll back counters, public floors, another head, predecessor state or real tombstones.
2. Drain seed/copy/lookup/storage users, close candidate handles and delete only the exact regular, non-reparse, single-link private object under the recorded parent binding. Do filesystem waits outside the journal gate and port dispatcher.
3. Confirm qualified absence and atomically acknowledge cleanup. If disposition already completed, retry bookkeeping rather than recreate/delete another file. A replacement or uncertain identity/removal stays `allocation_cleanup_unproved`.
4. Preserve positive tuple/request and cleanup receipt for replay; exclude completed work from recurring dispatch.

Capture exact native **NO_WAITER (`0x801F0020`)** from the sole allocation reply, bound to MessageId, RequestId, sent reply and positive allocation identity. Extend ordinary typed positive allocation replies to return this exact transport result to `StagedRejectedAllocation`; boolean failure or generic exception is insufficient. Keep legacy behavior, and do not use ordinary NO_WAITER authority for bound traffic.

Before disposal, persist NO_WAITER cleanup basis in the positive manifest and use the shared withdrawal/removal route. Replace the existing Unsealed-only retirement. This handles a fresh late “yes” whose original waiter disappeared, including one arriving after result 20 already resolved the kernel receipt. No completed ordinary CREATE received that allocation.

A crash between native NO_WAITER observation and durable recording loses that proof. The positive candidate remains namespace-inert and held as `allocation_cleanup_lifetime_unproved` until genuine kind-5 or other already-approved exact evidence resolves it. Restart, timeout and absent logs cannot fabricate NO_WAITER. Once the basis committed, startup resumes exact cleanup without reseeding or reclaiming a successor.

Unresolved cleanup may retain bounded private storage, a shell or a genuine predecessor lifetime pin. It does not retain the dead request’s name/publication ordering claim. Later saves use their own reservations; temporary resource exhaustion still fails closed. Completion releases every live claim; only historical positive evidence and unused generation identity remain.

### Flip safety

- **Lost no → later yes:** there was no persistent rejection. Current policy may permit a fresh candidate only if the original live process identity/authority still matches; PID reuse or owner exit cannot grant it. The driver’s dead disposition never attaches it. Candidate role cannot influence the visible namespace or publication ordering. Kind-5 or exact NO_WAITER withdraws/removes it. Private seeding cannot enter a visible view or become a seed source.
- **Durable yes → no:** impossible in valid operation because immutable positive lookup precedes current policy, process and filesystem checks, including after cleanup. Unreadable/mismatched positive evidence yields a hold, not 20.
- **Lost cleanup reply:** replays the exact cleanup outcome and releases references once. Neither branch performs publication, public deletion or another completed public mutation.

### Earlier-build negative files

Ignore `GUID.allocation-refused` files for all allocation, replay, epoch and admission decisions, even if a positive manifest with that GUID exists. Never deserialize their request/path as authority.

Remove them as obsolete metadata through bounded maintenance: enumerate only exact legacy filename patterns in the configured trusted staging directory, open the entry without following reparses, verify directory binding and regular single-link owned-file identity/security, and delete that opened metadata object. Apply the same rule to precisely identified legacy refusal temporary files. Do not derive or delete a stage, manifest, destination or predecessor from their names or contents.

A failure to remove obsolete metadata leaves it ignored and reports maintenance failure; it does not create refusal accounting or an allocation/unload veto. Actual maintenance handles/callbacks still drain normally. This exception does not apply to custody bytes, positive records or unknown files.

## 6. Exact released-stage driver-delete receipt

This applies to **normally Released**, published versions with `HandbackState=NotAttempted`. Justified/blocked hand-back cleanup retains its separate exact receipt path. No public file is deleted by this protocol.

### Exact release intent: control 35

Before sending, the agent persists an immutable release intent naming the original version, stage path and checked private-directory binding, driver epoch, committed rename count and unique ReleaseNonce. Reserve its durable receipt/dependency storage first. Do not initiate deletion from a mere missing leaf.

Release intents and their outcomes are indexed by historical tuple and nonce, not solely the transfer’s current head. Rename must preserve the old intent while creating a new current tuple.

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

Kernel validation requires current authenticated service and negotiated compatibility, legal envelope/phase/zeros, original driver epoch, transfer, positive generation, full stage identity, exact rename count, Released outcome and immutable nonce. For lookup, canonicalize only Phase and ExpectedReceiptId to the original Release form; all binding fields remain exact.

**Look up an existing historical record before checking the stream’s current tuple.** Matching old requests must find revoked/completed records after rename or stream release. Only a fresh Release requires the current retained stream tuple and no conflicting accepted release. A changed nonce for the same accepted tuple, changed binding or wrong ExpectedReceiptId refuses without touching the original record.

For fresh Release, reserve capacity and publish the exact binding before setting/defering disposal or queueing work. Same-request replay never allocates another accepted record or repeats deletion. Query never creates an accepted release, authorizes deletion or supplies completion facts.

The following values belong to a new control-35 result enum; no shipped enum is renumbered:

| Result | Release / Query | ReceiptId | Kernel action and agent handling |
|---|---|---|---|
| 1 — `ReleaseAccepted` | Release only | Nonzero | Binding and record ownership accepted before reply; set matching Released disposal, or suspend/defer it behind an existing rename. Queue worker. Agent persists binding to this historical intent; waits for op24. |
| 2 — `ReceiptPending` | Both | Nonzero for an accepted record | Keep its reservation/source/work ownership. Replay changes no disposal; Query may wake genuine pending work/delivery. Agent keeps binding and wait; no `StageDeleted`. |
| 2 — `ReceiptPending` | Both | Zero **only** for a tracked, bounded factory not yet accepted | Keep factory accounting until it drains; no accepted disposal authority. Agent binds nothing and retries/discovers using the same nonce. An accepted record can never regress to zero. |
| 3 — `ReceiptReady` | Both | Nonzero | Immutable successful-deletion op24 exists; queue/replay it. Keep record until matching op24 ACK and local-use drain. Agent awaits/records op24; this control reply alone cannot complete deletion. |
| 4 — `ReceiptUnavailable` | Both | Zero | Query found no matching record/factory; Release also lacks an exact retained stream eligible for acceptance. No disposal or free. Agent retains intent as `released_stage_delete_receipt_unavailable`; absence proves neither deletion nor nonacceptance of another in-flight copy. |
| 5 — `TupleRefused` | Both | Zero | Wrong epoch/tuple/count/nonce/ExpectedReceiptId or incompatible current state; no mutation. Agent keeps historical intent and named mismatch hold; reconcile exact rename/binding evidence, never retarget the request. |
| 6 — `RetryableFailure` | Both | Zero | No new acceptance in this call; release only drained per-call/factory ownership. Existing accepted records keep their state and return that state when lookup succeeds. Agent preserves exact intent and uses bounded EXCHANGE retry. |
| 7 — `CapacityUnavailable` | Release only | Zero | Refuse before accepted record/disposal mutation; keep stream/shell. Agent parks SERVICE as `driver_stage_delete_receipt_budget_exhausted`; receipt/connection progress or approved capacity restoration wakes an exact retry. Query uses bounded resident lookup resources and does not consume a new record slot. |
| 8 — `NotReady` | Both | Zero | Initialization/authentication/compatibility or permitted bookkeeping route unavailable; no new acceptance/mutation. Agent keeps intent and waits for normal authenticated readiness/reconciliation. |
| 9 — `ReleaseRevoked` | Both | Same nonzero old ID | Old release was revoked before DeleteClaimed. Keep revocation/preparation/delivery ownership; queue terminal revocation op24 after preparation drains. Agent does not mark deleted or reuse this ID for the renamed tuple. |
| 10 — `Denied` | Both | Zero | Typed denial on an authenticated channel changes no ownership/disposal. Agent parks SERVICE with denial reason; no completion inference. |

Invalid phase/result combinations, inconsistent IDs, wrong echoes/connection stamps or nonzero reserved fields are malformed. A native access denial, buffer/validation failure or generic transport error supplies no typed completion authority.

Every control return releases only its actual per-call lookup/scratch pins after the call drains; accepted map/source ownership persists. Reply transmission, including successful transmission, never frees a receipt.

After lost Release, the agent sends exact Query and, if needed, replays the original Release with the same nonce. After lost Query, repeat Query unchanged. Neither loss permits a fresh nonce or an agent filesystem-delete fallback. A delayed reply binds only the historical intent echoed in it, even if rename has advanced the head. Current-channel validation still applies.

For negotiated Released traffic, old control-29 `Held` replies are not completion authority. Keep that layout for existing uses, including the distinct CleanedUp route.

### Ownership before Release

Add **`AwaitingDisposal`** to the normal sealed-stream retirement predicate. If owner exit/supersession would otherwise unlink a sealed stream without resolved disposal, retain it in exact lookup; do not run the old unconditional free.

Retain the stream’s original tuple, rename count, stage locator/full identity, validated private-parent anchor, original/backing instance and read-only backing ownership, historical view/owner binding, genuine seal/op19 evidence and remaining ancestry/lease/reference obligations. Keep its allocated stream slot charged until actual destruction. Existing `STAGE_LIMIT=128` accounting includes these shells; it is not bypassed by detachment. This is a bounded ownership state, not a synthetic seal, deletion or `Retired` result.

- **Exited owner:** detach admission as today, but keep exact shell lookup. Agent inspection/publication and later historical Release need no live process. Missing real exposure/op19/seal evidence retains the earlier named hold.
- **Follow-up save:** the predecessor may be noncurrent while the successor runs normally. Keep each tuple separately. Real predecessor seed/allocation/RPC references prevent its deletion; releasing the predecessor must not detach or clear the successor’s current view.
- **Later Release:** control 35 finds the shell, reserves a receipt record, transfers/counts its source ownership and follows the normal deletion path.
- **CleanedUp:** retain the existing service-delete route. Matching authenticated notification is applied to the retained tuple/count; actual owned-object identity/delete-pending evidence and genuine local drain/close resolve kernel ownership. A notification, null backing or pathname absence alone cannot do so. Preserve a bounded exact shell if notification or evidence remains unfinished; startup/reconnect retries unfinished notification/bookkeeping without repeating service disposition.

If the existing delete-pending helper closes backing before a CleanedUp notification resolves, it must preserve the exact observed identity/tuple, delete-pending and real close/drain evidence in that shell before dropping the object. It cannot replace those facts with `BackingObject==NULL`.

Awaiting disposal is `stage_disposal_unresolved`, vetoes unload, and parks without recurring idle work. Release/CleanedUp, actual reference/close events and normal reconnect wake it. A record-capacity failure keeps the shell intact. Never-exposed residue remains governed by section 4, not this ordinary sealed-shell route.

### Kernel record accounting and state machine

Maintain a separate bounded **nonpaged** receipt map surviving stream release. Reserve factories before allocation and count factories, accepted, suspended, revoking, deleting, replay-pending and in-flight records together. Proposed development ceiling: **1,024 slots**, reused only after acknowledged records actually free; it is not a per-boot counter.

A record owns its exact release input, ReceiptId, original boot/driver, stage locator/private-parent binding, source/work ownership, terminal facts, full saved op24 request and state/reference accounting. Include bounded revoking-rename identity/receipt metadata in its original reservation. Bound record payload to 4,096 bytes with compile-time assertions; separately charge bounded RPC scratch and map/factory metadata. No extra slot/allocation is required to revoke an already accepted release.

State progression:

`Reserved → WaitingLocalLifetime → DeleteClaimed → DispositionAccepted → LocalLifetimeComplete → CompletionReady → AgentAcknowledged`.

Before DeleteClaimed only:

`Reserved/WaitingLocalLifetime ↔ RenameSuspended`.

On exact committed rename:

`Reserved/WaitingLocalLifetime/RenameSuspended → RevocationDraining → RevocationReady → AgentAcknowledged`.

Both terminal branches retain immutable evidence until matching ACK and actual local-use drain.

### Rename suspension, revocation and later release

Preserve supported rename behavior after Release and before DeleteClaimed.

1. An admitted rename exchange suspends deletion of its source tuple. The final DeleteClaimed arbitration must see no pending/in-flight rename or admitted producer, live application handle/object, follow-up seed owner or other conflicting lifetime. It cannot win over an already admitted rename.
2. Exact abort leaves generation/count unchanged. Restore only the original release’s eligibility/deferred disposal after the abort resolves. Failed, lost or uncertain rename replies keep suspension; they cannot authorize deletion or revocation.
3. Exact committed rename adoption atomically adopts the journal’s destination generation, increments count and clears `Disposed/DisposeDeferred` as today. In that same arbitration, mark the old release `RevocationDraining`, remove its link as the stream’s active delete intent and retain its immutable old tuple/nonce/ReceiptId. Never rewrite it to the new tuple. Destination generations are per name and can decrease across rename.
4. Cancel old queued preparation; any out-of-lock worker must revalidate the record before DeleteClaimed and before entering disposition. Drain its preparations/lookups and close only its preparatory DELETE-open handles/references outside callback-needed locks. Release its counted source pin once those uses end. **Do not close the renamed stream’s backing or clear its actual application/cache/share/ancestry ownership.**
5. Produce `RevocationReady` only with authenticated exact committed-rename evidence, proof that this release never entered disposition, and drained old preparation/source ownership. Keep terminal map/delivery references until ACK. Unproved drain remains `release_revocation_draining`; ready but unacknowledged evidence is `release_revocation_ack_pending`.

The agent’s atomic rename replacement preserves the historical Release intent and exact committed rename chain while returning the current tuple to `Sealed` and clearing prior inspection approval. Revocation closes only old release bookkeeping; it never sets/clears the current tuple’s `StageDeleted`, fabricates op19/seal or changes publication/delete floors.

The renamed tuple follows current-policy inspection/publication. Only its later ordinary Released state creates a **new nonce and receipt binding**, with the newly adopted generation/count and the same exact backing identity where applicable. It may progress while an old revocation awaits ACK; both records remain charged. Old terminal records do not retain the renamed stream merely to wait for delivery.

Old Release/Query replay returns `ReceiptPending` while suspended or `ReleaseRevoked` after commitment, with the original accepted ID. It never restores old disposal. After revocation ACK and final record free, old tuple replay returns `TupleRefused` if the changed stream remains, or `ReceiptUnavailable` if no owner remains; the agent uses its durable revocation outcome instead of restarting that release.

**After DeleteClaimed, freeze conflicting changes to this private version’s tuple, rename count, disposal and seed/attach ownership.** No previously admitted rename may still exist at that boundary. Independent public-name operations and saves with new transfer identities retain their normal paths. Failed/uncertain deletion cannot reopen the claimed version for rename or repurpose its receipt.

### Actual deletion and local lifetime

- Claim deletion under namespace serialization against attach/rename/follow-up/discard. Require ordinary seal/op19, exact Released disposal/tuple/count and genuine lifetime eligibility. Detach only the already-disposed private view.
- Keep stream ownership/count until actual destruction. Perform context/paging drain, identity/security/type checks, opens, disposition and closes outside namespace/spin locks.
- Verify original backing and DELETE-open object both match recorded volume/FILE_ID_128; require regular, non-reparse, single-link private backing and checked parent.
- Reserve result storage before mutation; record actual final disposition status immediately. Once accepted, never issue disposition again. Indeterminate outcome stays `driver_stage_delete_outcome_unproved`.
- Close every driver-owned stage handle and release stage-object references after real upper-object/share/cache/section/paging/callback/RPC drain. The worker’s explicit ownership pin must not be confused with an external user; counters alone do not attest drain.
- Confirm removal through complete stable observation under the checked private-parent/volume binding after close. Exact prior disposition plus lifetime evidence qualifies absence; pathname absence alone does not. Pending original link, replacement, changed/reparse parent, access error or incomplete observation remains held.
- Publish terminal immutable evidence before freeing/unlinking source ownership. Terminal records own no stage FILE_OBJECT/handle that could delay deletion. Release temporary instance/observer pins after their work drains.

Publish map ownership before unlinking a stream, closing the “not listed but teardown unfinished” gap. ACK cannot free a record with factory/work/send/lookup uses; unlink under lock and destroy/release charges outside it after the last use.

Pre-disposition transient preparation and genuine unsignaled drain waits use existing bounded scheduling. Accepted/uncertain disposition is never repeated. Evidence mismatch parks with named diagnostics. Own close/drain/reference events, rename resolution, normal reconnect and exact Query wake the worker; timers only request fresh qualifying observation.

### Operation 24: retained resolution replay

Send only `CompletionReady` or `RevocationReady` evidence using extension 29 and this **124-byte, pack-4** payload:

| Offset | Field |
|---:|---|
| 0 / 4 | ExtensionVersion=29 / StructSize=124, uint32 |
| 8 | ReceiptId, GUID |
| 24 / 40 | Original DriverInstanceId / TransferId, GUID |
| 56 | Original DestinationGeneration, uint64 |
| 64 | Original StageIdentity, 24 bytes |
| 88 / 92 | Original CommittedRenames / DisposeOutcome=Released(1), uint32 |
| 96 / 100 | Requested DispositionClass=`FileDispositionInformation` / DeleteFile=1, uint32 |
| 104 / 108 | DispositionStatus / DrainStatus, int32; meaningful for successful deletion, zero for revocation |
| 112 / 116 | CompletionFacts / OriginalBootSequence, uint32 |
| 120 | Reserved=0, uint32 |

Outer request: core version/size, retained nonzero RequestId, Operation=24, RequestorProcessId=0, Flags=`StageV19ReplyFlag` only, Reserved=29, ImageNameLength=124, original private-stage NT locator in Path and zero tails. No token, pointer or handle is exported.

CompletionFacts bits are:

| Bit | Attested fact |
|---:|---|
| `0x001` | Exact original Released disposal intent bound |
| `0x002` | Exact object/type/single-link/parent verified |
| `0x004` | Genuine T4 drain complete |
| `0x008` | Upper application-object/share lifetime ended |
| `0x010` | Cache/section/paging/callback/RPC users drained |
| `0x020` | Original exact disposition accepted |
| `0x040` | All driver-owned stage handles closed |
| `0x080` | Driver-owned stage-object references released |
| `0x100` | Exact qualified removal confirmed |
| `0x200` | Original release revoked by exact committed rename before DeleteClaimed |
| `0x400` | No disposition call entered for this release |
| `0x800` | Old release’s preparation/source ownership drained |

There are exactly two legal terminal forms:

- **Deleted:** facts exactly **`0x1FF`**, strict successful actual final disposition/drain statuses; reply result `DriverDeleteRecorded`.
- **Revoked:** facts exactly **`0xE01`**, both status fields zero as unused fields; reply result `DriverDeleteRevocationRecorded`. This attests cancellation only. It does not assert application lifetime end, stage absence or successful disposition.

Reject mixed/partial/unknown facts. Zero revocation status is not a successful-disposition assertion. Positive-indeterminate status, local close alone or forced coverage loss cannot produce deletion completion.

Retain identical terminal request bytes/RequestId through every retry. A ReceiptId gets one immutable terminal form. Copy/pin under the map lock, send at PASSIVE outside locks, then revalidate record kind and current channel before adoption.

### Agent validation: durable lookup first

Every handler, startup and publisher recovery route follows this order:

1. Validate envelope, sizes, flags/PID/tails, lexical locator and authenticated origin/connection **without stage/parent/ancestor filesystem observation or short-name expansion**.
2. Look up durable op24 resolution by ReceiptId and historical release key. Compare the entire saved immutable request and binding. An exact saved resolution immediately replays its saved result. It does not require current head eligibility, current parent identity, a live owner or fresh absence. A mismatch refuses before observation.
3. Only for a first resolution, obtain the preserved historical Release intent/binding and required evidence below. Journal storage reads are evidence lookup, not fresh stage observation.
4. Atomically persist raw request, release binding and resolution before ACK. A replacement fault is resolved by exact reread through step 2.

For every first resolution validate original driver/boot, transfer, positive generation/full stage identity, committed rename count, ordinary Released/non-hand-back eligibility of the historical intent, ReceiptId binding, requested disposition class/flag and legal terminal form. If Release reply was lost, exact control-35 Query binds the ID first; no inferred ID from path absence.

For **Deleted**, additionally require the intent remains unrevoked, no pending/committed rename invalidates its tuple, strict final statuses and complete `0x1FF`. Replace unconditional leaf `GetAttributes` with lexical containment, checked saved parent/ancestors and absence-capable anchored observation. A replacement, pending original, changed/reparse parent, access ambiguity or incomplete observation refuses. Only this matching complete receipt permits absent-stage completion. Atomically set `StageDeleted=true` for that exact version.

For **Revoked**, require `0xE01` and the preserved exact committed rename receipt/chain whose source matches this intent’s old driver/transfer/generation/full identity/count and whose destination/count matches the committed successor. Validate kernel cancellation/preparation-drain attestation. No stage observation is required or useful: the backing may belong to the renamed tuple or already have been cleaned through its later receipt. Persist `ReleaseRevoked` for the old intent only; never alter the current tuple’s deletion flag, inspection state or floors.

Do not require live original owner or current public-name generation: these complete historical private bookkeeping. They never repeat publication or delete a successor.

Changed receipt/tuple or conflicting evidence stays `released_stage_delete_receipt_mismatch`; unproved first-deletion observation stays `released_stage_delete_observation_unproved`; missing revocation chain stays `released_stage_release_revocation_unproved`. Historical driver-owned entries without receipt stay **`released_stage_delete_receipt_unavailable`**. Aggregate counters, `Held=0`, missing path, digest or reboot cannot certify them.

### Op24 replies: driver adoption

| Agent reply | What the driver does |
|---|---|
| `DriverDeleteRecorded` | Accept only for the same `CompletionReady`/`0x1FF` record, exact full echo/ReceiptId, zero nonapplicable fields and current authenticated channel. Mark acknowledged; remove only this record’s map ownership; free after all local uses drain. No further stage/public mutation. |
| `DriverDeleteRevocationRecorded` | Same validation, but only for `RevocationReady`/`0xE01`. Mark old record acknowledged and drain/free it. Never mark any stage deleted, restore old disposal or release the renamed tuple’s independent ownership. |
| `RetryableFailure` | Keep immutable terminal evidence and accounting; release attempt pin only; bounded EXCHANGE retry of recording/delivery, never disposition or rename. |
| Typed Held or generic DENY | Keep record and unload obligation; park SERVICE with named reason. Query/reconciled reconnect can retry; no refusal polling. |
| Wrong terminal-result kind, malformed/wrong receipt/stale reply | Keep record; release attempt pin once; no ACK adoption. |
| Lost reply/disconnect | Keep record/request; normal authenticated reconnect replays it. Agent returns saved resolution if replacement committed. |

Agent persistence precedes reply. Transmission alone does not release kernel ownership. Durable receipt/dependency storage remains charged and pinned in this batch; kernel ACK releases only the corresponding drained memory ownership.

### Restart and delivery limitations

Use existing normal SET_POLICY/authentication commit/op11 bootstrap and the new required mask. No retirement-only bootstrap is added. Op24 is receipt bookkeeping, not fresh staging authority; its handler must not require inspection/publication recovery readiness once normal authenticated driver binding/compatibility is established. Startup must not block negotiation or the receive loop waiting for a receipt its kernel sender cannot yet deliver: record the per-version hold, finish normal bootstrap and retry through the connected receipt worker.

Service restart with the same loaded driver preserves AwaitingDisposal shells, accepted/suspended records and terminal deletion/revocation evidence. Resume exact Release/Query intents and unfinished CleanedUp notification. Saved op24 resolutions replay before any fresh stage observation, including after later rename, cleanup or parent changes.

Voluntary unload is vetoed until shells resolve, terminal records are acknowledged and local uses drain. Mandatory teardown/reboot sends no fresh receipt RPC and fabricates no ACK; after local rundown it may destroy volatile ownership. If no durable agent receipt survived that loss, the entry remains named and held. A different driver/boot cannot recreate it. This batch does not promise cold-driver recovery of unpersisted delete/revocation evidence.

Completed cleanup/revocation leaves pending dispatch. Genuine unfinished disposal/recording has bounded backoff; evidence-dependent holds park. Do not reinstate batch 1’s per-entry idle loop.

## 7. Unload, locks and scheduling

Use [T5-VOLUNTARY-UNLOAD.md](T5-VOLUNTARY-UNLOAD.md) **as of `7ae16880`**, narrowed by the current scope decision and accepted custody exception:

| Phase | Contract |
|---|---|
| Reversible preparation | Close unload-owned admission, drain/check obligations; veto restores existing permitted listener/worker/recovery routes. |
| Existing quarantine / epoch exchange | Preserve exact cleanup and existing V20 op17 RequestId/nonce replay, service bookkeeping CREATE exception, normal authentication/reconciliation and **EPOCH_DRAINED**, including section 4’s exact custody qualification. Post-ACK veto keeps existing quarantine/progress behavior. |
| Committed local teardown | Only after exact EPOCH_DRAINED, final operational recheck and fence commit: close ports/owned holds, join workers, drain actual users, unregister/free. No rollback thereafter. Mandatory entry remains service-independent. |

No R/E retirement-only states, extension-29 op17, new preflight, `EpochRetired`, permanent-refusal mode or changed post-ACK reopen behavior belongs to batch 2.

Batch-2 vetoes are: pending/in-flight seal or missing exact seal evidence; unresolved op15/exposure/fence/op23 and associated pins/reservations; genuine op19/drain/cancellation-CLOSE/coverage obligations; unresolved positive allocation, claim withdrawal, kind-5/NO_WAITER cleanup or custody accounting; unproved retained-unexposed custody/charge/ancestry/nonpublication or unfinished handoff/local drain; AwaitingDisposal shells; driver-delete reserved/waiting/rename-suspended/revoking/deleting/unknown/terminal-unacknowledged records, factories or local uses; and incomplete durable released-stage/revocation/CleanedUp bookkeeping.

**Qualified, fully transferred service-owned residue bytes alone do not veto.** There is no allocation-refusal storage/accounting/drain obligation. Ignored obsolete negative metadata alone does not veto.

Keep new ownership nonpaged and capacity-reserved. Preserve namespace → stream Resource/StageListLock and existing native/publication orders. Use StageListLock to arbitrate bounded nonpaged stream/receipt keys and ownership flags; avoid a reverse map-lock → namespace dependency. Control callbacks never acquire namespace resources needed by the RPC worker.

Rename adoption/revocation and final DeleteClaimed arbitration run under namespace serialization with appropriate stream/list guards. Publish suspension/claim flags atomically against producers. Allocate, query, close, wait and RPC outside spin locks and callback-needed resources. Each out-of-lock operation owns a counted pin and revalidates before mutation; revocation drains those operations rather than canceling their lifetime by flag.

Dead-allocation disposition and name-barrier release serialize with original attach/cancel completion; do not clear another lifecycle hold. Keep cleanup identity/parent/RPC ownership separately from logical-name admission. Agent allocation/withdrawal helpers use consistent allocator → journal serialization; physical cleanup and native waits run outside the journal gate/port dispatcher. Include deletion, revocation, dead-allocation cleanup, custody handoff and retained-shell teardown in worker joins. Release slots only after actual destruction.

Before committed teardown, normal reconciled reconnect can wake exact recovery. Causes/deadlines survive pending→in-flight→reply; count in-flight obligations. Use existing 250 ms–8 s exchange and genuine drain retry behavior; SERVICE/refusal/capacity/evidence holds do not poll. DPC stays wake-only; timer state governs arming and idle cancellation.

Mandatory teardown performs local drains only; no seal/op23/op24/cleanup ACK is synthesized. Sticky Unknown, taint, feature gates and unsupported destinations remain unchanged. Late-load hardening is deferred by the scope decision, not silently implemented here.

## 8. Deferred work and owner choices

The owner’s stateless-allocation decision removes the refusal-storage hold, refusal-budget decision and refusal-receipt reboot/retirement/reclamation question. There is no negative allocation evidence to retire.

The earlier [retirement re-review](evidence/2026-10-14/t5-designs-rereview-sol61.md) does not authorize adding durable epoch retirement, retirement-only reconnect or permanent refusal to this batch. Any later retirement of **positive** recovery/custody/dependency evidence needs its own coherent storage, authentication/bootstrap, lifetime and failure-policy design. Existing EPOCH_DRAINED is not a receipt-reclamation authority.

Kernel delete-record limits and durable positive/custody recovery storage still require measured accounting before activation. Those are actual retained-object obligations, not allocation-refusal budgets.

The retained-residue custody exception is **accepted and implemented by the batch-2 contract in section 4**. Qualified bytes remain private and charged while permitting unload; unproved residue still vetoes. No automatic custody deletion, manual unlock, expiry, SYSTEM-created caller authority or broader restart inference is proposed. Supported pre-DeleteClaimed rename remains available; no owner decision to prohibit it is requested.

## 9. Required controls and delivery

Agent controls use actual handlers/fresh journals and `MemoryMarshal` wire bytes:

| Group | Required cases |
|---|---|
| Harness patterns | Resave/new/replace/mapped × approve/BLOCK; empty; occupied targets; name reuse; rename generation/count adoption; BLOCK→resave before/after cleanup; independent public bytes. |
| Seal | Before/after atomic intent+SealPending and measurement; every entry point/startup/migration; missing/tampered intent; exited owner; progressed/cleaned states; every lost reply/crash boundary; no repeated publication. |
| Exposure | Every prepare/commit/op15/op23 loss; exit/never retry/PID reuse; permission/refusal/delayed request races; success/CLEANUP ordering; late failure/coverage loss; cancellation-CLOSE keeps its named hold with no synthetic op19/seal/delete. |
| Stateless refusal | Lost result 20 → policy change → same request replay produces an inert positive candidate → kind-5 cleanup. Owner exit/PID reuse cannot grant fresh allocation. Replay after agent restart re-evaluates a refusal but resolves a positive first. Unjournaled backing must be removed before 20; uncertain commit/cleanup cannot return 20. No negative file is created. |
| Positive replay | Lost yes → policy denial/owner exit/restart returns the same immutable positive tuple, including after cleanup. No generation increment, recopy, fresh owner lookup or public mutation. Wrong request/epoch/reference stays held. Crash after positive replacement cannot become 20. |
| Claim ordering | Later saves before/after dead replay and while cleanup waits; candidate generation greater than a live save cannot mask it. Only exact live op13 promotes; stale activation rejects. Kind-5 and custody withdraw only their own claims, preserve actual tombstones/public floors and never decrement/reuse generations. No name barrier or predecessor pin remains after exact cleanup. |
| Late yes / NO_WAITER | First/fresh/replayed yes after failed CREATE; typed and legacy exact NO_WAITER, including yes after kernel adopted 20 and freed its receipt. Persist basis → restart → exact cleanup. Generic error/false return/time is not NO_WAITER. Before-basis crash stays inert/held. Concurrent NO_WAITER and kind-5 converge without duplicate pin release or successor deletion. |
| Legacy negative metadata | Existing refusal file cannot override a positive or new current-policy answer. Malicious contents/name-derived stage paths confer no authority. Safe deletion removes only opened legacy metadata; reparse/hard-link/replacement/unknown files are not followed/deleted. Metadata cleanup failure does not block admission/unload. |
| Retained custody | Exact never-exposed residue stays present/private/charged, receives typed op23 custody ACK, drains kernel ownership and permits voluntary unload/EPOCH_DRAINED when no other blocker exists. Remove or alter **each applicable proof field** individually: agent returns Held/EpochBusy and unload vetoes, including when path is absent. Generic Retained/legacy flags and false restrictions cannot qualify. |
| Custody lifetime/restart | Lost op23 reply, disconnect/reconnect, crash before/after atomic custody+charge replacement and delayed local reference release. Agent custody alone cannot free an unacknowledged/undrained kernel ticket. Reconstruct identical count/byte/dependency charges after service restart and unload/reload; malformed/duplicate/orphan accounting remains charged and held. Validate retained earlier-epoch records. |
| Custody nonpublication | Attempt every transition/startup/migration/inspection/publication/seed/export/hand-back/justification/automatic-cleanup route, including later approval/read-export grants. All reject before side effects. Bytes, restrictions, charge and ancestry survive compaction; no public/export/justified copy or automatic deletion/uncharge. Original app cannot access private custody after unload. |
| Driver deletion | Driver-held release→local drain→exact disposition/close/removal→service restart→one durable completion; rename count/epoch/generation/full identity mutations; lost Release/Query/op24 replies; before/after completion replacement faults; no second disposition/public mutation. |
| Rename revocation | Release accepted, then admitted rename before claim; lost/delayed Release reply; rename prepare/abort/commit and lost commit ACK; lower target generation; multiple renames; old replay before/after revocation ACK. Old preparations drain without disposition, normal rename succeeds, new tuple requires approval/new nonce. Old revocation after new deletion cannot change new `StageDeleted`. |
| Claim races | Active rename, app handle, follow-up seed/ancestry or callback prevents delete claim. Mutation after claim cannot retarget the record. Independent new-transfer saves remain normal. No revocation allocation failure or slot leak at capacity. |
| Pre-Release retention | Owner exit/supersession before inspection, publication or Release; delayed policy result; restart/disconnect; follow-up predecessor pins; old/new disposal in either order. Release finds exact shell without live owner. BLOCK/justified cleanup follows real CleanedUp drain, including lost notification/backing closed before notification. Shells stay counted until actual destruction. |
| Control 35 | Every result in each legal phase; reject illegal phase/result/ID combinations, wrong ExpectedReceiptId, echo/tail/channel mutations and generic denial. Factory-pending zero versus accepted-pending nonzero; capacity still permits existing Query/replay. Lost Release/Query never creates a new nonce, deletes through fallback or drops ownership. |
| Replay ordering | Saved deletion/revocation replay with missing/replaced stage, changed parent or throwing observation helpers; no fresh stage/parent observation. Crash after atomic resolution returns saved result. First receipt performs required validation; mismatched saved request fails before observation. |
| Negative deletion | Absent without receipt, historical receiptless entries, replacement/reparse/changed parent, access errors, pending link, incomplete lifetime, failed/indeterminate disposition and driver loss before persistence remain held. Revocation with missing committed chain/mixed facts/wrong reply kind remains held. |
| Bounds/unload | Factories/shells/revocations/in-flight records included; reserve before delete; slots return only after actual free. Unresolved positive cleanup, shell, revocation, unacknowledged deletion and unproved residue veto; qualified transferred residue alone does not. Normal reconnect resolves; quarantine/post-ACK behavior preserved; mandatory sends no new RPC. |
| Idle/compaction | Completed cleanup/revocation does no recurring per-entry work; unfinished work backs off; holds park. Positive allocation/cleanup receipts and claim roles, historical release intents, exact rename dependencies, ancestry/floors survive compaction. Batch-1 BLOCK/history-name fixes remain intact. |

The lost-refusal/policy-flip, positive-to-no prevention, typed NO_WAITER, generation-neutral cleanup and legacy-file controls must demonstrate the pre-change failures rather than merely mirror the new implementation.

Extend [publisher disposal tests](../agente/SafeUpload.Agent.Tests/StagedTransferPublisherTests.cs), [hand-back recovery tests](../agente/SafeUpload.Agent.Tests/StagedHandbackTests.cs), [journal/scan tests](../agente/SafeUpload.Agent.Tests/StagedTransferJournalTests.cs) and existing allocation/attachment/native controls. No renamed/removed tests, skips or weakened assertions.

Kernel source/property mutations must catch:

- seal intent omission/alternate-entry bypass/live-owner seal requirement; exposure reset/fabricated cleanup/early flag clear/double pins;
- dead allocation switching back to Live or recovery sending attach/seal traffic; result 20 adopted without exact echo/current channel/local drain;
- early name-barrier release before final failed completion, or dead cleanup continuing to reserve a name; clearing an actual delete/attachment hold;
- positive lookup after policy/legacy negative files; positive evidence becoming 20; result 20 before unjournaled cleanup; new durable allocation-refusal writes;
- candidates/withdrawn rows participating in active head/floor/reservation selection; cleanup resetting generation high-water, another head, predecessor or real tombstone;
- NO_WAITER dropped by typed reply adapters, inferred from generic failure/time, not persisted before cleanup or used after attachment ambiguity;
- lost kind-5 ACK releasing twice, leaking predecessor references, detaching a successor or deleting by pathname instead of exact private identity;
- qualified custody unconditionally vetoed, or unqualified residue exempted by owner exit/counters/legacy flags/opaque GUID alone;
- custody ACK without exact binding/current channel/local NeverExposed proof; live callback/RPC/lease ignored; premature pin/slot release; synthetic seal/deletion;
- custody field/charge/ancestry/restriction validation bypass; absence fallback; stale drain replay bypassing custody validation; earlier-epoch inventory skipped;
- publication/seed/export/justification guards omitted; generic Retained transition used for custody; startup/compaction/orphan cleanup dropping restrictions, ancestry, bytes or charges;
- delete without record reservation; map publication after unlink; undisposed owner-exit/superseded stream freed before exact Release/CleanedUp;
- rename clearing disposal without revocation; old request restoring disposal/retargeting receipt; missing suspension; claim racing admitted rename/seed owner;
- revocation after disposition entry, fabricated drain, closing renamed backing, early source-pin release or revocation ACK interpreted as deletion;
- wrong tuple/count/nonce; illegal control result/ReceiptId/phase adoption; counters/Held=0 used as completion;
- fresh observation before saved receipt lookup; current-head checks rejecting exact historical replay;
- accepting disposition without close/removal; repeating accepted/uncertain disposition; early ACK/free/slot return;
- uncounted factory/scratch ownership; PAGE/spin/I/O violations; reverse lock order; missing deletion/revocation/dead-allocation/custody/shell join;
- refusal polling/stale-channel adoption; introduction of deferred retirement/reconnect/permanent-refusal behavior.

Batch contracts, persistence, worker/accounting and positive receipt retention coherently. Run local four-profile compile, required-test preflight/all T5 checks, complete agent matrix and four WDK/PREfast/ApiValidator/import 0/0 gates; obtain fresh independent Sol 6.1 xhigh security/lifetime review before revised boot. Then authorized matched-pair loss/restart/unload/Verifier rows, independent bytes and separate restoration. Source acceptance, component results and protected qualification remain distinct.
