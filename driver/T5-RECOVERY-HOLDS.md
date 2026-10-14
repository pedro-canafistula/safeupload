# T5 recovery and activation holds

**Proposal against `1db2d9fec0447ce9916c55bf21f102ed424ac75e`, 2026-10-14.** Read-only source and receipt review; no edits, builds, tests or VM contact. The checkout was clean before and after inspection.

This batches the three holds from [fix7 finding 2](evidence/2026-10-14/t5-fix7-review-sol61.md), [replay2 findings 5–6](evidence/2026-10-14/t5-replay2-review-sol61.md) and [block2 finding 3](evidence/2026-10-14/t5-block2-review-sol61.md). It follows workflow rules 3–5 and the integrated T5 checkpoint in [POST-MVP-PLAN.md](POST-MVP-PLAN.md). It does not release activation or recovery qualification.

Source references below use:

- `K/` = `driver/SafeUpload.Minifilter/`
- `A/` = `agente/SafeUpload.Agent.Service/Interception/`

“Verified” describes source behavior at this commit. New states, fields, transitions and tests are proposed contracts requiring independent review.

## 1. Current states and stranding sequences

| Hold | Verified state machine and concrete failure |
|---|---|
| Lost seal ACK | `StageDrainAndSeal` drains the private version, closes its writable backing and irreversibly selects read-only backing; `StageSealVersion` queues a seal (`K/StageStream.c:5706`, `:5741`). Collection pins owner, view generation, transfer, destination generation and full stage identity (`:6070`). Each transport attempt currently creates a fresh RequestId and sends the 40-byte seal payload (`K/StageProtocol.c:2145`, `:2168`). The journal persists `SealPending`, then measured `Sealed` (`A/StagedTransferJournal.cs:2143–2182`). A lost reply leaves `SealRpcPending`; transport failure backs off, while refusal parks as SERVICE (`K/StageStream.c:6438–6472`). Meanwhile inspection/publication or BLOCK cleanup can advance. `SealAsync` can return a progressed measured entry, but first rejects cleanup/deletion and rechecks current destination and backing (`A/StagedTransferJournal.cs:2126–2137`). The handler additionally requires exactly `Sealed` (`A/MinifilterInterceptor.cs:1249`). Thus replay after progress or cleanup cannot acknowledge the original measurement; local `Sealed` remains false and retirement remains blocked. |
| Lost op15 / late fence | Agent attachment progresses `None → Prepared → Committed → CompletionPermitted`; op15 records permission, **not handle delivery** (`A/StagedTransferJournal.cs:882–972`). Kernel retains the exact op15 request and may-exist flag; failed CREATE rolls back its binding (`K/StageStream.c:3690–3774`). Only the original owner’s next writer CREATE can resume, with exact process/view/allocation checks (`:1746–1778`). Maintenance parks pending completion, completion fence and op16 retirement (`:5960`). V20 accepts only `CompletionPermitted` for op15 (`K/StageProtocol.c:1590`); generic DENY proves nothing. If the owner exits or never retries, there is no resolving attachment worker invocation. Owner-exit processing clears the private-delete flag, but does not resolve the attachment receipt (`K/StageStream.c:6542`). A late-fence sequence is also possible: attachment bookkeeping sets `AttachAcknowledged`, clears allocation bookkeeping and sets the fence before later bound/cancellation/exposure checks; a later failure rolls back, while fence clearing is success-only (`:4080–4105`, `:4163–4219`). Both sequences remain private and held. |
| Refusal storage | Allocation and refusal resolution serialize under `_v19AllocationGate`. A manifest wins before live-owner lookup; a definitive negative first removes any unjournaled backing, then flushes and renames the complete 1,192-byte request into `GUID.allocation-refused` (`A/StagedAllocationResolution.cs:28–103`). Exact replay returns the negative; changed bytes refuse. There is no cumulative count/storage reservation or retirement path. Fresh rejected reservations therefore accumulate despite the live-stream bound. `DrainDriverInstanceV20Async` scans journal `*.json`, not refusal files (`A/StagedTransferJournal.cs:93`); replacement overwrites the single epoch record (`:69`, `A/StagedDriverEpochStartup.cs`). The inference from these verified mechanisms is unbounded cumulative refusal storage, as the review records. |

The late-fence sequence is a source interleaving, not a reproduced runtime failure. Historical review line numbers differ from this commit.

## 2. Shared wire and evidence contract

Use one negotiated recovery family. Preserve all existing layouts and enum values.

**Proposed reservations:**

| Capability | Bit |
|---|---:|
| Durable exact seal receipt | `0x200` |
| Exact op15 refusal and attachment recovery | `0x400` |
| Charged refusal storage and durable epoch retirement | `0x800` |

The feature required mask becomes **`0xFBF`**, replacing `0x1BF`. Bound-head bit `0x40` remains independently disabled. Normal builds still compile staging out.

Reserve extension **29** for new seal/op15/recovery/epoch-retirement payloads and operation **23** for private attachment recovery. These identifiers are unused at the inspected commit; assert that before implementation. Existing operations 4, 15 and 17 gain separate extension-29 parsers. Do not reinterpret their old payloads.

An old driver’s `0x1BF` negotiation and an old agent’s incomplete mask cannot activate this family. Return existing reconciliation refusal/EpochBusy with no accepted capabilities; do not fall back to old seal acknowledgement or generic op15 DENY. A same-driver reconnect may retrieve historical receipts under the current authenticated connection; it acquires no new execution authority. Existing unresolved old-format requests remain conservative recovery holds, rather than being converted to fresh requests.

### Version request: operations 4, 15 and 23

Use the unchanged 1,192-byte outer request, with a **124-byte, pack-4** payload:

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

The outer request supplies core version/size, nonzero RequestId, operation, original owner PID, permitted volume flags, extension marker, payload length and path length/bytes. All unused image/path bytes are zero.

- **Seal:** path is the original private stage path; reference is the durable op19 RequestId; proof is zero.
- **Op15:** path is the exact destination name; reference is the committed op13 RequestId; proof is zero.
- **Recovery:** path is the original op15 destination name; reference is its RequestId; proof distinguishes `NeverExposed` from `ExposurePossible`.

Agent validation covers every field: envelope/length/tails/flags; owned stage basename for seal; exact raw request replay; transfer and full stage identity; generation; original driver epoch; owner PID/creation time against the original manifest; parent identity; phase reference; and permitted proof kind. Bind the nonzero view generation durably on first op15 and retain it through the exact rename history. A replay cannot refresh it. Bound entries additionally require their already-recorded mount/root/parent/case/leaf, security and seed dependencies; missing dependencies never fall back to path authority.

For a first authorization or measurement, retain the existing live-owner, current destination, policy, seed and object checks. For an **already-durable acknowledgement**, validate the saved request and receipt instead of demanding that the old name/object still be current.

### Typed recovery reply

Use a separate **1,296-byte, pack-4** reply buffer; the existing 152-byte response cannot hold it:

| Offset | Field |
|---:|---|
| 0 / 4 / 8 | Core Version / StructSize / RequestId |
| 16 / 20 | Verdict / operation-specific Result |
| 24 | Complete original 1,192-byte request echo |
| 1216 / 1224 | Current authenticated connection epoch / authority revision |
| 1232 | Durable ReceiptId, GUID |
| 1248 | MeasuredLength, int64 |
| 1256 / 1260 | Recorded op15 outcome / reason code, uint32 |
| 1264 | Reserved zero, 32 bytes |

Define result values in this new family; do not renumber old results. Each operation accepts only its listed results below. Nonapplicable fields are zero. Durable success/refusal replies require a nonzero ReceiptId; transient/held replies provide no terminal receipt authority.

Before adoption, the driver validates the whole echo, result legality, sizes/zeros and current connection/authority. It then revalidates the pinned stream, owner, view, epoch, identity, generation and operation claim under its state locks. A timeout, malformed reply, stale channel or generic verdict is never typed success.

## 3. Lost seal acknowledgement

Persist an immutable `SealReceipt` **in the same atomic manifest replacement as the completed measured seal**, before inspection can consume it. It contains the complete original request, receipt ID, original driver/boot binding, destination identity at sealing, exact stage identity/generation, op19 reference and measured length. Length zero follows the ordinary path.

Retain the original request in the kernel before the first send. All retries use the same bytes and RequestId.

The agent checks an existing receipt **before** cleanup/current-head/backing checks. Exact receipt replay is read-only in `Sealed`, `Inspecting`, `Approved`, `Publishing`, `Released`, `Blocked`, retained states and after exact cleanup. It neither remeasures nor queues inspection/publication. A receipt attests that this version was durably measured; it does not attest approval, publication or deletion.

| Reply | What the driver does |
|---|---|
| `SealRecorded` | Adopt only for the still-matching pinned request. Clear seal pending/in-flight state, set ordinary local `Sealed`, record the receipt and wake normal disposal/retirement. Release the RPC pin once. Keep every independent mapping, object, cleanup, publication and reservation obligation. |
| `RetryableFailure` | Keep the request, stream and obligations; release only the attempt pin. Retain EXCHANGE cause/deadline through collection and reply; retry unfinished measurement/bookkeeping with bounded backoff. |
| `Held`, generic DENY or malformed reply | Keep the exact request and lifetime state; park as SERVICE with `seal_receipt_unavailable`, `seal_receipt_mismatch` or the specific dependency reason. No timer polling of refusal. |
| Disconnect/stale reply | Keep the request; park until current-channel reconciliation and its sweep. Never apply a late old-channel ACK. |

Compaction must pin the seal receipt and its required manifest/dependency closure while valid driver replay remains possible. Cleanup or publication completion cannot erase it. Include this retained storage in cumulative journal accounting; a manifest size limit alone is insufficient.

A historical `SealedOnce`/length or content digest is not a substitute for the new exact request receipt. Historical records without sufficient receipt evidence stay held, especially after cleanup has begun.

## 4. Op15 refusal, owner-independent recovery and late fences

### Durable op15 outcome

Serialize op15 permission/refusal and recovery closure through the same journal gate. Persist the complete original op15 request and immutable outcome before replying:

- An existing exact permission always replays permission.
- An existing exact refusal always replays refusal.
- A first eligible op15 may persist permission after existing authorization checks.
- A definitive failure may persist `CompletionRefused` only after proving that no permission was committed for that request.
- Query/storage uncertainty or invalid authority gives no definitive refusal.

| Op15 reply | What the driver does |
|---|---|
| `CompletionPermitted` | Record permission known. Continue the original CREATE’s current validation and cancellation arbitration. Release allocation reservations only through successful CREATE completion; the reply alone releases nothing. |
| `CompletionRefused` | Prohibit exposure from that request and queue recovery after local CREATE rollback/completion drains. Keep reservations, receipt and predecessor pin meanwhile. A sent op15 does not become eligible for op16 or kind-5 cleanup. |
| `RetryableFailure` | Preserve the exact request and ambiguity. Complete/roll back the failed CREATE; queue evidence recovery. Do not manufacture a replacement CREATE. |
| `Held`/DENY/malformed/disconnect | Preserve ambiguity and named hold. No terminal release. Reconnect or new exact local evidence may wake recovery. |

### Kernel exposure evidence

Add allocation-level monotonic evidence; the existing transaction-local `ExposeClaimed` does not survive its transaction:

1. `ExposurePossible` is latched under the existing final exposure arbitration lock **before** successful `FltCompletePendedPreOperation`.
2. Record original CREATE completion status/information and that completion returned.
3. Record rollback completion, removal of transaction lookup/producer ownership, and actual cleanup/close/cache/paging rundown separately.
4. Never reset exposure evidence on retry, exit, disconnect or teardown.

**`NeverExposed` requires:** all CREATE transactions for the allocation completed with failure; no exposure claim ever occurred; binding rollback finished; no attach producer/lookup/worker remains; app file-object/share counts and cache/sections/paging ownership are drained; driver-owned backing/backend handles are closed; no competing rename, cancellation or RPC owns the version. Zero counters alone, PID exit and elapsed time are insufficient.

Claim recovery under `StageNamespaceResource` against the same owner-resume claim. Whichever wins excludes the other. Once abandonment is selected, a later owner CREATE uses a fresh allocation after resolution; it cannot revive the abandoned one.

### Operation 23

For `NeverExposed`, the agent validates the exact allocation/commit chain and reconstructs the referenced original op15 from its immutable tuple, original path/flags and committed op13 ID. Compare it byte-for-byte with any saved op15 receipt.

If no op15 outcome exists, atomically persist refusal for that original request, closing it against a delayed op15. Then persist `AttachmentRecovery = RetainedUnexposed` with the exact recovery request and driver lifetime evidence. Preserve the private bytes, original generation, security/provenance and high-water marks. Keep it nonpublishable and unavailable for justification/export without existing authority.

| Recovery reply | What the driver does |
|---|---|
| `RetainedUnexposed` | After rechecking the frozen local proof, detach only this failed view; clear its attachment pending/fence and allocation reservation; drop its one predecessor receipt pin and wake that predecessor. Retire the kernel shell through a distinct retained-unexposed terminal predicate, **without setting `Sealed`, `Discarded` or physical-deletion flags**. Free only after all local references drain. Private storage remains service-owned. |
| `HandleLifecycleRequired` | Exposure was possible: no abandonment or deletion. Preserve ordinary handle lifetime. Once original completion is known, recover only its bookkeeping/fence; actual cleanup, exact op19, drain and seal remain required. Owner exit cannot stand in for cleanup. |
| `Held` | Keep the reservation/receipt and applicable lifetime state with `attach_exposure_unproved`, `attach_lifetime_unproved`, `attach_outcome_unproved` or `attach_recovery_mismatch`. |
| `RetryableFailure` | Keep the frozen claim and exact request; retry persistence/evidence work only. |
| DENY/malformed/disconnect | Keep the hold; park until reconciled reconnect or new qualifying evidence. |

This resolves owner exit/never retry by recovering **evidence and bookkeeping**, not by issuing background op15 authorization or completing another app CREATE.

For late fences, distinguish a known failed, never-exposed CREATE from an exposure-possible CREATE. The former takes retained-unexposed recovery. The latter requires the real completion/lifetime route. Do not broadly clear `AttachCompletionFence` on failure.

Automatic deletion of retained unexposed bytes is outside this proposal.

## 5. Refusal accounting and epoch retirement

### Allocation operation 3

Keep the existing 72-byte V20 allocation request: version/size, reservation GUID, predecessor GUID, disposition, reference kind, driver GUID and original requester creation time; the outer request contains RequestId/PID/flags/destination. Preserve existing exact manifest/refusal replay and all validation.

Before any **fresh** allocation can create backing or write a refusal, reserve one potential refusal slot and its worst-case storage charge under the allocator/accounting gate. Existing exact replay needs no new slot. A positively committed allocation releases that potential-refusal charge only after its exact durable manifest is verified; uncertain replacement retains the charge.

Charges cover committed payload allocation, simultaneously live temporary, crash-orphan temporaries, bounded accounting/retirement records and filesystem allocation units/overhead allowance. Check stage-volume headroom as well; payload bytes alone are not disk accounting.

Keep the existing 1,216-byte complete-request-echo reply and results 19/20. Add negotiated result **21, `AllocationCapacityUnavailable`**, under capability `0x800`.

| Allocation reply | What the driver does |
|---|---|
| Ordinary exact allocation tuple | Existing tuple adoption and attachment/cleanup route. |
| 20, `NoAllocationCommitted` | Existing exact terminal release of this shell reservation and its one predecessor pin. No change to the predecessor’s own delete/publication state. |
| 19, transient/uncertain | Keep reservation/pin; bounded EXCHANGE backoff. |
| 21, capacity unavailable | No backing, generation claim or refusal receipt was created. Keep the exact request/reservation/pin; park as SERVICE with `allocation_refusal_budget_exhausted`. Retry after reconciled reconnect following capacity/configuration restoration; no refusal polling timer. |
| Generic DENY/malformed/disconnect | Existing held behavior; no terminal release. |

At startup, before admission, enumerate and validate committed refusals, their temporaries/orphans and accounting/retirement evidence. Reconstruct charges from disk, including legacy 1,192-byte receipts. Do not reset usage to zero on restart. Malformed, conflicting, unowned or unreadable evidence produces `allocation_refusal_accounting_unproved`; it is charged conservatively and blocks fresh admission.

Crash-orphan removal requires exact validated ownership and retirement evidence. A filename or age is insufficient.

### Durable epoch retirement

Reply transmission and service restart do not retire receipts. Extend operation 17 with an **80-byte, pack-4 extension-29 payload**:

| Offset | Field |
|---:|---|
| 0 / 4 / 8 | Version / StructSize / DriverInstanceId |
| 24 | DrainNonce, uint64 |
| 32 / 36 | Original OS boot sequence / proof flags, uint32 |
| 40 / 48 | Private-state revision / last pre-retirement RequestId, uint64 |
| 56 | QuiescenceNonce, GUID |
| 72 | Reserved zero, uint64 |

Outer PID/flags/path are zero. Required proof flags mean admission permanently closed, producers drained, request uses drained and local lifetimes drained. The private revision changes with relevant ownership/state transitions; an unchanged revision is consistency evidence, not lifetime proof.

Use two retirement constructions:

- **Surviving driver:** preserve voluntary-unload vetoes. Permanently fence new requests before collecting proof; drain producer/callback/worker/channel ownership and every possible old replay sender. Send only the exact retirement request thereafter. The agent closes epoch admission and drains its own continuations, allocator operations and journal work before confirming retirement. Kernel send completion alone cannot prove agent work ended.
- **Qualified full Windows Restart:** reuse the reviewed greater-boot/different-driver/authenticated complete replay and private-startup prerequisites. Persist retirement of the old epoch **before** replacing its accepted epoch record. Service restart, driver GUID change, Fast Startup, missing native rows and boot-counter rollback/wrap cannot qualify.

Persist an exact retirement record before replying `EpochRetired`. Include original driver/boot, retirement request/nonce/revision, construction used and agent quiescence result. Unlike today’s single overwritten epoch record, retain the proof until associated receipt reclamation completes. Reject retired epochs before allocation or receipt lookup, so deleting a negative receipt cannot revive its reservation.

| Retirement reply | What the driver does |
|---|---|
| `EpochRetired` | Keep old epoch admission permanently closed; continue existing safe unload completion. Retry only the saved retirement request if its reply was lost. |
| `Held`/EpochBusy | No retirement or reclamation; preserve existing veto/recovery progress. Wake from actual draining work or operator retry. |
| `RetryableFailure`, DENY, malformed or disconnect | Keep the exact retirement request and permanent fence; no old allocation/attachment/seal replay resumes. |

Reclamation runs only after durable retirement **and** quiescence. Persist reclamation intent, remove only matching validated receipt files, confirm removal, then release charges. Failed cleanup remains charged. Retirement/accounting metadata must itself be bounded and charged; reserve separate recovery headroom so allocation exhaustion cannot prevent retirement persistence.

No timer retires an epoch or receipt. Generation, published and delete floors survive reclamation. Retained private stages remain separate obligations and are not deleted by refusal reclamation.

## 6. Kernel scheduling, locks and restart behavior

- Keep new durable-request snapshots and exposure/claim bookkeeping in bounded **nonpaged** stream/transaction ownership. Allocate capacity before publishing ownership. Spin-lock bodies, DPCs and elevated-IRQL releases remain resident.
- Preserve `StageNamespaceResource → stream Resource/StageListLock`. Exposure arbitration uses `StageAttachLock`; introduce no reverse acquisition against the existing publication/native lock orders.
- Collect a counted stream/RPC pin and immutable request at PASSIVE, drop namespace/stream resources, perform RPC, then reacquire and validate before adoption. Release each attempt pin exactly once on every outcome. No handle close, filesystem I/O, allocation, callback wait or RPC under spin locks.
- Local close/flush/purge/rundown work runs outside resources needed by callbacks. The recovery worker cannot wait for a FILE_OBJECT whose last handle is its own backing/backend hold.
- Completion/rollback, actual CLEANUP/CLOSE, last local-reference release, owner-exit notification and successful reconnect reconciliation wake existing worker work. Owner exit only schedules evaluation. Extend batch/teardown participation controls for the added recovery performer.
- Add persistent seal/recovery wait causes and monotonic retry deadlines. Count eligible obligations while pending **and in flight**. Retryable storage/transport work uses existing 250 ms–8 s backoff; genuine unmap/drain waits retain existing behavior. SERVICE/refusal/capacity holds do not enter timer-only sweeps. DPC remains wake-only; arm from `KeReadStateTimer`, cancel/reset when no eligible work remains.
- Disconnect parks service exchanges without erasing requests or ownership. Startup reconstructs storage accounting and durable receipts before admitting fresh work. Reconnect unparks only after reconciliation succeeds; stale replies cannot undo a newer disconnect.
- Recovery continuations run off the receive loop and release bounded execution slots while waiting. Same-driver pending receipt resolution must be available during startup recovery without granting allocation/publication readiness, avoiding a startup-versus-recovery deadlock.
- Mandatory teardown sends none of these operations and waits for no service receipt. It fences admission, closes ports/owned handles, drains local callbacks/workers and retains durable private uncertainty. Voluntary veto leaves the resolving route usable. Coverage loss/Unknown remains sticky under existing rules.

## 7. Required controls and delivery boundary

### Agent controls

Drive the actual handlers and fresh journals/dispatchers, with exact wire bytes using `MemoryMarshal`.

| Group | Required cases |
|---|---|
| Harness patterns | Resave/new/replace/mapped × approve/BLOCK; empty content; name reuse; rename onto occupied names with generation adoption; BLOCK then resave both before and after retirement. Verify unchanged/prior/approved public bytes independently of journal labels. |
| Seal replay | Lose reply after `SealPending`, measured receipt replacement, inspection, approval/BLOCK, publication, disposal, cleanup acceptance and absence. Restart at each boundary. Exact replay acknowledges; mutation/publication counters do not increase. Include newer name generations and missing/substituted stage. |
| Attachment | Lose each prepare/commit/op15/recovery reply; owner exits, never retries or PID is reused; owner retry races recovery; permission races durable refusal; delayed op15 arrives after recovery closure. Inject late failure before exposure claim and after exposure becomes possible. |
| Lifetime | Duplicate/inherited handles, independent file objects, mapped/cache/paging retention, upper cancellation, completion-return race, forced instance loss and mandatory teardown. Missing evidence keeps the named hold. |
| Accounting | Count/byte boundaries; concurrent fresh refusals; committed allocation releases reservation; before/after-write/flush/rename faults; crash orphans; disk full; startup reconstruction; malformed receipts; exhaustion while exact replay continues. |
| Retirement | Lost retirement reply; service restart during reclamation; active kernel/agent request racing retirement; old epoch replay after receipt removal; same boot/Fast Startup/GUID change/rollback rejected; qualified Restart retires only after complete prerequisites. |
| Adversarial wire/storage | Mutate every envelope, tuple, owner, view, generation, identity, phase reference, proof, result, length, connection/revision and tail field. Conflicting positive/negative evidence stays held. Compaction retains receipts and ancestry until valid retirement. |

Extend existing `StagedAllocationResolutionTests`, attachment/journal controls and publication boundary controls; retain their names and assertions. Tests must distinguish receipt replay from first work and assert native/public mutation counts, not merely successful replies.

### Kernel source/property controls

Extend the existing attachment-replay, attach-pin, allocation-retry, reconcile-retry, rename-receipt and teardown controls; add executable state/property fixtures where source matching cannot establish an interleaving.

Mutations must be rejected for:

- fresh seal RequestId on replay; state-only seal acceptance; clearing pending before exact ACK;
- generic DENY treated as op15 refusal; refusal overwriting permission;
- missing exposure latch, latch after completion, or latch reset;
- recovery and owner-resume claims both winning;
- PID exit/zero counters/timer/native-map absence replacing lifetime proof;
- unresolved op15 entering op16/kind-5 or synthetic seal/deletion;
- wrong view/epoch/generation adoption; reservation or predecessor pin released early/twice;
- RPC under namespace/spin locks; paged buffers touched at raised IRQL; missing/double pins;
- in-flight obligations omitted from census; refusal polling or early deadline resend;
- old-channel reply accepted after disconnect; startup recovery blocked behind its own readiness gate;
- receipt write before charge, orphan omission, restart usage reset, premature charge release;
- epoch replacement erasing retirement proof; reply transmission/elapsed time enabling reclamation;
- any new recovery/retirement send or service wait reachable from mandatory teardown.

Batch the contracts, persistence, worker integration, accounting reconstruction, retirement/compaction dependencies and controls as one coherent change. Then perform local four-profile compile, required-test/discovery preflight and every T5 check; one complete agent matrix and four WDK/PREfast/ApiValidator/import gates; independent **Sol 6.1 xhigh** review of the coherent security/lifetime delta before boot; matched-artifact recovery/fault rows with independent bytes, Verifier and separate restoration. Acceptance, component passes and protected recovery qualification remain separate results.

Owner decisions needed before dependent activation:

| Decision | Recommendation and user-visible effect |
|---|---|
| Production receipt budgets | Approve measured count/storage/headroom defaults. Start evaluation with **4,096 retained refusal slots and 64 MiB charged refusal storage**, including temporary overlap, plus separately reserved recovery metadata headroom. These are proposed defaults, not approved limits. Exhaustion stops fresh protected allocations with a named explanation; existing exact replay/recovery continues. Include new seal/attachment receipt retention in the broader cumulative journal budget. |
| Retained never-exposed stages | Keep them private and nonpublishable while releasing the proved abandoned name reservation. The user can retry saving without waiting for an exited requester; retained residue consumes charged storage. Automatic deletion requires a separate retention/data-loss decision; do not add it in this batch. |
| Missing lifetime/outcome evidence | Keep the named hold and existing applicable remedy. Do not introduce automatic expiry, manual unlock, SYSTEM authority or broader reboot-based recovery. Any broader release policy requires its own concrete owner decision. |

The existing unreadable-seed option 1, full metadata/security contract, generation/delete rules, four bound-readiness blockers and unsupported-destination gates remain prerequisites. This proposal supplies contracts for the three holds; it does not establish their implementation or qualification.