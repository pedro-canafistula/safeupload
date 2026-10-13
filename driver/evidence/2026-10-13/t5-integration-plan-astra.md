# T5 integration gap inventory and implementation plan

**The integrated path is not ready to enable.** The repository has substantial journal, transport and native-recovery components, but live allocation still uses V19, bound publication has no kernel implementation, and startup deliberately refuses unresolved native holds.

Analysis began at `a00e7e145271fdf0a16360aae0d663517d903b3a`. During the read, HEAD advanced to `dfe7f48141401ba89b8e976773a77cb423a4ddde` on `feat/driver-m2`. That commit changes only T18 documentation; the T5 source and contracts cited below are unchanged. No files were edited and no builds, tests or VM actions were run. The only untracked entry observed was `.ai-memory.toml`.

Citation prefixes below expand to these repository directories:

- **K/** = [driver/SafeUpload.Minifilter/](driver/SafeUpload.Minifilter)
- **S/** = [agente/SafeUpload.Agent.Service/Interception/](agente/SafeUpload.Agent.Service/Interception)
- **M/** = [agente/SafeUpload.Agent.Minifilter/](agente/SafeUpload.Agent.Minifilter)
- **C/** = `agente/SafeUpload.Agent.Core/`; **A/** = `agente/SafeUpload.Agent.App/`.

The controlling decisions are option 1, ordinary empty-file publication, published-only delete suppression, automatic native recovery, and the narrowly scoped forced-instance exception. Earlier “pending choice,” EmptyHeld and synthetic-proxy proposals are superseded. See [POST-MVP-PLAN.md:49](driver/POST-MVP-PLAN.md:49), `:69`, `:75`, `:84`; [T5-PUBLIC-PROXY-ROUTING.md:4](driver/T5-PUBLIC-PROXY-ROUTING.md:4).

## 1. State table

**Connected** means connected to the current live prototype path. **Component** means implemented but gated, uncalled, or disconnected from the complete transaction. No component result establishes qualification of the protected pair.

| Path element | Kernel: connected / component / missing | Service: connected / component / missing |
|---|---|---|
| **Allocation** | **Connected:** `StageCreate` calls `SafeUploadStageAllocateV19`, retaining its allocation receipt. **Component:** `SafeUploadStageAllocateBoundV23` exists without a caller. **Missing:** corrected writer lease, complete authority/metadata capture and V23 selection from live CREATE. `K/StageStream.c:2233,2272`; `K/StageProtocol.c:984`. | **Component:** V23 dispatcher, allocation turn, generation claim and bound manifest. **Disconnected:** `_stageBoundHeadReady` is initialized false and has no enabling integration. Security is optional at the allocator boundary and absent from the live call. `S/MinifilterBoundAllocation.cs:12,45,89`; `S/StagedBoundTransferAllocator.cs:12,33`; `S/StagedBoundAllocationJournal.cs:73,88`. |
| **Seeding** | **Component:** original CREATE subject/input capture and identity helpers. **Missing:** writer-specific checked public backend, retained original-rights object, post-RPC revalidation, proved coherent copy and seed-completion receipt. The existing `SafeUploadStagePublicOpenBackend` is DELETE-oriented and uncalled. `K/StageStream.c:2818`; `K/StagePublic.c:603,664,691`. | **Component:** predecessor identity/length validation and seeded private-file creation. **Wrong route for integrated T5:** existing public bytes come through a second service read handle. It is anchored and identity checked, but does not preserve original caller sharing/authority. **Missing:** kernel-seeded allocation completion and inherited export provenance. `S/StagedBoundTransferAllocator.cs:50,58,68`; `S/StagedDestinationDirectory.cs:75`. |
| **Seal** | **Connected:** local stream drain, read-only backing transition, pending seal receipt and retry. **Missing:** binding seal to completed V23 seed/security provenance and the shared destination head. Existing drain also needs mandatory-teardown separation. `K/StageStream.c:4942,5048,5077,5672`. | **Connected:** V19 seal validates driver/stage/generation and measures the stage. **Missing:** bound completion prerequisite and connected bound publication dispatch. `S/MinifilterInterceptor.cs:1087`; `S/StagedTransferJournal.cs:1941`. |
| **Inspection hand-off** | **Connected:** immutable-stage/seal notification machinery. **Missing:** integrated bound allocation/seed authority carried through that hand-off; an ordinary seal receipt alone is insufficient. `K/StageStream.c:5048,5672`. | **Connected:** legacy sealed-transfer inspection and current-policy checks. **Explicitly disconnected:** `PublishCoreAsync` rejects `BoundAllocation` before inspection. **Missing:** bound inspection branch retaining the same extraction, policy and justification gates. `S/StagedTransferPublisher.cs:81,83,214`; `S/MinifilterInterceptor.cs:1228`. |
| **Publication permit** | **Component:** V26 layouts and size assertions only; no control-33 handler or permit-record implementation. Legacy permits are not substitutes. **Missing:** create/rename permit state, immutable facts, one-way data fence and full-identity namespace reservation. `K/StageBoundPublication.h:5,80`; `K/Communication.c:1971`; `K/StageProtocol.c:231`. | **Component:** V26 send, complete paged Facts replay and exact ACK client. **Missing:** live callers and publication orchestration using these permits. `M/BoundPublicationClientV26.cs:12,19,48`. |
| **Physical publish** | **Missing:** actual original service CREATE/rename callback enforcement, exact temporary capture, post-I/O drain/flush, target recheck and native outcome capture. V26 declarations confer no authority. `K/StageBoundPublication.h:5`; contract `driver/T5-BOUND-PUBLICATION.md:36,82,102`. | **Connected:** legacy path-based temporary creation/commit. **Component:** shared-head publication intent and native-result projection. **Missing:** durable pre-CREATE attempt, parent-relative exact-object publication and Published→Released completion. Bound transfers correctly cannot fall back to legacy. `S/StagedTransferPublisher.cs:83,344,356`; `S/StagedDestinationCommitJournal.cs:746`; `S/StagedPublicationNativeJournal.cs:87,122,150`. |
| **Public delete** | **Component:** original nonwriting native CREATE/disposition lifecycle hooks, bounded records and inline ordinary disposition relay. **Gated:** native forwarding requires negotiated readiness. **Missing:** combined writer+DELETE backend routing, complete owner tombstone integration and common publication name gate. `K/StageStream.c:3550,7876,8310`; `K/StageNativeRecords.c:508,632`; `K/StageProtocol.c:1043`; `K/StagePublic.c:603`. | **Component:** shared-head delete admission, ordinary/native result handling and dispatchers. **Gated:** live dispatcher wrappers require `_stageBoundHeadReady`. **Missing:** connection to every physical publication/delete route and associated owner-visible namespace changes. `S/StagedDestinationCommitJournal.cs:321,388,432,619`; `S/StagedPublicOpenDispatcher.cs:351`; `S/StagedNativeLifecycleDispatcher.cs:199`. |
| **Native accepted/unresolved recovery** | **Component:** original-object facts, actual NTFS result, cancellation/cleanup evidence and coverage-loss recording. **Missing:** complete live integration with shared physical publication and combined backends. `K/StageNativeRecords.c:632,668,740,818`. | **Component:** dispatcher records facts, obtains exact lifetime proof, observes the anchored name and reconciles under the recovery turn. **Gated:** live wrapper. Existing journal can release the exceptional hold without inventing a physical delete receipt. `S/StagedNativeLifecycleDispatcher.cs:54,85,101,109,206`; `S/StagedDestinationCommitJournal.cs:536,575`. |
| **Startup recovery** | **Component:** authenticated native replay/boot identity and metadata-only name observation controls. **Missing:** V26 publication replay producer and integration across retained private/publication/native obligations. `K/Communication.c:1971`; `K/StageBoundPublication.h:5`. | **Connected:** asynchronous startup reconciliation and conservative private recovery. **Explicit gap:** startup throws on unresolved native holds rather than resolving them. Bound `Publishing` is also rejected by generic recovery. `S/StagedNativeStartupRecovery.cs:64,84,105`; `S/StagedTransferJournal.cs:2776,2790`; `S/StagedTransferRecovery.cs:65`. |
| **Last-close reconciliation** | **Component:** native post-CLEANUP records last-handle evidence and removes non-owning lookup keys; cancellation CLOSE is separately tracked. **Missing:** full backend/application lifetime integration and event-driven name reconciliation for remaining pending cases. `K/StageNativeRecords.c:740,767`; `K/StageStream.c:8351`. | **Component:** lifecycle/public-open reconciliation methods consume exact evidence and anchored observations. **Missing:** complete trigger wiring, including subsequent directory changes when the original file remains delete-pending. `S/StagedNativeLifecycleDispatcher.cs:96`; `S/StagedPublicOpenDispatcher.cs:242`; contract `driver/T5-NATIVE-PUBLIC-OPENS.md:283`. |
| **Cleanup ACK / retirement** | **Connected:** legacy seal/discard/allocation retry obligations. **Component:** native record ACK removal only after terminal local facts. **Missing:** V26 cleanup/ACK producer and lifetime integration for new objects. `K/StageStream.c:5236,6113`; `K/StageNativeRecords.c:913`; `K/StageBoundPublication.h:5`. | **Component:** native ACK arming followed by later authenticated removal proof; exact private cleanup and bound compaction support. **Missing:** V26 pre-CREATE/failed-attempt lifecycle, ACK persistence/retirement orchestration and complete reference closure. Native publication receipts currently preserve ACK fields but do not implement that workflow. `S/StagedNativeLifecycleDispatcher.cs:133,154`; `S/StagedDestinationCommitJournal.cs:825,846`; `S/StagedPublicationNativeJournal.cs:124,129`. |
| **Voluntary unload veto** | **Connected:** native-record veto, admission preflight, stage/RPC/attachment checks and epoch-drain handshake. **Missing:** coverage of new writer/permit/backend references and alignment with the approved “any outstanding private stage” rule. Idle ordinary native records are intentionally distinguishable from outstanding obligations. `K/StageStream.c:6444,6470,6531,6684`; `K/StageNativeRecords.c:75,991`. | **Connected:** epoch/drain and cleanup support. **Missing:** complete bound cleanup receipts for all new components. A service outage must leave a recoverable unload veto, not trigger abandonment. `S/StagedDriverEpochStartup.cs:12`; contract `driver/T5-DELETES.md:342`. |
| **Mandatory teardown** | **Incorrectly service dependent:** `FilterUnload` retries `PrepareUnload(TRUE)` before closing ports; preparation requires service readiness, cleanup and epoch ACK. **Missing:** irreversible admission fence plus service-independent local drain. `K/Filter.c:482,490,527`; `K/StageStream.c:6531,6703`. | **Connected recovery primitives:** interrupted Allocated becomes Unsealed; uncertain Publishing stays held; known discard/released cleanup is retried. **Missing:** integration of bound/native publication recovery, not a shutdown responder. Mandatory teardown must not require service execution. `S/StagedTransferJournal.cs:2768,2790`; `S/MinifilterInterceptor.cs:1418`. |

## 2. Option 1 implementation specification

### Authority and provenance

There is currently **no affirmative old-byte export-authority check** on the bound seed-to-hand-back path.

The legacy security path checks requested CREATE rights; it does not establish a separate right to disclose seeded bytes. Its metadata reads also use a different access path. The corrected original effective subject is captured before queueing, but is not connected to a writer backend or durable export evidence. The bound service dispatcher primarily binds process identity; the copier binds the destination session user and creates a readable hand-back. Those are different proofs. Evidence: `K/StageSecurity.c:18,63,105,146`; `K/StagePublic.c:140,187`; `K/StageStream.c:2818`; `S/MinifilterBoundAllocation.cs:65`; `S/StagedHandbackCopier.cs:89,238,920`.

Implement the following within the reviewed [seed/read-authority correction](driver/T5-NATIVE-PUBLIC-OPENS.md:609):

1. **Determine seed origin at allocation**, from the actual native disposition/result and exact source: no prior public bytes, existing public source, or private predecessor carrying prior provenance. Persist full source/binding identity and predecessor generation. New/absent and truncating/superseding cases start without old bytes. Do not infer this from final length, write masks or apparent overwrites.
2. **Determine read authority under the retained original effective subject**, independently of requested write access. Bind the result to the exact source and captured security/identity evidence. A write-only requested handle is not a denial. Distinguish explicit access/label denial from sharing failure, unsupported probe or other indeterminate result.
3. **Validate export to the eventual recipient**, not merely the process-primary SID. An effective-thread grant cannot automatically authorize disclosure to another principal through a user-profile hand-back.
4. **Persist provenance and affirmative authorization**, including enough evidence/versioning to reject stale or mismatched recipients and sources. Carry restrictions through private predecessor seeds. Missing evidence must remain unresolved.
5. **Separate allocation metadata from completed seeding.** The source/authorization intent precedes copying; completion records the exact private object, coherent copy, EOF/flush and revalidation before exposure. Do not mutate an already committed immutable security snapshot to mean “copy completed.”

The current security snapshot contains construction/stored descriptors and binding metadata, not this provenance: `S/StagedAllocationSecuritySnapshot.cs:11,16`. Its durable ordering is reusable: `S/StagedBoundAllocationJournal.cs:88`. The proposed paged writer-metadata carrier in `reports/T5 native writer authority.md:42` remains a design/mechanism dependency; preserve existing V18/V23/V26 layouts and add no successor protocol or journal state.

### Persisted blocked-private behavior

For a blocked version containing prior bytes without affirmative export authority, persist:

- Existing `TransferJournalState.Blocked`.
- Existing `StagedHandbackState.Failed`.
- A named `HandbackFailureReason`; proposed names are `seed_export_denied`, `seed_export_unproven` and `seed_export_recipient_unproven`.
- No hand-back path or length; justification closed; private stage retained.

These diagnostic names are implementation proposals, not existing constants. This is the approved option 1 representation, not a new lifecycle state. See `driver/T5-NATIVE-PUBLIC-OPENS.md:638`.

Persist the private/no-export outcome before any copier or justification registration can execute. Recovery must recognize an interrupted blocked transition from provenance alone and finish that bookkeeping without copying bytes.

### Required path changes

| Path | Change and current insertion points |
|---|---|
| **Initial hand-back** | Gate before `HandbackSnapshotAsync`; enforce again at the copy boundary. Current `HasRequestorIdentity` only establishes identity availability. `S/StagedTransferPublisher.cs:245,734`; `S/StagedHandbackCopier.cs:89`. |
| **Journal APIs** | Prevent `BeginHandbackAttemptAsync` from resetting an export-restricted Failed entry to Copying; prevent `CompleteHandbackAsync` from recording Verified without matching affirmative authorization. Current guards do not do this. `S/StagedTransferJournal.cs:2411,2434`. |
| **Justification** | Require export eligibility plus verified hand-back at registration, recovery registration and callback execution. Preserve current digest, version, policy fingerprint and current-policy checks. Do not let a stale remembered callback bypass new provenance. `S/StagedTransferPublisher.cs:214,250,259,599`; `agente/SafeUpload.Agent.Service/Notifications/StagedJustifications.cs:12,25`. |
| **Recovery** | Apply the same check before recopying NotAttempted/Copying, revalidating Verified, or restoring justification. Missing legacy bound provenance cannot become permission. A Failed diagnostic does not itself authorize a later retry. `S/StagedTransferPublisher.cs:499,527,570,581`. |
| **Cleanup and compaction** | Preserve the existing requirement for verified hand-back before blocked-stage cleanup. Retain provenance/security/predecessor references as long as needed by a restricted descendant or unresolved receipt. Do not reap private blocked or unsaved data as a side effect. `S/StagedTransferPublisher.cs:648`; `S/StagedTransferJournal.cs:2516`; `driver/POST-MVP-PLAN.md:749`. |
| **Tray** | Append a reason to `StagedBlockReason`; do not reuse `ReservedEmptySavePrivate = 0`. Carry it through notification routing and render a specific explanation with no returned-file link or justification action: prior contents cannot be returned with the available permissions, so this version remains private. Distinguish denied from unproved authority in diagnostics. `C/Contracts/AgentNotification.cs:33,54`; `A/Views/BlockNotificationWindow.xaml.cs:125,132,137`. |

Clean write-only saves still use the normal inspected publication path when destination authority and all other gates pass. Read/export denial alone must not become option 2’s refusal of editing. A future authority refresh must produce affirmative bound evidence; neither service restart nor a new SYSTEM open is such evidence.

### Tests to add

Extend `StagedHandbackTests`, `StagedTransferPublisherTests`, `StagedAllocationSecuritySnapshotTests`, `StagedBoundAllocationIntegrationTests` and `StagedBoundCompactionTests`:

- Write-only request with independent read authority retains ordinary hand-back/justification; explicit read or label denial preserves clean publication but blocks full-file export.
- Sharing/probe failure is unresolved rather than denial or approval; effective-thread and recipient identities cannot be substituted.
- Public seed → private successor → blocked descendant preserves restriction; new/truncate/supersede cases correctly begin without prior-byte provenance.
- Crashes before/after Blocked persistence, Failed persistence and notification never create a hand-back or restore justification without evidence.
- Direct journal/copier calls and stale justification callbacks cannot bypass the guard; cleanup/compaction retain restricted versions and their required references.
- Empty content follows ordinary seal/inspect/publish; no EmptyHeld revival.
- Native controls establish the read-check mechanism, identity, oplock/audit effects and original share behavior; component mocks cannot establish these Windows semantics.

## 3. Service-independent mandatory teardown specification

### Current dependency chain

`FilterUnload` calls `SafeUploadStagePrepareUnload(Mandatory)`, then retries failed mandatory preparation every 250 ms. Ports close only after success. Preparation first demands native-record retirement, enables worker progress, checks protocol reconciliation/readiness and outstanding RPCs, and finally requires `SafeUploadStageEpochDrainV20` to return `EPOCH_DRAINED`.

Thus an absent service can prevent reaching the port close that would wake pending sends. References: [Filter.c:482](driver/SafeUpload.Minifilter/Filter.c:482), `:490`, `:527`; [StageStream.c:6470](driver/SafeUpload.Minifilter/StageStream.c:6470), `:6531`, `:6684`.

Merely changing `StageStopping` is insufficient: native/public-open fact flushes occur outside the worker’s existing stop-conditioned collection block, and already collected RPC batches and attach-failure retirement paths can still send. `K/StageStream.c:6067,6078,6113,3772`.

### Required split and ordering

Keep voluntary preflight reversible until its existing commit boundary. Introduce a distinct mandatory **local teardown** path; helper names and exact decomposition are implementation choices.

1. **Fence new ownership:** atomically close CREATE/attach, native/publication admission and new worker-RPC acquisition. Cancel queued attaches; deny new metadata/permit work. Cover precollected batches and failure-unwind sends.
2. **Close the service channel early:** revoke the connection’s unused authority and close ports to wake existing `FltSendMessage` calls. Drain actual communication references without awaiting an application reply or cleanup ACK. Reuse the existing local close/drain primitives: `K/Communication.c:434,1197,1263`.
3. **Close driver-owned public backend handles outside global locks**, while retaining the record/instance pins needed by resulting callbacks. Do this before waiting for the last close that the driver’s own hold otherwise prevents.
4. **Drain actual local users:** callback bodies; active attaches; worker-local batches; channel users; publication I/O; staged FILE_OBJECT and section users; paging rundown; backend callbacks. Snapshot and pin under locks, then drop locks before I/O, close, waits or joins.
5. **Join workers and release references in proved order.** Existing `StopWorker`, `ReleaseInstanceReferences` and `StageFree` depend on stronger preparation assumptions than the new path supplies; revise those assumptions rather than bypassing them. `K/StageStream.c:6347,6771,6795`.
6. **Unregister/free only after the applicable lifetime barriers.** Retain communication callback state through unregister and final rundown. Do not reopen admission after irreversible port close. `K/Filter.c:542,558,565`.
7. **Leave private disk state and durable uncertainty intact.** No new blocking cleanup RPC, manufactured epoch ACK, synthetic seal, automatic unsaved-stage deletion or timeout-based release.

The required local drain is explicitly allowed to remain unbounded when external handles or mappings remain. Service independence is not a deadline guarantee. Contract: [T5-DELETES.md:351](driver/T5-DELETES.md:351).

### Obligations that survive service absence

Preserve exact transfer ID, generation, stage/full volume identity, allocation/attachment uncertainty, destination barriers, pre-forward mutation intents, known native outcomes and cleanup obligations. A committed service transition remains replayable; a transition that never committed cannot imply an approved allocation.

Differentiate **local memory retirement** from **durable receipt retirement**. Ending a worker/RPC reference does not prove physical deletion, publication failure or service ACK. Durable unknown outcomes retain their barriers; volatile records cannot be discarded while they remain the only protection against a live object.

Current private recovery already converts Allocated to Unsealed and retains uncertain publication. It does not reap every interrupted stage: `S/StagedTransferJournal.cs:2776,2790,2821`.

### Forced-instance exception

The owner permits coverage-lost fixed-NTFS names to remain held until exact evidence or a qualified full Windows Restart. App close without the lost callback, service restart and Fast Startup do not suffice. Keep `FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP` and voluntary-unregister vetoes. `K/Filter.c:190`; `K/StageNativeRecords.c:818,991`; `driver/POST-MVP-PLAN.md:84`.

Do not implement mandatory teardown by deleting coverage-lost records or treating a new driver GUID as proof of ended lifetime. The new local drain must preserve that distinction; if live local lifetime cannot be proved ended, it cannot free the state. Actual shutdown does not simply exercise `FilterUnload`, and Fast Startup can retain the original driver/map; see `driver/T5-NATIVE-PUBLIC-OPENS.md:309`.

### Controls and review risks

- Static/call-graph controls: no mandatory path reaches epoch drain, service-dependent preparation or fresh cleanup sends; include worker batches, attach cancellation, failure unwind and native/publication fact paths.
- Race/fault controls: absent or disconnected service; in-flight send; queued/active attach; accepted delete; unknown rename; held backend handle; active write/flush; mapping; cancellation; forced-instance loss.
- Verify close-before-wait for driver-owned handles, exact once-only reference release and callback residency through unregister.
- Verify voluntary veto preserves listener/worker/retry usability and all new obligations participate.
- Verify restart leaves unsealed/private state retained and never repeats a successful public mutation.
- Run four WDK/PREfast/ApiValidator builds at 0 warnings/errors before review. Runtime tests require later owner authorization; the T4 stop remains in force.

## 4. Connected-path increments

These are commit boundaries, not promises that every native mechanism is already available. A blocked native prerequisite keeps the dependent increment dormant.

**Verification notation:** **A** = focused agent controls during development plus complete normal/feature × Debug/Release agent matrix at delivery; **K** = four normal/feature × Debug/Release WDK builds, PREfast and ApiValidator, all 0/0; **N** = specified native controls, with Windows PowerShell 5.1 parse/signature/self-checks for harness changes and a real run only when authorized. **L** marks kernel lifetime/lock-order work for the single pre-boot package.

1. **Persist option 1 provenance and enforce private/no-export outcomes — agent.**
   Change `StagedTransferJournal`, allocation metadata records, publisher/copier, justification guards and tray reason propagation at the locations in §2. Add lineage retention and crash-recovery controls. Contract: `T5-NATIVE-PUBLIC-OPENS.md:619`. No dependency on a working kernel producer: missing bound evidence fails closed. **A.** Bound capability remains false.

2. **Implement the original-authority writer lease and complete capture — kernel [L].**
   Extend `StagePublic` and CREATE capture/ownership in `StageStream`; introduce a writer-specific factory rather than widening the DELETE backend. Use original static effective subject, original root/raw identity, sequential supplemental disposition check then retained original-rights/share FILE_OPEN lease, complete ancestor snapshots and separate construction/stored security. Validate low impersonation and native creator-grant semantics. Contract: `T5-NATIVE-PUBLIC-OPENS.md:456`; `reports/T5 native writer authority.md:11`. **K, N.** No exposure or V23 activation yet.

3. **Connect bounded writer metadata transport and durable allocation prerequisites — kernel/agent [L].**
   Add the reviewed metadata-carrier mechanism in `Communication.c`, allocation support and the minifilter client; require exact bound security/provenance in `MinifilterBoundAllocation`, `StagedBoundTransferAllocator` and `StagedBoundAllocationJournal`. Bind every page to reservation/driver/connection/phase, bound storage and reject incomplete replay. Preserve fixed protocol layouts. Depends on 1–2 and concrete carrier/security review. Contract: `reports/T5 native writer authority.md:42`; `T5-NATIVE-PUBLIC-OPENS.md:650`. **A, K, N.** NotReady remains.

4. **Connect V23 allocation, kernel seeding and seal prerequisites — kernel/agent [L].**
   Switch the prepared bound CREATE branch from `SafeUploadStageAllocateV19` to V23 only after valid capture; revalidate after RPC, seed the exclusive backing through the checked kernel source, complete EOF/flush and record completion before exposing the app object. Remove the second public read from this branch. Propagate predecessor provenance and bind seal to completed seeding. Depends on 2–3 and proved coherent-copy controls. Contract: `T5-NATIVE-PUBLIC-OPENS.md:384,609`; `T5-DELETES.md:230`. **A, K, N.** The global bound capability stays off pending the rest.

5. **Implement V26 kernel permit/facts lifecycle — kernel [L].**
   Implement the declarations in `StageBoundPublication.h`, control-33 dispatch, callback routing, bounded preallocated records, exact service CREATE capture/security validation, one-way DataFenced I/O drain, rename permit, namespace reservation, revoke/cleanup and Facts/ACK retention. Depends on 2–3 and descriptor construction proof. Contract: `T5-BOUND-PUBLICATION.md:36,82,102,124`. **K, N; A for transport controls.** CreatePermit remains NotReady unless all prerequisites are present.

6. **Connect bound inspection and physical publication to the shared head — agent.**
   Add the bound branch alongside the explicit legacy rejection; prepare/inspect outside the short physical turn, persist pre-CREATE and rename intents, use anchored original service operations and V26 permits, persist native facts before Published, then complete Released. Extend `StagedPublicationNativeJournal` to cover attempts before rename and failed CREATE, not only an existing PendingCommit. Depends on 1, 4–5. Contract: `T5-BOUND-PUBLICATION.md:229`; source `S/StagedPublicationNativeJournal.cs:118`. **A, N.** No legacy fallback; readiness still false.

7. **Unify public deletes and supported namespace mutations — kernel/agent [L].**
   Connect original ordinary disposition, scheduled native CREATE and combined writer+DELETE backend to the same destination turn and kernel name gate; implement accepted-only owner tombstones, FALSE cancellation semantics and sealed-private cancellation generation handling. Preserve original request mode/thread/flags/status and T10 public security-only routing. Depends on 2, 4–6. Contract: `T5-DELETES.md:166,230`; `T5-NATIVE-PUBLIC-OPENS.md:3,114`. **A, K, N.** No synthetic FCB, second application handle or scheduled-delete emulation; readiness remains false.

8. **Connect startup/last-close recovery and exact receipt retirement — kernel/agent [L where callbacks/events change].**
   Replace startup’s unconditional unresolved-hold refusal with the reviewed anchored dispatcher; wire last-close and directory-change triggers; reconcile bound Publishing from exact native facts; finish V26 ACK persistence and later-replay retirement. Extend compaction closure. Keep recovery off the receive loop when it can wait or issue controls—the current seal handler is synchronous. Depends on 5–7. Contract: `T5-NATIVE-PUBLIC-OPENS.md:217,283,742`; `T5-BOUND-PUBLICATION.md:229`; source `S/MinifilterInterceptor.cs:369,1107`. **A, K, N.** Readiness cannot become true until the complete recovery pass succeeds.

9. **Close the T11 SOP startup/retirement condition — kernel [L].**
   Validate original SOP lifetime at startup and retire changed-incarnation entries with explicit lifetime evidence; inspect `StageWriters` activation/quiescence paths and `StageAdmission` accounting. Current changed-SOP activation logic is not itself closure of the open T11 condition. Preserve sticky Unknown and every reference/section obligation. Depends on the final ownership model from 2, 4–5, 7–8. Contract/status: `POST-MVP-PLAN.md:748`; source `K/StageWriters.c:4049,4160,6104,6181`; `K/StageAdmission.c:774`. **K, N.** No T4 threshold or reclamation workaround.

10. **Implement mandatory local teardown and final readiness composition — kernel/agent [L].**
    Split `FilterUnload`/`SafeUploadStagePrepareUnload`, fence every producer, close/wake the channel, close owned backend handles, drain/join local work and preserve durable uncertainty as §3 specifies. Extend voluntary vetoes to all preceding records. Compose `_stageBoundHeadReady` only from the completed negotiated path and successful recovery; disconnect/replay invalidation clears it. Depends on all preceding ownership and recovery work. Contract: `T5-DELETES.md:333`; `T5-BOUND-PUBLICATION.md:119`. **A, K, N.** Normal builds still compile staging out; unsupported storage and taint gates remain unchanged.

The ten commits form one coherent kernel lifetime review package. Any new security mechanism beyond the reviewed contracts needs independent design review; this does not justify a separate review for each mechanical revision. Required product VM rows remain stopped until owner direction.

## 5. Blocking semantic questions and conservative behavior

The reason names below are proposed diagnostics. “Allowed hold” means a development/recovery safeguard, not approval to ship a narrower M2 contract.

| Question / evidence | Conservative behavior and user experience | Decision/control status |
|---|---|---|
| **Can native temporary CREATE preserve the full assigned descriptor?** Seven builder cases gave five exact matches and two inherited-descriptor mismatches: `0x8C04 → 0x8804`, losing `SE_DACL_AUTO_INHERITED`. Adding AUTO_INHERIT_REQ did not repair them. `driver/T5-NATIVE-PUBLIC-OPENS.md:698`. | `publication_security_not_equivalent`: refuse the create permit or withhold exposure after mismatch, preserve exact cleanup facts and retain the save privately. No control-bit stripping, protected-DACL substitution, privileged post-set or AccessState injection. Global readiness stays off. | **Native mechanism unresolved.** Fail-closed refusal is explicitly allowed by `T5-BOUND-PUBLICATION.md:63,73`. Declaring the two cases unsupported or relaxing metadata equality requires owner approval. Builder 19045.6466 evidence is not target 19045.2965 qualification. |
| **How are construction and stored descriptor semantics represented?** Native construction-only/defaulted behavior is not identical to every stored bit. Creator controls also show initial write can succeed with an eventual read-only/empty DACL. `T5-NATIVE-PUBLIC-OPENS.md:698`; `K/StageSecurity.c:211,222`. | `native_create_security_unproved`: hold/refuse the affected operation while retaining separate construction and expected stored descriptors. Do not substitute “would the resulting DACL grant a new write open?” for the original creator grant. | **Native control required**, followed by owner decision only if faithful construction is impossible. Conservative hold is allowed; changing original caller semantics is not. |
| **Can the captured effective subject be used faithfully for all supported callers?** `SeCreateClientSecurityFromSubjectContext` remains a limitation for low impersonation levels even when the local `RequireImpersonation` guard is false. `K/StagePublic.c:140,187`; `reports/T5 native writer authority.md:11`. | `writer_subject_unrepresentable`: refuse that unproved transaction before exposure. Never fall back to SYSTEM, the process token or a broader impersonation token. | **Native/control design dependency.** Temporary fail-closed behavior follows the invariants. Permanent exclusion of required caller modes needs a scope decision. |
| **Does the exact checked kernel source support a coherent seed interval?** Full ID and EOF do not make content atomic; per-chunk locks or matching digest do not prove a whole-copy interval, especially with mapped writers. `T5-NATIVE-PUBLIC-OPENS.md:609`; `reports/T5 native writer authority.md:52`. | `seed_coherence_unproved`: retain/refuse before app exposure; never present a mixed or partial seed. This can temporarily prevent existing-file saves during development. | **Native control required** for original rights, range locks, oplocks and compatible writers/mappings. Blanket denial of read-denied editing as a finished solution would be unapproved option 2. |
| **How is old-byte read/export authority proved, including recipient identity?** Current process/session binding does not answer this. `T5-NATIVE-PUBLIC-OPENS.md:624`; `S/StagedHandbackCopier.cs:238`. | Denied/unproved export gives Blocked + Failed, named reason, no full-file hand-back or justification; clean saves still publish after all ordinary gates. | **Product policy settled: option 1.** Native proof and durable implementation remain open. No further choice between options 1 and 2 is needed. |
| **Can combined writes/deletes preserve actual Windows behavior?** Ordinary disposition must remain on the reviewed original request; scheduled native CREATE cannot be rewritten into an Ex disposition. Existing backend is not connected. `T5-NATIVE-PUBLIC-OPENS.md:3,114`; `K/StagePublic.c:603`. | `public_delete_binding_unproved`: refuse before forwarding when authority/binding is missing. Once NTFS accepted, preserve its result, hold publication and reconcile; do not manufacture a later failure. | Reviewed contracts settle the intended behavior; **implementation/native controls remain**. If actual Notepad ordering removes the prior public file before a blocked save and conflicts with required UX, use the owner-decision stop in `T5-DELETES.md:286`, not a silent emulation. |
| **What releases a hold after lost instance coverage?** Exact cleanup may be unavailable. `K/StageNativeRecords.c:818`; `S/StagedNativeRecoveryEvidence.cs:124`. | Name the file; hold it private until exact evidence or qualified full Windows Restart. No service restart/Fast Startup shortcut or timer-based expiry. | **Already approved for local fixed NTFS only.** Any broader recovery or live-state abandonment needs a new decision. |
| **Which remaining metadata behavior is required?** ACL/owner fidelity is mandatory; broader T8 metadata choices are not all settled. `POST-MVP-PLAN.md:431,732`. | `publication_metadata_unproved`: refuse an affected unsupported/mismatched case without altering descriptors or falsely claiming successful faithful publication. | Existing fail-closed guards permit continued implementation. A lasting change to the metadata contract, supported scope or resource defaults requires owner direction. |

Native controls should be a finite matrix resolving these mechanisms, as called for in `M2-COMPLETION-PLAN.md:56` and `reports/T5 native writer authority.md:66`. They must preserve failed receipts and stop repeated identical failures. They are not authorization for new protected target rows.

## 6. Exact pre-boot Sol review package

Use **`gpt-6.1-sol`, reasoning effort `xhigh`**, replacing historical Luna wording without rewriting historical reports. Review the coherent final kernel change before its first VM boot.

Provide the following changes and explicit invariants:

1. **Original CREATE authority:** `StagePublic.c/.h`, `StageStream.c`, affected `StageSecurity.c` paths. Original effective subject, request flags/root/raw identity, native grants and sharing survive capture, queueing and post-RPC revalidation. Supplemental handles close before retained writer lease acquisition. SYSTEM creates no caller authority.
2. **Writer/backend ownership graph:** enumerate every process, token/security-context, root/parent/source/backing/temporary FILE_OBJECT, handle, instance, callback and work-item owner; acquisition, transfer and release sites; cancellation and disconnect paths. Distinguish owning references from non-owning lookup keys.
3. **Bound allocation and metadata:** `StageProtocol.c`, `Protocol.h`, `StageBoundAllocation.h`, `Communication.c` and the concrete metadata implementation. Preserve existing ABI sizes, enforce current authenticated connection/revision, exact reservation identity, bounded pages/storage and complete replay. No partial metadata becomes permission.
4. **Seed/coherence/seal:** `StageStream.c` and new copy helpers. Prove the entire copy interval, post-RPC source/anchor checks, explicit offsets, bounded aligned buffers, EOF/flush and no app exposure before completion. Read/export provenance survives private successors. Empty stages take the ordinary path.
5. **V26 permit records:** `StageBoundPublication.h` and its implementation/dispatch. Preallocate before forwarding; consume each original CREATE/rename at most once; record actual status/information; preserve failed CREATE and unknown outcomes. Exact service grant/options/security checks do not inject privilege.
6. **Data fence:** same-lock I/O admission and irreversible DataFenced transition; postoperation/cancellation rundown; flush outside global locks; no Fast I/O, MDL, mapping, paging or duplicated-handle mutation bypass. The renamed still-open handle cannot change inspected public bytes.
7. **Destination serialization:** complete root/mount/parent/full-ID/case/leaf key; shared head plus kernel name gate across all supported mutations and delayed delete cleanup. No path-only target authority, stale predecessor publication or pending-save cancellation of a prior delete.
8. **Native delete/backend lifetime:** `StageNativeRecords.c`, `StagePublic.c`, `StageStream.c`. Preserve actual NTFS acceptance; ordinary inline relay and scheduled CREATE semantics; accepted-only tombstones; exact FALSE cancellation; remove non-owning keys before address reuse; driver-held handles cannot deadlock last-close.
9. **Recovery and retirement:** exact callback/lifetime evidence, anchored complete observation, authenticated replay revision and boot proof. Service ACK never substitutes for local lifetime; local close never substitutes for physical mutation result. Durable receipts retire only after the required later complete replay. No retry repeats an accepted public mutation.
10. **T11 writer/SOP accounting:** `StageWriters.c`, `StageAdmission.c`. Validate startup SOP lifetime, retire changed incarnations only with proved obligations resolved, preserve sticky Unknown and accounting. No timer, digest, forced context deletion or T4 threshold change serves as lifetime evidence.
11. **Unload/teardown ordering:** `Filter.c`, `StageStream.c`, `Communication.c`, native/publication record teardown. Voluntary veto remains recoverable; mandatory work cannot send or await service RPC/ACK; close owned handles before dependent waits; join/drain before free/unregister; callback state survives its source barrier. Explicitly review the existing unregister/callback-barrier inference at `K/Filter.c:558`.
12. **Lock-order and failure matrix:** document actual lock nesting and each wait/I/O boundary across namespace/stream resources, local record locks, admission/fence state, channel transition/rundown and service head turns. Include allocation failure, cancellation, disconnect, service crash, policy change, native accepted/lost result, forced instance teardown and mapped/open-handle teardown.

Attach the exact committed source identity and delivered artifact hashes, all four WDK/PREfast/ApiValidator results at **0 warnings / 0 errors**, complete agent matrix discovery/execution and relevant native-control receipts. Keep failed attempts and unresolved conditions visible; no skipped tests, weakened assertions or warning suppression.

Review acceptance, component verification and qualification of the protected driver/agent pair remain separate. The T4 loaded-context stop still blocks product VM rows; the owner’s separate hand-back attribution diagnostic does not authorize booting this implementation.