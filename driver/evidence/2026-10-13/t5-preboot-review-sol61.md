# T5 pre-boot lifetime review — Sol 6.1 xhigh (2026-10-13)

Reviewer: `gpt-6.1-sol`, `reasoning_effort=xhigh`, read-only, web search enabled. Input: commit `a27defd8` (detached checkout), [package](../../T5-PREBOOT-REVIEW-PACKAGE.md), kernel delta `9e86822f^..a27defd8`. Brief: increments 2–10 lifetime, lock order, teardown, fail-closed, bounds, pre-boot readiness. Verbatim final report below; checkout paths shortened.

**Verdict: REJECT for the first Verifier boot of `a27defd8`.**

The dormant gates remain intact, but feature-driver initialization has a reachable leak. Capture accounting also needs correction before protected traffic. The supplied WDK and agent receipts establish static/component results; they do not cover these failures.

Review remained read-only. The checkout is clean; no builds, tests or VMs were run.

**Confirmed findings**

1. **Blocker — failed V26 worker creation leaks the writer-registry pool.**

   [StageStream.c:6691](driver/SafeUpload.Minifilter/StageStream.c:6691) initializes writers before starting V26. Writers allocate the nonpaged compact pool at [StageWriters.c:6766](driver/SafeUpload.Minifilter/StageWriters.c:6766). If `PsCreateSystemThread` fails at [StageBoundPublication.c:1386](driver/SafeUpload.Minifilter/StageBoundPublication.c:1386), the unwind at **StageStream.c:6696–6700** omits `SafeUploadStageWritersUninitialize`.

   `StageInitialized` remains false, so the common DriverEntry cleanup calls `SafeUploadStageFree`, which immediately returns at **StageStream.c:7359**. The pool’s only release is **StageWriters.c:6812**.

   **Failure sequence:** pool allocation succeeds → worker creation fails under resource pressure → DriverEntry returns failure → allocated pool survives driver-image removal. Bound readiness being FALSE does not prevent this initialization path. Microsoft requires failed DriverEntry to release acquired resources; the unload callback is not subsequently called. [DriverEntry contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/driverentry-return-values).

   **Required change:** release the initialized writer registry in this failure unwind, preserving reverse initialization order and exactly-once cleanup. Add a failure control for successful pool allocation followed by worker-creation failure.

2. **Major — native replay writes paged buffers while holding `NativeLock`. Activation hold.**

   [StageStream.c:6315](driver/SafeUpload.Minifilter/StageStream.c:6315) and **:6383** allocate replay rows from `POOL_FLAG_PAGED`. Both reach [StageNativeRecords.c:1288](driver/SafeUpload.Minifilter/StageNativeRecords.c:1288), where `NativeAcquire` raises IRQL; **:1297** writes `Rows[*Count]` before releasing the lock.

   **Failure sequence:** native forwarding becomes enabled → facts worker allocates paged rows → a destination page is nonresident → snapshot assignment at DISPATCH faults. Pageable memory must not be accessed under a spin lock. [Microsoft spin-lock rules](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-spin-locks).

   **Required change:** use bounded nonpaged replay storage, or snapshot into nonpaged storage under the lock and copy afterward. This branch is currently unreachable because **StageProtocol.c:1085** requires the bound capability, while **:1733** installs only `Required=0x3f`. It can remain an explicit dormant-boot hold, but must be fixed before native forwarding.

3. **Major — attach limits exclude concurrent capture allocations and handles.**

   [StageStream.c:2962](driver/SafeUpload.Minifilter/StageStream.c:2962) allocates the name snapshot and transaction. **:2982–3006** then acquires object/process/subject references and copies CREATE inputs before checking capacity at **:3016–3058**. EA and security copies can consume **196,764 bytes per callback**, excluding transaction/name storage; their limits are **StagePublic.h:31–32**.

   **Failure sequence:** many CREATE callbacks pause after capture but before quota admission → `StageAttachActiveCount` still excludes them → their aggregate nonpaged memory, token and root-handle ownership exceeds the advertised 128-global/32-instance bound. Later refusal and cleanup prevent a permanent leak, but do not bound this peak.

   **Required change:** reserve capture capacity before the first allocation/reference acquisition. Include captures in progress in admission and teardown accounting, retain the reservation through owned-resource release, and return it exactly once on every failure/cancellation path.

**Q1 — Lifetime and retirement**

Apart from finding 1, I found no additional confirmed double release or use-after-free.

| Owner | Acquisition, holders and retirement |
|---|---|
| Attach transaction and captured inputs | Producer, lookup, worker and cancellation references protect captured subject/process/root/filter/instance/volume/FILE_OBJECT ownership. PASSIVE cleanup releases these before lookup removal; final cancellation destruction is resident and handle-free. **StageStream.c:2810, 2840, 3055, 3065, 4025**. |
| Writer lease / backend | Factory returns one owner, transferred transaction → app `STAGE_HANDLE`; first bound CLEANUP transfers the closed evidence shell to the version. Backend operation references/rundown protect local users. Final `DereferenceBackend` performs destruction; the drained event follows memory and SOP-owner release. [StagePublic.c:577](driver/SafeUpload.Minifilter/StagePublic.c:577), **:597–621**; **StageStream.c:5092–5175**. |
| Metadata carrier and readers | Immutable blob belongs to the lease. Each of four reader slots pins a lease and operation, owns one page, then releases page → operation → lookup → slot on the common exit. Close drains readers/operations before freeing metadata. **StagePublic.c:1949, 2342, 2371–2469**. |
| V23 allocation and seed | Attach owns candidate/backing and predecessor pins. Lost reply transfers the original lease to `AllocationWriterLease`; exact same-channel recovery or mandatory local release disposes that owner. Seed’s two aligned buffers and source-volume pin have local common-exit cleanup. **StageStream.c:2656, 5844, 6941**; **StagePublic.c:2201–2329**. |
| Native records and tombstones | Map plus producer/postoperation references; record owns instance and optional backend reference. Tombstones are embedded bounded tuples. FILE_OBJECT lookup keys are non-owning and removed before CLOSE/address reuse. ACK or mandatory terminal drain converges on `NativeDestroy`. **StageNativeRecords.c:269, 584, 1173, 1318, 1430**. |
| V26 records, permits, reservation and worker | Map/work/control/callback `Uses` protect process/token/security and source ownership. Source holds a stream RPC pin and explicit anchor/security references. Worker’s temporary FILE_OBJECT reference is short-lived. Terminal ACK/local drain converges on `BpDestroy`; drain joins and closes the worker handle. **StageBoundPublication.c:297, 608, 722, 1495**; **StageStream.c:9164, 9228**. |
| Private stream, backing and sections | Version list owns the stream; app objects, shares, cache/section state, RPC and callback/paging rundown delay retirement. Mandatory drain checks actual ownership before lease, backing and instance release. **StageStream.c:6882–6953, 7329–7351**. |
| SOP witness, registry and reservations | Context and bound entries independently reference the witness; it has no owning back-edge. Natural context cleanup sets Ended; explicit deletion/mandatory/instance loss sets Invalid. Prune rechecks H/W/T, section/spill slots, reservations, transactions, Unknown and owner sequence before unlinking. [StageWriters.c:2864](driver/SafeUpload.Minifilter/StageWriters.c:2864), **:3936, 4090–4170**. |
| SOP anchors | List or visiting worker owns handle/object/instance/entry. Mandatory close detaches list owners; the visiting worker cannot reinsert after the fence and closes at end-visit. **StageWriters.c:5817, 5862, 5888, 5964**. |
| Agent delete/recovery receipts | Durable heads retain exact intents/results across service crashes. ACK arming retains receipts; later complete authenticated removal proof retires them. Destination turns/cells are disposed after continuation joins. **StagedBoundPublicationJournal.cs:200, 239**; **StagedDestinationCommitJournal.cs:837, 858**; **MinifilterInterceptor.cs:535–586**. |

Service crash does **not** retire uncertain records. Normal retirement may require durable ACK bookkeeping; mandatory local retirement does not. Timers/scans supply wakeups or fresh checks, never missing lifetime evidence.

**Q2 — Lock order and IRQL**

The relevant nested graph is:

```text
NamespaceResource → stream Resource → StageListLock
NamespaceResource → RegistryLock
RegistryLock → WriterLock
RegistryLock → RenameLoss lock → entry StateLock → SectionLock
RegistryLock → SectionLock
PublicListLock → SectionLock
NativeLock → BpLock → StageAttachLock
NativeLock → protocol-state lock → connection-state lock
BpLock → protocol-state lock → connection-state lock
```

Evidence: **StageStream.c:6914, 9172–9199**; **StageWriters.c:3965, 4123, 5419–5467**; **StagePublic.c:186–198**; **StageNativeRecords.c:269–364**; **StageBoundPublication.c:1076–1257**.

Anchor membership and connection-transition locks are separate boundaries. Connection close drops its transition lock across `FltCloseClientPort` and waits (**Communication.c:1185, 1270, 1301**). Native disposition holds no namespace/native lock or policy epoch while waiting for the service turn (**StageNativeRecords.c:786–923**). Rundowns protect lifetimes; waits occur outside spin locks.

I found no reverse edge or additional PAGE-marked new spin-lock owner. Finding 2 remains a confirmed paged-data violation. Generic posts can run at DISPATCH; synchronized posts at ≤APC; CREATE posts at PASSIVE; draining posts at ≤APC. The resident post paths accommodate these contracts. [Microsoft postoperation contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_post_operation_callback).

**Q3 — Teardown**

After successful initialization, mandatory teardown is service-independent and includes every new owner type. [Filter.c:478](driver/SafeUpload.Minifilter/Filter.c:478) bypasses `PrepareUnload`; **:525–582** closes ports, closes anchors/backends, drains communication, joins workers, performs local retirement, unregisters, then drains callback rundown.

Pre-gate backend publication is covered by close → factory join → rescan (**StagePublic.c:253–260**). Anchor reinsertion and attach/native/V26 admission recheck the permanent fence.

**Completion is not guaranteed:** external mappings and missing native/V26 lifetime evidence can hold local drain indefinitely (**StageStream.c:6933–6935; StageNativeRecords.c:1448–1470; StageBoundPublication.c:1514–1526**). That is the recorded safety hold, not a bounded shutdown promise.

Voluntary preflight vetoes owners without destroying native state; ordinary rollback reopens admission, while quarantined cleanup remains available. Retry becomes usable when ordinary obligations retire; sticky Unknown continues to veto. **StageStream.c:6963–7326; StageWriters.c:5985**.

System shutdown does not call `FilterUnloadCallback`; shutdown/Restart/Fast Startup recovery remains separate qualification. [Microsoft unload lifecycle](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/when-the-filterunloadcallback-routine-is-called).

**Q4 — Fail-closed behavior**

No new bound-path approval escape was found:

- Kernel selector is literally FALSE at **StageProtocol.c:1101–1104**; normal builds exclude staging sources at **SafeUpload.Minifilter.vcxproj:80–93**.
- Production readiness always includes all four native holds; stale completion tickets cannot remove them. [StagedBoundReadiness.cs:47](agente/SafeUpload.Agent.Service/Interception/StagedBoundReadiness.cs:47), **:71–107, 152–170**.
- Construction and post-cleanup version authority remain refused; preserving seed coherence and durable seed completion remain refused. **StagePublic.c:1877, 2193, 2515**; **StageStream.c:2059, 2523**.
- Option-1 export refuses denied/unproved source or recipient authority before hand-back. **StagedSeedProvenance.cs:135–175; StagedTransferPublisher.cs:809–819**.
- Delete supersession uses newer durable Published identity, not pending/blocked allocation. **StagedDestinationCommitJournal.cs:569–573, 615–623**.
- Recovery records Facts/Published/Released and later ACK removal without repeating CREATE/rename/delete. **StagedPublicationNativeJournal.cs:186–201; StagedTransferRecovery.cs:79–112**.

This does not qualify the unchanged legacy V19 behavior.

**Q5 — Bounds**

Native and V26 factories/maps reserve within 1,024 records before record allocation; writer preparation caps factories/backends at 128. Metadata readers cap pages/pins at four. Snapshot anchors/security, descriptor/name copies, metadata blob, seed buffers and journal records have explicit size limits and refusal cleanup. **StageNativeRecords.c:288; StageBoundPublication.c:722; StagePublic.c:1690, 2000, 2342**.

Finding 3 prevents claiming aggregate capture bounds. V26 scratch/Facts limits are per call; kernel-wide port concurrency is not capped by `BpCalls` (**StageBoundPublication.c:858, 890**). The supplied client serializes sends, but that is not kernel quota enforcement.

Witness population follows retained FltMgr contexts; T4’s loaded-context bound remains unqualified. Mandatory waits and bookkeeping retries can be indefinite; none repeatedly authorizes a completed public mutation.

**Q6 — Pre-boot readiness and remaining questions**

Before the first protected boot:

- Fix findings **1 and 3**, verify failure/cancellation accounting, obtain fresh four-profile WDK/PREfast/ApiValidator 0/0 receipts for the revised kernel, and complete coherent review acceptance.
- Preserve both dormant gates. Finding **2** may remain an explicit unreachable hold for that dormant boot; fix it before native forwarding.
- Deliver matched artifacts/hashes and retain unchanged assertions and stop rules.

The authorized Verifier controls must cover initialization failure, service-absent/crashed teardown, pre-gate factories, four readers, worker/callback cancellation, voluntary veto/retry, mapped/cache/image/paging lifetimes, forced instance loss and stable pool/reference accounting. The concrete inventory is **T5-PREBOOT-REVIEW-PACKAGE.md:453–461**; use win10-debug3 only with separate restoration.

**Statically unsettled:** Windows communication-callback delivery ordering around unregister needs the recorded Verifier control. Source retains callback state through unregister and final rundown (**Filter.c:575–582**), consistent with the documented callback-unregistration contract, but source inspection does not prove delivery ordering. [FltUnregisterFilter](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltunregisterfilter).

Descriptor equivalence, coherent seed intervals, effective export/recipient proof and post-cleanup publication authority are acceptable recorded holds for a **dormant** boot. They remain prerequisites to activation and protected-pair qualification.