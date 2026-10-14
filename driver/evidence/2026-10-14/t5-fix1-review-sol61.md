# T5 focused re-review of c7518c7a — Sol 6.1 xhigh (2026-10-14)

Reviewer: `gpt-6.1-sol`, `reasoning_effort=xhigh`, read-only, web search enabled. Input: commit `c7518c7a` (fixes for the [pre-boot review](../2026-10-13/t5-preboot-review-sol61.md)). Verbatim final report; checkout paths shortened.

**Verdict: REJECT** for the first dormant Verifier boot of `c7518c7a` on `win10-debug3`. The Sol 6.1/xhigh review found a remaining IRQL violation reachable during dormant startup.

1. **Blocker — replay identity still writes paged memory under `NativeLock`.**

   [StageNativeRecords.c:1253](driver/SafeUpload.Minifilter/StageNativeRecords.c:1253) acquires the spin lock, then writes caller outputs at lines 1254–1255. Both replay controls pass `DriverInstanceId` inside paged work buffers: [StageNativeWire.c:140](driver/SafeUpload.Minifilter/StageNativeWire.c:140)–142 and 221–223.

   **Failure sequence:** feature-agent startup recovery requests replay → paged work allocation succeeds → identity retrieval raises IRQL → assignment touches a nonresident or Verifier-invalidated page. Dormancy does not prevent this: [Communication.c:2061](driver/SafeUpload.Minifilter/Communication.c:2061)–2070 dispatches replay without the bound gate, and [MinifilterInterceptor.cs:256](agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:256)–281 starts recovery before bound readiness.

   **Required change:** snapshot identity and boot sequence into resident locals under the lock; assign outputs afterward. Add coverage for paged identity outputs.

2. **Major — three paged-input violations remain in facts processing. Activation hold.**

   Paged replay rows from **StageStream.c:6396** reach disposition confirmation at **:6418** and open confirmation at **:6431**. Their inputs are read under `NativeLock` at [StageNativeRecords.c:747](driver/SafeUpload.Minifilter/StageNativeRecords.c:747)–750 and **:1380**. Paged rows allocated at **StageStream.c:6464** reach acknowledgment at **:6495**, with locked reads at **StageNativeRecords.c:1340**.

   **Failure sequence:** forwarding becomes enabled → worker obtains paged rows → confirmation/ACK raises IRQL → comparison reads nonresident input.

   **Required change:** use nonpaged worker rows or capture bounded resident arguments before locking. The forwarding checks at **StageStream.c:6394–6395 / 6462–6463** keep these paths dormant, so these are activation conditions rather than another dormant-boot blocker.

3. **Major — the new allocation failure can strand later facts pages. Introduced defect; activation hold.**

   [StageNativeRecords.c:1292](driver/SafeUpload.Minifilter/StageNativeRecords.c:1292)–1293 adds a per-page allocation failure. Both workers mark the revision attempted after page zero, then abandon a failed later page: [StageStream.c:6402](driver/SafeUpload.Minifilter/StageStream.c:6402)–6406 and **:6471–6477**.

   **Failure sequence:** more than 16 records → page one produces no map change → page-two allocation fails → subsequent passes skip the unchanged attempted revision → later facts remain unsent.

   **Required change:** preserve incomplete traversal or reset its attempt marker and arrange a resource-failure retry. Add a multi-page allocation-failure control.

4. **Low — unused detach helper can report a false zero during conversion.**

   [StageStream.c:6912](driver/SafeUpload.Minifilter/StageStream.c:6912) reads active and capture counters separately. It can read active=0 before conversion and capture=0 afterward, across **:3132–3135**.

   **Required change:** sample attach participation under `StageAttachLock`. There are no current callers, so this does not independently block boot. Voluntary unload avoids the race by closing admission under that lock at **:7116** before reading counts at **:7177–7178**.

The original fixes otherwise trace as follows:

- **Finding 1 resolved.** [StageStream.c:6777](driver/SafeUpload.Minifilter/StageStream.c:6777)–6791 now unwinds acquired resources in reverse order exactly once. Earlier public/protocol/event initialization acquires no dynamic ownership. `StageInitialized=FALSE` prevents duplicate common cleanup. Successful initialization followed by later DriverEntry failure reaches worker/communication cleanup and `StageFree` through [Filter.c:353](driver/SafeUpload.Minifilter/Filter.c:353)–384. No additional initialization leak found.
- **Finding 2’s specific row write resolved.** Nonpaged snapshots are filled under the lock and copied afterward at **StageNativeRecords.c:1292–1313**. Ordering, partial-page completion, revision checks and existing failure outputs remain intact for the two workers, two replay controls and name-observation control. **Statuses are not completely unchanged:** allocation failure adds `STATUS_INSUFFICIENT_RESOURCES` with zero outputs and can precede `STATUS_DEVICE_NOT_READY`. All callers reject failure; finding 3 identifies the worker retry consequence.
- **Finding 3 resolved in reachable lifecycle paths.** [StageStream.c:2955](driver/SafeUpload.Minifilter/StageStream.c:2955)–2982 reserves global/per-instance capacity before capture. Every preconversion exit releases resources before returning its slot; conversion is within one lock hold; postconversion failures release active accounting. Instance presence, worker drain and voluntary veto include captures at **:3194–3195, :6877, :7178**. Event transitions share the lock, and stopping/teardown prevents late conversion. No new lock edge, double release, UAF or source-demonstrated instance-teardown deadlock found; the existing unbounded lifetime holds remain.

**Tests:** 14/14 source controls pass here; all three new controls fail against in-memory `a27defd8` sources. They guard the original syntax changes, not the full properties. [teardown-participation-selfcheck.py:193](driver/scripts/t5/teardown-participation-selfcheck.py:193)–228 omits native/fence unwind checks, other paged callers, reservation arithmetic and worker-drain semantics. In-memory mutations removing native/fence cleanup, reintroducing a paged row write with alternate spelling, and omitting the capture decrement all still passed. Strengthen those controls alongside the corrections.

Read-only throughout; no files changed, builds or VMs. After correction, fresh four-profile WDK/PREfast/ApiValidator receipts and matched artifact hashes remain required. The previously accepted security/seed/export/version-authority holds remain valid for dormancy; they do not cover finding 1.