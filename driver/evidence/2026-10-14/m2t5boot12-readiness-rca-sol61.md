# Readiness root-cause analysis for m2t5boot10-12 — Sol 6.1 xhigh (2026-10-14)

Reviewer: `gpt-6.1-sol`, `reasoning_effort=xhigh`, read-only, web search enabled (Codex session `01a13a79-1441-7381-b6cc-d3837ac99bda`). Verbatim final report; checkout paths shortened.

**Two blockers are supported: a startup retry defect, and writer Unknown whose original loss remains unattributed. FAT hive maintenance is a plausible trigger, not a proven root cause.**

1. **Startup reconcile: proven defect; high-confidence explanation for boot11/12.**  
   The timer DPC sets `StageRetryFired`, but only `StageWorkerPass` consumes it and clears `StageRetryArmed`. Pending reconcile skips that pass; after another Busy reply, timer maintenance sees “already armed” and schedules nothing further. See [StageStream.c:6326](driver/SafeUpload.Minifilter/StageStream.c:6326), **6337–6362**, and [6582–6625](driver/SafeUpload.Minifilter/StageStream.c:6582).

   Agent preparation runs asynchronously and returns `EpochBusy` until completed; successful preparation does not wake the driver. See [StagedNativeStartupRecovery.cs:38](agente/SafeUpload.Agent.Service/Interception/StagedNativeStartupRecovery.cs:38), **153–159**, and [MinifilterInterceptor.cs:889](agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:889). Preparation finishing before either available handshake explains successful boots; slower preparation exposes the defect.

   Boot11 diagnostics **line264**, boot12 **line166** match: `waitingVersions=1`, `passes=0`, `wakeTimer=0`, `timerArms=1`, no versions created. The exact handshake history was not captured, so attribution remains high confidence rather than proven execution. Boot10 lacks those counters. Boot11’s zero Unknown demonstrates that writer loss cannot explain every failed boot.

2. **Writer Unknown: confirmed, but neither volume nor initiating callback is established.**  
   Relevant paths in `StageWriters.c` are:

   | Reason | Paths that can publish it |
   |---|---|
   | ALLOCATION | Reservation/node allocation **1569–1588 → 1735**; failed stream-context/lifetime binding **2696–2700**; failed fallback writer tracking **3655–3657, 3724**. Some failures include unsupported contexts or failed references, so this bit does not prove pool exhaustion. |
   | IDENTITY | Missing instance context/filesystem query **1500–1536**; failed post-CREATE identity query **2667–2669 → 2751**; SOP association/identity collision **2703–2706, 3635–3636**. |
   | CLEANUP | Successful unmatched writer cleanup on a trusted instance **2811–2819, 2853–2858**; context destruction with remaining writer nodes **2881–2892**. |

   [Reservation paths](driver/SafeUpload.Minifilter/StageWriters.c:1500), [post-CREATE paths](driver/SafeUpload.Minifilter/StageWriters.c:2666), [cleanup paths](driver/SafeUpload.Minifilter/StageWriters.c:2795).

   **Cross-volume propagation exists in source.** `StageRegistryUnknownSopCount` counts every marker, regardless of protected volume, and feeds aggregate admission at **7837**. `StageRegistryMarkUnknownAt` sets global Unknown when `!instanceMarked`, even with a supplied instance. Global loss then obstructs C: activation; agent admission degrades on either aggregate Unknown field. See [StageWriters.c:3771](driver/SafeUpload.Minifilter/StageWriters.c:3771), [998](driver/SafeUpload.Minifilter/StageWriters.c:998), **6052–6055**, and [AdmissionCoverage.cs:232](agente/SafeUpload.Agent.Minifilter/AdmissionCoverage.cs:232).

   `registryInstanceUnknown=1` proves an instance was marked at least once; it does not identify a currently mounted volume. Aggregate `0x46` combines instance/global/deferred losses and does not identify one event. An instance loss, possibly accompanied by global escalation, fits; a solely SOP-marker explanation is insufficient.

   **Ordinary FAT/BCD activity is excluded:** reservation requires fixed NTFS at **1539**; unmatched cleanup requires trusted status, while the canary marks FAT unsupported at [StageAdmission.c:1589–1606](driver/SafeUpload.Minifilter/StageAdmission.c:1589). An earlier lookup failure can still escalate globally, or an unnamed **NTFS** volume can contribute markers. Neither occurred demonstrably in these receipts.

3. **Hive maintenance: plausible workload/timing trigger; medium confidence.**  
   Event16 records access-bit clearing and dirty pages. Original reverse-engineering research identifies a default seven-day age check, making time-triggered maintenance on a restored base plausible. There is no successful-boot System-log comparison or hive timestamp evidence proving it began at 09:37. [Event16 research](https://research.nasbench.dev/research/etw/microsoft-windows-kernel-general).

   Expected consequences include hive/log writes and flushing; mapped/cache-backed writes can outlive the original handle cleanup. SafeUpload tracks paging writes through exact SOP/W bookkeeping rather than treating each write as a new writer handle ([StageStream.c:8735](driver/SafeUpload.Minifilter/StageStream.c:8735)). Windows also periodically flushes registry changes. [Microsoft RegFlushKey documentation](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regflushkey). Event16 itself does not reveal the actual callback sequence.

4. **Epoch pinning: possible, but unproven here and separate from reconcile.**  
   Mutating CREATE/SET_INFORMATION/SET_SECURITY/FSCTL retain policy tokens through lower completion; an oplock acknowledgment wait can therefore pin policy drain. Raw WRITE/FLUSH_BUFFERS are excluded from that classifier. See [StageStream.c:8459](driver/SafeUpload.Minifilter/StageStream.c:8459), **9013–9019, 9184**. Windows imposes no oplock acknowledgment timeout. [Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/breaking-oplocks).

   `SafeUploadStageReconcileV20` itself performs no policy drain. Its `EpochBusy` concerns service preparation/durable epoch state, not proof of an outstanding policy token. Thus hive flush or an oplock pin is unnecessary to explain boot11/12.

**Proposed fix and verification:**

- **Repair retry bookkeeping first:** consume fired timers on every worker wake, including reconcile, preserving owed stream retry/sweep work at **StageStream.c:6357, 6581**. Continue existing exchange retries until an authenticated current-channel receipt arrives. This changes no Unknown state.
- **Scope correction:** at **StageWriters.c:3771/7837**, count loss only where stable volume/lifetime evidence cannot exclude the current/pending protected union. Retain sticky markers. At **960–1003**, preserve identifiable instance loss rather than widening solely because its context disappeared—but retain global effects when identity is genuinely unresolved. SOP `InstanceIdentity` is non-owning (**271**); pointer equality is insufficient. Never exclude unprotected filenames on C:, which can acquire protected aliases.
- **Tests:** delay startup preparation beyond several Busy replies, then accept without reconnect or unrelated wakes; verify idle timer cessation, disconnect/stale replies and drain replay. Inject loss on another volume, C: and an unresolved instance; require isolation only for proven disjoint volumes and persistent degradation wherever loss applies. Then perform the required reviewed WDK/Verifier qualification separately.

A confirming run should capture **full admission receipts** (`WriterGlobalUnknown`, `WriterEntriesUnknown`), every instance’s volume/GUID/filesystem/trust and first Unknown reason/site—already exposed at [StageAdmission.c:212–217](driver/SafeUpload.Minifilter/StageAdmission.c:212)—plus per-instance SOP marker counts, first global-loss origin/status, reconcile attempts/results, timer armed/fired state, preparation completion and outstanding epoch operations, timestamped monotonically.

Fail-closed behavior after applicable lifetime loss is correct. The proven availability defect is stalled handshake retry; out-of-scope loss propagation is a separate source risk whose occurrence here needs attribution.

References use HEAD/boot11 lines; later boot12 `StageStream.c` lines are five lower. Sol 6.1 xhigh independently checked the reconcile and scoping conclusions. No files changed, builds run or VMs booted.