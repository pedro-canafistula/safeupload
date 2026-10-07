# SafeUpload reclaim churn analysis

Snapshot: `a53d01bb` (read only). No repository file was changed. The requested `Section.c` does not exist in this snapshot; section acquire/release accounting is in `StageWriters.c`, dispatched from `StageStream.c`.

## Finding

**Most likely cause: the lifetime recheck is global and unconditional for every successful cleanup and every close, and a recheck restarts the registry cursor.** `StagePostOperationCore` calls `SafeUploadStageWritersQueueLifetimeRecheck` after every successful cleanup at `StageStream.c:3706-3713`; `StageDispatchCore` calls it for every close at `StageStream.c:3374-3379`. Neither call passes the `FILE_OBJECT`, SOP, or instance. In the current implementation, `StageWriters.c:5857-5863` suppresses only a callback running on the exact reclaim worker thread; otherwise it calls `SafeUploadStageWritersQueueRecheck`, which sets `RegistryReclaimResetCursor` and calls `StageRegistryQueueReclaim` (`StageWriters.c:5843-5849`). A cleanup/close on an unrelated thread or unrelated file therefore requests a full global sweep even if no registry state changed.

That explains the hot-loop shape without making Activating itself a timer: the worker includes Activating entries even while `H` is nonzero (`StageWriters.c:5727-5740`), and `StageRegistryActivationProcess` performs link-name classification / identity work before its `H/W/T` early return (`StageWriters.c:5356-5359`, `5394-5395`, `5441-5446`). Each unrelated lifetime event can consequently cause the same below-instance work for the unchanged Activating target. When `H/W/C/T=0` but NTFS retains a cache pointer, `FltFlushBuffers2` is attempted and `CacheRetained` exits without marking the target scan unfinished (`StageWriters.c:5455-5472`). A later global lifetime event retries that work. The pass coalescer limits simultaneous work to one worker plus a coalesced rescan, but sustained cleanup/close traffic can keep that rescan bit set and repeatedly restart the cursor.

The same callbacks can be caused by the reclaim body's own identity/parent opens if the lifecycle callback is delivered on a different thread: both opens request only `FILE_READ_ATTRIBUTES | SYNCHRONIZE` (`StageWriters.c:4181-4192`, `4263-4270`), but the generic cleanup/close recheck does not inspect those access bits. The `d0f92f67` thread identity guard prevents the same-thread case only. The retained source and runtime readouts do not show whether the remaining event stream came from off-thread probe callbacks or unrelated filesystem activity; there are no per-callsite queue counters or callback-thread receipts. This is the main uncertainty in attributing the 2.5–3k/s rate to one producer.

### Evidence

- `goal-cache2-runtime-readout.json`: `goald1` ends with 296,507 reclaim passes, 231 entries, 2,150 pruned, zero registry/instance Unknown and zero capacity failures. Writer counters include 3,043 post-create runs, 1,984 counted / 1,744 released writer objects, zero unmatched cleanups and zero untracked creates. Those counters do not count ordinary closes or reclaim queue reasons.
- `goal-cache3-and-cache4-runtime-readout.json`: `goalc1` ends with 285,686 passes, 233 entries, 2,143 pruned, zero registry/instance Unknown and zero capacity failures. The exact target is Activating with `H/W/C/T=0`, `S=NO`, `unknownReasons=0`, and `classificationStep=CacheRetained` (step 11). This is direct evidence that the observed failed promotion reached the cache-retained exit, which itself does not request a continuation.
- `goal-reader-runtime-readout.json`: `goalrecl101` has 226,211 passes and the exact target still Activating with `H/W/C/T=0`, `S=NO`, no Unknown, `CacheRetained`, and an empty promotion trace. `goalreader101` later records the native CAS `ACTIVATING -> PROTECTED`, but its global reclaim count is 398,614. That shows the counter is global and can continue growing after the target promotes; it does not identify the queuing producer.
- `driver/MVP-PLAN.md:1696-1712` records the d0f92f67 repair contract and explicitly says runtime comparison is required. At `:1776-1778`, the unchanged-observer `goalrecl101` result says thread-local lifetime suppression did not eliminate churn. At `:1850-1851`, the reader readout is described as retaining hash-bound result/counter evidence.
- The plan also records boot policy finalization before the service readiness loop and no `POLICY_PENDING` flag for goald1 (`MVP-PLAN.md:1717-1724`). The service's `PublishAdmissionCoverageLoopAsync` polls every 500 ms (`agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:719-796`), but it queries `GetAdmissionCoverageStatus`; the kernel coverage path reads status and calls `SafeUploadStageWritersAdmissionCoverage` (`Communication.c:1096-1117`, `StageAdmission.c:687-690`) and contains no reclaim queue call. The service readiness poll is therefore not itself the source shown by this tree.
- Inspector status is also read-only for this target: `SafeUploadStageWritersActivatingTargetStatus` only copies the resident entry (`StageWriters.c:6694-6728`); registry evaluate returns a resident pending-entry snapshot before an identity open (`StageWriters.c:7343-7350`, `7415-7422`). Repeated status queries do not queue rechecks in these paths.

### What is and is not established

The source proves the global cleanup/close wakeup exists and is not scoped to a state transition or a registry identity. It also proves that Activating with a live `H` is not independently requeued merely because it is not Free. The evidence does **not** prove which cleanup/close producer dominated the measured interval. The precise diagnosis is therefore: **high confidence in the uncontrolled global lifetime wakeup as the source-level defect; medium confidence that it alone accounts for the measured rate, because the retained evidence has no queue-source or cleanup/close-rate counters.**

A second, conditional self-continuation issue exists in the unknown-SOP marker scan: `StageRegistryUnknownSopMarkersQuiescent` resets its local work budget to 32 for each call, scans the slot array from its first chunk, and has no saved slot cursor (`StageWriters.c:3538-3582`). When more than 32 unknown markers exist, it sets `WorkRemaining` after budget exhaustion; activation sets `ScopeScanPending` (`:5476-5479`), and the worker treats that as unfinished and requeues (`:5771-5775`, `5811`). If the first 32 markers stay live, the same first set can be opened again on every pass and later slots can be starved. The runtime readouts do not report unknown-SOP slot count. It is not the likely cause of the cache3/cache4 observations because `CacheRetained` returns before this marker scan; that classification step is evidence against it for those captures. It remains a separate conditional polling risk, not proven in these runs.

## Reclaim/recheck call-site inventory

`StageRegistryQueueReclaim` is the coalescing scheduler (`StageWriters.c:5820-5841`). `STAGE_RECLAIM_QUEUED` means one worker queued/running; `STAGE_RECLAIM_RESCAN` coalesces further requests. `StageRegistryReclaimWorkerFinish` clears the rescan bit when it hands off (`:5670-5689`); the CAS does not unconditionally re-arm itself. The worker internally sets a rescan only for a full bounded candidate batch or explicitly unfinished scan work (`:5771-5776`, `5802-5812`).

| Call site | Trigger | Can repeat without target state changing? |
|---|---|---|
| `StageRegistryGetOrInsert`, `StageWriters.c:1173` | Capacity failure during a create bind. | Only on repeated create/capacity failures; not caused by an Activating pass. Runtime capacity-failure counters are zero. |
| `StageRegistryGetOrInsert`, `:1205-1213` | Entry/instance reaches 3/4 capacity threshold. | Repeats on inserts while pressure remains; independent of a reclaim pass. Evidence counts are far below configured capacity. |
| `SafeUploadStageWritersReserveCreate`, `:1581-1594` | Compact-slot/capacity reservation failure; marks capacity Unknown before scheduling. | Event/failure driven, not a poll. Readouts show no capacity failures. |
| `StageRegistryCompleteDirectoryRename`, `:1920-1942`, `2064-2067` | Completion changed or may have changed an affected name range; resume alias classification. | Can schedule for a real rename completion; no periodic or per-pass trigger. |
| `SafeUploadStageWritersCompleteRename`, `:2171-2245` | Successful rename/link updates name/version and begins an alias probe, or returns a pending recheck. | Completion-driven; alias pending is cleared by versioned resolution (`:5105-5148`) or retained fail-closed on uncertainty. Not a steady poll for a stable name. |
| `SafeUploadStageWritersOnCleanup`, `:2562-2572` | Tracked writer cleanup reaching `H=0` while Activating; or the unmatched/Unknown-writer branch. | The `H=0` branch is a real state transition. The unknown branch may queue both here and through `StageRegistryUnknownWriterEnd` (`:3435`), but only on a cleanup event. |
| `StageRegistryEndMutatingIoEntry`, `:3051-3072` | Tracked `W` transitions to zero. | Each real I/O completion may queue; an unchanged holder alone does not call it repeatedly. Correct wakeup for writer completion. |
| `StageRegistryEndMutatingIoMarker`, `:3076-3095` | Spilled-mutating-I/O count transitions to zero. | Transition-driven; not a poll. |
| `StageRegistryUnknownWriterEnd`, `:3417-3435` | Exact Unknown SOP marker's unknown-writer count transitions to zero. | Transition-driven; not a poll. It preserves marker/Unknown retirement rules. |
| `StageStream.c:3374-3379` -> `SafeUploadStageWritersQueueLifetimeRecheck`, `:5857-5863` | **Every close**, regardless of file identity or access. | **Yes.** Any other-thread close globally resets the cursor and can request a sweep even with no entry change. Own-thread reclaim I/O is the only case suppressed today. Primary suspect. |
| `StageStream.c:3706-3713` -> same lifetime helper | **Every successful cleanup**, after `OnCleanup`, including cases where `OnCleanup` immediately returns for non-write/delete handles. | **Yes.** Same global, state-independent behavior as close. Primary suspect. |
| `SafeUploadStageWritersQueueRecheck`, `StageWriters.c:5843-5849` | Shared recheck helper used by `EndMutatingIoEntry`, marker completion, unknown-writer completion, and lifetime notifications. | It always sets `RegistryReclaimResetCursor=1`; itself is not an independent producer. Any repeated caller can keep restarting the global sweep. |
| `StageRegistryReclaimWorkerFinish`, `:5674-5681` | Retry only if work-item queueing fails while a rescan bit is set. | Self-retries only on queue failure. No evidence of queue-allocation failure is retained. |
| `SafeUploadStageSectionReleaseComplete`, `:6124-6132` | Successful removal of a section slot: every writable release queues; an Activating read-only release queues only off the reclaim thread. A writable release also queues if the release record was not removed. | Genuine section-release event. Same-thread read-only self-release is suppressed by d0f92f67; writable release deliberately remains a wakeup. No evidence says this fires every pass. |
| `SafeUploadStageSectionAcquireFailed`, `:6146-6155` | Failed writable section acquire removes its in-flight slot. | One failed acquire event; not a poll. |
| `SafeUploadStageWritersApplyPendingScope`, `:6410-6463` | Policy apply begins alias probes for existing entries and schedules the PASSIVE worker. | One policy-apply pass, not readiness polling. Failure stays fail-closed (`:6463-6479`). |
| `SafeUploadStageWritersReconcileCurrentScope`, `:6484-6539` | Current-policy finalization begins alias probes and schedules classification. | Policy-finalization event driven; no call from the coverage/readiness query path. |
| `StageRegistryEnlistTransaction`, `:7037-7043` | Transaction enlist failure while an alias probe is pending; marks Unknown and requests worker processing. | Failure-driven and fail-closed, not a poll. |
| `SafeUploadStageTransactionNotification`, `:7049-7090` | Commit/rollback removes transaction `T`; an Activating or alias-pending entry needs the committed view rechecked. | Terminal transaction event; not a poll. |
| `StageRegistryReclaimWorker`, `:5724-5752`, `5771-5812` | Internal bounded continuation when 128 candidates were reached or link/marker scan work remains. | Batch continuation is finite as the cursor advances. A stable Activating entry by itself does not set `unfinishedScan`. The conditional unknown-SOP marker cursor issue described above can make this path poll if its preconditions hold. |

There are no reclaim queue calls in `StageAdmission.c`. It computes and returns coverage. `Communication.c` status handlers likewise do not call `StageRegistryQueueReclaim`.

## Minimal proposed change

Make generic cleanup/close wakeups exact-SOP and data-handle scoped. Keep the direct H/W/C/T/transaction/rename/capacity wakeups unchanged. The reclaim probes use attribute-only opens, so filtering on the `FILE_OBJECT` data access flags prevents those opens' cleanup/close from rearming a pass even if a callback runs on a different thread. Looking up the same SOP preserves rechecks needed to prune a real entry, retry an Activating cache barrier after a real reader/writer closes, and retry an Unknown SOP marker. The patch changes scheduling only: it does not relax promotion predicates, clear Unknown, remove bounded work budgets, or bypass rundown/teardown handling.

```diff
--- a/driver/SafeUpload.Minifilter/Filter.h
+++ b/driver/SafeUpload.Minifilter/Filter.h
@@ -705,5 +705,6 @@
 NTSTATUS SafeUploadPolicyAdmissionEpochStatus(_Out_ PSAFEUPLOAD_ADMISSION_EPOCH_STATUS Status);
 VOID SafeUploadPolicyAdmissionForceNextTimeout(VOID);
 VOID SafeUploadStageWritersQueueRecheck(VOID);
-VOID SafeUploadStageWritersQueueLifetimeRecheck(VOID);
+VOID SafeUploadStageWritersQueueLifetimeRecheck(_In_opt_ PFLT_INSTANCE Instance,
+    _In_opt_ PFILE_OBJECT FileObject);
 BOOLEAN SafeUploadPolicyEntryIsNewlyScoped(_In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
--- a/driver/SafeUpload.Minifilter/StageStream.c
+++ b/driver/SafeUpload.Minifilter/StageStream.c
@@ -3375,5 +3375,5 @@
         StageTraceFileLifetime(Data, Objects, SAFEUPLOAD_ADMISSION_TRACE_EVENT_FILE_CLOSE);
 #if SAFEUPLOAD_STAGING_PROTOTYPE
-        SafeUploadStageWritersQueueLifetimeRecheck();
+        SafeUploadStageWritersQueueLifetimeRecheck(Objects->Instance, Objects->FileObject);
 #endif
         break;
@@ -3710,4 +3710,4 @@
             Objects->FileObject != NULL ? Objects->FileObject->SectionObjectPointer : NULL);
         } else if (NT_SUCCESS(Data->IoStatus.Status)) {
             SafeUploadStageWritersOnCleanup(Data, Objects);
-            SafeUploadStageWritersQueueLifetimeRecheck();
+            SafeUploadStageWritersQueueLifetimeRecheck(Objects->Instance, Objects->FileObject);
         }
--- a/driver/SafeUpload.Minifilter/StageWriters.c
+++ b/driver/SafeUpload.Minifilter/StageWriters.c
@@ -331,4 +331,6 @@
 #define StageRegistryMarkEntryUnknown(Entry, Reason) \
     StageRegistryMarkEntryUnknownAt((Entry), (Reason), (ULONG)__LINE__)
 static BOOLEAN StageRegistryQueueReclaim(VOID);
+static BOOLEAN StageRegistrySopNeedsLifetimeRecheck(_In_opt_ PFLT_INSTANCE Instance,
+    _In_opt_ PVOID SectionObjectPointer);
 static KSPIN_LOCK SectionLock;
@@ -5857,7 +5859,14 @@
-VOID SafeUploadStageWritersQueueLifetimeRecheck(VOID)
+_IRQL_requires_max_(APC_LEVEL)
+VOID SafeUploadStageWritersQueueLifetimeRecheck(_In_opt_ PFLT_INSTANCE Instance,
+    _In_opt_ PFILE_OBJECT FileObject)
 {
-    /* The reclaim body's own attribute-only probes cannot release an external
-     * holder. Rechecking their cleanup/close would perpetually reschedule it.
-     * All ledger updates and their counted-writer wakeups run independently. */
-    if (!StageRegistryIsReclaimIoThread()) SafeUploadStageWritersQueueRecheck();
+    /* Recheck only a real data-access lifetime on a tracked SOP. The reclaim
+     * probes request FILE_READ_ATTRIBUTES only; unrelated closes cannot restart
+     * the global registry sweep. */
+    if (StageRegistryIsReclaimIoThread() || Instance == NULL || FileObject == NULL ||
+        (!FileObject->ReadAccess && !FileObject->WriteAccess && !FileObject->DeleteAccess))
+        return;
+    if (StageRegistrySopNeedsLifetimeRecheck(Instance,
+            FileObject->SectionObjectPointer))
+        SafeUploadStageWritersQueueRecheck();
 }
@@ -6247,4 +6256,26 @@
     unknownMarker = found && slot != NULL && slot->Unknown &&
         slot->InstanceIdentity == (PVOID)Instance;
     StageReleaseSpinLock(&SectionLock, irql);
     return unknownMarker;
 }
+
+_IRQL_requires_max_(APC_LEVEL)
+static BOOLEAN StageRegistrySopNeedsLifetimeRecheck(_In_opt_ PFLT_INSTANCE Instance,
+    _In_opt_ PVOID SectionObjectPointer)
+{
+    PSTAGE_REGISTRY_ENTRY entry;
+    BOOLEAN relevant = FALSE;
+
+    if (Instance == NULL || SectionObjectPointer == NULL) return FALSE;
+    entry = StageRegistryReferenceSop(SectionObjectPointer);
+    if (entry != NULL) {
+        FltAcquirePushLockShared(&RegistryLock);
+        relevant = entry->Listed && !entry->Retired && entry->Instance == Instance &&
+            InterlockedCompareExchangePointer(
+                (PVOID volatile *)&entry->SectionObjectPointer, NULL, NULL) ==
+                    SectionObjectPointer;
+        FltReleasePushLock(&RegistryLock);
+        StageRegistryDereference(entry);
+    }
+    return relevant || StageRegistryUnknownSopForInstance(Instance,
+        SectionObjectPointer);
+}
```


The access-bit filter should be confirmed on the supported Windows build for `FltCreateFileEx2(FILE_READ_ATTRIBUTES | SYNCHRONIZE)`. The source request is attribute-only, but the retained runtime artifacts do not record `FILE_OBJECT.ReadAccess/WriteAccess/DeleteAccess` for those opens. If this build reports any of those bits for the probe, use an explicit reclaim-probe file-object tag instead of weakening the exact-SOP filter.

## Risks and confirmation

- A legitimate data-access close on an Activating/registered SOP still requests a pass; this preserves the needed retry after the final holder or cached reader closes. A valid read-only handle release also remains visible. A global Unknown SOP marker is checked separately.
- A cleanup/close on a file absent from both the bound SOP map and the Unknown marker table will no longer sweep the registry. That file cannot justify clearing Unknown or promote an entry; a lost-tracking path must remain Unknown under existing logic.
- The scan budget and `STAGE_RECLAIM_RESCAN` handoff are unchanged. The conditional no-cursor unknown-SOP marker loop remains a separate possible churn source and should be measured if marker slots are present; this patch does not alter marker retirement.
- The decisive runtime comparison is the **delta of `WriterState.registryReclaimPasses`** over the same ~90-second holder interval, sampled before and after. With no genuine target-SOP lifetime transitions during the held interval, the delta should fall from hundreds of thousands to near zero (allowing initial/policy and genuine state-transition passes). Promotion must still be checked after release with the existing exact-ID `ACTIVATING -> PROTECTED` CAS and unchanged H/W/C/T/S/Unknown predicates. Also capture `SectionInFlightNow`, `RegistryUnknownReasons`, `RegistryCapacityFailures`, and the target classification step to ensure the scheduling change did not mask a live section, Unknown marker, cache-retained result, or teardown state.
