# T4 design note: stage-version lifetime and an event-driven stage worker

Status: design, before implementation. Plan task: `POST-MVP-PLAN.md` T4. Owner decision 2026-10-10: the stage worker may arm a
one-shot retry timer only while a version waits on something Windows does not signal; everything else is event-driven.

## 1. Today

Per staged save the driver allocates, all nonpaged and never freed before unload:

- a `STAGE_STREAM` (about 3.3 KB: two 512-character name buffers, two ERESOURCEs, a byte-range lock, the backing handle and file object);
- a `STAGE_VIEW` for a new (owner, name) pair (about 1.2 KB, with a reference on the owner's `EPROCESS`);
- a `STAGE_OLD_NAME` per rename (the name plus a pointer to the renamed version);
- on disk, the stage file. An approved stage is never deleted; only a blocked or justified stage is deleted after its hand-back.

`StageStreamCount` is never decremented. `STAGE_LIMIT` (128) therefore caps every version created since boot: the 129th staged create
fails with `STATUS_INSUFFICIENT_RESOURCES`. Views and `EPROCESS` references also accumulate, so exited owners stay as zombie processes.

`StageWorker` wakes every 250 ms and walks every stream: it finishes renames whose commit was not acknowledged, retires a sealed version
whose stage file the service deleted (query `DeletePending` on the backing), and drains and seals an unsealed version with no handles,
sections or file objects.

## 2. Who references a version

| Reference | Held by | Protected by |
| --- | --- | --- |
| `view->Current` of an attached view | name lookups (`StageFindView`, `StageFindId`), directory overlays, rename | NamespaceResource |
| upper file objects (`FsContext`, `FsContext2` -> `STAGE_HANDLE`) | create success to `IRP_MJ_CLOSE`, counted in `FileObjects` | `FileObjects`; sections and cache maps hold file objects |
| paging I/O post-operations | in-flight paging reads and writes | `PagingRundown` (waited before the backing closes) |
| `STAGE_OLD_NAME.Version` | `StageHiddenStream` (hidden-name lookup, `TOMBSTONE_CREATE` allocation) | NamespaceResource |
| `StageStreams` list | `StageStreamForObject`, worker, unload | `StageListLock` |
| the service | the stage file, by transfer ID (the stage basename is the transfer GUID in "N" form) | journal, not the driver |

## 3. New lifetime rules

**Tombstones no longer point at versions.** `STAGE_OLD_NAME` becomes a `STAGE_TOMBSTONE` in one global, bounded table: owner
(`EPROCESS`, referenced), owner PID, name, sequence, and the renamed version's transfer ID (32 characters). This is the plan's "small
tombstone record" (the destination generation is the service's; the driver keeps the transfer ID that names it). `StageHiddenStream`
returns the tombstone; the create passes its transfer ID to `SafeUploadStageAllocate` (which reads only the 32 characters of the basename).
- A rename that leaves name N adds or replaces the owner's tombstone for N (one per owner and name, the newest wins, as the lookup already
  does), but only while a public file has the name N. A name that exists only privately (an application's temporary file) needs no
  record: nothing public is hidden. Otherwise every unique temporary name of a long-running editor would occupy the table until the
  process exits (Luna review).
- A view that takes name N (create or rename destination) removes the owner's tombstone for N. Pre-T4 an attached view shadowed the
  tombstone forever. Post-T4 the view can be detached, so the stale tombstone would hide the owner's own published file again.
- The table is freed per owner when the owner exits (section 5) and at unload.
- Cap: `STAGE_TOMBSTONE_LIMIT` 1024. A rename that would exceed it fails with `STATUS_INSUFFICIENT_RESOURCES` and is counted (fails
  closed: the rename does not happen).

**A version is released** (backing closed, stream freed, slot returned) by the worker, under NamespaceResource, when all hold:
`Sealed`; `RenameExchange == NULL`; `FileObjects == 0`; `ShareAccess.OpenCount == 0`; no `SharedCacheMap`, `DataSectionObject` or
`ImageSectionObject`; and it is no longer reachable by name: superseded (`view->Current != stream`) or its view is `Detached`.
The final check and the unlink run under `StageListLock` (section 4); `StageStreamCount--` and `view->Streams--` follow under
NamespaceResource. The teardown runs after the worker drops NamespaceResource, because nothing can reach the stream any more:
`FsRtlTeardownPerStreamContexts` (other filters' stream-context cleanup callbacks), wait `PagingRundown`, delete the stage file if
the service disposed of it as approved (section 3.1), then `StageFreeStream`. None of these runs under the lock that every staged
create takes.

An unsealed version is never released: it is drained and sealed first, as today, even if its view was detached by a rename replace or
an owner exit. A superseded version is released as soon as it is unreferenced, even before the service has inspected it. The service
reads the stage file by path, and the private-namespace gate refuses every non-service writer under `\ProgramData\SafeUpload\staging\`,
so closing the driver's read-only backing (which denied write sharing) opens no write window.

**A view is detached** (name lookups skip it; held file objects keep their version) when:
- (today) a rename replaced it;
- (today) its version was retired because the service deleted the stage;
- (new) the service disposed of its current version and that version has `FileObjects == 0`;
- (new) its owner exited.

**A view is freed** when it is detached and no allocated stream points to it (`view->Streams == 0`). This drops its `EPROCESS` reference.

**The cap** (`STAGE_LIMIT` 128) counts allocated versions only. In steady state that is one or two per open document, plus versions
waiting for inspection or inside a block's hand-back window.

### 3.1 Disposal: new control message `SAFEUPLOAD_CONTROL_STAGE_DISPOSE`

The service tells the driver when it no longer needs a version:
- after an ordinary approval reaches `Released`, with outcome `Released`;
- after a blocked or justified stage's cleanup has deleted the stage file, with outcome `CleanedUp`.

Body: `SAFEUPLOAD_CONTROL` header, `TransferId` (GUID), `Outcome` (1 or 2), `CommittedRenames`. Reply: `Held` (0 or 1). The message is
accepted only from the agent service (the `STAGE_PUBLICATION` SID check).

`CommittedRenames` is the number of committed renames of the transfer in the journal state the disposal describes (one
`NamespaceTombstone` per commit). The driver counts acknowledged commits per version. A committed rename of a sealed version sends it
back to `Sealed` in the journal for a new inspection, so a disposal sent for the earlier approval must not apply (Luna review):
- If the count differs, the disposal is stale: ignored, reply `Held = 1`, so the service does not delete the stage.
- If a rename exchange is in flight, the disposal is deferred. It applies if the rename aborts, which changes nothing in the
  journal. It is dropped if the rename commits.
- An acknowledged commit clears an earlier disposal.

With `Held = 0` the service reads the journal entry again and deletes the stage only if it is still `Released` with the same count.

The handler never takes NamespaceResource. The worker holds it while waiting for a service reply. If the service thread sending DISPOSE
also held the journal gate that the reply needs, blocking here would deadlock. Instead the handler, under `StageListLock`, finds the
allocated stream whose transfer ID matches. The transfer ID is parsed from the allocation reply into the stream at create. The handler
sets `Disposed` and the outcome, queues the stream, signals the worker and replies `Held = 1`. If no stream matches, it replies `Held = 0`.

The worker detaches the view of a disposed current version only once that version has `FileObjects == 0`. While handles exist, the
version stays exactly as today. A program that keeps the file open (Word) renames through its handle (`StageRename` needs an attached
view and `view->Current == stream`). A later write open of the name seeds the new version from the stage file (`STAGE_FOLLOWUP`). Both
need the version until the last handle closes. After the detach, the owner's next open resolves to the public name:
- after an approval, that holds the published bytes (or a later publication by someone else, which every other process already sees);
- after a block, it holds the pre-save content, as today after retirement.

Stage file of an approved version: only the driver knows when its handle closes. So with `Held = 1` the driver deletes the stage file at
release. It opens the stage by name with `DELETE`, `FILE_OPEN_REPARSE_POINT` and `FILE_NON_DIRECTORY_FILE`, requires the file ID to equal
the backing's, sets the disposition and closes. With `Held = 0` the service deletes it itself. When the service starts, it resends DISPOSE
for every `Released` entry whose stage file still exists (DISPOSE is idempotent) and deletes the file when the reply is not held. A
`CleanedUp` stage is already delete-pending; closing the backing at release lets NTFS remove it.

`Retained` and other non-final states are never disposed: the owner keeps its private version (bounded by the cap and by owner exit).

## 4. Events instead of the 250 ms poll

| Event | Source | Work queued |
| --- | --- | --- |
| last handle cleanup (`OpenCount` reaches 0) | `IRP_MJ_CLEANUP` | drain and seal |
| last file object close (`FileObjects` reaches 0) | `IRP_MJ_CLOSE` | drain and seal, retire, release |
| DISPOSE | service control message | detach and release |
| service connects | `SafeUploadPortConnect` | sweep: pending renames, unsent seals, a `DeletePending` check of every sealed version |
| owner exits | process notify (Taint.c) | detach the owner's views, drop its tombstones, release |
| create or rename meets a pending state | inline, under NamespaceResource | finish a pending rename inline; retire a delete-pending version that has no file objects inline |
| retry timer (owner decision) | `KTIMER` and DPC | only while a version waits on a mapped view or a failed exchange |

**Queue.** `StageWorkQueue` (a list) plus per-stream `WorkLink` and `WorkQueued`, all under `StageListLock`. `StageWorkEvent` is a
synchronization event. The close handler decrements `FileObjects` and queues at zero under the same spinlock. The worker's release step
re-checks `FileObjects == 0 && !WorkQueued` and unlinks the stream from `StageStreams` under that spinlock. So no producer can touch a
stream after it is released: a producer either queued it first (release is skipped and retried after the dequeue) or holds a live file
object (`FileObjects > 0`). The DISPOSE handler and the connect sweep find streams only through `StageStreams` under the spinlock.

**Worker.** `KeWaitForMultipleObjects({StageWorkerStop, StageWorkEvent}, WaitAny)` with no timeout. Each pass runs under NamespaceResource:
1. take the sweep request (connect), if any;
2. drain the exited-owner ring;
3. dequeue streams one at a time. For each: finish a pending rename; check retirement (`DeletePending`); drain and seal if unsealed;
   detach a disposed version that has no file objects; try release; then free the view if it is empty.

The stream lookup by file object stays a list walk over allocated streams only, so it is no longer bounded by the boot's history.

**Retry timer.** `KTIMER` and `KDPC`. The DPC only sets `StageWorkEvent` and a "timer" wake reason. At the end of a pass the timer is
armed one-shot if some version is waiting:
- on a mapped view: drain returned busy with `OpenCount == 0` and user-mapped views (`MmCanFileBeTruncated` false or sections present).
  The delay is 250 ms, doubling to at most 1 s. That keeps the seal within about a second of the unmap. The wait is rare: a program
  holding a mapped view after closing its handle.
- or on an unanswered exchange: a seal or a rename commit or abort that got no reply. The delay is 250 ms, doubling to at most 8 s. A
  request the service answered with a refusal is not retried on the timer; it waits for the next service connect, as a refusal is
  permanent for that service instance.

The delay resets when the waiting set empties. When nothing waits, the timer is cancelled and never fires. Unload: `KeCancelTimer` plus
`KeFlushQueuedDpcs` before the worker stops.

Why C02 needs it: the actor closes its handle, stores through a mapped view, flushes, unmaps and closes the section. Windows sends no
request at the unmap. The cached section keeps the upper file object alive, and after the flush no paging write follows.

**Owner exit.** The process-notify routine already registered in Taint.c also calls `SafeUploadStageProcessExited(Pid)`. When no view or
tombstone exists, it returns at once. Otherwise it looks the process up and pushes the referenced `EPROCESS` into a 64-entry ring under
`StageListLock`, then signals the worker. The worker matches views and tombstones by that pointer, never by PID, and then dereferences it.
A queued PID cannot be reused while the ring holds the reference (Luna review: a bare PID could detach a new process's view).
- If the lookup fails or the ring is full, a full-sweep flag is set instead. The worker then checks each owner with a zero-timeout wait
  on the process object. An exiting process is signalled only after its notification, so the sweep stays owed until one starts at least
  1 s after the last overflow; the retry timer fires within 1 s while it is owed (Luna implementation review and re-review). The flag and the ring are checked and changed under `StageListLock`, together with
  `StageInitialized`, so an exit racing the unload cannot leave a reference behind.
- If the notify registration failed (it is not fatal today), views and tombstones of exited owners are still bounded by the two caps.

**Unload.** A voluntary unload is refused (new veto reason `STAGE_RENAME`) while any version has a rename exchange whose commit or abort
the service has not acknowledged. Unloading would leave the journal's prepared rename unresolved (Luna review).

**Failures.** These retry on the timer: a drain or backing reopen that fails for any reason other than open handles or file objects, and
a seal or rename that fails for any reason other than a refusal or an absent service (no reply, no memory for the request). A refused
seal or rename, or one sent while no service is connected, waits for the next service connect. If the driver fails to delete an approved
stage at release, the file stays until the next service start, which resends DISPOSE for every `Released` entry whose stage file still
exists, gets `Held = 0` and deletes it.

**Out of T4 (to T9).** A staged create that fails after the service allocated its stage leaves that stage and its journal entry
(today's behaviour). These use disk, not driver memory or the cap. T9's stage-space budget must count and clean them up (Luna review, P1).

## 5. Locking

The order is unchanged: NamespaceResource, then stream `Resource`, then `StageListLock` (a spinlock, leaf). Producers at
`<= DISPATCH_LEVEL` take only `StageListLock`. Release: NamespaceResource exclusive, then the checks, then `StageListLock` for the final
re-check and unlink, released before any teardown call. Teardown runs at `PASSIVE_LEVEL` in the worker. Stage creates and the release step
both run under NamespaceResource, so the count `StageStreamCount` is still changed only under it.

## 6. Unload (also see section 4)

The order is unchanged. `StageStopping` stops queue processing, the timer is cancelled and its DPC flushed, the worker exits, and
`SafeUploadStageFree` frees the remaining streams, views and tombstones. DISPOSE cannot run after `FltUnregisterFilter`. Before that,
it races only with the worker, through `StageListLock`. A process exit after `SafeUploadStageFree` sees `StageInitialized` false and only
returns.

## 7. Counters (diag counters, read through the agent's diagnostics pipe)

- `StageLive`, `StageReleased`, `StageViewsLive`, `StageViewsReleased`, `StageTombstones`, `StageCapRefusals`, `StageTombstoneRefusals`;
- worker wakes by source: cleanup, close, dispose, connect, exit, timer, inline;
- `StageTimerArms`, `StageDisposeHeld`, `StageDisposeNotHeld`, `StageStageDeletes`, `StageStageDeleteFailures`.

## 8. Tests

- New row T4Cycles: 10,000 save cycles in one boot under runtime Verifier with special pool on the driver:
  - about 1 in 4 is CPF content (blocked), the rest clean (approved);
  - the patterns are a same-name re-save, a new name, a temp file plus rename-over, and a mapped write.

  It samples nonpaged pool by our tags (`SpUs`, `SUfl`) and in total every 500 cycles.

  Pass when:
  - our tags return to the baseline band;
  - `StageLive` returns to 0 when idle;
  - every cycle reached its outcome;
  - there is no Verifier stop.
- An idle check: with nothing waiting, the stage worker's wake counters stay flat for 60 s.
- C01-C04, B01, B02 and X01 in all three modes, then the full gate.

## 9. Risks and what changes for users

- The stream is freed after the last close, while upper filters' post-close callbacks may still run. NTFS frees its FCB inside close
  too. Nothing touches the stream after the decrement, and `FsRtlTeardownPerStreamContexts` runs before the free.
- After an approval and the last close, the owner sees the public file instead of its private copy. The bytes are the same, unless
  someone else published a newer version since.
- After a block's cleanup and the last close, the owner sees the pre-save public content (unchanged from today's retirement).
- Approved stage files are now deleted. Nothing reads a `Released` entry's stage again: justified cleanup tolerates a missing stage, and
  recovery handles only `Blocked` and `Publishing`.

## 10. Registry-cache retention measured during T4 qualification (2026-10-10)

The implemented stage worker released all 256 versions and views, left no tombstones, and stayed idle for 60 seconds in both
`m2t4stat1` and the repeat `m2t4stat2`. The repeat had no extra guest diagnostics between coordinator samples. Its Driver Verifier
module pool still grew from 389,168 bytes at cycle 64 to 3,368,496 at cycle 256 and remained at 3,284,448 after idle. The `SwUr`
registry tag grew from 6,557,568 to 9,770,240 bytes while listed entries stayed near 242. `SpUs` returned to zero. These results fail
the existing pool assertion; they do not qualify the required 10,000-cycle run.

The next candidate is an entry that passed `StageRegistryPruneLocked` but is retained by `WriterRegistryEntry` on an idle stream
context. That cache takes its own reference when the first writer is inserted and previously dropped it only on replacement or
context cleanup. Pruning removes registry/map ownership and instance/volume references, but NTFS can retain the stream context.
The observed tag growth supports investigating this path; runtime attribution is still needed before calling it the cause.

The candidate correction keeps the existing identity reopen, exact-SOP memory-manager predicate and locked prune exclusions.
After a quiescent reopen, it acquires an existing stream-context reference with
[`FltGetStreamContext`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetstreamcontext).
Only after the locked prune succeeds does a resident helper take `WriterLock` and remove the cache when it still points to that
retired entry, the writer list is empty, H/W/T are zero, and neither the context nor entry is Unknown. It drops the cache reference
after releasing the spin lock, while the worker still owns its independent entry reference. Every successful context acquisition
is matched by `FltReleaseContext`, including a failed prune.

An empty-cache witness under `WriterLock` preserves the retired entry's previous H=0 census. A newly allocated context has no
witness; a new cache binding clears it; an overflow node or sticky `WritersUntracked` still makes the census Unknown. The witness
is not consulted for scope classification, nested mutation admission or policy matching. Their existing missing/stale-entry
fallbacks remain in force. No context is detached, no counter is decremented as a substitute for exact cleanup, no Unknown is
cleared, and no timer or rescan is added. The registry lock is released before the helper takes `WriterLock`.

Qualification still requires all four WDK/PREfast/ApiValidator builds, Luna review before the first VM boot of this lifetime
change, runtime Verifier plus the unchanged short and 10,000-cycle pool assertions, raw-volume regression rows, and untouched-base
restoration. This candidate has not run on a debuggee and M2 remains incomplete.
