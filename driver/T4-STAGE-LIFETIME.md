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
an owner exit. T5's [private-delete design](T5-DELETES.md) detaches the name at last cleanup and retires the version instead of sealing
it. Discarded is terminal and never publishable; release still requires local drain and its exact cleanup ACK. An accepted/queued
discard reply is not that ACK. A superseded version is released as soon as it is unreferenced, even before the service has inspected it. The service
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
- after blocked or justified cleanup has marked the exact object delete-pending and durably recorded acceptance,
  with outcome `CleanedUp`. Notify before waiting for absence: the driver's read backing can be the last remaining handle.

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
view and `view->Current == stream`). A later write open of an eligible sealed version can seed from its stage (`STAGE_FOLLOWUP`).
A blocked predecessor instead returns a retryable conflict until retirement; it never seeds another version from blocked bytes.
After the detach, the owner's next open resolves to the public name:
- after an approval, that holds the published bytes (or a later publication by someone else, which every other process already sees);
- after a block, it holds the pre-save content, as today after retirement.

Stage file of an approved version: only the driver knows when its handle closes. So with `Held = 1` the driver deletes the stage file at
release. It opens the stage by name with `DELETE`, `FILE_OPEN_REPARSE_POINT` and `FILE_NON_DIRECTORY_FILE`, requires the file ID to equal
the backing's, sets the disposition and closes. With `Held = 0` the service deletes it itself. When the service starts, it resends DISPOSE
for every `Released` entry whose stage file still exists (DISPOSE is idempotent) and deletes the file when the reply is not held. A
`CleanedUp` stage is already delete-pending; closing the backing at release lets NTFS remove it. The service records
`StageDeleted` only after confirmed absence against its exact accepted-disposition receipt. A cleanup-start marker alone
cannot recreate that receipt after a crash. See [boot14 allocation and cleanup](T5-DELETES.md#boot14-blocked-retirement-and-allocation-resolution--2026-10-14).

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

**Unload.** A voluntary unload is refused (veto reason `STAGE_RENAME`) while any version has a rename exchange whose commit or abort the
service has not acknowledged; it is also refused (`STAGE_DISCARD`) while a private-stage discard or its deletion is unacknowledged.
Unloading would leave the journal's prepared rename unresolved or discard retry state behind (Luna review). The 2026-10-11 T5
rescope also vetoes voluntary unload for any outstanding private stage, RPC or public-delete reservation. Mandatory teardown follows
[T5-DELETES.md section 7](T5-DELETES.md#7-unload-and-shutdown-rescope): drain local references, close backend holds, and never wait for
service availability or cleanup ACKs. Interrupted private stages remain retained and nonpublishable under existing startup recovery.

**Failures.** These retry on the timer: a drain or backing reopen that fails for any reason other than open handles or file objects, a
discard whose service acknowledgement is refused (including a stage that could not be removed), and a seal or rename that gets no reply
or cannot allocate a request. A disconnected service or refused seal/rename waits for the next service connection. If the driver fails to
delete an approved stage at release, the file stays until the next service start, which resends DISPOSE for every `Released` entry whose
stage file still exists, gets `Held = 0` and deletes it.

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

## 11. Journal failure recovery — 2026-10-12

The latest [10,000-cycle verdict](evidence/2026-10-11/m2t4boot10k1011a2-verdict.txt) passes pool/cap/idle checks but fails outcomes and
cleanup. Four private manifest replacements failed with native error 5; two followed successful public publication, two preceded
hand-back. The [diagnosis](evidence/2026-10-11/t4-journal-failure-diagnosis.md) establishes the skipped Publishing recovery path; the
native denial's cause and exact historical transfer/name associations remain unproven. The kernel reclamation fix stays intact.

Owner-approved behavior: automatically finish interrupted bookkeeping; never repeat a confirmed public save. The focused design
received a Luna 6 max security review in this conversation before implementation. It adds no persisted protocol states:

- A typed journal persistence error records the transfer/generation, intended state, write step, native error and manifest/temp names.
  It is distinct from validation, identity and content failures. After any uncertain write, invalidate cached state and reread disk.
- After a successful native publication rename, retain an in-process receipt bound to the exact transfer, generation, namespace,
  measured stage/digest and committed temporary identity. The worker may finish only the matching journal record, then existing
  notification/disposal. It never calls publication again. The same native result cannot authorize a changed journal version.
- A legacy publication without a surviving exact receipt stays Publishing after restart, preserving its reservation. A matching
  destination hash cannot invent a successful operation. The tray names the file and directs the user to diagnostics. T5 bound
  records still require the existing anchored destination-head/native-receipt dispatcher; this repair does not activate it.
- A failed hand-back intent/completion write keeps NotAttempted/Copying (or Verified if replacement succeeded before the error).
  Fresh durable reads decide which step remains. Live and startup recovery reuse the transfer-specific copier, verifying an existing
  copy instead of overwriting it. Identity/content/copier failures retain the existing Failed behavior and private stage.
- Recovery runs single-flight, with per-transfer persistence retry delays of 250 ms up to 8 s, using a monotonic clock. No retry delay
  holds the journal gate. Other transfers continue. The current journal scan remains; indexing old history is a separate optimization.

The [Windows agent matrix](evidence/2026-10-12/exact-agent-matrix-t4-journal-recovery6-summary.txt) at `8e0156c9` (product fix through `aea1ec16`) passes normal
Debug/Release (895 tests each) and feature Debug/Release (1,245 each), with no skipped tests and all agent/app/test builds at 0/0.
It includes 15 new cases: deliberate failures before/after manifest replacement; native publication followed by failed Released
persistence; unchanged/changed public bytes; lost receipt at restart; live/restarted hand-back recovery without duplicate copies;
and exact-version rejection after a prepared rename. The hand-back cases also verify live notification/justification completion
after a lost completion acknowledgement. These are Windows service tests, not protected VM qualification.

The protocol-18 backport on `fix/t4-journal-recovery-v18` preserves the existing T4 driver pairing; it does not enable unfinished
T5 capabilities. Qualification still requires its agent matrix, short Verifier run, 10,000 cycles, raw-observer regressions and
independent restoration. The older restart test now requires a held reservation, preserving its byte/non-overwrite assertions and adding refusal
of a later allocation. This records the approved failure-policy change, not a relaxation of any product byte assertion.

## 12. Unaccepted allocation reply — 2026-10-12

The [short retry diagnosis](evidence/2026-10-12/t4-allocation-reply-diagnosis.md) records 255/256 successful saves, one residual
stage, and a failed pool slope, with separate restoration passed. There were no journal replacement failures. Two replies returned
`ERROR_FLT_NO_WAITER_FOR_REPLY`; the historical logs do not bind them to an operation/transfer, so they cannot authorize cleanup.

Owner approved focused diagnosis/fix after these repeated errors. Luna 6 max reviewed the narrow repair: the exact NO_WAITER
result from the sole native reply proves that this request did not receive its fresh allocation basename. Keep the original
transfer/generation and full file identity from the creation handle through that call. All other errors and restart ambiguity
retain the existing private recovery behavior. No kernel or wire change is needed for this limited case.

Candidate `6198eee7` on `fix/t4-journal-recovery-v18` queues that exact rejection for the existing worker. It revalidates the original
Allocated record under the journal gate, opens the original file exclusively and checks its full identity, journals Unsealed,
then deletes through that handle. Keep the manifest/generation; never manufacture verified hand-back or reuse StageDeleted.
An uncertain journal write retries only the exact intended disposition. The volatile receipt is not reconstructed after a crash.
The random stage name has no other issuer: no driver stream was created, hence no legitimate later seal can arrive for this
particular Unsealed record. This does not make Unsealed terminal in general.

Fault tests cover successful/other native replies, changed identity/state/generation, before/after-write failures, sharing failure
and retry, absent identity, and restart without a rejection receipt. Monotonic request diagnostics separate owner/policy, backing,
journal wait/scan/write and reply latency. The patch does not claim to fix the failed pool slope or establish the delay's cause.
It remains isolated from the unfinished T5 allocation protocol. The [Windows agent gate](evidence/2026-10-12/exact-agent-matrix-t4-rejected-allocation1-summary.txt)
passes at `6198eee7`: 558 normal / 625 feature tests per configuration, no skips, all service/app/test builds at 0/0, packages independently
verified. The harness's PowerShell 5.1 parse and cleanup self-checks passed. Protected qualification remains pending.

The [instrumented short run](evidence/2026-10-12/t4-instrumented-short-result.md) completes 256/256 outcomes with no reply/journal
failures, no remaining stages/versions/views/tombstones, an idle worker and separate restoration passed. It still fails the unchanged
pool gate (318.863 B/cycle against 4). The NO_WAITER branch was not triggered; its protected fault-path qualification is not claimed.
Aggregate growth follows the writer-registry tag while stage-owned allocations return to zero; object/reference attribution remains
open. Further VM tests stop under the owner's repeated-failure rule. The 10,000-cycle and raw-observer gates remain outstanding.

### 12.1 V20 allocation/Prepare reply recovery — 2026-10-16

The owner's `uxk5t4ord2-*` report (driver ux-k5, agent `59c7e319`) stopped at cycle 548 after three mapped-name failures:
cycle 532 first returned Win32 121, then later opens returned Win32 5. StageAttachPrepare's reply returned NO_WAITER after
7,267 ms; allocation/seal journal waits/scans/writes also took seconds. The supplied raw evidence path was unavailable in the
`ux/allocfault` workspace, so those timings are owner-supplied observations, not independently re-read here.

The V20 ownership defect is distinct from the legacy basename cleanup above. After a lost Prepare, the driver knew the exact
allocated tuple but left `AttachCompletionPending` and `AttachPrepareMayExist` held. Only a may-have-reached op15 could resume
on another CREATE; maintenance could neither seal nor discard the prepared version. The next open therefore hit the permanent
same-name delete-pending barrier. Journal scanning latency explains the opportunity for a timeout; this change does not optimize
those scans or claim to eliminate timeouts.

- A failed Prepare now enters terminal unattached cleanup after the synthetic binding unwinds. The existing collector still
  requires zero upper objects/shares/sections/cache, closed backing, no attachment in flight and no op15 ambiguity. It pins the
  stream through every unlocked exchange. Unknown StageAllocate replies retain the existing byte-exact request replay, followed
  by kind-5 cleanup (or the existing exact NoAllocationCommitted terminal receipt); no new allocation identity is invented.
- Before kind-5 cleanup of an unknown Prepare, the worker sends the exact op14 Abort. The agent serializes Abort with Prepare
  under the journal gate and may abort an exact `None` allocation as well as `Prepared`. An abort-first record prevents a late
  Prepare from reviving it. Prepared-first abort preserves its historical Prepare receipt; replay only returns that history.
  Commit/permission ambiguity never enters this new cleanup path. AlreadyCommitted, generic DENY, timeout and malformed replies
  grant no deletion/release authority. Abort requests remain byte-identical across retries; lost abort/deletion replies retry
  unfinished bookkeeping against the original object and generation.
- The existing exact kind-5 deletion/absence ACK resolves the journal disposition and only then releases the kernel reservation,
  predecessor receipt reference and version. DiscardPending plus DiscardAcknowledgedAtUtc is the terminal record; StageDeleted
  remains the separate publication-disposal receipt. Channel changes or changed tuples cannot apply an old ACK. During cleanup,
  both same-owner and foreign CREATE routes return a retryable sharing conflict; the first timeout remains Win32 121. After ACK,
  the next CREATE uses a fresh allocation/generation. Actual private deletes and ambiguous op15 retain their existing holds.

No wire layout, imports, runtime activation gate, sticky Unknown rule or T4 assertion changes. The updated driver/agent must be
delivered together: an older agent may conservatively refuse abort-before-Prepare. Service absence, structural identity failure,
unresolved deletion or a crash before durable disposition remain held; the fix does not turn uncertain cleanup into success.

Local verification: production C extraction compiled/run with GCC and Clang (UBSan, warnings as errors); existing T5 self-checks,
three existing C shims, T4 verdict replay and import self-check; feature agent Debug/Release build and focused diagnostic controls.
The focused Linux runner uses a failure-only shim for diagnostic GetFileInformationByHandleEx (returns failure, never identity
authority); it is not Windows native evidence. Results and the independent Sol 6.1 xhigh review are recorded in
[the implementation receipt](evidence/2026-10-16/ux-allocfault/result.md).

Required VM list, with all existing T4 assertions retained:

1. Matched feature Debug/Release WDK/PREfast/ApiValidator at 0/0, both artifact import gates, and the four feature agent matrix legs
   (Debug/Release × user/SYSTEM), before product qualification. No product VM was booted for this implementation.
2. Allocation-reply fault row in ordinary/runtime-Verifier/boot-Verifier: delay/drop StageAllocate before/after durable allocation;
   delay/drop Prepare before/after journal commit; Abort ordered before late Prepare; lost Abort and lost cleanup ACK; same-owner
   and foreign retries. Require retryable failure, unchanged independent public-byte observations, exactly one disposition/delete,
   durable journal resolution, fresh successful open/generation after ACK, zero residual stage/version/view/receipt references,
   and no cap refusal or Verifier finding. Negative controls: changed identity/generation/epoch, sharing failure, disconnect/reconnect
   and stale-channel ACK; op13/op15 ambiguity must remain held under its existing rules.
3. Unchanged 256 smoke then 10,000 ordinary/runtime-/boot-Verifier gates, including contexts/pool/idle/cap/Ready checks, followed
   by C01–C04/B01/B02/X01 independent raw-observer regressions in all three modes and separate baseline restoration. Follow the
   current status plan's stop rules and builder-free timing windows on `win10-debug3` only.

## Implementation note — increment 9

2026-10-13; `wt/t5-inc9`, based on `77466b8142a6a24b924a1d228494f46a3595373f`. Kernel implementation draft,
not build/review/qualification evidence. No commit, WDK build or VM action was performed. The orchestrator owns the four
normal/feature × Debug/Release builds with PREfast and ApiValidator at 0 warnings/errors. The coherent increments 2–10
lifetime package still needs **Sol 6.1 xhigh** review before its first authorized boot; the T4 product-row stop remains.

This closes the implementation gap identified by [increment 9 and review item 10](evidence/2026-10-13/t5-integration-plan-astra.md).
It is not a T4 retention repair. The [attribution diagnostic](evidence/2026-10-13/t4-handback-attribution-result.md) does not
supply original-stream lifetime evidence. No T4 threshold, retry interval, resource cap or accepted native outcome changes.

### Original lifetime and retirement argument

`StageRegistryBindLifetime` attaches a small nonpaged `STAGE_SOP_LIFETIME` witness to the **already attached** original
stream context during successful physical post-CREATE. Every entry owns one reference to that witness; the context owns
one. The witness holds only an immutable SOP comparison token and interlocked reference/ended/invalid fields. It holds
**no** FILE_OBJECT, handle, context, entry, instance or volume reference. Ordinary cache pruning can therefore still free
the large registry allocation without waiting for a filesystem-retained context. The context's small witness allocation
(`SwUl` when displayed in pool-tag byte order) lasts until its natural cleanup; its size and the added context fields must
be included in later memory qualification. Allocation failure keeps the entry Unknown; no lower CREATE is canceled by the ledger.

Filter Manager [deletes contexts when their associated object is deleted, an instance detaches, or the filter unloads](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/managing-contexts).
The implementation distinguishes those cases: `SafeUploadStageWritersFreeContext` publishes Ended only with an ACTIVE
instance teardown token, mandatory teardown inactive, no explicit invalidation, an empty original writer list, and no
`WritersUntracked`. All other cleanup invalidates the witness. Only successfully attached contexts acquire witnesses;
a losing `FltSetStreamContext(KEEP_IF_EXISTS)` allocation cannot manufacture a receipt. The diagnostic explicit
`FltDeleteContext` call first invalidates the witness and publishes sticky tracking loss. No forced deletion is added.
This argument depends on retaining that rule at **every** future explicit deletion/replacement site.

There are two distinct retirement proofs:

| Proof | Required evidence and locked recheck |
| --- | --- |
| Original incarnation still live | Identity reopen verifies mounted volume/full file ID/exact SOP; `FltGetStreamContext` must return the original witness, not just the same SOP address. `MmCanFileBeTruncated` checks that owned original FILE_OBJECT's SOP. The context stays referenced through the final prune. An unchanged registry activity sequence and all ordinary ledger/section exclusions are required at unlink. |
| Original incarnation ended | The original context's natural Ended receipt is valid. Under RegistryLock then SectionLock: no H/W/T, rename, directory-rename uncertainty, bound CREATE reservation, transaction association, section acquire/release slot (including read-only), spilled writer/mutator or new owner remains. Unknown, invalid/missing evidence and global tracking loss veto retirement. No replacement object's MM result is used. |

A missing name, failed identity reopen, different SOP, recycled SOP address, content digest, scan or elapsed time is **not**
either proof. Entries never change their original SOP/witness binding. SOP map address reuse requires the old entry's Ended
receipt and resolved obligations before its map reference can move; history retains its own reference until normal prune.
Unknown overflow markers have no original lifetime witness and stay sticky; the bounded marker walk only observes them.
It no longer opens files or clears markers. Admission counts these markers even when no complete registry entry exists.

Startup/activation validates the original context **before** a name classification can clear its pending state. An ended
entry is retired by the existing reclaim worker rather than promoted on a new incarnation's behalf. A current base-stream
entry waits for other incarnation histories to retire. Live promotion retains the existing scope/generation, H/W/C/T,
cache-flush and exact-SOP checks, additionally requiring the memory-manager truncation predicate and all section callback
slots clear. Missing natural cleanup stays pending for its real event. Natural witness completion, final owner release and
a waited-on sibling's actual prune wake the existing worker; there is no new timer or polling worker. The existing
identity anchors remain ordinary owned handles; no new FILE_OBJECT pin is introduced to obtain lifetime evidence.

The nested-mutation “known outside” lookup and SOP policy lookup also verify the original context witness before trusting
cached classification. A recycled address with a different context cannot inherit the old entry's outside-scope authority.

### Owners from increments 2–8

`SafeUploadStageWritersOwnerAcquire/Release` adds an interlocked obligation count serialized with final promotion and prune
under SectionLock. Its edges advance the registry/coverage sequences and SOP-map generation. Thus an owner entering and
leaving during a PASSIVE proof invalidates that proof even when the count returns to zero. No ABI layout changes.

| Owner | Count starts | Count ends |
| --- | --- | --- |
| Public/writer factory | Before the accepted factory performs capture/open work | After factory cleanup/ownership transfer |
| Writer lease, DELETE backend, temporary native-name metadata backend | Immediately after allocation, before acquiring instance/object/handle references | Common final destructor, after local operation rundown, all closes, snapshot/input cleanup and instance dereference |
| V26 record | Before creator/token/source capture or record publication | `BpDestroy`, after callbacks/work uses are gone and source/version/root/parent/writer ownership is released |
| Native record, including combined backend and retained recovery facts | Before instance/reference acquisition and map insertion | Failed factory unwind, or `NativeDestroy` after terminal record removal and local backend/callback/epoch ownership is gone |

Transfers to attach handles, unresolved allocation replay, publication source pins, metadata readers and native combined
operations remain covered by their existing owner's count; they do not acquire an uncounted replacement owner. A service
ACK is not the release hook. Retained uncertainty continues to count until the existing exact terminal/removal rules permit
the final local destructor. Counter corruption publishes sticky Unknown rather than manufacturing zero.

The count is deliberately **global and conservative**: these owners can retain multiple public/private/ancestor objects,
and destination ID/path/hash alone cannot enumerate that authority. Any counted owner delays registry promotion/prune
and aggregate Ready, including unrelated entries. `WriterEntries/WriterEntriesNotReady` include obligation units (not
unique filenames). This may keep admission Pending while an ordinary native record or durable receipt is retained; it
is not a claim that final bound readiness or availability is qualified. Existing bound capability gates remain false.

The new lock edges are PublicListLock → SectionLock for factory admission, and RegistryLock → SectionLock for retirement;
SectionLock never calls back into public/native/publication locks. Witness binding uses WriterLock without taking RegistryLock.
All allocation, identity/MM/flush work and context acquisition occur outside spin locks; spin sections are resident helpers.
Owner-release wakeups occur after locks and local references are released. This increment adds no wait, RPC or ACK dependency
to mandatory teardown. Voluntary preflight additionally checks the aggregate count after closing its producer gates and uses
the existing reversible veto path.

### Reviewer checklist and increment 10 composition

- [ ] **T11 lifetime:** verify natural cleanup versus diagnostic deletion, detach/dismount, canceled CREATE, shutdown and
  losing context allocation; all future context replacement/deletion sites must invalidate first. Check missing witness,
  delayed cleanup, changed/recycled SOP, base/ADS and Unknown-marker cases without dereferencing old SOP tokens.
- [ ] **T11 obligations:** hold each of H/W/T, read-only/writable section slots, spilled callbacks, rename/reservation,
  writer factory/lease, metadata reader, V26 work/source and native/combined record while requesting activation/prune.
  Require refusal until the real release; include a complete acquire/release cycle inside a proof and a sibling retired
  after the waiting entry's turn. Audit every normal/failure/teardown destructor for exactly one owner release.
- [ ] **T11 execution:** check SAL/residency, initialized outputs, lock order, no wait/I/O under spin locks, sequence stability,
  normal-build exclusion and all four WDK/PREfast/ApiValidator results. Run native/Verifier races only after owner authorization.
  Source-only checks here are diff whitespace, lexical brace balance and review of helper declarations/call sites, not WDK tests.
- [ ] **T5 increment 10:** compose the existing local teardown pieces with all producers and owners: fence admission, close/wake
  the channel, join local workers/callbacks, close owned handles before dependent lifetime waits, release allocation/publication
  leases and V26/native source pins, then drain/unregister/free. **Do not wait for this aggregate counter before destroying
  the records that own it**, and do not require service availability, RPC, ACK or durable certainty for mandatory local drain.
  Preserve unresolved durable/native coverage-loss facts and sticky Unknown; local destruction is not a publication/delete receipt.
- [ ] **T5 increment 10 readiness:** combine current authenticated negotiation, seed/security prerequisites, successful complete
  startup recovery, per-name uncertainty holds and this stable original-lifetime/owner census. Disconnect/replay invalidation
  clears readiness. A zero owner count or retired old registry entry alone enables nothing. Complete the single coherent lifetime
  review before boot and keep component verification separate from protected-pair qualification and T4 retention attribution.
