# gen4b review — sealed stream retirement and reopen guard

**Verdict: ACCEPT WITH CONDITIONS** — no P0/P1 found for the ordinary user-open path. Review was limited to the requested driver diff plus read-only tracing of its consumers. No source edits, VM, or build.

## P2 — query contract on a recursive create

At [StageStream.c:1391-1394](/home/victor/Work/safeupload-wt-gen4/driver/SafeUpload.Minifilter/StageStream.c:1391), `StageCreate` holds `StageNamespaceResource` exclusively, but not `stream->Resource` yet. The namespace lock does protect `BackingObject` lifetime: worker retirement takes NamespaceResource then Resource, and unload sets `StageStopping` under NamespaceResource before closing backings. `StageCreate` is a create callback; the ordinary create path is PASSIVE_LEVEL, and `StageAcquire` disables normal APCs, not special kernel APCs.

There is no `IoGetTopLevelIrp()` guard. Microsoft’s [FltQueryInformationFile contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltqueryinformationfile) requires PASSIVE_LEVEL with special kernel APCs enabled and warns that a non-NULL top-level IRP can deadlock. If a recursive protected-name create reaches this branch with a top-level IRP set, the synchronous query can stall while holding the global namespace lock. Keep this branch limited to a null-top-level context, or otherwise route it safely. I found no ordinary standard-user direct-open path that sets this condition.

## P2 — overlapping open/deletion ordering

The query at lines 1391-1394 precedes share-access accounting and `FileObjects` increment at lines 1447-1471. If a create passes the query, is preempted, and the service deletes the stage before that create commits, the create can still finish against the retained backing; the worker cannot retire until NamespaceResource is released. Treat the successful query as the logical admission point, so an overlapping create admitted before disposition is equivalent to a pre-delete open. If the required cutoff instead means no create may *complete* after `File.Delete` succeeds, this check does not serialize that stronger rule with the service.

For a writer, an already-pending backing is rejected before `SafeUploadStageAllocate` at lines 1386-1394. If the service copy opens the previous stage first, its `FileShare.Read`-only input blocks a successful delete until copying ends. If deletion wins first, `FILE_OPEN` fails; `FILE_OPEN_IF` may create an empty stage as its disposition allows, but it cannot copy the deleted bytes.

## Other checks

- `STATUS_DELETE_PENDING` is an appropriate fail-closed create status. It returns no stage name or bytes; it only reports that the already-visible logical file is being deleted.
- Existing `StageQuery` consumers require an upper file object, which retirement excludes (`OpenCount == 0`, `FileObjects == 0`). `StageFindView` and `StageFindId` skip detached views. Directory collection also skips detached current views; `StageAddOverlay` has a `BackingObject == NULL` → `STATUS_DEVICE_BUSY` guard.
- Tombstone lookup can retain a retired stream’s `StageName`, but it passes that name only as a tombstone identifier; the service does not seed a tombstone allocation from it. Unload’s `StageDrain` is safe for a retired read-only stream: it skips backing flush, and `StageCloseBacking` is null-safe.
- `SafeUploadProcessHasMappings` now ignores exactly detached, retired current views, resolving the prior persistent false positive.
