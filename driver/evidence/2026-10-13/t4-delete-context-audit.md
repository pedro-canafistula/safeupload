**The cause remains undetermined.** In `60fecdbc`, a successful DELETE-access open deliberately creates or finds a stream context. I found balanced context references through the ordinary create → disposition → cleanup path, and no owning FILE_OBJECT reference in its writer node or SOP slot. There is a separate driver-owned file lifetime—the **activation anchor**—but the evidence does not associate any anchor with these deleted files.

The evidence also does **not yet establish 2,087 surviving stream contexts belonging to exactly 1,500 files**. It establishes that increase in global `SUfl` pool allocations during the diagnostic interval.

I read the requested evidence first, inspected historical source with `git show`, and compared the minifilter against HEAD. Nothing was edited or run on a VM; `.ai-memory.toml` remains untouched.

All historical source references below are pinned to **`60fecdbc`**, under `driver/SafeUpload.Minifilter/`.

**The tested and current implementations differ.** The directory diff contains 23 changed files, +10,585/−242 lines:

- `Context.c`: stream allocation, attachment and cleanup are unchanged; changes concern instance/device admission.
- `StageWriters.c`: DELETE tracking, node insertion/removal, context releases and anchors are unchanged. Changes remove `WRITE_DAC/WRITE_OWNER` from the mutating-create mask and correct policy-generation comparisons.
- `Filter.c` and `StageAdmission.c`: admission, lifecycle and topology checks changed.
- `StageStream.c`: substantial new native/publication handling.
- `StageNativeRecords.*`, `StageNativeObservation.c`, `StageNativeWire.*`, `StagePublic.*` and associated bound-publication definitions **did not exist in the tested commit**. Their T5 paths cannot explain k11’s result.

**The ownership audit shows the following.**

| Path | Historical source evidence | Ownership and release |
|---|---|---|
| Pre-create dispatch | [StageStream.c:4190–4211](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/StageStream.c#L4190-L4211); [StageWriters.c:1400–1411](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/StageWriters.c#L1400-L1411), `1451–1565` | DELETE qualifies for a writer reservation. The reservation owns registry bookkeeping and instance/volume references, **not a stream-context or FILE_OBJECT reference**. Being outside protected scope does not exempt the open from writer tracking. |
| Legacy `Filter.c` pre/post-create | [Filter.c:1602–1608](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/Filter.c#L1602-L1608); `1838–1859`, `1939–1941` | DELETE-only and attribute-only opens bypass the legacy content path. A combined data-read/delete open can also use its context cache; that lookup reuses the same stream context and releases its reference at `1941`. |
| Context creation/attachment | [Context.c:580–674](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/Context.c#L580-L674) | Gets an existing referenced context, or allocates and attaches with `KEEP_IF_EXISTS`. The losing allocation is released at `660`; an existing winner is returned referenced. Successful attachment supplies FltMgr’s association reference; the caller must release its own reference. |
| Writer post-create | [StageWriters.c:2529–2674](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/StageWriters.c#L2529-L2674) | `hasWriterHandle = WriteAccess || DeleteAccess`. Failed/reparse creates leave before context creation. Successful tracking gets/creates at `2626`, installs the node at `2639`, releases the context at `2650`. `TrackingLost` releases at `2668`. |
| Unknown-writer fallback | [StageWriters.c:3535–3620](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/StageWriters.c#L3535-L3620) | Can get/create another caller reference at `3549`, including after normal tracking failed. It installs a normal or overflow-marker node, then releases the context at `3620`. It does not retain the context reference. |
| Node insertion | [StageWriters.c:107–113](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/StageWriters.c#L107-L113); [2384–2425](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/StageWriters.c#L2384-L2425) | `FileObject` and `SectionObjectPointer` are identity tokens. The node owns an **entry reference**; the stream context separately caches another entry reference at `2413`. No `ObReferenceObject(FileObject)` or `FltReferenceContext` occurs here. |
| Disposition SetInformation | [StageStream.c:4339–4390](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/StageStream.c#L4339-L4390); [StageWriters.c:3014–3070](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/StageWriters.c#L3014-L3070) | Both ordinary and extended disposition enter mutation accounting. `BeginMutatingIo` temporarily gets the stream context, takes an entry reference/increments `W`, then releases the context **before sending the operation below**. The completion owns the entry/ticket, not the context or FILE_OBJECT. Completion releases it at `StageStream.c:4583–4584`. Legacy `Filter.c:2266–2271` ignores disposition classes. |
| Cleanup | [StageStream.c:4232–4241](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/StageStream.c#L4232-L4241), `4593–4599`; [StageWriters.c:2707–2773](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/StageWriters.c#L2707-L2773) | Successful synchronized post-cleanup includes DELETE-access objects. It gets the context at `2723`, removes the exact FILE_OBJECT’s node at `2743`, decrements `H`, drops the entry reference and frees the node at `2762–2763`, then releases the context at `2773`. No context is created here. |
| Cleanup exceptional cases | Same locations | Failed/draining cleanup can leave accounting unresolved until context teardown. That deserves diagnosis if observed, but a remaining node still has **no owning context/FILE_OBJECT reference**. Legacy dirty-cache cleanup separately gets/releases at [Filter.c:2143–2163](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/Filter.c#L2143-L2163). |
| Close | [StageStream.c:4245–4248](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/StageStream.c#L4245-L4248); [StageWriters.c:6696–6710](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/StageWriters.c#L6696-L6710) | Traces lifetime and potentially queues a registry recheck. It does not acquire/store a context or FILE_OBJECT reference. The queued recheck does not retain the callback’s FILE_OBJECT. |
| Stream-context cleanup callback | [Context.c:158–196](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/Context.c#L158-L196); [StageWriters.c:2776–2817](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/StageWriters.c#L2776-L2817) | Drains residual nodes, records missing-lifetime evidence as Unknown, releases entry references and the teardown token, then deletes the push lock. It neither resurrects the context nor transfers it to deferred work. FltMgr handles its storage release. |

The important ownership direction is:

```text
FltMgr stream attachment → SafeUpload stream context → registry entry
                                                    → writer nodes → registry entry
```

The registry entry has no context back-reference. Therefore, **a retained context can retain registry bookkeeping; that bookkeeping does not itself retain the context**. The context’s teardown token also has no reverse context pointer.

Other ownership paths checked:

- **Registry/SOP/transaction/deferred bookkeeping:** entries reference instance and volume; SOP slots reference entries and store non-owning SOP identities. They do not reference an Mm section or cache map. Transaction associations and deferred rename/Unknown work likewise retain bookkeeping objects, not this stream context. See [StageWriters.c:124–268](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/StageWriters.c#L124-L268), `909–917`, `2348–2360`.
- **Other temporary context lookups:** snapshot `2839→2862`; tracked-writer check `2876→2888`; entry fallback `7136→7143`; policy/SOP fallback `7225→7233`. The reclaim worker is the notable longer-lived temporary pin: [StageWriters.c:4180–4183](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/StageWriters.c#L4180-L4183) closes its probe FILE_OBJECT/handle while returning a context reference; that reference is released at `6594`, whether pruning succeeds or fails. Pruning deliberately does not detach the context (`2428–2454`).
- **Activation anchor—an actual owning file reference:** [StageWriters.c:5882–5885](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/StageWriters.c#L5882-L5885) stores the by-ID handle and referenced FILE_OBJECT across worker visits. It can outlive the application’s last handle. New anchors require a listed, non-retired `ACTIVATING` entry with `H != 0`; existing anchors can remain at `H == 0` while activation remains unresolved (`5854–5875`). Destruction dereferences/closes both at `5796–5797`. This is a concrete candidate to inspect, **not an established explanation**. Outside-path status alone is not an anchor census.
- **StageAdmission.c:** no stream-context acquisition. Its identity-open helper returns an owning handle/FILE_OBJECT pair to its caller, with failure cleanup at [StageAdmission.c:76–109](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/StageAdmission.c#L76-L109). Admission canaries concern separate test objects.
- **Synthetic staging objects:** `STAGE_STREAM` is distinct from `SAFEUPLOAD_STREAM_CONTEXT`; it owns a backing handle/FILE_OBJECT and its synthetic stream’s section state. Backing releases occur at [StageStream.c:1144–1154](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/StageStream.c#L1144-L1154) and `1248–1251`. Tombstones contain a referenced process plus names/transfer identity, **no file/context reference** (`1031–1039`). The diagnostic reports zero remaining versions/views/tombstones/stage files.
- **Native-record/T5:** absent from k11. At HEAD, the record’s FILE_OBJECT fields are explicitly non-owning or callback-lifetime identities; cleanup/close clear them. Its persistent owned reference is the instance. See current [StageNativeRecords.c:16](driver/SafeUpload.Minifilter/StageNativeRecords.c:16), `202–207`, `740–784`. Record reference counts must not be mistaken for stream-context or FILE_OBJECT reference counts.

**The 1.39 count has no established per-file explanation.**

From [samples 13–15](driver/evidence/2026-10-13/m2t4hbdiag1-samples.jsonl:13):

| Measurement | Before diagnostic | After deletion + wait | After second purge + wait |
|---|---:|---:|---:|
| Outstanding `SUfl` pool allocations | 583 | 2,670 | 2,633 |
| Registry entries | 237 | 241 | 243 |
| Outstanding `SUwH` writer-node allocations | 230 | 231 | 236 |

The first interval has **14,501 allocations and 12,414 frees**, net **2,087**. The byte increase is `2,087 × 224 + 192`, consistent with predominantly stream-sized blocks but not a perfectly homogeneous population. After the second purge, the excess is **2,050**, or **1.367/file**.

Three qualifications matter:

1. The “before” sample precedes enumeration and Restart Manager queries for all three file sets. There is no intervening sample immediately before deletion. See [cycles-coordinator.ps1:232–253](driver/scripts/t4/cycles-coordinator.ps1:232). Background and diagnostic activity remain in the global delta.
2. `SUfl` covers multiple context types, registered at [Context.c:103–152](https://github.com/pedro-canafistula/safeupload/blob/60fecdbc/driver/SafeUpload.Minifilter/Context.c#L103-L152). Fixed-size FltMgr contexts use lookasides, so outstanding pool blocks are not automatically attached contexts. [Microsoft context allocation documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/registering-context-types).
3. This is **not grounds to dismiss the growth as lookaside caching**. The earlier same-k11 KD row found 1,943 outstanding logical stream-context allocations; its allocator counters implied only about three additional cached blocks at that snapshot. Those observations belong to another run and are non-atomic. [Earlier attribution](driver/evidence/2026-10-12/t4-memory-attribution-result.md:43).

The suggested mechanisms consequently rank as follows:

| Suggested explanation | Audit result |
|---|---|
| Attribute-query open followed by DELETE open | Does not inherently give two contexts. Pure attribute access creates none through these paths. Multiple FILE_OBJECTs for the same stream/instance share one attached context. |
| Combined legacy and staging tracking | Both use `GetOrCreate` and `KEEP_IF_EXISTS`; they do not intentionally attach separate contexts. |
| Alternate data stream | Could account for another context **if another stream was actually opened and tracked**. Deleting a file with ADS does not by itself prove separate SafeUpload-observed ADS opens. No stream inventory establishes this here. |
| `FILE_OPEN_REPARSE_POINT` | Changes reparse handling, not context multiplicity by itself. `STATUS_REPARSE` post-create exits without creating a writer context. Different actual streams/objects would need to be demonstrated. |
| POSIX deletion | Can explain disappearance of a name before object teardown. It does not inherently create a second stream context. |
| Other streams, instances, background activity or allocator storage | Possible contributors; require identity-level attribution. |

FltMgr permits **one attached stream context per minifilter instance per stream**, not one per open. Thus “one for every file plus a second for 587 files” is an arithmetic fit, not a demonstrated mechanism. [FltSetStreamContext documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltsetstreamcontext).

**Windows has separate namespace, handle, FILE_OBJECT and stream-structure lifetimes.**

POSIX disposition unlinks the name when the deleting handle closes while allowing existing opens to continue accessing the stream. That contract does not specify an SCB/FCB destruction deadline. [Microsoft disposition documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information_ex).

I could not verify “DeleteFileW since 1709/RS5” as stated:

- OSR documented the disposition extensions in the RS1-era headers, but reported that the functionality was disabled before RS1 release and expected back in RS2. That concerns capability availability, not necessarily `DeleteFileW`’s default implementation. [OSR’s contemporary account](https://www.osr.com/nt-insider/2017-issue1/windows-10-whats-new-for-fs-filters/).
- Eryk Sun’s contemporary observations place the `DeleteFileW` switch at **Windows 10 1903**. This is observational evidence, not a Microsoft version guarantee. [Python tracker account](https://bugs.python.org/msg359981).
- Microsoft’s WIL source describes `DeleteFile`/`RemoveDirectory` as using POSIX deletion with fallback. [Microsoft WIL implementation](https://github.com/microsoft/wil/blob/master/include/wil/filesystem.h).

Therefore POSIX deletion is plausible on this 19045 target, but **the actual disposition class, flags and fallback outcome were not captured in this evidence**.

After the last **handle** closes:

- `IRP_MJ_CLEANUP` occurs, but outstanding references can keep the FILE_OBJECT alive and delay `IRP_MJ_CLOSE`. [Microsoft cleanup](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-cleanup), [close](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-close).
- Cache Manager shared-cache structures and Mm control areas can retain FILE_OBJECT references. Mapped views can survive closure of their originating handles. Microsoft’s Molly Brown explicitly describes these ownership relationships. [Microsoft explanation on OSR](https://community.osr.com/t/cache-information/17822).
- A per-open private cache map should not simply be assumed to remain forever: the filesystem must call `CcUninitializeCacheMap` when closing the file. Shared-cache/MM teardown and outstanding work are separate questions. [Microsoft cache-uninitialization contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccuninitializecachemap).
- Even after FILE_OBJECT close, NTFS can retain cached FCB/SCB structures. Microsoft’s filter-group lead explains that stream-context cleanup can occur after the final close, with the FILE_OBJECT already gone. **That general statement does not prove that POSIX-deleted SCBs on 19045.2965 follow the suspected delayed-close path.** [Microsoft explanation on OSR](https://community.osr.com/t/detect-last-file-close-in-mini-filter/21466).

The memory-list purge operates on physical-memory residency/reclamation. It is not a documented command to drain every NTFS delayed-close structure, release arbitrary object references, or delete attached minifilter contexts. It can indirectly cause reclamation—as the first purge plainly did—but its failure to release these blocks does not distinguish a driver reference from filesystem retention. This is an inference from the separation of memory lists and object ownership, not a verified description of the target’s internal purge path. [Microsoft memory categories](https://techcommunity.microsoft.com/blog/askperf/mystery-memory-leak-where-did-my-memory-go/1675369).

Likewise, Restart Manager’s empty holder result is not a kernel reference census.

**The decisive next experiment is one identity-resolved KD attribution row on the unchanged k11 pair.** A builder-native control could establish native behavior on the builder, but would not identify the owner of these SafeUpload contexts on the qualified target.

Proposed steps:

1. Use only `win10-debug3`, exact 19045.2965, unchanged k11/agent artifacts and matching private PDB, through the existing disposable-overlay and `T4_MEMORY_TOOLS` workflow.
2. Create a bounded corpus, for example 256 ordinary unprotected `.txt` files. Record full volume/file IDs, confirm one unnamed data stream and no reparse points, and close all observing handles.
3. Perform the initial purge and holder probes, **then take a fresh baseline**. Delete serially with the same SYSTEM PowerShell `[IO.File]::Delete` calls. Take snapshots after 30 seconds and after the same purge plus another 30 seconds.
4. In each snapshot, separate pool storage, logical allocator counts and actual attachments. Resolve addresses from that run’s symbols; use the existing debugger extension’s help to confirm flags:

   ```text
   lmvm SafeUpload
   !fltkd.filter <filter> 0x1f 1
   !fltkd.volume <target-volume> 0x10 1
   !fltkd.streamlist <stream-list-control> 0x3f 1
   !fltkd.ctx <context-node> 1
   dt SafeUpload!_SAFEUPLOAD_STREAM_CONTEXT <context-payload>
   dd SafeUpload!StageAnchorCount L1
   !fileobj <file-object>
   !object <file-object> 1
   dt nt!_SECTION_OBJECT_POINTERS <sop>
   !ca <data-control-area>
   ```

5. For every retained corpus context, record its instance, stream identity, attachment/reference state, writer list, cached registry entry, `H/W/T`, and any matching anchor. Follow surviving FILE_OBJECTs into shared cache maps/control areas. Also inspect FltMgr name/context references. Use registry IDs or symbol-resolved NTFS identity to match the original corpus; paths and reused addresses alone are insufficient.
6. Inspect NTFS delayed-close ownership only where symbols permit reliable interpretation. If private structure information is unavailable, record that attribution as unresolved. Local-KD snapshots are non-atomic; inconsistent walks require corroboration, not guessed offsets.

Expected discriminators:

| Hypothesis | Required observation |
|---|---|
| SafeUpload owns the lifetime | An unmatched driver context reference, or a corpus-matched owning handle/FILE_OBJECT in an anchor—specifically the ownership transferred at `StageWriters.c:5882–5885`—or another positively identified driver owner. A raw pointer in a writer node is insufficient. |
| Filesystem/cache/MM retention | Context remains attached with no extra SafeUpload-owned context/file reference, **and** a positively identified cache/MM or NTFS lifetime owner accounts for the stream. |
| Lookaside/pool-count mismatch | Pool blocks remain while logical outstanding/attached context counts do not; allocator free-list storage accounts for the difference. |
| Mixed/global activity | Surviving contexts predominantly map to other file IDs, streams or instances, resolving the apparent 1.39 multiplier. |

This is a proposed experiment only. The repository’s existing T4 stop requires separate owner authorization for that new VM row. No source finding here justifies forced context deletion or changing the cleanup assertion.