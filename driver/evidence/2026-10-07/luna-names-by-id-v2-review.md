# Adversarial review: `9b964be9`

**Verdict: ACCEPT WITH CONDITIONS**

No P0 or P1 escape is apparent in this diff. The v1 false “no names” result is corrected: the names-only open verifies volume serial and the full 128-bit file ID, then classifies the hard links returned for that current file. A scoped result publishes Activating (or stays Unknown and gated), and the activation open and second SOP check require the exact recorded pointer. The condition is to keep the existing NTFS SOP-lifetime premise explicit and qualify the stale-entry capacity behavior described below. This is source/evidence review only; I could not run the v2 build on a VM.

## Findings

### P2 — Changed-SOP entries can remain in the bounded registry indefinitely

**Location:** `StageWriters.c:1033-1047, 3927-3965, 4107-4215, 4693-4730`.

The new path can successfully classify an entry whose recorded SOP is stale, but it deliberately does not retire it. The normal reclaim path calls `StageRegistryEntryQuiescent`, which uses `StageRegistryOpenIdentity(..., FALSE)`; a successful by-ID reopen with a different SOP becomes `STATUS_FILE_INVALID` at 4212-4215, so quiescence returns false. Registry lookup keys on the raw SOP pointer, so a later incarnation can create another entry for the same volume/file ID. Entries with a sticky Unknown reason are also ineligible for pruning (3871-3878).

**Scenario:** A persistent file is written and closed repeatedly. If NTFS tears down its SCB before the reclaim probe and returns a different SOP each time—the exact behavior cited for the MountMgr database—each old entry can fail exact-SOP reclaim while a later open binds a new entry. Enough distinct incarnations can exhaust the bounded registry and turn the volume Unknown/coverage Degraded. This is fail-closed availability loss, not a false Ready or a byte escape. The supplied runtime artifact demonstrates one changed-SOP case, not accumulation; qualify the rate/limit on the target build.

### P2 — The existing SOP-reuse premise is broader than the documented contract

**Location:** `StageWriters.c:3716-3802` (especially 3736-3740 and 3788-3802).

The v2 classifier no longer uses SOP inequality to claim that names are gone, and that is the right separation. The separate association code still says a changed/reused SOP proves that no old handle, section, or view remains. Microsoft documents one `SECTION_OBJECT_POINTERS` per stream and says its members are opaque, but does not specify the allocation lifetime of the structure. NTFS file IDs are stable only until deletion and are not unique over time. The code’s raw-pointer map-reuse path can replace a map entry without checking the old entry’s H/W/T/C counters; it relies on the lifetime premise to make those states impossible. This is not evidence that NTFS 19045 violates the premise, but the cited p2a1 artifact does not test it.

**Scenario:** If an old VCB/SCB’s SOP storage were reused while an old file object or writable section still referred to it, a new post-create could encounter the same raw SOP address and replace the old map binding. Later SOP lookups for the old object could then resolve to the new entry while the old entry still owns writer state. That would be security-significant. On the other hand, if NTFS keeps the SCB/SOP alive for every such reference, the scenario cannot occur. The v2 names-only path itself is insulated: it does not change the SOP binding, and scoped names still fail closed at the exact-SOP activation open. Keep this as an explicit, target-build precondition rather than treating the public SOP documentation as proof of lifetime.

## Requested checks

1. **File identity, streams, and mounts.** For a normal stream on the same pinned `PFLT_INSTANCE`/`PFLT_VOLUME`, file ID plus volume serial is suitable for asking which base-file hard links exist. A hard-link name is a name for the base file; its folder-scope result is the same for each ADS. The noncompact ADS suffix is retained in the by-ID open. Compact entries resolve a suffix by hash, so a collision can select another ADS on the same base file; that does not change folder membership, and the later exact-SOP activation open fails closed if it selected the wrong stream. File ID alone is not a stream identity or a mount-generation token, but the open is issued through the entry’s pinned instance/volume and verifies the returned serial and full ID; a new mount is not silently substituted by the relaxed SOP check. Pointer ABA remains relevant only to the separate raw-SOP association premise above.

2. **Races, counters, and locking.** There is no retirement publication in v2, so the old v1 race about retiring an entry without rechecking H/W/T/rename/spills/C does not apply. Classification publication rechecks T/transaction version and per-entry rename state/version under exclusive `RegistryLock`; it does not recheck H/W/spilled writers/spilled mutating I/O/C because it makes no Free or retirement claim. If links classify scoped, `StageRegistryResolveAliasProbeForGeneration` publishes Activating before promotion checks. Activation and quiescence call the exact-SOP form; promotion also checks H/W/T, rename, spills, C, S, and empty cache pointers. Scope transition admission is drained before alias scanning, while new current/pending-scope writes and link/rename mutations are gated. The v1 create-reservation scenario therefore does not retire a live writer here; an unresolved identity remains gated/Unknown and prevents Ready.

   The new calls remain PASSIVE-level file-system probes. The classifier does not hold `RegistryLock` over file I/O or take `SectionLock`; the existing association order is RegistryLock then SectionLock. I found no new lock inversion or IRQL issue.

3. **Activating semantics.** There is no retirement path to bypass Activating. A present scoped hard link makes `unionScoped` true and resolves the alias probe to Activating when the entry has no sticky Unknown reason; otherwise it stays Unknown and gated. Activation then requires the recorded SOP. A changed SOP at that later step becomes Unknown and blocks Ready. If the hard-link query proves only out-of-scope names, clearing the alias gate is correct even if H is live, because that writer has no name in the protected folder. If the file-ID open cannot prove the identity or links, the entry stays fail-closed.

4. **`STATUS_MORE_ENTRIES` and buffer safety.** A partial scan stores `ScopeScanNextLink`, link count, and accumulated scope bits at 4715-4721. The reclaim worker sees either `ScopeScanPending` or `AliasProbePending`, resets its cursor to the first unfinished entry, and queues another pass (5776-5816). A T race is retried by the transaction terminal callback. Persistent churn can keep the bounded worker retrying and delay later entries, but the entry remains pending/gated, so this is a liveness failure rather than false Ready. The `links->EntriesReturned` read at 4717 is guarded by `noRemainingNames`: both pre-query `PublishResult` paths set that flag; every other route reaches publication only with a successfully allocated and validated link buffer.

## v1 scenario disposition and evidence

- **v1 P1 hard-link escape:** fixed. The reopened object is no longer mislabeled “nameless” because its SOP differs. The code queries and classifies its actual hard-link list. A scoped result reaches Activating, then exact-SOP activation can only succeed for the recorded incarnation.
- **v1 P1 retire-versus-writer/reservation race:** removed with the retirement behavior. The names classifier does not retire/publish Free. Any scoped/uncertain candidate stays behind activation/Unknown gates.
- **v1 compact-ADS collision:** not a folder-scope escape here. A collision can select the wrong ADS on the same base file, but all ADS share that base file’s hard-link paths; exact-SOP promotion still refuses a wrong stream.
- **v1 directory-rename publication concern:** the classifier itself does not recheck directory-rename ranges at publication. However the scope transition drains prior callbacks, current/pending-scope rename destinations are denied, and `StageRegistryActivationProcess` refuses to process an entry while its retained path intersects a live directory-rename range. I found no concrete route from this omission to Ready under those gates.

The supplied p2a1 artifact supports the reported symptom: one `MountPointManagerRemoteDatabase` entry has H/C/T/W=0, Unknown(ID), and OpenById failure; admission coverage has one unknown/not-ready entry and Degraded state. It does not prove SOP lifetime with a live handle/view or demonstrate that v2 now reaches Ready.

## Sources consulted

- [Microsoft: SECTION_OBJECT_POINTERS](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_section_object_pointers) — one structure per stream; members are opaque; no lifetime rule.
- [Microsoft: BY_HANDLE_FILE_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information) — NTFS file IDs persist until deletion; file IDs are not guaranteed unique over time.
- [Microsoft: FILE_DISPOSITION_INFORMATION_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information_ex) — POSIX deletion removes the visible link while existing handles can still access stream data.
- [MS-FSCC: FileHardLinkInformation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/46021e52-29b1-475c-b6d3-fe5497d23277) — the query returns hard-link names and requires at least one name.

