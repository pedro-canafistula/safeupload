# Adversarial review: `c1086343` + `3c730996` + `2d471fa9`

**Verdict: REJECT — one P2 predicate/evidence gap; no P0/P1 bypass found in the alias-refusal defense.**

Read-only source review. I inspected the requested commits/diff, the writer-state design and MVP plan, the prior reports, and the supplied C01/C04 artifacts. No VM was available and I did not run tests. The supplied runtime evidence shows the original readiness failure, but does not exercise the new replacement-incarnation CAS or its sibling predicate.

## Findings

### P2 — The `0x20` path does not establish file-wide Free when a sibling stream has a writable view

**Location:** `driver/SafeUpload.Minifilter/StageWriters.c:4986-5000, 5324-5337, 5541-5548, 5574-5591, 5065-5079`; basis comment in `driver/SafeUpload.Minifilter/Protocol.h:1119-1121`.

The new sibling walk checks H/W/T, rename, spilled writers/mutating I/O, C, and Unknown on each listed row, including compact ADS rows. It does not query `MmDoesFileHaveUserWritableReferences` or cache state for those sibling SOPs. The `MmDoes...` and flush/purge checks at activation time apply only to the reopened live base-stream SOP. That proves the base stream’s current S/cache state; it does not prove all streams sharing the file ID are writer-free, despite the sibling walk and `0x20` comment making that broader claim.

**Scenario:** Before scope application, a standard user opens `F:meta` for write, creates a writable section and keeps a mapped view after closing the file and section handles. The compact or named-stream registry row for `F:meta` remains listed and scoped, with H/C/T/W and Unknown clear but S still YES on its ADS SOP. The base-stream row A later loses its old SCB. Its fallback reopens the base file as SOP P, observes S(P)=NO and an empty base-stream cache, then the sibling helper sees zeros on the ADS row and promotes A with `0x20`. A pre-scope writer view still exists for the same file ID, but the helper never samples it.

This does **not** show a Ready escape: the ADS row should remain Activating because its own promotion checks S on its own SOP, so aggregate coverage should stay pending/degraded until that view is gone. It does make the purported file-wide `0x20` proof false and permits a Protected transition while a pre-scope writer to a scoped stream of that file remains. If the intended rule is strictly per-stream, then this promotion can be valid for the base stream, but the identity-wide sibling claim and protocol comment must be narrowed to that meaning; the current code checks siblings across named streams while omitting their S/cache state.

**Disposition:** either make the CAS predicate include the relevant sibling-stream S/cache proof, or define this basis as “the replaced base-stream incarnation is Free” and rely explicitly on each ADS row’s own activation gate. Do not treat current `0x20` as evidence that the whole file identity is Free.

## Requested attack checks

### 1. Writer state and identity

- A pre-scope writer on a second entry keyed by the live **base-stream SOP** can exist while A’s own counters are zero. `StageRegistryFindByKeyLocked` keys on SOP (`StageWriters.c:1037-1052`), so this is a real separate row. The new walk catches its H/W/T/rename/spilled/C/Unknown state. For an existing writable section on that same live base SOP, the activation path also samples `MmDoesFileHaveUserWritableReferences` on the reopened object. A standard-user create that began before the scope transition is covered by the admission epoch through post-create; new creates after the scope is current are gated before writer reservation.
- A standard-user writer opened after the old base SCB died but before scope application creates or binds the live-SOP row. It is included in the scope inventory and its H/T/C/S keeps its own row pending. The identity-wide recheck sees ordinary live counters. This is not the same as A’s own zero counters.
- The base-stream-only restriction excludes compact ADS entries from the relaxed reopen (`StageRegistryEntryIsBaseStream` and the `CompactStream`/`StreamChars` checks). That avoids resolving a compact suffix hash to a different stream. Compact and noncompact ADS siblings are still included in the walk, with the S omission above.
- Hard-link aliases are checked independently of registry state for a new out-of-scope writer open. `StageAdmit` treats `FILE_WRITE_ATTRIBUTES`, `DELETE`, other write rights, and overwrite dispositions as writer access (`StageStream.c:2607-2613, 2737-2744`). By-ID writer opens run `SafeUploadStageWritersClassifyById` and fail closed for scoped or undecidable identities (`StageStream.c:2624-2673`; `StageWriters.c:4764-4864`).
- TxF T and per-file rename state are part of the sibling predicate. Destination names in current or pending protected scope are refused for link/rename operations (`StageStream.c:2883-2888`); unresolved relevant operations fail closed. Instance/volume references and serial/file-ID checks bind the reopen to the pinned volume instance, so I found no dismount/remount substitution in this path under the stated target-build premise.
- Reclaim’s by-ID probe requests only `FILE_READ_ATTRIBUTES` and is issued below this filter through the pinned instance (`StageWriters.c:3951-3961, 4191-4201`). It cannot create a user writer entry or itself contribute H/W/T/C.

### 2. Reopen, S/cache, rebound check, and CAS races

The relaxed file-ID open happens without registry locks, and the held file object keeps its live SOP available through S/cache evaluation and the CAS attempt. The final `Entry->SectionObjectPointer != ReplacedLiveSop` predicate is under exclusive `RegistryLock` and `Entry->StateLock`; `StageRegistryAssociateSectionPointer` takes `RegistryLock` before `SectionLock`, so the old entry cannot rebind to that captured live SOP between the check and CAS. The main entry’s H/W/T/rename/spill/C predicates are rechecked at CAS, and `StageRegistryTryPromoteStateNoInline` rechecks marker generation and section slots under `SectionLock`.

For standard-user same-base-stream writers, the earlier live-SOP S/cache sample is not an evident bypass: section acquisition reserves C before its name/SOP gate (`StageStream.c:3554-3567`), ordinary write handles have H before they can create a writable section, and post-scope opens through an outside alias are refused. The remaining CAS-time gap is sibling-stream S/cache, described above; `RegistryLock` does not make those MM state samples atomic because they are not sampled at all.

The sibling walk follows RegistryLock → SectionLock, matching the existing promotion/map order. It performs bounded in-memory snapshots at APC-or-lower IRQL and holds no filesystem open across the lock. It skips Retired rows; under the stated SOP-lifetime premise, retirement requires the old row to be quiescent, so that skip is reasonable. A persistent writer handle or transaction on any included sibling keeps `siblingsFree` false indefinitely. That is fail-closed and consistent with “no timers”; a read-only handle does not increment H and does not block. A truly long-lived trusted service write handle would likewise delay readiness; the code does not bound that lifetime.

### 3. Promote versus retire

Keeping A behind its activation gate, promoting it only after the stale-incarnation proof, then allowing reclaim to prune it is reasonable for the **base stream**. A live-SOP row remains independently keyed and gated, while the name-based alias refusal protects later standard-user opens even if that row was created after the scope inventory. Immediate retirement would remove A’s admission/coverage row without recording this proof. This semantic choice is sound only with the narrower per-stream meaning above; it does not turn A’s CAS into proof that every named stream with that file ID is Free.

### 4. Alias refusal, receipt, and harness

I found no concrete standard-user bypass of the new alias-refusal argument:

- `SafeUploadStageCheckNamedAliases` strips the ADS suffix, opens the named base object read-only/share-all, and checks the full hard-link list (`StageAlias.c:140-170, 91-137`). Any non-success status is denied by `StageAdmit`; `IoGetTopLevelIrp()!=NULL` returns access denied; more than 64 links, partial/inconsistent enumeration, allocation/query failure, and oplock failure therefore fail closed. `FILE_COMPLETE_IF_OPLOCKED` avoids waiting on an oplock, and `IO_STOP_ON_SYMLINK` makes unresolved reparse redirection a failure rather than a negative alias result.
- A new protected hard link cannot race past this check through ordinary `FileLinkInformation`/rename: destination names in current or pending scope are denied. A link/rename that began before scope publication is covered by the admission epoch and scope drain. A read-only open can avoid the alias check, but access rights are fixed at open; it cannot be upgraded to a writable file handle, and writable section creation has its own C-before-gate path (`StageStream.c:3152-3189, 3554-3567`). I found no standard-user path from that read-only handle to a writable section.
- Long names and ADS paths still classify the base object; hard-link enumeration is by parent ID and leaf, not a retained alias path. A compact ADS cannot be selected by the replacement fallback. Admin/SYSTEM or another kernel component below the filter is within the stated trusted boundary.

`0x20` lets a reader identify that the replaced-incarnation branch reached CAS. It is not an independent receipt of the reopened SOP or sibling census: the trace’s `SectionObjectPointer` is read from A, while `LastSState` was set from the live SOP; sibling values are not recorded and the snapshot is explicitly noncoherent. The script accepts the new bit in its existing `0x3f` mask and the self-check has a positive `0x20` fixture, so there is no trace-layout/ABI break. The main promotion assertion still does not require `0x20` on this path or validate the live-SOP/sibling relationship (`Test-StagedInvariantSuite.ps1:3912-3916, 4328-4334`). Thus the label is recognizable, but the harness cannot detect the predicate gap found above.

## Overall

The P1 live-SOP hard-link admission gap from the second review is closed for standard users by the pre-create alias refusal, with by-ID, uncertainty, and concurrent-link paths failing closed. The remaining P2 issue is that the new identity-wide basis is broader than its S/cache proof. The C01 artifact motivates the fallback but does not verify this new CAS on Windows 10 19045.2965.
