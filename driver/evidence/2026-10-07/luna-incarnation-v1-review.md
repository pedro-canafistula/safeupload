# Adversarial review: `c108c607`

**Verdict: REJECT**

The change has a useful distinction—old SOP incarnation versus current stream identity—but publishes that distinction as “no names.” A different SOP can mean NTFS tore down the prior SCB after its last users closed while the same file and all its hard links still exist. The new path then skips the hard-link query and removes the entry from scope coverage without classifying the reopened stream. A standard user can later write through an out-of-scope hard link to bytes also named inside the protected folder.

## Findings

### P1 — SOP change is published as proof of no names; a live hard-link alias escapes activation

**Location:** `StageWriters.c:4210-4217, 4524-4539, 4715-4763, 5419-5438, 5183-5193, 6811-6825`.

On a successful by-ID open, the file object has the same volume serial and file ID, but a different SOP. The new branch sets `noRemainingNames = TRUE` and jumps straight to publication, without querying `FileHardLinkInformation` on that live file object. The activation worker then treats the result as outside; the alias resolver clears `AliasProbePending` and `ActivationEnforced` for the negative classification. If the entry still carries an identity Unknown reason, that reason remains, but admission coverage skips it once activation is no longer enforced.

**Scenario:** A tracked file has an out-of-scope name and a hard link in a folder that is about to become protected. Its old writer closes; NTFS releases the old SCB but leaves the file and both names. During scope apply, the by-ID open creates/returns a fresh SOP for the same stream. This code classifies it as nameless/outside instead of probing its links. After coverage reports Ready, a standard user opens the old out-of-scope name for write. The fresh SOP does not resolve to the old SOP slot, and a fresh registry entry is keyed to that SOP and outside name. The write changes the same bytes reachable through the protected hard link.

A changed SOP can support “the old SOP allocation is no longer the current one,” assuming the NTFS lifetime premise holds. It does **not** support “the file has no names,” “the file has no protected aliases,” or “the replacement SOP has no writers.” Do not route this case through the no-names result.

### P1 — Publish recheck only covers the old entry; a replacement-SOP writer/reservation can pass beside it

**Location:** `StageWriters.c:1033-1047, 1132-1204, 4733-4753, 3736-3762`.

The recheck samples the old entry’s H/W/T, rename fields, spilled counters and C. It does not inspect unbound create reservations or writer/section state associated with the live SOP returned by the by-ID open. The claimed “writer that rebinds the entry meanwhile” is not the normal new-SOP path: `StageRegistryFindByKeyLocked` requires the SOP pointer to match, so a post-create using the replacement SOP does not find the old entry; `StageRegistryGetOrInsert` creates another entry. `StageRegistryAssociateSectionPointer` can rebind only an entry already supplied to it.

**Scenario:** During the scope scan, a standard-user create through an out-of-scope hard-link name has inserted its pre-create reservation but has not completed post-create. The reservation is not bound to the old entry yet. The by-ID open sees the replacement SOP. At publication, the old entry still has zero H/W/T/C and zero old-SOP spilled counts, so the recheck passes. Post-create then inserts a second, unscoped entry for the replacement SOP; the scope-apply list walk has already passed. Once the reservation is removed, coverage can be Ready while that writer remains outside activation. This is also why the exclusive `RegistryLock` does not make the recheck identity-complete: it serializes old-entry binds, but not state on a distinct SOP-keyed entry.

### P2 — The NTFS lifetime premise is plausible but not established by the cited evidence or public contract

**Location:** `StageWriters.c:4212-4217` (new use); existing premise at `StageWriters.c:3736-3739`.

Microsoft documents that there is one `SECTION_OBJECT_POINTERS` per file stream and that multiple file objects for a stream use the same pointer. It also says the file system allocates the structure and that its members are opaque. That documentation does not define when NTFS frees the containing SCB/SOP, which references keep it alive, or teardown behavior during dismount/remount. The same-mount `PFLT_INSTANCE`/`PFLT_VOLUME` arguments reduce cross-VCB ambiguity, but serial plus file ID alone is not a mount-generation identity. Inequality is conservative for pointer-address ABA (same-address reuse would miss this branch); the larger gap is that an old stream can be reopened with a fresh SOP while its file ID and names remain live. Compact ADS entries add ambiguity: `StageRegistryResolveCompactStream` selects a stream by 64-bit FNV suffix hash only (`StageWriters.c:646-668, 4074-4087`), so a collision can make the comparison refer to another ADS.

The cited boot evidence confirms the readiness symptom, not the new proof: `ready-timeout--activating-status.out` shows the MountPointManager entry with H/C/T/W zero, S Unknown, identity Unknown and OpenById failure; `ready-timeout--admission-coverage.out` shows one unknown writer entry and Degraded coverage. It contains no SOP comparison, hard-link inventory, or evidence that a live replacement stream has no scoped names.

References: [Microsoft SECTION_OBJECT_POINTERS documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_section_object_pointers), [MS-FSCC NTFS Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c54dec26-1551-4d3a-a0ea-4fa40f848eb3).

## Requested race and worker checks

- The publish-time check covers the old entry’s H/W/T, per-entry rename version/in-flight state, old-SOP spilled writer/mutating-I/O counts and C slots. Under the asserted “old SOP is gone” premise, old-SOP S cannot be queried safely; however, the live replacement SOP’s S and other entry state are not checked. The check does not include pending create reservations or directory-rename ranges. Directory rename state is checked before the scan at `5371-5385`, but not at publish; only a later directory-rename completion can rewrite names and queue a new probe.
- Lock order and IRQL look consistent: this classifier runs at PASSIVE_LEVEL; publication holds RegistryLock then samples SectionLock-backed state, matching the existing RegistryLock-to-SectionLock order in association/pruning. I found no inversion or elevated-IRQL access in this added path.
- `STATUS_MORE_ENTRIES` is re-run: the new deferral resets `ScopeScanNextLink` to zero and sets `ScopeScanPending` (`4747-4753`); the reclaim worker notices pending work and requeues from the first unfinished sequence (`5817-5822, 5848-5858`). The null-`links` publication paths set `noRemainingNames`, so the conditional `ScopeScanLinkCount` read is protected. Persistent link-list churn may keep a scan pending (fail-closed); the new mismatch path itself does not establish that the names are gone.
- No tests or VM checks were run; this review was a read-only source/evidence review.
