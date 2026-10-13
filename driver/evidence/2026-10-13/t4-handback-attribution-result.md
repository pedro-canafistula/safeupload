# T4 hand-back attribution diagnostic — `m2t4hbdiag1` (2026-10-13)

Owner-authorized, harness-only and **non-qualifying** ([owner direction](../../POST-MVP-PLAN.md#owner-decisions)). Harness
`e642e212`; unchanged pair k11 `EBDFCE54…C851` and agent `6198eee7` archive `21F725DD…93F`, both hashes verified before boot
([pair](m2t4hbdiag1-pair.txt)). win10-debug3 only, boot Verifier, 2,000 cycles, three in four blocked.
[Verdict](m2t4hbdiag1-verdict.txt); separate restoration `T4IndependentRestoration=PASS` ([host log](m2t4hbdiag1-host.txt)).

## Result

All 2,000 outcomes passed (500 approved, 1,500 blocked hand-backs); no blocked bytes published; versions, views, tombstones
and stage files released; worker idle; Ready returned after idle. Live `SUfl` allocations (224-byte stream contexts):

| Sample | Live SUfl | Note |
|---|---:|---|
| start | 349 | |
| idle after 2,000 cycles | 4,773 | +4,424 |
| purged (existing gate step) | **583** | +234 above start, with 1,500 hand-backs still present |
| after deleting all 1,500 hand-backs | **2,670** | +2,087 (bytes +467,680 = 224.1 B each) |
| after a second purge | **2,633** | |

Restart Manager reported **no holder** for any of the 1,500 hand-backs, 2,000 journal manifests or 128 public files.

## What this shows

1. **The hypothesis is refuted.** With 1,500 hand-backs on disk the purge left only 234 contexts above start, so the 10k
   row's residual (2,377) is not the kept hand-backs.
2. **Deleting files adds retained contexts.** Deleting the 1,500 unheld hand-backs (outside protected scope, as SYSTEM)
   added 2,087 stream contexts — about 1.39 per deleted file — that a second purge did not release, although the files
   are gone and nothing holds them. `DELETE` access counts as writer access (`StageWriters.c:2530`), so each delete open
   gets a writer-tracked stream context.
3. **Consistent with the earlier rows.** Residual after purge versus the driver's own stage-file deletes: this row 234 for
   500 deletes; the 10k row 2,377 for 7,500 deletes (about 81 + 0.31 per delete). The 256-cycle smoke row (440 for 192)
   does not fit, so this is a lead, not a fit.

A source audit of the create-time writer paths (`StageWriters.c` success path, `TrackingLost`, `StageRegistryTrackUnknownWriter`)
found every `SafeUploadGetOrCreateStreamContext` reference released, and no `FltReferenceContext` on stream contexts. That
leaves two explanations to separate: the deleted files' streams are still alive below the filter (NTFS/Cache Manager
retention of closed, deleted streams that the memory-list purge does not reach), or a driver reference not visible in that
audit (cleanup-path or writer-node ownership).

## Next step implied by the drop

The drop was **negative**: deletion, not hand-back retention, is the attributable growth source. Next, without changing
`T4ContextsReleased`, any assertion or adding reclamation:

- Source: audit `SafeUploadStageWritersOnCleanup`, writer-node removal and the stream-context cleanup callback for a path
  that keeps a context referenced after its last DELETE handle closes (static, no VM).
- If the audit finds no driver reference: one read-only local-KD attribution row with the existing `T4_MEMORY_TOOLS`
  mechanism (as in `m2t4memdiag1`), deleting a fixed set of unprotected files and inspecting the retained contexts' streams
  (FltMgr context list, SCB/FCB state, file-object references). This is a new product VM row and needs owner authorization;
  the T4 stop on other rows remains.
