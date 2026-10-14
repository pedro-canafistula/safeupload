# T4 KD delete-attribution row — `m2t4delattr1` (2026-10-13)

Owner-authorized, **non-qualifying**. Harness `503e4801`; unchanged k11 `EBDFCE54…C851` and agent `6198eee7` archive
`21F725DD…93F`, private PDB and debugger archive hashes recorded before boot ([pair](m2t4delattr1-pair.txt)). win10-debug3
only (win10-debug2 off), boot Verifier, 256 cycles, then the delete corpus. [Verdict](m2t4delattr1-verdict.txt);
separate restoration `T4IndependentRestoration=PASS` ([host log](m2t4delattr1-host.txt)). Launcher exit 24
(`memory-teardown-failed`, see below).

## Result

256/256 outcomes passed; no blocked bytes published; versions, views, tombstones and stage files released.

| Sample | Live SUfl | Note |
|---|---:|---|
| start / idle / purged | 554 / 1,033 / 515 | ordinary 256-cycle row |
| del-baseline | 728 | 256 corpus files written and closed by SYSTEM, then purge + 30 s |
| del-after | 582 | all 256 deleted (no errors), + 30 s |
| del-after-purge | 566 | second purge + 30 s |

Deleting files whose contexts were still attached **released** them (728 → 582 → 566; 51 above the pre-corpus purged
level). In `m2t4hbdiag1` the hand-backs' contexts had already been released by the first purge, and deleting them
**added** 2,087 retained contexts. The difference points at the delete opens creating new contexts on streams NTFS had
already torn down, and those contexts surviving the deletion — not at deletion itself.

## What failed

- **KD attribution produced no identity data.** Pass 1 of every snapshot stopped at a harness syntax error: a `.if`
  condition used C++ `&&` and `->` inside the MASM evaluator ("Numeric expression missing", stdout line 1697). KD then
  waited at its prompt until the 180 s kill, so the anchor census and `!poolfind SUfl` never ran. Earlier commands did run
  (layout: pool header 0x10, FltMgr context node 0x60, stream context 0x68 bytes).
- **Voluntary unload was refused** in the diagnostic memory teardown (`fltmc unload SafeUpload`), unlike `m2t4memdiag1`
  with the same driver. Not yet explained; it may be an outstanding object or obligation and is itself attribution data.

Raw KD scripts/stdout and summaries are retained locally under `m2t4delattr1-memory/`.

## Next step

Fix the harness offline (C++ evaluator for every compound condition, one KD session per command block so a failure
cannot lose the rest, explicit teardown-veto capture), pass the Windows PowerShell 5.1 gate, and **ask the owner** before
a second row: the authorization covered one row. No gate, threshold, assertion or reclamation change.

## Row 2 — `m2t4delattr2` (harness `a22a604a`)

256/256, restoration PASS, launcher exit 0 (voluntary unload succeeded this time). [Verdict](m2t4delattr2-verdict.txt),
[pair](m2t4delattr2-pair.txt), [host log](m2t4delattr2-host.txt).

| Snapshot | Live SUfl | FltMgr logical outstanding / pool storage | Activation anchors |
|---|---:|---:|---:|
| del-baseline | 764 | 723 / 725 | 0 (walk complete) |
| del-after | 563 | 539 / 541 | 0 |
| del-after-purge | 527 | 525 / 529 | 0 |

- **The activation anchor is ruled out** as the owner: the census completed and found none.
- **These are live FltMgr stream contexts**, not lookaside caching: logical outstanding equals pool storage within 2–4.
- Deleting files whose contexts were attached again released them. Newly written files kept their contexts through a
  purge (baseline 764 vs 517 before the corpus), so the purge does not tear down recently written streams.
- The per-block identity walk saw no blocks: `!poolfind SUfl 0` uses an older syntax this debugger rejects (it printed
  usage). The hand-back scenario of `m2t4hbdiag1` — files whose contexts the purge had already released, then deleted — was
  not reproduced by this corpus design.

Next: row 3 combines the hand-back deletion with the KD snapshots (`!poolfind SUfl`), so the contexts created by deleting
already-released files are walked to their stream, FILE_OBJECT and control-area owners.

## Row 3 — `m2t4delattr3b` (harness `38e42a09`)

Hand-back deletion with the KD walk, block-heavy mix (`T4_HANDBACK_DIAGNOSTIC`), unchanged pair ([pair](m2t4delattr3b-pair.txt)),
restoration PASS, launcher exit 24 (voluntary unload refused, veto `CLIENT` / `0xC01C0010`, last recorded only).
[Verdict](m2t4delattr3b-verdict.txt), [host log](m2t4delattr3b-host.txt). The first attempt `m2t4delattr3` stopped before boot
because the main disk had 14 GB free (15 required; [receipt](m2t4delattr3-host.txt)); `3b` placed its run overlay on the Storage HDD.

| Sample | Live SUfl | Note |
|---|---:|---|
| start / idle / purged | 608 / 1,881 / 548 | the 192 hand-backs' contexts were released by the gate purge |
| del-baseline | 999 | after the harness's metadata-only identity opens of the 192 hand-backs, then purge + wait |
| del-after | 841 | all 192 deleted (no errors) |
| del-after-purge | 821 | second purge |

- **Growth follows opens, not deletes.** Opening already-released files only for their identity created 451 contexts
  (≈2.35 per file) that survived a purge; deleting the files then released 158. In `m2t4hbdiag1` the delete opens were the
  first opens after release, hence the growth attributed to deletion. With no handle holder (Restart Manager), no activation
  anchor (row 2) and balanced driver references (static audit), the leading hypothesis is stream lifetime below the filter:
  NTFS keeps closed files' FCB/SCB (and so the filter's stream contexts) until its own teardown, which the memory-list purge
  does not force. A driver reference outside the audit is not excluded.
- **KD identity walk impossible this way.** Under local KD on 19041, `!poolfind SUfl` scans only the large-pool table and cannot
  read segment-heap page segments (363 read failures), so the 224-byte blocks were never found and each pass hit the 180 s kill.
  Rows 2 and 3 both failed to identify blocks, by different causes; no further `!poolfind` row under local KD.
- **Two required assertions failed (non-qualifying row; first failure preserved).** `T4CyclesCompleted` 255/256: cycle 35
  (replace, approve) got `CreateFile Win32=5` on its new temporary file because the service answered allocation request 761
  after 18.8 s (`ERROR_FLT_NO_WAITER_FOR_REPLY`); the kernel had stopped waiting and refused the create. No bytes were
  published and every version, tombstone and stage file was released. Eight NO_WAITER replies occurred (rows 1–2: none); save
  acknowledgments had median 867 ms versus ~135 ms in rows 1–2, max 10.1 s. `T4PoolEndpoint`: idle driver nonpaged bytes
  6,489,352 versus limit 6,456,376 (rows 1–2: 6,426,328). Hypothesis: the HDD-backed overlay (with the block-heavy mix) slowed
  service I/O beyond the kernel's allocation wait. This incidentally exercised the allocation-reply fault path under protection,
  failing closed, but does not qualify it.

Next, without any gate, threshold or assertion change: keep T4 run overlays on the main disk (timing-sensitive rows), and
separate stream lifetime from a driver reference with a volume-teardown discriminator instead of KD pool walks — run the
hand-back open/delete sequence on a VHD-backed NTFS volume inside the guest, then detach it. Contexts released by the
dismount point at NTFS stream retention; contexts that survive it point at a driver reference.

## Row 4 — volume-teardown discriminator `m2t4vol1` (harness `4b7e5d82`)

Unchanged pair ([pair](m2t4vol1-pair.txt)), win10-debug3, boot Verifier, 256 cycles, run overlay on the main disk; restoration
PASS. [Verdict](m2t4vol1-verdict.txt), [host log](m2t4vol1-host.txt). Launcher exit 1 (one required assertion failed, below).

| Sample | Live SUfl | Step |
|---|---:|---|
| vol-s0 | 462 | after the existing purged sample |
| vol-s1 | 521 | 512 files written on a fresh 1 GB VHD NTFS volume (filter attached), VHD detached |
| vol-s2 | 551 | VHD reattached (filter attached), metadata-only open of all 512 files |
| vol-s3 | 546 | first 256 deleted |
| vol-s4 | 546 | VHD detached |

- **Classification `Inconclusive`: the growth did not reproduce on a plain NTFS volume.** 512 metadata-only opens of files whose
  streams the detach had torn down retained only 30 contexts (row 3 on C:: 451 for 192 hand-backs). Retention is therefore not a
  property of every open of a released stream; it depends on the C: files involved (location under the actor's profile, how the
  service created them, extra streams, or other openers there). The 59 contexts between s0 and s1 belong to C: activity while the
  VHD was absent, not to the volume.
- **`T4CyclesCompleted` 255/256 again, on the main disk.** Cycle 187 (replace) reached its outcome after 73 s; cycle 188 (mapped,
  approve) got `CreateFile Win32=5` after 13.6 s. The service answered staged requests 1833 (13.1 s) and 1836 (20.5 s, allocation)
  after the kernel's wait ended (`ERROR_FLT_NO_WAITER_FOR_REPLY`), after a 67 s gap with no service events. The kernel refused the
  create; no blocked bytes were published and every version and stage file was released (all other assertions PASS, including
  `T4PoolEndpoint`). The builder's kernel build ended about 50 s before the stall. This is the historical allocation-reply delay
  ([diagnosis](../2026-10-12/t4-allocation-reply-diagnosis.md)); the pair's phase log (`handler=20535.8`) cannot locate the wait.

Next, without a gate, threshold or assertion change: (1) trace the allocation handler's phases (journal lock wait, backing creation,
manifest scan, journal write/flush) before another protected T4 row, and keep builder jobs off the host during timing-sensitive rows;
(2) repeat the open/purge comparison on C: with the same population in and out of the actor profile and with/without the service's
hand-back creation path, to find what makes those streams outlive the purge.
