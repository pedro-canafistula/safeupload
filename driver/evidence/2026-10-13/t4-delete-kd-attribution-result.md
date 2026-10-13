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
