# T8: Word drop 2 — plan

**Status 2026-10-30:** W0 and W1/W3 done. Kernel `7f7d6b62` (m2w1k1030b) fixes Save As over an existing name. Word remains intermittent after a save (a Retained
superseded version, a rename roll-back meeting a pending prepare, a Read-Only reopen). Rows are stopped pending an owner decision; see
[the drop 2 record](../../../evidence/2026-10-30/m2mvp-word-drop2.md).

2026-10-29. **Plan, no implementation.** The owner chose to ship MVP drop 1 without Word and to deliver Word as drop 2. Drop 1 was qualified on
kernel/agent `8d6e8737` ([record](../../../evidence/2026-10-29/m2mvp-rows.md)). This plan uses
[T8-PUBLICATION-WINDOW.md](T8-PUBLICATION-WINDOW.md) (Increments 0/A/B/C) and the 2026-10-22 [discovery](../../../evidence/2026-10-22/t8-discovery-1.md).

## Goal and bar

The four Word cases in `t5/notepad-cases.json` (Save As to a new name, in-place edit, Save As over an existing published name, CPF hand-back)
must PASS. The bar is the same as drop 1: ordinary and runtime Verifier on one new matched pair, with separate restoration. Because the kernel will
change, A/C/D and Excel B must also PASS again on that pair. There are no gate or assertion changes.

## State on `8d6e8737` (Office diagnostics mvpBWdiag9–15)

| Case | Result | What is known |
|---|---|---|
| Save As to a new name | PASS 2 of 3 runs | In mvpBWdiag15 one version ended `Retained` (Sealed → Retained, no inspection). This was the `~WRD0000.tmp` version renamed onto `word-saveas.docx`, with a committed rename receipt. A second version published. The run left one stage file and one hot-journal entry. |
| In-place edit | PASS | Works since the owner reopen wait (`101da975`). |
| CPF hand-back | PASS | Shows Read-Only after the block, because the hand-back copy grants read only (by design). |
| Save As over an existing name | **FAIL, deterministic** | `0x800A156F` file permission error. Ring: every open of the name by Word (and by Explorer) returns `STATUS_DELETE_PENDING` for about 0.4 s; then Word's rename of `~WRD0000.tmp` onto the name returns `STATUS_OBJECT_NAME_COLLISION`. On 2026-10-22 it also failed with Windows Search stopped and after forced section trimming, with no process handle visible to Restart Manager. |

Two facts are not proven:

- **Who returns the collision.** It could be NTFS, because the old file is physically delete-pending, or the driver's staged-rename path (`StageRename`).
- **What keeps the old name alive after Word's delete.** Candidates are the driver's public backend or proxy object (`StagePublic.c`), a memory-manager section reference on the old public file, or the agent.

The mvpBWdiag15 openability watcher cannot answer either question. Its PowerShell job started after `SaveAs2` had already failed, so it saw only the rolled-back file.

## W0 — capture both blockers (diagnostic only, dev loop on the Office base)

1. **Fix the watcher.** Start it and wait for its ready signal before `SaveAs2`. Poll every 5 ms, and record status plus the file ID for both `word-overwrite.docx` and `~WRD0000.tmp`.
2. **Native control.** Run the same Word overwrite in an unprotected control folder on the same volume. This gives Word's native sequence: delete or rename-to-backup, the replace flag, and when the name frees.
3. **In-box trace.** Run the same case under WPR (`wpr -start FileIO`, in-box on 19045), protected and control. The goal is Word's exact `IRP_MJ_SET_INFORMATION` classes, the `ReplaceIfExists` and POSIX flags, and the result of each operation. There is no third-party install, and the overlay is disposable.
4. **Driver snapshot.** At the collision, take `stage-streams` (command 37, now fixed) and the counters. This records live streams, views, FileObjects, section pointers and backend count for both names.
5. **Retained flake.** Repeat Save As to a new name about 10 times. Collect the service log reason for Sealed → Retained, and the order of seal, rename prepare and rename commit for the `~WRD0000.tmp` version. Check whether the synchronous commit send (`8d6e8737`) changed that order. Sealed → Retained without inspection has a few known routes: stage open `IOException`, identity or length mismatch, metadata refusal, and out-of-scope extension.

**Exit:** one written finding per failure, naming the operation, the object and the code path, recorded in `evidence/2026-10-30/`.

## W1 — Save As over an existing name (kernel; the fix depends on W0)

| W0 finding | Fix |
|---|---|
| A driver-held public backend or proxy object keeps the deleted name alive | Close that hold when the app handle that set the delete is cleaned up (`SafeUploadStagePublicCloseBackend` already states the rule "never leave the driver's own public hold preventing the last close"). This is a lifetime fix with no semantic change. |
| A memory-manager section on the old public object | Increment C territory. The only allowed step is to force the data section closed when there is no user mapping, no writable section and the paging rundown is released (`MmCanFileBeTruncated`). This needs its own short design note. |
| NTFS correctly keeps the name delete-pending until Word's own handles close, and Word renames before that | The staged rename onto a name the same process has delete-tombstoned is admitted as a replace in the driver namespace. Publication later replaces the public file atomically. This keeps the T5 rule: only an already-published successor cancels the delete; if the successor is Blocked, the delete applies and the name ends absent, as for a native delete. |

For every route, Word must see native results: the rename succeeds, and the reopen returns the new private version, not the deleted object.
Nothing uninspected becomes public. A Blocked successor leaves no old bytes under the name after a confirmed delete.

## W2 — Retained rename version (agent, possibly driver ordering)

Fix the route W0 names. If a version is retained before its rename into scope commits, the committed rename must trigger re-inspection
("renaming into scope re-inspects"). It must never leave a stage file or journal entry once Word has exited. Add a deterministic host control that
reproduces the order seen in mvpBWdiag15.

## W3 — fold in the drop-1 review notes (same kernel patch)

These come from the 2026-10-29 adversarial review of `28f67174..8d6e8737`:

- Skip the 10 s reopen wait when the blocking state is a service wait or the service is unavailable.
- Recheck `View == NULL` / `Detached` / `Current != Stream` in the wait's not-busy test.
- Queue the stream after every reopen-wait unpin, as before.
- Add one Verifier row with the agent paused during a rename, to measure the synchronous commit send.

## W4 — qualification

1. **Review.** The kernel patch (W1, W3, and any W2 ordering change) gets one independent review before its first boot. The AGENTS.md policy applies again after 2026-10-29.
2. **Gates.** Exact kernel build (two feature builds, PREfast, ApiValidator, imports, all at 0/0), four-leg agent matrix, and the PS 5.1 harness gate. The harness changes are the W0 watcher and the WPR capture, both kept diagnostic-only.
3. **Stability before rows.** The Word cases pass 3 consecutive Office diagnostics in the dev loop. This is a diagnostic check, not a gate.
4. **Rows on the new pair.** Run W ordinary and runtime Verifier (`T5_OFFICE_BASE=1 T5_OFFICE_APPS=Word`), plus the regression rows: A/C/D and Excel B, each ordinary and runtime Verifier. Every row gets restoration.
5. **Close.** Run a short adversarial review of the pair, then update the status plan and deliver the pair hashes.

## Order and rough cost

| Step | Estimate |
|---|---|
| W0 | about half a day, mostly VM time |
| W1 | half a day to 2 days, depending on which row of the W1 table W0 selects (the last two need a design note and review first) |
| W2 | about half a day |
| W3 | an hour, inside the W1 patch |
| W4 | about a day of builds and rows: matrix about 70 min, 6 pairs of rows about 15 min each |

Decisions for the owner arise only if W0 selects the third row of the W1 table, which changes delete/successor ordering, or a section-closing rule (Increment C).
Each comes with a recommendation.
