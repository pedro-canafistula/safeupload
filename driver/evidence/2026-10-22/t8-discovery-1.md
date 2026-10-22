# T8 discovery 1 — native-parity sweep on the current pair (2026-10-22)

Dev-loop result, **not a qualification**. Pair under test: driver `29D6130E…` (m2t5d7k6) and agent `FB181402…` (m2t5a5), installed on win10-debug3's
retained Office dev disk with `dev-pair.sh` label `m2dev1022a` (loaded paths and hashes checked). Standard user `t5actor`, interactive session,
Microsoft 365 Apps 16.0.20326, 24 cases of `driver/scripts/t8/parity-cases.ps1`, each run in an unprotected control folder (DACL mirrored from
`C:\Protected`) and in `C:\Protected`. Raw: `t8sweep-v0full/` (first sweep, ring wrapped), `t8sweep-v1full/` (24 cases, ring read after every case),
`t8sweep-v1diag/` (6 diagnostic cases), `t8sweep-v1budgeton/` (5 cases, budget on). Per-sweep text: `verdict.txt`, `summary.txt`.
Budget **off** (`Interception:StageSpace:Enabled=false`) for v0/v1full/v1diag; **on** (the product default) for v1budgeton.

**Result (v1full): 22 of 24 cases differ from the control; `word-locked-open` and `shell-move-in-out` match it, and both still show driver refusals.** The deltas
group into eleven defects. None is a harness artifact after the fixture fixes (control DACL mirror, per-side source folders, per-run folder names).

## Defects (user-visible first)

| ID | What the user sees | Cases (v1full) | Evidence and mechanism | Owner/plan item |
|---|---|---|---|---|
| F1 | Every file the user saves into the protected folder is owned by **SYSTEM** (owner and group), not the user. The user then cannot change its permissions, and Properties shows SYSTEM. | 17 of the 24 cases (every case that leaves a published file) | `META … owner control …\t5actor protected NT AUTHORITY\SYSTEM`. `StagedPublicationSecurity` only compares; nothing constructs the descriptor yet. | T8 metadata contract (workstream D); owner decision 2026-10-16 already requires owner/group/DACL as Windows gives the caller |
| F2 | File attributes are not what Windows would give: published `.xlsx`/`.pptx`/some `.txt` carry **NotContentIndexed** (files drop out of Windows Search); extracted files turn `Normal`→`Archive`; a **ReadOnly** flag set right after saving is lost, so the file can then be written and deleted (control refuses both with access denied). | excel-*, ppt, zip-roundtrip, txt-cmd-ops, txt-attributes | `META … attributes`; txt-attributes `write-readonly`/`delete-readonly` ok in protected, win32:5 in control; `at2.txt` final `[Archive]` vs `[ReadOnly, Archive]` | T8 metadata (attributes revalidated at commit) |
| F3 | A file just created is **invisible to other programs for about 0.5–2 s**: a second process gets "file not found" for `type`, `copy`, `ren`, `move`, `icacls`, `Copy-Item` after a rename. Worse, `echo a > f` then `echo b >> f` from two commands **loses the first write** (protected file contains only `beta`; control `alpha`+`beta`). | txt-cmd-ops, txt-acl, txt-lifecycle, robocopy (re-run and mirror see different files) | Another process's CREATE finds no private view, goes native, and the name does not exist yet; an append then creates a new file. After a rename in the same process, gate 6 (pending RenameExchange) refuses even a READ_ATTRIBUTES open: ring `STATUS_SHARING_VIOLATION reason 17 aux 0x00010406 access 0x80`. | New: publication-window rule (below) |
| F4 | **Word: "Word cannot complete the save due to a file permission error"** on an in-place save or Save As over an existing file, a stray `~$` owner file stays, the document then reopens **read-only** (`readOnly=True` vs control `False`), PowerPoint "An error occurred while saving". Which save fails varies run to run (save 3 in v1diag, save 1 in v1full). | word-saveas-edit, word-inplace, word-overwrite, ppt-saveas-reopen | Ring around the failure: gate 6 `0x00010406` on the file Word saved seconds earlier (one FileObject still alive, rename exchange pending), then rename `SET_INFORMATION` sharing violation, `OBJECT_NAME_COLLISION`, and `OBJECT_NAME_NOT_FOUND` on the public name while the swap is in flight. Confirms the 2026-10-19 gate-6 analysis; the earlier ReadOnly symptom reproduces. | New: same publication-window rule; Word row of T8 |
| F5 | With the **product default (budget on) nothing can be saved**: even `Set-Content` of one line fails with a sharing violation after ~3 s. | all (v1budgeton) | `StageAllocate` takes 1.5–4.7 s (`prepare` up to 4.7 s, journal scan ~0.5 s) and the driver stops waiting at ~3 s. On the previous (old) pair the symptom was the whole-allowance grant: a second concurrent allocation gets "Not enough staging space". | T9 growing reservations and allocation latency; first fix |
| F6 | A 64 MiB file cannot be written: "There is not enough space on the disk." | large-file | Budget off caps the seed at 16 MiB (`MaximumSeedBytes`); budget on hits F5. | T9 |
| F7 | In the protected folder a **folder with content cannot be renamed or deleted** (even by an administrator), a folder cannot be moved in, and Copy of a folder leaves children the user cannot remove. Creating folders and files in them works. | folder-rename, folder-delete, folder-copy-move, folder-create (cleanup), zip-roundtrip | `CREATE STATUS_ACCESS_DENIED access 0x110080` on the folder, `0x100100` on children; win32:87. | T6 (pull rename/delete of folders into M2 — owner decision) |
| F8 | **Delete key in Explorer fails** (send to Recycle Bin): "The system call level is not correct"; nothing is restored from the bin. Cut and paste out works in the last run but failed in the first two. | shell-recycle, shell-move-in-out | Rename into `$Recycle.Bin\<SID>\` gets `SET_INFORMATION STATUS_SHARING_VIOLATION`; moves out get `STATUS_NOT_SAME_DEVICE` then a refused temporary rename in the unprotected target. | T5/T6 |
| F9 | Retained held transfers and refusal noise after a failed save: `Staged recovery holds C:\Protected\w2.docx … Retained … recovery_evidence_unavailable` (the user would see held items), `c1.txt` could not be removed afterwards ("used by another process"). | after F3/F4 | agent events in `t8sweep-v1diag/agent-events.txt`, `t8sweep-v1full/cleanup.txt` | follows F3/F4 |
| F10 | Object-ID FSCTL (`0x900C0`) is refused on `\Protected` up to 44 times per Word save; `FSCTL_SET_COMPRESSION`, `FileStatInformation (0x37)`, `QUERY_SECURITY` return NOT_SUPPORTED. Word and Excel tolerate all of them today. | every Office case | ring files; owner decision 2026-10-10 keeps object-ID writes refused in M1 | allow-list with rationale or make native; not a defect while apps tolerate it |
| F11 | Not a product defect: a PowerShell COM call with a `Join-Path` result spins at 100 % CPU inside `SaveAs2` (PSObject-wrapped string); fixed in the harness (`[IO.Path]::Combine`). | — | memory note | — |

What passes (step results equal): lock semantics while a document is open (`word-locked-open`: another process' write open, rename and delete behave as native), five
immediate Word reopens (read-only false), Excel save/reopen/in-place and PowerPoint save and reopen with budget off, shell copy in/out, text create/append/rename/truncate/delete within one
process, setting times (last-write preserved), PDF export, zip create/extract.

## Consequences for the plan

1. The dominant cause is a **publication window** (F3, F4, F8): for about a second after a save, the name is not natively visible and any operation touching it is refused
   or sees nothing. Native Windows has no such window. The fix is one rule in the driver, designed once and reviewed once: **an operation on a name with an in-flight
   publication waits (bounded) for settlement instead of failing, with the saving process's own open handles accounted for** (they are why the exchange cannot finish).
   This extends the 2026-10-19 reviewed owner-reopen idea (review verdict REVISE: zero FileObjects is not proof of progress) to non-owner processes, renames and metadata opens.
2. F5/F6 make T9 the **first** fix: without it the default configuration cannot save a text file on this guest.
3. F1/F2 are the metadata contract (workstream D); F7/F8 are folder and move semantics (T6), which the closure plan had postponed but everyday Explorer use needs.
4. Order of work becomes: T9 allocation/budget → publication-window rule (kernel, one review before the first boot) → metadata contract → folder/Recycle Bin → re-sweep.

## Limits of this result

Dev disk, retained state aside (staging and journal were set aside at install). Budget-on was exercised only on the same disk and only five cases, so F5's magnitude may differ
on a fresh disk; the old-pair "Not enough staging space" and the new-pair 3 s latency are two faces of the T9 defects. No case was repeated for variance except Word (F4 varies
by save). Browser download, robocopy `/MOV`, 7-Zip, Excel in-place under load and the `~$`-file lifecycle are not covered yet. Control DACL equals the protected folder's DACL
(checked by the launcher). No gate, threshold or assertion was changed.

## Owner decisions this result needs

1. **Publication window.** Recommended: an operation on a name whose publication is still in flight waits (bounded, proposed 10 s) and then proceeds, instead of failing with
   a sharing violation or "not found"; after the bound it fails exactly as it does today. Users see a save-then-open take up to about a second longer and nothing fail
   spuriously. The alternative (keep the window and document it) leaves Word in-place saves, scripts and robocopy re-runs broken, so it cannot meet "no bugs like the delete and
   .docx ones".
2. **Folders in M2.** Recommended: pull rename and delete of a folder inside the protected folder (and the Recycle Bin move) into M2; keep moving a whole folder in from outside
   as copy-and-inspect (the earlier T6 decision). The alternative (postpone all folder work) leaves Explorer's rename, delete and Delete key broken in the protected folder.

## Owner answers (2026-10-22, same session)

1. Publication-window wait: **Yes** (bounded, proposed 10 s) — design in [T8-PUBLICATION-WINDOW.md](../../docs/design/publication-and-namespace/T8-PUBLICATION-WINDOW.md).
2. Folder rename/delete and the Recycle Bin move in M2: **not now** (T6 stays postponed; F7 and F8 are recorded known limits).

## Addendum: follow-up measurements (same day)

- **Windows Search is a large share of F3/F4.** With the `WSearch` service stopped (`t8sweep-v2nowsearch`, budget off), `word-inplace`, `word-saveas-edit` and `txt-lifecycle` pass
  every step; with it running they fail. The indexer opens each new file and a counted `FileObject` keeps the rename exchange from committing. `word-overwrite` still fails without
  it (gate 6 on a document closed 4-8 s earlier); Restart Manager shows no handle holder 1.6 s after the close, and the stage worker keeps one extra live version and view for
  more than 10 s, so a lingering upper object is the likely holder there (not resolved).
- **F5 holds from a clean state.** `t8sweep-v2budgetonclean` (budget on, staging and journal set aside, rebooted): Word first saves fail, Excel `SaveAs` fails, `big.bin` fails; every
  `StageAllocate` event takes 1.51-1.59 s, equal to `StagedSpaceBudget.RefundGrace` (1500 ms). Cause in `StagedSpaceBudget.Reserve`: the grant is the whole remaining allowance, so a
  second concurrent allocation waits the grace and fails. Retained transfers (from the F4 failures) additionally keep their full charge and lock the user out.
