# M2 MVP drop 2 (Word), 2026-10-30

Plan: [T8-WORD-DROP2](../../docs/design/publication-and-namespace/T8-WORD-DROP2.md). Target win10-debug3 only, Office base
`office-base-20261029`. Raw evidence is local and ignored (`mvpW0a-*`, `mvpW1*-*`, `mvpWord*G1-*`, `mvpB*G1-*`, `mvpACD*G1-*`).

## W0 — what blocks Word's Save As over an existing name (mvpW0a, kernel `8d6e8737`)

- **Native sequence** (WPR FileIO trace, control folder `C:\T5\wd-native`): Word renames `wd-native.docx` to its backup `~WRL0004.tmp`
  (FileRenameInformation, class 10), renames its temporary file onto `wd-native.docx` **without** the replace flag (the name is free
  natively), then deletes the backup (FileDispositionInformationEx, class 64).
- **Protected folder:** the first rename is staged. The public `word-overwrite.docx` stays at its name until the service applies the
  move, and is hidden from Word by the owner's tombstone. Word's opens see `STATUS_DELETE_PENDING` (ring 230–234). The second rename
  (`SET_INFORMATION`, class 10, no replace) then returned `STATUS_OBJECT_NAME_COLLISION` from the driver (ring 242).
  `SafeUploadStageCheckRenameAccess` treated the hidden public file as an existing destination.
- So this is the driver's own namespace, not NTFS delete-pending and not a memory-manager hold. W1 table row 1 applies (a driver-side
  consistency fix). Row 3 (delete/successor ordering) and Increment C (section closing) are **not** needed, so no owner decision arises.

## W1/W3 — kernel `7f7d6b62` (m2w1k1030b)

- `StageRename`: a rename onto a name whose public file the **same owner** renamed away is checked as a replacement. The waiver is bound
  to the vacated file's identity (volume serial + 128-bit file ID recorded in the tombstone), so a different file that later takes the name
  still collides. The waiver is rechecked with the same tombstone sequence after the exchange. The replacement check still requires DELETE
  on that file and add-file access on the parent. Nothing becomes public without inspection: the incoming version stays private until
  inspected and published, and the move is published by the service in journal order.
- W3 (drop 1 review notes): the reopen wait stops early when the version left its view (`View == NULL`, `Detached`, `Current != Stream`)
  or when the blocking obligation waits for the service. The stream is queued after every unpin, not only the last.
- Gates: exact kernel build m2w1k1030b on builder1, Debug and Release feature builds, PREfast and ApiValidator, 0 warnings / 0 errors,
  imports PASS, signed `.sys` `55EEBC89…29F4EF7`. The agent source is unchanged since `8d6e8737`, so agent matrix m2mvpa1029g
  (zip `21028FA8…F100D`) still matches. PS 5.1 harness gate m2mvph1030d PASS (watcher type fixes `8d943b0b`, `46a3a747`).

## Dev-loop stability (ordinary, diagnostic, not rows)

| Run | Kernel | Word result |
|---|---|---|
| mvpW0a | `8d6e8737` | Overwrite FAIL (the W0 capture above); Save As, in-place and CPF PASS |
| mvpW1a, mvpW1b | m2w1k1030b | Overwrite not reached: the harness watcher type failed to compile (`Warning as Error`, fixed in `8d943b0b`/`46a3a747`); other Word cases PASS |
| mvpW1c, mvpW1s1, mvpW1s2 | m2w1k1030b | **MVP W PASS** (all four Word cases, staging and journal empty, restoration PASS) |
| mvpW1s3 | m2w1k1030b | Not run. The host rebooted at 01:43 BRT during the actor phase. The run disk and Office repoint were restored by hand later (`mvpW1s3-final-restored-state-after-host-reboot.txt`, `mvpW1s3-office-return-after-host-reboot.txt`: XML unchanged, overlay deleted, both bases' size/mtime unchanged). |

W2 (the Retained Save As version seen once in mvpBWdiag15 on `8d6e8737`): did not recur. Save As passed in 5 of 5 runs on m2w1k1030b,
with no `Retained` state in the agent state lists of W1c/s1/s2. The cause was not isolated. Carried as a watch item; if it recurs, take
the W0.5 capture.

## Rows on the drop 2 pair (kernel m2w1k1030b + agent m2mvpa1029g)

Chain `~/Work/safeupload-tools/session-scratch/drop2-rows.sh`, serial, stop on first failure.

### mvpWordOrdG1 (ordinary): FAILED (preserved); the chain stopped

- Pair hashes, mode readback and restoration PASS. Save As, in-place edit and CPF save PASS.
- Overwrite failed at its **seed** step, a Save As of `word-overwrite.docx` to a new name, before the overwrite itself.
  - After `SaveAs2`, Word held the document **Read-Only** (`Word save/reopen failed: word-overwrite - Read-Only - Word`).
  - The version (`6ca46437…`) was published cleanly at 12:02:23.766Z: allocated .327, sealed .405, inspecting .415, approved .754, released .766.
  - It then stayed live: driver `liveVersions=1`/`liveViews=1`; stage file and journal entry left. `T5StagingEmptyAfterRun` and `T5JournalSettledAfterRun` FAIL.
  - These run-level dependencies also mark MVP B FAIL in this Word-only profile. Excel was not run.
- Word's handle on `word-overwrite.docx` appears at 23.425 (FSCTL `0x900C0`, the known object-ID refusal), inside the inspection window.
  - The deny ring has **no** refusal of Word's reopen.
  - Hypothesis: the reopen landed in the inspection window and Word's write open failed. Word then fell back to read-only, and its handle kept the version alive. A writer CREATE finished on the attach worker (READMIT → `STATUS_SHARING_VIOLATION`) would not be noted in the ring.
  - This matches the drop 1 Save As instability: one bad version after a `~WRD0000.tmp` rename onto a new name.
  - Not proven. Next step: a diagnostic run with `T5_WORD_DIAG=1`, which now traces the seed and Save As saves too (`c5558cce`).

### Diagnostics after the failed row (`T5_WORD_DIAG=1`, same pair; not rows)

- **mvpWdiagG1:** seed, Save As, in-place edit and CPF PASS; no leftover. The overwrite stopped on a harness timeout: the third WPR session delayed Word's alert monitor past 15 s. Fixed for diagnostic mode only (`459fe10f`: 60 s; trace keeps CREATE completions).
- **mvpWdiagG2:** Word's **in-place edit** of `word-saveas.docx` failed with `0x800A156F`.
  - Word's own sequence: it opened the published document for writing, giving private successor `a4167baa`, and renamed that version to its backup `~WRL0001.tmp`.
  - The rename of `~WRD0000.tmp` onto `word-saveas.docx` then failed. Its journal prepare (`a4167bb2`) stayed pending.
  - Word's roll-back (backup back onto the name) was refused by the journal: "The rename destination is busy: a4167bb2 … renaming to word-saveas.docx".
  - The backup version then went Sealed → Inspecting → **Retained** and stayed (stage file and journal entry left). This is the drop 1 "Retained" symptom.
  - The overwrite case's later `0x800A14E9` ("file in use by another process") touched no protected file in the trace; it is a knock-on.
  - The driver's refusal of the forward rename had already left the 256-entry deny ring (object-ID FSCTL refusals fill it). From `39ac1911`, diagnostic mode keeps every folder refusal during traced cases and also traces the edit step.
- **mvpWdiagG3:** no verdict. Four WPR traces plus the OperationEnd scan of ~800 MB CSVs ran the coordinator past its 1800 s bound (harness cost, fixed in `4d2c00d6`: one trace per run).
  - Its ring capture has no failed rename, only Word's usual `FileRenameInformationEx` `NOT_SUPPORTED` before the class-10 fallback.
- **mvpWdiagG4 (reproduced, root cause of the Retained version):**
  - Save As, then Word's edit and save of `word-saveas.docx`. The new version `1cce057d` (generation 4) sealed at 17:08:51.586.
  - **19 ms later**, the same Word process opened `word-saveas.docx` for writing. Its follow-up successor `1cce057e` (generation 5) was seeded from the still-private sealed version.
  - At 51.914 the service's Sealed → Inspecting transition failed: "A later save or pending rename supersedes this destination version" (`StagedTransferJournal.RequireCurrentDestinationAsync`; any higher-generation entry counts, even an unsealed follow-up of this version). `1cce057d` became **Retained**.
  - The successor sealed when Word closed and published the same 13,450 bytes at 52.723, so the user's content was published.
  - The Retained predecessor stays forever: journal entry, stage file, and a live driver stream (Sealed, ViewDetached, OwnerExited, one FileObject, data section). The harness's settlement and no-leftover checks fail on it.
  - In passing runs Word does not reopen the document for writing right after a save.
  - User effect when it happens: the save becomes public only when Word next closes the document (seconds or hours later), and a stage file and journal entry leak.
- **mvpWdiagG2 explained by the same window plus a second defect:** a rename that fails its post-prepare recheck (`StageRename`, `STATUS_SHARING_VIOLATION`) leaves its journal prepare pending until the worker sends the ABORT. Word's immediate roll-back rename then meets "destination busy". Fix direction: send the ABORT inline, like the COMMIT (`8d6e8737`).
- **mvpWordOrdG1:** the version was Released but never disposed (`liveVersions=1`), and Word held the document Read-Only. This fits T8-PUBLICATION-WINDOW Increment C (a lingering reference keeps a published version's view alive, so a writer reopen meets a published predecessor). Not separately proven.

**Status:** the W1 overwrite fix works (Word overwrite PASS in every run where it was reached). Word stays intermittent: about 3 of 9 Word runs on m2w1k1030b show one of the post-save races above. Rows stopped (stop rule: hypothesis before more rows). The remaining fixes change publication semantics (agent currency rule or a kernel publication wait), so they need the owner's choice and an independent review before boot.
