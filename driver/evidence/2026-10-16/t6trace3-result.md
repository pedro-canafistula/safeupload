# T6 native traces, steps 1–2 (`t6trace3`, 2026-10-16)

Harness `wt/t6-dirs` `6dfe9c3d` (`driver/scripts/t6/Invoke-DirMoveTraces.ps1`), PS 5.1 gate `hg-t6trace3` PASS, builder1
(DESKTOP-O1LP5DG, 19045, PS 5.1.19041.6456), 88 cases, runner validation Complete=true, VHDX second volume detached and deleted.
Mechanism evidence on the builder, **not** target qualification and no SafeUpload driver/agent involved. Earlier attempts
`t6trace1` (null run root under the remote wrapper) and `t6trace2` (Run-Process pipeline leak; all cases ran, validation refused)
are kept locally. Raw JSON/summary stay local under `wt/t6-dirs` `driver/evidence/2026-10-16/t6trace3/`.

**Step 1 — folder moves (empty, populated, nested with hidden/system members, empty files and folders):**

| Caller | Same volume | Real second volume |
|---|---|---|
| PS 5.1 Move-Item (±-Force, into existing folder) | native rename | copy + delete: source gone, destination complete |
| IFileOperation (Explorer engine, automation) | native rename | copy + delete, not aborted |
| cmd move | native rename | fails (exit 1), source intact |
| MoveFileEx 0 | succeeds | fails Win32 17 ERROR_NOT_SAME_DEVICE, source intact |
| MoveFileEx MOVEFILE_COPY_ALLOWED | succeeds | fails Win32 5, source intact |
| robocopy /E · /MOV · /MOVE | copy · files moved, folders kept · all moved | same |

**Step 2 — cross-drive metadata reference (owner decision 2026-10-16):** same-volume moves keep every field. Cross-volume moves by
every caller keep owner, group, SACL and label, but the DACL and control flags change to the destination's inheritance (explicit deny
and protected ACEs are not carried). Timestamps depend on the caller: the Explorer engine and robocopy keep file creation times,
PS 5.1 creates new ones; all keep last-write. Staged publication must therefore let each caller's own basic-information setters
reach the published file (T8 timestamp contract).

**Still open (need the implementation):** induced same-volume STATUS_NOT_SAME_DEVICE (does PS 5.1 fall back on the status or decide
by drive root?), Windows 10 directory admission, MOTW ordering, busy/idle behavior, and the real interactive Explorer drag on the VM.
