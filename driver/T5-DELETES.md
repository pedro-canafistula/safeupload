# T5/T8 design note: deletes and in-folder renames in a protected folder

Status: design, before implementation (2026-10-10). Plan tasks: `POST-MVP-PLAN.md` T5 (Notepad Save As) and T8 (Office and common
applications). A delete and an in-folder rename change version lifetime, so this note gets a Luna review before the first VM boot.

## 1. Today

- A staged handle has no `FileDispositionInformation` case: `DeleteFile` of a name the caller has a private version of fails, and
  `FILE_DELETE_ON_CLOSE` is refused at admission for protected names and unsupported in `StageCreate`.
- `DELETE` counts as writer access, so `DeleteFile` of a published file (open `DELETE`, set disposition) first creates a staged version
  seeded from the public file, and then fails on the disposition. Nobody can delete a file inside a protected folder.
- A physical handle (no staged version) cannot rename or delete inside a scope: `StageExternalRename` and `StagePhysicalMutationEx`
  refuse every name that touches the protected namespace.
- Staging never removes a public name: a staged rename moves the version's destination and hides the old public name from the
  renaming process only (tombstone); publication writes the new name and leaves the old public file.

Notepad Save As (T5): the common file dialog test-creates the target unless `OFN_NOTESTFILECREATE` is set, then deletes it, then the
application saves. Office (T8) saves to a temporary name, renames the original to a backup name, renames the temporary to the final name
and deletes the backup; it also creates and deletes `~$` owner files.

## 2. Principle

A delete or an in-folder rename adds no byte: it removes or renames bytes that are already public (approved, or present before protection).
As for reads (T7) and permissions (T10), Windows' own access check decides who may do it. Every write still goes through staging, and
moves into the folder keep T6's copy fallback.

## 3. Rules

**R1. Delete of a public file.** An open of a protected file whose access is only `DELETE` plus non-mutating rights (`READ_*`,
`SYNCHRONIZE`, `READ_CONTROL`, `FILE_READ_ATTRIBUTES`, plus T10's security rights), by a process with no private version of that name, is
not staged: it reaches the real file and NTFS checks `DELETE` on the file or `FILE_DELETE_CHILD` on the parent. `FileDispositionInformation`
(and `Ex`) and `FILE_DELETE_ON_CLOSE` on such a physical handle pass for a file inside a scope. Directories keep today's rules: a scope
root or any directory above a scope cannot be deleted, and directory creation stays refused.

**R2. In-folder rename of a public file.** On such a physical handle, a rename or hard link whose source and destination are both inside
current protected scopes on the same volume passes (`ReplaceIfExists` included: both names hold public bytes). Destinations outside every
scope keep today's rules (a protected file renamed out of the folder stays refused until an owner decision), and T6 is unchanged for
sources outside.

**R3. Delete through a private version.** A disposition with `DeleteFile = TRUE` (or `FILE_DISPOSITION_DELETE` in `Ex`) on a staged
handle, or `FILE_DELETE_ON_CLOSE` on a staged create, marks the version *discard on close*; `DeleteFile = FALSE` before cleanup clears it.
When the last handle is gone the worker does not seal the version for inspection: it sends the service `STAGE_DISCARD` (transfer ID),
waits for the durable acknowledgement as it does for a seal, detaches the view and releases the version under T4's rules. The name is
then absent for the owner; if a public file has the name, the owner's tombstone hides it, as for a rename that leaves a public name.
A discarded version is never inspected or published.

**R4. Ordering.** The service journals a discarded version as a terminal `Discarded` state that keeps its destination generation. Since
only the newest generation of a destination may be inspected, approved or published, an older version of the name that was sealed
before the delete can never publish after it, and a later save gets a newer generation as usual. If the older version is already
`Publishing`, the discarding create fails with a sharing violation, as any create of that name does during publication.

## 4. What the dialog and Office then do

- Save As: the test create makes version V1; the dialog's `DeleteFile` opens the name with `DELETE`, which, while V1 is attached and
  sealed, creates V2 (newer generation, supersedes V1) and marks it discard-on-close; Notepad's save creates V3, which is inspected and
  published. If V1 had already been released and detached, the delete reaches the public empty file (R1) instead.
- Office: the backup rename of the original is R2 when the original is opened without write access, or today's staged rename otherwise;
  the backup delete is R1 or R3; `~$` owner files are ordinary staged writes, deleted by R3.

## 5. Not covered here

A delete through a private version does not delete a public file of the same name (the owner sees it absent until it exits); renaming a
protected file out of the folder; directory create and delete inside a scope; metadata carried by publication (T8).
