# T5 UX namespace gap on the MVP pair

2026-10-16. Base `79795efa` (`demo/apps`), worktree branch `ux/kernel`.
Sharing correction: `1dfadee4`.
**Incomplete implementation: the four reported workflows are not fixed by this change.**
No VM, WDK/PREfast/ApiValidator or independent implementation review was run.

The owner's requested behavior is the contract: operations on already inspected public
bytes should use native namespace semantics; private renames retarget inspection and
publication; a Word swap must finish with the inspected temporary version at the final
name. The earlier blanket physical-rename refusal in [T5-DELETES.md](T5-DELETES.md)
does not override this new request. Neither does it supply the missing public transaction.

The 2026-10-16 Demo build decision is absent from this checkout's
[status plan](POST-MVP-PLAN.md). It was read in the main worktree's
[current plan](/home/victor/Work/safeupload-staging/driver/POST-MVP-PLAN.md), along with the
[reported evidence](/home/victor/Work/safeupload-staging/driver/evidence/2026-10-16/demo1/).
The main worktree and its evidence were not changed.

## Implemented correction

`StageRename` formerly required `ShareAccess.OpenCount == ShareAccess.SharedDelete`.
That also required the **renaming open** to grant delete sharing. A handle with DELETE
access can rename its own file without granting other openers delete sharing; the other
opens must still permit deletion. `StageRenameShareAllowed` discounts only that open's
missing share-delete bit, under the existing stream resource. Duplicated handles still
refer to the same FILE_OBJECT; the share ledger is not modified.

This removes one concrete cause of Word's legacy-rename sharing failure. It does not
establish that this was the only cause in the recorded trace. DELETE authority, target
sharing/image checks, namespace checks and exact service receipts remain in place.

The helper is PAGE code with `PAGED_CODE` and an APC-or-lower SAL contract. Its sole
call occurs under the existing stream resource, outside spin locks. It adds no import,
allocation, wait, object owner, timer or lock-order edge. The two unsigned counters are
ordered before subtraction, so malformed counters cannot underflow into permission.

`scripts/t5/rename-sharing-selfcheck.py` compiles the actual production predicate with
`cc` and `clang`, warnings as errors. It exercises 1,022 handle/share configurations,
same-open duplication, missing DELETE, invalid counters and 32-bit boundary counts.
The original predicate fails the same controls. This is a host shim, not native evidence.

## Precise integration blocker

There is no live checked public namespace transaction on this MVP profile:

| Boundary | Existing code | Consequence |
|---|---|---|
| Public DELETE open | `StageAttachWorkerBody` selects `StageAttachPrepareNative` only when `SafeUploadStageProtocolNativeForwardAllowed` succeeds and there is no owner private view. | The active MVP path can allocate a private version for a DELETE-capable open of a public file. Deleting that version cannot delete the checked public object. |
| Public delete relay | `StageDispatchEpoch` calls `SafeUploadStagePublicDispositionPre`, but it handles only objects in the native record map. | Calling the relay earlier does not create the missing original native open or combined writer capability. |
| Capability/readiness | `SafeUploadStageProtocolNativeForwardAllowed` requires bound-head bit `0x40`. `StagedBoundReadiness.NativeHolds` keeps that path off; `SafeUploadStageProtocolBoundAllocationReady` returns FALSE. | Flipping a selector or advertising the bit would bypass the explicitly retained create-security, seed/export and version-publication prerequisites. |
| Public rename | `StageRename` updates private names and owner tombstones through V20. `StageExternalRename` refuses protected physical renames except authenticated publication. V25's `NativeDispositionPrepare` accepts disposition, not rename. | There is no existing public two-name rename relay to invoke. Reinspection/copy publication at the new name leaves the old public link behind. |
| Publication ordering | The unbound branch of `StagedTransferPublisher` uses the legacy publication permit/temporary/rename path. `IsCurrentDestinationAsync` uses `DestinationVersionsAsync` for these entries. The bound head/commit queue is a separate branch. | Recording a public delete only in the bound head would not fence an older unbound publisher. Checking current path absence is insufficient. |
| Sealed private reopen | `StageCreate` rotates a sealed stream whenever `Writer` is true; `StageAdmit` includes DELETE in `writerAccess`. | A namespace-only reopen can become a new version rather than retain the pending version being renamed. The supplied success/old-name observation does not identify the exact seal/publication interleaving. |

Consequently, forwarding a rename/delete directly to NTFS, deleting an old path as SYSTEM
after publishing a copy, or merely adding accepted flag bits is not a complete fix.
Those approaches respectively omit durable ordering, exact caller/object authority, or
the actual public namespace operation. The existing private retarget path is not a
physical-rename receipt. No false-success workaround or readiness bypass was added.

Finishing the task needs a coherent **driver and agent** change, with these boundaries
closed together before claiming the four cases work:

1. Use the original native DELETE-only open, or the already caller-checked combined
   backend for a data writer. Preserve its grant, sharing, subject, identity and cleanup.
   A namespace-only reopen of a still-private sealed version must keep that exact version.
2. Put every active MVP allocation/publication and public delete/rename through the same
   destination ordering authority. A source barrier must also prevent an older private
   version from resurrecting the source after rename/delete, including after restart.
   Migrating only public operations to the dormant bound head does not accomplish this.
3. Extend the existing relay with a two-name, exact-object public rename prepare/result
   transaction. Snapshot both destination identities and expected heads. Preserve native
   source-object identity; retain an uncertain result instead of retrying the mutation.
   A Word backup delete then targets the renamed original object, never a replacement.
4. Carry accepted rename flags and original target authority through commit. In particular,
   `FILE_RENAME_IGNORE_READONLY_ATTRIBUTE` requires target WRITE_ATTRIBUTES when replacing
   a read-only file. The current V20 rename source frame carries no flags, and the legacy
   publisher's rename flags are fixed. Accepting the bit only in `StageRename` loses that
   contract. Storage-reserve flags also have access requirements; they are not safe no-ops.

This boundary needs the independent product-security design review required by
[AGENTS.md](../AGENTS.md) and the concrete lifetime review before boot. The current status
plan requires that review to come from a fresh Sol 6.1 xhigh session launched by Claude;
no self-review is represented as that result here. The present sharing correction does
not enable the missing transaction.

API audit references:
[rename flags and access](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information),
[documented FILE_OBJECT access/share fields](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_object),
[share-check serialization](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocheckshareaccess), and
[destination name-query contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetdestinationfilenameinformation).

## Local verification

All 16 scripts passed: all twelve `scripts/t5/*selfcheck.py` scripts (including the new
sharing shim), T5 `notepad-verdict.SelfCheck.py`, T4 `verdict-selfcheck.py`, the exact agent
matrix runner self-check, and the driver-import self-check. The last is synthetic import
validation; no newly built driver artifact is claimed. The changed Python script parses,
`git diff --check` passes, and the changed helper/API audit passes. The final sharing-shim
rerun also compiles the exact changed caller block under its existing resource.

[Local result and source hashes](evidence/2026-10-16/ux-kernel-namespace1/result.txt)
records the diagnostic scope; full per-script logs remain local alongside it. No agent
source was changed or matrix queued. The four WDK builds and native share/rename controls
remain necessary before qualification of even this limited correction.

## Manual VM acceptance list

Run as standard user `t5actor` on `win10-debug3` only, using matched packages and the
approved disposable baseline. An independent reader outside the actor process must
observe `C:\Protected`; the actor's private directory listing is not a public receipt.
Record the commit, package hashes, policy and driver/agent readiness first. Keep the
initial failure logs; do not count the sharing-only patch as passing this list.

1. **Sharing regression:** on ordinary NTFS, then staging, open a new file with
   `GENERIC_READ | GENERIC_WRITE | DELETE`, sharing READ|WRITE but not DELETE. Write
   `ux-clean-sharing`, rename through that same handle with class 10, then close.
   The rename must succeed and the clean bytes must appear only at the new name.
   Repeat with a duplicated handle. Separately hold another open without delete sharing;
   a conflicting DELETE open/rename must fail as in the native control.
2. **Word new Save As:** type `ux-clean-word-new` into a new document and save as
   `C:\Protected\ux-word-new.docx`. Wait for the publish receipt, reopen in Word, and
   verify the text, valid nonempty DOCX, and no surviving backup. Trace both rename
   information classes and their flags, source identities, temporary identities and
   actual NTSTATUS values. A successful dialog or an empty final file fails this row.
3. **Published rename:** publish `ux-public-old.txt` with `ux-clean-public-rename`.
   Record its volume/full file ID and bytes. Explorer F2 to `ux-public-new.txt` must
   remove the old link and preserve the ID/bytes. Repeat using `Rename-Item`. Test an
   occupied target with replace off, replace on, and read-only target with/without
   IGNORE_READONLY and target WRITE_ATTRIBUTES authority. Compare native results.
4. **Published delete:** publish `ux-delete.txt`, then Explorer Delete; repeat using
   `Remove-Item`. After native last-close completion the independent reader must find
   the name absent. Test another open denying delete sharing, denied file DELETE plus
   denied parent DELETE_CHILD, and parent-only DELETE_CHILD authority against native NTFS.
5. **Immediate private rename:** create/write/close `ux-fast-old.txt`, then immediately
   rename to `ux-fast-new.txt`, at delays 0, 10 and 100 ms; repeat at least 20 times per
   delay with unique names. Observe from before create until publication. After success,
   only the new name may remain. Correlate transfer, seal, rename receipt and publication
   generation to distinguish a private retarget from a public rename. Repeat empty files.
6. **Word replacement:** publish a clean `ux-word-replace.docx`, edit and save from Word.
   Observe target-to-backup, private temporary-to-target, and backup delete. Final text
   must be the new text; the backup must disappear. Repeat with the replacement containing
   the policy's known blocked CPF. No uninspected nonempty bytes may reach any public
   name, including backup/temp names. Only a recorded public delete/rename can remove
   prior public bytes; pending or blocked saves cannot suppress it.
7. **Ordering/failure:** hold a private writer while deleting/renaming the prior public
   file; close the writer afterward. The prior name must not resurrect. Repeat at seal,
   inspecting and publication boundaries. Disconnect/restart the service before/after
   the native result and lose a result reply: unfinished bookkeeping may retry, a public
   mutation may not. Verify exact held diagnostics and reconciliation, then unchanged
   ForbiddenByteCount and the required ordinary/runtime/boot-Verifier rows.

The reported FSCTLs are separate remaining surfaces: `0x9C040` is SET_COMPRESSION;
`0x900C0` is CREATE_OR_GET_OBJECT_ID. The latter can create metadata and must not be
globally reclassified as a read-only query. Neither refusal was changed here.
