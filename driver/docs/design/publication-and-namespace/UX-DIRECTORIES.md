# Directory UX on the unbound MVP profile

This is the small F1–F4 implementation for `ux/dirs`, based on `demo/apps`
`8925d1cf` and the 2026-10-16 owner decisions in [the status plan](../../../POST-MVP-PLAN.md#owner-decisions).
It does not adopt the parked T6 census/ancestry migration design. Local controls
are component feedback; WDK/PREfast/import gates and Windows qualification remain required.

- F1: native local fixed NTFS directory CREATE/OPEN_IF/OPEN, including broad
  directory rights. Empty directory creation adds no content. Descendant files
  still take ordinary staged admission: policy prefixes match whole components
  at every depth (`Policy.c:SafeUploadPathUnderPrefix` and agent
  `Domain/Policy.cs:IsUnderMonitoredPath` both enforce component boundaries).
  Directory EA payloads, stream/index selectors, unsupported
  attributes, raw IDs and scheduled delete-on-close remain refused. Existing
  unflagged directory opens are metadata-probed, then pinned to directory type
  on the original CREATE; a substituted file cannot receive native write access.
- F2: native directory rename/move and ordinary disposition only after a bounded
  walk of `StageStreams` and `StageAllocationReservations`, under the existing
  namespace resource. Every retained version counts, across owners, including
  detached/sealed versions, unresolved allocation and private delete/recovery.
  A pending private rename's destination counts too. Busy returns
  `STATUS_SHARING_VIOLATION`; configured scope roots/ancestors remain fixed.
  NTFS retains caller DELETE/DELETE_CHILD, share, emptiness and collision checks.
- F3: an outside directory rename into the protected namespace returns
  `STATUS_NOT_SAME_DEVICE` before forwarding. A protected child can move out
  after the same idle check. Callers with recursive copy fallback create the
  tree and copy each file through staging; cmd/MoveFileEx whole-folder moves
  can report the normal cross-drive failure.
- F4: Explorer can create destination trees. Every child file is independently
  inspected/published or blocked/handed back by the existing agent path; no
  folder transaction or source-retention promise is introduced.

The scan reserves one short global directory-mutation fence, carried by the
existing admission epoch token until lower completion. New private CREATEs and
retargets refuse during it. A sequence captured before name lookup also rejects
queued CREATEs captured across a completed mutation. Lower I/O runs without
namespace/stream/spin locks; known success/failure completion releases atomically.
A draining completion with an unknown outcome leaves the fence latched until
reboot; it cannot silently reopen admission.
The bounded writer-registry rename bookkeeping still runs unchanged.

Limitations: the fence makes unrelated staged saves busy too, and a delayed
lower operation/oplock can prolong that refusal. Retained
terminal versions can conservatively keep a tree busy until normal retirement.
Scheduled directory deletes remain unsupported (ordinary RemoveDirectory is the
supported route). This is the unbound MVP path, not qualification of V30 or of
persisted identity/ancestry relocation across service restart. Existing service,
policy, trust and activation gates remain in place. No agent changes are needed.

## Exact Windows test list

Run serially as **t5actor** on **win10-debug3, 19045.2965**, with matched driver
and agent hashes, each in ordinary, runtime-Verifier and boot-Verifier modes.
Use independent raw-volume byte observation throughout every content row;
`ForbiddenByteCount=0` is mandatory. Preserve all failed evidence. Before boot:
Debug/Release WDK, PREfast and ApiValidator at zero warnings/errors, both import
availability gates, and independent Sol 6.1 xhigh review.

1. D01: Explorer New folder, cmd `md`, PS 5.1 New-Item, nested empty directory
   trees, existing-name collision and OPEN_IF. Compare original caller grants,
   inherited ACLs and sharing with a native outside tree. Denied add-subdirectory
   must remain denied. Open for DELETE with omitted type flags as Explorer does.
2. D02: copy a nested tree with empty directories, empty files, two clean files
   and a CPF file using Explorer and PS 5.1 Copy-Item. Clean/empty files publish
   exact bytes, CPF stays absent and is handed back, siblings finish. Repeat
   over an existing CPF target: prior public bytes remain intact.
3. D03: Explorer move and PS 5.1 Move-Item from outside into protection. Trace
   NOT_SAME_DEVICE then directory creates/per-file copies and caller source
   removal. cmd move and MoveFileEx flags 0/COPY_ALLOWED leave the whole-folder
   source intact with the native cross-drive error when no fallback is supplied.
4. D04: rename an idle empty and an idle published populated child directory
   within protection, then move it out. Repeat case-only, collision, denied
   DELETE/DELETE_CHILD, share-delete denied and open-child cases; NTFS decides.
   Afterwards save clean/CPF files at the new and recreated old paths.
5. D05: keep a descendant private writer open in a deep subdirectory; attempt
   parent rename, move out, destination replacement and RemoveDirectory from
   the same and another process. Require SHARING_VIOLATION and unchanged names.
   Repeat during inspection, blocked hand-back, pending discard, detached old
   version and unresolved allocation/recovery; retry after normal retirement.
6. D06: pause native rename/disposition after admission. Race new staged CREATE
   and private retarget into either source/destination; require busy. Pause a
   queued CREATE before its worker, complete a directory mutation, then resume:
   stale capture must refuse. Also resume a native directory request whose
   name was captured before another directory mutation, and complete a rename
   during a private-retarget lookup. Repeat failed/cancelled lower I/O and draining
   completion; no stuck fence on known failure, uncertainty stays fail closed.
7. D07: RemoveDirectory on an idle empty directory succeeds; a native nonempty
   directory retains DIRECTORY_NOT_EMPTY. Repeat ordinary/extended disposition
   and FALSE clear. Configured scope roots and ancestors remain refused.
8. D08: directory EA pointer/length variants, `:stream`, `:Zone.Identifier`,
   `::$DATA`, `$I30:$INDEX_ALLOCATION`, unsupported create dispositions, by-ID,
   reparse creation/payload and EFS/offline create attributes, delete-on-close and extended ON_CLOSE remain
   refused without content effects. Probe/forward type substitution cannot
   expose an ordinary file for unstaged write. Basic directory timestamps and
   caller-authorized ACL/owner changes remain native. Unprotected removable/
   SMB/non-NTFS metadata operations retain their previous routing.
9. D09: rerun existing T6 file-move controls (including C05), T5 empty/Notepad/
   delete controls and folder-copy cancellation; retain independent clean/CPF
   observations and separate baseline restoration evidence.

## Local result (2026-10-16)

The [independent Sol 6.1 xhigh review](../../../evidence/2026-10-16/ux-dirs-review-sol61.md)
is **ACCEPT WITH CONDITIONS**; its code findings and documentation correction
are addressed. Windows/build qualification remains outstanding.

`TMPDIR="$PWD/.scratch" python3 driver/SafeUpload.Minifilter/tests/test_directory_ux.py`
passes both controls. Actual new directory helpers, policy-prefix/anchor helpers
and external rename bodies compile with GCC and Clang (`-Wall -Wextra -Werror`,
UBSan); CREATE/dispatch/postoperation wiring is checked structurally. Both existing
kernel host fixtures and 14 runner/T4/T5 self-check scripts pass (16 checks total).
No agent source changed and no VM or remote build was run. Raw local attempts,
including failed fixture setup and API-audit attempts, remain in `.scratch/verification`.

The full existing kernel API audit was loaded from `wt/t5-batch2` because this
base does not include that script/header inventory. It reports exactly the same
pre-existing missing `InsertHeadList` header exception at `Taint.c:356` on base
`8925d1cf` and this source. The assertion was not changed. A separate comparison
passes with **zero newly introduced external call identifiers**. This does not
replace the binary import gate. Audit script/header copies, hashes and receipts
are retained in `.scratch/verification/api-audit` and `kernel-api-*.log`.
