# T5 UX namespace gap on the MVP pair

2026-10-16. Round 1 base `79795efa` (`demo/apps`); round 2 base `ca173d2a`, branch `ux/kernel`.
Sharing correction: `1dfadee4`.
**Round 2 design (owner / Claude orchestrator, 2026-10-16): implement D1–D6 on the unbound MVP profile.**
The sharing correction below records the base; the unbound design has no V30 prerequisite.
Round 2 had no VM, WDK/PREfast/ApiValidator or independent implementation review.
The later REVISE review and its corrections are recorded below.

The owner's requested behavior is the contract: operations on already inspected public
bytes should use native namespace semantics; private renames retarget inspection and
publication; a Word swap must finish with the inspected temporary version at the final
name. The earlier blanket physical-rename refusal in [T5-DELETES.md](T5-DELETES.md)
does not override this new request. The native original-object operations below implement that namespace contract.

The current [status plan](POST-MVP-PLAN.md) records the demo decisions. The
[reported evidence](/home/victor/Work/safeupload-staging/driver/evidence/2026-10-16/demo1/)
was read without changing the main worktree or its evidence.

## ux/nsfix pre-boot review corrections

Follow-up base `597d09d1`, branch `ux/nsfix`, 2026-10-16. The supplied independent
Sol 6.1 xhigh review of the same kernel code at `85e89b7f` returned **REVISE**
([local review](../.scratch/review1.md)). These are implementation corrections to
D1–D6 on the unbound MVP profile; they introduce no V30/readiness activation.
Review acceptance and Windows qualification remain outstanding.

1. **Stale classification / file and directory races.** File operations now use
   the existing directory mutation fence and sequence. The admission slot's
   sequence is captured at dispatch, before lookup; claiming the fence rejects
   a crossed generation, including a completed move out/back with identical
   final path and file ID. Protected external file/folder mutations and the
   service's unbound publication rename join the same exclusion. Clearly outside
   moves keep their ordinary availability. Filesystem-only, current-provider
   observations compare the current source object's name and file ID with the
   source-name binding, and retain destination-parent and optional target file
   IDs. Those bindings are checked again after cancellation, immediately before
   forwarding. Directory disposition and rename also validate their original
   object/name binding. The admission epoch holds exclusion through lower and
   registry completion; draining latches it until reboot. No resource spans
   those observations, cancellation RPC or native lower I/O.
2. **Cancellation after caller authority.** Native delete-on-close CREATE first
   performs a side-effect-free private-handle preflight. It forwards the original
   CREATE, retaining the common fence. Only successful NTFS authorization and
   legacy post-create processing, the original object's DELETE grant, and its
   exact file ID permit cancellation in the PASSIVE post-create callback. Denied
   CREATEs never cancel a save. Private replacement now checks source sharing,
   the pinned target view's immutable DELETE security, and destination access
   before cancelling the sealed target. The target stream reference retains
   its view/security across both access checks and RPC; source/target generations
   and name ownership are revalidated before cancellation and afterward, before
   releasing that evidence. Access checks run outside the namespace resource.
   Cancellation rechecks closed-handle state atomically with its busy claim;
   private CREATE refuses while cancellation owns that claim.
3. **Registry lifetime / Sticky Unknown.** Native SET_INFORMATION starts the
   existing mutating-I/O owner, prepares registry rename ownership, and transfers
   both through the native completion tag. Resident completion calls the existing
   registry completion routines on success, failure and drain before the epoch
   releases exclusion. Known success updates the retained name and rename version
   without clearing an existing Unknown reason. Uncertain completion preserves
   Unknown and the latched namespace fence. This closes the new-name admission
   bypass while preserving native rename flags and lower NTFS enforcement.

The added helpers repeat their IRQL contracts on definitions. PAGE placement is
before definitions; the raised-IRQL completion contains no name query, resource
acquisition, wait or allocation. CREATE alone calls its PASSIVE helper, including
on drain. The only new cross-completion name reference is bounded by the single
native mutation owner and is released on every CREATE outcome. Source API
inventory found six new internal helper calls and **no new external API symbols**;
this is not a binary-import or ApiValidator result.

Host verification (2026-10-16): all seven kernel Python runners (16 tests), all
14 T5 self-check runners (103 unittest tests plus 14 Notepad verdict assertions), and all three UX self-check runners (9 tests)
passed. T11 SOP-lifetime controls (3 tests), T4 verdict self-check and the driver
import gate's offline self-check also passed. Relevant namespace/directory/MVP
controls were rerun after the final namespace changes. Raw logs and failed
setup/control attempts are retained locally in `.scratch/verification/` and the
`.scratch/namespace-ux-*` failure directories; none is Windows qualification.

`tests/test_namespace_ux.py` compiles the production native pre/post path, binding
and fence helpers, replacement-access helper, and registry completion/name gate
with both `cc` and `clang`, warnings as errors and fatal UBSan. Deterministic
controls cover the move-out/modify/move-back generation, the file/folder fence
interleaving in both directions, current source name/object substitution, changed
destination parent/leaf, denied lower/legacy CREATE, denied replacement security,
original rename flags, ordinary failure and draining ownership, and renamed
Activating/Sticky Unknown admission. Ten negative mutations must fail executed
controls. The existing directory and MVP cancellation controls remain in place.

Remaining conditions / VM rows for the orchestrator:

- Repeat independent pre-boot review; feature Debug/Release WDK + PREfast +
  ApiValidator at 0/0 and binary import availability, then the matched pair's
  ordinary, runtime-Verifier and boot-Verifier controls on `win10-debug3` only.
- Pause a native file rename after classification; move its object out, modify
  outside, then resume; repeat with a folder rename moving its containing tree.
  A stale request must refuse and independent raw observations must show no
  uninspected bytes inside. Check both overlapping and already-completed B.
- Deny DELETE/traverse/share on native delete-on-close CREATE and target DELETE
  or parent-add access on private replacement. The exact pending-save receipts
  must remain uncancelled on authorization denial. Include restricted/impersonated
  callers, successful grants, object substitution, cancellation disconnect/fault,
  and cleanup/draining. A granted delete-on-close CREATE whose later cancellation
  fails is cancelled with its original grant; NTFS can apply its requested
  delete-on-close effects during that cleanup. This is not an authorization
  denial or a retry of a completed public mutation.
- Rename Activating and Sticky Unknown entries; the new name must remain held,
  old-name bookkeeping must follow known success, and uncertain completion must
  stay held. Exercise failed lower rename and draining ownership with Verifier.
- Published rename/delete, monitored-extension copy fallback, move outside,
  Word published-backup/private-temp/final-name swap, first 0-byte placeholder,
  idle folder rename and busy subtree refusal. Include legacy and extended native
  rename/disposition flags, native ACL alternatives and outside-move concurrency.

No Windows build, VM row or agent change was made for this correction. Git's
shared metadata remains unchanged; delivery uses a scratch Git repository and
`.scratch/ux-nsfix.bundle` with branch head `ux/nsfix`.

## Round 1 sharing correction

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

## Decided unbound design (D1–D6)

This design supersedes the former requirement in this note for a bound public
transaction. Bound readiness and V30 stay disabled on this profile. Staging-out builds were
retired by the owner on 2026-10-15; shipping checks use feature Debug/Release.

- D1: a non-content-writing existing-name open with no requester private view uses
  the original NTFS CREATE, caller grant/share and cleanup. DELETE, reads and
  WRITE_ATTRIBUTES do not rotate a sealed private version. Generic/MAXIMUM_ALLOWED
  requests remain content-capable; creating/truncating dispositions remain staged.
  The legacy CREATE gate must not reject an admitted namespace-only open. Its
  read inspection/taint callbacks remain active. OPEN_IF uses this route only for
  an existing file and is narrowed to OPEN to prevent a racing unlink creating a placeholder.
- D2: original-handle disposition and delete-on-close go to NTFS. First refuse
  matching private versions with open handles. On a granted DELETE handle, cancel
  sealed unpublished versions through the existing exact V28 request/receipt.
  For native delete-on-close CREATE, cancellation follows the successful original
  NTFS CREATE in post, before app cleanup. Cancellation supplies no public grant.
- D3: original-handle rename forwards its entire native buffer/flags unchanged.
  Same protected scope is allowed, except unmonitored-to-monitored extension gets
  NOT_SAME_DEVICE for staged copy. Leaving protection is native. Source pending
  versions and replacement target pending versions follow D2. Hard links retain
  the existing gate. NTFS enforces DELETE, target access, sharing and flag rules.
- D4: private namespace-only reopen retains its exact sealed version. Private
  rename retargets the existing V20 transaction and invalidates any old inspection
  attempt; publication must use the committed name/generation and reinspect it.
  A namespace reopen pins the closing version and uses the existing monotonic
  ten-second receipt wait to let an already-started seal settle, outside every
  resource. A seal starting just after that wait readmits the CREATE. No new
  timer, forced drain or lifetime inference is introduced.
- D5: native published-to-backup rename, private temp-to-final retarget and native
  backup delete compose without a placeholder or cancelled old save publishing later.
- D6: unbound final rename and cancellation share the journal mutex. Immediately
  before the rename, re-read the exact intent, current generation, cancellation and
  pending rename. A successful rename records an in-process receipt under that
  mutex. On crash, existing unresolved Publishing recovery holds the name; no
  digest/path inference and no replay of the public mutation.

Kernel namespace mutation uses a single bounded admission fence: install it under
StageNamespaceResource, pin one matching stream at a time, release every resource
before V28 RPC, and retain the fence through the original NTFS operation's post
callback. While fenced, protected allocations/private retargets and publication
renames return sharing violation. No lock spans RPC or native I/O. This deliberately
serializes these short namespace operations globally on the MVP profile; it adds no
per-name table, timer, unbounded storage or imports. A monotonic sequence change
also refuses an allocation/retarget which started before the fence and resumes
after it cleared. An in-flight attachment must recheck before exposing its handle. Accepted cancellations remain
terminal if a later native operation fails. Failed/lost cancellation replies refuse
the native operation and replay the same exact request on retry.

V28 uses the existing operation ID, transfer ID, driver instance, full stage ID,
generation and owner PID/creation time. The agent verifies each against the manifest
and active epoch. Unbound cancellation writes its durable receipt to that manifest;
the receipt also bars transition, rename, justification and startup publication.
Replies echo the entire request; only Canceled with a strictly later generation or
RequiresPublicDelete with zero generation is accepted. Bound requests keep their
existing anchored destination-turn path. No new wire layout or readiness bit.

Independent review remains an orchestrator obligation before a revised VM boot.
This implementation task runs local diagnostic checks only; no WDK, PREfast,
ApiValidator, Windows PowerShell gate or protected runtime qualification is implied.

## Round 2 implementation and verification

D1–D3 route by-name, non-content-writing native opens, metadata changes,
disposition and rename through `StageMvpNamespacePre`. No writable public handle,
private version, second app object, altered sharing or flag translation is added.
Existing-file identity probes are metadata only; the original NTFS operation
still supplies all caller authority. The private namespace stays ahead of this
route. DELETE grants are checked before SET_INFORMATION cancellation; native
CREATE delete-on-close still receives NTFS's original access check.

D4 retains the sealed private version on namespace reopens and permits the V20
retarget to invalidate a live unbound inspection/approval/publication attempt.
Sealed replacement targets use exact cancellation first. Every publisher state
transition checks its captured transfer and generation, preventing an old
inspection from approving the retargeted version. Unresolved, restarted
Publishing entries cannot be retargeted/cancelled from an inferred result.

D6 reuses the V28 wire tuple and validates it against the active unbound manifest.
Its durable cancellation receipt is terminal, survives restart/reply loss and
blocks inspection, justification and final publication. Startup and live workers
retry exact stage cleanup and ordinary disposal acknowledgement separately.
The publisher checks the complete intent and current destination under the journal
mutex immediately before its native rename; it reserves the in-process result
slot before I/O, so no allocation follows the successful mutation in that mutex.
A confirmed mutation is never retried because its Released bookkeeping failed.

Local diagnostics and source hashes are in
[the round 2 receipt](evidence/2026-10-16/ux-kernel-namespace2/result.txt).
The C controls compile the actual namespace-open, copy-fallback, cancellation and
legacy writer predicates with cc/clang, warnings as errors, including a negative
mutation. The cancellation controls exercise open-handle conflicts, both names,
all pending versions, RPC failure, pins, lock release and never-sealed probes.
Existing T5 controls, the two driver C fixtures, import controls and agent compile
checks remain separate from a newly built `.sys` import/PREfast gate.

The selected agent diagnostic executes the actual test methods and all InlineData
rows in process because VSTest's local socket is denied by the sandbox. It is not
a substitute runner for the Windows matrix. The retained result records both
passing journal controls and Windows-only failures. No test or assertion is
removed, renamed, skipped or relaxed. Added cases: **16 normal / 17 feature**,
including two real-publisher controls requiring Windows.

Commit delivery is blocked in this session: `git add` cannot create
`/home/victor/Work/safeupload-staging/.git/worktrees/safeupload-ux-kernel/index.lock`
(`Read-only file system`). HEAD stays `ca173d2a`; files remain reviewable in the
worktree. No push, VM, remote build, independent review, or qualification is claimed.

Residual limitations: the bounded global fence can return a transient sharing
violation to unrelated private opens/retargets. Cancellation remains terminal if
the subsequent native request fails. Existing private cross-parent rename remains
held by its allocation-parent/op19 identity check; native published-file rename
within a protected scope can cross parents. Native delete-on-close timing,
permissions/flags and all real application results still need the VM controls
below, including later saves while a scheduled delete is open. Existing unbound
profile seed/metadata limitations are not evidence of bound readiness.

API audit references:
[rename flags and access](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information),
[documented FILE_OBJECT access/share fields](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_object),
[share-check serialization](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocheckshareaccess), and
[destination name-query contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetdestinationfilenameinformation).

## Round 1 local verification

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

## Additional round 2 VM rows

Use the unbound MVP profile explicitly: bound-head capability 0x40 off, bound
readiness false. After orchestrator review and four WDK/PREfast/ApiValidator builds,
run serially on win10-debug3 with matched committed packages, a standard actor,
independent file-ID/byte observations and separate baseline restoration.

- D1: READ_DATA/READ_ATTRIBUTES/WRITE_ATTRIBUTES/DELETE opens of an existing file,
  with and without read access, sharing denial, duplicate handles, denied DELETE
  with parent DELETE_CHILD alternatives, READ_CONTROL and OPEN_IF. No private
  allocation for admitted native opens; sensitive published reads still taint.
- D2/D3: disposition legacy/Ex, clear/on-close/POSIX, native CREATE delete-on-close;
  rename legacy/Ex, replace on/off, native accepted flags and access denials,
  read-only/image/share conflicts. Check source and target private-open conflicts,
  multiple sealed generations/owners, cancellation reply loss and exact cleanup.
- D3: same-scope cross-parent native rename preserves full file ID and bytes;
  monitored to unmonitored is native; unmonitored to monitored returns
  NOT_SAME_DEVICE and its copy stages/blocks as appropriate. Moving outside
  protection is native; outside-to-protected still uses staged copy.
- D4/D5: create/write, then rename after 0/100 ms, before/after close/op19/seal,
  while inspecting and before final rename. Clean and CPF variants; old-name
  absence for a new private temp, exact inspected bytes only at the final name.
  Word Save As and overwrite, published-to-WRL backup, WRD-to-final retarget,
  backup delete, and a zero-byte placeholder both pending and already published.
  Repeat with Explorer, Rename-Item, DeleteFile/Remove-Item and real app handles.
- D6: pause the publisher immediately before final rename and race native source
  delete/rename, replacement target cancellation, private retarget and restart.
  Cancelled generations never publish. An already successful rename is not
  replayed. Repeat with a later pending, blocked and published save while a
  scheduled delete is open; verify NTFS last-close results and recovery holds.
