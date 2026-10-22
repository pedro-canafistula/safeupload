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

The current [status plan](../../../POST-MVP-PLAN.md) records the demo decisions. The
[reported evidence](/home/victor/Work/safeupload-staging/driver/evidence/2026-10-16/demo1/)
was read without changing the main worktree or its evidence.

## 2026-10-17 integration review corrections

The independent review of `412f05ad` returned REVISE for two P1 findings;
the lease/retirement delta had no additional P0/P1 finding. This correction
still needs independent acceptance and a new WDK build before qualification.

- Native CREATE eligibility is only permission to attempt routing. DOC retains
  its original writer intent until a private handle or the complete native
  fence/preflight/post path owns it. Readmission restores that original intent
  and rechecks the full eligibility predicate after an unlocked receipt wait.
  Uncertain identity refuses DOC. A final dispatch guard prevents an unresolved
  or protected DOC declined by both routes from reaching legacy CREATE; only a
  resolved, alias-checked outside name can release that guard.
- A public replacement with no unpublished cancellation obligation goes to
  native NTFS without the legacy approximate permission gate. Before cancelling
  pending private work for any rename, a dedicated helper validates the original target-parent
  object's full identity and checks target DELETE **or** parent DELETE_CHILD
  against one captured original subject, using descriptors read from the exact
  bound objects. It relies on the original I/O-manager parent lookup for
  traversal/create-child authority, without requiring bypass-traverse privilege
  or reopening under SYSTEM authority. NULL ParentOfTarget is accepted only for
  a simple relative leaf in the existing source parent, with current ADD_FILE
  checked there. A non-replacing collision refuses before cancellation.
  Same-object rename retains the source handle's DELETE grant; an exact
  case-sensitive same-name no-op needs no new ADD_FILE grant.
  Original rename flags and share state stay with NTFS, including its final
  refusal after a terminal private cancellation.

References: Microsoft's [SET processing](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/set-file-information-processing)
and [replacement access checks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-set-information3).
Host controls execute the routing, readmission and supplemental authority
bodies with GCC and Clang/UBSan, including denied/both-granted delete
alternatives, original restricted subjects, exact-object substitution, query
faults and missing parent evidence. They do not qualify native Windows behavior.

## ux/nsfix re-review 2 and ns-k2 corrections

Base `ee14eee8` (the first correction plus the owner's initial PREfast fixes).
The supplied [re-review](../../../../.scratch/review2.md) closed the original stale-source
and authorization-ordering findings and found no further blocker in the leak
rework. It returned **REVISE** for the following three P1 cases. The supplied
[ns-k2 receipt](../../../../.scratch/ns-k2-prefast.txt) also failed PREfast; the corrections
below are source changes and passing host controls, **not a passing WDK build**.

1. **Deferred directory registry completion.** The epoch wrapper now requests
   `FLT_PREOP_SYNCHRONIZE` for every fenced SET_INFORMATION, including directory
   rename and disposition. Normal completion finishes the bounded registry
   rewrite before the epoch releases exclusion. This uses the documented
   [synchronized-completion contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/returning-flt-preop-synchronize)
   without retaining a resource across lower I/O. Draining may still defer; its
   existing fence remains latched until reboot. `NameActivating` additionally
   consults the existing live directory-rename range records under RegistryLock,
   gating both old and new prefixes until completion removes the record. It
   never clears an entry's Sticky Unknown reason. The host control compiles the
   real directory completion, deferred worker and name gate, pauses the injected
   DISPATCH queue, and attempts new-name admission before running the worker.
   New/old ranges stay held; an adjacent sibling remains outside the range.
2. **Native routing / writer-demotion mismatch.** `StageMvpNamespaceCreateEligible`
   is now the shared predicate for native CREATE routing and writer demotion.
   It includes options, operation flags, transaction/IRP context, fixed NTFS and
   the existing protocol/service exclusions. OPEN|DELETE_ON_CLOSE|OPEN_REPARSE_POINT
   therefore keeps writer classification when native pre declines it; it must
   take ordinary staged admission or refuse. It cannot fall through to an
   unfenced legacy public CREATE. The cross-owner control combines the full
   native pre with the actual demotion and absent-requester-view fallback
   fragments from StageAdmit/StageCreate; the excluded open cannot acquire a
   legacy handle or cancel the other owner's pending sealed save. Reinstating
   the former intent-only demotion fails this executed control.
3. **Alternate successful CREATE outcomes.** Native post now recognizes
   `NT_SUCCESS` opened-object outcomes, including
   [STATUS_OPLOCK_BREAK_IN_PROGRESS](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/breaking-oplocks),
   rather than testing exact STATUS_SUCCESS. Opened/created/overwritten/superseded
   information requires an actual FILE_OBJECT with FsContext; reparse, pending,
   failures and non-open information are excluded. The original object's DELETE
   grant and exact file ID are still checked, then pending saves are cancelled,
   before handle exposure and fence release. Successful informational status is
   preserved. Controls exercise ordinary/oplock/informational success across all
   opened information values, object substitution, reparse/pending/failure and
   non-open outcomes. The former exact-success test fails these controls.

PREfast/source-contract corrections:

- C28213: `StageRenameShareAllowed` and `StageMvpNamespaceOpen` definitions now
  carry `_Use_decl_annotations_` alone. Their original IRQL contracts remain on
  their prototypes; the owner's corrected cancellation prototype is preserved.
- C28150: the spin-protected RenameExchange install is now a `noinline` resident
  helper with DISPATCH-capable entry and same-IRQL return contracts. The PAGE,
  PASSIVE StageRename calls that helper while retaining the original lock order;
  no raised-IRQL instruction remains in its PAGE body. The helper has no wait,
  allocation or name access. Host controls verify incoming IRQL is restored at
  PASSIVE/APC/DISPATCH.
- All remaining private-rename reads of StageDirectorySequence are interlocked.
  The new `namespace-contract-selfcheck.py` audits both changed production units
  for combined `_Use_decl_annotations_`/SAL, late PAGE pragmas, non-interlocked
  fence/sequence accesses and the PAGE spin-lock pattern, with negative controls.
- C6001/C4701: namespace binding structs and observation/snapshot locals are
  initialized. External rename also requires an explicit successful binding
  capture before revalidation; zero initialization never supplies authority.

Verification: all 7 kernel runners (17 unittest tests), all 15 T5 Python
self-check runners (105 unittest tests plus the 14-assertion Notepad verdict
control), and all 3 UX runners (9 tests) passed. T11 SOP lifetime (3 tests), T4
verdict self-check and the offline import-gate self-check passed. The expanded
namespace runner passes with cc/clang, warnings as errors and fatal UBSan;
15 compiled negative mutations and the source-contract rejection controls fail
as required. The namespace runner was repeated after its final admission-fragment
control was added. No assertions, thresholds or warnings were suppressed.

The corrected source API inventory uses the vcxproj's 22 production translation
units and top-level headers: four new internal helpers, no new external API
symbols. The first inventory mistakenly included host fixture C files; its failed
receipt is retained separately. Raw receipts and failed attempts are local under
`.scratch/nsfix2-verification/` and `.scratch/namespace-ux-*`. No agent code changed.

Remaining gates: focused independent re-review, feature Debug/Release WDK +
PREfast + ApiValidator at 0/0, both binary-import availability results, then the
matched Windows/Verifier pair on win10-debug3. Add native rows for paused directory
completion/new-name admission, the exact cross-owner reparse-flag delete-on-close
sequence, and FILE_COMPLETE_IF_OPLOCKED alternate success with independent
identity/cancellation receipts. Keep the earlier Word swap, placeholder,
file/folder interleaving, denied-authority and fault/draining rows below.
No VM or remote build was run here. Shared Git metadata is unchanged; delivery is
`.scratch/ux-nsfix2.bundle`, head `ux/nsfix`, based on `ee14eee8`.

## ux/nsfix pre-boot review corrections

Follow-up base `597d09d1`, branch `ux/nsfix`, 2026-10-16. The supplied independent
Sol 6.1 xhigh review of the same kernel code at `85e89b7f` returned **REVISE**
([local review](../../../../.scratch/review1.md)). These are implementation corrections to
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

Historical round-1 annotation claim (corrected after ns-k2 above): the added
helpers repeated IRQL contracts on definitions. PAGE placement is
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

### D7 — OPEN_REPARSE_POINT opens of regular files take the native route (owner 2026-10-21; revision 3, design ACCEPTED)

Reviews: [revision 0](../../../evidence/2026-10-21/t5-d7-review-sol61.md) REVISE; revision 1 re-review REVISE
([evidence](../../../evidence/2026-10-21/t5-d7-rereview-sol61.md)): findings 1 and 3 resolved; revision 2 re-review REVISE
([evidence](../../../evidence/2026-10-21/t5-d7-rereview2-sol61.md)): findings 1, 2, 3, 5, 6 resolved. Revision 3 answers its blocking
finding 8 (unload race) and conditions 4 and 7. Revision 3 re-review: **ACCEPT, design only**
([evidence](../../../evidence/2026-10-21/t5-d7-rereview3-sol61.md)); host controls, an implementation review, WDK/PREfast/ApiValidator/
import gates and Windows rows remain required before qualification.

**Evidence and diagnosis (finding 1).** Row `m2t5ord8` ([T5 checkpoint](../../../evidence/2026-10-21/t5-checkpoint.md)): `DeleteFileW` of a
published protected file returned 5. `DeleteFileW` opens with DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE and FILE_OPEN_REPARSE_POINT,
then sets FileDispositionInformationEx and falls back to FileDispositionInformation. `StageMvpNamespaceCreateEligible` excludes
FILE_OPEN_REPARSE_POINT (round-1 item 2 below), so the open keeps writer classification (DELETE is writer access) and is staged as a
seeded private version (journal: allocation 34–87 ms before each refusal). Owned-stream routing precedes native namespace routing
(`StageDispatchCore`), and for that unsealed staged handle the disposition reaches `StagePublicNameFree`, which refuses a name that
exists publicly (`StageStream.c` ~5330; sealed versions take the separate cancellation branch ~5314). The deny-ring records are entries
109–112 of the full row result (kept locally; the tracked verdict retains entries from 113). `del`, `Remove-Item` and Explorer's
permanent delete of a published file therefore fail; recycling is a rename and works. T5 requires both `DeleteFileW` calls to succeed.

**Scope.** A *D7 request* is a CREATE that (a) carries FILE_OPEN_REPARSE_POINT, (b) is FILE_OPEN or FILE_OPEN_IF (narrowed to
FILE_OPEN as for D1), (c) does **not** carry FILE_DELETE_ON_CLOSE, (d) requests no content-writing access (the access mask
`StageMvpNamespaceOpen` already excludes; FILE_READ_DATA is permitted as for D1), and (e) whose writer classification comes only from
DELETE and/or FILE_WRITE_ATTRIBUTES. Directory, by-file-ID and SL_OPEN_TARGET_DIRECTORY opens stay excluded. **FILE_DELETE_ON_CLOSE |
FILE_OPEN_REPARSE_POINT stays excluded in the shared routing/demotion predicate** (today's staged admission or refusal): a cancelled
delete-on-close CREATE can still apply NTFS delete effects during cleanup, so a post check cannot prove a link intact. The predicate
change is exactly "a D7 request is eligible", never a bare removal of the reparse exclusion.

**Classification and declines (condition 2).** The D7 request is classified from the CREATE parameters first, independently of the
rest of eligibility. The existing service early returns (authenticated inspector, protocol native forward) and the transaction /
top-level-IRP / non-fixed-volume returns keep today's handling for this flag (staged admission or refusal), never an unguarded legacy
CREATE. Once a D7 request names a protected fixed-NTFS path, every later decline (identity query failure, unresolved name, non-NTFS,
binding failure, completion-context allocation failure) completes STATUS_ACCESS_DENIED in pre. The only exception is genuine
private-view routing (`StageFindView`/hidden name), which keeps its private route; this newly admits such reopens to the existing
bounded D4 receipt wait, which retains its explicit pin and drops resources before waiting (no new wait or timer).

**Completion ownership (condition 5, blocking finding 8).** An admitted D7 request allocates a small nonpaged per-CREATE context in
pre holding the identity captured in pre (FileIdInformation from the existing `SafeUploadStageQueryIdentity`), the legacy completion
context and the legacy callback-required flag. It never touches the fenced singleton `StageMvpNamespaceCreate*` state and acquires no
namespace fence. Pre returns FLT_PREOP_SUCCESS_WITH_CALLBACK through the existing admission-epoch wrapper, so the context is the epoch
token's inner completion context, and the epoch is released only after this post ran. `StagePostOperationCore` recognises the context
by its own tag before generic legacy CREATE processing.

**Voluntary unload (blocking finding 8).** Voluntary unload does not wait for epochs: it closes admission
(`StageSetUnloadAdmissionClosed(TRUE)`) and then takes zero-count snapshots (`SafeUploadPolicyPublicationQuiescent`, before and after
quarantine), vetoing while any epoch callback is active. A CREATE can pass the initial unload-admission gate in the pre-operation entry,
pause before `SafeUploadPolicyAdmissionAcquire`, and resume after the last snapshot; the unfenced namespace path has no later gate. So a D7
request, after its epoch is acquired and before any lower I/O, re-reads `StageUnloadAdmissionClosed` and
`SafeUploadStageMandatoryTeardownActive()` with interlocked reads; if either is set it completes STATUS_DEVICE_NOT_READY in pre, as the
initial gate does, and frees its context. Ordering: unload's interlocked close precedes its snapshot taken under `SafeUploadEpochLock`;
the CREATE's epoch acquisition (ActiveCallbacks increment under the same lock) precedes its interlocked read. One of the two always
observes the other, so either the snapshot sees the active callback and unload vetoes, or the CREATE sees the closed gate and refuses.
Voluntary unload is therefore **vetoed while a D7 validation is outstanding**; it never proceeds past one, and no lower CREATE of a D7
request starts after unload committed. Pre frees the context itself on every refusal or allocation failure, where no post follows.
**A draining post** (mandatory teardown) frees the context, leaves the status unchanged and claims no refusal: draining is cleanup on
copied callback data, not enforcement. Mandatory teardown follows the existing coverage-loss rules (the namespace latch stays closed until
reboot; the fixed-NTFS forced-teardown exception); D7 adds nothing there.

**Post validation (blocking finding 4).** In a non-draining post, before the legacy post, any cancellation, or handle exposure:

1. *Genuine non-open:* the lower CREATE failed (`!NT_SUCCESS`) or returned STATUS_REPARSE. Free the context and run the legacy post as
   today; nothing else.
2. *STATUS_PENDING in post* (not a completed outcome): fail closed with STATUS_ACCESS_DENIED / Information 0; never forwarded to legacy
   processing.
3. *Unexpected successful outcome for this OPEN-only route:* NT_SUCCESS with any information other than FILE_OPENED (FILE_CREATED,
   FILE_OVERWRITTEN, FILE_SUPERSEDED, FILE_EXISTS or another value). Refused, not passed through: FltCancelFileOpen when a FILE_OBJECT with
   FsContext exists, STATUS_ACCESS_DENIED, legacy post skipped.
4. *Opened outcome with invalid object evidence:* NT_SUCCESS (including informational/oplock-break-in-progress success) with
   FILE_OPENED but no FILE_OBJECT or no FsContext. Fail closed: set STATUS_ACCESS_DENIED / Information 0 and call no object-dependent API
   on invalid pointers. Skip the legacy post.
5. *Opened object:* query FileAttributeTagInformation and FileIdInformation on the opened FILE_OBJECT, synchronously, at PASSIVE, outside
   every resource. Pass only if both succeed with complete replies, FILE_ATTRIBUTE_REPARSE_POINT is clear (no tag allow-list) and the
   file ID equals the pre-captured identity (a different regular object substituted between pre and post fails). Otherwise
   FltCancelFileOpen, STATUS_ACCESS_DENIED, and skip the legacy post. On a pass, run the legacy post with the stored context and flag; a
   legacy-post denial cancels the open itself, and D7 cancels nothing further (no double cancel).

This proves the final object's attribute and identity only; name/parent/no-follow bindings stay as today. The pre identity lookup
(`StageSecurity.c` IO_STOP_ON_SYMLINK) already refuses symlinks and directories before post; post validation covers a reparse point or
substitution that the pre lookup did not see.

**Mutations stay on the fenced D2/D3 path (condition 6).** A D7 CREATE cancels nothing; a MoveFileExW source open validates without
cancelling, and the later rename owns cancellation. In the `StageMvpNamespacePre` SET_INFORMATION branch, at PASSIVE, after
`StageNamespaceBeginMutation` and `StageNamespaceCaptureBindings`, outside every resource and before the first `StageMvpCancelNames`
call, the handle's FileAttributeTagInformation is queried; failure, a short reply or a reparse attribute refuses the SET_INFORMATION with
STATUS_ACCESS_DENIED (no FltCancelFileOpen in a pre-SET path). Published-only successor suppression, D3 rename flags, NOT_SAME_DEVICE
copy fallback and hard-link gates are unchanged; deleting one hard link affects only that link. No new lock, RPC under a resource or
retirement path.

**Controls before the first boot (condition 7).** Host/source controls, each with a negative mutation (guard removed, cancellation moved
before validation, identity comparison dropped, or context leaked) that must fail:

1. DELETE-only and DELETE | WRITE_ATTRIBUTES D7 CREATE of a published regular file: native open, post passes, no allocation, no
   cancellation at CREATE; a later disposition and a MoveFileExW rename take the fenced D2/D3 path.
2. Pre identity lookup refusing a symlink or directory (refused in pre, no post) kept distinct from an injected reparse attribute or
   substitution seen only in post (cancelled after the query); the other owner's pending save untouched in both.
3. Tag or ID query failure and short replies; a different regular object substituted between pre and post (refused by identity);
   NT_SUCCESS/FILE_OPENED without FILE_OBJECT or FsContext (refused without object calls); informational and oplock-break success.
4. WRITE_ATTRIBUTES without DELETE; FILE_READ_DATA with DELETE; OPEN_IF narrowing; NTFS caller DELETE/share denial (no validation side
   effect, no cancellation); failed lower CREATE; legacy-post denial (single cancel).
5. Pre refusal and context-allocation failure free the context; concurrent D7 opens and fenced mutations never share state; a draining
   post frees the context without changing status; the epoch is released only after the post.
6. DELETE_ON_CLOSE | OPEN_REPARSE_POINT still excluded; the round-1 cross-owner control rewritten so an authorized regular-file
   delete-on-close CREATE (no reparse flag) still reaches fenced cancellation while real-reparse, denied or uncertain D7 opens leave the
   other owner's save untouched.
7. A reparse attribute set on a validated open handle before SET_INFORMATION disposition: refused before any cancellation.
8. Private-view reopen of a D7 request: private route and bounded receipt wait/readmission unchanged.
9. Unexpected successful outcomes (FILE_CREATED, FILE_OVERWRITTEN, FILE_SUPERSEDED, FILE_EXISTS, unknown) and STATUS_PENDING in post:
   refused, never passed to the legacy post.
10. Unload race: a D7 CREATE paused between the initial unload-admission gate and epoch acquisition, with unload closing admission and
    snapshotting in between, in both interleavings: either unload vetoes on the active callback or the CREATE refuses
    STATUS_DEVICE_NOT_READY before any lower CREATE; no lower CREATE occurs after unload committed. Mandatory teardown active at the
    recheck: refused.

Native evidence to record in the T5 row (not a substitute for the controls): the actual access and options of `DeleteFileW` and of
`MoveFileExW`'s source open, from the driver's admission trace. Then WDK feature Debug/Release, PREfast, ApiValidator and import gates over
both builds, and the T5 row's public-delete cases in all three modes. Host controls do not establish NTFS cleanup behaviour or
qualification.

### D7 revision 5 — native-route writers take the writer-registry reservation (2026-10-22; accepted with conditions)

Revision 4 (`42769931`) drew a Sol 6.1 high REVISE ([review](../../../evidence/2026-10-22/t5-d7-rev4-review-sol61.md)): an unload guard for D1,
the nullable-reservation contract, explicit DOC post ordering, and stronger controls. The first implementation of revision 5
(`b3c87c70`, registry post before the legacy post as in the generic path) drew a second REVISE
([review](../../../evidence/2026-10-22/t5-d7-rev5-review-sol61.md)): a node registered before a later cancellation is never retired, because
`FltCancelFileOpen` delivers its cleanup below the supplied instance only, so the registry post must be last. This text is the corrected
revision; its re-review at `3a16ec0f` is **ACCEPT WITH CONDITIONS** ([review](../../../evidence/2026-10-22/t5-d7-rev5-rereview-sol61.md)): no source blocker to the first boot after the build gates; qualification needs zero Unknown masks/origins (`T5WriterRegistryKnown`) and a later approved publication, and those observations are not exhaustive proof of registry accounting.

**Evidence.** Row `m2t5ord9` ([T5 checkpoint](../../../evidence/2026-10-21/t5-checkpoint.md)) on the accepted D7 implementation
(`9eb46e87`, signed `26075F68…`): after the first native D7 `DeleteFileW` the agent logged "Admission coverage Degraded:
WriterStateUnknown", and from then on the legacy create gate refused every approved publication (fail-closed held: refused, not
exposed). The bypass is confirmed in source: the registry classifies DELETE and FILE_WRITE_ATTRIBUTES opens as writers
(`StageWriterCreateCanMutate`) and expects a reservation, which only the generic CREATE path takes
(`SafeUploadStageWritersReserveCreate` in `StageDispatchCore`); the native namespace route returns before that point. The registry's
cleanup marks `SAFEUPLOAD_REGISTRY_UNKNOWN_CLEANUP` both for a writer handle with no stream context and for a context lacking that
exact node, so the unmatched cleanup of a D7 handle explains the Unknown. That it was the *first* Unknown in the row is strongly
supported but not proved: the event reports only `WriterStateUnknown`, not the origin, and the row did not capture the reason mask.
The next row therefore records the registry's Unknown reasons and first-Unknown origins afterwards (`T5WriterRegistryKnown`). The same
bypass exists for the pre-existing D1 non-mutation route and the native delete-on-close (DOC) route whenever their open is
writer-classified; D7 made it common.

**Rule.** Every CREATE that the native namespace route admits and that `StageWriterCreateCanMutate` classifies as a writer takes the
writer-registry reservation, and its post consumes it:

1. *Unload / teardown guard.* A native CREATE that will own a reservation (any writer-classified open: D7, D1, DOC) repeats the
   post-epoch recheck of `StageUnloadAdmissionClosed` and mandatory teardown before any name, identity or reservation I/O, as D7 does.
   Epoch acquisition still admits a callback after unload's last zero-count snapshot, so either the snapshot sees this callback and
   unload vetoes, or this read sees the closed gate. Non-writer D1 opens keep the bare legacy context and no recheck.
2. *Where the reservation is taken.* After the legacy pre-create (`SafeUploadPreCreate`), so a legacy COMPLETE never leaves one, and
   before the lower CREATE. The call is `SafeUploadStageWritersReserveCreate` with a NULL alias proof (the native route has none; a NULL
   proof cannot manufacture an outside-scope classification). A failure cancels any partial reservation and records
   `SafeUploadStageWritersTrackingLost(ALLOCATION)`; a required reservation that could not be made does the same. Reserve may also
   succeed with no reservation (not a writer, excluded, out of scope, instance already Unknown); that is not an error and nothing is
   recorded. Nothing after the reservation can refuse the CREATE (DOC: the fenced singleton is stored and the callback returned).
3. *Ownership.* The legacy completion context and callback flag stay in the existing owner independently of the reservation: the
   per-CREATE context (D7 and D1 writer opens) or the fenced singleton (DOC), with the reservation as a separate nullable field. Neither
   uses `SafeUploadStageWritersSetCompletion`. The registry post is never called without a reservation. A reservation is consumed by
   exactly one registry post (or one cancel) and the owner's field is cleared before that call.
4. *Post ordering: the registry post is last.* Every step that can deny or cancel the open comes first, and the registry post then reads
   the final status, so a refused or cancelled open is released without tracking and no node is ever registered for a handle this filter
   cancels (`FltCancelFileOpen` delivers its cleanup/close below the supplied instance, not to this filter, so such a node could
   never be retired).
   - **D7:** validation first; a refusal cancels the open where it did, sets `STATUS_ACCESS_DENIED` and runs no legacy post. A pass or a
     genuine non-open runs the legacy post (which may itself deny and cancel). Then the registry post. Draining: no validation, no
     legacy post (unchanged from the accepted rev 3, which skipped it even without a reservation), then the registry post, which
     records teardown Unknown and releases.
   - **D1 writer open:** no object validation; legacy post, then the registry post; draining skips the legacy post as D7 does.
   - **Fenced DOC:** legacy post (also under draining, as before this delta), identity validation and the single pending-version
     cancellation, then the registry post, all before the fence and epoch are released. A legacy denial cancels the open and sets the
     failure status, which the identity step then sees as not opened, so the pending save is cancelled at most once and never for a
     denied open; the registry post then releases without tracking.
   - The registry post returns success for tracking loss (the loss is recorded inside) and failure only when draining; the callers
     ignore the return value and neither treat success as proof of tracking nor re-record the loss.
   - This differs from the generic CREATE post, which registers before the legacy post and so can leave a node for a handle that the
     legacy post then cancels. That existing behaviour is outside this delta and is not changed here.
5. *What registers.* An open that survives every denying step registers exactly as a generic writer open does, through the same
   `SafeUploadStageWritersPostCreate`; its exact-object cleanup is the ordinary IRP_MJ_CLEANUP post path, unchanged. This delta adds no
   registry code, lock, or retirement path.

The reserve and post calls run at PASSIVE, after `StageListLock` and the namespace resource are released, and the registry post
finishes before the fence and epoch release. They add existing blocking work to these paths (a name query and the registry push lock;
for DOC under the directory-mutation fence, which is a flag and the epoch, no resource). The second review found no path that holds the
registry lock while waiting for that fence.

**Controls.** Host fixture `namespace_ux_fixture.c` compiles the production pre/post paths and the production writer classifier against
a registry boundary that models the API contract (reserve outcomes 0-4, consume-once, draining failure, release on failure status,
register on success) and records a call trace. It asserts: reserve after the legacy pre and before the lower CREATE (trace `LR`); legacy
post before the registry post (`LRpP`); every D7 refusal class sets the failure status before the registry post and runs no legacy
post (`LRXP` / `LRP`); a legacy denial or a DOC identity failure cancels the open before the registry post and no node is registered for it
(`LRpXP`, registered 0, released 1); lower failures and `STATUS_REPARSE` release without tracking and still run the legacy post;
draining; all four reserve outcomes with and without a reservation, including cancel of a partial one and tracking-lost recording;
several concurrent contexts posted out of order; D1 writer versus non-writer owners; the unload and mandatory-teardown recheck for D1
writers, before any name or identity I/O and with unload closing after the recheck; DOC variants (success, lower failure, legacy denial,
identity substitution, draining, no reservation, legacy COMPLETE, partial reservation) with one pending-version cancellation; native
SET_INFORMATION never reserves; no live reservation, context or singleton remains. 53 negative mutations, including registering before
the legacy post or before the refusal status in D7 and DOC, are each killed by an intended assertion
([receipts](../../../evidence/2026-10-22/t5-d7-rev5-host-mutants.json)).
The host controls do not compile `StageWriters.c`. With the registry post last, this delta calls the registry only with the final status
of an open nothing will cancel, so its node insertion, `H`/reference accounting and exact-object cleanup are the unchanged generic ones,
exercised on Windows. The next T5 row therefore captures the driver's registry Unknown masks and first-Unknown origins after the
public-delete cases (`T5WriterRegistryKnown`, required: all zero) and requires a later approved publication to succeed.

### D8 — a cancelled private version the driver already released (2026-10-22; review pending)

**Evidence.** Rows `m2t5ord10` and `m2t5ord11` (D7 revision 5 driver): Notepad's Save As probe leaves an empty private version that is
sealed and then cancelled by a native operation (journal history `0,10,1,7`, `UnboundCancellation` generation 2). The service deletes
its exact stage (the staging directory is empty after the run), yet for the rest of the run the agent logs "Staged recovery holds …
state Retained … recovery_evidence_unavailable … Cancelled stage disposal acknowledgement is pending" about every 6 s and the journal
entry never completes (`ok.txt`, `cpf.txt`; with `ord8`'s older driver the same probe was discarded before sealing and left nothing).
The row's counters show `disposeNotHeld` 59 against `disposeHeld` 25.

**Cause.** The driver accepts a cancellation (`StageCancelSealedPrivate`) by marking the stream's view detached. `StageTryRelease`
frees a detached, sealed stream that has no handle, section, RPC or receipt without waiting for any service disposal, so it normally
disappears within the worker pass that follows the accepted cancel. The service's cleanup for an unbound cancellation deletes the exact
stage and then reports the disposal (`StageDispose`, outcome CleanedUp); by then no stream with that transfer id exists and the driver
answers `Held = 0`. `RecoverPendingTransferAsync` treats `Held = 0` as "acknowledgement pending" and retries for ever, although there
is nothing left to acknowledge. The older flows only completed when the service happened to win the race.

**Rule.** In the unbound-cancellation branch of recovery, once the exact stage is confirmed absent (`TryDeleteExactAndConfirmAbsent`,
unchanged), both answers of the disposal call complete the cleanup: `Held = 1` (the driver still held the version and accepted the
disposal) and `Held = 0` (the driver holds no version of this transfer, so no reference to the stage remains in it). A refused or
malformed call (an exception) still keeps the obligation pending and diagnosed. Nothing else changes: the Released and Blocked paths
keep their exact receipts, `Held = 0` is not accepted as proof that a stage was deleted (the proof is the service's own exact
identity delete and absence check), and no path completes on it without the journaled cancellation receipt, which already blocks
inspection, justification and any final publication of that version.

**Controls.** Agent tests: held, not held, and a refused call (stays pending with no completion receipt, one disposal attempt). Row
requirement (new, `T5JournalSettledAfterRun`): after the run the hot journal holds no entry, so no Notepad probe stays Retained.

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
[the round 2 receipt](../../../evidence/2026-10-16/ux-kernel-namespace2/result.txt).
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

[Local result and source hashes](../../../evidence/2026-10-16/ux-kernel-namespace1/result.txt)
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
