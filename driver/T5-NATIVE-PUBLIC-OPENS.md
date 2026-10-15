# T5 native public opens and delete lifetime

## Ordinary public disposition integration — proposal for review, 2026-10-12

**Review status: READY WITH CORRECTIONS; Luna 6 max confirms the recorded conditions permit implementation.**
This is design approval only; the relay, integrated lifetime review and protected runtime remain open.

The remaining ordinary-delete path must preserve the actual NTFS open and caller's DELETE grant. The earlier exported service
handle introduces a second application handle count on that same FILE_OBJECT and difficult foreign-handle revocation/reuse races.
Proposed correction: the service orders and journals the transaction, while a one-use driver permit releases the **original outer
SetInformation operation once** to NTFS. For non-writing native public opens, keep the original TargetFileObject. No service reopen,
exported handle or synthesized data FCB. Combined private DELETE+write opens retain their separately NTFS-checked public backend;
for ordinary disposition only, retarget to that exact same-volume backend, call FltSetCallbackDataDirty and pin it through postoperation.
Preserve the original operation flags, requestor mode and thread. Never route data, cache/sections or FILE_DISPOSITION_ON_CLOSE through
this retarget path. It does not revive the rejected synthetic public-FCB design. The supported retarget contract is documented in
[FLT_IO_PARAMETER_BLOCK](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_io_parameter_block).
The independent security-design review is complete; this does not permit a change in product behavior.

1. Extend the local native-object map to distinguish ordinary non-writing FILE_OPEN + DELETE from CREATE delete-on-close. Ordinary
   open does not allocate a delete generation, delete or tombstone a name. Reserve its nonpaged record before the original CREATE;
   establish a short logical destination binding reservation, then forward the original CREATE unchanged. Binding and reservation
   release use the exact original object/volume/root/parent/leaf and actual DeleteAccess. No local object reference prevents cleanup.
   NTFS owns reads, cache, sections, byte locks and sharing. Failed ordinary tracking grants no disposition authority; original open
   results remain native. Rebinding an accepted read-only object must be exact and automatic before a disposition can be authorized.
2. Capture the destination's durable Published generation at ordinary binding as evidence, without allocating a delete version.
   Bind the case-aware parent/leaf, volume and full file ID, including the binding-time Published identity. Under the destination
   turn, recheck that exact link and head before forwarding. A later delete gets a fresh transfer/nonce/operation and max+1 generation.
   An old open must never confer DELETE on a
   replacement: if exact observation shows a different identity and the shared head proves that replacement was Published after
   this open bound, the old-object operation cannot delete or tombstone the replacement. An allocated/unsealed/blocked successor
   supplies no such suppression evidence. Unexplained identity changes fail closed. Native scheduled ordering remains unchanged.
3. Queue each ordinary disposition under its exact currently open FILE_OBJECT and checked DELETE grant, including duplicate or
   inherited handles. Capture the complete original flags/information-class, requestor mode and operation sequence. Do not use
   a primary PID token as filesystem authority or recheck a DACL under SYSTEM. Pin only references needed by pending I/O, with no
   extra application handle. Normal FALSE clears still affect all provisional ordinary intents on that same checked name/object,
   across handles/owners; they cannot cancel native CREATE delete-on-close or completed deletion. FALSE without an ordinary provisional
   intent remains a native no-op: reuse ClearDisposition/PendingCommit for the exact checked object, allocate no delete generation,
   and record the actual NTFS result. The current journal's refusal of that no-op must be corrected before connecting the relay.
4. The service acquires the destination reconciliation turn, includes retained manifest/tombstone high-water and durably records
   the existing ordinary delete intent/PendingCommit before returning a typed, exact one-use forward permit. It retains the logical
   turn through NTFS result recording, outside global locks and bounded disk slots. The kernel atomically checks current channel
   authority, immutable object binding, operation sequence, cancellation and instance retirement before releasing the original
   SetInformation to NTFS. No service grant substitutes for Windows' actual handle DELETE/parent DELETE_CHILD authorization.
   Accept only exact STATUS_SUCCESS and a complete typed reply matching phase/nonce/epoch/operation/object/revision; NT_SUCCESS
   cannot authorize forwarding because FltSendMessage's STATUS_TIMEOUT is a success code. Atomically consume the permit once.
   Cancellation before consumption records exact no-forward resolution. After consumption, lost results or timeouts retain
   PendingCommit and its barrier; never replay SetInformation or infer that no mutation happened.
5. Preserve the original I/O's security/privilege context and flags through the lower operation. Preferred preoperation path is an
   inline prepare at supported IRQL, without namespace/stream/spin locks, so the original callback thread proceeds to NTFS unchanged.
   Require this inline path; no pended worker fallback is approved. Any proposed fallback needs a separately established mechanism
   preserving the original operation subject and privileges without modifying Data->Thread or falling back to SYSTEM.
6. Postoperation captures the actual NTSTATUS and complete immutable operation facts away from unsafe callback contexts. Persist accepted
   or failed disposition before completing the caller when possible. Never turn an NTFS-accepted mutation into an artificial failure
   after lost bookkeeping; retain the durable intent/hold and reconcile automatically. Original NTFS failure remains a failure.
   Close/reconnect/timeout/cancellation must release local references and permit ownership exactly once; they never imply no mutation.
7. A service crash loses its ephemeral turn but not PendingCommit. Startup reconciles exact native operation facts and anchored name
   state before releasing that destination's barrier or allowing another physical commit. No replay invokes original SetInformation
   a second time. Actual last cleanup and resolving directory events complete deletion/clear receipts. Owner tombstones appear only
   after actual accepted disposition and apply to the checked name/object, never a newer proven published replacement.
8. Ordinary read-only opens alone must not add an unload veto when no private work, mutation, RPC or cleanup is outstanding: NTFS
   owns their complete data lifetime. In-flight binding/disposition, accepted/uncertain deletion and callback/worker references veto
   voluntary unload. Mandatory shutdown drains only local work without waiting on the service, retaining durable uncertainty.

The concrete ABI must preserve existing operation/enum numbers and use distinct feature-only versions with exact packing/length,
zero-tail and phase/nonce/operation/sequence/object/generation checks. Read-only replay must expose enough immutable operation facts
to reconcile the durable intent; never infer execution from PID, a counter, absence alone or a generic verdict. Add no persisted
recovery state beyond the already approved AcceptedUnresolved; ordinary Intent/Accepted/Failed/Canceled/Complete remain as defined.
Keep admission disabled until all ordinary/native disposition, publication and recovery paths share this head.

Required controls: original ShareAccess=0, denied DELETE and parent DELETE_CHILD, readonly/image/byte-lock restrictions, FALSE across
owners, duplicate handles, old handle after a newer Published replacement, blocked successor, canceled before/after forward, lost
prepare/result, service crash/restart at each durable transition, resolving last close, all forced-order/Notepad/raw-byte assertions,
and the single integrated kernel lifetime review before the first revised boot. If the relay changes who may delete, accepted results,
or the owner's timing/automatic-recovery guarantees, stop and ask with user-visible options before implementing it.

Date: 2026-10-11. **Security design READY WITH CORRECTIONS; implementation and runtime qualification remain pending.**
The [focused Luna review](evidence/2026-10-11/t5-automatic-native-delete-recovery-review-luna6.md) requires the corrections below.
This replaces the synthetic public-FCB proposal at `05ad4df9`, rejected by the
[Luna review](evidence/2026-10-11/t5-public-proxy-routing-design-review-luna6.md).
The [focused follow-up](evidence/2026-10-11/t5-native-public-open-followup-luna6.md) also rejects its suggested second-open and
on-close emulation. The accepted empty/public-delete design in [T5-DELETES.md](T5-DELETES.md) remains in force; the corrections and
owner-approved automatic-recovery conditions below are feasible with these corrections. Integrated kernel lifetime/lock-order review
is still required before the revised pair's first VM boot; this note is not runtime qualification.

## Supported correction

For a known non-writing DELETE-capable open of an existing public name with no owner-private view, pass the **original CREATE once**
to NTFS with its original desired access, share access, effective security subject and supported flags. Attach per-open Filter Manager
state to the resulting native FILE_OBJECT. Do not open a separate native backend first: two independently opened objects conflict
when the caller requests ShareAccess=0. Duplicate/inherited application handles retain the same native FILE_OBJECT and grant.

NTFS owns this object's FCB, cache, section pointers, position and byte locks. Reads, queries, read/image mappings and paging continue
on that native object. No synthetic FCB borrows NTFS section pointers, no TargetFileObject retarget is needed for those operations,
and the private 16 MiB read bound is not applied to public reads. Preserve native mapped-file and share-mode delete restrictions.

Content writers, mutating create dispositions and requests whose rights cannot be proven non-writing before opening (including
MAXIMUM_ALLOWED/generic-all requests) continue through the private-stage path. Their checked public deletion capability stays separate
from private data. No writable app handle, writable file mapping or paging write is exposed on the public branch. This classification
must preserve the supported request surface rather than reject broad-access requests to avoid staging them.

Before forwarding, anchor the parent/canonical leaf and preallocate local context/rundown storage. A scheduled-delete CREATE also
needs its durable delete generation/intent before forwarding; an ordinary DELETE-capable open does not itself delete or tombstone a name.
Use a short logical destination reservation to exclude competing physical publication while CREATE and exact binding finish;
hold no StageNamespaceResource across RPC, file I/O or callback completion. After native success, bind the actual volume/full 128-bit
file ID and read-only native DeleteAccess grant to the original caller and any scheduled intent. An ordinary delete allocates its own
generation when the caller requests disposition. Windows remains the authority for DELETE
or parent DELETE_CHILD; there is no SYSTEM reopen, share widening, added privilege or path-based replacement capability.

An ordinary disposition uses the same currently open native FILE_OBJECT and the one-use, exact-object service transaction under the
destination journal turn. The service orders and journals the original operation without an exported second application handle;
combined private DELETE+write opens retain the separately checked backend described above. Return NTFS's actual result.
Ordinary TRUE/FALSE cancellation and accepted-disposition reservations remain as specified in T5-DELETES section 4.2.

## Native scheduled delete: preserve timing without holding all future saves

Do not emulate FILE_DELETE_ON_CLOSE with DELETE|FILE_DISPOSITION_ON_CLOSE. The
[MS-FSA contract](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/4c26c8cb-5a8f-4339-a372-b315c4974131)
requires an already deleted link for that Ex operation; the [native control](evidence/2026-10-11/t5-ntfs-disposition-control-1011.txt)
returned Win32 50. Stripping the CREATE flag and remembering it only in filter state would also lose the scheduled delete at mandatory
unload. Pass a supported native FILE_DELETE_ON_CLOSE unchanged only after its durable intent exists. NTFS then owns scheduled deletion
and duplicate-handle/last-close behavior, including during filter unload. Preserve actual unsupported extended-flag results.

The original native control allowed sharing-compatible opens before the creator closed, and became delete-pending afterward.
A long-lived scheduled-delete handle must not create an additional SafeUpload wait for every newer clean publication. The proposed
ordering therefore releases the short CREATE/binding reservation after exact durable binding; it does not retain an exclusive
publication reservation for the handle's whole lifetime. Keep a separate exact-object scheduled intent and provisional generation floor.
Newer clean generations may take their normal commit turn; only a **durably Published** newer generation suppresses removal of the
current public name. Allocated, unsealed, inspecting or blocked successors do not cancel the scheduled delete. Older generations
cannot publish through that intent. Native cleanup may remove only the originally checked old link/object, never a replacement.

Serialize the service's atomic rename and durable Published receipt under the destination turn. Persist its exact temporary identity
and generation before rename. Native scheduled cleanup acts on the original NTFS open/link; it cannot remove the replacement created
by the existing POSIX rename. If service loss interrupts rename/receipt, reconcile the exact publication intent and renamed identity
before admitting another physical commit; a changed name alone is not a durable Published receipt. A pathname's
absence or a later object's existence alone is insufficient. Do not hold a destination lock through an arbitrary reader lifetime,
silently change latency, or turn Publishing into Published to make the race pass. If this ordering cannot be implemented while
preserving the owner's rules, ask the owner before adopting a different timing policy.

The [builder control](evidence/2026-10-11/t5-native-delete-publication-control-1011a1.txt), using the existing publication flags
REPLACE_IF_EXISTS | POSIX_SEMANTICS, succeeded before creator cleanup and preserved the successor's full identity/bytes after all old
handles closed. After creator cleanup with another reader still open, both the native metadata open and publication rename returned
Win32 5. The control deliberately fails its proposed zero-result assertion; this is not product qualification or evidence that the
exceptional recovery hold can end. Do not assume POSIX rename bypasses native delete-pending. The review must distinguish exact
automatic recovery from NTFS's remaining native restriction without silently claiming cancellation/completion or approving a new delay.
Source: [native-delete-publication-control.ps1](scripts/t5/native-delete-publication-control.ps1); PS5.1 parse and encoder self-check passed.

## Owner decision: failure after NTFS accepts scheduled deletion

T5-DELETES section 4.2 currently requires failed proxy construction to leave an unchanged backend. That cannot be promised for the
unchanged native delete-on-close CREATE: NTFS may already have accepted the scheduled mutation before post-CREATE identity/context
binding fails. Microsoft's [FltCancelFileOpen contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcancelfileopen)
says cancellation does not undo changes. Preallocation reduces failures but does not prove an exact identity mismatch, I/O failure or
lost service connection is impossible. Reporting a harmless failed open would conceal a deletion that can still occur at close.

**Approved conditionally by the owner, 2026-10-11; Luna confirms feasibility with these required corrections:**

1. Before native CREATE is forwarded, a failure leaves the public file untouched and returns failure. No durable intent means no forward.
2. After NTFS accepts scheduled deletion, preserve that accepted Windows result; do not claim cancellation undid it or report a
   no-effect failure. If exact binding/recording cannot complete, keep the pre-CREATE intent and destination reservation in an explicit
   accepted/unresolved recovery state. Never fabricate an exact acknowledgement or reopen a changed path as SYSTEM.
3. Prevent further physical commits to the affected destination while the accepted mutation is unresolved; keep later edits private.
   Reconcile automatically at that app's last-handle close and again at service startup after a crash. Publication is held meanwhile,
   so the result must be absence or the original pre-open file. Release the recovery hold automatically after exact reconciliation;
   later saves are held only until then. Reconciliation needs the exact anchored object/link and durable intent.
   Existing global Unknown/reboot rules remain unchanged; this proposal grants no new automatic Unknown clearance.
4. Unbound native handles must not bypass tracked disposition/namespace mutation checks. Mandatory unload still drains only local work
   and never waits for the service; it cannot undo NTFS's already accepted scheduled delete. Retain durable recovery state on disk.
5. If reconciliation cannot decide, keep the hold, name the file and an actionable next step in the tray, and record diagnostics.
   Recovery is never a manual journal edit/unlock. Reuse the durable pre-CREATE intent and existing startup recovery; add no new
   protocol states beyond accepted/unresolved. Fault-injection rows must show the hold ends automatically after the handle closes
   and after service restart. If the automatic guarantee cannot be met, return to the owner before implementation.
6. **Owner-approved fixed-NTFS exception, 2026-10-11:** forced instance teardown can hide exact cleanup. For M2 local fixed NTFS,
   retain the named-file hold until exact evidence or a qualified Windows Restart permits automatic reconciliation. Preserve the
   service-stop prohibition and voluntary-unload veto for coverage-lost records. This exception does not apply to USB/removable:
   T21 must design automatic reconciliation at remount after the removed-volume handle can no longer change the file; do not build it now.

**What users notice:** normal empty saves, Explorer New Text Document, empty copy/move and clear-and-save keep their
ordinary publication behavior. Normal delete-on-close uses Windows timing. In the exceptional tracking-failure case, Windows' accepted
delete may still finish; SafeUpload holds further saves to that name private until automatic close/startup reconciliation establishes
the exact result. If it remains undecidable, the tray names the affected file and tells the user the applicable next step.
It does not tell the application that an already accepted delete had no effect.

The approval does not establish implementation feasibility or approve dropping delete-on-close support, weakening existing rows,
or narrowing the MVP to DeleteFileW-only behavior. M2 public-delete qualification remains open.

## Reviewed automatic-recovery construction

The existing destination head already has a durable physical intent and a reconciliation turn that bypasses its logical hold.
Its wait releases the destination semaphore, global journal gate and worker thread. Reuse that head/queue, not a second recovery
protocol. Append one AcceptedUnresolved value without renumbering persisted enum values and persist it before forwarding CREATE;
it conservatively reserves the destination even if a crash prevents recording NTFS's result. Unresolved pre-CREATE intents remain
nonpublishable if the service disconnects before it can persist the accepted result. Durable intent is recovery evidence, never
proof of a DELETE grant or physical completion.

Before forwarding original CREATE, allocate a bounded nonpaged record and register it against the original TargetFileObject under
local rundown. Include operation/transfer identity, anchored destination, original full file ID and pre-CREATE journal generation.
That fallback record must survive failure to attach the post-CREATE stream-handle context: cleanup cannot depend on the operation
whose failure selected this path. No driver/service handle keeps the application open alive; no context/FILE_OBJECT reference cycle.
The [cancelled-CREATE review](evidence/2026-10-11/t5-native-cancelled-create-design-luna6.md) additionally requires a **non-owning**
original-object lookup: retaining an object reference across upper post callbacks can prevent CLOSE after an upper filter cancels
before any app handle exists. The pending CREATE/completion context pins local record ownership; remove lookup keys at actual
CLEANUP/CLOSE or callback-coverage loss before object-address reuse. Correlate CREATE completion through its preallocated record,
even after instance teardown removed the object lookup. Lower-filter cancellation with `FO_FILE_OPEN_CANCELLED` and no created handle
remains accepted/unresolved and starts exact automatic parent/identity reconciliation without waiting for an unobservable CLOSE.
For upper-filter cancellation, the exact canceled-before-handle CLOSE completion is its separate terminal lifetime receipt.
Neither receipt proves physical deletion or grants a delete permit. `STATUS_REPARSE` is not an accepted open.
Record references are local lifetime bookkeeping, not a new protocol state. Complete registration/allocation failures before
forwarding; never rely on a fresh allocation in failed post-CREATE or cleanup.

For this exact recorded object, pre/post IRP_MJ_CLEANUP records last-handle cleanup and wakes existing asynchronous reconciliation
outside StageNamespaceResource. CLEANUP, not CLOSE or PID exit, identifies the last application handle; duplicate/inherited handles
do not release the hold early. Microsoft's [cleanup contract](https://learn.microsoft.com/en-us/previous-versions/windows/drivers/ifs/irp-mj-cleanup)
distinguishes zero handles from outstanding cache/memory references. [Stream-handle context attachment](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltsetstreamhandlecontext)
can only occur after native opening, which is why failed attachment needs the preallocated fallback. A draining callback is not a
physical-delete acknowledgement.

Extend the existing service startup recovery entry point to reconcile these destination intents before physical publication is
admitted. A surviving driver replays exact live/cleaned records for its authenticated instance; a service restart must not infer
cleanup from pathname, process ID or a changed connection epoch. Cold-driver recovery must not treat reload as proof that old native
handles closed. Reconciliation verifies anchored parent/canonical leaf, full original identity and durable intent under the existing
destination turn. Missing/replaced/unreadable anchors, unexplained replacement or unknown native state remain held and diagnosed.

At exact recorded last-handle CLEANUP and service startup, enter the existing reconciliation turn and enumerate the anchored parent
with FileIdExtdDirectoryInfo / FILE_ID_EXTD_DIR_INFO. Validate complete enumeration, stable parent identity, canonical leaf and full
FILE_ID_128. This is read-only directory metadata, not a child reopen or share widening. The
[builder control](evidence/2026-10-11/t5-native-pending-link-control-builder-1011a1.txt) found the exact pending original despite a
Win32-5 child-open refusal, then found exact absence after last reader close; supported-VM/protected recovery rows remain required.
`StagedDestinationNameObserver` implements this read-only observation on borrowed, checked directory handles: verify root/parent
identities, non-reparse directory type and case mode, then require two complete matching enumerations and unchanged anchors. It
never opens the child or interprets access denial as absence. The production transport below returns metadata directly;
the live recovery call remains pending.

**Reviewed transport correction.** Perform that same read-only anchored observation in the driver and return
the checked metadata instead of exporting directory handles. The
[Luna review](evidence/2026-10-11/t5-native-observation-transport-review-luna6.md) requires the original Mount Manager volume GUID
in the native binding and durable anchor, alongside root/parent full identities and canonical
leaf in the durable head. Its query binds the authenticated current driver/connection/boot/replay revision and those exact identities,
case mode and leaf. It grants no access to the public file and carries no DELETE permit, file handle or cleanup ACK.

For surviving-driver and qualified-Restart recovery, select a currently attached fixed NTFS instance by its exact recorded Mount
Manager volume GUID, then open its root as a directory and verify the recorded volume serial plus full root ID. A serial/root-ID match
alone can select a clone while the original is absent. Legacy missing-GUID records remain held; never backfill from a replacement.
Reject missing/ambiguous matches, an incomplete instance enumeration,
retiring/untrusted instances and any changed authority. Open the parent by file ID relative to that checked root, never by the saved
locator; NTFS may use an eight-byte file-ID selector only when the recorded high half is zero, but compare the resulting complete
128-bit ID and volume serial before use. Query directory/non-reparse type and exact case mode, perform two complete matching
extended-ID directory enumerations for the canonical leaf, then recheck both anchors and the instance gate. A child-open refusal is
never interpreted as absence. The existing observer's enumeration bound remains fail-closed; there is no truncation-based absence proof.

The authenticated port callback pins the exact service process/connection and references candidate instances while running this
metadata I/O outside namespace/native locks. Close every local directory handle and release references before returning the reply;
no cross-process handle lease/revocation protocol or application FILE_OBJECT hold is added. Bracket I/O with unchanged quiescent
topology generations and no setup/teardown in flight; check the instance retirement gate before/after opens and queries.
Bind the reply to the requested tuple,
destination and leaf, recheck native replay revision and connection at completion, and reject malformed/stale/partial replies in the
service. The service still independently checks lifetime proof and enters its destination reconciliation turn before downgrading a hold.
Directory absence/original identity remains only name-mapping evidence, not physical cleanup or permission to delete.

The implemented feature-only port control `31` uses native extension `22`, a 640-byte request and a 664-byte reply.
`StageNativeObservation.c` keeps directory handles local to the callback; `FilterPort.ObserveNativeName` validates the exact
request binding, two completed scans, presence and full child identity. The reply exports no handles or kernel addresses.
Malformed, stale, incomplete or unsupported observations return failure and provide no absence evidence. This transport is
not yet connected to automatic hold release; that requires the lifetime proof and reconciliation turn described above.

The existing owner-approved close/startup and fixed-NTFS Restart conditions,
named-file diagnostics, generation floor, supported capability gates and independent runtime observers remain required. No new journal
or protocol state is introduced; live admission and runtime qualification remain pending. Native replay uses a new version 22 layout
for the captured GUID; version 21 is rejected rather than silently reinterpreted. Core v18/v20 layouts and persisted enum values remain unchanged.

**Scope correction — fixed-reporting USB (implemented; runtime pending).** The original volume classifier only checked
`FILE_REMOVABLE_MEDIA`. Commit `1d3f47cc` additionally captures complete `FileFsDeviceInformation` through
[`FltQueryVolumeInformation`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltqueryvolumeinformation)
at `PASSIVE_LEVEL` in `SafeUpload.Minifilter/Context.c:383`. The instance gate (`Context.c:514`), coverage readiness
(`StageAdmission.c:481`), native reserve and metadata observer require this positive local fixed-NTFS admission;
the public binding factory repeats it (`StagePublic.c:434`). Portable, removable, remote, unknown and incomplete query results fail closed.
The query must succeed with `IO_STATUS_BLOCK.Information == sizeof(FILE_FS_DEVICE_INFORMATION)`.
[Static gates pass](evidence/2026-10-11/t5-native-volume-static-gates.md); actual fixed-reporting USB refusal still needs runtime evidence.
This guards M2 scope and adds no T21 capability or additional bus-probing requirement. On an unqualified instance the metadata observer
returns failure and retains any recovery hold. Microsoft defines `FILE_REMOVABLE_MEDIA` as removable *media* and
`FILE_PORTABLE_DEVICE` as a device on a portable bus such as USB in
[FILE_FS_DEVICE_INFORMATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/616b66d5-b335-4e1c-8f87-b4a55e8d3e4a).

If the name still maps to original A, or exact enumeration establishes absence, automatically downgrade AcceptedUnresolved to the
existing nonblocking scheduled-intent representation (Admitted plus an immutable native-on-close kind field). Retain the scheduled
generation floor and original intent. This removes only the exceptional recovery barrier: it is never Complete or Canceled.
Enumeration proves the current name-to-file-ID mapping, not NTFS's per-open link identity or delete-pending bit. Absence alone is not
an exact physical-cleanup ACK. Retire/complete only with the separately required exact cleanup proof. A different unexplained ID
retains the hold; a newer ID needs exact durable publication-intent/PublishedIdentity reconciliation before Superseded.

Both the physical-turn and publication guards must block AcceptedUnresolved, and wake their existing waiters after durable downgrade.
Normal scheduled Admitted records enforce their generation floor without adding a whole-handle-lifetime publication reservation.
NTFS may still refuse publication while another reader keeps the old link pending. Retain the clean private stage and retry
automatically on directory-change wake followed by exact re-enumeration; never report a successful rename or bypass NTFS. That native
restriction is separate from the exceptional SafeUpload hold. These are required implementation rules, not a claim that current
startup recovery or the live journal dispatcher already implements them.

Diagnostics retain destination/transfer/generation, original identity, accepted status, driver epoch, cleanup evidence and reason.
The tray uses existing session/SID-scoped notification delivery: identify the file, explain that later saves remain private, and
give the applicable automatic-retry trigger (close the app if still open; restart SafeUpload if disconnected; collect diagnostics
if the exact outcome remains undecidable). A button or edit that manually clears the hold is outside the approval.

Required fault rows inject context attachment/identity query/acceptance-record failure after native success; lost cleanup notification;
service disconnect before close; service crash after close before durable resolution; and startup with live versus closed handles.
Each decisive case must prove the original identity or absence, no later physical publication while held, automatic durable release
without manual action, then clean successor publication. The undecidable identity/anchor case must retain the hold and named-file
notice/diagnostics. Re-run duplicate-handle and outstanding-reader cases; distinguish NTFS's actual restriction from a SafeUpload
recovery hold. Use the existing independent observer, Verifier and separate VM restoration gates.

## Local lifetime and required verification

**Forced-instance boundary — approved for M2 fixed NTFS, 2026-10-11.** The
[focused feasibility review](evidence/2026-10-11/t5-native-instance-teardown-feasibility-luna6.md) identifies a limit in the construction:
after `InstanceTeardownStart`, Filter Manager stops invoking pre/post callbacks for new I/O on that instance, including a later app
cleanup. Referencing the instance does not restore callback coverage; the query-teardown veto applies only to manual detach.
Keep the durable accepted/unresolved hold when exact cleanup evidence is lost. The owner approves the named-file/full-Windows-restart
remedy only for M2 local fixed NTFS. Its existing qualified-boot
proof remains sound only if the feature's mandatory-service-stop prohibition stays enabled and a coverage-lost native record stays
in the driver's global rundown map: voluntary unload must veto before unregister, not wait for a callback that cannot arrive.
OS shutdown skips FilterUnloadCallback; Fast Startup retains that driver/map and cannot qualify as a new lifetime.
T21 must instead design automatic remount recovery; do not extend this exception or implement removable recovery now.
The pre-unregister drain below is a prerequisite while
callback coverage remains intact, not proof that every forced instance can be drained after its callback cutoff.

Object references preserve allocation, not the native open after last-handle cleanup. Disposition must use a still-open object at
PASSIVE_LEVEL. Drop the driver's own handle holds before waiting for exact last-close completion; do not keep the app's own open alive
with a service/kernel handle. Context ownership must not create a FILE_OBJECT/context reference cycle. Nonpaged completion bookkeeping
can release operation holds at elevated IRQL; final handle/context destruction runs at PASSIVE_LEVEL after local rundown.

Voluntary unload vetoes outstanding private stages, RPCs, native records/operations and cleanup; retain the prototype's service-stop
prohibition. For mandatory unload, fence new native CREATE/disposition/namespace mutations but keep exact CLEANUP/CLOSE and local
operation-rundown callbacks admitted. Close ports to cancel service-dependent requests, drop driver/service handle holds and
unneeded map-owned references, then drain every relevant app FILE_OBJECT to last-handle CLEANUP and all local callback/operation
holds **before** FltUnregisterFilter. Never wait for service ACK or use a veto status as if it prevented mandatory removal.
This is the already-approved unbounded local lifetime drain in T5-DELETES section 7; a timeout does not authorize unregister/free.
No live delete-capable app handle crosses a detached interval. Allowed native read-only mappings may outlive app cleanup because
NTFS owns their sections; they do not extend this native-record drain. Private stages keep their separate paging/section rundown.
Actual OS shutdown does not call FilterUnloadCallback. Startup distinguishes an actual OS boot using trusted boot evidence, never
merely a different driver-instance GUID; retain exact durable intent across loss. No automatic Unknown clearance is added.
The OS-boot sequence is the OS-loader `KUSER_SHARED_DATA.BootId` documented in
[the WDK reference](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data), also present in the
installed `10.0.28000.0/km/ntddk.h`. Bind its original value into the durable native intent and obtain the current value from the
authenticated driver. This counter is one part of the boot proof below; a service epoch, driver GUID, adjustable boot-time timestamp,
unknown value or counter rollback/wrap cannot replace it.

The [boot-lifetime review](evidence/2026-10-11/t5-native-boot-lifetime-design-review-luna6.md) rejects that counter alone as proof:
the loader counts boot attempts, and hibernation/Fast Startup can retain handles and drivers. Release the exceptional hold only with
either exact authenticated original-object last-handle cleanup, or **all** of a strictly greater unsigned counter, a different
authenticated driver instance, and a complete reconciled native-record replay containing no live original record. Preserve the
instance and live records across resume. The mandatory local drain above is a prerequisite, not an inference from a new empty map.
Bind proof to the current connection; disconnect, rejected replay or newer replay invalidates an old snapshot. A partial/unreconciled
replay cannot prove absence. Exact cleanup remains valid even if the counter wrapped or rolled back; the boot branch does not.
Same-boot reload without authenticated cleanup remains fail-closed until a qualified boot under the existing late-attach rule.
These are proof metadata, not new protocol states. Remote/removable lifetime proofs require their own destination design.

**Reviewed startup prerequisite.** `StagedTransferJournal.ReconcileDriverInstanceV20Async` currently rejects a
different driver instance while its preceding epoch lacks an exact durable drain nonce. After an unclean full Restart this would
prevent activation before the approved native hold recovery runs. The proposed correction adds the authenticated original OS boot
sequence as optional epoch metadata, reads/reconciles the current authenticated replay before epoch activation, and permits a new
epoch only after qualified full-Restart lifetime proof and safe existing private-stage recovery. The
[focused Luna review](evidence/2026-10-11/t5-native-startup-epoch-design-review-luna6.md) requires a separate private-stage recovery
gate: native replay reports public-open records and cannot establish private attachment lifetime by itself. Preserve the service-stop
prohibition, voluntary native/private unload veto and local lifetime drain; do not synthesize a drain nonce. Keep old manifests bound
to their original driver instance, retain uncertain stages and `PendingRename`, and complete existing conservative startup recovery
before exposing staging/publication readiness. Failed recovery stays degraded. Obtain/reconcile the complete authenticated replay
before replacing the epoch; never block the receive loop on a long recovery while kernel RPCs wait for replies.

A changed GUID, clock, PID or counter alone never qualifies; the current unsigned boot sequence must be strictly greater than the
saved original value, without wrap inference. Legacy epochs without trusted boot metadata stay fail-closed on a changed driver.
Only the same authenticated original driver may capture its missing baseline for a future restart; never manufacture an old boot
sequence from a replacement driver. This adds no persisted enum or protocol state. Epoch metadata, asynchronous private preflight,
authenticated final replay checks and visible readiness gating are implemented in `9c1f9737` with
[passing agent component gates](evidence/2026-10-11/t5-native-startup-static-gates.md). Anchored native hold release and runtime
qualification remain open; the startup path refuses an unresolved hold until that dispatcher is connected.

- Implement the corrections in the READY WITH CORRECTIONS security-design review; do not claim the existing recovery is already wired.
- Review the integrated kernel lifetime/lock-order/retirement change once before its first revised VM boot.
- Four WDK/PREfast/ApiValidator configurations at 0/0 and the agent matrix after service changes.
- Native ShareAccess=0, duplicate/inherited handles, real public identity/size/security/name, reads beyond 16 MiB and implicit position.
- Native byte-lock conflicts/cancellation, read/image mappings past app cleanup and rejection of public writable sections/paging writes.
- Deterministic native deletes before seal and after independent publication observation; native scheduled-delete/publication races.
- Inject pre/post-CREATE tracking failures, identity replacement, service disconnect and mandatory unload without hiding accepted mutations.
- Existing private disposition assertions, real Notepad clean/CPF rows in all three modes, independent byte observers and separate restoration.

## Allocation and publication integration — reviewed contract

The current allocator orders manifests by pathname and its ordinary allocation payload carries no original volume/root/case binding.
The destination head is keyed by those identities. The current publisher does not consult that head. Therefore connecting the native
observer alone must not enable exceptional hold release or make startup Ready. This proposal completes that shared integration;
it changes no approved delete, empty-file, permission, generation, or recovery policy.

Use an explicitly 4-byte-packed feature-only bound-allocation payload, version 23, of 124 bytes within the existing 126-byte valid
image-name payload limit (the buffer is 128 bytes; keep its terminator/unused tail zero):
the existing allocation header/reservation/reference/disposition fields (48), captured public source FILE_ID_128 (16),
recorded Mount Manager GUID (16), root FILE_ID_128 (16), parent volume serial/full ID (24),
parent case mode (2), and canonical-leaf byte count (2). Require explicit size/offset assertions and matching managed packing.
The source ID replaces the redundant request DriverInstanceId: obtain that instance only from the authenticated active connection,
and persist it with the intent. The source ID denotes the exact captured public target, independent of whether bytes are copied;
zero means proven public absence. With no private reference, FILE_OPEN/FILE_OVERWRITE require a target and FILE_CREATE requires absence.
With a FOLLOWUP reference, existence comes from the separately journaled exact private predecessor; a tombstone reference keeps its
fresh-create rule. An existing private predecessor is seeded only from its exact held stage identity. For FILE_OPEN/FILE_OPEN_IF
public seeding, open relative to the checked parent, compare the complete opened ID with the captured source ID and copy from that
held handle; a swapped locator cannot select the seed. Preserve disposition-specific existence checks and fail closed on mismatch.
Use a dedicated V23 carrier marker and exact 124-byte parser, with zero unused bytes and path tail; the generic V20 parser stays unchanged.
Its leaf is the checked final component of the driver's normalized request path, whose full bytes remain in the existing path field.
Validate UTF-16 length, no stream/wildcard selector and the exact final-component boundary. The full path is a locator, not the
destination identity. Root serial must equal the parent serial. Capture anchors through a no-reparse component walk that respects
each directory's case mode; do not use the existing unconditional OBJ_CASE_INSENSITIVE helper as authority. Resolve an existing
short-name alias to its actual NTFS long leaf and verify the requested leaf against the original CREATE. Persist the exact UTF-16 leaf;
do not use ToUpperInvariant as authority or independently fold in the driver. One bucket resolver uses
CompareStringOrdinal(..., TRUE) for insensitive names and exact ordinal comparison for sensitive names, consistently across every
head lookup, queue, allocation, publication, delete and recovery path. Equivalent leaves under the same volume/root/parent/case bucket
select one retained head. Legacy folded heads require conservative bucket reconciliation, with conflicting candidates held, never
silently duplicated or published from a reconstructed locator. Qualification tests verify equivalent spellings/aliases share a head;
any divergence from actual NTFS name equivalence keeps admission closed until the comparator matches. Tests cannot replace this resolver.
Capture the actual root/parent/case binding, source ID and canonical NTFS leaf on the original instance before the allocation RPC;
reserve the name, release namespace locks for metadata/RPC, and revalidate the exact name/parent binding and captured public target ID
or absence after the RPC before exposing the private open.
Missing, changed, unsupported or ambiguous authority fails closed. A descriptor conveys no DELETE or new caller access grant.

Negotiate a new feature-only head-aware capability before live staging admission. An old pair cannot silently use the old publication
path alongside native deletes. Leave normal builds compiled out and existing core/v19/v20 layouts intact; reserve older enum slots.
Existing legacy private recovery remains conservative. An exact still-live driver-owned transfer may supply its checked binding;
never reconstruct a lost original binding from an old manifest locator or invent its volume GUID after a restart.

The allocator obtains the destination allocation turn, reserves max(manifest high-water for this exact identity, destination head)+1
and persists that full binding and generation with the manifest before replying. Allocation replay binds the exact descriptor,
source ID, transfer, authenticated driver and ancestry. Hold the allocation turn through the durable manifest claim.
A partial backing/head/manifest transaction is a private nonpublishable recovery candidate; retry the same exact reservation or
retain its cleanup obligation without rolling back the high-water mark or authorizing an older commit.

The publisher opens the recorded volume/root/parent by GUID and file ID, checks full identities/non-reparse type/case mode, and creates
its inspected temporary relative to that held parent. On NTFS use the 64-bit ID selector only when the captured high half is zero,
then re-query and compare the complete 128-bit identity. Never substitute the saved pathname or export driver directory handles.
Use two linked one-use driver permits: create bound to the checked parent, unique temporary leaf and allocation/generation; then
rename bound to the created temporary's full ID, destination, expected head and inspected digest. The temporary ID is not known
before creation. Bind permits to actual callback file objects and checked parent/leaf identities, not path strings or an ignored volume.
Prepare inspection and temporary bytes outside the short physical turn. Within the destination turn, persist the exact commit intent,
use the rename permit, rename relative to the checked parent with the qualified POSIX replacement semantics,
then durably record Published/Released before dropping that turn. Actual operation anchors must match the permit; locator equality is
insufficient. A native unresolved hold blocks that public name; an unrelated name must continue. Waiting work must release global locks,
the receive loop and any bounded execution slot. Rename/delete continuations acquire multiple destination turns in a stable key order.

Every publisher retry, recovery and interrupted-Publishing reconciliation must use this bound head/permit path; the current
path-and-digest-only ReconcilePublishingAsync is not sufficient for a bound entry. Dispatch allocation and journal continuations
asynchronously off the synchronous filter-port receive loop, so cleanup/close and unrelated names can progress during disk work.
After every physical publication/namespace mutation uses this head and permit path, connect the native observer and lifetime proof to
startup and last-close reconciliation. Reconcile interrupted publication intents against exact identity/rename outcome before resolving
native holds or announcing Ready. Release only the
exceptional barrier, preserve its generation floor, keep unresolved named-file diagnostics, and retain separate exact cleanup ACKs.
The single integrated kernel lifetime/lock/retirement review remains required before first revised VM boot; this proposal requests a
product-security design review of authority transport and shared commit integration, not a per-revision kernel review.
The [Luna design review](evidence/2026-10-11/t5-bound-allocation-publication-design-review-luna6.md) is READY WITH TWO REQUIRED CONTRACT
CORRECTIONS for non-live implementation: source ID/absence revalidation and consistent ordinal filename bucket resolution, specified
above. Full pipeline integration, the kernel lifetime review and protected runtime gates still precede live admission. No revised boot has occurred.

### Kernel permission and identity capture — required integration corrections

The service allocation path is connected on `be78b958`; kernel capture is next. The current private CREATE uses
`SafeUploadStageCaptureSecurity` and `SafeUploadStageQueryIdentity` (`StageStream.c:2156`, `StageSecurity.c:18–105`): those privileged
metadata opens use unconditional case-insensitive names, and the grant is a separate DACL check. They cannot supply the new bound
authority. The existing public backend factory (`StagePublic.c:395–510`) instead asks NTFS with the original effective subject,
but deliberately requires DELETE; ordinary staged writers must not acquire that delete-only capability.

For a bound writer, capture the original CREATE subject on the original callback before queueing. On the unimpersonated system
worker, outside namespace/stream/spin locks, validate the supported fixed-NTFS instance and resolve the original request with its
original case flags and no-reparse rules. A present target gets a **noncreating, nontruncating FILE_OPEN** under that captured
subject, with the calibrated disposition-check rights and original sharing. NTFS decides authorization, including mandatory integrity and traversal;
never add backup/restore privilege or substitute SYSTEM. Capture identity and grants from that same checked object. Model each
disposition's extra native checks: present FILE_CREATE retains its collision result; overwrite needs implicit write and applicable
EA/attribute authority; supersede needs the documented DELETE check and applicable EA/attribute authority. Any claimed parent
DELETE_CHILD alternative must be proved against native supersede controls before it can be used.
Implicit check rights are separate from the rights exposed on the app's handle. A supersede permission check does not grant an
ordinary writer DELETE. Creation-only flags must not cause mutation during the probe. The operation/flag matrix requires native
controls before admission, including caller identification-level tokens; never promote an otherwise unusable subject.

The disposition-check handle is temporary. Close it completely after capturing identity/security/anchors, then make a second
nonmutating FILE_OPEN under the same captured subject with only the original requested rights and share. Compare this object's
full ID and descriptor/ancestor tuple to the check snapshot, reject any mismatch, and retain only this original-grant object for
the app file object's lifetime. Keeping supersede's supplemental DELETE right would change later sharing. Preserve the original
disposition's app-visible Information result; neither helper's FILE_OPENED result is the application's result.

For proven absence, require the original disposition to allow creation, then have NTFS check FILE_ADD_FILE on the exact parent
with that same subject and original path/case semantics. Assign the private view's descriptor from the exact held parent's security
and the original CREATE descriptor/subject, without granting a right merely because the worker can create a backing file. Preserve
the supported CREATE-option matrix and security-only public-open behavior; combined unsupported metadata changes remain refused.
Overwrite retains the existing descriptor. Supersede must follow actual NTFS semantics: the native controls below retain the
queried existing descriptor when no CREATE descriptor is supplied; do not replace it blindly with a newly inherited descriptor.
Fresh creation uses the descriptor NTFS would assign from the exact parent, original CREATE descriptor and subject. The supplied
descriptor controls below establish the tested existing/absent distinction; full assignment still needs implementation and comparison.
Include owner/group, inheritance, SACL and mandatory labels, not only a DACL copy. A
discrepancy with the native control keeps admission closed; do not silently broaden grants or narrow required product behavior.

Separately open read-only metadata anchors below the original instance, walking each component with its actual directory case
mode and rejecting reparses. Query the checked source object's canonical long name, verify its parent/leaf against those anchors,
and retain the full identity, case mode and security snapshot of every ancestor, the parent and target, plus mount GUID, leaf and
assigned security needed by the private view.
The exact original-grant/share-checked object remains owned through the app object's cleanup to preserve its native share reservation.
For absence, perform complete anchored enumeration with the original lookup semantics; an incomplete lookup is not absence.
Capture the tuple outside namespace locks after reserving the name. Send V23 and persist its exact retry snapshot. Before exposing
the private open, reopen/recheck those anchors and the target ID or absence outside locks, then revalidate the reserved view,
predecessor, caller lifetime and service generation under the namespace lock. Do not reopen the target with the writer's rights
or zero access after the RPC: the retained original share reservation makes that construction unsuitable. The original NTFS-checked
object remains the caller authority. Metadata-only anchored checks must compare every relevant identity, leaf link, case mode and
complete descriptor against the captured state; they establish no new caller grant or traversal requirement. Any mismatch retains/discards the private candidate
through the existing exact receipt path. It cannot expose a different source, rename a public file or grant DELETE.

The public DELETE/read-only native factory remains separate and retains its actual NTFS-checked backend. Its original-sharing and
last-close timing must not be changed by this allocation correction. Both new allocation authority and native delete authority
eventually feed the same bound head/permit pipeline; neither enables live admission by itself. Required controls include ordinary
and denied access, DELETE_CHILD/SUPERSEDE, case-sensitive/short-name resolution, label/traversal denial, target/parent replacement,
and unchanged native sharing/cleanup behavior. The integrated lifetime/lock/retirement review still precedes the first revised boot.

**Current review status, 2026-10-12: REVISE; admission remains disabled.** The live writer identity check on allocation replay is
implemented in `dbe02d04`, both before and after replay; PID/session/SID/creation identify ownership, not filesystem authority.

The latest Luna 6 max review identifies four remaining implementation prerequisites; this records its corrections, not a READY
decision. First, every routed writer CREATE and existing-view reopen must retain the original effective static subject, requestor
process lifetime, mapped/previously granted access, share mask, disposition, options, attributes and supported supplied EA/security
inputs in owned storage before queueing. `StageAttachQueueCreate` currently captures `PublicDeleteSubject` only for DELETE-like
requests (`StageStream.c:2738–2745`); cached `view->Security` on reopen (`:2186–2190`) cannot replace a current native check.
Retain original `SL_CASE_SENSITIVE` separately from the parent's case-sensitive mode; V23 currently carries only the latter.

Second, the nonmutating check must cover disposition-implied rights as well as the requested mask, preserve native status and
`IoStatus.Information`, and keep its exact original-share reservation through the app file object's cleanup. Supplemental check
rights never become the app handle's grant. Validate supersede's DELETE requirement and any parent alternative against direct
native controls; do not assume DELETE_CHILD satisfies supersede. No share bypass or mutating probe option is allowed. The current
`StageSecurity.c:18–42,63–103,105–234` helper does not establish these facts. See Microsoft's
[NtCreateFile contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatefile) and
[CREATE operation flags](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_io_parameter_block).

Third, descriptor assignment must retain owner/group, ordered DACL/SACL, labels, inheritance and control/defaulted flags from the
correct original subject, supplied descriptor and exact parent/target. Its immutable assigned descriptor and seed/read provenance
need an approved typed metadata transport: current V23/SAFEUPLOAD_REQUEST has neither (`StageBoundAllocation.h:11–39`,
`Protocol.h:216–278`). The service supplies that assignment on its original temporary CREATE; the kernel compares both callback
and actual post-CREATE security. Post-allocation target/descriptor changes retire the candidate before exposure. SYSTEM defaults,
private-stage ACLs and stale overwrite descriptors cannot substitute for this assignment.

Fourth, seeding must use the exact checked source with its original sharing and prove coherent bytes/EOF under range locks,
oplocks and concurrent writers. Independently check READ authority under the original subject; requesting only WRITE is not a
READ denial, and a share failure is unresolved. Verify exact-object `FltReadFile` behavior without adding READ_DATA to the app grant;
its [documented contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltreadfile) does not
promise an access bypass or atomic snapshot. A privileged second read open cannot silently replace this proof. Seeded provenance
and affirmative recipient/read authority persist through private predecessors and later writes. Native-versus-candidate controls
must cover each supported disposition, rights/privileges, labels/traversal, case, full descriptors, sharing and source races without
mutating the public target. These corrections introduce no new owner policy; the hand-back choice below stays pending.
Kernel permission capture, seed transport and descriptor assignment are not yet integrated.

**Native rights/grant evidence:** source `0a5add63`, [raw Windows control](evidence/2026-10-12/writer-permission-native-control-a5.txt),
Windows 10 **19045.6466 builder**, Windows PowerShell 5.1 parse/self-checks and real execution pass. All **980** existing-target
comparisons match exact native status and projected app grant: seven ACL profiles, four existing-share conditions, five
dispositions and seven explicit/generic/maximum-access masks. The permission probe uses supplemental overwrite/supersede check
rights; projection onto the mapped original request (or checked maximum grant) matches the raw native app grant. This is a
Windows baseline comparison, not authority to broaden a staged data handle. Apply the existing T10 restriction separately:
staged data handles never receive WRITE_DAC, WRITE_OWNER or ACCESS_SYSTEM_SECURITY (`StageSecurity.c:123–141`,
`StageStream.c:8015–8019`); supported security operations use their separately NTFS-checked real-public-file route.
Parent DELETE_CHILD can satisfy the native supersede check in these cases. Native owner/group/DACL/SACL SDDL queried before/after
remains unchanged for NULL supplied descriptors, including supersede. Every probe retains source bytes, full identity and queried
security; Restore is disabled only on a private token copy, and process privileges compare unchanged. This settles these controls,
not fully assigned descriptor construction, absent-parent checks, supplied descriptors, case/labels, seed coherence or lifecycle.
It is not qualification on product VM **19045.2965** and supplies no protected FilterPort/Verifier or byte-privacy evidence.

**Later control outcomes, source `283fff88`:** the [combined a6 attempt](evidence/2026-10-12/writer-permission-native-control-a6.txt)
fails at its zero-access revalidation assertion and is not a passing control run. Luna's bounded design review remains **REVISE**:
retain the original-subject object per app handle, obtain its ID directly without a READ_ATTRIBUTES query, and use separate
metadata anchors for post-RPC state validation. Native write-only/asynchronous ID-query controls, complete ancestor snapshots,
assigned-descriptor transport and per-handle cleanup ownership remain finite implementation gates; do not add caller rights or
narrow supported opens to make them pass. No kernel code or activation depends on the rejected revalidation candidate.
The [separate supplied-descriptor control](evidence/2026-10-12/writer-supplied-descriptor-native-a6.txt) completes nine native cases:
the four absent-target dispositions apply the tested supplied descriptor; all five existing-target dispositions, including
supersede, retain the prior queried descriptor. These results do not prove arbitrary descriptor assignment, protected publication
or qualified-platform behaviour.

**Retained-object gate:** the [direct-query a8 control](evidence/2026-10-12/writer-permission-native-control-a8.txt) passes Windows
PowerShell 5.1 parsing/self-checks, all eight retained share-0 write/append cases and the unchanged 980 permission comparisons.
`NtQueryInformationFile(FileIdInformation)` returns exact success and 24 bytes matching the original full ID, including async
handles without SYNCHRONIZE and explicit READ_ATTRIBUTES denial. Luna's existing design review is ready for implementation after
this direct-query gate, retaining its complete-ancestor/full-descriptor/per-app-lease requirements. This is builder evidence only.
The kernel now captures every queued CREATE's original static effective subject and owned request inputs before cancellation or
queue publication: access masks, sharing/options/attributes, case flags/requestor mode, allocation size, exact EA bytes and a
self-relative supplied descriptor copy. Native preparation consumes the immutable access/share/options snapshot. Destruction and
local teardown free partial or complete copies. This does not yet create the checked writer backend, transport assigned security,
seed content or expose bound admission; their integration and the single pre-boot lifetime review remain required.

**Supplemental-rights lifetime correction:** the [focused native control](evidence/2026-10-12/writer-implicit-rights-share-lifetime-a1.txt)
finds that keeping a supersede check's supplemental DELETE grant rejects a later share-3 reader which the native supersede
handle allows. The 980 initial-status/grant comparisons do not establish persistent sharing. Luna's existing design review requires
the two sequential checks above, with complete snapshot equality and no overlapping check/lease handles. The
[split-sequence control](evidence/2026-10-12/writer-split-share-lifetime-native-a9.txt) then passes 90 unique cases:
five dispositions × read/write/append requested masks × original share 0/7 × later-reader share 1/3/7. Native status/IOSB and
final grant match, candidate bytes stay unchanged and process privileges stay unchanged; PowerShell 5.1 parse/self-checks pass.
This satisfies the review's bounded implementation gate, with no new owner decision. Complete ancestors, assigned security,
source coherence and per-app cleanup remain required; the backend is not implemented or runtime-qualified yet.

**Capture builds:** kernel source `f5cff550` passes [all four WDK builds](evidence/2026-10-12/exact-t5-writer-capture3-summary.txt)
at 0 warnings/0 errors with PREfast/ApiValidator; Inspector, writer fixture and test signature pass. Earlier compiler failures are
retained locally and fixed in `fe1c9738`/`f5cff550`. Agent source is unchanged from the 880/1230-per-profile passing matrix.
These are static gates, not a protected-pair or lifetime-review result.

**Original lookup capture, 2026-10-13:** queued CREATE now retains its opened name or exact original related-file-object/raw-ID
lookup pair in owned nonpaged storage. Relative requests keep the original root object rather than reconstructing its pathname;
same-volume and directory checks precede publication to the worker queue. Absolute requests capture the opened form, preserving
the original case flags separately. Active transaction rundown releases the root/name alongside the original subject before lookup
removal. The empty final destructor remains nonpageable because cancellation can drop the final reference at DISPATCH_LEVEL.
This completes capture only: it does not establish an NTFS grant, assigned descriptor, coherent seed or bound-head admission.
The checked writer backend and post-allocation ancestor/security comparisons remain required.
Source `4b478e10` passes [all four WDK/PREfast/ApiValidator builds at 0 warnings/errors](evidence/2026-10-13/exact-t5-lookup-capture4-summary.txt);
Inspector, writer fixture and signature gates also pass. No revised protected pair has booted.

#### Seed sharing and read-authority correction

The service's current second public-source read open (`StagedDestinationDirectory.cs:68`) can fail a CREATE whose original sharing
would succeed. The proposed replacement seeds through the exact original-rights/share-checked live FILE_OBJECT in the kernel,
after post-RPC revalidation, into the exclusive private backing. Do not add READ_DATA to the app's handle. Use explicit offsets,
bounded aligned chunks, exact EOF/flush and complete source/anchor revalidation before expose. The existing service public-read
route must be removed from this live path, rather than adding a share bypass to it. This proposal still needs source range-lock,
oplock and compatible concurrent-writer controls; an open full-ID object is not an atomic content snapshot. No new residual
behavior is approved by this note. See Microsoft's [FltReadFile contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltreadfile).

Full blocked-save hand-back is a separate read disclosure. The allocator seeds old public bytes for OPEN/OPEN_IF, and the existing
publisher copies the entire blocked snapshot to a hand-back with user FR access (`StagedBoundTransferAllocator.cs:57–68`,
`StagedTransferPublisher.cs:235–245,693–706`, `StagedHandbackCopier.cs:916–920`). A subject may be allowed to append to a file while
being denied its old contents. Returning those contents in another file must not create read authority.

Do not confuse a write-only requested handle with a read-denied subject: ordinary users can request FileAccess.Write while
remaining authorized to open the same file for reading. Preserve their existing hand-back and justification behavior. The reviewed
candidate checks READ authorization independently on the exact source under the retained original effective subject, without
reading through that probe or exposing it to the app. A share failure is unresolved, not an access denial; a share-bypassing read
open cannot substitute for the original source/read-authority proof. Its oplock/audit effects and exact identity must be controlled.
Explicit access/label denial and an indeterminate probe have distinct diagnostics; neither establishes permission to export old
bytes. Validate the eventual hand-back recipient too; the process-primary SID is not the original thread's effective subject.

Persist source provenance plus affirmative read/recipient authorization with the bound allocation, carrying it through any seeded
private predecessor. New/absent targets and truncating/superseding dispositions start without old public bytes and retain the
ordinary hand-back path; do not infer provenance from final length or a changed write mask. No new journal state is needed.

#### Owner choice — unreadable seeded bytes

1. **Preserve native write-only editing.** Clean saves publish normally with the required destination permissions. If a blocked
   version contains prior bytes whose read/export authority is denied or unresolved, keep it service-private using existing
   Blocked + HandbackState.Failed with a named diagnostic/tray reason. No readable full-file hand-back is made. Existing behavior
   closes justification without verified hand-back and prevents cleanup of that blocked stage. Normal read-authorized saves keep
   their current hand-back and justification. Users of a write-only protected log can continue clean appends, but cannot retrieve
   the entire blocked log through SafeUpload.
2. **Require read authority for edits that preserve old bytes.** Refuse such an existing-file open when read/export authority
   cannot be proved. Those apps cannot edit or append through SafeUpload in that mode; new and full-replacement saves continue.
   Admitted blocked saves retain the full-file hand-back model. This deliberately narrows native Windows editing behavior.

**Owner decision, 2026-10-13: option 1.** It is not yet implemented. Option 2 is not approved.

#### Focused implementation research, 2026-10-13

The [writer-authority report](<../reports/T5 native writer authority.md>) consolidates the native controls, Microsoft contracts
and current integration gaps into five stages and seven finite control groups. It is provisional design evidence, not an
integrated kernel review or activation approval. The published V18/V23/V26 layouts, supported CREATE surface and pending owner
choice remain unchanged.

Three corrections must be resolved before integration: removing the local impersonation-level guard does not remove the capture
DDI's low-token restriction; construction/defaulted flags require a distinct native stored-descriptor comparator, and supplying
an assigned descriptor to a SYSTEM temporary CREATE is not proven idempotent; initial absent-object creator grants must not be
denied by rechecking the newly assigned DACL as an existing object. Exact-object full-security queries, kernel reads and whole-copy
coherence also remain mechanism gates. The report specifies finite differential controls rather than assuming these contracts.

#### Durable allocation security record, implementation checkpoint

The service allocation journal now accepts an immutable security snapshot alongside a V23 binding. Construction and expected
native stored descriptors are separate binary values; the storage codec never derives assignment, access or a stored form from
construction flags. Format 1 packs component offsets and outer padding while preserving the complete control/RM bytes, SID values,
ACL bytes, ACE order and opaque payloads. Its structural checks are not a substitute for the checked driver's native descriptor
validation or assignment controls.

Two full descriptors can exceed the existing 128-KiB manifest limit. A bounded private `.security` record is therefore flushed
before the allocation manifest records its snapshot GUID, exact length and SHA-256. The 112-byte header binds driver, reservation,
assignment/query provenance and a binary digest of every V23 binding field, including exact UTF-16 leaf bytes. Each descriptor's
component bound is 131,228 bytes (two maximal ACLs, two maximal SIDs and alignment); the binary record bound is 262,568 bytes.
The JSON manifest limit and published wire layouts stay unchanged. Replay cannot add, remove or replace a committed snapshot.
Recovery reads the no-follow, single-link private object and verifies the full reference and allocation tuple; missing or changed
data cannot become permission through a current SYSTEM observation.

Compaction keeps snapshots referenced by retained high-water/ancestry manifests. A flushed record interrupted before manifest
commit remains private and is eligible after the ordinary retention cutoff; cleanup checks the held object and deletes only its
exact identity. Startup ACL recovery recognizes this bounded binary file and its private temporary form. Crash-left temporary
cleanup remains part of T11's general temporary-file retention work.

The first Windows matrix compiled at 0 warnings/errors but the new missing-record control caught an allocation cleanup bug:
a missing committed binary dependency propagated `FileNotFoundException`, which the existing allocation finder interpreted as
a missing manifest. Missing snapshot dependencies now become `InvalidDataException`, preserving the journaled stage and refusing
replay; the same control continues to assert stage retention. Two tampering controls had the wrong expected exception family and
now require the precise corrupt-record result. Revised source `ac69dc00` passes the
[exact Windows agent matrix](evidence/2026-10-13/exact-agent-matrix-t5-security-storage2-summary.txt): normal Debug/Release
913 tests each and feature Debug/Release 1,269 each, exact discovered/executed case sets, no skips, and all service/app/test builds
at 0 warnings/errors. The [earlier failed matrix](evidence/2026-10-13/exact-agent-matrix-t5-security-storage1-summary.txt) is retained.
These controls qualify binary storage, commit/replay, missing/tampered dependencies and retention; they do not qualify native
assignment, original-object seeding, publication descriptor comparison or a protected pair.
No wire producer currently supplies this record, and live admission remains off.
The metadata RPC, complete checked snapshot, rename rebinding, original publication CREATE descriptor, seed/export provenance
and integrated kernel lifetime review remain required before protected qualification.

#### Native publication security control, 2026-10-13

The [seven-case SYSTEM measurement](evidence/2026-10-13/t5-security-roundtrip-native4.txt) supplies the queried descriptor on the
original parent-relative UserMode NtCreateFile. Every temporary retains the required `0x00110082` grant, share zero and `0x2A`
I/O mode. A separate metadata-only observer obtains `0x01020000` under the live writer/temporary share-zero handles and matches
their full IDs. Its private SYSTEM token enables SeSecurityPrivilege for SACL queries; creator/process privileges remain unchanged.
The initial SYSTEM task's disabled privilege produced `STATUS_PRIVILEGE_NOT_HELD`; it was not a sharing failure. This proves the
tested Win32 observer route, not the corresponding kernel DDI, all security-information classes or other original subjects.

Five stored descriptors round-trip exactly (protected read-only, unprotected/defaulted, protected empty DACL, NULL DACL and low
label). Two do not: inherited NULL-input creation and an inherited existing file moved from another parent both change
`0x8C04` to `0x8804`. Independently compared bytes differ only at the `SE_DACL_AUTO_INHERITED` bit; owner/group, ACL bytes and
ACE flags/order remain equal. The supplied/defaulted input also confirms `SE_DACL_DEFAULTED` does not survive native assignment.
Native initial WRITE_DATA grants succeed in the protected read-only/empty-DACL creator cases without checking those newly
assigned DACLs as existing objects.

The current exact inheritance/control contract therefore has a concrete counterexample even for a SYSTEM-only baseline.
The storage codec must not erase that bit or silently redefine expected stored security. No protection-bit repair, privileged
post-set or CREATE access-state injection is approved; publication stays NotReady until a native-equivalent construction strategy
is proved or the owner explicitly revises that contract. Kernel assignment and ordinary/restricted/low-token controls remain open.
See Microsoft's [control semantics](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control) and
[assignment/inheritance rules](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-seassignsecurityex).

The first complete measurement failed only its fixture teardown because the reset unnecessarily requested owner/group changes.
DACL-only cleanup now succeeds; the [retained fixture recovery](evidence/2026-10-13/t5-security-roundtrip-recover3.txt) validates all
seven source identities before removing the exact fourteen-file fixture. The final run removes its fixture and restores its scoped
SYSTEM task/worker. [Independent restoration](evidence/2026-10-13/t5-security-roundtrip-independent-restoration.txt) confirms
zero retained fixture directories or tasks on builder 19045.6466. The
[PowerShell 5.1 gate](evidence/2026-10-13/harness-windows-gate-t5-security-roundtrip4.txt) passes parsing and native signatures;
this is measurement evidence, not protected-pair or M2 qualification.

The [14-row follow-up](evidence/2026-10-13/t5-security-auto-request1.txt) tests a second construction input on each of the same
seven sources: an exact copy of the queried descriptor with only `SE_DACL_AUTO_INHERIT_REQ` (`0x0100`) added. This uses the
documented [inheritance request control](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control)
on the original CREATE; it changes no expected stored bit, ACE, protection flag, source/parent security or handle grant.
The request does **not** resolve either counterexample on builder 19045.6466. Both constructions produce five exact matches
and the same two `0x8C04` → `0x8804` failures. The [independent byte/input audit](evidence/2026-10-13/t5-security-auto-request1-byte-audit.json)
confirms that only the request bit changed in the candidate input and that all result bytes except the auto-inherited control
bit remain equal. This candidate is rejected as an exact publication construction; the stored-descriptor contract and NotReady
gate remain unchanged. No claim is made about other subjects, kernel assignment or every use of this request flag.
The [PowerShell 5.1 gate](evidence/2026-10-13/harness-windows-gate-t5-security-auto-request1.txt) passes, and
[strict independent restoration](evidence/2026-10-13/t5-security-auto-request1-independent-restoration2.txt) confirms zero fixture
directories/tasks, an absent exact worker and worker script, and no loaded SafeUpload driver. No product VM was booted.

#### Descriptor candidate controls, 2026-10-15

Three further SYSTEM measurements on builder 19045.6466 test the finite candidates of the
[decision memo](evidence/2026-10-15/t5-descriptor-decision-sol61.md) (controls `a85e8dbb`; [PowerShell 5.1 gate](evidence/2026-10-15/harness-windows-gate-hg-t5desc2.txt)
PASS; the first gate attempt `hg-t5desc1` failed because the main checkout's runner lacked the new files, receipt kept). Each run
passed independent restoration (zero fixtures/tasks, no worker, no loaded driver).

| Candidate | Result |
|---|---|
| 2 — NULL-input CREATE in the destination parent ([run](evidence/2026-10-15/t5-descriptor-t5-inherit-new1.txt)) | **Inherited NULL-input creation: EXACT.** The everyday shape (a new file inheriting its folder's permissions) round-trips byte for byte. The moved-from-another-parent file differs in ACE masks (its old parent's grants), as required; protected/explicit shapes differ, and stored replay remains exact for them. |
| 5 — auto-inherit conversion before CREATE ([run](evidence/2026-10-15/t5-descriptor-t5-convert-new1.txt)) | **Rejected.** Both counterexamples still lose only `0x0400`; two other shapes stop matching. |
| 6 — marker behavior ([summary](evidence/2026-10-15/t5-descriptor-t5-marker-new1-summary.json)) | All 30 rows have identical access matrices. Adding, changing or removing an inheritable parent ACE, both tree resets and an icacls restore make the marker-clear candidate byte-identical to the reference (Windows re-marks it). A backup/restore round trip preserves the difference faithfully. |

So an exact construction exists for every measured shape except a file moved from another folder and then saved in place, which
differs only by `SE_DACL_AUTO_INHERITED`, with equal access and self-healing on the next inheritance operation. These are
mechanism measurements: non-SYSTEM subjects, kernel assignment, Explorer display and target 19045.2965 remain open, and the
exact contract and NotReady gate are unchanged until the owner decides.

### Implementation note — increment 2

`StagePublic` now has a distinct opaque writer lease and `SafeUploadStagePublicOpenWriter`; the DELETE factory still requires
its original DELETE grant. The writer factory is **preparation only**, with no live CREATE caller. It uses the captured static
effective token and exact original root/name bytes (including supported binary ID selectors), original case, access and sharing.
A supplemental, nonmutating FILE_OPEN captures a comparison snapshot; **all** supplemental and observer handles/references close
before the original-rights FILE_OPEN. The second snapshot must match. Actual retained access and the prospective T10-limited staged
grant remain separate, as does the original disposition's prospective Information result. No token privilege is enabled or removed.

Snapshots retain root, every ancestor, parent and target: mount GUID, volume/full ID, exact canonical components, directory case,
non-reparse/type, basic/standard metadata and complete binary stored security. The all-parts `BACKUP_SECURITY_INFORMATION` query
has no partial-security fallback; it is not a privilege grant. Metadata observers have no target data/delete rights or sharing bypass.
`SafeUploadStagePublicRevalidateWriter` directly requeries the held lease and recaptures all metadata after RPC. Later integration
must still check reservation, predecessor, policy/channel generations, cancellation and caller lifetime under the namespace lock.
It must retire the exact candidate on failure; this hook does not perform RPC or authorize exposure.

Original supplied input, construction security and expected stored security have separate owners/slots. Expected stored security
comes from the exact checked target. **Construction remains absent**, rather than being derived from stored bits or supplied input;
`SafeUploadStagePublicCheckWriterSecurity` always refuses. It reports `publication_security_not_equivalent` for auto-inherited
stored descriptors (including the recorded `0x8C04 → 0x8804` counterexample), otherwise `native_create_security_unproved`.
Low token levels report `writer_subject_unrepresentable`; absent creating candidates report `writer_creator_grant_unproved`.
Present FILE_CREATE precedence, pregrants, supplied descriptors/EAs, allocation hints, enabled Restore and unqualified flags are
`writer_create_semantics_unproved` or `native_create_security_unproved`. Unprovable roots/ID-selected links, incomplete metadata,
changed snapshots and capture limits have distinct `writer_lookup_unproved`, `writer_metadata_unproved`, `writer_snapshot_changed`
and `writer_capture_limit` counters. These refusals are development gates, not approval to narrow M2. Creator grants are never
rechecked against a prospective new DACL. There is no control-bit repair, protected-DACL substitution, post-set or AccessState injection.

Ownership follows the existing backend list/operation rundown. Each prepared writer owns an instance pin, process reference and
SYNCHRONIZE-only lifetime handle, a reference to the original static token, copied CREATE inputs/root locator, retained writer
handle/object and snapshot metadata handles/objects/buffers. Factories unwind locally; successful return transfers one owner to the
caller, released by `SafeUploadStagePublicReleaseWriter`. No new worker is created. The attach transaction has a dormant lease slot;
its PASSIVE failure/active rundown closes lease/root handles **before** removing the instance lookup. Final cancellation destruction
remains nonpageable and handle-free. Voluntary preflight atomically fences factories and vetoes their active count or any backend;
rollback reopens admission. Mandatory close drains factories/local operations, closes public/root/ancestor/process handles outside
the list lock, then waits for dependent owner retirement. No new service dependency is introduced. All I/O, waits, token work and
descriptor allocation are PASSIVE and outside namespace/stream/list locks; the list lock only protects admission/counts/list pins.

Capture has explicit temporary safety bounds: 128 factory/backend slots for writer preparation, 128 anchors, 2 MiB stored-security
bytes per snapshot, 64 KiB per queried NTFS descriptor, 64 KiB supplied EA and 131,228 bytes supplied descriptor. Both race-window
snapshots can coexist. A bound hit refuses the entire capture; these are not approved final resource defaults.

Finite builder controls (the report's seven groups; run serially, retain failures, no protected VM):

| Group | Increment-2 control and existing entry point |
|---|---|
| 1 — subject/CREATE | Run `writer-permission-native-control.ps1` without switches: 980 comparisons, eight direct-ID cases, nine supplied-descriptor cases. Missing kernel controls: actual primary/anonymous/identification/impersonation/delegation and restricted/deny-only subjects; six dispositions/presence, pregrants, privileges, EA/options/attributes, collision and creator precedence. |
| 2 — lookup/metadata/races | The same script supplies the eight user-mode ID/metadata baselines. Missing kernel controls: exact 24-byte FltQueryInformationFile, all-parts security, original root close/rename, relative/`..`/raw-ID/case/short-name/hard-link selectors, and target/every-ancestor/link/case/security replacement in both windows. No existing script qualifies those kernel/race cases. |
| 3 — binary security | Run `bound-publication-native-control.ps1`, then `Invoke-SecurityRoundTripNativeControl.ps1 -Label <fresh-label>` (SYSTEM wrapper, seven cases). Inspect binary control/ACE equality and creator grants; the two known mismatches must remain failures of equivalence. Do not rerun the already rejected `-CompareAutoInheritanceRequests` candidate without a new hypothesis. Kernel assignment, complete query classes and non-SYSTEM subjects remain unproved. |
| 4 — carrier/replay | No carrier is added. Preserve V18/V23/V26 layouts; malicious page/replay controls belong to increment 3. |
| 5 — seed coherence | No read/copy is added. Exact-object kernel reads and deterministic whole-copy races belong to increment 4; no existing script closes them. |
| 6 — export/recipient | No export authority is asserted. Option 1 remains controlling; recipient/provenance controls belong to the agent/seed increments. |
| 7 — lifetime | Run `writer-permission-native-control.ps1 -ShareLifetimeOnly` (90 cases). Missing kernel controls: cancellation at each acquisition, root cleanup, duplicate/inherited versus independent app objects, process/instance teardown, reversible veto and mandatory close-before-wait. These need the later reviewed kernel harness/pair, not a user-mode script. |

Before native execution, run Windows PowerShell **5.1** parsing and each of the three `*native-control.ps1 -SelfCheckOnly` entry
points. The orchestrator owns the four WDK/PREfast/ApiValidator builds and builder execution. This checkout has not been built or
booted. V23 remains uncalled, bound capability remains NotReady, legacy `StageSecurity` behavior and published wire layouts are
unchanged, normal builds compile the additions out. Review full-query semantics/observer side effects, original-root cleanup races,
snapshot consistency, diagnostic refusal coverage and teardown ordering before the first authorized boot.

### Native scheduled-CREATE integration transport — reviewed contract

**2026-10-12: Luna 6 max effort READY for transport/producer implementation after the revision, high-water and receipt-retention
corrections below.** This is design readiness; the integrated lifetime review and first protected boot remain pending.

The reviewed original-CREATE construction still lacks the request path between the kernel record map and the durable destination
head. Connect that path without exporting a second file handle, serializing a token, or treating read-only metadata as DELETE
authority. This transport preserves the approved native result, generation ordering and accepted/unresolved failure policy.
The pending seeded-content hand-back choice is independent and remains unimplemented.

Reserve feature-only operation 20 and carrier version 24. A 4-byte-packed 72-byte payload contains version/size (8), phase and
reserved-zero (8), transfer GUID (16), request nonce (16), operation GUID (16) and native-map revision (8). Phases are pre-CREATE
prepare and facts-changed. Require exact image length, zero unused image/path bytes, no path-as-authority fallback and explicit
size/offset assertions. Driver/connection identity comes from the exact authenticated channel, not a second payload authority.

Before prepare, resolve the normalized parent/leaf by metadata only and reserve the bounded nonpaged record against the original
unopened FILE_OBJECT. Capture the original CREATE subject before queueing; record its caller SID/session and referenced process
lifetime. Keep GrantedAccess zero: neither directory enumeration nor the requested DELETE mask is an authorization grant.
No target-file backend is opened. Support this initial path only for the already reviewed non-writing FILE_OPEN with explicit
DELETE and native FILE_DELETE_ON_CLOSE, with no owner-private view; other supported requests keep their respective staged paths.
This first connection does not complete ordinary public disposition handling or widen the supported request surface.

The asynchronous service prepare handler obtains complete authenticated native replay (control 30) and matches the payload's
immutable transfer/nonce/operation and revision to exactly one unforwarded record on that channel. Check caller/header identity,
boot, volume GUID, full root/parent/target IDs, case/leaf and supported original flags; reject missing/duplicate/mismatched records.
Take the destination allocation turn, include retained manifests/tombstones in max+1, and flush the existing native pre-CREATE
AcceptedUnresolved intent before replying. The request does not authorize a service mutation. Only the original Windows CREATE
decides access, sharing and whether native scheduled deletion is accepted. The reply echoes request/phase/transfer/operation and
the exact positive journal generation; a lost or stale reply is not authority to forward.

Prepare is explicitly fail closed: require an actual typed reply, not NT_SUCCESS(STATUS_TIMEOUT) or the generic fail-open verdict.
Echo/validate request ID, phase, transfer, nonce, operation and exact map revision. Prepare requires the row's original connection
epoch to equal the current authenticated connection; facts after reconnect retain the original epoch while using the new channel.
MarkForwarded must compare the expected revision atomically under the native lock, alongside cancellation/channel/instance checks.
A stale prepare can replay from a fresh revision event while the original CREATE remains pending; otherwise MarkNotForwarded.
Compute retained manifest/tombstone high-water for the exact destination under the allocation turn and journal gate; no caller-
supplied default or stale scalar is enough.

After all cancellation and instance/channel checks, MarkForwarded transfers the producer reference to the original post-CREATE
callback and complete the pended preoperation with SUCCESS_WITH_CALLBACK. Preserve the original CREATE/options exactly. Do not
cancel an NTFS-accepted scheduled delete to hide a tracking failure. A preparation/cancellation failure calls MarkNotForwarded;
its exact negative receipt remains replayable even when the durable prepare result was lost. Release local producer references
through the existing rundown; no record owns an extra public FILE_OBJECT reference that would prevent cleanup/CLOSE.

CREATE/CLEANUP/canceled-CLOSE/teardown update the existing record map and wake the bounded kernel worker. Coalesce facts-changed
requests by revision; no RPC or observation runs under namespace/native locks, and no timer polls an unchanged map. The service
reconciles exact outcomes with the durable head. After accepted-but-unbound CREATE, preserve AcceptedUnresolved and its publication
hold. Use fresh complete replay plus identity-anchored observation (control 31) and the existing reconciliation turn for last-close
and startup release. All physical publication/delete/recovery paths must already use the shared head before this release is enabled.
Same-channel revision changes are retried from an event; stale/partial facts never become absence or lifetime evidence.

Use a separate typed reply, with exact request/phase/transfer/operation/generation echoes and a result distinguishing durable
prepare, recorded progress and terminal cleanup acknowledgement. Recording CREATE acceptance or releasing an exceptional hold
is not terminal cleanup. ACK/remove the kernel record only after the exact scheduled-link disposition is terminal with independent
identity evidence, or after exact never-forwarded cancellation is durable. Pending original links retain cleanup obligations;
directory-change wakeups and startup reconciliation must complete them without a busy timer. A newer Published identity may
supersede the old link only under the existing durable published-identity rules, not because a later allocation exists.

The native terminal transition uses existing Complete only after exact lifetime-ended proof and independent anchored absence,
advancing CommittedDelete; an unexplained replacement fails closed. Superseded requires the exact newer durable PublishedIdentity.
An original still-present/pending link stays Admitted. Neither hold release nor CREATE-result recording permits terminal ACK.
Keep the terminal head receipt after replying: local Acknowledge can be busy or its response lost. Retire that receipt only after
a later complete authenticated same-driver replay/explicit confirmation proves the exact record was removed. Startup must still
match every forwarded row to its retained durable intent. Consume the full forwarded/CREATE-outcome/identity/generation facts,
not only a lifetime projection; exact never-forwarded negative receipts become Failed before ACK. Ambiguous acceptance remains
AcceptedUnresolved. A false trackingBound result cannot later become true merely because a replay supplies a bool.

Persist the original CREATE options/desired-access/share tuple and immutable CREATE outcome facts with that existing receipt;
these are evidence fields, not new states. Before a terminal reply, persist its native-map revision. Same-driver retirement
requires a later complete authenticated map with a greater revision and no matching transfer/nonce/operation. Keep maxAllocated
and the completed-delete floor after receipt removal. A lost terminal reply replays the same receipt; it never repeats CREATE.

The feature-only reply is 88 bytes: the exact 72-byte request followed by positive journal generation, result and reserved zero.
The outer request ID is also exact. A generic verdict, short reply, nonzero tail or timeout cannot authorize forwarding.

Keep the bound-head capability unadvertised and producer forwarding disabled until native prepare/facts/ACK, ordinary disposition,
all physical commits and startup/last-close recovery are connected. Kernel lifetime/lock-order/retirement review still precedes
the first revised boot. Required controls include lost prepare/result/ACK, canceled before forwarding, native identity mismatch,
service reconnect, stale map revision, original ShareAccess=0, duplicate handles, last cleanup, unchanged accepted results and both
deterministic delete orders, followed by the real three-mode Notepad/raw-observer/restoration gate.

### Writer metadata carrier — increment 3 design

This is a **read-only prerequisite**, not admission or a publication permit. Control 34, extension 27, is added only in feature
builds; V18 (1192 bytes), V23 (124 bytes), V26 and all existing enum values remain unchanged. Live CREATE still selects V19 and
bound readiness stays NotReady. Increment 4 must supply the live reservation/lease integration, post-RPC recapture and coherent
kernel seed completion. Construction assignment and read/export checks still have no qualified producer.

All integers are little endian, GUIDs use the existing Windows byte layout, packing is 4. A 136-byte request contains core Control
(16), extension/phase (8), driver GUID (16), reservation GUID (16), original allocation RequestId (8), connection epoch (8), authority
revision (8), snapshot GUID (16), byte offset/reserved-zero (8), SHA-256 (32). Phases: Discover=1, Read=2, Confirm=3. Discover requires
nonzero driver/reservation/request and zero epoch/revision/snapshot/offset/digest. It returns only the snapshot header. Read and
Confirm pin every returned value; Read starts at zero and advances by exactly 4096 bytes except the last page; Confirm uses the exact
total length and returns no bytes. No new journal state or mutating control is added.

The fixed 4232-byte reply is a 136-byte header plus 4096 bytes: extension/size/phase/result (16), driver/reservation (32), request/
epoch/revision (24), snapshot (16), offset/total/count/flags (16), SHA-256 (32). Result Captured=1 describes bytes, not authority;
Unavailable=2, Stale=3 and NotReady=4 are defined refusals; native transport failures return no usable page and are also refusals. Unused payload bytes and all reserved fields are zero. Captured flags are
ConstructionPresent=1, StoredPresent=2, AncestorsComplete=4, IdentityComplete=8, AssignmentProven=16. A fully fetched snapshot without
all five flags cannot enter allocation. The increment-2 producer supplies only captured facts, including an empty construction slot
and assignment revision zero; this intentionally fails the service's complete-authority prerequisite.

The immutable blob has a 1024-byte format-1 header, then separate original binary construction and stored descriptors, each bounded
at 131228 bytes (total <=263480, <=65 pages). Header offsets are: format/header size 0/4; exact V23 binding 8; canonical leaf (512
zero-tailed UTF-16 bytes) 132; process/session/creation time 644/648/652; process SID length/data (68 bytes) 660/664; effective subject
SID length/data 732/736; twelve uint32 original CREATE facts at 804 (desired/original/remaining/pregranted/native/staged grants,
options, attributes, sharing, operation flags, requestor mode, prospective Information); allocation size 852; ancestor count 860;
ancestor SHA-256 864; assignment revision/security-information 896/900; construction/stored lengths 904/908; seed origin 912
(None=0, ExistingPublic=1, PrivatePredecessor=2); read/export outcomes 916/920 (Unproven=0 only in this increment); independent native
status slots 924/928 (STATUS_NOT_SUPPORTED); effective-subject snapshot GUID 932; reserved zeros 948..1023. No token, pointer or
handle is exported. Process identity is not substituted for the effective subject or an eventual recipient.

The ancestor commitment hashes an explicit, padding-free ordered encoding of the captured mount GUID, uint32 anchor count, normalized name uint16 length/bytes,
original lookup uint16 length/bytes and every anchor: full volume/128-bit ID, attributes/reparse tag, four timestamps/attributes, allocation
size/EOF/link count/delete-pending/directory/case, component offset/length, security length and exact complete descriptor. Integers
are encoded in little endian at their declared widths; directory/delete-pending/case are uint32, offsets/lengths uint16, all other
scalar widths follow their Windows declarations. Complete objects remain lease-owned. Hashes commit to captured facts; neither
hash equality nor the immutable snapshot replaces post-RPC recapture or caller lifetime checks.

One immutable blob belongs to one referenced writer lease and one allocation request. No global metadata map, worker or independent
lease reference is created. The existing 128 writer factory/backend bound bounds simultaneous blobs at <33 MiB, in addition to
increment-2 capture bounds. Preparation holds backend operation rundown from before serialization through publication, serializes per lease, validates the entire binding against captured identities and stores
exact cookie/epoch/revision/request. Recheck Closing and the channel tuple before publishing; a second preparation refuses before
allocating another blob, so transient preparation is included in the bound. A global four-reader kernel limit applies to every
authenticated control caller, independently of the managed client's limit. Under the existing list lock, reserve a reader slot
before lease lookup/reference, operation rundown or page allocation. Saturation returns STATUS_INSUFFICIENT_RESOURCES with
`writer_metadata_resource_limit` and zero returned bytes. Closed/mandatory teardown admission returns STATUS_FLT_DELETING_OBJECT
with `writer_metadata_stale`. Page lookup then pins the lease under that lock and acquires operation rundown outside it;
allocation/hash/copy/waits run at PASSIVE outside that lock. Close revokes lookups, drains local operations, and frees the blob while
closing the lease's handles. The single control exit frees the page, releases operation and lookup references, then returns the slot
on success and every failure/exception path after reservation. Four pages total at most 16928 bytes, with at most four reader operation
pins. A notification event, cleared on the first reservation and set on the last release under the list lock, tracks local drain.
Readers participate in voluntary veto alongside backends/factories; mandatory close closes admission under that same lock, waits
outside it for readers to drain, then performs the existing factory/backend rundown. It requires no service ACK and cannot admit new
readers during that wait. The count/event are kernel-local ownership additions; no wire field, exported API or service receipt changes.
Disconnect/revision change revokes reads; a new connection cannot adopt or refresh an old snapshot. Candidate retirement remains the
existing allocation owner's obligation, even if metadata was fetched or a reply lost.

Communication requires the current port process, agent-service SID and authenticated connection. A StageProtocol helper samples
cookie/epoch/revision under the existing state lock; every page rechecks that tuple before and after copying. Preparation and the
V23 helper pin that same tuple for sending. Discovery does not negotiate permission: recognizing this extension only establishes
transport compatibility, and allocation additionally requires complete metadata and all existing head/recovery capabilities.

The client holds one send lease for discovery, ordered bounded reads and the final unchanged Confirm. It rejects wrong request,
reservation, driver, epoch, revision, snapshot, phase, offset/count/total, digest, flags, nonzero tails and incomplete replay before
returning an immutable value. A duplicate/out-of-order page is invalid; a whole exact replay is permitted only for the same immutable
durable reservation. Reusing that reservation with changed metadata, request or connection is refused, including after service restart.
At most four client fetches are admitted; excess callers fail closed before allocating snapshot storage.

The service checks exact V23/caller/descriptor/provenance binding at dispatcher, allocator and journal boundaries. The existing
`.security` file gains storage format 2: its original 112-byte header and canonical separate descriptors are retained, offset 72
records the appended metadata envelope length, offset 76 remains zero. The envelope contains the captured reply header and complete
original blob, preserving its digest and noncanonical original descriptor bytes independently of canonical storage. Format 1 remains
decodable for historical evidence, but cannot satisfy a bound allocation or its authoritative durable read. The bounded record is <=526184 bytes.
Require envelope/header/blob/canonical-record equality on snapshot, driver, reservation, request, connection, assignment/query
provenance and seed intent. Canonical descriptors must equal canonicalization of their corresponding original blob descriptor;
complete flags cannot coexist with empty construction, zero assignment revision or an incomplete all-parts query mask.
Flush this immutable binary record before committing its reference in the existing manifest. Missing/tampered/truncated dependencies
retain the private stage and fail replay; recovery never refreshes authority from SYSTEM. Seed origin comes from disposition and
exact predecessor/public source; captured effective-subject/read/export slots feed option-1 evidence as **Unproven**, never Allowed.
A seed completion receipt remains separate and does not rewrite allocation authority. A pre-provenance bound manifest with the entire
security/provenance/completion tuple absent remains readable for conservative recovery: it is Unproven, cannot be recopied/exported
or registered for justification, and retains its backing. This compatibility does not admit a refreshed allocation replay or a new
bound allocation using that legacy predecessor. Once any member of that tuple exists, every bound manifest read requires the security
record and provenance with its allocation binding; partial erasure remains invalid. Captured origin is compared even when JSON source fields have been erased. A public
seed must equal the provenance derived from its original captured binding/security/evidence. A preserving descendant must name the
captured predecessor ID and the predecessor's exact generation/stage identity, driver and destination, and retain precisely its source
fields, evidence, prior-byte flag and export restriction. The journal validates the complete predecessor chain iteratively; strictly
decreasing allocation generations exclude cycles with constant ancestry memory. Missing ancestors become an invalid committed
dependency, never an absent allocation eligible for orphan deletion. A changed predecessor version is held, not refreshed. Bound scan
entries bypass the manifest-only cache because a child's own timestamp cannot validate its ancestors. Original allocation generations
survive rename only with the retained matching namespace tombstone. Erasure/contradiction refuses replay, export and cleanup while
retaining backing; the in-memory export guard also treats missing/contradictory bound intent as Unproven before its empty-source path.
Named refusals include `writer_metadata_seed_provenance_missing`, `writer_metadata_seed_intent_mismatch`,
`writer_metadata_seed_lineage_mismatch` and `writer_metadata_seed_predecessor_missing`.
Required controls cover packing, all page
bindings/bounds, cancellation/disconnect, exact replay, restart, missing/tampered storage and unproved export behavior. Static builds,
independent design review and the later integrated pre-boot lifetime review are distinct gates; no VM run is authorized here.


Review status: the owner's independent **Sol 6.1 xhigh** review at `e7981708` returned **REVISE** for provenance erasure and unbounded
kernel readers. The earlier implementation/design self-review is not independent acceptance. The revisions above address those two
findings in source; compiler matrices, execution of the new controls and integrated pre-boot review remain outstanding.
CNG hashing uses the documented PASSIVE kernel API and feature-only Cng.lib dependency
([Microsoft API contract](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider)).

Implementation boundary: `SafeUploadStageAllocateBoundV23` now requires a writer lease, prepares its exact request carrier and
checks the still-unproved construction gate before any send. It remains uncalled from live CREATE. Same-connection policy/authentication
changes increment authority revision and revoke old carrier reads. The ancestor digest includes the anchor count and explicit uint16
name lengths. Primary-process SID/session are captured as a recipient candidate separately from the retained effective subject;
read/export outcomes and their independent status slots remain Unproven/STATUS_NOT_SUPPORTED. Format-2 journal reads also compare
source provenance with those captured slots, preventing an edited JSON outcome from promoting it to Allowed.

The retained-request-only `SafeUploadStageReplayAllocationV19` entry point explicitly refuses V23 with
`writer_metadata_replay_unbound`: that V18-sized saved request cannot retain the original cookie/revision/lease. Increment 4 must
carry the original owner receipt into same-channel replay and exact candidate retirement, never substitute a fresh connection tuple.
V19 replay is unchanged. The service already supports exact immutable metadata replay and rejects refreshed request/connection values.
Recovery validates inherited source evidence using its captured original author; a descendant's changed recipient remains subject to
the option-1 export guard. A namespace rename can retain the original security record through its exact recorded original binding and
namespace tombstone; reading that history grants no publication authority at the new binding, whose permit remains unimplemented.

Static handoff checks in this checkout: `git diff --check` and independent Windows pack-4 size/offset arithmetic passed (136-byte
request/header, 4232-byte page, 1024-byte facts, 65-page maximum, 526184-byte storage ceiling). Added component controls cover the
client transport, page tuple/order/tails/bounds/cancellation, contradictory facts and descriptor storage, allocator/journal missing
metadata, exact replay/restart, changed connection/request/snapshot, missing/tampered dependencies, original-versus-descendant author
and retained rename authority. Revision regressions additionally cover erasure in public roots and preserving children/grandchildren,
forged/missing predecessors, read/replay/export/cleanup refusal with retained bytes/security, and the common normal/feature export
guard. `driver/SafeUpload.Minifilter/tests/test_writer_metadata_readers.py` compiles extracted production control/admission/close
bodies against portable OS stubs; its controls exercise four simultaneous native readers, excess refusal, fault cleanup, voluntary
veto, mandatory drain and close retry. This runner is an unexecuted mocked component control, not WDK/SEH/runtime qualification.
Existing source-only fixtures now supply synthetic complete metadata explicitly; they are not a native
constructor. No compiler, agent test runner, WDK build, VM or commit was run here. The orchestrator still owns all four WDK/PREfast/
ApiValidator builds and the full normal/feature Debug/Release agent matrix. Source inspection is not independent review acceptance;
full integrated lifetime/lock-order/retirement review before boot and runtime qualification remain outstanding.

### Implementation note — increment 4

This is a **gated implementation draft**, not bound admission or qualification. `StageCreate` now has a prepared V23 branch;
`SafeUploadStageProtocolBoundAllocationReady()` still returns FALSE, and the service's testable `BoundAllocationImplemented`
prerequisite is FALSE in addition to `_stageBoundHeadReady`. Ordinary live allocation therefore still selects V19. Within the
prepared branch, a failed original-subject writer factory, incomplete assigned security, incomplete metadata flags or stale
connection refuses the request; it never retries that bound request as V19. Increment-3 request/reply/blob layouts and its existing
function signatures are unchanged, as are V18/V23/V26 layouts. Normal WDK configurations still exclude the staging sources.

A lost V23 reply transfers the original lease from the transaction to the unresolved stream receipt. The maintenance worker uses
`SafeUploadStageReplayAllocationBoundV23` with that same request, binding, canonical name and original cookie/revision, without
preparing or refreshing metadata. Success recovers only the exact candidate tuple for existing kind-5 retirement, then releases
the lease outside namespace locks. A stale/reconnected channel or missing owner stays held. Mandatory teardown, after worker and
callback drains, locally detaches/releases unresolved allocation leases before waiting for the backend count; it neither replays
allocation nor waits for cleanup ACK. The request-only V19 replay entry continues to refuse V23.

The attach worker captures a separate increment-2 lease for each original CREATE before the bound allocation attempt. The
allocation keeps the existing name reservation, predecessor pin and exact allocation/retirement receipt. After the RPC, outside
namespace/stream/spin locks, it directly revalidates the writer object and complete snapshot, checks the metadata connection,
opens the exact exclusive backing and invokes `SafeUploadStagePublicSeedWriter`. Before binding it checks the reserved view,
predecessor tuple, service generation, cancellation and teardown under the namespace resource. Completion after attachment RPCs
also revalidates the lease/metadata outside locks and then checks the view, cancellation and authority revision. Bound admission
cannot borrow a legacy stream/predecessor or an incomplete capture. Independent bound reopens remain refused until their current
lease can also be bound to immutable version authority; there is no old-lease reuse shortcut.

The kernel copy mechanics use the retained writer FILE_OBJECT, explicit 64-bit offsets, nonpaging noncached reads that preserve
the synchronous file position, and at most two 64-KiB buffers, each aligned by its own instance. Sector sizes must be bounded powers
of two; final write padding is zero, short/unexpected reads or writes fail, the existing 16-MiB product limit stays, and exact EOF,
completed flush, backing remeasurement, source/snapshot/channel revalidation and cancellation checks precede a local completion
record. No target data handle is reopened and no source grant/share fields are changed. The completion is zero on failure and
partial private output is never exposed. New/absent and truncating stages start at zero and require ordinary completion and seal.

**No coherent whole-copy interval is proved.** `StageWriterSeedInterval` refuses every preserving public or private-predecessor
seed with `seed_coherence_unproved`, including an apparently empty source. The loop is prepared mechanics behind that refusal,
not a claim that any preserving seed currently executes. It must not be enabled using identity, stable EOF, matching digests or
per-chunk locks. A private predecessor needs its own exact held immutable interval, not the public writer lease substituted as its
source. The local receipt records driver, reservation, metadata request/epoch/revision/snapshot/digest, private full identity and
generation, source origin, predecessor transfer/full identity/generation, length and completion. It is separate from immutable
allocation metadata and grants no read/export authority.

The service V23 allocator now creates and journals only an **empty private candidate** with seed intent and inherited option-1
provenance. It does not call `OpenPublicSource`, open a predecessor data reader or copy seed bytes. Allocation reply/replay is a
candidate handoff to the kernel, not app exposure. A nonempty incomplete candidate cannot be replied/reseeded; exact identity and
private bytes remain held. Initial direct journal commit also requires an empty object. Legacy allocators are unchanged.

`StagedSeedCompletion` format 2 adds a separate immutable receipt bound to exact version, allocation binding, driver, metadata,
origin and predecessor plus EOF/flush/revalidation facts. Historical two-field format-1 receipts remain readable evidence but cannot
satisfy bound exposure/seal. `CompleteBoundSeedAsync` validates and durably persists the exact receipt, refuses altered retry, and
never performs another copy. There is **no live authenticated completion transport yet**: the V27 read-only carrier and V19/V20
ACKs cannot stand in for one. `BoundSeedDurable` therefore has no success setter. This explicit `seed_completion_unproved` gate
prevents even an empty local completion from exposing an app object until that integration exists; it does not revive EmptyHeld.
The journal enforces the same prerequisite on CompletionPermitted, including the early replay path, on seal/reseal, migration and
inspection/publication transitions. A successful component fixture still takes the ordinary empty SealPending → Sealed path.
Public and private preserving receipts are rejected as coherence-unproved even if they claim successful I/O.

| Owned resource | Acquisition/transfer | Local release and teardown |
| --- | --- | --- |
| Original subject, request inputs, process/root/instance/callback references | Existing attach transaction; original callback capture precedes worker use | Existing PASSIVE attach release; final cancellation dereference remains nonpageable and empty |
| Writer lease, source handle/object, snapshots and metadata | `StageAttachResumeOrRun` → transaction; successful binding transfers one owner to one `STAGE_HANDLE`; duplicated/inherited handles share that object | Failed attach releases transaction owner; rollback or last-handle CLEANUP releases handle owner outside namespace/stream locks; canceled CLOSE has the same fallback |
| Lost-reply metadata/lease owner | Transaction transfers its original lease to `AllocationWriterLease` only while the exact allocation tuple is unknown; recovery RPC reference pins the stream | Successful same-channel tuple recovery detaches the lease and releases it outside namespace locks; mandatory teardown releases it locally after joins and before backend-owner drain |
| Writer operation rundown | Metadata-current check and seed helper; retained across any seed I/O | Released on every helper exit; common backend close waits only for local operations, then closes handles |
| Candidate backing and local completion | New attach-owned stream plus existing name reservation and allocation receipt; source predecessor remains pinned through out-of-lock failure close | Failed bound candidate closes backing outside namespace locks before existing exact retirement; incomplete/unknown allocation receipts stay held; mandatory teardown does not send a fresh RPC |
| Two aligned copy buffers / source volume reference | Seed helper only, after interval prerequisite | Freed/dereferenced on every exit, before operation rundown release; no global buffer owner |
| Security, provenance and durable completion | Service-private security record/manifest; predecessor lineage preserved unchanged by intent allocation | Existing exact cleanup and compaction rules; option-1 blocked descendants retain required ancestry/security and cannot export without affirmative recipient authority |

The existing backend/factory counts include these leases in voluntary veto. Attach/stream/RPC counts cover candidates and seed work.
Mandatory admission fencing, port wakeup, `SafeUploadStagePublicCloseAllBackends`, local operation rundown and attach/worker drains
remain the teardown path; no new service ACK wait, worker or mandatory RPC is added. Close-before-dependent-wait remains required.
The new pageable helpers declare PASSIVE SAL contracts and PAGE allocation, initialize output storage before refusal and publish a
completion only after success. No wait or I/O is added under a spin lock.

Named seed refusals are `seed_coherence_unproved`, `seed_completion_unproved` and kernel `seed_io_failed`; existing capture,
security, snapshot-change and metadata-stale diagnostics remain. Export uses the existing option-1 `seed_export_denied`,
`seed_export_unproven` and `seed_export_recipient_unproven` policy. Export denial is not used to reject an otherwise proven clean
write-only edit. Missing completion independently prevents export; apparent empty/final rewritten content does not erase lineage.

Added/updated component controls cover empty candidate intent for each disposition, no second public reader under native share 0,
partial-copy replay retention, missing/substituted/legacy receipts, public/private coherence refusals, inherited provenance,
completion persistence faults before/after replacement, immutable retry, completion-permit replay and ordinary empty seal.
`StagedSeedCompletionTests` is compiled in normal and feature configurations; filesystem/carrier integration controls retain their
feature guard. Synthetic receipts/fixtures prove only component prerequisites, not a native copy or kernel authorization.

Required native controls remain report groups 1/2 (original grants/share and post-RPC ancestor/object/absence races), 5 (actual
READ/WRITE/APPEND objects, share 0/7, sync/async/no-buffering, 0/1/sector/chunk/multichunk lengths, deterministic first/middle/final
barriers against cached/noncached writes, append/truncate/regrow, mappings, hard links, keyed locks, cancellation and oplocks),
6 (independent read/export authority and effective recipient through preserving descendants), and 7 (cancellation at every owner,
duplicate/inherited versus independent objects, process/instance teardown and unload). Test transport beyond 16 MiB separately
without changing the product limit. Exact EOF/flush/receipt and independent byte observations are required; builder controls are
not protected-target qualification.

Increment 5 must implement the reviewed V26 bounded permit/Facts lifecycle, actual original service CREATE/security comparison,
one-way I/O fence, checked rename/name reservation, native outcomes and exact retirement/ACK handling. Its authority owner must
retain the exact version's security/seed evidence after per-app public leases close, and it must refuse absent/incomplete seed
completion. Before any bound activation, the integrated path also needs an authenticated, replay-bound durable seed-completion
handoff (without repurposing the read-only V27 carrier), qualified coherent source ownership, descriptor construction/round-trip,
independent export/recipient proof and complete publication/recovery/head integration. These are explicit remaining conditions,
not permission to enable the path by changing the two readiness guards.

Verification for this draft is source/diff inspection only. No build, test execution, commit, push or VM boot was performed.
The orchestrator still owns four WDK Debug/Release × normal/feature builds with PREfast/ApiValidator at zero warnings/errors and
the complete agent matrix. Independent integrated kernel lifetime review and the owner's product-run release remain required
before a revised protected boot; the T4 stop is unchanged.


## Implementation note — increment 8

2026-10-13, working tree `wt/t5-inc8`, base `017955abcf110ff1daaa916eb4598c2f24b83b5d`.
No commit, build, test execution or VM boot was performed. The orchestrator owns the normal/feature × Debug/Release
WDK builds with PREfast/ApiValidator at 0 warnings/errors and the agent matrix. Source inspection and `git diff --check`
are the local checks; the tests below are added controls, not execution or protected-pair evidence.

`StagedNativeStartupRecovery.PrepareAsync` now invokes `StagedNativeRecoveryDispatcher` when the authenticated observation
transport is present. The dispatcher reconciles full CREATE facts against the durable intent, obtains lifetime proof from
that connection's complete replay, enters the existing reconciliation turn, and requests control-31 observation of the exact
mount GUID/root/parent/case/leaf. It rechecks the same driver/connection/boot/revision and rows around the observation and pass.
A changed replay fails the pass. Missing transport retains the prior fail-closed startup guard. A completed pass may leave an
explicit per-name hold and owner-scoped guidance; accepting an epoch is not permission to publish to that held destination.
`_stageBoundHeadReady` still has no true assignment. No new persisted state, protocol version or public mutation was added.

The original CLEANUP/cancelled-CLOSE facts remain the only same-driver positive lifetime evidence. The new
`SafeUploadStageNativeNameChanged` only advances the native-map observation revision and wakes its existing bounded worker
when the instance has a retained cleanup obligation. Non-draining directory-notify completion, external SET_INFORMATION and
independent-reader CLEANUP trigger it; the original record's own CLEANUP still uses its existing callback. Successful V26 rename
also supplies a wake after releasing the publication lock. Service metadata/private I/O is excluded from generic wakes to avoid
an observer-close/replay feedback loop. Notifications own no FILE_OBJECT, handle, instance pin, timer or extra work item; their
nonpaged callback has no wait, allocation, namespace lock or RPC. The existing worker obtains fresh complete replay and anchored
observation through the V24/V25 continuation. A notify completion or unrelated reader close does not change any lifetime fact.
An original still delete-pending stays scheduled until a subsequent event proves absence or exact newer publication.

`StagedPublicOpenDispatcher.ReconcileStartupAsync` processes retained ordinary disposition results and cleanup receipts without
prepare/forwarding, including lost slot/removal replies. A qualified full Restart can reconcile an old ordinary record only with
its durable native result and exact anchored observation; missing disposition outcome remains held. Same-driver absence requires
the later ACK/cleanup revisions. The scheduled-native startup dispatcher uses the existing greater-boot/different-driver/complete
replay proof; a new GUID, service restart, Fast Startup, timer, PID or clock alone cannot discharge forced-instance loss. The
fixed-NTFS observer remains the scope gate. USB/remote recovery is not implemented. Unreadable anchors, unexpected replacements
and lost evidence remain held with named diagnostics and owner/session/SID-scoped tray guidance; no manual clear is offered.

`RecoverBoundReceiptsAsync` enumerates destination attempts independently of manifest state. Startup and the existing publication
worker therefore continue V26 bookkeeping for Publishing, Released and Retained, including pre-rename and failed-CREATE attempts.
`ReconcilePublishingAsync` requires an explicit bound dispatcher for those records; normal services retain the refusal. Exact
accepted Facts plus anchored temporary-ID observation finish an interrupted PendingCommit; the replay is checked again after
observation. Already-Published durable heads finish a lost Released write even if the original map is gone, without implying
cleanup. ACK is armed durably after terminal local facts and result persistence, and storage retires only on later complete,
greater-revision authenticated absence of the exact attempt. New-driver/unknown cleanup remains retained. Recovery never issues
CREATE, rename, disposition, orphan-path deletion or a mutation permit. The existing worker's backoff retries bookkeeping only;
it does not supply lifetime evidence. The V26 transport is rebound per connection after previous work drains.

| Durable evidence | Recovery state / permitted action |
| --- | --- |
| AcceptedUnresolved, original lifetime live/unproved | Keep name held; close-app guidance, or full Restart for forced fixed-NTFS coverage loss |
| Exact original cleanup/cancellation or qualified Restart; anchored original present | Downgrade exceptional native hold to Admitted; keep generation floor and cleanup receipt; never Complete/ACK from presence |
| Same lifetime proof; anchored absence | Complete scheduled deletion, advance committed-delete floor, arm ACK; retain receipt until later removal proof |
| Exact newer durable Published identity | Superseded under existing generation/identity rules; pending/blocked successors have no effect |
| Unknown ordinary disposition result | Keep PendingCommit and named hold, including across a qualified Restart |
| Bound PendingCommit and exact accepted native rename Facts | Recheck anchored object and replay; persist Facts → Published → Released; never rename again |
| Already-Published bound head, lost Released write | Finish manifest bookkeeping; retain unresolved cleanup independently |
| Failed/never-forwarded bound operation with terminal cleanup | Persist Retained and exact ACK fields; never repeat its native mutation |
| ACK reply lost or driver removal reply lost | Repeat only exact bookkeeping/ACK while record exists; retire after later authenticated absence (native full-Restart exception as above) |
| Unknown result, changed anchor/replay, unproved cleanup | Retain private bytes/receipt and applicable barrier, with diagnostics; no inferred success |

Feature seal handling now uses the connection-owned `StagedRequestContinuations` rather than blocking the receive loop on journal
or stage I/O. It validates the captured driver and cancellation before replying. Connection shutdown cancels/joins both startup
and continuations before disposing the ordinary dispatcher or port. Compaction pins pending commits, native delete bindings,
ordinary mutation/original-open bindings, V26 attempts/receipts and private cancellations, then applies the existing manifest,
seed/predecessor and security-reference closure. ACK arming alone never removes those roots; generation floors remain in the head. Native retirement also requires the supplied
ACK revision to equal its durable value; the existing terminal-unlink test now explicitly arms that receipt before checking
same-revision rejection and later removal, preserving every assertion.

Added component controls (all unexecuted):

| Required case | Controls |
| --- | --- |
| Native startup durable boundaries | `StagedIncrement8RecoveryTests`: result, hold release, Complete, ACK-armed, retired; fresh startup/journal after each injected crash |
| Live last-close, original delete-pending, directory change, lost removal reply | `Startup_live_original_then_last_close_then_directory_change_keeps_distinct_receipts`; existing V24 lifecycle tests remain |
| Forced-instance / full Restart / same boot / rollback | `Forced_instance_requires_exact_cleanup_or_qualified_full_restart`; original present and unknown ordinary result in `Ordinary_forced_instance_recovery_requires_known_result_boot_proof_and_anchored_absence` |
| Stale/unreadable/replaced observation and retired native replay | `Startup_observation_failure_or_changed_revision_never_releases_the_name`; `Retired_native_receipt_cannot_be_recreated_by_old_forwarded_facts`; `Native_retirement_requires_the_persisted_ack_revision_not_a_caller_supplied_floor` |
| V26 Retained / ACK persistence / removal crashes and lost ACK | `StagedIncrement8PublicationTests`: three durable-boundary cases and Released/failed-CREATE/failed-rename startup-worker cases; unchanged mutation counters |
| Published before Released with driver loss; revision changes during observation | `Durable_published_head_finishes_released_after_driver_loss_without_retiring_unproved_cleanup`; `Recovery_rechecks_authenticated_facts_after_anchored_observation` |
| Retired V26 replay / compaction | `Retired_publication_facts_cannot_resurrect_an_attempt_or_mutation`; `Outstanding_ordinary_open_receipt_pins_its_original_manifest_and_security_after_publication_retirement`; existing outstanding-V26/ancestry controls |
| Ordinary startup/slot/cleanup ACK loss and receive-loop independence | `StagedIncrement8PublicOpenTests`: exact original pending/absent progression and continuation cancellation/join control |

The existing increment-6 13-boundary reply-loss/crash matrix and increment-7 disposition/cancellation controls remain required.
Synthetic component facts do not prove callback delivery, native security equivalence, actual NTFS pending-link behavior or
protected lifetime. The orchestrator must retain all matrix/build failures; the coherent Sol 6.1 xhigh lifetime review still
precedes the first authorized revised VM boot, which remains prohibited in this task.

Increment 9 must prove original SOP lifetime and changed-incarnation retirement in StageWriters/StageAdmission with all
reference/section/accounting obligations preserved and sticky Unknown unchanged. Increment 10 must finish service-independent
mandatory fencing/port wake/local drain/join, voluntary veto closure, and readiness composition/invalidation for the complete
negotiated recovery path. It must preserve named unresolved holds and uncertain publication/private residue. Descriptor/coherent
seed prerequisites and the protected three-mode/raw-observer/restoration gates remain separate qualification requirements.
