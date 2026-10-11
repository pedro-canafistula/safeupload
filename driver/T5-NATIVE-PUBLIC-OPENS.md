# T5 native public opens and delete lifetime

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
destination journal turn. The exported service handle is ephemeral and cannot prevent last-handle cleanup. Return NTFS's actual
result. Ordinary TRUE/FALSE cancellation and accepted-disposition reservations remain as specified in T5-DELETES section 4.2.

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
never opens the child or interprets access denial as absence. Authenticated anchor export and the live recovery call remain pending.

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

- Implement the corrections in the READY WITH CORRECTIONS security-design review; do not claim the existing recovery is already wired.
- Review the integrated kernel lifetime/lock-order/retirement change once before its first revised VM boot.
- Four WDK/PREfast/ApiValidator configurations at 0/0 and the agent matrix after service changes.
- Native ShareAccess=0, duplicate/inherited handles, real public identity/size/security/name, reads beyond 16 MiB and implicit position.
- Native byte-lock conflicts/cancellation, read/image mappings past app cleanup and rejection of public writable sections/paging writes.
- Deterministic native deletes before seal and after independent publication observation; native scheduled-delete/publication races.
- Inject pre/post-CREATE tracking failures, identity replacement, service disconnect and mandatory unload without hiding accepted mutations.
- Existing private disposition assertions, real Notepad clean/CPF rows in all three modes, independent byte observers and separate restoration.
