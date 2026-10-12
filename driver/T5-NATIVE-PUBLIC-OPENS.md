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
subject, with the original requested rights and sharing. NTFS decides authorization, including mandatory integrity and traversal;
never add backup/restore privilege or substitute SYSTEM. Capture identity and grants from that same checked object. Model each
disposition's extra native checks: present FILE_CREATE retains its collision result; overwrite needs implicit write and applicable
EA/attribute authority; supersede needs the native delete/parent DELETE_CHILD alternative and applicable EA/attribute authority.
Implicit check rights are separate from the rights exposed on the app's handle. A supersede permission check does not grant an
ordinary writer DELETE. Creation-only flags must not cause mutation during the probe. The operation/flag matrix requires native
controls before admission, including caller identification-level tokens; never promote an otherwise unusable subject.

For proven absence, require the original disposition to allow creation, then have NTFS check FILE_ADD_FILE on the exact parent
with that same subject and original path/case semantics. Assign the private view's descriptor from the exact held parent's security
and the original CREATE descriptor/subject, without granting a right merely because the worker can create a backing file. Preserve
the supported CREATE-option matrix and security-only public-open behavior; combined unsupported metadata changes remain refused.
Overwrite retains the existing descriptor; supersede/new creation use the descriptor NTFS would assign from the exact parent,
original CREATE descriptor and subject. Include owner/group, inheritance, SACL and mandatory labels, not only a DACL copy. A
discrepancy with the native control keeps admission closed; do not silently broaden grants or narrow required product behavior.

Separately open read-only metadata anchors below the original instance, walking each component with its actual directory case
mode and rejecting reparses. Query the checked source object's canonical long name, verify its parent/leaf against those anchors,
and retain only the exact full root/parent/target IDs, mount GUID, case mode, leaf and assigned security needed by the private view.
For absence, perform complete anchored enumeration with the original lookup semantics; an incomplete lookup is not absence.
Capture the tuple outside namespace locks after reserving the name. Send V23 and persist its exact retry snapshot. Before exposing
the private open, reopen/recheck those anchors and the target ID or absence outside locks, then revalidate the reserved view,
predecessor, caller lifetime and service generation under the namespace lock. Repeat the exact disposition-specific NTFS rights,
sharing, traversal and label checks after the RPC; unchanged IDs alone do not establish unchanged authorization. Capture the
resulting descriptor again. Any mismatch retains/discards the private candidate
through the existing exact receipt path. It cannot expose a different source, rename a public file or grant DELETE.

The public DELETE/read-only native factory remains separate and retains its actual NTFS-checked backend. Its original-sharing and
last-close timing must not be changed by this allocation correction. Both new allocation authority and native delete authority
eventually feed the same bound head/permit pipeline; neither enables live admission by itself. Required controls include ordinary
and denied access, DELETE_CHILD/SUPERSEDE, case-sensitive/short-name resolution, label/traversal denial, target/parent replacement,
and unchanged native sharing/cleanup behavior. The integrated lifetime/lock/retirement review still precedes the first revised boot.

**Current review status, 2026-10-12: REVISE; admission remains disabled.** The live writer identity check on allocation replay is
implemented in `dbe02d04`, both before and after replay; PID/session/SID/creation identify ownership, not filesystem authority.
Kernel permission capture, seed transport and descriptor assignment are not yet integrated.

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
reading through that probe or exposing it to the app. An ignore-share authorization probe is only a candidate for this separate
read check; the original CREATE check never bypasses sharing. Its oplock/audit effects and exact identity must be controlled.
Explicit access/label denial and an indeterminate probe have distinct diagnostics; neither establishes permission to export old
bytes. Validate the eventual hand-back recipient too; the process-primary SID is not the original thread's effective subject.

Persist source provenance plus affirmative read/recipient authorization with the bound allocation, carrying it through any seeded
private predecessor. New/absent targets and truncating/superseding dispositions start without old public bytes and retain the
ordinary hand-back path; do not infer provenance from final length or a changed write mask. No new journal state is needed.

#### Owner choice pending — unreadable seeded bytes

1. **Preserve native write-only editing.** Clean saves publish normally with the required destination permissions. If a blocked
   version contains prior bytes whose read/export authority is denied or unresolved, keep it service-private using existing
   Blocked + HandbackState.Failed with a named diagnostic/tray reason. No readable full-file hand-back is made. Existing behavior
   closes justification without verified hand-back and prevents cleanup of that blocked stage. Normal read-authorized saves keep
   their current hand-back and justification. Users of a write-only protected log can continue clean appends, but cannot retrieve
   the entire blocked log through SafeUpload.
2. **Require read authority for edits that preserve old bytes.** Refuse such an existing-file open when read/export authority
   cannot be proved. Those apps cannot edit or append through SafeUpload in that mode; new and full-replacement saves continue.
   Admitted blocked saves retain the full-file hand-back model. This deliberately narrows native Windows editing behavior.

This is a failure-policy/product decision required by the owner's stop-and-ask rule. Neither option is implemented or approved.

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
