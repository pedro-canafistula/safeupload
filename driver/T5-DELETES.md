# T5/T8 design: private discard, public delete, and in-folder rename

Status: owner decision recorded 2026-10-11. A zero-byte staged file is an ordinary sealed file: the service checks its stable length,
classifies it trivially clean, and publishes it through the normal exact-destination path. EmptyHeld and its private tray notice are
retired. Public-file deletion is an M2 feature. The [independent Luna design review](evidence/2026-10-11/t5-empty-public-delete-design-review-luna6.md)
accepted this design in `434315cf`. Implementation is underway; concrete kernel lifetime/lock-order/retirement changes need their
review before the first revised VM boot, and runtime qualification remains required.

The native public-open routing correction is **READY WITH CORRECTIONS** in the
[focused Luna review](evidence/2026-10-11/t5-automatic-native-delete-recovery-review-luna6.md). See [T5-NATIVE-PUBLIC-OPENS.md](T5-NATIVE-PUBLIC-OPENS.md) for the
supported-object correction, required scheduled-delete ordering and owner-approved automatic-recovery conditions. Section 4.1's original
proxy construction is not authority to implement the rejected synthetic FCB/native-section-pointer pairing or unsupported on-close emulation.

This note covers the Notepad Save As test-file sequence (T5), Office temporary/backup sequences (T8), deletion of a public file, and
the lifetime and recovery rules needed to make those operations safe. The earlier R1 physical-delete and R2 physical-rename/link
proposals remain withdrawn. Physical rename and link operations touching protected names stay refused; in-folder rename continues
through the staged rename transaction and T6 copy fallback.

## 1. Invariants

1. A destination is ordered by a durable generation for its normalized volume and name. A delete is a journaled generation barrier.
   A version below that barrier cannot be inspected, justified, or published after the delete commits.
2. Decisions about a stage file bind the transfer ID, volume identity, and full 128-bit file ID. A path alone, basename alone, or
   64-bit file index is not proof of identity. An exact cleanup opens without following reparse points, verifies the recorded volume and
   FILE_ID_128, deletes through that exact opened object, and records a durable receipt for that same identity.
3. A sealed byte count is measured only after the driver has drained writers, file objects, mappings/cache maps, and paging I/O. The
   service verifies the exact stage identity and stable length before inspection or publication. Length equality remains mandatory;
   the old positive-length-only rule is removed.
4. Empty is ordinary content. Stable length zero is trivially clean and can be published under the same generation, permit,
   destination, and atomic-commit checks as non-empty content. The test suite drops only the old assertion that no empty file may be
   published. It retains the independent raw-volume no-uninspected-nonempty-bytes assertion, exact final clean bytes, CPF new-name
   absence, CPF existing-name prior bytes when no public delete was requested, and no empty leftover.
5. Windows decides whether the caller may delete a public name. The service must not use its service account's privilege to manufacture
   user authority. The driver-issued one-use permit records a successful caller-side Windows authorization for DELETE on the file or
   DELETE_CHILD on its parent, and binds that authorization to the caller, transfer, generation, exact destination, and exact public
   file identity. Normal share-mode and mapped-file checks still apply.
6. No namespace resource is held over a service RPC, destination-queue wait, file I/O, or callback drain. Any object used after dropping
   the namespace lock has an explicit pinned reference. Voluntary unload cannot discard an outstanding delete/discard intent, exact
   cleanup receipt, callback, owner reference, worker item, or in-flight RPC. Mandatory teardown follows section 7's local rundown
   and durable retained-stage recovery rules.

## 2. Empty files and old journal entries

For a new save, the driver first completes the T4 drain. The service opens the exact stage object without following reparse points,
denies new writers, confirms the recorded volume and 128-bit file ID, and records the measured length. If the stable measured length is
zero, the service records an ordinary Sealed state and an empty-content digest, applies the ordinary clean result, and publishes the
empty file through the normal exact publication permit and atomic destination commit. There is no EmptyHeld branch, no empty-specific
discard, and no EmptySavePrivate notification or tray route.

The persistent numeric value previously used by EmptyHeld is reserved as LegacyEmptyHeld and is never emitted for a new entry. Do not
renumber any existing journal or protocol enum. At service startup, every legacy EmptyHeld manifest must be reopened by transfer ID and
its recorded volume and FILE_ID_128. The service performs a fresh stable-length check before allowing publication:

- First reconcile the legacy entry's discard request/acknowledgement, pending deletion, child ancestry, owner-exit, and driver-epoch
  obligations. If any such obligation is unresolved, keep the entry nonpublishable and complete or retain that exact cleanup work
  before migration. Never turn an entry with a pending discard into Sealed.
- At stable length zero, and only when no such obligation exists and the entry is still the current generation, rewrite the manifest to
  ordinary Sealed with the exact identity, measured length zero, and the empty digest.
- At stable length greater than zero, rewrite it to ordinary Sealed with the fresh measured length and digest, then send those bytes
  through normal inspection.
- If the object is missing, the identity differs, a reparse point is encountered, a writer/mapping can still change the length, or
  the check cannot complete, keep the entry private and nonpublishable in a recovery/retained state. Never trust the old zero length
  or publish from its old EmptyHeld label.

This migration preserves the generation high-water mark. A later create always receives the ordinary next generation. The migration
does not infer approval from a historic empty classification.

## 3. Private-version discard

Private discard applies to a never-sealed version whose name has no public file, such as the common file dialog's newly created test
file, an application temporary/backup name, or an Office owner file. A delete of an existing public file follows section 4, even if
the caller also has a staged version of that name.

A successful ordinary disposition sets the version's shared delete-pending state immediately. An ordinary clear through another
DELETE-authorized handle can clear it, as verified on real NTFS both before and after the first handle's cleanup in the
[native control](evidence/2026-10-11/t5-ntfs-disposition-control-1011.txt). Keep the existing stream-wide ordinary disposition;
do not invent a per-handle ordinary-delete guarantee. FILE_DELETE_ON_CLOSE and supported FILE_DISPOSITION_ON_CLOSE state remain
per handle. Preserve the existing private-view admission contract: scheduled on-close requests contribute to its aggregate pending
state, and new private opens/renames receive STATUS_DELETE_PENDING until the requests are cleared or the version is retired. The
existing probe-doc and probe-onclose assertions, including Win32 303 before private cleanup, stay unchanged. This existing private
contract is stricter than the native public-file CREATE delete-on-close control, which allowed opens before creator cleanup and
became pending afterward; that native timing governs the new public backend in section 4, not a waiver of private-row assertions.
Cleanup folds an effective on-close request into persistent disposition; last-cleanup admission and
create/rename transitions are serialized under StageNamespaceResource. The extended on-close control returned unsupported on the
builder and is not evidence of qualification; the existing native extended-disposition rows remain required on the product VM.

At the last cleanup for the version, the driver detaches it from the owner's name immediately and retires the private namespace view.
The next same-name create uses ordinary allocation at the current maximum generation plus one; it does not wait for the prior stage's
physical deletion and does not use a successor reservation. A discarded version is terminal and is never sealed, inspected, justified,
or published. An older sealed/blocked version remains barred by the durable discarded generation.

After the T4 lifetime drain, the worker closes the backing and snapshots the transfer ID, generation, owner, volume identity, and
FILE_ID_128. It drops StageNamespaceResource before sending STAGE_DISCARD. The service validates the exact tuple, durably records a
nonpublishable discard intent/Discarded state, enqueues exact-object deletion, and promptly replies with an accepted/queued result.
The FilterPort receive loop must not wait for physical deletion: it must continue serving ordinary allocation, seal, lifecycle, and
reconciliation messages while the cleanup worker removes the stage.

The driver keeps a retired stream/cleanup record and vetoes voluntary unload until it receives the exact cleanup acknowledgement that confirms
the recorded stage identity is absent and the receipt is durable. Journal acknowledgement and physical deletion are separate states.
On a lost reply or service restart, the driver retries idempotently; the service's durable cleanup worker resumes from the journal.
The service must not acknowledge physical cleanup merely because a pathname is absent, and must not delete a replacement file at the
same path. The driver validates the returned transfer, generation, epoch, and identity before releasing its pinned record.

There is no special CREATE_AFTER_PRIVATE_DISCARD allocation. Once the private view is detached, a later ordinary create can allocate
max+1 while exact deletion is still running. The old discarded entry remains a generation barrier. Remove the successor-retirement
chain that existed only to clean up an EmptyHeld predecessor before attaching an unparented allocation. Keep independent unattached
allocation cleanup when it protects a failed ordinary allocation.

## 4. Public-file deletion (M2)

A delete of an existing public file creates a durable public-delete generation, distinct from private discard. The request is bound to
the exact protected destination and the caller's checked Windows delete authority. The service must not trust a path supplied by the
caller or an ACL check performed as SYSTEM. Windows' actual access check must authorize either DELETE on the file or DELETE_CHILD on
the parent. The denial test removes both grants. Share conflicts, open mappings, and other normal filesystem restrictions remain
effective.

### 4.1 Checked public capability and app-facing proxy

Use an owned app-facing FILE_OBJECT for a delete-capable open. A non-writing delete proxy is backed by the real public object;
a combined DELETE+write open remains backed by its private stage for data edits and also holds the separate public delete capability.
No writable app handle or writable section is ever redirected to the public backing. The app proxy's cleanup is independent of the
public backend's handle lifetime; a kernel/service handle on the app's own FILE_OBJECT would prevent that cleanup and is not the design.

The public backend open is an actual NTFS OPEN_EXISTING, with the original request's DesiredAccess and ShareAccess. It must never
truncate, create or overwrite the public file. Capture the effective subject from the original create's security context, including
impersonation, restricted tokens and impersonation level, rather than the PID's primary token. Pin that exact subject while queued;
use it for the real filesystem open with OBJ_FORCE_ACCESS_CHECK and OBJ_KERNEL_HANDLE, without backup/restore privilege elevation
or a SYSTEM fallback. Never use IO_IGNORE_SHARE_ACCESS_CHECK or broaden sharing to make a backend open succeed.
An unavailable or non-impersonatable subject fails the request. NTFS grants or refuses file DELETE or parent DELETE_CHILD and normal
share rights. Record the backend's actual successful DELETE grant, not an access mask checked only against the file DACL.
For an absent public name there is no public capability: an owned private probe uses section 3 or private cancellation instead.

Bind the checked capability to the public volume identity, full FILE_ID_128, verified parent directory identity and canonical leaf.
Resolve from an anchored parent without following reparse points in any component; OPEN_REPARSE_POINT on the final component alone
is insufficient. Check the binding before a disposition under the destination turn. If a newer publication replaced that public
object, use the published-only suppression rule below; any other identity mismatch is ambiguous and fails closed.
Keep the originally checked capability through application handle duplication: disposition is authorized by the granted handle,
not by a new access check under the process that later uses it. Do not acquire a second public open on each SetInformation.

The service receives only an ephemeral DELETE-capable handle to this same backend FILE_OBJECT, exported solely into the authenticated
service process. KernelMode ObOpenObjectByPointer is a handle-transfer mechanism, never authority to grant access: DELETE must already
be proven on that exact object. Restrict the exported handle to DELETE; keep broader originally granted access only on the driver's
backend for allowed proxy operations. Validate the connected service process and epoch, pin it during export, and close exported
handles on completion, cancellation, disconnect and process exit. A service handle cannot outlive its request/permit. The driver keeps
the backend hold while an ordinary disposition can still be cleared or an on-close request is still live, and closes it at final proxy
cleanup. Exact physical-delete reconciliation retains object identity and durable state, not a backend handle that prevents last close.

A one-use driver permit binds request nonce, connection epoch, transfer, generation, exact parent/name and backend identity. It permits
only the specified disposition on the checked backend; no data writes, rename, reparse change or substitution. The service applies the
disposition under the shared destination journal turn. The filter recognizes this exact inner service operation and forwards it to
NTFS rather than recursively requesting another service transaction. Consume/revoke the permit on the actual operation; no replay
under another caller, generation, name or object is allowed.

The proposed same-volume routing and section/cleanup lifetime mechanism is detailed in
[T5-PUBLIC-PROXY-ROUTING.md](T5-PUBLIC-PROXY-ROUTING.md); it needs its focused security-design review before implementation.
The proxy preserves the original handle's supported surface. For a non-writing delete proxy, forward allowed reads, positioning,
byte-range locks and filesystem metadata queries to the checked public backend under the caller's originally granted rights; report
its real size, attributes, streams, public FILE_ID_128/internal ID, public name and volume. Never expose a private proxy backing's
identity, path or length. FileName/NormalizedName, FileId/Internal, Standard/All, Basic/NetworkOpen, AttributeTag, Streams and other
supported query classes need that branch in StageQuery. For combined write+delete handles, data and staged-length queries remain
private while namespace/security mutations follow T10 and the explicit public-delete transaction. Preserve the established refusal
of physical rename/link and unsupported mutation classes. The public backend share ledger and read/section/lock rundown are separate
from the private stage's ledger. Qualification must compare the allowed proxy operations and duplicated handles with native NTFS;
supporting only DeleteFileW or silently refusing previously supported query classes is not an acceptable implementation shortcut.

### 4.2 Disposition acceptance and last-close completion

Persist DeleteIntent and acquire the per-destination turn before the service applies ordinary non-POSIX disposition on its exact
checked handle. Return NTFS's actual result: an open/mapping restriction or permission failure is not reported as success. If it
succeeds, persist DispositionAccepted before completing the caller's SetInformation; close the temporary service handle before
waiting for cleanup. Do not wait synchronously for physical unlink: DeleteFileW closes its caller handle only after SetInformation
returns. New public opens fail normally while NTFS marks the target delete-pending; already-open handles retain Windows semantics.

Retain a durable logical destination reservation while waiting for final proxy/backend cleanup and exact old-link absence. Release
the global metadata semaphore and worker thread while waiting; keep an explicit operation reference. New saves may allocate ordinary
higher generations, but their physical publication waits behind this reservation. Last proxy cleanup closes the driver's backend
hold. Other real file objects can still delay unlink, as on NTFS. After exact link removal is proven against the accepted identity and
intent, persist PhysicalDeleteComplete and the immutable committed delete barrier. Register asynchronous parent-directory change
notification before the pending close, and wake reconciliation on proxy/backend cleanup, notification, overflow or service reconnect;
do not poll continuously while the system is idle. Notification names alone are not receipts: reconcile the exact anchored parent,
leaf and accepted object identity. Lost notifications trigger enumeration/reconciliation; ambiguity retains the reservation.
Never certify a replacement or infer success
from path absence without the prior exact accepted operation. A changed or ambiguous link blocks the destination for recovery.

Ordinary disposition remains stream-wide. A FALSE request from another still-live DELETE-authorized proxy for that same public
object may clear it under the same logical destination turn. Return its actual NTFS result; a verified effective clear persists
Canceled for all still-provisional accepted ordinary-delete intents, publication barriers and owner tombstones for that exact public
object identity, across handles and owners. Reconcile them together before releasing its logical reservation and retain maxAllocated.
An unrelated object, immutable completed delete, or later TRUE ordered after this clear is unaffected. Scheduled per-handle on-close
requests are not canceled by ordinary FALSE; their later cleanup can establish a new effective pending disposition. A canceled delete
does not commit an irreversible delete watermark or supersede still-current private content. No clear can resurrect an already
physically deleted object. Multiple pending dispositions for the same exact object must reconcile with this shared NTFS state.
FILE_DELETE_ON_CLOSE and supported FILE_DISPOSITION_ON_CLOSE remain separately tracked scheduled requests. The corrected native route
preserves the original CREATE and native scheduled-delete flag after durable pre-CREATE intent; it does not emulate that flag by an
unsupported extended disposition. A failure before forwarding leaves the public file untouched. Once NTFS accepts deletion, a later
tracking failure cannot be described as an unchanged failed open. The owner-approved exception is accepted/unresolved, with physical
publication held and automatic reconciliation at the app's last-handle close and service startup. Exact absence or the original
pre-open identity releases the recovery hold automatically; an undecidable result retains it with a named-file actionable tray
notice and diagnostics. Reuse existing intent/startup recovery; no additional protocol states beyond accepted/unresolved. The
reviewed corrections in [T5-NATIVE-PUBLIC-OPENS.md](T5-NATIVE-PUBLIC-OPENS.md) are mandatory; if automatic
recovery cannot be met during implementation, ask the owner. Preserve actual unsupported-flag results; the unsupported builder on-close probe is not
evidence that those flags work on the qualification VM.

The FilterPort receive loop dispatches these transactions to bounded workers and remains available for create, seal, cleanup,
cancel, acknowledgement and reconnect traffic. It must not await a destination queue turn, backend deletion or last-close event.
Cancel before the physical operation revokes that request's permit and leaves the public object untouched; after NTFS accepted disposition,
report that accepted result and reconcile or execute an explicit authorized object-wide clear. Cancellation/disconnect cannot pretend that an
already-applied mutation was undone. Recovery resumes only from exact durable intent/acceptance evidence; it never reopens a
changed path under SYSTEM to regain a lost caller capability.

The owner receives a tombstone when its checked delete request is admitted, so future owner open-by-name operations no longer reveal
the old public version. A request that fails or is canceled before NTFS accepts its disposition removes only its own tombstone.
After acceptance, cancellation retains the accepted result until reconciliation; a successful authorized ordinary FALSE clears all
provisional tombstones for the exact object under the object-wide rule above. Other processes retain the old name until the
service applies disposition, then new opens fail as delete-pending until last-close removal; existing handles keep Windows semantics.
At physical completion, the service durably records the delete result and destination watermark under the journal gate. A later ordinary save gets a
higher generation and can publish clean replacement bytes. A rejected/CPF version cannot restore or publish bytes.

The delete applies unless a newer generation has already reached durable Published/Released commit before the delete takes its
destination commit turn. Allocated, Unsealed, SealPending, Sealed, Inspecting, Approved, Publishing, Blocked, and Retained versions
do not suppress it. A newer in-flight commit may win only if its exact atomic rename and published receipt complete first; the delete
then observes that newer published generation and records itself as superseded without removing it. If the delete commits first, a
newer save may publish afterward only by completing its own normal clean inspection and exact atomic commit. An older transfer can
never perform a physical rename after the delete watermark.

The current publisher writes Publishing to the journal, then separately obtains a permit, writes a temporary destination, performs a
native rename, and records Released. A per-manifest journal semaphore alone does not serialize that physical commit. Before public
delete is implemented, publication and delete need a shared per-destination commit protocol:

1. Prepare inspection and temporary bytes outside the short destination commit turn.
2. Enter a cancel-aware per-destination journal commit queue keyed by volume and normalized parent/name. The per-destination journal
   commit lock is the serialization authority for both publication and delete. Publication holds it across physical rename and durable
   Published; deletion holds it across NTFS disposition and durable DispositionAccepted, then hands off to a durable reservation for
   last-close completion. It never holds the lock while waiting for last close. The global manifest metadata semaphore is separate: do not wait for the destination queue while
   holding it.
3. Inside the per-destination journal commit lock, reread the generation head and persist an exact commit intent containing operation
   ID, generation, expected destination identity, and temporary identity. Briefly take the global metadata semaphore only to persist
   each journal update. Then validate the one-use permit, perform atomic rename or ordinary disposition, and persist Published or
   DispositionAccepted respectively. Release the per-destination lock; the delete reservation's later exact completion persists
   PhysicalDeleteComplete under its own short continuation turn.
4. On collision with a physical commit already inside this short turn, queue behind that turn and release all global locks while
   waiting. When admitted, reread the durable generation head before touching the public name. Cancellation before commit removes the
   queued request; after the durable intent/physical operation starts, cancellation cannot report the mutation as undone.
5. On restart, reconcile any durable intent by exact object identity and operation ID. Complete an operation only if the exact expected
   rename/delete is proven. If the target is absent or changed in a way the receipt cannot disambiguate, keep the destination blocked
   for recovery; never guess from the path or let an older generation publish.

The physical turn ends immediately after disposition acceptance, with its durable reservation handed to an asynchronous completion
record. Subsequent publications queue behind that reservation rather than a held thread/semaphore. Authorized disposition clears
and cleanup notifications can enter the reservation's continuation; they must not queue behind the very delete they are resolving.
An immutable delete watermark is recorded only at PhysicalDeleteComplete; DispositionAccepted enforces a provisional barrier until
completion or a verified clear. Waiting creates still obtain higher maxAllocated generations without advancing a physical publication.

The durable key and in-memory queue key use the same checked identity: volume serial plus volume-root FILE_ID_128, parent-directory
FILE_ID_128, parent case-sensitivity mode and canonical leaf. Volume GUID/drive/device strings are locators, not separate destinations;
aliases reaching that same checked parent share a head and queue. Fold the leaf only for a case-insensitive parent, using ordinal
Windows name comparison; keep case-distinct names separate in a case-sensitive directory. Resolve existing names/short-name aliases
to their actual normalized leaf through the opened object, and recheck parent/name binding on commit. A new name uses the checked
parent and canonical requested leaf. Reject ambiguous normalization or reparse/parent changes rather than splitting a generation head.
Retain the public locator alongside the identity for recovery, but never infer the head from a path comparison alone.

Allocation admission must use this same destination queue: replace CreateAsync's current Publishing/Reserved rejection with a wait
outside the global metadata semaphore and outside StageNamespaceResource. On wake, reread the head and allocate normal max+1;
never attach a stale allocation reply. The queue covers creates, private sealed-version cancellation, public-delete admission and
physical publication, so a create cannot fail before reaching the queue merely because the previous probe is Publishing. A queued
operation owns explicit references and cancellation state; the receive loop must remain able to deliver its completion. An already
admitted physical publisher finishes its turn before a waiting allocation advances the head. Failed/cancelled queued creates do not
invent a committed generation or leave a live owner view.

A sealed-but-unpublished probe is private-view cancellation, not deletion of a nonexistent public object. Authorize it against the
owner's exact private view/transfer; under the same destination gate create a newer cancellation generation and durably bar the old
sealed version before returning success. It performs no public filesystem deletion and needs no fictitious public file ID or public
DELETE authorization. If the old version published before cancellation acquires the turn, switch to the real public-delete path and
its actual Windows authorization; never claim a private discard removed a public file.

Use a cancel-safe queue only for IRP-based callbacks that support it (for example, FltCbdqInsertIo); do not assume every callback form
is cancellable. The product-facing delete must return the actual committed, superseded, denied, or failed result. Do not hold
StageNamespaceResource, the global manifest metadata semaphore, or a spin lock while waiting for the destination turn. The
per-destination journal commit lock itself remains held across the short physical mutation and its corresponding durable result;
the asynchronous last-close reservation is not a held lock.

## 5. Save As and Office behavior

- New-name Save As: the dialog's CREATE_NEW test creates a private empty transfer. If DeleteFileW arrives while that transfer is
  Allocated/Unsealed, it uses private discard. If the probe has sealed but has not become public, an owner-authorized private
  cancellation generation bars that exact sealed transfer; it performs no public delete and does not invent a public file identity.
  If the probe has already published, DeleteFileW uses the public-delete path and
  the service removes that exact public object. In every order the application save receives a later ordinary generation; clean bytes
  publish, while CPF bytes remain private and the new public name is absent.
- Save As over an existing name: the test CREATE_NEW must fail with ERROR_FILE_EXISTS and must not call DeleteFileW after that failed
  probe. The original public bytes remain until a clean replacement publishes. A CPF-blocked save leaves the existing public bytes
  unchanged and the private hand-back follows the existing CPF rule. The real Notepad row must capture its actual UI/native sequence
  and prove this behavior; the native harness must not infer it from its new-name test.
- Explicit DeleteFileW followed by a CPF-blocked save is a public delete followed by a rejected newer save. The old name remains
  absent because a blocked/allocated/inspecting successor does not suppress a committed delete. This is distinct from Save As over an
  existing file when the CREATE_NEW probe failed.
- Explorer's New Text Document path may create and rename an empty public file before another process sees it. If a later dialog
  deletes that already-published probe, use public delete. If it sees a still-private sealed probe, use the private cancellation
  generation above. The test must prove which state occurred rather than assuming the probe remained private.
- Office temporary-to-final replacement remains staged rename plus ordinary clean publication. A private-only backup/owner file uses
  private discard. If the backup name exists publicly, its delete is a public-delete generation and follows section 4.
- A physical rename or hard link remains refused. A staged rename must carry the exact destination generation and continue to use
  T6's copy-and-inspect path for cross-volume or out-of-scope movement.

The working-tree actor currently uses CREATE_NEW for the native probe, but its probe-delete path must stop before DeleteFileW if
CREATE_NEW failed. The real existing-name dialog row is required before claiming the UI path has no public deletion. If that row shows
that Notepad actually issues an authorized public delete before saving over an existing name, the prior-bytes CPF rule and that dialog
sequence conflict; record the trace and return that exact product choice to the owner before implementing that path.

## 6. Durable compatibility

All persisted journal and protocol enum numbers remain stable. The existing EmptyHeld numeric value remains reserved as
LegacyEmptyHeld and is accepted only by startup migration. Existing discard-kind values assigned to EmptyHeld cleanup, owner-exit
empty cleanup, and driver-unload empty cleanup remain reserved and are never repurposed. The generic unattached-allocation cleanup
kind remains available. CREATE_AFTER_PRIVATE_DISCARD and its operation number, reply fields, reservation kinds, and state names are
retired from new traffic and reserved in the ABI; a new protocol operation for public deletion gets a new number and is negotiated
explicitly. Do not change request sizes or reinterpret a legacy payload.

Persist a per-destination head keyed by volume identity plus normalized parent/name. Its generation high-water never decreases;
its latest published generation and committed delete barrier survive removal of individual transfer manifests. Commit the head/result
so recovery can distinguish incomplete updates; reconcile an incomplete intent before admitting another physical operation. Compaction
must retain this durable head/tombstone (or a proven equivalent) even when no transfer manifests remain. Normal max+1 allocation reads
both it and retained manifests. An old manifest can never become current again after restart, compaction or deletion of the last file.

Journal compaction must retain every legacy EmptyHeld migration, discarded generation barrier, pending public-delete/commit intent,
and exact cleanup receipt until reconciliation proves it is no longer needed. A missing path alone is not enough to compact an
identity-qualified cleanup obligation.

## 7. Unload and shutdown rescope

The existing local teardown protections remain independent requirements: close stage/callback admission before taking
the final state snapshot; pin objects used after releasing StageNamespaceResource; drain in-flight callback bodies, worker batches, and
channel rundown before unregister/free; do not release stream, backing-file, or instance references while local callbacks or paging
I/O can still use them; and preserve every unresolved exact stage identity, generation barrier, journal intent, and cleanup receipt.
An unload veto must leave the worker, listener, and retry path usable. A retry delay is not evidence that a callback, file object, or
service operation has drained.

Voluntary-unload policy under the owner's 2026-10-11 rescope: return STATUS_FLT_DO_NOT_DETACH while any private stage is still outstanding (including an
allocated/unsealed stage), any STAGE_DISCARD or other stage RPC is pending/in flight, any exact cleanup ACK is outstanding, any
allocation/attachment receipt is unresolved, any public-delete proxy/capability/reservation remains, or local callback/worker/owner
references remain. Keep the service channel and worker live
so normal app close, delete, service reconnect, exact cleanup, and a later unload retry can finish. User-visible effect: an operator's
`fltmc unload` can fail while an application has an open staged file or the service is unavailable; the staged file remains private and
the operator can retry after the app closes and cleanup is acknowledged. This is fail-closed and avoids abandoning an in-memory-only
retirement obligation.

Mandatory-unload/shutdown policy under that rescope: close admission, prevent new worker RPCs, cancel or deny queued attaches, and close ports
to wake pending sends. Drain actual local callbacks, attach/channel references, paging rundown, staged FILE_OBJECTs and sections; join
workers before freeing their objects or unregistering. Do not call the current service-dependent PrepareUnload(TRUE)/epoch-drain loop.
Close driver-owned public backend handles during this local teardown; already accepted dispositions may then complete at normal
NTFS last close and are reconciled from their durable acceptance record on service restart. Never wait for a backend FILE_OBJECT
whose last handle is the driver's own hold without first closing that hold. Preserve the distinction between public backend handles,
application proxy FILE_OBJECTs, and private stage backings throughout rundown.
This is service-independent teardown, not a promise of bounded completion: external open or mapped handles still require a safe lifetime
resolution. A timeout never authorizes freeing their state. Never wait for the
service, an RPC reply, or an exact cleanup ACK. Do not issue a fresh blocking cleanup RPC during mandatory teardown. Leave any private
stage file in place and preserve its transfer ID, generation, full volume+FILE_ID_128, and last durable journal state. A request whose
service journal transition committed remains replayable by the service; one whose transition did not commit remains an unsealed,
nonpublishable allocation. Existing service startup recovery calls RetainInterruptedAsync and keeps an Allocated entry Unsealed; it does
not publish it. It retries durable Discarded cleanup and released-stage cleanup. Do not claim that startup recovery currently deletes
every arbitrary Allocated/Unsealed stage: such an entry can remain as retained private disk state until a separate authorized cleanup
or recovery policy resolves it. Do not let an interrupted zero-byte stage become an implicit approval. User-visible effect: shutdown
does not wait for service availability; safe local reference drains can still delay teardown. A private temporary may consume disk and remain retained/nonpublishable
after restart if its exact cleanup never reached the journal.

The evaluated design removes the service dependency from the current SafeUploadStagePrepareUnload(TRUE) retry loop. It preserves
the existing nonpublishable retention behavior for interrupted Allocated/Unsealed stages and never reaps unsaved data automatically.
The owner already directed mandatory teardown to avoid service waits; no additional choice between service waits and local rundown
is required. Any proposal to free live local state or automatically discard retained unsaved stages changes that behavior and requires
a separate owner decision. Luna must review the concrete lifetime changes before their first VM boot.

## 8. Required qualification

Preserve all existing assertions except the old no-empty-publication assertion. Required assertions are:

- The raw NTFS observer never sees uninspected non-empty bytes at a protected destination.
- A clean publication has the exact expected destination bytes, including a zero-byte file.
- A CPF new-name save leaves the name absent and leaves no empty stage or public file behind.
- A CPF Save As over an existing public name, with no explicit delete, leaves the previous public bytes intact.
- An explicit public delete followed by a CPF-blocked save leaves the name absent.
- Private discard never publishes; exact cleanup removes only the recorded volume and 128-bit file ID.

Add deterministic native DeleteFileW rows for both delete-before-seal and delete-after-observed-publication. Synchronize on stage/journal
receipts and independent raw-volume observations; do not use a four-second delay as evidence. Add rows for Explorer New Text Document
then in-folder rename then a second-process Notepad open (which must observe the empty file unchanged), empty copy and move, clear the
Notepad document and clean Save As over an existing name (which must publish zero bytes), public delete with allowed and denied rights
(denied fixture removes both file DELETE and parent DELETE_CHILD), delete while a newer save is in flight, and explicit delete followed
by a CPF-blocked save. The in-flight cases must exercise both orders around the short physical commit turn.

Before any code change, require independent Luna review of this design. After implementation, require four exact WDK builds,
PREfast and ApiValidator with zero warnings/errors, the exact agent matrix, both native delete orderings, and real Notepad clean and
CPF runs in all three supported modes under Driver Verifier. Capture final destination bytes independently from the service and
application, preserve raw NTFS observer data and journal/permit receipts, and verify VM restoration to the recorded original state.

## 9. Prior design evidence

The 2026-10-10 v3 product review is at
driver/evidence/2026-10-10/luna-t5-empty-probe-product-design-v3-review.md. It is a static review of an earlier design/source snapshot,
not runtime qualification. Its findings on synchronous discard blocking FilterPort, exact cleanup acknowledgements, pinned references,
and per-name barriers are retained here. The 2026-10-10 implementation review also identified disposition serialization and unload
veto gaps; those are requirements for implementation and are not waived by this redesign.
