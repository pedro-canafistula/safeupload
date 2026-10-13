# T21 — USB/removable staged protection

2026-10-13. Design proposal against `wt/designs` at `6128a892b30c0151a9cc2684b45d2cee56040cb1`.
No implementation, capability activation, infrastructure change or VM run is authorized by this document.
Owner decisions in section 9 and the independent Sol 6.1 xhigh security review precede implementation.
Windows mechanisms marked **U** are unverified on the qualification target; section 10 gives finite controls.
Documentation establishes API contracts, not successful SafeUpload integration or protected-runtime qualification.
**Design status: REVISE before implementation.** The independent review identified an upper-stream routing blocker
at forced instance teardown (section 6.2). The requirements, rejected alternatives and finite controls remain useful;
the current owned-stream construction must not be enabled on USB or booted there as a presumed working extension.

Independent review: `gpt-6.1-sol`, `xhigh`, 2026-10-13, `/root/t21_design_review`; final verdict **REVISE**.
The review confirmed the section 6.2 blocker and the separate C1 PnP proof condition; DELETE-only recovery,
remount temporary-cleanup authority and device-resource ACK corrections are incorporated in section 7.
D1–D7, the surviving routing construction and resource-ACK extension remain unaccepted; this is neither
security acceptance, protected-pair qualification nor permission to release the T4 stop or run a VM.

## 1. Binding scope and completion conditions

The sequence is M2 → M3 → T21 → T22 → T23 → combined M4; T21 is required MVP work.
USB stays disabled until its approved support envelope, destination gates and owner cutover approval exist.
Taint remains enabled; normal builds compile staging out. ReFS is T24, outside this design.
Sources: `driver/POST-MVP-PLAN.md:7`, `:61`, `:66`, `:813`, `:831`, `:871`, `:936`.

The owner requires automatic reconciliation on remount after proving that the old removed-volume handle can no
longer change the file, then validating the returning volume/file state. Windows Restart is not a remedy.
The forced-teardown Restart exception is strictly M2 local fixed NTFS (`driver/POST-MVP-PLAN.md:88`, `:839`).
This note proposes the missing removal proof; it does not generalize instance teardown into that proof.

T21 is done only when the owner-approved combinations survive attach, removal in every save phase and return,
with independent medium-byte observations, matched driver/agent results, Verifier and separate restoration.
An ordinary unchanged return must release decidable recovery holds automatically, even with old app handles open.
Ambiguous identity, lost execution facts or genuine global Unknown remain diagnosed failures, not passing rows.
If ordinary surprise removal routinely reaches those failures, T21 is not done; a reboot instruction cannot close it.

The T4 loaded-context stop remains in force. Its sole authorized attribution diagnostic does not authorize T21 boots.
The M2 completion review is proposed execution guidance, not approval of pending choices or target changes.
Sources: `driver/POST-MVP-PLAN.md:36`, `:184`, `:202`; `driver/M2-COMPLETION-PLAN.md:3`, `:119`.

## 2. Current implementation and reusable contracts

| Current fact at the source commit | Evidence and consequence |
|---|---|
| Policy exposes `removableDrives`, default true; the factory sends volume-kind scope. | `agente/SafeUpload.Agent.Core/Infrastructure/PolicyDocument.cs:197`; `agente/SafeUpload.Agent.Service/Interception/MinifilterPolicyFactory.cs:45`. Policy intent is not staged support. |
| The original classifier checks network type and `FILE_REMOVABLE_MEDIA`. | `driver/SafeUpload.Minifilter/Context.c:247`, `:271`. This alone misses portable devices reporting fixed media. |
| Feature setup queries complete device information and classifies `FILE_PORTABLE_DEVICE` as removable. | `driver/SafeUpload.Minifilter/Context.c:383`. This is a refusal guard, not USB qualification. |
| Positive admission requires fixed disk, NTFS, trusted canary and no instance/global Unknown. | `driver/SafeUpload.Minifilter/Context.c:514`; explicit probe refusal at `driver/SafeUpload.Minifilter/StageStream.c:895`. |
| Writer tracking is limited to fixed NTFS. Teardown detaches trust, releases anchors and retires registry entries. | `driver/SafeUpload.Minifilter/StageWriters.c:1519`, `:1324`. Reusing this path needs a lifetime review. |
| Backing allocation is fixed-volume and installs private ACLs. Its constructor also accepts ReFS. | `agente/SafeUpload.Agent.Service/Interception/StagedTransferAllocator.cs:36`, `:63`. That broader constructor does not qualify ReFS backing for T21. |
| Bound-head admission is deliberately off; the legacy publisher rejects bound allocations. | `agente/SafeUpload.Agent.Service/Interception/MinifilterBoundAllocation.cs:14`; `agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs:83`. |
| Shared destination identity contains volume/root, parent, case, leaf and Mount Manager GUID. | `agente/SafeUpload.Agent.Service/Interception/StagedDestinationCommitJournal.cs:13`, `:46`. A drive letter or file ID alone is not its key. |

The historical architecture explains taint and the original removable classifier (`driver/ARQUITETURA.md:237`,
`:384`); its fail-open descriptions do not override current staged fail-closed behavior.
`driver/MVP-PLAN.md:9` defines the existing standard-user threat model and historical fixed-NTFS platform.
`driver/STAGED-WRITES.md:29`, `:40`, `:63` describe owned upper streams, private backing, retirement and publication;
its historical stream limits and retirement summaries are subordinate to the current T4/T9 decisions.

Reuse T5's checked caller authority, shared head, native-result facts and one-use create/rename permits.
Do not build a USB-specific competing publisher or substitute legacy path-and-digest recovery.
Sources: `driver/T5-BOUND-PUBLICATION.md:14`, `:38`, `:82`, `:229`;
`driver/T5-NATIVE-PUBLIC-OPENS.md:384`, `:456`, `:609`.
Those are integration contracts with open gates, not claims that the current pair already performs them.

## 3. Privacy boundary and proposed support envelope

Treat the entire removable medium as externally observable from the first physical write.
A temporary filename, hidden attribute, denied Windows open or later rename does not make its sectors private.
NTFS ACLs do not protect against reading the detached medium elsewhere under the user's control.
FAT32/exFAT have no persistent file ACLs at all [filesystem comparison][W01].
Therefore **no uninspected content, seed, inspection snapshot, hand-back or diagnostic payload goes onto USB**.
This is a design deduction from the required offline observer, not a claim of a special Windows security feature.

Private bytes and authoritative journals live on the managed machine's fixed NTFS system volume, under the existing
service-private, no-reparse, identity-checked storage contract. All copies are charged to T9 storage accounting.
Backing on a mounted USB folder under `C:` is still removable backing and is refused after object-level resolution.
An unavailable/full/untrusted private store denies new admission; it never falls back to the destination volume.
Existing unsaved versions stay private; byte retention and resource exhaustion are visible separately from DLP blocks.

The proposed first envelope is single-device, basic local NTFS volumes on qualified USB mass-storage stacks,
including devices reporting fixed media, with whole-device removal and a freshly established mount instance.
Both plain NTFS and unlocked BitLocker To Go NTFS need their own successful rows before inclusion.
No multi-disk/dynamic/spanned layout, media-only reader swap, virtual-on-USB nesting, MTP/WPD, network redirector,
cloud-sync root, paging/dump destination or unqualified storage filter/transport is implicitly admitted.
These are proposed capability limits requiring D1 approval, not a declaration that Windows cannot support them.

On unsupported in-scope filesystems/stacks, refuse mutating access before data exposure and explain the capability
failure. Continue Windows-authorized reads under T7. Do not silently treat the device as an ordinary fixed disk,
or let a service/excluded-process shortcut bypass the protected mutation gate. Legacy normal-build behavior stays.
The refusal includes create/overwrite/supersede, existing-handle writes, writable sections, rename/link ingress,
offload/clone/zero/EOF operations and unclassified mutators; qualification must demonstrate each applicable route.
Raw disk writes by trusted administrators remain outside the standard-user model; raw reads are the test oracle.

### 3.1 Filesystem and mechanism matrix

| Property | NTFS removable candidate | exFAT candidate, disabled | FAT32 candidate, disabled |
|---|---|---|---|
| File identity | NTFS ID stays with the live file until deletion; IDs may later be reused. Compare full queried identity. [W02] | Do not assume NTFS-style persistent IDs or open-by-ID support. Exact query/enumeration/remount behavior is **U**, C2. | ID can depend on directory-entry position; rename/defragmentation can change it. Not durable object authority. [W02] |
| Owner/ACL/label contract | Persistent ACLs exist; T5 exact descriptor and original caller checks remain required. [W01] | No persistent ACL/owner contract; cannot emulate it with a hidden stage directory. [W01] | Same limitation as exFAT. [W01] |
| Private stage on medium | Rejected: offline exposure despite ACLs. | Rejected: offline exposure and no ACL boundary. | Rejected: same reasons. |
| Publication | Fixed NTFS snapshot → approved USB temporary → same-volume NTFS rename. | Fixed NTFS snapshot → approved temporary/copy only if separately designed and approved. | Same; size-bound controls must include the approximately 4-GiB filesystem limit. [W01] |
| Rename/replace | Same-volume rename; POSIX replacement has defined old-handle behavior. Target-build semantics remain C3. [W03] | Basic rename does not establish POSIX replace/delete timing or atomic power-loss recovery; **U**, C2/C3. | Same; changing a name can also change its ID. [W02] |
| Supersede | Native DELETE/disposition checks, sharing and descriptor behavior from T5; never truncate public bytes to probe. [W04] | Native outcomes and metadata loss need differential controls; no NTFS authorization reuse. | Same; read-only attributes are not ACLs or caller authority. |
| Transactions | Metadata journaling exists, but is not a two-volume service transaction. No TxF dependency. [W01], [W05] | No metadata journal in the comparison; no assumed atomic transaction. [W01] | Same. [W01] |
| Cache and flush | Cached/lazy writes and metadata caching require explicit flush/fence controls. [W06], [W07] | Same Windows API caution; actual storage/FS behavior **U**, C3. | Same; write-through is not a whole-file atomic copy. |
| Returning medium | Full anchors plus lifetime proof and fresh file-state validation; never ID-only. | No approved durable authority construction; refuse protected saves. | Unstable IDs preclude borrowing T5's recovery unchanged; refuse. |

D1 recommends NTFS first and explicit refusal of FAT32/exFAT. Fixed staging makes their byte privacy plausible,
but does not solve exact-object recovery, caller semantics or whole-file replacement. Supporting them requires a
separate coherent revision and owner-approved user contract; removing filesystem guards is not an increment.
ReFS remains excluded for destination and backing here (`driver/POST-MVP-PLAN.md:936`).

### 3.2 Identity and encryption are independent properties

Volume serials are assigned at format time, not hardware identities [volume information][W08].
Volume GUID paths are Windows mount locators; drive letters change and one volume can have multiple GUID paths [W09].
A USB serial, device instance string, partition GUID, filesystem serial or content digest is not authenticated proof
against a copied image or spoofed device. This design does not claim otherwise; D4 defines the remaining boundary.

BitLocker To Go supports removable NTFS/FAT/exFAT and can be unlocked on another computer [BitLocker FAQ][W10].
It supplies neither a service-private stage namespace nor the original writer's authority after unlock.
Locked media stay unavailable. Unlock must trigger full binding/canary/reconciliation before staged admission.
Relock, encryption conversion, protector changes and filter-stack changes suspend admission until revalidated.
Do not store recovery keys on the medium or in test logs; ciphertext-only observation cannot prove plaintext privacy.
BitLocker qualification needs both encrypted-sector evidence and independent decrypted-volume observation (C7).

## 4. Admission, classification and authority

At first attachment, capture filesystem type and complete `FileFsDeviceInformation`; distinguish
`FILE_DEVICE_DISK_FILE_SYSTEM` from the storage query's `FILE_DEVICE_DISK` [W11], [W12].
`FILE_REMOVABLE_MEDIA` denotes removable media; `FILE_PORTABLE_DEVICE` includes portable-bus devices [W11].
Query bounded `STORAGE_DEVICE_DESCRIPTOR` through `IOCTL_STORAGE_QUERY_PROPERTY` on the actual storage stack:
validate returned sizes/offsets, `RemovableMedia`, `BusType`, device type and available serial fields [W13].
Classify removable scope if any trustworthy evidence says removable/portable/USB; disagreement cannot mean fixed.
Missing/truncated/unknown evidence means Unsupported/NotReady for potentially protected mutations, never passthrough.
Bus type and user-visible DriveType are classification inputs, not identity or qualification certificates.

Attach a deny-capable filter instance before exposing protected writes. Do not return DO_NOT_ATTACH as a blocking
mechanism: it prevents attachment, not the underlying I/O [instance setup][W12].
Setup must not wait for service IPC or thread synchronization; establish local closed admission and queue PASSIVE
discovery. Qualification C1 must prove denial of the first racing writer, including writes before service readiness.
The old registry's fixed-only branch must be extended coherently; merely relaxing `Context.c:514` is insufficient.

Proposed immutable mount binding, stored with every allocation and physical intent:

| Binding part | Required contents and use |
|---|---|
| Current authority | Authenticated driver/connection, policy revision, capability revision and fresh mount-incarnation nonce. |
| Device lifetime | Locally assigned device-incarnation nonce; checked volume-to-storage-device association and PnP registration identity. Never export pointers. |
| Return candidate | Captured Mount Manager GUID, filesystem serial/full root ID, filesystem/features, checked device/partition descriptors. |
| Destination | Exact parent full ID, case mode/canonical leaf, original public ID or proven absence; T5 security/seed provenance. |
| Version/operation | Transfer, stage volume/full ID, generation, original checked grant/share/subject and exact create/delete/rename attempt. |

Drive-letter, mount-folder and device-number changes update display locators only after anchored resolution.
Multiple paths to the same checked object share the destination head; multiple identical sticks do not share authority.
Do not add the fresh mount nonce to the durable head key and thereby reset generations on every reconnect.
Use it as a live-authority qualifier. Any head migration/alias resolution retains high-water marks and rejects conflicts.
The current implementation includes Mount Manager GUID in equality (`StagedDestinationCommitJournal.cs:46`);
new GUID aliases require verified canonicalization, not simply dropping that field from existing persisted keys.

Bind `removableDrives` to actual volume classification for every path, including mount folders and ID-based opens.
`false` removes that policy selector, not independently configured destination scopes or existing recovery obligations.
Policy changes revoke unconsumed permits; scope expansion obeys preexisting-writer admission, never a scan-based Ready.
No new writable authority while activation is incomplete. An old permit is invalid on a new mount or service connection.
Current Windows caller grants, sharing, effective subject, ancestor traversal and assigned metadata remain T5 gates.
Read-denied seeds stay service-private on block/removal; no readable full-file hand-back or justification is invented.
The binding owner decision is option 1 (`driver/POST-MVP-PLAN.md:49`; `driver/T5-NATIVE-PUBLIC-OPENS.md:636`).

## 5. Data path and publication under removal

### 5.1 Stage location alternatives

| Construction | Result |
|---|---|
| Plain private stage on removable NTFS, then same-volume rename | Fails offline privacy before inspection, even with SYSTEM-only ACLs. Rejected. |
| Plain stage on removable FAT/exFAT, then rename | Also lacks a local ACL boundary. Rejected. |
| Encrypted stage on removable media, key only on host | Requires a new encryption/key/recovery design; later plaintext publication still needs approval-first copy. Not proposed. |
| Fixed NTFS private stage, then rename directly across volumes | Not a Windows rename. Renames are same-volume; MoveFileEx COPY_ALLOWED simulates copy/delete. [W03], [W14] |
| Fixed NTFS stage, inspect, copy to approved USB temporary, then rename there | Proposed NTFS route. USB contains only inspected approved content, even before final naming. |

The backing must stay fixed NTFS even when the destination instance disappears. Keeping owned upper cache/sections
on that removable instance is not yet a safe construction: section 6.2 records the callback-routing blocker.
Cross-volume stack/sector/MDL compatibility and a safe replacement routing mechanism need C4 and a reviewed design;
the existing fixed-volume path is not USB retirement qualification.
Do not seed public bytes by SYSTEM pathname reopen. Use T5's original-rights object and proved coherent copy.
If removal interrupts seeding, the private partial copy is not a complete version; refuse the open and retain cleanup.

### 5.2 Ordered publication

1. Finish T4 writer, section, cache and paging rundown; seal the exact fixed-stage object with measured EOF/digest.
   Inspect the complete immutable snapshot. Unsupported content, timeout, partial extraction or missing policy blocks.
2. Before the first byte is copied onto USB, verify current policy, original caller's native save authority, current mount,
   exact destination anchors and eligibility under the shared head. Persist the exact exposure/create intent locally.
   The temporary is an external exposure: first-copy authorization must be at least as strict as final publication.
3. Use the T5 create permit for a unique temporary relative to the checked removable parent. Admit only its exact
   service FILE_OBJECT and approved snapshot bytes, under the original assigned public metadata contract.
   No uninspected tail, reused buffer residue, seed fragment or alternate stream may enter the copy.
4. Copy with bounded aligned buffers, measured offsets and exact EOF. Zero alignment padding before submission;
   do not expose bytes beyond the approved range via allocation/valid-data-length shortcuts. Preserve native errors.
   Require noncached/write-through operation, record actual flush completion and then apply T5's one-way data fence.
5. Drain every admitted temporary write/resize; revalidate full ID/EOF/flush and policy. Under the destination turn,
   reread generation/delete floors, observe the expected public identity and persist the linked rename intent.
6. Consume the exact same-volume rename permit once. Capture native status, persist Published before Released,
   then finish local bookkeeping. No post-rename write permission; no retry of an accepted physical rename.
   Unknown outcome retains PendingCommit and the name hold until exact reconciliation.

Steps 2–4 extend the exposure boundary; they do not waive T5's checks at steps 5–6.
Policy changes fence further copy writes and force reinspection before further exposure; already emitted approved
bytes cannot be recalled. D3 must explicitly accept this nonretroactive behavior, including authorized overrides.
The linearization point for each emitted range is its current-policy admission under the exposure permit;
an in-flight admitted write may complete after the policy changes. No later write inherits that old admission.
Reject any proposed semantics that promise physical rollback of bytes already readable elsewhere.

### 5.3 Torn publication and durability

A removal mid-copy can leave an approved prefix or a damaged approved temporary on the stick, readable elsewhere.
It must never leave a prefix of a not-yet-inspected version. The prior final name is not deliberately truncated.
A removal during rename can leave an uncertain namespace/durability outcome; never report an exact final save from
the copy/rename call alone when required bookkeeping or flush failed. Keep the complete private source available.
The normal clean-save row still requires exact final bytes; a torn temporary is not a successful clean publication.

Windows caching, write-through and flush contracts reduce buffered loss [W06], [W07], [W15]; they do not establish
whole-file atomicity under arbitrary USB power loss or dishonest device firmware. NTFS metadata journaling does
not journal this two-volume transaction [W01]. TxF is not a solution for exposed raw sectors [W05].
Crash/removal media outcomes, parent metadata persistence and old-name survival are **U**, C3/C6.
After an uncertain flush, retain the uncertain outcome even if a subsequent cached read looks correct.

The invariant applies to bytes SafeUpload emits. Preexisting medium contents and modifications performed on another
machine are not retroactively sanitized; record a baseline and distinguish those from this transaction's writes.
Do not claim a securely erased stick, controller-flash forensic erasure or protection on an unmanaged computer.
Every new file-data write observed from the protected pair must derive from an approved complete version or permitted
zero initialization. Metadata/ADS/EAs follow the explicitly approved T8/T9 content/metadata scope, never a bypass.

## 6. Surprise removal: two separate lifetime proofs

### 6.1 External device lifetime is not Filter Manager context lifetime

InstanceTeardownStart stops callbacks for new I/O; existing operations can still complete. TeardownComplete drains
Filter Manager's outstanding work but is not evidence that all application FILE_OBJECTs disappeared [W16].
Its dismount flag has several meanings, including failed mount; it is not a PnP removal receipt.
FSCTL_DISMOUNT_VOLUME is also not hardware removal and can be followed by remount [W17].
Last-handle CLEANUP still permits cache/memory references [W18]. None alone proves that an old handle cannot
affect returning media. A timer, process exit, digest match or forced context deletion supplies no missing proof.

For surprise removal, Windows requires the old device stack to prevent new device I/O and fail outstanding I/O.
After the surprise-removal IRP completes, PnP notifies registered kernel clients with
`GUID_TARGET_DEVICE_REMOVE_COMPLETE` [surprise-removal contract][W19]. Final `IRP_MN_REMOVE_DEVICE` can wait
for open handles indefinitely [W20]; requiring it would defeat the owner's old-handle-open scenario.
Use the exact target-device notification, not user-mode arrival/removal messages or interface disappearance alone.
The similarly named notification is not permission to infer that every old device object has been freed.

**Proposed proof, U/C1:** before admitting any protected open, bind a target-device notification registration to
the exact storage device serving that mount, and retain its local device-incarnation record independently of Flt
instance contexts. Capture `FltGetDiskDeviceObject` only in an early I/O-related callback with admission still
closed; its contract does not permit inspecting the returned device fields from teardown callbacks [W21].
Do not call it from PnP, InstanceSetup or an unrelated discovery worker. Transfer its counted reference explicitly
to bounded discovery work and pair it with `ObDereferenceObject`; pinning an allocation does not preserve hardware.
A separately opened device FILE_OBJECT registers `EventCategoryTargetDeviceChange` [W22], [W23].
Prove the volume/partition/device-stack association before registration and recheck it before opening admission;
names used to obtain the registration object are locators. Wrong/ambiguous stack association fails admission.
The exact association procedure through the supported basic-disk stack must be demonstrated by C1, not guessed
from a disk number. No new storage-filter component is assumed or authorized if this API construction fails.

The callback validates notification type/size and the original registration context, monotonically marks that
incarnation removed, closes its admission/permits and schedules bounded fact recording. No service wait in PnP.
Its context owns its own rundown; it does not dereference the notification's file pointer after that object's release.
The device FILE_OBJECT may be closed after registration when callbacks use only the retained registration context;
Microsoft documents continued notification after close [W23]. It is never the application's native delete object.
Unregister and drain notification callbacks on a separate safe worker using the documented API [W24]; do not
deadlock by waiting for the current callback. Keep required local storage alive until callback rundown completes.

The service may accept a **DeviceLifetimeEnded** fact only when the original authenticated driver supplies all of:

- The pre-admission exact device/mount association and its registration identity, with no coverage gap.
- A genuine target-device removal-complete receipt for that registration and monotonic irreversible old-incarnation fence.
- Completion/drain of SafeUpload-issued old-destination operations, with native results or explicit unresolved facts.
- A new admission candidate independently bound to its current device/mount; no reuse of old permits or FILE_OBJECTs.
- Complete stable replay tying every affected version/delete/publication intent to that old incarnation.

This conjunction is an inference from the documented removal contract plus the implementation's own fencing.
C1 must validate it with stale native writers, delete-on-close, duplicate handles and dirty mappings still alive.
It is not established by this note. A missing receipt retains the hold; no reboot remedy or success claim follows.
Media exchange in a still-present reader lacks this whole-device proof and stays unsupported until separately proved.

### 6.2 Local private lifetime remains live until actually drained

**Architecture blocker:** the current upper FILE_OBJECT belongs to the removable destination instance and carries
SafeUpload's synthetic FCB/section pointers (`driver/SafeUpload.Minifilter/StageStream.c:2434`). Its preoperation
and paging route (`:4548`, `:4663`) is what redirects I/O to fixed backing. After teardown starts, that route no
longer receives new I/O [W16]. Keeping references cannot guarantee rejection, private late paging or safe delivery
of EOF/CLEANUP/CLOSE; it also cannot authorize letting the lower filesystem consume the synthetic context.
The old fixed-NTFS construction therefore cannot simply be extended by adding PnP notification and holding objects.

Required correction before USB owned-stream implementation/boot: a reviewed routing owner must remain reachable
for the entire upper FILE_OBJECT/section lifetime independently of the removable instance. One candidate is to
establish the private upper open on a fixed-volume instance at initial CREATE, before returning any app handle,
while keeping the checked USB destination capability separate. Another is a dedicated supported filesystem owner.
Neither is selected or claimed feasible here. Reparse-based host routing needs a separate concrete contract for
original subject/grants, sharing, one-use unforgeable admission, names/volume/ID queries, directories, handle-relative
operations and sections; changing TargetFileObject or borrowing lower filesystem section pointers is not a solution.
Do not silently drop writable mappings or change app-visible native semantics to evade this requirement.
C4 must first validate the selected construction's callback/lifetime premise under a separately reviewed diagnostic.

Its required behavior is to fence new app I/O after removal, finish only already-owned private paging into fixed
backing, retain safe FCB/cache/section ownership until actual release and refuse to seal mutable/incomplete data.
No old upper object reconnects to a new USB instance; no late bytes can publish under the old device capability.

The driver retains version/operation rundown, removed-device facts and native result records until their exact
acknowledgements. The service retains the fixed stage/snapshot, charged space, manifests, security provenance,
head floors and any uncertain temporary/rename/delete facts. Neither holds the app's native handle open for recovery.
Release the old external-device hold independently of local stage retirement; removal is not a private seal.
An unsealed removed save remains nonpublishable even if its last observed length was zero.

| Phase at removal | Retained state and permissible next action |
|---|---|
| Allocating/seeding/writing | Revoke attachment/publication; keep incomplete fixed backing nonpublishable and charged. |
| Seal pending | Accept a seal only after the real private lifetime drain and exact durable ACK; removal alone supplies neither. |
| Sealed/inspecting/blocked | Keep immutable local version and provenance; any inspection result grants no removed-device authority. |
| Approved/copying/fenced | Stop new medium writes; retain complete source and exact temporary/outcome facts. Approved remnants may exist. |
| Rename in flight/Published | Preserve actual result and uncertainty separately; retry only missing recording, never the physical save. |
| Hand-back/cleanup | Continue only on exact fixed-volume objects after recipient/identity checks; keep unresolved cleanup receipts. |

Preserve namespace → stream ordering, separate paging rundown and non-owning native object lookups.
PnP/teardown callbacks only fence/record/wake; no namespace/native lock spans file I/O, service RPC, destination wait
or callback drain. Reconciliation uses the existing head turn without waiting under the global journal gate.
Mandatory teardown drains local ownership and preserves durable uncertainty without service ACK waits.
Voluntary unload still vetoes live private/native obligations; see `driver/T5-DELETES.md:333` and
`driver/T5-NATIVE-PUBLIC-OPENS.md:309`. Removing a device does not waive T4 retirement or the failed contexts bound.

### 6.3 Writer registry and Unknown

Expected, fully tracked USB removal is a distinct terminal device event, not generic loss of writer accounting.
Old entries cannot transfer Ready to a new mount. Create a fresh admission/canary/registry domain on attachment;
retain old references until their actual local rundown and removal facts allow retirement.
This changes the USB lifecycle integration only; it must not clear existing instance/global sticky Unknown.
Any genuine tracking loss remains sticky under `driver/POST-MVP-PLAN.md:129`; a new mount cannot launder it.
`driver/SafeUpload.Minifilter/StageWriters.c:1370` already widens unexpected context loss to global Unknown.
Prove by fault controls that the expected-removal path reserves its receipt storage before admitting work and
does not require allocation in the removal callback. Resource exhaustion refuses new work before exposing it.
If routine removal necessarily creates global Unknown, revise the mechanism and return to review; do not ship a
Restart-based USB recovery workflow under a different label.

## 7. Automatic remount reconciliation

Keep the new mount closed to protected mutation until device classification, canary and current policy succeed.
Wake from mount/unlock, completed PnP facts or service reconnect, not a periodic scan that clears uncertainty.
Service restart replays the still-loaded driver's exact facts; a new service epoch is not a device lifetime proof.
Persist the removal receipt and replay revision on fixed storage before any head hold is reduced.
An ordinary system restart during absence uses qualified boot recovery for its actual lost process lifetime;
it is not a requested remedy and cannot substitute for a missing same-boot/remount proof in qualification.

### 7.1 Match and validate before changing a head

1. Resolve the returning candidate independently; reject ambiguous device/volume matches, cloned simultaneous
   candidates, missing registration, unsupported filesystem, dirty/unreadable identity or changed storage topology.
   Compare captured GUID/serial/root ID and device/partition descriptors, without treating their equality as anti-clone proof.
2. Validate the old DeviceLifetimeEnded receipt and finish old-destination I/O accounting. While that is pending,
   return NotReady for physical commits; allow unrelated already-qualified destinations to continue.
3. Under the head reconciliation turn, reopen the root/parent through the current checked mount, verify full IDs,
   no-reparse type, case mode and security; perform complete stable anchored enumeration of canonical leaf and exact
   temporary identities. Recheck topology before and after I/O. An inaccessible child does not prove absence.
   Reuse the corrected observer contract (`driver/T5-NATIVE-PUBLIC-OPENS.md:233`) with a reviewed USB selector.
4. For content-dependent recovery, obtain complete current bytes/EOF and required metadata through a proved stable
   observation interval, and compare only with a baseline actually captured for that operation (table below).
   Same ID/time/size is insufficient; same digest is content evidence only. A DELETE-only original-present hold
   downgrade is read-only identity reconciliation, not a content approval or a claim that no offline edit occurred.
5. Resolve only the applicable row below, persist its exact evidence and unchanged generation floors, and wake waiters.
   A fresh save uses current Windows authority and fresh inspection; no old device grant transfers across remount.

### 7.2 Evidence available to each operation

| Operation | Pre-absence evidence; limit on remount inference |
|---|---|
| Staged save/seed | Exact original grant, anchors/security and any actually proved coherent seed snapshot/provenance. No invented historical digest if a snapshot was not taken. Changed recorded baseline blocks stale-save recovery. |
| Publication temporary | Exact create/rename intent and captured full ID, inspected immutable snapshot/EOF/digest and assigned metadata; native outcomes separately. Compare complete current content before claiming that approved image survives. |
| Native DELETE-only / scheduled delete | Exact target/parent/case, original DELETE grant and actual accepted/forwarded facts; no assumed prior data snapshot or READ_DATA grant. Original-present exceptional hold downgrade neither classifies content nor completes cleanup. |

Full current reads are required to assert a content-dependent result or admit fresh exposure, not to manufacture
READ authority for a DELETE-only caller. Missing comparison evidence prevents that comparison claim; it does not
by itself make an unchanged-return native-delete hold permanent. Fresh saves still need fresh coherent inspection.

### 7.3 Recovery outcomes

| Durable/live evidence and returning state | Automatic action |
|---|---|
| Never-forwarded public attempt, exact original/absent target, verified lifetime and anchors | Record the negative attempt; release that attempt's hold. Retain local unsaved data; a new save needs a new operation. |
| Accepted/unresolved scheduled delete; original object/anchors still present and independently validated | Downgrade only the exceptional hold to nonblocking Admitted; retain floor/history. No content approval, no reused DELETE, no physical cleanup ACK, no automatic pending-save replay. |
| Exact accepted delete plus lifetime ended and anchored original-link absence, with sufficient identity continuity | Complete the existing delete receipt and barrier; no deletion of a replacement. Absence without accepted exact intent stays unresolved. |
| Rename success known and exact published object/content/metadata survives | Complete only missing Published/Released bookkeeping. Never rename again; then resolve dependent delete ordering from that Published receipt. |
| Exact rename never forwarded/failed, old target intact, temporary remains | Record failure; leave the remnant diagnosed. The removed FILE_OBJECT's DELETE grant/permit is dead; matching ID/hash does not authorize remount cleanup. A new deletion needs separately reviewed fresh caller/object authority and the namespace gate. |
| Native rename result unknown, even if target digest matches | Retain PendingCommit unless the separately qualified exact native-outcome recovery proves the operation. No digest-based Published or blind recopy. |
| Target/parent replaced, reformatted volume, missing/changed anchor, conflict with an actually recorded content/security baseline, corrupt filesystem | Retain the affected recovery hold and diagnose conflict. No automatic overwrite/delete/adoption. Lack of a DELETE-only data baseline is not evidence of unchanged contents. |
| BitLocker locked or medium absent | Keep local bytes and durable heads; retry only on a meaningful availability event. Absence consumes no polling worker. |

The original-still-present delete row is the approved T5 exceptional-barrier downgrade, not a physical cleanup ACK
(`driver/T5-NATIVE-PUBLIC-OPENS.md:283`). A still-pending native link restriction is a separate Windows result.
Require a separate reviewed **device-resource ACK** extension: retire the old PnP registration/native nonpaged
record only after DeviceLifetimeEnded, all local callback/operation references drained, and a complete durable
incarnation/intent/floor receipt. Retain that receipt until complete authenticated replay proves map removal.
This ACK is not T5 physical cleanup, cannot mark delete Complete or drop a scheduled floor, and cannot free private
FCBs/sections. Without it, original-present records could accumulate forever after callback coverage ends.
C6/C8 must crash between durable ACK and map removal and prove bounded records over repeated detach/replug cycles.
No ABI number or new terminal meaning for the abandoned scheduled intent is assigned here.

Offline edits complicate continuity: NTFS IDs can be reused [W02], and an exact cloned image can reproduce all
unauthenticated on-disk identifiers. The listed checks detect ordinary replacement, not every malicious clone.
For a detectable conflict, no old grant/cleanup is reused; a user's newly initiated save to a freshly authorized
different destination can proceed. It does not erase or manually unlock the unresolved old transaction.
For an indistinguishable clone, strong physical-medium identity cannot be established by these Windows fields.
D4 must choose an explicit threat/scope boundary or stronger authenticated media; this is an unresolved support
condition, not an invitation to treat a fingerprint as object authority. C5 tests detectable clones and records the limit.

If the medium never returns, local data/charges and compact durable head floors remain. Offer a local recovery copy
only after exact stage sealing and recipient/export authorization. Do not expire unresolved evidence or discard unsaved
bytes automatically. D5 covers retention defaults; new admissions fail predictably when reserved capacity is exhausted.
Diagnostics identify file, device label plus safe identifier, phase, old/new incarnation, operation, retained-byte count,
native status and next action: reconnect/unlock the recorded device, save an authorized local copy, or collect conflict
diagnostics. Never offer a manual journal edit, force-release button or Windows Restart for ordinary USB removal.

## 8. T5/T4 integration rules that cannot change accidentally

Empty saves use ordinary stable seal/inspection/publication; no EmptyHeld resurrection (`driver/POST-MVP-PLAN.md:73`).
Public DELETE, native FILE_DELETE_ON_CLOSE and ordinary TRUE/FALSE disposition preserve original Windows results,
sharing and last-handle behavior. They share the same USB mount qualification and head with publication.
Accepted native mutation cannot be undone by failing its tracking acknowledgement; retain AcceptedUnresolved.
Only durably Published successors suppress a prior delete; Approved/Publishing/blocked/private successors cannot.
Sources: `driver/T5-DELETES.md:166`, `:223`; `driver/T5-NATIVE-PUBLIC-OPENS.md:114`, `:147`.

Head ordering survives replug, service crash, old transfer retirement, rename and compaction. Preserve maxAllocated,
published identity/generation, committed delete floor and every unresolved operation/cleanup reference.
A removable journal is never authoritative: it can be edited elsewhere. Persist the authority on fixed private NTFS.
Old formats without device/mount binding remain held; no migration fills missing identity from the currently present stick.
Negotiate feature-only USB binding/fact capabilities with exact lengths and explicit versioning; preserve existing
ABI numbers and normal builds. No new numeric layout is assigned by this design.

A device-end receipt says nothing about the private stage's cache/section lifetime or caller read/export authority.
Unsealed retention, rejected allocation cleanup, public temporary cleanup and hand-back completion remain separate
obligations. Retry only unfinished recording, never completed public mutation (`driver/POST-MVP-PLAN.md:121`).
M2's forced-instance fixed-NTFS recovery remains unchanged; no USB logic may weaken its existing gates.

## 9. Owner decisions needed before dependent implementation

All entries below are **pending**. Recommendations do not approve a scope change, new failure policy or VM run.

| Decision / option | What users notice | Risk or cost | Recommendation |
|---|---|---|---|
| D1 A: qualify basic USB NTFS first; refuse FAT32/exFAT and reader media-only swaps | NTFS sticks/external disks can save after checks; common FAT/exFAT sticks show a named unsupported reason. | Narrower compatibility; USB stack variants still need separate proof. | **Choose A for first T21 envelope**, explicitly record exclusions. |
| D1 B: require FAT32/exFAT in first delivery using fixed staging plus approved copy | More sticks usable; native metadata and recovery limitations become visible. | No existing exact-object recovery construction; may require a different product contract, not just more tests. | Defer pending C2 and a revised reviewed design. |
| D2 A: removal aborts future publication; retain local recoverable version, automatically reconcile holds on return | Reconnecting fixes decidable holds; interrupted saves need a fresh Save/recovery action. | App may have reported a buffered write successful; tray must clearly distinguish saved locally from exported. | **Choose A**; reconciliation is automatic, replaying the save is not. |
| D2 B: automatically finish an interrupted approved save after replug | Fewer manual saves after reconnect. | Requires renewed caller/export authority and exact outcome proof; must never repeat an accepted rename or overwrite external edits. | Defer until a separately reviewed resumable-save contract. |
| D3 A: approved bytes may appear as a partial temporary; policy revocation is nonretroactive | Safe removal is advised; surprise removal may leave an incomplete approved file and local complete copy. | Privacy holds, but whole-file availability/atomicity is not promised across power loss. | **Choose A**, with exact normal-save and remount controls. |
| D3 B: require no partial visible approved file anywhere on the medium | Users get a stronger offline atomic-export expectation. | Ordinary filesystem copy cannot provide it; requires a container/encryption protocol and compatible readers. | Do not promise this with the proposed architecture. |
| D4 A: ordinary unmanaged media, explicit limit for malicious indistinguishable clones | Normal unchanged return reconciles; detected identity/conflict cases stay held with diagnostics. | Windows identifiers cannot authenticate physical media or prove absence of every offline identity forgery. | **Choose A only with this limit explicitly accepted**; never reuse old grants for new mutations. |
| D4 B: require strong authenticated device/volume identity against clones | Only enrolled capable media work; generic sticks refused. | Requires an additional hardware/cryptographic design and provisioning; BitLocker alone is insufficient. | Choose B if anti-clone identity is required; block T21 activation until designed. |
| D5 A: retain interrupted data until explicit authorized recovery/discard; apply shared T9 budgets | Unsaved work survives absence; a full local budget blocks new saves with a named storage reason. | Long-absent media can consume disk; exact cleanup remains necessary. | **Choose A**, measure accounting, then approve numerical per-user/total reserves. |
| D5 B: time-based deletion of interrupted stages | Space recovers without user action. | Can destroy unsaved work; unresolved generation/operation evidence still cannot expire. | Reject as default; requires explicit retention/data-loss policy. |
| D6 A: include plain and unlocked BitLocker To Go NTFS after separate rows | Encrypted sticks work after unlock; locked ones remain unavailable. | Additional filter/lock/observer qualification. | **Choose A conditionally on C7**, never use encryption to waive privacy. |
| D6 B: plain NTFS only initially | Encrypted media get an unsupported explanation. | Reduced enterprise usability; does not remove the offline-exposure rule. | Acceptable only as explicit first-envelope scope. |
| D7 A: approve isolated USB lab device/controller and disposable media images | Enables reproducible hot-unplug and independent-byte tests. | Changes the target topology; requires approved infrastructure diff and baseline acceptance. | **Choose A when product rows are released**, under section 11. |
| D7 B: leave lab unchanged | Design/component work continues; USB runtime proof remains unavailable. | T21 cannot qualify from fixed VHD results or builder controls. | Keep capability disabled. |

## 10. Finite native controls: settle mechanisms before qualification

Each control has fixed cases and a single hypothesis. Run unprotected differential controls only when separately
authorized; preserve failed attempts. A repeated identical failure stops that candidate; revise the hypothesis first.
Builder 19045.6466 results are mechanism evidence. Repeat required controls on target 19045.2965 before support.

| Control | Fixed experiment and decisive result |
|---|---|
| C1 — removal boundary and attach race | On NTFS USB mass-storage, hold native write, share-0, duplicate/inherited and delete-on-close handles plus dirty mapped views. Register exact target PnP notification; capture volume/device association, teardown, lower I/O completions and monotonic ordering. Whole-device detach/re-add at the same and another port while old handles remain open; attempt write/flush/EOF/disposition through each old handle before/after new mount. Require zero mutations on returned media, failed old device I/O and automatic new qualified admission without app close. Contrast software dismount/remount, canceled eject, interface disable, failed start and reader media-only swap; none may forge the accepted boundary. Race the first writer against discovery/registration. |
| C2 — filesystem capabilities and IDs | NTFS/exFAT/FAT32: query full ID, open-by-ID, extended-ID directory enumeration, feature flags and native security results before/after short→long rename, replace, supersede, delete/recreate, clean remount and offline edit. Record exact status/length/IDs. FAT/exFAT failures retain refusal; a passing ID sample alone does not establish lifetime stability or clone resistance. |
| C3 — publication semantics | Compare native/candidate create/overwrite/supersede, POSIX replacement and open-reader/delete-pending cases. Pull at 0, one aligned block, half, last partial block, flush-pending, fenced, rename-pending and rename-complete. Read offline image before recovery; require no forbidden byte, exact normal result and honest interrupted outcomes. Compare quick-removal/better-performance cache settings without changing the gate. |
| C4 — owned upper stream on lost instance | New/seeded/overwrite, cached/noncached writes, dirty mappings with closed source, image/read mappings, canceled I/O and queued paging rundown. Detach during allocation, seed, seal and hand-back. Keep old views live across replug; prove all late data remains on fixed private NTFS, no use-after-free, no false seal and eventual exact retirement after actual release. |
| C5 — return identity and conflict | Two identical-model sticks, absent/duplicate serial, same drive letter, serial collision, cloned image simultaneously and sequentially, format, parent replacement, leaf replacement, same-ID content/ACL edit, name alias and GUID change. Require no old grant/cleanup on a substituted object, no generation reset, detected ambiguity held; explicitly record the indistinguishable-clone limit requiring D4. |
| C6 — durable facts and native deletes | Fault each intent/result/ACK boundary; kill service during absence/return; duplicate/stale/partial replay. Exercise accepted-but-unbound CREATE, ordinary clear, both delete/save orders and known/unknown rename outcome. Include DELETE-only/share-0 with no prior digest, then same-ID offline content edit: permit only the read-only exceptional-hold downgrade, never false Complete, old cleanup or stale-save replay; a freshly authorized/inspected successor can proceed. Require automatic release of decidable holds; genuine unknowns stay held. |
| C7 — BitLocker and observation | Locked→unlocked NTFS, forced relock, detach while copying, conversion/protector/stack change and unlock elsewhere. Prove current-mount rebinding and no premature admission. Validate encrypted raw capture plus decrypted independent observer against positive-control approved markers and forbidden markers. |
| C8 — capacity and coverage faults | Reserve exhaustion before admission, private/USB disk full, failed notification registration, truncated descriptor, incomplete enumeration, lost fact page and genuine sticky Unknown. Require named refusal/retention, bounded buffers/records and no timeout-based Ready. Replug must not clear genuine global Unknown. |

No control is claimed executed here. C1 failing its exact association or stale-handle premise blocks this construction.
C4 is an architecture gate: the current removable-instance-owned upper route already loses callbacks by contract;
a different reviewed routing construction must precede its diagnostic boot, not follow a failed product trial.
C3 cannot establish arbitrary hardware power-loss atomicity; results define supported storage behavior and D3 wording.
C5 cannot prove cryptographic identity from noncryptographic identifiers; a scope decision is unavoidable.

## 11. Qualification and infrastructure boundary

Use `SAFEUPLOAD_DEBUGGEE=win10-debug3` explicitly; keep `win10-debug2` off. Windows 10 19045.2965 remains the target.
The USB topology does **not** currently have approval merely because this note describes it. Obtain a concrete
owner-approved infrastructure change: isolated USB controller plus QEMU `usb-storage` backed by disposable test
images, with libvirt-managed hotplug/removal and retained before/after XML. QEMU documents emulated storage and
host-device passthrough separately [QEMU USB][Q01]; libvirt describes USB disks/host devices [domain XML][Q02].
Emulated `usb-storage` is the deterministic first tier, not proof that physical passthrough or a controller exists.
If actual host USB passthrough is needed, approve only a dedicated sacrificial device and its binding; never a host
system disk. Qualify physical models/USBSTOR or UASP stacks separately before naming them supported.

Use the existing disposable OS overlay, reset EFI variables on every start, no TPM, test signing, Secure Boot off.
The USB image is separate disposable run media, never the qualified OS base. Use host-controlled removal, not
guest flush/eject, for surprise rows. Observe and preserve the detached image before reconnecting it to any writer.
No host-wide polkit/QEMU-hook/sudoers/libvirt-daemon/systemd or image automation change is part of a routine run.
Infrastructure approval, release of the current T4 product stop and each planned product run remain distinct.

The independent observer must read the actual medium: guest raw-volume/device reads outside the service/app path,
plus host backing-device capture and offline parsing of an immutable detached image. Include temporary names,
allocated clusters, slack, free-space remnants and filesystem metadata in forbidden-marker searches.
Use fresh baseline images and distinct markers for old approved content, newly approved content, blocked content
and attempted stale-handle writes. Never remove forbidden observations as “temporary” or trust service logs as bytes.
Raw Windows device access has documented access/sharing/alignment restrictions [CreateFile][W15]; C7 separately
settles encrypted visibility. Validate the observer with intentional positive markers before interpreting zero counts.

Sampled reads/final images alone cannot prove every instant. Preserve the existing T19 requirement by recording
the complete emulated-device write stream and causal exposure/permit/native-result ledger, independently mapping
file-data ranges to approved snapshots or baseline bytes and checking metadata/slack for forbidden markers.
Keep raw images as a separate observation. Missing write capture is an evidence gap, not PASS.
Do not read an actively changing qcow2 file as if it were a coherent raw disk; use a supported consistent capture
mechanism whose completeness is independently controlled, then offline raw-device analysis. That harness is **U**.
For physical devices, retain raw sampling and the qualified lower-write observation mechanism; no emulator-to-hardware
equivalence claim. See `driver/POST-MVP-PLAN.md:912` for the unchanged continuous-evidence obligation.

| Required row family | Variants and required outcome |
|---|---|
| Q1 Attach/admission | Boot-present and hot-attach; fixed-reporting USB; service down; policy on/off/expansion; letter/mount aliases; unsupported FS. No pre-Ready protected write; explicit unsupported refusal. |
| Q2 Ordinary operations | Empty/clean/CPF new/overwrite, coherent append/seed, native grants/denials, public reads/deletes, rename/copy ingress, required application and both mapping-leak repros. Exact final/blocked prior-byte rules. |
| Q3 Removal during write/seed | Cached/noncached and mapping variants; duplicate handles and late paging. Medium never contains forbidden bytes; private incomplete version retained. |
| Q4 Removal during seal/inspect | Before/after writer drain and seal ACK; timeout/parser failure/service crash. No implicit approval or zero-length shortcut. |
| Q5 Removal during publication | Every C3 cut point; policy change; copy disk full; native success before durable result; uncertain rename. Approved-only physical data, honest outcome, no duplicate mutation. |
| Q6 Reconnect/recovery | Unchanged same/other port, old handles still alive, accepted native-delete tracking failure, restart service during absence/return. Automatic exact hold release and a fresh clean successor, no Windows Restart. |
| Q7 Changed/absent media | C5 conflicts, no return, locked media, malformed replay and stale permit. Local retention/diagnostics; no substitution or generation reset. |
| Q8 Stress/coexistence | Serial detach/replug cycles, concurrent independent destinations, resource failures, Defender/approved filter stacks and BitLocker. Bounded retention, no hang/bugcheck, unchanged privacy gates. |

Run the required families on the final matched pair in ordinary, runtime-Verifier and boot-Verifier modes.
Include Special Pool, Pool Tracking, I/O/Filter verification, deadlock and relevant low-resource rows in the existing
approved Verifier configuration; record flags rather than silently changing them. BLOCK-window rows run serially.
Four normal/feature × Debug/Release WDK builds, PREfast/ApiValidator 0 warnings/errors, complete agent matrix,
PowerShell 5.1 parse/native-signature checks and harness self-checks precede authorized real rows.
Require exact test discovery/execution, no skips, `ForbiddenByteCount=0`, exact expected outcomes and complete receipts.
Native controls, source review, component passes and final protected-pair qualification remain separately reported.

Record source commit, delivered artifact hashes, device descriptors/topology, OS/stack, policy, monotonic cut point,
all raw observations and structured verdicts under `driver/evidence/README.md:3`. Preserve the first failed attempt.
Stop on required failure, repeated identical failure or changed baseline; no weakened threshold/assertion or warning suppression.
After evidence retention, independently verify untouched OS/media bases, approved domain XML restored, EFI reset,
no leaked USB attachment/task and deletion of disposable OS/USB run disks. Restoration is a separate verdict.
The owner's existing restoration contract remains `driver/POST-MVP-PLAN.md:96`; approve any temporary XML deviation
explicitly and compare restoration against the original approved baseline, not against the changed test topology.

## 12. Implementation increments and review exits

| Increment | Deliverable and exit |
|---|---|
| T21.1 Design | Resolve section 6.2's routing owner in a concrete revised design, record D1–D7 choices and obtain Sol 6.1 xhigh security acceptance. USB stays off. No M2 stop release implied. |
| T21.2 Mechanism controls | Implement bounded diagnostic controls/harness with PS5.1 gate; approve topology and runs separately. Settle C1/C2/C3 before selecting support combinations. |
| T21.3 Bound admission/lifetime | Implement only the accepted surviving-upper-route construction, device/mount binding, PnP facts, closed attach gate and registry/rundown integration. Four static builds and component checks. **Independent Sol 6.1 xhigh kernel lifetime/lock-order/retirement review before the first changed-driver boot**, including any diagnostic driver. |
| T21.4 Shared transaction | Extend the existing T5 exposure permits, head/journal and remount reconciliation together; local retention/read-authority UX and charged storage. No legacy fallback or partial activation. Relevant controls then full delivery matrix. |
| T21.5 Destination qualification | Run Q1–Q8/all required modes on the approved envelope, raw/continuous observers and separate restoration; close removal and mapping failures. Final working-pair adversarial Sol review. |
| T21.6 Handoff to M4 | Cite owner scope, matched hashes, complete evidence and remaining exclusions. Mark ready for combined M4 only when T21 Done when is met; cutover/taint removal still require later owner sign-off. |

## 13. Documentation references

Microsoft sources below were consulted for the specific contracts cited, not as proof of target qualification.
Repository references are file:line locations at the source commit above; newer status decisions take precedence.

[W01]: https://learn.microsoft.com/en-us/windows/win32/fileio/filesystem-functionality-comparison
[W02]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information
[W03]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information
[W04]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatefile
[W05]: https://learn.microsoft.com/en-us/windows/win32/fileio/transactional-ntfs-portal
[W06]: https://learn.microsoft.com/en-us/windows/win32/fileio/file-caching
[W07]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers
[W08]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw
[W09]: https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-volume
[W10]: https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/faq#bitlocker-to-go
[W11]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/616b66d5-b335-4e1c-8f87-b4a55e8d3e4a
[W12]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_instance_setup_callback
[W13]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_device_descriptor
[W14]: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw
[W15]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
[W16]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_instance_teardown_callback
[W17]: https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_dismount_volume
[W18]: https://learn.microsoft.com/en-us/previous-versions/windows/drivers/ifs/irp-mj-cleanup
[W19]: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/handling-an-irp-mn-surprise-removal-request
[W20]: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/understanding-when-remove-irps-are-issued
[W21]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetdiskdeviceobject
[W22]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioregisterplugplaynotification
[W23]: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/registering-for-target-device-change-notification
[W24]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iounregisterplugplaynotificationex
[Q01]: https://www.qemu.org/docs/master/system/devices/usb.html
[Q02]: https://libvirt.org/formatdomain.html
