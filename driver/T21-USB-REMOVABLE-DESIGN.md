# T21 — USB/removable staged protection

2026-10-13. Third revision of design `e6f1990b`; implementation baseline remains `wt/designs` at `6128a892b30c0151a9cc2684b45d2cee56040cb1`. No implementation, capability activation, infrastructure change or VM run is authorized by this document. Owner decisions in
section 9 and the independent Sol 6.1 xhigh security review precede implementation. Windows mechanisms marked **U** are unverified on the qualification target; section 10 gives finite controls. Documentation establishes
API contracts, not successful SafeUpload integration or protected-runtime qualification.

**Design status: revised, awaiting independent re-review.** Sections 6.2–6.3 select StageFs and its cross-volume public-delete relay;
section 5.3 couples exposure to shared-head transitions. This revision adds pre-attachment close ownership (§6.3) and ordinary-delete remount resolution (§7.3). These are proposed designs, not implemented or qualified mechanisms. D1–D8 remain pending.

## Review history

- `35f057ce`, independent Sol 6.1 xhigh: **REVISE**, [first retained receipt](evidence/2026-10-13/t21-design-review-sol61.md). Findings: no surviving routing owner and insufficient shared-head/exposure ordering.
- `0953036a`, independent Sol 6.1 xhigh: **REVISE**, [retained re-review receipt](evidence/2026-10-13/t21-design-rereview-sol61.md). Routing partly resolved; exposure ordering resolved at design level. Required: concrete StageFs→USB public-delete relay and corrected provenance/references.
- `e6f1990b`, independent Sol 6.1 xhigh: **REVISE**, [third retained receipt](evidence/2026-10-13/t21-design-review3-sol61.md). Earlier routing, exposure, relay selection and provenance findings addressed at design level; required: close ownership when scheduled attachment fails and original-present recovery for ordinary deletes.
- This third revision answers those findings in sections 6.3/7.3 and C6/C11b/c, and exposes the surviving-file outcome in pending D2. No new independent verdict is claimed. All three receipts are retained unchanged in the sibling `safeupload-staging` repository; links are repository-relative. Review acceptance, owner decisions, pre-boot review and qualification remain separate gates.

## 1. Binding scope and completion conditions

The sequence is M2 → M3 → T21 → T22 → T23 → combined M4; T21 is required MVP work. USB stays disabled until its approved support envelope, destination gates and owner cutover approval exist. Taint remains enabled; normal
builds compile staging out. ReFS is T24, outside this design. Sources: [milestone order](POST-MVP-PLAN.md#milestone-order), [owner decisions](POST-MVP-PLAN.md#owner-decisions), [T21](POST-MVP-PLAN.md#t21-usb-and-removable-media), [required gates](POST-MVP-PLAN.md#gates-that-stay-required), [T24](POST-MVP-PLAN.md#t24-refs).

The owner requires automatic reconciliation on remount after proving that the old removed-volume handle can no longer change the file, then validating the returning volume/file state. Windows Restart is not a remedy. The
forced-teardown Restart exception is strictly M2 local fixed NTFS ([Owner decisions: forced-teardown recovery scope](POST-MVP-PLAN.md#owner-decisions), [T21 requirement](POST-MVP-PLAN.md#t21-usb-and-removable-media)). This note proposes the missing removal proof; it does not generalize instance teardown into that proof.

T21 is done only when the owner-approved combinations survive attach, removal in every save phase and return, with independent medium-byte observations, matched driver/agent results, Verifier and separate restoration. An
ordinary unchanged return must release decidable recovery holds automatically, even with old app handles open. Ambiguous identity, lost execution facts or genuine global Unknown remain diagnosed failures, not passing
rows. If ordinary surprise removal routinely reaches those failures, T21 is not done; a reboot instruction cannot close it.

The T4 loaded-context stop remains in force. Its sole authorized attribution diagnostic does not authorize T21 boots. The M2 completion review is proposed execution guidance, not approval of pending choices or target
changes. Sources: [Owner decisions: M2 completion direction](POST-MVP-PLAN.md#owner-decisions), [M2 status](POST-MVP-PLAN.md#m2--active); `driver/M2-COMPLETION-PLAN.md:3`, `:119`.

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
| Ordinary Accepted deletion remains held when the original is present, even with lifetimeEnded; its generation-floor helper covers scheduled records only. | `agente/SafeUpload.Agent.Service/Interception/StagedPublicRelayJournal.cs:183`, `:200`; `StagedDestinationCommitJournal.cs:886`, `:891`. Section 7.3 selects an explicit USB evidence extension, not reuse of this mounted-volume result. |

The historical architecture explains taint and the original removable classifier (`driver/ARQUITETURA.md:237`, `:384`); its fail-open descriptions do not override current staged fail-closed behavior.
`driver/MVP-PLAN.md:9` defines the existing standard-user threat model and historical fixed-NTFS platform. `driver/STAGED-WRITES.md:29`, `:40`, `:63` describe owned upper streams, private backing, retirement and
publication; its historical stream limits and retirement summaries are subordinate to the current T4/T9 decisions.

Reuse T5's checked caller authority, shared head, native-result facts and one-use create/rename permits. Do not build a USB-specific competing publisher or substitute legacy path-and-digest recovery. Sources:
`driver/T5-BOUND-PUBLICATION.md:14`, `:38`, `:82`, `:229`; `driver/T5-NATIVE-PUBLIC-OPENS.md:384`, `:456`, `:609`. Those are integration contracts with open gates, not claims that the current pair already performs them.

## 3. Privacy boundary and proposed support envelope

Treat the entire removable medium as externally observable from the first physical write. A temporary filename, hidden attribute, denied Windows open or later rename does not make its sectors private. NTFS ACLs do not
protect against reading the detached medium elsewhere under the user's control. FAT32/exFAT have no persistent file ACLs at all [filesystem comparison][W01]. Therefore **no uninspected content, seed, inspection snapshot,
hand-back or diagnostic payload goes onto USB**. This is a design deduction from the required offline observer, not a claim of a special Windows security feature.

Private bytes and authoritative journals live on the managed machine's fixed NTFS system volume, under the existing service-private, no-reparse, identity-checked storage contract. All copies are charged to T9 storage
accounting. Backing on a mounted USB folder under `C:` is still removable backing and is refused after object-level resolution. An unavailable/full/untrusted private store denies new admission; it never falls back to the
destination volume. Existing unsaved versions stay private; byte retention and resource exhaustion are visible separately from DLP blocks.

The proposed first envelope is single-device, basic local NTFS volumes on qualified USB mass-storage stacks, including devices reporting fixed media, with whole-device removal and a freshly established mount instance.
Both plain NTFS and unlocked BitLocker To Go NTFS need their own successful rows before inclusion. No multi-disk/dynamic/spanned layout, media-only reader swap, virtual-on-USB nesting, MTP/WPD, network redirector,
cloud-sync root, paging/dump destination or unqualified storage filter/transport is implicitly admitted. These are proposed capability limits requiring D1 approval, not a declaration that Windows cannot support them.

On unsupported in-scope filesystems/stacks, refuse mutating access before data exposure and explain the capability failure. Continue Windows-authorized reads under T7. Do not silently treat the device as an ordinary
fixed disk, or let a service/excluded-process shortcut bypass the protected mutation gate. Legacy normal-build behavior stays. The refusal includes create/overwrite/supersede, existing-handle writes, writable sections,
rename/link ingress, offload/clone/zero/EOF operations and unclassified mutators; qualification must demonstrate each applicable route. Raw disk writes by trusted administrators remain outside the standard-user model;
raw reads are the test oracle.

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

D1 recommends NTFS first and explicit refusal of FAT32/exFAT. Fixed staging makes their byte privacy plausible, but does not solve exact-object recovery, caller semantics or whole-file replacement. Supporting them
requires a separate coherent revision and owner-approved user contract; removing filesystem guards is not an increment. ReFS remains excluded for destination and backing here ([T24](POST-MVP-PLAN.md#t24-refs)).

### 3.2 Identity and encryption are independent properties

Volume serials are assigned at format time, not hardware identities [volume information][W08]. Volume GUID paths are Windows mount locators; drive letters change and one volume can have multiple GUID paths [W09]. A USB
serial, device instance string, partition GUID, filesystem serial or content digest is not authenticated proof against a copied image or spoofed device. This design does not claim otherwise; D4 defines the remaining
boundary.

BitLocker To Go supports removable NTFS/FAT/exFAT and can be unlocked on another computer [BitLocker FAQ][W10]. It supplies neither a service-private stage namespace nor the original writer's authority after unlock.
Locked media stay unavailable. Unlock must trigger full binding/canary/reconciliation before staged admission. Relock, encryption conversion, protector changes and filter-stack changes suspend admission until
revalidated. Do not store recovery keys on the medium or in test logs; ciphertext-only observation cannot prove plaintext privacy. BitLocker qualification needs both encrypted-sector evidence and independent
decrypted-volume observation (C7).

## 4. Admission, classification and authority

At first attachment, capture filesystem type and complete `FileFsDeviceInformation`; distinguish `FILE_DEVICE_DISK_FILE_SYSTEM` from the storage query's `FILE_DEVICE_DISK` [W11], [W12]. `FILE_REMOVABLE_MEDIA` denotes
removable media; `FILE_PORTABLE_DEVICE` includes portable-bus devices [W11]. Query bounded `STORAGE_DEVICE_DESCRIPTOR` through `IOCTL_STORAGE_QUERY_PROPERTY` on the actual storage stack: validate returned sizes/offsets,
`RemovableMedia`, `BusType`, device type and available serial fields [W13]. Classify removable scope if any trustworthy evidence says removable/portable/USB; disagreement cannot mean fixed. Missing/truncated/unknown
evidence means Unsupported/NotReady for potentially protected mutations, never passthrough. Bus type and user-visible DriveType are classification inputs, not identity or qualification certificates.

Attach a deny-capable filter instance before exposing protected writes. Do not return DO_NOT_ATTACH as a blocking mechanism: it prevents attachment, not the underlying I/O [instance setup][W12]. Setup must not wait for
service IPC or thread synchronization; establish local closed admission and queue PASSIVE discovery. Qualification C1 must prove denial of the first racing writer, including writes before service readiness. The old
registry's fixed-only branch must be extended coherently; merely relaxing `Context.c:514` is insufficient.

Proposed immutable mount binding, stored with every allocation and physical intent:

| Binding part | Required contents and use |
|---|---|
| Current authority | Authenticated driver/connection, policy revision, capability revision and fresh mount-incarnation nonce. |
| Device lifetime | Locally assigned device-incarnation nonce; checked volume-to-storage-device association and PnP registration identity. Never export pointers. |
| Return candidate | Captured Mount Manager GUID, filesystem serial/full root ID, filesystem/features, checked device/partition descriptors. |
| Destination | Exact parent full ID, case mode/canonical leaf, original public ID or proven absence; T5 security/seed provenance. |
| Version/operation | Transfer, stage volume/full ID, generation, original checked grant/share/subject and exact create/delete/rename attempt. |

Drive-letter, mount-folder and device-number changes update display locators only after anchored resolution. Multiple paths to the same checked object share the destination head; multiple identical sticks do not share
authority. Do not add the fresh mount nonce to the durable head key and thereby reset generations on every reconnect. Use it as a live-authority qualifier. Any head migration/alias resolution retains high-water marks and
rejects conflicts. The current implementation includes Mount Manager GUID in equality (`StagedDestinationCommitJournal.cs:46`); new GUID aliases require verified canonicalization, not simply dropping that field from
existing persisted keys.

Bind `removableDrives` to actual volume classification for every path, including mount folders and ID-based opens. `false` removes that policy selector, not independently configured destination scopes or existing
recovery obligations. Policy changes revoke unconsumed permits; scope expansion obeys preexisting-writer admission, never a scan-based Ready. No new writable authority while activation is incomplete. An old permit is
invalid on a new mount or service connection. Current Windows caller grants, sharing, effective subject, ancestor traversal and assigned metadata remain T5 gates. Read-denied seeds stay service-private on block/removal;
no readable full-file hand-back or justification is invented. The binding owner decision is option 1 ([Owner decisions: unreadable seeded bytes](POST-MVP-PLAN.md#owner-decisions); `driver/T5-NATIVE-PUBLIC-OPENS.md:636`).

## 5. Data path and publication under removal

### 5.1 Stage location alternatives

| Construction | Result |
|---|---|
| Plain private stage on removable NTFS, then same-volume rename | Fails offline privacy before inspection, even with SYSTEM-only ACLs. Rejected. |
| Plain stage on removable FAT/exFAT, then rename | Also lacks a local ACL boundary. Rejected. |
| Encrypted stage on removable media, key only on host | Requires a new encryption/key/recovery design; later plaintext publication still needs approval-first copy. Not proposed. |
| Fixed NTFS private stage, then rename directly across volumes | Not a Windows rename. Renames are same-volume; MoveFileEx COPY_ALLOWED simulates copy/delete. [W03], [W14] |
| Fixed NTFS stage, inspect, copy to approved USB temporary, then rename there | Proposed NTFS route. USB contains only inspected approved content, even before final naming. |

The backing stays fixed NTFS; section 6.2's StageFs owns upper cache/sections independently of the USB stack. C4 proves cross-volume stack/sector/MDL compatibility and retirement; the existing fixed-volume path is not
that proof. Do not seed public bytes by SYSTEM pathname reopen. Use T5's original-rights object and proved coherent copy. If removal interrupts seeding, the private partial copy is not a complete version; refuse the open
and retain cleanup.

### 5.2 Ordered publication

1. Finish T4 writer, section, cache and paging rundown; seal the exact fixed-stage object with measured EOF/digest. Inspect the complete immutable snapshot. Unsupported content, timeout, partial extraction or missing
   policy blocks.
2. Before the first byte is copied onto USB, verify current policy, original caller's native save authority, current mount, exact destination anchors and eligibility under the shared head. Persist the exact
   exposure/create intent locally; install section 5.3's revision-bound exposure record through the same destination turn. The temporary is an external exposure: first-copy authorization must be at least as strict as
   final publication.
3. Use the T5 create permit for a unique temporary relative to the checked removable parent. Admit only its exact service FILE_OBJECT and approved snapshot bytes, under the original assigned public metadata contract.
   Require T5's complete assigned descriptor, original CREATE descriptor equality and post-CREATE object equality before enabling data; missing owner/group/DACL/SACL/label/inheritance proof returns NotReady, never a
   SYSTEM default. No uninspected tail, reused buffer residue, seed fragment or alternate stream may enter the copy.
4. Copy through section 5.3's per-range admission with bounded aligned buffers, approved logical ranges and its explicit zero-only alignment envelope. Set exact logical EOF afterward; no allocation/valid-data-length
   shortcuts. Preserve native errors. Require noncached/write-through operation, then apply T5's one-way data fence before drain and final flush.
5. Drain every admitted temporary write/resize; revalidate full ID/EOF/flush and policy. Under the destination turn, reread generation/delete floors, observe the expected public identity and persist the linked rename
   intent.
6. Consume the exact same-volume rename permit once. Capture native status, persist Published before Released, then finish local bookkeeping. No post-rename write permission; no retry of an accepted physical rename.
   Unknown outcome retains PendingCommit and the name hold until exact reconciliation.

### 5.3 Per-range exposure and shared-head transitions

Add one bounded nonpaged **ExposureHead** per active canonical destination, owned by the common kernel transaction core, not the removable instance. This is the runtime admission mirror of the existing durable head, not
another journal. It contains driver/connection/mount identity, head revision, maxAllocated, Published/delete/cancellation/scheduled floors, typed native reservations/AcceptedUnresolved bits, transition nonce and at most
one active copy attempt. An attempt binds the original live version/grant, inspected immutable snapshot/EOF, policy/override revision, temporary FILE_OBJECT/full ID, next logical offset, submitted/zero-padding bounds,
range sequence, DataFenced and in-flight count.

Attempt installation is **Prepared/NoWrite → TempBound → CopyEnabled**: persist its exposure/create intent first, install Prepared while fencing any older attempt, then
capture the exact accepted post-CREATE object/full ID and descriptor equality into TempBound. Under ExposureGate, compare the unchanged head/policy and durably recorded create facts before enabling copying. Preparation's
own matched facts do not self-fence; a competing transition does. Missing/unknown create outcome never permits a byte. This attempt can consume its create/rename grants only once.

One short nonpaged **ExposureGate** serializes these fields, policy-epoch changes and T5 temporary data fencing. No I/O, hashing, allocation, RPC, namespace/stream lock or journal wait occurs while it is held;
records/buffers are reserved first. Callbacks take only this gate; service head turns may request transitions without holding kernel locks. Final rename still uses T5's name reservation and target check
(`driver/T5-BOUND-PUBLICATION.md:92`).

At the actual original noncached WRITE/EOF callback, under ExposureGate, require the exact temporary and creator, live mount/connection, current inspected policy, no transition/fence/uncertainty or blocking reservation,
generation == maxAllocated, generation above delete/cancellation/scheduled floors and no already-Published result for this attempt. Require the expected head revision, contiguous next approved logical range and valid
snapshot bounds.

Noncached offsets/lengths obey the queried target-sector alignment [W40]: full chunks are aligned, the last submission rounds up with an explicit zero-only suffix beyond approved EOF. Record logical and
submitted extents separately; the owned submitted buffer is immutable through completion, and padding is verified zero before admission. Limit the entire aligned submission to 64 KiB and one in-flight range per attempt;
sector alignment above that bound is an unsupported stack, not an unsupported ordinary file length. Atomically consume its sequence and acquire operation rundown before releasing the gate and forwarding once. A queued
buffer or service token is not admission. Postoperation records actual status/bytes and releases rundown under the same gate; partial/error results fence the attempt. No automatic range retry, including after a lost
completion. Final EOF shrink from padded length to the inspected logical EOF uses the same eligibility predicate, then the irreversible data fence/drain/flush sequence. If removal or a head change prevents that shrink,
retain an incomplete approved temporary containing only approved data plus authorized zeros; never report a clean save or rename it. Zero-extension has the same explicit range limits.

Every allocation, private cancellation, ordinary/scheduled delete, publication and hold-resolution path uses: **BeginHeadChange(expected revision, operation nonce) → durable head/native facts → CommitHeadChange(new
revision)**. Begin runs under ExposureGate before a newer generation becomes durable or a native mutation is forwarded; it sets TransitionPending and irreversibly DataFenced on the old attempt. Commit installs the exact
validated head; it cannot reopen that attempt. Failure/disconnect leaves the head closed until complete replay proves its state. Commit compares transition nonce, base head revision, connection and native-facts revision
under ExposureGate; it cannot clear an unaccounted concurrent event. Every admission/fence/result updates the replay revision. Even a proven aborted transition requires a fresh exposure attempt; no reused range sequence
or create/rename grant. The service keeps the existing per-destination turn across this protocol, never across the whole copy. The kernel reserves a pending native hold before forwarding DELETE/DELETE_ON_CLOSE or any
other relevant native mutation; accepted result plus missing service/journal ACK becomes AcceptedUnresolved with the fence already set. Thus a service bookkeeping failure cannot leave a stale exposure window. No
reservation slot means no forwarding. Ordinary clears/negative results also require the same revisioned transition; only qualified resolution can clear holds.

Blocking reservations are pre-forward/binding uncertainty,
AcceptedUnresolved and ordinary accepted-delete barriers. A fully bound normal **NativeOnClose Admitted** intent is a nonblocking scheduled floor: a newer inspected version may expose/publish while the old scheduled
handle remains open (`driver/T5-NATIVE-PUBLIC-OPENS.md:122`). Its later native cleanup may impose an actual NTFS restriction, which is separately respected; do not invent a SafeUpload whole-handle reservation.
Allocation/Blocked never removes that scheduled intent. Section 7.3 additionally makes an ordinary Accepted record nonblocking only through an exact dead-incarnation remount receipt; its ordinary kind, native acceptance and generation floor survive.

| Concurrent event | Atomic effect on the older copy |
|---|---|
| Newer allocation, even if later blocked/cancelled | Fence before persisting maxAllocated; the old copy never resumes. Allocation/Blocked does not cancel a prior delete. |
| Ordinary or scheduled public delete | Fence at native reservation before forwarding; ordinary accepted delete blocks, exact scheduled Admitted retains only its floor and permits a newer fresh copy. Only Published suppresses a prior delete. |
| Private cancellation | Fence before its newer cancellation generation is durable or success is returned; no public-delete fiction. |
| AcceptedUnresolved, lost facts, removal, disconnect or policy change | Close admission at the kernel event, before service notification; no stale revision can reopen it. |

An already admitted range is ordered **before** the competing transition and may finish afterward, including a device-cache write. Record that bounded range as earlier authorized exposure; cancellation cannot retract its
bytes. Every subsequent range is refused. D3 explicitly covers this nonretroactivity for head changes as well as policy. An EOF/final-copy success cannot override a fence. Drain all admitted operations before final
flush/rename or temporary cleanup, and recheck current head/policy plus T5's irreversible DataFenced state at rename admission. On reconnect, complete authenticated replay reconstructs closed heads before any fresh
attempt; no journal-only head writer may bypass BeginHeadChange. C9 forces both orders at admission, lower completion and durable ACK. This extends preparation outside T5's short physical turn
(`driver/T5-BOUND-PUBLICATION.md:32`), while preserving the shared allocation/delete/cancellation order (`driver/T5-DELETES.md:240`, `:264`).

### 5.4 Torn publication and durability

A removal mid-copy can leave an approved prefix or a damaged approved temporary on the stick, readable elsewhere. It must never leave a prefix of a not-yet-inspected version. The prior final name is not deliberately
truncated. A removal during rename can leave an uncertain namespace/durability outcome; never report an exact final save from the copy/rename call alone when required bookkeeping or flush failed. Keep the complete
private source available. The normal clean-save row still requires exact final bytes; a torn temporary is not a successful clean publication.

Windows caching, write-through and flush contracts reduce buffered loss [W06], [W07], [W15]; they do not establish whole-file atomicity under arbitrary USB power loss or dishonest device firmware. NTFS metadata
journaling does not journal this two-volume transaction [W01]. TxF is not a solution for exposed raw sectors [W05]. Crash/removal media outcomes, parent metadata persistence and old-name survival are **U**, C3/C6. After
an uncertain flush, retain the uncertain outcome even if a subsequent cached read looks correct.

The invariant applies to bytes SafeUpload emits. Preexisting medium contents and modifications performed on another machine are not retroactively sanitized; record a baseline and distinguish those from this transaction's
writes. Do not claim a securely erased stick, controller-flash forensic erasure or protection on an unmanaged computer. Every new file-data write observed from the protected pair must derive from an approved complete
version or permitted zero initialization. Metadata/ADS/EAs follow the explicitly approved T8/T9 content/metadata scope, never a bypass.

## 6. Surprise removal: two separate lifetime proofs

### 6.1 External device lifetime is not Filter Manager context lifetime

InstanceTeardownStart stops callbacks for new I/O; existing operations can still complete. TeardownComplete drains Filter Manager's outstanding work but is not evidence that all application FILE_OBJECTs disappeared
[W16]. Its dismount flag has several meanings, including failed mount; it is not a PnP removal receipt. FSCTL_DISMOUNT_VOLUME is also not hardware removal and can be followed by remount [W17]. Last-handle CLEANUP still
permits cache/memory references [W18]. None alone proves that an old handle cannot affect returning media. A timer, process exit, digest match or forced context deletion supplies no missing proof.

For surprise removal, Windows requires the old device stack to prevent new device I/O and fail outstanding I/O. After the surprise-removal IRP completes, PnP notifies registered kernel clients with
`GUID_TARGET_DEVICE_REMOVE_COMPLETE` [surprise-removal contract][W19]. Final `IRP_MN_REMOVE_DEVICE` can wait for open handles indefinitely [W20]; requiring it would defeat the owner's old-handle-open scenario. Use the
exact target-device notification, not user-mode arrival/removal messages or interface disappearance alone. The similarly named notification is not permission to infer that every old device object has been freed.

**Proposed proof, U/C1:** before admitting any protected open, bind a target-device notification registration to the exact storage device serving that mount, and retain its local device-incarnation record independently
of Flt instance contexts. Capture `FltGetDiskDeviceObject` only in an early I/O-related callback with admission still closed; its contract does not permit inspecting the returned device fields from teardown callbacks
[W21]. Do not call it from PnP, InstanceSetup or an unrelated discovery worker. Transfer its counted reference explicitly to bounded discovery work and pair it with `ObDereferenceObject`; pinning an allocation does not
preserve hardware. A separately opened device FILE_OBJECT registers `EventCategoryTargetDeviceChange` [W22], [W23]. Prove the volume/partition/device-stack association before registration and recheck it before opening
admission; names used to obtain the registration object are locators. Wrong/ambiguous stack association fails admission. The exact association procedure through the supported basic-disk stack must be demonstrated by C1,
not guessed from a disk number. No new storage-filter component is assumed or authorized if this API construction fails.

The callback validates notification type/size and the original registration context, monotonically marks that incarnation removed, closes its admission/permits and schedules bounded fact recording. No service wait in
PnP. Its context owns its own rundown; it does not dereference the notification's file pointer after that object's release. The device FILE_OBJECT may be closed after registration when callbacks use only the retained
registration context; Microsoft documents continued notification after close [W23]. It is never the application's native delete object. Unregister and drain notification callbacks on a separate safe worker using the
documented API [W24]; do not deadlock by waiting for the current callback. Keep required local storage alive until callback rundown completes.

The service may accept a **DeviceLifetimeEnded** fact only when the original authenticated driver supplies all of:

- The pre-admission exact device/mount association and its registration identity, with no coverage gap.
- A genuine target-device removal-complete receipt for that registration and monotonic irreversible old-incarnation fence.
- Completion/drain of SafeUpload-issued old-destination operations, with native results or explicit unresolved facts.
- A new admission candidate independently bound to its current device/mount; no reuse of old permits or FILE_OBJECTs.
- Complete stable replay tying every affected version/delete/publication intent to that old incarnation.

This conjunction is an inference from the documented removal contract plus the implementation's own fencing. C1 must validate it with stale native writers, delete-on-close, duplicate handles and dirty mappings still
alive. It is not established by this note. A missing receipt retains the hold; no reboot remedy or success claim follows. Media exchange in a still-present reader lacks this whole-device proof and stays unsupported until
separately proved.

### 6.2 Selected surviving owner: SafeUpload.StageFs

Select a dedicated, local **StageFs filesystem driver**, loaded before USB admission. Register its named control device normally [W42]; create a private non-PnP software disk per USB mount incarnation and mount an
**unnamed StageFs volume device** with its own VPB [W43]. File I/O targets that volume, never the control device. The software disk lives until StageFs drains, independently of USB PnP. Give it a named native target and
immutable unique ID distinct from USB; implement bounded MOUNTDEV_QUERY_DEVICE_NAME/QUERY_UNIQUE_ID replies [W45]. Notify Mount Manager using **IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION** for this non-interface client
[W47], not IoRegisterDeviceInterface on a non-PnP object. Record its exact target/unique-ID/GUID triple. Before admission, remove any assigned drive-letter link using exact private-volume matching with
IOCTL_MOUNTMGR_DELETE_POINTS [W48] and requery that the private GUID remains and no drive letter does; a mismatch keeps admission closed. No global automount setting changes. Reject raw disk/control access. No payload
lives in a raw image: StageFs maps FCBs to exact fixed-NTFS backing. StageFs also owns the shared nonpaged binding/exposure core and late-I/O code. The minifilter uses a rundown-bound kernel interface for
admission/events; removing a USB instance drops only its interface reference. Paging/close never call back through an unloaded filter image or a stored instance. Module unload waits for these actual owners. StageFs
evaluates removable policy through that logical destination binding, never its private volume's apparent fixed-device class. The removable minifilter only admits/reparses CREATE and protects the real namespace; it never
installs synthetic FCB/section pointers in a USB-owned FILE_OBJECT. That existing construction (`driver/SafeUpload.Minifilter/StageStream.c:2434`, `:4548`, `:4663`) loses dispatch at teardown [W16]. StageFs remains
loaded until its own objects/sections drain; USB removal neither deletes its device nor unregisters its dispatch. This is a selected architecture, not implemented proof.

**CREATE and authority.** Before reparse, capture the original subject/request and run T5's nonmutating native disposition check, close the supplemental-rights probe, retain the separate original-grant/share lease (section 6.3 owns its construction and scheduled-delete exception),
capture complete assigned security and anchors, and seed coherently. Missing T5 prerequisites deny admission (`driver/T5-NATIVE-PUBLIC-OPENS.md:465`, `:482`, `:498`, `:616`). Reserve the durable generation and private
backing. StageFs owns a one-use open record containing this tuple, original process lifetime, request masks/options, logical name/view ID, native Information result, backing identity and cancellation state; no kernel
pointers go to user mode. The minifilter replaces the initial filename with that private volume path plus opaque view/open nonce and returns STATUS_REPARSE, before any app handle exists. Microsoft's SimRep demonstrates
this redirection [W25]; it is not handle transplantation. Attach a kernel ECP naming the record: ECP propagation across reparses is documented [W26]. StageFs retrieves it from the create IRP [W27], rejects user-origin
ECPs [W28], and matches its owned record, original request/subject, mount/generation and nonce under the open-record lock. A kernel-origin bit or nonce alone is not authority. Consume once, install StageFs-owned
FsContext/CCB/section pointers and complete the create with exactly the checked app grant and original disposition result. Set the FSD access state from that checked result, never supplemental/SYSTEM rights. Initial
allocation requires that ECP; direct device/root opens, guessed allocation paths and user IOCTLs cannot mint one. Two ECP-free **reopen** locators are allowed: an exact live StageFs RelatedFileObject or the returned
private volume/view path. Resolve only an existing owner view; then capture the new original subject/request and repeat the same native grant/share/anchor and private-view read-authority checks to mint a distinct record.
A path/view ID is not authority. Unknown, retired, wrong-owner or removed bindings fail; neither route can allocate arbitrary backing. Device namespace access only permits reaching this check; fixed backing keeps its
SYSTEM-private ACL. Cancellation/removal racing consumption has one winner under the record lock: no new data authority after the fence. Section 6.3's pre-attachment record owns the backend until atomic CCB handoff;
failed/unconsumed reparse and canceled-before-handle completion claim its close-once worker without waiting for app CLEANUP. Backend acceptance and outer CREATE outcome are separate facts. ECP cleanup participates in that ownership protocol, never destroys an attached CCB. No self-reference to an app FILE_OBJECT is retained until CLOSE.

**Sharing and operations.** One CCB per app FILE_OBJECT owns the original grant, native lease and cleanup bit; duplicated/inherited handles share that CCB, while an independent reopen gets a fresh original-subject
check/lease. Use one locked IoCheckShareAccess/IoRemoveShareAccess domain per logical stream [W29], [W30], shared with the namespace gate so native/public opens and absent-target creates cannot bypass private sharing.
Present targets retain NTFS's original share lease through upper CLEANUP, with section 6.3's separate failed-attachment/proved-removal close triggers; never close at seal or service ACK. No supplemental DELETE or second public seed-read handle changes sharing. StageFs
enforces each CCB's read/write/append/delete rights; supported security-only/public-native opens retain T5's separate real-NTFS route. Section 6.3 selects public disposition on combined handles; private cancellation/rename uses the same head turns, not direct USB
mutation. Keep T5/T10's exact supported/refused QUERY_SECURITY, SET_SECURITY, Basic/EA/ADS and CREATE-option matrix; an assigned descriptor grants no WRITE_DAC, WRITE_OWNER or SACL access
(`driver/T5-NATIVE-PUBLIC-OPENS.md:482`). Never forward a synthetic upper FILE_OBJECT as the native security/metadata target.

| Request family | StageFs dispatch and removal behavior |
|---|---|
| Cached/noncached READ/WRITE, EOF, flush | Own advanced FCB header, main/paging resources, sizes and section pointers [W31], [W32]. Cached I/O uses its cache; noncached/paging I/O uses bounded child requests with the genuine fixed NTFS backing FILE_OBJECT. Never send an upper FCB to NTFS, reuse a USB device pointer, or use the service to service paging. |
| Sections/image mappings | Register StageFs section/modified-writer/flush synchronization callbacks [W33]; initialize its cache map with owned lazy-writer callbacks [W34]. Preserve writable/read/image mappings; enforce native image-write/truncate checks [W35], [W36]. Decline fast data/MDL paths to their IRP fallback; no uncounted alternate write path. |
| Removal | Atomically mark the binding RemovedPrivate and close exposure/CREATE admission. Fail new ordinary mutations with STATUS_DEVICE_NOT_CONNECTED; admitted private I/O and existing mappings may still dirty fixed backing. Do not claim to revoke CPU stores or reject mandatory MM synchronization. Even a section created later through an existing authorized handle stays private and keeps the version mutable. |
| Queries | Return private StageFs volume identity and stable `\v\<view-id>\<leaf>` names, original app grant/mode, per-open position and private EOF/assigned attributes. Preserve opaque per-view IDs and original-namespace overlay lookup (`driver/SafeUpload.Minifilter/StageStream.c:1921`, `:4056`, `:4100`); qualify identity by the actual queried volume. Never call torn-down OriginalInstance or expose backing names/IDs/ACLs. These are virtual-view identities, never public NTFS authority. |
| Relative opens and IDs | Real USB directory handles stay native: capture their exact related object/raw selector before CREATE reparse. Reopen relative to a StageFs file (including empty-name reopen) resolves its exact view but performs a new subject/grant/share check; a file cannot become a directory. Supported ADS follow T8, others refuse. Private open-by-ID resolves only the exact owner view/mount; public IDs resolve through checked NTFS, never across remount. RelatedFileObject is captured during CREATE only [W32]. |
| Handle-relative rename/delete | Capture rename RootDirectory as a file object with ObReferenceObjectByHandle, using UserMode for a user handle [W41]; validate its directory/full anchors/case and T5 private-rename contract. Disposition carries no replacement pathname: section 6.3 routes the exact bound public object or private discard. Removed bindings cannot authorize a new public mutation; DELETE-only objects retain their native route. |
| CLEANUP | Cancel this CCB's queued user I/O, release its byte-range locks/share lease once, process its exact delete/cancellation intent and uninitialize its private cache map [W18], [W30], [W37]. No service ACK wait and no claim that sections have ended. |
| CLOSE | Release the CCB after actual object-reference rundown [W38]; MM/Cache Manager may deliver paging between CLEANUP and CLOSE. The StageFs dispatch, FCB, backing and callbacks remain valid throughout. |

Native GetFinalPathNameByHandle reports the actual StageFs NT/GUID path; DOS form may return ERROR_PATH_NOT_FOUND without a drive letter [W46]. It does not report the original USB GUID merely because a descriptor
contains it. Returned paths reopen only through the fresh checks above. An authenticated, exact owner-SID/view-scoped SafeUpload query separately returns the captured logical USB destination for service/tray display,
never mutation authority. D8 keeps this visible query difference pending; no DeviceObject spoofing, API hooks or promise of transparent adaptation for arbitrary applications. C4 tests all native final-path flags/reopens
and the required app matrix.

**Actual retirement.** Namespace state progresses Live → RemovedPrivate/SealPending → Drained → SealedRetained → Retired. Stop new opens under namespace → FCB ordering. Keep separate counts for CCBs until actual CLOSE,
cache/section callbacks and child I/O; child completion releases its pinned buffer/backing reference only after the real lower result. Reserve paging resources before exposing dirty-capable storage; no dependency on a
blocked service worker, USB callback, global journal lock or destination turn can prevent paging/cleanup progress. Run cache uninitialization/flush outside the namespace lock with an FCB lifetime pin; wait for its actual
event [W37]. Only after zero handles/CCBs, exclusive section synchronization, no mapped/retained data or image section, successful private flush/purge and zero callback/child-I/O rundown may sealing/retirement proceed
[W35], [W36], [W37], [W39]. A successful purge alone is insufficient; mapped sections are not purged [W39]. A retry schedules the same native checks, never treats elapsed time as evidence. Unsealed/incomplete removed
data cannot become publishable on replug. Retire the exact backing only after the separate durable stage/cleanup ACK; then release FCB/device references. After every StageFs open/section/child reference drains, delete
only that recorded private volume's Mount Manager links/database entries with DELETE_POINTS, verify their absence, then retire VDO/software disk/VPB ownership. Each deletion specifies the exact private
device/unique-ID/link tuple, never a wildcard or the USB volume tuple. Keep a local alias-cleanup receipt across crashes; revalidate its exact private identity before retrying. C4/C8 require no stale private link,
database-entry or nonpaged-volume accumulation over repeated removal and restart cycles. They also verify that failure/retry leaves original USB aliases unchanged and no private DOS letter exists at Ready. Old StageFs
objects never rebind to a returned USB instance. Boot recovery retains unsealed manifests as incomplete. Driver/service unload cannot destroy live StageFs objects; service loss only closes new admission. OS shutdown
records uncertainty without waiting for remount. C4 must prove this concrete route before any product qualification.

The driver retains version/operation rundown, removed-device facts and native result records until their exact acknowledgements. The service retains the fixed stage/snapshot, charged space, manifests, security
provenance, head floors and any uncertain temporary/rename/delete facts. Neither holds the app's native handle open for recovery. Release the old external-device hold independently of local stage retirement; removal is
not a private seal. An unsealed removed save remains nonpublishable even if its last observed length was zero.

| Phase at removal | Retained state and permissible next action |
|---|---|
| Allocating/seeding/writing | Revoke attachment/publication; keep incomplete fixed backing nonpublishable and charged. |
| Seal pending | Accept a seal only after the real private lifetime drain and exact durable ACK; removal alone supplies neither. |
| Sealed/inspecting/blocked | Keep immutable local version and provenance; any inspection result grants no removed-device authority. |
| Approved/copying/fenced | Stop new medium writes; retain complete source and exact temporary/outcome facts. Approved remnants may exist. |
| Rename in flight/Published | Preserve actual result and uncertainty separately; retry only missing recording, never the physical save. |
| Hand-back/cleanup | Continue only on exact fixed-volume objects after recipient/identity checks; keep unresolved cleanup receipts. |

Preserve namespace → stream ordering, separate paging rundown and non-owning native object lookups. PnP/teardown callbacks only fence/record/wake; no namespace/native lock spans file I/O, service RPC, destination wait or
callback drain. Reconciliation uses the existing head turn without waiting under the global journal gate. Mandatory teardown drains local ownership and preserves durable uncertainty without service ACK waits. Voluntary
unload still vetoes live private/native obligations; see `driver/T5-DELETES.md:333` and `driver/T5-NATIVE-PUBLIC-OPENS.md:309`. Removing a device does not waive T4 retirement or the failed contexts bound.

### 6.3 Selected StageFs→USB public-delete relay

**Route and topology.** Attach the same SafeUpload minifilter to StageFs and USB at the **same altitude**, before exposing a staged handle. The StageFs instance intercepts the original IRP_MJ_SET_INFORMATION;
for a public disposition it changes **both** TargetInstance to the live USB instance and TargetFileObject to the CCB's exact NTFS backend, calls FltSetCallbackDataDirty and returns FLT_PREOP_SUCCESS_WITH_CALLBACK. No new SetInformation IRP is synthesized.
Microsoft requires that backend to reside on the target instance's volume and **USB volume DeviceObject.StackSize >= StageFs volume DeviceObject.StackSize** [W49]. Query both via FltGetVolumeFromInstance/FltGetDeviceObject,
record the pair with a topology revision, and recheck before permit consumption; release query references correctly. StageFs uses its real minimal stack, never falsifies StackSize or transplants DeviceObject/FCBs.
Unequal altitude, smaller target stack or absent relay instance closes capability admission before CREATE; a later topology change fences existing public relays and requires requalification. C11 must pass equal/larger target stacks and refusal of smaller ones.
References pin memory, not USB liveness. The original pre/post pair receives its original parameters [W49]; its preallocated completion context therefore owns both endpoints and operation facts. Lower USB filters see the changed target;
do not depend on another pre-callback at SafeUpload's USB instance to consume the permit. StageFs data/cache/sections/CLEANUP/CLOSE stay on its surviving route; loss of the StageFs filter also fences public delegation in the FSD.

**Backend construction and ownership.** StageFs, not the removable instance or service, owns the original-grant backend handle and bounded close worker. Its factory issues IoCreateFileEx FILE_OPEN through the top of the USB stack (DeviceObjectHint=NULL) [W57],
with a one-use kernel ECP in IO_DRIVER_CREATE_CONTEXT tied to its owned CREATE record, checked mount/anchors, worker and original request; the USB callback consumes that record to allow only this non-data backend open, without recursive staging. ECP origin alone is insufficient.
Use T5's captured effective CREATE subject (static client context, restricted state, impersonation level and enabled privileges), SeImpersonateClientEx on an otherwise unimpersonated system worker, OBJ_FORCE_ACCESS_CHECK/OBJ_KERNEL_HANDLE,
IO_FORCE_ACCESS_CHECK/IO_STOP_ON_SYMLINK, original desired access/share/case and no share bypass or added privilege [W55], [W56], [W57]. Always revert/delete the client context. Close supplemental probes before this sole retained original-rights lease; a public-delete binding requires NTFS's actual DELETE grant.
An ordinary writer gains no DELETE from supersede's probe. StageFs owns the lease before any USB-instance teardown; its handle is not a minifilter-created helper requiring closure at teardown [W16]. The current factory is fixed-only and strips DELETE_ON_CLOSE
(`driver/SafeUpload.Minifilter/StagePublic.c:637`, `:672`); neither behavior is the proposed USB factory. No service handle export or second open per disposition is permitted.

| Binding/request | Selected effect |
|---|---|
| Existing public object, combined writer with checked DELETE | Bind PublicBound to the original volume/full ID, parent/link, binding-time Published generation and native lease. Ordinary TRUE/FALSE targets that backend. Data remains private; the delete's generation fences older unpublished saves. |
| Proven absent target / private probe / explicit STAGE_DISCARD | PrivateOnly disposition or typed private discard uses T5's private generation and retirement path. It never reopens USB, acquires public DELETE later, or deletes a subsequently published file. A PublicBound operation cannot fall back to private success after native failure. |
| Newer replacement at the same public name | Preserve T5's Published-only suppression against the exact bound old link; never retarget to the replacement. Allocated/blocked successors do not suppress deletion. Unexplained identity changes stay held. |

**Original subject and one-use admission.** Serialize this CCB's operations with owned operation records, not a lock held across I/O. Capture the original information class, complete TRUE/FALSE or Ex flags, mode, request thread,
CCB/open sequence and cancellation state. StageFs validates DELETE and private section restrictions; NTFS checks the public object's native restrictions [W53]. Preserve the original outer operation's per-handle access check; a reduced-right duplicate cannot acquire DELETE from the CCB's broader grant [W41].
The actual calling thread's effective subject/privileges govern any operation-time checks; neither the creator's primary token nor SYSTEM replaces that subject. Run T5's bounded prepare inline on that original callback thread,
without impersonating it, pending to a worker or editing Data->Thread/RequestorMode (those fields cannot be changed [W50]). Require current thread == Data->Thread and the qualified IRQL/context. Higher filters can pend onto workers [W51];
C11/Q8 must establish the inline path for every supported stack/application. A context mismatch is a named capability failure, not permission to synthesize or silently drop an operation; the affected stack cannot qualify by excluding required deletes.

Under the shared destination turn, revalidate anchors/head, run section 5.3 BeginHeadChange, persist PendingCommit and reserve a native-outcome slot before issuing the permit. The permit binds channel epoch, both instance/mount identities,
topology revision, CCB/backend IDs, operation/class/flags/sequence, current head revision, generation and nonce. Ordinary TRUE allocates a delete generation; FALSE without a provisional intent forwards as a native no-op without allocating one.
Only exact STATUS_SUCCESS plus a full matching reply authorizes forwarding; FltSendMessage STATUS_TIMEOUT is success-class but is not approval [W52]. Under the short exposure/operation gate, recheck binding, live lease, context, cancellation,
retirement and revision, then atomically consume once and take rundown. Release locks before the original IRP proceeds to NTFS. No permit may cover data/EOF, rename, private cancellation or a later operation.

**Native results and cancellation.** Before consumption, cancellation/removal/timeout wins the gate and records NotForwarded; release the unconsumed intent only after exact no-forward reconciliation. After consumption the original IRP owns cancellation;
never manufacture rollback, issue a compensating FALSE or retry SetInformation. A lower cancellation/failure remains its actual result. Postoperation copies native Status/Information and immutable facts into reserved nonpaged storage [W54].
Queue only result persistence, never the original mutation, to a safe worker; where safe, finish that bounded recording before returning to the caller. No service wait in a draining callback. An accepted result with missing tracking/ACK remains accepted,
with AcceptedUnresolved and the exposure fence retained. A draining callback supplies no native success evidence. TRUE updates public pending/tombstone facts only after acceptance; a successful effective FALSE clears ordinary provisional intents across
authorized handles/owners for that exact object, preserving scheduled intents, private discarded generations and completed-delete floors. Query overlays use those facts, never private discard as a public-delete receipt. Source: `driver/T5-NATIVE-PUBLIC-OPENS.md:33`, `:48`, `:53`.

**Scheduled deletion and separate outcomes.** For original CREATE FILE_DELETE_ON_CLOSE on a PublicBound writer, reserve its durable scheduled generation and head fence before the final backend FILE_OPEN; carry that flag unchanged on this open, never on a probe [W04].
Preallocate the open/lease record, StageFs CCB/ECP, close work and private storage first; prepare the seed before this mutation-capable open and validate coherence against the final checked lease. No substitute Ex ON_CLOSE operation.
Record NativeBackendAccepted/status independently from OuterCreateStatus/terminal reason/observed handle flags. STATUS_REPARSE is not an open; cancellation cannot undo an accepted native effect [W59]. A failed attachment or canceled outer CREATE returns its actual failure,
while the accepted schedule remains AcceptedUnresolved until exact reconciliation. Bookkeeping failure alone does not turn an otherwise successful StageFs open into an artificial failure; an attached held CCB grants no uncertain data access.
Never invent an app handle or app CLEANUP to discharge an accepted backend. Release the normal binding reservation once exact facts are durable; a fully bound NativeOnClose intent is the nonblocking scheduled floor of section 5.3.
For an actual caller-supplied Ex ON_CLOSE request, use a distinct ScheduledDisposition permit with this same original-IRP cross-volume transport, preserving all flags and actual native supported/unsupported results [W53]. This explicitly extends T5's ordinary-only
same-volume relay; it never emulates CREATE scheduling. PrivateOnly on-close remains private cancellation; PublicBound scheduling does not also execute STAGE_DISCARD. Ordinary FALSE cannot cancel CREATE scheduling; only an already-Published successor suppresses deletion of the current public name.

**Pre-attachment close owner.** Before calling the backend factory, allocate a nonpaged OpenLease record with the durable intent tuple, backend handle/object slot, exact native/outer facts, attachment nonce, rundown counters, initialized DPC and reserved StageFs work item.
Its single atomic ownership word progresses **PreAttach → CcbOwned → CloseClaimed → Closed**, or **PreAttach → CloseClaimed → Closed**. These are local resource states, not new journal outcome enums. The record owns even an in-progress backend CREATE;
if abandonment wins before that call returns, its returned handle is delivered to CloseClaimed, never to a new CCB. Exhausted close-work capacity refuses before forwarding the mutation-capable CREATE.
StageFs consumes the outer attach ECP only while PreAttach remains live. After validating and installing the preallocated CCB/FCB binding, it atomically changes PreAttach to CcbOwned and installs that CCB's lease reference before exposing success.
The same ownership gate arbitrates cancellation/removal. Failed installation keeps PreAttach ownership; a failed transfer rolls back private attachment. No interval has zero owners or two closable handles. CCB installation still does not prove an app handle exists.

| Exact terminal trigger | Close-once action |
|---|---|
| Failure before reparse dispatch/ECP installation; explicit failed unconsumed reparse | Creator records the real outer failure, claims PreAttach → CloseClaimed and closes after factory/seed/attach rundown. No app cleanup is expected. |
| Outer reparse ECP destruction with no successful ownership transfer | Callback records EcpEnded and claims PreAttach → CloseClaimed. A concurrently consumed but not installed attachment must fail its transfer. Final ECP deletion, not STATUS_REPARSE or elapsed time, is the trigger [W26], [W60]. |
| ECP consumed, attachment subsequently fails before success | StageFs CREATE failure completion claims the still-owned lease; release transient FCB/share state through normal private retirement. Preserve any accepted backend result. |
| CCB installed, then cancellation before a handle exists | An exact canceled post-CREATE receipt (FO_FILE_OPEN_CANCELLED, no FO_HANDLE_CREATED), or actual StageFs CLOSE without prior CLEANUP, claims CcbOwned → CloseClaimed [W59], [W38]. CLOSE covers cancellation above our post callback and handle-insertion failure; absence of a handle flag alone is not a terminal receipt. |
| Successful outer open / ordinary ECP destruction after handoff | ECP only releases its record reference. Keep CcbOwned until real last-handle CLEANUP, canceled-before-handle CLOSE, or proved removal. Duplicates/inheritance cannot close the lease early. |

Use distinct ECP types for the backend factory permit and outer attachment. IoCreateFileEx's caller-owned factory ECP is explicitly freed after that call and never signals outer abandonment; the dynamically attached outer ECP follows reparse lifetime [W26], [W57].
Keep the record referenced by the creator, ECP, CCB and queued close work as applicable; never reference the app FILE_OBJECT just to await cancellation/CLOSE. Non-owning object lookup keys are removed at actual terminal callbacks before reuse.
The ECP callback only sets atomic facts/claims ownership and queues the preinitialized DPC [W60], [W61]; it performs no close, RPC or wait. Once factory/seed/attach/relay rundown is zero, the DPC or final rundown release queues the reserved
IoQueueWorkItem on StageFs, once, for PASSIVE processing [W62], [W63]. Neither a callback nor a worker waits for its own reference or service ACK; if rundown is pending, its last release supplies the wakeup. StageFs/device/module pins survive both queues.
The worker alone removes and closes the valid backend handle, drops its native object reference, records BackendLeaseClosed with trigger/operation/revision, and wakes existing automatic anchored delete reconciliation even when no app handle ever existed.
An accepted backend canceled before its kernel handle was returned uses its exact native cancel/CLOSE receipt instead; never close an invalid handle or infer native closure from outer failure. Native outcome uncertainty stays explicit.
Retain the native acceptance, outer failure/cancellation, close fact and generation until durable receipt/replay ACK; ECP/CCB/worker references retire independently. A CLOSE may free the CCB after transferring ownership to the record; the worker uses no freed CCB pointer.
After Closed, remaining CCB/ECP lease references contain immutable history/closed state only, with no USB instance/object pins or callable backend; charge those references to StageFs lifetime, not the device-resource ACK. Later cleanup cannot reopen the lease.
This construction is **U** until C11b/c prove automatic no-handle recovery while the device remains mounted, including both sides of ECP consumption and upper-filter cancellation. Source constraint: `driver/T5-NATIVE-PUBLIC-OPENS.md:195`, `:201`, `:205`.

**Cleanup, removal and retirement.** Actual last-handle CLEANUP (not the first duplicate close or section release) claims the same CcbOwned → CloseClaimed transition, refuses new relays and cancels unconsumed work [W18].
The reserved worker closes with ZwClose only after actual I/O rundown; closing is not itself a drain proof [W58]. Complete upper CLEANUP after this local close step,
without waiting for service ACK, physical unlink or remount. Never retarget upper CLEANUP/CLOSE to USB. NTFS owns backend cleanup/scheduled effects; native other opens can delay unlink. Record backend cleanup separately from private stage retirement.
On USB removal, close the relay gate immediately. Already consumed operations retain real results or unresolved facts; after DeviceLifetimeEnded and their drain, the removal worker may claim that same close-once lease before app cleanup (section 7.4).
Later CCB cleanup sees LeaseClosed. Never attach the old backend or permit to the returned instance. Teardown alone lacks this early-close authority: if USB detaches while present, retain the StageFs-owned lease until actual upper cleanup,
or a separately proved failed/canceled attachment trigger above; fence public operations and retain uncertainty. Private paging/close continue without USB callbacks. Drop endpoint pins after completion/drain, remove non-owning lookup keys before reuse, and retire operation records only through exact result/device ACKs.
The selected relay's topology, subject and cleanup integration is **U** until C11 settles it with C1/C4/C6. Their lifetime/lock-order review precedes **any** changed-driver diagnostic or product boot. No default refusal of combined-handle public operations counts as implementing this relay.

### 6.4 Writer registry and Unknown

Expected, fully tracked USB removal is a distinct terminal device event, not generic loss of writer accounting. Old entries cannot transfer Ready to a new mount. Create a fresh admission/canary/registry domain on
attachment; retain old references until their actual local rundown and removal facts allow retirement. This changes the USB lifecycle integration only; it must not clear existing instance/global sticky Unknown. Any
genuine tracking loss remains sticky under [Owner decisions: earlier decisions](POST-MVP-PLAN.md#owner-decisions); a new mount cannot launder it. `driver/SafeUpload.Minifilter/StageWriters.c:1370` already widens unexpected context loss to global Unknown. Prove
by fault controls that the expected-removal path reserves its receipt storage before admitting work and does not require allocation in the removal callback. Resource exhaustion refuses new work before exposing it. If
routine removal necessarily creates global Unknown, revise the mechanism and return to review; do not ship a Restart-based USB recovery workflow under a different label.

## 7. Automatic remount reconciliation

Keep the new mount closed to protected mutation until device classification, canary and current policy succeed. Wake from mount/unlock, completed PnP facts or service reconnect, not a periodic scan that clears
uncertainty. Service restart replays the still-loaded driver's exact facts; a new service epoch is not a device lifetime proof. Persist the removal receipt and replay revision on fixed storage before any head hold is
reduced. An ordinary system restart during absence uses qualified boot recovery for its actual lost process lifetime; it is not a requested remedy and cannot substitute for a missing same-boot/remount proof in
qualification.

### 7.1 Match and validate before changing a head

1. Resolve the returning candidate independently; reject ambiguous device/volume matches, cloned simultaneous candidates, missing registration, unsupported filesystem, dirty/unreadable identity or changed storage
   topology. Compare captured GUID/serial/root ID and device/partition descriptors, without treating their equality as anti-clone proof.
2. Validate the old DeviceLifetimeEnded receipt and finish old-destination I/O accounting. While that is pending, return NotReady for physical commits; allow unrelated already-qualified destinations to continue.
3. Under the head reconciliation turn, reopen the root/parent through the current checked mount, verify full IDs, no-reparse type, case mode and security; perform complete stable anchored enumeration of canonical leaf
   and exact temporary identities. Recheck topology before and after I/O. An inaccessible child does not prove absence. Reuse the corrected observer contract (`driver/T5-NATIVE-PUBLIC-OPENS.md:233`) with a reviewed USB
   selector.
4. For content-dependent recovery, obtain complete current bytes/EOF and required metadata through a proved stable observation interval, and compare only with a baseline actually captured for that operation (table
   below). Same ID/time/size is insufficient; same digest is content evidence only. A DELETE-only original-present hold downgrade is read-only identity reconciliation, not a content approval or a claim that no offline
   edit occurred.
5. Resolve only the applicable row below, persist its exact evidence and unchanged generation floors, and wake waiters. A fresh save uses current Windows authority and fresh inspection; no old device grant transfers
   across remount.

### 7.2 Evidence available to each operation

| Operation | Pre-absence evidence; limit on remount inference |
|---|---|
| Staged save/seed | Exact original grant, anchors/security and any actually proved coherent seed snapshot/provenance. No invented historical digest if a snapshot was not taken. Changed recorded baseline blocks stale-save recovery. |
| Publication temporary | Exact create/rename intent and captured full ID, inspected immutable snapshot/EOF/digest and assigned metadata; native outcomes separately. Compare complete current content before claiming that approved image survives. |
| Native DELETE-only, ordinary TRUE/FALSE and scheduled delete | Exact target/parent/case, original DELETE grant, native result and ordered operation history; no assumed prior data snapshot or READ_DATA grant. Original-present hold resolution neither classifies content nor completes physical deletion. |

Full current reads are required to assert a content-dependent result or admit fresh exposure, not to manufacture READ authority for a DELETE-only caller. Missing comparison evidence prevents that comparison claim; it
does not by itself make an unchanged-return native-delete hold permanent. Fresh saves still need fresh coherent inspection.

### 7.3 Recovery outcomes

| Durable/live evidence and returning state | Automatic action |
|---|---|
| Never-forwarded public attempt, exact original/absent target, verified lifetime and anchors | Record the negative attempt; release that attempt's hold. Retain local unsaved data; a new save needs a new operation. |
| Accepted/unresolved scheduled delete; original object/anchors still present and independently validated | Downgrade only the exceptional hold to nonblocking Admitted; retain floor/history. No content approval, no reused DELETE, no physical cleanup ACK, no automatic pending-save replay. |
| Known accepted ordinary TRUE; exact original still present after proved device lifetime end | Apply the ordinary remount receipt below. Keep Kind=Ordinary and State=Accepted, retain its generation floor; stop only that dead incarnation's publication hold. Do not mark Complete/Canceled/Superseded or turn it into NativeOnClose. |
| Known accepted ordinary FALSE, including recovered native result with lost bookkeeping | Persist the original clear result and apply it once to its ordered ordinary predecessors; allocate no delete generation. Validate the returning state and resolve only those records as below. Never issue another FALSE. |
| Exact accepted, uncleared delete plus lifetime ended and anchored original-link absence, with sufficient identity continuity | Complete the existing delete receipt and barrier; no deletion of a replacement. Absence without accepted exact intent stays unresolved. |
| Ordinary TRUE/FALSE result genuinely missing or contradictory | Retain the matching PendingCommit/AcceptedUnresolved hold even if the original returns; neither presence nor device death reconstructs a native result. |
| Rename success known and exact published object/content/metadata survives | Complete only missing Published/Released bookkeeping. Never rename again; then resolve dependent delete ordering from that Published receipt. |
| Exact rename never forwarded/failed, old target intact, temporary remains | Record failure; leave the remnant diagnosed. The removed FILE_OBJECT's DELETE grant/permit is dead; matching ID/hash does not authorize remount cleanup. A new deletion needs separately reviewed fresh caller/object authority and the namespace gate. |
| Native rename result unknown, even if target digest matches | Retain PendingCommit unless the separately qualified exact native-outcome recovery proves the operation. No digest-based Published or blind recopy. |
| Target/parent replaced, reformatted volume, missing/changed anchor, conflict with an actually recorded content/security baseline, corrupt filesystem | Retain the affected recovery hold and diagnose conflict. No automatic overwrite/delete/adoption. Lack of a DELETE-only data baseline is not evidence of unchanged contents. |
| BitLocker locked or medium absent | Keep local bytes and durable heads; retry only on a meaningful availability event. Absence consumes no polling worker. |

The scheduled original-present row reuses T5's exceptional-barrier downgrade (`driver/T5-NATIVE-PUBLIC-OPENS.md:283`). The ordinary rows require the following USB-specific extension; they are not already implemented by T5.

**Ordinary TRUE/FALSE remount transaction.** Keep original native results immutable. Add an optional typed **OrdinaryRemountReceipt** to the bound ordinary operation evidence, not a new delete-state enum or a boolean administrative override.
It contains the exact delete/clear operation IDs and ordering revision, original binding/full ID/generation, old driver/boot/device/mount IDs, DeviceLifetimeEnded receipt and terminal replay revision, closed backend leases,
new device/mount binding, complete stable parent/leaf observation (original present, absent or exact durably Published successor), and resulting head revision. Its presence is evidence only after the full validated transaction below;
old formats, partial receipts, unexplained replacements or missing native results cannot qualify. This construction is **U** until C1/C6/C11c establish same-boot native isolation and fresh publication while old app handles remain open.

1. Keep the returning mount's mutation gate closed. Require section 6.1's whole-device lifetime proof, drained old I/O, closed helper leases and complete authenticated replay (or its durably retained terminal snapshot) of **all** ordinary/scheduled operations for the exact name/object,
   including each consumed permit's known terminal result or exact NotForwarded fact. One last-handle cleanup or a re-created filter instance is insufficient. The old native capability must be permanently unable to affect the new mount [W19]; no old handle is reused.
2. Under the reconciliation turn, reconstruct the original ordered results before resolving holds. A lost service ACK is recoverable from the driver's exact retained status; a genuinely missing/contradictory native result stays PendingCommit/AcceptedUnresolved.
   Known FALSE acceptance clears only still-provisional ordinary TRUE predecessors for that exact object and old incarnation that precede it in the shared-head/native sequence, across handles/owners. Persist their existing Canceled outcomes once;
   later TRUE, scheduled intents, Completed deletes and other objects are unaffected. FALSE with no predecessor records its native no-op. Never infer a successful clear from the file being present or the device having died.
3. Validate the current volume/parent/leaf under section 7.1. For an accepted, not subsequently cleared ordinary TRUE whose **original survives**, persist OrdinaryRemountReceipt while keeping Ordinary/Accepted and the original native status.
   This proves that the accepted old-incarnation effect has no remaining capability to delete the returned file; it does not prove deletion happened, undo the acceptance, or certify unchanged contents. No READ_DATA baseline is invented.
   Its owner tombstone is scoped to the dead incarnation and stops hiding the new mount's observed name when this receipt commits; retain the historical tombstone and do not revive any old private version.
4. For **absence**, Complete/CommittedDelete is allowed only for the exact accepted, uncleared delete with sufficient identity continuity; FALSE itself is never a deletion receipt. For an exact **already-Published successor**, apply normal Published-only suppression.
   A clear's returning original/absence is current namespace evidence, not proof that the clear caused restoration/removal. Any additional unexplained replacement, incomplete observation or unknown later operation remains held.
5. Use BeginHeadChange → durable native-result/receipt/head update → CommitHeadChange for this resolution. Clear only a matching operation's PendingCommit after its result is durably recorded. Derive the hold predicate from the validated receipt:
   `Ordinary && Accepted && ValidOrdinaryRemountReceipt` contributes **no live publication reservation**, but retains its accepted-generation floor. It never becomes scheduled Admitted or physical Complete merely to satisfy an existing predicate.
   Generalize PublicationGenerationFloor to include these retained ordinary generations alongside scheduled and committed floors; keep maxAllocated and every immutable delete/cancellation high-water. A verified FALSE removes only the provisional ordinary effects
   it actually cleared, retaining maxAllocated and committed floors. The service head, ExposureHead, startup/reconnect readers, schema validation and compaction must implement the same rule; no path may fall back to the current original-present wait.
6. Once every relevant old hold is exactly resolved, automatically admit **fresh** current-subject saves with generations above all retained floors, renewed native grants and full inspection. Do not wait for old app CLEANUP or Windows Restart.
   Honor actual sharing/delete-pending restrictions on the new mount; clearing SafeUpload's old-incarnation hold grants no Windows permission. Do not replay the old save, synthesize FALSE, redelete the survivor or restore absent bytes.

The present implementation deliberately retains ordinary Accepted when the original is present (`agente/SafeUpload.Agent.Service/Interception/StagedPublicRelayJournal.cs:183`, `:200`), and its retirement path requires terminal delete states (`:240`).
Change those consumers together with `StagedDestinationCommitJournal.cs:886`, `:891`, and its schema validator (`:1041`): a validated ordinary remount receipt permits **resource** retirement without falsifying the semantic state. M2/live-volume reconciliation stays unchanged.
DeviceResourceAck may retire closed device records before remount under section 7.4; the service retains their complete native facts/terminal snapshot. Persist OrdinaryRemountReceipt before releasing the head gate or acknowledging ordinary resolution,
using that snapshot if kernel records already retired. This never fabricates LastCleanup or PhysicalDeleteComplete. Keep durable native history, remount evidence and the ordinary generation floor through compaction; absence from the driver alone proves no outcome.
Crashes before persistence leave the hold; crashes after persistence replay the same resolution/ACK only. An unknown TRUE or FALSE result remains a diagnosed failure even if the original returns unchanged. Missing bookkeeping with a retained exact result is not that uncertainty.
Diagnostics say “Delete was accepted before removal; the file is still present. Protection recovered; delete again if intended.” D2 must approve this visible outcome. A new delete is a new user-authorized operation, never recovery under the old grant.

### 7.4 Device-resource ACK contract

Reserve one record per device incarnation before admission. Its states are Tracking → RemovedDraining → FrozenForAck → Retired; missing DeviceLifetimeEnded evidence keeps it Tracking/held, never guessed terminal.
RemovedDraining fences native/exposure admission, unregisters PnP on its safe worker, drains registration/native callbacks and issued I/O, removes non-owning FILE_OBJECT lookup keys and closes invalidated helper leases
once. StageFs CCBs retain immutable authority history plus LeaseClosed, not callable USB pointers; their later cleanup cannot double-close. Actual native app handles may still exist; DeviceLifetimeEnded, not their CLOSE,
bars mutation. FrozenForAck requires these drains and complete immutable native facts (including unknown outcomes, never fake LastCleanup). Freeze a terminal revision over driver/boot/device/mount IDs, all operation
IDs/nonces/results, pre-attachment ownership/terminal-trigger and backend-close facts, coverage, generation floors and unresolved intents. No OpenLease with pending factory/close work may be frozen as closed. The service atomically persists and flushes that exact receipt with its head/intent references on fixed NTFS before sending DeviceResourceAck over
the authenticated connection. The ACK supplies those IDs, expected terminal revision and receipt ID/digest; digest matches receipt bytes only, not object authority. The driver compares its frozen tuple and zero device-operation/callback
references under the fact-map lock, removes those records and increments the replay revision. Private StageFs references are separate. Duplicate ACK is result-only; stale/partial/mismatched ACK refuses. Retain the service receipt until a complete unchanged
authenticated replay proves the exact records absent; afterward compact resource facts but retain unresolved operation history/floors until their own T5 exits. Lost ACK/reply repeats bookkeeping only. A new driver boot
cannot infer same-boot removal from a missing record. This extension retires device resources, never T5 physical cleanup, delete Complete, scheduled floors or StageFs FCBs/sections. No numeric ABI is assigned. C6/C8
crash before/after durable receipt, ACK consumption and map removal, including original-present deletes, and require bounded nonpaged records across repeated detach/replug cycles.

### 7.5 Conflict and absence

Offline edits complicate continuity: NTFS IDs can be reused [W02], and an exact cloned image can reproduce all unauthenticated on-disk identifiers. The listed checks detect ordinary replacement, not every malicious
clone. For a detectable conflict, no old grant/cleanup is reused; a user's newly initiated save to a freshly authorized different destination can proceed. It does not erase or manually unlock the unresolved old
transaction. For an indistinguishable clone, strong physical-medium identity cannot be established by these Windows fields. D4 must choose an explicit threat/scope boundary or stronger authenticated media; this is an
unresolved support condition, not an invitation to treat a fingerprint as object authority. C5 tests detectable clones and records the limit.

If the medium never returns, local data/charges and compact durable head floors remain. Offer a local recovery copy only after exact stage sealing and recipient/export authorization. Do not expire unresolved evidence or
discard unsaved bytes automatically. D5 covers retention defaults; new admissions fail predictably when reserved capacity is exhausted. Diagnostics identify file, device label plus safe identifier, phase, old/new
incarnation, operation, retained-byte count, native status and next action: reconnect/unlock the recorded device, save an authorized local copy, or collect conflict diagnostics. Never offer a manual journal edit,
force-release button or Windows Restart for ordinary USB removal.

## 8. T5/T4 integration rules that cannot change accidentally

Empty saves use ordinary stable seal/inspection/publication; no EmptyHeld resurrection ([Owner decisions: empty files and deletes](POST-MVP-PLAN.md#owner-decisions)). Public DELETE, native FILE_DELETE_ON_CLOSE and ordinary TRUE/FALSE disposition preserve original
Windows results, sharing and last-handle behavior. They share the same USB mount qualification and head with publication. Accepted native mutation cannot be undone by failing its tracking acknowledgement; retain
AcceptedUnresolved. Only durably Published successors suppress a prior delete; Approved/Publishing/blocked/private successors cannot. Sources: `driver/T5-DELETES.md:166`, `:223`; `driver/T5-NATIVE-PUBLIC-OPENS.md:114`,
`:147`. Section 6.3 supplies the selected cross-device transport and StageFs-owned backend lifetime; T5's same-volume relay is not assumed to cover StageFs.

Head ordering survives replug, service crash, old transfer retirement, rename and compaction. Preserve maxAllocated, published identity/generation, committed delete floor and every unresolved operation/cleanup reference.
A removable journal is never authoritative: it can be edited elsewhere. Persist the authority on fixed private NTFS. Old formats without device/mount binding remain held; no migration fills missing identity from the
currently present stick. Negotiate feature-only USB binding/fact capabilities with exact lengths and explicit versioning; preserve existing ABI numbers and normal builds. No new numeric layout is assigned by this design.

A device-end receipt says nothing about the private stage's cache/section lifetime or caller read/export authority. Unsealed retention, rejected allocation cleanup, public temporary cleanup and hand-back completion
remain separate obligations. Retry only unfinished recording, never completed public mutation ([Owner decisions: T4 recovery](POST-MVP-PLAN.md#owner-decisions)). M2's forced-instance fixed-NTFS recovery remains unchanged; no USB logic may weaken its
existing gates.

## 9. Owner decisions needed before dependent implementation

All entries below are **pending**, including the added D8 query contract. Recommendations do not approve a scope change, failure policy or VM run.

| Decision / option | What users notice | Risk or cost | Recommendation |
|---|---|---|---|
| D1 A: qualify basic USB NTFS first; refuse FAT32/exFAT and reader media-only swaps | NTFS sticks/external disks can save after checks; common FAT/exFAT sticks show a named unsupported reason. | Narrower compatibility; USB stack variants still need separate proof. | **Choose A for first T21 envelope**, explicitly record exclusions. |
| D1 B: require FAT32/exFAT in first delivery using fixed staging plus approved copy | More sticks usable; native metadata and recovery limitations become visible. | No existing exact-object recovery construction; may require a different product contract, not just more tests. | Defer pending C2 and a revised reviewed design. |
| D2 A: retain interrupted saves, automatically reconcile holds and retain files surviving interrupted deletes | Reconnecting releases decidable holds and permits a fresh Save. A delete accepted before removal can leave the original visible again; tray reports that outcome and the user issues a new delete if intended. | Buffered-save success and accepted-delete status do not guarantee durable export/unlink. No automatic redelete or old-save replay; genuine unknown results remain diagnosed holds. | **Choose A**, including §7.3's ordinary TRUE/FALSE evidence rule; owner approval remains pending. |
| D2 B: automatically finish an interrupted approved save or enforce an earlier delete after replug | Fewer manual saves/deletes; a surviving original could disappear automatically. | Requires fresh caller/export/delete authority and exact outcome proof; old grants cannot authorize replay or removal of offline edits. | Do not enable under this design; a separately reviewed resumable-operation contract would be required. |
| D3 A: approved bytes may appear as a partial temporary; policy/head revocation is nonretroactive | Removal, a newer save or delete can leave an approved prefix; the one already-admitted range may finish after that event. A local complete copy remains. | No whole-file power-loss atomicity or recall of previously authorized ranges; cancellation only fences subsequent exposure. | **Choose A**, with the 64-KiB single-range bound and C9 races. |
| D3 B: require no partial visible approved file anywhere on the medium | Users get a stronger offline atomic-export expectation. | Ordinary filesystem copy cannot provide it; requires a container/encryption protocol and compatible readers. | Do not promise this with the proposed architecture. |
| D4 A: ordinary unmanaged media, explicit limit for malicious indistinguishable clones | Normal unchanged return reconciles; detected identity/conflict cases stay held with diagnostics. | Windows identifiers cannot authenticate physical media or prove absence of every offline identity forgery. | **Choose A only with this limit explicitly accepted**; never reuse old grants for new mutations. |
| D4 B: require strong authenticated device/volume identity against clones | Only enrolled capable media work; generic sticks refused. | Requires an additional hardware/cryptographic design and provisioning; BitLocker alone is insufficient. | Choose B if anti-clone identity is required; block T21 activation until designed. |
| D5 A: retain interrupted data until explicit authorized recovery/discard; apply shared T9 budgets | Unsaved work survives absence; a full local budget blocks new saves with a named storage reason. | Long-absent media can consume disk; exact cleanup remains necessary. | **Choose A**, measure accounting, then approve numerical per-user/total reserves. |
| D5 B: time-based deletion of interrupted stages | Space recovers without user action. | Can destroy unsaved work; unresolved generation/operation evidence still cannot expire. | Reject as default; requires explicit retention/data-loss policy. |
| D6 A: include plain and unlocked BitLocker To Go NTFS after separate rows | Encrypted sticks work after unlock; locked ones remain unavailable. | Additional filter/lock/observer qualification. | **Choose A conditionally on C7**, never use encryption to waive privacy. |
| D6 B: plain NTFS only initially | Encrypted media get an unsupported explanation. | Reduced enterprise usability; does not remove the offline-exposure rule. | Acceptable only as explicit first-envelope scope. |
| D7 A: approve isolated USB lab device/controller and disposable media images | Enables reproducible hot-unplug and independent-byte tests. | Changes the target topology; requires approved infrastructure diff and baseline acceptance. | **Choose A when product rows are released**, under section 11. |
| D7 B: leave lab unchanged | Design/component work continues; USB runtime proof remains unavailable. | T21 cannot qualify from fixed VHD results or builder controls. | Keep capability disabled. |
| D8 A: accept actual StageFs native volume/path identity; show logical USB destination in SafeUpload | Handle-based tools see a private GUID/NT path; DOS lookup may fail. Authorized path reopens repeat checks. Tray shows the intended USB file. | Apps that demand the original USB volume identity may be incompatible; required T8 workflows must still pass. | **Choose A explicitly, conditional on C4/app qualification**; this is the selected construction's exact query contract. |
| D8 B: require all handle-based identity/path queries to appear native USB | Such tools retain complete original-volume transparency. | StageFs cannot promise this while its real routing device remains independent; spoofing that device defeats the lifetime proof. | Do not accept or enable this construction under B; no hidden compatibility narrowing. |

## 10. Finite native controls: settle mechanisms before qualification

Each control has fixed cases and a single hypothesis. Run unprotected differential controls only when separately authorized; preserve failed attempts. A repeated identical failure stops that candidate; revise the
hypothesis first. Builder 19045.6466 results are mechanism evidence. Repeat required controls on target 19045.2965 before support.

| Control | Fixed experiment and decisive result |
|---|---|
| C1 — removal boundary and attach race | On NTFS USB mass-storage, hold native write, share-0, duplicate/inherited and delete-on-close handles plus dirty mapped views. Register exact target PnP notification; capture volume/device association, teardown, lower I/O completions and monotonic ordering. Whole-device detach/re-add at the same and another port while old handles remain open; attempt write/flush/EOF/disposition through each old handle before/after new mount. Require zero mutations on returned media, failed old device I/O and automatic new qualified admission without app close. Contrast software dismount/remount, canceled eject, interface disable, failed start and reader media-only swap; none may forge the accepted boundary. Race the first writer against discovery/registration. |
| C2 — filesystem capabilities and IDs | NTFS/exFAT/FAT32: query full ID, open-by-ID, extended-ID directory enumeration, feature flags and native security results before/after short→long rename, replace, supersede, delete/recreate, clean remount and offline edit. Record exact status/length/IDs. FAT/exFAT failures retain refusal; a passing ID sample alone does not establish lifetime stability or clone resistance. |
| C3 — publication semantics | Compare native/candidate create/overwrite/supersede, POSIX replacement and open-reader/delete-pending cases. Lengths include 0, 1, sector−1, sector+1 and 64KiB+1. Pull at 0, one aligned block, half, final padded submission, logical EOF shrink, flush-pending, fenced, rename-pending and rename-complete. Read offline before recovery; require exact normal EOF/data, zero-only padding, no forbidden byte and honest interrupted outcomes. Compare quick-removal/better-performance settings without changing the gate. |
| C4 — StageFs routing/retirement | Prove actual FILE_OBJECT dispatches to the StageFs VDO before/after USB removal. Differential new/seeded/overwrite, share-0/supersede, restricted/write-only subjects, duplicates/relative/ID/rename, image/read/write mappings, canceled reparse/ECP replay and service loss. Query OPENED/NORMALIZED × DOS/GUID/NT/NONE final paths, volume/view IDs and reopen returned paths while mounted/removed; require the exact D8 contract, fresh rights and no backing disclosure. Hold mappings after app close, detach at allocation/seed/seal/hand-back and force late paging/EOF/CLEANUP/CLOSE. Require no USB callback dependency, false seal/free or leak after actual release; all required apps must pass. |
| C5 — return identity and conflict | Two identical-model sticks, absent/duplicate serial, same drive letter, serial collision, cloned image simultaneously and sequentially, format, parent replacement, leaf replacement, same-ID content/ACL edit, name alias and GUID change. Require no old grant/cleanup on a substituted object, no generation reset, detected ambiguity held; explicitly record the indistinguishable-clone limit requiring D4. |
| C6 — durable facts and native deletes | Fault each intent/result/ACK boundary; kill service during absence/return; duplicate/stale/partial replay. Exercise accepted-but-unbound CREATE, ordinary clear, both delete/save orders and known/unknown rename outcome. Include DELETE-only/share-0 with no prior digest, then same-ID offline content edit: permit only the read-only exceptional-hold downgrade, never false Complete, old cleanup or stale-save replay; a freshly authorized/inspected successor can proceed. Require automatic release of decidable holds; genuine unknowns stay held. |
| C6r — ordinary remount outcomes | Force accepted ordinary TRUE → surprise removal before app/backend cleanup → unchanged return with old handles still open → automatic hold resolution → fresh inspected publication. Require Ordinary/Accepted plus original native result, retained floor/maxAllocated, no Complete/Canceled/NativeOnClose fiction and zero repeated disposition. Repeat TRUE→accepted FALSE with journal/result-ACK loss: recover the exact FALSE fact, clear only earlier ordinary intents, then publish fresh; repeat FALSE no-op and a later TRUE. Negative cases: lost native result, different leaf/parent, later unknown operation and incomplete replay must stay held. Include original absence and exact Published replacement; crash at receipt persistence, head ACK and compaction, with device-resource ACK both before and after remount. No app CLEANUP or Windows Restart may be required for the unchanged-return success cases. |
| C7 — BitLocker and observation | Locked→unlocked NTFS, forced relock, detach while copying, conversion/protector/stack change and unlock elsewhere. Prove current-mount rebinding and no premature admission. Validate encrypted raw capture plus decrypted independent observer against positive-control approved markers and forbidden markers. |
| C8 — capacity and coverage faults | Reserve exhaustion before admission, private/USB disk full, failed notification registration, truncated descriptor, incomplete enumeration, lost fact page and genuine sticky Unknown. Require named refusal/retention, bounded buffers/records and no timeout-based Ready. Replug must not clear genuine global Unknown. |
| C9 — exposure/head races | Pause a three-range copy before admission, after admission/before lower completion, and before durable head ACK; force both orders against newer allocated then blocked saves, ordinary DELETE TRUE/FALSE, scheduled delete, private cancellation, accepted native result with failed tracking ACK, and policy change. Repeat at final padded submission/EOF shrink for C3's short/unaligned lengths. Require exact sequence/head revision: only one pre-transition range may finish, zero later range, no old rename/retry or false delete suppression. Keep a bound scheduled handle alive: a newer inspected successor must expose/publish without an extra SafeUpload wait, while the older copy stays fenced. Service crash at Begin/Commit leaves incomplete replay closed. |
| C10 — continuous observer validation | On disposable images, inject known overlapping/aligned/partial writes, explicit zero/discard, failed completion, pre/post-hot-unplug writes and log truncation. Compare the block filter's ordered payload ledger against independent raw readback and replayed images; all expected positive markers must appear and intentional omissions must fail coverage. Repeat encrypted capture with independent decrypted observation. No product PASS with observer divergence. |
| C11a — cross-device transport and subject | Compare direct USB NTFS with combined StageFs DELETE+write handles: ordinary TRUE→FALSE, FALSE without TRUE, independent cross-owner clear, basic/Ex flags and public versus PrivateOnly discard. Run duplicate (including reduced-right) and inherited handles, impersonated/restricted callers, denied DELETE plus DELETE_CHILD, allowed parent DELETE_CHILD, disabled privileges, readonly and image-mapped files, ShareAccess=0 and conflicting share masks. Log actual request/current thread, mode, effective subject, both instance altitudes/stack sizes, original and backend grants/IDs, native Status/Information and exactly one lower disposition. Test equal/larger target stack; smaller/mismatched/absent instances and an upper-filter worker handoff must fail capability qualification explicitly, never use SYSTEM or synthetic disposition. Require native success as well as denial cases; rejecting all requests fails. |
| C11b — scheduling and no-handle cleanup | Compare combined CREATE DELETE_ON_CLOSE and actual Ex ON_CLOSE with native NTFS, including ordinary FALSE, duplicates/inheritance, other readers, private sections and newer allocated/blocked/Published saves. After backend acceptance, fail before outer ECP installation, during unconsumed reparse, after consumption before CCB transfer, and after CCB installation before handle creation (lower/upper cancellation and handle-insertion failure). Keep USB mounted; require zero app handles/no app CLEANUP, preserved native acceptance plus actual outer failure/cancellation, one backend close, released helper sharing and automatic anchored reconciliation. Also cancel backend CREATE after NTFS acceptance but before its kernel handle returns. Fault seed validation/result ACK/service restart; normal successful ECP destruction must retain the lease. No false deletion completion, private bytes or lost generation. |
| C11c — cancellation, removal and lost results | Race creator failure/ECP destruction/canceled-before-handle CLOSE/real CLEANUP/removal against the single lease handoff and close claim, including backend CREATE still in flight. Require one close worker, no orphan share lease, no callback/CCB use-after-free and no service-ACK wait; teardown alone cannot close a live app lease. At ordinary relay permit/native-result boundaries, repeat C6r's accepted TRUE and accepted FALSE remount cases with old combined/duplicate/mapped handles alive. Known results recover automatically; missing results remain held. Assert no replay, compensating FALSE, redelete or mutation through old objects. Repeat both sides of ECP consumption and head persistence under C9's continuous observer. |

No control is claimed executed here. C1 failing its exact association or stale-handle premise blocks this construction. C4/C11 test StageFs and the selected relay; independent kernel lifetime/lock-order review must
precede even its first changed-driver diagnostic boot. No experiment is permission to try the rejected USB-instance-owned route. C3 cannot establish arbitrary hardware power-loss atomicity; results define supported
storage behavior and D3 wording. C5 cannot prove cryptographic identity from noncryptographic identifiers; a scope decision is unavoidable.

## 11. Qualification and infrastructure boundary

Use `SAFEUPLOAD_DEBUGGEE=win10-debug3` explicitly; keep `win10-debug2` off. Windows 10 19045.2965 remains the target. The USB topology does **not** currently have approval merely because this note describes it. Obtain a
concrete owner-approved infrastructure change: isolated USB controller plus QEMU `usb-storage` backed by disposable test images, with libvirt-managed hotplug/removal and retained before/after XML. QEMU documents emulated
storage and host-device passthrough separately [QEMU USB][Q01]; libvirt describes USB disks/host devices [domain XML][Q02]. Emulated `usb-storage` is the deterministic first tier, not proof that physical passthrough or a
controller exists. If actual host USB passthrough is needed, approve only a dedicated sacrificial device and its binding; never a host system disk. Qualify physical models/USBSTOR or UASP stacks separately before naming
them supported.

Use the existing disposable OS overlay, reset EFI variables on every start, no TPM, test signing, Secure Boot off. The USB image is separate disposable run media, never the qualified OS base. Use host-controlled removal,
not guest flush/eject, for surprise rows. Observe and preserve the detached image before reconnecting it to any writer. No host-wide polkit/QEMU-hook/sudoers/libvirt-daemon/systemd or image automation change is part of a
routine run. Infrastructure approval, release of the current T4 product stop and each planned product run remain distinct.

The independent observer must read the actual medium: guest raw-volume/device reads outside the service/app path, plus host backing-device capture and offline parsing of an immutable detached image. Include temporary
names, allocated clusters, slack, free-space remnants and filesystem metadata in forbidden-marker searches. Use fresh baseline images and distinct markers for old approved content, newly approved content, blocked content
and attempted stale-handle writes. Never remove forbidden observations as “temporary” or trust service logs as bytes. Raw Windows device access has documented access/sharing/alignment restrictions [CreateFile][W15]; C7
separately settles encrypted visibility. Validate the observer with intentional positive markers before interpreting zero counts.

Sampled reads/final images alone cannot prove every instant. Preserve the existing T19 requirement by recording the complete emulated-device write stream and causal exposure/permit/native-result ledger, independently
mapping file-data ranges to approved snapshots or baseline bytes and checking metadata/slack for forbidden markers. Keep raw images as a separate observation. Missing write capture is an evidence gap, not PASS. Select a
host QEMU block-filter observer on the disposable USB image's logical device boundary, before image-format translation: append sequence/LBA/length/exact payload, issue/completion status and flush/zero/discard/hot-unplug
boundaries to a separate retained ledger. It never queries SafeUpload for expected bytes. Preserve uncertain or partial writes as uncertain, not absent. A missing sequence, overflow, truncated record or unobserved
operation fails coverage. Replay that stream onto the immutable initial raw image and compare independent detached raw-device readback; map each exposed file-data range to the separately retained
approved-snapshot/head-admission ledger. Do not read an active qcow2 file as coherent raw media. This new observer is **U** until C10 validates completeness; its infrastructure/code deployment is part of pending D7, not
assumed available or authorized by this note. For physical devices, retain raw sampling and the qualified lower-write observation mechanism; no emulator-to-hardware equivalence claim. See [T19: Continuous evidence](POST-MVP-PLAN.md#t19-continuous-evidence)
for the unchanged continuous-evidence obligation.

| Required row family | Variants and required outcome |
|---|---|
| Q1 Attach/admission | Boot-present and hot-attach; fixed-reporting USB; service down; policy on/off/expansion; letter/mount aliases; unsupported FS. No pre-Ready protected write; explicit unsupported refusal. |
| Q2 Ordinary operations | Empty/clean/CPF new/overwrite, coherent append/seed, native grants/denials, public reads/deletes including all C11a/b combined-handle cases, rename/copy ingress, required application and both mapping-leak repros. Exact final/blocked prior-byte rules. |
| Q3 Removal during write/seed | Cached/noncached and mapping variants; duplicate handles and late paging. Medium never contains forbidden bytes; private incomplete version retained. |
| Q4 Removal during seal/inspect | Before/after writer drain and seal ACK; timeout/parser failure/service crash. No implicit approval or zero-length shortcut. |
| Q5 Removal during publication | Every C3 cut point and C9 head race; policy change; copy disk full; native success before durable result; uncertain rename. Approved-only physical data, exact earlier-range ordering, no later exposure or duplicate mutation. |
| Q6 Reconnect/recovery | Unchanged same/other port, old handles still alive, accepted native-delete tracking failure, all C11c relay/close races, restart service during absence/return. Automatic exact hold release and a fresh clean successor, no Windows Restart. |
| Q7 Changed/absent media | C5 conflicts, no return, locked media, malformed replay and stale permit. Local retention/diagnostics; no substitution or generation reset. |
| Q8 Stress/coexistence | Serial detach/replug cycles, concurrent independent destinations, resource failures, Defender/approved filter stacks and BitLocker. Repeat C11 topology/subject/cleanup checks on each stack. Bounded retention, no hang/bugcheck, unchanged privacy gates. |

Run the required families on the final matched pair in ordinary, runtime-Verifier and boot-Verifier modes. Include Special Pool, Pool Tracking, I/O/Filter verification, deadlock and relevant low-resource rows in the
existing approved Verifier configuration; record flags rather than silently changing them. BLOCK-window rows run serially. Four normal/feature × Debug/Release WDK builds, PREfast/ApiValidator 0 warnings/errors, complete
agent matrix, PowerShell 5.1 parse/native-signature checks and harness self-checks precede authorized real rows. The matched driver package includes minifilter and StageFs hashes; normal builds omit StageFs/USB
activation. Require exact test discovery/execution, no skips, `ForbiddenByteCount=0`, exact expected outcomes and complete receipts. Native controls, source review, component passes and final protected-pair qualification
remain separately reported.

Record source commit, delivered artifact hashes, device descriptors/topology, OS/stack, policy, monotonic cut point, all raw observations and structured verdicts under `driver/evidence/README.md:3`. Preserve the first
failed attempt. Stop on required failure, repeated identical failure or changed baseline; no weakened threshold/assertion or warning suppression. After evidence retention, independently verify untouched OS/media bases,
approved domain XML restored, EFI reset, no leaked USB attachment/task and deletion of disposable OS/USB run disks. Restoration is a separate verdict. The owner's existing restoration contract remains
[Owner decisions: VM restoration](POST-MVP-PLAN.md#owner-decisions); approve any temporary XML deviation explicitly and compare restoration against the original approved baseline, not against the changed test topology.

## 12. Implementation increments and review exits

| Increment | Deliverable and exit |
|---|---|
| T21.1 Design | Obtain independent re-review of StageFs, §6.3 relay/pre-attachment lease ownership, §7.3 ordinary remount evidence, per-range exposure and device-resource ACK; record pending D1–D8 choices and obtain Sol 6.1 xhigh security acceptance. USB stays off. No M2 stop release implied. |
| T21.2 Mechanism controls | Implement bounded diagnostic controls/harness with PS5.1 gate; approve topology and runs separately. Settle C1/C2/C3 before selecting support combinations. |
| T21.3 Bound admission/lifetime | Implement accepted StageFs CREATE/dispatch/retirement, atomic pre-attachment lease handoff and no-handle close worker, relay topology/subject, device binding, PnP and registry/rundown. Four static builds and component checks. **Independent Sol 6.1 xhigh kernel lifetime/lock-order/retirement review before the first changed-driver boot**, including any diagnostic driver and C11 harness driver. |
| T21.4 Shared transaction | Integrate native results/cleanup, OrdinaryRemountReceipt and all hold/floor/replay/compaction consumers with T5 exposure permits and remount reconciliation; local retention/read-authority UX and charged storage. Require C1/C4/C6 (including C6r)/C9/C10/C11 exits, then the full delivery matrix. No legacy fallback or partial activation. |
| T21.5 Destination qualification | Run Q1–Q8/all required modes on the approved envelope, raw/continuous observers and separate restoration; close removal and mapping failures. Final working-pair adversarial Sol review. |
| T21.6 Handoff to M4 | Cite owner scope, matched hashes, complete evidence and remaining exclusions. Mark ready for combined M4 only when T21 Done when is met; cutover/taint removal still require later owner sign-off. |

## 13. Documentation references

Microsoft sources below establish the cited API contracts, not target qualification. This revision checked cancellation, ECP/close lifetime, worker dispatch and removal contracts; W49–W58 remain the selected relay's sources. Implementation references use file:line at the stated baseline;
status-plan links use sections, including T21 and T19. Only the three retained receipts in Review history establish review verdicts; newer owner decisions take precedence.

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
[W25]: https://learn.microsoft.com/en-us/samples/microsoft/windows-driver-samples/simrep-file-system-minifilter-driver/
[W26]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltallocateextracreateparameter
[W27]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlgetecplistfromirp
[W28]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlisecpfromusermode
[W29]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocheckshareaccess
[W30]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioremoveshareaccess
[W31]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_fsrtl_advanced_fcb_header
[W32]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_object
[W33]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlregisterfilesystemfiltercallbacks
[W34]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccinitializecachemap
[W35]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-mmflushimagesection
[W36]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-mmcanfilebetruncated
[W37]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccuninitializecachemap
[W38]: https://learn.microsoft.com/en-us/previous-versions/windows/drivers/ifs/irp-mj-close
[W39]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccpurgecachesection
[W40]: https://learn.microsoft.com/en-us/windows/win32/fileio/file-buffering
[W41]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandle
[W42]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ioregisterfilesystem
[W43]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_vpb
[W45]: https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/supporting-mount-manager-requests-in-a-storage-class-driver
[W46]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew
[W47]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/mountmgr/ni-mountmgr-ioctl_mountmgr_volume_arrival_notification
[W48]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/mountmgr/ni-mountmgr-ioctl_mountmgr_delete_points
[W49]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_io_parameter_block
[W50]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_callback_data
[W51]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/writing-preoperation-callback-routines
[W52]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltsendmessage
[W53]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information_ex
[W54]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_post_operation_callback
[W55]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-secreateclientsecurityfromsubjectcontext
[W56]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-seimpersonateclientex
[W57]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-iocreatefileex
[W58]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwclose
[W59]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcancelfileopen
[W60]: https://learn.microsoft.com/en-us/previous-versions/ff551124(v=vs.85)
[W61]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keinsertqueuedpc
[W62]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioqueueworkitem
[W63]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-io_workitem_routine
[Q01]: https://www.qemu.org/docs/master/system/devices/usb.html
[Q02]: https://libvirt.org/formatdomain.html
