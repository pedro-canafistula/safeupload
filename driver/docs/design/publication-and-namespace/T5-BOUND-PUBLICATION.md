# T5 bound publication: concrete integration contract

2026-10-12. Proposal for the next shared-head integration, following the reviewed
[allocation/publication contract](T5-NATIVE-PUBLIC-OPENS.md#allocation-and-publication-integration--reviewed-contract).
No capability activation or changed-driver boot is authorized by this note. No owner policy changes are proposed.

**Review status: READY WITH CORRECTIONS, Luna 6 max, 2026-10-12.** The existing review closed its concrete Facts, write-fence,
target-check, failed-CREATE retirement and descriptor-mechanism findings. Implement this contract without granting publication
until the separate writer-metadata/security and complete recovery prerequisites are met. The unreadable-seed owner choice remains
pending; this is not activation, lifetime-review or boot sign-off. The [direction review](../../../evidence/2026-10-12/m2-progress-direction-review.md)
records the integration checkpoint. Native-mask [PowerShell 5.1 control](../../../evidence/2026-10-12/bound-publication-native-ab6dc0b9.txt)
passes on the unprotected builder; its first mode-query harness failure is retained locally under `bound-publication-native-c4b7b7e9.txt`.

## Authority and ordering

The existing `StagedTransferPublisher` refuses bound entries; its legacy permit uses two path strings and its rename ignores
the supplied target volume (`StageProtocol.c:230–338,394–429`). Keep that legacy mode available only to its existing pair.
A head-aware pair must refuse legacy publication of protected entries. A bound entry never falls back to path authority.

The service opens the recorded fixed-NTFS volume/root/parent, rechecks full IDs, non-reparse types and parent case mode, and retains
those handles. It creates a unique temporary leaf relative to that parent, copies only the locked inspected snapshot, sets exact EOF
and flushes noncached output. It then obtains the destination physical-commit turn, rereads its head, observes the exact target,
and persists the linked rename intent before attempting rename. Hold that turn through actual rename and durable Published result.
No namespace/spin/global journal lock, receive-loop thread or bounded worker slot waits for another destination turn or app close.

An original still-live, identity-bound kernel version supplies the publication authority: transfer, driver instance, generation,
private stage full ID, destination anchors, checked CREATE rights and assigned security. Its captured subject and native
disposition/sharing/traversal/label checks must satisfy the writer corrections in the allocation note. An unbound legacy stream,
missing native permission proof, lost original subject, changed anchors, uncertain seeding or unresolved head is not authority.
This transport cannot make the REVISE writer capture ready or decide unreadable-seed hand-back policy.

Prepare outside the turn; publication can wait behind an accepted native-delete reservation without holding the snapshot/global
semaphore or blocking unrelated destinations. On admission, revalidate current inspection/policy, current save generation,
committed delete floor and every unresolved intent. Allocated/blocked successors cannot suppress a delete; only Published can.

## Two linked permits and actual objects

1. **Create permit:** bound to the exact parent/root/mount/case, unique temporary leaf, original version and measured digest/length.
   Reserve its nonpaged record before forwarding the service's original CREATE_NEW once. Verify actual callback anchors outside
   global locks. Consume under the current authenticated service connection/authority; never reset a consumed grant on replay.
   Capture the actual accepted temporary FILE_OBJECT and full ID in post-CREATE; failure/lost facts remain replayable for recovery.
2. **Rename permit:** linked to that create nonce and exact held temporary object/full ID, destination leaf, expected public identity
   or absence, head generations and inspected digest/length. Refuse if create outcome/identity, flush/EOF or original version authority
   is unproven. Persist the exact head intent first. Recheck actual source/destination parent anchors, case semantics and the current
   public leaf identity or proven absence under the name gate below before atomically consuming once. Forward the original same-volume parent-relative POSIX replace operation; do not synthesize a SYSTEM
   operation on a different file object. Record the actual NTSTATUS. A repeated grant/query is never permission to execute again.

### Temporary CREATE and assigned security

Accept only the original authenticated service's UserMode, same-process CREATE on the anchored parent with FILE_CREATE (2),
share 0 and explicit DesiredAccess **0x00110082**: FILE_WRITE_DATA, FILE_READ_ATTRIBUTES, DELETE and SYNCHRONIZE. CreateOptions
must be **0x0020006A**: FILE_WRITE_THROUGH, FILE_NO_INTERMEDIATE_BUFFERING, FILE_SYNCHRONOUS_IO_NONALERT,
FILE_NON_DIRECTORY_FILE and FILE_OPEN_REPARSE_POINT. FileAttributes is FILE_ATTRIBUTE_NORMAL; EA length and allocation size
are zero. Reject GENERIC_*, MAXIMUM_ALLOWED, backup/restore/open-by-ID/transaction flags, delete-on-close, extra access, options,
EAs, alternate streams and a different subject or parent. Compare the actual callback's access state after generic mapping too:
the effective request/grant must contain exactly this mask, never additional app authority. Post-CREATE must prove FILE_CREATED
and a regular non-reparse temporary on the recorded volume before exposing its write grant.

The temporary uses the fully assigned destination descriptor retained by the corrected original writer CREATE, including owner,
group, DACL/inheritance, SACL and mandatory labels. This permit transport does **not** transmit or inject a descriptor and must
not rewrite a UserMode CREATE access state. The service must already possess the exact assigned descriptor from the corrected
writer-metadata path and supply it as the original NtCreateFile OBJECT_ATTRIBUTES.SecurityDescriptor. Until that prerequisite is
implemented and verified, CreatePermit returns NotReady and admission stays off; SYSTEM's default descriptor is not a fallback.

At the actual callback, copy/validate the CREATE's SecurityContext.AccessState.SecurityDescriptor into bounded owned canonical
buffers outside global locks and compare it with the original version's immutable assigned descriptor. Require exact owner/group,
ordered DACL/SACL ACEs, mandatory labels and the inheritance/control semantics; null, partial or unmatched input refuses forwarding.
Do not keep the caller's descriptor pointer in the permit. Retain the original canonical descriptor and callback-owned copy through
post-CREATE, query the actual object's complete security and compare again before admitting writes. A mismatch cancels exposure
and retains exact cleanup facts. This is equality validation on the original CREATE, not synthetic privileged descriptor injection.
The service receives no WRITE_DAC, WRITE_OWNER or ACCESS_SYSTEM_SECURITY temporary-handle grant. This internal CREATE does
not substitute its SYSTEM rights for the original writer's required native destination checks. A missing/unrepresentable descriptor
or any descriptor mismatch keeps publication disabled; do not copy the private staging ACL onto a public file.

These fixed access/options are a contract to validate with the native control before implementation is activated, following
Microsoft's [NtCreateFile contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatefile).
The native control checks granted access exactly and the queried I/O mode **0x2A**; FILE_NON_DIRECTORY_FILE and
FILE_OPEN_REPARSE_POINT are CREATE options outside the queried
[FILE_MODE_INFORMATION subset](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_mode_information).
It separately verifies that the created file is regular and non-reparse.

### One-way data fence

Only the authenticated original service process can use noncached writes, exact EOF/allocation resize and flush on the captured
temporary FILE_OBJECT. Every admitted write/resize owns a local rundown reference and counter until its actual postoperation,
including cancellation or draining completion. Deny Fast I/O/MDL bypasses, mappings, paging writes, EAs, links, reparses, security
changes and other mutators on that object. These checks also apply to duplicated/inherited handles from other processes.

Before arming RenamePermit, atomically set the record's **DataFenced** bit under its local lock. Admission tests that same bit
while taking the I/O reference, so an operation is either already counted or refused. This transition is irreversible for the
attempt, including failure, disconnect and replay. Reject new writes/resizes; drain already admitted I/O outside all namespace,
spin and journal locks. Do not wait in the FilterPort receive loop. Once counts reach zero, requery the exact object's EOF/full ID
and complete a lower-stack flush, retaining its actual status. Only exact measured EOF/identity and successful completed flush
permit rename. Recheck the one-way fence and zero counts at the actual rename callback; no reconnect can reopen write authority.
The still-open renamed handle is limited to queries, flush and close, so it cannot change the public bytes.

Revoke permanently disables rename and uses the same fence/drain. For a proven uncommitted temporary only, its original DELETE
grant permits one ordinary delete disposition on that exact original FILE_OBJECT, under the authenticated creator. Reserve its
cleanup nonce/operation in the record before forwarding, capture the actual result and last cleanup, and retain them in Facts.
Never grant this cleanup if rename was accepted or its result is unknown. Exact cleanup may not reopen a leaf substitute.

### Rename target check and namespace gate

The service's head turn serializes all cooperating publication/delete operations, but is not by itself a kernel namespace gate.
When arming rename, reserve the destination's root/parent/full-ID/case/leaf key in the driver. Every supported protected namespace
mutation must consult that gate: temporary/public creates, replacement/rename/link, native disposition and its delayed cleanup.
An already accepted deletion or unresolved operation keeps the name unavailable; do not arm this rename over it. Changes to the
root/parent anchors, their case mode or reparse state invalidate the attempt before forwarding. No legacy path bypasses the gate.

At the actual original rename callback, hold that reservation, identify the real destination parent from the rooted operation,
recheck root/mount/parent/source full IDs and case, and perform complete anchored leaf enumeration. Compare the observed full
target identity or absence with ExpectedPublicIdentity. A partial enumeration is unknown; any changed target refuses forwarding.
The gate remains held through NTFS completion and durable outcome acknowledgement, so no admitted competing mutation can occur
between this comparison and native rename. Existing pending native cleanup must have reconciled before the grant; reader-only
opens do not grant a mutation. A normalized path from
[FltGetDestinationFileNameInformation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetdestinationfilenameinformation)
is a locator, not proof of target identity. Keep source/target observations and actual native result separately in Facts.

No target FILE_OBJECT reference or second application handle may prevent service cleanup. Short callback/I/O references have explicit
owners; remove non-owning lookup keys before CLOSE/address reuse. Pins on original private versions, callbacks, RPCs and uncertain
temporary cleanup veto voluntary unload. Mandatory teardown drains local work without waiting for service ACK, preserving durable
uncertainty; its complete lifetime integration is reviewed once before first boot.

## Concrete feature-only transport

Reserve control **33**, extension **26**, separate from the core/v19/v20/V23/V24/V25 parsers. Core Control stays version 18, 16 bytes.
Fixed request is **960 bytes, pack 4**, including zero-filled UTF-16 tails:

| Offset | Field | Bytes |
| ---: | --- | ---: |
| 0 | Core Control | 16 |
| 16 | ExtensionVersion, Phase | 8 |
| 24 | TransferId, DriverInstanceId, PermitNonce, CreateNonce, OperationId | 80 |
| 104 | DestinationGeneration | 8 |
| 112 | MountManagerVolumeId | 16 |
| 128 | VolumeRootIdentity, ParentIdentity, StageIdentity, TemporaryIdentity, ExpectedPublicIdentity | 120 |
| 248 | MeasuredLength, ExpectedLatestPublished, ExpectedCommittedDelete, ExpectedMaxAllocated | 32 |
| 280 | Flags, ParentCaseSensitive, DestinationLeafBytes, TemporaryLeafBytes (uint16 each) | 8 |
| 288 | InspectedDigest | 32 |
| 320 | DestinationLeaf (256 UTF-16 characters) | 512 |
| 832 | TemporaryLeaf (64 UTF-16 characters) | 128 |

Phases are CreatePermit=1, RenamePermit=2, Revoke=3, read-only Facts=4 and CleanupAck=5; these are ephemeral control operations,
not persisted journal states. The fixed 128-byte mutation/ACK reply has a 16-byte version/size/phase/reserved header, the five GUIDs, generation, current connection epoch and authority
revision, then a typed result and reserved zero field. Only exact transport success plus Prepared permits forwarding. Consumed,
revoked, expired, unknown or result-only replies cannot grant or renew authority. Facts uses the separate fixed format below;
the 128-byte reply is never interpreted as execution facts.
Typed results are Prepared=1, Consumed=2, Revoked=3, Acknowledged=4, Unknown=5, Rejected=6 and NotReady=7. Prepared is valid only
for Create/Rename; Revoke never returns Prepared, and CleanupAck never returns a forwarding grant. A mutation reply echoes its
exact request IDs/generation; CleanupAck echoes the original Create request IDs/generation and the pinned current connection epoch.

Require nonempty distinct attempt/operation/nonces, positive generation, valid digest/length, exact leaf boundaries and no streams,
wildcards, dot components or reparse/portable/network scope. Zero expected public identity means observed absence; it is independent
of seeding. Create has zero temporary identity and PermitNonce=CreateNonce; rename supplies its fresh nonce plus the driver's captured
temporary identity. Flags encode only expected-public-presence; every reserved bit/field/tail and all phase-irrelevant fields are zero.
Normal builds omit this transport and retain existing ABI/enum numbers.
Revoke identifies the immutable Create tuple with PermitNonce=CreateNonce, preserving its request fields except phase and the
captured temporary identity when known. It cannot renew an earlier Rename. Before the native cleanup, the driver allocates the
exact cleanup nonce/operation; the service reads them in Facts and durably records the cleanup intent before issuing disposition.

### Authenticated Facts replay

Facts request is **64 bytes, pack 4**: Control at 0 (16), ExtensionVersion/Phase at 16 (8), expected DriverInstanceId at 24 (16),
ConnectionEpoch at 40 (8), SnapshotRevision at 48 (8), StartIndex at 56 (4), Reserved at 60 (4). The initial index-zero request
may use zero expected driver/epoch/revision; all continuation and final-check requests pin the returned nonzero tuple. Phase is 4.
Only the exact authenticated current service connection may read; startup can read before admission. The rows identify the original
creator even after reconnect; a current header does not silently transfer a creator's execution authority.

Page header is **64 bytes**: version/size at 0 (8), driver at 8 (16), current epoch at 24 (8), revision at 32 (8), boot sequence at
40 (4), StartIndex at 44 (4), Count at 48 (4), Complete at 52 (4), Reserved at 56 (8). Eight **2112-byte** rows follow; fixed page
size is **16960 bytes**. The simultaneous map bound is 1024 retained attempts, not a per-boot counter. Reject before forwarding
when no slot can be reserved; never evict unacknowledged execution/cleanup facts. A retired slot can be reused.

| Row offset | Field | Bytes |
| ---: | --- | ---: |
| 0 | Immutable CreatePermit request | 960 |
| 960 | Immutable RenamePermit request; all zero until armed | 960 |
| 1920 | Original service PID, session ID | 8 |
| 1928 | Original process creation time, connection epoch | 16 |
| 1944 | Actual captured temporary identity | 24 |
| 1968 | Actual pre-forward target identity; zero for proven absence | 24 |
| 1992 | EOF observed after data drain | 8 |
| 2000 | Actual CREATE IoStatus.Information | 8 |
| 2008 | Facts flags (uint64) | 8 |
| 2016 | Actual CREATE, identity query, flush, rename, target query, cleanup NTSTATUS (int32 each) | 24 |
| 2040 | Teardown reason, in-flight writes, in-flight mutators, original boot sequence (uint32 each) | 16 |
| 2056 | Cleanup operation ID, cleanup nonce | 32 |
| 2088 | Reserved, zero | 24 |

Facts bits, in ascending bit order, are CreateConsumed, CreateForwarded, CreateNotForwarded, CreateResultKnown,
CreateAccepted, TemporaryIdentityKnown, DataFenced, DataDrained, FlushResultKnown, FlushSucceeded, RenameArmed, RenameConsumed,
RenameForwarded, RenameNotForwarded, RenameResultKnown, RenameAccepted, TargetObservationKnown, TargetAbsent, CleanupArmed,
CleanupForwarded, CleanupNotForwarded, CleanupResultKnown, CleanupAccepted, LastCleanup, CoverageLost, CallbackOwned.
All higher bits are reserved zero. Unobserved status/information/identity fields are zero; zero status alone never proves success.
Identity/observation proof bits are distinct from raw query status: an executed failed or positive-indeterminate query retains its
actual status without asserting identity/observation proof. Unproved identity fields remain zero. CreateAccepted requires a known
final nonpending native result and FILE_CREATED; identity must be separately known. A query failure never grants rename or proves
absence. Complete directory enumeration can retain native STATUS_NO_MORE_FILES with TargetObservationKnown; that completion has
no success meaning for CREATE/rename/flush. DataDrained requires DataFenced and zero counts. FlushSucceeded requires a known successful final result and
drained data. Rename forwarding requires the immutable armed rename, spent grant, checked actual target and successful fence/flush.
Forwarded and NotForwarded are mutually exclusive for each operation. NotForwarded is affirmative kernel evidence, not a missing row.
CoverageLost precludes inferring last cleanup. No kernel pointer, handle or token is exported.

Each map mutation increments its nonzero global revision, including consuming grants, callbacks, counts, result/identity capture,
fence/flush, cleanup and retirement. Copy each page under the map lock into bounded allocated output; hold no map lock across I/O.
Pagination pins driver/epoch/boot/revision and monotonically advances StartIndex. Nonfinal pages have exactly eight rows; an explicit
Complete page ends the snapshot, followed by an empty Complete check at the resulting index with the identical tuple. Unused rows,
reserved fields and tails are zero. Duplicate attempt/nonces, impossible flag/status combinations, short pages, revision change,
missing final marker or map-bound overflow invalidate the whole snapshot. Stale/truncated/incomplete replay remains **unknown**:
retain PendingCommit and all holds. Absence from a verified complete unchanged snapshot is useful only with a previously retained
exact terminal receipt and the later ACK-removal rule; it is never a lost-operation success receipt.

### Cleanup acknowledgement

CleanupAck is a separate **64-byte** request: Control (16), ExtensionVersion/Phase (8, phase 5), DriverInstanceId (16 at 24),
CreateNonce (16 at 40), ExpectedReplayRevision (8 at 56). It is available to the current authenticated service only. The service
first persists the exact terminal native outcome and required cleanup/publication result, then ACKs the pinned record. The kernel
requires that revision, matching driver/attempt and locally proven terminal facts: no callback/RPC/admitted I/O, no unknown native
result and either original temporary last cleanup, affirmative never-forwarded CREATE, or a final consistent failed CREATE proving
no FILE_CREATED outcome and no acquired temporary identity. For the last branch, persist the exact failure status and
IoStatus.Information before ACK; collision/FILE_EXISTS is not an accepted temporary. A malformed status/information pair, success
without FILE_CREATED, reparse/indeterminate completion or any possibly acquired temporary remains unknown and cannot retire.
An accepted rename is not canceled by ACK.
Remove non-owning object keys before the record can retire. Reply echoes the record's immutable IDs/generation and current
epoch/authority revision; an exact successful ACK is not permission to reuse any spent CREATE/rename grant.

The service retains the durable receipt until later complete authenticated replay at a greater revision proves record removal.
Lost ACK/reply is retried as an acknowledgement only, never as CREATE/rename. Missing receipt or ambiguous removal preserves the
hold and generation floors. Forced coverage loss remains subject to the existing fixed-NTFS owner exception and startup proof.

## Durable outcomes and recovery

Use the existing Approved/Publishing/Released states and PendingCommit, adding optional immutable attempt facts, not a new journal
state. Persist a unique attempt/create intent before CREATE; persist its actual temporary ID as soon as authenticated post-CREATE
facts establish it. If service loss precedes that receipt, retain the pre-CREATE tuple and kernel replay; never delete a path substitute.

Under the destination turn, persist exact rename operation, expected old identity, temporary identity, length/digest and generation.
Native success records Published in the shared head before Released and before releasing that turn. Lost final manifest bookkeeping
is reconciled through the exact head/operation; it does not republish. Native failure or proven never-forwarded result can release
only that intent and clean the exact temporary. Unknown outcome retains the barrier. Revocation/disconnect cannot erase execution
facts or cancel an accepted rename. Reconnect/startup reconciles exact intent, authenticated kernel facts and anchored name identity;
path absence, digest alone, a PID, clock or a new driver GUID cannot replace outcome/lifetime proof.

Persist immutable actual CREATE status/information, captured temporary identity, rename status/forwarding, target observation and
cleanup facts with the attempt before reducing the outcome to the head's existing committed Boolean. Preserve accepted native
success without rewriting it after bookkeeping failure. STATUS_PENDING is not a final outcome. An unavailable final result keeps
PendingCommit; only exact native facts and the existing qualified lifetime/anchored-state recovery can resolve it.

Retire operation/cleanup receipts only after durable exact acknowledgements and later authenticated replay. Preserve maxAllocated,
Published and committed-delete floors. Missing/ambiguous identity retains the existing named hold and diagnostics; no manual
recovery or new failure policy is introduced. Read-only native holds may release only after this shared recovery is integrated.

## Required qualification

- [x] Independent Luna security-design review before transport code: READY WITH CORRECTIONS above; failed-CREATE retirement and
  descriptor equality mechanism are part of the approved contract. Separate writer/security and boot prerequisites remain open.
- [ ] Connect publisher, journal/head, parent-relative I/O, driver permits and startup together; keep capability off throughout.
  - [ ] Test empty/clean/CPF, newer allocated/blocked versus Published, stale/duplicate/short replies, wrong IDs/case/volume/subject,
    create/rename/result loss, cancellation and service restart at each durable boundary, exact orphan cleanup and no post-rename write.
- [ ] Four WDK 0/0 profiles, agent matrix and the single integrated kernel lifetime review before changed boot.
- [ ] Protected forced orders, real Notepad in all modes, independent byte observers, Verifier and separate restoration.

## Implementation note — increment 5

The feature-only kernel implementation is `SafeUpload.Minifilter/StageBoundPublication.c`, with kernel-only declarations in
`StageBoundPublicationInternal.h`. Control 33 is connected through the authenticated service-SID dispatch. V18, V23 and V26
published layouts are unchanged. This is a **gated source implementation, not positive publication qualification**. The global
bound capability remains NotReady, and no build, component execution or VM boot was performed for this working-tree increment.
The independent Sol 6.1 xhigh review conditionally accepted the gated mechanics after correction of filename pageability,
namespace bypass/rundown, teardown installation, query provenance, cleanup/unwind, app-share lifetime and shared enumeration-cursor
issues. That working-tree review does not replace the final coherent pre-boot review or qualification of matched artifacts.

Create preparation reserves capacity before allocating a zeroed nonpaged record and before any original filesystem operation.
The map plus concurrent factories cannot exceed 1,024 records. A dedicated local worker prepares metadata or drains/flushes;
the port callback never waits for that worker or sends a service request. Initial preparation returns NotReady; identical polling
can only return the record's current result. Refusal produces affirmative CreateConsumed/CreateNotForwarded, with zero native
status/information and no invented NTFS result. Capacity exhaustion is a failed transport. Changing an existing nonce's immutable
request, including generation, is rejected. Every consume, result, fence/count transition and removal advances the replay revision.

V26 OriginalSessionId describes the authenticated **service creator**, not the staged application's effective subject. Capture it
with documented [SeQueryInformationToken(TokenSessionId)](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-sequeryinformationtoken)
on the exact referenced service process primary token already retained by the record. The original unimpersonated service CREATE
must present that same token and the same queried session. Both queries run at PASSIVE_LEVEL outside BpLock and free their
caller-owned paged result buffers on every exit. Query failure cannot become a session-zero fact or a prepared permit: initial
failure unwinds the private record/capacity, and callback failure refuses forwarding. Session metadata alone is never authority;
the referenced process, token, authenticated connection and current revision checks remain required.

Orchestrator feedback build `t5-inc5a` of `d8ed0291` reported two case-flag C4389 errors and an undeclared process-session API.
The correction uses ULONG expected case flags and the documented token query above. The owner's `0f2cacd3` ProbeForWrite convention
and previousIdentity initialization are preserved. This correction has source checks only; its WDK/PREfast/ApiValidator rerun is
outstanding, and the draft's agent matrix was still running when this feedback was received.

The descriptor constructor remains unproved. `SafeUploadStagePublicCheckWriterSecurity` keeps the existing
`publication_security_not_equivalent` / `native_create_security_unproved` refusals. The implementation does not strip control
bits, protect a replacement DACL, post-set security, inject AccessState or turn SYSTEM access into caller authority. Callback
validation captures a bounded canonical descriptor before forwarding, compares every stored byte/control semantic, and retains
the copy through post-CREATE. The native result is recorded before any subsequent exposure cancellation.

There is a second explicit activation prerequisite: **live version publication authority after application cleanup is not yet
implemented or qualified**. The version retains a closed writer evidence shell, not the application's open native lease. Owned
CLEANUP closes the original data handle and all snapshot/lookup handles outside namespace/stream resources, then publishes
PublicationEvidenceClosed. This preserves native sharing and does not keep a public target reference alive. Immutable subject,
security and identity evidence survives until version retirement; closed metadata is never reopened as authority. The separate,
never-enabled PublicationAuthorityProved gate prevents a future descriptor fix alone from activating this route. A later corrected
version authority must validate captured rights/current policy after Save-and-close or app exit without requiring the app to stay
alive. This prerequisite is distinct from the implemented permit/fence/receipt mechanics.

### Ownership and local retirement

| Owner / resource | Acquire or transfer | Release / failure path |
| --- | --- | --- |
| Permit record, immutable CREATE/rename/Facts | `BpMutation`: capacity slot precedes nonpaged allocation; map owns one Uses reference | Exact revision ACK plus `BpTerminal`, or mandatory local terminal drain; `BpDestroy` outside BpLock |
| Exact service process and primary token | Record allocation references process/token; port separately pins authenticated sender | Record destruction dereferences both; port pin released on every control exit; reconnect never transfers creator authority |
| Closed writer evidence shell | Owned CLEANUP transfers first bound writer to version; closes backend before EvidenceClosed | `StageFreeStream`, or mandatory version-owner release after callback drain; additional app leases close normally |
| Private version and borrowed evidence pointer | `SafeUploadStagePublicationAcquireSource` increments RpcReferences under NamespaceResource | Partial-failure unwind / `BpDestroy` calls ReleaseSource outside BpLock; no free while pinned |
| Source instance, root/parent metadata references, construction/stored buffers | Dormant qualified source acquisition takes explicit refs and bounded copies before Prepared | ReleaseSource unwinds each partial acquisition and zeroes the source; no public target/temporary handle is retained |
| Temporary FILE_OBJECT lookup key | Original pre-CREATE installs **non-owning** key; post-CREATE proves actual identity | Remove before original CLOSE/address reuse; exact failed CREATE removes it; teardown removal marks CoverageLost, never last cleanup |
| Short temporary I/O reference | Worker references the exact object under BpLock after data drain | Dereferenced outside BpLock after EOF/identity query and lower-stack flush; worker Uses prevents ACK meanwhile |
| Callback, queued work and worker reference | Same-lock admission takes Uses/Callbacks before forwarding; enqueue takes worker Uses | Actual postoperation (including cancellation/draining) and worker completion; CallbackOwned includes queued/working state |
| CREATE security capture | Bounded allocation and validation outside spin lock; transfer to record only before forwarding | Failure frees/zeros outputs; record destruction frees retained capture |
| Directory enumeration cursor exclusion | BpObserve takes backend operation rundown and the same lease Revalidating gate used by ancestor validation | Allocation failure/all normal enumeration exits release both; concurrent use refuses instead of restarting a shared cursor |
| Namespace reservation | Immutable full mount/root/parent/case/leaf key stored before rename preparation | Held through native completion and terminal ACK; no timeout, disconnect or failed bookkeeping releases an uncertain reservation |

Voluntary unload vetoes records, factories and sticky namespace coverage loss. Mandatory teardown closes admission, revokes/fences,
joins local work and drains terminal records before stage RpcReferences are awaited. It does not wait for service ACK. Missing local
lifetime evidence, including CoverageLost, is not erased to make teardown finish. Completed real CLEANUP proves handle lifetime
even when NTFS returns an error; it does not prove deletion. Ordinary CLOSE alone is insufficient. A canceled never-exposed CREATE
requires exact cancellation/no-handle evidence and known temporary identity. Indeterminate positive native completions remain held.

### Lock order and fence argument

| Lock / boundary | Ordering and protected facts |
| --- | --- |
| BpLock | Record map/revision, Uses, callback/I/O counts, consume bits, DataFenced and namespace reservation; no allocation, waits or filesystem I/O |
| NativeLock → BpLock | Native reserve/forward checks publication exclusion; publication calls NativePublicationIdle only after dropping BpLock |
| BpLock → StageAttachLock; BpLock → protocol state → connection state | Retirement and current authority checks; teardown/reset release their earlier locks before revoking publication records |
| EpochLock | Existing tokens cover prior namespace callbacks, including pending CREATE ownership transfer; quiescence samples current and all draining epochs after reservation installation; never held on entry to BpLock |
| NamespaceResource / stream resource | Source lookup takes a version pin, then drops resources before backend validation; no path takes BpLock while holding these resources |
| PASSIVE worker / callback validation | Directory/identity/security queries, descriptor capture, flush and all waits run outside the above locks and outside callback-needed resources |

Write/EOF/allocation admission checks DataFenced and increments its rundown count in the same BpLock acquisition used to set the
fence. Therefore every mutation is either already counted or refused. The bit is never cleared, including revoke, failed rename,
disconnect and replay. Noncached writes have explicit bounded sector-aligned offsets; bounded final-sector padding is allowed only
before an exact measured EOF resize. Real postoperations decrement the corresponding counts. Draining completion records coverage
loss rather than manufacturing a completed mutation. Zero counts permit a short object pin, exact EOF/full-ID query and lower-stack
flush on the local worker; actual flush status is retained separately from later validation errors. Original rename forwarding
rechecks the permanent fence, zero counts, exact target, original actor/current authority and reservation. Fast I/O, MDL, mapping,
paging, alternate mutators and other-process duplicate-handle writes are refused. A successfully renamed open handle cannot write
or resize; only queries, flush and lifetime operations remain usable.

The first implementation conservatively excludes **all namespace mutations on the reserved instance**, while retaining the full
destination key; it does not claim fine-grained parallelism. Matched V26 CREATE/disposition/rename operations also consult other
reservations, and CREATE rechecks before forwarding. Arming refuses another live publication object/callback on that instance.
Native records, including pending DELETE/cleanup, block preparation and cannot reserve/forward behind the gate. Existing epoch
tokens drain previously admitted generic mutations; SET_SECURITY and FILE_SYSTEM_CONTROL now participate. An uncounted admission
or draining completion latches namespace uncertainty, revokes permits and vetoes voluntary unload. A later zero-count scan cannot
clear it. Shared durable generation-head/delete integration remains increment 7; conservative exclusion is not that integration.

Facts pages are zeroed bounded copies, with exact authenticated driver/epoch/boot/revision pagination and a final empty check.
Identity/target native query statuses are separate from local validation statuses. Complete target enumeration retains its actual
terminal STATUS_NO_MORE_FILES (0x80000006); the decoder accepts that value only as an enumeration completion when observation is
explicitly known. It never constitutes CREATE/rename/flush success. Failed or indeterminate queries without identity/observation
proof cannot authorize publication. A lost ACK reply is reconciled using the retained durable terminal receipt and a later complete
snapshot at a greater revision; no physical operation is repeated. New transport controls cover refused permits, stale generation,
bounds/revision/epoch changes, ACK loss, native query provenance and indeterminate outcomes; normal-build controls check that the
feature API is absent. These controls have not been executed in this increment.

### Before activation and increment 6

Required native controls remain: full descriptor construction/stored equality (including both 0x8C04→0x8804 counterexamples),
creator-only grants and read-denied callers; exact 0x00110082 grant/0x0020006A options and mode 0x2A; app cleanup/share release and
app-exit version authority; original CREATE failure/cancellation/exposure-cancel status and Information; queued/canceled writes,
EOF/padding/flush versus fencing; duplicate/mapped/paging/MDL/Fast-I/O denial; rename target/ancestor/case/volume races and delayed
delete cleanup; lost replies/reconnect/revision ACK; startup unwind, voluntary veto, forced instance teardown and local rundown.
All four WDK/PREfast/ApiValidator profiles, the full agent matrix and the coherent pre-boot review remain required. No current
product-VM stop is relaxed by this implementation or its source review.

Increment 6 must use the V26 client with exact persisted CREATE intent before attempting the original parent-relative CREATE,
then authenticated Facts for the actual native result/temporary ID. Only an exact Prepared response can forward once. Persist
the immutable rename/head intent under the destination turn before requesting the fence; preserve PendingCommit on uncertain
results. Publish the shared head before Released, reconcile completed mutations instead of republishing, and use the original
temporary object for permitted cleanup. Persist terminal native receipts before ACK, retain them until later complete replay
proves removal, and keep generation floors. Descriptor bytes must come from the corrected metadata channel, not this permit
transport. Keep all positive behavior off until descriptor, live-version authority and remaining integration gates are proved.

## Implementation note — increment 6

2026-10-13, working-tree agent implementation on `wt/t5-inc6`; requested base
`d8ed029179ed57df4498952263df1da07c20ab99`, HEAD at hand-off `c3616acf6d09ccc4494b8ec5b08e0fc77ea89b0e`
(the intervening commit contains kernel-only warning fixes, preserved untouched). **Not built, executed or qualified in this increment.**
The orchestrator owns the complete normal/feature × Debug/Release agent matrix. No commit, kernel change or VM boot was made.
`_stageBoundHeadReady` remains false; the real V26 CreatePermit prerequisites remain NotReady. Installing the feature dispatcher
in service composition does not activate it: its live-operation readiness predicate is that unchanged flag. Increment 10 still
owns positive readiness composition. The native implementation below is a dormant consumer of the reviewed contract, not proof
that descriptor construction or post-application-close publication authority works.

`StagedTransferPublisher.PublishCoreAsync` shares its existing snapshot/extraction, measured seal/digest, current-policy,
justification and option-1 export gates with bound entries. Only the physical publisher branches. A bound entry without its
feature dispatcher is explicitly refused; no bound path calls the legacy path permit, pathname CREATE, pathname rename or orphan
`File.Delete`. Existing bound attempts are routed to bookkeeping before any new inspection. Clean/empty content uses the same
ordinary path; blocked/export-restricted versions retain the existing Failed/no-export/no-justification behavior.

`StagedBoundPublicationDispatcher` persists a new immutable CREATE tuple before asking V26 for permission. Identical NotReady
polls use a monotonic two-second development deadline; a lost control reply goes to Facts recovery. Neither polling nor a saved
intent is authority to execute. Only an exact Prepared reply permits one original operation in that live invocation. All retry
and restart entry points query/reconcile receipts and cannot issue CREATE, rename or cleanup. The caller releases the private
snapshot and stage leases after copying the inspected bytes, before waiting for the destination physical turn. The anchored
parent and original temporary handle remain held.

`StagedBoundPublicationNative` uses the recorded fixed-NTFS volume/root/parent and the captured construction descriptor in original
NtCreateFile: access `0x00110082`, share 0, disposition FILE_CREATE, options `0x0020006A`, attributes NORMAL, no EA/allocation size.
It uses bounded aligned noncached copying, exact EOF and flush, then same-handle parent-relative NtSetInformationFile
FileRenameInformationEx with REPLACE_IF_EXISTS | POSIX_SEMANTICS. The kernel must still prove full stored security equality,
authority, one-way data fencing and native target checks. No service post-set or broader access grant was added. Service return
values do not become native execution evidence: authenticated V26 Facts supply the CREATE status/information, exact temporary
identity, rename status and cleanup facts.

| Existing state / durable evidence | Ordering and permitted next work |
| --- | --- |
| Sealed/Inspecting → Approved → Publishing | Shared inspection and policy gates; no public mutation from these states alone |
| `PublicationAttempts.CreateBase64` | Full validated 960-byte CREATE request, persisted before CreatePermit and original CREATE; failed/lost CREATE is representable without PendingCommit |
| `PublicationNativeReceipts` after CREATE | Exact 2112-byte Facts row; positive CREATE/identity plus the live original handle are required before copying |
| `PublicationAttempts.RenameBase64` + `PendingCommit` | Atomically persisted under the physical turn after rereading current generation, published/delete floors, reservations and complete anchored target observation; precedes RenamePermit/fence |
| Native rename → durable Facts | Actual status/forwarding/target/fence evidence is persisted first; unknown or positive-indeterminate native completion retains PendingCommit |
| Shared head Published | Separate write of LatestPublished/PublishedIdentity, exact result projection and the attempt's HeadPublished receipt; the same physical turn spans rename, Facts and this write |
| Publishing → Released | Dedicated exact-receipt completion after Published; generic bound Released transitions are refused; replay never regresses a newer published head |
| Failed CREATE / proven failed or never-forwarded rename | Preserve exact native result; only resolved intents are released. Original-handle cleanup requires revoke, reserved cleanup Facts and a durable cleanup intent; no cleanup of accepted/unknown rename |
| ACK obligation | Persist terminal exact facts and outcome before arming ACK. A failed attempt becomes Retained only with resolved intent and complete cleanup proof. Retain the receipt even after ACK reply loss |
| Later complete Facts replay | A greater revision, same driver/boot, nondecreasing connection and exact record absence can retire a previously armed terminal receipt. Missing receipts, stale replay or a pending intent cannot retire it |

Attempts and receipts remain optional fields on the existing destination head; no protocol or manifest state was added. The
existing 128-KiB head limit remains enforced, with reserved worst-case wire/JSON space for outstanding attempt facts before CREATE.
Compaction now pins each attempt's manifest and its existing metadata/ancestry closure until receipt removal. Named diagnostics
include `publication_permit_not_ready`, `publication_generation_changed`, `publication_policy_changed`,
`publication_create_unproved`, `publication_rename_unproved`, `publication_cleanup_unresolved`,
`publication_recovery_name_changed` and `publication_ack_removal_unproved`. An armed rename with no decisive kernel outcome
remains held even if temporary cleanup is known; ACK cannot erase the unresolved intent.

Component controls were added to the partial `StagedPublicationNativeJournalTests` in
`agente/SafeUpload.Agent.Tests/StagedBoundPublicationDispatcherTests.cs`, alongside the updated native journal fixture:

| Required case | Component control |
| --- | --- |
| Intent → permit → native → Facts → Published → Released | `Bound_order_is_intent_permit_native_facts_published_released_and_later_ack_removal` |
| Lost replies and service restart | `Lost_reply_or_restart_at_each_boundary_never_repeats_native_mutation`: 13 boundaries × reply loss/crash, fresh journal/dispatcher, unchanged native-operation counters |
| Failed CREATE, failed rename, ACK loss | `Failed_create_and_failed_rename_keep_native_status_through_ack_loss`; existing immutable-result/corrupt-projection controls retained |
| Unknown outcome | `Unknown_rename_holds_pending_commit_and_never_cleans_or_retries` |
| Stale generation/reply and disabled readiness | `Newer_allocation_during_copy_bars_stale_generation_without_publishing`; `Exact_prepared_and_service_readiness_are_both_required` |
| Policy changes | `Policy_change_while_preparing_or_after_fence_never_forwards_rename`; `Bound_publisher_uses_shared_inspection_gates_without_any_legacy_fallback` includes change during extraction |
| Newer Published successor | `Newer_published_successor_is_not_replaced_by_old_receipt_bookkeeping` |
| Delete ordering | `Accepted_delete_reservation_releases_snapshot_and_waits_without_holding_the_turn`; `Only_a_published_successor_supersedes_an_admitted_delete` covers Approved/Blocked/Published successors |
| Empty/clean/blocked/incomplete extraction | `Bound_publisher_uses_shared_inspection_gates_without_any_legacy_fallback` |
| Export restriction | `Bound_export_unproved_recovery_keeps_blocked_private_and_justification_closed`; existing option-1 hand-back/recipient/justification controls exercise the shared gates |
| No legacy bypass | `Missing_bound_dispatcher_is_an_explicit_rejection_never_a_legacy_fallback`; `Bound_released_cannot_be_written_through_the_legacy_transition` |
| Durable retention | `Unacknowledged_bound_attempt_pins_manifest_security_and_ancestry_for_compaction` |

These are unexecuted component controls with synthetic driver/native facts. They do not prove native security construction,
coherent seeded editing, protected callback ordering, data fencing, target qualification, or full service startup recovery.

**Increment 7 must connect** ordinary/native/scheduled and combined writer+DELETE operations, cancellation/tombstones and every
supported namespace mutation to this same destination head/turn and the kernel name gate. Only an already-Published successor
suppresses a prior delete; the component ordering controls do not implement those remaining native routes.

**Increment 8 must connect** startup enumeration and last-close/directory-change/reconnect triggers to the receipt-only dispatcher,
including attempts before rename and failed CREATE, exact original-object orphan cleanup and lost-lifetime/coverage recovery.
The generic startup refusal of unresolved bound Publishing/native holds remains. Recovery can finish a surviving exact accepted
rename using authenticated Facts and an anchored temporary-ID observation, or replay an already-Published head, but it cannot
invent evidence for an unarmed/unknown intent. Wire ACK retries and later-complete-replay retirement even for Released manifests,
finish broader native/publication compaction closure and audit/notification retry routing, and keep waiting/control work off the
receive loop. Final service scheduling/readiness must preserve independent destination progress while publication waits on a
delete. Full startup success, kernel prerequisites, the coherent review and later authorized native/VM qualification remain
separate conditions before increment 10 can advertise readiness.

## Implementation note — increment 10 readiness

See [T5-PREBOOT-REVIEW-PACKAGE.md](../../reviews/T5-PREBOOT-REVIEW-PACKAGE.md) for the final source composition and lifetime map.
`_stageBoundHeadReady` is now read-only and derived from `StagedBoundReadiness`, live V20 and startup recovery.
A delivered V20-only capability receipt cannot satisfy the reserved bound path. Full startup completion produces
an exact driver/connection/boot/replay receipt, separately marking any unresolved durable prerequisites; partial,
failed, invalidated or old-connection completion supplies no readiness. Disconnect, protocol/authority revision,
policy and observed replay changes invalidate the connection ticket before local joins; stale work cannot restore it.
The production snapshot always includes `native_create_security_unproved`, `seed_coherence_unproved`,
`seed_export_authority_unproved` and `version_publication_authority_unproved`, reports `bound_not_ready:` with all
blockers, and therefore remains NotReady even with successful negotiation/recovery/coverage. The kernel selector
still returns FALSE, and the reserved capability is not advertised. Normal/feature builds, tests and pre-boot review
are pending orchestrator delivery; these source changes grant no native authority or VM authorization.
