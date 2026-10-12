# T5 bound publication: concrete integration contract

2026-10-12. Proposal for the next shared-head integration, following the reviewed
[allocation/publication contract](T5-NATIVE-PUBLIC-OPENS.md#allocation-and-publication-integration--reviewed-contract).
No capability activation or changed-driver boot is authorized by this note. No owner policy changes are proposed.

**Review status: READY WITH CORRECTIONS, Luna 6 max, 2026-10-12.** The existing review closed its concrete Facts, write-fence,
target-check, failed-CREATE retirement and descriptor-mechanism findings. Implement this contract without granting publication
until the separate writer-metadata/security and complete recovery prerequisites are met. The unreadable-seed owner choice remains
pending; this is not activation, lifetime-review or boot sign-off. The [direction review](evidence/2026-10-12/m2-progress-direction-review.md)
records the integration checkpoint. Native-mask [PowerShell 5.1 control](evidence/2026-10-12/bound-publication-native-ab6dc0b9.txt)
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
All higher bits are reserved zero. Unknown status/information/identity fields are zero with their Known bit absent; zero status
alone never proves success. CreateAccepted requires a known final nonpending native result and FILE_CREATED; identity must be
separately known. A known failed identity/target query can retain its negative native status without asserting a successful identity/
observation; that failure never grants rename or proves absence. DataDrained requires DataFenced and zero counts. FlushSucceeded requires a known successful final result and
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
