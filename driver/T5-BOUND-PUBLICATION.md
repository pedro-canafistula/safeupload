# T5 bound publication: concrete integration contract

2026-10-12. Proposal for the next shared-head integration, following the reviewed
[allocation/publication contract](T5-NATIVE-PUBLIC-OPENS.md#allocation-and-publication-integration--reviewed-contract).
No capability activation or changed-driver boot is authorized by this note. No owner policy changes are proposed.

**Review status: REVISE before permit transport.** Luna 6 max found three unresolved contract requirements: complete authenticated
execution-facts replay with pagination/revision and native results; a one-way temporary-write fence that rejects new mutators and
drains admitted I/O; and actual rename-time target identity/absence validation. Define the accepted temporary CREATE access/share/
options/security mask as part of that fence. The proposal below is not approved for implementation; record the corrections here
before continuing its existing design review. The [direction review](evidence/2026-10-12/m2-progress-direction-review.md) records
the current integration checkpoint. The unreadable-seed owner choice remains separate.

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
   is unproven. Persist the exact head intent first. Recheck actual source/destination parent anchors and case semantics before
   atomically consuming once. Forward the original same-volume parent-relative POSIX replace operation; do not synthesize a SYSTEM
   operation on a different file object. Record the actual NTSTATUS. A repeated grant/query is never permission to execute again.

Only the authenticated service process can use the temporary's noncached write/resize/flush authority. Bind it to the actual
FILE_OBJECT, not its path, and forbid mappings, paging writes, reparse/link/other namespace operations. End data-write authority
before releasing rename to NTFS so its still-open handle cannot subsequently alter the public file. Permit identity/digest is
inspection evidence from the trusted service, not a new bypass for application writers. Metadata/security must preserve the
qualified original CREATE descriptor, mandatory labels and agreed T10 semantics; SYSTEM's abilities confer no extra caller right.

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

Phases are CreatePermit=1, RenamePermit=2, Revoke=3 and read-only Facts=4; these are ephemeral control operations, not persisted
journal states. The fixed 128-byte reply has a 16-byte version/size/phase/reserved header, the five GUIDs, generation, current connection epoch and authority
revision, then a typed result and reserved zero field. Only exact transport success plus Prepared permits forwarding. Consumed,
revoked, expired, unknown or result-only replies cannot grant or renew authority. Facts exposes accepted IDs/results through a
separately sized authenticated replay, with explicit packing/bounds/zero-tail checks; it is available during startup before activation.

Require nonempty distinct attempt/operation/nonces, positive generation, valid digest/length, exact leaf boundaries and no streams,
wildcards, dot components or reparse/portable/network scope. Zero expected public identity means observed absence; it is independent
of seeding. Create has zero temporary identity and PermitNonce=CreateNonce; rename supplies its fresh nonce plus the driver's captured
temporary identity. Flags encode only expected-public-presence; every reserved bit/field/tail and all phase-irrelevant fields are zero.
Normal builds omit this transport and retain existing ABI/enum numbers.

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

Retire operation/cleanup receipts only after durable exact acknowledgements and later authenticated replay. Preserve maxAllocated,
Published and committed-delete floors. Missing/ambiguous identity retains the existing named hold and diagnostics; no manual
recovery or new failure policy is introduced. Read-only native holds may release only after this shared recovery is integrated.

## Required qualification

- [ ] Independent Luna security-design review before implementing the new permit transport.
- [ ] Connect publisher, journal/head, parent-relative I/O, driver permits and startup together; keep capability off throughout.
  - [ ] Test empty/clean/CPF, newer allocated/blocked versus Published, stale/duplicate/short replies, wrong IDs/case/volume/subject,
    create/rename/result loss, cancellation and service restart at each durable boundary, exact orphan cleanup and no post-rename write.
- [ ] Four WDK 0/0 profiles, agent matrix and the single integrated kernel lifetime review before changed boot.
- [ ] Protected forced orders, real Notepad in all modes, independent byte observers, Verifier and separate restoration.
