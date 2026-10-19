# T8 concrete integration analysis

2026-10-19. Analyst: **gpt-6.1-sol, high**. Source: `62127384df75e479877725e551045f4f64e1ef9a`;
proposal `adc1fb11`, [retained independent review](t8-design-review-sol-high.md).
This is a design delta proposal, **not independent acceptance of this proposal**.
No product edits, build, VM action or native experiment was performed by this analyst.
Today's first native attempt failed before row evidence; it establishes no descriptor/grant result.
The owner's 2026-10-16 native metadata/MOTW contract and required real-app M2 result remain unchanged.

## Findings and smallest defensible direction

The existing pieces are prerequisites, not a working publication contract:

- `SafeUpload.Minifilter/StagePublic.c:1877` refuses native construction;
  `:2506` correctly closes app evidence/backend at cleanup; `:2487` still requires live backend
  observation and cannot become post-cleanup version authority by setting a boolean.
- `SafeUpload.Minifilter/StageStream.c:10831` forwards public SET_SECURITY with no inner post callback.
  The outer policy epoch (`:10938`) is useful, but no admitted-IRP count represents future cleanup or mappings.
- `SafeUpload.Minifilter/StageBoundPublication.c:354`, `:1057`, `:1128` contain an existing coarse
  per-instance reservation and an admission choke point. `:608` drains only the attempt's output;
  `Policy.c:348` samples global callback quiescence, not all public metadata owners.
- `agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs:438` still creates a default
  temporary, applies basic metadata and renames. Its journal turn at `:458` cannot exclude Windows I/O.
  `StagedMotwSnapshot.cs:9` explicitly has no live producer or publication authority.

**Recommendation:** develop exact privileged restoration as a narrow internal execution step; add a
common physical-object/name commit gate; retain the producer feasibility stop. Additional closes,
quiet intervals, oplocks or kernel counters do not establish stock-browser/Explorer transaction completion.
The first two deltas below are implementable candidates requiring controls and review. The third has
no demonstrated transparent stock integration; claiming all three blockers closed would be unsupported.

## 1. Existing-file WRITE_DATA does not become permission to construct a new file

The current proposal's blanket rejection of privileged post-setting should become an explicit exact-restore
primitive. Running output creation as the original user cannot solve the required case: that user may write
an existing non-owned file while lacking parent ADD_FILE and all security-setting rights. An access check
for creating its sibling is an extra requirement. `SeAssignSecurityEx` is a new-object security constructor;
it does not perform NTFS creation, preserve an arbitrary existing descriptor by assertion, or grant caller
rights. Its documented owner/privilege checks also matter. [Microsoft: SeAssignSecurityEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-seassignsecurityex)

Proposed `RestoreExactVersionMetadata` contract:

1. At original admission, preserve the actual caller-checked operation/grant, token, share result,
   anchored target ID, transfer/generation and operation kind. Transfer those immutable facts to a
   separate version record before closing the app/backend handles at existing cleanup. No new public
   access right is projected into the original app handle. No original backend/share reservation is retained.
2. For **existing edit/overwrite**, under the final gate capture the *current* complete target descriptor
   and native creation-time state from that exact target. The originally authorized operation permits
   changing content, not replacing a later admin ACL with an admission-time snapshot. Preserve logical
   per-app time setters/suppression separately. A changed target ID requires explicit successor/cancel
   handling; it is not automatically the same authorized target.
3. Have a dedicated kernel execution worker create/hold one inaccessible output on the same NTFS volume.
   Use a private execution subject/handle, never adjust the caller token. The finite internal grant is
   limited to output write/size/attributes, DELETE for that output's commit/cleanup, full security
   query/restore and synchronization. Do not copy the experiment's FILE_ALL_ACCESS mask into a product
   permit without reducing/reviewing it. Kernel handles never leave the worker. Service supplies exact
   sealed snapshots and intent identifiers, not an arbitrary path, descriptor or unrestricted handle.
4. After base/approved streams are written, restore the kernel-captured descriptor through one
   `BACKUP_SECURITY_INFORMATION` set on this exact private output. Bind the permitted full descriptor
   bytes/components, target/parent IDs, generation and phase in the kernel record. Query all parts and
   compare there, with the existing semantic comparator mirrored at that authority boundary. Allow only
   the already approved directional 0x0400 exception with actual moved-save provenance. Do not modify
   the public target's ACL, clear its readonly bit or give the caller WRITE_DAC/WRITE_OWNER/SACL rights.
5. Fence output changes, flush, consume one anchored commit, query exact outcome, close/revoke every
   mutating output handle before releasing the commit gate. Before-first-open isolation must survive
   the restored SD granting broad access: reserve its leaf before creation, then full ID before exposure;
   reject outsider CREATE/by-ID/ADS/link routes and any preexisting unexpected handle. Share-zero alone
   is insufficient for security-only opens. Cleanup is exact-ID/capability cleanup, never generic repair.

The [native control](../../scripts/t8/metadata-construction-native-control.md) tests this privileged-restore
candidate. A successful result would establish a bounded mechanism, not this isolation/fence or arbitrary
native equivalence. Its actual descriptors must cover non-caller owner, inherited/protected/NULL/empty
ACL, audit/label and post-rename state; target controls remain necessary. The use of privilege is internal
implementation of already-authorized write, not evidence that Windows granted the caller rename/delete
or metadata rights. In particular, an in-place writer may coexist with a reader that denies delete sharing,
while a sibling replacement may fail. Exact descriptor restore does not solve that namespace/sharing
difference. Prove that publication can wait for the conflicting lifetime under existing staged-save
semantics without reporting a false native failure or bypassing the reader; otherwise a different
publication mechanism is required. A privileged POSIX replacement must not silently discard native
share/read-only/deletion refusals.

For **new/copy-fallback** operations, construct the expected native descriptor under the captured effective
subject, same destination parent and original CREATE SD/EA inputs, with a caller-checked native creation
probe/semantic object before exposing success; do not use SYSTEM creation defaults. Creator grants belong
to that original CREATE result, including cases where its descriptor prevents reopening. The exact-restore
primitive can materialize that proven descriptor later. Parent changes before commit require native
reconstruction under the same captured subject and fence; they cannot be normalized away.

For **app temporary replacement**, record successful logical CREATE/disposition and subsequent
rename/security/basic-information operations, exact participating objects and native flags. A temp filename
or app name cannot select the rule. The experiment's ordinary rename fixture is not ReplaceFile/Office
proof. Obtain traces for each required Office workflow, establish its actual native metadata result on
same-caller unprotected controls, then implement/review that finite operation sequence. If staged handling
currently strips a grant needed by that sequence, represent the original logical grant explicitly; never
let the private backing ACL decide it. This remains engineering work, not a new owner metadata choice.

## 2. One gate for admission, native completion and cleanup owners

Proposed record: `VersionCommit`, with immutable boot/instance/version/generation, stage and output IDs,
root/ancestor/parent IDs plus exact parent-leaf/case key, expected target ID/absence, phase, admitted callback
count, cleanup-owner count, section-owner facts, coverage status and one consumed native-result receipt.
Use `Open -> ClosingAdmission -> Draining -> Captured -> Committing -> OutcomeKnown -> Acked -> Retired`;
any coverage loss or unobserved forwarded result is a held state. No timer transitions to drained.

Place common admission before owned/native/service routing at `StageStream.c:10938`, not only inside the
bound-output path. Pre-CREATE has no stream identity yet: register a resolving admission token *before*
name/identity I/O, retain it through native post-CREATE, and validate the resulting full ID before returning
an opened object. A gate installation drains older resolving tokens; new unresolved potentially-conflicting
mutations retry/refuse until resolved. For non-CREATE use a referenced full-ID/stream binding independent
of the current name. By-ID, old, duplicate and outside-alias handles must hit the same object key.

| Operation | Ownership and completion rule |
|---|---|
| CREATE/overwrite/supersede, ADS CREATE, delete-on-close | Resolving token before dispatch; successful post records exact object, grant and cleanup obligations. Native create that can alter bytes must never be allowed first and rejected after destructive success. |
| WRITE/MDL prepare/complete, EOF/allocation/VDL/basic/disposition/rename/link, SET_SECURITY, SET_EA, mutating FSCTL | Atomically test gate and acquire admission under its lock; retain token until actual lower completion or proved not-forwarded cancellation. Unknown/unsupported classes conflict conservatively. Namespace operations check source, target and ancestor keys. SET_SECURITY needs a real inner completion route, including preopened metadata-only handles. |
| Section acquire/release; paging, mod-write, CC flush | Track acquire in-flight through result and actual section lifetime using existing C/S/SOP witnesses, not the release of a filesystem synchronization lock as proof of unmapping. Never block lower paging/flush needed to drain an existing owner; keep publication held instead. Writable/MDL ownership or sticky Unknown forbids capture. |
| CLEANUP/CLOSE | Always permit native cleanup/close progress. An owner exists from the admitted mutating open/setter until successful lower cleanup, with final time observation at the proved native boundary. Mark drain/teardown loss Unknown; do not decrement into permission. Remove non-owning FILE_OBJECT keys before address reuse; free records only after all completion/worker/lifetime references end. |

`H` currently counts write/delete opens (`StageWriters.c:14`), so it cannot stand in for this cleanup ledger.
Delayed timestamp effects need particular care: read-only access can affect LastAccess, and Microsoft only
guarantees file-time reflection when the changing handle closes. [Microsoft: File Times](https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times)
Track all relevant physical FILE_OBJECT lifetimes, including metadata-only/read observers capable of deferred
time effects, or hold when such an effect cannot be excluded. During the short final gate, a new CREATE or
read with a possible timestamp effect must also conflict/queue; calling it a reader cannot exempt it from
the timestamp proof. Existing native reads/cleanup must progress to drain. If this cannot preserve ordinary
app liveness, the proposed owner ledger is insufficient and needs a different proved time mechanism.
Do not alter LastAccess host configuration to
make the proof easy. Never fail CLEANUP/CLOSE. [Microsoft: filtering operations](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/filtering-i-o-operations-in-a-minifilter-driver)

Keep the new gate spin lock **unnested** with StageNamespaceResource, stream Resource, RegistryLock,
SectionLock, policy locks, BpLock and journal locks. Under it only inspect immutable keys/phase and adjust
references/counters. Callers acquire/drop the gate token before existing lock chains; post paths finish inner
bookkeeping and release all existing locks before retiring the token. Materialize referenced key snapshots
outside the gate lock and revalidate their revision during admission. No query, flush, native call, RPC,
allocation or wait under it. Reuse existing epoch and completion wrappers, with a new explicit composite
context rather than another undocumented pointer-tag collision.

Copy/inspect bulk bytes before the final gate. At the destination journal generation turn, atomically close
competing admission, drain old tokens/owners outside all locks, then rewalk and capture current metadata.
If known long-lived owners prevent progress before any public mutation is forwarded, abort this attempt,
release its gate and hold/retry the version; do not freeze unrelated users indefinitely. A brief coarse
per-volume resolving fence can bootstrap identity resolution, but the durable/uncertain hold must be on
exact objects/names: current `BpOtherReservation`'s volume-wide exclusion is not a suitable indefinite
uncertain-result policy. Apply current metadata to the prebuilt output, drain/validate/flush it, persist intent,
revalidate current policy/cancellation/anchors and consume one native commit. Keep exact conflicting gates
until actual result and durable acknowledgement. Known failure permits exact cleanup/reprepare; accepted
rename is bookkeeping-only recovery. Unknown retains its diagnostic/authority, never retries rename.

Required review cases include cleanup-delayed times, inherited security propagation, service-generated I/O
below this filter (the worker must explicitly participate), filter/volume teardown and natural SOP lifetime.
A global W count reaching zero or a second query immediately before rename does not replace this proof.

## 3. Stock producer completeness: unresolved feasibility, not another callback

There is an indistinguishability problem: a save with no MOTW and a download that has closed its main stream
but will write Zone.Identifier later have the same filesystem prefix. Publishing that prefix loses atomic
MOTW; waiting forever breaks ordinary-save liveness. A later Zone write treated as a successor does not
repair the first public exposure. Oplocks/locks can restrict *future access*, but cannot prove that the missing
provenance belongs to no unfinished producer operation.

Documented candidates do not fill the missing global hook:

- `IAttachmentExecute::Save` operates after a local copy exists, can alter/delete content and may attach ADS.
  An observation of Save return supplies neither before-first-write registration nor enforceable revocation
  of the producer's other handles. [Microsoft: Save](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-iattachmentexecute-save)
- `IFileOperationProgressSink` attaches to an IFileOperation instance owned/advised by its caller; it is not
  a documented system-wide subscription to stock Explorer's operations. [Microsoft: progress sink](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-ifileoperationprogresssink)
- `ICopyHook` is a folder/printer permission callback, not whole-file pre/post completion.
  [Microsoft: CopyCallback](https://learn.microsoft.com/en-us/windows/win32/api/shlobj/nf-shlobj-icopyhooka-copycallback)

These API facts do not prove no transparent mechanism can exist; they rule out asserting these mechanisms
as the solution. Next engineering artifact must identify the **installed Edge/Explorer component and exact
supported interception/extension point**, demonstrate registration before any protected mutation, and
show finalization after every attachment/stream/metadata operation with a kernel-enforced write cutoff.
A filesystem trace is useful to discover the sequence but does not establish an enforceable producer.
Do not adopt COM hijacking, arbitrary process injection or a browser extension by inference from this note.

The smallest complete cooperative implementation is a broker owning the full operation: register exact
transaction before protected writes; capture base/Zone from an exact source under mutation cutoff; run
attachment finalization against its private destination; finalize immutable manifest; revoke/drain every
writer; inspect both under current policy; write/flush both on one uncommitted output; perform the single
base rename. Wire `StagedMotwSnapshot.cs:27` only after this contract exists and reconcile its dormant
64-KiB guard with approved accounting. Unknown fields and URLs remain inspected, whole-version hand-back
keeps exact base plus Zone, and no extension-scope bypass implies approval.

A custom broker or download/copy action is **not the presently required stock-app result**. If the transparent
prototype fails and the owner elects a broker/extension/extra UI step or narrower supported clients, that is
then a concrete product-choice request: users would change how downloads/copies are initiated. Recommend
first presenting a working prototype and its exact workflow impact; do not ask to reapprove MOTW itself or
silently count safe stock refusal as successful M2 support. No new owner decision is required to continue
native construction controls, callback/lifetime design or producer discovery under existing scope.

## Delivery conditions

Before product implementation, revise the actual T8 design with the chosen restore privilege/handle masks,
wire layouts, concrete gate ownership/completion contexts, exact supported native operation rules and a
working real-producer integration; obtain independent acceptance. Review the coherent lifetime/lock delta
before qualification. Preserve every native-control failure receipt. Component passes, independent review,
real-app success and matched-pair ordinary/runtime-/boot-Verifier qualification remain distinct results.
