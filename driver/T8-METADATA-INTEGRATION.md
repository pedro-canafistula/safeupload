# T8 metadata and whole-version publication integration

2026-10-17. **Proposal for independent review; no implementation or qualification claim.**
Source reviewed: `c1a3ba04902bd5b9bc72cd20b22518760fd8f58c`.
The [owner contract](POST-MVP-PLAN.md#owner-decisions),
[metadata increment](UX-METADATA.md) and [round-2 checkpoint](UX-METADATA-ROUND2.md)
remain authoritative. This is required M2 work for ordinary applications on local
fixed NTFS, including successful browser downloads and downloaded-file copies.
It does not activate V30/bound allocation, import batch-3 scope, change resource
defaults or authorize another destination. Root obtains independent review before
product implementation and the coherent kernel lifetime review before qualification.

## Defect and integration boundary

The live unbound publisher creates a service-default temporary, copies unnamed
bytes, applies three dates/ordinary attributes and renames it. It neither preserves
full native security nor excludes a concurrent authorized public metadata change.
An inventory followed by rename is insufficient. `Zone.Identifier` is refused;
the existing MOTW snapshot and full-descriptor comparator have only test callers.
Safe refusal is containment, not successful T8 browser/copy behavior.

| Current point | Required integration |
|---|---|
| [attach subject/input capture](SafeUpload.Minifilter/StageStream.c#L3440), [effective static subject](SafeUpload.Minifilter/StagePublic.c#L390) | Preserve exact operation evidence before completing original CREATE. |
| [original-subject checked open](SafeUpload.Minifilter/StagePublic.c#L1526), [full security query](SafeUpload.Minifilter/StagePublic.c#L1225), [snapshot](SafeUpload.Minifilter/StagePublic.c#L1354) | Reuse checked object/query primitives, with their missing native cases proved first. |
| [cleanup closes backend](SafeUpload.Minifilter/StagePublic.c#L2506), [cleanup transfer](SafeUpload.Minifilter/StageStream.c#L6026) | Transfer immutable evidence, not a still-open app/backend handle, into separate version authority. |
| [publication temporary](../agente/SafeUpload.Agent.Service/Interception/StagedDestinationFile.cs#L51), [apply/commit](../agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs#L438) | Replace path-only publication with the exact version/output/target contract below. |
| [journal commit](../agente/SafeUpload.Agent.Service/Interception/StagedUnboundNamespaceJournal.cs#L12) | Preserve generation/cancellation ordering; add native exclusion, not another journal-only lock. |

Line references describe the reviewed source, not stable ABI numbers. New transport
layouts and narrowly required access masks must be specified and reviewed with the
implementation; do not silently expand an existing V19/V20 layout or bound permit.

## Authority that survives application cleanup

Capture the effective subject from the original CREATE AccessState, including
impersonation level, restricted state and enabled privileges, using the existing
STATIC/EFFECTIVE_ONLY capture. Preserve original requested/granted access, shares,
disposition, options, explicit SD/EA inputs and exact rooted lookup bytes. PID/SID,
process-primary-token lookup and a private backing descriptor are not substitutes.

Create one immutable **version authority** before acknowledging attachment. Bind it
to boot/driver instance, original operation and writer identity, transfer, generation,
stage full ID, destination mount/root/parent/full leaf identity and case mode. Record
the original Windows grant/result and separately the expected native metadata rule:
new object, existing-object edit/truncate, app temporary replacement, or copy/move
fallback. An app/process name never selects that rule. Original operation evidence
and traced native operation shape select it; unsupported/unproved transformations hold.

The authority owns a referenced static subject and bounded immutable inputs/snapshots;
it owns no original app FILE_OBJECT/handle, backend open, share reservation or cached
section after application cleanup. Complete already admitted app I/O and capture its
final logical state, then close the original backend at its existing cleanup boundary.
Do not resurrect `PublicationWriterLease` as a live backend after close. The current
bound writer factory is conditional and rejects absent/create cases; it is a source
of primitives, not a ready replacement for unbound admission.

A publication attempt derives a one-use capability from that authority, the exact
sealed snapshots, current policy and current destination generation. Bind its unique
output object, phases, permitted operations and actual results. Internal service
creation/copy is execution of that restricted capability, never evidence that the
caller had a denied create, read/export, WRITE_DAC, WRITE_OWNER or SACL grant.
Keep existing seed-export decisions and recipient checks; metadata observation rights
do not license returning unreadable source bytes.

Crash/reboot cannot reconstruct the captured token from SID/PID. Persist evidence and
outcomes, but not a claim that serialized evidence is a live token. Recovery can finish
already accepted bookkeeping or exact cleanup; it may publish only with still-valid
live authority or a separately proved original-authority recovery mechanism. Missing
authority holds with a concrete remedy. Do not add an indefinite token/record leak:
release after exact terminal obligations, charge retained records/storage to existing
accounting and keep unresolved obligations explicit.

## Native metadata construction and comparison

For absent-name new files and approved cross-drive copy/move fallback, native creation
under the captured effective subject and original inputs must produce destination-parent
inheritance, owner/group, full DACL/SACL/label and creator grants. For an existing-object
edit/truncate, preserve that operation's current native descriptor and creation-time
semantics. For actual app replacement, reproduce the traced native replacement result;
do not assume ordinary rename and ReplaceFile have interchangeable metadata behavior.

Implement and prove the construction producer before connecting publication. It must
return distinct construction inputs and the expected complete stored descriptor, plus
operation-shape evidence. Query the actual created output and compare every meaningful
component/control/ordered ACE. Never treat queried stored bits as automatically valid
CREATE inputs, or use SYSTEM defaults, privilege enablement, token adjustment, arbitrary
ACL post-setting or the private stage ACL as a fallback.

**Native feasibility prerequisite:** prove new-file creator grants, inherited audit/
integrity state and replacement of an object writable by a caller who lacks parent
FILE_ADD_FILE/WRITE_OWNER/WRITE_DAC. The required in-place save must not acquire those
extra caller requirements merely because the implementation uses a new output object.
The existing `SafeUploadStagePublicCheckWriterSecurity` always refuses construction.
This design does not resolve that native mechanism by assertion; retain the refusal
until the controls establish an exact mechanism and independent review accepts it.

Wire [StagedPublicationSecurity](../agente/SafeUpload.Agent.Service/Interception/StagedPublicationSecurity.cs)
into expected-versus-actual output validation after native construction and again at
the commit fence. The optional `0x0400` set-to-clear exception requires immutable proof
of the specific native moved-file-save shape established by controls; save-as names,
hash equality, generic replacement, copy fallback or process identity are insufficient.
No reverse exception, `0x0800` exception, reordered ACEs or other normalized controls.
Equivalent validation must also be enforced at the kernel authority boundary; an agent
boolean is not proof. An unchanged complete descriptor needs no exception.

Retain the existing exact sealed creation/access/write timestamps and ordinary flags.
Apply them to the exact uncommitted output after data/streams, suppress only its own
cleanup updates, and let native rename establish publication ChangeTime. Do not replay
an old ChangeTime. Prove final times after all handles close. Honor original per-upper-
FILE_OBJECT suppression/resumption if required by app traces; the shared backing's
suppression state cannot stand in for it. Current negative-control refusal remains
explicit until that implementation exists. Readonly flags must preserve original
Windows setter/delete/share refusals; no clearing of the public object for convenience.

## Commit exclusion and revalidation

Use one short logical destination/object/ancestor reservation shared by publication,
native namespace/delete, security, basic metadata, stream/EA/storage/link/reparse
mutations. Key object routes by full identity, not just names; account for old and
duplicated handles, by-ID/outside aliases, parent/root changes and service workers.
Readers remain native. No authenticated-service-wide bypass applies.

Each mutating operation atomically checks reservation state while taking its admission
reference, then retains that reference through actual completion, including cancellation
and draining. Before capture, close admission to competing mutations and drain admitted
ones outside global/namespace/spin/journal locks. A reference counter is not evidence
that an existing writable section or delayed cleanup setter cannot mutate: account for
those owners too. An untracked mapped/paging writer, pending disposition/cleanup or
lost callback keeps the attempt held; missing lifetime evidence never times out into
permission. This is the indispensable T8 fence, not permission to activate batch 3.

Under the reservation and existing destination generation turn:

1. Revalidate stage/version/current policy, delete floor and cancellation/retarget facts.
2. Rewalk anchored parent/root and observe the exact target ID or proven absent leaf.
   Capture full SD, basic/ordinary flags, stream set, EA state, link count and unsupported
   storage/reparse state from exact objects. Query failure is not absence.
3. Compare metadata inputs with the operation's recorded native rule. A later authorized
   target/parent change invalidates stale construction. Hold/reprepare from current state
   through the same rule; never overwrite it with an old snapshot. Reinspection is required
   if content/stream/policy inputs change. A changed target ID is not automatically adopted.
4. Materialize/validate the output's approved streams and full metadata, fence its writes,
   drain them, validate exact length/IDs and flush. Persist exact attempt/rename intent.
5. Consume one original-object, anchored rename permission. Hold competing admission
   closed through actual native result and durable outcome acknowledgement. Return actual
   failure; accepted rename is never attempted twice. After commit, the service output
   handle has no continuing data/security/attribute mutation capability.

Only tracked logical reservations span these steps; no filesystem I/O/RPC under a kernel
resource or spin lock. Uncertain completion retains its reservation/diagnostic for exact
reconciliation. Expiry/disconnect cannot erase an accepted or uncertain owner. Coverage
loss uses the existing sticky Unknown behavior through reboot, not a scan-based reset.

## Whole-version MOTW and completion witness

A producer must register the exact protected transaction **before its first protected
mutation**, bind original caller/destination/version and declare whether it is an
attachment/copy with required provenance. The kernel keeps such versions private until
an authenticated completion witness and all actual writers/cleanup have drained.
An unregistered main stream cannot later be retroactively declared an attachment after
it was exposed. A producer credential alone does not grant filesystem or inspection rights.

The witness binds a producer transaction nonce, exact stage/generation/destination,
immutable stream manifest and final operation result. The producer relinquishes its
write/rename capabilities for that version when finalizing. The admission boundary
enforces that relinquishment atomically: a racing write is counted before finalization
and invalidates its manifest, or cannot touch that version. Later accepted changes use
an inspected successor version; they cannot patch a published version outside the gate.
No timer, quiet interval, first ADS close, process list, main-stream close or ordinary
rename proves this witness.

| Workflow | Defensible witness and feasibility evidence required |
|---|---|
| Browser attachment | A real integration at the component owning download/attachment finalization registers before destination creation and finalizes after its base, attachment processing and final MOTW writes are complete. It explicitly transfers the complete stream set and relinquishes the version. Trace the installed Edge build and its attachment path, including delayed/retried finalization and broker restart. A filesystem trace or observation of `IAttachmentExecute::Save` return alone is not a pre-registration or an enforceable future-write cutoff. No working stock-Edge producer is established by current source. |
| Copy/downloaded-source move fallback | The operation-owning integration registers before the destination write and supplies the exact source object plus complete base/MOTW snapshot under a source mutation cutoff/read lease. Its operation completion acknowledges all stream copies and final metadata setters, then relinquishes the destination version. Source open/ID/digest and process-correlated reads are not proof that two unrelated handles belong to one copy. Prove the actual Explorer/PowerShell/robocopy integration; current stock operations expose no demonstrated transaction witness here. |
| Ordinary save with no required MOTW | Must be distinguishable from an attachment/copy before publication by enforced registration/routing of every supported attachment/copy producer. Unknown provenance on that path holds. Do not classify solely by absence of an ADS today. |

**Feasibility stop:** the approved end-user result is unchanged. First demonstrate
transparent pre-registration/finalization on the required real browser/copy workflows.
If this requires replacing the user's download/copy action with a SafeUpload broker,
new extension, UI step or an unsupported-client refusal, that is a user-visible product
choice requiring the owner's decision before adopting it. Nothing here approves that
change. Likewise, an unproved transparent hook does not permit claiming browser success.
This is the remaining integration boundary, not a request to reapprove MOTW preservation.

Capture base and MOTW into private immutable snapshots bound to one manifest. Reuse
[StagedMotwSnapshot](../agente/SafeUpload.Agent.Service/Interception/StagedMotwSnapshot.cs)
for exact-length/EOF capture and whole-text inspection, including URLs/unknown fields.
Its current 64-KiB guard is a dormant implementation bound, not a newly approved
product default; reconcile it with approved resource/failure behavior before wiring.
Owning-file scope must require inspection of MOTW text even when `.txt` is not a monitored
extension; do not bypass policy or treat an out-of-scope result as approval. Bind both
verdicts to the same current policy. Any malformed, incomplete, unsupported or blocked
part blocks/holds the entire version with the existing owner-scoped recovery behavior.

Create both streams on the exact uncommitted output before its only base rename.
The capability admits only the exact `Zone.Identifier` stream of that output and
manifest, not arbitrary ADS. Drain/fence/flush/validate both; first public base visibility
must already include exact inspected MOTW. Other ADS, EAs, EFS/offline, reparses and
multiple hard links stay refused. Sparse/compressed saves remain held until their
approved semantic preservation and complete logical inspection are implemented.

Persist the manifest, snapshots/identities, inspection policy/results, expected metadata,
attempt, finalization receipt and native outcome with existing journal durability.
Restart retries incomplete capture/inspection/bookkeeping, never an accepted rename.
Lost finalize/rename replies reconcile exact facts. Unknown outcome retains bytes and
actionable diagnostics; path/digest matches cannot manufacture accepted publication.
Hand-back carries exact blocked base and MOTW as one owner-authorized logical result,
with the approved source read/export checks. Never release a clean-looking base while
silently dropping blocked provenance. If the recipient filesystem cannot carry that
result, retain it with a reason; do not invent a provenance-free fallback or archive.

## Native controls and implementation increments

Use same-caller unprotected controls on target 19045.2965; record actual app builds,
token/grants, original API sequence, IDs, binary metadata and final bytes after cleanup.
Builder-native results are mechanism evidence only. Preserve existing T8-M01–M11 and
T8-R2-01–08 rows; these controls add detail, not replacement assertions.

| Control | Required evidence |
|---|---|
| Construction | New/create/overwrite/supersede, existing edit and real Word/Excel/PowerPoint replacement; creator-only grants, restricted/impersonating callers, parent-create denied but existing-file-write allowed, non-caller owner, audit SACL/label, NULL/empty/protected ACL and readonly/share conflicts. Query full SD under observer rights without adding caller authority. |
| Marker eligibility | Proven moved-save expected set/actual clear passes; reverse direction, ordinary copy/new/save, changed SACL `0x0800`, RM/ACE/control/owner/label changes fail. |
| Fence races | Pause before/after reservation, drain, capture, metadata apply and rename. Use pre-opened/new/duplicated/by-ID/alias handles and a second service worker to change ACL/owner/SACL/label/dates/flags, streams/EAs/links/reparse/storage, target or ancestors. Include writable mapping and cleanup-delayed setters. Require native result or explicit hold, never stale metadata or uninspected bytes. |
| MOTW | Real Edge and downloaded-file copy/move: absent/replacement destinations, main close before deliberately delayed Zone write, CPF in base/HostUrl/ReferrerUrl/unknown field, malformed/oversized encodings, policy change, producer/service death and writes racing finalization. Independent stream/Office reopen observer must never see the new base without its inspected MOTW. |
| Outcomes | Fail each query/apply/copy/flush/rename/journal/cleanup and lose each reply. Exact accepted mutation executes once; unknown state stays held. Hand-back bytes/ADS/digest and recipient read/export authority remain exact. |
| Lifecycle/cost | App share-zero/reopen/cleanup remains native; no retained backend/section/share leak. Exercise repeated saves, service restart and existing 10k workload; account new snapshots/authority records and demonstrate unrelated-user progress under existing budget rules. |

- T8 increment 1: native construction/operation-shape feasibility controls and real
  browser/copy producer trace/prototype, without product activation. Resolve feasibility
  stops with evidence; obtain design review on the concrete mechanism.
- T8 increment 2: immutable version authority plus exact output/security capability and
  native metadata fence; connect full descriptor comparison, dates/flags and recovery.
  Keep unsupported streams held. Review the coherent kernel lifetime/lock delta.
- T8 increment 3: enforce producer registration/finalization, durable manifest, base/MOTW
  inspection, atomic publication and exact hand-back/recovery. Retain ordinary app liveness.
- T8 increment 4: feature Debug/Release WDK/PREfast/ApiValidator/import gates at 0/0,
  four-leg Windows agent matrix, applicable PS5.1 harness gates, then all required matched
  pair ordinary/runtime-/boot-Verifier rows with independent bytes and separate restoration.
  Review acceptance, component passes and final qualification remain separate results.

No native feasibility run or protected qualification was performed for this proposal.
