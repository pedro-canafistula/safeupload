# T5 voluntary unload: batch 1

Implementation scope: the owner's 2026-10-14 batch-1 decision in
[POST-MVP-PLAN.md](POST-MVP-PLAN.md), using the three-phase design at `7ae16880`.
The design reviews are [the first Sol 6.1 review](evidence/2026-10-14/t5-designs-review-sol61.md)
and [its re-review](evidence/2026-10-14/t5-designs-rereview-sol61.md).
This change implements ordinary-history retirement, the agent's completed-BLOCK dispatch fix,
and restoration veto capture. It does not establish Windows qualification.

## Basis and unchanged obligations

The three C01 restoration failures refused voluntary unload after the product case completed.
`SafeUploadStageWritersUnloadReady` required empty volume-wide registry, reservations,
transaction associations and directory-rename lists, with no global or SOP Unknown markers.
The retained observations showed roughly 230–250 registry entries on the running system,
including idle samples with zero staged streams/file objects. The source supports the
excessive history veto; the exact first runtime veto was not captured in those receipts.

That predicate exceeded [T5-DELETES section 7](T5-DELETES.md#7-unload-and-shutdown-rescope).
Registry history is an owning cache, with real instance/volume pins, but inactive history
is not unfinished staged work. Emptying it naturally cannot be an unregister prerequisite
when unregister/instance retirement is what disposes of it.

Both voluntary snapshots now check real local obligations: lifetime owners, CREATE
reservations, in-flight W and per-file rename operations, transaction association users or pending
enlistment, active directory-rename completions, tagged section callback ownership, and live
mutating-I/O spill tokens. Ordinary H/UnknownWriterCount nodes carry non-owning
FILE_OBJECT identities; quiet open handles are tracking history, not owning backend/lease
holds. Their counts do not veto, while their admission/Unknown meaning is unchanged. A table-only inactive transaction association,
an inactive registry entry, idle section pairing history, global Unknown and a diagnostic-only SOP Unknown marker do
not themselves veto. This is solely an unload predicate; it supplies no Free/Ready evidence.

Every other existing staged veto remains: bound/native/public records and factories,
including coverage-lost native records and the existing bound namespace loss veto;
policy publication, attach captures/completions, reserved/owned staged objects and sections,
allocation/attachment/lifecycle ambiguity, private-delete reservations, seal/discard/rename
RPCs and receipts, worker work, fence coverage, retained private residue, and the exact
service epoch ACK. Unresolved identities and uncertain public results remain held.

## P / Q / T lifecycle

| Phase | Admission and permitted progress | Exit |
|---|---|---|
| P — reversible preparation | Existing app/attach and Connect/Message body gates close; the authenticated service's existing bookkeeping CREATE route and exact outbound channel remain usable. Drain admitted bodies and inspect local/staged obligations. No history is retired. | A reversible veto restores only unload-owned gates. Exact cleanup may instead latch Q. |
| Q — existing quarantine | Preserve the current exact cleanup and saved epoch RequestId/nonce replay. App admission remains closed; existing cleanup, reconciliation and reconnect paths can resolve obligations. | Only exact `EPOCH_DRAINED`, the second operational snapshot and successful fence commit permit T. |
| T — committed local teardown | Publish the permanent local gate, close ports and owned holds, join producers and drain actual local lifetimes. Retire local history; never issue service cleanup/epoch RPCs. | Unregister and free after source/rundown barriers. No veto, rollback or admission reopen is allowed. |

No wire layout, capability, op17 result or agent epoch state is changed. In particular,
**post-ACK veto behavior is unchanged**: a failed second snapshot or fence commit remains
quarantined and uses the existing callback/worker retry path. Q is not durable retirement.
Only successful preparation reaches T, in `SafeUploadUnload` after `PrepareUnload(FALSE)`.

Mandatory teardown enters T directly. It never calls PrepareUnload or the epoch drain,
and does not invent a service receipt. The historical `MandatoryTeardownActive`,
`BeginMandatoryTeardown` and `DrainMandatoryTeardown` API names now also describe the
common committed voluntary path; the flag records local permanence, not ACK authority.

## Local ownership and source barriers

The orchestration in [Filter.c](SafeUpload.Minifilter/Filter.c) follows these rules:

1. Publish the permanent gate before closing ports. Deny fresh CREATE/attach, registry
   insertion/enlistment/rename, section creation and reclaim ownership. SyncTypeOther
   synchronization remains available for existing cache/paging draining. Already-admitted
   completion/CLEANUP/CLOSE/paging paths retain their references and can finish.
2. Close ports early to wake pending sends. Close list-owned activation anchors before
   channel/worker waits they could prevent, and close driver-owned public backend handles.
   The anchor insertion fence also rejects a worker-taken anchor's attempted reinsertion.
3. Drain communication and channel users. Join attach/stage/admission workers; cancel the
   stage retry timer and flush queued DPCs before unloading the image. Drain fence,
   bound/native/public owners, staged objects, callbacks and paging lifetimes using the
   existing local teardown. A pacing delay only requests another check; it grants no authority.
4. `SafeUploadStageWritersRetireHistory` joins direct directory-rename completions outside
   locks. Deferred rename workers were joined through ChannelRundown. Purge only records
   already marked Abandoned after their tracking loss was published. Retire all instances'
   ordinary registry history through the existing instance helper, using NULL as the
   all-instances selector only in T. Reservations stay owned by post-create/cancel callbacks.
5. Association retirement unlinks the table reference, publishes its tracking-terminal wake
   and releases that reference outside RegistryLock. Notification/enlistment users keep
   their own references. This does not assert that the Windows transaction committed.
6. Registry retirement unlinks and marks each entry retired under RegistryLock, copies and
   nulls each instance/volume pin once, then releases the pins and history reference outside
   the lock. Contexts, nodes and completions keep their independent entry references.
7. AcquirePending/ReleasePending distinguish tagged callback ownership from residual section
   pairing history. Reserve acquire ownership at preoperation, relinquish it at successful
   or draining postoperation, and remove the slot only on the existing exact failed acquire
   or successful non-draining release after both tagged callbacks relinquish ownership.
   If release completes before acquire postoperation, ReleaseCompleted defers the remove
   until acquire postoperation ends; a failed acquire concurrent with an owning release
   sets AcquireFailed and defers removal until that release ends. Release preparation
   cannot retake either terminal marker. The last callback transfers the slot reference
   into a local pointer and releases it outside SectionLock.
   A draining release relinquishes callback ownership
   but retains its slot and sticky loss. No timer expires either owner.
   Drop idle SOP map references without declaring a natural lifetime end. Preserve live
   spill-token maps and **all tagged section slots** through `FltUnregisterFilter`. Instance
   teardown start alone is not a completion-source barrier and may not zero/reuse those slots.
8. After unregister and communication callback rundown, set Filter to NULL and call
   `SafeUploadStageWritersFinishTeardown`: assert reservations/associations/history/rename
   lists drained, purge abandoned rename records, then drop residual SOP/section pairing
   references outside SectionLock. `Uninitialize` asserts the compact pool is fully returned
   and retains its defensive refusal to free a live pool if that invariant fails.

Teardown context cleanup publishes Invalid, never synthetic Ended. Unknown remains sticky
and authoritative throughout attachment. Destroying a representation after permanent
withdrawal/source barriers is not a policy transition and does not admit a save.

Lock orders stay `NamespaceResource -> stream Resource -> StageListLock`,
`RegistryLock -> SectionLock`, and `NativeLock -> AttachLock`. No lock spans port close,
RPC, file I/O, flush/purge, worker join or rundown wait. New direct spin-lock bodies and
DISPATCH/APC destructors are resident; PASSIVE orchestration is explicitly annotated.
WDK/PREfast must verify these properties on the builder.

## Agent dispatch and retry contract

[RCA defect (1)](evidence/2026-10-14/m2t5purgeattr1-agent-loop-rca-sol61.md) is agent-only.
A completed BLOCK requires StageDeleted, no cleanup-start/pending rename, Verified hand-back,
a closed justification window, and a matching blocked-deletion receipt: transfer,
destination generation, full stage identity, committed rename count, length and digest.
It leaves pending dispatch while its manifest, receipt and namespace tombstones remain.
StageDeleted or absence alone never supplies that proof.

The pending projection may reuse a cached terminal bound snapshot solely to omit dispatch.
Fresh direct reads and destination/authority scans retain bound ancestry validation.
Completed cleanup-only snapshots also make queued recovery/cleanup visits perform no per-entry I/O.
Explicit bound-publication receipt recovery remains a separate obligation and bypasses that idle shortcut.
Historical receipt source/target and tombstone names use lexical canonical-path validation,
without GetFullPath's Windows short-name expansion. Current names, authorization and
mutation continue through the existing live path and exact object checks.

All genuinely unfinished BLOCK and justified-Released cleanup now goes through the existing
serialized recovery dispatcher. Its retry state is per transfer: monotonic deadlines of
250 ms, 500 ms, 1, 2, 4 and at most 8 seconds. Unfinished last-close/persistence/evidence
work arms it; completion clears it. No delay is awaited under the journal gate. A skipped
retry does no per-entry work; reconnect/restart reconstructs durable work without authorizing
publication or deletion from elapsed time. A new publisher has no carried-over retry state.
The internal timestamp provider permits deterministic component tests; production uses
Stopwatch. Completed receipt adoption racing a stale queued snapshot is safe because an
idle shortcut grants no mutation authority; any unfinished attempt rereads durable state.

Bound-publication receipts and justified-Released private-stage cleanup own separate
retry state, with the same bounded monotonic deadlines. Explicit receipt dispatch checks
exact publication Facts and ACK bookkeeping; a retained attempt arms its receipt retry
even without a diagnostic. The live Released/Verified cleanup route bypasses receipt
reconciliation and uses its own deadline. An ACK failure or an eight-second receipt wait
cannot suppress eligible exact private cleanup; last close can finish cleanup first.
Cleanup completion clears only its local retry and never retires a publication attempt.
Receipt retirement still requires the existing later exact replay. Neither retry invokes
publication. Full interrupted hand-back recovery still restores Verified notification and
justification progress, while the live cleanup-only route does not repeat that progress.

## Restoration diagnostic

If no service-connected unload attempt succeeds, `driver-with-service` stops the restarted
agent, invokes the feature inspector's `--writer-state-status` through the existing helper
in direct mode, and records `driver-unload-veto-status.txt` before later restoration unloads.
This captures lastUnloadVeto/status and registry counters without a stopped agent proxy.
The original attempt receipt and every restoration assertion remain. Diagnostic failure
is recorded; an unload refusal still fails restoration. Source is ASCII without BOM and
must pass the Windows PowerShell 5.1 gate before a real row.

## Deferred work and required verification

Durable R/E epoch retirement, op17 extension, retirement-only storage/reconnect and refusal
receipt reclamation are deferred. The re-review found no complete retirement storage route,
authentication/bootstrap contract or approved permanent-refusal policy. Batch 1 preserves
existing charged receipts and recoverable Q behavior. Retained-unexposed private residue
continues to veto under the conservative owner default.

Late-load/reload hardening is deferred separately. Runtime-Verifier rows currently use
`fltmc load` and the demand-start trust path; changing that behavior changes qualification
and needs its own owner decision. This implementation neither changes that path nor claims
reload hardening. Batch 2 contains exact seal/op15/exposure/refusal work and negotiated
per-version driver-delete receipts; RCA defect (2) cannot be solved by an absent-file catch.

The source controls replace only the historical-empty veto expectation, retaining every
existing test name. They check both snapshots, ACK-before-T, common no-return teardown,
exactly-once pin/table reference release, callback-owned reservations/slots, anchor fences,
sticky Unknown/Invalid, resident spin bodies and timer/worker shutdown. Adversarial mutations
must fail these properties. Agent controls cover all eight actor patterns, terminal receipt
mismatches, repeated idle dispatch, bounded last-close retry, requester exit, old-name reuse,
rename receipt/tombstone replay and service restart/same-epoch reconnect.

Run the local four-profile compile, every `scripts/t5/*.py` control and required-test preflight.
These are diagnostic source/compile checks. Still required before a boot: fresh independent
Sol 6.1 xhigh review, four WDK/PREfast/ApiValidator 0/0 builds, the complete Windows agent
matrix and Windows PowerShell 5.1 parsing/native signature gate. On the matched pair,
qualify idle/C01 unload with nonzero ordinary history, all real staged/native/callback vetoes,
quarantine/replay and post-ACK failure behavior, ordinary/runtime-Verifier/boot-Verifier,
independent bytes and separate restoration on win10-debug3. Successful unload requires
exit 0 and filter absence, final destructor/pool evidence and no surviving image work.
