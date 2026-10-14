# T5 voluntary unload: RCA and joint retirement design

**Revised against `7ae168804698ebd01ada4570694abfa88efb985f`, 2026-10-14.** Incorporates the independent Sol 6.1 xhigh REVISE receipt `t5-designs-review-sol61.md`. This revision is unreviewed. Read-only; no edits, builds, tests or VM actions.

The kernel/agent interception source remains unchanged from `1db2d9fe`. Wire, attachment/seal recovery and residue custody are specified in [T5-RECOVERY-HOLDS.md](T5-RECOVERY-HOLDS.md). Both notes define the same op17/unload states.

## 1. Verified RCA and remaining vetoes

**The excessive empty-history predicate is confirmed in source; the exact first veto in the three failed runs remains inferred.** Approved [T5 section 7](T5-DELETES.md#7-unload-and-shutdown-rescope) requires outstanding staged/local/durable obligations to finish. The driver additionally requires machine-wide writer history to disappear naturally.

`SafeUploadStageWritersUnloadReady()` requires empty registry, reservation, transaction-association and directory-rename lists, zero owners/global Unknown/Unknown SOP markers. `a27defd8` installed it in both voluntary snapshots. First-snapshot failure selects **STAGE_OBJECTS=4 / STATUS_DEVICE_BUSY**. See [StageWriters.c](SafeUpload.Minifilter/StageWriters.c), lines 6051–6064, and [StageStream.c](SafeUpload.Minifilter/StageStream.c), lines 7547 and 7784.

The original audit’s retained raw receipts report:

- unload refusal in all three restoration receipts;
- `m2t5oc1`: 119 failed attempts, 0.5–119.2 seconds, `AgentRestarted=True`;
- trial idle-reclaim registry entries: 225, 224 and 222;
- `m2t5boot15-samples.jsonl`: 228–250 entries, including 245 idle and 241 after purge, with zero staged streams/file objects at those final samples.

These support the blocker, without proving every live-volume case or identifying the first runtime branch absent `LastUnloadVeto`. Stopped-agent attempts independently fail protocol readiness. The kernel subtree matches `cdfdb396`; agent interception matches `18e07a90`.

Registry entries own instance/volume pins. Destruction and instance retirement release them; `SafeUploadStageWritersUninitialize()` retains an incompletely returned compact pool as a lifetime defect. This defensive condition does not prove these runs leaked that pool; observed histories were in the name tier. See [StageWriters.c](SafeUpload.Minifilter/StageWriters.c), lines 979, 3930 and 6860.

Current veto inventory, before the proposed phase-specific corrections:

| Condition | Source | Recorded reason |
|---|---|---:|
| Bound records/factories or `BpNamespaceUnknown` | `StageStream.c:7466`; `StageBoundPublication.c:1465` | 3 — STAGE_DRAIN |
| Native factories/records/disposition capability, including coverage loss | `StageStream.c:7470`; `StageNativeRecords.c:1416` | 3 |
| Public factories/readers/backends | `StageStream.c:7475`; `StagePublic.c:159` | 4 — STAGE_OBJECTS |
| Closing communication or failed five-second body drain | `StageStream.c:7499`; `Communication.c:781,1285` | 3 |
| Fence/final scan entries, skipped coverage or failed scan | `StageStream.c:7515`; `StageFence.c:1692` | 2 — FENCE |
| Reconciliation/protocol/drain-replay prerequisites | `StageStream.c:7535–7545` | 7 — STAGE_DISCARD |
| Policy quiescence, writer predicate, attach/capture counts | `StageStream.c:7547`; `Policy.c:344` | 4 |
| Reserved streams/global FILE_OBJECT count | `StageStream.c:7555–7566` | 4 |
| Attachment pending/fence/retirement/lifecycle ambiguity | `StageStream.c:7574–7583` | 4 |
| Rename work | `StageStream.c:7588` | 6 — STAGE_RENAME |
| Per-stream FILE_OBJECT | `StageStream.c:7595` | 4 |
| Discard/op19/seal/allocation/RPC/reference work | `StageStream.c:7600–7618` | 7 |
| Exact unattached cleanup needed | `StageStream.c:7620,7662` | 7; cleanup quarantine |
| Unsealed/discard/private-delete/backing/drain obligation | `StageStream.c:7625–7654` | 7 |
| Worker/sweep/exit-ring/overflow/retry work | `StageStream.c:7682`, predicate `417` | 7 |
| Nonce/epoch exchange or non-`EPOCH_DRAINED` | `StageStream.c:7713–7741` | 3 |
| Post-ACK policy/writer recheck | `StageStream.c:7757` | 4 |
| Final fence commit | `StageStream.c:7766`; `StageFence.c:1634` | 5 — FENCE_COMMIT |

Constants are in [Protocol.h](SafeUpload.Minifilter/Protocol.h), lines 1484–1491. Feature unload does not veto merely for a connected inspector ([Filter.c](SafeUpload.Minifilter/Filter.c), line 445). `LastUnloadStatus` retains helper status; the operator receives `STATUS_FLT_DO_NOT_DETACH`. The common veto recorder may overwrite an earlier reason.

Replace empty-history readiness with an operational predicate proving no live operation can create/change an obligation after fencing. Keep actual stages, receipts, public/native capabilities, uncertain results, active reservations/renames, callbacks and owners as vetoes.

Ordinary history, inactive associations and standalone diagnostic Unknown are disposable only during committed destruction. Unknown remains authoritative while attached; never clear it to admit saves, manufacture `Ended`, or interpret unload as publication/deletion completion. An empty bound map’s namespace-loss flag is likewise not an owner; actual unresolved bound/native records and the approved coverage-loss veto remain.

## 2. Joint op17 / voluntary-unload state machine

The exact extension-29 op17 request/reply and required mask `0xFBF` are in [recovery section 5](T5-RECOVERY-HOLDS.md#5-accounting-and-the-joint-op17unload-contract). Existing `EPOCH_DRAINED` cannot substitute for new `EpochRetired`.

| State | Allowed work and transition |
|---|---|
| **P — Reversible preparation** | Close unload-owned admission, drain control bodies and inspect operational/durable obligations; op17 preflight is nonterminal. Veto may restore only unload-owned gates and exact prior work. No Unknown clear. If cleanup may commit, enter Q. If every prerequisite is proved, freeze final op17 and enter R. |
| **Q — Cleanup quarantine** | App admission stays closed. Complete only already-identified exact cleanup/bookkeeping, required service-private bookkeeping CREATE and current-channel reconciliation needed for it. Recheck all obligations, including retained residue. No epoch retirement yet. Then enter R; no rollback to P. |
| **R — Retirement-only** | Permanently fence every ordinary sender/authority path and drain previously admitted uses. Only the saved final op17 request/replay and necessary local draining are allowed. Agent closes epoch admission, drains prior continuations and audits terminal/absent obligations. No return to P/Q. |
| **E — Epoch retired, local commit pending** | Exact `EpochRetired` adopted. Keep all fences. Final operational recheck/fence commit may veto, but leaves E and local-drain-only progress; no ordinary RPC/reconciliation or service bookkeeping CREATE resumes. Once checks pass, enter T without a new epoch request. |
| **T — Committed local teardown** | Common permanent teardown: close ports/owned holds, join workers, drain actual users, release instance pins, unregister and free after source barriers. No veto/rollback/reopen; genuine lifetime waits may be unbounded. |

Op17 ProofFlags=0 performs a pre-retirement audit and returns nonterminal `EpochReady` or a named blocker. Include service custody inventory and default retained-residue veto before selecting R. Final ProofFlags=`0xF` and immutable request attest permanently closed admission, drained producers/prior sends/local lifetimes. The agent separately proves continuation quiescence.

Persist agent `Retiring` with exact request before asynchronous drain, then `EpochRetired` with request/nonce/driver/boot/revision/quiescence evidence. Reply adoption checks complete original request echo, legal result, nonzero durable receipt, exact identifiers/zeros and current authenticated connection/authority.

- `EpochReady` authorizes no retirement/reclamation.
- `EpochRetired` moves R→E and never restores ordinary authority.
- Held/EpochBusy, retryable, DENY, malformed, timeout or lost reply in R retain **R**. Only final immutable op17 may replay; local events/operator retries can inspect/drain. Unexpected missing obligations remain held.
- A post-ACK veto retains E; only local recheck/drain/fence commit proceeds.
- Reconnect in R/E authenticates retirement-only transport. No op11, capability activation, startup recovery or full stream sweep. Only saved final op17/reply can cross it; unsupported peers fail closed.
- Mandatory teardown bypasses P/Q/op17, enters service-independent permanent local draining and fabricates no epoch receipt.

### Required correction to existing retry paths

Current [StageStream.c](SafeUpload.Minifilter/StageStream.c), lines 7735–7740, 7757–7773 and 7793–7801, enables `StageUnloadPrepareWork` and reopens callback admission after failed epoch/post-ACK checks. Preserve that behavior only where appropriate to **Q**, not R/E.

Introduce explicit monotonic phase checks in rollback, veto, connection notifications, worker dispatch, collectors and common transports. P alone can reopen reversible gates. R/E may open a narrow **local-release-only** callback route for genuine CLEANUP/CLOSE/completions, never general Message/CREATE/bookkeeping admission. A disconnect, fresh channel, queued worker batch, stale DPC or second unload attempt cannot lower phase.

An E veto can return `DO_NOT_DETACH` while the filter remains permanently fenced. The operator sees a named local-drain/fence blocker and can retry unload; continued saving is not silently resumed. After T, no path returns a veto.

### Sender and agent closure

Before R, finish/quiesce all kernel allocation/follow-up/recovery, attach 12–16/18/op19, seal, rename, discard, op23, private cancellation, native/public disposition/facts, publication/metadata/observation/Facts/ACK controls, epoch reconciliation, legacy/advisory sends and canary/fence/activation/reclaim producers. Enforce at collection and common communication/control entry; a batch collected before R cannot send after it.

The agent gate covers inline/deferred handlers, startup/private/native recovery, destination-turn waiters, inspection/publication, native controls, discard/BLOCK/released cleanup, hand-back and justification work that can authorize/mutate. Quiesce work requiring new conversation before R; then drain previously admitted bodies/I/O/recording without repeating completed mutations. Cancel is not join; op17 waits outside journal locks and the receive loop and excludes its own coordinator from the drain.

Only the exact final op17 gets a retirement transport pin in R/E. Necessary local release/drain retains existing references; no new remote work starts. The receive loop can deliver retirement replies without granting ordinary staging readiness.

## 3. Retained residue and recovery obligations

**Owner-recorded conservative default:** proved retained never-exposed residue still vetoes voluntary unload and epoch retirement. Keep the agent’s terminal-and-absent predicate ([StagedTransferJournal.cs](../agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs), lines 114–124). Drained kernel shell memory, zero stage counters and durable service custody do not meet it.

Op23 may release the abandoned application name and drained shell after exact custody acknowledgement, while retaining a bounded charged epoch residue ticket. Reconstruct it from validated custody inventory before preflight. Missing custody gives `retained_unexposed_custody_unproved`; confirmed residue gives `retained_unexposed_blocks_unload`. No automatic delete/seal/seed/export/publication. Restart establishes lifetime evidence only; retained bytes and their charges do not thereby qualify for retirement.

Users can retry their failed save, but idle voluntary unload remains refused until separately authorized exact cleanup or an approved exception resolves this obligation.

**Recommended narrow exception — NOT implemented until owner approval:** accept only proved never-exposed, fully drained residue with exact immutable service custody; protected complete bytes/metadata; durable reconstructed charges; retained ancestry/security/provenance and generation floors; no app/native/section/callback/lookup producer; no pending public/cleanup/uncertain mutation; permanent nonpublication/nonseeding and unchanged export policy. Op17 must audit/include custody, and receipt retirement must preserve custody storage/dependencies. Kernel dependency release transfers responsibility to durable service ownership. No automatic deletion or exposure/coverage-loss exception.

Under that option, operators could unload while the retained bytes remain service-private and consume charged storage. Until approved, the default veto applies to every retirement audit.

Lost seal/op15/receipt-storage failures remain obligations until exact resolution. Seal intent is atomic with `SealPending` and used by every entry point; exited-owner sealing uses historical binding plus genuine op19/drain. Fresh op15 needs live original authority. Current policy controls inspection/publication.

`HandleLifecycleRequired` is nonterminal unless its exact success-return/real-cleanup attestation qualifies for the specified attachment bookkeeping transition. Canceled CREATE reaching CLOSE without CLEANUP retains `attach_canceled_close_lifetime_unproved`; no fabricated op19, seal or deletion. Coverage loss retains its named hold. See [recovery section 4](T5-RECOVERY-HOLDS.md#4-op15-and-complete-exposure-recovery).

Receipt reclamation requires durable exact epoch retirement and quiescence, never reply transmission, elapsed time or restart alone. Preserve retirement history before epoch replacement and keep all floors/custody accounting. Default retained residue blocks reclamation of its epoch’s receipts.

## 4. Committed local retirement and lock constraints

Generalize existing mandatory local-teardown helpers for T, preserving entry differences: voluntary reaches T only after exact retirement, final operational recheck and fence commit; mandatory never performs service-dependent preflight. Voluntary must not call mandatory teardown to bypass receipts.

| Resource | Required local retirement |
|---|---|
| Registry histories/instance-volume pins | Unlink/retire under RegistryLock, detach pointers, release pins outside lock and drop history ownership. Contexts/completions retain their own references. |
| CREATE reservations | Finish through actual owner postoperation/draining/cancel path; never free callback-carried or transferred ownership (`StageWriters.c:1806`). |
| Transaction associations | Reuse instance-retirement unlink/wake/table-ref release (`:3897`); notification users retain references. No invented transaction commit. |
| Directory renames | Join ordinary/deferred completion; purge only abandoned records with existing tracking-loss evidence (`:820,2212,2239`). Add final empty/drain postcondition; instance retirement alone does not sweep them. |
| Activation anchors | Block reinsertion; close list-owned holds before dependent waits, join worker-taken anchors. Destroy releases object/handle/instance/entry (`:5883,6030`). SOP witnesses own no FILE_OBJECT. |
| SOP maps/history/witnesses | Drop map/history references after authority withdrawal; context teardown invalidates witnesses (`:2922`). Never force `Ended`. |
| Section slots/tagged completions | Keep callback ownership; no bulk zero/reuse while tagged pointers survive. Audit teardown detachment (`:3596`) against exact source/drain barrier. |
| Staged/native/public objects | Close owned holds, drain actual callback/object/section/paging owners, release stream instance pins before unregister (`StageStream.c:7344,7809`). Remove contexts and prove destructor completion before shared storage free. |

Existing mandatory teardown supplies close-before-wait, communication/channel drain, worker joins and staged/native/public drains. Registry retirement occurs in instance teardown. **Do not wait for registry history to empty before invoking its retirement source.** See [Filter.c](SafeUpload.Minifilter/Filter.c), line 478, and [StageWriters.c](SafeUpload.Minifilter/StageWriters.c), line 1400.

The unregister/context and communication-callback source-barrier inference at `Filter.c:575–582` remains an independent/runtime condition; unregister does not waive local completion references.

Orchestration is PASSIVE. Preserve namespace → stream Resource → StageListLock, RegistryLock → SectionLock and NativeLock → AttachLock. Take anchor/backend locks separately; detach under lock, destroy outside. No resource/push/spin lock spans RPC, port close, I/O, flush/purge, worker join or rundown wait. Spin-lock and APC/DISPATCH release bodies remain nonpaged, including PASSIVE-entry routines holding spin locks.

Service-private bookkeeping CREATE is allowed only in the necessary P/Q preparation route, **closed before R**. T rejects new ownership; genuine CLEANUP/CLOSE/paging/releases remain admitted. Join every producer/batch, cancel timers and flush DPCs before code/storage release; reuse the stage timer shutdown (`StageStream.c:7214`). R/E wakes cannot resurrect ordinary work.

## 5. Reload and interim restoration

### Reload remains fail-closed

Late mounted-volume attachment starts PENDING_REBOOT in boot mode or UNTRUSTED_FLAGS in demand mode (`Context.c:343`). Canary promotes only newly mounted setup flags (`StageAdmission.c:1010`); strict destination admission requires trust/canary and no writer loss (`Context.c:505`).

However, registry `Start` supplies `BootStartMode` (`BootPolicy.c:332`), demand diagnostics bypass `SafeUploadInstanceTrustGateSatisfied` (`Context.c:490`), the unbound protected CREATE uses that helper (`StageStream.c:8193`), and global Unknown is image-local.

Do not claim all reload routes already preserve protection loss. Product feature routes must reject late/missing-history attachment regardless of `Start`; remove the diagnostic shortcut from protected authorization. Reconstruct missing-history loss on every late eligible fixed-NTFS attachment for the rest of that boot. Scan/reconnect/canary/GUID/reload cannot restore coverage; full Restart remains the remedy. Normal builds and unsupported destinations retain their gates.

Operators can unload idle ordinary history under this design, but stages/recovery/residue still veto. Successful unload disables protection; reload cannot resume protected saves before fresh restart coverage. Preserve service-stop prohibition (`Filter.c:192`). Demand-reload authorization would need a separate owner decision and is not recommended.

### Reboot restoration is not live-unload evidence

The existing [restoration helper](scripts/StagedTestAgent.ps1), line 259, preserves a refused loaded image under an owned renamed path, durably installs hash-verified original bytes and requires reboot. Reuse it; do not overwrite mapped bytes in place.

Retain failed raw-cell receipts, restore demand start/original bytes, stop owned actors/agent, reset Verifier and full Restart. Defer absent-filter cleanup until reboot. Require original hashes, filter absence, stopped agent, service configuration/ACL/state restoration, then independent baseline/disposable-overlay/base/XML verification.

This preserves final restoration, not live voluntary unload. Explicit harness handling must move the checkpoint; do not suppress failure or report restoration success before reboot. Preserve all three failures and unchanged raw-byte assertions. Reboot restoration cannot pass the unload lifecycle gate.

## 6. Controls and delivery evidence

- Operational predicates allow idle ordinary history but reject each real stage/receipt/residue/callback/owner. Catch unconditional-ready, missing owner/reservation guards, missing second snapshot and teardown before exact retirement.
- State tests cover P rollback, Q cleanup quarantine, R request/reply loss, E post-ACK policy/fence veto, reconnect/second unload/stale DPC/collected batches, and T no-veto behavior. Catch any R/E ordinary RPC, op11, bookkeeping CREATE, capability activation or worker reopen.
- Agent tests cover every inline/deferred/startup/publisher/cleanup waiter at retirement entry; canceled tasks must actually drain. Retired epochs cannot reallocate after refusal reclamation.
- Default retained residue vetoes even after shell release/restart; owner option cannot activate inadvertently. Verify custody/accounting/ancestry corruption and no deletion/publication.
- Seal tests require atomic exact request at `SealPending`, all resume entry points and exited-owner historical binding. Exposure tests cover success/failure/cleanup order, missing completion evidence and cancellation-CLOSE named hold without synthetic op19.
- Local retirement catches missing/double refs, retained associations, anchor reinsertion, active reservation/tagged-slot free, forced `Ended`, Unknown clear, PAGE/spin violations and timer/work after unload. Replace the empty-history expectation in [teardown-participation-selfcheck.py](scripts/t5/teardown-participation-selfcheck.py), line 140, with operational/retirement properties.
- Reload tests catch demand bypass, Start spoofing, late-canary promotion and scan/reconnect/reload recovery.
- Matched-pair idle/C01 unload must run with **nonzero registry history**, plus stage/native/callback/residue veto and phase-specific retry cases. Capture inspector `--writer-state-status`, including LastUnloadVeto/status and all ownership counters (`Inspector/main.c:1163`; `StageWriters.c:7964`). Preserve first failure before another unload overwrites it. The current pre-retirement stopped-agent case expects reason 7; it cannot represent R/E reconnect behavior.
- Success requires exit 0 **and filter absence**, final destructor/retirement evidence, no compact-pool residue/stale work and Verifier lifetime/lock checks. Post-unload status query cannot supply vanished counters.
- Complete local/source controls, full agent matrix and four WDK/PREfast/ApiValidator/import 0/0 gates; fresh combined Sol 6.1 xhigh pre-boot review; then serial authorized ordinary/runtime-Verifier/boot-Verifier rows on `win10-debug3`, independent bytes and separate restoration. Include reload refusal/restart recovery.

These remain design requirements. No new execution or qualification occurred.
