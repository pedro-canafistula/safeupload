# T5 voluntary unload: RCA and design

Source: `1db2d9fe`, 2026-10-14. Read-only audit; no edits, builds or VM actions.

**The hypothesis is confirmed in source, with one qualification: the exact veto branch in the three failed runs was not captured.** The driver requires machine-wide writer history to disappear before allowing voluntary unload. That exceeds the approved [T5 section 7 contract](T5-DELETES.md:464), which requires outstanding staged work and its local/durable obligations to finish.

`SafeUploadStageWritersUnloadReady()` requires empty registry, reservation, transaction-association and directory-rename lists, zero owners, zero global Unknown and zero Unknown SOP markers. `a27defd8` added this predicate to both voluntary-unload snapshots. Failure at the first snapshot sets `objectPending` and ultimately records **`STAGE_OBJECTS=4`, `STATUS_DEVICE_BUSY`**. See [StageWriters.c:6051](SafeUpload.Minifilter/StageWriters.c:6051), [StageStream.c:7547](SafeUpload.Minifilter/StageStream.c:7547) and its final veto recorder at `7784`.

The kernel subtree matches `cdfdb396`; the agent interception subtree matches `18e07a90`. The raw receipts were read from the local `driver/evidence/2026-10-14/` receipts:

- All three restoration receipts report driver-unload refusal.
- `m2t5oc1` records **119 failed attempts**, from 0.5 through 119.2 seconds, with `AgentRestarted=True`.
- The trials’ idle-reclaim observations report **225, 224 and 222 registry entries**, respectively.
- `m2t5boot15-samples.jsonl` reports **228–250 entries**, including 245 at idle and 241 after purge, with zero staged streams/file objects at those final samples.

These observations strongly support the registry blocker. They do not prove a universal impossibility theorem for every live volume, nor identify the first runtime veto without `LastUnloadVeto`. The stopped-agent attempts also have an independent protocol-readiness blocker.

Registry entries really own instance/volume references. Their destructor releases them; instance teardown explicitly nulls and releases those pins before context destruction. `SafeUploadStageWritersUninitialize()` only frees a completely returned compact pool and otherwise retains it as a lifetime defect. That is a verified defensive condition, **not evidence that these runs leaked the compact pool**; the reported retained entries were in the name tier. See [StageWriters.c:979](SafeUpload.Minifilter/StageWriters.c:979), `3930` and [6860](SafeUpload.Minifilter/StageWriters.c:6860).

**Other vetoes remain possible after C01 completes.** “Ready” and completed publication do not establish unload readiness. The following table gives the final recorded reason; veto constants are defined in `Protocol.h:1484–1491`.

| Condition | Source | `LastUnloadVeto` |
|---|---|---|
| Bound publication records/factories remain, or `BpNamespaceUnknown` is set | `StageStream.c:7466`; `StageBoundPublication.c:1465` | **3 — STAGE_DRAIN** |
| Native factory, record or future disposition capability remains, including coverage-lost records | `StageStream.c:7470`; `StageNativeRecords.c:1416` | **3** |
| Public factory, metadata reader or backend remains | `StageStream.c:7475`; `StagePublic.c:159` | **4 — STAGE_OBJECTS** |
| Communication is closing, or admitted Connect/Message bodies fail the five-second preflight drain | `StageStream.c:7499`; `Communication.c:781,1285` | **3** |
| Fence gate cannot close; demand-start final scan fails, retains entries or skips volume/reparse coverage | `StageStream.c:7515`; `StageFence.c:1692` | **2 — FENCE** |
| Reconciliation needed/in flight; protocol not ready; drain-only replay lacks the retained request/nonce | `StageStream.c:7535–7545` | **7 — STAGE_DISCARD** |
| Policy publication not quiescent; writer predicate fails; attach active/capture count nonzero | `StageStream.c:7547`; `Policy.c:344` | **4** |
| Reserved staged stream or global staged FILE_OBJECT count nonzero | `StageStream.c:7555–7566` | **4** |
| Attachment completion/fence/retirement/lifecycle ambiguity, including an allocation receipt that may have attached | `StageStream.c:7574–7583` | **4** |
| Rename exchange/pending/in-flight RPC | `StageStream.c:7588` | **6 — STAGE_RENAME** |
| Per-stream FILE_OBJECT remains | `StageStream.c:7595` | **4** |
| Discard, handle receipt, seal, allocation recovery/RPC, allocation-receipt reference or other RPC reference remains | `StageStream.c:7600–7618` | **7** |
| Allocation receipt needs exact unattached cleanup | `StageStream.c:7620,7662` | **7**; quarantine retained once cleanup is committed |
| Unsealed stage, unfinished discard, private-delete reservation, unexplained missing backing, or failed `StageDrain` | `StageStream.c:7625–7654` | **7** |
| Worker queue, sweep, owner-exit ring/overflow, fired retry or exit sweep remains | `StageStream.c:7682`; pending-work predicate `417` | **7** |
| Drain nonce creation fails; epoch exchange fails or returns other than `EPOCH_DRAINED` | `StageStream.c:7713–7741` | **3** |
| Post-epoch policy/writer recheck fails | `StageStream.c:7757` | **4** |
| Final fence commit fails: work/setup/attach/entry counts, quarantine, skipped coverage or retry state remains | `StageStream.c:7766`; `StageFence.c:1634` | **5 — FENCE_COMMIT** |

The feature path does **not** veto merely because the inspector is connected (`Filter.c:445`). `LastUnloadStatus` records the helper failure or `STATUS_DEVICE_BUSY`; the operator still receives the common `STATUS_FLT_DO_NOT_DETACH` result. The final `Veto:` recorder can overwrite an earlier reason.

**Recommended design: separate operational obligations from disposable tracking history.**

Keep outstanding stages, receipts, native/public capabilities, uncertain public results, callbacks and genuine owners as veto conditions. Replace “all writer history has naturally retired” with a predicate proving that no live local operation can create or change an obligation. Do not require ordinary registry histories, inactive transaction associations or diagnostic Unknown markers to become naturally Free before unregister.

Unknown remains authoritative while the filter is attached. Teardown may destroy its representation only after protection authority is permanently withdrawn; it must never manufacture `Ended`, clear Unknown to admit saves, or treat unload as a successful delete/publication receipt.

Use three phases:

1. **Reversible preparation.** Close the existing admission gates, drain control bodies and inspect staged/local work. A veto restores unload-owned gates and preserves the listener, workers, exact requests and retry eligibility. Active CREATE reservations and directory-rename completions remain real work, not disposable history.
2. **Existing quarantine/epoch commit.** Preserve the exact cleanup and drain replay behavior. Once cleanup may have committed or epoch drain begins, keep admission latched; lost replies replay the same request/nonce. A post-epoch veto remains quarantined.
3. **Committed local teardown.** After exact `EPOCH_DRAINED`, the final operational recheck and fence commit, enter a common permanent teardown state. Close ports, prevent new ownership/work, close owned holds, join workers and drain actual local users. From this point no path returns a veto or reopens admission. Completion may wait indefinitely for genuine lifetimes; elapsed time authorizes nothing.

The existing mandatory path supplies most of phase 3. Generalize its local-teardown predicate/helpers for both callers, while preserving the distinction: mandatory teardown never performs voluntary service-dependent preflight; voluntary teardown reaches the common path only after its obligations are resolved. Do not route voluntary unload directly into mandatory teardown to bypass receipts.

| Resource | Required retirement/release |
|---|---|
| Registry entries and instance/volume pins | Reuse instance retirement: unlink and mark retired under `RegistryLock`, detach instance/volume pointers, release pins outside the lock, then drop history ownership. Contexts and completions retain their own entry references until their destructors. |
| CREATE reservations | Finish through their owning postoperation/draining path and `SafeUploadStageWritersCancelReservation()` (`StageWriters.c:1806`). Never free a reservation still carried by a callback or transferred owner. |
| Transaction associations | Reuse instance retirement’s table unlink, terminal wake and table-reference release (`3897`). Notification users keep their references. This retires driver tracking; it does not claim the Windows transaction committed. |
| Directory renames | Join ordinary/deferred completion, then purge only abandoned records with their existing tracking-loss evidence (`820`, `2212`, `2239`). The instance-retirement helper does not itself sweep this list; add a verified empty/final-drain postcondition. |
| Activation anchors | Close list-owned anchors before waits that their own handles can prevent. Block reinsertion; join worker-taken anchors. `StageAnchorDestroy()` releases FILE_OBJECT, handle, instance and entry (`5883`); existing close-all helper is at `6030`. These are the writer ledger’s retained owning FILE_OBJECT references; SOP witnesses own none. |
| SOP maps, histories and witnesses | Drop map/history references without declaring natural lifetime completion. Context teardown marks witnesses Invalid and releases their references (`2922`). The common teardown predicate must prevent forced unload cleanup from publishing `Ended`. |
| Section slots/tagged completions | Preserve each live completion’s ownership. Do not bulk-zero/reuse slots while a callback can still carry its tagged pointer. Audit the existing teardown detacher (`3596`) together with acquire/release completions; retire residual slots only after the corresponding source/drain barrier. |
| Staged sections/backings and contexts | Reuse local staged-object drain and paging rundown; close backings and release stream instance pins before unregister (`StageStream.c:7344,7809`). Let Filter Manager remove ordinary contexts; release held context references and verify final destructor completion before freeing shared storage. |

Mandatory teardown already closes anchors/backends before dependent waits, drains communication/channel users, joins workers, drains staged/native/public owners and releases staged instance pins. Ordinary registry retirement then occurs in `InstanceTeardownStart` through `StageRegistryRetireInstance`. **Do not wait for the registry list to empty before invoking the teardown that empties it.** [Filter.c:478](SafeUpload.Minifilter/Filter.c:478), [StageWriters.c:1400](SafeUpload.Minifilter/StageWriters.c:1400).

Filter Manager documents that unregister invokes instance teardown and removes contexts. Existing I/O may still complete after teardown starts, so local completion references remain necessary. The repository’s communication-callback source-barrier inference at `Filter.c:575` remains a review/runtime condition. [Microsoft unregister contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltunregisterfilter), [instance teardown contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_instance_teardown_callback).

Apply the same ownership distinction to an empty bound map’s `BpNamespaceUnknown`: preserve the loss while attached, but a flag alone is not an outstanding owner. Any actual unresolved bound/native record remains held. Preserve the expressly approved coverage-lost native-record veto.

**Concurrency constraints are part of the fix.**

Run orchestration at **PASSIVE_LEVEL**. Preserve `NamespaceResource → stream Resource → StageListLock`, `RegistryLock → SectionLock` and the existing native producer order `NativeLock → AttachLock`. Take anchor/backend locks separately; detach owned objects under their lock and destroy them outside it. Hold no namespace/resource/push/spin lock across port close, RPC, file I/O, flush/purge, worker join or rundown wait.

Spin-lock helpers and APC/DISPATCH completion/destructor paths must stay nonpaged, even when their entry contract is PASSIVE. Keep paged anchor/name handling in PASSIVE orchestration. Require exact references after every lock drop.

During preparation, the authenticated service retains its required bookkeeping CREATE exception. Committed teardown closes that exception too. New CREATE/attach/ownership is denied; existing CLEANUP/CLOSE, paging and exact completions remain able to release references. Fence refresh/retry, reclaim, canary, attach and maintenance producers must obey the common permanent gate. Join their batches, cancel timers and flush queued DPCs before code/storage release; `StageStopWorker` already does this for the stage retry timer (`StageStream.c:7214`).

**Reload is partially protected today, but needs an explicit correction.**

Late attachment to an existing mounted volume starts `PENDING_REBOOT` in boot mode or `UNTRUSTED_FLAGS` in demand mode (`Context.c:343`). Canary success upgrades trust only for newly mounted setup flags (`StageAdmission.c:1010`); strict destination admission requires passed trust/canary and no writer loss (`Context.c:505`). Thus boot-configured `fltmc` reload on the existing fixed NTFS volume remains fail-closed.

However:

- `BootStartMode` is inferred from registry `Start`, not the actual load event (`BootPolicy.c:332`).
- `SafeUploadInstanceTrustGateSatisfied()` deliberately returns TRUE for demand-start diagnostics (`Context.c:490`), and the unbound protected CREATE path uses it (`StageStream.c:8193`).
- The global writer Unknown variable is image-local. Reload does not preserve its old numeric value.

Therefore **do not claim all reload routes already preserve protection loss**. Require feature product routes to reject late/missing-history attachment regardless of `Start`; remove the demand diagnostic shortcut from protected authorization. Latch missing-history loss for the remainder of that boot, reconstructed on every late attachment to an eligible fixed NTFS volume. A scan, service reconnect, new driver GUID or repeated reload cannot restore coverage. Full Windows Restart remains the remedy. Normal builds and unsupported destinations retain their existing gates.

Operators can then unload an idle feature driver despite ordinary Windows history. Open stages or unresolved recovery work still produce an actionable refusal. Successful unload disables protection; an update/reload cannot resume protected saves until restart establishes fresh coverage. Preserve the service-stop prohibition (`Filter.c:192`). This implements existing owner decisions; allowing protected saves after a demand reload would require a separate owner decision and is **not recommended**.

**Interaction with the parallel recovery-hold change:** lost seal ACK, op15 ambiguity/owner exit and refusal-storage failures remain unload obligations until their exact resolution. Typed refusal may resolve allocation ambiguity, but does not prove local callback retirement or authorize public mutation. Refusal receipts must retain storage accounting until durable, exact driver-epoch evidence permits retirement. Epoch drain currently checks terminal/absent transfer manifests before writing its receipt (`StagedTransferJournal.cs:81`); extend its prerequisite audit to the new receipt storage. Teardown must neither erase those holds nor repeat a completed mutation. Review and qualify the combined pair.

**Interim raw-cell restoration can use reboot, with an explicit limitation.**

The existing [restoration helper](scripts/StagedTestAgent.ps1:259) already preserves a refused loaded image under an owned renamed path, durably installs the hash-verified original bytes and requires reboot. Reuse that pattern rather than overwriting the mapped image in place.

For raw cells: retain the failure receipt, restore demand start/original bytes, stop owned actors/agent, reset Verifier and perform a full Restart. Defer cleanup requiring an absent filter until after reboot. Require the unchanged final checks: original hashes, filter absent, stopped agent, service configuration/ACL/state restoration, then separate baseline verification and disposable-overlay/base/XML checks.

This preserves the **final restoration guarantee**, but supplies **no evidence of live voluntary unload**. Moving that restoration checkpoint requires explicit harness handling; suppressing the current failure or emitting restoration success before reboot would weaken it. Preserve all three failed attempts. Raw-byte assertions remain unchanged, and reboot restoration cannot pass the unload lifecycle gate.

**Required controls and evidence before delivery:**

- Source/property controls must allow retained ordinary history with no work, but reject every live staged/receipt/owner condition. Mutations: unconditional-ready return, removed owner/reservation guard, deleted second snapshot, early teardown before epoch ACK, or rollback after commit.
- Retirement controls must catch missing/double pin release, association references retained, anchor reinsertion, freeing active reservation/section completions, forced `Ended`, Unknown clearing, PAGE placement around spin locks and timer/work surviving unload. Existing `teardown-participation-selfcheck.py:140` encodes the faulty empty-history requirement; replace that expectation with the approved obligation/retirement properties.
- Reload controls must catch demand-start trust bypass, registry-Start spoofing, canary promotion of late attachment and readiness restored by reconnect/scan/reload.
- Combined recovery controls must cover lost seal/epoch replies, op15 owner exit and typed refusal, receipt-storage exhaustion/restart accounting, and no repeated public mutation.
- On the reviewed matched pair, run idle/C01 unload with **nonzero registry history**, plus held-stage/native/callback veto and rollback cases. Capture full inspector `--writer-state-status` around failures: it exposes `lastUnloadVeto`, `lastUnloadStatus`, registry/reservation/transaction/SOP and stage counters (`Inspector/main.c:1163`; `StageWriters.c:7964`). After an agent-connected failed attempt, stop the agent and query before another unload overwrites the reason. An attempt made with the agent stopped currently expects reason **7**.
- Successful unload needs exit 0 **and filter absence**, final retirement/destructor evidence, no retained compact pool or stale driver work, and Verifier lifetime/lock checks. A status query after successful unload cannot provide those counters.
- Complete the four WDK/PREfast/ApiValidator 0/0 builds, required local/source controls and full agent matrix; obtain the combined fresh Sol 6.1 xhigh pre-boot review; then serial ordinary/runtime-Verifier/boot-Verifier rows on `win10-debug3`, independent bytes and separate restoration. Include reload refusal and restart recovery.

Source acceptance, these component controls and matched-pair qualification remain distinct. No new verification was run in this audit.