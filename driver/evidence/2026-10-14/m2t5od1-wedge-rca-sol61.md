**Leading hypothesis: an unload veto leaves a global CREATE gate latched.** The source proves this failure mechanism; the failed receipts do not identify the triggering veto. The checked product source matches `b97d263e`; the worktree is clean. No edits, builds or VM actions performed.

The decisive code is [StageStream.c:9391](driver/SafeUpload.Minifilter/StageStream.c:9391): `StageUnloadAdmissionClosed` rejects **every CREATE reaching an attached instance**, including unprotected reads and attribute opens, with `STATUS_DEVICE_NOT_READY`, before path/scope classification. Only the authenticated agent is exempt. `StageMandatoryTeardown` removes even that exemption. This explains ordinary open failures directly; SSH resets caused by failing executable/configuration opens remain inferred.

1. **Highest: epoch-drain refusal enters quarantine and returns with admission closed.**

   Preparation closes admission at [StageStream.c:7489](driver/SafeUpload.Minifilter/StageStream.c:7489). An unsuccessful drain—including `EPOCH_BUSY`—sets `StageUnloadQuarantined`, re-enables worker/control-callback progress, but **does not reopen CREATE admission**, then returns a veto at [StageStream.c:7734](driver/SafeUpload.Minifilter/StageStream.c:7734). Exact allocation-cleanup preparation can enter the same retained state at line 7664. **Yes, `fltmc` can return while ordinary opens remain denied.**

   A concrete likely trigger is unfinished Released bookkeeping: [StagedTransferJournal.cs:116](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:116) requires both absence and `StageDeleted`. Driver-held disposal returns before setting that field at [StagedTransferPublisher.cs:502](agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs:502); restart cleanup checks the absent leaf with `GetAttributes` at [line 1011](agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs:1011), before reaching the absence-capable deletion helper.

   **Prediction:** failed drain, veto reason 3, quarantine=1, admission=1, permanent teardown=0, filter still present. This fits `od1`/`oe1` returning to the parent with inaccessible stdout. Supporting historical evidence: `oc1`’s exported `service-after-…json` has Released/`StageDeleted=false`; its 119 vetoes occurred before batch 1 allowed ordinary history past the writer predicate.

2. **Next: post-ACK writer/fence veto, compounded by broken same-connection replay.**

   Both writer snapshots—[StageStream.c:7549](driver/SafeUpload.Minifilter/StageStream.c:7549) and [line 7759](driver/SafeUpload.Minifilter/StageStream.c:7759)—use [StageWriters.c:6102](driver/SafeUpload.Minifilter/StageWriters.c:6102). It vetoes actual owners, CREATE reservations, W/rename operations, active transaction users/enlistment, directory completions, tagged section callbacks and spill tokens; ordinary history/H/sticky Unknown alone no longer veto.

   After `EPOCH_DRAINED`, a failed second snapshot or fence commit returns with quarantine/admission latched at [StageStream.c:7753](driver/SafeUpload.Minifilter/StageStream.c:7753). **Again, `fltmc` can return.**

   **Verified replay defect:** the agent clears both active and replay driver IDs after delivering the ACK at [MinifilterInterceptor.cs:525](agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:525), while its drain handler requires one at [line 948](agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:948). The driver retains exact replay authority. Consequently, a subsequent same-connection replay is denied unless reconciliation restores agent context.

   **Prediction:** durable drain receipt, first veto reason 4 or 5, then drain refusals; filter present and CREATE denied. No failed-run receipt currently proves an ACK occurred.

3. **Lower: preparation or committed teardown blocks indefinitely.**

   Fence preparation closes its gate, stops retries and waits for accepted workers; boot-start skips the filesystem scan: [StageFence.c:1692](driver/SafeUpload.Minifilter/StageFence.c:1692).

   Successful preparation newly enters permanent local teardown at [Filter.c:496](driver/SafeUpload.Minifilter/Filter.c:496). It permanently fences attach/native/public/bound producers, registry insertion, anchor reinsertion and fresh sections. Communication/channel rundown, worker joins, local stream/cache/owner drains, history retirement and paging rundown precede unregister ([Filter.c:529](driver/SafeUpload.Minifilter/Filter.c:529), [StageStream.c:7346](driver/SafeUpload.Minifilter/StageStream.c:7346), [StageWriters.c:6151](driver/SafeUpload.Minifilter/StageWriters.c:6151)). Any unresolved wait can retain global denial.

   **Prediction:** unload remains pending; permanent teardown=1 for committed waits. A blocked [FltUnregisterFilter at Filter.c:578](driver/SafeUpload.Minifilter/Filter.c:578) cannot reach this callback’s success return. Unregister removes callbacks/contexts when completed. [Microsoft contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltunregisterfilter).

   This ranks lower because the pinned parent executes `Get-Content` **after the AfterBoot child exits** ([qualification wrapper:244](driver/scripts/Invoke-StagedInvariantQualification.py:244)). A synchronous unload wedged inside that child would prevent that read.

Ordinary **pre-quarantine** vetoes explicitly restore admission: callback preflight and fence failures use [rollback at StageStream.c:7427](driver/SafeUpload.Minifilter/StageStream.c:7427). I found no permanent-teardown flag set on those returned branches. The retained quarantine gates are intentional; their unscoped CREATE effect is the problem.

**Smallest decisive diagnostic:** before restoration, preopen a diagnostic sink and preload an in-process native probe. After each unload attempt record duration, exit/output, `fltmc filters` including launch failures, and fresh unprotected Documents create/read/attribute probes with numeric errors. Flush immediately; current [loop:6638](driver/scripts/Test-StagedInvariantSuite.ps1:6638) writes attempts only afterward, when CREATE may already fail. Capture the **first** veto before another attempt overwrites it. A failed probe should stop retries and preserve state.

For a wedged-state dump, read `StageUnloadAdmissionClosed`, `StageUnloadQuarantined`, `StageMandatoryTeardown`, `StageStopping`, `StageUnloadPrepareWork`, `StageLastUnloadVeto`, saved epoch request/nonce, protocol replay state and `FenceLateControl`; inspect unload/worker stacks and whichever rundown, reservation, W, section-callback or instance reference they await.

**Fixes are evident, but unvalidated:** scope unload admission so unprotected opens continue safely; preserve exact same-connection epoch replay after ACK; finish driver-deleted Released bookkeeping from an exact deletion receipt. Blindly reopening protected admission or treating absence as deletion authority would violate the approved contract.