# REJECT

Reviewed `git diff 94334034 f550666b` at HEAD `f550666be3588cffda0c3858f46295f00b80d68b`. No source changes; no VM, build, or tests.

## Findings

- **P2 — P2-a’s `OpenIdentity` race is fixed, but compact ADS scan churn still becomes sticky Unknown.** In [StageWriters.c:4645](/home/victor/Work/safeupload-wt-gen3/driver/SafeUpload.Minifilter/StageWriters.c:4645), the compact-stream scan queries the opened object’s normalized name and returns `STATUS_FILE_INVALID` if its stream-suffix hash differs from the snapshotted suffix at line 4660. Concrete interleaving: a tracked compact ADS is opened and passes `StageRegistryOpenIdentity`’s final rename check; its stream rename then completes before `FltGetFileNameInformationUnsafe`, which observes the new suffix. The mismatch exits before `PublishResult` checks `RenameInFlight`/`RenameVersion` (lines 4830–4839). `StageRegistryActivationProcess` treats this failed scan as a failed probe and sets sticky `Unknown(IDENTITY)` at lines 5654–5662. The rename completion’s later probe cannot clear that sticky reason, so this normal rename can permanently withhold Ready. The new retry handling covers churn during `StageRegistryOpenIdentity`; it does not cover this post-open, pre-publication failure.

- **P2 — parked-scan reclaim churn: recorded condition, not an independent acceptance blocker.** A parked `ScopeScanPending` candidate with `T == 0` marks the worker pass unfinished and is requeued ([StageWriters.c:6120](/home/victor/Work/safeupload-wt-gen3/driver/SafeUpload.Minifilter/StageWriters.c:6120)). A rename that never completes can therefore keep the worker retrying. The entry remains gated and not Ready/prunable. The MVP plan already records reclaim rescan CPU churn as a known post-MVP issue ([MVP-PLAN.md:1894](/home/victor/Work/safeupload-wt-gen3/driver/MVP-PLAN.md:1894)); I treat it as a release condition, not a separate blocker.

**No P0/P1 found.** The incarnation-replaced fallback’s `STATUS_FILE_INVALID` check is safely skipped on `STATUS_RETRY`: the entry remains gated and the next stable pass can take that fallback if the SOP really was replaced. The compact-stream resolver’s propagated `STATUS_RETRY` is caught by the scan’s retry branch. Both quiescence callers treat all non-success statuses as non-quiescent; the SOP-marker path consequently retains its marker on retry.

## Fail-closed check

I found no weakening in `cfee5a33..f550666b`: retry parks/defer scans, gates remain active, no unknown reason is cleared, and failed or ambiguous identity checks still fail closed. The residual P2 is over-gating through sticky Unknown, not a fail-open path.
