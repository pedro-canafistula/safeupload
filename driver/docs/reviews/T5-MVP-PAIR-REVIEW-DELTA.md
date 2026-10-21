# T5 MVP pair: focused pre-boot review delta

Base: `wt/mvp-pair`, `b97d263ebb8a32eeb2409647a0fd25750009b84f` (t5-pair14).
Owner scope: 2026-10-16 “MVP pair now, batch 3 in parallel” in
[the current staging plan](/home/victor/Work/safeupload-staging/driver/POST-MVP-PLAN.md).
This is a request for **one independent Sol 6.1 xhigh implementation review** before boot;
no independent review or protected-pair qualification is claimed here.

## Witness detach

Port only the `StageWriters.c` delta from `026eecd4`, implementing revision 2 of
`driver/T5-SOP-WITNESS-DETACH.md` at `77fc029f`; the design review at `6001208a`
accepted it with conditions. Inspect those with `git show`. Retained
[RCA](/home/victor/Work/safeupload-staging/driver/evidence/2026-10-14/m2t5boot10k1-pool-slope-rca-sol61.md) and
[design re-review](/home/victor/Work/safeupload-staging/driver/evidence/2026-10-15/t5-witness-detach-rereview-sol61.md)
resolve outside this checkout.

Exact production functions: `StageRegistryBindLifetime`, `StageRegistryPruneLocked`,
`StageRegistryRetireInstance`, `StageWritersReleasePrunedCache`,
`StageRegistryDereference`; new helpers `StageRegistryLifetimeViolation` and
`StageRegistryRetireLifetimeLocked`.

- `STAGE_SOP_LIFETIME.NonRetiredBindings` uses x64 padding (24-byte assertion).
  RegistryLock exclusive serializes +1 on the winning NULL-to-witness CAS and
  -1 at the only two guarded live retirement writes. No counter changes on
  Unknown, failed work, cache release, context cleanup or entry destruction.
- Binder second check and successful ordinary-prune detach take RegistryLock
  exclusive then WriterLock. Entry must remain listed/non-retired/non-transient
  at bind. Detach requires exact witness equality, zero bindings, retired/unlisted
  entry, empty writer nodes, no untracked/Unknown/Invalid. Cache equality is a
  separate unchanged predicate, covering metadata-only successor prune order.
- Entry points run at IRQL <= APC_LEVEL; WriterLock raises to DISPATCH_LEVEL.
  Added spin regions are resident/O(1), with no traversal, allocation, wait, I/O,
  filter-object call, StateLock or SectionLock. Prune releases SectionLock before
  detach. No new WriterLock-to-RegistryLock acquisition.
- Allocation's one reference transfers to context; first binding adds one entry
  reference. CAS losers undo a tentative reference while the context still owns
  one. Skipped allocation followed by intervening detach retries both checks;
  genuine OOM fails. Unused fresh allocations release once after locks.
- Retirement retains entry references. Detach transfers/releases only the context
  witness reference after both locks, then releases any cache-entry reference.
  Final entry destruction releases its witness; context cleanup consumes only
  an attached witness. Counter violations invalidate/publish sticky tracking loss,
  never repair counts or authorize detach. Natural End/Unknown remain unchanged.
- Committed teardown gains only retirement accounting: invalidation, instance/
  volume pins, surviving context/node/completion owners and unregister barriers
  remain as on the base. Retirement alone does not invoke ordinary detach.

## Journal persistence and V20 retry

Port from `3627a054` with the later `026eecd4` reader-sharing correction retained:
readers already share Read|Delete and deny in-place writes on this base.
`StagedJournalReplacement.CommitAsync` flushes once, then retries only the failed
private rename on the same held temporary handle: Win32 5/32/33, six attempts,
five waits of 20/40/80/160/320 ms. No retry after success or public mutation.

`MinifilterInterceptor.ApplyStageLifecycleV20` returns an exact echoed V20 payload
with RetryableFailure for **StagedJournalPersistenceException only** on op13/op15;
structural failures retain refusal. `StageProtocolStatusResultValid` admits that
result only for these added operations; existing exact-envelope validation maps
it to STATUS_DEVICE_BUSY. No V29/V30 machinery or capability changes.

`StageAttachExchangeRetry` keeps the counted CREATE transaction, object/view/epoch
owners and same immutable RequestId/frame across at most six exchanges, with the
same five backoff waits (620 ms total scheduled wait, excluding RPC/storage time).
It waits at PASSIVE_LEVEL with no namespace/spin lock; checks cancellation, owner
exit, channel/instance and mandatory teardown around waits. Success exits before
waiting. Exhaustion returns STATUS_DEVICE_BUSY through the existing fail-closed
lifecycle: no successful CREATE/permission is inferred, uncertain journal progress
stays held. Existing cancellation-only terminal reconciliation remains unchanged.

## Verification and remaining conditions

Local diagnostic results (2026-10-16): all 12 Service/App/Tests builds across
normal/feature x Debug/Release PASS; all 18 added focused cases PASS in each
profile. The temporary Linux invoker marks the existing Windows-only diagnostic
identity query unavailable; no production/test code or authority is substituted.
All 11 T5 Python checks, T4 verdict self-check and matrix-runner self-check PASS
(13 scripts). Host C controls compile actual changed function bodies with `-Wall -Wextra
-Werror` and exercise interleavings and negative mutations. Full clang-cl syntax
probe stops at missing `fltKernel.h`; this is not a WDK build. Required-test
preflight against `t5-batch1b` finds no removed/renamed methods. Local receipts,
including failed attempts, are under
[evidence/2026-10-16/mvp-pair-local-1](../../evidence/2026-10-16/mvp-pair-local-1/).

Expected Windows matrix counts (baseline plus 18 new unconditional cases):
normal Debug **1,633**, normal Release **1,633**, feature Debug **2,215**, feature
Release **2,215**. Each count combines the existing user/SYSTEM partition once.

Required before any boot:
one focused independent implementation review, four WDK/PREfast/ApiValidator
builds at 0 warnings/errors, Windows agent matrix. Runtime conditions remain
concurrent CREATE/reclaim lock-hold measurements, direct SwUl sampling including
pre-purge idle, unchanged T4PoolFlat/other assertions, exact matched artifacts,
independent destination bytes and separate restoration. This scope does not
port the later T4 sampler harness changes or claim the inferred pool attribution
has become a passing resource result.

## Changed files

- Agent: [MinifilterInterceptor.cs](../../../agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs),
  [StagedTransferJournal.cs](../../../agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs),
  new [StagedJournalReplacement.cs](../../../agente/SafeUpload.Agent.Service/Interception/StagedJournalReplacement.cs).
- Kernel: [StageWriters.c](../../SafeUpload.Minifilter/StageWriters.c),
  [StageProtocol.c](../../SafeUpload.Minifilter/StageProtocol.c),
  [StageStream.c](../../SafeUpload.Minifilter/StageStream.c).
- Agent controls: [StagedAttachmentV20Tests.cs](../../../agente/SafeUpload.Agent.Tests/StagedAttachmentV20Tests.cs),
  new [StagedJournalReplacementTests.cs](../../../agente/SafeUpload.Agent.Tests/StagedJournalReplacementTests.cs).
- Kernel/protocol controls: [attachment-replay-selfcheck.py](../../scripts/t5/attachment-replay-selfcheck.py),
  new [manifest-retry-selfcheck.py](../../scripts/t5/manifest-retry-selfcheck.py),
  new [sop-witness-detach-selfcheck.py](../../scripts/t5/sop-witness-detach-selfcheck.py).
- This delta note. No status plan, memory, feature gate or VM harness changes.
