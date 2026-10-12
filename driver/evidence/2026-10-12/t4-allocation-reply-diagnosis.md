# T4 short retry: allocation/reply failure — 2026-10-12

Status: failed qualification; owner approved focused diagnosis and preparation of a reviewed fix after the repeated reply errors.
No thresholds or privacy assertions changed. No further protected run has started.

## Run and restoration

`m2t4recover256a1`, win10-debug3 only, Verifier 0x13B from boot. Kernel `60fecdbc`, artifact `m2-driver5-t11`
(SHA256 `EBDFCE549EA1DC271498A5F6A38D151AC952ADE9105D476B073A313EB271C851`); protocol-18 service `0cfdc7c6`
([passing agent matrix](exact-agent-matrix-t4-recovery-v18a1-summary.txt)). The current M2 agent needs unfinished T5 negotiation,
so the isolated backport is intentional. The subsequent `91c6a3be` hand-back notification correction passes its
[agent matrix](exact-agent-matrix-t4-recovery-v18a3-summary.txt); it was not this run's binary.

The [verdict](m2t4recover256a1-verdict.txt) records 255/256 successful outcomes, one residual stage, and failed pool slope
(192.225 bytes/cycle against the unchanged limit of 4). Live versions/views/tombstones reached zero; all 255 created versions
were released, no cap refusals, no idle worker passes/timer fires. The sampled public-byte checks passed; they do not qualify
the separate raw-volume regressions. The row [completed with failures](m2t4recover256a1-stop.txt).

The [test restoration](m2t4recover256a1-final-restored-state.txt) and
[independent fresh-disk baseline/restoration](m2t4recover256a1-independent-restoration.txt) passed: overlays deleted, base untouched,
XML unchanged. The [test start](m2t4recover256a1-checkpoint.txt) and [verification start](m2t4recover256a1restore-start.txt) record EFI reset.
Both debug VMs are off; only win10-debug3 was used.

## Established evidence

- [Service events](m2t4recover256a1-service-events.txt) contain no `Journal persistence failed:` or allocation-handler exception.
  Requests 1308 and 1334 have `FilterReplyMessage` HRESULT `0x801F0020`, at 16:05:39.864Z and 16:06:03.650Z.
  Windows SDK 10.0.26100.0 `shared/winerror.h:43247-43253` identifies this as `ERROR_FLT_NO_WAITER_FOR_REPLY`.
  It identifies an absent waiter, not the operation, the cause of the wait ending, or a safe deletion authority.
- [Cycle outcomes](m2t4recover256a1-cycles.jsonl): cycle 121 failed writing `C:\Protected\t4\same-1.txt` with access denied,
  after 5848.9 ms. The [captured journal](m2t4recover256a1-failure-evidence/failure-evidence/cycle-000121/journal/5f99575c4abe4cf0a14dce22ce2df7cd.json)
  has transfer `5f99575c-4abe-4cf0-a14d-ce22ce2df7cd`, generation 16, Allocated, never sealed, created 16:05:34.1038551Z.
  This is consistent with an allocation completing after the create was refused. Existing logs cannot prove request 1308's
  operation or tie the final residual stage to its exact file identity.
- The service synchronously handles one received request before replying (`MinifilterInterceptor.cs:251-300` in `0cfdc7c6`).
  Allocation creates/flushed the private stage and then commits the journal before returning its basename. A reply exception
  only logs a request ID. It loses the allocation object and has no unaccepted-allocation cleanup obligation.
- Kernel `60fecdbc`, `StageProtocol.c:266-270`, refuses allocation unless an exact valid ALLOW reply arrived. The new stream
  is constructed only after that. A timeout cannot make these staged bytes public. Generic communication comments describing
  the old taint path's fail-open behavior do not describe this allocation caller.
- [Pool samples](m2t4recover256a1-samples.jsonl): `SpUs` returns to zero after settle. `SwUr` is 6,347,264 bytes at cycle 64,
  6,392,864 at 256, and 6,368,864 after idle; registry entries are 238, 255, and 249. This supports examining registry/name
  retention, but neither proves a leak nor excuses the failed slope. Driver module pool ends at 6,399,976 bytes after idle.

## Focused follow-up

1. Preserve exact request/operation/transfer correlation and monotonic phase timing. Trace backing creation, journal wait/scan/write,
   handler duration and native reply result. Do not infer the slow phase from the 5.8-second total.
2. Have Luna review the minimum allocation-ownership repair. Missing/ambiguous replies never justify deleting a possibly adopted
   stage. Any cleanup must bind the exact fresh allocation and full file identity; no path-only deletion or inferred close.
3. Examine historical manifest scans and registry retention independently. Do not widen a deadline, ignore an error, reduce Verifier,
   or waive the pool check to obtain a pass. Prepare deterministic fault tests before the next protected run.

Native API reference: [FltSendMessage](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltsendmessage)
documents that a wait can end before a reply (timeout, disconnection or thread termination); the current evidence does not distinguish them.

## Prepared repair

`6198eee7` on `fix/t4-journal-recovery-v18` implements the Luna-reviewed narrow cleanup and monotonic phase diagnostics described
in [T4-STAGE-LIFETIME §12](../../T4-STAGE-LIFETIME.md#12-unaccepted-allocation-reply--2026-10-12). Only the exact native NO_WAITER
result for one correlated new allocation creates cleanup authority. Other errors retain private data. Cleanup verifies the original
full file identity, retains the Unsealed journal/generation, and deletes through that handle off the receive loop.

The [four-profile agent matrix](exact-agent-matrix-t4-rejected-allocation1-summary.txt) passes: 558 normal / 625 feature tests per
configuration, no skipped cases, service/app/test builds at zero warnings/errors. Eleven new general cases plus three feature native-status
cases cover changed identity/state/generation, journal-write ambiguity, sharing, retry and restart. This does not prove the historical
leftover's identity or resolve the delay and failed pool slope; protected runtime has not been repeated.
