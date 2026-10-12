# T4 recovery backport for the pre-T5 runtime pair

This branch starts at `970239a3` (agent `t4-af1`) and carries the focused journal-recovery fix from
`feat/driver-m2` through `0cd58e79`. It pairs with the already-built/reviewed `m2-driver5-t11` (`60fecdbc`).
The base wire protocol, startup negotiation, kernel and admission evidence are unchanged. Do not merge this
old tree over M2 or treat its runtime results as qualification of the final M2 pair.

The native-success receipt binds the legacy journal's exact transfer, destination generation, namespace
history and approved digest. It also captures the identity and length of the held stage, and the committed
public temporary's identity. Unlike current M2, the legacy journal has no T5 attachment epoch or persisted
measured-stage fields; this backport adds neither. Hand-back retains the baseline private-path, sharing,
owner and digest checks. No T5 capability is enabled or simulated.

Recovery only finishes bookkeeping after observed native success. Lost receipts after restart keep the
Publishing reservation and name the file in the tray. Persistence failures during hand-back keep its
obligation retryable; actual identity/content/copy failures keep the baseline terminal behavior.

The current commit-based Windows matrix harness is carried back so no freeze/pin artifacts are required.
It checks all discovered cases exactly once across the normal-user/SYSTEM legs, all four profiles at 0/0,
the admission tests and the new recovery tests. T5-only mandatory test names are replaced by the recovery
names because those components do not exist in this source; the main-branch matrix is unchanged.

Runtime remains pending: short Verifier run, 10,000 cycles with a six-hour-or-longer deadline, raw-volume
regressions and separate verified VM restoration. No failed result is converted to a pass.
# Exact unaccepted-allocation cleanup (2026-10-12)

The short Verifier run `m2t4recover256a1` failed one save and retained one stage. It logged two `ERROR_FLT_NO_WAITER_FOR_REPLY`
results but lacked operation/transfer correlation. No cleanup inference is drawn from those historical errors.

Luna 6 max reviewed this narrow security design before implementation. Carry the fresh transfer, generation and full volume/file ID
(captured on the original backing creation handle) to the one native reply. Only that call's exact NO_WAITER result creates a volatile
cleanup obligation. A successful reply, any other error, an elapsed deadline or a surviving Allocated record does not. The old driver
cannot construct an upper stream without first receiving this sole issuer's random stage basename. No kernel or wire change is needed.

The existing worker performs cleanup outside the receive loop. Under the journal gate, reread the exact original record (Allocated,
never sealed, no rename/cleanup); reopen the stage exclusively with DELETE and READ_ATTRIBUTES, reject reparse/directory or full-ID
mismatch, retain the existing Unsealed manifest/generation, and delete through the verified handle. Keep StageDeleted's existing
hand-back meaning. An exact attempted journal disposition is retained before replacement, making before/after-write failures retryable
without accepting unrelated changes. Retries use monotonic 250 ms–8 s backoff. On a crash the volatile proof is lost: existing startup
recovery retains the private record/file, and must not infer rejection. Unsealed is not generally terminal; this transfer cannot get a
legitimate future seal because its name was never delivered. Any future alternate issuer must revisit that invariant.

Request diagnostics record operation, request/message IDs, transfer/generation/full-ID and monotonic phases (owner/policy, preparation,
backing creation, journal wait/scan/write, handler/reply). Only failed replies and requests taking at least one second emit the normal
timing warning. No timeout, assertion or readiness rule changes. These timings are needed to distinguish actual latency causes before
attempting journal-index or kernel-lock changes. Pool attribution remains open; this patch does not claim to fix the failed pool slope.

The repair is specific to the reviewed protocol-18 T4 pair. It is not copied over the main branch's unfinished T5 allocation/discard
protocol. It requires its Windows agent matrix and a new protected short run before the 10,000-cycle qualification; none is implied here.
