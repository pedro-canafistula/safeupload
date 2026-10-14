# T5 exact v20 attachment replay

Source-only change to `StageStream.c`, staging feature build. No WDK build,
commit, service change or VM boot performed. The orchestrator must supply the
four normal/feature × Debug/Release WDK/PREfast/ApiValidator results at 0/0;
independent review is required before a product VM boot.

## Verified defect and choice

On the checked-out baseline (`38e188c0` fix present), `StageAttachRunLifecycle`
returns an unsuccessful op15 exchange without clearing `AttachCompletionPending`
or `AttachCompletionMayExist` (old line 3618). `StageProcessStream` parks that
pending stream (old line 5774), despite its old worker-replay comment. The
reservation check in `StageCreate` (old line 2204) refuses every owner before
`AllowAttachResume` can be considered (old line 2308). The allocation receipt,
private stage and global name barrier therefore survive until reboot.

**The original owner's next writer CREATE drives replay on the existing attach
worker.** Read-only CREATE continues using today's routing and does not drive
attachment replay. The maintenance worker does not send op15: it has no live
caller CREATE/file object with which to complete attachment. No new automatic
retirement or process-exit policy is introduced. The owner can retry once the
service channel is ready. If it never retries, exits, or the instance tears down,
the allocation remains private/held for existing retained-stage recovery.

The reservation lookup is only name selection. `StageAttachOwnerCanResume`
requires the pinned original EPROCESS and PID, the current attached view and
captured view generation, the original instance, the allocation reservation ID
matching the transfer ID, the recorded generation and full stage/expected stage
identity, driver epoch and original parent identity. A nonzero saved op15 with
MayExist is required; it must also pass
`SafeUploadStageAttachmentRequestV20Matches` against the complete recorded tuple,
including its existing RequestId, destination and volume kind. It rejects actual
private delete, retirement, incomplete allocation recovery and live bindings.
Other owners cannot satisfy it; the existing DELETE_PENDING refusal remains.
Later access/share checks and `StageAttachValidateCurrent` still apply.

## State machine and release authority

| State | Sender / next event | Result and release |
| --- | --- | --- |
| Allocated, attach pending | Original live CREATE on attach worker runs existing op12/op13/op15 lifecycle | No release before final successful attachment or exact terminal retirement. |
| Op15 ambiguous (`MayExist`, saved nonzero RequestId, pending) | Roll back the failed local binding; original owner's next writer CREATE passes the identity gate | Same stored `AttachCompletionRequest` is sent; no new RequestId, synthetic result or public mutation retry. Maintenance worker cannot seal. |
| Replay in flight | `AttachLifecycleInFlight` is claimed under NamespaceResource before StageCreate returns | Single claim lasts through binding rollback, cancellation arbitration and CREATE completion, then clears before the transaction drops its RpcReferences pin. |
| Exact `COMPLETION_PERMITTED` | Existing successful attachment path | Existing final successful CREATE-completion block clears PrivateDeleteReserved only absent DiscardOnClose/Discarded, then requeues. Nothing clears it merely on receiving op15. |
| Exact op13 `COMMIT_DENIED` | Existing exact op14 abort, then kind-5 cleanup | Existing exact terminal ACK retires the allocation and clears the reservation. |
| Committed, op15 provably never sent | Existing op16 unexposed retirement after local binding rollback | Existing exact op16 terminal ACK retires/releases. Op15 ambiguity cannot enter this branch. |
| Timeout, generic DENY, malformed/wrong-tuple reply, cancelled or torn-down replay | Rollback/completion; store DrainStatus, retain pending/fence and receipts | No reservation release or seal. A live future owner CREATE can resolve a still-pending request. |
| Mandatory teardown | Existing local close/drain/join paths | No replay or service wait. Private stage and last durable service state remain for retained recovery. |

**There is no typed exact op15 refusal in the current v20 wire contract.**
`StageProtocolStatusResultValid` accepts only `COMPLETION_PERMITTED` for op15;
the service journal likewise provides no persisted op15 denial result. A generic
DENY cannot prove permission was never recorded, so it stays held. The existing
exact refusal/retirement path is op13 COMMIT_DENIED → op14 ABORTED → kind-5. Adding
a typed op15 refusal and a service-side durable proof would require a coordinated
protocol/service design outside this kernel/source-control scope; this change
does not reinterpret DENY as that proof or enable op18.

A cancellation that wins before the replay send prevents it. A cancellation or
teardown that races an already-entered send uses existing communication rundown
and CREATE completion arbitration. Even if the exact permit arrived, cancelled
CREATE cannot enter the final successful reservation-release block. Diagnostics
retain the failed lifecycle status, or STATUS_CANCELLED if lifecycle returned
success but completion left a pending/fenced stream. Existing late-failure fence
retention is preserved; no new recovery policy for that fence is claimed.

No PrivateDeleteReserved clear or StageClearPrivateDelete call site is added.
Pre-existing non-attachment disposition, last-cleanup, allocation-parent and
owner-exit behavior is unchanged. For an unresolved allocation, its pending
allocation receipt prevents those generic helper clears from releasing it.

## Lock order and lifetime

- `StageAttachOwnerCanResume`: PASSIVE attach worker, NamespaceResource held;
  resident process/view/stream fields are stable. Existing request matching
  allocates scratch and compares bytes; it sends no RPC or callback wait.
- `StageCreate`: NamespaceResource → stream Resource for access/share/binding,
  or NamespaceResource → StageListLock for list/queue operations. The claim is
  set before NamespaceResource is dropped. No new I/O/send/wait is introduced.
- `StageAttachRunLifecycle` / `StageAttachExchangeRetry`: PASSIVE asserted.
  The attach worker's RpcReferences pin keeps the stream allocated across RPC.
  NamespaceResource is dropped before exchanges. The instance check briefly
  takes StageAttachLock and releases it before sends; no spin lock spans RPC.
  Existing process/cancellation/completion waits are outside namespace/spin locks.
- `StageAttachDrainTransaction`: finishes rollback/CREATE completion first,
  then NamespaceResource → StageListLock for the final wake. It clears the
  lifecycle claim and drops the transaction pin under NamespaceResource; no
  service or callback wait is added to that critical section.
- Mandatory teardown keeps its existing permanent admission fence, early port
  closure, channel rundown and local worker join. It never calls a new replay
  helper or waits for an exact service result.

## Source controls and mutations

Run `python3 driver/scripts/t5/attachment-replay-selfcheck.py` and
`python3 driver/scripts/t5/teardown-participation-selfcheck.py`.
The new suite has 11 production contracts and one mutation test that requires
all 14 mutations to fail the production contracts. Mutations affect in-memory
source only; production contracts must pass before mutation testing starts.

| Mutation | Contract that catches it |
| --- | --- |
| `fresh_op15`: use the retire request for op15 | Lost-op15 control requires the stored AttachCompletionRequest. |
| `reset_request`: erase the saved op15 before send | Lost-op15 control forbids resetting replay storage. |
| `owner_pid_only`: remove EPROCESS binding | Identity control requires original pinned process lifetime as well as PID. |
| `wrong_generation`: omit captured view generation | Identity control requires current view generation. |
| `wrong_allocation`: omit allocation reservation/transfer equality | Identity control binds resume to that allocation. |
| `fresh_owner_resume`: allow resume without a recorded may-have-reached op15 | Identity control requires nonzero saved op15 and MayExist, preventing a fresh op15 through this exception. |
| `foreign_bypass`: replace the owner identity gate with FALSE | Barrier control requires the gate before DELETE_PENDING, with no name-only exemption. |
| `cancel_send`: remove op15 cancellation/retry gate | Cancellation control requires live-transaction checks before send. |
| `lost_diagnostic`: remove held status assignment | Cancellation control requires pending/fenced diagnostics. |
| `missing_claim`: remove per-stream claim | Single-in-flight control requires claim before namespace unlock and release after completion. |
| `early_release`: clear reservation on failed op15 | Release inventory and held-failure controls reject new helper/direct clear sites. |
| `early_seal`: seal instead of parking pending attachment | Maintenance control requires pending return and forbids seal there. |
| `synthetic_op15_result`: accept any op15 result | Typed reply control permits only the defined exact COMPLETION_PERMITTED result. |
| `changed_replay_bytes`: skip exact request comparison | Lost-reply control requires byte-equality validation of recorded RequestId/tuple. |

Other production contracts check exact reply tuple fields, existing abort/op16/
kind-5 paths, successful-release ordering, PASSIVE/no-lock send structure,
mandatory-teardown exclusions and staging preprocessor guards. Existing teardown
controls include the successful-attachment reservation guard and local-only
mandatory teardown contracts.

Both suites pass (12 new tests, including 14 rejected mutations; 17 existing
teardown tests). Initial new-suite failures were control-authoring mistakes:
the barrier slice started at a local declaration and an EPROCESS mutation token
was not unique. They were corrected without changing product code or removing
assertions. No source control establishes actual Windows behavior.

## Reviewer conditions

WDK/PREfast/ApiValidator and independent review remain outstanding. Qualify
lost replies, service reconnect, caller cancellation before/during/after replay,
instance/mandatory teardown races, simultaneous owner retries, foreign writer
refusal and existing foreign-reader behavior on the matched product pair. Keep
independent byte observations and exact retirement assertions. No VM boot is
authorized for this change before independent review. Review the identity gate's
existing pageable scratch allocation while NamespaceResource is held, existing
late-completion fence behavior and the absence of a typed op15 refusal explicitly.
