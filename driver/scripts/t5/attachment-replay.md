# T5 exact v20 attachment replay

Rework of `c78ef895` on `wt/t5-attach-replay`, rebased onto `034a906f`.
The latter's single op16 pin release and single send are preserved. Source-only
change to `StageStream.c` and T5 controls, staging feature build. No WDK build,
commit, service change or VM boot performed. The orchestrator must supply the
four normal/feature × Debug/Release WDK/PREfast/ApiValidator results at 0/0;
independent review is required before a product VM boot.

## Verified defect and choice

The original defect (before the replay change, `38e188c0` fix present): `StageAttachRunLifecycle`
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
the allocation remains private/held. Automatic recovery of that hold is not
implemented or qualified by this change.

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
Later access/share checks and `StageAttachValidateCurrent` still apply, including
when `AttachCompletionKnown` caches an exact permit. The lifecycle now validates
before accepting that cache: current view/owner/generation/instance, stage and
driver identities, and a fresh no-reparse query of the current parent against
the allocation's parent identity. Validation failure returns failure through
rollback/drain, keeps pending permission private/held and does not send a new
authorization RPC. The cached permit is only permission for the recorded tuple,
not proof that a new CREATE still names its current parent.

## State machine and release authority

| State | Sender / next event | Result and release |
| --- | --- | --- |
| Allocated, attach pending | Original live CREATE on attach worker runs existing op12/op13/op15 lifecycle | No release before final successful attachment or exact terminal retirement. |
| Op15 ambiguous (`MayExist`, saved nonzero RequestId, pending) | Roll back the failed local binding; original owner's next writer CREATE passes the identity gate | Same stored `AttachCompletionRequest` is sent; no new RequestId, synthetic result or public mutation retry. Maintenance worker cannot seal. |
| Replay in flight | `AttachLifecycleInFlight` is claimed under NamespaceResource before StageCreate returns | Single claim lasts through binding rollback, cancellation arbitration and CREATE completion, then clears before the transaction drops its RpcReferences pin. |
| Exact `COMPLETION_PERMITTED` | Existing successful attachment path | Existing final successful CREATE-completion block clears PrivateDeleteReserved only absent DiscardOnClose/Discarded, then requeues. Nothing clears it merely on receiving op15. |
| Cached `COMPLETION_PERMITTED`, cancellation before attachment ACK | Original owner's next writer CREATE, same pinned transaction handoff | Run live validation before accepting the cached permit; no op12/op13/op15 send on cache acceptance. Failure rolls back the new binding and stays held. |
| Exact op13 `COMMIT_DENIED` | Existing exact op14 abort, then kind-5 cleanup | Existing exact terminal ACK retires the allocation and clears the reservation. |
| Committed, op15 provably never sent | Existing op16 unexposed retirement after local binding rollback | Existing exact op16 terminal ACK retires/releases. Op15 ambiguity cannot enter this branch. |
| Timeout, generic DENY, malformed/wrong-tuple reply, cancelled or torn-down replay | Rollback/completion; store DrainStatus, retain pending/fence and receipts | No reservation release or seal. A live future owner CREATE can resolve a still-pending request. |
| Unresolved attachment during voluntary unload | Full attachment preflight under NamespaceResource, before cleanup classification/quarantine | STATUS_DEVICE_BUSY → reversible Veto → reopen CREATE/attach, backend, native, publication, fence and callback admission. Owner retry remains available. |
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

Maintenance returns with `STAGE_WAIT_SERVICE` for pending attachment, late
completion fence or op16 retirement retry; it leaves `DrainStatus` untouched.
The reset to `STAGE_WAIT_NONE` occurs only after this gate. SERVICE is excluded
from both retry-timer accounting and timer-only sweeps: no periodic attachment
retry is armed. A service-connect sweep may revisit the hold but cannot replay
op15; only the original owner's live writer CREATE supplies that authority.

## Reversible voluntary-unload veto

After admission/capture and callback preflight, scan **all** streams for
`AttachCompletionPending`, `AttachCompletionFence`, `AttachRetirePending`,
`AttachLifecycleInFlight`, or an allocation receipt with op15 MayExist/Known.
This precedes all unload cleanup classification/queueing and the first cleanup
quarantine latch. No unresolved attachment receipt is treated as kind-5 cleanup.
The common nonmandatory, nonquarantined Veto releases NamespaceResource before
`StageRollbackUnloadPreparation` and callback-admission reopen. It resets
StageStopping/StageUnloadPrepareWork and reopens CREATE/attach admission, allowing
the same owner's retry after the unload refusal. Terminal op13-denied/op14-aborted
cleanup remains eligible for the existing exact cleanup/quarantine path.

Kind-5 has additional checks at unattached-allocation queueing, maintenance's
allocation-receipt branch and discard collection. MayExist/Known never passes;
collection also refuses pending/fenced/retiring/in-flight attachment state even
if a stale pending cleanup flag is present. A future changed transition cannot
turn an ambiguous op15 into cleanup by falling through maintenance's early gate.
Existing irreversible quarantine/epoch drain is not reopened by this change.
Mandatory teardown still uses its separate local begin/drain roots; it does not
call PrepareUnload or send/wait for any attachment/cleanup/service result.

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
- Cached permission uses the same `StageAttachValidateCurrent`: NamespaceResource
  protects the view check, then releases before the current-parent filesystem
  query. This adds the existing live identity I/O to cached-permit opens, without
  adding an authorization exchange or holding a spin lock across I/O.
- `StageAttachResumeOrRun`: both op16 resume and installed binding transfer one
  RpcReferences pin to Transaction->Stream under NamespaceResource. Ordinary
  attached opens, initial/replayed/cached op15, all failures and cancellation
  keep it through common drain; no helper clears the handoff or releases it early.
- `StageAttachDrainTransaction`: finishes rollback/CREATE completion first,
  then NamespaceResource → StageListLock for the final wake. It clears the
  lifecycle claim and drops the transaction pin under NamespaceResource; no
  service or callback wait is added to that critical section.
- Voluntary attachment preflight and maintenance run under NamespaceResource;
  discard collection keeps NamespaceResource → stream Resource. New tests require
  rollback after namespace release. No new wait or service use in these guards.
- Mandatory teardown keeps its existing permanent admission fence, early port
  closure, channel rundown and local worker join. It never calls a new replay
  helper or waits for an exact service result.

## Source controls and mutations

Run every `driver/scripts/t5/*.py` self-check. Replay has 15 production contracts
and one mutation test requiring all 29 mutations to fail; pin accounting has
6 production contracts and one mutation test requiring all 11 mutations to fail.
Teardown participation, stream listing and Notepad verdict controls also run.
Mutations affect in-memory
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
| `missing_handoff`, `missing_attach_pin` | Binding handoff control requires Transaction->Stream and the one pin before lifecycle/ordinary-open exits; pin suite also checks both. |
| `missing_initial_validation`, `cached_permit_before_validation`, `lost_current_parent_query` | Initial/live validation control orders validation and failure return before the sole cache branch and requires the parent query/identity comparison. |
| `unload_attachment_cleanup`, `unload_irreversible_veto`, `unload_keeps_create_closed` | Preflight control requires the busy veto before cleanup/quarantine, no quarantine mutation in the gate and CREATE admission reopen on reversible rollback. |
| `kind5_queue_after_op15`, `kind5_maintenance_after_op15`, `kind5_collect_after_op15` | Kind-5 control requires each queue, maintenance and collection guard independently. |
| `lost_held_wait`, `pre_gate_wait_reset`, `maintenance_lost_diagnostic`, `held_timer_retry` | Maintenance control requires SERVICE before return, no earlier NONE reset/DrainStatus assignment, and no SERVICE timer accounting or timer-only sweep. |

The pin suite's mutation coverage is separate:

| Mutation | Contract that catches it |
| --- | --- |
| `missing_attach_handoff`, `missing_attach_pin`, `missing_resume_handoff`, `missing_resume_pin`, `extra_attach_pin` | Nonvacuous exact two-handoff/two-increment inventory, adjacency and per-path +1/−1 balance. |
| `double_resume_release`, `lost_common_release`, `lost_common_reset`, `early_drain_exit` | Exactly one common release/reset, no resume release, no post-worker early return, completion before release. |
| `completion_releases_pin`, `completion_loses_handoff` | Worker/lifecycle/exchange/retire/rollback/completion retain pin ownership until drain; no helper pointer assignment or RpcReferences update. |

Pin coverage checks the production return edges for op16 success/lost reply,
ordinary attached open, invalid pending state and lifecycle completion. All
initial/replayed/cached op15 validation/RPC/cancellation/denial exits must retain
the same pin for rollback/completion/drain. This is structural source accounting,
not a simulated Windows race or runtime proof of balanced references.

Other production contracts check exact reply tuple fields, existing abort/op16/
kind-5 paths, successful-release ordering, PASSIVE/no-lock send structure,
mandatory-teardown exclusions and staging preprocessor guards. Existing teardown
controls include the successful-attachment reservation guard and local-only
mandatory teardown contracts.

Offline results: replay 16/16 (29 rejected mutations), pin 7/7 (11 rejected
mutations), teardown 17/17, stream listing 3/3, Notepad verdict 14 assertions.
No source control establishes actual Windows behavior. While authoring the pin
lock control, a linear scan mistook the returning NULL-stream unlock branch for
an unlock on the successful handoff path; the control now explicitly checks that
branch returns before handoff, without changing product code or weakening gates.

## Reviewer conditions

WDK/PREfast/ApiValidator and independent review remain outstanding. Qualify
lost replies, service reconnect, caller cancellation before/during/after replay,
instance/mandatory teardown races, simultaneous owner retries, foreign writer
refusal and existing foreign-reader behavior on the matched product pair. Keep
independent byte observations and exact retirement assertions. No VM boot is
authorized for this change before independent review. Review the identity gate's
existing pageable scratch allocation while NamespaceResource is held, existing
late-completion fence behavior and the absence of a typed op15 refusal explicitly.

Recovery qualification still requires:

- Owner exit/never retry and late completion fences: indefinite private holds
  remain. Establish approved recovery/lifetime evidence without repeating any
  completed public mutation; no process-exit, timer or digest release is added.
- No typed durable op15 refusal in v20: generic DENY remains ambiguous/held.
  A coordinated protocol/service design is required before a terminal refusal
  can authorize retirement.
- Lost seal ACK: `MinifilterInterceptor.cs` around line 1216 rejects an
  already-progressed measured entry despite `SealAsync`'s replay capability.
  Agent work only; recorded here, with no agent edit in this task. Resolve exact
  seal acknowledgement without repeating publication, then qualify the pair.
- Cached permit followed by cancelled ACK: replace/remove/reparse the parent,
  then retry; prove live validation refuses it, no authorization RPC or cleanup
  is sent and bytes stay private. Also prove unchanged-parent retry succeeds.
- Voluntary unload with ambiguous op15 and an unrelated cleanup receipt:
  prove reversible refusal, admission restoration, successful owner retry and
  no kind-5 send for the ambiguous tuple. Prove service-absent mandatory teardown
  performs only local drain. Reconnect, concurrent retries and cancellation
  races need Verifier and independent byte observations, not source counts.
