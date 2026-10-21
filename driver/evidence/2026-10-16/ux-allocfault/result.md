# T4 allocation-reply recovery implementation receipt

2026-10-16, branch `ux/allocfault`, parent `2a2a2b8973bcb30dadbea7a0ec4b669448bbed78` (`demo/apps`).
Implementation and local diagnostics only; no Windows builder job, product VM boot or qualification was performed.
The delivery commit is in `.scratch/ux/allocfault.bundle`, ref `refs/heads/ux/allocfault`; original repository Git metadata is unchanged.

## Root cause and repair

The owner's `uxk5t4ord2-*` report describes cycle 532 timing out with Win32 121 and the same mapped name subsequently returning
Win32 5, stopping at cycle 548. The supplied raw directory was unavailable here; its timing details are not independently verified.
Source establishes a matching V20 ownership hole: unknown Prepare stayed pending, but only an ambiguous op15 could resume on a
new CREATE. Neither worker cleanup nor name reuse could progress. Long journal scans/writes create timeout opportunities; their
performance is outside this repair.

A failed Prepare now queues exact unattached cleanup after local binding rollback. The existing collector retains all object,
share, cache, section and lifecycle drains and the no-op15 guard. Before kind-5 deletion, unknown Prepare is durably aborted with
the exact allocation tuple. Agent Abort accepts None/Prepared, serializes with Prepare and persists Aborted/DiscardPending, so a
late Prepare cannot revive it. Confirmed existing abort paths keep their existing flow. Unknown allocation replies keep their
existing byte-exact replay/NoAllocationCommitted handling. No uninspected bytes are published.

The driver releases the reservation and predecessor reference only on exact identity-qualified deletion/absence ACK, rejects
stale channel/tuple results, and returns sharing conflict while cleanup is pending through both owner and foreign admission
routes. Duplicate replies/retries resolve bookkeeping; they do not repeat a public mutation. Actual delete and op15 ambiguity
remain held. No imports, wire fields, resource caps, readiness gates, existing tests or T4 assertions changed.

## Verification

All raw attempts and local tools are retained under `.scratch/verification`, `.scratch/focused`, and `.scratch/tmp`, per this
session's scratch instruction. Failed first attempts were not overwritten.

| Local check | Result and scope |
|---|---|
| New extracted production C controls | PASS, GCC + Clang, `-Wall -Wextra -Werror -fsanitize=undefined`; 2 tests. Runtime timeout/Abort/discard, lost abort, pending/ACK, stable request replay, exact tuple/channel, commit/op15 and teardown gates; source wiring covers both retry routes and drain collection. |
| All 13 existing Python T5 self-check entry points | PASS, assertions/mutation controls unchanged. |
| Three existing production C shim entry points | PASS (publication buffers, directory decisions, metadata readers). |
| T4 verdict self-check + import self-check | PASS. These are offline harness/import-checker controls, not a binary import or VM verdict. |
| Feature agent Debug and Release local builds | PASS, 0 warnings / 0 errors each, .NET SDK 10.0.400. |
| Focused agent diagnostic execution | 33/33 PASS in each configuration: all 14 new cases plus 19 existing allocation envelope/result controls, no skips within the explicitly selected subset. |
| Source API audit | Delta PASS: no new external kernel calls. The full inherited local audit reports the identical pre-existing `Taint.c:356: InsertHeadList` reference-table gap on base and working source; not reported as a full API gate PASS. |
| Diff whitespace/links | PASS; new design/status links resolve. |

The agent subset executes the actual tests by reflection on Linux. Native Windows journal/sharing/security behavior is not
qualified. A Linux library implements only failure of the failure-only diagnostic GetFileInformationByHandleEx call, enabling
the journal write-failure controls without manufacturing file identity. All production tuple checks and test assertions execute
unchanged. The broader initial direct run hit Windows-only APIs/process launch and was retained as a failed diagnostic attempt;
it is not counted as a passing suite. Test SDK/Windows user+SYSTEM discovery/execution gates remain required.

New agent controls cover abort-before/after Prepare; successful Abort/replay without a live owner or positive policy; lost Abort
reply and restart; historical late-Prepare replay versus refusal of a fresh Prepare/Commit/permit; exact cleanup ACK and duplicate
ACK; unchanged public bytes; fresh next allocation/generation; four before/after journal-replacement failures; six changed-tuple
refusals; and two committed/permitted negative controls. Independent source review:
[Sol 6.1 xhigh, ACCEPT WITH CONDITIONS](review-sol61.md).

## Remaining gates and risks

- Matched feature Debug/Release WDK, PREfast and ApiValidator at 0/0; both delivered binary import gates; Windows feature agent
  Debug/Release × user/SYSTEM matrix. No local shim result substitutes for these.
- All [allocation-reply fault row variants](../../../docs/design/lifetime/T4-STAGE-LIFETIME.md#121-v20-allocationprepare-reply-recovery--2026-10-16)
  on `win10-debug3` in ordinary/runtime-Verifier/boot-Verifier modes, with independent byte observations, exact journal/kernel
  disposition counts, successful later open, zero residual allocations and separate restoration. Include sharing failure and
  reconnect/stale reply negatives; commit/op15 ambiguity retains its existing hold.
- Unchanged 256 smoke/10k contexts, pool, cap, Ready and idle gates, then C01–C04/B01/B02/X01 raw-observer regressions in all
  three modes. Follow current stop rules and builder-free timing windows.
- Long per-save journal history/scans can still cause retryable timeouts. An unavailable service, changed identity/parent,
  unresolved deletion or restart ambiguity still keeps the exact version private and held. The matched updated agent is required
  for abort-before-Prepare; an older agent may refuse it conservatively. This is a candidate fix, not protected-pair qualification.
