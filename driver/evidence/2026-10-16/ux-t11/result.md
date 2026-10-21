# T11 UX review conditions — local delivery result

2026-10-16; base `demo/apps` `2ed2b20b45df06e8cd26aab73f0e8640c3e93717`;
branch `ux/t11`. Original Git is read-only. Delivery is `.scratch/ux/t11.bundle`
with `refs/heads/ux/t11` at its new commit; its final commit/bundle SHA-256 is in
`.scratch/ux/t11-delivery.txt`. No remote build, VM action or push was performed.

Changes:

- Startup validates SOP sharing while two opens live and across original-handle
  cleanup with only a section retained. By-name proof precedes explicit deletion;
  successful full-ID/SOP reopen precedes further mutation. Close failure cannot
  be consumed as lifetime proof. Repeated PASSIVE SAL/PAGE/PAGED_CODE, existing
  DDIs, no new allocations/imports/lock-spanning waits.
- Existing changed-SOP retirement is retained and tested against original Ended
  evidence and all unresolved obligations; no replacement-SOP MM inference or
  forced context deletion. [Lifetime reasoning](../../../docs/design/lifetime/T11-SOP-LIFETIME.md).
- Hot unbound live-epoch receipts and unfinished disposal/cleanup records survive
  compaction. Missing durable epoch cannot rebootstrap over retained receipts via
  either entry point. Pending delete's forward CREATE_AFTER successor joins exact
  reference closure. Legacy journal-only and bound gate behavior are preserved.
- Fourteen new agent cases also cover registered-segment failed-flush reflush,
  second-segment inventory pre/post replacement, cancellation and fresh index use.
  Archive observer hooks expose ordering without changing the durability boundary.
- [Final review checklist](../../../docs/reviews/M2-REVIEW-CONDITIONS.md) inventories 80 retained
  review reports plus current UX/design conditions, maps each to tested source or
  exact unrun rows, and explicitly parks bound/V30 work under the evening scope.

## Verification

[Structured results, raw-log and assembly hashes](local-checks.json).

| Check | Result / actual scope |
|---|---|
| New SOP production C controls | 3/3 PASS, GCC + Clang, `-Wall -Wextra -Werror`, UBSan. Simultaneous/section-only opens, failed closes/reopen/ID/SOP, original witness and nineteen prune outcomes, two semantic negative mutations. |
| Offline driver/runner/UX controls | All 27 entry points PASS: 14 T5, 3 UX, 4 kernel fixtures, T4 verdict, exact-agent/source runner, feature defaults, import checker and new T11 control. Final T11 rerun after annotation/width correction also PASS. Synthetic import-checker result is not a new binary import gate. |
| Local feature builds | Service/App/Tests Debug and Release PASS, 0 warnings/errors; final focused builds recompile final Service/Tests with warnings as errors, 0/0. Offline SDK 10.0.400. |
| Focused agent execution | Debug **88 passed / 5 failed**, Release **88 passed / 5 failed**; all **14 added cases PASS**. Actual xUnit methods/data/assertions invoked serially in process, no method skips within the selected subset and no native-API substitution. Includes both real 10k archive controls, compaction chains/ties, maintenance retry, legacy compaction and epoch startup/replay controls. |
| Unchanged-base comparison | `2ed2b20b`: **74 passed / same 5 failed**. Failures are the three bound-name scaling rows and two Windows Unicode-comparator rows (`kernel32.dll`/Windows comparator required). These remain failures, not converted to skips/PASS. |
| Standard VSTest attempt | Aborted: sandbox local socket `SocketException (13): Permission denied`. The reflection diagnostic is separate from the Windows discovery/execution gate. |
| Test inventory | 1,102 -> 1,110 methods, **8 added / 0 removed or renamed**; all **43 required methods present**. Historical `t9-word-stream3` discovery preflight STOP already exists at base (one removed old bound-seeding method); not waived or repaired by changing tests. G02 records the stop. |
| API audit | Zero new external DDI call identifiers; 39 audited host DDI declarations supported. Full inherited audit FAILS identically on base/final at `Taint.c:356: InsertHeadList` (reference inventory gap), not reported as full API PASS. Both built-binary import gates remain required. |
| Review | [Sol 6.1 xhigh advisory ACCEPT WITH CONDITIONS](review-sol61.md), including final documentation check. Qualifying orchestrator review and Windows qualification remain separate. |

All scratch, generated sources, binaries and failed setup/control attempts remain
under `.scratch`; original `.ai-memory.toml` is untouched. No existing test,
assertion, threshold, capability or readiness gate was weakened or removed.

## Remaining risks and exact VM list

All Windows tests are **UNRUN here**. Use the exact G01–G04, T11-S01–S04,
T11-J01–J05, T4-F01/Q01/Q02 and carried T5–T10/UX rows in the
[checklist](../../../docs/reviews/M2-REVIEW-CONDITIONS.md#exact-windows-execution-rows-claude-all-unrun-here).
Claude runs protected rows as **t5actor**, win10-debug3/19045.2965 only, serially in
ordinary/runtime-Verifier/boot-Verifier, with matched hashes, independent bytes and
separate restoration. Feature kernel Debug/Release WDK/PREfast/ApiValidator/import
and feature agent Debug/Release × user/SYSTEM remain prerequisites.

A failed SOP reopen after original close may leave one uniquely named one-page
SYSTEM-only canary file; it fails trust and never deletes a substitute. Repeated
cleanup-close failure remains a kernel-resource diagnostic. Host shims do not
prove actual MM/FltMgr/view-only lifetime or lock contention. Necessary archive
history/barrier index memory grows with retained obligations; startup/compaction
are O(retained history). Checksums/local frontiers do not establish cold external
anti-rollback. Full metadata/MOTW/resources and MVP restart-time recovery limits
remain explicitly open in the checklist. This is no M2/T11 qualification claim.
