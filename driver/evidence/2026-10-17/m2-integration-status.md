# M2 integration checkpoint — 2026-10-17

**M2 incomplete. No product VM boot or qualification in this integration continuation.** Target remains win10-debug3 only;
win10-debug2 stays off. No host-wide configuration changed. Memory/reports unrelated to this work remain untouched.

| Scope | Evidence / source | Result and limit |
|---|---|---|
| Integrated kernel/agent | `412f05ad` | Namespace, context lease/retirement, archive/epoch and absent-stage fixes combined; not qualified. |
| First WDK build | [m2-ux-kernel-1017a](exact-m2-ux-kernel-1017a-summary.txt), [imports](exact-m2-ux-kernel-1017a-imports.txt) | Feature Debug/Release, PREfast/ApiValidator 0 warnings/errors; imports PASS. This earlier source still had review blockers. |
| Kernel correction review | [Sol high review](kernel-namespace-integration-sol-high.md); `23b7cbcf`, `311c393e` | ACCEPT WITH CONDITIONS; host controls only. |
| Corrected-kernel first build | [m2-ux-kernel-1017b](exact-m2-ux-kernel-1017b-summary.txt) | FAIL: C28251 annotation mismatch in query wrapper. Corrected in `f8e99d25`; fresh [m2-ux-kernel-1017c](exact-m2-ux-kernel-1017c-summary.txt) passes both profiles 0/0, [imports PASS](exact-m2-ux-kernel-1017c-imports.txt), signing valid. No suppression. |
| Harness first attempt | local `harness-windows-gate-m2-ux-harness-1017a.txt` | FAIL: unique probe absent from bounded top-30 directory list. First receipt retained. |
| Harness correction | `8735cd37`; [m2-ux-harness-1017b](harness-windows-gate-m2-ux-harness-1017b.txt) | PS5.1 parse and every self-check PASS, including immediate-reopen native controls. Exact probe aggregates replace ranking dependence; display bounds unchanged; failed ETL retained in future failures. |
| First agent attempt | local `exact-agent-matrix-m2-ux-agent-1017a-summary.txt` | FAIL: xUnit2031 assertion style; same assertion corrected in `80dc919c`. No tests executed. |
| Agent matrix | [m2-ux-agent-1017b summary](exact-agent-matrix-m2-ux-agent-1017b-summary.txt), local `exact-agent-matrix-m2-ux-agent-1017b-feature-debug-results-agent-tests-user.trx` | Feature Debug user: 2,753 passed / 7 failed / 0 skipped, 2,760 executed; remaining legs not run. Matrix FAIL. |
| Agent repair candidate | `6e29d67f`, diagnostics `0264806f` | Effective policy-default fixtures, actual Windows DACL restore, deterministic checkpoint collision and exact legacy child cleanup reservation. Assertions/deadlines unchanged. Local feature Debug Service/App/Tests compile PASS. Windows focused diagnostic pending, then all four matrix legs required. |

Seven matrix failures: two same-version policy mutations read an omitted default field; a handback policy mutation has the same
fixture issue; reservation recovery reused an unchanged ACL object (Windows SetAccessControl no-op); notification checkpoint fault
used a directory (Windows reports UnauthorizedAccessException); legacy owner cleanup incorrectly inherited current-name status after
an unattached child retired; timeout-failure justification exceeded its 5-second control deadline. The last remains under diagnosis,
with existing publisher phase logs/QPC added to its test output before a focused retry. No deadline increase or assertion removal.

Next: finish current kernel build and focused agent diagnostic; resolve their actual failures; pass the four-leg matrix; idle builders
for timing-sensitive T4 smoke/10k and preserve separate restoration receipts. All T5–T11 final pair gates remain outstanding.
Raw outputs stay local per evidence/README.md; only cited compact receipts are tracked.
