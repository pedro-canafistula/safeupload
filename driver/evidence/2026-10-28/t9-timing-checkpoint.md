# T9 timing diagnostic continuation — 2026-10-28

**14/14 focused controls and the subsequent four-leg Windows delivery gate pass.**
Owner authorized the prepared diagnostic and set the persistent M2 completion
goal. Scope, thresholds, existing deferrals and runtime activation gates remain.
No protected driver/agent pair was installed or qualified by this work.

Source `afd972efc73600cb247e76742a9842cf741445ff`, source archive SHA-256
`24b60f4485a0c5cab3962f4fe8a67acbcb982398a5f33740e1bd3819c38a4671`.
The existing exact-source runner prepared the archive; the diagnostic compiled
fresh feature Debug tests with warnings as errors, then selected precisely the
three affected methods (14 cases), user leg only.

## Capacity refusal retained

`m2t9diag1028a1` on builder1 refused preflight at 6,139,707,392 free bytes,
below the unchanged 15-GiB diagnostic headroom requirement. No source upload,
compilation or test started. [Refusal receipt](t9-diagnostic-m2t9diag1028a1/result.json).
The successful feature profiles already had their generated outputs removed.
An audit preserved all sources, packages, receipts and failed outputs; no files
were deleted. Builder1 was gracefully shut down and excluded as capacity-ineligible
for the next job. The existing first-free dispatcher selected approved builder2.

## Focused result and limits

`m2t9diag1028a2`, builder2 `SU-BUILDER2` / Windows 19045.6466, user `vika`,
PowerShell 5.1.19041.6456, about 34.9 GiB free at preflight:

- Fresh Debug build: zero warnings/errors. Test DLL SHA-256
  `B169E8D4F94ACA08061907C5223B7F2EA766D9741BFD796A238B55A76D32DE5F`.
- **14 executed / 14 passed / zero skips**, about 12 seconds total. Both clean
  Office package cases and all ten failed-inspection publisher cases pass.
- Legacy queue+parser deadline: result 6,002 ms; queued return about 6,006.6 ms;
  parser cancellation about 6,002.2 ms. Staged counterpart about six seconds.
- Timeout/override publisher case completes the whole test in about 2.06 s;
  captured journal flushes total about 32.8 ms. Image/override whole test about
  68 ms. These observations include subsequent hand-back/recovery/justification
  work in the test; they are not isolated initial-publication latency figures.
- xUnit timing/log output is present in the TRX. [Structured result](t9-diagnostic-m2t9diag1028a2/result.json)
  retains all 14 outcomes/output and binds the local raw TRX/build/transport logs.

This demonstrates success under these inputs on the other approved builder.
It does not attribute or erase the two failed Windows attempts on builder1.
Different builder, free space and load prevent a causal comparison. No product
fix, assertion change, timeout increase or failure waiver was made.

After inspecting these timings, required four-leg matrix **m2t9totalsb1** was
started on builder2, source `afd972ef`, with product targets off and no broad
FileIO trace. It must establish exact discovery/execution, both user/SYSTEM legs,
both feature configurations, packages/hashes and zero warnings/errors before a
delivery-gate result can be recorded. A focused green result cannot substitute.

## Completed four-leg gate

**m2t9totalsb1: ExactAgentMatrixGate=PASS**, source `afd972ef`, builder2.
Feature Debug and Release each executed exactly **3,159 user + 25 SYSTEM**
cases, matching discovery and required result IDs, zero failures/skips. All
service/app/test builds and discovery steps have zero warnings/errors. Both
SYSTEM jobs proved process/task cleanup. The complete result is 6,368 executions.
[Structured gate receipt](t9-matrix-m2t9totalsb1/result.json) binds all four raw
TRX files, source/archive, package validation and the retained root readout.

Verified Release package SHA-256
`E02380695BA4F1EF3F52FB4D3FCDE1A2FBC8A3D92BCBF03D1D342F5EAD522B3D`;
service EXE `5F6D38BBF1E00D88517711F11C875FC4872E5B1CCB6870F41611CCD410E2CAA9`;
tray EXE `3B1ED61D5FE0FCAFF5E1440D30C86979CEC7BC420344D75318295C68824934BC`.
No installation or runtime qualification. This satisfies the maintained-totals
review's Windows delivery condition, not the later passive wire/schema changes,
growing reservations, shared metadata debt or M2 pair qualification. The prior
failed receipts remain failed; their cause has not been established by this pass.
