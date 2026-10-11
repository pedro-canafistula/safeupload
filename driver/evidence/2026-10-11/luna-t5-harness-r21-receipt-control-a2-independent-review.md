# R21 receipt-writer control a2 review

## Frozen inputs and verdict

I reviewed `output/review-candidates/m2-t5-harness-r21-receipt-writer-control-a2-root-a1`, bound by `driver/evidence/2026-10-11/m2-t5-harness-r21-receipt-writer-control-a2-root-review-capture.json` (SHA-256 `0ec098e291138b215e891c77e54f97075236cbbe7e63c6aa3b61a1f0adb2df72`). The capture records a closed inventory, stable two-descriptor reads, and post-copy equality for its 7 author, context, and payload files. Its payload pins the R21 module at `f9dba8569c7bf2fafef648c5b6d49211ee299b6adc4651733dfb5acbbd6f251a` and the control at `265b1bef47b4b5ccd907cfc5f8427bbfee5113f583ae8136d042e5d041f1b3c0`.

**Bounded GO** for the exact two-file control in a fresh private TEMP fixture under ordinary Windows PowerShell 5.1 Desktop x64. I compared the frozen a2 control with the rejected a1 control: the only change is the success-result boundary string. It replaces the false claim that no Windows run has occurred with `This Windows control exercises only the extracted receipt writer; it does not qualify the full gate or product.` The module bytes, executable statements, conditions, assertions, cleanup, and function extraction are unchanged. The a1 issue is resolved, and the a2 PASS output now describes the scope truthfully.

## Control boundary

The control verifies the exact R21 module length and SHA-256, parses module bytes as data, and extracts only the four pinned top-level function definitions needed for job names, the ready path, and the receipt writer. It defines its own fixture-only state-root adapter. It does not import the module or invoke native code, `Add-Type`, remote commands, a service, the coordinator, or the harness. Its target is checked to resolve inside a new GUID-named TEMP directory.

The covered cases reject a wrong job tuple and wrong final path before writing; require an existing-target collision to surface an underlying `IOException`, preserve sentinel bytes, and leave no temporary artifact; and verify the successful receipt’s exact closed JSON bytes, tuple, and matching returned/on-disk/independently assembled SHA-256. Fixture membership is checked against only owned files. On failure the fixture is retained; on success owned files are deleted only after exact membership and marker checks, and the directory is removed only when empty.

The synchronous control does not observe a staging file during an in-progress partial write. It provides focused Windows behavior evidence for the actual extracted writer’s validation, no-overwrite collision, cleanup, successful receipt, and hash. The frozen source review remains the basis for the flush-close-move order and final-path-only consumer claim.

## Limits

This is an authorization for that bounded control only. It does not qualify the full R21 gate, the preserved R16 coordinator failure, a product run, or cutover. I did not parse or execute either payload, import the module, invoke the writer, use a VM, access a host, or perform a Git operation; this verdict is read-only source review.
