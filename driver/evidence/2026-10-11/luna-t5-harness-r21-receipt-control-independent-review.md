# R21 receipt-writer control review

## Frozen inputs and verdict

I reviewed the exact root-frozen control bundle `output/review-candidates/m2-t5-harness-r21-receipt-writer-control-root-a1`, bound by `driver/evidence/2026-10-11/m2-t5-harness-r21-receipt-writer-control-root-review-capture.json` (SHA-256 `2f0c2865bf0fed7f0697395a897c9a4bbee27edbb6dbc96b589afca8346d16c0`). The 10-file capture records stable descriptor reads and post-copy equality. The payload pins the exact R21 protocol module at SHA-256 `f9dba8569c7bf2fafef648c5b6d49211ee299b6adc4651733dfb5acbbd6f251a` and the control at SHA-256 `16ad9481d69b2e76ad13cbf5b29368ae08f5ea53b726d73b2282a39f50119049`.

**NO-GO for executing this exact frozen control.** Its success result includes the literal boundary statement `No Windows run has occurred yet; this script is a prepared plan for independent review.` at control line 302, after the Windows writer control has run. A PASS result would therefore contain a false statement about its own execution. Remove or replace that stale text, freeze a new control candidate, and review the new capture before running it. This is an evidence-truthfulness correction; it does not require weakening any test.

## Scope and checks reviewed

The test boundary is otherwise appropriate for a focused Windows-only receipt-writer control. The script requires Windows PowerShell 5.1 Desktop x64, records PID and UTC start FILETIME, checks the exact module length/hash, parses module bytes as data, and verifies there is exactly one top-level AST definition for each of four allowlisted functions: the two job-name helpers, the deterministic ready-path helper, and the actual R21 writer. It reparses and dot-sources only those function extents. It does not import the module or invoke `Add-Type`, native APIs, process controls, remote commands, or the harness.

The fixture adapter maps the deterministic receipt path into a fresh GUID-named directory beneath TEMP. The script creates an ownership marker, tracks only its own files, verifies exact directory membership, and on success deletes only those recorded files before removing the empty directory. Its failure path retains the fixture for review; it does not recursively delete or touch the shared harness state root.

The planned cases test that an invalid job tuple and wrong ready path are rejected before any write; a pre-existing final target raises an underlying `IOException`, preserves the exact sentinel bytes, and leaves no temporary artifact; and a valid call produces exactly the expected closed UTF-8 receipt and matching return/on-disk/independently assembled hashes. The collision assertion correctly inspects `GetBaseException()` so a PowerShell method-invocation wrapper cannot hide the required underlying exception type. The test asserts only its exact owned fixture entries after each path.

The script does not observe a temporary file during a partial in-progress write. Its runtime evidence would cover the actual source writer’s success, validation guards, and final-name collision behavior. The publication order and final-path-only consumer checks remain supported by the separate source review; the synchronous control must not be described as a race-observation test or full gate qualification.

## Limits

This is a read-only source review. I did not parse or execute the control, invoke the writer, import the module, use a VM, access a host, or perform a Git operation. No R21 receipt-writer Windows result is established by this report. The R16 coordinator self-check failure and R17 fixture correction remain separate qualification boundaries; passing a corrected receipt-writer control would not qualify the full harness or product.
