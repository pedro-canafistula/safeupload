# R21 keeper receipt writer: prepared Windows control plan

Status: prepared for independent review; **not executed**.

This bundle contains only the exact root-frozen R21 protocol module and a standalone Windows PowerShell 5.1 control script. The module copy is pinned to SHA-256 `f9dba8569c7bf2fafef648c5b6d49211ee299b6adc4651733dfb5acbbd6f251a` and length 102,549 bytes. Its root-frozen source is `output/review-candidates/m2-t5-harness-windows-gate-r21-root-a1/src/driver/scripts/HarnessWindowsGateProtocol.psm1`; the R21 author capture that records the same source pin is `output/review-candidates/m2-t5-harness-windows-gate-r21-root-a1/author/source-capture.json` (SHA-256 `5ab229c89e075097a715bd6730b94a3d1b6492cdfde6f3482f36117a1fcd44a0`).

The script checks for ordinary Windows PowerShell 5.1 Desktop x64, records its own PID and UTC start FILETIME, and hashes both inputs before and after. It reads the pinned module bytes and passes their decoded text to `Parser.ParseInput`. It does not import or invoke the module. It requires one top-level AST definition each for exactly these four functions, extracts each function's extent, reparses the extent as a one-function scriptblock, and dot-sources only those four function definitions:

- `Get-HarnessGateJobName`
- `Get-HarnessGateKeeperJobName`
- `Get-HarnessGateKeeperReadyPath`
- `Write-HarnessGateKeeperReadyReceipt`

The script supplies its own fixture-only `Get-HarnessGateStateRoot` adapter. That adapter returns one newly created GUID-named directory under the current process TEMP path. The writer's deterministic ready path is checked to have that directory as its parent before any receipt test. It creates an exclusive ownership marker inside the fixture. The marker and test receipt are the only paths the script considers owned. On any test failure it retains the fixture. On success it first verifies exact directory membership, plain-file attributes, and marker bytes; it deletes only its recorded owned files and removes the fixture only after confirming the directory is empty. It never recursively deletes, scans, or cleans the shared harness state root.

The prepared control exercises three source-writer cases:

1. A wrong main-job tuple and a wrong deterministic target path each fail with the writer's exact identity-guard message, and the fixture entry set remains unchanged.
2. A pre-existing final target containing a sentinel byte sequence causes the source writer to fail with an underlying `IOException` (including through a PowerShell method-invocation wrapper); the sentinel bytes remain exact and the writer's temporary artifact is absent.
3. A valid call creates the final receipt. The control compares its bytes to the exact closed UTF-8 JSON schema and current tuple, checks the property set and values, and compares the writer return value, actual file SHA-256, and independently assembled expected receipt SHA-256.

The script emits one complete `R21_RECEIPT_WRITER_CONTROL_PASS` JSON line only after all assertions, input post-pins, and owned-fixture cleanup succeed. Failure emits one `R21_RECEIPT_WRITER_CONTROL_FAIL` line to stderr and exits 1. Raw stdout/stderr and the process identity should be retained by the separate Windows runner.

The script itself is prepared but has not been parsed or run by PowerShell in this environment. The source-writer test is synchronous and does not observe the staging file during an in-progress partial write; it verifies actual source-writer success, guard failures, and final-name collision behavior. The frozen implementation order remains covered by independent source review. No .NET primitive-only staging probe is included, to keep the control focused on the pinned writer.

This is not a full module import, native job/process action, Add-Type call, service/actor/coordinator invocation, harness execution, builder test, or product-VM test. The known R16 standalone coordinator self-check failure at “Verified handback child is terminal only after justification closes and stage deletion is acknowledged” remains a qualification boundary. Root and the reviewer traced it to raw-versus-projected inputs in adjacent fixture variants; a separate R17 correction is pending and is not included here. Passing this prepared control would establish only the reviewed receipt writer behavior on the tested Windows PowerShell/.NET environment; it would not qualify the broader gate or product.

Before any execution, a different author should independently inspect the script, validate PS5.1 parser compatibility, verify the module and control hashes, and decide whether root should run it in a fresh directory with the exact two-file payload. This preparation alone authorizes no Windows execution.
