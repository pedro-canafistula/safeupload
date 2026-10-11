# Independent focused source review: SafeUpload T5 Windows gate R20

**Bounded verdict: PASS for the R20 shell-pin correction and local pre-delivery verification.** The reviewed R20 bundle may proceed to the already-scoped source diagnostic step under the existing containment design. This verdict covers the one-file, five-literal correction and its offline verification; it is not full source acceptance, Windows runtime qualification, or T5 gate completion. The inherited partial-readiness-file race remains an open, fail-closed startup reliability concern.

## Scope and frozen evidence

The frozen source candidate is `output/review-candidates/m2-t5-harness-windows-gate-r20-root-a1/src`. Its exact 63-path inventory, sizes, and SHA-256 pins are recorded in `driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r20-root-review-capture.json` (SHA-256 `41e88a1b5dcb7bceff4782263f21c4fe9f75819e43738fcec877ea86bf9adacc`). The canonical inventory digest is `e5107b6cf73adcbe8718f377e5621c2a99d7de020604e3413aa36a7239d12190`. I verified every captured path, byte count, and SHA-256 against the candidate tree: 63 of 63 match, with no missing or extra files. The full pin table is preserved in that capture rather than duplicated here.

The capture records the R19 baseline capture SHA-256 `8958ae1cc166773431c5b463dbe8ebfe7497d9766f8b7e9a3cd3c4156e155a13`, 62 byte-identical source files, one changed file, no additions or removals, and all 33 execution inputs unchanged. I independently compared the two trees and confirmed that the only changed path is `driver/scripts/Invoke-HarnessWindowsGate.sh`. R20's shell SHA-256 is `53877a59d30bc7a993bb527438d4ed17539e59763d38742e0f38907a896ca32f`.

The root offline-control receipt is `driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r20-root-offline-controls.json`, SHA-256 `e40047902daca1a4bbeff28137d084908e3f96f9698dc36b5d5fa28230b27575`. It records nine exact shell literal bindings, successful real manifest verification, rejection of all five stale-pin mutants, and that no Windows execution, network action, or product VM occurred. The receipt also records that all six PowerShell compiler input hashes are unchanged from R19. The R19 root compiler-only receipt remains `driver/evidence/2026-10-11/m2-t5-harness-r19-compiler-a1-root-result.json`, SHA-256 `30c0b0590db7ae31e8893ae47528bbab418a590be2f5331a66c426ba5a672185`; it reports zero parse errors for the six PowerShell sources and two embedded workers and zero warnings/errors compiling the embedded protocol C#. This compile-only result does not execute the source or qualify runtime behavior.

## R20 correction and independent controls

R20 changes only five expected hash literals in the frozen shell. Each now matches its corresponding R19-pinned local file:

| Shell binding | R19 stale value | R20 value |
|---|---|---|
| `expected_client_sha256` | `60ab182e917731587dee238f0c802a9ac6aff8c6bf8cd31a8890f4d180e7d3f1` | `d5f558bc6c7435a0e8f6628ae2fffc465b34ed0981d1470d90de44980f4975c8` |
| `expected_manifest_sha256` | `2cbe36281a8d8d1dbb8698cb34fd490204810382b3eb96c525b126bdd3cf0784` | `7d5ea90a1cf1c941610572f038a9db8ff43b5c934e41a0adbf3f54bbd98d11f7` |
| `expected_runner_sha256` | `eeb0054a906b2f932ad09a4b359c146f891872cfe8a885c6d5a44c091cb682eb` | `6e1765e52ed051a493f55826f066d3fc050bcbe75edef783bd4c555a84eb5918` |
| `expected_keeper_sha256` | `7561a06f163990460ee42e4865c93d74cef8fab1801696dfcc816fcdc152d9c8` | `aa24884d0f943ff0e97bc37132f5fe4a9f2c595166a7a7b9515198abc2606fa2` |
| `expected_fixture_sha256` | `812a514fa5e79ef9793853ca71f07fe5fdb6948ff1f194438747a83df796ba03` | `599eb7da9e0177b2443d5edd937a15b29c72b0357e5c4b71a3c2397b62fb1489` |

The helper, worker, remote-control, and protocol expected hashes remain unchanged and also match their R20 bytes. I checked all nine shell `expected_*_sha256` bindings against the corresponding pinned files. I then ran the real local `verify_local` pre-delivery path in a disposable copy with its remote phase stopped after local verification: the unmodified R20 shell passed and the manifest verifier checked 33 execution sources plus eight support files (41 total). Five separate disposable copies changed one corrected literal back to its R19 value; each was rejected with exit 2 before remote work. The root receipt independently records the same five mutant rejections and manifest-verification result. `bash -n` passed, and I repeated the manifest verifier against the frozen candidate; it passed all 41 files.

The R19 root blocker is therefore closed for this pre-delivery path: the old client literal caused the shell to stop before manifest verification, and the other four stale literals would likewise fail their local hash comparisons. The shell's finish self-check alone is not sufficient evidence for this closure because it stubs `verify_local`; the real local pre-delivery path and one-at-a-time stale-literal mutations exercise the actual comparisons.

## Inherited keeper containment and open reliability concern

The keeper implementation is byte-identical to the R19-reviewed file. R19 arms sticky handle retention after verifying exact job membership and persisted token/path/PID/FILETIME, but before publishing readiness. If readiness publication or a later drain/query fails, it emits at most one sanitized diagnostic and remains alive with both inherited job handles. It closes those handles only after final active-count zero and an exact empty PID list. The one-hour monotonic timer initiates a real drain; it is not treated as evidence that the job is empty. RUN/CANCEL continue to use held native process/job identities, and a missing job does not become synthetic zero. The lifecycle fixture source retains the terminal proof sequence: RUN's native process handle is terminal while the same keeper remains in the outer fixture job; exact CANCEL then kills that keeper, proves the named jobs empty, and proves the outer job empty after the controller ends. These controls were not executed as a Windows fixture.

**Open bounded reliability concern:** readiness is created at its final pathname before the write and flush complete. RUN treats any visible file as complete and reads/parses it immediately without retrying a partial or empty read. A reader that arrives during the write can cause truthful startup NO_GO and exact cleanup. The reviewed code does not turn that incomplete receipt into false PASS or drop the retained keeper handles. This race remains a potential transient startup failure; runtime frequency is untested. R20 does not change or resolve it.

## Limits

This is a focused review of the shell pin propagation plus the inherited R19 keeper containment. It does not re-review the unchanged 62 files as a new full source acceptance. The separate T5 coordinator self-check concern noted during R19 review is also unchanged and outside this focused correction; accordingly this report does not call the overall T5 gate fully accepted. No source module, harness, fixture, actor, service, coordinator, or product VM was executed; no native method or Windows job operation was invoked; no network action or host-policy change was performed. Normal compile-out and taint-retention requirements remain in force, and the owned-stream MVP goal remains open.
