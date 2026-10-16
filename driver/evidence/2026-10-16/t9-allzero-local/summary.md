# T9 all-zero card local verification — 2026-10-16

Uncommitted on `wt/t9-allzero`; baseline `feat/driver-m2` at `08897d59a89edbf316675aea447afc29e620b289`.
Only `0000000000000000` is excluded; all other 16-digit Luhn-valid numbers retain detection.

- Final `Invoke-LocalAgentCompile.sh normal-debug normal-release feature-debug feature-release`: 12/12 Service/App/Tests builds pass, 0 warnings/errors, SDK 10.0.400/runtime 10.0.11. See `compile-final.log`.
- Feature Debug and Release: 114/114 focused cases pass each, no failures/skips (228 executions). Uses actual xUnit 2.9.3 in-process discovery and execution, including original test assertions and lifecycle. See `current-feature-*-discovery.json` and `current-feature-*-run.log`.
- Existing streaming/legacy parity corpus is byte-for-byte unchanged and passes in both configurations.
- `agent-test-preflight.py --baseline feat-driver-m2-local --evidence driver/evidence/2026-10-16`: PASS, all 43 required methods present, no removed methods. Its baseline is local xUnit discovery from a clean Git archive of the stated ref, not a passing Windows matrix. Three unchanged normal-only methods appear as additions in its source-versus-feature-discovery report; direct source comparison shows exactly five new methods and zero removed methods.
- Discovery: 2,197 baseline -> 2,235 current cases in each feature configuration, +38 / -0. Expected Windows legs: Debug user 2,235; Debug SYSTEM 2,235; Release user 2,235; Release SYSTEM 2,235; total 8,940.
- `git diff --check`: PASS. No existing test removals, threshold/limit changes, commits or pushes.

VSTest aborted before running tests because the workspace sandbox denies its TCP socket (`SocketException (13)`); receipt retained as `focused-normal-debug.trx`. Temporary runner compile errors (variable scope and xUnit message-sink inheritance) and an initial preflight evidence-directory mismatch are retained under `attempt1-*`/`attempt2-*`; these were diagnostic tooling setup failures, not product test failures. The corrected in-process runner, orchestration script, inventories, source patch and local assembly hashes are retained here.

These are local diagnostics. No Windows user/SYSTEM matrix, package delivery, driver build, protected VM row or product qualification is claimed.
