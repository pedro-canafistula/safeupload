# Phase 1 feature-only delivery gates

Owner decision: 2026-10-15, “staging is the product; the staging-out profile is retired”
in the staging worktree's `driver/POST-MVP-PLAN.md`. This changes build/gate process only.
Product source, feature tests, activation/readiness gates and cutover approval are unchanged.

- [x] Agent delivery: `feature-debug`, `feature-release`, each with user and SYSTEM execution (4 legs).
  Required feature methods/cases, exact discovery/execution coverage, no skips, 0 warnings/errors,
  SYSTEM identity/lifetime proof and feature Release package validation remain required.
  Summary/source/provenance/compatibility receipts identify the profile set.
- [x] Kernel delivery: `owned-feature` (Debug), `owned-feature-release` (Release), both with
  PREfast/ApiValidator and 0 warnings/errors. Feature Inspector and writer fixture remain required.
  Signing still copies and verifies feature Debug. Imports must pass for both builds and the signed copy;
  missing/duplicate/failed per-artifact results fail the combined summary gate.
- [x] Developer defaults: local compile and required-test preflight use both feature profiles.
  Normal profiles remain explicit diagnostics through local compile arguments and preflight `--profile`.
- [x] Diagnostic continue: attempts all 4 legs, records 2 completed profiles/4 attempted legs,
  retains failures and always reports `AgentMatrixGate=False`. Parity remains a separate non-gate.
- [x] Offline controls: omissions, substitutions and guard mutations covered by the checks below.
- [ ] Real Windows verification: PS 5.1 gate, one agent matrix and one kernel build, using fresh labels.

Implementation is uncommitted on `wt/runner-builders`, based on `27c8807f`; no remote build or VM row
was launched for this change. Local evidence: `driver/evidence/2026-10-15/phase1-feature-delivery-offline.txt`.
The planned workload drops from 8 to 4 agent legs and 4 to 2 WDK builds; normal Release packaging
and the normal Inspector also disappear. Measured wall time saved awaits the real runs; use the
matrix duration receipt (first-leg time and every test over 60 s) and kernel build timestamps.

Files changed:

| Purpose | Files |
|---|---|
| Process documentation | [AGENTS.md](../AGENTS.md), this guide |
| Agent delivery and timing | [Invoke-ExactAgentMatrixBuild.py](scripts/Invoke-ExactAgentMatrixBuild.py), [Build-ExactAgentMatrix.ps1](scripts/Build-ExactAgentMatrix.ps1), [matrix-durations.py](scripts/matrix-durations.py) |
| Kernel delivery and summary/import gate | [Invoke-ExactSourceBuild.sh](scripts/Invoke-ExactSourceBuild.sh), [Build-ExactSource.ps1](scripts/Build-ExactSource.ps1) |
| Developer defaults | [Invoke-LocalAgentCompile.sh](scripts/Invoke-LocalAgentCompile.sh), [agent-test-preflight.py](scripts/agent-test-preflight.py) |
| Offline controls | [Invoke-ExactAgentMatrixBuild.SelfCheck.py](scripts/Invoke-ExactAgentMatrixBuild.SelfCheck.py), [Build-ExactAgentMatrix.SelfCheck.ps1](scripts/Build-ExactAgentMatrix.SelfCheck.ps1), [Build-ExactSource.SelfCheck.ps1](scripts/Build-ExactSource.SelfCheck.ps1), [Invoke-ExactSourceBuild.SelfCheck.py](scripts/Invoke-ExactSourceBuild.SelfCheck.py), [FeatureAgentDefaults.SelfCheck.py](scripts/FeatureAgentDefaults.SelfCheck.py) |

Local verification passed: 19 matrix controls, 2 kernel wrapper controls, 2 developer-default
controls, existing driver-import controls, both PowerShell self-checks (14 and 8 mutations),
shell/Python syntax and diff whitespace. All four changed PowerShell files parse under local
`pwsh` 7.4.2; this is separate from Windows PowerShell 5.1 verification. Comparison with the base
confirms the same 43 required feature methods, 26 v20 methods and 3 required case groups.

Run offline checks from the checkout root:

```bash
python3 driver/scripts/Invoke-ExactAgentMatrixBuild.SelfCheck.py
python3 driver/scripts/Invoke-ExactSourceBuild.SelfCheck.py
python3 driver/scripts/FeatureAgentDefaults.SelfCheck.py
python3 driver/scripts/Test-DriverImports.SelfCheck.py
pwsh -NoProfile -File driver/scripts/Build-ExactAgentMatrix.SelfCheck.ps1
pwsh -NoProfile -File driver/scripts/Build-ExactSource.SelfCheck.ps1
bash -n driver/scripts/Invoke-ExactSourceBuild.sh driver/scripts/Invoke-LocalAgentCompile.sh
```

Developer feedback (diagnostic):

```bash
bash driver/scripts/Invoke-LocalAgentCompile.sh
python3 driver/scripts/agent-test-preflight.py --baseline <last-passing-matrix-label>
# Explicit normal diagnostics only:
bash driver/scripts/Invoke-LocalAgentCompile.sh normal-debug normal-release
python3 driver/scripts/agent-test-preflight.py --baseline <old-matrix-label> --profile normal-debug --profile normal-release
```

After integrating the change into a committed delivery checkpoint, verify serially on builder1
(no concurrent job on that builder and no timing-sensitive T4 row on either builder):

```bash
SAFEUPLOAD_BUILDER=builder1 bash driver/scripts/Invoke-HarnessWindowsGate.sh <fresh-ps51-label> .
SAFEUPLOAD_BUILDER=builder1 python3 driver/scripts/Invoke-ExactAgentMatrixBuild.py <fresh-matrix-label> --commit <delivery-commit>
SAFEUPLOAD_BUILDER=builder1 bash driver/scripts/Invoke-ExactSourceBuild.sh <fresh-kernel-label> <delivery-commit>
```

Require `HarnessWindowsGate=PASS` with PS 5.1 parse/self-check/native-signature results;
`ExactAgentMatrixGate=PASS` with exactly the two feature profiles, both account legs, complete discovery/TRX
coverage and verified feature Release package/hashes; and `ExactSourceBuildSummaryGate=PASS` with both
feature WDK rows at 0/0, PREfast/ApiValidator, import results and verified signing. Inspect raw receipts,
source commit and artifact hashes. These build results do not qualify a protected driver/agent pair.
