# Driver scripts

Builds, Windows harnesses, verdict checks and lab runners. Read the usage comment at the top of a script before running it: the lab runners
change a VM and several of them only make sense for one target (`win10-debug3`, see `debuggees.txt` and
[`AGENTS.md`](../../AGENTS.md)). Do not edit a launcher or harness file while a row or batch that uses it is running.

## Offline checks (no VM, no builder)

| Script | What it checks |
|---|---|
| `t4/verdict-selfcheck.py` | Replays retained T4 evidence through the cycles launcher's own verdict code, including the pool band controls. |
| `Invoke-ExactAgentMatrixBuild.SelfCheck.py` | Matrix summary and package rules with synthetic artifacts. |
| `Invoke-StagedInvariantQualification.ArchivePayload.SelfCheck.py` | Host validation of archived journal payload frames. |
| `check-doc-links.py` | Relative Markdown links across the tracked docs; fails only on links absent from `doc-links-baseline.txt`. |
| `Invoke-LocalAgentCompile.sh` | Local offline compile of the agent for feature Debug/Release. Diagnostic only; the matrix is the gate. |
| `agent-test-preflight.py` | Preflight before queuing an agent matrix. |
| `t5/*-selfcheck.py`, `t11/`, `ux/*-selfcheck.py` | Source-level controls for the kernel and agent changes of those items. |
| `*.SelfCheck.ps1` | Controls for one harness file; they run in the Windows PowerShell 5.1 gate below. |

## Builds and gates

| Script | Purpose |
|---|---|
| `Invoke-ExactSourceBuild.sh <label> <commit>` | Build committed kernel source on the isolated builder and fetch the artifacts (WDK profiles, PREfast, ApiValidator, imports). |
| `Invoke-ExactAgentMatrixBuild.py <label> --commit <commit>` | Four-leg feature Debug/Release agent matrix (user + SYSTEM legs) and the service package. Run it on the first free approved builder (`approved-builders.json`); one job per builder. |
| `Invoke-ExactAgentBuild.sh <label> [commit]` | A single exact agent build; read its summary/TRX for the verdict. |
| `Invoke-HarnessWindowsGate.sh <label> .` | Windows PowerShell 5.1 parse and native-signature gate for the harness files plus their self-checks. |
| `Build-ExactAgent*.ps1`, `Build-ExactSource.ps1`, `Build-ExactSectionFault.ps1` | The builder-side scripts those launchers upload and run. |
| `Test-DriverImports.py`, `reference/win10-19045-exports.txt` | Import availability against the qualified Windows 10 export list. |
| `Verify-BuilderBuild.sh` | Independent verification of a builder run from the builder's own files. |

## Lab plumbing

| File | Purpose |
|---|---|
| `run-disk.sh`, `image-store.sh` | Sourced by the runners: disposable run disk (qcow2 overlay, EFI reset, deleted afterwards). |
| `Verify-RunDiskRestoration.sh` | Boots a fresh disposable disk and re-runs the baseline check (the separate restoration proof). |
| `remote_ps.py` | Runs stdin PowerShell on a recorded debuggee or an approved builder. |
| `approved-builders.json`, `approved_builders.py`, `ApprovedBuilders.ps1` | Approved builder inventory and selection. |
| `debuggees.txt` | Debuggee inventory; current approval is `win10-debug3` only. |
| `Update-DevPair.ps1`, `Prepare-DemoVm.sh` | Install a driver and agent pair on the authorized dev disk or a demo VM. |

## Product rows (one launcher per T item)

Each launcher takes `<debuggee> <label> <driver.sys> <agent zip> [ordinary|runtime-verifier|boot-verifier]`, runs on its own disposable run disk and
writes `driver/evidence/<date>/<label>-*` with a `<label>-verdict.txt`. The exit status is not a verdict; read the verdict lines.

| Launcher | Item | Guest-side files |
|---|---|---|
| `Invoke-StageCycles.sh` | T4: N save cycles in one boot, pool and context gates | `t4/` |
| `Invoke-StageNotepad.sh` | T5: Notepad Save As, native delete orders, empty files | `t5/notepad-*.ps1`, `t5/*-native-control.ps1` |
| `Invoke-StageMoves.sh` | T6: moves into a protected folder | `t6/` |
| `Invoke-StagePermissions.sh` | T10: permission and owner changes | `t10/` |
| `Invoke-InstallerWorkload.sh`, `Invoke-NewProfileDiagnosis.sh` | T3 / T2: installers, first sign-in of a new user | `t3/` |
| `t8/Invoke-MetadataConstructionNativeControl.sh` | T8: native metadata construction control | `t8/` |
| `t8/motw-completion-native-control.ps1` | T8: unprotected Edge/shell MOTW completion feasibility probe; see its adjacent `.md` | `t8/` |
| `t8/explorer-paste-native-control.ps1` | T8: actual Explorer Win+E/copy/paste on unprotected tagged fixtures; pair with owned FileIO tracing | `t8/` |

## Phase 4 invariant suite (raw-volume cells)

`Test-StagedInvariantSuite.ps1` (guest side), `StagedInvariantCases.psd1` (immutable case data), `StagedInvariantObserver.psm1` (independent raw-volume observer),
`Invoke-StagedInvariantQualification.py` (host adapter), `Invoke-StagedSuiteBatch.sh` (serial batches, one run disk per case),
`suite_case_verdict.py` and `Get-StagedMvpStatus.py` (verdicts and the MVP gate). `StagedInvariant*.SelfCheck.ps1` hold the pure controls for each part.

## Earlier single-purpose experiments

`Test-Staged*.ps1` and the `Invoke-Staged*Qualification.py` checkpoints are the focused probes from the 2026-10 MVP phase (fences, aliases, locks, identity, journal
recovery, publication permits, ...). They run through `Invoke-DebuggeeExperiment.sh` or the checkpoint adapters and are kept for reference and regression; each one's
header says what it proves. Small C# helpers they use live in `Staged*Probe*/`, `StagedApprovalClient/`, `LargeFileMeasure/` and `InspectionMeasure/`.

## Original deployment scripts

`Publish-SafeUpload.ps1` (build, sign and package) and `Invoke-SafeUploadTest.ps1` (install and test) automate parts A and B of
[`docs/operations/DEPLOY.md`](../docs/operations/DEPLOY.md); `serve.py` serves the package to the target VM.
