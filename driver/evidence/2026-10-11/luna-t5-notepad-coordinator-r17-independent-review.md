# R17 coordinator self-check review

## Frozen source and verdict

I reviewed `output/review-candidates/m2-t5-notepad-coordinator-r17-root-a1`, bound by `driver/evidence/2026-10-11/m2-t5-notepad-coordinator-r17-root-review-capture.json` (SHA-256 `7fd178b5560c782cecb655557e17889b1ce6b9739dc54d009191732c89289d79`). The capture records stable descriptor reads and post-copy equality for a closed inventory of 4 source files, 8 context files, and 7 author files.

The two standalone runtime inputs are `notepad-coordinator.SelfCheck.ps1` at SHA-256 `be52114a729e2861afccf6c73d900d5b03fc9f476e3664a64f10f959cb33ae47` and the unchanged `notepad-coordinator.ps1` at SHA-256 `c21757ed59acd607138be5eaafbdbcd2192dd48dd840c80563cb5b21f22d291d`. The two managed schema review inputs are unchanged at `4b270eaef4616c06ba52e0b88deb701d72463dcef8ed6c9c8cc4c39893b23f8d` and `5f4a5ae360513425f1ff79c3ad8c0c4fc8c2b3464f416cecc43c57c42224053a`.

**Bounded GO** for a fresh standalone Windows PowerShell 5.1 diagnostic using exactly those two runtime files. No source defect remains in the reviewed seven fixture substitutions. This is not source acceptance, a full harness result, or runtime qualification; I did not execute or parse the candidate.

## R16 failure and R17 correction

The preserved R16 diagnostic failed at the verified-handback positive assertion because its child fixture was raw while `Test-T5DirectEmptyHeldChildTerminal` consumes the projected shape. The helper reads top-level transfer identity and uses projected writer, state, lifecycle, and lineage properties. The raw journal object nests its transfer ID and does not provide that projection. The same wrong shape made six adjacent negative fixtures return false before reaching the condition their mutations were meant to test.

The R17-to-R16 diff changes exactly seven copy sources in `notepad-coordinator.SelfCheck.ps1`. `failedHandbackChild`, `pendingRenameChild`, `sameStageChild`, `wrongCreateReservationChild`, `wrongAllocationReferenceChild`, `cleanupStartedChild`, and `verifiedHandbackChild` now copy `$releasedPendingChildProjection`. Each existing field mutation remains immediately after its copy. All assertion conditions, assertion text, lineages, and other source bytes are unchanged. The negative variants therefore retain the valid projected identity and reach their named invalid condition; the verified-handback positive retains the same projection shape and can reach the intended closed-justification and `StageDeleted` branch.

The production coordinator and both managed schema files are unchanged. There is no new helper, gate, or validator change. This is the smallest correction for the recorded fixture mismatch; the standalone result will establish whether the existing assertions pass under PS 5.1.

## Diagnostic bounds

Use fresh run labels and a fresh absent two-file destination, pin these exact self-check and coordinator hashes before and after transfer and execution, confirm both files are ordinary regular files, verify both parse without errors under Windows PowerShell 5.1, and require one complete self-check PASS sentinel. Preserve process identity and all raw outputs. The previous R16 failed result remains immutable; do not reuse its paths or report it as an R17 result.

The approved diagnostic may execute the self-check’s isolated pure validation helpers and temporary fixture operations only. It must not invoke the coordinator top level, actor, service, full gate, product VM, host policy, network, or Git. A pass does not qualify R21’s existing 33-file harness inventory; that inventory must separately incorporate and pin the corrected self-check before any broader gate.
