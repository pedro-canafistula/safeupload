# R16 coordinator self-check failure diagnosis

## Frozen evidence

This is an additive diagnosis of the preserved R16 standalone diagnostic failure. The reviewed candidate is `output/review-candidates/m2-t5-notepad-coordinator-r16-root-a1`, bound by root capture `driver/evidence/2026-10-11/m2-t5-notepad-coordinator-r16-root-review-capture.json` (SHA-256 `479cd969a36c6d010efcd0758caf1f3f6a798f235b6accffef8d7a638ccd8411`). The exact R16 self-check and coordinator source hashes are `e64729a084d6d87db93bfc99a41cc95537cbf3e5e2f2977bf53c49761758afe8` and `c21757ed59acd607138be5eaafbdbcd2192dd48dd840c80563cb5b21f22d291d`.

The immutable R16 run record remains failed at `Verified handback child is terminal only after justification closes and stage deletion is acknowledged`. Root’s verification is `m2-t5-coordinator-r16-diag-a1-root-verification.json`, SHA-256 `c22d5fdeb88f1f8c212f57a1bb493ed32177aba7d1b93c1427d9a85a3468e757`; its failure disposition preserves the original process and inputs. This report does not authorize retry or cutover.

## Root cause

The failure is in the self-check fixture shape, not evidence of a production-validator mismatch. `Test-T5DirectEmptyHeldChildTerminal` consumes projected entries. It reads top-level fields such as `TransferId`, `IsV20`, `State`, and writer identity before it reaches the terminal-state branch. `Get-T5Projection` creates those fields from the raw journal entry, whose transfer ID is nested at `Transfer.TransferId`.

The valid baseline is projected at self-check lines 421–422 and passed to the helper at 424–425. The next seven child variants—failed handback, pending rename, same stage, wrong create reservation, wrong allocation reference, cleanup started, and verified handback—are each copied from the raw `$releasedPendingChild` and then passed directly to the projection validator. These raw objects lack top-level `TransferId` and `IsV20`; the helper therefore returns false at its initial identity guard before checking the changed condition. The failed-handback and pending-rename lineage assertions also receive raw children, so the missing child projection can itself make the parent’s exact reserved successor unresolved. Those negative assertions do not prove the named defects. The verified-handback assertion fails for the same shape mismatch before it can evaluate closed justification and acknowledged stage deletion.

The root’s PS 5.1 object-copy probe, result `m2-t5-ps51-object-copy-a1-root-result.json` (SHA-256 `262a820c2ab84ef04f03354e373bb610a7a6f1a779409be280c10db1e6135fc7`), confirms scalar-property mutations on `PSObject.Copy()` do not mutate the original object. Copy aliasing is not the cause.

## Smallest correction

Keep the production validator and every assertion unchanged. For each of those seven variants, copy `$releasedPendingChildProjection` instead of `$releasedPendingChild`. Each mutant then retains the full projected identity and lifecycle shape, while the existing field mutation exercises the intended condition. The failed-handback and pending-rename lineage calls will then receive projected children and test the actual lineage error. Preserve all assertion texts, conditions, and legacy/mixed/history controls; add no helper or gate.

This is static diagnosis only. No source was changed, no project function was invoked, and the failed R16 result and its process/source pins remain untouched.
