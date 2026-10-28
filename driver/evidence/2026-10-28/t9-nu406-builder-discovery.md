# T9 N-U4-06 control: builder mechanism discovery and PowerShell 5.1 gates

Mechanism discovery on builder 19045.6466 (`builder2`, `SU-BUILDER2`), admin remote-shell subject only. **Not target evidence, not qualification.** Target 19045.2965 must reproduce every row (N-U4-06).

| Run | Source / control SHA-256 | Result |
|---|---|---|
| Harness gate `m2t9nu406h2` | `a69e8e02` / `AE003E26…` | PASS: Windows PowerShell 5.1.19041.6456; parse, C# compile and self-check mutants |
| Discovery `nu406b1` | `a69e8e02` | **FAIL before the control ran**: the runner compared the CRLF preflight receipt with `grep -x` (harness defect, fixed in `ae62ab39`) |
| Discovery `nu406b2` | `ae62ab39` / `AE003E26…` | **DIFFERS**: all 32 replacement / 48 allocation / 7 fault / 8 retention / 1 release rows ran. 50 comparisons PASS, 12 record-only (unpreallocated chunked allocation), 2 DIFFERS, both from the two unmeasured FileId hypotheses |
| Harness gate `m2t9nu501h1` | working tree at `ae62ab39` | **FAIL** in the unrelated T4 `StagedInvariantProofAdapters.SelfCheck.ps1`: sharing violation reading its own temporary `identity.clixml` (it had passed in `h1`/`h2`). Intermittent harness defect; fix if it repeats |
| Harness gate `m2t9nu501h2` | `b7877339` / `9338320A…` | PASS, including both N-U5-01 guest scripts |
| Discovery `nu406b3` | `b7877339` / `9338320A…` | **PASS**: 52 PASS + 12 record-only, every row count complete, empty stderr, child exit 0 |

Measured on the builder (`nu406b2`, reproduced by `nu406b3`):

- Reopening the held, POSIX-unlinked predecessor by FileId (relative to the anchor, `FILE_OPEN_BY_FILE_ID`) **succeeds** (`0x00000000`). It returns the same identity with Links=0 and DeletePending=True; the hypothesis was `0xC0000056`.
- After the last handle closes, the identical request returns `0xC000000D` (the hypothesis was `0xC000000F`). Because the same request succeeded while held, the change is attributed to object destruction.
- Every fault stage (preallocation, write, F1, EOF, F2, F3) refused through a handle without write access returns exactly `0xC0000022`, and class 65/flags 3 without predecessor SHARE_DELETE returns `0xC0000043`. Every fault row is Held. Retained R_phys never decreases across the fault and the normalization, including a real 3xQ overrun. The release row stays NativeDestroyedChargeHeld: no native refund, and the persisted release record remains agent-side evidence.
- Volume free-cluster deltas are recorded only, with no invented tolerance.

Raw evidence (ignored by git): `driver/evidence/2026-10-28/t9-builder-native-nu406b{1,2,3}/`.
