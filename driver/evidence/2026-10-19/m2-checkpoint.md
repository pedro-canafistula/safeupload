# M2 checkpoint — 2026-10-19

T4–T11 remain open. Focused tests, builds and dev feedback do not qualify a protected pair.

- [x] T4/T5: retained focused Windows controls at `c1a3ba04`: **89/89 passed, zero skipped**;
  local raw receipt `../2026-10-17/m2-ux-agent-focus-1017c/` (TRX/build/package hashes).
- [x] T4: two feature WDK profiles, PREfast/ApiValidator **0 warnings / 0 errors**, imports PASS at `f8e99d25`;
  [build summary](../2026-10-17/exact-m2-ux-kernel-1017c-summary.txt).
- [ ] T4: full four-leg feature agent matrix `m2-ux-agent-1019a`, source `62127384`: **FAIL**, first leg 2,759/2,760,
  zero skipped. Office part-limit assertion received timeout; remaining legs did not run. Raw summary and TRX retained locally.
  Reviewed fix `a3ea2a48` applies the existing part ceiling before SDK graph loading; unchanged Windows coverage controls
  **204/204 passed** ([focused result](m2-openxml-focus-result.json), raw `m2-openxml-focus-1019a/`). Fresh full matrix
  `m2-ux-agent-1019b` started 11:30 BRT on builder1; Debug user **2,760/2,760** and SYSTEM **25/25 passed**, zero skipped;
  Release legs/final structured gate pending. Smoke/10k have not started.
- [x] T5–T11 dev loop: retained Office disk base/XML/no-TPM preflight passed (`dev-disk-preflight-1019a.json`);
  started win10-debug3 with reset NVRAM. Guest is 19045.2965, interactive t5actor, tray running.
- [x] T5–T11 dev loop: transferred package and driver hashes match the retained receipts; driver signature Valid.
  `Update-DevPair.ps1` at `907a8d5c` passes PS5.1 parsing and self-check (`m2dev1019a-ps51-selfcheck.txt`).
- [x] T5–T11 dev loop: pair staged on fresh versioned binary paths; old binaries retained, configuration readback passed
  (`m2dev1019a-install.txt`). Paired reboot scheduled (`m2dev1019a-reboot.txt`).
- [x] T5–T11 dev loop: first reboot exposed an updater boot-path defect; preserve receipt, use Windows-relative path (`aacdb2d1`),
  reboot again. Exact loaded driver/service/tray and Ready status pass (`m2dev1019a-postboot4.txt`).
- [ ] T5/T8: real Notepad clean case has no public file. Diagnostics identified a same-ID folder selected instead of the Save
  button; exact Button selector `859540ac` fixes that harness defect but the next real case still fails. No Notepad PASS.
  Each attempt/self-check/observer receipt is retained as `m2dev1019[a-e]-notepad-*`. Owner reauthorized focused diagnosis after
  repeated failures. No product threshold or privacy assertion changed.
- [ ] T8: Word SaveAs2 publishes the expected clean package (13,382 bytes), but Word reports ReadOnly=True; workflow FAIL.
  [Gate analysis](word-readonly-gate-analysis-sol-high.md) ties immediate reopen refusals to pending rename, unsealed and zero
  FileObjects; proposed exact-owner settlement wait is not implemented or independently accepted.
- [ ] T8: native construction feasibility first attempt `t8native1019a1` failed before structured rows;
  root fixture remained and cleanup masked the primary error. Retain failed run and fixture, instrument original/cleanup failures,
  then diagnose with a fresh label. Raw: `t8-construction-t8native1019a1/`; this is unprotected builder mechanism work.
  Instrumented attempt `t8native1019b1` captured `STATUS_REPARSE_POINT_ENCOUNTERED` on fixture registration before any row;
  root and failure evidence retained. Product design remains [REVISE](t8-design-review-sol-high.md), not implementation approval;
  [concrete design analysis](t8-concrete-design-analysis-sol-high.md) separates restore/fence work from unresolved stock producer proof.

Retained dev artifacts (verified again 2026-10-19):

| Artifact | SHA256 |
|---|---|
| Signed driver, `f8e99d25` | `B3830AF1D35D73CA33DD71E5417BAB3889F7260CF558AFE5BE0A44F509FD775E` |
| Dev agent ZIP, `c1a3ba04` | `5BFE59A84E38FB5A9FF22B52BE922E1F1C0463459987A39BD0244013806320A4` |
| Service executable | `F0287411619F10F7514741661A0B8439F8823ABA5EDC48FF2CE61560BF82470F` |
| Tray executable | `1077A7A13A72CB58C82EDF21CD380523CE66202D5C904992B2737FC02898F3A1` |

Retained dev disk is **not deleted** (owner instruction); this is not a qualification/restoration claim.
Qualification still requires fresh disposable disks, reset EFI, no TPM, unchanged base/XML and separate restoration.

- [x] T4 preparation: Office dev disk parked with both original run-state files retained under `m2t4-dev-disk-park/`;
  [receipt](m2t4-dev-disk-park/park-result.txt). Base stat and canonical XML unchanged, no TPM. Dev disk was not deleted.
- [ ] T4 preparation: `m2t4preflight1019a` baseline check on a fresh disposable disk, before any new product row. This is
  a baseline preflight, not a qualification/restoration claim for the retained development disk.
