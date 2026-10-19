# M2 checkpoint — 2026-10-19

T4–T11 remain open. Focused tests, builds and dev feedback do not qualify a protected pair.

- [x] T4/T5: retained focused Windows controls at `c1a3ba04`: **89/89 passed, zero skipped**;
  local raw receipt `../2026-10-17/m2-ux-agent-focus-1017c/` (TRX/build/package hashes).
- [x] T4: two feature WDK profiles, PREfast/ApiValidator **0 warnings / 0 errors**, imports PASS at `f8e99d25`;
  [build summary](../2026-10-17/exact-m2-ux-kernel-1017c-summary.txt).
- [ ] T4: full four-leg feature agent matrix `m2-ux-agent-1019a`, source `62127384`, started 11:17 BRT on builder1.
  Raw host output: `m2-ux-agent-1019a-host.txt`; no matrix verdict yet. Smoke/10k have not started.
- [x] T5–T11 dev loop: retained Office disk base/XML/no-TPM preflight passed (`dev-disk-preflight-1019a.json`);
  started win10-debug3 with reset NVRAM. Guest is 19045.2965, interactive t5actor, tray running.
- [x] T5–T11 dev loop: transferred package and driver hashes match the retained receipts; driver signature Valid.
  `Update-DevPair.ps1` at `907a8d5c` passes PS5.1 parsing and self-check (`m2dev1019a-ps51-selfcheck.txt`).
- [x] T5–T11 dev loop: pair staged on fresh versioned binary paths; old binaries retained, configuration readback passed
  (`m2dev1019a-install.txt`). Paired reboot scheduled (`m2dev1019a-reboot.txt`).
- [ ] T5–T11: verify the rebooted pair and collect real app/independent public-byte evidence. No new app PASS yet.
- [ ] T8: native construction feasibility first attempt `t8native1019a1` failed before structured rows;
  root fixture remained and cleanup masked the primary error. Retain failed run and fixture, instrument original/cleanup failures,
  then diagnose with a fresh label. Raw: `t8-construction-t8native1019a1/`; this is unprotected builder mechanism work.
  Product design remains [REVISE](t8-design-review-sol-high.md), not implementation approval.

Retained dev artifacts (verified again 2026-10-19):

| Artifact | SHA256 |
|---|---|
| Signed driver, `f8e99d25` | `B3830AF1D35D73CA33DD71E5417BAB3889F7260CF558AFE5BE0A44F509FD775E` |
| Dev agent ZIP, `c1a3ba04` | `5BFE59A84E38FB5A9FF22B52BE922E1F1C0463459987A39BD0244013806320A4` |
| Service executable | `F0287411619F10F7514741661A0B8439F8823ABA5EDC48FF2CE61560BF82470F` |
| Tray executable | `1077A7A13A72CB58C82EDF21CD380523CE66202D5C904992B2737FC02898F3A1` |

Retained dev disk is **not deleted** (owner instruction); this is not a qualification/restoration claim.
Qualification still requires fresh disposable disks, reset EFI, no TPM, unchanged base/XML and separate restoration.
