# Large-mode integration local receipt

2026-10-16. `ux/large` (`7edba345`) merged with `demo/apps` (`667a2652`).
[Integration design](../../UX-LARGE-INTEGRATION.md), [review](ux-large2-review-sol61.md),
[counts, raw receipt locations and local assembly hashes](ux-large2-local.json).

Large mode remains opt-in/default-off. Normal metadata seals, failure-only v31,
packed journal scaling/retention and exact allocation-abort/name-release fences
are preserved. Integration controls cover combined seal state, packed metadata,
archive quota/retry, unreserved history, hot/packed ACK refunds, compaction pins
and exclusion of refunded history from foreground reconciliation.

- Feature Debug and Release Tests (including Service/Core/Minifilter) and tray
  builds: PASS, 0 warnings / 0 errors, using the requested local SDK 10.0.400.
- Focused actual xUnit methods/data, direct serial execution: **476/476 PASS in
  each configuration**, identical unique case sets, no skipped selected cases.
  Includes 10 integration, 34 archive, 28 metadata, 14 lost-Prepare, 22 rename-wire,
  19 allocation-envelope, 85 PowerPoint and the existing large parser/scanner controls.
- All **27** selected driver/runner Python self-check/shim entry points: PASS,
  including extracted allocation-fault/metadata/namespace code and GCC/Clang controls.
- Source API delta against `667a2652`: **zero new kernel call names**; all **90**
  host stub declarations supported. The borrowed full audit reports the same
  pre-existing `Taint.c:356: InsertHeadList` header-inventory gap on base and
  integrated source. This is not a full API audit or binary import gate PASS.
- Independent Sol 6.1 xhigh source review: ACCEPT WITH CONDITIONS. Diff whitespace
  checks pass. Original checkout Git metadata, source and `.ai-memory.toml` are unchanged.

These are local diagnostics from the integrated working source before its scratch
merge commit. VSTest aborts because the sandbox denies its local TCP listener;
raw aborted output/TRX remain in `.scratch`. Native Windows metadata/publisher,
large-file and user/SYSTEM matrix cases were not executed. The failure-only Linux
metadata-query shim used by the prior allocation-fault controls supplies no object
identity or successful native operation. No Windows builder/VM was contacted.
Existing exact committed-source Windows builds/static analysis/import gates and
matched-pair native/Verifier/byte-observer/restoration rows remain required.

Initial unsupported-platform diagnostic failures remain separately retained.
One full Debug attempt hit a stale service assembly while source changed during a
build; a forced rebuild made the unchanged new reconciliation control pass, then
the final stable Debug/Release runs passed all 476 cases. Its raw failure log was
accidentally reused while fixing a scratch runner path; the failure, stack location,
observed timestamps and evidence limitation are summarized in
`.scratch/ux-large2-first-failure.json`. A separate scratch wrapper error did not
count as a pass; the final complete runs use fresh, successful receipts. No test,
assertion, threshold, resource default or runtime gate was weakened.

Delivery is `.scratch/ux-large2.bundle`, ref `refs/heads/ux/large`; the adjacent
scratch delivery receipt records its exact commit and bundle hash. No original
Git ref/index update, push, product activation/cutover or milestone completion is claimed.
