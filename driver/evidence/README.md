# Evidence

Raw harness and VM output (per-run artifacts, CLIXML trials, raw volume captures, logs) is written here by the scripts and **stays local**:
`.gitignore` excludes this folder. Only curated, decision-level evidence is tracked; add a file explicitly with `git add -f <path>` when a
document cites it.

All raw evidence produced up to the MVP gate close (51,592 files) is preserved in git under the tag `mvp-history-2026-10-08`
(`git checkout mvp-history-2026-10-08 -- driver/evidence/<path>` restores any file).

Tracked:
- `2026-10-08/mvp-gate-final.txt`: the release gate status of the frozen pair (two-tier and strict).
- `2026-10-08/luna-phase5-final-review.md`: the Phase 5 review of the final driver + agent pair.
- `2026-10-08/luna-gen4b-review.md`: the review of the last driver change (blocked-version cleanup).
- `2026-10-08/manual-test-win10-debug/`: the owner's manual test as a standard user, with screenshots and raw journal records.
