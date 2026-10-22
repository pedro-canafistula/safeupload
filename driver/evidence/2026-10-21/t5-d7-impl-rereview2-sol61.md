# T5 D7 implementation re-review 2 — Sol 6.1 high (gpt-6.1-sol, reasoning_effort=high), read-only, 2026-10-22

Same session (resumed). Reviewed commit `9eb46e87`. Brief: `~/Work/safeupload-tools/workers/t5-d7-impl-rereview2-brief.md`; raw log `t5-d7-impl-rereview2.log` (EXIT=0). Verbatim result:

**ACCEPT — implementation review.**

1. **[note] Finding 4 is resolved.** The independent classifier now excludes directory, by-ID and target-directory opens ([StageStream.c:9124–9125](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:9124)). Consequently, admission no longer assigns them the D7 refusal obligation ([9183–9187](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageStream.c:9183)). Their existing routing remains intact; DOC and content-writing exclusions remain unchanged.

2. **[note] The regression controls and receipt are consistent.** New assertions cover all three exclusions and confirm that an ordinary D7 request still matches ([namespace_ux_fixture.c:424–432](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/tests/namespace_ux_fixture.c:424)). The new mutation removes those exclusions ([test_namespace_ux.py:116](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/tests/test_namespace_ux.py:116)); its receipt reports assertion exit 97 at the by-ID exclusion check. All 32 [receipts](/home/victor/Work/safeupload-staging/driver/evidence/2026-10-21/t5-d7-host-mutants.json:1) match the mutation list/order and record assertion failures. I did not rerun them.

3. **[note] No other product-code change or new defect found in this diff.** The remaining changes are controls, updated mutant receipts, the saved review, and three build summaries. Those summaries concern earlier commits—the latest names `e41913c4` ([m2t5d7k3 summary:3](/home/victor/Work/safeupload-staging/driver/evidence/2026-10-21/exact-m2t5d7k3-summary.txt:3)). They do not establish build/import or Windows qualification for `9eb46e87`; those delivery gates remain separate.

Reviewed read-only and offline. No edits, builds, tests or remote actions performed.