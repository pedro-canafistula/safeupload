# T9 early OpenXML part-count refusal — Sol high design review

Independent reviewer `t8_design_completion`, gpt-6.1-sol, high, 2026-10-19: **ACCEPT WITH CONDITIONS**.

Failure: full feature matrix `m2-ux-agent-1019a`, commit `62127384`, reported
`OfficeRelationshipBudgetTests.Excessive_reachable_parts_fail_explicitly_before_clean_text_can_authorize_the_package`:
expected `inspection_limit`, actual `inspection_timeout`. Both refuse staged content; the reason assertion remains required.

The existing guard permits at most 16,384 visited parts and rejects duplicate or orphan payloads. Every package it accepts must
therefore contain at most 16,384 physical payload parts, including the admitted PowerPoint root thumbnail. Count those parts from
the held ZIP before the SDK materializes its graph. This is an earlier application of the existing ceiling, not a new acceptance rule.

Conditions: use exactly the existing raw-name/case-sensitive infrastructure and empty-directory exclusions; retain the complete
relationship, duplicate, orphan and infrastructure checks; cancellation before ZIP work and during enumeration; restore stream position
and retain ownership. Apply before Word, Excel and PowerPoint SDK Open calls. Keep the 17,000-part regression and existing coverage,
fake relationship, duplicate/orphan and thumbnail assertions unchanged. No timeout, threshold or product decision changes.

`ZipArchive.Entries` may itself materialize central-directory metadata. This reduces SDK graph work; it is neither a general parser
allocation bound nor a guarantee that an arbitrary scheduling delay always reports limit before timeout. Windows controls and full
four-leg qualification remain required. Local feature Debug Service/App/Tests compile passed (`m2-openxml-preflight-compile.txt`).
