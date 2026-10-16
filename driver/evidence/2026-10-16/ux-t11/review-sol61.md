# T11 coherent source review — advisory

2026-10-16. Independent read-only sub-agent `/root/t11_review`, explicitly
`gpt-6.1-sol`, reasoning effort `xhigh`, launched by this implementation worker.
Scope: working delta over `2ed2b20b`, StageAdmission startup SOP proof,
StagedTransferJournal/compaction/epoch/archive fault observers and controls,
existing StageWriters lifetime/prune contracts and T11 design note.

**ACCEPT WITH CONDITIONS — worker advisory source acceptance.** The repository's
fresh orchestrator-launched pre-boot review and final adversarial pair review are
still required. The reviewer ran only read-only source inspection and
`git diff --check`; no build, component execution or VM action was performed.

Resolved during review:

- Both handle closes needed for section-only proof check exact FltClose success
  before consuming ownership. Shared-open owners remain available to cleanup;
  failure preserves failed canary status. Added failed-close host scenarios.
- Missing epoch metadata cannot bootstrap over retained hot/archive driver
  receipts through either entry point. Qualified full-Restart behavior remains
  separately bound to its existing authenticated evidence/recovery contract.
- Reference closure retains pending delete -> CREATE_AFTER successor and its
  transitive dependencies, including an archived overtaken child.
- New cleanup/discard fixtures were corrected to valid manifest states before
  execution. No prior test or assertion was changed.

The original Ended witness or exact original live object/context remains
necessary for registry retirement. A changed/recycled SOP alone never prunes.
New helpers have repeated PASSIVE SAL, PAGE placement and PAGED_CODE; no new I/O
under locks, storage allocation or external DDI was found in the source review.

Conditions: finish the linked M2 review checklist (subsequently written in this
workspace); final exact Windows WDK/PREfast/ApiValidator/import and agent matrix,
matched native/ordinary/runtime-Verifier/boot-Verifier rows and separate
restoration. Host shims do not establish Windows MM/FltMgr/context lifetime.
The final documentation follow-up is recorded below when received.

API: [FltClose return status and PASSIVE requirement](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltclose).

## Final documentation follow-up

The same independent reviewer subsequently confirmed the checklist/source index
and this advisory report exist, local links resolve, and diff whitespace is
clean. No blocking scope/row inconsistency was found. Metadata/MOTW/resource and
held-recovery limitations remain explicit; the historical preflight stop is not
waived. StageCanaryRun's repeated PASSIVE/PAGE annotations match its sole worker
caller. The documentation condition is closed; advisory source acceptance stands.
The reviewer still performed no builds/tests/VM actions.
