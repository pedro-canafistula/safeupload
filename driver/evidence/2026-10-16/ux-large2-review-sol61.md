# Large-mode integration review

2026-10-16. Independent `gpt-6.1-sol`, xhigh, read-only review of the scratch integration
against `667a2652` and `7edba345`. Reviewer performed no edits, builds, tests or VM actions.

**ACCEPT WITH CONDITIONS at source-review level. No remaining integration blocker found.**

Normal seals preserve the 72-byte metadata layout; failure-only v31 retains its strict
48-byte envelope. Metadata and sticky space failure survive journal replay. Seed identity
persistence precedes output metadata validation and seed bytes. Bounded hot serialization
retains journal timing. Lost-Prepare abort, name-release and service-generation fences remain intact.

Review follow-ups addressed before acceptance:

- Cache cold allocation totals rather than enumerate completed segments during foreground
  journal admission; bind the cache to its canonical directory and predebit buffered growth.
- Install archive callbacks before large-mode recovery can extend a segment/inventory.
- Consume exact durable private-discard ACKs for content refunds, separately from StageDeleted,
  while retaining identity/path, absence, rename, cleanup, hand-back and snapshot checks.
- Pin unconsumed content-reservation cleanup receipts and their reference closure against
  compaction. Skip refunded history during foreground reconciliation.

Conditions remain: final committed-source Windows build/static-analysis/import gates, agent
user/SYSTEM matrix, matched-pair native and Verifier qualification, independent byte observations
and restoration. Review acceptance establishes no activation/cutover approval or milestone completion.
