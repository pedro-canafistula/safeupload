- Seed evidence correction design: S00-S02 already execute one cold plus100
  unheld native attempts, unlike held C01-C04 functional actors. The MVP gate
  must accept those existing seed latency receipts only after checking every
  native operation, expected class/status (0 for S00; access-denied5 for S01/2),
  exact Trial0..100/Cold flags, whole complete same-boot writer fence, monotonic
  QPC, sample-to-operation identity, and recomputed100-warm p95/all-sample max.
  No new allowlisted assertion, no strict-gate change, no substitution for any
  C write-path dedicated run. Correct generic percentile to100 warm samples;
  cold remains in max. Seed gate controls must reject held/missing/duplicate/
  forged/failing native or over-budget data. Saved sol-ready1 outcomes stay false.
- An authenticated well-formed notification tail from a previous boot (or
  earlier than the requested current-boot fence) is missing durable coverage,
  not a reader/parser/security error. Keep all copied raw chain/head/location
  artifacts, Status INCONCLUSIVE and exact RecordedBootId/HistoricalTail reason;
  never use its entries as current-boot event absence. The existing independent
  AgentDidNotRun plus unchanged authenticated location remains the only fallback.
  Actual malformed chain/hash/ACL/read errors and same-boot frequency mismatch
  still produce Errors and block MVP. The any-Errors gate is unchanged.
- C03 unknown journal child diagnostics must retain the exact filename and
  attributes before any retry is considered. A private atomic .json.<guid>.tmp
  is a hypothesis until observed; don't ignore child files or claim complete
  inventory while they exist. Add name/attributes to the existing incomplete
  snapshot reason now; no journal schema/ACL/completeness relaxation.
