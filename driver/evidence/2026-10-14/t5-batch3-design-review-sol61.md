**REVISE.**

Reviewed `2c6e1756` against the batch-2 source, owner decisions and prior review. The proposed Stop → responder fence/drain → persisted closure → reclamation ordering addresses the earlier late-positive ownership gap. It also correctly preserves object obligations, custody charges and uncertain mutations after replay closure. These are design conclusions, not runtime verification.

1. **High — removing full scans changes an existing integrity guarantee without the required owner decision.**  
   **Verified:** [the current test](agente/SafeUpload.Agent.Tests/StagedDestinationIndexIntegrationTests.cs:129) requires even a warm lookup to detect unrelated destination corruption. [The completion plan](driver/M2-COMPLETION-PLAN.md:82) explicitly requires agreement before changing that timing. [The new note](driver/T5-RECEIPT-LIFETIMES.md:87) replaces those scans with indexed access but does not define equivalent detection or list this decision.  
   **Required:** specify authoritative-store integrity, alias/conflict validation and exactly when untouched corruption becomes visible. Recommend validating accessed records/dependencies, complete startup validation and bounded integrity audits, with a named hold on detected corruption. Obtain approval for the user-visible consequence: unrelated saves may continue before unrelated damage is discovered.

2. **Medium — the generic “immutable outcome” contract needs explicit exceptions and control-family semantics.**  
   **Verified:** [Open](driver/T5-RECEIPT-LIFETIMES.md:21) promises identical outcomes before closure. However, [op3 result20](agente/SafeUpload.Agent.Service/Interception/StagedAllocationResolution.cs:14) is deliberately time-local; the same request can later create a positive candidate. [Control35](driver/SafeUpload.Minifilter/StageDeleteReceipts.inc:216) canonicalizes Phase/ExpectedReceiptId, while its status progresses from Pending to Ready/Revoked. That conflicts with binding one ticket to an entirely immutable control frame/outcome.  
   **Required:** distinguish immutable committed receipts from transient/discovery replies. Preserve stateless op3 refusals. Define whether control35 closes one canonical Release family or individual messages; explicitly bind its phase variants and drain **all** Release/Query/CloseObsolete senders before family closure. Otherwise the inferred implementation choices either freeze progress or violate the stated replay contract.

3. **Medium — chain compaction lacks the concrete replacement for chain-derived authority and remaining caps.**  
   **Verified:** the source limits namespace history to [16 entries](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:1848), derives [CommittedRenames from chain length](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:2959), and caps [state history](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:3079). The note requires folding these histories, but does not specify the replacement authority.  
   **Required:** define an absolute, nonresetting committed-rename counter, compact per-name floors and the exact evidence retained for outstanding historical references. Specify how validators establish ancestry after intermediate links disappear. Add repeated renames between the same two names beyond 16 commits and repeated state cycles beyond 64 entries. **Inferred risk:** retaining the chains preserves caps; merely shortening them changes counts or loses historical binding.

The closure mechanism is justified; the universal 96-byte envelope is not yet shown necessary. I recommend a smaller encoding:

- Reuse the existing monotonic `RequestId` as the generation within each operation bank; derive the slot from `RequestId % capacity`, skipping occupied slots during issuance.
- Retain one active full binding and one closed-through RequestId per slot, scoped by DriverInstanceId. Preserve the proposed fence, drain, cleanup transfer and acknowledgment-before-reuse rules.
- Add a durable issuer sequence for agent-origin controls, which currently lack that RequestId. Keep existing reservation/ReleaseNonce bindings.
- Piggyback closure on suitable tuple-bearing requests; use explicit closure for terminal and unknown-tuple cases.

This retains the necessary new lifetime capability/control routes while avoiding duplicate identity fields around every existing data frame. A lone maximum acknowledgment is insufficient with out-of-order requests; DriverInstanceId alone cannot reclaim within one long-running instance.

Remaining owner decisions are **integrity timing** above and **resource sizing** already identified by the note. Recommend separate live-work and physical-storage budgets, reserved recovery workspace and actionable capacity holds. Preserve private, charged custody with no automatic deletion. Proof-based reclamation itself needs no additional product choice under the stated instance-replacement premise.

Read-only review; checkout unchanged. No builds, tests or VM actions.