**REVISE** — independent Sol 6.1, xhigh review at `e7981708`.

1. **High — Durable provenance can lose its export restriction while captured metadata remains intact.**
   [StagedTransferJournal.cs:1413](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:1413) checks source evidence only when source fields exist. [StagedSeedProvenance.cs:68](agente/SafeUpload.Agent.Service/Interception/StagedSeedProvenance.cs:68) checks expected origin only when `AllocationBinding` exists.

   For an ExistingPublic seed, retain `Allocation`, `AllocationSecurity` and `SeedCompletion`, but set `Origin=None`, `ContainsPriorBytes=false`, erase `AllocationBinding` and clear source/evidence fields. Validation accepts this contradiction despite the immutable blob retaining ExistingPublic. The [export guard then returns success](agente/SafeUpload.Agent.Service/Interception/StagedSeedProvenance.cs:102), permitting hand-back eligibility without affirmative authority.

   **Required:** enforce captured seed intent, binding and mandatory provenance on every durable read, including exact predecessor lineage. Missing fields must retain restriction. Add restart regressions for provenance erasure in public seeds and preserving children/grandchildren; assert refusal and retained backing.

2. **Medium — Concurrent metadata readers have no kernel limit.**
   [StagePublic.c:2091](driver/SafeUpload.Minifilter/StagePublic.c:2091) allocates another 4,232-byte page per concurrent request while retaining operation rundown. The [four-fetch limit](agente/SafeUpload.Agent.Minifilter/WriterMetadataClient.cs:13) exists only in the managed client. Direct authenticated native requests bypass it; the 128-lease bound bounds blobs, not readers.

   **Required:** reserve a bounded kernel reader slot before allocation/rundown acquisition, refuse excess requests and release accounting on every exit. Add saturation, failure-cleanup and teardown controls.

Other inspected boundaries appear sound for this disabled prerequisite: V18/V23/V26 layouts remain unchanged; control 34/extension 27 agree; page bindings, lengths, digest and exact replay are checked; construction and stored descriptors remain separate. No additional UAF, lock-order defect or service-ACK teardown dependency was identified.

The current incomplete producer remains refused and live admission stays disabled, so these findings establish latent integration defects, not current protected-path exposure. Checkout unchanged; diff check passed. No builds, component tests or VM runs were performed. Compiler matrices, integrated pre-boot review and runtime qualification remain outstanding.