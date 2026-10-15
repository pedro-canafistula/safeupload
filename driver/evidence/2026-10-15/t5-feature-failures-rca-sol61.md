**The 128 newly exposed failures trace to stale feature fixtures after batch-2 exact-seal activation.** The reported product refusals agree with the accepted designs. The two known EmptyHeld failures are excluded.

Verified from the [TRX](/home/victor/Work/safeupload-tools/workers/integ-m1-feature-debug.trx), source and Git history; proposed fixes below were not executed.

**Introducing change:** `900f484d` added `RequiresExactSealV29` and receipt-aware `HasMeasuredSeal`. **`92f2b159` activated them for these fixtures** by changing the required capability mask from `0x1BF` to `0xFBF`. The affected fixtures received only capability-constant updates. `740d094e` appears on this branch as cherry-pick **`e833efbf`**; it changed refusal handling and legacy readability, rather than creating the missing-evidence condition. The relevant product and fixture files are unchanged between `8ed0bdce` and `9c1d141f`.

1. **89 × `seal_request_unavailable` — fixture protocol mismatch.**

   Exactly **88** failures use the shared native-publication fixture, including its dispatcher partial; **one** is the empty-seal integration test. [Allocate](agente/SafeUpload.Agent.Tests/StagedPublicationNativeJournalTests.cs:59) supplies legacy attachment operations and calls `SealAsync` without an exact request or stored intent. [The guard](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:2258) correctly refuses it.

   **Minimal fix:** migrate that helper and the empty-seal setup in `StagedBoundAllocationIntegrationTests.cs` to authenticated op12/13 frames, typed op15, exposure/CLEANUP evidence, genuine op19, then exact op4. Existing patterns are in [StagedCompletionV29Tests](agente/SafeUpload.Agent.Tests/StagedCompletionV29Tests.cs:61). Preserve application-write ordering before cleanup/seal and all publication assertions. No dispatcher product change is indicated.

2. **32 × unstable predecessor — fixture manufactures a seal without its evidence.**

   **30 compaction + two allocation-integration cases.** [CapturedPublicLineageAsync](agente/SafeUpload.Agent.Tests/StagedBoundCompactionTests.cs:156), the restricted-descendant setup, and integration `SaveMeasuredFixture` write `SealedOnce`/length/state directly, omitting exact seal evidence. Consequently, [HasMeasuredSeal](agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:2469) is false and ancestry admission refuses.

   **Minimal fix:** update those synthetic captured-state fixtures with a coherent exact request/intent/receipt and its attachment/exposure dependencies before applying the existing corruption mutations. Preserve ancestry, security, retained-byte and export assertions, including the deliberately receiptless legacy negative control. Do not relax predecessor admission.

   `92f2b159` introduced the incompatibility; `e833efbf` lets receiptless historical manifests remain readable, exposing the subsequent **IOException** instead of earlier manifest-validation rejection.

3. **Seven string mismatches — invalid seal stimulus masks the intended seed check.**

   All expect `seed_completion_unproved`; requestless `SealAsync` now stops earlier with `seal_request_unavailable`.

   **Minimal fix:** in `StagedBoundAllocationIntegrationTests.cs`, exercise the unchanged seed-error assertions through valid authenticated pre-exposure op15, whose [seed check](agente/SafeUpload.Agent.Service/Interception/StagedCompletionV29.cs:67) precedes permission. Also retain explicit refusal of requestless sealing. Seal-specific seed negatives need valid attachment evidence and a fault **before first measurement**. Changing expected strings alone would lose coverage.

There is one **source-verified masked conflict**: [the publication seed-corruption test](agente/SafeUpload.Agent.Tests/StagedPublicationNativeJournalTests.cs:95) expects completed-exchange replay to reject missing seed evidence. The accepted [seal design](driver/T5-RECOVERY-HOLDS.md:137) requires historical receipt replay first; [batch-3 lifetimes](driver/T5-RECEIPT-LIFETIMES.md:42) preserve that distinction. Split first-operation refusal fixtures from completed-receipt replay coverage. Keeping that replay-refusal assertion against the same completed exchange conflicts with the design.

These findings explain the recorded first failures; they do **not** establish that corrected fixtures would pass downstream assertions. No edits, builds or VMs were performed; Git status remained clean.