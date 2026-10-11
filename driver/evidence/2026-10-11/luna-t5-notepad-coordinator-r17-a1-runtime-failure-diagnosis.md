# R17 a1 runtime failure diagnosis

The standalone R17 diagnostic is **NO-GO for qualification**: the pinned inputs parsed with zero errors, but the self-check exited at `projection retains exact HandleObserved receipt`. This failure is explained by a fixture cardinality error in the self-check. It does not show a coordinator or managed-schema defect.

The frozen source review capture is `m2-t5-notepad-coordinator-r17-root-review-capture.json` (SHA-256 `7fd178b5560c782cecb655557e17889b1ce6b9739dc54d009191732c89289d79`). Its executable-source pins are SelfCheck `be52114a729e2861afccf6c73d900d5b03fc9f476e3664a64f10f959cb33ae47`, coordinator `c21757ed59acd607138be5eaafbdbcd2192dd48dd840c80563cb5b21f22d291d`, `StagedTransferJournal.cs` `4b270eaef4616c06ba52e0b88deb701d72463dcef8ed6c9c8cc4c39893b23f8d`, and `StagedJournalFile.cs` `5f4a5ae360513425f1ff79c3ad8c0c4fc8c2b3464f416cecc43c57c42224053a`.

The root result `m2-t5-coordinator-r17-diag-a1-root-result.json` has SHA-256 `334b8794c812cdcd7330104b3f269457185aeef405fb6abfbf1998438bd2edf4`; its post-run verification is SHA-256 `5a552d5adc1e3a18c3bbdca55795b31e63aa1a7dc72279679304d353641192bc`. The captured process was Windows PowerShell `5.1.19041.6456`; both parser checks reported zero errors and the exact source hashes above. The self-check then failed at line 487. The verification records the exact process as terminal (PID 5328, start FILETIME `134362013037965246`), preserves both remote source pins and all five local pins, and marks `RuntimeQualified`, `PairQualified`, and `StandaloneWindowsControlsPassed` false. This review does not upgrade that run to a pass.

In the frozen SelfCheck, `New-T5Entry` calls `Set-T5HandleObserved` for both State 11 and State 5 (lines 48–49, 120). That setter assigns AttachmentState 6 and the four lifecycle IDs 12, 13, 15, and 19 (lines 140–146). The direct-chain fixture creates a State 11 parent and State 5 child (lines 400–402); both therefore carry `HandleObservedRequestIdV20 = [uint64]19`. The child is set again to the same values at line 404. Both entries are serialized to the journal before `Get-JournalFor` runs (lines 415–416).

The preceding journal assertions passed in the actual run: line 485 found zero parse and schema errors, and line 486 found the expected two records. At line 487, the filter checks only AttachmentState 6 and RequestId 19, then expects one match. It matches both serialized records, so the expected cardinality is two. The smallest assertion-preserving correction is to require exactly two matches and exactly one match for each fixture TransferId, using `Get-T5UInt64Text` for the exact unsigned receipt comparison:

```powershell
$observedReceipts = @($journal.Records | Where-Object {
    $_.AttachmentStateV20 -eq 6 -and
    (Get-T5UInt64Text $_.HandleObservedRequestIdV20) -ceq '19'
})
Assert-T5 (
    $observedReceipts.Count -eq 2 -and
    @($observedReceipts | Where-Object { $_.TransferId -ceq $parent.Transfer.TransferId }).Count -eq 1 -and
    @($observedReceipts | Where-Object { $_.TransferId -ceq $child.Transfer.TransferId }).Count -eq 1
) 'parent and child projections retain exact HandleObserved receipts'
```

This replaces the failed assertion with a stronger check of the same intended projection property; it does not weaken or remove an assertion. The source-level projection copies the lifecycle fields directly (`Get-T5Projection`, coordinator lines 834–838), and both serialized records passed schema validation before the failure. The HandleObserved value here is 19, so the failure is not evidence of a large-UInt64 rounding issue. The earlier assertions at SelfCheck lines 186–218, which round-trip `UInt64.MaxValue` stage-identity fields and compare their exact identity keys, also passed before line 487.

The FILETIME-related fixture value is `[long]638957232000000000` (SelfCheck line 62); `Set-T5ExactParent` copies that process-owner value from parent to child (lines 123–138). The projection passes `RequestorProcessCreationTime` through without a numeric cast (coordinator line 822), and `Test-T5SameWriter` compares it as an integer (lines 867–870). The schema accepts only exact integer-shaped values for this field; the managed CreateAfter request also declares the process-creation value as `long` (`StagedTransferJournal.cs` line 3427). The failing assertion does not inspect the FILETIME field, and the evidence does not support FILETIME loss as its cause.

I audited the remaining SelfCheck assertions after line 487 against the frozen coordinator/schema. Their direct lineage and terminal-helper calls use projection objects; the remaining raw copies are converted with `Get-T5Projection` before those helper calls. The duplicate-request negative control intentionally reuses a phase ID within one entry and is rejected by the per-entry lifecycle uniqueness checks. The later V1/V2/V3 fixtures reuse the same default phase IDs across separate entries, but the pinned PowerShell `$seen` map and managed `HashSet<ulong>` are scoped to one entry; the lineage helper does not enforce cross-entry RequestId uniqueness. These duplicates do not establish another failure under the pinned schema. I found no further concrete raw/projection or duplicated-default fixture defect in the assertions after line 487.

The diagnosed correction is limited to SelfCheck. This failure provides no basis to change the coordinator or managed schema. Preserve the original R17 result, verification, and raw logs; this note is additive and no source, runtime, host, VM, network, or Git action was performed during the review.
