# ux-large4 independent source re-review

2026-10-16. Reviewer: Sol 6.1, xhigh. Scope: current working files and `.scratch/ux-large4/source-review2.patch` against 45102e57, with the revised design and earlier review findings. No implementation, original Git, build or VM changes were made by this reviewer.

**Verdict: ACCEPT WITH CONDITIONS. No remaining product-security, lifetime or lock-order blocker found in this delta.** This accepts the reviewed source design; it does not assert completed component testing or Windows/pair qualification.

The previous blockers are resolved:

- Acknowledged never-attached kind-5 claims now recognize `None` and validated `Aborted`, exclude seal/completion/handle/namespace ambiguity, and retain their generation as allocation high-water. Real PREPARE → ABORT → kind-5 controls cover hot and packed/restarted history.
- Destination/archive lookup and compaction preserve independent effective and high-water frontiers. Compaction keeps the last effective publication barrier as well as a later retired allocation, including reference closure and the existing separation of pathname and identity-bound authority. The added A/B/C disk control exercises compaction/restart and rejects revival of the older save.
- Empty-history first-use is restricted to constructor recovery. Online empty history takes the explicit corruption/reset path and rotates InstanceId; its regression checks sequence 1/zero hash/new identity and subsequent strict validation.
- Retained staging-space alerts reject publication digest and override authority, alongside the existing snapshot/handback restrictions. Invalid shape rejection occurs before storage-failure handling and leaves later valid appends usable.
- Negative bytes are inventoried at startup and refunded only after exact confirmed deletion. Background batches no longer rescan the whole negative population. Completed ledger retirement uses existing conservative metadata frontiers rather than enumerating hot/packed directories for every retirement.

The approved owner stateless-refusal contract is preserved: no new negative receipt files; late positives remain private and follow exact kind-5 cleanup. Validated old compatibility files retire only after no manifest, exact unissued backing cleanup/absence and no companion grant. Partial/uncertain old data remains private and charged, without the removed global negative cap. Missing process identity due to access/query error is not treated as process exit. Issued, legacy, unknown-object and snapshot obligations remain held; completed metadata retirement preserves hot/packed replay inventory and reconstructible shared storage accounting.

Lock direction remains coherent: allocator serialization covers no-manifest recovery and prepare; journal reads complete before taking the accounting lock; accounting retirement does not await the journal. Exact metadata/grant deletion validates the opened object's full identity and expected bytes/length before refund. No new kernel lifetime, DDI/import or lock-order change is introduced by this delta.

Conditions before delivery claims:

1. Execute all added refusal/recovery, aborted-kind-5, high-water/effective-compaction, notification shape and online recovery controls, plus the existing relevant suites and required preflight/compile checks. Preserve failures and discovery coverage. This reviewer read the controls but did not run them.
2. Obtain the required feature Debug/Release user + SYSTEM matrix and Windows native evidence for real CREATE sharing failure, exact replacement refusal, inaccessible identity/metadata, cleanup interruption/restart, and notification storage failure/recovery. Native direct-method controls remain component/mechanism evidence.
3. Keep VM/pair qualification, artifact hashes, runtime readiness and cutover approval separate from this review. Re-run the actual affected protected CREATE/notification scenario on the authorized target under the existing owner/lab rules before claiming the observed regression fixed there.
4. Describe background recovery as bounded item batches. Existing hot-journal admission/inventory scans and startup reconstruction still scale with retained data, and physical I/O latency is not constant. Native latency measurements are needed for broader scalability claims.

Earlier design/source review reports remain historical findings, superseded for this delta by the dispositions above. Unrelated upstream work and unresolved qualification conditions remain unchanged.

Addendum, same day: inspected the final negative-storage accounting adjustment. Startup and exact-deletion refund both call `NegativeStorageCharge(length)`, which charges at least one rounded data allocation unit plus one metadata unit, including empty retained files. This is conservative bookkeeping, introduces no allocation/object authority, and preserves the verdict above. Also inspected the compaction control's destination-directory creation before directory identity capture; that fixes its fixture prerequisite without weakening its assertions. The first fixture failure is preserved by the primary; rerun results remain the primary's verification evidence.
