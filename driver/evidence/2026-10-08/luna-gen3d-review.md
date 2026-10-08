# gen3d review — `ClassifyAllLinkNames` churn conversion

**Verdict: ACCEPT WITH CONDITIONS**

Reviewed `cfee5a33..840e6479` in `driver/SafeUpload.Minifilter`; HEAD is `840e6479a321a126ba753bca62f9590727443446`. Static review only; no build or VM.

1. **Churn coverage:** Yes. After `versionsCaptured`, every `STATUS_FILE_INVALID` reaching `Exit` checks the live entry under exclusive `RegistryLock`. The compact-stream suffix-hash mismatch is covered, as are the other post-capture invalid results from identity/name/link validation and the final live-entry check. Rename pre/completion moves `RenameVersion`; a later alias probe moves `AliasProbeSerial`; an in-flight rename is also detected. A detected move clears continuation state, leaves the scan pending, and returns `STATUS_MORE_ENTRIES`, so the caller does not convert that result to sticky Unknown.

2. **Genuine identity loss:** A concurrent unrelated rename can defer a genuine invalid result for that pass. Once the entry is stable, the next scan takes the normal failure path (including Unknown for a genuine identity error); an identity loss already proven by the existing complete no-name rule retains its existing handling. One transient overlap costs one retry. Repeated churn can defer classification repeatedly, so progress is not bounded if churn never settles.

3. **Exit locking / IRQL:** All direct `RegistryLock` acquisitions in this function are released on every branch before `goto Exit`, including both `PublishResult` early exits. Helpers called on these paths release their own locks. The new block therefore takes only exclusive `RegistryLock`; `StageRegistryParkScopeScanLocked` performs interlocked updates and takes no nested lock. The function is `_IRQL_requires_(PASSIVE_LEVEL)` and calls `PAGED_CODE()`, which is within the push-lock and helper SAL limits. I found no lock-order or held-lock exit defect.

4. **Other fail-closed changes:** No P0/P1, actual fail-open, or deadlock found in the range. The earlier range changes make stale scan consumption version/receipt-checked; rename/open churn is deferred, while unresolved identity failures remain on the existing failure path. The gen3d change does not clear Unknown reasons.

**Condition:** Retain the previously recorded P2 release condition that parked pending scans are reclaimed and retried; sustained churn can prolong over-gating. This is a liveness condition, not a fail-open finding.
