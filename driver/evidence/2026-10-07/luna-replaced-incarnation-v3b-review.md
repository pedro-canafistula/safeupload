# Adversarial review: `c1086343` + `3c730996`

**Verdict: REJECT**

The second commit fixes the compact-ADS false match and moves the “still bound away from this live SOP” guard under `RegistryLock` and `StateLock`. The base-stream identity reopen is also the right shape for reclaiming a replaced base-stream incarnation. The remaining problem is that the code treats a second SOP-keyed entry as independently gating without ensuring that a newly created live-SOP entry is ever alias-probed. This permits a Ready scope to admit writes through an out-of-scope hard link to the same file.

Review was read-only. I ran the requested `git show c1086343 3c730996` and `git diff c1086343~1 3c730996 -- driver/SafeUpload.Minifilter`. No VM or tests were run.

## Findings

### P1 — A new live-SOP entry can be unscoped and bypass the protected alias

**Location:** `driver/SafeUpload.Minifilter/StageWriters.c:5437, 5476, 5515, 5550, 5578; 1144, 1191, 1205; 2408, 2453, 2470; 6320, 6400, 6420, 6442; 6821, 6832, 6834`.

`StageRegistryFindByKeyLocked` keys on the SOP as well as volume and file ID. `StageRegistryGetOrInsert` therefore creates a second entry when the same base file is opened through a new SOP; the new entry starts `UNSCOPED` and `PostCreate` does not begin an alias probe for it. `SafeUploadStageWritersSopMatchesPolicy` then evaluates that entry’s retained name and activation state, not sibling entries with the same file ID. Admission coverage skips entries with `ActivationEnforced == 0`.

**Scenario:** Entry A was first recorded through an out-of-scope hard-link name. Its SCB is later torn down. Applying a scope that contains another hard link makes A’s alias scan identify the file as scoped. The new fallback reopens the base stream by file ID with SOP P, sees no writable section or cache pointers, and promotes A. Coverage can report Ready. A standard user then opens A’s out-of-scope hard link for write. The new post-create binds the writer to a P-keyed entry with the out-of-scope name and default `UNSCOPED` state. The SOP policy check returns false for that name, and coverage ignores the row. The user can write bytes reachable through the protected hard link.

This also defeats the claimed reclaim semantics: `StageRegistryEntryQuiescent` considers A quiescent as soon as the base-stream reopen has a different SOP (`3955`, `3956`, `3958`), and `StageRegistryPruneLocked` checks A’s state, not the live-SOP row. It can prune A while P has a live writer, on the assumption that P independently gates. The code does not establish that gate for a post-scope P entry. The new path must preserve/transfer the scoped file-identity gate to the live-SOP entry, or keep admission fail-closed until that entry has completed alias classification.

### P2 — The successful CAS is entry-local while a pre-scope writer can remain on the live SOP

**Location:** `driver/SafeUpload.Minifilter/StageWriters.c:5303, 5305, 5311; 5507, 5515, 5521, 5550, 5565; 5025, 5028, 5046, 5050; 4893, 4916, 4918, 4941, 4965`.

The zero-state sample and final CAS recheck H/W/T/rename/spills/C only on A. The live SOP P is used for S and cache checks, but its entry’s H/W/T/rename/spill/C state is never part of the CAS. The 3c guard correctly prevents A from having rebound to the exact captured P under the locks; it does not turn the predicate into an identity-wide Free check.

**Scenario:** A’s recorded SOP has died and A has zero counters. Before scope application, a standard-user write handle opens the same stream under new SOP P and is counted as H on a distinct P-keyed entry. A’s fallback sees `S(P) == NO` and empty cache pointers, then its CAS can transition A to `PROTECTED` while P’s H is still 1. P’s own alias-pending row should keep aggregate coverage from becoming Ready if it was present for the scope walk, so this scenario is not itself a Ready escape. It does violate the stated no-promotion-while-a-pre-scope-writer-may-exist rule and means the `0x20` event is not evidence of identity-wide Free. If this is meant to be a stale-row discharge, it needs discharge/retirement semantics rather than a successful Protected promotion.

## Requested checks

1. **Identity and writer state.** Yes, a pre-scope writer can exist while A is unbound from live SOP P and A’s counters are zero: it can be tracked on P’s separate SOP-keyed entry. If P existed before scope application, it is itself alias-probed and its H/T/C/S state keeps aggregate coverage pending. Hard-link enumeration is on the base file, so it finds aliases, but does not merge state between SOP entries. Existing writable section references on P are seen by `MmDoesFileHaveUserWritableReferences(P)`; H-only writers and a section created after the S sample are not part of A’s CAS. TxF and rename state on P have the same separate-entry limitation. The base-stream-only gate correctly excludes compact ADS entries; long-name compact entries for the unnamed data stream still qualify. The opens use the pinned instance/volume and verify serial plus the full file ID, so I found no distinct dismount/remount substitution in this diff under the stated lifecycle premise. Reclaim’s own read-attributes by-ID open pins the live SOP temporarily but is not user writer state.

2. **Races and locks.** The c108 unlocked rebound check is fixed: both association and the final inequality check serialize through `RegistryLock`, and the final state transition is under `StateLock`. I found no recursive `RegistryLock` acquisition in `StageRegistryEntryIsBaseStream`: both callers (`StageRegistryActivationProcess` and `StageRegistryEntryQuiescent`) call it outside that lock. The CAS still relies on earlier samples of `MmDoesFileHaveUserWritableReferences` and the live SOP cache pointers; the final recheck is for A’s counters/map/section slots, not P’s writer state or S. The P1 new-entry gap makes that reliance unsafe for admission.

3. **Promote versus retire.** Promoting A can clear its activation gate only if P’s scoped identity is independently protected. The existing-row case is covered by the scope walk; new P rows are not. Therefore “promote A as discharge” is not a safe general semantic here. Reclaim pruning A while P has a writer is safe only after the live-SOP row has its own scoped admission gate.

4. **Receipt and harness.** `SAFEUPLOAD_PROMOTION_BASIS_INCARNATION_REPLACED` (`0x20`) distinguishes this branch. The trace has no field for the reopened live SOP: `SectionObjectPointer` records the entry’s SOP at CAS, while S/cache were evaluated on the reopened object. Thus the bit labels the branch but cannot independently prove the live stream identity or the state of a sibling entry. The current script validator allows bits through `0x3f` and has a positive self-check for `0x20` (`Test-StagedInvariantSuite.ps1:3909`, `StagedInvariantProofAdapters.SelfCheck.ps1:64`, `:66`); the change adds no trace-layout/ABI size change. The harness accepts the branch label but does not validate the missing live-SOP relationship or require the bit when this path is expected.

## Second-commit fixes verified

- The activation fallback now requires an unnamed base stream, so compact ADS hash resolution cannot select a different ADS for this proof.
- The rebound-to-live-SOP check is under `RegistryLock` and `StateLock`; no lock recursion was found in the new helper.
- Reclaim now reopens base streams by identity and recognizes a different SOP as a replaced old incarnation; compact ADS keeps the exact-SOP path.
- Those fixes do not address the live-SOP admission gap above. The C01 evidence supports the original readiness failure, but does not exercise this replacement-SOP hard-link case.
