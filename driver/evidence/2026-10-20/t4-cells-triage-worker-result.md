# T4 raw-volume cell triage — offline worker

2026-10-20. Branch `t4/cells-triage`, base `ad92dc4a85e820461c0c67600081353e09eabfd8`.
No network, VM, builder, SSH or libvirt operation was performed. No product source, status plan, assertion allowlist, required row list, deadline or latency/byte threshold was changed. This is analysis and a proposed harness patch, not Windows validation or a passing product gate.

## Finding

The observed C01 failure is principally **(b), a journal storage contract mismatch**. The reader assumes a flat directory containing only `<transfer-N>.json`. The current agent legitimately persists `driver-epoch.state` and packs completed receipts under `completed/`. Rejecting those children leaves the journal snapshot incomplete; C01 then cannot authenticate its held transfer, sealed digest, terminal history or service timeline. Extending the timeout or deferring these assertions would be incorrect.

There is also a source-confirmed, previously masked **(b) state contract mismatch**: the agent emits `SealPending` (**10**, not 9) before measuring and sealing a version; the reader maps only 0–8 and several exact-history checks expect the older direct Allocated → Sealed transition. Neither mismatch is evidence that staging failed to protect bytes.

The two available current receipts have the same eight MVP blockers. Both have `LiveTaintFlags=PASS`: **taint is not their cause**. The Portuguese “classificacao de fontes em todos os volumes” log is unconditional text (`MinifilterInterceptor.cs:1836`), not a readback of enabled classification. `MinifilterPolicyFactory.cs:21`/`:42` disables test taint in feature builds and calls `WithAllSources()` only when taint is enabled. Its implementation is identical at `586ae7cb` and this clone's base.

## Evidence inspected

All original evidence below is under the read-only root `/home/victor/Work/safeupload-staging/driver/evidence/`.

| Receipt | Observation |
|---|---|
| `2026-10-20/phase4-suite-m2t4o1-index.txt` and `boot-start-invariant-C01-approve-absent-ordinary-m2t4o1-artifacts/case.json` | INCONCLUSIVE; ForbiddenByteCount=0; RestorationClean=true; both gates false. Three incomplete held snapshots; 407 incomplete outcome polls (5 reject epoch; 402 reject completed); zero transitions; timeout waiting for Released. |
| `2026-10-20/phase4-suite-m2t4r1-index.txt` and `boot-start-invariant-C01-approve-absent-runtime-verifier-m2t4r1-artifacts/case.json` | Initially only an index header; completed during this analysis. Same eight blockers, INCONCLUSIVE, zero forbidden bytes and clean restoration. Three incomplete held snapshots; 240 incomplete outcome polls (1 epoch, 239 completed). One Allocated transition survives partial collection, but no terminal transition. Timeout says “last observed=Allocated”. |
| `2026-10-2*/...m2t4b*` | `phase4-suite-m2t4b1-index.txt` appeared at the final inventory with schema and matching-pair provenance only (two lines); no outcome record or case export yet. `m2t4bv10k1`/`m2t4bvoff1` are cycles workloads, not this cell. No boot-Verifier cell verdict is inferred. |
| `2026-10-20/batch-m2t4o1-*`, `batch-m2t4r1-*`, per-case lifecycle and restoration files | Read as lifecycle context; batch stops on the failed first cell. Later cells were not qualified by these receipts. |

Ordinary case SHA256: `C7F655E90C53E6E9F6AF02C4DFC60E8DC1429FA0F79E3EECF7DCB7E8172E9C8D`.
Runtime case SHA256: `3638BDFB79D0AD34ADAD60EB05E1A57B20AF0772224826E0F84C221B68A06149`.

The index pins kernel `d1068cc302ed2431db7cf1d2c277d0d0d86bfc0a`, agent `586ae7cb6a874225d15a1396208f46bc20430d83`, signed driver SHA256 `3547377ADC04D3047B4A9297C856C6A1F65356D08ED803765AF31EC66566F352`, service package `1EA4A2E12823C9765B8D4B05EB29B82322A4A3E8C223004763F0534C22C77DC4`, service tree `6C7C0BF83131B578142DF863E9B526D04A5DD4938F9C334083311D747A63594E`. The exact current journal/archive/policy/interceptor source files were also compared to `586ae7cb`; no differences.

The ordinary trial contains 411 raw samples, 381 OK and 30 ERROR. Its final successful sample contains the 12,288-byte destination image with SHA256 `522DE0FB0AD2C036476A8286C0942B4BEF423C0DA6903825C7E2948C4E139B3B`, equal to independently generated A. Native writer open/write/flush/close each returned 0. This shows successful sampled publication, **not** authenticated approval/order or complete temporal coverage. Some ERROR samples have raw/FSCTL sequence mismatches (e.g. record 174495, raw sequence 6, API sequence 8); these checks must remain. Runtime has 244 raw samples (243 OK, 1 ERROR). Neither zero forbidden-byte count nor a final digest repairs missing journal authority.

## Blocker → check → missing observation → class → fix

File:line references in this table refer to **unmodified base `ad92dc4a`**, so they identify the checks that produced the retained receipt. The patch moves later suite lines. `Suite` means `driver/scripts/Test-StagedInvariantSuite.ps1`; `Q` means `driver/scripts/Invoke-StagedInvariantQualification.py`.

| Blocker | Producing check | Concrete missing observation | Class and smallest correct fix |
|---|---|---|---|
| ActualServiceTimelines | Suite:3843 fallback after absent ServiceEvidence; normal construction Suite:3756. Generic evaluator Suite:2589 is not the fallback hit here. Q:1041 promotes the non-PASS assertion to a blocker. | Timeout aborts before the authenticated after snapshot, journal delta and full notification-window proof. There is no completed ServiceEvidence in either current trial. | **b, cascading**. Collect current storage completely, reach the actual terminal receipt, then execute the existing timeline proof. Never substitute startup logs for it. |
| C01Execution | Suite:3688 throws on missing terminal after 120 s; Suite:3775 catches, retains Errors and adds this assertion; Q:1041. | Ordinary has no journal state; runtime has only Allocated from a partial snapshot. Neither observes authenticated Released. | **b, cascading**. Correct the reader, retain the same deadline and exception path. A continuing timeout after that needs product diagnosis. |
| C01HeldJournal | Suite:3335 requires snapshot OK and exactly one entry. Get-CachedJournalObservation Suite:2664 calls Get-ServiceSnapshot Suite:2306; Suite:2322 rejects unknown children. Q:1041. | Three held snapshots per run are incomplete. Ordinary sees zero entries because epoch is rejected first. Runtime can retain an Allocated entry before encountering an unknown child, but completeness is still missing. | **b, direct**. Authenticate/retain the epoch and complete the hot/archive inventory; preserve exactly-one transfer, PID/session and identity checks. |
| C01JournalOrder | Suite:2604–2619, particularly :2618 when history is absent; Q:1041. | Ordinary history empty; runtime only Allocated. Expected Sealed/Inspecting/Approved/Publishing/Released evidence is unavailable. Current SealPending would be an additional mismatch once readable. | **b, direct + masked contract issue**. Decode terminal archive receipts and represent state 10. Compare the entire exact legacy or current sequence; retain every required inspection/publication state and reject duplicates/reordering. |
| C01JournalPoll | Suite:3664 adds an assertion for every non-OK poll; underlying child rejection Suite:2322; Q:1041. | 407 ordinary / 240 runtime snapshots fail on epoch or completed, rather than yielding a complete authenticated inventory. | **b, direct**. Add explicit storage adapters with existing file authority checks. Unknown/corrupt/incomplete storage must still produce non-OK snapshots. |
| C01SealedDigest | Suite:2620–2623; Q:1041. | No observed SealedOnce entry with digest to compare to whole A. The separate raw destination digest is insufficient. | **b, cascading**. Recover the actual sealed manifest/payload, then retain the existing exact digest assertion. |
| FailureOrErrorsInEvidence | Q:1051–1057 recursively rejects FAIL or nonempty Errors. | Trial.Errors contains the journal timeout; ServiceBefore and journal snapshots retain the unknown-child exceptions. | **b, aggregate of real evidence failures**. Fix collection; preserve all original failures. Do not clear Errors, whitelist them or regrade these receipts. |
| TrialPrerequisites | Q:993–998. | Trial.Errors is nonempty (timeout). Disposal is OK, trial verdict INCONCLUSIVE and forbidden-byte count 0; these other fields are not what triggered it. | **b, aggregate**. Complete execution with genuine proof, keeping every prerequisite. |

`StagedInvariantCases.psd1:213`/`:234` describe the C01 APPROVE/BLOCK timelines and barriers; the table does **not** generate these blocker strings. `StagedInvariantObserver.psm1` does not generate these eight names either; it independently validates raw bytes/NTFS identity. Its raw/FSCTL identity check is at `:323` and is unchanged. `suite_case_verdict.py:47` requires PASS, strict GatePassed and MvpGatePassed; it does not generate the MVP blocker list. Offline replay of the ordinary index returns exactly:

```text
CaseVerdict=FAIL reason=Verdict must be 'PASS'
```

## Historical comparison and the missing requested passing receipt

I searched every supplied `driver/evidence/*/phase4-suite-*-index.txt` for the exact CaseId and recursively searched `case.json` exports whose path contains it: **32 indexed outcomes, 11 case exports, zero same-case MvpGatePassed=true exports or indexed outcomes**. The final inventory includes runtime `m2t4r1`. No C01 receipt from the stated 2026-10-09/10 `m1-driver21` / `4d02039a` pair is present in that supplied tree. Local Git's `mvp-history-2026-10-08` tree also has only the older C01 exports. The historical status narrative mentions successful later C01 rows, but it cannot supply their missing configuration and authenticated timeline. I cannot name the most recent passing same-case run from evidence that is absent.

For a **same-case mechanism comparison**, I used `2026-10-07/phase4-suite-p1a2-index.txt` and `boot-start-invariant-C01-approve-absent-runtime-verifier-p1a2-artifacts/case.json`. This is explicitly **not a passing MVP comparison**: its six blockers concern missing dedicated unheld latency. It is driver `cb66c0e0901a03ecbf427998014855760cd1de99`, agent `d9501a718e88bb0123578c52b8b0d286e9246977`, not the final M1 pair.

| Aspect | p1a2, same C01 APPROVE/absent | m2t4o1 |
|---|---|---|
| Service/configuration | Real SYSTEM test service; StagingPrototype=true, Minifilter mode, debug EventLog and proof proxy. Before snapshot OK with 14 pre-existing hot JSON manifests. LiveTaintFlags PASS; policy flag boundaries 0x20/0x30. | Same launcher switches (`StagedTestAgent.ps1:39`, Suite base:3511). Published appsettings now default StageSpace.Enabled=true; no StageSpace=off override in this cell. Before snapshot rejects driver-epoch.state. LiveTaintFlags PASS, so source classification text is not actual policy evidence. |
| Storage | Flat, per-transfer JSON; current schema understood by reader. | Epoch sidecar plus completed packed receipts; reader rejects both. Actual pack bytes/epoch bytes were not collected in these failing runs. |
| Journal timeline | Polls Allocated then Released; retained final durable history is exactly Allocated → Sealed → Inspecting → Approved → Publishing → Released, with digest `2AC763A62C1242D0283C98D182AEB04C2809558BDD63EB655C44D2A6CBB086F9`. | No transitions; 120 s journal timeout. Source now inserts SealPending before measured seal, but the current run's sealed history was not collected, so its exact emitted sequence cannot be reconstructed offline. |
| Authenticated proof | ServiceEvidence present; notification chain complete with retained before/after heads. Journal order and digest assertions pass. | ServiceEvidence absent; cannot authenticate terminal state/notifications even though later raw image equals A. |
| Raw observer | Eight samples including one ERROR, final exact approved image. | 411 samples including 30 ERROR; timeout prolongs capture window. Raw identity errors remain independent limitations. |

For a real **different-case MVP pass**, `2026-10-10/phase4-suite-m2t7o1-index.txt` records B02 with MvpGatePassed=true, no MVP blockers and zero forbidden bytes, but Verdict=INCONCLUSIVE and GatePassed=false. This proves why “MVP pass” and full Phase 4 pass cannot be interchanged. `m2t6rv4` is a move/coordinator row, not a C01 same-case control.

## Classification and affected cells

- **a — taint-era expectations:** owner removal direction is explicit in POST-MVP-PLAN (2026-10-15). This base still contains taint tests/readback and the test policy disable bit. Those pass in both current receipts; none of these eight blockers is a missing-taint failure. The stock Reasons string falsely says live taint is unavailable even after the wrapper replaces its provisional assertion with PASS. The patch corrects that diagnostic wording. Removing the actual taint capability/readback contract should accompany the approved product removal; no new owner decision is needed for that removal, but this patch does not fabricate a taint-free binary or alter gates to simulate one.
- **b — legitimate staged journal evolution:** epoch persistence (`StagedTransferJournal.cs:179`, `:247`), completed archive (`StagedTerminalArchive.cs:13`, `:95`, `:397`, `:409`, `:484`), and durable SealPending (`StagedTransferJournal.cs:2297`, enum `:3971`). These are direct source/evidence explanations. The warning `bound_not_ready` is emitted when the feature connection begins (`MinifilterInterceptor.cs:262`) and records unmet native create/seed/export/publication proofs. Its presence does not prove this successful held writer used bound allocation. The completed archive's producer explicitly requires **unbound** terminal entries. Do not enable a bound path or suppress its blockers to repair a journal reader.
- **c — real regression:** not established by these blockers. Native writer calls and sampled final A contradict a claim that all saves were refused. Authenticated terminal policy/identity history is absent, so a latent publication or bookkeeping regression is also not ruled out. After storage compatibility, any remaining timeout, wrong digest/history, unresolved cleanup or coverage failure stays a product failure requiring retained first-failure diagnosis.
- **d — lab/observer effect:** the raw/API MFT sequence disagreements are concrete observations, also seen in the old comparison run. Their cause is not established as a changed lab baseline; do not blame memory pressure or Verifier without evidence. Keep the exact raw identity assertion and existing bounded observer recovery. CoverageQueryFailed (0x800704D5) warnings and later Ready messages are diagnostic context, not an explanation for rejection of journal child names. Sticky Unknown/readiness and restoration gates stay intact.

| Required T4 cells | Case table at base | Shared code / exact exposure |
|---|---|---|
| C01-approve-absent / C01-block-absent | StagedInvariantCases.psd1:213 / :234 | Cached executor, held snapshots, terminal polling and exact history/digest. Directly reproduced only for APPROVE. |
| C02-approve-absent / C02-block-absent | :270 / :291 | Same executor and Get-CachedJournalObservation; mapped writer lifetime adds its own assertions. Same storage defect; new SealPending history affects both. |
| C03-approve-existing / C03-block-existing | :313 / :334 | Same reader/executor for overwrite, plus existing seeded-image invariants. |
| C04-approve / C04-block | :356 / :377 | Same reader/executor for replacement, with generation/namespace-commit proof still required. |
| B01 | :476 | Explicitly dispatches to cached preparation/execution (Suite base:6774); same held and blocked journal reader, plus junction/sentinel/hand-back-failure checks. |
| B02 | :498 | Separate executor; Get-B02Journal (Suite base:6428) calls the same cached journal observer and throws on any incomplete/nonunique snapshot. Exact stale-v1/reinspected-v2 histories also need the state-10 representation. |
| X01 | :662 | Separate executor; Get-X01Journal (Suite base:5859) calls the same reader and requires exactly one actor transfer. Both versions' exact histories are affected. |

Thus all **11 expanded rows × 3 modes = 33 cells** share this storage mismatch. They need not emit the identical eight blocker names: B02/X01 fail in their own execution paths, and family renaming changes C02–C04 assertion prefixes. No result for unrun cells is inferred. The independent raw observer remains necessary for all of them.

## Proposed patch and remaining conditions

The working patch is in `driver/scripts/Test-StagedInvariantSuite.ps1`, with `StagedInvariantJournalStorage.SelfCheck.ps1` added to the existing Windows gate's automatic SelfCheck discovery.

1. Authenticate and retain epoch bytes (4 KiB bound, nonempty driver identity, UTC accepted time, paired positive drain request/nonce and ordered drain time). Epoch data is storage context, never grant/publication authority.
2. Pin/authenticate completed directory and every inventory/pack object through the existing same-handle owner/protected exact DACL/no-reparse/single-link reader. Retain physical files and frame offsets, validate SUAC frontier checksum and exact complete segment inventory, then SUJA v1 frame ID, payload bound and SHA256. The per-manifest 131,072-byte bound is unchanged; 4 MiB is the producer's separate pack bound, not a raised manifest limit.
3. Present archive payloads under their original transfer logical identity, retaining physical provenance. Exact hot/archive duplicates during consolidation must have identical bytes; conflicting bytes or repeated archive identities reject the snapshot. Compare archive bytes again after hot collection and recheck inventories so a concurrent move cannot silently erase a receipt. Recognized atomic-replacement names use the existing five-second wait, not omission or a longer deadline. Uncommitted tails, persistent temporaries, segment gaps and unknown files stay incomplete.
4. Accept only source-supported archived ordinary Released or exact Blocked/justified-Released cleanup tuples, including the version/generation/stage-ID/digest/length/rename count. Bound archives, `.security` sidecars, cancelled/discarded workflows and other unsupported storage remain held for explicit adapters. This patch is scoped to the listed save cells, not universal bound-journal qualification. The direct BLOCK-window hot-manifest reader still needs a storage-aware adapter if a tested window outlives hot retention; do not bypass its exact cleanup/owner checks.
5. Preserve state 10 as SealPending in exported histories. Accept the complete legacy history or complete new history with exactly one SealPending between Allocated and Sealed. Never filter it out, invent states, discard a bad observation or remove inspection/publication transitions. Extra trailing durable states now explicitly fail rather than falling through to incomplete-prefix handling, and a final exact history cannot hide a contradictory polled state.
6. Leave raw capture/identity assertions, every existing non-taint product assertion, latency thresholds, poll deadlines, error aggregation, MVP deferred set, required table and strict batch verdict untouched. Retained o1/r1 evidence is never rewritten or reclassified as passing.

This is **not sufficient to promise a green rerun**. New native storage collection needs Windows PowerShell 5.1 parse/native checks and an authorized real run; none can be performed in this offline task. Current captures lack real pack payloads for replay, and an inventory changing during acquisition intentionally remains incomplete. The existing strict batch classifier additionally requires full Phase4 PASS/GatePassed, while the functional suite deliberately exports INCONCLUSIVE for missing lower mutation/permit/temporal evidence. Even a repaired functional/MVP result cannot satisfy that classifier by changing a flag. Keep that gate and implement its missing authenticated evidence; do not treat a different-case historical MVP pass as approval to downgrade it.

No new product decision is needed to collect the correct existing journal contract. The unproved bound seed/read/export choices remain product decisions outside this patch: enabling unproved paths could hand users bytes they cannot read natively or create SYSTEM-derived authority; keeping the current NotReady gate refuses those bound operations until the approved authority contract is proven. Recommendation: retain the gate and qualify the approved exact caller/object contract; do not select a fallback or enable readiness as a harness workaround.

## Offline verification

[Verbatim command results and failed attempts](t4-cells-triage-offline-results.txt) are retained separately; this is the exact stdout/stderr, including test counts and environment failures. Raw per-check logs and the same-case search inventory remain local under `t4-cells-triage-offline/`.

- First pass ran 31 local checks: 22 exit 0, 9 exit 1. No assertions were skipped or changed.
- Final new storage check: `JournalStorageSelfCheck=PASS;Checks=44;Qualification=False`.
- ProofAdapters: `ProofAdapterEvaluationChecks=452;PASS (host-safe synthetic evaluation, collector mocks and identity publication only)`.
- T4 verdict replay, exact agent matrix SelfCheck, strict case-verdict SelfCheck, A04, dedicated latency, exact sources, MVP gate/tiers, seed latency, block window, latency authoring/lite, live-taint, R03, restart/justification, trace window, T4 delete attribution, purge signatures and Verifier controls passed on Linux where applicable. These are synthetic/source controls, not Windows results.
- Runtime SelfCheck initially lacked TEMP; with TEMP=/tmp its complete unmodified check passed (`Controls=35`). T4 holders/memory/volume still fail on Windows native calls. T5 security requires .NET Framework's WindowsImpersonationContext. Reopen SelfCheck explicitly requires Windows PowerShell 5.1.
- CoreVariants and RowsA fail under Linux Windows-path semantics; unmodified `ad92dc4a` produces the same respective failures. No path assertion was weakened to pass them.
- Python ProofAdapters first failed solely because the clone lacks its untracked historical S00 fixture. A local ignored symlink to the original read-only `2026-10-04/...wp3s00g-artifacts/case.json` supplied the exact fixture, after which the complete 20-test check passed. Initial failure retained; no source or assertion changed.
- Windows-only Observer, ActivationDuplicate, T4Failure, T4Ipc, T4PurgeAttribution and Robustness native controls could not be executed on Linux. No native Windows signature/handle/ACL authority is claimed from PS7.
- Final Linux PowerShell **7.4.2** parsing of the edited suite and new SelfCheck: 0 errors each. This does **not** meet the required Windows PowerShell **5.1** gate. `git diff --check -- driver/scripts` passed. The staged verbatim log retains one trailing space emitted by a PowerShell native-error record; the all-files whitespace check reports that evidence line.

No passing gate, qualification result, absent boot-Verifier result or missing historical same-case pass is claimed.

## Delivery state

No commit was created. Initial staging succeeded, but staging the final report update failed with `fatal: Unable to create .../.git/index.lock: Read-only file system`. The working tree is complete and partly staged on `t4/cells-triage`; no push was attempted. A standalone source/test patch is retained at [t4-cells-triage-harness.patch](t4-cells-triage-harness.patch). Apply it to base `ad92dc4a`; the report and verbatim result file are separate deliverables.
