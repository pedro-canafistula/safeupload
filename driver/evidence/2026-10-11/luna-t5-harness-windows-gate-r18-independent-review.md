# Independent cybersecurity/source review: SafeUpload T5 Windows gate R18

**Verdict: SOURCE NO_GO. Windows runtime remains unqualified.** R18 corrects the R17 stale-job and post-create assignment races at source level, but this frozen bundle cannot run: the root's Windows PowerShell 5.1 parse-only diagnostic reports three parse errors. I also found a keeper failure path that closes the exact job handles needed by a later CANCEL after RUN has exited.

## Scope and evidence

I read the active owned-stream MVP goal and found no repository AGENTS.md instructions. The reviewed immutable candidate is output/review-candidates/m2-t5-harness-windows-gate-r18-root-a1: 63 source paths, six author artifacts, and three context documents. The root capture is driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r18-root-review-capture.json, SHA-256 4da629bbdc11533484c4a2ed0b2aebfe587f47f2518d5b23c5727d369f81c100. Its canonical source inventory digest is recorded as ec9b22bd5dac458f52a820aaa0c7a28335140ad33e28fca01e507076f1547695.

I independently read and checked all 63 source pins, all six author pins, and all three context pins using two consecutive reads with stable file identity, size, and modification time. The source tree exactly matches the 63 captured paths. Against R17's 60-file author candidate, the comparison is 52 identical, eight changed, three added, and zero removed. All 33 paths listed as test/coordinator inputs by the manifest remain byte-identical to R17. The complete verified pin list is below.

I reviewed the changed harness implementations, the keeper and lifecycle fixture, the manifest/client/helper/shell closure, the R18 design and handoff documents, and the R17 review/disposition context. The R18 changed implementation paths are HarnessWindowsGate.manifest.json, HarnessWindowsGateClient.py, HarnessWindowsGateManifest.py, HarnessWindowsGateProtocol.psm1, HarnessWindowsGateRemote.ps1, HarnessWindowsGateRemoteControl.ps1, HarnessWindowsGateWorker.ps1, and Invoke-HarnessWindowsGate.sh. Additions are HarnessWindowsGateLeaseKeeper.ps1, HarnessWindowsGateLifecycleFixture.ps1, and the R18 dual-handle design record.

This review ran only the requested offline Python/Bash controls. It made no candidate source edits, Git mutations, network or builder calls, Windows harness execution, service/actor execution, product VM work, or host-policy actions. The only new repository file from this review is this additive report.

## Findings

### F1 — Windows PowerShell parser rejects the runner and lifecycle fixture

**Severity: Blocker.** The root's Windows PowerShell 5.1 parse-only receipt reports three exact parse failures in pinned R18 files:

- HarnessWindowsGateRemote.ps1 line 226, column 72: unexpected token $jobName.
- HarnessWindowsGateRemote.ps1 line 227, column 78: unexpected token $keeperJobName.
- HarnessWindowsGateLifecycleFixture.ps1 line 223, column 77: unexpected token $fixtureJobName.

Each location is a static method call written without method-call parentheses. The parser receipt confirms the protocol module, remote control, worker, keeper, and two embedded worker scripts parsed with zero errors. It skipped native C# compilation after the PowerShell parse failures. The receipt says no fixture/harness execution, native method invocation, or driver activity occurred. The source pins in that receipt match this R18 bundle.

The parse-only evidence is driver/evidence/2026-10-11/m2-t5-harness-r18-compiler-a1-root-result.json, SHA-256 4644cd10ae76f5832729120e26d295df582f8400f924a7361947ccd23537469f. This is a real Windows PowerShell 5.1 parse result supplied by root; I did not run a Windows parser or execution. The exact raw compiler evidence hashes are listed under Independent Windows parse-control evidence.

### F2 — Keeper exits and drops the job handles after a drain/query failure

**Severity: High; source blocker for CANCEL recovery.** HarnessWindowsGateLeaseKeeper.ps1 lines 82–98 starts the 3600-second drain, calls TerminateJob, and queries the held main job. If termination, the final query, or the exact PID-list query throws or fails to prove zero, control reaches lines 101–109. The catch calls exit 1 and finally closes both inherited main-job and keeper-job handles.

That conflicts with the R18 reviewed design, which requires the keeper to remain alive with both handles when deadline termination or proof fails so CANCEL can use the exact named jobs. After ordinary RUN has exited, the keeper may be the last holder of those jobs: the runner closes its own handles in HarnessWindowsGateRemote.ps1 lines 440–449, and a completed worker has closed its inherited main-job handle. The keeper's failure exit therefore closes the last keeper-job handle, invoking kill-on-close and destroying the named keeper job. If the main job has no remaining process-held handle, it can disappear too. A later control opens both named jobs before acting and explicitly throws if either is missing (HarnessWindowsGateRemoteControl.ps1 lines 330–333). It then cannot stop or prove the remaining main-job members. This remains fail-closed—there is no fabricated terminal receipt—but it removes the exact recovery path R18 claims for a failed drain.

Keep the keeper and both job handles available after any unproven drain, or provide a pinned recovery protocol that does not treat a missing named object as terminal. A timeout or query error must not make the keeper exit and discard the only proof objects.

## R18 protocol review

At source level, the central R17 fixes are present. RUN acquires the per-token mutex before the atomic state claim and retains it through creation, exact identity persistence, and resume of the keeper and worker. VERIFY, CANCEL, and CLEANUP acquire the same mutex before state/job observation. CANCEL's no-run tombstone is created only while holding that mutex after both named jobs are absent; a RUN state with a missing job throws without emitting a terminal record.

Worker and keeper processes use STARTUPINFOEX handle-list and job-list attributes in CreateProcess; there is no AssignProcessToJobObject fallback. Each remains suspended while the parent checks membership and captures its native process handle, PID, and creation FILETIME. RUN durably writes PID/FILETIME before ResumeThread. CANCEL holds both exact named job handles, requires real active-process counts and complete PID lists, retains exact RUN/worker/keeper process handles, and rechecks both job objects after termination. I found no missing-job-to-zero substitution in the ordinary control path.

The normal RUN-to-VERIFY-to-CLEANUP handoff is represented by the keeper inheriting both job handles, publishing an exact readiness receipt, and remaining in its keeper job after RUN exits. The outer lifecycle fixture source checks that RUN's retained handle is signaled while the suspended keeper remains the sole keeper-job member and remains in the outer fixture job; it starts the pinned CANCEL child inside that outer job, waits on the same keeper handle, proves both named jobs empty, then checks outer-job emptiness after the CANCEL controller exits.

The parent stream writer reserves the whole attempted chunk before Write/Flush and latches per-stream write failure. Worker output uses bounded 64 KiB overlapped reads, retains event/OVERLAPPED/buffer state when cancellation completion is unknown, and does not accept a child PASS until its process and readers are terminal. Parent output uses a 15 MiB worker-file bound, 16 MiB per remote stream, and 64 KiB metadata cap. The worker's native 15 MiB combined stream quota also charges its summary metadata, so it may fail conservatively before a self-check consumes the full per-child allowance; that can reject a valid high-output run but cannot create a false PASS.

The local client requires complete transports, exact final remote markers, a bound process identity, a terminal control record, and closed manifest pins. The shell explicitly uploads the 33 reviewed inputs plus seven support/manifest files, runs the two-barrier fixture before the main diagnostic, rechecks local pins, and only emits its final PASS after post-delivery pin verification and cleanup. The manifest self-check covers exact inventory, duplicate JSON keys, unsafe paths, symlinks, missing/changed files, and independent pins.

The fixture exercises the two keeper barriers (before PID publication and before ResumeThread). It does not exercise the separately described worker create-before-publication, worker failed-resume, mutex/tombstone ordering, or injected partial-write/flush-failure cases. The source contains fail-closed handling for those worker boundaries, but their Windows behavior remains unproven. This is a limit on runtime evidence, not a new product qualification or an additional product gate.

## Offline controls rerun

All five requested Linux-safe controls exited 0 against the frozen candidate:

| Control | Result |
|---|---|
| Exact manifest verification, 33 sources plus eight support pins | PASS; checked 41 |
| Manifest synthetic self-check | PASS; 15 assertions |
| Client protocol/process-tree self-check | PASS; 85 assertions |
| Bash syntax check | PASS; no diagnostics |
| Shell finalizer self-check | PASS; two assertions |

The client self-check's disposable process-tree exercise ran locally and exited through its bounded cleanup path. No Python actor/service or PowerShell source was executed. These controls do not compile PowerShell or the embedded C# and do not validate Windows job-list/nested-job or named-pipe behavior.

## Independent Windows parse-control evidence

Root parser receipt: driver/evidence/2026-10-11/m2-t5-harness-r18-compiler-a1-root-result.json; SHA-256 4644cd10ae76f5832729120e26d295df582f8400f924a7361947ccd23537469f.

The receipt's compiler-helper SHA-256 is cbc6a5b227e0f56017db072f04954130aa4345e3d1d4ecc3bdc7c4b122f0aae0. Its raw inputs and outputs are:

| Artifact | SHA-256 |
|---|---|
| m2-t5-harness-r18-compiler-a1-compile-input.ps1 | 7ed61218122a005256e42f4f3eede2f4895715abb05b41c45e249bf4664a12ec |
| m2-t5-harness-r18-compiler-a1-helper-input.ps1 | cbc6a5b227e0f56017db072f04954130aa4345e3d1d4ecc3bdc7c4b122f0aae0 |
| m2-t5-harness-r18-compiler-a1-preflight-input.ps1 | 68e4556d7b24b49effd6da40a8803a61abc4c0cc852b8707fe36d70b0c292a5f |
| m2-t5-harness-r18-compiler-a1-compile.stderr.txt | aa4c6b5187e8a52a4b02316c91eb0c7a4cfdce4cdea9b9d7ecfe2faa1d97cce4 |
| m2-t5-harness-r18-compiler-a1-compile.stdout.txt | a1f892636b549a15cc332c9033594846a4fbd4803fccad54686fbb3dcf3785ad |
| m2-t5-harness-r18-compiler-a1-delivery.stderr.txt | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| m2-t5-harness-r18-compiler-a1-delivery.stdout.txt | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| m2-t5-harness-r18-compiler-a1-preflight.stderr.txt | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| m2-t5-harness-r18-compiler-a1-preflight.stdout.txt | fbaa7892d5652979e593f2a197f0853605c3aca2db2cfd25fcd26929136e4860 |

The compiler receipt reports PSVersion 5.1.19041.6456, CompilerProcessExit 0 for the parse-only helper, no source execution, no native invocation, no C# compilation attempt, and RuntimeQualified=false. The helper's successful process exit is not a compile or source-acceptance result.

After that parse receipt, root ran a separate compiler-only check against the exact R18 protocol module's embedded C# literal. It parsed the pinned protocol module and compiled the extracted literal successfully with no warnings or errors. The native compiler input hash is 5e32aa317f7c30abf10dc350050afeb530a04f0c35bce8b735995d7fc815e7e0; the output assembly hash is dc5c1e61215ed2d4546b43bf26c02ad22f934eae442da00790c3ed061dcc12f3. Receipt: driver/evidence/2026-10-11/m2-t5-harness-r18-native-compiler-a2-root-result.json, SHA-256 232e34c36550ab0d8c807b34c8e4489d2296a2f1c283919ae7f9ed9ea89b2cc8. It reports no source/harness execution or native-method invocation and RuntimeQualified=false. This isolated success does not clear the runner/fixture parser errors or qualify runtime behavior.

## Limits

This is a source review plus Linux-safe offline checks. The Windows parser result is a separately captured root control. No Windows C# compilation or job/pipe execution was performed in this review. No actor, coordinator, service, native product driver, product VM, upload, network, or host action was performed. The owned-stream MVP goal remains open; this report does not approve taint removal, enable unsupported capabilities, or qualify any protected destination.

## Frozen R18 source pins
| Path | SHA-256 |
|---|---|
| agente/SafeUpload.Agent.Service/Interception/StagedJournalFile.cs | 5f4a5ae360513425f1ff79c3ad8c0c4fc8c2b3464f416cecc43c57c42224053a |
| agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs | 4b270eaef4616c06ba52e0b88deb701d72463dcef8ed6c9c8cc4c39893b23f8d |
| driver/evidence/2026-10-11/luna-t5-harness-windows-gate-r15-independent-review.md | 992e5229652ffb85199984d502d71a7be9da7ceaa412f581a890f8ed425ddedf |
| driver/evidence/2026-10-11/luna-t5-notepad-coordinator-r14-independent-review.md | 714a0d4ad56682a6a33aa95048ec7ec20abf939783a1419ee884c207510cedb3 |
| driver/evidence/2026-10-11/m2-t5-coordinator-r14-diag-a1-root-result.json | db51a75d2833bc7d9c0fda78c484fe94708ef24166f3ae664a7f3bd3f50ae725 |
| driver/evidence/2026-10-11/m2-t5-coordinator-r14-diag-a1-root-verification.json | 60b5ec053da0d06f774578ae754607c587419affa9de81a5587b3d87e417bec5 |
| driver/evidence/2026-10-11/m2-t5-empty-service-r13-root-review-capture.json | 828246fd46b6cdaf8ea3be2fab94267dfa9e158c0542c2aa675806b6e7906d19 |
| driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r15-author-note.md | 2c56d07635a4bf3423dd51983c111bac56d8e7a28d7922cb4cee00f9ad8a77db |
| driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r15-author-result.json | ca51d31b45590f472d81a58fc506afe776e04171c6f3ba36a92b3261abe45e1c |
| driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r15-offline-controls.txt | 145edd7d3dde1b897a6a210e4e7a27c7eabb59dcd65815e655928f7314e18daf |
| driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r15-root-review-disposition.json | c690a5b7a5ac3afc5f56bba94123bb890e86afaeae1cf4684cf74fd29328f220 |
| driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r16-author-note.md | c56721e0f63ccd57193608531f9ed4317052c8ea4bf52f9d192d447913b80b97 |
| driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r16-author-result.json | ccf6a8490b8a27edf77bff8839bd80f537d8e57fccbee25fd58bcd56d603962d |
| driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r16-offline-controls.txt | b84e98b50162bdcb0ce271af441ac4c8ead48ec27f9289fc257f29507f9fba5f |
| driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r18-dual-handle-design.md | 69e47c0b091b0d236c535e4e19d2b18815806614d45cbf668ccc4bf54e7a9044 |
| driver/evidence/2026-10-11/m2-t5-notepad-coordinator-r14-root-review-capture.json | cf0231084dab2b7cb1e36c3e041fa7bb6206e9c3faa4a47b126c9705e324efb0 |
| driver/evidence/2026-10-11/m2-t5-notepad-coordinator-r14-root-review-disposition.json | 386b2dcb492ad66835fcac15a3d2552ef33345149b99accd1f3d52331b215d51 |
| driver/scripts/Build-ExactAgent.ps1 | eb9be83ed99aa0057b00f160419e8c123bc2b4a79991c894086de86571ad2e52 |
| driver/scripts/Build-ExactAgentMatrix.ps1 | 90aebd88352c4c23265508a244437895d0a84218bc7815d031de7e81bec45ac7 |
| driver/scripts/HarnessWindowsGate.manifest.json | 2cbe36281a8d8d1dbb8698cb34fd490204810382b3eb96c525b126bdd3cf0784 |
| driver/scripts/HarnessWindowsGateClient.py | 60ab182e917731587dee238f0c802a9ac6aff8c6bf8cd31a8890f4d180e7d3f1 |
| driver/scripts/HarnessWindowsGateLeaseKeeper.ps1 | 7561a06f163990460ee42e4865c93d74cef8fab1801696dfcc816fcdc152d9c8 |
| driver/scripts/HarnessWindowsGateLifecycleFixture.ps1 | 812a514fa5e79ef9793853ca71f07fe5fdb6948ff1f194438747a83df796ba03 |
| driver/scripts/HarnessWindowsGateManifest.py | a7cebdf3eb20fe1ab8df9976721a648725a526b5c39a584fb721a59658f2a6c8 |
| driver/scripts/HarnessWindowsGateProtocol.psm1 | 9fb561090d9e1f7a4370b7cb4c8369001ca69e06e4f406c4f072480f7a0ebacf |
| driver/scripts/HarnessWindowsGateRemote.ps1 | eeb0054a906b2f932ad09a4b359c146f891872cfe8a885c6d5a44c091cb682eb |
| driver/scripts/HarnessWindowsGateRemoteControl.ps1 | 48a16decedec44e7c529ee2df099f9dbde1f2b69ef33d23d95fc58cd2b3b3caa |
| driver/scripts/HarnessWindowsGateWorker.ps1 | 8826d5f39295be32b1a2782ff2aaf378a1871b71260c707a810ba0ee5fba2731 |
| driver/scripts/Invoke-HarnessWindowsGate.sh | dd3ba8816cc14ba632ac5509b00948641f16609b9e4195f03ab6eeeee634dfda |
| driver/scripts/StagedInvariantActivationDuplicate.SelfCheck.ps1 | 56f10e03983bb996d851584c6604554fee1762c115535a4d2ed005ca50ea15e8 |
| driver/scripts/StagedInvariantBlockWindow.SelfCheck.ps1 | 4f25dde8342906dce67227fec8fcd154b1f4793377c18f0be262cc15d828f893 |
| driver/scripts/StagedInvariantCases.psd1 | c7c91697b77b278c3f4f0aec627cfcb1b3b86e06b9d05b81d4616d00062af7b6 |
| driver/scripts/StagedInvariantCoreVariants.SelfCheck.ps1 | 5a2c2e365a20e566eb1fb395cc3df537cc630d9b28dbd545fd1098421ba9c990 |
| driver/scripts/StagedInvariantDeniedRenameLatency.SelfCheck.ps1 | 9d55ec0ae3ad55ffab0cf1c992715f6e903dea43c1820b71cdcbea334ecb6fb5 |
| driver/scripts/StagedInvariantLatency.SelfCheck.ps1 | 344e33acf1036757b2c5284e67179d26b96681a5b4bf19c6609ad5c9600f9c86 |
| driver/scripts/StagedInvariantLatencyLite.SelfCheck.ps1 | a91b37beb4f5d137d604f4bbdab928a68c72b72b5e8d527ee6c3f698d595dc1e |
| driver/scripts/StagedInvariantLiveTaint.SelfCheck.ps1 | 967b8e791bc9c26a4e992cd33582519556e251d10690bb3f48deb8eb0530017d |
| driver/scripts/StagedInvariantObserver.SelfCheck.ps1 | 8cd16c071114d2e2d93cf1594ae27b61f6d7672c45d73cb42bbe7fa850de49e1 |
| driver/scripts/StagedInvariantObserver.psm1 | 48577d312b66287f432b75e0ee61cca787a30f6e3632a1d2912085cc32070bc8 |
| driver/scripts/StagedInvariantProofAdapters.SelfCheck.ps1 | 2dd78b9dcd6f21ab0220c983ca1924b1440c26fc9670bc3ef927ce5ea227e764 |
| driver/scripts/StagedInvariantR03.SelfCheck.ps1 | 91620bc811b38a8ef0e26e7f41c459eea61a9b0d8d66019fdb584b9cf644e40e |
| driver/scripts/StagedInvariantRestartJustification.SelfCheck.ps1 | 6418ed356b1bcb80b24c449da431069ba7d30a9db26489c43789726c7a9e9715 |
| driver/scripts/StagedInvariantRobustness.SelfCheck.ps1 | d3ea4d476a766a8f0dc5d9b70713eb3c671b81c770472c836c3aaee21739d41e |
| driver/scripts/StagedInvariantRowsA.SelfCheck.ps1 | d23d22e48e24433a94b98b8789bacd1e548ccf516dbbb3e80d8c1b2c2070033b |
| driver/scripts/StagedInvariantT4Ipc.SelfCheck.ps1 | af41aa53f16390f023911d519c9493f15658274c1381aef6532c4dcf48b45513 |
| driver/scripts/StagedInvariantT4Runtime.SelfCheck.ps1 | 0e6598eb65c44e8c4e5aeac97f92c5b28fdd2de648c0ff4284ee6962069e712d |
| driver/scripts/StagedInvariantT4Verifier.SelfCheck.ps1 | a0282ae55b388dc19db5e3976d773faeb06992026b0ade17cebf9d118454f02c |
| driver/scripts/StagedInvariantTraceWindow.SelfCheck.ps1 | b1911961ad0ed225c6ba2ae02a19d5de08256aa6c326981c1fd8afd65c54844d |
| driver/scripts/Test-StagedInvariantSuite.ps1 | 773bc9348b374f52dee78c06ee69d7144b7b16a8aa6c03ba3b5ee50ae4e0a672 |
| driver/scripts/remote_ps.py | 39ed7a7892555d61b1577380fd84888ab39278a0115a7ca9b47b16ca6c52995b |
| driver/scripts/t10/permissions-actor.ps1 | 208ebd1639f30bd61ca9fab1e8bb2a98bfdd874f1c9ecaaa42dc0cbf7a1d9cc6 |
| driver/scripts/t10/permissions-coordinator.ps1 | d916c2d18a9da5e50441c164df61d19ba772bf7289fa42062592bb6b487cbe48 |
| driver/scripts/t4/cycles-actor.ps1 | 7338124c4da1c44025f93cbfc754e6a002ba09e39bb68a045a5fea25f0af04e9 |
| driver/scripts/t4/cycles-coordinator.ps1 | e7b5349888eeaeefd7dfc09fd92e23447ba142fb70a67892ee3a9c3c4ff7c677 |
| driver/scripts/t4/cycles-progress.ps1 | dfa5d200c5778d3025ed57e8440b400d0bff5e6c8de4781f22435e691aafaf6b |
| driver/scripts/t4/runtime-verifier.ps1 | 04dfbfad81daf4c3b8d613f068d88e05adbb73c10bd2e1376de8c69f8a9148c1 |
| driver/scripts/t5/notepad-actor.ps1 | fe85a4259a8fa1da10db3b7be7a684ffccffee107491bf02442f95ae75c1ce11 |
| driver/scripts/t5/notepad-coordinator.SelfCheck.ps1 | dbc00a84c456b97f6903cfcb4ccc0ba37c5ff763fc6b67e83aab3e86e807245f |
| driver/scripts/t5/notepad-coordinator.ps1 | c21757ed59acd607138be5eaafbdbcd2192dd48dd840c80563cb5b21f22d291d |
| driver/scripts/t6/moves-actor.ps1 | 22d427bd811c2bf396d45f8d65a1c3ef197d6fa6428b9630aef367bde138857a |
| driver/scripts/t6/moves-coordinator.ps1 | 5218b675460f540ac1ef077a0112ec018b5000e73dff8f54d7adbd729f94df3d |
| output/review-candidates/m2-t5-harness-windows-gate-r15-1011-a1/source-capture.json | e7df89326202d432b9f1846368e3716bb27d207926dc07267dbdbadb293aa4c8 |
| output/review-candidates/m2-t5-harness-windows-gate-r16-1011-a1/source-capture.json | 0cce292047acb14c0f00b62acc1efc998b59d743441e118c2f4d4debdce765e0 |

## Frozen author and context pins
| Scope/path | SHA-256 |
|---|---|
| author/author-design.md | 321d05521bdd40dddd9ced7eca7688b983e4cbc6e8287fc81a99c606f8156471 |
| author/author-note.md | e1e7d6b18155ae55eb43d38ca66abc9b8be31bedf6ed9cbd6055dd760ee4c163 |
| author/author-result.json | 42fa7ac666b60db4d9cb6e14e911a13270586a29006988005c5dd49062c31fb8 |
| author/offline-controls.txt | 1c468c7d4b474a123cfd1e44446eb7e21cf18428a76e8663fcfa6e3eaa0bc8e1 |
| author/outer-fixture-job-addendum.md | 049566c14da61cf5c9d83620b87e8ed0d10c2970392c1f0f499acbc18c39d97d |
| author/source-capture.json | d74f348f192e697b70a169af9c5e75fb0ad09e87b6d9ffe7bcb93b514203f14a |
| context/driver/evidence/2026-10-11/luna-t5-harness-windows-gate-r17-independent-review.md | 3e25dcc8e3e6f37da9ae8c9d8f5987c5675f52c56ec4f32920d9542bf3617d3b |
| context/driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r17-root-review-disposition.json | 53e1a3f30ae2bbdceaae8c87d811314dbc78497585f5a43379fbff92c67251ec |
| context/driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r18-dual-handle-root-design-a1.json | e268773b15ae2832e6e8b4020d7bb44d1d06ac58c9442a62a323a57117c50227 |
