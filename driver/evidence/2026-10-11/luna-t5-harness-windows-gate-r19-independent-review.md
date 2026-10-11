# Independent cybersecurity/source review: SafeUpload T5 Windows gate R19

**Verdict: SOURCE NO_GO. Runtime remains unqualified.** R19 corrects the three R18 PowerShell syntax errors and preserves keeper job handles after a post-readiness failure. However, the frozen shell still pins the R18 client, manifest, runner, keeper, and fixture hashes, so its real pre-delivery verification rejects the R19 bundle before upload or diagnostics. I also found an inherited fail-closed race in readiness-file publication that can cause a transient startup failure.

## Scope and evidence

I read the active owned-stream MVP goal and found no repository `AGENTS.md`. The immutable root candidate is `output/review-candidates/m2-t5-harness-windows-gate-r19-root-a1`: 63 source paths, seven author artifacts, and six context documents. Its capture is `driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r19-root-review-capture.json`, SHA-256 `8958ae1cc166773431c5b463dbe8ebfe7497d9766f8b7e9a3cd3c4156e155a13`; the canonical source inventory digest is `6899176de36cf694a61cf268f7ec49cceacc94b2c7b6c01f77d7f7541d0854f6`.

I independently read and checked all 63 source pins, seven author pins, and six context pins using stable descriptor/path identity checks. There were zero mismatches. Compared with the frozen R18 root capture, R19 has 58 identical source files, five changed files, zero additions, and zero removals. All 33 manifest execution-source records are unchanged. The full verified inventory is included below.

The five source changes are the manifest, client, keeper, lifecycle fixture, and remote runner. The R19 parser corrections parenthesize the three `CreateKillOnCloseJob` calls. The keeper now arms sticky retention before attempting readiness publication, keeps both exact inherited job handles after a post-readiness failure, and releases them only after a final active-count-zero and exact-PID-list-empty result.

Root's fresh Windows PowerShell 5.1 compiler-only receipt is `driver/evidence/2026-10-11/m2-t5-harness-r19-compiler-a1-root-result.json`, SHA-256 `30c0b0590db7ae31e8893ae47528bbab418a590be2f5331a66c426ba5a672185`. It reports six pinned PowerShell sources and both nested worker scripts parsed with zero errors, and the embedded protocol C# compiled with zero warnings/errors. The six source hashes match the root R19 snapshot. It did not execute a source module, invoke a native method, run the fixture or harness, start a product VM, or qualify runtime behavior.

I reran the safe offline controls: manifest verification (41 checked files) and its 15-assertion self-check; client self-check (88 assertions); four disposable source-mutant rejections; Bash syntax; and the two-assertion shell finalizer self-check. The mutant script ran from a temporary mirror containing the byte-identical pinned R19 source because the root freeze stores author files separately from `src`. I also ran the shell's actual pre-delivery path in a disposable clone: it exited 2 at the R19 client hash check before manifest verification, upload, or any network-capable command. All temporary test copies were removed. No candidate source, live source, Git state, network, Windows harness, service, actor, coordinator, product VM, or host policy was touched by this review.

## Findings

### F1 — R19 shell preflight still pins five R18 hashes

**Severity: Blocker.** `Invoke-HarnessWindowsGate.sh` is unchanged from R18. Its expected local pins at lines 26–31 still name R18 versions:

| File | Shell expects | R19 candidate SHA-256 |
|---|---|---|
| `HarnessWindowsGateClient.py` | `60ab182e917731587dee238f0c802a9ac6aff8c6bf8cd31a8890f4d180e7d3f1` | `d5f558bc6c7435a0e8f6628ae2fffc465b34ed0981d1470d90de44980f4975c8` |
| `HarnessWindowsGate.manifest.json` | `2cbe36281a8d8d1dbb8698cb34fd490204810382b3eb96c525b126bdd3cf0784` | `7d5ea90a1cf1c941610572f038a9db8ff43b5c934e41a0adbf3f54bbd98d11f7` |
| `HarnessWindowsGateRemote.ps1` | `eeb0054a906b2f932ad09a4b359c146f891872cfe8a885c6d5a44c091cb682eb` | `6e1765e52ed051a493f55826f066d3fc050bcbe75edef783bd4c555a84eb5918` |
| `HarnessWindowsGateLeaseKeeper.ps1` | `7561a06f163990460ee42e4865c93d74cef8fab1801696dfcc816fcdc152d9c8` | `aa24884d0f943ff0e97bc37132f5fe4a9f2c595166a7a7b9515198abc2606fa2` |
| `HarnessWindowsGateLifecycleFixture.ps1` | `812a514fa5e79ef9793853ca71f07fe5fdb6948ff1f194438747a83df796ba03` | `599eb7da9e0177b2443d5edd937a15b29c72b0357e5c4b71a3c2397b62fb1489` |

`verify_local` compares the client hash first (lines 48–57), before invoking the manifest verifier (lines 59–67). The normal pre-delivery call is at line 143. Thus R19 exits 2 with `HarnessWindowsGateClient=pre-delivery:FAIL: local client SHA-256 mismatch` before the lifecycle fixture, upload, or main diagnostic. I reproduced that exact local-only path in a disposable clone. The shell finalizer self-check cannot detect this stale-pin set: its negative and positive branches replace `verify_local` with functions that unconditionally return 1 or 0 (lines 91–115), and the self-check exits before real pre-delivery verification.

The runner, keeper, fixture, client, and manifest pins all need to match the R19 bytes before this bundle can pass its own gate. This finding is independent of the successful parser/compiler receipt.

### F2 — R18 keeper handle-retention defect is corrected at source level

The R18 keeper could exit after a failed deadline drain/query and close the only remaining job handles. R19 sets `$retainHandlesForCancel = $true` only after checking exact job membership and persisted token/path/PID/FILETIME, but before writing the readiness file. If readiness creation/hash or a later deadline/drain/query operation fails, its catch emits at most one sanitized 2,048-character diagnostic and sleeps at one-second intervals. It does not retry queries or close handles. The `finally` closes both handles only after the final active-count and exact PID-list queries prove the main job empty; the one-hour stopwatch initiates real termination and does not itself prove completion.

That closes the reviewed last-handle-loss window after the readiness receipt can become visible while RUN still may accept it. RUN keeps the startup mutex and its own job/process handles through receipt validation, durable `KEEPER_READY` state, worker creation, identity persistence, and resume. Its startup catch terminates the exact held jobs and waits on retained native process handles before publishing any terminal failure. A later CANCEL uses the deterministic named jobs and exact keeper identity or the existing narrowly bound unpublished-keeper recovery; missing job objects remain UNKNOWN and cannot become synthetic zero.

The lifecycle fixture source still checks both pre-publication and pre-resume barriers: it holds RUN's native handle, verifies the suspended keeper is in both exact keeper and outer fixture jobs, terminates RUN, proves the same keeper handle remains active, runs exact CANCEL, proves both named jobs empty, then checks the outer job reaches zero after the controller ends. These are source-level controls only; the fixture was not executed.

### F3 — Visible readiness file can be read before its write is complete

**Severity: Medium; fail-closed startup reliability.** The unchanged `Write-HarnessGateKeeperReadyReceipt` creates the final path directly with `FileMode.CreateNew` and `FileShare.Read`, then writes and flushes the JSON in place (`HarnessWindowsGateProtocol.psm1` lines 1501–1508). The file name is visible as soon as the create succeeds, including while its contents are empty or partial. RUN's `Wait-KeeperReady` treats any visible leaf as complete and immediately calls `Get-Content`/`ConvertFrom-Json` and `Get-FileHash` (Remote.ps1 lines 145–161); parse/read errors are not retried.

A reader that observes the path between create and completed write/flush can therefore fail startup and cause RUN's exact cleanup path to terminate the jobs. I found no way for this to turn an incomplete receipt into a false terminal PASS, and the R19 sticky handle flag protects the keeper if its own write/hash path fails. It remains a concrete transient NO_GO race. Publishing via a same-directory temporary file followed by flush and atomic move, or retrying an incomplete read while the exact keeper remains live, would remove this race. Runtime frequency is untested.

## Offline control results

| Control | Result |
|---|---|
| Exact manifest verification | PASS; 33 execution sources + 8 support files = 41 checked |
| Manifest synthetic self-check | PASS; 15 assertions |
| Client protocol/process-tree self-check | PASS; 88 assertions |
| Disposable client-control mutants | PASS; 4 unsafe variants rejected |
| Bash syntax | PASS |
| Shell finish self-check | PASS; 2 assertions |
| Real shell local pre-delivery verification, disposable clone | Expected NO_GO; exit 2 on stale R19 client pin before any remote operation |

## Windows compiler-only evidence and limits

Root receipt: `driver/evidence/2026-10-11/m2-t5-harness-r19-compiler-a1-root-result.json`, SHA-256 `30c0b0590db7ae31e8893ae47528bbab418a590be2f5331a66c426ba5a672185`. It records Windows PowerShell 5.1.19041.6456, six exact source hashes, zero PowerShell parse errors, zero nested-worker parse errors, and successful compilation of the embedded protocol C# (`NativeInputSHA256=5e32aa317f7c30abf10dc350050afeb530a04f0c35bce8b735995d7fc815e7e0`; assembly SHA-256 `c3897154910d3a6bc3edc371d87468d3f37778021639584b74dd9a27c0109ace`). No source or harness ran and no native methods were invoked. The compiler receipt is not runtime qualification or source acceptance.

This review is source analysis and offline checking. It does not approve taint removal, enable unsupported capabilities, or qualify any protected destination. The owned-stream MVP goal remains open.

## Frozen R19 source pins

| Path | SHA-256 |
|---|---|
| `agente/SafeUpload.Agent.Service/Interception/StagedJournalFile.cs` | `5f4a5ae360513425f1ff79c3ad8c0c4fc8c2b3464f416cecc43c57c42224053a` |
| `agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs` | `4b270eaef4616c06ba52e0b88deb701d72463dcef8ed6c9c8cc4c39893b23f8d` |
| `driver/evidence/2026-10-11/luna-t5-harness-windows-gate-r15-independent-review.md` | `992e5229652ffb85199984d502d71a7be9da7ceaa412f581a890f8ed425ddedf` |
| `driver/evidence/2026-10-11/luna-t5-notepad-coordinator-r14-independent-review.md` | `714a0d4ad56682a6a33aa95048ec7ec20abf939783a1419ee884c207510cedb3` |
| `driver/evidence/2026-10-11/m2-t5-coordinator-r14-diag-a1-root-result.json` | `db51a75d2833bc7d9c0fda78c484fe94708ef24166f3ae664a7f3bd3f50ae725` |
| `driver/evidence/2026-10-11/m2-t5-coordinator-r14-diag-a1-root-verification.json` | `60b5ec053da0d06f774578ae754607c587419affa9de81a5587b3d87e417bec5` |
| `driver/evidence/2026-10-11/m2-t5-empty-service-r13-root-review-capture.json` | `828246fd46b6cdaf8ea3be2fab94267dfa9e158c0542c2aa675806b6e7906d19` |
| `driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r15-author-note.md` | `2c56d07635a4bf3423dd51983c111bac56d8e7a28d7922cb4cee00f9ad8a77db` |
| `driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r15-author-result.json` | `ca51d31b45590f472d81a58fc506afe776e04171c6f3ba36a92b3261abe45e1c` |
| `driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r15-offline-controls.txt` | `145edd7d3dde1b897a6a210e4e7a27c7eabb59dcd65815e655928f7314e18daf` |
| `driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r15-root-review-disposition.json` | `c690a5b7a5ac3afc5f56bba94123bb890e86afaeae1cf4684cf74fd29328f220` |
| `driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r16-author-note.md` | `c56721e0f63ccd57193608531f9ed4317052c8ea4bf52f9d192d447913b80b97` |
| `driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r16-author-result.json` | `ccf6a8490b8a27edf77bff8839bd80f537d8e57fccbee25fd58bcd56d603962d` |
| `driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r16-offline-controls.txt` | `b84e98b50162bdcb0ce271af441ac4c8ead48ec27f9289fc257f29507f9fba5f` |
| `driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r18-dual-handle-design.md` | `69e47c0b091b0d236c535e4e19d2b18815806614d45cbf668ccc4bf54e7a9044` |
| `driver/evidence/2026-10-11/m2-t5-notepad-coordinator-r14-root-review-capture.json` | `cf0231084dab2b7cb1e36c3e041fa7bb6206e9c3faa4a47b126c9705e324efb0` |
| `driver/evidence/2026-10-11/m2-t5-notepad-coordinator-r14-root-review-disposition.json` | `386b2dcb492ad66835fcac15a3d2552ef33345149b99accd1f3d52331b215d51` |
| `driver/scripts/Build-ExactAgent.ps1` | `eb9be83ed99aa0057b00f160419e8c123bc2b4a79991c894086de86571ad2e52` |
| `driver/scripts/Build-ExactAgentMatrix.ps1` | `90aebd88352c4c23265508a244437895d0a84218bc7815d031de7e81bec45ac7` |
| `driver/scripts/HarnessWindowsGate.manifest.json` | `7d5ea90a1cf1c941610572f038a9db8ff43b5c934e41a0adbf3f54bbd98d11f7` |
| `driver/scripts/HarnessWindowsGateClient.py` | `d5f558bc6c7435a0e8f6628ae2fffc465b34ed0981d1470d90de44980f4975c8` |
| `driver/scripts/HarnessWindowsGateLeaseKeeper.ps1` | `aa24884d0f943ff0e97bc37132f5fe4a9f2c595166a7a7b9515198abc2606fa2` |
| `driver/scripts/HarnessWindowsGateLifecycleFixture.ps1` | `599eb7da9e0177b2443d5edd937a15b29c72b0357e5c4b71a3c2397b62fb1489` |
| `driver/scripts/HarnessWindowsGateManifest.py` | `a7cebdf3eb20fe1ab8df9976721a648725a526b5c39a584fb721a59658f2a6c8` |
| `driver/scripts/HarnessWindowsGateProtocol.psm1` | `9fb561090d9e1f7a4370b7cb4c8369001ca69e06e4f406c4f072480f7a0ebacf` |
| `driver/scripts/HarnessWindowsGateRemote.ps1` | `6e1765e52ed051a493f55826f066d3fc050bcbe75edef783bd4c555a84eb5918` |
| `driver/scripts/HarnessWindowsGateRemoteControl.ps1` | `48a16decedec44e7c529ee2df099f9dbde1f2b69ef33d23d95fc58cd2b3b3caa` |
| `driver/scripts/HarnessWindowsGateWorker.ps1` | `8826d5f39295be32b1a2782ff2aaf378a1871b71260c707a810ba0ee5fba2731` |
| `driver/scripts/Invoke-HarnessWindowsGate.sh` | `dd3ba8816cc14ba632ac5509b00948641f16609b9e4195f03ab6eeeee634dfda` |
| `driver/scripts/StagedInvariantActivationDuplicate.SelfCheck.ps1` | `56f10e03983bb996d851584c6604554fee1762c115535a4d2ed005ca50ea15e8` |
| `driver/scripts/StagedInvariantBlockWindow.SelfCheck.ps1` | `4f25dde8342906dce67227fec8fcd154b1f4793377c18f0be262cc15d828f893` |
| `driver/scripts/StagedInvariantCases.psd1` | `c7c91697b77b278c3f4f0aec627cfcb1b3b86e06b9d05b81d4616d00062af7b6` |
| `driver/scripts/StagedInvariantCoreVariants.SelfCheck.ps1` | `5a2c2e365a20e566eb1fb395cc3df537cc630d9b28dbd545fd1098421ba9c990` |
| `driver/scripts/StagedInvariantDeniedRenameLatency.SelfCheck.ps1` | `9d55ec0ae3ad55ffab0cf1c992715f6e903dea43c1820b71cdcbea334ecb6fb5` |
| `driver/scripts/StagedInvariantLatency.SelfCheck.ps1` | `344e33acf1036757b2c5284e67179d26b96681a5b4bf19c6609ad5c9600f9c86` |
| `driver/scripts/StagedInvariantLatencyLite.SelfCheck.ps1` | `a91b37beb4f5d137d604f4bbdab928a68c72b72b5e8d527ee6c3f698d595dc1e` |
| `driver/scripts/StagedInvariantLiveTaint.SelfCheck.ps1` | `967b8e791bc9c26a4e992cd33582519556e251d10690bb3f48deb8eb0530017d` |
| `driver/scripts/StagedInvariantObserver.SelfCheck.ps1` | `8cd16c071114d2e2d93cf1594ae27b61f6d7672c45d73cb42bbe7fa850de49e1` |
| `driver/scripts/StagedInvariantObserver.psm1` | `48577d312b66287f432b75e0ee61cca787a30f6e3632a1d2912085cc32070bc8` |
| `driver/scripts/StagedInvariantProofAdapters.SelfCheck.ps1` | `2dd78b9dcd6f21ab0220c983ca1924b1440c26fc9670bc3ef927ce5ea227e764` |
| `driver/scripts/StagedInvariantR03.SelfCheck.ps1` | `91620bc811b38a8ef0e26e7f41c459eea61a9b0d8d66019fdb584b9cf644e40e` |
| `driver/scripts/StagedInvariantRestartJustification.SelfCheck.ps1` | `6418ed356b1bcb80b24c449da431069ba7d30a9db26489c43789726c7a9e9715` |
| `driver/scripts/StagedInvariantRobustness.SelfCheck.ps1` | `d3ea4d476a766a8f0dc5d9b70713eb3c671b81c770472c836c3aaee21739d41e` |
| `driver/scripts/StagedInvariantRowsA.SelfCheck.ps1` | `d23d22e48e24433a94b98b8789bacd1e548ccf516dbbb3e80d8c1b2c2070033b` |
| `driver/scripts/StagedInvariantT4Ipc.SelfCheck.ps1` | `af41aa53f16390f023911d519c9493f15658274c1381aef6532c4dcf48b45513` |
| `driver/scripts/StagedInvariantT4Runtime.SelfCheck.ps1` | `0e6598eb65c44e8c4e5aeac97f92c5b28fdd2de648c0ff4284ee6962069e712d` |
| `driver/scripts/StagedInvariantT4Verifier.SelfCheck.ps1` | `a0282ae55b388dc19db5e3976d773faeb06992026b0ade17cebf9d118454f02c` |
| `driver/scripts/StagedInvariantTraceWindow.SelfCheck.ps1` | `b1911961ad0ed225c6ba2ae02a19d5de08256aa6c326981c1fd8afd65c54844d` |
| `driver/scripts/Test-StagedInvariantSuite.ps1` | `773bc9348b374f52dee78c06ee69d7144b7b16a8aa6c03ba3b5ee50ae4e0a672` |
| `driver/scripts/remote_ps.py` | `39ed7a7892555d61b1577380fd84888ab39278a0115a7ca9b47b16ca6c52995b` |
| `driver/scripts/t10/permissions-actor.ps1` | `208ebd1639f30bd61ca9fab1e8bb2a98bfdd874f1c9ecaaa42dc0cbf7a1d9cc6` |
| `driver/scripts/t10/permissions-coordinator.ps1` | `d916c2d18a9da5e50441c164df61d19ba772bf7289fa42062592bb6b487cbe48` |
| `driver/scripts/t4/cycles-actor.ps1` | `7338124c4da1c44025f93cbfc754e6a002ba09e39bb68a045a5fea25f0af04e9` |
| `driver/scripts/t4/cycles-coordinator.ps1` | `e7b5349888eeaeefd7dfc09fd92e23447ba142fb70a67892ee3a9c3c4ff7c677` |
| `driver/scripts/t4/cycles-progress.ps1` | `dfa5d200c5778d3025ed57e8440b400d0bff5e6c8de4781f22435e691aafaf6b` |
| `driver/scripts/t4/runtime-verifier.ps1` | `04dfbfad81daf4c3b8d613f068d88e05adbb73c10bd2e1376de8c69f8a9148c1` |
| `driver/scripts/t5/notepad-actor.ps1` | `fe85a4259a8fa1da10db3b7be7a684ffccffee107491bf02442f95ae75c1ce11` |
| `driver/scripts/t5/notepad-coordinator.SelfCheck.ps1` | `dbc00a84c456b97f6903cfcb4ccc0ba37c5ff763fc6b67e83aab3e86e807245f` |
| `driver/scripts/t5/notepad-coordinator.ps1` | `c21757ed59acd607138be5eaafbdbcd2192dd48dd840c80563cb5b21f22d291d` |
| `driver/scripts/t6/moves-actor.ps1` | `22d427bd811c2bf396d45f8d65a1c3ef197d6fa6428b9630aef367bde138857a` |
| `driver/scripts/t6/moves-coordinator.ps1` | `5218b675460f540ac1ef077a0112ec018b5000e73dff8f54d7adbd729f94df3d` |
| `output/review-candidates/m2-t5-harness-windows-gate-r15-1011-a1/source-capture.json` | `e7df89326202d432b9f1846368e3716bb27d207926dc07267dbdbadb293aa4c8` |
| `output/review-candidates/m2-t5-harness-windows-gate-r16-1011-a1/source-capture.json` | `0cce292047acb14c0f00b62acc1efc998b59d743441e118c2f4d4debdce765e0` |

## Frozen R19 author and context pins

| Scope/path | SHA-256 |
|---|---|
| `author/author-design.md` | `65317fc497f2454fae7a7ddf65d08440a62a295cbc65ce431239fa9a99db682c` |
| `author/author-note.md` | `924a89565968b0ff0b9d1c1f1bcef669d9205d9250c08b9876ddb187ef22f66b` |
| `author/author-result.json` | `53697ae75fe2c407689277e1a4504f9814b7391a58fe6c69bd3082a9639ba22e` |
| `author/offline-controls.txt` | `c08e09ffa1bd9fdb4454276c2462910b1abbb624d5b6862354ef909aef50bf78` |
| `author/offline-r19-controls.py` | `f0435269655758868ac3ae865e0dd704996421941d1fce4674fa6611374c0a9b` |
| `author/r18-source-capture-baseline.json` | `d74f348f192e697b70a169af9c5e75fb0ad09e87b6d9ffe7bcb93b514203f14a` |
| `author/source-capture.json` | `4ce3bc6cc05f27228dcbda5ecf4a5eac99da8ef9e27c4fcc187c8bcb73b2624a` |
| `context/driver/evidence/2026-10-11/luna-t5-harness-windows-gate-r18-independent-review.md` | `8d2eb7dcf8af5d4e8533a00b789b4f03679541aaeb399422906da0f17077e3fb` |
| `context/driver/evidence/2026-10-11/m2-t5-harness-r18-compiler-a1-root-result.json` | `4644cd10ae76f5832729120e26d295df582f8400f924a7361947ccd23537469f` |
| `context/driver/evidence/2026-10-11/m2-t5-harness-r18-native-compiler-a2-root-result.json` | `232e34c36550ab0d8c807b34c8e4489d2296a2f1c283919ae7f9ed9ea89b2cc8` |
| `context/driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r18-dual-handle-root-design-a1.json` | `e268773b15ae2832e6e8b4020d7bb44d1d06ac58c9442a62a323a57117c50227` |
| `context/driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r18-root-review-capture.json` | `4da629bbdc11533484c4a2ed0b2aebfe587f47f2518d5b23c5727d369f81c100` |
| `context/driver/evidence/2026-10-11/m2-t5-harness-windows-gate-r18-root-review-disposition.json` | `b545b9211ad6b4f4bfba6c41b1fa019ed17fb6b29b4c2aa757aaa731b856c130` |

## Root compiler raw-output hashes

| Artifact | SHA-256 |
|---|---|
| Compiler helper | `308a12fa669dd10faec4bc777804b4a6f9f85a0e2d95d5b3d65199be3c97f550` |
| Embedded C# input | `5e32aa317f7c30abf10dc350050afeb530a04f0c35bce8b735995d7fc815e7e0` |
| Compiled diagnostic assembly | `c3897154910d3a6bc3edc371d87468d3f37778021639584b74dd9a27c0109ace` |
| `m2-t5-harness-r19-compiler-a1-compile.stderr.txt` | `aa4c6b5187e8a52a4b02316c91eb0c7a4cfdce4cdea9b9d7ecfe2faa1d97cce4` |
| `m2-t5-harness-r19-compiler-a1-compile.stdout.txt` | `5fee3c122fd2b599d89d303cd184a9b09bf6054d59d1b061bf5a06bdb0683987` |
| `m2-t5-harness-r19-compiler-a1-delivery.stderr.txt` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `m2-t5-harness-r19-compiler-a1-delivery.stdout.txt` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `m2-t5-harness-r19-compiler-a1-preflight.stderr.txt` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `m2-t5-harness-r19-compiler-a1-preflight.stdout.txt` | `31591cd0e0b0a8fb80d9d103361a1d0ef1793a706f492f4407678dd64f366b05` |
