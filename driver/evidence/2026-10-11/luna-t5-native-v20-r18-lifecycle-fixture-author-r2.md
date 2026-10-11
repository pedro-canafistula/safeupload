# T5 lifecycle fixture R2 author correction record (source-only)

Date: 2026-10-11  
Scope: narrow corrections to the additive R18 user-mode lifecycle fixture after independent R1 review. Only the lifecycle fixture script changed; the helper, native source, other existing fixtures, R1 candidate, and R1 reports remain immutable. No fixture or helper was executed, and no Windows, VM, driver installation/load, host policy, network, or Git action was performed.

## Disposition

R2 closes the three R1 source findings: `fltmc` failures no longer mean filter absence; temporary recovery material is removed only after all independent restoration checks pass; and SCM command response, sequential status samples, and final `STOPPED` status are recorded separately. The raw op17 ACK remains explicitly unobserved, with no claim inferred from the durable epoch receipt or filter disappearance. The aggregate result remains `INCONCLUSIVE` under the R1 fixture policy pending a separate scope disposition; this note does not assert that raw-frame observation is an owner cutover requirement.

This is an author freeze for independent review, not source acceptance or runtime qualification. The root R18 receipt remains `RuntimeQualified=false`, `PairQualified=false`, and `CutoverAuthorized=false`. Taint stays in place, unsupported capabilities remain disabled, normal builds keep staging compiled out, and unapproved bytes remain private.

## Exact inputs and closure

The active owner objective attachment `pasted-text-1.txt` is SHA-256 `a982e6762ab1e18664509339c40a333eb7a0fab4b0794dd83c0630a7a7f1232d`. The frozen R18 root capture `m2-t5-driver-wire-v20-r18-root-review-capture.json` is SHA-256 `f47075cfce996c87b7a51c8080621b47bdc7bc731ff3cb4dc02dc6d055e17c2d`; the accepted source receipt `m2-t5-driver-wire-v20-r18-root-source-acceptance-a1.json` is SHA-256 `9e0ae87e8b17712a1f8967ccae0561cb29e21344c03c221e66622a869604492b`; the four-profile build/signer result `m2-t5-native-v20-r18-diag-a1-root-result.json` is SHA-256 `ca42ee32bac179561992defc0c860e63f6aead038ab739544be527a138cf8646`; and the root readiness readback `m2-t5-native-v20-r18-runtime-readiness-root-readback-a1.json` is SHA-256 `23b9270a0bcaf23cba033d7b92ed7bd26827a03e7a77e8d2343aa19c1cf869df`.

The R1 independent report is SHA-256 `11454ba7717c087c3c79bc3810cda49ced46f5f26b7f0d8e3991802579438bf8`; the immutable R1 readiness note is SHA-256 `d08ce66165588ee9ee9202488bc84ed8e0f8d68327927fdcda9f3ceacf4e7ee5`; its root PowerShell 5.1 parse-only receipt is SHA-256 `2377e1eef14e0c174aacfdac2cc48a486d1984613d7710f4c29efa36062bb7d3`. R1's frozen fixture remains SHA-256 `d96f40d1563df2c8c48c57d03fd49199fd580f7a96fac04ed8994a74468d4378` and the pinned helper remains SHA-256 `abd9c67925a4a18b4635bb4b1d21b35cd033453d6ca0c03acf46246472aa6dd7`. The exact R1-to-R2 fixture delta is `luna-t5-native-v20-r18-lifecycle-fixture-r2-r1-delta.diff`, SHA-256 `97196a31452eed114b87fbeee710f000858ff58b7d7a14c9d4cbb1efad4e94e1`.

The R2 candidate is `output/review-candidates/m2-t5-lifecycle-fixture-r2-luna-a1/src`. Its exact inventory is two files:

| Candidate path | SHA-256 | Disposition |
|---|---|---|
| `driver/scripts/Test-StagedMinifilterUnloadLifecycle.ps1` | `b1bbe99ddb3a7bed2593e397675531d8a8c3c5684373d3be11225a607a089abf` | Changed from R1; exact same bytes as the live authoring path at freeze. |
| `driver/scripts/StagedTestAgent.ps1` | `abd9c67925a4a18b4635bb4b1d21b35cd033453d6ca0c03acf46246472aa6dd7` | Unchanged pinned helper. |

The only changed existing path is `driver/scripts/Test-StagedMinifilterUnloadLifecycle.ps1`, R1 `d96f40d1563df2c8c48c57d03fd49199fd580f7a96fac04ed8994a74468d4378` to R2 `b1bbe99ddb3a7bed2593e397675531d8a8c3c5684373d3be11225a607a089abf`. The R2 delta and candidate preserve the original R1 source separately.

All 26 R18 native source paths below were read with stable no-follow checks from both the live tree and the frozen root candidate and matched the immutable R18 readiness pins at 26/26. R2 changed no native input.

| Frozen R18 native path | SHA-256 |
|---|---|
| `agente/SafeUpload.Agent.Minifilter/FilterPort.cs` | `f752d17cc002d6865850739dac232e3128156efe8b2177308915e419ce6f71f2` |
| `agente/SafeUpload.Agent.Minifilter/Protocol.cs` | `865120edcaa5ec9dad587e5223e221f2ae93597e68990ac32b261bcbc4c60222` |
| `driver/SafeUpload.Minifilter/BootPolicy.c` | `47ed57eb10e339bc912d6774429820a0a4122e72c963fef12e88dd05edd1536c` |
| `driver/SafeUpload.Minifilter/Communication.c` | `f0b0e585f421182850ca29536d22ada4f35b8d4c4e3dff3546508b5f9d186ab3` |
| `driver/SafeUpload.Minifilter/Context.c` | `76b5a00f06d9f6f136194a729c0e67feee847ad9d0bb58afab08bc9f85d794cf` |
| `driver/SafeUpload.Minifilter/DenyRing.c` | `8864cae294552e5f3bf16f6c2b158fa32a05521cfc3748ff1804767fa38d582b` |
| `driver/SafeUpload.Minifilter/Filter.c` | `46224c3b8a72da759395a15742ad4e3ec3de4f2fe5b1e20ba48fa612229a20cd` |
| `driver/SafeUpload.Minifilter/Filter.h` | `9a3c699d3bbff053cf85bf3b5be6008414c1ece9377e3c6f702472daeda9168f` |
| `driver/SafeUpload.Minifilter/Override.c` | `babbf6aed51162156b3bec6db523b38bb1725c1885c9bb5d8e7bd7ad087c5b87` |
| `driver/SafeUpload.Minifilter/Policy.c` | `855a36fc5a296f9cadf72a9dfc1b3e5b86c1b35d7c65b6aabc8c86c073d5e203` |
| `driver/SafeUpload.Minifilter/Protocol.h` | `d36e22d05087b708f51410d4436ced8353af72ca7245a57e1eb1ae4c064d72cb` |
| `driver/SafeUpload.Minifilter/SafeUpload.Minifilter.vcxproj` | `69d419d6101e4028008d9eecf375fa4b74bee46988303b877a63d1c2f43cca53` |
| `driver/SafeUpload.Minifilter/SafeUpload.inf` | `b6f0400e7751f9d70cb03a3ffcd9c53c976bdca155451e41e2bc779741486f1d` |
| `driver/SafeUpload.Minifilter/SafeUpload.rc` | `7b29c6cd59a4fee84a98f8cd63f4a4b9a1daab4ce00f69f78b6f8861f1355eeb` |
| `driver/SafeUpload.Minifilter/Stage.h` | `607621ace06ce2b0195309c799a80d5347796cbaa0067bdae01ef2080f0d8aad` |
| `driver/SafeUpload.Minifilter/StageAdmission.c` | `1ba12eff7a0a3d87b206bfe3f835e8e50a21cb54b6574abb60f0ba7ba71a312a` |
| `driver/SafeUpload.Minifilter/StageAlias.c` | `6d90dd60c0d7f3403410f55337ed662130322a825bd9d1cebed964a4653c5895` |
| `driver/SafeUpload.Minifilter/StageDirectory.c` | `2e7085bf0f28267169a78a6cfb4355e3dcc82be3b794359ee960c0dd82276bf1` |
| `driver/SafeUpload.Minifilter/StageFence.c` | `5e9cb09e0df04445b9911f0db6382603b36c957a799f024169c59c1ab981ce90` |
| `driver/SafeUpload.Minifilter/StageProtocol.c` | `80068f5115428300e19bd025c95cbafeb843bde38db0f36b2f8af3d5d4457072` |
| `driver/SafeUpload.Minifilter/StageSecurity.c` | `51c3c8383ccf692d254a4112bb08f9323df392d26a6a85f1caf8bc6013eb926a` |
| `driver/SafeUpload.Minifilter/StageSecurity.h` | `f384df8f53313cebf72a91a7fa070c4ff4159f536de4250c4986020e32871d38` |
| `driver/SafeUpload.Minifilter/StageStream.c` | `6967314cba4a6a593325575d0102ece591d038fe42780b55e30e4922c4925475` |
| `driver/SafeUpload.Minifilter/StageWriters.c` | `a1acfe1f506d88c0af22563bff0c7d4a8f7261de8fa7b99586279e183c044ef3` |
| `driver/SafeUpload.Minifilter/Taint.c` | `a6c6391a95861a047510855800c4deba0018c2a540387235b9a16e54fcee3f6d` |
| `driver/SafeUpload.Minifilter/Txf.c` | `7b37ff95704e985bc22b7c89da1d103228bd29bd66233c5e55e47b61037ef1a1` |

## Corrections made

`Get-FilterStateFromCapture` now returns `PRESENT` or `ABSENT` only when `fltmc filters` exits successfully and emits a recognizable filter table. A failed or unrecognizable query throws as `UNKNOWN`. `Test-FilterLoaded` uses that tri-state boundary; `Write-FilterSnapshot` checks successful filter and instance queries before summarizing them; `Test-FilterAttached` rejects failed or empty `fltmc instances` output. In the finalizer, both `PRESENT` and `UNKNOWN` preserve the installed image, backup, package, and mounted fixture. Before a driver restore, the fixture queries again and proceeds only on known `ABSENT`; it checks the original driver hash and known filter absence after restoration.

Restoration now has separate success flags for the agent service baseline, observer completion, original driver bytes/filter absence, Verifier idle baseline, driver service configuration, inspector status-task removal, private stage/journal cleanup, and volume detach. It checks the exit code when verifying the Verifier baseline. Temporary service package, backup, image, and diskpart files are deleted only if every restoration flag passes. Any `PRESENT`/`UNKNOWN` state or failed restoration check keeps recovery material and prevents successful exit. Observer failure remains sticky `FAIL` for its existing leak/exit-2 cases and otherwise makes the run inconclusive.

SCM evidence now avoids implying atomicity between process response and neighboring status/filter samples. `sc.exe` process exit is an accepted-command observation; `sc query` and `fltmc` results are separate timestamped captures. Stop progress is labeled as a sequential correlation. The mandatory final-service subcase is `OBSERVED` only after a successful query exit and parsed `STATE=1` (`STOPPED`); otherwise the subcase is `INCONCLUSIVE`.

The event is now `ExactOp17WireAckObservation` and explicitly says the raw request/ACK frame is unavailable and no claim is made. The durable instance/request/nonce receipt remains correlated evidence, never represented as a wire ACK. The R2 aggregate remains inconclusive pending the separate scope decision; R2 does not add instrumentation or change the protocol.

## Source-only controls and limits

A custom lexical pass over the 1,125-line R2 fixture verified balanced delimiters, strings, comments, and here-string closure. Focused source checks verified fail-closed filter queries, the pre-restore guard, post-restore absence check, all-restoration cleanup gate, successful final `STOPPED` query requirement, separate SCM evidence labels, and the absence of “required op17 subcase” wording. Stable no-follow audits confirmed the live R2 script equals its frozen candidate; the helper equals R1; all 26 live/frozen R18 source pins match; and the R1 fixture, helper, report, readiness note, and parser receipt pins are unchanged.

This author did not run Windows PowerShell, `fltmc`, SCM, Verifier, the observer, the helper, the fixture, or any native build. The lexical pass is not a PowerShell parser or execution result. Root may run its parse-only check against this exact candidate. The observer still samples sequentially every 40 ms and accepts the exact hash after the allowlist update; it cannot establish a continuous-byte or exact-close-boundary guarantee. Startup failure inside a failing `FltStartFiltering` call, stale disconnect completing after a newer generation, exact raw op17 ACK, and callback/worker overlap at unregister remain unqualified. Manual detach exit 5 remains unqualified or a negative expectation, never a pass. Every actual VM run still needs independent destination observation and separately enforced restoration.
