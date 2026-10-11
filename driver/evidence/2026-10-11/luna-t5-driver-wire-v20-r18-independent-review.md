# SafeUpload native v20 R18 independent source and diagnostic review

**Review date:** 2026-10-11 UTC  
**Reviewer:** different-author independent review; not the R18 implementation author  
**Frozen source:** `m2-t5-driver-wire-v20-r18-root-a1`  
**Diagnostic:** `m2-t5-native-v20-r18-diag-1011-a1`

## Disposition

**NO-GO for source acceptance pending resolution of the communication-callback source/code-image boundary.** The source review finds R18 materially corrects the R17 startup and mandatory-unload ordering defects, and I found no source change that weakens the existing staging scope, privacy, policy, taint, or protocol gates. The generic Microsoft callback-unregistration wording gives a credible architectural basis for treating the three communication-port callbacks as filter callbacks, but the callback-specific removal and post-return image-lifetime guarantee is still an explicit interpretation. Local callback counts, `EX_RUNDOWN_REF`, and `FltObjectReference` protect active callback state and filter-object references; they do not establish that Filter Manager cannot dispatch a registered callback pointer after the image’s source boundary. This is a source-acceptance blocker until the architecture contract is explicitly resolved.

**Compiler/signing diagnostic: PASS_COMPILER_AND_SIGNER_ONLY.** The terminal result is zero exit, all four driver profiles have zero warnings/errors, ApiValidator and PREfast pass in every profile, both inspector profiles and the writer fixture compile cleanly, and the expected local test signer validates. This does not accept the source, qualify Windows runtime behavior, qualify a matched pair, or authorize cutover. **Runtime/Windows disposition: NO-GO / NOT RUN.** Nothing in this review was installed or loaded in a product VM.

## Evidence chain and exact source closure

I read the owner objective before reviewing. It keeps all taint and unsupported capabilities in place until the owner approves cutover; the normal build must compile staging out. The objective’s definition of done still includes the agent matrix, both mapping-leak reproductions, USB including surprise removal, UNC/SMB, real sync-client tests with independent destination observers, crash/recovery/Verifier/stress/latency, VM restoration, and owner-authored plan/sign-off. Those runtime and owner gates remain open.

I rehashed the root-owned 26-input capture, the full author freeze note, the complete 882-line R17-to-R18 delta, and every `VerifiedContextHashes` entry. The capture’s exact closed inventory is 26/26, all source pins match, and the five changed paths match the capture: `Communication.c`, `Filter.c`, `Filter.h`, `Stage.h`, and `StageStream.c`. `StageProtocol.c`, `StageFence.c`, and the managed wire inputs are unchanged. The root capture records an exact regenerated delta; this review independently checked the frozen byte pins and inventory rather than claiming to have regenerated the root’s diff algorithm output.

| Evidence | SHA-256 |
|---|---|
| Root 26-input capture, `m2-t5-driver-wire-v20-r18-root-review-capture.json` | `f47075cfce996c87b7a51c8080621b47bdc7bc731ff3cb4dc02dc6d055e17c2d` |
| Full R18 author freeze note | `d91d2e4a852ee2707492f76e8fc0c91c24dce6982f3527a52fb9365ed239420d` |
| Full 882-line R18 delta | `2dade2dc2367263f892d475ba046802d56c1b2aee2de23de0c1c83734776d434` |
| Prior R17 different-author report | `55362d4323875ef1b41571a9462df230749b35f0b53c0a2def36281a68e42720` |
| Prior R17 root disposition | `3ea9e496622d3525b016c31f5dd166978feb83817f9cc5d89dc4d6627abbfb16` |
| R18 root design disposition | `e7f77435aa87ef9f14522ecb6ec7236c5b48b8a28ed94281c101c5442b163dd6` |
| R18 root ordering design addendum | `55862e7e08202d8a603f3c95ce45a66e2d1fd91ec148a44bd6318fca70ebfea3` |
| R18 rollback draft observation | `a1f6870f84cfb831d47c3da1c4459e9ec7ddd7d647f4258f77c6c47eb3deacd7` |

The eight context inputs were also individually rehashed against the root capture:

| Context path | SHA-256 |
|---|---|
| `driver/evidence/2026-10-11/luna-t5-driver-wire-v20-r17-independent-review.md` | `55362d4323875ef1b41571a9462df230749b35f0b53c0a2def36281a68e42720` |
| `driver/evidence/2026-10-11/luna-t5-native-v20-r18-r17-delta.diff` | `2dade2dc2367263f892d475ba046802d56c1b2aee2de23de0c1c83734776d434` |
| `driver/evidence/2026-10-11/m2-t5-driver-wire-v20-r17-root-review-capture.json` | `457f3481b4969fa92671b322cb1e1a53d6af7015c842177dfc555a20383ce96e` |
| `driver/evidence/2026-10-11/m2-t5-driver-wire-v20-r17-root-review-disposition.json` | `3ea9e496622d3525b016c31f5dd166978feb83817f9cc5d89dc4d6627abbfb16` |
| `driver/evidence/2026-10-11/m2-t5-driver-wire-v20-r17-voluntary-veto-order-root-observation.json` | `442aeff09586e62222d40ac040be5e1487690ba0942871f9487f7080c6ef15db` |
| `driver/evidence/2026-10-11/m2-t5-driver-wire-v20-r18-rollback-draft-a1-root-observation.json` | `a1f6870f84cfb831d47c3da1c4459e9ec7ddd7d647f4258f77c6c47eb3deacd7` |
| `driver/evidence/2026-10-11/m2-t5-driver-wire-v20-r18-root-design-disposition.json` | `e7f77435aa87ef9f14522ecb6ec7236c5b48b8a28ed94281c101c5442b163dd6` |
| `driver/evidence/2026-10-11/m2-t5-driver-wire-v20-r18-root-ordering-design-addendum.json` | `55862e7e08202d8a603f3c95ce45a66e2d1fd91ec148a44bd6318fca70ebfea3` |

All 26 frozen source paths and hashes follow. Each was recomputed from the immutable root candidate and matched the capture.

| Frozen source path (relative to candidate `src/`) | SHA-256 |
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

## Source findings

### R18 closes the R17 startup ownership cycle at source level

Microsoft documents that Filter Manager can present I/O and volume notifications before `FltStartFiltering` returns and requires failed startup to unregister the filter ([Initiating Filtering](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/initiating-filtering)). R18 starts with `StageFilteringReady == 0` (`StageStream.c:6778`) and `SafeUploadStageDispatch` rejects every staging `IRP_MJ_CREATE` before epoch admission, writer reservation, or stream creation until the successful return (`StageStream.c:8836-8855`; `Filter.c:329-344`). The failed-start path closes and drains communication, joins workers, releases instance references, unregisters, then frees state (`Filter.c:350-387`). This directly addresses the R17 path in which a callback delivered during a failed `FltStartFiltering` could create stage ownership before the function returned. Runtime still needs to exercise canary and failed-start paths.

### Callback-body admission and outbound service admission are distinct

`SafeUploadTryStageCallbackUnloadPreflight` sets only `SafeUploadStageCallbackAdmissionClosed` while holding the transition lock/state spin lock and waits for current control callbacks with the transition lock dropped (`Communication.c:713-764`). The same path explicitly leaves channel-use admission and `FilterReplyMessage` available. `SafeUploadControlCallbackEnter` checks the stage gate only for `NewWorkCallback`; Connect/Message are denied before their internal bodies, while Disconnect enters cleanup and retires only its cookie (`Communication.c:953-1015, 1287-1316, 1450-1468`). Thus the service channel remains available for mandatory cleanup ACKs and epoch drain while new Connect/Message bodies cannot mutate staged state. A callback counter reaching zero is only a momentary body-quiescence observation: a later denied callback may still enter the wrapper, and this count is expressly not a callback-source-removal proof.

### Rollback is conditional and preserves monotonic failure state

The reversible `StageRollbackUnloadPreparation` calls fence cancel, clears unload-owned `StageStopping` and `StageUnloadPrepareWork` under `StageNamespaceResource`, then reopens the isolated unload attach gate and wakes the worker (`StageStream.c:6964-6979`). It does not restore `StageAttachAccepting` or clear `StageAttachStopping`; sticky allocation failure and worker-stop denial remain sticky. `StageAttachQueueCreate` checks those sticky flags and the separately serialized unload gate before publishing active ownership (`StageStream.c:3194-3204`).

There are three explicit voluntary pre-quarantine rollback callsites: callback-preflight failure, fence-preparation failure, and the final local scan’s `Veto` path (`StageStream.c:7022-7035, 7038-7052, 7313-7336`). Each runs the narrow stage rollback and then `SafeUploadOpenStageCallbackUnloadAdmission`, whose transition-lock wrapper refuses to reopen after connection close has committed (`Communication.c:724-774`). These are the only paths that restore the reversible pre-unload state.

If preparation is mandatory or the state is already quarantined, the callback gate may reopen so the service can reconnect and retry, but R18 retains `StageStopping`, the attach fence, required worker eligibility, the listener, and instance ownership. Failures after cleanup/quarantine can commit—drain nonce creation, exact epoch-drain exchange, or fence commit—are monotonic: they set quarantine/work state, open callback bodies only for reconnect/retry, and veto without resetting stage/attach fences (`StageStream.c:7250-7304`). A successful stage prepare does not reopen Connect/Message bodies.

### Final scan and exact drain ordering

The unload gate closes CREATE/attach admission before the scan (`StageStream.c:7005-7014`), then callback-body admission is closed and its current users are drained before fence and ownership inspection (`StageStream.c:7016-7022`). Under `StageNamespaceResource`, the final scan rejects pending reconcile or invalid protocol/drain replay state, active attach work, reserved streams and global or per-stream FILE_OBJECTs, rename exchange/RPC, cleanup/discard/seal/handle-receipt/allocation-recovery state, allocation-receipt references, per-stream RPC references, private delete reservation, unsealed/unretired objects, and `StageDrain` failures. It queues exact retained cleanup/replay work where appropriate and will not cross commit while unrelated work or ownership remains (`StageStream.c:7054-7178`). If cleanup must first reach the service, it quarantines and retries with the worker and service path alive (`StageStream.c:7180-7221`). `StageWorkerHasPendingWork` checks queued streams, sweep, process-exit ring/overflow, retry-fired state, and delayed exit sweep (`StageStream.c:384-395`); any such work vetoes.

Only after those checks does the worker-pass gate become false under `NamespaceResource`; this serializes against a worker already collecting local release/RPC batches. The final scan then rechecks global file-object state before leaving the resource (`StageStream.c:7223-7248`). An already-collected worker-local batch is not assumed empty by the scan: FilterUnload drains channel use, joins both stage workers (including local release, discard/seal/rename/recovery/receipt batches), then releases paging rundown/backing handles and instance refs (`StageStream.c:6511-6575, 6577-6662, 6886-6934, 7340-7362`; `Filter.c:521-557`).

The epoch drain carries a retained exact request ID/nonce. Before each send, channel cookie/generation is pinned; after the reply, it is revalidated. A disconnect/reset before validation fails the attempt and retains replay state; stale cookies cannot reset a replacement generation (`StageProtocol.c:450-579, 581-600`; `StageStream.c:7250-7292`). After exact DRAINED, a later disconnect may set reconciliation state but cannot start a new worker pass or admit staged CREATEs. R18 does not claim that epoch drain can be retried through an already DRAINED service fence: failed pre-DRAINED requests replay the exact same id/nonce; failed fence commit remains latched for a later unload retry; success proceeds forward.

There is no reversible feature veto after that commit. Feature `FilterUnload` calls stage prepare first and may return a voluntary veto only if preparation fails before success. It then commits the fence and closes ports; close-helper busy results are followed by safe waits and retries instead of a `DO_NOT_DETACH` return that would leave a live filter with closed ports (`Filter.c:480-531`). Normal builds retain the original reversible connected-client and full communication preflight veto path (`Filter.c:448-457, 501-515`). Mandatory retries re-run exact preparation every 250 ms while preserving service and worker availability; the delay only paces retries and does not prove owner release or quiescence (`Filter.c:489-498`). This can wait without bound for external FILE_OBJECT owners or service availability, a documented operational consequence rather than forced release or a timeout-based safety claim.

### Teardown and separate process-notify lifetime

After port close, channel rundown drains sends; then R18 joins workers, waits paging rundown, closes backing handles, and releases each stream’s `BackingInstance` and `OriginalInstance` references before `FltUnregisterFilter` (`Filter.c:521-564`; `StageStream.c:7340-7362`). This is the needed correction for the R17 self-dependency where unregister could wait on instance refs that the same unload callback would release only afterward. Filter, callback state, stage state, policy and taint state remain resident through unregister and communication-callback EX rundown. `StageFree` runs after unregister; policy/taint/overrides are released last (`Filter.c:557-578`; `StageStream.c:7368-7394`). Filter Manager documents that unregister invokes instance teardown callbacks and waits for outstanding opaque-filter references ([Unregistering the Minifilter](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/unregistering-the-minifilter), [FltUnregisterFilter](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltunregisterfilter)). Late instance teardown is a separate callback path: it publishes a teardown tombstone, cancels any matching attach transaction, and its completion removes the tombstone (`Filter.c:735-754`; `StageStream.c:3320-3386`). Runtime must still test dismount/removal races around worker stop and unregister.

Process-notify source lifetime is separate from port callback lifetime. `SafeUploadStageFree` sets `StageInitialized = FALSE` while holding `StageListLock`, drains referenced process objects, then frees stage lists (`StageStream.c:7370-7394`); the process-exit handler rechecks initialization under the same list lock before queuing into the exit ring (`StageStream.c:6735-6757`). Later `SafeUploadFreeTaint` removes the `PsSetCreateProcessNotifyRoutine` registration before deleting the taint lock/table (`Taint.c:185-230`). This guards a distinct callback source and does not prove the Filter Manager communication callback source contract.

### Callback-source/code-image contract remains the source blocker

Microsoft’s communication-port DDI explicitly binds Connect, Disconnect and Message callback pointers to `FltCreateCommunicationPort` and describes when it calls them ([FltCreateCommunicationPort](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcreatecommunicationport)). Microsoft’s communication overview explicitly labels these `PFLT_CONNECT_NOTIFY`, `PFLT_DISCONNECT_NOTIFY`, and `PFLT_MESSAGE_NOTIFY` as minifilter callback routines passed to that API ([Communication between user-mode and minifilters](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/communication-between-user-mode-and-kernel-mode)). Separately, the `FltUnregisterFilter` DDI says it unregisters the minifilter driver’s callback routines and that Filter Manager no longer calls the driver to process I/O; the unregister overview says callback routines are unregistered and instances torn down.

Taken together, this is a plausible category-level interpretation that port-bound callbacks are included in the generic callback-unregistration contract. It is not a callback-type-specific statement that after `FltUnregisterFilter` returns Filter Manager cannot newly dispatch, or still has no executing invocation of, the three function pointers supplied separately through `FltCreateCommunicationPort`. The local rundown and object reference protect callback-reachable state and filter-object lifetime once code is entered; they cannot keep the driver image mapped if the source callback itself can start after unregister and before the local rundown acquisition. Therefore source acceptance remains NO-GO pending explicit maintainer/architecture confirmation or a more exact authoritative contract for these exact callback pointers. Windows stress can test observed behavior but cannot create an API guarantee absent from the contract.

### Normal build and feature scope

The project defines `SAFEUPLOAD_STAGING_PROTOTYPE=1` only for an explicitly enabled staging build and conditionally compiles stage units; communication, filter, policy, override and taint remain in normal builds (`SafeUpload.Minifilter.vcxproj:55-85`). R18 preserves the normal connected-client/full-communication preflight behavior. The candidate’s five-file delta does not alter `StageProtocol.c`, `StageFence.c`, agent wire files, policy, taint, or security code. The root diagnostic’s normal profiles confirm compileout and the feature profiles confirm inclusion. These source and compiler observations are not a product feature enablement or privacy-policy approval.

## Compiler and signer diagnostic

The terminal diagnostic result is `driver/evidence/2026-10-11/m2-t5-native-v20-r18-diag-a1-root-result.json`, SHA-256 `ca42ee32bac179561992defc0c860e63f6aead038ab739544be527a138cf8646`. Its capture receipt is `m2-t5-native-v20-r18-diag-a1-root-capture.json`, SHA-256 `4b76a1cd615199c6c7c95cb520ecf18f0a78bfb12ce035992dfb6a1698e36805`. Source archive and manifest hashes are `de74f7c680be30b666d4f4f90961dbcc966b490aa1238ccd08e1be55183287e8` and `cf0b1e5066e67beda401600131bbb6543b50ca75fe2a3865ff2dc2f7319554ac`. All four WDK logs were read in full after BOM/UTF-16 decoding. The result records all 26 source pins unchanged after build.

| Profile | Feature define | Warnings / errors | Exit | ApiValidator / PREfast | Raw WDK log SHA-256 | `.sys` SHA-256 |
|---|---:|---:|---:|---:|---|---|
| Normal Debug | false | 0 / 0 | 0 | True / True | `cc34a2cd7b0ade4bd05f05be423cea3ac669790a52411b63c3a4ae679fc46cbe` | `ce2d57e9b5d12b40aecb1f1fcbabd5dcd39da40e593436b94a79d9b3df580170` |
| Normal Release | false | 0 / 0 | 0 | True / True | `55b70ba4ffed8af17dbd231166a155aaa39d2a39ccbdeb74fc802a1b5283cb15` | `0623c6aae056861d9b1914b3d1d58d4f29a15b27831bca60e7d42a742c080881` |
| Feature Debug | true | 0 / 0 | 0 | True / True | `a726fa2af90e472ea953c1dafab925852ecb7f1779938ceca4d8e27765a30d68` | `a47073e660214c6934022e668091360a306e2fc2b9c5d6b51132b858fb290946` |
| Feature Release | true | 0 / 0 | 0 | True / True | `46de5d91e71a83b4770bd91afede0ff03c68f271eb3ce5ec32b00fbc978411c0` | `e425c53fa5e9117459e26b145e8ed701b1b5f2009bbae63d7a3be8ec14eaf504` |

The unsigned feature Debug binary is `a47073e660214c6934022e668091360a306e2fc2b9c5d6b51132b858fb290946`; the separately signed copy is `4f143e0a8ee8e719e405a613465f05fade4017808d47ca262423e5f5e7af3417`. Signature verification reported `Valid` with actual and expected signer `A6D6CE1AA28835D509160A80ADB7894869AADF38`; the unsigned copy remained unchanged. Treat this as diagnostic signing evidence only, not release-signing or runtime qualification. Both inspector build profiles and the writer fixture have zero warnings/errors. The owner’s agent integration tests remain outstanding.

Every one of the 43 raw/fetched artifact pins in the root result was recomputed and matched; no missing or mismatched artifacts were found. The full 43-entry pin table follows.

| Pinned artifact path | SHA-256 |
|---|---|
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/SafeUpload-stage-prototype.sys` | `4f143e0a8ee8e719e405a613465f05fade4017808d47ca262423e5f5e7af3417` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/inspector-feature-release.exe` | `a2f25339555d61494bb5ff8f8018e68ec94a5195ddc8797fa5d5b82047d931f1` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/inspector-feature-release.txt` | `9c3b80e3408fe34ba5bc364d78966516f2d5853b6e49a5e7c589505fb25599b2` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/inspector-normal-release.exe` | `438dd7a37983d9431afb17c77b8200c6fa931c3c9f1822f2e20e8500520dbdd4` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/inspector-normal-release.txt` | `12147e53395e043cb44701ecb151a3b4c2cde0bc194da38274c4c4483c1c28f5` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/normal-release-wdk.txt` | `55b70ba4ffed8af17dbd231166a155aaa39d2a39ccbdeb74fc802a1b5283cb15` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/normal-release.sys` | `0623c6aae056861d9b1914b3d1d58d4f29a15b27831bca60e7d42a742c080881` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/normal-wdk.txt` | `cc34a2cd7b0ade4bd05f05be423cea3ac669790a52411b63c3a4ae679fc46cbe` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/normal.sys` | `ce2d57e9b5d12b40aecb1f1fcbabd5dcd39da40e593436b94a79d9b3df580170` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/owned-feature-release-wdk.txt` | `46de5d91e71a83b4770bd91afede0ff03c68f271eb3ce5ec32b00fbc978411c0` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/owned-feature-release.sys` | `e425c53fa5e9117459e26b145e8ed701b1b5f2009bbae63d7a3be8ec14eaf504` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/owned-feature-wdk.txt` | `a726fa2af90e472ea953c1dafab925852ecb7f1779938ceca4d8e27765a30d68` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/owned-feature.sys` | `a47073e660214c6934022e668091360a306e2fc2b9c5d6b51132b858fb290946` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/sign.txt` | `57ff1a839ef06e2123e8c6f38f3c532018fc873f9fb04723f641f0793f4e79f5` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/signature-verification.json` | `b91a07c450519edd5d8e39365a4fb19d634596408915f975850c96eae53509c3` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/source-provenance.json` | `da8439c9ba5283b4cc9502f20a163717a25b7e1471caff0baaf0924ade965754` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/src.manifest` | `cf0b1e5066e67beda401600131bbb6543b50ca75fe2a3865ff2dc2f7319554ac` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/src.zip` | `de74f7c680be30b666d4f4f90961dbcc966b490aa1238ccd08e1be55183287e8` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/summary.txt` | `0aab896bf34793f4cecccb7383cf8f497eced9b6a126d8f14d7ad7e2e5d4c481` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/tools/Build-ExactSource.ps1` | `ff537d9426c5539fdfbd976ed77e55ee90f2a64501f17d463aa926f09cebd5d6` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/tools/Invoke-ExactSourceBuild.sh` | `5630091e233d34a5df4e4411d318663ea46e36a232e2fc9cd1189eb42b747a3e` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/tools/Prepare-ExactWorktreeSource.py` | `67386727e63ac8ff961548101276bdaa4b9bf0d0f970d23e801a915e6adff107` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/tools/remote_ps.py` | `39ed7a7892555d61b1577380fd84888ab39278a0115a7ca9b47b16ca6c52995b` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/writer-fixture.exe` | `b47ba3e6e1da9a24a84cdb96cbb511693357fd3f536decb687ca08e43a67c6bf` |
| `/tmp/claude-1000/exact-m2-t5-native-v20-r18-diag-1011-a1/writer-fixture.txt` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `driver/evidence/2026-10-11/exact-m2-t5-native-v20-r18-diag-1011-a1-artifact-hashes.txt` | `3901c02c22953fea12f6abf25b1155104ee762c79a618d8ff45b192d1e5481ec` |
| `driver/evidence/2026-10-11/exact-m2-t5-native-v20-r18-diag-1011-a1-build.stderr.txt` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `driver/evidence/2026-10-11/exact-m2-t5-native-v20-r18-diag-1011-a1-build.txt` | `2db070dff211a059e5ed044fac4e831235cb44b1a1f913e8b8ba5bb76ab05b68` |
| `driver/evidence/2026-10-11/exact-m2-t5-native-v20-r18-diag-1011-a1-builder-preflight.txt` | `aa30ce738b29d2df279d1792236b445660ef1ed4e538186b40d7b802a670f8d3` |
| `driver/evidence/2026-10-11/exact-m2-t5-native-v20-r18-diag-1011-a1-destination-preflight.stderr.txt` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `driver/evidence/2026-10-11/exact-m2-t5-native-v20-r18-diag-1011-a1-destination-preflight.stdout.txt` | `bd40e786e8ddbff296f920d320320c0a121e21f8c0e574c6232f213a54dc60d5` |
| `driver/evidence/2026-10-11/exact-m2-t5-native-v20-r18-diag-1011-a1-inspector-feature-release.txt` | `9c3b80e3408fe34ba5bc364d78966516f2d5853b6e49a5e7c589505fb25599b2` |
| `driver/evidence/2026-10-11/exact-m2-t5-native-v20-r18-diag-1011-a1-inspector-normal-release.txt` | `12147e53395e043cb44701ecb151a3b4c2cde0bc194da38274c4c4483c1c28f5` |
| `driver/evidence/2026-10-11/exact-m2-t5-native-v20-r18-diag-1011-a1-normal-release-wdk.txt` | `55b70ba4ffed8af17dbd231166a155aaa39d2a39ccbdeb74fc802a1b5283cb15` |
| `driver/evidence/2026-10-11/exact-m2-t5-native-v20-r18-diag-1011-a1-normal-wdk.txt` | `cc34a2cd7b0ade4bd05f05be423cea3ac669790a52411b63c3a4ae679fc46cbe` |
| `driver/evidence/2026-10-11/exact-m2-t5-native-v20-r18-diag-1011-a1-owned-feature-release-wdk.txt` | `46de5d91e71a83b4770bd91afede0ff03c68f271eb3ce5ec32b00fbc978411c0` |
| `driver/evidence/2026-10-11/exact-m2-t5-native-v20-r18-diag-1011-a1-owned-feature-wdk.txt` | `a726fa2af90e472ea953c1dafab925852ecb7f1779938ceca4d8e27765a30d68` |
| `driver/evidence/2026-10-11/exact-m2-t5-native-v20-r18-diag-1011-a1-sign.txt` | `57ff1a839ef06e2123e8c6f38f3c532018fc873f9fb04723f641f0793f4e79f5` |
| `driver/evidence/2026-10-11/exact-m2-t5-native-v20-r18-diag-1011-a1-signature-verification.json` | `b91a07c450519edd5d8e39365a4fb19d634596408915f975850c96eae53509c3` |
| `driver/evidence/2026-10-11/exact-m2-t5-native-v20-r18-diag-1011-a1-source-manifest.txt` | `cf0b1e5066e67beda401600131bbb6543b50ca75fe2a3865ff2dc2f7319554ac` |
| `driver/evidence/2026-10-11/exact-m2-t5-native-v20-r18-diag-1011-a1-source-provenance.json` | `da8439c9ba5283b4cc9502f20a163717a25b7e1471caff0baaf0924ade965754` |
| `driver/evidence/2026-10-11/exact-m2-t5-native-v20-r18-diag-1011-a1-summary.txt` | `0aab896bf34793f4cecccb7383cf8f497eced9b6a126d8f14d7ad7e2e5d4c481` |
| `driver/evidence/2026-10-11/exact-m2-t5-native-v20-r18-diag-1011-a1-writer-fixture.txt` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

## Remaining gates

This independent review closes source/build inspection only. R18 is not source accepted and is not runtime or pair qualified. The callback-source/code-image contract still needs disposition. Then the owner’s Windows lifecycle and matched-pair tests must cover both mapping-leak repros and supported destinations, including USB surprise removal and UNC/SMB, real sync clients with independent destination observation, canary and failed-start paths, detach/reset/disconnect races, crash/recovery, Driver Verifier, stress, latency, and confirmed VM restoration. No product cutover is supported by this diagnostic. Preserve taint, unsupported-capability blocks, and normal-build staging compileout until the owner’s stated acceptance and approval gates are complete.
