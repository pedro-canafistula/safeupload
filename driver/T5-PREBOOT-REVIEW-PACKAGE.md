# T5 increments 2–10: pre-boot lifetime review package

2026-10-13. **Accepted source package; NotReady; not booted.** Increments 5–10 landed on `feat/driver-m2` as one dormant
commit whose kernel, agent and `driver/scripts/t5` trees equal local branch `wt/t5-inc10` at
`03fbe057b9bdc6a31f5479ed4c7db95c5bf4ad67`: increment 10 (`4527c83d`), the kernel warning fixes (`923dca3e`), two WDK
build fixes (`0b4a3372`, `03fbe057`) and one agent-test fix (`e6b3d53c`). The exact WDK and agent receipts are in the
gate table below. This document is the input to the single **Sol 6.1 xhigh (`gpt-6.1-sol`, `reasoning_effort=xhigh`)**
pre-boot review; it is not that review.

Controlling scope: [integration plan §3, §4 and §6](evidence/2026-10-13/t5-integration-plan-astra.md),
[T5 deletes §7](T5-DELETES.md#7-unload-and-shutdown-rescope),
[bound publication](T5-BOUND-PUBLICATION.md), [native opens](T5-NATIVE-PUBLIC-OPENS.md),
[T4 increment 9](T4-STAGE-LIFETIME.md#implementation-note--increment-9), and
[current owner decisions/stops](POST-MVP-PLAN.md). Normal builds exclude the feature. Taint and fixed-local-NTFS scope,
unsupported USB/UNC/cloud gates, ordinary empty publication and option-1 private/no-export policy remain intact.
The owner's 2026-10-13 row authorization covers planned M2 rows on win10-debug3 only; this implementation is not booted before the pre-boot review accepts it.

## Increment-10 result and readiness

Mandatory teardown now explicitly fences writer factories/metadata readers with native/V26/attach producers, closes
registry identity anchors before channel/backend lifetime drains, and retires local owning records before checking
aggregate owner counts. Native factories reserve bounded capacity before capture/allocation and veto voluntary unload.
A voluntary attempt no longer destroys an ordinary native-open record during preflight: a later veto retains its future
disposition lookup and retry path. Unresolved SOP histories/reservations/Unknown markers also veto, conservatively,
until normal retirement; there is no forced context deletion. Voluntary CREATE fencing retains the authenticated service's
existing bookkeeping path and rechecks writer/epoch ownership after the service epoch reply. Mandatory CREATE fencing
has no service exception. Published backend handles close before the factory join, followed by another scan for a pre-gate factory's
late publication. This prevents an existing driver hold from blocking the very factory teardown is joining.
The backend-drained event is published only after memory and SOP-owner release.

Native/V26 routines that own a spin lock across statements are resident even when their entry contract is PASSIVE.
Returning from a nonpageable lock wrapper does not make a PAGE-marked caller safe at DISPATCH. Increment 10 removes
those PAGE placements. The warning-fix follow-up also removes the remaining `PAGED_CODE()` calls from their resident
bodies, retaining PASSIVE entry annotations/assertions and the spin-lock save/restore contracts. See the IRQL map below.

`StagedBoundReadiness` replaces a writable unexplained Boolean with a locked composition and monotonically invalidated
connection ticket. `_stageBoundHeadReady` is a read-only projection also requiring the live V20/recovery bits.
The startup receipt is exposed only after the entire asynchronous recovery task succeeds, including private/V26/ordinary
recovery, native reconciliation, final authenticated replay and durable epoch completion. A completed pass with retained
prerequisites is distinguishable from a failed/incomplete pass. Late negotiation or recovery from an invalidated ticket
cannot restore readiness; a fresh connection needs a new full pass. No configuration, transport bit or diagnostic switch
can remove the production native holds.

| Current inputs | Composed result / named blocker |
| --- | --- |
| Disconnected, or old completion after disconnect | NotReady: `Disconnected`, `StartupRecoveryIncomplete`, `NegotiatedPathIncomplete` |
| V20 `Required=0x3f` successfully delivered | NotReady: `NegotiatedPathIncomplete`; reserved bound bit `0x40` is not advertised |
| Complete bound-path negotiation without full startup completion, or failed/canceled/partial recovery | NotReady: `StartupRecoveryIncomplete`; replay failure additionally latches `ReplayInvalidated` |
| Complete recovery without delivered bound negotiation | NotReady: `NegotiatedPathIncomplete` |
| Recovery leaves a pending commit, scheduled/native hold, ordinary relay receipt or V26 attempt/receipt | NotReady: `UnresolvedPrerequisite`; exact durable name barriers remain |
| Complete negotiation/recovery, but SOP/owner/coverage census is Pending/Degraded/unavailable | NotReady: `CoverageNotReady` |
| Disconnect, changed driver/epoch/boot/replay revision, failed replay, protocol/authority revision or policy change | Clear completed prerequisites and invalidate the ticket (`Disconnected`, `ReplayInvalidated`, `ProtocolChanged`, `PolicyChanged`) |
| All synthetic prerequisites proved (pure component composition only) | Ready iff every input is complete and every blocker is absent; this has no production setter |
| All transport/recovery/coverage inputs successful in the actual service | **Still NotReady:** `native_create_security_unproved`, `seed_coherence_unproved`, `seed_export_authority_unproved`, `version_publication_authority_unproved` |

The warning log reports `bound_not_ready:` followed by the actual blockers at connection/negotiation. Existing V19 admission
coverage reporting is preserved; its Ready result is not an advertisement of bound capability. Current negotiation continues
to require exactly `0x3f`; neither the wire enum/layout nor kernel positive selector is widened. Kernel
`SafeUploadStageProtocolBoundAllocationReady()` independently remains FALSE. The proof enum/class is absent from normal
agent builds. Global unresolved-head/owner vetoes are deliberately conservative; their availability cost is not qualification.
An observed native or publication replay revision change invalidates the ticket even before startup receipt consumption;
bookkeeping can continue, but a late receipt cannot restore readiness. A new connection and complete pass are required.

## Exact kernel delta inventory

The list below is the union of function bodies/signatures touched by each cited commit, including removed helpers, plus
increment 10 and this warning-fix follow-up. `:line` refers to the current working-tree definition (historical/replaced names remain attributable to their
commit). Headers and build wiring are listed separately; inspect their complete cited deltas, including non-function
record fields, counters and pragmas. Use `git show <commit> -- driver/SafeUpload.Minifilter` and
`git show 4527c83d -- driver/SafeUpload.Minifilter` for increment 10 and
`git diff 4527c83d 03fbe057 -- driver/SafeUpload.Minifilter` for the warning and build fixes.
This is an inventory, not a source-freeze or review-disposition framework. `StageSecurity.c` and published
`StageBoundPublication.h` layouts are unchanged by these increments and remain required dependency reads.

### Landed mandatory teardown — `9e86822f`

- [Communication.c](SafeUpload.Minifilter/Communication.c): `SafeUploadCloseCommunicationPortInternal` (:440), `SafeUploadCloseCommunicationPort` (:517), `SafeUploadCloseCommunicationPortEarly` (:525), `SafeUploadConnectionUseAcquire` (:576), `SafeUploadConnectionIsAuthenticated` (:640), `SafeUploadConnectionGetAuthenticatedIdentity` (:666), `SafeUploadConnectionIsAuthenticatedIdentity` (:707), `SafeUploadConnectionPublishClientPort` (:877), `SafeUploadConnectionCommitAuthentication` (:941), `SafeUploadConnectionUseIsCurrent` (:972), `SafeUploadConnectionUseIsCurrentForProcess` (:997), `SafeUploadControlCallbackEnter` (:1047), `SafeUploadConnectionPinAuthenticatedProcess` (:1804).
- [Filter.c](SafeUpload.Minifilter/Filter.c): `SafeUploadUnload` (:398).
- [Filter.h](SafeUpload.Minifilter/Filter.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [Stage.h](SafeUpload.Minifilter/Stage.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageAdmission.c](SafeUpload.Minifilter/StageAdmission.c): `SafeUploadStageAdmissionBeginTeardown` (:1650), `SafeUploadStageAdmissionStopWorker` (:1660).
- [StageFence.c](SafeUpload.Minifilter/StageFence.c): `FenceLateControlReserve` (:1298), `FenceLateControlReserveAttach` (:1317), `SafeUploadStageFenceDrainLocal` (:1619).
- [StageNativeRecords.c](SafeUpload.Minifilter/StageNativeRecords.c): `NativeChanged` (:93), `SafeUploadStageNativeInitialize` (:250), `NativeDispositionFlush` (:766), `SafeUploadStageNativeReopenAdmission` (:1413), `SafeUploadStageNativeCloseAdmission` (:1421), `SafeUploadStageNativeDrainLocal` (:1430), `SafeUploadStageNativeUninitialize` (:1474).
- [StageNativeRecords.h](SafeUpload.Minifilter/StageNativeRecords.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageProtocol.c](SafeUpload.Minifilter/StageProtocol.c): `StageProtocolReadyForGenerationLocked` (:199), `StageSendV19Exchange` (:484), `SafeUploadStageNativeExchange` (:1139), `SafeUploadStagePublicOpenExchange` (:1257).
- [StagePublic.c](SafeUpload.Minifilter/StagePublic.c): `SafeUploadStagePublicInitialize` (:211), `SafeUploadStagePublicCloseAllBackends` (:228), `SafeUploadStagePublicDrainBackends` (:267), `SafeUploadStagePublicDereferenceBackend` (:597), `SafeUploadStagePublicAcquireOperation` (:625), `StagePublicOpenBackend` (:939), `SafeUploadStagePublicOpenBackend` (:1061).
- [StagePublic.h](SafeUpload.Minifilter/StagePublic.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageStream.c](SafeUpload.Minifilter/StageStream.c): `StageCacheAcquire` (:1418), `StageCacheRelease` (:1431), `StageCreate` (:2129), `StageAttachReleaseActive` (:2899), `StageAttachIsInstanceTearingDown` (:3119), `SafeUploadStageAttachInstanceTeardownStart` (:3169), `StageAttachExchangeRetry` (:3284), `StageAttachRetireUnexposed` (:3606), `StageAttachComplete` (:3857), `StageAttachDrainTransaction` (:4025), `StagePreOperationCore` (:4942), `StagePreOperation` (:5232), `SafeUploadStageGenerateName` (:5248), `StageTeardownReleased` (:5590), `StagePerformAllocationRecoveryRpcs` (:5844), `StagePerformHandleReceiptRpcs` (:5936), `StagePerformDiscardRpcs` (:5989), `StagePerformSealRpcs` (:6060), `StagePerformRenameRpcs` (:6099), `StageUpdateRetryTimer` (:6178), `StageWorkerPass` (:6235), `StagePublicOpenFlushFacts` (:6302), `StageNativeFlushFacts` (:6368), `StageWorker` (:6434), `SafeUploadStageInitialize` (:6636), `SafeUploadStageStopWorker` (:6759), `SafeUploadStageMandatoryTeardownActive` (:6850), `SafeUploadStageBeginMandatoryTeardown` (:6856), `SafeUploadStageDrainMandatoryTeardown` (:6882), `SafeUploadStageReleaseInstanceReferences` (:7329), `SafeUploadStageFree` (:7354), `SafeUploadStageDispatch` (:8873), `SafeUploadCollectDirectoryOverlay` (:9096).

### Increment 2 — `657a0319`, `e7981708`, `83be6f74`

- [StagePublic.c](SafeUpload.Minifilter/StagePublic.c): `SafeUploadStagePublicRecordWriterRefusal` (:137), `SafeUploadStagePublicWriterRefusalCount` (:144), `SafeUploadStagePublicWriterRefusalName` (:151), `SafeUploadStagePublicTryCloseAdmission` (:159), `SafeUploadStagePublicReopenAdmission` (:170), `StagePublicBeginOpen` (:186), `StagePublicEndOpen` (:201), `SafeUploadStagePublicInitialize` (:211), `StagePublicCaptureSubject` (:389), `SafeUploadStagePublicCaptureCreateSubject` (:439), `SafeUploadStagePublicCaptureCreateLookup` (:450), `SafeUploadStagePublicFreeCreateLookup` (:529), `SafeUploadStagePublicCloseCreateLookup` (:546), `StagePublicCloseObject` (:556), `SafeUploadStagePublicReferenceBackend` (:570), `SafeUploadStagePublicCloseBackend` (:577), `SafeUploadStagePublicDereferenceBackend` (:597), `SafeUploadStagePublicOpenBackend` (:1061), `StageWriterFreeAnchor` (:1143), `StageWriterFreeSnapshot` (:1152), `StageWriterCloseHandles` (:1163), `StageWriterFree` (:1188), `StageWriterFullId` (:1205), `StageWriterReadSecurity` (:1225), `StageWriterOpenAnchor` (:1261), `StageWriterCheckLink` (:1316), `StageWriterCaptureSnapshot` (:1354), `StageWriterEqualSnapshots` (:1468), `StageWriterCopyInput` (:1488), `StageWriterOpenOriginal` (:1526), `StageWriterValidateRequest` (:1569), `StageWriterProcessRunning` (:1647), `SafeUploadStagePublicOpenWriter` (:1658), `SafeUploadStagePublicReleaseWriter` (:1821), `SafeUploadStagePublicGetWriterBinding` (:1828), `SafeUploadStagePublicRevalidateWriter` (:1835), `SafeUploadStagePublicCheckWriterSecurity` (:1877).
- [StagePublic.h](SafeUpload.Minifilter/StagePublic.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageStream.c](SafeUpload.Minifilter/StageStream.c): `StageAttachCaptureCreateInput` (:2743), `StageAttachTransactionDereference` (:2809), `StageAttachReleaseRelatedObjects` (:2840), `StageAttachQueueCreate` (:2941), `StageRollbackUnloadPreparation` (:6963), `SafeUploadStagePrepareUnload` (:6978).

### Increment 3 — `b6ce355a`, `713dcdd5`, `ba884bc2`

- [Communication.c](SafeUpload.Minifilter/Communication.c): `SafeUploadPortMessageInternal` (:1877).
- [Protocol.h](SafeUpload.Minifilter/Protocol.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [SafeUpload.Minifilter.vcxproj](SafeUpload.Minifilter/SafeUpload.Minifilter.vcxproj): declarations, layouts, includes or feature build wiring (review the cited delta).
- [Stage.h](SafeUpload.Minifilter/Stage.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageBoundAllocation.h](SafeUpload.Minifilter/StageBoundAllocation.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageProtocol.c](SafeUpload.Minifilter/StageProtocol.c): `StageSendV19Exchange` (:484), `SafeUploadStageProtocolAuthenticationChanged` (:639), `SafeUploadStageAllocateBoundV23` (:999), `SafeUploadStageProtocolMetadataIdentity` (:1108), `SafeUploadStageReplayAllocationV19` (:1384).
- [StagePublic.c](SafeUpload.Minifilter/StagePublic.c): `SafeUploadStagePublicTryCloseAdmission` (:159), `SafeUploadStagePublicInitialize` (:211), `SafeUploadStagePublicCloseAllBackends` (:228), `StageWriterCloseHandles` (:1163), `StageWriterHashAncestors` (:1905), `SafeUploadStageWriterMetadataPrepare` (:1949), `StageWriterMetadataBeginRead` (:2342), `StageWriterMetadataEndRead` (:2360), `SafeUploadStageWriterMetadataControl` (:2371).
- [StagePublic.h](SafeUpload.Minifilter/StagePublic.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageWriterMetadata.h](SafeUpload.Minifilter/StageWriterMetadata.h): declarations, layouts, includes or feature build wiring (review the cited delta).

### Increment 4 — `63112d44`, `6ba0c30a`

- [Stage.h](SafeUpload.Minifilter/Stage.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageProtocol.c](SafeUpload.Minifilter/StageProtocol.c): `SafeUploadStageAllocateBoundV23` (:999), `SafeUploadStageProtocolBoundAllocationReady` (:1101), `SafeUploadStageReplayAllocationBoundV23` (:1341), `SafeUploadStageReplayAllocationV19` (:1384).
- [StagePublic.c](SafeUpload.Minifilter/StagePublic.c): `SafeUploadStagePublicWriterMetadataCurrent` (:2120), `SafeUploadStagePublicWriterReplayIdentity` (:2153), `StageWriterSeedInterval` (:2193), `SafeUploadStagePublicSeedWriter` (:2201).
- [StagePublic.h](SafeUpload.Minifilter/StagePublic.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageStream.c](SafeUpload.Minifilter/StageStream.c): `StageFreeStream` (:1470), `StageBoundSeedReady` (:2059), `StageAllocateBound` (:2080), `StageCreate` (:2129), `StageAttachRollbackBinding` (:3538), `StageAttachResumeOrRun` (:3665), `StageAttachComplete` (:3857), `StagePreOperationCore` (:4942), `StageSealVersion` (:5418), `StageCollectSealRpcs` (:5761), `StagePerformAllocationRecoveryRpcs` (:5844), `SafeUploadStageDrainMandatoryTeardown` (:6882), `StageAdmit` (:7485).

### Shared warning corrections — `c3616acf`

- [StagePublic.c](SafeUpload.Minifilter/StagePublic.c): `SafeUploadStageWriterMetadataControl` (:2371).
- [StageStream.c](SafeUpload.Minifilter/StageStream.c): `StageCreate` (:2129).

### Increment 5 — `d8ed0291`, `ae62d018`

- [Communication.c](SafeUpload.Minifilter/Communication.c): `SafeUploadPortMessageInternal` (:1877).
- [Filter.c](SafeUpload.Minifilter/Filter.c): `SafeUploadInstanceTeardownStart` (:754).
- [Filter.h](SafeUpload.Minifilter/Filter.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [Policy.c](SafeUpload.Minifilter/Policy.c): `SafeUploadPolicyPublicationQuiescent` (:344).
- [SafeUpload.Minifilter.vcxproj](SafeUpload.Minifilter/SafeUpload.Minifilter.vcxproj): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageBoundPublication.c](SafeUpload.Minifilter/StageBoundPublication.c): `BpAcquire` (:150), `BpRelease` (:153), `BpEnter` (:155), `BpEqual` (:157), `BpZero` (:159), `BpId` (:166), `BpLeaf` (:168), `BpLeafEqual` (:184), `BpValid` (:192), `BpChangedLocked` (:226), `BpFind` (:231), `BpCallback` (:240), `BpFence` (:248), `BpQueue` (:257), `BpRevoke` (:265), `BpTerminal` (:279), `BpDestroy` (:297), `BpTokenSession` (:314), `BpReply` (:328), `BpSameSource` (:339), `BpOtherReservation` (:354), `BpNonceUsed` (:363), `BpQuery` (:379), `BpIdentity` (:391), `BpAnchors` (:417), `BpCaptureSecurity` (:446), `BpStoredSecurity` (:483), `BpObserve` (:503), `BpChannelCurrent` (:561), `BpPrepare` (:571), `BpDrainAndFlush` (:608), `BpWorker` (:687), `BpMutation` (:722), `SafeUploadBoundPublicationControl` (:839), `BpDeny` (:963), `BpActor` (:970), `BpCheckCreate` (:976), `BpCheckRename` (:1022), `BpNamespaceMutation` (:1057), `SafeUploadBoundPublicationPre` (:1076), `SafeUploadBoundPublicationPost` (:1260), `SafeUploadBoundPublicationInitialize` (:1370), `SafeUploadBoundPublicationNamespaceCoverageLost` (:1392), `SafeUploadBoundPublicationRevokeConnection` (:1408), `SafeUploadBoundPublicationInstanceTeardown` (:1422), `SafeUploadBoundPublicationNamespaceAvailable` (:1450), `SafeUploadBoundPublicationTryCloseAdmission` (:1465), `SafeUploadBoundPublicationReopenAdmission` (:1475), `SafeUploadBoundPublicationCloseAdmission` (:1482), `SafeUploadBoundPublicationDrainLocal` (:1495), `SafeUploadBoundPublicationUninitialize` (:1532).
- [StageBoundPublicationInternal.h](SafeUpload.Minifilter/StageBoundPublicationInternal.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageNativeRecords.c](SafeUpload.Minifilter/StageNativeRecords.c): `SafeUploadStageNativeReserve` (:366), `SafeUploadStageNativeMarkForwarded` (:584), `SafeUploadStageNativePublicationIdle` (:1490).
- [StageNativeRecords.h](SafeUpload.Minifilter/StageNativeRecords.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageProtocol.c](SafeUpload.Minifilter/StageProtocol.c): `SafeUploadStageProtocolConnectionReset` (:617), `SafeUploadStageProtocolAuthenticationChanged` (:639).
- [StagePublic.c](SafeUpload.Minifilter/StagePublic.c): `SafeUploadStagePublicPublicationBeginObservation` (:2483), `SafeUploadStagePublicPublicationEndObservation` (:2498), `SafeUploadStagePublicCloseWriterEvidence` (:2506), `SafeUploadStagePublicPublicationSecurity` (:2515), `SafeUploadStagePublicPublicationCurrent` (:2579).
- [StageStream.c](SafeUpload.Minifilter/StageStream.c): `StageFreeStream` (:1470), `StagePreOperationCore` (:4942), `SafeUploadStageInitialize` (:6636), `SafeUploadStageBeginMandatoryTeardown` (:6856), `SafeUploadStageDrainMandatoryTeardown` (:6882), `StageRollbackUnloadPreparation` (:6963), `SafeUploadStagePrepareUnload` (:6978), `SafeUploadStageFree` (:7354), `StageEpochOperation` (:8324), `StageDispatchCore` (:8421), `StageDispatchEpoch` (:8772), `StagePostOperationCore` (:8905), `SafeUploadStagePostOperation` (:8999), `SafeUploadStagePublicationAcquireSource` (:9164), `SafeUploadStagePublicationSourceCurrent` (:9207), `SafeUploadStagePublicationReleaseSource` (:9228).

### Increment 6 — agent only; no kernel delta


### Increment 7 — `017955ab`

- [Stage.h](SafeUpload.Minifilter/Stage.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageNativeRecords.c](SafeUpload.Minifilter/StageNativeRecords.c): `NativeOrdinaryIdle` (:108), `NativeBindingValid` (:143), `NativeDestroy` (:236), `NativeReserve` (:269), `SafeUploadStageNativeReserve` (:366), `SafeUploadStageNativeBindWriter` (:377), `SafeUploadStageNativeCloseWriter` (:450), `SafeUploadStageNativeOwnerNameStatus` (:488), `SafeUploadStageNativeReleaseRecord` (:651), `SafeUploadStagePublicDispositionConfirm` (:725), `NativeDispositionFlush` (:766), `NativeDispositionPrepare` (:786), `SafeUploadStagePublicDispositionPost` (:954), `SafeUploadStageNativePostCreate` (:1041), `SafeUploadStageNativeAcknowledge` (:1318), `SafeUploadStagePublicOpenConfirm` (:1353), `SafeUploadStageNativeDrainLocal` (:1430), `SafeUploadStageNativePublicationIdle` (:1490).
- [StageNativeRecords.h](SafeUpload.Minifilter/StageNativeRecords.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageNativeWire.c](SafeUpload.Minifilter/StageNativeWire.c): `PublicWireCopyRow` (:70).
- [StageProtocol.c](SafeUpload.Minifilter/StageProtocol.c): `SafeUploadStageCancelPrivate` (:1204).
- [StagePublic.c](SafeUpload.Minifilter/StagePublic.c): `SafeUploadStagePublicReleaseCallbackOperation` (:655), `SafeUploadStagePublicReferenceWriterDelete` (:674).
- [StagePublic.h](SafeUpload.Minifilter/StagePublic.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StagePublicRelay.h](SafeUpload.Minifilter/StagePublicRelay.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageStream.c](SafeUpload.Minifilter/StageStream.c): `StageAttachRollbackBinding` (:3538), `StageAttachExchangeNative` (:3762), `StageAttachComplete` (:3857), `StageCancelSealedPrivate` (:4482), `StageSetDisposition` (:4539), `StageRename` (:4603), `StagePreOperationCore` (:4942), `StagePublicOpenFlushFacts` (:6302), `StageAdmit` (:7485), `StageDispatchCore` (:8421), `StageDispatchEpoch` (:8772).

### Increment 8 — `77466b81`

- [StageBoundPublication.c](SafeUpload.Minifilter/StageBoundPublication.c): `SafeUploadBoundPublicationPost` (:1260).
- [StageNativeRecords.c](SafeUpload.Minifilter/StageNativeRecords.c): `SafeUploadStageNativeNameChanged` (:1119).
- [StageNativeRecords.h](SafeUpload.Minifilter/StageNativeRecords.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageStream.c](SafeUpload.Minifilter/StageStream.c): `StageDispatchCore` (:8421), `StagePostOperationCore` (:8905).

### Increment 9 — `7366dcf1`

- [Filter.h](SafeUpload.Minifilter/Filter.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [Stage.h](SafeUpload.Minifilter/Stage.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageAdmission.c](SafeUpload.Minifilter/StageAdmission.c): `SafeUploadStageAdmissionCoverageStatus` (:506).
- [StageBoundPublication.c](SafeUpload.Minifilter/StageBoundPublication.c): `BpDestroy` (:297), `BpMutation` (:722).
- [StageNativeRecords.c](SafeUpload.Minifilter/StageNativeRecords.c): `NativeDestroy` (:236), `NativeReserve` (:269).
- [StagePublic.c](SafeUpload.Minifilter/StagePublic.c): `StagePublicBeginOpen` (:186), `StagePublicEndOpen` (:201), `SafeUploadStagePublicDereferenceBackend` (:597), `SafeUploadStagePublicCaptureNativeName` (:850), `StagePublicOpenBackend` (:939), `SafeUploadStagePublicOpenWriter` (:1658).
- [StageStream.c](SafeUpload.Minifilter/StageStream.c): `SafeUploadStageAdmissionDeleteStreamContext` (:1023), `SafeUploadStagePrepareUnload` (:6978).
- [StageWriters.c](SafeUpload.Minifilter/StageWriters.c): `StageRegistrySiblingsHoldNoWriterStateLocked` (historical/replaced), `StageRegistryCopyUnknownSopChunk` (historical/replaced), `StageRegistrySopSnapshotQuiescent` (historical/replaced), `StageRegistryUnknownSopMarkersQuiescent` (historical/replaced), `StageRegistryEntryIsBaseStream` (historical/replaced), `StageRegistryRetireUnknownSopIfSame` (historical/replaced), `StageRegistryLifetime` (:905), `StageRegistryLifetimeEnded` (:911), `StageRegistryReleaseLifetime` (:921), `StageRegistryDereference` (:927), `StageRegistryFindByKeyLocked` (:1112), `StageRegistryBindLifetime` (:2534), `SafeUploadStageWritersInvalidateLifetime` (:2588), `SafeUploadStageWritersPostCreate` (:2600), `SafeUploadStageWritersFreeContext` (:2864), `StageRegistryMarkSopUnknown` (:3582), `StageRegistryUnknownSopChunkPresent` (:3752), `StageRegistryUnknownSopCount` (:3771), `StageRegistryUnknownSopMarkersClear` (:3789), `StageRegistryOldIncarnationResolvedLocked` (:3936), `StageRegistryAssociateSectionPointer` (:3965), `SafeUploadStageWritersOwnerAcquire` (:4032), `SafeUploadStageWritersOwnerRelease` (:4048), `SafeUploadStageWritersOwnerCount` (:4066), `StageRegistryPruneLocked` (:4090), `StageRegistryOriginalContext` (:4174), `StageRegistryEntryQuiescent` (:4195), `StageRegistryTryPromoteStateNoInline` (:5264), `StageRegistrySiblingIncarnationsRetiredLocked` (:5363), `StageRegistryTryPromoteEntry` (:5386), `StageRegistryEntryHoldsNoWriterState` (:5792), `StageAnchorEndVisit` (:5888), `StageRegistryActivationProcess` (:6011), `StageRegistryReclaimWorker` (:6496), `SafeUploadStageWritersInitialize` (:6757), `SafeUploadStageSectionAcquired` (:6868), `StageSectionRemoveSlot` (:6945), `StageRegistryReferenceStreamEntry` (:7177), `SafeUploadStageWritersSopMatchesPolicy` (:7264), `SafeUploadStageWritersAdmissionCoverage` (:7814).

### Increment 10 — `4527c83d`

- [Filter.c](SafeUpload.Minifilter/Filter.c): `SafeUploadUnload` (:398).
- [Stage.h](SafeUpload.Minifilter/Stage.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageBoundPublication.c](SafeUpload.Minifilter/StageBoundPublication.c): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageNativeRecords.c](SafeUpload.Minifilter/StageNativeRecords.c): `SafeUploadStageNativeInitialize` (:250), `NativeReserve` (:269), `SafeUploadStageNativeTryCloseAdmission` (:1398), `SafeUploadStageNativeDrainLocal` (:1430).
- [StageProtocol.c](SafeUpload.Minifilter/StageProtocol.c): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StagePublic.c](SafeUpload.Minifilter/StagePublic.c): `SafeUploadStagePublicCloseAdmission` (:178), `SafeUploadStagePublicCloseAllBackends` (:228), `SafeUploadStagePublicDereferenceBackend` (:597).
- [StagePublic.h](SafeUpload.Minifilter/StagePublic.h): declarations, layouts, includes or feature build wiring (review the cited delta).
- [StageStream.c](SafeUpload.Minifilter/StageStream.c): `SafeUploadStageBeginMandatoryTeardown` (:6856), `SafeUploadStageDrainMandatoryTeardown` (:6882), `SafeUploadStagePrepareUnload` (:6978), `SafeUploadStageDispatch` (:8873).
- [StageWriters.c](SafeUpload.Minifilter/StageWriters.c): `StageRegistryBindLifetime` (:2534), `StageAnchorInsert` (:5862), `SafeUploadStageWritersCloseAnchors` (:5964), `SafeUploadStageWritersUnloadReady` (:5985), `StageRegistryQueueReclaimWorkItem` (:6455).

The increment-10 residency-only edits also cover `NativeReserve`, `NativeDispositionPrepare`,
`SafeUploadStageNativeBindWriter`, `SafeUploadStageNativeCloseWriter`, `SafeUploadStageNativeOwnerNameStatus`,
`BpPrepare`, `BpDrainAndFlush`, `BpWorker`, `BpMutation`, `SafeUploadBoundPublicationControl`,
`SafeUploadBoundPublicationInstanceTeardown` and `SafeUploadBoundPublicationDrainLocal` (pragma changes are outside
function bodies). `tests/test_writer_metadata_readers.py` now extracts the shared close-admission helper as well;
`tests/writer_metadata_readers_fixture.c` asserts that the published backend closed before factory rundown.


### Kernel warning fixes — `923dca3e`, `0b4a3372` and `03fbe057` atop `4527c83d`

The two later commits fix only WDK build failures: `StageNativeRecords.c` now includes `StageSecurity.h` for the owner-name
identity queries (C4013 in `t5-top1`/`t5-inc9a`), and the `NativeDestroy` definition uses its declaration's annotations
(C28251 in `t5-top2`). No behavior change.

- `StageBoundPublication.c`: `BpPrepare`, `BpDrainAndFlush`, `BpWorker`, `BpMutation`, control, instance teardown and
  local drain remain resident with PASSIVE entry contracts, without `PAGED_CODE()`. `BpAcquire/Release` and the
  local-drain body cannot inline into PAGE callers. `BpWorker` uses `KSTART_ROUTINE` and inherited callback annotations.
- `StageNativeRecords.c`: the same resident-body correction covers `NativeReserve`, bind/close writer, owner-name
  lookup and disposition prepare. `NativeReserve` cannot inline into its PAGE wrapper. Owner-name lookup copies both
  exact and folded leaves into a fixed **1,024-byte nonpaged allocation** before `NativeLock`; Unicode folding and the
  original path queries stay at PASSIVE. The V26 locked CREATE match likewise uses exact bytes, never a Unicode helper.
- `StageBoundPublication.c`: V26 control request/reply scratch is one fixed **1,088-byte nonpaged allocation**; Revoke
  canonicalization uses a separate fixed **960-byte nonpaged allocation**. The existing **16,960-byte nonpaged Facts
  page** remains. These are per-call bounds, not a new aggregate port-concurrency budget. Allocation failures return
  `STATUS_INSUFFICIENT_RESOURCES` before the corresponding map mutation; every success/failure/auth/probe exit frees its
  scratch outside locks. No record/source ownership, lock order, one-way fence or native mutation is changed.
- V26 output length is checked before dispatch and again against the exact concrete page/reply immediately before its
  probe/copy. Internal replies/pages are fully zeroed. Only the existing probe-only C6001 convention is added (two sites).
- `BpCaptureSecurity` and `BpCheckCreate` retain descriptors locally and transfer only a nonnull, completely validated
  exact-success result; failures leave NULL/zero outputs and free owned memory. Informational statuses cannot satisfy
  the nonnull success contract. `NativeDispositionPrepare` initializes its completion output; the legacy cleanup call
  gets an explicitly empty slot, and `SafeUploadPreCleanup` clears the pointee rather than its local pointer variable.
- `StageWriters.c`: witness Ended/Invalid initialization and newly revised registry-cache accesses use interlocked
  operations. Prune, promotion and coverage sample the retained witness pointer once before testing/dereferencing it;
  missing/invalid witnesses still refuse readiness/retirement. No witness ownership or retirement rule is relaxed.

This is a static-correctness/residency and scratch-storage change, not an independent lifetime review. Both bound
readiness gates, all named holds, native-result retention and the required pre-boot Sol review remain in force.

## Ownership graph and destruction order

Arrows below mean owning references unless explicitly labelled comparison-only. An ACK is not a reference or lifetime barrier.

```text
original CREATE callback -> attach transaction -> subject/token + process + root/related object
                                      |-> instance + writer lease -> public handle/object
                                      |                         |-> root/parent/ancestor metadata handles/objects
                                      |                         |-> process lifetime handle + copied inputs/security
                                      |                         `-> immutable V27 metadata blob
                                      |-> staged handle -> stream/version -> backing handle/object + instance pins
                                      `-> unresolved allocation receipt -> AllocationWriterLease
app CLEANUP -> closed evidence shell -> version.PublicationWriterLease (no public handle)
V26 map -> record -> creator process/token + Source -> stream RpcReferences + borrowed evidence shell
                |-> root/parent/instance/security copies
                |-> queued worker/callback/I/O Uses (additional references)
                `-> name reservation + Facts + temporary lookup key (NON-OWNING)
native map -> record -> instance + optional combined backend reference
                   |-> producer/callback references + disposition gate/epoch/operation rundown
                   `-> original app FILE_OBJECT / app-release keys (NON-OWNING)
registry history/SOP map/writer node/section slot/reservation -> registry entry -> SOP witness
original attached stream context -------------------------------> SOP witness
reclaim anchor -> entry + instance + original metadata handle/object
SOP witness -> immutable SOP comparison token only; NO object/context/instance back-reference
```

| Owner | Acquisition / transfer | Normal, canceled and mandatory release |
| --- | --- | --- |
| CREATE input/process/subject/root | `StageAttachCaptureCreateInput`, queue capture; original static effective subject and referenced process/root, exact raw locator | `StageAttachReleaseRelatedObjects` closes handles at PASSIVE before final transaction destructor; failure/cancellation and attach joins retain the transaction until completion |
| Factory and writer/DELETE backend | `StagePublicBeginOpen`, `SafeUploadStagePublicOpenWriter` / `StagePublicOpenBackend`; factory and allocated backend each charge an SOP obligation | Every factory exit uses `StagePublicEndOpen`; backend final destructor closes Operations, public/metadata/process handles, buffers/token/process and instance, then releases owner; drained event is last |
| V27 reader | `StageWriterMetadataBeginRead` reserves one of four slots under PublicListLock before lookup/page allocation; reader pins lease and operation rundown | Common control exit frees page, releases operation and lookup, then slot; close admission precedes reader event wait; snapshot cannot move to a new cookie/revision |
| V23 private allocation | Attach owns candidate/backing and predecessor/RPC references; unknown allocation transfers original lease to `AllocationWriterLease` | Exact same-channel recovery detaches lease after recovering tuple; mandatory detach after workers/callback drain releases lease locally, preserving request/identity and disk files |
| Bound publication source | `SafeUploadStagePublicationAcquireSource` takes stream RpcReferences under NamespaceResource, then immutable writer/anchor/security validation outside it | `SafeUploadStagePublicationReleaseSource` releases root/parent/instance/copies and stream pin outside BpLock; V26 drain precedes stream RpcReferences wait |
| Closed writer evidence | Owned app CLEANUP closes real handles, transfers first lease shell to `PublicationWriterLease`, publishes `PublicationEvidenceClosed` | Version retirement or mandatory local owner release; no reopening metadata as caller authority, no post-cleanup target handle retained |
| V26 record/factory | `BpMutation` reserves capacity before allocation/token capture; map Uses plus queued work, controls and callbacks | Worker releases actual Uses; exact terminal ACK or mandatory `BpTerminal` removes map; `BpDestroy` drops source/process/token/security and SOP obligation. Unknown/coverage-lost records stay live |
| V26 namespace reservation | `NameReserved` under BpLock binds full immutable destination; generic epoch users drain after reservation | Remains through native result and exact terminal retirement; revoke/disconnect do not clear it. Mandatory local destruction of a proven-terminal record is not durable ACK |
| Native record/factory | `NativeReserve` reserves factory capacity under NativeLock before mount query/allocation, then map+producer refs, instance and optional backend owner | Factory exit always decrements/signals; callback completion drops refs; local drain requires sole map ref, no keys/backend/callbacks and exact terminal lifetime; `NativeDestroy` releases instance/SOP obligation |
| Combined disposition | `SafeUploadStageNativeBindWriter` binds checked original lease; `NativeDispositionPrepare` takes backend operation, then epoch only after destination turn reply | Ownership transfers to original post callback; `SafeUploadStagePublicReleaseCallbackOperation` is resident, drops short ref then rundown last; canceled/unforwarded paths release both. App CLEANUP removes keys, closes backend outside locks, then releases map's backend owner |
| Staged streams, sections and backing | Stream list owns version; app FILE_OBJECTs, share count, cache/section state, RPC and owned callback-body rundown keep it alive | Mandatory stream loop checks actual handles/FO/cache/sections/RPCs, never elapsed time; callback body drain then lease release; PagingRundown before backing close and instance release; no private file deletion |
| SOP witness/registry | Attached original context and each bound entry reference the tiny nonpaged witness; context binding is fenced on mandatory teardown | Only natural context cleanup can set Ended. Mandatory/forced/explicit loss sets Invalid, never Ended; context/entry destructors drop independent witness refs. No wait for witness Ended before unregister and no wait on the global owner count before owner destruction |
| SOP anchor/reclaim | Reclaim list or its single visiting worker owns anchor; worker holds ChannelRundown | Mandatory close detaches list anchors under AnchorLock, closes outside; mandatory gate bars insertion/requeue; visiting worker closes at end-visit before releasing channel rundown. Original context can still outlive an anchor |
| Communication callbacks | Exact authenticated connection-use pins, channel rundown and callback-body rundown; port owns callback source | Early close wakes pre-gate sends, then actual uses drain; unregister removes callback source; final callback EX rundown precedes state free |

Mandatory sequence is: publish permanent gate and cancel queued attaches → revoke/fence native/V26/public producers →
close ports → cancel canary → close list-owned SOP anchors and all driver-owned public backends (after their local metadata/
I/O users) → drain communication/channel users → join attach/maintenance/canary and reclaim work → drain fence workers →
join/drain V26 records and release source pins → drain staged handles/mappings/cache/FO/RPC and owned callback bodies →
release allocation/publication evidence leases → drain native records → drain final backend destructors → check aggregate
owner balance → paging rundown/backing/instance release → unregister → final communication callback rundown → stage/policy free.
The aggregate owner check is an assertion **after** destruction, never a wait preceding it. External lifetimes can keep the
local drain pending indefinitely. The native/V26 cleanup callback entry points remain available while their records drain.

## Lock order and blocking boundaries

| Lock / ordered edge | Protected state and restrictions |
| --- | --- |
| NamespaceResource → stream Resource → StageListLock | View/version topology, share/state snapshots and queued ownership. Snapshot/pin before releasing; mandatory flush/purge/close/waits execute without these locks |
| NamespaceResource → RegistryLock (voluntary census) | Read-only conservative history/reservation census after CREATE/epoch preflight. Unknown-slot scan runs after RegistryLock release |
| RegistryLock → SectionLock | SOP maps, section slots, final promotion/prune and accounting sequence recheck. No I/O, allocation, context acquisition, wait or dereference that can close under SectionLock |
| Context WriterLock | Witness binding and writer list. Does not acquire RegistryLock; witness has no owning back-edge; mandatory check is interlocked |
| StageAnchorLock | Anchor list transfer; all object/handle/instance release outside it. Gate checked at reinsertion; ChannelRundown joins a worker-taken anchor |
| PublicListLock → SectionLock | Factory admission/SOP obligation acquisition. Reader slot/count, backend list pins and voluntary veto share PublicListLock. Metadata copy, token/security I/O, operation rundown waits and close outside it |
| NativeLock → StageAttachLock; NativeLock → BpLock; NativeLock → protocol/connection identity checks | Native reserve/consume and publication exclusion. BeginMandatoryTeardown drops AttachLock before entering native/Bp locks; publication calls native-idle only after releasing BpLock |
| BpLock → StageAttachLock; BpLock → protocol state lock → connection lock | Uses/callback/write counts, immutable Facts revision, fencing/consume/reservations. No RPC, allocation, handle close, token query or flush under BpLock |
| EpochLock | Generic mutation admissions and publication quiescence (current plus draining epochs). Not held when entering BpLock. Delete destination-turn wait owns no policy epoch |
| Native disposition semaphore / backend Operations | Wait outside native/namespace locks. Early port close wakes service exchange before teardown waits for operation rundown; original post releases epoch/operation/semaphore |
| Connection transition / callback rundown | Close listener/client slot early; no namespace/spin resource across port close/drain. Keep disconnect cleanup resident until unregister and final callback rundown |
| Service destination turn → journal gate | Preparation/inspection/copy outside short physical turn; durable intent precedes permit. Recovery and receipt retirement enter reconciliation turn; no journal lock across native I/O or startup callback |
| Service readiness lock | Only local scalar/receipt updates. No transport, journal, waits or logging inside; invalidation rejects stale completion tickets |

No reverse acquisition of public/native/Bp locks from SectionLock is introduced. The resident spin wrappers restore IRQL
before any pageable helper. Their callers are also resident, with no `PAGED_CODE()` restriction, if execution continues
while the lock is held. PASSIVE entry does not authorize paged data access inside those DISPATCH-level sections.
See Microsoft’s [IRQL annotation contracts](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/irql-annotations-for-drivers). Review SAL against
all actual callers, including cancellation/draining posts; annotations and a successful static build alone are not proof.

## IRQL and paging map

| Code / data | Entry, residency and permitted work |
| --- | --- |
| `SafeUploadUnload`, stage begin/drain, public close/drain, SOP anchor close | PASSIVE entry; waits, FltClose, flushing and joins outside locks. New public/SOP helpers are resident; existing unload is PAGE before taking any spin ownership |
| NativeLock/BpLock helpers, map predicates, revoke/fence, callback accounting, owner acquire/release | Resident/nonpaged, lock sections at DISPATCH; bounded scalar/list work only. Exact/folded name copies, V26 request/reply/canonical scratch and Facts records/pages are nonpaged; allocation/folding/free happens outside the locks |
| Native factory, bind/close writer, owner-name lookup, ordinary disposition prepare | PASSIVE for capture/token/I/O but **resident** bodies: `NativeReserve`, `NativeDispositionPrepare`, `SafeUploadStageNativeBindWriter`, `SafeUploadStageNativeCloseWriter`, `SafeUploadStageNativeOwnerNameStatus` |
| V26 prepare/drain/worker/control/instance/local teardown | PASSIVE entry but **resident** bodies: `BpPrepare`, `BpDrainAndFlush`, `BpWorker`, `BpMutation`, `SafeUploadBoundPublicationControl`, `SafeUploadBoundPublicationInstanceTeardown`, `SafeUploadBoundPublicationDrainLocal` |
| Backend callback-operation release; native/V26 post callbacks | Resident through DISPATCH, no destructor/handle close there; PASSIVE terminal drain/ACK thread owns final destructor |
| Writer security/capture/metadata hash+page/seed, V26 token query/security/query/observe/check helpers | PASSIVE, PAGE permitted when they never retain a spin lock across their own instructions. Source file pragmas define exact placement; buffers initialized before copy out; complete outputs required |
| Registry entry proof/reclaim | PASSIVE filesystem/context/MM/flush outside locks; noinline resident helpers for SectionLock work. Worker pinned by ChannelRundown; queues stop at mandatory gate |
| SOP witness/context cleanup/section accounting | Tiny nonpaged witness, only interlocked state/token comparisons; no dereference of historical SOP token, no filesystem query or service call in cleanup |
| Private paging/cache callbacks | Keep resident callback/rundown state until actual mapping/cache/FO drain; PagingRundown precedes backing release. Ordinary callbacks cannot authorize a timeout-based release |

The critical source-barrier inference remains explicit: `FltUnregisterFilter` removes filter callbacks; applying that to the
Connect/Disconnect/Message callbacks registered by `FltCreateCommunicationPort` is the existing inference in `Filter.c`.
Final `CommunicationCallbackRundown` is retained after unregister. The reviewer must accept or correct that inference; the
source controls do not prove Windows callback delivery ordering, actual shutdown, hibernation or Fast Startup behavior.

## Failure and interruption matrix

| Trigger | Before forwarding / local ownership | Accepted/uncertain result and durable recovery | Teardown/readiness consequence |
| --- | --- | --- | --- |
| Allocation failure at factory, metadata page, witness, seed buffer, permit or reservation | Reserve bounds before ownership where specified; initialize outputs; unwind only acquired pins. Missing witness/identity records Unknown, not authorization | V23 unknown allocation retains exact request and lease; partial seed retained unexposed; never send a positive incomplete carrier | Factories/readers are counted before their work; failed production never bypasses gate. Static controls plus pending fault-injection rows |
| Cancellation at queued/active CREATE, copy, pre/post native operation | Cancel queued transaction once; close lease/root handles before final transaction release. Unforwarded facts remain distinct from NTFS failure | Record actual lower result if already forwarded; canceled pre-handle CLOSE needs exact no-handle evidence | Join actual callback/worker refs. No cancellation token or timeout substitutes for last cleanup; agent ticket invalidation refuses stale reply |
| Disconnect / service absent / service crash during send | Permanent mandatory gate rejects new sends/authority. Early close wakes existing exact port slot; backend local users unwind | Pre-forward intents, unknown allocations/PendingCommit and known native results stay durable; no manufactured ACK/seal | No service restart or reply needed for local memory drain; external objects may still delay it. Bound readiness clears before continuation/startup joins |
| Policy, protocol or authority revision change | Old cookie/revision/permit/carrier fails current-identity checks; data fence is irreversible | Current-policy inspection and exact destination generation still required; old replay cannot refresh authority | Policy push, coverage generation, protocol failure, authority revision and replay changes invalidate bound ticket; new connection requires full recovery |
| Native CREATE/rename/disposition accepted, result/reply lost | Original operation is consumed at most once; real status/Information retained before exposure cancellation | Reconcile Facts/anchored name and finish journal projection; never repeat CREATE/rename/delete. Known Published can finish Released without a physical retry | Local close is not deletion proof. Uncertain temporary/namespace/native receipt vetoes voluntary unload; complete recovery can report a named hold |
| Forced instance teardown / lost callbacks | Revoke forwarding, remove non-owning lookup keys before object address reuse; retain record/instance obligations and coverage-loss facts | Same-driver disappearance is not cleanup. Only exact evidence or qualified full Windows Restart can resolve approved fixed-NTFS exception | Mandatory local drain cannot erase missing proof to finish; new GUID, service restart, Fast Startup, timer and digest do not release it |
| External open / duplicate / inherited handle | Retained original authority/share semantics; driver's public/anchor handles close first after their local users | Accepted scheduled delete follows real NTFS last-close behavior; no synthetic scheduled-delete emulation | Actual app/backend cleanup and callback release required; no duration bound promised |
| Mapped data/image, paging or retained cache | App share count zero is insufficient: check FILE_OBJECTs, MM section predicates/cache maps, callbacks and paging rundown | Do not seal/publish or delete private residue on uncertain lifetime | Pending local drain can be unbounded; no timeout frees live memory. Mapped-write/callback controls remain required |
| Voluntary veto, including idle ordinary native open or SOP history | No destruction of native map on a reversible preflight. Public/native/V26 producer gates reopen on ordinary rollback; quarantined stage cleanup remains eligible | Listener, exact allocation/cleanup retries and service bookkeeping remain usable | Outstanding factories/readers/records/name reservations/SOP obligations veto; after epoch reply recheck local ownership. No service ACK can erase a live owner |
| Crash after ACK arm or lost ACK reply | Durable exact ACK fields remain tied to complete replay revision | Retry bookkeeping only; retire only after later complete authenticated removal proof; keep generation floors/manifest/security lineage closure | A boolean response or missing page never enables bound readiness; receipt still pending is diagnosable |

## Review invariants: integration plan §6 items 1–12

1. **T5 original CREATE authority:** `StagePublic` capture/open and `StageAttachCaptureCreateInput` preserve original static
   effective subject, process lifetime, request mode/options/share/raw/root inputs and exact identity through queue/RPC.
   Supplemental observers close before retained original-rights open. `StageSecurity` remains a dependency, not a source of
   SYSTEM-created caller authority. Native creator/low-impersonation and descriptor controls remain unproved holds.
2. **T5 ownership graph:** audit every edge in the ownership table, including partial factory unwind, metadata slots, combined
   backend operations, closed evidence shell, V26 Source/version pin, non-owning FO keys and SOP witness. Each owner releases
   once; callbacks cannot own the final pageable destructor. Close driver handles before waiting on lifetimes they prevent.
3. **T5 bound allocation/metadata:** V18=1192, V23=124, V27 request=136, page=4232, blob<=263480 and four-reader bounds remain;
   V26 layouts unchanged. Every page pins request/reservation/driver/cookie/epoch/authority/snapshot/digest/offset; final replay
   required. Complete stored and construction descriptors and provenance are independent prerequisites, never inferred from bytes.
4. **T5 seed/coherence/seal:** exact checked original source, bounded aligned explicit-offset copy, exact EOF/flush and post-RPC
   full snapshot/channel/reservation rechecks precede exposure/seal. Whole-copy interval is still unproved; partial/mixed seed
   cannot pass. Empty files use ordinary completion/seal/inspection/publication. Preserving descendants keep option-1 lineage.
5. **T5 V26 records:** bounded preallocation and immutable nonces precede original service CREATE/rename, consume once, retain
   actual status/Information even when later identity/tracking/exposure fails. Full native grant/options/security comparison
   grants no privilege. Failed CREATE and indeterminate native outcomes remain different facts.
6. **T5 one-way data fence:** same BpLock admits/counts I/O and sets DataFenced; only actual posts drain counts. Flush occurs
   outside locks after count drain. Fast I/O/MDL/paging/mapping/duplicate-handle mutations cannot bypass or reset the fence;
   renamed still-open handles cannot change inspected public bytes. Local shutdown cannot reset it.
7. **T5 destination serialization:** root/mount/parent/full IDs/case/leaf, current generation and exact expected target are all
   required. Service head and conservative instance-wide kernel name gate cover supported mutations/delayed cleanup. Pending,
   approved, blocked or empty successors do not cancel a prior delete; only an already-Published successor does.
8. **T5 native delete/backend lifetime:** retain native acceptance, original inline ordinary disposition thread/mode/flags/status,
   original scheduled-CREATE semantics and accepted-only owner tombstones. Ordinary FALSE is scoped to accepted ordinary state,
   not queued TRUE/ON_CLOSE/completed deletion. Remove lookup keys before reuse; close map-owned backend holds outside locks.
9. **T5 recovery/retirement:** exact original cleanup/cancellation or qualified boot proof plus anchored complete observation and
   authenticated replay; later removal replay retires durable ACKs. A local destructor supplies neither physical deletion nor
   publication nor ACK. No recovery path repeats a successful public mutation. Pending receipts/private bytes stay retained.
10. **T11 SOP/accounting:** original witness cannot be rebound to replacement SOP, recycled address, hash or path. Natural Ended
    differs from forced Invalid; missing/Unknown stays sticky until reboot. Retirement rechecks every writer/section/reservation/
    transaction/history and owner sequence. Mandatory teardown invalidates witnesses and closes anchors; it never waits on
    aggregate owner count before owner destruction, invents a natural Ended receipt or changes T4 thresholds.
11. **T5 unload/local teardown:** all producers are fenced, precollected/failure-unwind sends are denied, ports wake local users,
    owned handles close before dependent waits, and workers/callbacks/paging drain before free/unregister. No mandatory epoch RPC,
    service ACK wait or timeout release. Review unregister/communication-callback source-barrier inference explicitly.
12. **T5 locking/failures:** audit the lock/IRQL and interruption tables against actual instructions, including newly resident
    native/V26 bodies. All allocation/I/O/waits/close are outside spin locks. Voluntary rollback preserves service/worker progress;
    mandatory gate never reopens. Validate every failure and cancellation edge on the final matched pair when authorized.

## PREfast convention and open fail-closed holds

The existing one-statement C6001 suppression immediately before `ProbeForWrite` follows the owner's `0f2cacd3` convention,
retained in `c3616acf`. Its SAL annotation treats the destination as read, although this operation probes user **output**.
The request/output length, alignment and exception boundary still apply; zero-initialize internal replies and copy only
complete bounded output after the probe. This is not suppression of actual uninitialized reply bytes. The warning-fix
follow-up adds only that same single-probe convention at the two V26 output branches. Current sites:

- `StagePublic.c`: writer metadata control, `ProbeForWrite` following the C6001 pragma at 2457; explicit page zero remains.
- `StageNativeWire.c`: native V22 and public-open V25 page outputs (pragmas at 164 and 245).
- `StageNativeObservation.c`: exact name observation reply (pragma at 341).
- `Communication.c`: staged disposal and existing diagnostic/control outputs (pragmas at 190, 2139, 2172, 2220, 2236,
  2452, 2475, 2532, 2606, 2628, 2657, 2689, 2729, 2763, 2788 and 2819).

`StageBoundPublication.c`: Facts and mutation/ACK probes, each directly following its exact output-size check;
both source buffers are initialized. All source-level suppression inventory is reviewable with
`rg -n '#pragma warning' driver/SafeUpload.Minifilter`. Existing initialization fixes for complete writer anchors, metadata
page and previous-stage identity remain intact; unproved allocation replay without a retained lease stays failed closed.

| Named hold | Required proof / user consequence |
| --- | --- |
| `native_create_security_unproved`, `publication_security_not_equivalent` | Exact native construction/stored owner/group/DACL/SACL/label/control semantics; two inherited-descriptor `0x8C04 → 0x8804` counterexamples remain. Save stays private; no bit stripping, protected replacement DACL, privileged post-set or AccessState injection |
| `seed_coherence_unproved`, `seed_completion_unproved`, `seed_io_failed` | Whole-copy interval and exact completion. No partial/unproved seed exposed, sealed or exported |
| `seed_export_authority_unproved` (global), `seed_export_denied`, `seed_export_unproven`, `seed_export_recipient_unproven` (option 1) | Prove effective source read/export and recipient authority. Blocked unreadable/unproved seeded version stays private with Failed/no hand-back/no justification; do not convert this to an approved blanket ban on clean write-only edits |
| `version_publication_authority_unproved` | Closing app lease evidence does not establish live version authority after app cleanup/exit. Descriptor proof alone cannot enable publication |
| `writer_subject_unrepresentable`, `writer_creator_grant_unproved`, `writer_create_semantics_unproved` | Faithful subject level, original disposition/creator and supplied-input behavior, without SYSTEM fallback |
| `writer_lookup_unproved`, `writer_metadata_unproved`, `writer_snapshot_changed`, `writer_capture_limit` | Complete anchored identity/metadata and unchanged snapshots within explicit bounds; paths/digests alone grant nothing |
| `writer_metadata_stale`, `writer_metadata_replay_unbound`, binding/seed provenance/lineage reasons | Complete current immutable carrier and exact durable lineage. No refreshed authority for a lost reply |
| `public_delete_binding_unproved`, native coverage-loss / `NativeRecoveryUnresolved` | Exact original backend/lifetime/anchored evidence or approved qualified full Restart. Name stays held; no timeout/manual clear |
| `publication_*_unknown`, `publication_outcome_unresolved`, `publication_cleanup_unresolved`, `publication_replay_or_ack_pending` | Exact Facts/durable intent/terminal cleanup/later replay. Retain private bytes and bookkeeping; never retry the public mutation |
| `publication_metadata_unproved` | Unsupported/mismatched broader metadata stays a hold; no narrowed permanent metadata contract is approved here |

## Verification and native controls still required

Local checks on the kernel warning fixes (`923dca3e`):

- `git diff --check`: PASS.
- `python3 driver/scripts/t5/teardown-participation-selfcheck.py`: **11 source-contract tests PASS**, including PAGE
  placement **and `PAGED_CODE()` exclusion** for NativeLock/BpLock owners. This is not a transitive call-graph or IRQL proof.
- `python3 driver/SafeUpload.Minifilter/tests/test_bound_publication_buffers.py`: **PASS** using actual V26 control,
  reply and descriptor-capture bodies, production wire layouts and mocked OS/map boundaries. Checks exact/short/long
  reply sizes, output canaries, zero-filled unused fields/rows, allocation/auth/probe failures, immutable ACK retirement
  after reply loss, and descriptor failure/positive-status ownership cleanup. Native execution is not modeled.
- `python3 driver/SafeUpload.Minifilter/tests/test_writer_metadata_readers.py`: **PASS** for saturation, failure cleanup,
  voluntary veto and local teardown. Its first host compile failed because the fixture lacked `RtlZeroMemory` and passed
  the MSVC probe pragma to GCC; that failure is retained locally as
  `driver/evidence/2026-10-13/t5-inc10-kernel-fixes-metadata-first-failure.txt`. The adapter now supplies the missing mock
  and omits only the approved MSVC probe pragma from generated host C; `-Wall -Wextra -Werror` and assertions remain.

These portable controls do not run Windows SEH, PREfast, ApiValidator, NTFS or a loaded driver. The WDK and agent
receipts below are exact builds of committed source; the agent matrix includes `StagedBoundReadinessTests`, the extended
`StagedNativeStartupRecoveryTests` and normal-build feature absence. No component/source PASS changes production NotReady.

| Required gate | Status / exact delivery requirement |
| --- | --- |
| Four WDK configurations, PREfast + ApiValidator | **PASS** `t5-top3` at `03fbe057`: normal/feature × Debug/Release, **0 warnings / 0 errors** ([summary](evidence/2026-10-13/exact-t5-top3-summary.txt), [hashes](evidence/2026-10-13/exact-t5-top3-artifact-hashes.txt)). Driver SHA-256: normal `1DEE37D9…3722`, feature `AADEEB88…6A46`, normal Release `BA183997…BC85`, feature Release `70E61EA8…A938`. Failed receipts retained: [`t5-top1`](evidence/2026-10-13/exact-t5-top1-summary.txt) (C4013), [`t5-top2`](evidence/2026-10-13/exact-t5-top2-summary.txt) (C28251) |
| Agent delivery matrix | **PASS** `t5-top2` at `e6b3d53c` (agent tree equal to `03fbe057`): 1,453/1,453 normal and 2,023/2,023 feature tests executed and passed in each configuration, exact discovery, no skips ([summary](evidence/2026-10-13/exact-agent-matrix-t5-top2-summary.txt)). Release packages: normal `2A0A2B89…8CAB`, feature `A61493CD…0E25`. [`t5-top1`](evidence/2026-10-13/exact-agent-matrix-t5-top1-summary.txt) failed the feature test build (CS8604; receipt retained) |
| Metadata reader and V26 extracted-C controls | Local PASS at `923dca3e`; actual bodies with mocked boundaries, not WDK or native qualification |
| Single coherent lifetime review | [Sol 6.1 xhigh](evidence/2026-10-13/t5-preboot-review-sol61.md): REJECT at `a27defd8` (init unwind leak, paged rows under `NativeLock`, attach capture before admission); fixed in `c7518c7a` ([four WDK builds `t5-fix1`](evidence/2026-10-13/exact-t5-fix1-summary.txt) 0/0); focused re-review pending |
| Protected target and Verifier rows | Not run. Not booted before this review accepts the pair; then `win10-debug3` only (owner authorization 2026-10-13), with `SAFEUPLOAD_DEBUGGEE=win10-debug3` and separate restoration |

Finite native/control matrix still outstanding:

- **T5 caller/CREATE/security:** qualified target 19045.2965; original primary/anonymous/identification/impersonation/delegation,
  restricted/deny-only/low-integrity subjects, all six dispositions/presence, native creator grants, exact sharing, supplied
  descriptors/EAs/options and pregrants. Resolve both inherited-descriptor counterexamples without weakening binary equality.
  Existing `writer-permission-native-control.ps1`, `bound-publication-native-control.ps1` and
  `Invoke-SecurityRoundTripNativeControl.ps1` provide mechanism controls, not protected qualification. Builder 19045.6466
  observations do not qualify 19045.2965; do not repeat a rejected candidate without a new hypothesis.
- **T5 lookup/carrier:** original root close/rename, relative/raw-ID/short-name/hard-link/case selectors; full-ID and every
  ancestor/link/case/security replacement in both windows; lost/substituted/out-of-order/bounded metadata pages and readers,
  original cookie/revision revocation, cancellation at every acquisition and complete durable provenance replay.
- **T5 seed/export:** checked READ/WRITE/APPEND handles, share 0/7, synchronous/asynchronous/no-buffering; 0/1/sector/chunk/multichunk
  sizes; deterministic cached/noncached/mapped/append/truncate/regrow/hard-link/oplock/lock races across first/middle/final copy.
  Explicit offsets, exact EOF/flush and independent bytes; effective recipient/export through preserving private descendants.
  Transport above 16 MiB is a separate control, not a cap change.
- **T5 publication/fence:** exact grant `0x00110082`, options `0x0020006A`, mode `0x2A`; failed/canceled original CREATE and
  exposure cancellation status/Information; app cleanup/share release and app-exit version authority; queued writes/EOF/padding/
  flush versus fence; duplicate-handle/mapping/paging/MDL/Fast-I/O denial; final anchored target/ancestor/case/volume races.
- **T5 deletes/recovery:** ordinary and scheduled CREATE, combined backend, accepted-only tombstones and ordinary FALSE versus
  ON_CLOSE/queued TRUE; both destination-turn orders, Published-only supersession, cancellation generations; real last close,
  later directory change, accepted/lost result, reply/persistence/ACK boundaries and later replay without repeated mutation.
- **T5 teardown/T11:** absent/crashed service; active send; queued/active/canceled attach; writer factory/lease and each of four
  readers; V26 factory/worker/CREATE/write/rename/Facts/name reservation; combined disposition callback/epoch; held backend,
  external duplicate/inherited/open/mapped/image/cache/paging lifetimes; forced instance coverage loss; SOP anchor in list and
  taken by reclaim; natural cleanup versus explicit diagnostic deletion/unregister/dismount/recycled SOP; each H/W/T/section/
  spilled/reservation/transaction owner and a full acquire/release cycle inside a proof. Include voluntary veto/retry usability,
  double close, allocation failure at every owner, shutdown/full Restart/Fast Startup, and stable reference/pool accounting.
- **T5 final UX/pair:** real Notepad clean/CPF, empty saves and required ordinary/runtime-Verifier/boot-Verifier rows, raw byte
  observations with forbidden bytes zero and separate baseline restoration. If authorized native delete removes prior bytes
  before a blocked save, follow the existing owner-decision stop; do not emulate a different sequence.

Windows PowerShell **5.1** parse/native signature checks and relevant self-checks precede any changed harness execution.
Use fresh labels and committed source with the existing runners; retain failed receipts under [evidence conventions](evidence/README.md).
The final package still needs the orchestrator's exact source commit, driver/agent package hashes, complete structured matrix
summaries and native receipts. Review acceptance, component verification and protected-pair qualification are separate results.
