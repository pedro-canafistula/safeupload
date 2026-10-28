# T9 increment 3 kernel pass 4: independent pre-boot re-review (Sol 6.1 high)

Reviewer: Codex `gpt-6.1-sol`, reasoning effort high, fresh read-only session `01a18418-5d56-78e0-b8f0-5ab40fbe04cd`, 2026-10-28. Subject: `8bd4d0f0..a2e5d428` (kernel files unchanged at HEAD `a12a64f3`). Note: this and earlier 2026-10-28 worker sessions ran on the Codex fast service tier through a launcher default, contrary to the owner's 2026-10-17 no-fast-tier rule; the launcher now requests the standard tier. Verbatim report follows.

**ACCEPT WITH CONDITIONS.** Pass 4 closes the three original source findings in my review. The first protected-target boot remains blocked by the execution gates below; the proposed N-U5-01 scheduling does not satisfy the existing review/design.

Reviewed `8bd4d0f0..a2e5d428`, the complete `StageResourceMetadata.c/.h`, and the unchanged routing/communication/teardown hooks. HEAD was `a12a64f3`; those kernel files match `a2e5d428`. This was read-only and offline. No network, VM or builder access occurred, and I wrote nothing.

The remaining findings are execution-gate findings, not newly identified kernel-source defects.

1. **Medium — N-U5-01 cannot become its own protected-boot prerequisite. [before-first-boot]**

   [UX-LARGE-GROWTH-PROTOCOL.md:1988](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:1988), [readiness conjunction:2788](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:2788).

   Concrete ordering failure: install the new kernel on debug3 → boot/reach legacy Ready → arm runtime Verifier → execute N-U5-01. The protected-target boot has already happened before its required progress evidence exists. Verifier does not resolve that ordering.

   The existing wording requires source acceptance, then real-port N-U5-01 on a **separately authorized component-host setup**, then the first protected-target boot/checkpoint. Running N-U5-01 during the first protected boot does **not** satisfy it. A distinct component-only debug3 setup would need explicit handling under that requirement; relabelling a protected boot is insufficient. This review grants no additional host or run authorization.

2. **Medium — The prepared N-U4-06 script does not establish every required fault/accounting condition. [before-first-boot]**

   [native-store-mechanism-control.ps1:338](../../../driver/scripts/t9/native-store-mechanism-control.ps1:338), [execution coverage:458](../../../driver/scripts/t9/native-store-mechanism-control.ps1:458), [design requirement:1393](../../../driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:1393).

   Concrete unsupported conclusion: all 32 replacement and 48 allocation rows pass → temporary-directory cleanup succeeds → declare N-U4-06 completely closed. Those rows exercise normal allocation sequences and expected rename failures. I found no injected allocation/write/barrier failure sequence demonstrating retained `R_phys` across failure and normalization, or corresponding exact accounting-release evidence. Recursive directory removal alone does not establish that accounting contract.

   The proposed **fresh target overlay, exact 19045.2965, without the new metadata kernel, non-qualifying component row** satisfies the required placement. Its receipt must additionally cover—or explicitly cite complementary target controls for—the required fault/retention/release assertions. A PASS from this script alone should receive its narrower coverage description.

**Original finding 1: closed at source level.**

The decisive change is [StageResourceMetadata.c:2649](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:2649): draining/high-IRQL CREATE clears `Key` and sets `Closed` while the completion still owns its object reference, before publishing `Deferred`.

The adversarial interleaving now works: post withdraws membership → worker immediately consumes `Deferred` → worker drops the last extra reference → address recycles. No metadata key remains for that address. An unknown successful CREATE also loses metadata authority; it is not promoted to Active or represented as a successful storage receipt.

The other release paths remain consistent:

| Path | Lifetime result |
|---|---|
| Pre-CREATE refusal after reservation | Key removed before `MetadataReleaseIo`; completion output remains null. |
| Normal failed CREATE | Key removed/Closed set before reference release at [2668](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:2668). |
| Invalid successful CREATE | PASSIVE cancellation runs while the completion reference/pins remain owned; key withdrawal precedes their release at [2683](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:2683). |
| Ordinary child/root CLEANUP and CLOSE | CLEANUP disables use; pre-CLOSE removes membership before native destruction. CLEANUP/context pins prevent premature record reuse. |
| Ordinary revoke | Authority disappears, but keys remain to observe native CLOSE while callback coverage remains available. Waiting for an actually open handle is intentional. |
| Instance teardown/unload/forced forgetting | [MetadataForgetKeysLocked:227](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:227) withdraws root, child and capture keys synchronously, before subsequent releases or callback loss. |

The lookup race is also safe within this contract. Membership lookup and group-rundown acquisition occur under `MetadataLock`. A forwarded operation acquires its embedded context/record pin before dispatch; target-object lookup takes its actual object reference under the lock. Native callback ownership protects the current callback’s FILE_OBJECT during admission. An operation arriving after withdrawal falls through the existing route; it receives no surviving metadata bypass. Revocation prevents a previously matched ordinary admission from becoming newly authorized.

I found no new double-release or credit leak: `Deferred` transfers one existing owner, the worker consumes it once, retirement waits for both completion owners and both pin classes, and removing a replacement edge wakes another retirement pass. The header’s distinction between record pins and FILE_OBJECT ownership is upheld.

**Original finding 2: closed at source level.**

[MetadataFsFilterPre:2288](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:2288) runs before subject/IRQL admission and generic non-IRP refusal.

| Callback | Contract assessment |
|---|---|
| Section acquire, `SyncTypeOther` | Passes without a metadata context; cannot be refused by service authentication. |
| Section release | Passes without taking or releasing a metadata-owned filesystem resource. |
| Acquire/release mod-write and CC flush | Pass to lower NTFS without ordinary admission or completion ownership. |
| Section acquire, `SyncTypeCreateSection` | `FLT_PREOP_COMPLETE` with `STATUS_INSUFFICIENT_RESOURCES` is the supported failure form. The section attempt fails; this does not report a successful acquire requiring a later metadata release. |
| `IRP_MJ_QUERY_OPEN` | Uses `FLT_PREOP_DISALLOW_FSFILTER_IO`, requesting the normal open/query fallback rather than fabricating completion. |

These are FsFilter callbacks, not ordinary IRPs. Passing their synchronization work does not grant cached/paging data I/O. Registered, revoked and provisional-capture objects all reach this classification before ordinary refusal. I found no remaining registered-object branch that fails one of these **release** callbacks.

CREATE now returns `FLT_PREOP_SUCCESS_WITH_CALLBACK` at [2508](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:2508), consistent with Filter Manager’s CREATE post synchronization. Early `FLT_PREOP_COMPLETE` branches leave the output context null; branches that reserved an internal context release it before returning COMPLETE. They do not hand Filter Manager a dangling post owner.

**Original finding 3: closed at source level.**

The bridge at [909](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:909) duplicates the existing handle, rather than opening another handle from the object pointer. A successful duplicate contributes to the **same FILE_OBJECT’s handle count**, so the original last-handle close cannot deliver CLEANUP until that bridge also closes.

The critical interleaving is now:

- Validate the caller’s handle with UserMode access checks.
- Duplicate it atomically; re-reference the duplicate and require exact object equality.
- Publish `CaptureKey` under `MetadataLock`.
- Close the bridge outside the lock.
- If that was the last handle, CLEANUP observes the capture key and marks it cleaned.
- Promotion checks that mark under the same lock, or atomically transfers membership to `Roots`.

If promotion wins the lock first, subsequent CLEANUP finds the registered root. If CLEANUP wins, promotion refuses. There is no uncovered interval. Closing the duplicate causes CLEANUP only when the shared handle count reaches zero; it does not create a second independent CLEANUP lifetime.

`ZwCurrentProcess()` addresses the sending process’s handle table here: the control-message callback executes synchronously in sender context, and authentication requires that current process to equal the registered process. There is no worker handoff or process attachment between validation and duplication. `DUPLICATE_SAME_ACCESS` preserves granted access; the duplicate is used only for lifetime. Handle reuse between validation and duplication is rejected by the object comparison.

Duplication, reference validation, close and native capture all run at PASSIVE outside `MetadataLock`. Allocation at [934](../../../driver/SafeUpload.Minifilter/StageResourceMetadata.c:934) is also **outside** the lock; its nonpaged backing makes the later bounded field transfers under the lock valid. Descriptor contents remain PASSIVE-only.

Failure/revoke paths withdraw provisional membership before releasing the bridge/reference, retain `RootBusy` through cleanup, and publish no new RootId. `ZwDuplicateObject` is a supported PASSIVE kernel DDI usable here; the local 19045-family export reference includes it. Native verification of the actual bridge/CLEANUP behavior remains **[before-qualification]**, including close-before-duplicate, close-after-duplicate, close-at-promotion, handle reuse and each capture failure.

**The previous “survived” assessments remain intact in this patch.**

| Area | Re-review result |
|---|---|
| Spin locks and lock order | No new allocation, handle operation, dereference, Filter Manager call or blocking wait under `MetadataLock`. No new reverse communication-lock edge. |
| Worker/rundown | Deferred publication remains the post’s last context access. Forced key removal preserves context owners; destruction still joins the actual worker thread. |
| Outer routing | Metadata recognition remains before epoch/generic dispatch. Startup/mandatory-teardown CREATE gates remain outside it; metadata post classification precedes generic tag/drain handling. |
| Authentication/root authority | Original process/token/service-SID/cookie checks, channel restrictions, fixed installation capture, security predicates and no-SHARE_DELETE ancestry anchors remain. |
| Pools/replacement graph | Separate 8+8 pools, four total child credits, pending-intent claim, alias rejection and New→Current pin direction remain. |
| Role enforcement/buffers/accounting | Existing role limits, captured inputs, preallocation requirements and retained accounting remain. No new refund or native-mutation retry was introduced. |
| Dormancy | Well-formed Commit remains unconditionally NotReady with zero authority fields. Fence/ACK/Snapshot remain unsupported; no actor/echo interface appeared. |

These remain source assessments. Their native race, failure and conservation controls are **[before-qualification]**.

I independently matched all six raw-file hashes in the `m2t9i3k1028a8` receipt. Debug and Release logs contain PREfast, ApiValidator and 0 warnings/0 errors; imports report 252/251 PASS. That closes the fresh static-gate condition, not target execution or pair qualification.

**Confirm the first-boot protocol with these amendments. [before-first-boot]**

1. Close N-U4-06 with the complete target evidence described above. Close N-U5-01 in the required separately authorized component setup before the protected boot. Its real adapter/callback progress, Busy distinctions, watchdog release and finite disconnect drain must be observed; fake sends remain insufficient.
2. Use only `SAFEUPLOAD_DEBUGGEE=win10-debug3`, with debug2 off, a fresh disposable overlay, reset EFI variables, no TPM, test signing and Secure Boot off. Record source and delivered artifact hashes.
3. Reach legacy Ready using the established procedure, then arm `/volatile /flags 0x13B /adddriver SafeUpload.sys` and require actual `/query` readback. Exercise fresh metadata-group allocations after arming. This is runtime-Verifier coverage, not boot-Verifier coverage.
4. Run serially: unregistered legacy regressions → Probe/pair and installed-root authority negatives → duplicate/CLEANUP race controls → one child create/preallocate/write/F1/EOF/F2/query/close → held-predecessor replacement and independent bytes → pool/Busy/concurrent-CREATE controls → failed/invalid/draining CREATE and address reuse → revoke/disconnect/service termination → detach/permitted unload.
5. Include section `SyncTypeOther`/CreateSection, all synchronization releases, mod-write/CC-flush and QUERY_OPEN controls under system/APC conditions. Require progress for releases and failure of new section creation. Preserve the no-SHARE_DELETE `0xC0000043` negative without fallback.

Stop immediately on a Verifier report, hang, unresolved owner, stale-key match, unexpected native status/link/allocation result, grant activation, forbidden public bytes or required failed assertion. Preserve the first failure and identify its hypothesis before another run. Verify restoration separately.

**[before-qualification]** Ordinary, runtime-Verifier and boot-Verifier rows on the final matched pair, independent byte observations, full lifetime/conservation evidence and the later actor/growth obligations remain open. This acceptance permits no modern admission or cutover.