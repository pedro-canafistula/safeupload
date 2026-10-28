**REVISE. The current source should not receive its first boot.**

Reviewed HEAD `15d593ccbe80361d9f718a509ff1ad4c96fabfa6`, including `git diff 51056ce7..HEAD -- driver/`. The kernel source is unchanged from `8bd4d0f0`. This review was read-only and offline; no files were written and no network, builder or VM was accessed.

The findings below are source-derived failure scenarios, not claimed runtime reproductions.

1. **High — Deferred CREATE completion can leave a stale FILE_OBJECT key after releasing its last owned reference.**

   [StageResourceMetadata.c:2542](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageResourceMetadata.c:2542), [worker release:1806](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageResourceMetadata.c:1806), [reference release:1765](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageResourceMetadata.c:1765).

   Concrete interleaving:

   - Pre-CREATE installs `Key`, reserves the child and retains the completion reference.
   - The lower CREATE fails; its post callback is drained.
   - The draining branch marks the child Revoked/uncertain and publishes `Deferred`, bypassing the ordinary failed-CREATE branch that clears `Key` and sets `Closed`.
   - The worker calls `MetadataReleaseIo`, dropping the reference without removing that key.

   A failed CREATE does not promise a subsequent CLOSE through this instance. The record therefore can retain an address after the FILE_OBJECT is destroyed. Retirement requires `Closed`, so the child, transaction slot and retiring group can remain stranded. Address reuse can subsequently misclassify an unrelated object’s operations. Instance teardown’s `ForceForgetKeys` handles one teardown case; it does not establish the required invariant for every deferred CREATE.

   **Before first boot:** give deferred CREATE an explicit key/lifetime disposition. Unknown outcomes must either retain ownership that prevents address reuse or remove the key before releasing that ownership. A worker that merely releases references is insufficient. Test draining failed CREATE with **no synthesized CLEANUP/CLOSE**, then immediate address reuse.

2. **High — Filesystem synchronization callbacks receive ordinary request refusal, including callbacks needed to finish native lifetimes.**

   [StageResourceMetadata.c:2297](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageResourceMetadata.c:2297), [non-IRP rejection:1972](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageResourceMetadata.c:1972), [completion helper:2214](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageResourceMetadata.c:2214).

   Concrete input: a registered object receives `IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION`, or an acquire with `SyncTypeOther`, in a system thread or at APC_LEVEL.

   Except for CLEANUP/CLOSE, the branch first requires PASSIVE_LEVEL and the original service subject. It returns `FLT_PREOP_COMPLETE` with NotReady/AccessDenied when those checks fail. Even an authenticated PASSIVE invocation reaches the blanket non-IRP rejection.

   Rejecting new mappings does not justify failing native release or existing synchronization work. These callback classes require their own legal dispositions. The shipped code already distinguishes `SyncTypeOther` as necessary for completing cache/paging lifetimes at [StageWriters.c:7345](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageWriters.c:7345).

   **Before first boot:** classify these operations before ordinary subject/IRQL admission. Preserve necessary native release/synchronization progress without entering generic policy routing; refuse section creation through its supported callback contract. Handle `IRP_MJ_QUERY_OPEN` with its FsFilter-specific disposition. Also return `FLT_PREOP_SUCCESS_WITH_CALLBACK` for CREATE rather than applying the generic `FLT_PREOP_SYNCHRONIZE` return at [2401](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageResourceMetadata.c:2401).

3. **Medium — RegisterRoot can publish an already-cleaned original object because CLEANUP can pass before publication.**

   [StageResourceMetadata.c:917](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageResourceMetadata.c:917), [publication:936](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageResourceMetadata.c:936), [lookup:2250](/home/victor/Work/safeupload-staging/driver/SafeUpload.Minifilter/StageResourceMetadata.c:2250).

   Concrete interleaving:

   - Registration completes its final `FO_CLEANUP_COMPLETE` check.
   - Another service thread closes the last original root handle.
   - CLEANUP runs before `Roots[index].Key` exists, so metadata routing does not record it.
   - Registration publishes that FILE_OBJECT with `Cleaned == FALSE` and returns a successful RootId.

   The object reference prevents address reuse here, but it does not prevent CLEANUP. Independently opened installation anchors also do not preserve the original FILE_OBJECT’s handle lifetime. Subsequent registrations can consume credits against an unusable root; reopening the directory produces another FILE_OBJECT that the retry path refuses.

   **Before first boot:** bridge original-handle lifetime through publication, or publish a non-authorizing provisional entry that observes CLEANUP during capture. Another unlocked flag check leaves the same race.

4. **Medium — Two explicitly required pre-boot execution gates remain unproved.**

   [Readiness conjunction:2787](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:2787), [N-U5-01:1962](/home/victor/Work/safeupload-staging/driver/docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md:1962).

   The concrete unsupported substitution would be booting `win10-debug3` using builder-native results as target mechanism proof and fabricated-port tests as real callback-progress proof.

   - **N-U4-06:** no cited result establishes the selected sharing/rename/allocation mechanisms on target **19045.2965**, without the new kernel loaded.
   - **N-U5-01:** the current resource-send tests use fabricated handles and a fake sender. The repository supplies the seam, but no completed real-port control establishing registration and raw-store progress while `HoldLegacySendForTesting` owns `_sendGate`.

   Both remain **before-first-protected-target-boot** conditions. Missing separately authorized component-host execution cannot be replaced by treating the first protected boot as that prerequisite.

The following source properties survived this review, subject to those findings:

| Area | Assessment |
|---|---|
| **Spin-lock discipline** | I found no allocation, paged-descriptor access, user-memory access, Filter Manager call, dereference, handle close or blocking wait under `MetadataLock`. The target-object reference is taken under the lock and released outside it. Authentication takes communication state protection after releasing metadata protection; no reverse lock edge was identified. |
| **Worker/rundown** | Embedded contexts and record pins prevent normal context/slot reuse. Deferred publication is the transferring callback’s last context access. Retirement that releases a predecessor pin signals another worker pass. Destruction joins the actual system thread. Finding 1 prevents accepting the complete lifetime proof. |
| **Outer routing** | Recognition precedes epoch acquisition and generic namespace/BP dispatch. Startup and mandatory-teardown CREATE gates remain outside it. Recognized invalid requests stay handled and use captured refusal telemetry. Metadata context classification precedes generic draining/tag decoding. With no registered group, the new lookup falls through structurally to the existing path; runtime regression remains required. |
| **Authentication/root authority** | Process-object, primary-token, impersonation, service-SID, connection-cookie and driver-instance checks constrain the capability. Wrong-channel requests fail. Either port disconnect revokes the group. The independently opened fixed installation graph, component-by-component reparse rejection and identity comparisons prevent enrollment of an arbitrary SYSTEM-owned directory. Private-root and Windows-ancestor security predicates are separate; exclusion handles omit SHARE_DELETE. Finding 3 concerns the original-object handoff. |
| **Pools and replacement graph** | Pending intents reserve one of four transaction credits before CREATE. Opening/Active/retiring owners retain that credit. Growth/NonGrowth pools are separate; retained tag-flipped aliases are rejected and Busy survives dispatch. Two simultaneous CREATEs cannot claim one intent. New→Current replacement dependencies do not form a cycle. |
| **Normal CREATE** | Exact access/options/disposition/sharing checks precede forwarding. Active publication follows native identity/type/link/security validation. Normal failed CREATE removes the key. Invalid successful CREATE reaches cancellation at PASSIVE. The deferred path is the unresolved exception. |
| **Role enforcement** | Current roles have narrow read/query/delete authority and explicit exclusions. New outputs require bounded preallocation, writes and F1/EOF/F2. Segment EOF/allocation cannot shrink; raw offset writes remain available for the later append/frontier consumer. HistoryCandidate freezes at F2 and cannot regain write access through FILE_OPEN. LegacyNegative delete remains refused without proof. Cached/paging/MDL-backed data operations are rejected; FsFilter lifecycle handling needs finding 2’s correction. |
| **Buffers/accounting** | Control inputs are bounded, probed, copied and header-rechecked before use. SET_INFORMATION inputs are captured before forwarding; post does not reread those inputs. Data extent arithmetic avoids addition overflow. Q includes independent A/U padding; writes require measured preallocation. Observations raise retained charge before hold, and retirement transfers it to retained bookkeeping without refund. These are kernel bounds/diagnostics, not agent debit authority. `ObservedPeak` tracks the live component, so it alone is not proof of additive live-plus-retired storage. |
| **Dormancy** | Negotiation has no Ready branch: well-formed Commit returns NotReady with Mode/capabilities/grant fields zero. Fence/ACK/Snapshot do not return successful authority stubs. I found no implemented actor/echo symbol or diagnostic opcode interface in the kernel source. |

I independently checked the local evidence rather than relying solely on the worker reports. The static receipt’s six referenced raw-file hashes match; its Debug/Release logs show PREfast, ApiValidator and 0 warnings/0 errors, with import availability PASS at 251/250 imports. All four agent TRX hashes match: 3,509 user and 25 SYSTEM results per configuration, all passed, including 97 N-U4/N-U8 user-native cases in each configuration. This closes the corrected **builder component** execution claim. It does not exercise the proposed kernel callbacks or qualify target 19045.2965.

The minimal ordered correction is:

1. Repair deferred CREATE key ownership, then callback-class dispositions, then root publication/CLEANUP handoff. Add controls for those exact interleavings.
2. Re-review the coherent patch and obtain fresh committed-source Debug/Release WDK, PREfast, ApiValidator and import gates. Preserve the existing failed receipts.
3. Complete N-U4-06 on the exact target baseline without the new metadata kernel.
4. After source acceptance, complete real-port N-U5-01 on an authorized component host. Keep the full held-old-epoch/actor proof open to increment 6.

After those blockers close, the first protected boot should be informative as follows:

- Use **`SAFEUPLOAD_DEBUGGEE=win10-debug3`**, keep debug2 off, and use a fresh disposable overlay with reset EFI variables, no TPM, test signing and Secure Boot off. Record source commit and delivered artifact hashes.
- Use the existing runtime-Verifier procedure: reach legacy Ready, arm **`0x13B` for SafeUpload.sys**, and verify actual `/query` readback. Those flags cover Special Pool, Force IRQL Checking, Pool Tracking, I/O Verification, Deadlock Detection and Security Checks. Modern Commit must remain NotReady.
- First confirm unregistered unbound-v1 and bound-head behavior. Then exercise Probe/pair and RegisterRoot with the **real installed agent store**: wrong process/token/channel, wrong identity/root, reparse ancestry, insufficient grants and root-close-during-registration negatives.
- Run one exact child create/preallocate/write/F1/EOF/F2/query/close sequence before replacement. Then test class 65/flags 3 against the exact held predecessor, independently observing old Links=0/DeletePending/readability and the successor. Preserve the no-SHARE_DELETE `0xC0000043` negative without fallback.
- Run serial pool/credit and lifetime controls: ninth transaction, fifth child, tag aliases, competing CREATEs, failed/invalid/draining CREATE, address reuse, revoke under active I/O, either-port disconnect, service termination, detach and permitted unload. Require finite local drain and conserved owners.
- Qualification still needs ordinary, runtime-Verifier and boot-Verifier rows on the final matched pair, independent byte observations and separate restoration.

Stop on any Verifier report, hang or unresolved owner, stale-key match, unexpected native status/link/allocation result, admission/grant activation, forbidden public bytes or required failed assertion. Preserve the first failure and identify its hypothesis before another run. Verify restoration separately; do not weaken a gate to proceed.