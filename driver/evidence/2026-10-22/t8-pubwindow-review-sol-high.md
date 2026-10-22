# Independent review: T8 publication window, revision 1 (2026-10-22)

Reviewer gpt-6.1-sol, reasoning effort high, no fast tier; read-only. Reviewed HEAD 51661d10. Verdict REVISE; answered by revision 2 of the design.

**REVISE.** The bounded-wait policy is reasonable, but this design does not yet establish a correct settlement predicate or independent progress on every route. Its literal predicate can keep an already-published name pending, and the proposed blocker test cannot be implemented exactly from the existing ownership records.

Reviewed current HEAD `51661d10a951805733f799868b1d7654d03657b9` on `feat/driver-m2`. This was read-only and offline: no files changed, builds, tests, remote jobs or VM actions. Code references below use `driver/SafeUpload.Minifilter/StageStream.c` unless another path is given.

1. **Blocking — publication, retirement and release are different states.**  
   [T8-PUBLICATION-WINDOW.md:34](/home/victor/Work/safeupload-staging/driver/docs/design/publication-and-namespace/T8-PUBLICATION-WINDOW.md:34), `StageStream.c:5286`, `:6446`, `:6585`, `:7663`.

   `MvpPublicationObserved` is set when the native-namespace cancellation exchange reports that publication won. Ordinary successful publication instead reports `Disposed` with `SAFEUPLOAD_STAGE_DISPOSE_RELEASED`; it need not set `MvpPublicationObserved` or `Retired`.

   Consequently, a normally published stream can remain live, detached, non-retired and `!MvpPublicationObserved`. The proposed scan still calls it pending. Holding its `RpcReferences` pin prevents `StageTryRelease`; released-stage deletion normally happens after unlinking, in `StageTeardownReleased`. Waiting for final release or consequent stage deletion would therefore depend on dropping the waiter's own pin.

   **Use an exact publication outcome independently of lifetime reclamation.** An accepted Released disposal can supply publication observation for its validated transfer/rename lineage; it is not permission to open whatever subsequently occupies the path. Preserve the existing stale/deferred-disposal checks and perform fresh destination admission.

   Conversely, `Retired` is **not publication proof**: blocked-stage deletion and acknowledged discard also set it. The aggregate `liveVersions=3/liveViews=2` observation cannot identify the lingering tuple or its publication state. Under the literal proposed predicate, already-public versions can indeed cause repeated full-bound waits.

2. **Blocking — the driver cannot promptly recognize the proposed Blocked terminal state.**  
   [T8-PUBLICATION-WINDOW.md:43](/home/victor/Work/safeupload-staging/driver/docs/design/publication-and-namespace/T8-PUBLICATION-WINDOW.md:43), `StagedTransferPublisher.cs:291`, `:617`, `:823`, `:891`.

   The service records Blocked before hand-back and possible justification. Driver notification through CleanedUp disposal comes later, after the required cleanup conditions. Failed hand-back or an open justification window can retain the stage. There is no corresponding immediate Blocked field in `STAGE_STREAM`.

   Thus adding busy terms to the existing helper cannot satisfy “Blocked never waits the full bound.” Waiting for deletion/disposal also incorrectly ties namespace progress to hand-back and possibly user action.

   Specify an authenticated, exact-tuple outcome observation or query that distinguishes:

   - Publication completed.
   - This publication attempt ended without publication: Blocked, acknowledged cancellation or acknowledged discard.
   - Publication outcome remains uncertain or held.
   - The selected tuple changed.

   Blocked may later be justified; “this attempt ended” must not authorize a later attempt or erase its retained evidence. After a non-publication outcome, re-admission may find the previous public file or absence. **Do not synthesize success, assume the public file exists, or turn uncertainty into absence.**

3. **Blocking — the existing helper locations are too late, and one pre-dispatch check leaves a race.**  
   [T8-PUBLICATION-WINDOW.md:56](/home/victor/Work/safeupload-staging/driver/docs/design/publication-and-namespace/T8-PUBLICATION-WINDOW.md:56), `StageStream.c:8750`, `:9498`, `:9723`, `:10672`, `:11257`, `:11262`.

   The route ordering is concrete:

   | Route | Required placement |
   |---|---|
   | Pure read/query CREATE | Before binding/share insertion; it currently bypasses epoch acquisition. |
   | Writer or other mutating CREATE | Before `SafeUploadPolicyAdmissionAcquire`, not inside `StageAdmit`. |
   | Native DOC CREATE | Before epoch acquisition and before `StageMvpNamespacePre` installs its mutation fence. |
   | Owned rename/delete SET_INFORMATION | Before epoch acquisition; publication waiting inside `StageRename` or `StageSetDisposition` is too late. |
   | Native rename/delete SET_INFORMATION | Before epoch acquisition and before `StageNamespaceBeginMutation`. The physical rename fallback also reaches that fence at `:9723`. |

   Add preflight at dispatch before ordinary epoch acquisition, while preserving the existing special disposition ordering. Then revalidate at the protected admission/mutation decision: another process can install a pending version between preflight and epoch acquisition.

   A late conflict must return an **internal retry-to-dispatch outcome**, unwind its epoch and any reservations/fences, then reconsider outside them. `StageAdmit`’s local `Readmit` loop does not release the outer epoch.

   Also distinguish profiles accurately: the shipped unbound permit path does not itself use the bound publication quiescence check. The explicit zero-active-epoch requirement is visible in `StageBoundPublication.c:651`. The design must prove ordering for the implemented profile and preserve policy-swap safety, rather than treating every publication path as identical.

4. **High — “requestor holds the blocker” is neither exact nor adequately represented.**  
   [T8-PUBLICATION-WINDOW.md:40](/home/victor/Work/safeupload-staging/driver/docs/design/publication-and-namespace/T8-PUBLICATION-WINDOW.md:40), `StageStream.c:338`, `:1951`, `:5910`, `:6278`.

   `STAGE_HANDLE` records grants, cleanup, a writer lease and byte-lock owners. It does not contain a complete inventory of current handle holders or section owners. Duplicates share the file object; the original view owner does not identify every process retaining it. `LockOwners` records processes issuing byte locks, not all duplicate recipients. Section pointers and cache-held objects likewise do not establish process ownership.

   Checking “any file object attributed to the requestor” remains insufficient. The requestor may also hold an incompatible handle or mapping on the **old public destination**, preventing replacement without holding an upper object on the pending private stream.

   Initially, use a conservative progress predicate: for closing-to-seal waits, require zero shares/FileObjects, no unresolved attachment/allocation obligations, and the prior review’s section/cache exclusions. Where ownership is unknown, do not claim independent progress. Supporting waits through live blockers requires additional evidence, not inference from creator PID.

   A SET_INFORMATION request also retains its source handle throughout the wait. That exact object may itself prevent the awaited drain or public replacement. Preserve handle identity and grants; never redirect an existing handle operation to a newly published same-name object.

   Finally, “unchanged behaviour” is not always “today’s refusal”: some owner opens against an active private version currently succeed. The conservative skip must preserve their existing result.

5. **Blocking — the universal rule includes the service operation needed to complete the wait.**  
   [T8-PUBLICATION-WINDOW.md:36](/home/victor/Work/safeupload-staging/driver/docs/design/publication-and-namespace/T8-PUBLICATION-WINDOW.md:36), `StagedTransferPublisher.cs:458`, `StagedUnboundNamespaceJournal.cs:12`, `StageStream.c:9478`.

   The unbound publisher performs its native commit while holding the journal gate. A pre-epoch rule applying to “any process” and rename targets can intercept that service rename and wait for publication of its own destination. Publication cannot finish until the rename returns. Journal operations needed by rename/receipt processing can then queue behind the same gate.

   Preserve the existing authenticated service/internal progress routes explicitly, including publication’s destination observations and commit. This must retain their existing permit and operation checks; **SYSTEM identity alone is not an exception**.

   The dependency proof must also cover:

   - No namespace/stream/spin lock, namespace fence or registry reservation across waiting.
   - No execution on the stage worker, attach worker or service receive path whose work is required for settlement.
   - Cleanup, CLOSE, unmap-related progress, paging/MDL completion and cache callbacks remain able to run.
   - No wait for global callback rundown or final version release.
   - Mandatory teardown releases waiter pins locally after its latch, without requiring a worker or service that has stopped.

   The narrower rename → op19 → drain → seal chain remains a plausible independent path under the conservative lifetime exclusions. Full publication adds dependencies that this proposal has not yet closed.

6. **High — foreign append semantics are correct in principle, but require atomic rechecking and explicit timeout behavior.**  
   [T8-PUBLICATION-WINDOW.md:67](/home/victor/Work/safeupload-staging/driver/docs/design/publication-and-namespace/T8-PUBLICATION-WINDOW.md:67), `StageStream.c:2059`, `:2701`, `:4842`, `StagedTransferAllocator.cs:214`.

   For sequential `alpha` then foreign-process append, the correct successful sequence is:

   1. Observe publication of the selected first version.
   2. Re-enter ordinary writer admission using the second caller’s original request.
   3. Seed its new private version from the freshly checked public object.
   4. Append at the seeded EOF and inspect/publish that new generation normally.

   Do not give the second process the first owner’s view, predecessor stage or authorization. Generation ordering alone does not prove that the seed contains `alpha`.

   Recheck all relevant same-name contenders and allocation reservations before committing admission. Otherwise a new contender can enter after the wait and recreate the race. Replacements between publication observation, security capture and seeding must cause normal identity validation/retry or refusal.

   **Timeout must explicitly refuse the pending conflict.** Falling through to today’s ordinary missing-name `OPEN_IF` path can create `beta` and repeat the reported loss. “Fails exactly as today” is contradictory here because the observed defective operation succeeded. Define the existing refusal status used for each affected route.

   Preserve disposition semantics: CREATE collides after publication; OPEN/OVERWRITE require existence; OPEN_IF seeds when present; truncating dispositions remain truncating. Retain append-only grants and the unreadable-seed read/export restrictions. An append-only caller must not gain permission to read seeded bytes because SYSTEM copied them.

7. **High — the existing void wait helper is not the claimed cancellation/deadline mechanism.**  
   [T8-PUBLICATION-WINDOW.md:49](/home/victor/Work/safeupload-staging/driver/docs/design/publication-and-namespace/T8-PUBLICATION-WINDOW.md:49), `StageStream.c:5314`, `:9491`, `:9524`, `:8040`, `:8115`.

   Each helper invocation creates a new ten-second deadline. It returns no distinction between settlement and timeout, does not check request cancellation during polling, and only gates one busy term with `StageStopping`. Admission can repeat.

   Require a per-original-operation monotonic deadline carried through every retry and both rename names. Return typed internal outcomes: settled, changed/retry, terminal-without-publication, timeout, cancelled and not-ready/teardown.

   Capture the referenced owner, instance, view generation, transfer/stage/driver identity, destination binding and rename lineage. Copy transaction values; do not dereference an exchange after ACK frees it. Accept a COMMIT generation change only through the existing validated apply path.

   Drop each pin exactly once on every exit and queue only when teardown permits. Check cancellation/readiness again before binding or forwarding. Ten seconds bounds intentional polling, **not total I/O duration**, because resource acquisition and native flush/drain operations can themselves block.

8. **Medium — evidence supports the UX defects, but not the asserted blocker attribution or a guaranteed Word repair.**  
   [T8-PUBLICATION-WINDOW.md:26](/home/victor/Work/safeupload-staging/driver/docs/design/publication-and-namespace/T8-PUBLICATION-WINDOW.md:26), `StageStream.c:3021`, `:5147`, `:6723`.

   `0x00010406` means gate 6, pending rename and one counted FileObject. It does not identify that object’s owner or prove the object prevents COMMIT. Neither rename RPC collection nor reply application requires FileObjects to reach zero; drain does.

   Stopping Search materially changes observed behavior, but attribution still needs exact stream/object and worker-phase evidence. Restart Manager finding no handle does not exclude mappings, cleaned-but-retained objects or unresolved protocol work.

   Per-case ring files also contain earlier entries. For example, the current `lc2.txt` refusals in `t8sweep-v1full/ring-txt-lifecycle.ndjson:248` carry sharing violations without the gate-6 detail; older Office gate-6 entries in that file must not be assigned to `copy-within`. The parity result proves the failure, while its precise route needs capture.

   The no-Search sweep improves application steps, but its cases are not overall parity PASS: metadata differences remain, and `word-saveas-edit` retains an owner-file delta.

**Implementation conditions**

Implement the **2026-10-19 conservative owner-reopen candidate first**, after the approved T9 prerequisite. It is the smallest coherent increment for same-process `copy-within` probes and Word reopen:

- A dedicated unbound owner read/query CREATE predicate based on original access/options, including the observed pure-attribute `FILE_OPEN_REPARSE_POINT` form. Do not broadly expand native-routing eligibility.
- Exact current attached tuple; cleanup evidence; no ambiguous attachment/allocation/delete state. For the new closing-phase wait, zero shares/FileObjects and NULL cache/data/image-section pointers, rechecked during waiting.
- One pin and one deadline through rename, op19, read-only backing reopen and exact seal ACK. Stop at usable **ReadOnly + Sealed**, or explicitly readmit changed state.
- Ordinary security, sharing, attachment, backing DeletePending and seed-export checks still decide the open.

That increment need not wait for inspection/publication or introduce foreign-name arbitration. It **cannot be promised to fix the measured one-FileObject Word case**: the conservative predicate may exclude it. Capture the actual blocker before widening the patch. Keep foreign publication waiting as a separate coherent increment with its outcome protocol and dispatch retry mechanism.

For that later increment, the privacy argument must be explicit: foreign requests never bind to another owner’s backing; publication observation only triggers fresh admission; native NTFS checks the current public object; staged writers obtain their own caller-authorized version. Changed tuples, failed inspection, timeout and uncertain publication confer no authority. Empty files use the same ordinary path.

The proposed controls are necessary but insufficient. Add deterministic controls and corresponding mutants for:

- Already-public but retained/detached versions; Released while pinned; Retired-by-discard versus published.
- Blocked with a long justification window or failed hand-back; cancellation/discard during waiting; uncertain publication after service loss.
- A contender appearing between preflight and epoch acquisition, between settlement and allocation, and on either rename name.
- Duplicated handles, mappings surviving handle close, cache-held objects, outstanding MDL/paging work, and incompatible handles on the old public destination.
- Service publication re-entry while the journal gate is held; cancellation, unload and instance teardown with active waiters.
- Actual ACL/share denial after successful settlement, impersonated callers, append-only/unreadable seeds, real reparse points, unsupported request forms and empty files.

**Essential missing negative control:** hold publication before inspection completes, issue foreign read and append requests, then Block the version. Neither may receive its private bytes or report successful publication, and both must stop waiting promptly when the exact Blocked outcome becomes available. Repeat over an existing approved file and a never-published name.

Host controls should exercise the production decision logic and verify actual ownership of epochs/fences/reservations throughout the wait. A counter saying “no epoch before waiting ended” does not prove there was no fence or late admission race.

**Conditions before the first VM boot**

- Review the actual coherent kernel patch before any first boot, using the required Sol 6.1 high reviewer. This design verdict does not accept an implementation.
- Pass both feature Debug/Release WDK builds, PREfast and ApiValidator with zero warnings/errors, plus import availability for both. Service/protocol changes require focused controls and the four-leg agent delivery matrix. Harness changes require PowerShell 5.1 parsing/signature checks and relevant self-checks.
- Use committed source, fresh labels and recorded matched artifact hashes. Follow the current status plan’s T9 ordering. Keep budget-off results explicitly diagnostic/isolation results.
- Boot only `win10-debug3` with `SAFEUPLOAD_DEBUGGEE=win10-debug3`, the approved disposable overlay procedure and separate restoration verification; keep `win10-debug2` off.
- Begin under Verifier with deterministic progress/privacy controls and independent byte observations. Then run Search-enabled application parity, preserving native denied-operation controls and the remaining metadata failures.
- Distinguish private drain blockers from native publication-sharing blockers in the 1/9/11-second tests. Native publication currently has six attempts with 3.1 seconds of scheduled backoff (`StagedPublicationRetry.cs:12`); a nine-second native blocker can exhaust that retry policy before the driver’s wait expires. The wait alone cannot promise success there.
- Record exact waited tuples, phases, outcomes, elapsed time and pin balance. Stop on required failed assertions, repeated identical failures or changed baselines. Keep review acceptance, focused runtime evidence and ordinary/runtime-/boot-Verifier pair qualification as separate results.