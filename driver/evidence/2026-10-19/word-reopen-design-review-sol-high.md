# Independent review: Word owner-read reopen settlement

2026-10-19 — **gpt-6.1-sol, high**; independent reviewer, not the proposal's author.
Reviewed [proposal](word-readonly-gate-analysis-sol-high.md), current owner decisions,
T4 lifetime design and actual driver/agent source. Checkout observed at
`1d9420eb0fc5ed274ab16aec1994554b5b2754a6`; `git diff f8e99d25 --
driver/SafeUpload.Minifilter/StageStream.c` is empty. Agent reference is the
reported dev pair `c1a3ba04`; this review inspected checkout source, not deployed
binaries. No product/harness edit, build, builder job, VM action, commit or push.
The running `m2t4smoke1019a`/10k priority is unchanged.

**Verdict: REVISE the proposal's mechanism claims; the conservative candidate
below is suitable to implement and then review as one coherent patch.** This is
design review, not implementation acceptance or pair qualification.

## Findings

1. **The diagnosis is supported; the progress precondition is not yet proved.**
   Gate 6 refuses unresolved rename or ReadOnly-but-unsealed versions
   (`driver/SafeUpload.Minifilter/StageStream.c:2616`). The existing helper waits
   on op19 and ReadOnly-but-unsealed, not rename or the earlier closing phase
   (`:5276`). Rename locally retargets the name and returns while COMMIT may
   remain pending (`:5694`, `:5702`). Adding rename alone leaves a window after
   ACK in which a new reader prevents drain. However, zero FileObjects from the
   diagnostic is not affirmative no-mapping/no-MDL/no-lazy-cleanup proof:
   `StageDrain` separately checks shares, truncatability, cache/section pointers
   and paging rundown (`:6233`–`:6248`). The proposal's lines 94–96 overstate the
   evidence when they infer an independent drain path from the observed zero
   counter. No recorded sections/rundown observation closes that condition.

2. **No new CREATE epoch/registry-lease cycle exists on a strictly pure-read
   route; correct the contrary statement.** The proposal's lines 64–66 say this
   CREATE owns an admission epoch. `StageEpochOperation` excludes FILE_OPEN
   read/query access with no mutation/security rights (`:10084`–`:10099`), and
   dispatch bypasses epoch acquisition (`:10970`). Writer-registry reservation
   runs only after `StageAdmit` returns native (`:10618`); a private read completed
   by `StageCreate` never reaches it. The wait must remain before upper binding,
   share insertion and FileObjects increment (`:2879`, `:2899`, `:2921`). Do not
   reuse the broad eligibility predicate as proof of pure access: existing
   routing can demote mutation-bearing FILE_OPEN requests to `writer=FALSE`
   (`:9305`–`:9309`). Eligibility must inspect the original DesiredAccess and
   options. Mutation-bearing requests can own epochs and are excluded here.

3. **The exact pin works, but it is not authority or a ready predicate.**
   `RpcReferences` prevents stream release (`:6537`), which also keeps its view
   and referenced owner alive until release (`:6564`–`:6570`); it does not stop
   drain (`:6230`). The worker's rename→op19→drain→seal chain does not test this
   pin (`:6580`, `:6600`, `:6659`, `:6918`). COMMIT legitimately changes
   DestinationGeneration only through the typed receipt (`:5113`–`:5145`).
   Store copied identity/transaction values, not an exchange pointer to
   dereference after ACK frees it (`:5160`). Every check must require the same
   referenced owner, instance, original requested name, attached view generation,
   current stream, transfer/stage/driver identity and applicable rename lineage.
   A changed current stream, detached view, retarget, successor, delete or new
   exchange goes through full readmission; it must not be silently adopted as
   the waited version. A pin cannot prevent legitimate disposal/retirement.

4. **Cancellation/teardown/deadline behavior needs explicit implementation,
   not merely reuse of the void helper.** Existing polling only checks
   cancellation before it starts (`:9406`), starts a fresh ten-second deadline
   each call (`:5272`), and allows eight admission attempts (`:9453`). Its op19
   busy terms ignore StageStopping, so adding another busy term is insufficient.
   Mandatory teardown independently latches before namespace acquisition
   (`:7995`), stops workers (`:8012`), and waits for RpcReferences to reach zero
   (`:8064`). A waiter must observe that latch, cancel/service-loss/readiness
   failure and unload closure, drop its one pin locally, and complete refused;
   it must never need a stopped worker or service ACK to release the pin.
   Keep one interrupt-time deadline outside Readmit and return a typed outcome
   (settled/readmit/conflict/cancel/not-ready), with a cancellation check before
   eventual binding as well. Existing `StageCreate` has another cancellation
   check at `:2866`. A polling budget bounds intentional delays; it is not a
   hard ten-second I/O deadline because resource acquisition and existing native
   drain operations can block (`:6238`–`:6247`). Report that limit accurately.

## Smallest acceptable implementation candidate

- Add a dedicated predicate for the **observed unbound owner route** first:
  IRP CREATE, PASSIVE_LEVEL, local fixed NTFS, no TxF/top-level IRP, FILE_OPEN,
  default stream, no EA payload, read/query/synchronize access only after proper
  generic-access handling. Exclude MAXIMUM_ALLOWED and every mutation/security/
  delete right. Permit FILE_OPEN_REPARSE_POINT only for the already-resolved exact
  non-reparse private object; retain normal reparse/identity and unsupported
  options gates. Do not broaden `StageMvpNamespaceCreateEligible` or native
  routing (`:9066`). The flag currently excludes observed metadata probes there.
- Under namespace→stream resources require the exact current attached tuple,
  cleanup observed, no unresolved attachment/allocation, no deletion/cancellation,
  zero app shares and FileObjects. For a **new pre-ReadOnly wait**, conservatively
  require SharedCacheMap, DataSectionObject and ImageSectionObject all NULL.
  This concrete predicate avoids guessing whether a remaining section is an
  app mapping or transient cache state. If it excludes an observed Word case,
  obtain mechanism evidence before broadening it. Do not initiate an app-lifetime
  wait when these checks fail; preserve existing routing/refusal. Keep the worker's
  full flush/purge/PagingRundown barrier, including partial-MDL completion
  (`:5755`–`:5759`); the waiter must not run or replace that barrier itself.
- Pin once and queue, release resources, poll/check only while the captured work
  remains independently progressable. Recheck lifetime exclusions each pass;
  an active handle/section appearing later terminates this special wait. Wait
  through rename, op19, local ReadOnly reopen and exact seal ACK; require
  ReadOnly+Sealed and a usable backing for the original tuple, or explicitly
  readmit current state. Never treat “not busy”, timeout or RPC refusal as ready.
  Drop the pin once under NamespaceResource and queue only when teardown allows;
  clear transient view pointers on every exit.
- Re-enter ordinary `StageCreate` authorization/share/attachment/delete-pending
  checks (`:2595`, `:2607`, `:2627`, `:2880`). Do not export backing handles,
  grant READ_DATA because the owner/service can write/read, bypass seed provenance,
  or alter blocked-save policy. Original effective-subject checking is in
  `driver/SafeUpload.Minifilter/StageSecurity.c:268`; it is not itself proof of
  the whole seeded read/export contract. Owner option 1 remains required
  (`driver/POST-MVP-PLAN.md:365`). This review does not certify unfinished seed
  provenance machinery merely because the increment preserves existing checks.

The source chain supports settlement without publication: exact rename COMMIT
records journal state without an application callback
(`agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs:2565`),
and ordinary seal measures and durably records the exact stable stage
(`:2247`–`:2335`);
`agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs:1297`
returns its ACK before content inspection/publication. Never wait for inspection,
publication, disposition ACK, global callback rundown, app close/unmap or final
version release. Even without an epoch, waiting for final release would cycle on
the waiter's own RpcReferences pin. Finite contention/native I/O failures remain
possible; source dependency analysis supplies no Word latency guarantee.

## Conditions before declaring the repair accepted

Review the actual coherent patch for original-access classification, exact tuple
transition and one-pin balance on every exit. Focused controls must distinguish
delayed rename/op19/pre-ReadOnly/seal, exact metadata/reparse probes, concurrent
readers/successor/retarget/delete, active mapping/MDL/paging/lazy cleanup,
cancel/service-loss/mandatory teardown, native share/security denial and unreadable
seeded data. Prove no wait requires the blocked caller to close/unmap, no foreign
process gains private bytes, no deadline multiplication and no retained pin/cap
leak. Then repeat real standard-user Word SaveAs/edit/save/reopen with independent
bytes and Saved/ReadOnly observations, recording owner-file failures separately.
Required WDK/static checks and ordinary/runtime-/boot-Verifier matched-pair gates
remain separate from this design result.
