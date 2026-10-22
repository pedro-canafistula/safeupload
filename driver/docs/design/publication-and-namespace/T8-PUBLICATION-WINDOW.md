# T8: publication window — operations on a name with an in-flight publication wait instead of failing

2026-10-22, revision 2. **Proposal for independent review; no implementation.** Owner approved the rule in principle on 2026-10-22 ("Yes", decision 1 of
[T8-CLOSURE-PLAN.md](../T8-CLOSURE-PLAN.md): bounded wait, proposed 10 s). Revision 1 was reviewed
([REVISE](../../../evidence/2026-10-22/t8-pubwindow-review-sol-high.md)); this revision answers its findings. Earlier work:
[owner-reopen analysis](../../../evidence/2026-10-19/word-readonly-gate-analysis-sol-high.md) and its
[review](../../../evidence/2026-10-19/word-reopen-design-review-sol-high.md). Evidence: [discovery 1](../../../evidence/2026-10-22/t8-discovery-1.md),
[stuck versions](../../../evidence/2026-10-22/t8-stuck-versions-1/).

## Problem and user result

After a save closes, the new version needs about a second (longer with an indexer or scanner) before it is the public file. Native semantics break meanwhile:

1. The **saving process** reopens or renames the name and gets `STATUS_SHARING_VIOLATION` (gate 6: `RenameExchange` pending or `ReadOnly && !Sealed`; ring `reason 17`,
   aux `0x00010406` = gate 6, rename pending, one counted FileObject). Word then reports "file permission error" or reopens read-only.
2. **Another process** has no private view (views are keyed by the requestor `EPROCESS`, `StageFindView`), takes the native path, and the name does not exist yet:
   `FILE_NOT_FOUND`. An `OPEN_IF`/append from that process creates a **new** file: `echo a > f` then `echo b >> f` lost `a` (`txt-cmd-ops`).
3. A rename of the just-published file (Word's swap) is refused while the previous version drains.

Required result: every operation the control folder accepts is accepted in the protected folder, possibly after a short wait; nothing sees an uninspected byte; nothing
is lost. After the bound the operation is **explicitly refused** with the status it gets today on that route (never a fall-through to a missing-name create).

## What is measured and what is not (answering review finding 8)

- Gate 6 with `0x00010406` proves: the stream has a pending rename exchange and one counted upper FileObject. It does not identify the object's owner and does not
  prove that object prevents the rename COMMIT (RPC collection and reply application do not require FileObjects to reach zero; drain does).
- With Windows Search stopped, `word-inplace`, `word-saveas-edit` and `txt-lifecycle` pass every step and with it running they fail: the indexer's open matters, but exact
  stream/object attribution is not captured. Those runs are not parity PASS (metadata deltas remain).
- `word-overwrite` fails deterministically with and without the indexer, and also when the memory manager is forced to trim cached sections between the saves (3 of 3,
  `t8sweep-v3trim*`). Restart Manager shows no process handle on the file for 40 s.
- Versions of Word's saves stay live in the driver **after Word exits** (liveVersions 5, liveViews 4, 9 journal entries `Retained`, service log "Cancelled stage cleanup is waiting
  for its exact handles") and retire only after memory pressure with no Office process running (`t8-stuck-versions-1`). So a lingering upper FILE_OBJECT held outside any
  process handle exists, plausibly the memory manager's reference through a mapped or cached section. It keeps a version live for minutes. A 10 s wait cannot fix that.
- Per-case ring files hold older entries; a refusal is attributed to a step only by timestamp and name (`ring-txt-lifecycle.ndjson` `lc2.txt` entries carry sharing violations
  without the gate-6 aux).

Consequence: this design is **three increments**, in order, and none is promised to repair the measured Word overwrite until its actual blocker is captured.

## Increment 0 — capture the blocker (diagnostic, dev loop)

A read-only diagnostics query `stage-streams` (driver snapshot relayed by the service like `counters`): per live stream, bounded to 64: normalized name tail, transfer id, flags
(Sealed, ReadOnly, RenameExchange, Retired, Detached, MvpPublicationObserved, DiscardOnClose), FileObjects, ShareAccess.OpenCount, `Sections` pointers non-NULL, handle count,
RpcReferences, view owner PID. No behaviour change, no authority. Needed to decide the predicates below and to attribute the lingering FileObject.

## Increment A — conservative owner reopen (the 2026-10-19 candidate)

Smallest coherent patch for same-process probes after a rename (`copy-within`, `Test-Path`) and a Word reopen of a settled version:

- A dedicated predicate for an unbound owner read/query CREATE (access and options as originally requested, including the pure-attribute `FILE_OPEN_REPARSE_POINT` form
  `0x01200000` that `StageMvpNamespaceCreateEligible` excludes today). The routing predicate is **not** widened.
- Exact current attached tuple, cleanup evidence, no ambiguous attachment/allocation/delete state. For the closing phase: zero shares, zero FileObjects, NULL cache/data/image
  section pointers, re-checked during the wait.
- One pin and one per-operation deadline through rename → op19 → read-only backing reopen → exact seal ACK; stop at usable ReadOnly + Sealed, or re-admit on a changed tuple.
- Ordinary security, share, attachment, backing DeletePending and seed-export checks still decide the open. No wait for inspection or publication, no foreign arbitration.

It may not fix the one-FileObject Word case (the conservative predicate can exclude it). Increment 0 decides.

## Increment B — foreign publication wait

Applies to any process touching a *pending name*, after Increment A.

**Exact outcome protocol (finding 1, 2).** `Retired` is not publication (blocked-stage deletion and acknowledged discard also set it) and a normally published version reports `Disposed`
with `RELEASED` without setting `MvpPublicationObserved`. Add an authenticated, exact-tuple (transfer, driver instance, generation, destination binding, rename lineage) outcome
observation the service sends to the driver, with four values: **Published**, **AttemptEndedWithoutPublication** (Blocked, acknowledged cancellation, acknowledged discard),
**Uncertain/Held**, **TupleChanged**. The driver stores it on the stream; an accepted Released disposal supplies Published for its validated lineage. It is never permission to open
whatever occupies the path: after Published the open runs full admission and native checks against the current public object; after AttemptEnded the open re-admits (previous
file or absence); Uncertain keeps waiting until the bound and refuses. Blocked must stop waiting promptly (the service records Blocked before hand-back; the notification is new, not
the later CleanedUp disposal). Blocked may later be justified: "this attempt ended" authorizes no later attempt and erases no retained evidence.

**Placement (finding 3).** A dispatch preflight **before** ordinary epoch acquisition (`SafeUploadPolicyAdmissionAcquire`), then a re-validation at the protected admission or mutation
decision, because another process can install a pending version in between. A late conflict returns an internal *retry-to-dispatch* outcome that unwinds the epoch, any
reservation and fence, and reconsiders outside them (`StageAdmit`'s local `Readmit` loop does not release the outer epoch).

| Route | Placement |
|---|---|
| pure read/query CREATE | before binding/share insertion |
| writer or other mutating CREATE | before epoch acquisition, not inside `StageAdmit` |
| native DOC CREATE | before epoch acquisition and before `StageMvpNamespacePre` installs its fence |
| owned rename/delete SET_INFORMATION | before epoch acquisition; waiting inside `StageRename`/`StageSetDisposition` is too late |
| native rename/delete SET_INFORMATION (both names for rename) | before epoch acquisition and before `StageNamespaceBeginMutation`; the physical-rename fallback reaches that fence again |

The unbound and bound profiles differ (`StageBoundPublication.c:651` zero-active-epoch requirement is bound-only); ordering is proved for the shipped unbound profile and policy-swap safety
is preserved.

**Service progress is exempt (finding 5).** The authenticated service's own publication operations (destination observation, native commit under the journal gate, receipt rename) keep
their existing permit and operation checks and never wait; SYSTEM identity alone is not an exception. No wait runs on the stage worker, attach worker or service receive path, and none
holds a namespace/stream/spin lock, fence or registry reservation; cleanup, CLOSE, unmap progress, paging/MDL completion and cache callbacks stay runnable; no wait for global callback
rundown or final version release; mandatory teardown releases waiter pins locally after its latch.

**Blocker test (finding 4).** The requestor-holds-blocker test cannot be exact from `STAGE_HANDLE` (it has grants, cleanup, writer lease, byte-lock owners; no inventory of handle or
section owners; duplicates share the file object). Use the conservative predicate: wait only when zero shares/FileObjects and NULL section pointers can be reached **without** the
requestor, and never claim independent progress where ownership is unknown. A SET_INFORMATION request keeps its source handle through the wait; preserve its identity and grants, never
redirect it to a newly published same-name object, and keep today's result where an owner open against an active private version succeeds now.

**Foreign append (finding 6).** Sequence for `alpha` then a foreign append: observe Published for the first version; re-enter ordinary writer admission with the second caller's original
request; seed its own new private version from the freshly checked public object; append at the seeded EOF; inspect and publish that generation normally. The second process never gets the
first owner's view, predecessor stage or authorization. Re-check all same-name contenders and allocation reservations before committing admission; a replacement between publication
observation, security capture and seeding forces normal identity validation (retry or refusal). Dispositions keep their meaning (CREATE collides after publication; OPEN/OVERWRITE require
existence; OPEN_IF seeds when present; truncating dispositions truncate); append-only grants and unreadable-seed read/export restrictions are unchanged. **On timeout the pending conflict is
refused** with the route's existing status (sharing violation for CREATE and rename, never a missing-name create).

**Deadline and outcomes (finding 7).** One monotonic 10 s deadline per original operation, carried through every retry and both rename names; typed internal results: Settled,
ChangedRetry, TerminalWithoutPublication, Timeout, Cancelled, NotReadyTeardown. Capture owner, instance, view generation, transfer/stage/driver identity, destination binding and rename
lineage; copy exchange values (never dereference one after its ACK frees it); accept a COMMIT generation change only through the existing validated apply path; drop each pin exactly once;
re-check cancellation and readiness before binding or forwarding. Ten seconds bounds the polling, not total I/O. Native publication retries six times with 3.1 s scheduled backoff
(`StagedPublicationRetry.cs:12`); a 9 s native blocker can exhaust it before the wait expires, so the wait alone cannot promise success there.

## Increment C — retirement independent of CLOSE (investigation first)

If Increment 0 confirms a memory-manager-held upper FILE_OBJECT, the lifetime rule "FileObjects == 0" keeps versions, backing files, journal entries and budget charge alive for
minutes and blocks gate 6 for that name (T4 qualified retirement with Notepad only). The candidate: separate **namespace detach** from **backing close** — a sealed read-only version
with cleanup done, no handle, no user mapping (`MmCanFileBeTruncated`), no writable section and the paging rundown released can detach its view and let the name resolve to the public
file while the backing stays open until the last CLOSE. Not a shortcut for missing lifetime evidence: it needs its own design and review, and must keep sticky Unknown, the
no-forced-deletion rule and the section proof of T11. Not specified here.

## What this does not fix

Folders (owner decision 2026-10-22: not now), SYSTEM ownership and attributes (metadata contract), budget-on allocation (T9; the first fix), a block held by the waiting process itself,
inspection longer than the bound.

## Controls

Deterministic host controls and mutants for: already-public but retained/detached versions; Released while pinned; Retired-by-discard versus Published; Blocked with a long
justification window or failed hand-back; cancellation/discard during the wait; uncertain publication after service loss; a contender between preflight and epoch acquisition, between
settlement and allocation and on either rename name; duplicated handles, mappings surviving handle close, cache-held objects, outstanding MDL/paging work, incompatible handles on the old
public destination; service publication re-entry while the journal gate is held; cancellation, unload and instance teardown with active waiters; actual ACL/share denial after settlement,
impersonated callers, append-only and unreadable seeds, real reparse points, unsupported request forms, empty files. Host controls exercise the production decision logic and verify actual ownership
of epochs, fences and reservations throughout the wait.
**Essential negative control:** hold publication before inspection completes, issue foreign read and append requests, then Block the version: neither receives private bytes or a success, both stop
waiting promptly when the exact Blocked outcome arrives. Repeat over an existing approved file and a never-published name.
Windows: the parity catalog with Windows Search **running**, a deliberate foreign handle held 1, 9 and 11 s (separating private drain blockers from native publication-sharing blockers), counters for waits
entered/settled/bound-hit/skipped; independent byte observation; Verifier first, then ordinary.

## Delivery

Order inside T8: T9 allocation first (owner order), then Increment 0, A, B, C as the evidence allows; each kernel increment reviewed as a coherent patch before its first boot; feature WDK
Debug/Release builds, PREfast, ApiValidator and imports at 0 warnings / 0 errors; four-leg agent matrix for protocol changes; PowerShell 5.1 checks for harness changes; `win10-debug3` only;
committed source and recorded matched hashes; budget-off results stay labelled diagnostic.
