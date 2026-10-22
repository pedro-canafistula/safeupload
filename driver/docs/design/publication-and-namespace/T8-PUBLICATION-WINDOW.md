# T8: publication window — operations on a name with an in-flight publication wait instead of failing

2026-10-22. **Proposal for independent review; no implementation.** Owner approved the rule in principle on 2026-10-22 ("Yes", decision 1 of
[T8-CLOSURE-PLAN.md](../T8-CLOSURE-PLAN.md): bounded wait, proposed 10 s). This note makes it concrete. It extends the 2026-10-19
[owner-reopen analysis](../../../evidence/2026-10-19/word-readonly-gate-analysis-sol-high.md) and its
[review](../../../evidence/2026-10-19/word-reopen-design-review-sol-high.md) (REVISE; the conservative candidate there is the first step of this design).
Evidence: [discovery 1](../../../evidence/2026-10-22/t8-discovery-1.md) (`t8sweep-v1full`, `v2nowsearch`).

## Problem and user result

After a save closes, the new version needs about a second (more with a busy indexer or scanner) before it is the public file. For that time native Windows
semantics break:

1. The **saving process** reopens or renames the name and gets `STATUS_SHARING_VIOLATION` (gate 6: `RenameExchange` pending or `ReadOnly && !Sealed`, ring
   `reason 17`, aux `0x00010406`). Word then reports "file permission error" or opens the document read-only.
2. **Another process** (a child `cmd`, `icacls`, `robocopy` re-run, Explorer) finds no private view for it (views are keyed by the requestor `EPROCESS`,
   `StageFindView`), takes the native path, and the name does not exist yet: `FILE_NOT_FOUND`. An append from that process creates a **new** file, losing the
   first write (`txt-cmd-ops`: protected `c1.txt` = `beta`, control `alpha`+`beta`).
3. A **rename** of the just-published file (Word's save swap) is refused with a sharing violation while the previous version is still draining.

Required result: for every operation the control folder accepts, the protected folder accepts it too, possibly after a short wait; nothing sees an
uninspected byte and nothing is lost. After the bound the operation fails exactly as it does today (no new status code).

## Evidence that the blocker is often a foreign handle

With Windows Search stopped, `word-inplace`, `word-saveas-edit` and `txt-lifecycle` pass every step (v2nowsearch); with it running they fail
(v1full). The indexer opens each new file; a counted `FileObject` keeps the rename exchange from committing until it closes (a second or two).
`word-overwrite` still fails without the indexer (gate 6 on a document Word closed 4–8 s earlier; Restart Manager shows no handle holder 1.6 s after the
close, but the stage worker still reports an extra live version/view 10 s later), so the cause there is a lingering upper `FILE_OBJECT` or section, not a handle
a process can be asked to close. **The wait cannot fix a block that only the waiting process can release** (its own handle or mapping).

## Rule

Define *pending name* `N` on instance `I`: a live, non-retired stream with `Name == N` whose version is not yet public (`!MvpPublicationObserved`, not
`Retired`, not `Discarded`, not `PrivateCancellationAccepted`), or whose `RenameExchange != NULL`, or `ReadOnly && !Sealed`.
An operation `O` that touches `N` (CREATE of any intent; SET_INFORMATION rename/delete source or target; native DOC open/delete/rename) by **any** process
applies this decision, in order, before any epoch, admission slot, namespace mutation fence or reservation is taken:

1. No pending name: unchanged.
2. The requestor holds the blocker (any handle, section or `FileObject` of the requestor process on the pending stream: per-handle owner tuple already
   exists): **unchanged behaviour** (today's refusal). No wait, because the wait could never end.
3. Otherwise wait, outside every lock, in 10 ms steps on one monotonic 10 s budget, for **exact settlement**, never elapsed time:
   the pending name stops being pending because (a) the stream reached `Retired`/public-visible after the service's publication, or (b) it reached a terminal
   state that publishes nothing (Blocked, cancelled, discarded: then return the native result at once, which is "not found" for a never-published
   name — never a wait for a version that cannot appear). A bound hit, cancellation, teardown, service loss or changed tuple is not settlement: fail as today.
4. After settlement re-run full admission from the top against the **current** state (public file exists, inspected). Nothing is served from the private
   backing to a different process; no handle, share, access or security result is skipped.

This is the same exact-pin discipline as the existing `StageWaitHandleReceiptSettled` (the pin is an `RpcReferences` count, dropped with a queue wake, one
deadline across re-admits). The busy predicate gains `RenameExchange != NULL`, the closing phase (cleanup observed, not yet `ReadOnly`), and
`!MvpPublicationObserved` for foreign requestors. The OPEN_REPARSE_POINT pure-attribute probe (`0x01200000`, `StageMvpNamespaceCreateEligible` excludes it
today) joins, because it is the form READ_ATTRIBUTES probes (`Copy-Item`, `Test-Path`, Word) take.

## Cycles to rule out (the reviewer's main task)

- **Epoch cycle.** Publication drains admission epochs. A mutating CREATE, a SET_INFORMATION and a writer open hold an epoch (`StageEpochOperation`). The
  wait must sit in the dispatch path *before* epoch acquisition (and before `StageNamespaceBeginMutation`, the DOC fence and reservation slots), or release it
  and re-acquire; waiting inside an epoch can never settle. Pure-read CREATEs take no epoch (`StageEpochOperation`, `:10160`).
- **Namespace/stream resources.** The wait holds neither `StageNamespaceResource` nor a stream resource nor a spin lock (existing helper polls with
  `KeDelayExecutionThread` at PASSIVE_LEVEL). Non-PASSIVE, top-level-IRP and transacted requests do not wait.
- **Worker progress.** Settlement needs the stage worker, the service's rename COMMIT/op19/seal ACKs and the service's publication. None may require the
  waiting thread. The 10-19 review found the rename → op19 → drain/seal chain independent of a new reader, but said zero `FileObjects` is not proof of progress.
- **Foreign requestor with its own pending version.** Process A waits for B's version while B waits for A's: both are bounded; both then fail as today.
  The decision-2 check (requestor holds the blocker) removes the same-process case.
- **Inspection time.** Waiting for publication includes content inspection. Large files can exceed 10 s: the operation then fails as today. Whether to
  extend the bound for big versions is a separate choice (T9 throughput is postponed to M4).
- **Write-after-pending.** A writer waiting for foreign publication then re-runs as a normal writer against the public file (a new version seeded from it).
  Appends are therefore never turned into creates of a missing name.

## What this does not fix

Folders (rename/delete of a folder with content, Recycle Bin move into `$Recycle.Bin`) — owner decision 2026-10-22: not now. SYSTEM ownership and attributes
(metadata contract, workstream D). Budget-on allocation (T9). Any block held by the waiting process itself.

## Controls

Host fixture (`namespace_ux_fixture.c` style): pending-name state matrix × operation matrix × requestor identity (same process with/without blocker, foreign
process); epoch non-hold assertion (a counter proves no epoch was taken before the wait ends); exact pin balance; deadline shared across re-admits; mutants
for each predicate term and for the foreign-process path. Windows: the parity catalog (`txt-cmd-ops`, `txt-lifecycle`, `txt-acl`, `word-*`, `robocopy`,
`excel-*`, `ppt-*`) with Windows Search **running**, plus a deliberate foreign handle held 1, 9 and 11 s; counters for waits entered/settled/bound-hit/skipped-own-blocker
in `Get-SafeUploadDiagnostics.ps1 -Query counters`. Existing private-byte refusal for foreign processes unchanged (privacy rows).

## Questions for review

1. Is the requestor-holds-blocker test (decision 2) implementable exactly, including mapped sections and cache-held upper objects, or must it be conservative
   (any live `FileObject` of the requestor process on the stream)?
2. Where exactly is the pre-epoch point for each route (`StageAdmit`, `StageMvpNamespacePre` DOC path, rename/delete SET_INFORMATION)? Is there a route that
   reaches `StageNamespaceBeginMutation` after taking an epoch and so needs a retry-from-the-top?
3. Is waiting for public visibility (rather than for the narrower rename → op19 → seal chain) safe with respect to the inspection and hand-back paths?
4. Does the existing lingering `liveVersions`/`liveViews` after a closed save (counters at rest: 3 versions, 2 views) mean the pending predicate can stay true
   forever for a name that is already public, so the wait would always time out? State the exact terminal conditions to use.
