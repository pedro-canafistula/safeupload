# T4: disposal completion and inert stream-context retirement

Follow-up: [CREATE leases and reopen regression candidate](UX-LEAK2.md). The
event-wait protocol below is historical; Word regression native validation is
open.

2026-10-16, `ux/leak`, base `54e0efd7`. Implementation/review input; not a
Windows build or protected-pair qualification receipt.

The supplied `uxk8t4ord-samples-at-stop.jsonl` has zero stage versions/views at
every sample and a near-constant writer registry. SUfl grows by about 224
bytes per net outstanding allocation (223.900 across the endpoints). Stream contexts use SUfl; registry,
native, publication and stage records have separate tags. Pool aggregates do
not by themselves identify individual FILE_OBJECTs or prove a reference leak.

Two distinct retirement problems are addressed:

1. After the driver deletes an approved stage, `RequirePrivateStagePath` queries
   the absent leaf before the exact absence/disposal path can run. The exception
   is caught, leaving StageDeleted false forever. Publisher maintenance walks
   hot Released manifests on every pass; each sends DISPOSE, so DisposeNotHeld
   counts calls, not items visited in a kernel scan. History-sized hot sets give
   quadratic cumulative calls. Validate all existing ancestors as before, allow
   only a missing leaf, then keep the exact no-follow delete/absence check and
   journal version/state/rename checks. Archive only after durable completion.
2. Ordinary registry prune already proves the original live incarnation
   (identity/context/MM plus locked sequence/obligation recheck), or original
   natural Ended. It drops the cache and last witness binding, but leaves the
   now-inert Filter Manager stream context attached to each filesystem-retained
   stream. Unique hand-backs and journal files can retain these beyond a save.
   Removing hot manifests alone cannot bound that population.

After successful ordinary prune and cache/witness release, a resident helper
rechecks under RegistryLock -> WriterLock: the entry is retired/unlisted, the
context has the explicit pruned-cache receipt, no cache entry or witness, no
writer node, no untracked writer, no invalid lifetime and no global Unknown.
It irreversibly fences that exact context as retired. Only after dropping both
locks does it call FltDeleteContext on the already pinned context. Outstanding
references retain memory normally; the worker releases its pin as before.

This deletes an inert cache, not a live lifetime witness. It never publishes
Ended, clears Unknown, forces MM state, retires an unresolved entry or opens a
replacement to obtain original-incarnation evidence. Diagnostic deletion of a
live context still invalidates first. No time-based expiry or new list exists.

Rebinding and retirement serialize under WriterLock. BindLifetime and every
node insertion reject fenced contexts. The sole retiring worker deletes the
context and signals its per-context event while retaining its pin. Get/create
waits for that event at PASSIVE with no caller lock held, then retries lookup;
post-CREATE also retries if fencing won between
lookup and binding. A successful bind raises NonRetiredBindings, preventing
fencing until that entry itself passes ordinary prune. The CREATE reservation
keeps its entry from being pruned during this interval. A snapshot holding an
old context reports Unknown after fencing, never a stale zero writer count.
OriginalContext consumers continue to require the original witness. Unknown
writer fallback cannot insert into a fenced context and keeps tracking loss
sticky if it cannot record a node. No allocation, I/O, wait or Filter Manager
call occurs under WriterLock; context deletion is outside RegistryLock too.
The existing explicit-delete diagnostic claims deletion by invalidating under
the same WriterLock: invalidation winning vetoes ordinary detach; fencing
winning refuses diagnostic deletion. Concurrent diagnostic requests also have
one deletion owner. The event adds resident bytes per live context (the exact
WDK sizeof/pool bucket must be measured); the old 224-byte observation must not
be reused as the revised allocation size.

Required interleavings: bind before/after fence; lookup before fence; detached
old reader alongside a new writer; sibling witness bindings; each Unknown,
H/W/T, reservation, transaction, section, spill and owner veto; late old worker
after new-context attachment; delayed cleanup and mandatory teardown. Host
controls execute production decision bodies but cannot establish Windows MM,
Filter Manager or IRQL behavior. Independent review and feature Debug/Release
WDK/PREfast/ApiValidator/import gates precede the first VM boot. Unchanged T4
10k ordinary/runtime-/boot-Verifier rows and restoration remain required.

API contract: [FltDeleteContext](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltdeletecontext)
removes the exact context from lookup, preserves the caller's reference, and
defers memory release until all references end (IRQL <= APC_LEVEL).
