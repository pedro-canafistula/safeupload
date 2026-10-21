# Retirement follow-up: CREATE leases and immediate reopen controls

2026-10-16, `ux/leak`, base `429e7fa9`. **Reviewed repair candidate; the reported
Word regression is not yet diagnosed or demonstrated fixed on Windows.**

The owner bisected the Word read-only/read-open regression to `90a908c7` on
win10-debug3: reader access `0x120089`, FILE_OPEN, STATUS_SHARING_VIOLATION for
about 40 seconds after publication; reverting at `85e89b7f` succeeds. The kernel
retirement code in `90a908c7` and this branch's `429e7fa9` is identical.

The previous fix adds no public backing handle, FILE_OBJECT reference, section
or share-access record. Its new wait is in `SafeUploadGetOrCreateStreamContext`,
called during successful physical post-CREATE: Windows has already accepted the
FILE_OBJECT/access/share state, but the caller cannot finish opening until the
retiring worker detaches and signals. That new scheduling dependency is removed
here. It is a plausible cause, **not a proved explanation of the 40-second
receipt**. The shared inspection cache is also evicted by ordinary retirement;
that performance effect remains.

The reported deny-ring line is more specific than a generic NTFS share error:
`SafeUploadStageDispatch` logs errors the driver completes itself. A reader with
no private view normally takes `StageMvpNamespacePre`'s native path. Its success
cannot establish that the original writer's private view is usable. Exact
StageCreate refusal-site detail is still needed to distinguish namespace fence,
seal/rename pending, delete-pending backing, nested query and synthetic share
access. No public handle owner has been identified from the supplied line.

## Candidate change

Replace the per-context detached event and post-CREATE retry/wait with explicit
active-use leases and a short association turn:

- Lookup/set holds Association shared only through obtaining the context and
  incrementing its lease under WriterLock. Allocate context/token outside it.
  All three get/create clients release through `SafeUploadReleaseStreamContext`;
  raw snapshots, cleanup lookups and worker proof pins remain ordinary refs.
- After the existing exact identity/context/MM proof, the worker takes
  Association exclusive **before pruning**. An active lease vetoes unlink.
  Keep that turn through locked prune, cache/witness release, fencing and
  `FltDeleteContext`; release it before final context/entry/instance references.
  Lock order is Association -> RegistryLock -> WriterLock. The worker pin
  prevents its context cleanup callback during deletion. Cache/witness drops
  are asserted nonfinal: worker pins Entry; Entry retains its witness.
- Last lease release requeues the existing reclaimer after dropping WriterLock.
  A vetoed entry stays listed, so there is no stranded pruned context, pending
  detach list, new timer or poll. Binding cannot race ordinary fencing.
  Counter underflow invalidates and records sticky tracking loss, never repairs
  a count or supplies retirement evidence.

This preserves the original live/Ended proof, H/W/T, reservation, TxF, section,
Unknown, teardown and exact-context delete-owner checks. Explicit deletion
still never supplies natural Ended. The absent-leaf disposal/archive fix is
unchanged. The lease does not create object authority or clear Sticky Unknown.

Association pushlock contention remains possible while Filter Manager unlinks
an inert context. Removing an event does not prove that NTFS/Filter Manager
internal lock schedules are qualified. No new kernel API names were added;
actual import validation remains required. New resident helpers repeat SAL;
the PAGE getter/binder pragmas precede their definitions.

## Controls and next native observation

The host C controls execute the production getter, lease, bind, cache/witness
release, idle and fence decision bodies: 10,000 retirements; allocation/set
races; final-reference lock placement; lease veto and last-user requeue;
sibling/Unknown/diagnostic cases; compiled negative mutations. They do not
model NTFS internals or demonstrate the Word failure before/after this change.

`T4_IMMEDIATE_REOPEN=yes` on the existing `Invoke-StageCycles.sh` adds an
additional control. Before each clean save, the actor prestarts a second process
under its own token. After SYSTEM independently observes that cycle's unique
approved public bytes, it signals both processes. The original writer attempts
read and read/write opens once; the child attempts both once and reads the
expected bytes. No sharing failures are retried. PIDs, native errors, file IDs
and QPC times are retained in `reopens.jsonl`. Child ownership lasts through bounded joins,
including abort/kill paths; unconfirmed termination explicitly fails the row. Existing T4 assertions and pool thresholds stand.
The extra read/write opens themselves exercise staged follow-up lifetimes.

New deny reason 17 preserves the refusal and encodes StageCreate's gate in Aux
bits 7:0, ReadOnly/Sealed/Rename in 10:8, FileObjects in 31:16. Gates 1..10 are
listed in Protocol.h. Gate 0 means another propagated sharing status. A refused
readmit after eight attempts may still have no StageCreate sharing detail.
The ring size/wire layout and existing reason values are unchanged.

Before a target boot: feature Debug/Release WDK, PREfast, ApiValidator and import
gates; Windows PowerShell 5.1 gate (includes the new positive/exclusive-negative
native helper self-check). Then same-owner/Word and cross-process reopen on
win10-debug3, precise deny-gate capture if it fails, and unchanged one-boot
10,000-save ordinary/runtime-/boot-Verifier rows plus separate restoration.
The T4 fixture uses its existing .txt saves; actual Word/.docx reproduction is
separately required. Source review and Linux host controls are distinct from
those results.
