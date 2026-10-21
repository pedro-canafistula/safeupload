# T9 large files: product defaults and accounted staging

2026-10-16, `ux/large`. Initial base `62fd1673`; product-default/upgrade delta based on `a2b67984`. **T9 is not complete or qualified.**
Claude owns Windows builds and VM execution as standard user `t5actor`. No product VM was contacted here.
The [demo/apps integration](UX-LARGE-INTEGRATION.md) preserves packed journal scaling, allocation-abort fences and sealed metadata.
Read the [qualification list](UX-LARGE-VM.md), [initial local receipt](../../../evidence/2026-10-16/ux-large-local/result.md) and
[product-default/upgrade receipt](../../../evidence/2026-10-16/ux-large3-local/result.md) and
[failed-allocation/notification recovery](UX-LARGE-RECOVERY.md).

## Admission and authority

`Interception:StageSpace:Enabled` defaults to **true** (owner, 2026-10-16). `TotalBytes`, `PerUserBytes` and
`FreeSpaceFloorBytes` default to the approved formulas below, evaluated on the staging volume at service initialization.
Explicit settings override each field; an overridden total also determines the default per-user quarter.
`ParserMemoryBytes` defaults to 256 MiB. `appsettings.json` documents enablement/parser memory; formulas remain runtime code.
The service first obtains an exact four-byte v31 support receipt through authenticated service-SID control 35.
An older driver, a short/oversized receipt, or another version keeps large-mode admission closed.
Runtime activation, V30 and other readiness gates remain unchanged. Large mode refuses bound allocation and
create-after-private-discard; it must not imply qualification of those paths.

Before creating/seeding content, persist a reservation against the exact requester SID and total budget. Charge
four overlapping content copies plus metadata. At admission also subtract outstanding reservations from the live
volume free space above its configured floor. The double subtraction of already materialized bytes is deliberately
conservative. Capacity is the currently available SID share rounded down to both stage and destination allocation
units (at least 64 KiB). There is no fixed per-file size constant on a granted version. A capacity below 16 MiB is
refused: a missing companion can therefore only reduce authority to the legacy guard, never exceed its debit.
Per-user exhaustion is a resource refusal, not a coverage/Unknown transition.

After native CREATE, record the full stage identity before the first seed byte. After manifest allocation, persist
`GrantIssued` before writing a 64-byte service-only `.space` companion or returning the typed create reply. The
companion binds magic/version, capacity, full volume/file identity, transfer GUID and zero padding. The kernel
opens it no-follow, checks one link, exact length and identity, then applies its immutable capacity to backing
open, ordinary writes, EOF and allocation changes. Overflow/alignment checks use signed 64-bit limits. Grant and
initial unbound backing I/O run in the existing attach-owned interval outside namespace/stream/spin resources.
The new completion-status predicate is resident and safe at DISPATCH_LEVEL; grant/name work is PASSIVE/PAGE.
No new kernel DDI/import is introduced. A fresh binary import/PREfast gate is still required.

The explicit disabled profile retains its 16 MiB guard. New product-default allocations have no fixed per-file
staging cap; their immutable capacity comes from SID/total/free-space accounting. Disabling with retained accounting
records still refuses startup: restore enablement to recover. Older-service binary downgrade remains unqualified.
This configuration change does not certify the driver/agent pair or bypass runtime readiness gates.

## Accounting and cleanup

The trusted private ledger is reconstructed before admission. Existing root, reservation directory and records
are checked for trusted ownership/no untrusted mutation before allocator ACL recovery. Reservation DACLs are
protected; JSON is parsed through the same held no-follow, single-link, size-bounded handle whose ACL was checked.
Persisted locators must remain direct children of the private stage root. Corrupt/partial accounting and unknown
objects remain held; there is no filename-only orphan deletion sweep.

Normally retain 1 MiB per transfer and 1 MiB globally for metadata. On larger-cluster volumes, each becomes at least
16 allocation units. At most half the transfer envelope is admitted for journal files, including failed replacement
residue; ledger current/replacement records are each bounded to 64 KiB, the grant is 64 bytes, and the remaining
headroom covers their allocation rounding and private-object MFT/index overhead. Global journal metadata
receives one quarter of the global envelope; refusals are stateless and create no metadata. Legacy refusal files
are charged separately by rounded storage plus per-file metadata and recovered exactly. Journal serialization now
refuses before writing beyond the existing 128 KiB limit. Exhausted metadata headroom refuses further creation;
failed residue is preserved. Unbound-only scope excludes bound descriptor/security-store copies.

One snapshot slot is admitted before copying content. Its exact identity is durably recorded. Every duplicated
read handle retains the charge, including a parser outliving the publisher's deadline. Closing the publisher alone
does not refund it. Restart/live reconciliation deletes only recorded exact snapshot objects via the existing
exclusive no-follow helper. Full content capacity is refunded only after the journal's exact `StageDeleted`
receipt, terminal state/no pending rename or copying hand-back, and all snapshot leases have gone. Metadata
remains charged as long as its records remain. There is no silent expiry or destructive pruning.

A failed allocation with no manifest and no issued grant can retire its recorded exact seed after confirmed
exclusive deletion, or accept confirmed absence when no identity was ever captured. Unknown existing objects
stay charged on allocation retry and terminal refusal alike. The same stable failed intent can retry without
double charging; it cannot reuse a completed grant. Confirmed unissued failed allocations retire their exact ledger
rather than retaining one MiB forever. Completed kind-5/private retirement ACKs can replace their per-SID metadata
charge with the reconstructible shared journal envelope; replay and generation high-water remain durable. A committed-manifest replay validates the tuple and held
stage identity, then completes the same durable grant before returning; it never reseeds or allocates a new generation.

## Existing installations

Startup validates the existing trusted hot and packed journal before admitting new work. Completed legacy records
retain their exact bytes, generations, checksums and indexes. Completed-shape records with confirmed stage absence
receive inventory compatibility only: they cannot grant capacity, authorize publication, or authorize deletion.
A shared global metadata envelope charges twice the rounded existing hot/cold bytes plus 16 MiB for bounded
recovery/packing overlap. It is reconstructed on restart and charged against total/free space, not unrelated SIDs.
Existing immutable `.security` snapshots are held/ACL/format/ID validated and charged by this envelope; their IDs
permit only security-file metadata inventory, never transfer/capacity authority. New bound allocations stay refused.

Pending legacy stages are **accounted on first start and finished under the original 16 MiB guard**. Persist a
`LegacyGuard` reservation for four overlapping 16 MiB copies plus retained metadata, using the recorded SID and
full object identity. An absent SID becomes unattributed total debt; an absent identity remains absent and cannot
authorize cleanup/refund. These records cannot issue a `.space` companion, reuse new capacity or use the
no-manifest failed-allocation retirement path. Exact existing cleanup/discard evidence and drained snapshots still
control content refund. Repeated/partially completed migration checks the same guard/identity/no-companion rules.

A missing ledger cannot relabel a modern large grant as legacy: a companion, actual or sealed content above the
old guard, identity mismatch or inaccessible/untrusted object stays held. Unknown loose objects and interrupted
corrupt accounting remain diagnostic holds; filenames never become deletion authority. Ordinary deleted-on-close
legacy snapshots need no sweep; any unknown surviving snapshot remains held.

Historical negative allocation receipts have no count-based admission veto. Valid exact V20 request/intent/name
records retire only after no manifest and exact unissued backing/grant absence. Partial/corrupt canonical or temporary
records remain charged and hold their own nonce while unrelated saves continue; new refusals persist no files. Existing valid use above a configured budget,
or a zero/tiny default on a nearly full volume, permits startup/recovery while new reservations fail with the
staging-space reason. Physical persistence failures still retain custody and require storage recovery.

## Failure behavior and inspection

Disk full, disk quota, quota exhaustion and denied growth set `SpaceFailed` permanently for that version, including
native allocation, paging/AdvanceOnly and flush completion failures. V31 carries a strictly validated failure-only
seal, preserving the existing normal-seal layout and validation. Its journal flag blocks approval, publication,
justification and seeding a successor from that failed prefix. Even an empty or otherwise clean prefix is blocked.
A successful native rename is never retried. Existing exact-handle temporary cleanup keeps failed publication
from replacing the old destination. Failed hand-back keeps private custody. The tray/block window explain
"not enough staging space"; physical flush/capture failure can remain Retained until storage recovers.

Complex staged parsers execute in another copy of the service executable, before host/service initialization.
The parent assigns a Windows Job Object with process memory, active-process=1 and kill-on-close limits before
supplying a read-only duplicated snapshot handle. The child receives only extension, selected categories, size
policy and a nonce through bounded framed IPC. Only a complete result, matching nonce, clean process exit and
EOF are accepted. Cancellation kills/drains before the exact read lease and Core worker slot are released.
The Job Object is a resource container, **not a security sandbox**; restricted-token/sandbox hardening is separate.
Native containment, kill/drain and hostile parser cases require Windows evidence.

Plaintext uses the existing strict BOM-aware streaming scanner. ZIP plaintext members now stream from the held
archive with length, CRC, exact compressed extent and final DEFLATE marker validation. A bounded four-MiB text
replay avoids repeatedly decoding small members; overflow returns to full streaming passes. ZIP metadata has a
fixed four-MiB admission bound. Seek-requiring nested Office/PDF/ZIP members are limited to eight MiB each, with
three-level nesting; larger ones explicitly fail `inspection_limit`, never partially approve. ZIP64 and 7z remain
refused under the existing format scope. Large ZIP qualification here means supported ZIP32 plaintext members.

Seeding remains a linear copy with constant-size buffers, checked capacity and a monotonic cancellation deadline
(120 seconds in `StagedSpaceOptions`, maximum ten minutes). It is not lazy/COW seeding. The existing synchronous
MVP allocation queue/RPC can still make a slow large seed fail or delay unrelated creates; this needs the native
seed-cost rows and, if they fail, asynchronous seeding work. Do not count safe refusal as successful large editing.

## Approved resource defaults

Owner accepted these storage defaults on 2026-10-16. Native whole-operation qualification remains open:

| Setting | Default | User consequence |
|---|---|---|
| Total physical reservation budget | min(32 GiB, 10% of available stage-volume bytes at initialization) | Keeps substantial room for Windows/other work; limits simultaneous large saves. |
| Per-SID physical reservation budget | min(8 GiB, total / 4) | One user cannot reserve the configured total. Four-copy accounting means roughly a quarter becomes content capacity. |
| Free-space floor | max(1 GiB, 5% of volume size) | Refuses early when Windows is low on space. A floor above available space admits nothing. |
| Complex parser memory | 256 MiB per worker, two existing Core worker slots | Explicit incomplete-inspection failure on exhaustion; Windows aggregate peak still needs measurement. |
| Seed deadline | 120 s | Bounds copying work; does not extend the existing foreground allocation RPC deadline. |

For omitted resource fields in local/remote policies, staged inspection (`LoadCurrentAsync`) defaults to
**4096 MiB / 900 seconds**. Legacy inspection (`LoadAsync` and `CreateDefault`) retains **20 MiB / 5 seconds**
and its existing RN-012/RN-013 behavior; `CreateStagedDefault` selects the staged view. Newly generated policy
JSON omits these resource overrides so provisioning from either mode cannot pin the other mode's defaults.
Each explicit field overrides that field in both modes; explicit null remains malformed. The effective values
still participate in the policy fingerprint, and staged policy reads still require current authority without fallback.
The measured 2 GiB DOCX took 246 seconds, versus 97 seconds for text and 154 for ZIP; 15 minutes leaves
processing/queue margin. Parser memory defaults to 256 MiB versus the measured 54–74 MiB process peaks.
Staged timeout, hostile parser/resource failure and incomplete inspection still fail closed.

Existing explicit policy limits remain authoritative, including a persisted `20` MiB/`5` second policy: upgrade
does not silently rewrite an administrator policy or its version/fingerprint. Such installations must update those
explicit policy fields to use the new large-file limits. A 2 GiB protected save still needs **more than 8 GiB per SID**
including metadata: the approved default budget may correctly refuse it; increase explicit budgets for that row.

The current whole-SID capacity lease permits one active content reservation per SID; simultaneous Word/temp
saves can refuse. The owner approved replacing it with [growing reservations](UX-LARGE-CONCURRENCY.md) on
2026-10-19, within the same budgets and stronger concurrent no-overspend controls. That design is under independent
review and is not implemented or qualified. Automatic metadata retirement and lazy seeding remain separate work. Legacy
upgrade accounting is implemented above; hostile/corrupt stores remain holds. This is not full T9 qualification.
