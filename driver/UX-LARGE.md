# T9 large files: opt-in unbound MVP implementation

2026-10-16, `ux/large`, base `62fd1673`. **Local prototype; T9 is not complete or qualified.**
Claude owns Windows builds and VM execution as standard user `t5actor`. No product VM was contacted here.
Read the [qualification list](UX-LARGE-VM.md) and [local receipt](evidence/2026-10-16/ux-large-local/result.md).

## Admission and authority

`Interception:StageSpace:Enabled` selects the large-file path. It requires explicit `TotalBytes`, `PerUserBytes`,
`FreeSpaceFloorBytes`, and `ParserMemoryBytes` settings. Proposed resource defaults are not silently activated.
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

The disabled legacy profile retains its 16 MiB guard. This is a compatibility/cutover boundary, not a claim that
T9 has removed the qualified product limit. Disabling large mode with retained accounting records refuses startup;
restore the mode/configuration to recover. Enabling on unreserved legacy stages or historical transfer metadata
also refuses. Automatic legacy migration and mixed-version downgrade with old service binaries are not qualified.

## Accounting and cleanup

The trusted private ledger is reconstructed before admission. Existing root, reservation directory and records
are checked for trusted ownership/no untrusted mutation before allocator ACL recovery. Reservation DACLs are
protected; JSON is parsed through the same held no-follow, single-link, size-bounded handle whose ACL was checked.
Persisted locators must remain direct children of the private stage root. Corrupt/partial accounting and unknown
objects remain held; there is no filename-only orphan deletion sweep.

Normally retain 1 MiB per transfer and 1 MiB globally for metadata. On larger-cluster volumes, each becomes at least
16 allocation units. At most half the transfer envelope is admitted for journal files, including failed replacement
residue; ledger current/replacement records are each bounded to 64 KiB, the grant is 64 bytes, and the remaining
headroom covers their allocation rounding and private-object MFT/index overhead. Global journal metadata and
negative allocation receipts each receive at most one quarter of the global envelope. Journal serialization now
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
double charging; it cannot reuse a completed grant. A committed-manifest replay validates the tuple and held
stage identity, then completes the same durable grant before returning; it never reseeds or allocates a new generation.

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

## Proposed owner resource decision

Recommendation for an initial conservative trial, pending owner selection and Windows whole-operation measurements:

| Setting | Proposal | User consequence |
|---|---|---|
| Total physical reservation budget | min(32 GiB, 10% of available stage-volume bytes at initialization) | Keeps substantial room for Windows/other work; limits simultaneous large saves. |
| Per-SID physical reservation budget | min(8 GiB, total / 4) | One user cannot reserve the configured total. Four-copy accounting means roughly a quarter becomes content capacity. |
| Free-space floor | max(1 GiB, 5% of volume size) | Refuses early when Windows is low on space. A floor above available space admits nothing. |
| Complex parser memory | 256 MiB per worker, two existing Core worker slots | Explicit incomplete-inspection failure on exhaustion; Windows aggregate peak still needs measurement. |
| Seed deadline | 120 s | Bounds copying work; does not extend the existing foreground allocation RPC deadline. |

The existing policy remains **20 MiB / 5 seconds**. Measurements of 2 GiB Word take minutes, so those defaults
cannot promise ordinary large-file completion. Select inspection size/latency separately; diagnostic probes use
4 GiB / ten minutes and never alter product policy. A 2 GiB protected row needs more than 8 GiB per SID including
metadata, enough actual free space for reservations/floor, and an explicitly suitable inspection policy.

The conservative whole-SID capacity lease permits one active content reservation per SID; simultaneous Word/temp
saves can refuse. Granular concurrent leases, seamless legacy migration, automatic metadata retirement and lazy
seeding remain follow-up work. This implementation is reviewable evidence toward T9, not the finished everyday UX.
