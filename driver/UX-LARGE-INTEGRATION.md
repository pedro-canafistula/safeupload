# Large-mode integration on demo/apps

2026-10-16. Merge `ux/large` (`7edba345`) with `demo/apps` (`667a2652`), including
allocation abort (`110da6b7`), packed journals (`83bceea2`) and basic metadata (`9ef5b17f`).
Large mode remains explicitly opt-in and default-off. Runtime readiness/capability
and qualification gates remain unchanged. This is local integration, not T9/M2 completion.

Normal seals retain the metadata branch's exact 72-byte envelope. The strict
48-byte v31 failure-only seal remains distinct and cannot approve a clean prefix.
The journal preserves both immutable metadata and sticky space failure. Seeding
captures the exact private object before metadata validation/first seed bytes,
while retaining metadata checks, configurable capacity and the seed deadline.

Packed terminal receipts keep their existing indexes, validation, frontier,
retention and active-only dispatch behavior. Their storage now uses the retained
large-mode metadata debits: admission counts hot files plus a conservative cached
cold allocation, charging projected append/inventory/compaction growth before I/O.
Cold accounting is rebuilt at startup and after closed-handle archive maintenance;
foreground admission does not enumerate packed segments. Failed residue remains
charged. Hot serialization retains its 128 KiB output bound and journal timing.
Archive callbacks are installed before large-mode recovery can extend a segment or
inventory. Unreserved packed history prevents large-mode startup.

Content accounting consumes exact durable disposal or private-discard ACKs, including
lost-Prepare kind-5 cleanup. An ACK is distinct from StageDeleted; path/identity,
absence, rename/cleanup, hand-back and live snapshot conditions still apply.
Compaction pins unconsumed content-reservation owners and their reference closure.
Refunded history keeps its metadata debit without foreground receipt reads.
No missing manifest, timeout or mere path absence grants a content refund.

Local verification and remaining limits: [integration receipt](evidence/2026-10-16/ux-large2-local.md).
Existing [large-mode qualification rows](UX-LARGE-VM.md), [metadata limitations](UX-METADATA.md)
and [packed-journal qualification](T11-UNBOUND-JOURNAL-SCALING.md) remain required.
