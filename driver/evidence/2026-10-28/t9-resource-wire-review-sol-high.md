# Independent review: passive T9 resource wire v32

2026-10-28. Reviewer **gpt-6.1-sol, high**, no fast tier; fresh read-only agent
`/root/t9_resource_wire_review`. Reviewed the working
[wire proposal](../../docs/design/large-files/UX-LARGE-RESOURCE-WIRE.md) against
HEAD `afd972ef`, accepted growing-reservation revision 5, current C/C# protocol,
allocator and startup code. No edits, builds, remote or VM access.

**ACCEPT WITH CONDITIONS for standalone passive types, parsers and mutation
controls only.** No receive-loop registration, negotiation success, worker or
capacity consumer in this increment. No readiness, cutover or pair qualification.

The sizes/offsets are consistent: 1192-byte outer request, 104-byte allocation
intent, 160-byte growth/retirement, 352-byte result and 376-byte reply. Operations
23/24, extension 32 and control 36 do not collide. Separate generations,
monotonic capacity, denied outer verdict and persistent downgrade marker fit
the accepted design.

Conditions before settling the parser contract:

1. Define operation-specific field grammar: offset 112 is zero for allocation,
   growth ObservedCapacity or retirement AuthorizedCapacity; successful grants
   are positive, aligned, signed-64-bit and at least the initial window; every
   inapplicable field is zero. Live adoption compares the exact companion/ledger
   binding, not shape alone. Allocation ImageNameLength is 104.
2. Separate transport RequestId from durable binding/kind/sequence plus complete
   semantic request. Reused sequence with changed extent/deadline/measurements
   refuses; sequence never wraps. Old-cookie retirement acknowledgment reports
   historical acceptance only, with no new connection authority or second refund.
3. Enforce checked Issued <= now < Deadline, equality expired. Post-expiry
   resolution cannot revive/attach a failed CREATE or renew its deadline. Check
   immediately before adoption. Choose concrete growth duration before its
   producer/consumer; passive layouts may precede that choice.
4. Keep the v20 larger ALLOW/byte-identical original-request resolution helpers
   unchanged. A v32 reduced tuple is not a substitute. Future v32 non-commitment
   consumption needs retained complete original intent and exact absence/
   non-adoption proof excluding another duplicate commit. Passive enum values
   supply no cleanup/release authority.

Root incorporated those clarifications in the design before writing passive
types and controls. Remaining integration conditions: concrete negotiation and
cookie issuance; dispatch before ordinary fallback; bounded allocation/lifecycle/
reply paths; reconnect/rundown and abandoned-work accounting; metadata capability
confinement; custody/storage-release proofs; modern startup/schema/marker
transactions; and all growth/MM/adoption consumers. Pending bounds apply before
retaining work and do not reset unresolved SID counts on reconnect.

Implementation/component checks are separate from this design review. Required
WDK/static/import gates and final matched-pair qualification remain outstanding.

## Subsequent root implementation checks

Root implemented passive C/C# layouts, standalone payload/reply parsers and
correlation checks, with no active handler/producer/worker. Final local Debug/
Release test-project builds have zero warnings/errors; 32 local controls pass
with zero skips, including mutation of every byte in the correlated growth reply,
complete identities, malformed requests, expired or unbacked grants, retirement
allocation measurements and allocation basename/intent correlation.
[Structured local receipt](t9-resource-wire-local/result.json) binds source and
raw build/TRX outputs. A portable C compile checks the header's layout assertions
using stubs of existing prerequisite layouts; it is not a WDK build. No changed
kernel was booted. This paragraph records root checks after the design review;
it is not an independent implementation review or delivery-gate acceptance.
