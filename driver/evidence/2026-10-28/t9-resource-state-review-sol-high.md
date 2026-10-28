# Independent review: passive T9 modern custody schema

2026-10-28. **gpt-6.1-sol, high**, no fast tier, read-only reviewer
`/root/t9_resource_wire_review`, follow-up against `c5e5c83c` and the working
[state proposal](../../docs/design/large-files/UX-LARGE-RESOURCE-STATE.md).
No edits, builds, remote/VM access or implementation delegation.

**ACCEPT WITH CONDITIONS for the passive codec and pure validation increment.**
No native I/O, budget adoption, activation or qualification follows from a valid
record. Required bounded corrections, incorporated by root before implementation:

- Deterministic phase/debit rules: ClosedUnissued keeps full debit until explicit
  MetadataOnly; MetadataOnly requires no FullDebitHeld/pending companion and only
  Empty/Released slots. Constrain phase, binding, closure and receipt combinations.
- Original immutable-stage EOF/allocation must equal the accepted receipt. A
  released/reused stage requires retained exact identity/slot/incarnation proof;
  no zero-allocation slot may understate a large-allocation driver receipt.
- Required/null slot fields, nonnegative checked/aligned measurements and ceilings,
  exact release identities/incarnations, non-creation distinct from deletion,
  occupied zero-length obligations and no incarnation reset/wrap.
- Exact pending companion predecessor/target/revision relationships; prepared
  states require captured replacement identity. Closure may advance the record
  revision without changing the target revision; pending state keeps full debit.
- Preserve unsigned cookie/sequence/identity words; retain complete original
  intent with exact encoding, and do not reject history solely because its old
  deadline expired. Metadata units/defaults are separate from content alignment.
- Growth high-water/semantic replay persistence must be added before any growth
  consumer; clearing PendingCompanion alone cannot satisfy the replay contract.

Native release adapters, anchored persistence, shared completed-history handoff,
initial/companion crash recovery, combined totals and persistent downgrade marker
remain mandatory integration gates. The schema explicitly does not claim active
growth-ledger completeness.

## Subsequent root checks

Root implemented bounded required-field JSON, strict unknown/duplicate rejection,
full original-intent checks and conservative charge/slot/phase validation, with no
runtime consumer or I/O. ImmutableReleasePending preserves measured immutable
allocation; abandoned mutable copying keeps ReservedMax until exact release.
Capacity-commit GrantRevision is retained separately from later custody revisions.

Local Debug/Release test-project builds pass with zero warnings/errors; **33/33**
controls pass with zero skips. They include required false/null fields, duplicate/
unknown/corrupt records, pending copies, reader retention, large preallocation at
zero EOF, growth closure, slot reuse/stale release, metadata-only proof, lost
growth-reply accounting, metadata defaults, overflow and complete original intent.
[Local receipt](t9-resource-state-local/result.json) binds the source/build/TRX
outputs. These are root component checks after the design review; no independent
implementation review, Windows delivery gate or protected-pair result is claimed.
