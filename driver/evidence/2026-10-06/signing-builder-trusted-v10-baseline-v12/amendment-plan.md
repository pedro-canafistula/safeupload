# V12 amendment: pinned schema audit and concrete post-sign ACL linkage

This separate, read-only amendment keeps the frozen V10 checkpoint and V11
amendment intact. V11 passed Windows PowerShell 5.1 parsing, then stopped at its
post-sign JSONL record-0 condition before any host checkpoint operation. The
pinned record has `NewThumbprint`, not `Thumbprint`, and records ACL state as
`KeyAclSddl`, `KeyAclOwner`, `KeyAclGroup`, `KeyAclProtected`,
`KeyAclCanonical`, and ordered `KeyAclRules`; it has no `KeyAclUnchanged`
boolean. The retained V11 root readout records `HostCheckpointAttempted=false`
and `TrustModified=false`. This failure is a verifier-schema mismatch, not
evidence of host state drift.

V12 retains V11's case-insensitive SHA-256 digest equality fix. It adds exact
property-set checks for every JSON/JSONL object consumed by the baseline,
including nested ACL snapshots, store maps, evidence-pin maps, key-rule rows,
original-file rows, and the original-certificate object. These expected shapes
were checked against the actual hash-pinned inputs listed in
`schema-audit-inventory.json`; the inventory includes SHA-256 values and
recursive observed property/type shapes for the relevant JSON, JSONL, and
proof-manifest files. A schema mismatch reports the input object and missing
or unexpected field names before value checks use those properties. Existing
result fields are checked with per-field diagnostic labels where the prior
baseline grouped them into one compound predicate.

For post-sign JSONL record 0, V12 checks the actual `NewThumbprint` field. It
binds each reported ACL SDDL, owner SID, group SID, protected/canonical flags,
and ordered access-rule row to both mint-time ACL snapshots and both trust-time
ACL snapshots. The reported rule values map directly to the helper's ordered
snapshot representation: the rule must carry the same SID, Allow type, rights,
and inherited flag; Windows numeric inheritance and propagation values must
both be zero, matching the snapshot's `None` values. V12 does not infer or
require a nonexistent `KeyAclUnchanged` field. The existing live `Get-Acl`
snapshot, exact default-ACL check, comparisons against all four pinned
snapshots, and the post-sign root readout's `KeyAclMatchesMint` assertion remain
in place.

The six-store trust delta, identity, code-signature, no-private-export,
no-install/load, original-file retention, and no-build-process checks remain
based on the frozen V10 baseline. V12 does not add a VM, key, certificate-store,
trust, signing, build, or driver-install action. It has not been parsed or run.
Root must parse the exact source under Windows PowerShell 5.1 and rerun only the
read-only guest baseline against the existing evidence before any checkpoint
mutation is considered.
