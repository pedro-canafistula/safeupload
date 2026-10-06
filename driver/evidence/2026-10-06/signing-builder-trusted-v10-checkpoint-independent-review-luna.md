# Independent review: V10 trusted signer checkpoint package

Review mode: read-only. No VM, key, certificate-store, trust, signing, build, or
driver-install action was performed.

## Frozen package reviewed

The checkpoint source manifest is
`driver/evidence/2026-10-06/signing-builder-trusted-v10-checkpoint/source-manifest.sha256`,
SHA-256 `49574cb4ae56014eabfd325f6cb16ed893efb6e300a8565b47634cb4e0aa5f11`.
All 33 entries pass `sha256sum -c`. The frozen review pins are:

- Plan: `ebe94f4e702bfbcce99b232dcd69625b1a92bde223b4c422a3ca51a83f845a9b`
- Inputs: `07f4fa882b2b95b23f0ebb1aa35f27bee79651757ee344c7179e4f1929e7f944`
- Read-only baseline verifier: `369c4cfa978ef38d63daeae1d846d44791388488ea9fd123e98573c300e04dbe`
- ACL helper: `9585e1acd512f9532de032c6ce2df251fa774acc83d27cfc6afceb437ce64c42`

I independently recomputed 13 core pins from `inputs.json`: V10 trust receipt,
trust readout and source manifest; V8 cold-challenge receipt and readout; V10
signer source, source manifest and root-run record; post-sign JSONL, stderr and
root readout; and the baseline verifier and helper. All hashes match.

## Assessment

Static review passes for the stated checkpoint scope. The verifier performs
read-only identity, certificate-store, signature, file-hash, testsigning,
process and machine-key ACL checks. It requires the exact six-store V10 trust
delta, compares the ordered key ACL with mint and trust snapshots, confirms
the original certificate files remain, validates the signed public copy and
unchanged unsigned input, and binds the two-record post-sign readout, its
stderr capture, and the zero-exit root readout. The post-sign evidence states
that no signing was attempted by the verifier, state was not mutated, and the
driver was not installed or loaded.

The plan keeps the failed retry1 disk out of the lineage, preserves the
healthy retry2 parent, limits the operation to a fresh system-disk child, and
does not claim that firmware, TPM, RAM, or shared NVRAM is checkpointed. It
requires the parent to remain read-only and the preexisting parent metadata to
match before and after. `inputs.json` correctly remains
`ReadyForExecution=false` pending reviewer approval, live host/domain
preflight, confirmation that the child path is absent, and confirmation that
the active domain source is the pinned healthy parent.

No static blocker remains for review of this exact package. Before any host
mutation, parse the exact frozen `baseline-check-v10.ps1` with Windows
PowerShell 5.1 without invoking it; this environment did not provide that
parser. Execution also remains contingent on all live preflight gates in
`inputs.json`. This review does not authorize driver installation, loading,
debuggee trust changes, or use of the signed artifact.
