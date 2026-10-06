# V11 amendment for the frozen V10 trusted-signer baseline

This separate amendment preserves the frozen V10 checkpoint package and source
manifest. It corrects case-sensitive SHA-256 comparisons that rejected valid
uppercase digest values from the pinned Windows evidence. It does not change
the evidence schema, trusted-state requirements, six-store assertions,
ordered-key-ACL checks, or read-only behavior.

The amendment adds `Test-Sha256Equal`, which accepts only 64 hexadecimal
characters on both sides, lowercases both using invariant culture, and uses
ordinal comparison. The helper is used consistently for the file digests and
the SHA-256 fields in the pinned metadata, trust receipt, cold-challenge
receipt/readout, post-sign JSONL/root readout, artifact proof, evidence pins,
proof manifest, and retained original files.

The failed V10 run was read-only and stopped at the creation-metadata file hash
comparison. `Get-FileSha256` returns lowercase while the pinned metadata hash
constant is uppercase. Inspection of the pinned JSON confirms additional
uppercase/lowercase mismatches that the corrected gate must pass: signed hash
in the independent JSONL and root readout, and signed-artifact plus builder
trust-receipt hashes in the artifact proof. The amendment normalizes these
values without weakening their required exact digest equality.

The V10 failed-run root readout is pinned in `amendment-pins.json`; its
pre-shutdown attempt exited 1 before host mutation, with empty stdout and the
retained CLIXML error stream. A separate Windows PowerShell 5.1 parse and input
pin check of V10 exited 0 with zero parse errors. Those results confirm the
source parsed but its first runtime hash comparison stopped the guest baseline;
they do not prove a V10 trusted-state baseline pass.

The original V10 baseline remains pinned at
`369c4cfa978ef38d63daeae1d846d44791388488ea9fd123e98573c300e04dbe`; the V10
reviewed source manifest remains
`49574cb4ae56014eabfd325f6cb16ed893efb6e300a8565b47634cb4e0aa5f11`; and the
independent package review note remains pinned in `amendment-pins.json`.

No VM, key, certificate-store, trust, signing, build, or driver-install action
was performed while preparing V11. This source has not been parsed or run.
Root must parse the exact V11 source under Windows PowerShell 5.1 and perform
the read-only trusted-baseline verification before any checkpoint mutation.
