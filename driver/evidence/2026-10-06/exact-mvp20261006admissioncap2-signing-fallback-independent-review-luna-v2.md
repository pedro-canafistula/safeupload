# Independent signing-fallback review, V2

Review date: 2026-10-06. Reviewer: Luna 6.1 Max. Scope: read-only cybersecurity and correctness review of the V2 signing-key recovery package and prepared exact-build helper. This is a review of the procedure, not approval to mutate either VM or a claim that signing works.

## Pinned inputs and checks

- V2 manifest SHA-256: `64c989f2246f1e5a3facb94a00008169fc637c884b78d44c8d5836bca3b753a8`
- Fallback plan SHA-256: `ca4db24bcceb1eae72306e9d2e991e6bfa02c2d73dc3695fe5d386281bb6016b`
- Key-creation script SHA-256: `9a81661bd8946b6d393800713614774c5b4a825b8886a4baa9f95d06b68034ea`
- Prepared `Build-ExactSource.ps1` SHA-256: `ccd8996a91de8b7663e0d2dfe5c78629c346513dbc72909014339538f8865773`

I verified every V2 manifest entry with `sha256sum -c`. The retained Windows PowerShell 5.1 authoring record reports zero parse errors for the pinned key-creation script and empty stderr; it did not execute the procedure. Root's read-only builder baseline reports the builder identity, six logical store inventories, and `testsigning=No`; no key or trust change was made.

## Verdict

**The key-creation procedure passes static review with host-state preconditions. The V2 trust-add/rollback scripts are blocked pending correction of their logical-store delta model.**

The V1 blockers are corrected: the two `Test-Path` commands are parenthesized, and the key-creation acceptance checks now require RSA-3072, machine/non-ephemeral Microsoft Software KSP, nonexportability, RSA public-key and SHA-256/RSA certificate signature OIDs, subject/issuer equality, exactly one CA=false Basic Constraints extension, code-signing-only EKU, and DigitalSignature-only key usage. A post-mint guard failure records public metadata and explicitly requires preserving the failed branch, restoring the verified pre-fallback checkpoint, and independently checking the original store and PFX/CER baselines before retry. This is a safe fail-closed path even if the new key's actual default ACL differs from expectation.

## Trust-store projection blocker

Windows' logical CurrentUser stores inherit LocalMachine contents except for Personal. Microsoft states that a certificate added to LocalMachine Root also appears in CurrentUser Root; the rule applies to the other CurrentUser stores as well ([Local Machine and Current User Certificate Stores](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/local-machine-and-current-user-certificate-stores)). The system-store reference describes these logical stores as collections of physical stores ([System Store Locations](https://learn.microsoft.com/en-us/windows/win32/seccrypto/system-store-locations)). The root-provided builder baseline independently confirms equal CurrentUser/LocalMachine thumbprint sets for Root and TrustedPublisher before mutation.

Therefore, after the debuggee imports the replacement into `LocalMachine\Root` and `LocalMachine\TrustedPublisher`, the same new thumbprint is expected in vika's logical `CurrentUser\Root` and `CurrentUser\TrustedPublisher` views. The current debuggee trust script rejects those two expected projections and removes the just-imported machine entries. The current rollback script also expects the projected CurrentUser entries to remain after removing the machine entries, so it can throw after the underlying trust removal. Revise both scripts and their expected inventory assertions to allow exactly these same-thumb projections while rejecting every other delta; review the new frozen hashes before either trust operation.

The store inventory helpers use `Get-ChildItem -ErrorAction SilentlyContinue`. Root's separate, successful baseline inventory mitigates the pre-mint snapshot concern. Before trust changes, every full-store before/after inventory must still be independently checked for complete enumeration; suppressed enumeration errors cannot count as proof of an unchanged inventory. Changing these reads to fail on error is the clearest fix.

## Preconditions and limits

Before minting, root must verify both exact pre-fallback checkpoints, backing identities, and restorability. The current host metadata about an existing disk is not itself proof that a new key-bearing checkpoint has restrictive permissions. Require the new checkpoint and containing directory to have reviewed access controls and the exact expected VM UUID/backing before relying on it. Record full baseline store inventories and testsigning state on both VMs.

Before calling the signer fallback usable, separately re-review the post-mint certificate metadata and public CER hash, verify the key-bearing checkpoint and ACL, correct the trust-store projection scripts, update only the approved active signer pins, pass `-CertificateStoreLocation LocalMachine` and the exact new thumbprint into the exact build, and require the builder and debuggee signature gates to report `Valid` with that exact thumbprint. No signer pin has been repointed and no artifact has been signed yet. Agent matrix E need not be repeated solely for a signer change, but its pass does not close runtime or byte-privacy gates.

This review was static and read-only. No PFX password or private-key bytes were read; no certificate was created/exported/imported; no trust, source pin, VM, checkpoint, build, artifact, or Git state was changed. `pwsh` is unavailable in this review workspace; PowerShell 5.1 syntax evidence is the retained authoring record. The V1 blocked review remains preserved separately.
