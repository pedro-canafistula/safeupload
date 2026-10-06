# Independent signing-fallback review

Review date: 2026-10-06. Reviewer: Luna 6.1 Max. Scope: read-only cybersecurity and correctness review of the pinned signing-key recovery/fallback package and the prepared exact-build helper. This review does not authorize VM changes or signing.

## Pinned inputs

- `exact-mvp20261006admissioncap2-signing-key-recovery-sha256.txt`, SHA-256 `5a2183db373fc5ee140a145d5990675d03ce1c2dbeab2079d6c06c7cfe3ac31e`
- Fallback plan, SHA-256 `4112bbab30d48288e3a1459ed15b626fc3d1f7ec141e9e5065702fbf0bf60b61`
- Key-creation script, SHA-256 `bcb59409e451b1569d757d36af88e006e800d32be33132f7c33e4095736ad94d`
- Builder trust script, SHA-256 `f7583a70258fe71bf581756870f537ecc5b9dfaf7ba74c4a01eeba70ea77d476`
- Debuggee trust script, SHA-256 `131add3f660d37a9a7cec3aec6d54b5ed57ccd02676306a9479bf2fc19e0e5d4`
- Trust rollback script, SHA-256 `a66da4d9377d21ee1fece93ebca8e1ce726321bb12cf362cfd9eb0d3d4a80004`
- Prepared `Build-ExactSource.ps1`, SHA-256 `ccd8996a91de8b7663e0d2dfe5c78629c346513dbc72909014339538f8865773`

The recovery manifest was checked with `sha256sum -c`; every listed input matched. The canonical user objective is in `/home/victor/.codex/attachments/c478f92e-2f53-4c9f-9289-6b6e446cc18d/pasted-text-1.txt`. The current MVP boundary remains the one in `driver/MVP-PLAN.md`: signer resolution is open; a valid exact signer is required before using artifacts; the full USB/UNC/sync-client and privacy gates remain open.

## Findings

**Blocked pending two corrections.**

1. In the key-creation script's pre-mint output guard, the condition is written as `if (Test-Path ... -or Test-Path ...)`. PowerShell command argument parsing does not safely separate these two invocations at `-or`; it can bind `-or` as a `Test-Path` argument and stop before creation. Write it as `if ((Test-Path ...) -or (Test-Path ...))`, then review the new hash-pinned input.

2. The requested certificate parameters are appropriate, and the script checks RSACng, provider, nonexportability, code-signing-only EKU, DigitalSignature key usage, and validity. Before trusting this self-signed certificate as a root, its postconditions should also require a 3072-bit RSA key, RSA public-key and SHA-256/RSA signature algorithm identifiers, `Issuer == Subject`, and Basic Constraints `CA=false`. These properties are requested by the creation command but are not currently verified by the acceptance code.

The ACL routine fails closed if the new key already has a vika ACE other than one explicit `Read` ACE. That is appropriately restrictive, but it runs after key creation. The exact KSP default ACL is not established by the local evidence. Any post-mint guard failure must therefore stop all trust/source/signing work, restore the independently verified pre-fallback builder checkpoint, and verify the old certificate/store and PFX/CER baselines before another attempt. Do not manually broaden permissions or continue with the unbacked key. The plan already retains the pre-fallback checkpoint and baseline restoration requirements; make this immediate failure path explicit in the execution record.

## Reviewed controls that pass static review

- The existing signer recovery evidence distinguishes the empty-password PFX result from the unrelated SSH key-access problem and does not claim the original key was deleted. The original certificate and file hashes are pinned and retained.
- The replacement design confines the nonexportable machine key to the exact disposable builder. Trust additions are narrowly scoped: builder `CurrentUser\Root`; debuggee `LocalMachine\Root` and `LocalMachine\TrustedPublisher`. The original signer remains present. Full thumbprint inventories are captured and checked; debuggee `testsigning` must remain `Yes`, while rollback compares the actual state on either machine.
- Rollback removes only the new thumb from the trust stores, keeps the private key intact until baseline restoration, and requires independently verified pre-fallback checkpoints. Historical evidence and old signer pins remain attributable to their original signer.
- The prepared exact-build helper refuses an existing signed-output path, verifies the copied output hash against the unsigned artifact, preserves and rechecks the unsigned hash, selects `/sm` for `LocalMachine`, and requires both Authenticode `Valid` and the exact signer thumbprint.
- The change set stays within the existing compile/signing gate. Matrix E's agent tests and package verification already pass and need not be repeated solely because of the signer change. That result does not qualify runtime privacy, destination, recovery, Verifier, stress, or latency gates.

## Review limits and disposition

This was a static, read-only review. No PFX password or private-key bytes were read; no key was created; no certificate or trust store was changed; no checkpoint, signer pin, build, artifact, VM, or Git state was changed. `pwsh` is unavailable in this review workspace, so I did not independently parse the PowerShell scripts; the root-provided PowerShell 5.1 parse result remains separate evidence. The review does not prove the actual builder's KSP ACL, checkpoint restorability, Windows trust result, or signing behavior.

Do not execute the fallback using the pinned key-creation script until both blockers are corrected and the revised files receive a new frozen manifest. After that, root must independently verify the exact VM checkpoints and execute the approved steps in the order in the plan. Signer replacement alone does not change the MVP completion boundary or permit taint removal.
