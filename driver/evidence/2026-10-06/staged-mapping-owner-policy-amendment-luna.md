# Bounded owner candidate and fixed-NTFS mapping policy amendment

This amendment supplements, and does not replace, `staged-mapping-observer-review-luna.md` (SHA-256 `3943267b2fc4604f732e75c97391fee57cbc521f2ee19583dc5dc6f58b8f8e55`). The separate-process observer helper and its byte/LCN checks remain unchanged. The M2 fixture is now rooted under the bounded `C:\SafeUpload\Owner Candidate\policy-transition-{guid}` directory, outside the initial `C:\SafeUpload\Escopo Monitorado` test policy. It no longer uses the broad Documents tree.

Current exact source pins:

| File | SHA-256 |
| --- | --- |
| `driver/scripts/StagedMappingByteObserver.ps1` | `76d3b9f6ef90880fbb748b4d194f42ef16a52403bdf4824eedb9271531ddeb91` |
| `driver/scripts/Test-StagedPreAttachmentMapping.ps1` (M1) | `666d792b37d7e7bd6d3b081fb518f96bd5f13c73a767b9497ad91b9337e315c8` |
| `driver/scripts/Test-StagedPolicyTransitionMapping.ps1` (M2) | `e39c5bfdd8241a1dc766b5e3d4cd80f6cdb1930aae30fb74729ad7f7a4b9456c` |
| `driver/scripts/Test-StagedPreAttachmentMapping.SelfCheck.py` | `99e53db40f9ff586bf512f9973f1ca58b9723d1d38f04c0d1b9f4d1a2fab86eb` |

M2 prepares a test-only fixed-NTFS policy from the pinned production policy. It limits destination roots to the monitor root, disables removable-drive and network scopes for this mapping probe, and compares the remaining policy fingerprint so categories, limits, failure behavior, exclusions, and synchronization/content fields are preserved. M2 saves and verifies the exact original policy bytes before installing the test policy; expansion adds only the bounded candidate root; shrink restores the exact fixed test-baseline bytes; final cleanup restores and verifies the exact original production bytes/hash. `PolicyRejectionOnly` bypasses the test-only policy write and continues against the unmodified production policy. Logs explicitly make no USB/UNC/sync DOD qualification claim for the fixed-NTFS mapping probe.

M1 keeps its hard owner-setup gate and documents that any future fixed-NTFS test-policy activation comes only after the owner-protected private mapping and flush. M2 also retains `OWNER_SETUP_API_TODO` before service extraction, driver replacement, fixture writes, or mapping opens. Neither mapping path is runtime-ready until the immutable OwnerScopes record and authenticated owner allocator are actually wired into its setup sequence; this amendment does not claim an owner-ready or privacy result. The original successful write, view/file flush, disposal, separate-process buffered and uncached reads, stable raw extent checks, and privacy-verdict predicates remain required.

Checks run locally:

- `python3 driver/scripts/Test-StagedPreAttachmentMapping.SelfCheck.py` — PASS.
- `python3 -m py_compile driver/scripts/Test-StagedPreAttachmentMapping.SelfCheck.py` — PASS.
- `git diff --check` — PASS.

No PowerShell runtime, driver, service, fixture, or VM operation was run. These exact source pins need independent review and Windows PowerShell 5.1 parsing before any future test run.
