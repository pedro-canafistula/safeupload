# Separate-process mapping observer review

Review scope: add independent byte readers to M1 (`Test-StagedPreAttachmentMapping.ps1`) and M2 (`Test-StagedPolicyTransitionMapping.ps1`) while preserving their write, flush, section disposal, original NTFS path, retrieval-pointer/LCN, raw-byte, and privacy verdict requirements. The prior source pins at the start of this review were M1 `1c493c8a0489c1315347336d15fc0dcd7accb963fb9981c661ba5600931b4dd0`, M1 selfcheck `38ecd7b93cfe48163159f35fe3ac1efb27bc8686be3514c247b8674a7fe8b1c4`, and M2 `094f149ce4f96f8139e951f05103c2bf95ff90995a15e8184dfa55a4b4606c81`.

Final reviewed source pins:

| File | SHA-256 |
| --- | --- |
| `driver/scripts/StagedMappingByteObserver.ps1` | `76d3b9f6ef90880fbb748b4d194f42ef16a52403bdf4824eedb9271531ddeb91` |
| `driver/scripts/Test-StagedPreAttachmentMapping.ps1` (M1) | `064352f320a44e346f93138087aaa2474bd8c189c8bc3beffe682cbb50e6beac` |
| `driver/scripts/Test-StagedPolicyTransitionMapping.ps1` (M2) | `4d6057f669b002ef69718f80206c982d69be0eccbc246f4dee05dc0dd0702d5e` |
| `driver/scripts/Test-StagedPreAttachmentMapping.SelfCheck.py` | `42542f874a78fb01ca9b255f657888ffa8a2779d6060b2bc0746cd313d839014` |

The helper runs each requested buffered, uncached, and raw observation in a distinct PowerShell child and binds its result to a request ID, parent/child PID, helper hash, and target path. It returns complete fixture bytes for full-array comparison. Raw measurements repeat retrieval-pointer checks against the pinned first LCN and read the original volume device; a failed or incomplete observation cannot qualify as unchanged. The helper rejects reparse targets/ancestors, mismatched volume roots, and target lengths different from the 4096-byte baseline. M1 keeps its successful mapped write, view flush, independent file-buffer flush, handle release, buffered/uncached byte comparisons, and stable 20-sample raw comparison requirements. M2 retains the corresponding successful write/flush/disposal/raw requirements for retained-section and expansion cases; its expansion `BLOCKED` result also now requires both separate-process buffered and uncached reads to succeed with baseline-identical bytes.

Both new mapping modes are hard-gated with `OWNER_SETUP_API_TODO` before fixture or service/driver mutation. M1 stops before creating its fixture. M2 leaves `PolicyRejectionOnly` available and stops the mapping path before service extraction, driver replacement, or fixture write/open/mapping. The authenticated owner setup/allocator integration and any resulting M1/M2 qualification remain pending.

Checks run locally:

- `python3 driver/scripts/Test-StagedPreAttachmentMapping.SelfCheck.py` — PASS; includes paired M2 structural assertions and the historical M1 false-pass controls.
- `python3 -m py_compile driver/scripts/Test-StagedPreAttachmentMapping.SelfCheck.py` — PASS.
- `git diff --check` — PASS.

No PowerShell runtime, driver, service, fixture, or VM operation was run as part of this review. The scripts still require builder-side Windows PowerShell 5.1 parsing and a fresh review of these exact pins before any run; passing the offline selfcheck is not mapping or owner-route runtime evidence.
