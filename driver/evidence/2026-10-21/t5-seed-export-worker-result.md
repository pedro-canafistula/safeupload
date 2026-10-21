# T5 unbound seed export worker result — 2026-10-21

Branch `t5/seed-export`, base `6aef8cf65ea9f04afa80cae9e806c354abcd0302`.
Commit preparation was blocked by the sandbox: `fatal: Unable to create '/home/victor/Work/safeupload-t5seed/.git/index.lock': Read-only file system`. Changes and this note remain in the working tree; no commit/push is claimed.
Agent-only implementation of owner option 1 from [T5 native public opens](../../T5-NATIVE-PUBLIC-OPENS.md#owner-choice--unreadable-seeded-bytes), within the worker brief's explicit process-primary scope. No kernel or status-plan changes; no network, VM, builder, SSH or libvirt activity. No binaries/packages delivered. The compile helper deletes its successful temporary output; this is source delivery, not an artifact or Windows gate result.

## Receipt and evaluation

`TransferJournalEntry.UnboundSeedExport` is one optional field, omitted with `JsonIgnoreCondition.WhenWritingNull`. Its format-1 receipt records the exact public source's volume/file ID, requestor SID, PID, creation time and `Allowed` / `Denied` / `Unproven`. Presence records preserving public seeding; null remains compatible with old manifests and versions that never seeded public content. Equality/hash and journal validation include it. Preserving private follow-ups inherit the original receipt under the journal gate, without inspecting their SYSTEM-private ACL as caller authority. Truncating allocations do not inherit it.

`IStagedSeedReadAuthorityEvaluator` permits injected host controls. The default Windows implementation checks the descriptor on the **same held object** used by `StagedBackingFile` to copy, before copying. A SYSTEM open's success and bytes are never read-authority evidence. `OpenProcess` + `GetProcessTimes` match lifetime; the primary token SID and session must match the persisted requestor. `DuplicateToken` + `AccessCheck` request exactly `FILE_READ_DATA` with the native file generic mapping. Existing enabled, deny-only and restricted groups come from the token, without SID-only group reconstruction.

A single `GetSecurityInfo` query requests owner/group/DACL plus label, resource attribute, scoped policy, process trust label and access filter information (`0x1F7`); failed queries never retry with reduced security information. Unsupported non-label SACL entries, callback/object/generic-mask DACL ACEs, invalid subjects/descriptors and token/query failures yield Unproven. A successful DACL refusal yields Denied. Allocation also converts evaluator exceptions/invalid results to Unproven.

Allowed is intentionally conservative: ordinary medium-integrity, default/unfiltered, non-elevated, unrestricted, non-AppContainer primary; enabled `SeChangeNotifyPrivilege` for traversal; direct effective account-SID read grant (or null DACL), with no effective read-data deny ACE for any group. Group-only grants remain Unproven because hand-back grants the account SID. MIC is separately checked: successfully queried absent label means medium; native mandatory-label ACE bytes must be supported, token integrity must be at least object integrity, and `NO_READ_UP` is refused because the SID-only hand-back would broaden it. Unsupported profiles can therefore retain a blocked save privately even when a native read might succeed. Clean saves continue publication normally.

The shipped path has **no retained original thread-impersonation subject**. This implementation uses process-primary evidence only, as explicitly requested; it neither reconstructs an impersonated CREATE caller nor changes bound-profile semantics.

## Disclosure and presentation

The shared `StagedSeedExport.Failure` now reads the unbound receipt before existing provenance logic. Denied/Unproven use the existing named `seed_export_denied` / `seed_export_unproven` reasons; recipient mismatch uses existing `seed_export_recipient_unproven`.

Existing consumers automatically cover publisher blocked transitions, normal blocked hand-back, blocked recovery/retry and justification re-publication; `StagedHandbackCopier` copy/verification/read leases; `StagedJustifications` registration and stale callback rechecks; journal hand-back completion and stage-cleanup checks; and blocked terminal-archive eligibility. No boundary was bypassed or replaced. `PrivateBlocked` keeps Blocked + Failed, null hand-back path/length, closed justification and retained stage. Clean publication and released-stage archival remain independent of export authority.

The publisher already emits `Core/Contracts`' `StagedBlockReason.SeedExportRestricted` for every shared seed-export failure. `App/Notifications/StagedSeedBlockPresentation` and `Views/BlockNotificationWindow` already display the factual previous-content permission explanation and suppress hand-back/override actions. No new mapping, protocol value or product wording was needed. New unbound controls assert the persisted reason and the same notification reason.

## Journal, archive, recovery and validators

- **Changed:** `StagedTransferJournal.CreateAsync` atomically persists/inherits the receipt; `ValidateEntry` validates format, enum, source identity presence, subject binding and preserving/unbound disposition. Record equality/hash preserve archive replacement comparisons.
- **Reviewed, no executable change:** `StagedTerminalArchive` serializes/deserializes the full entry, preserving this receipt. Added a comment distinguishing durable history from unfinished bound work. Existing blocked archive checks call `StagedSeedExport.Failure`; restricted blocked stages cannot be archived as completed hand-backs. Released clean versions can archive their receipt. Recovery uses the same full-entry reader and shared guards.
- **Unchanged:** `driver/scripts/Test-StagedInvariantSuite.ps1`, `ConvertFrom-ServiceJournalRecord` checks required known fields, not an unknown-field allowlist; `ConvertFrom-ServiceArchive` retains the full JSON payload and does not classify the new receipt as unfinished bound work.
- **Unchanged:** `driver/scripts/t5/notepad-coordinator.ps1`, `Get-JournalSchemaErrors` requires existing fields and accepts optional additional fields. The new nullable field must not be added to its required list.
- **Unchanged:** `driver/scripts/Invoke-StagedInvariantQualification.py` validates run/result schemas and uses the guest journal validators; no fixed manifest-field allowlist needed updating. Repository search found no additional strict agent manifest unknown-field rejection.

No PowerShell/harness source was edited. Windows PowerShell 5.1 parsing, native signature checks, harness self-checks and real runs were not performed here.

## New tests: all compiled only, none executed

44 source-declared cases across the following 13 methods; this count is not Windows test discovery/execution evidence. Existing assertions/tests were not removed or weakened. Windows guards follow neighboring tests; no skipped-test attribute was added.

`StagedHandbackTests` in `StagedUnboundSeedExportTests.cs`:

- `Unbound_seeded_block_uses_persisted_authority_and_recovers_without_disclosure` (4): Allowed keeps exact full-file hand-back; Denied/Unproven/evaluator throw remain private with named notification, closed justification, retained stage and recovery guard.
- `Unbound_nonseeded_block_keeps_ordinary_handback_without_evaluating_read` (5): absent OPEN_IF/CREATE and SUPERSEDE/OVERWRITE/OVERWRITE_IF never evaluate seed read authority and keep ordinary hand-back.
- `Unbound_seed_restriction_does_not_change_clean_publication_and_survives_archive` (2): Denied/Unproven do not alter clean published bytes; archived receipt survives restart.
- `Unbound_private_followup_inherits_public_seed_receipt_only_when_preserving` (3): OPEN/OPEN_IF inherit; truncation drops the receipt without a private-ACL probe.
- `Unbound_old_journal_without_seed_field_roundtrips_unchanged` (1).
- `Unbound_seed_denial_guards_real_copier_lease_and_justification_boundaries` (1, Windows guard).

`StagedSeedReadAuthorityNativeTests.cs` (Windows guarded, NativeWindows trait):

- `Native_readable_current_primary_is_allowed_only_in_the_supported_profile` (1): independent token/PrivilegeCheck facts require Allowed for eligible standard medium primary, Unproven for elevated/SYSTEM/unsupported profile. Run under a real standard user to exercise the full affirmative path.
- `Native_AccessCheck_read_data_uses_the_supplied_token_and_descriptor` (2): real AccessCheck Allowed/Denied with a duplicated token, including on elevated/SYSTEM legs; uses the production DACL check seam.
- `Export_envelope_keeps_unsupported_primary_subjects_unproven` (8).
- `Export_envelope_does_not_broaden_group_only_or_deny_conditional_read_grants` (4).
- `Native_descriptor_read_denial_is_not_overridden_by_the_held_service_read_handle` (1).
- `Native_subject_or_source_uncertainty_never_becomes_allowed` (6): PID, lifetime, SID, session, missing subject and invalid source handle.
- `Label_proof_refuses_read_up_or_uncertain_integrity` (6).

Independent offline security design/source review: Sol 6.1, high (`gpt-6.1-sol`), accept with conditions, no reported P0/P1 under the explicit primary-token scope. Conditions included native affirmative/DACL and envelope controls (now added, compiled only), documenting the conservative limits, and later native/matrix execution. Review acceptance is not qualification.

## Verification and remaining limits

Read local helper usage before running exactly `bash driver/scripts/Invoke-LocalAgentCompile.sh feature-debug feature-release`. First attempt failed because the new test file lacked its Notifications namespace import; fixed without changing an assertion. Attempts 2, 3 and 4 passed all Service/App/Tests feature Debug/Release builds with `-warnaserror`; 3 and 4 recompiled additional native coverage. Final source compile is attempt 4. `git diff --check` passed. Raw outputs and first-failure per-project logs remain locally in `t5-seed-export-local-compile/`; the complete helper stdout/stderr is reproduced verbatim below.

No xUnit test ran. Windows P/Invoke behavior, full affirmative evaluation under an eligible standard user, label/MIC and special descriptor behavior, source sharing/query failures, real tray display, impersonated callers and protected-pair behavior remain unverified. Thread impersonation is unavailable on this protocol. The owner will run focused Windows tests and the feature Debug/Release user + SYSTEM four-leg matrix. No gate or Windows result is claimed.

## Local compile output (verbatim)

Attempt 1:

```text
LocalAgentCompile root=/home/victor/Work/safeupload-t5seed profiles=feature-debug feature-release sdk=10.0.400 work=/tmp/safeupload-agent-compile.ivNdPs (diagnostic only; the matrix is the gate)
LocalCompile feature-debug Service PASS
LocalCompile feature-debug App PASS
LocalCompile feature-debug Tests FAIL (exit 1, log /tmp/safeupload-agent-compile.ivNdPs/feature-debug-Tests.log)
    agente/SafeUpload.Agent.Tests/StagedUnboundSeedExportTests.cs(110,63): error CS0246: The type or namespace name 'StagedJustifications' could not be found (are you missing a using directive or an assembly reference?) [/tmp/safeupload-agent-compile.ivNdPs/feature-debug/agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj]
    agente/SafeUpload.Agent.Tests/StagedUnboundSeedExportTests.cs(127,73): error CS0246: The type or namespace name 'StagedJustifications' could not be found (are you missing a using directive or an assembly reference?) [/tmp/safeupload-agent-compile.ivNdPs/feature-debug/agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj]
    agente/SafeUpload.Agent.Tests/StagedUnboundSeedExportTests.cs(178,64): error CS0246: The type or namespace name 'StagedJustifications' could not be found (are you missing a using directive or an assembly reference?) [/tmp/safeupload-agent-compile.ivNdPs/feature-debug/agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj]
    agente/SafeUpload.Agent.Tests/StagedUnboundSeedExportTests.cs(56,64): error CS0246: The type or namespace name 'StagedJustifications' could not be found (are you missing a using directive or an assembly reference?) [/tmp/safeupload-agent-compile.ivNdPs/feature-debug/agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj]
    agente/SafeUpload.Agent.Tests/StagedUnboundSeedExportTests.cs(86,52): error CS0246: The type or namespace name 'StagedJustifications' could not be found (are you missing a using directive or an assembly reference?) [/tmp/safeupload-agent-compile.ivNdPs/feature-debug/agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj]
LocalCompile feature-release Service PASS
LocalCompile feature-release App PASS
LocalCompile feature-release Tests FAIL (exit 1, log /tmp/safeupload-agent-compile.ivNdPs/feature-release-Tests.log)
    agente/SafeUpload.Agent.Tests/StagedUnboundSeedExportTests.cs(110,63): error CS0246: The type or namespace name 'StagedJustifications' could not be found (are you missing a using directive or an assembly reference?) [/tmp/safeupload-agent-compile.ivNdPs/feature-release/agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj]
    agente/SafeUpload.Agent.Tests/StagedUnboundSeedExportTests.cs(127,73): error CS0246: The type or namespace name 'StagedJustifications' could not be found (are you missing a using directive or an assembly reference?) [/tmp/safeupload-agent-compile.ivNdPs/feature-release/agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj]
    agente/SafeUpload.Agent.Tests/StagedUnboundSeedExportTests.cs(178,64): error CS0246: The type or namespace name 'StagedJustifications' could not be found (are you missing a using directive or an assembly reference?) [/tmp/safeupload-agent-compile.ivNdPs/feature-release/agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj]
    agente/SafeUpload.Agent.Tests/StagedUnboundSeedExportTests.cs(56,64): error CS0246: The type or namespace name 'StagedJustifications' could not be found (are you missing a using directive or an assembly reference?) [/tmp/safeupload-agent-compile.ivNdPs/feature-release/agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj]
    agente/SafeUpload.Agent.Tests/StagedUnboundSeedExportTests.cs(86,52): error CS0246: The type or namespace name 'StagedJustifications' could not be found (are you missing a using directive or an assembly reference?) [/tmp/safeupload-agent-compile.ivNdPs/feature-release/agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj]
LocalAgentCompile=FAIL (logs kept in /tmp/safeupload-agent-compile.ivNdPs)
```

Attempt 2:

```text
LocalAgentCompile root=/home/victor/Work/safeupload-t5seed profiles=feature-debug feature-release sdk=10.0.400 work=/tmp/safeupload-agent-compile.0fnse9 (diagnostic only; the matrix is the gate)
LocalCompile feature-debug Service PASS
LocalCompile feature-debug App PASS
LocalCompile feature-debug Tests PASS
LocalCompile feature-release Service PASS
LocalCompile feature-release App PASS
LocalCompile feature-release Tests PASS
LocalAgentCompile=PASS
```

Attempt 3:

```text
LocalAgentCompile root=/home/victor/Work/safeupload-t5seed profiles=feature-debug feature-release sdk=10.0.400 work=/tmp/safeupload-agent-compile.PuDaH2 (diagnostic only; the matrix is the gate)
LocalCompile feature-debug Service PASS
LocalCompile feature-debug App PASS
LocalCompile feature-debug Tests PASS
LocalCompile feature-release Service PASS
LocalCompile feature-release App PASS
LocalCompile feature-release Tests PASS
LocalAgentCompile=PASS
```

Attempt 4:

```text
LocalAgentCompile root=/home/victor/Work/safeupload-t5seed profiles=feature-debug feature-release sdk=10.0.400 work=/tmp/safeupload-agent-compile.cy3ivv (diagnostic only; the matrix is the gate)
LocalCompile feature-debug Service PASS
LocalCompile feature-debug App PASS
LocalCompile feature-debug Tests PASS
LocalCompile feature-release Service PASS
LocalCompile feature-release App PASS
LocalCompile feature-release Tests PASS
LocalAgentCompile=PASS
```

## Update 2026-10-21 (orchestrator): owner chose option A for group-granted read access

The worker's first version also required a direct read ACE for the account SID (`AccountGrantPermitsExport`), so read access held only through a group
(`Users`, `Authenticated Users`, `Everyone`) stayed `Unproven`. The owner chose **option A**: the verdict is the real process-primary token's `AccessCheck`
for FILE_READ_DATA on the held source's descriptor, plus the unchanged envelope (medium integrity, default elevation, unrestricted token, traversal privilege,
label proof, PID/creation-time/SID/session match and recipient match). The direct-ACE rule and its two tests were removed; `Native_AccessCheck_read_data_...`
now also covers group-only allow (`WD`, `AU`), an applicable group deny, and a grant only to another SID. Statements above about "direct effective account-SID
read grant" and `Export_envelope_does_not_broaden_group_only_or_deny_conditional_read_grants` describe the superseded first version.
