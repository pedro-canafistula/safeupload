# T5 rows worker result — 2026-10-21

Harness implementation and offline diagnostics only. Branch `t5/rows`, unchanged HEAD/base `6aef8cf6`. No VM, builder, SSH, libvirt or network action ran. No Windows result, Windows PowerShell 5.1 gate, protected-driver qualification or cutover is claimed. `driver/POST-MVP-PLAN.md` and `.ai-memory.toml` were not changed.

The existing eight cases remain required, with their original native status expectations and raw/public-reader checks. Twelve additional case kinds express the requested eight workflow groups, giving 20 cases and 21 independently observed leaves (including the Explorer old name). `notepad-cases.json` is the single case/leaf inventory used by coordinator, launcher and self-checks. Raw sample/baseline cardinalities still require the complete inventory, including the parent image.

## Work by stage and file

1. Journal reader: ported SUAC/SUJA v1 framing, committed-frontier/payload SHA-256 verification, inventory/driver-epoch parsing, transient temporary-file handling and exact transfer-ID binding into `driver/scripts/t5/notepad-coordinator.ps1`. Archive first, hot records next, then archive-byte/inventory recheck; exact hot/archive consolidation is accepted only with byte equality and both artifacts retained. Conflicting copies fail closed. Every logical record still runs the T5 schema and lineage validators. The 1024 logical-record, 64 MiB snapshot and 128 KiB manifest limits remain; packs separately retain the product's 4 MiB bound. SealPending/state 10 remains accepted under the current T5 seal contract. Terminal adapters include acknowledged DiscardPending (whose StageDeleted field can correctly remain false), ordinary Released, exact blocked cleanup and exact unbound cancellation. None grants publication authority.
2. Inventory/failure isolation: `driver/scripts/t5/notepad-cases.json` replaces the duplicated hard-coded inventories in coordinator/launcher. Each case has its own catch/finally receipt; a failed observation gate is never released as proved. Its actor timeout/ack is drained before progressing. Aggregate verdicts still fail when any required case or evidence fails. Stage 2 was checked with the original eight cases before adding new kinds.
3. Workflow cases: `driver/scripts/t5/notepad-actor.ps1` adds native create/truncate/append/move, second-process read/write open and delete, held-handle controls, Shell.Application item rename and silent IFileOperation DeleteItem. It keeps one embedded C# definition so the existing actor self-check's exact-one-definition assertion remains intact. Every new ack includes actor PID/SID/path, native codes and child receipts; UI diagnostics retain window titles/text and Shell item observations, including failures. Real Notepad clean/CPF Save As stays present. Clear/save uses the explicitly labeled native TRUNCATE_EXISTING equivalent; existing blocked edit uses readable OPEN_EXISTING plus append.
4. Coordinator workflow helpers seed exact clean bytes, wait for journal release and stage cleanup alongside raw observations, apply/restore both DELETE and DELETE_CHILD denial fixtures as SYSTEM, compare native unprotected denial codes, inspect full hand-back bytes through three independent readers, and retain hand-back artifacts. New observations reject unexpected nonempty fixture bytes as well as CPF. This exact-fixture check does not replace an inspection/lower-mutation ledger.
5. `driver/scripts/Invoke-StageNotepad.sh` uploads the shared inventory, evaluates all case kinds separately, independently validates retained archive payload/container/transfer bindings and full hand-back artifacts, and permanently captures the agent journal, private staging directory and recursive listing from the diagnostic launcher. Immutable journal copies and hand-backs are also copied out. Diagnostic agent-directory copies are best effort; required raw/artifact evidence stays fail-closed.
6. `driver/scripts/Invoke-HarnessWindowsGate.sh` now includes the T5 schema/storage/native-declaration/existing actor self-checks and the tiny real-pack fixtures. Existing gate files/checks are preserved. Pack bytes are hashed rather than parsed as PowerShell. The gate was edited, never executed remotely.
7. Self-check files: existing `notepad-verdict.SelfCheck.py` reads the shared inventory; existing `notepad-coordinator.SelfCheck.ps1` imports the added reader dependencies and retains all 174 assertions. New `notepad-archive.SelfCheck.py`, `notepad-journal.SelfCheck.ps1`, `notepad-workflow.SelfCheck.py` and `notepad-native.SelfCheck.ps1` exercise actual helpers/declarations. `notepad-offline.SelfCheck.ps1` is an explicitly nonqualifying PS7 runner, preserving PS5.1 JSON timestamp strings during local replay. Windows runs the standalone checks without that adapter.

Each requested stage's `git add`/`git commit` was attempted. The sandbox rejected creation of `.git/index.lock` with `Read-only file system`, so no commit was created and HEAD is unchanged. Changes remain in the working tree; no push was attempted.

## New cases and expected outcomes

Sources: [T5-DELETES](../../T5-DELETES.md), especially sections 1 invariant 4, 2, 4 and 8; [decided unbound D1–D6](../../T5-UX-NAMESPACE-GAP.md#decided-unbound-design-d1d6).

| Kind / leaf | Required observed outcome | Source |
|---|---|---|
| ExplorerEmptyRename / explorer-renamed.txt (old explorer-new.txt) | CREATE_NEW + close publishes exactly zero bytes; Shell.Application FolderItem.Name renames in place; a second PowerShell process opens read/write and reads length 0/EOF. New name remains exactly empty; old name absent; no private leftover. | T5 §2, §8; D1, D3 |
| EmptyCopy / empty-copy.txt | Copy-Item of an empty source publishes exactly zero bytes with ordinary release/cleanup evidence. | T5 §2, §8 |
| EmptyMove / empty-move.txt | MoveFileExW(COPY_ALLOWED) publishes exactly zero bytes; source is absent. | T5 §2, §8 |
| ClearExistingSave / clear-existing.txt | Publish exact prior text, then native TRUNCATE_EXISTING + zero-byte write/close; ordinary release leaves exactly zero public bytes. This is a native equivalent, not a real Notepad clear/save result. | T5 §2, §8 |
| PublicDeleteRemoveItem / delete-remove.txt | Publish prior text; Remove-Item deletes it. Raw and buffered final reads agree on absence; no stage remains. Required journal public-delete barrier must also be proved. | T5 §4, §8; D1, D2 |
| PublicDeleteExplorer / delete-explorer.txt | Same final absence/cleanup/barrier requirements using IFileOperation::DeleteItem with FOF_SILENT, FOF_NOCONFIRMATION and FOF_NOERRORUI (0x414). All HRESULTs and aborted flag are checked. | T5 §4, §8; D1, D2 |
| PublicDeleteDeniedAcl / delete-denied.txt | Explicit deny of file DELETE and parent DELETE_CHILD for the actor; child-process DeleteFileW returns 5, exactly as the unprotected fixture. Public prior bytes unchanged; no private cancellation. Both original SDDLs restored exactly in finally. | T5 §4, §8; D1, D2 |
| PublicDeleteDeniedSharing / delete-sharing.txt | A separate open omits FILE_SHARE_DELETE; child-process DeleteFileW returns 32, matching unprotected NTFS. Prior bytes unchanged; no cancellation; held handle closes. | T5 §4, §8; D1, D2 |
| DeleteNewerWriterOpen / delete-writer.txt | Published P exists; actor holds the newer private writer. Probe-ready/go gates require two complete raw P images and the exact unsealed actor allocation. Second-process delete returns 32; closing the writer then permits exact newer clean publication. No cancellation is recorded on the refused delete. | D2, D6; T5 §1.4, §4, §8 |
| DeleteNewerPublished / delete-published.txt | Close the newer writer first. Probe-ready/go waits for exact Released/newer journal and raw bytes before child delete returns 0. Final name absent, no stage; public-delete barrier remains a separate required assertion. | D2, D6; T5 §1.4, §4, §8 |
| DeleteThenBlockedSave / delete-then-cpf.txt | Explicit child-process public delete succeeds and raw absence is observed before a CPF CREATE_NEW save. Exact CPF hand-back exists in the actor profile; final public name stays absent, with no empty public/private leftover. | T5 §1.4, §4, §8; D2, D6 |
| ExistingBlockedEditHandback / existing-blocked-edit.txt | Publish exact clean prior text, OPEN_EXISTING with caller read/write access, append CRLF + CPF and close. Blocked manifest and hand-back contain the full prior + appended bytes; public file keeps the original bytes. | T5 §8; caller read/export invariant in AGENTS.md; D1, D6 |

Every case produces `T5<Kind>`, `T5<Kind>NoEmptyLeftover` and workflow journal verdicts; in-flight cases additionally produce ForcedOrder, and public-delete cases produce DeleteBarrier. Native method and case errors are included in the main verdict detail.

## Deliberately unproved requirements

The existing probe gates cannot pause inside the short physical final-rename/journal-mutex turn. The implemented deterministic orders bracket it at **writer held before seal** and **independently observed Released publication after commit**. The ack/record/verdict explicitly says this; there is no invented timing race or sleep-based proof. Fine-grained inside-turn ordering remains for the orchestrator or a separately approved observation hook.

The current unbound native public-delete route need not write a durable public-delete journal barrier. A prior Released receipt, a private discard ACK or allocation ancestry is not that barrier. The new public-delete cases therefore leave `DeleteBarrierVerified=false` and emit **INCONCLUSIVE** for this required assertion; their overall case cannot PASS without a future qualified adapter for actual public-delete evidence. No fabricated record or threshold change hides this gap.

The existing canonical `T5CanonicalNoUnapprovedByte` remains INCONCLUSIVE: sampled raw images, exact fixture hashes and independent readers do not supply the missing complete lower-admission/completion mutation ledger. No new observed-image result promotes that verdict to PASS.

No native ACL, sharing, IFileOperation, UI, staging, hand-back or target Windows behavior was verified here. Windows PowerShell 5.1 parsing/native controls and the real win10-debug3 row remain orchestrator work. Overall row timeout and existing native-status requirements were preserved.

## Offline verification

Commands below ran locally, without VM/network contact. PowerShell executable used (not on PATH):

```
/home/victor/.local/share/containers/storage/overlay/8f5ff742b8cfe7eefa11cb0b3295450362e17c865ff95d1f7020623fb8524808/diff/opt/microsoft/powershell/7/pwsh
```

Its invocations used `TEMP=/tmp XDG_CACHE_HOME=/tmp/t5-pwsh-cache XDG_CONFIG_HOME=/tmp/t5-pwsh-config`. Initial direct PS7 schema replay exposed date parsing differences; the checked-in offline runner preserves original JSON date strings to emulate PS5.1. No production UTC assertion was relaxed. The standalone existing actor check explicitly requires Windows PS5.1/native NTFS and was not executed here; its assertions are unchanged and it is now included in the Windows gate.

Commands and verbatim final result lines:

```
python3 driver/scripts/t5/notepad-verdict.SelfCheck.py
T5HostVerdictSelfCheck=PASS;Assertions=14;ProductQualified=False

python3 driver/scripts/t5/notepad-archive.SelfCheck.py
T5ArchivePayloadSelfCheck=PASS;Assertions=45;ProductQualified=False

python3 driver/scripts/t5/notepad-workflow.SelfCheck.py
T5HostVerdictSelfCheck=PASS;Assertions=14;ProductQualified=False
T5WorkflowVerdictSelfCheck=PASS;Assertions=146;ProductQualified=False

pwsh -NoProfile -File driver/scripts/t5/notepad-native.SelfCheck.ps1
T5NativeDeclarationSelfCheck=PASS;Blocks=1;NativeCallsExecuted=False;ProductQualified=False

pwsh -NoProfile -File driver/scripts/t5/notepad-offline.SelfCheck.ps1
notepad-actor.ps1:ParseErrors=0
T5ActorNativeCompile=PASS;NativeCallsExecuted=False
notepad-coordinator.ps1:ParseErrors=0
notepad-coordinator.SelfCheck.ps1:ParseErrors=0
notepad-journal.SelfCheck.ps1:ParseErrors=0
T5 coordinator schema self-check PASS (174 assertions).
T5JournalStorageSelfCheck=PASS;Assertions=40;ProductQualified=False
T5OfflinePowerShellSelfCheck=PASS;JsonDateMode=PS5StringEmulation;WindowsGate=False;ProductQualified=False

python3 driver/scripts/t4/verdict-selfcheck.py
T4VerdictSelfCheck=PASS; retained replay and context/registry refusal controls; Qualification=False

python3 driver/scripts/Invoke-ExactAgentMatrixBuild.SelfCheck.py
Ran 21 tests in 1.789s
OK

python3 driver/scripts/Invoke-StagedInvariantQualification.ArchivePayload.SelfCheck.py
ArchivePayloadSelfCheck=PASS;Checks=18;RetainedReplay=ABSENT;Qualification=False
```

The unchanged Phase 4 archive check does not find its default retained replay in this clone. The T5 checks above require and replay **both** copied real packs; they do not silently skip missing fixtures.

A local extraction of the existing Windows gate's PowerShell file inventory, parsed with the PS7 parser without executing the gate, produced:

```
T5OfflineGateInventoryParse=PASS;Files=64;WindowsGate=False;ProductQualified=False
```

`bash -n driver/scripts/Invoke-StageNotepad.sh`, `bash -n driver/scripts/Invoke-HarnessWindowsGate.sh` and `git diff --check` exited 0 with no output. The Python self-checks parse the actual embedded launcher Python. Shared inventory parsing returned `CasesCount=20 FirstKind=ProbeDelete` and `LeavesCount=21`.

## Retained positive controls

`driver/scripts/t5/fixtures/provenance.json` records original read-only locations and SHA-256 values. Only these small pack copies are added; original evidence was not modified.

- C01 `service-after-completed-00000001.pack`: `8DE8709861A70B0EB86B65A2D64C39A7B71E5F4E96908BCD27274A97CC6B50B6`.
- m2t5ord4 `completed/00000001.pack`: `3777A7962DB91C952EDEF08F80A741C7280EFCD6BE1CCA411168373CB9A9B8F4`.

The new storage controls exercise both real packs, exact transfer binding, schema/lineage replay, sidecars, hot/archive consolidation, corruption refusal and all three inspection bounds. Workflow controls reject incomplete acks, wrong paths/principals, wrong native statuses, wrong final/intermediate bytes, invalid forced ordering and missing full-content hand-backs.

Implementation is left reviewable in the working tree. Offline diagnostics passed within the limitations above; committing, the Windows gate and target qualification remain outstanding.
