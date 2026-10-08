# Durable notification record v1

The service creates `%ProgramData%\SafeUpload\notifications`. Production requires a protected, trusted parent and an exact non-inherited SYSTEM/Administrators FullControl DACL on the directory and files, with a SYSTEM or Administrators owner. Existing permissions are inspected, never repaired. Final files are opened without following reparses, with same-handle ACL checks and exactly one hard link; path ancestors reject reparses. Privileged local actors remain trusted, as for policy/journal evidence. This is ACL-authenticated local evidence, not a signature against an administrator.

`emissions.jsonl` is UTF-8 without BOM, with one compact JSON object and LF per line. `previous.jsonl` retains the previous segment. Each segment is at most 4 MiB, each line less than 16 KiB. Every line has:

| Field | Meaning |
| --- | --- |
| `Version` | `1` |
| `Sequence` | Increasing Int64 across service starts, boots, and rotations |
| `BootId` | machine name + `/` + Windows boot UTC time in round-trip format (microsecond precision, matching the suite's CIM boot identity) |
| `InstanceId` | new GUID for each recorder/service lifetime |
| `Utc`, `Qpc`, `QpcFrequency` | UTC emission time, Stopwatch timestamp, and frequency |
| `Kind` | `Transfer`, `Event`, `Status`, or coverage/control `Start`, `Heartbeat`, `Stop`, `Rotation` |
| `TransferId`, `EventId` | transfer identity when available; legacy audit event identity separately |
| `Phase` | transfer phase or legacy audit verdict; null for status/control records |
| `TargetSessionId` | original notification routing session, if present |
| `PreviousSha256` | uppercase SHA-256 of the preceding exact UTF-8 JSON bytes, excluding LF; 64 zeroes for genesis |
| `DroppedThroughSequence` | announced discarded prefix, initially zero |

`head.json` contains `Version`, `Sequence`, and `Sha256` for the last line. This separate protected, flushed head detects tail truncation that a chain by itself cannot detect. `writer.lock` is a zero-byte exclusive writer lease, authenticated like the other files. A retained lease with missing history cannot silently start a new sequence.

Each append uses write-through IO and `Flush(true)`, then writes and flushes a private temporary head before replacing `head.json`. Only then can the hub retain/enqueue a publication. Replay enqueue and connection-status sends also append before sending. Broadcast publication has one record independent of subscriber count; these are emission records, not client delivery acknowledgments. A recording error is logged and suppresses that send; any uncertain recorder write poisons that recorder lifetime. A malformed/truncated record or interrupted head update is retained for investigation, never automatically repaired.

The recorder emits `Start`, one-second `Heartbeat` records, and a best-effort `Stop`. Rotation first durably appends a `Rotation` record announcing the prefix to discard, then removes the older segment and renames the active segment to `previous.jsonl`. Sequences and predecessor hashes continue into the new active file. Crashes partway through rotation may require investigation; they cannot qualify absence evidence. Total retained segment data is bounded by 8 MiB plus small head/lease/temporary metadata.

The WP4 adapter authenticates ancestors, owner, exact DACL, regular file type, single link, and bounded bytes from the same opened handles. Live files permit write/delete sharing so a snapshot cannot cause a service IO failure. Torn reads, incomplete lines, chain/sequence errors, and mismatched heads cause retry, then INCONCLUSIVE. Product bytes and descriptors are retained as case artifacts.

Absence requires complete operation QPC fences, matching boot/frequency, the exact before head retained in the after chain, contiguous sequences and predecessor hashes, one service instance, monotonic QPC, no Start/Stop in the covered range, no gap over five seconds, and records bracketing the whole operation window. Rotation past the starting head, stale/missing records, service restart, poison, or missing coverage cannot PASS. An empty Application log never supplies this proof. Agent-down cases without an independently covered record remain INCONCLUSIVE.

The current table's negative expectations use all agent emissions conservatively: `NoApproval` rejects transfer Released or event Approved; `NoRelease` also rejects event AllowedWithoutInspection; `NoHandBack` rejects transfer/event Blocked or Retained. `ExpectedNone`, `None`, and `NoNotification` reject every Transfer/Event/Status emission in the window. Unsupported expectations remain INCONCLUSIVE. Journal evaluation is unchanged; overall Phase 4 coverage still requires the existing lower-ledger/live-taint evidence.

# Orchestrator handoff (not run here)

These edits are uncommitted. **The existing exact-build wrapper archives a Git revision, not the dirty worktree.** The orchestrator must first integrate these exact files into its build revision outside this no-commit authoring task. Passing unchanged HEAD would build the old code. Qualification also checks agent source against that revision and refuses dirty or untracked agent source.

On the Windows guest, run the pure adapter check:

```powershell
powershell.exe -NoProfile -File driver\scripts\StagedInvariantProofAdapters.SelfCheck.ps1
```

From the repository, using unique labels and the integrated source revision:

```bash
bash driver/scripts/Invoke-ExactAgentBuild.sh "$NOTIFY_AGENT_LABEL" "$NOTIFY_AGENT_SOURCE_COMMIT"
python3 driver/scripts/Invoke-StagedInvariantQualification.py \
  "$NOTIFY_RUN_TAG" "$DRIVER_LABEL" "$DRIVER_SOURCE_COMMIT" \
  "$NOTIFY_AGENT_LABEL" "$ORIGINAL_POLICY_SHA256" \
  --agent-source-commit "$NOTIFY_AGENT_SOURCE_COMMIT"
```

The qualification command expands the table over ordinary, runtime-verifier, and boot-verifier modes, using the current suite/table/observer inputs and its Prepare → activating reboot → AfterBoot → restoration reboot → Finalize lifecycle. Existing NotReady rows and missing proof still prevent a full-suite PASS. For just the implemented seed cases, add `--cases S00-observer-control S01-denied-write-after-boot S02-agent-down-open-refused --modes ordinary`; this is a subset run, not full qualification.

`Invoke-ExactAgentBuild.sh` invokes `Build-ExactAgent.ps1` on the designated builder. Its exact xUnit and publish commands are:

```powershell
dotnet.exe test agente\SafeUpload.Agent.Tests\SafeUpload.Agent.Tests.csproj -c Release -warnaserror `
  --logger 'trx;LogFileName=agent-tests.trx' --results-directory $out
dotnet.exe publish agente\SafeUpload.Agent.Service\SafeUpload.Agent.Service.csproj -c Release -r win-x64 `
  --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -warnaserror -o $publish
```

No Windows execution or VM qualification was performed during authoring. The local host has no .NET SDK. Linux PowerShell synthetic evaluation and temporary compatibility compilation/exercises do not substitute for the builder's xUnit/TRX gate, Windows ACL/link behavior, boot identity comparison, or VM suite evidence.

# Changed files

- `agente/SafeUpload.Agent.Service/Notifications/NotificationRecord.cs` — recorder, head, lifecycle coverage, rotation, protected writer lease.
- `agente/SafeUpload.Agent.Service/Notifications/NotificationHub.cs` — record before publication, replay, or retained status send; suppress/log recording failures.
- `agente/SafeUpload.Agent.Service/Notifications/NotificationPipeServer.cs` — use the recorded retained-status path.
- `agente/SafeUpload.Agent.Service/Program.cs` — production recorder registration and fail-closed initialization fallback.
- `agente/SafeUpload.Agent.Service/Interception/StagedJournalFile.cs` — reuse no-follow/single-link handles with an optional write-through writer and caller size bound; journal defaults preserved.
- `agente/SafeUpload.Agent.Tests/NotificationRecordTests.cs` — ordering, exact chain/head, recovery, corruption/truncation, rotation, failure suppression/logging, concurrent emitters, duplicate writer, ACL and link refusal, replay/status coverage.
- `agente/SafeUpload.Agent.Tests/NotificationTestHub.cs` — explicit in-memory test recorder.
- `agente/SafeUpload.Agent.Tests/NotificationHubTests.cs` — use the explicit test recorder.
- `agente/SafeUpload.Agent.Tests/StagedTransferPublisherTests.cs` — use the explicit test recorder.
- `driver/scripts/Test-StagedInvariantSuite.ps1` — authenticated notification snapshots and covered-window expectation evaluation.
- `driver/scripts/StagedInvariantProofAdapters.SelfCheck.ps1` — raw-chain and negative-expectation synthetic cases.
- `driver/scripts/StagedInvariantCases.psd1` — describe the durable notification evidence contract.
- `agente/NOTIFICATION-RECORD.md` — format, proof rules, limitations, exact orchestrator handoff.
