# Local outcome-history repro

Run from the repository root with the supplied .NET SDK. Use fresh output labels;
keep previous runs, including failed attempts. For example:

```bash
/home/victor/Work/safeupload-tools/dotnet/dotnet restore driver/evidence/2026-10-16/ux-journal3/repro.csproj --artifacts-path "$PWD/.scratch/ux-journal3-repro-build" --source /home/victor/.nuget/packages -p:NuGetAudit=false -p:RestoreDisableParallel=true -p:SafeUploadAdmissionEvidence=true -m:1
/home/victor/Work/safeupload-tools/dotnet/dotnet build driver/evidence/2026-10-16/ux-journal3/repro.csproj --artifacts-path "$PWD/.scratch/ux-journal3-repro-build" --no-restore -p:SafeUploadAdmissionEvidence=true -m:1
/home/victor/Work/safeupload-tools/dotnet/dotnet .scratch/ux-journal3-repro-build/bin/repro/debug/SafeUpload.Agent.Tests.dll .scratch/ux-journal3-repro-run recent
```

This console fixture uses the journal's actual create/seal/state/commit/completion,
worker maintenance, archive, audit and durable notification implementations. The
native rename callback is a no-op. It measures metadata and audit work, not NTFS
public bytes, native caller rights, extraction, driver timing or product qualification.
The friend assembly name permits the same internal operations exercised by tests.

There are 10,000 sequential lifecycles over eight fixed destination names. `recent`
adds an observer audit append and `ReadRecentAsync(5)` after each completed save,
modeling the work reached by legacy `Announce`. Omit it for the journal-only control.
All terminal receipts are retained. Each 500th cycle reports hot/archived counts and
the last 100 saves' mean phase times in milliseconds, in this order:

1. Allocate.
2. Seal.
3. Worker receipt/progress/disposal/archive/audit/pending maintenance.
4. Journal inspection/approval/publication transitions and completion.
5. Publication audit/notification, stage disposal and archival.
6. Observer audit append and recent-event read (zero in the journal-only control).

Stage-file fixture construction is outside the timer. Required durability flushes
are inside it. The full before/fixed runs use identical fixture source; only the
product implementation changes. Checkpoint data retains write-phase latency bursts on the shared host.
The smaller committed xUnit control independently asserts allocation/time bounds,
exact newest-event IDs/order, unchanged history bytes and retention of all 10k events.

The original journal-only control was recorded before adding the observer phase;
its raw samples have five phase columns. The before/fixed observer runs have six.
