# T4 coverage query retries — 2026-10-12

**Finding:** the repeated `0x800704D5` query warnings have an intentional native retry path. The driver declines a coverage
snapshot that changed while it was read. The agent reports the failed query as degraded and polls again after 500 ms.
This explains the warning category; it does not prove that every degraded interval is brief or that runtime availability
is qualified. No readiness semantics or product behavior is changed here.

## Evidence and exact source

The [approved memory diagnostic's service events](m2t4memdiag1-service-events.txt) contain 21 unavailable-receipt warnings,
all with `0x800704D5` / `System.ComponentModel.Win32Exception`, and 21 corresponding `CoverageQueryFailed` degraded notices.
They span 23:40:40–23:45:48 UTC. No stage-reply or journal failure is present in this export.

Microsoft defines error 1237 (`0x4D5`) as `ERROR_RETRY`:
[system error codes](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1000-1299-).
[FilterSendMessage](https://learn.microsoft.com/en-us/windows/win32/api/fltuser/nf-fltuser-filtersendmessage) returns an HRESULT.

For the actual tested kernel `60fecdbc` and agent `6198eee7`:

1. `StageWriters.c:7750–7806` samples `RegistryChangeSequence` and global uncertainty around the complete registry walk.
   `:7799` returns `STATUS_RETRY` if either changed. The counter covers background registry activity too; it is not limited
   to this actor's protected files. Clearing uncertainty or ignoring this consistency check would be unjustified.
2. `StageAdmission.c:687–691` propagates that unsuccessful writer-summary status. The policy snapshot and epoch-status
   helpers do not return `STATUS_RETRY` in this path (`Policy.c:367–379,1306` onward).
3. `Communication.c:1164–1168` copies the coverage receipt only for successful native status. An unsuccessful snapshot
   therefore supplies no usable coverage receipt to the client.
4. `AdmissionCoverage.cs:324–328` throws when `FilterSendMessage` returns a nonzero HRESULT.
5. `MinifilterInterceptor.cs:809–868` logs the failure, publishes degraded coverage, and polls again after 500 ms. A query
   failure never authorizes a publication or declares protection Ready.

The service suppresses repeated warnings of the same exception type until a subsequent successful receipt resets
`lastQueryFailure` (`MinifilterInterceptor.cs:818,830–834`). Thus these 21 identical warnings imply at least 20 successful
receipt reads between them. A successful receipt may still evaluate as Pending or Degraded; this is not proof of 20 Ready
intervals. The warnings-only export omits informational Ready transitions, so it cannot establish recovery duration.

The source identifies a consistent explanation, but the previous run captured no native return-edge trace. Do not claim
that an individual warning's precise edge, or its effect on a save, was independently observed.

## Qualification action

The new `Invoke-StageCycles.sh` post-idle check reuses the existing bounded `t4/agent-readiness.ps1` reader after all original
memory/idle observations and the original verdict. It requires a current Ready frame, records its delay and last frame,
and fails the row if Ready does not return. It runs only after the original row passes, so repeated save failures proceed
straight to restoration. Earlier warnings remain in evidence. This adds an assertion; it changes no existing threshold,
sample window, kernel behavior, service status policy or cleanup authority.

The clean short row was launched at commit `1d488a3f`. The
[PowerShell 5.1 gate](harness-windows-gate-t4-post-idle-coverage1.txt) passes all 19 harness self-checks; Bash syntax and source
whitespace checks also pass. Runtime evidence for the post-idle assertion will be recorded with the qualifying row.
Further product changes, including reclassifying a retry as Pending
or keeping an older Ready status, would need the required security design review and an owner decision about user-visible
behavior. They are not part of this harness change.
