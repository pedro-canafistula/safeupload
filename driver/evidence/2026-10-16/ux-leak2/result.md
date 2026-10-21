# ux/leak2 candidate receipt

Base: `429e7fa90c6bf43b9973826629f90a1ed4af1611`. Owner regression: bisected
`90a908c7` versus reverted `85e89b7f`, win10-debug3, Word/read FILE_OPEN
sharing refusals for about 40 seconds. Raw bisect evidence was not accessible
in this workspace; the report is owner-supplied evidence, not our rerun.

Outcome: remove the previous fix's per-context post-CREATE event wait, preserve
bounded retirement through pre-prune leases, add same-owner and independent
process immediate reopen controls and exact sharing-gate diagnostics. **The
actual Word cause and successful native remediation remain unconfirmed.**
See [design and limits](../../../docs/design/lifetime/UX-LEAK2.md).

Host verification: 21 Python control scripts were executed. The initial run had
one source-literal failure after diagnostics expanded the delete-pending block;
the same mandatory sharing refusal/goto is now checked including its diagnostic
assignment. That focused control passes. The final retirement and getter
controls pass (5 and 3 cases, cc and clang, undefined-behavior sanitizer,
including compiled negative mutations). Retirement includes 10,000 cycles.
Other executed host controls passed; full discovery is in verification.json.
Embedded actor/observer C# compiles with .NET 10, 0 warnings/errors. Bash syntax
and diff whitespace pass. Source API-name comparison adds no kernel API names.

Sol 6.1 xhigh independently reviewed the candidate lifetime/lock protocol;
conditional acceptance is source-only. No WDK build, PREfast, ApiValidator,
actual import gate, PS5.1 parsing/native run, target boot, Word test or 10,000
save pool measurement was performed. VM read-only IPC and guest SSH attempts
were denied by the session sandbox before connecting (Operation not permitted).
No lab action or host configuration change was performed by those attempts.

Raw local controls and the first failed check remain under `.scratch/ux-leak2`.
Original Git HEAD/index/refs are read-only; the delivery commit and bundle are
created only in an isolated repository there. Existing evidence and memory are
preserved. Required native gates remain open; this is not T4 qualification.
