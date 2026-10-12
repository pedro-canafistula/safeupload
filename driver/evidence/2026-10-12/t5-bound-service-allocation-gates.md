# T5 connected service allocation — builder gates

Driver and agent source: `dbe02d0485fcc416726c9d316d1b58dd0063c369`; matrix/WDK label `t5-rpc-integration1`.
**AgentMatrixGate=True; independent discovery/execution gate PASS.** No revised driver pair was installed or booted.
The bound-head capability remains unadvertised and live admission disabled.

| Agent profile | Passed / discovered / unique executions | New allocation/continuation cases |
| --- | ---: | ---: |
| Normal Debug | 863 / 863 / 863 | compiled out |
| Normal Release | 863 / 863 / 863 | compiled out |
| Feature Debug | 1113 / 1113 / 1113 | 12 / 12 |
| Feature Release | 1113 / 1113 / 1113 | 12 / 12 |

Every service, tray, test, discovery and Release-package leg passes at **0 warnings / 0 errors**; no skipped tests.
The host gate independently checks discovered/executed totals and unique IDs. The 12 allocation results were additionally recounted
from both feature user TRX files: all Passed with unique executions. Eleven cases use the real Windows filesystem; one proves
unrelated continuation progress and cancellation/drain. These are service controls, not a protected FilterPort or Verifier run.

The receive branch now calls the V23 allocator asynchronously, copies each message before enqueueing, and drains accepted work
before port close. Allocation serializes duplicate reservation GUIDs and the destination turn, bounds active disk work, reopens
the recorded volume/parent by identity, validates full IDs and case mode, and seeds only an exact held source. Receipt validation
uses those anchors rather than the saved locator. A flushed bound manifest precedes its head claim; a failed claim retains the
private candidate, exact replay completes it, and an overtaken candidate cannot roll the head back. Bound entries are refused by
legacy pathname publication/recovery while the anchored commit pipeline is unfinished.

Allocation replay now checks the live process PID/session/SID/creation before and after replay. Its regression uses a real
Windows process and allocation, refuses stale lifetime/session/SID/PID tuples, and confirms the candidate stays private.
The kernel V23 sender retains a byte-identical replay request and validates packed binding, PID and zero tails. Ordinary RPCs
no longer hold a global mutex while allocation waits; epoch transitions remain serialized and an authority revision prevents
an old same-channel reply from restoring a grant after reconcile/drain. The producer is still unwired; these are static gates.

Controls cover existing-target dispositions and exact replay after reopen, parent rename plus locator replacement, changed
public identity/false absence, an actual native head-write failure after manifest flush, recovery of that same private identity
and generation, overtaken-candidate retention, concurrent GUID reuse, and continuation drain. The last source also proves a
failed head claim cannot produce an allocation receipt. Existing transport, generation, inspection and privacy assertions remain.

Normal Release package SHA-256: `A93C2B0EDB3FB561D3F146E201A40162D5AE855315EFCD237CC8DB6CF93F5364`.
Feature Release package SHA-256: `A2BFB9D2639AA4B2F615BCDFEE0DA74AA8A17F70B324CE0EB955BB1D24D6D1C9`.
Raw output stays local in `output/exact-agent-matrix/t5-rpc-integration1/` and the matching
`exact-agent-matrix-t5-rpc-integration1-*` / `t5-rpc-integration1-agent-host.txt` evidence files.

Earlier attempts remain retained: service1 stopped before delivery because the builder was off; service2 passed both normal
profiles and feature service builds, then failed the test analyzer on the assertion overload; service3 passed all four profiles.
Service4 passed at `be78b958`; the current integration gate supersedes it. No failure was relabeled as a pass.

All four WDK profiles on this same source pass at 0 warnings / 0 errors with PREfast/ApiValidator, as do the inspector/writer
builds and signature verification ([raw summary](exact-t5-rpc-integration1-summary.txt)). The signed feature Debug SHA-256 is
`F03AA35EF06EFBD923D41CC0D68E285E012F971D9A1C5DF16C2680EBA0777D08`.
Before building, only regenerable project bin/obj from completed old builder runs were removed; source, output logs and packages
were retained. Builder free space rose from 234 MB to 6.22 GB; no host or VM configuration was changed.
This does not complete T5: kernel capture/revalidation, seed-sharing/read-authority design, all
physical publication/delete permits, exact native close/startup recovery, acknowledgements and teardown still need integration,
the single pre-boot lifetime review, and protected native/Notepad/fault rows with independent bytes and separate restoration.
