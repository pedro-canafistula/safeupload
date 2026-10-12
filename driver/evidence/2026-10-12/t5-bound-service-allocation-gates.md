# T5 connected service allocation — builder gates

Agent source: `be78b95846181c50a1d61b3a169af9119a5fc9a7`; matrix `t5-bound-service4`.
**AgentMatrixGate=True; independent discovery/execution gate PASS.** No revised driver pair was installed or booted.
The bound-head capability remains unadvertised and live admission disabled.

| Agent profile | Passed / discovered / unique executions | New allocation/continuation cases |
| --- | ---: | ---: |
| Normal Debug | 863 / 863 / 863 | compiled out |
| Normal Release | 863 / 863 / 863 | compiled out |
| Feature Debug | 1112 / 1112 / 1112 | 11 / 11 |
| Feature Release | 1112 / 1112 / 1112 | 11 / 11 |

Every service, tray, test, discovery and Release-package leg passes at **0 warnings / 0 errors**; no skipped tests.
The host gate independently checks discovered/executed totals and unique IDs. The 11 new results were additionally recounted
from both feature user TRX files: all Passed with unique executions. Ten cases use the real Windows filesystem; one proves
unrelated continuation progress and cancellation/drain. These are service controls, not a protected FilterPort or Verifier run.

The receive branch now calls the V23 allocator asynchronously, copies each message before enqueueing, and drains accepted work
before port close. Allocation serializes duplicate reservation GUIDs and the destination turn, bounds active disk work, reopens
the recorded volume/parent by identity, validates full IDs and case mode, and seeds only an exact held source. Receipt validation
uses those anchors rather than the saved locator. A flushed bound manifest precedes its head claim; a failed claim retains the
private candidate, exact replay completes it, and an overtaken candidate cannot roll the head back. Bound entries are refused by
legacy pathname publication/recovery while the anchored commit pipeline is unfinished.

Controls cover existing-target dispositions and exact replay after reopen, parent rename plus locator replacement, changed
public identity/false absence, an actual native head-write failure after manifest flush, recovery of that same private identity
and generation, overtaken-candidate retention, concurrent GUID reuse, and continuation drain. The last source also proves a
failed head claim cannot produce an allocation receipt. Existing transport, generation, inspection and privacy assertions remain.

Normal Release package SHA-256: `493C1886434534D16C5C1F24D5C092BC2ACA4653E71B12B23357787AA9A65B00`.
Feature Release package SHA-256: `8B2F04BF0094D0DE39D4246FF78B7CD2883ABEC7FA3996E267828C7E9913A186`.
Raw output stays local in `output/exact-agent-matrix/t5-bound-service4/` and the matching
`exact-agent-matrix-t5-bound-service4-*` / `t5-bound-service4-agent-matrix-host.txt` evidence files.

Earlier attempts remain retained: service1 stopped before delivery because the builder was off; service2 passed both normal
profiles and feature service builds, then failed the test analyzer on the assertion overload; service3 passed all four profiles.
Service4 is the final source gate after request-copy and anchored-receipt corrections. No failure was relabeled as a pass.

Driver sources are unchanged from `827b3f41` through this agent source. Its four WDK builds remain at 0/0 with PREfast/ApiValidator
in [the driver/transport gate](t5-bound-allocation-static-gates.md). This does not complete T5: kernel capture/revalidation, all
physical publication/delete permits, exact native close/startup recovery, acknowledgements and teardown still need integration,
the single pre-boot lifetime review, and protected native/Notepad/fault rows with independent bytes and separate restoration.
