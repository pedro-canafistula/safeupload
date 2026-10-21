# SafeUpload contributor instructions

## Start here

- Read [driver/POST-MVP-PLAN.md](driver/POST-MVP-PLAN.md) for current scope, owner decisions, stops and qualification status. Read the relevant T-item design before changing its implementation.
- Doc map: [driver/README.md](driver/README.md) lists the layout, and [driver/docs/README.md](driver/docs/README.md) indexes the designs, reviews, operations notes and history (with the former path of every moved file).
- [driver/M2-COMPLETION-PLAN.md](driver/M2-COMPLETION-PLAN.md) contains the 2026-10-13 review and proposed execution order. Recommendations there are not approval of pending product choices or VM runs.
- [driver/MVP-PLAN.md](driver/MVP-PLAN.md) records the historical component baseline. Old logs, source comments and memory summaries do not override current decisions.
- Inspect `git status` before editing. Preserve unrelated work, local evidence and the user's `.ai-memory.toml`. Treat memory as historical evidence; verify it against source and current decisions.

## Repository map

| Area | Purpose |
|---|---|
| `driver/SafeUpload.Minifilter/` | Windows kernel minifilter; writer tracking, staging, admission and native operations |
| `agente/SafeUpload.Agent.Core/` | Policy, extraction, content detection and inspection budgets |
| `agente/SafeUpload.Agent.Service/Interception/` | Driver transport, staging, durable journals, publication and recovery |
| `agente/SafeUpload.Agent.App/` | Tray, block/failure explanations and justification UX |
| `agente/SafeUpload.Agent.Tests/` | Agent tests, including native Windows controls |
| `driver/scripts/` | Exact builds, Windows harnesses, verdict checks and disposable VM runs |
| `driver/evidence/` | Mostly ignored raw evidence; selectively tracked cited summaries |
| `web/` | Backend/frontend and their separate CI |

## Review policy

The owner's 2026-10-17 instruction uses **Sol 6.1, high** (`gpt-6.1-sol`, `reasoning_effort=high`) for delegated work, with no fast tier. It supersedes the earlier xhigh default. Preserve historical Luna and Sol reports and their provenance.

- Use independent review for product-security designs, kernel lifetime/lock-order/retirement changes before their first VM boot, and one adversarial review of the working milestone pair.
- Keep ordinary implementation with the primary agent. Review a coherent change and its remaining conditions; avoid a review for every small revision.
- Harness-only changes need Windows PowerShell 5.1 parsing, relevant self-checks and a real run when authorized; they do not require a separate model review each time.
- Review acceptance, component tests and qualification of a protected driver/agent pair are distinct results. Never present one as another.

## Product invariants

- Staged protection fails closed: no uninspected nonempty bytes at the protected destination. Incomplete extraction, timeout, missing policy or uncertain identity cannot imply approval. Preserve legacy behavior unless its change is explicitly in scope.
- Staging is the product path. Runtime activation/readiness gates (V30 enablement, NotReady holds, capability gates) stay until qualification and owner cutover approval; compile-time staging-out builds are retired (owner, 2026-10-15; this approves no activation or cutover of unqualified staging). Process-taint enforcement is being removed from the product (owner, 2026-10-15; superseded by staging). USB/removable, SMB/UNC and cloud sync remain disabled until their own approved support and qualification gates. M2 covers local fixed NTFS.
- Bind authorization, inspection, publication, delete and recovery to the exact object, destination identity, generation and current policy required by the design. Paths and content hashes alone are not object authority.
- Preserve the original caller's Windows grants, sharing, owner/DACL/SACL/label semantics and cleanup lifetimes. SYSTEM access must not create caller authority. Never hand back unreadable seeded bytes without the approved read/export policy.
- Empty files follow the approved ordinary seal/inspect/publish path. Do not revive EmptyHeld. Only an already-published successor cancels a prior delete; pending or blocked saves do not.
- Retry unfinished bookkeeping, never an already-completed public mutation. Keep uncertain publication and unresolved cleanup held with actionable diagnostics.
- Sticky Unknown remains until reboot. Timers, scans, forced context deletion and digest matches cannot substitute for missing lifetime evidence. The narrowly approved retry/restart exceptions are in the status plan.
- Remove resource caps only with the replacement accounting and failure behavior in place. Bound capture/storage as well as parser concurrency; do not claim bounded parser memory from bounded scanner buffers.

## Build and verification

Use committed source and fresh labels with the existing runners. Record the Git commit and delivered artifact hashes; do not introduce per-revision source-freeze or review-disposition frameworks.

| Work | Verification |
|---|---|
| Documentation only | Check diffs, links (`python3 driver/scripts/check-doc-links.py`) and consistency with current evidence; no product VM boot required |
| Agent component | Focused relevant controls for feedback; feature Debug/Release matrix with user + SYSTEM legs (4 legs) for the delivery checkpoint |
| Kernel | Two feature Debug/Release WDK builds, PREfast and ApiValidator, all at 0 warnings / 0 errors, with import availability PASS over both; required Verifier rows |
| Harness | Windows PowerShell **5.1** parse/native signature checks, relevant self-checks, then an authorized real run |
| Milestone | Matched driver/agent artifacts, all required ordinary/runtime-Verifier/boot-Verifier rows, independent byte observations, separate restoration and final adversarial review |

Current entry points (read usage before running):

```bash
# Offline checks; these do not contact or boot a VM.
python3 driver/scripts/t4/verdict-selfcheck.py
python3 driver/scripts/Invoke-ExactAgentMatrixBuild.SelfCheck.py

# Remote build/gate entry points; use a new label and a specific source commit.
python3 driver/scripts/Invoke-ExactAgentMatrixBuild.py <label> --commit <commit>
bash driver/scripts/Invoke-ExactSourceBuild.sh <label> <commit>
bash driver/scripts/Invoke-HarnessWindowsGate.sh <label> .
```

Inspect structured summaries, complete test discovery/execution coverage, packages and hashes. A successful transport/process exit or text containing `PASS` is not a product verdict. No skipped tests, weakened assertions, changed thresholds or warning suppression to turn a failure green. Diagnostic subsets must be labelled as such and never replace required gates.

## Lab boundaries and stop rules

- Check the status plan before any product VM action. **On 2026-10-13 the owner authorized every planned M2 product VM row ("I give my ok for every row") on win10-debug3 only, under these lab rules; see the status plan's owner decisions.** No gate, threshold or assertion change is implied, and a request to review or plan is not permission to start rows outside that plan.
- The approved target is **`win10-debug3` only**. Keep `win10-debug2` off because it shares the guest IP. Set `SAFEUPLOAD_DEBUGGEE=win10-debug3` explicitly; older runner defaults/inventory are broader than current authorization.
- The recorded builder is separate from the qualified Windows 10 **19045.2965** target. Native behavior observed on builder 19045.6466 is mechanism evidence, not target qualification.
- Use existing disposable qcow2 overlays, reset EFI variables at each start, no TPM, test signing and Secure Boot off. Preserve the original base/XML and delete the run disk. Verify restoration separately with the existing baseline procedure.
- Run BLOCK-window tests serially. One job per builder: two different approved builders may run jobs in parallel, but never run two jobs on the same builder or the same VM target, and run no builder job on either builder during a timing-sensitive T4 row (owner, 2026-10-15). Use monotonic elapsed time for deadlines; the guest wall clock can jump.
- Approved builders (owner, 2026-10-15): `builder1` = `192.168.122.210` (`DESKTOP-O1LP5DG`) and `builder2` = `192.168.122.211` (`SU-BUILDER2`, cloned from builder1, parity recorded). Both hold the test-signing certificate (owner decision B) and run every job type; dispatch each job to the first free builder with the role (`driver/scripts/approved-builders.json`), never behind a busy builder when the other is free.
- Stop on repeated identical failures, changed baselines or required failed assertions according to the status plan. Preserve the first failure and identify the hypothesis before proposing another run.
- Host-wide polkit, QEMU hooks, sudoers, libvirt, systemd or other host configuration changes require owner approval. Do not apply Ansible/Terraform/image changes to a qualified baseline as part of routine testing.
- Ask for product decisions only when needed: failure policy, read/export authority, metadata contract, resource defaults, scope or cutover. Explain what users will experience and give a concrete recommendation. Continue independent authorized work meanwhile.

## Evidence and delivery

- Keep raw logs/TRX/captures and failed attempts under the local evidence convention in [driver/evidence/README.md](driver/evidence/README.md). Never overwrite a failed receipt with a retry.
- Track a concise result and only the cited evidence necessary to audit it; avoid force-adding whole output trees. Do not delete or rewrite existing evidence/history to reduce repository size.
- Retain source/packages/evidence before reclaiming known generated build outputs. Cleanup must be narrowly identified and must not touch another active job or an unresolved failure.
- Keep the status plan concise; move detailed historical narratives to existing logs. Checklists start with the T item and use at most two levels.
- Deliver coherent changes with verification and remaining limitations. Commit/push only within the session's authorization; do not infer permission from historical work logs.
