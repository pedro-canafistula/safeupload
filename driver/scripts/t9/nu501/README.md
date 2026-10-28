# N-U5-01 in-service real-port component control

**Running requires the owner's explicit authorization of this component-host setup**
(design 8.7.4 “separately authorized native component host”). It is not the
protected first boot and does not qualify anything. No run is authorized by
this directory, its dry-run, a compile, a review or a managed test result.

The source contract is [8.7.4 and the 12.1.2 readiness conjunction](../../../docs/design/large-files/UX-LARGE-GROWTH-PROTOCOL.md)
and the [pre-boot re-review](../../../evidence/2026-10-28/t9-inc3-preboot-rereview-sol-high.md).
The kernel remains unchanged. All C# harness, command and connection additions
are under `SAFEUPLOAD_ADMISSION_EVIDENCE`; normal builds contain none of them.

The admin-only existing evidence pipe accepts one fixed 68-byte command
(`0x3155354e`, version 1, all remaining bytes zero) on a component binding.
The request supplies no path, native payload, handle, role, policy or grant.
The existing SYSTEM/Admin DACL, remote-client rejection and post-request Windows
authentication apply. Native work runs as the original unimpersonated SYSTEM
service process, including its unrestricted SafeUploadAgent service SID.
The client also checks the named-pipe server PID against the installed SCM
service process. A separate client never connects to the kernel ports.

Configure `Diagnostics:Nu501ComponentHost=true` on the real installed feature
service. Before accepting policy or binding the endpoint it requires the fixed
`C:\ProgramData\SafeUpload` installation, staged mode, zero protected destinations,
no removable/network scope, no overrides, fail-open or audit-only policy, and an
unchanged accepted policy fingerprint. At command entry the four fixed installed
roots must contain only their expected root subdirectories. Component mode starts
no staging allocator, recovery, publication, receive, heartbeat or policy-update
loop. It never changes policy during the command. One command consumes the binding,
including a failed command; a retry needs investigation and a fresh authorized run.

There are two necessary interpretation details:

- Probe/Commit are **main-port bootstrap** controls (8.3), so Probe/pair/Commit
  precede holding `_sendGate`. Root/child registration and the native transaction
  run with the gate held. Trying Probe on the resource port or behind that held
  main gate contradicts the protocol. Commit must be NotReady with zero grants.
- Literal absence of all policy cannot authenticate the service: the existing
  driver requires durable accepted SetPolicy and the domain requires a category
  (RN-009). Preparation therefore installs an inert validated policy with Cpf
  and **zero destinations**, no removable/network scope and no actor. It changes
  only the disposable overlay. This is no configured protection scope. The
  component readiness reached is the accepted inert policy and evidence binding;
  it does **not** assert legacy staged/product Ready, modern Ready or cutover.
  If the owner requires literal no SetPolicy or legacy staged Ready, stop for
  resolution instead of using this setup under that interpretation.

The harness records real successful request/cookie/driver/object/intent identities,
then uses the **same registered directory handle/FILE_OBJECT** as the native store's
relative anchor. Geometry/security is captured before registration because the
registered-root query allowlist is narrower. Four raw opaque ManifestNew outputs
exercise create/preallocation/write/F1/EOF/F2/read verification/F3/query; every
native result must succeed. No JSON serializer or modern resource consumer is
activated. The physical store debit remains retained after closing. Output bytes
and pending intents survive only on the discarded run disk.

The four open children exhaust one nongrowth transaction; seven additional
nongrowth and eight growth pending intents exhaust the independent 8+8 kernel
pools. Ninth transactions/fifth child must return the **native Busy HRESULT**
computed through the target's `RtlNtStatusToDosError`, with zero returned bytes.
Separate controls fill local store capacity and hold eight **real adapter** sends
before FilterSendMessage; the ninth must return managed Busy before input
construction. Their real native calls resume and must return malformed-tuple
refusals. Refused well-formed root tuples return typed refusal with no child ID.

Before the main progress sequence, three real-port controls hold EnterSend and
queue an actual EpochStatus send. Dedicated watchdog timeout, an expected managed
fault/finally, and cancellation must each release that lease and allow the real
legacy send to return. The timeout repetition deliberately observes watchdog
expiry (5 s); expiry in the main progress sequence remains a failure.

The main latch is signaled strictly inside `HoldLegacySendForTesting` after
`EnterSend` acquires `_sendGate`. An independent real EpochStatus send enters the
lifetime count and must stay blocked until explicit latch release. Finally,
cancellation and a **dedicated watchdog thread** release the latch without
requiring any measured progress or ThreadPool capacity. Overall cancellation is
90 s; main latch watchdog 60 s; local-adapter barrier watchdog 15 s. Unexpected
watchdog expiry fails the row. The disconnect barrier watchdog and finite drain
assertion are 5 s. The client deadline is 120 s and remote-command ceiling 180 s.

The final disconnect control pauses an admitted real adapter invocation **before
entering FilterSendMessage**, requests `FilterPort.Dispose` with a second real main lease held, verifies rejected
admission and retained handles/native ownership, cancels the revoke latch and
requires main-lease release while the admitted native call remains paused,
then releases the independent adapter barrier,
then requires real native return before disposal completes and zero adoption after
revoke. This proves the managed-admission/native-adapter boundary and disposal
join; it does not force a kernel callback to stall internally. Synchronous native
calls are always joined; a timeout never frees their buffers or port handle. If
native return hangs, the host stops the row and discards the disposable guest.
No diagnostic kernel opcode or fake sender is present in this execution path.

The response is an 8-byte magic/JSON-length header and bounded UTF-8 JSON receipt.
Each step has request/intent correlation, status/HRESULT or NTSTATUS, monotonic
elapsed milliseconds **since run start**, observed legacy-lease state, assertion
and detail. The service and independent Python validator both require the complete
step manifest. The client stores raw JSON and one `N-U5-01=PASS|FAIL` line;
transport success or that line alone cannot produce the host verdict.

## Offline diagnostics

```bash
bash driver/scripts/Invoke-LocalAgentCompile.sh feature-debug feature-release normal-debug normal-release
python3 driver/scripts/t9/nu501/selfcheck.py
bash -n driver/scripts/t9/nu501/Invoke-Nu501ComponentHost.sh
python3 driver/scripts/check-doc-links.py
```

`Nu501ControlTests` tests sequencing, independent watchdog/failure/cancellation/
revoke/disposal release and missing/duplicate/altered receipt mutants. Local Linux
in-process xUnit execution is **diagnostic only**. It closes no N-U5-01 execution
cell and does not replace the Windows Debug/Release × user/SYSTEM delivery matrix.
The Python self-check tests independent receipt mutants and dry-run refusal of
wrong hashes/targets, with external-command stubs that fail any accidental contact.

Windows PowerShell **5.1** parsing/native-signature validation and actual guest
execution remain required. There is no PowerShell runtime on this Linux host.
The runner performs actual PS5.1 parsing and hash checks before installation; the
orchestrator must also run the established Windows harness gate before authorizing
execution. No existing assertion, threshold or test is weakened.

## Authorized component run

After the orchestrator commits this source, reviews the complete source, closes
applicable native prerequisites and builds the reviewed dormant driver plus feature
agent, pin the actual driver, package and service executable SHA-256 values:

```bash
SAFEUPLOAD_DEBUGGEE=win10-debug3 \
  driver/scripts/t9/nu501/Invoke-Nu501ComponentHost.sh --dry-run \
  <fresh-label> <source-commit> <driver.sys> <driver-sha256> \
  <feature-agent.zip> <zip-sha256> <service-exe-sha256>
```

Only after explicit owner authorization of **this component-host setup**, replace
`--dry-run` with `--owner-authorized-component-host`. The flag records the operator's
assertion; it supplies no authorization itself. Historical M2 protected-row approval
must not be interpreted as this separately required component-host approval.

Dry-run validates local artifact hashes and prints the plan; it does not acquire
locks, create evidence or contact any guest/builder. A real run requires committed
scripts and matching pinned host helpers. It holds both existing builder locks
nonblocking through separate restoration, requires debug2/debug3 off, and uses
`run-disk.sh` for a fresh qcow2 overlay, preserved base/XML, EFI reset and no TPM.
It checks the independent baseline, UUID, 19045.2965, test signing and Secure Boot.
The reviewed installer seeds the inert policy and configures the service SID;
the runner restores demand-start and demand-loads the component without reboot.
No actor is created or launched and no protected destination is configured.

Preparation requires the component binding, arms runtime Verifier
`/volatile /flags 0x13B /adddriver SafeUpload.sys`, and requires actual `/query`
readback. All metadata-group/root/child allocations occur after arming. The runner
executes the client once, collects receipts, checks unchanged boot/Verifier state,
System crash/service events and dump absence, and independently validates JSON.
On failure it retains raw streams, copies guest evidence/minidumps when reachable,
captures domain/screen state, discards the overlay, then boots a **new restoration
overlay** for the independent baseline check and discards that too. Failed discard
blocks further boots and preserves run state for investigation. Never retry an
assertion/hang/Verifier failure without first identifying the hypothesis.

Evidence lives in `driver/evidence/<date>/t9-nu501-<fresh-label>/`. The runner records
source commit, all supplied artifact hashes and staged script hashes. It deliberately
makes no claim that a supplied hash proves review or artifact provenance: the
orchestrator must establish the reviewed matched source/artifact relationship.

## Prepared offline result (2026-10-28)

Against the uncommitted implementation based on `a193d41e`, the local compile
runner passed **12/12** builds: feature/normal × Debug/Release × Service/App/Tests,
with warnings treated as errors. The Linux in-process xUnit diagnostic discovered
3,765 cases and selected/executed **231/231** new managed controls, all passed,
zero failed/skipped/errors. The independent Python logic/dry-run self-check passed
**236** controls. Bash syntax, diff whitespace and documentation links passed
(298 pre-existing link-baseline entries, zero new broken links).

Raw [offline evidence](../../../evidence/2026-10-28/t9-nu501-offline-agent/)
is local diagnostic evidence, not a native result. Independent Sol 6.1 high
source review identified the exact-handle/constructor-query and receipt/health-
enumeration issues; they were corrected. Windows PS5.1 parse/native signatures,
actual FltLib Busy mapping, native callbacks/results, runtime Verifier, disconnect
drain and overlay/restoration remain **unexecuted**. N-U5-01 remains OPEN.
