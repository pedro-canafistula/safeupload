# SafeUpload overnight resume handoff

**Superseded by the current journal milestone at the top of STAGED-WRITES.md.**
The user canceled watchdog work and updated the Goal to the full taint-independent
replacement acceptance objective. Journal 28-case LocalSystem, actual service
corrupt-startup denial and integrated runtime gate now pass with D887… service
and unchanged 4B60… SYS; independent original-driver restoration passes. The
current disk is the new pre-journal-recovery checkpoint. Continue with the open
external-hard-link/object-identity and other acceptance items. Do not resume
timer work, start a second internals investigation or overlap VM experiments.

The user authorized continued overnight work, virtual USB or their Samsung drive,
a dedicated SMB share on the debugger VM, and their newly configured OneDrive.
Prefer disposable fixtures; do not alter existing user content. They also
explicitly asked to kill this session abruptly and prove the timer resumes it.
No ClickUp. No sub-agents. Do not change the acceptance objective or VM safeguards.

## Deliberate restart test

**Observed result: failure, not a passing restart gate.** The helper sent the
exact-owner SIGKILL at 03:37:18Z. The timer launched the same UUID at 03:38:15Z,
but the CLI exited 1 with a model-capacity error before model work. See
[sanitized evidence](watchdog-abrupt-resume.txt). Recorded environment and Goal
contexts were also misclassified as new user input by the original fingerprint
guard. The source now excludes only their explicit CLI metadata kinds, with
text-spoof/unknown/mixed-kind guard tests. This fix has not had another real abrupt
termination test. Never override a blocked/limited/paused Goal or change model to
hide the failure. The user has now woken and requested continuation; the original
ten-hour timer has expired. Do not start another runner alongside this session.

At this checkpoint the original CLI TUI is PID **3444**, birth ticks **5830**,
executable `/home/victor/.local/share/mise/installs/codex/0.159.2/bin/codex`.
Other Codex app-server processes are unrelated and must not be killed.
Original thread and active Goal are
**01a0f8c5-025f-7ea1-8510-0d278910e7d2**. The transient user timer polls only this
thread and resumes only after the original owner disappears. Configuration and
JSONL logs are private in `/home/victor/.local/state/safeupload-overnight`.

The deliberate kill must occur after a coherent commit and independent restored
VM baseline, with no active build/test/restoration. The resumed process must:

1. Inspect private `watchdog.jsonl`: record the `resume-started` PID/thread/time
   and absence of the recorded original process identity. Inspect its own CLI
   ancestry and the session record to prove same-thread resume. Save sanitized
   proof in `driver/evidence/2026-10-02/watchdog-abrupt-resume.txt` and update this
   file and STAGED-WRITES.md. A timer installation or dry run alone is not proof.
2. Independently rerun the restored-driver/Verifier/policy/task/volume checks on
   WIN10-DEBUGGED before a VM experiment. Check builder debugger fixtures absent.
3. Continue real implementation and VM gates. Do not stop after proving recovery.

Guard self-tests passed for active-only admission, expiry, pause, limits,
completion, changed user input, owner and overlapping exact-thread CLI resumes.
The real `thread/goal/get` call returned active; dry run returned owner-alive.
Expiry prevents new starts after 2026-10-02T13:31:10Z, without killing an in-flight
experiment. Stop future starts with:

```bash
systemctl --user stop safeupload-session-watchdog.timer safeupload-session-watchdog-expiry.timer
```

## Work saved and next increment

Repo `/home/victor/Work/safeupload-staging`, branch
`feat/staged-kernel-prototype`. Source checkpoint `3872681` hardens journal final
object handles, ACLs, bounds and schema. **275 Windows agent tests pass**. The
changed journal service Release publish and WPF app Release build now pass:

- Builder output `C:\Users\vika\Documents\journal-security-milestone`.
- New service ZIP SHA256
  **D887E0D7F38AD64AD40CEE18B841C6D38AD2BED4D6F760B1BDE4464927381997**.
- Local downloaded ZIP `/tmp/safeupload-journal-current-service.zip`, verified.
- **No updated service deployed or VM experiment active at the checkpoint.**
- Guest old qualified ZIP is still 4EB6D0B4… .
- Unchanged feature SYS SHA256
  **4B60DFA21CC9800DAEA7363208A13C783E59CA37BFC288D91918803E83F19E20**;
  guest `C:\Users\vika\Documents\SafeUpload-stage-prototype.sys`, local
  `/tmp/safeupload-parent-current.sys`.

Finish the journal increment first: inspect source and nine legacy manifests
read-only (already inspected before this checkpoint; no migration/deletion).
Generation zero remains accepted for older records. Create a fresh frozen
debuggee checkpoint on verified original/off baseline. Transfer/hash the new
service ZIP. Implement a small real-LocalSystem journal recovery negative harness
(at that handoff, newly written in `driver/scripts/StagedJournalProbe` and
`Test-StagedJournalRecovery.ps1` but not yet VM-qualified; now qualified above), preserving
malformed/outside bytes and ACLs, then run
`Test-StagedOwnedStreams.ps1 -Verifier -ReplacementCases -PublicationIterations 24`
with the stronger service. Restore and independently verify the original driver
after **every** experiment, including failures. Record evidence and commit.

Return to the remaining tracker: filesystem aliases/stable identity and private
namespace operations; full principal/policy/fault approval negatives;
driver/reboot recovery and safe export; stage security, races, quotas/reclamation;
USB/SMB/sync qualification; full application/mapped/concurrency/independent-byte,
crash/fault/stress/latency matrix. Keep unqualified capabilities disabled. Normal
staging is still compiled out. WDK four-way builds and Release validation fix are
qualified for the unchanged kernel; repeat required gates for later changes.

## VM authority and restoration

- Builder 192.168.122.210 **DESKTOP-O1LP5DG**: modify only
  `C:\Users\vika\Documents\safeupload-staging-test`, never original checkout.
- Debuggee 192.168.122.51 **WIN10-DEBUGGED**, UUID
  **9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D**. KDNET .232 is separate.
- Original installed SYS SHA256
  **ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE**;
  filter unloaded, service Manual/Stopped (start 3).
- Original policy SHA256
  **29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731**,
  overrideAllowed false. Configured and active Verifier off.
- Active disk
  `/var/lib/libvirt/images/win10-debug.safeupload-pre-parent-boot-20261002`.
  Preserve parent/permit/tombstone/generated-paging/owned snapshots and forensic
  disks/RAM; never commit into original base or delete them.
- LocalSystem launchers always redirect both stdout/stderr (recorded condrv
  crash with attached console). Stop agent before unloading. Use recorded durable
  Restore logic, preserve fixtures on failed unload, reboot original when needed.
- KD/Verifier boot recipe and key handling remain in STAGED-WRITES.md. No debugger
  retargeting is active; never print the private key or raw BCD key. Do not clear
  logs. A fresh checkpoint and verified authority precede any new fault campaign.

Independent pre-kill evidence records guest UTC23:32:15 and builder UTC03:32:27
(clocks differ): original driver/policy, filter and Verifier off, no temporary
tasks/service/app/volume, builder temporary KD task/rule/process zero. Existing
`C:\Users\vika\Documents\paging-final-state-command.ps1` supplies most checks;
also assert active query says no drivers verified, service Manual/Stopped,
original policy hash and VM hostname/UUID. Check original debugger host/key
privately against `/var/tmp/safeupload-original-kd-settings.private.json` if any
debugger setting changes; never publish the key.

OneDrive is running in Session 1 on both VMs. Registry Account UserFolder is
`C:\Users\vika\OneDrive` on builder, business OneDrive folder on debuggee. Fetch
the latter directly from the registry to avoid non-ASCII encoding errors. Folder
presence/account setup has no destination qualification credit yet. Use a unique
test child; no old files or credentials inspected.
