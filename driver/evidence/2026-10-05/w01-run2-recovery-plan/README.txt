W01 run 2 preserved-branch recovery proposal — NOT APPLIED
Run GUID: fe004c32b19e4cc88a0cf42389818d7b
Domain: win10-debug, UUID 9d44eee8-81cf-4cc1-9fba-7670f11def4d

Why this is an operator step
The existing host wrapper records rollback commands for an operator and does not
repoint disks itself (Invoke-DebuggeeExperiment.sh, write_offline_rollback_step).
The failed run's recovery-required.json says to preserve the VM/processes/ports/
overlay and requires operator disposition. This proposal does not clear or
reinterpret that latch. Normal Finalize cannot recover this state: it requires
Restored=true and RecoveryRequired=false, and normal restoration requires a
completed child/terminal receipt. Here the child never started.

Evidence checked before proposing this branch
- Fresh guest identity, expected upper/lower hashes, RecoveryRequired=true,
  ChildStarted=false, AgentTouched=false, no matching actors, phase task Ready.
- Original independent baseline before run 2: BaselineClean=True, original driver
  and policy, both filters absent, Verifier off, no owned fixtures/actors.
- Successful C: cache flush and subsequent atomic external checkpoint receipt.
- Live domain XML and actual QMP image metadata identify the same failed overlay
  and the same immediate parent. The planned branch uses its pre-W01 ancestor,
  bound to run 1's clean baseline/cache-flush/atomic-checkpoint receipts.
  This avoids the generic baseline's blind spot for leftover W01 phase tasks.
  Persistent vda identifies the failed run 2 overlay.
- No other running domain's top-level disk is the proposed parent.
- Both proposed XML files pass the installed libvirt schemas. Normalized comparison
  permits only vda's source replacement and removal of derived backingStore XML.
These preparation checks are not proof that restoration has happened.

Proposed operation, only after operator disposition and final review
1. Recheck the exact domain UUID, live/persistent source, QMP immediate parent,
   no actor/phase job running, no foreign writable parent attachment, no libvirt
   job/managed save, enough free storage, and unused output paths. Stop on drift.
2. Save the current VM's RAM to the unique MemoryPreservationPath in plan.json:
   virsh -c qemu:///system save win10-debug <MemoryPreservationPath> --running
   This deliberately stops the VM while preserving its failed memory state.
   Poll that same job if slow. Do not destroy it, abort it, or retry on timeout.
   Require successful completion, shut-off domain, and save-image-dumpxml proving
   the original UUID and failed vda source. Keep the saved image and failed disk.
3. Create a NEW qcow2 recovery child using recovery-volume-planned.xml:
   virsh -c qemu:///system vol-create default <recovery-volume-planned.xml> --validate
   Read back its format, capacity and exact backing path. Do not write to the
   frozen parent or merge, delete, rebase, flatten, or reuse an existing image.
4. Define domain-recovery-planned.xml, then independently read persistent XML.
   Verify UUID and all non-vda-source configuration against the retained original.
   Start the new branch only when these checks pass. Do not restore failed RAM
   into the clean branch; the saved state references the separate failed disk.
5. After a fresh boot, independently run the pinned Get-StagedBaseline.ps1 from
   the original run and the additional read-only W01 checks. Require original
   driver/policy hashes and ACLs, Manual/Stopped upper, lower absent, both Verifiers
   off, original persisted Verifier values, no BootPolicy/Parameters residue,
   no W01 actors/tasks/fixtures and restored audit. Compare against the pre-run
   baseline and preserve the new branch on any mismatch. A boot alone is no pass.
6. Record restoration as an external recovery of the failed case. W01/A05 stays
   INCONCLUSIVE and Phase 4 stays NOT_QUALIFIED. Retain failed disk/RAM and evidence.
   Resolve only the operator-authorized exact marker paths/hashes AFTER independent
   clean restoration. Do not clear other markers or treat another clean run as proof.

Failure policy
If save, volume creation, XML definition, boot or final checks fail, stop and retain
all artifacts and the actual state. No automatic rollback or deletion is proposed.
Saved failed RAM can be restored only with its original failed disk/configuration;
that is a separate operator recovery decision, not an automatic fallback.

Primary API references
https://www.libvirt.org/manpages/virsh.html#save
https://www.libvirt.org/formatstorage.html#backing-store-elements
The save API preserves RAM rather than copying disk state; the separate failed
overlay is therefore retained. Storage volume backingStore describes the new
copy-on-write child and its existing parent.

Completed authoring/review checks (not restoration)
- gpt-6-luna max reviewed this pre-W01 branch proposal and completed the
  external read-only Invoke-W01RecoveryBaselineCheck.ps1.
- Parent verified its SHA-256, Windows PowerShell 5.1 ParseFile, six negative
  controls and a deserialized registry-map positive control on the recorded
  builder. Full checker and baseline helper were not invoked on either VM.
  Raw output/stderr, first rejected BOM attempt and independent readout retained.
- root-preparation-readout.json independently checks pinned pre-W01 receipts,
  chain selection, source-only domain change, pool/volume path, schema and markers.

Post-boot checker invocation requirements
The exact retained state.clixml must be supplied outside the Documents fixture
scan, for example as a hash-verified temporary read-only input. The checker accepts
OriginalStatePath and DomainUUID (host must separately bind UUID/disk/config).
Its failed boot, run GUID, original state and baseline helper hashes are fixed.
Do not use the W01 phase-task wrapper. Invoke directly; do not run the experiment
parent, AfterBoot, Finalize, child or restore helper. Preserve its entire output
and require W01_RECOVERY_BASELINE_VERIFIED=True; any throw stops disposition.
Remove only newly staged verification inputs afterward and repeat the separate
pinned independent baseline before declaring recovery verified. Failed artifacts
remain on their separate saved RAM/disk branch and in host evidence.
