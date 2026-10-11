# Independent review: T5 file-lease and host-install checkpoint R1

Captured 2026-10-11. **Disposition: NO-GO for source integration as an active
host installer, installation, policy application, or VM execution.** The
checkpoint contains useful fail-closed transaction work and passes its
disposable rollback self-check, but it does not contain or prove the
whole-state runtime guard. It also does not acquire the canonical lock before
the first durable install-transaction writes, contrary to the author note's
ordering claim. This is a review of the exact frozen checkpoint below; it does
not change host state or authorize a product run.

## Review boundary and pin verification

I independently read the owner objective, the complete author note, root
capture, two source files, manifest, lock-path disposition, topology and
backing-chain receipts, and the retained offline lease/rollback controls. The
root capture is
`driver/evidence/2026-10-11/m2-t5-lifecycle-file-lease-guard-r1-root-review-capture.json`,
SHA-256 `c9649ac5c6a7d1b72ed0bfde13533713a380407efa725e43b8f696f8ae5f3523`.
It declares a closed 19-file inventory, two source inputs, and explicitly
records `SourceAccepted=false`, `RuntimeQualified=false`,
`HostPolicyApplied=false`, and `ProductVMStarted=false`.

I recomputed all 19 hashes from stable no-follow reads, checked the exact
file-set in each group, and confirmed no extra file in the candidate groups.
All match the capture. The author manifest hash is
`bf8a21f3168e2a0fae1cd417d42312a2928d95e90ada02962e0b0e212c87ea87`; the
author note hash is
`9aaa29497a42cf78babbd8252ef9c94c25e97eecba416b8fe861fa0778eaee50`.

| Group | Frozen path | SHA-256 |
| --- | --- | --- |
| Source | `driver/scripts/t5/T5WritableStateHostInstall.py` | `98bdacf3abfc1864a62b9f69934c5fd5824c8cf80a5e34752be9a0f32824414d` |
| Source | `driver/scripts/t5/T5WritableStateHostInstall.SelfCheck.py` | `c56b709beb1b060e207afea4aeca3617693e1edf802cea2fc61dfdca68cc8e8a` |
| Author | `driver/evidence/2026-10-11/m2-t5-lifecycle-file-lease-guard-r1-luna-inputs.json` | `bf8a21f3168e2a0fae1cd417d42312a2928d95e90ada02962e0b0e212c87ea87` |
| Author | `driver/evidence/2026-10-11/m2-t5-lifecycle-file-lease-guard-r1-luna.md` | `9aaa29497a42cf78babbd8252ef9c94c25e97eecba416b8fe861fa0778eaee50` |
| Context | `driver/evidence/2026-10-11/m2-t5-domain-backing-survey-a2-root.json` | `11662e2abcc3ead1c7ac7cc751ce83380b947847ad4bfd246798e4ecaac54d7a` |
| Context | `driver/evidence/2026-10-11/m2-t5-file-lease-controls-a2-root.json` | `705b532a6369794de52ac44860d013b4daa4fb2cdcf5a184fae8483224f98ceb` |
| Context | `driver/evidence/2026-10-11/m2-t5-file-lease-controls-a2-root.py` | `8512ecbd04a060cf277f160b9a0d685f65a86051cb92b19d6fe0cc43bdd33cd2` |
| Context | `driver/evidence/2026-10-11/m2-t5-file-lease-controls-a3-root.json` | `aac441ca57162624727864121484b161b6de97b7bf75c0f8150e3a6509a961f4` |
| Context | `driver/evidence/2026-10-11/m2-t5-file-lease-controls-a3-root.py` | `22d1047db86161a70de648200d5f3c395ffe56b30b10ec121c090552da9cb267` |
| Context | `driver/evidence/2026-10-11/m2-t5-file-lease-fsync-controls-a2-luna.json` | `20a8c74f0b04ed1ba20e11ff65b002995101f29cf347058ee147401c3f598067` |
| Context | `driver/evidence/2026-10-11/m2-t5-file-lease-fsync-controls-a2-luna.py` | `f66dc2a7c7a27f53818f093097e5e6b48b1d0cf941024b4b0af1074c5ce8841c` |
| Context | `driver/evidence/2026-10-11/m2-t5-file-lease-fsync-controls-a3-root.py` | `fd24cc8413a0d7fa9623813694ed064c50ac759b9d492529804a52ec402ad8ef` |
| Context | `driver/evidence/2026-10-11/m2-t5-file-lease-fsync-controls-a3-root.stderr.txt` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Context | `driver/evidence/2026-10-11/m2-t5-file-lease-fsync-controls-a3-root.stdout.txt` | `7b83a785515fabe30735b10a4b70eb4ff0049582de9dcda18a1e551286671056` |
| Context | `driver/evidence/2026-10-11/m2-t5-host-install-topology-a1-root.json` | `9f30ee3e8baf0e8924d4fec6ba444198100f9c0effdf9faf9b85449ba79b7c44` |
| Context | `driver/evidence/2026-10-11/m2-t5-host-kernel-package-metadata-a1-root.json` | `7aaeb0de1d17846639fe6627b4ea9175a89e6ef27d3258588693634323c53140` |
| Context | `driver/evidence/2026-10-11/m2-t5-hostinstall-rollback-selfcheck-a3-luna.json` | `6028740dbb2bf70f44a21883e2830c4717121807ba9f656a3094d86f335cc604` |
| Context | `driver/evidence/2026-10-11/m2-t5-lifecycle-lock-path-root-design-disposition.json` | `28860cc9f2fec83f46e0959525acb2902392b2258305e973d1a5c25e06531bc8` |
| Context | `driver/evidence/2026-10-11/m2-t5-source-backing-metadata-a1-root.json` | `e9d4aa7497069d28e4d54042cf07bcf0bab716c678a88c4a06edd4d760608591` |

The closure is exactly an installer plus its self-check, with author materials
and context. It is **not** the six-source installed runtime closure named by
`REQUIRED_SOURCE_NAMES` in the installer (lines 71–75). In particular, this
capture does not include the lifecycle supervisor, QEMU hooks, polkit runtime
rule, or a running lifecycle service. Source-only checks here cannot establish
their behavior, installation identity, or end-to-end guard semantics.

## Source findings

**P1 — the canonical lock is not acquired before durable transaction state is
written.** In the authorized path, `main()` reserves `ATTEMPT_PATH` at lines
1772–1775 through `_reserve_attempt()` (1055–1063). `_apply_transaction()`
then creates, owns, fsyncs, and appends `TRANSACTION_BEGIN` to
`JOURNAL_PATH` (1496–1519). Only after those persistent writes does it create
and flock the canonical path (1520–1526). Thus the lock orders the later
preflight and install objects, but not the attempt reservation or journal.
The author note says the lock is held before creating persistent state; that
description is broader than the implementation.

The self-check does not catch this. `check_transaction_order()` parses only
`_apply_transaction()` and compares the lock against the second
`_collect_preflight()` and later install-object helpers (self-check lines
38–60). It never models `main()` calling `_reserve_attempt()` before
`_apply_transaction()`, nor `JOURNAL_PATH` creation at function entry. The
self-check's `LockBeforeRecheckAndInstallObjects=PASS` is true for the
narrower property it checks, but it is not evidence for lock-before-first
persistent-transaction-write.

Close this ordering gap by pre-provisioning and identity-checking the one
canonical lock inode, then acquiring that lock before reserving an attempt,
creating the journal, or performing any host-side transaction action. Keep
lock bootstrap itself narrowly serialized and never replace the agreed inode.
Extend the structural control across the full `main()` → reservation →
transaction path, including journal creation and the first durable event.
This is an ordering correction; the current O_EXCL and no-replay behavior
reduce replay ambiguity but do not create a shared lock around these writes.

**P1 — the installer lock is short-lived and is not the whole-run guard.** The
installer closes `lock_fd` in its `finally` at lines 1749–1753 after
installation. The source has no continuously held supervisor or lease, no
runtime closure in this 19-file capture, and no proof the lock is shared by
the copy/run/restore consumers. The canonical-lock design disposition also
requires a retained boot-lifetime inode, a private held FD, exact supervisor
identity, one-use lease/token, and common-path binding across those consumers;
this checkpoint implements none of that run-time coordination. The receipt's
`ProductionInvocationEnabled=false` and `EffectivePolicyProven=false` are
status fields, not an internal code interlock that makes the privileged
installer inert.

**P1 — effective start/write exclusion and the selected backing path remain
unproved and currently refused.** The root topology receipt says selected
`win10-debug3` is stopped, but its managed backing metadata names
`/mnt/storage/libvirt/images/win10-debug2.flat-20261009.qcow2`; the domain
survey identifies stopped `win10-debug2` as sharing that backing. The survey
is explicitly not an atomic full snapshot, and direct image-header and
open-handle proofs are absent. Its user-owned `/mnt/storage` ancestors are
also a preflight refusal. `_no_user_write()` rejects writable modes/ACLs; it
does not migrate or protect the ancestor chain. The author correctly leaves
the cold-sharing gate closed.

The policy text embedded in the installer delegates `NO_LEASE` to other
polkit rules (`NOT_HANDLED`). The receipt deliberately says effective policy,
QEMU hook invocation, external start/stop exclusion, and filesystem-write
exclusion are false. A generic `pkcheck` denial and a no-op main-hook probe
do not prove effective default-deny behavior, QEMU hook execution, direct
write exclusion, or that already-authorized/in-flight operations have
drained. A marker or cooperative lock alone is insufficient for those paths.

**P2 — the root lock and installation record are not installed runtime proof.**
The fixed path is `/run/safeupload-t5/win10-debug3.lifecycle.lock`; the
checkpoint's only holder is the installer process. It authenticates the
current lock-file identity and flock while it runs, but the capture contains
no root supervisor, service unit, runtime consumer set, or tested restart
retention. An empty 0444 lock file cannot authenticate a live holder. The
root design's exact supervisor/token/dev-inode binding remains a separate
runtime requirement.

## Partial behavior that is sound within its tested scope

The config replacement path records a durable exact-byte backup and captured
metadata, rechecks the original content/device/inode before atomic replacement,
and verifies the replacement bytes and inode afterwards
(`_atomic_replace_config()`, lines 1109–1167). Pre-restart restore refuses to
overwrite a changed config path, verifies the backup, reconstructs bytes,
mode, owner/group, mtime and xattrs, rechecks the replaced inode immediately
before rename, and verifies the restored file (`_restore_replaced_config()`,
1284–1346). The author explicitly acknowledges the original inode and ctime
cannot be restored. If restart has been attempted or mutation state is
ambiguous, automatic rollback is refused and artifacts are retained
(`_rollback_pre_restart()`, 1393–1430); the restart intent is durably recorded
before `systemctl restart` and a failed/uncertain restart stays behind the
retention barrier (1626–1643). These are valuable fail-closed source
properties, not proof that live host rollback or recovery works.

After reading the self-check source and confirming its filesystem mutations
are confined to a newly created `/tmp` fixture and its `__main__` path only
runs that fixture, I ran:

```text
python3.14 -B output/review-candidates/m2-t5-lifecycle-file-lease-guard-r1-root-a1/src/driver/scripts/t5/T5WritableStateHostInstall.SelfCheck.py
```

It exited 0 with all eight disposable checks passing: exact created-file
removal, changed-file preservation, empty-directory removal, nonempty-directory
preservation, config bytes/mode/mtime/xattrs restore, changed-config
preservation, post-restart retention, and ambiguous-mutation retention. The
run reported `Scope=temporary fixtures only; no host installer entry point or
API calls` and `XAttrFixtureSupported=true`. Its printed temporary journal
digest was `d9e6b39eb1b76a40dcc608f97e06b774ceff7ef70315baa2e7c152093bee9104`;
the fixture removed its `/tmp` tree in `finally`. This is repeatable local
fixture evidence only. It is not a host install, active policy, VM, crash
recovery, or independent restoration result.

## Goal-alignment audit

The owner objective requires all tracker items and runtime gates to pass,
unapproved bytes to remain private, normal builds to keep staging disabled,
and **every VM run to end with independently verified restoration**. The
existing T5 tracker makes that concrete: bind run XML to private disk, EFI
NVRAM, and TPM state; prove guarded completion and whole-state restoration;
exclude direct filesystem mutation and cross-domain attachment in a reachable
host transaction; and preserve failure evidence/recovery state. Those are the
acceptance outcomes. A private copy by itself is not enough: it prevents the
guest from writing the original through that binding, but does not prevent an
independent host writer or prove the original stayed unchanged.

For the observed selected topology, a minimum goal-aligned transaction is:

1. Before reading/copying source payload or starting the VM, hold one
   root-controlled admission barrier that covers ordinary-user libvirt
   start/redefine/attach/migration/restore and storage changes **and** direct
   source writes. Drain work authorized before the barrier or fail closed.
   Bind the same barrier across supervisor, copy, run, preservation, and
   restoration. Preserve the unrelated active builder through any daemon
   transition; do not restart its daemon without a reviewed exact reconnect
   path.
2. While the barrier is held, prove the selected `win10-debug3` chain from
   direct image headers and libvirt state, account for the cold `win10-debug2`
   definition that shares the Ext4 backing image, and keep that definition
   unable to start or attach until the selected run and verification finish.
   Do not treat two managed-volume metadata reads as atomic source proof.
3. Capture a complete pre-run baseline of the original writable state: the
   selected qcow chain (including the shared backing), firmware NVRAM, full
   TPM state tree, and the original inactive domain XML/state. Bind the run
   XML only to private disk/NVRAM/TPM copies, validate that binding before
   start, and preserve the overlay and available failure evidence on any
   timeout, crash, or uncertain stop.
4. Keep the admission barrier through verified guest/process shutdown, exact
   restoration of the original definition, and an independent post-run
   comparison of every original object's bytes and required metadata against
   the baseline. Confirm no selected or cold-sharing process retains an
   original write reference and the selected guest is inactive. On any
   uncertainty, retain the lock/guard, backups, run artifacts, and evidence;
   do not claim success or allow cleanup/replay to erase the recovery path.
5. Close every run with independently retained evidence that the originals
   match and the private run state is isolated. If that evidence is missing,
   the outcome remains failed/inconclusive and the run is not promoted.

The topology receipts make the cold shared backing and active builder
practical constraints, not optional future hardening. Conversely, the exact
mechanism is not fixed by the owner objective. Kernel-package patchset
identity, an inode-specific dirty-page-at-lease test, systemd FD-store survival
through manager reexec, and global `fs.lease-break-time=0` are not stated as
standalone owner/tracker acceptance items. They are confidence requirements
for the particular lease/fsync/global-sysctl/FD-store design proposed in the
author note. If that implementation relies on one of those behaviors, it must
qualify that dependency or choose another verified mechanism; those probes
should not be added as universal product gates when the same invariant is
proved by a safer alternative. The actual required result remains continuous
exclusion, private run-state binding, unchanged original state, retained
failure recovery, and independently verified restoration. Likewise, migrating
the ancestor ACL/ownership is one possible route; the required result is that
no unapproved source mutation can occur during the guarded transaction.

## Final disposition and limits

The two-file correction is safe to retain as a **source-only draft checkpoint**
for the exact rollback behavior described above. It is not safe to promote as
an active installer/runtime or to call “runtime disabled” based only on the
receipt field: the privileged `main()` installation path exists, and this
closure supplies no deployment interlock or reviewed installed runtime
controls. Keep host installation, policy/permission/sysctl changes, source
copying, libvirt operations, and VM starts disabled until the full transaction
is reviewed and independently qualified.

I made no Git changes, protected-file access, libvirt/API call, service
operation, host policy/permission/sysctl change, or VM action. The only
execution was the reviewed disposable `/tmp` self-check. Root's read-only
receipts are treated as context, not as my direct observation or as proof of
an atomic host snapshot, effective enforcement, source immutability, or
restoration. No upstream Linux/systemd/libvirt reference substitutes for
qualification of installed behavior.
