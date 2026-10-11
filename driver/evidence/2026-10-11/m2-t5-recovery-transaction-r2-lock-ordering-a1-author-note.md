# R2 lock-ordering checkpoint A1

**Disposition: source-only candidate; independent review pending.** This checkpoint was copied from the root-frozen R1 source closure. It changes only the installer and its offline self-check. The immutable R1 candidate remains unchanged.

## Correction

R1 reserved `ATTEMPT_PATH` in `main()` before `_apply_transaction()` created and fsynced `JOURNAL_PATH`; the journal then acquired the canonical lock. That left both durable replay records outside the critical section. R2 now bootstraps and validates the fixed `/run/safeupload-t5/` directory and `win10-debug3.lifecycle.lock` inode, takes a nonblocking exclusive `flock`, and only then checks replay paths, reserves the attempt, creates the journal, and records `TRANSACTION_BEGIN`. The already-held descriptor and device/inode identity are passed into `_apply_transaction()`.

The no-authorization path also acquires the same lock before collecting and writing its durable preflight record. The namespace lock bootstrap is the only necessarily unguarded operation: it creates the one canonical directory and file with `mkdir` and `O_CREAT|O_EXCL|O_NOFOLLOW`, opens an existing inode without unlinking or replacing it, and verifies owner, group, type, mode, link count, size, pathname identity, parent identity, and the exact held lock shown in `/proc/<pid>/fdinfo`. The runtime directory and lock inode remain after the call. A stale or unexpected runtime entry fails closed.

## Offline result

`python3.14 -B` ran the exact frozen self-check source. It passed the structural `main()` ordering check; a simultaneous bootstrap race from an absent directory (one holder, one blocked caller, one inode); a separate-process exclusion check on the held inode; the authorized `main()` fixture through attempt and journal creation; and the no-authorization `main()` fixture through durable preflight creation. Existing rollback checks also passed, including changed-object preservation, config bytes/mode/mtime/xattr restoration, restart-barrier retention, and ambiguous-mutation retention.

All writes were confined to fresh temporary directories. The imported `main()` was called with its host namespace and authorization/transaction boundaries replaced by fixture functions. The actual lock implementation ran only against the temporary namespace. No host installer entry point, libvirt API, systemd, policy, permission, sysctl, protected source file, or VM was touched. See `selfcheck-result.json`, the raw output, and the source delta for the exact evidence.

| File | SHA-256 |
|---|---|
| `src/driver/scripts/t5/T5WritableStateHostInstall.py` | `145ed9008255cec4264a07160a15b6a98af76b729b5dd55e80e727a926102bc0` |
| `src/driver/scripts/t5/T5WritableStateHostInstall.SelfCheck.py` | `8244ca6c5f234c854953b20414640aaa7c2474f7547d841412d68bad6ab37bdd` |
| `selfcheck.stdout.json` | `cfc6211ea26f3ccde8368525c4c53000047ed15482a3705d9b7d1b17a1d691a2` |

## Limits and next transaction work

This closes only the first R1 P1: local installer and preflight state now serialize before their first durable write. The lock serializes callers that honor it; it does not exclude libvirt APIs or direct filesystem writers. The candidate is still **NO-GO for installation, source-copy preparation, or production invocation**.

The full R2 candidate must still supply and exercise a single recovery transaction around source admission, exact source identity and continuous write exclusion, private disk/NVRAM/TPM run binding, run execution, failure evidence retention, XML restoration, and independent original whole-state verification. It must handle the cold `win10-debug2` alias to the selected `win10-debug3` backing explicitly and keep the unrelated active builder intact across every transition. Existing draft helpers are inputs to review, not accepted runtime. The current host installer still includes a libvirtd restart path; no restart or source change is authorized by this checkpoint.

The source lease controls in the carried R1 evidence cover disposable Btrfs and Ext4 writer/mmap/open cases, with limited fd-based fsync behavior. They do not qualify a non-expiring lease, kernel patch identity, systemd FD-store crash survival, or the whole-run guard. Those are mechanism dependencies to test with disposable surrogates if this mechanism is used; no global timeout, host policy, service, permission, or protected state was changed here. The final candidate needs a concrete crash, retention, install, and rollback procedure before owner approval is requested.

## Provenance

- Original independent review: `driver/evidence/2026-10-11/luna-t5-lifecycle-file-lease-guard-r1-independent-review.md`, SHA-256 `30853874ae6cf6e521f5b395279c2c3b3b32e779e736c9dee36f89b38978e707`.
- Root-frozen R1 capture: `c9649ac5c6a7d1b72ed0bfde13533713a380407efa725e43b8f696f8ae5f3523`.
- Root R1 disposition: `3e1bdb85c69853f6dc41928953bd789249107beb4ece4a5589794fb89f25c799`.
- Canonical lock-path source design: `28860cc9f2fec83f46e0959525acb2902392b2258305e973d1a5c25e06531bc8`.

None of these pins is source or runtime acceptance. This checkpoint remains a new R2 review artifact, separate from R1.
