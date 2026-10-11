# Independent review: T5 recovery transaction R2 lock-ordering checkpoint A1

**Disposition: GO for this narrow source-ordering correction and its recorded disposable controls; NO-GO for integration, installation, host invocation, or runtime/full-transaction acceptance.** This review is limited to the lock-ordering checkpoint and does not qualify the recovery transaction.

## Captured source and evidence

I reviewed the root-frozen candidate `output/review-candidates/m2-t5-recovery-transaction-r2-lock-ordering-a1-root-a1`, whose closed capture is `driver/evidence/2026-10-11/m2-t5-recovery-transaction-r2-lock-ordering-a1-root-review-capture.json` (SHA-256 `0b1299ef9b41b2211bf5730059160267487cbafb8ec65d27fe2e4ff11cbdd14c`). It binds two source files, six author artifacts, and three context artifacts. The runtime source SHA-256 is `145ed9008255cec4264a07160a15b6a98af76b729b5dd55e80e727a926102bc0`; the self-check SHA-256 is `8244ca6c5f234c854953b20414640aaa7c2474f7547d841412d68bad6ab37bdd`; the source delta SHA-256 is `be19030288c25decf11a3ebcdc29ef54fe08521c4bbae2e4135075e13e333581`.

The checkpoint is compared against immutable R1 capture `c9649ac5c6a7d1b72ed0bfde13533713a380407efa725e43b8f696f8ae5f3523` and root disposition `3e1bdb85c69853f6dc41928953bd789249107beb4ece4a5589794fb89f25c799`. R1 was correctly marked `NO_GO_R1_ACTIVE_INSTALL_OR_RUNTIME_FULL_TRANSACTION_REQUIRED`: durable attempt reservation and journal creation preceded the canonical `flock`; the installer lock did not guard the full run; and runtime closure, effective exclusion, and cold shared-backing handling remained unproved.

## Ordering correction

In the R2 `main()` authorized branch, namespace and authorization reads and `_verify_auth()` precede the lock, but no durable attempt or journal record is written there. `main()` then acquires the canonical lock, rejects an existing attempt/journal, reserves `ATTEMPT_PATH`, and calls `_apply_transaction()` with that held descriptor and its device/inode identity. `_apply_transaction()` creates and fsyncs the journal, syncs its parent, then appends the lock-acquired and transaction-begin records. The `finally` in `main()` holds the descriptor through the operation and closes it on exit. In the no-authorization branch, the same lock is acquired before preflight collection and the exclusive durable preflight write.

The fixed namespace bootstrap is a separate necessary step before the lock can be held. The reviewed implementation uses a fixed `/run/safeupload-t5/` directory and lock path, no-follow directory/file opens, exclusive creation for absent objects, no unlink/replacement, metadata and path-identity checks, nonblocking exclusive `flock`, and a held-inode check through `/proc/<pid>/fdinfo`. These checks address the R1 ordering finding: attempt, journal, and durable preflight state are now serialized before their first write by the canonical installer lock. The source diff is confined to the installer and its self-check.

## Controls and limits

The pinned checkpoint result (`98bb789b8352b3e4551e4fdbb0cb49026155a2d9bf1ad7cf5c442b61253588a9`) and raw output (`cfc6211ea26f3ccde8368525c4c53000047ed15482a3705d9b7d1b17a1d691a2`) record PASS for structural branch-order checks, one-inode bootstrap race/exclusion fixtures, authorized lock/attempt/journal order, no-authorization lock/preflight order, and the carried rollback fixtures. The self-check substitutes fixture boundaries around `main()` and uses temporary paths for the real lock operation. I reviewed these as recorded disposable controls; I did not rerun them. They do not establish host/runtime behavior.

This correction does not provide a whole-run guard, continuous source exclusion, exclusion of direct filesystem or libvirt writers, private disk/NVRAM/TPM binding, cold `win10-debug2` shared-backing treatment, preservation of the active builder, crash recovery, or independent whole-state restoration. The existing installer still has a libvirtd restart path. The lease and service-manager questions are mechanism-specific dependencies, not universal owner gates, and remain outside this narrow disposition. No host policy, permission, sysctl, ACL, daemon, VM, or protected source state was changed or qualified by this review.

Accordingly, this checkpoint is suitable to continue as a candidate correction to the R1 lock-order defect. R2 remains **NO-GO** for source integration, installation, host invocation, and full transaction/runtime claims until the separate full-candidate review and its required safety evidence are complete.
