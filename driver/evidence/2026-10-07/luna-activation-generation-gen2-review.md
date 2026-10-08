# Adversarial review: cfee5a33

**Verdict: ACCEPT WITH CONDITIONS**

**P0/P1: none. P2: one very-long-horizon generation comparison issue** at `driver/SafeUpload.Minifilter/StageWriters.c:5180`.

## P2 — signed comparison stops stamping fresh entries after the generation sign bit

`SafeUploadCurrentPolicyGeneration` returns a `LONG`, and the new loop compares `LONG stamped < LONG live` (StageWriters.c:5178-5183). The promotion predicate later compares these generation bit patterns as `ULONG` (StageWriters.c:5105-5106); policy generation is incremented as a 32-bit `LONG` (Policy.c:1178).

Concrete scenario: after 2^31 successful policy commits, the live generation is `0x80000000` (signed `LONG_MIN`). A newly created runtime entry still has stamp 0. Since `0 < LONG_MIN` is false, BeginAliasProbe does not stamp it. Promotion compares 0 with `0x80000000` and defers it. A later policy reconcile can stamp existing rows, but a new runtime activation after that reconcile repeats the failure. This requires an extreme number of commits and is not a practical release blocker, but generation ordering should be unsigned with a defined wrap policy (or the generation must be widened / rollover rejected).

## 1. Monotone stamp and policy-writer matrix

The previous “between apply and increment” regression is closed. Apply visits an entry under exclusive `RegistryLock`, calls BeginAliasProbe, then writes G+1 at StageWriters.c:6646-6649. The runtime rename-completion callers of BeginAliasProbe also hold `RegistryLock` (for example lines 1908-1926 and 2176-2245). Reconcile holds the same lock (6680-6729). Thus these direct exchanges do not race with a BeginAliasProbe in the current call paths, despite not taking `StateLock`; apply and reconcile are also serialized by the policy-update flow.

| Timing | Result |
|---|---|
| Begin before apply visits the entry | Begin stamps G; apply then stamps G+1. |
| Begin after apply but before generation increment | Begin samples live G, but the CAS loop preserves the existing G+1. The promotion predicate fails on the entry-generation mismatch. |
| Generation increment before reconcile | A worker carrying G fails against the G+1 stamp and/or the live-generation re-read. A worker that starts under G+1 must classify under the published G+1 policy before promotion. |
| Reconcile versus runtime Begin | Both serialize on `RegistryLock`; reconcile writes G+1 after Begin and no older Begin can lower it afterward. |

For a failed finalize after apply, the stamp can remain G+1 while the live generation stays G. Policy.c:1158-1165 leaves the pending candidate in place, sets failed-closed, and returns; there is no rollback or re-stamp to G. If the service never retries (or the machine never restarts), the row can retain that unreachable stamp indefinitely. That is coupled to the already fail-closed pending-policy state: `SafeUploadPolicyAdmissionMustRetry` is true for failed-closed policy (Policy.c:314-317), and a different candidate is refused while one is pending (Policy.c:1057-1063). A successful retry commits G+1 and ReconcileCurrentScope stamps G+1 (StageWriters.c:6722-6725). So this is not a new stamp-only availability regression; recovery is retry or restart, not rollback.

## 2. Residual generation-check-to-CAS window

The read at StageWriters.c:5106 is not atomic with the state CAS at 5123-5129; the policy-generation increment at Policy.c:1178 can land between them. The commit-message claim that reconcile alone closes that interval would be insufficient: until reconcile reaches an entry, a Protected row can have `AliasProbePending == 0`, and NameActivating's state filter skips Protected rows in that case (StageWriters.c:6391-6399).

The current finalization path supplies the missing admission barrier. Finalize sets `SafeUploadPolicyFinalizing=1` before replacing/draining the epoch (Policy.c:1158-1160), leaves it set through publication, generation increment, and reconciliation, and clears it only when `SafeUploadPolicyTryEndScopeTransition(..., FALSE)` succeeds after reconciliation (Policy.c:1180-1185; Policy.c:650-671). StageStream checks `SafeUploadPolicyAdmissionMustRetry()` for operations touching the current/pending union and returns retry before dispatching them (StageStream.c:3640-3644). The epoch drain waits for callbacks that passed this check before finalization began. Therefore no new protected-union admission can use the brief stale Protected state; after reconcile takes RegistryLock, it re-begins each in-scope entry before the barrier is lifted.

After that re-begin, the named readers agree: NameActivating treats `AliasProbePending` as activating even for Protected state (StageWriters.c:6391-6402); SopMatchesPolicy returns TRUE for alias-pending entries (6523-6527); admission coverage counts alias-pending rows as not ready (6954-6969). Coverage also rejects a generation mismatch. No missing gate was found in these paths. If finalization's retry barrier were removed, NameActivating by itself would leave the pre-reconcile Protected interval uncovered.

## 3. Lock / IRQL check

Reading the generation under `Entry->StateLock` adds no lock-order edge: `SafeUploadCurrentPolicyGeneration` is a nonblocking interlocked read (Policy.c:1213-1219), with no policy or registry lock acquisition. The call is safe at the raised IRQL used by the spin lock. The re-read still has the narrow race described above, but current finalization admission/drain ordering covers it.

No files other than this report were changed. No VM or tests were run.
