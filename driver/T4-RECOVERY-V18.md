# T4 recovery backport for the pre-T5 runtime pair

This branch starts at `970239a3` (agent `t4-af1`) and carries the focused journal-recovery fix from
`feat/driver-m2` through `0cd58e79`. It pairs with the already-built/reviewed `m2-driver5-t11` (`60fecdbc`).
The base wire protocol, startup negotiation, kernel and admission evidence are unchanged. Do not merge this
old tree over M2 or treat its runtime results as qualification of the final M2 pair.

The native-success receipt binds the legacy journal's exact transfer, destination generation, namespace
history and approved digest. It also captures the identity and length of the held stage, and the committed
public temporary's identity. Unlike current M2, the legacy journal has no T5 attachment epoch or persisted
measured-stage fields; this backport adds neither. Hand-back retains the baseline private-path, sharing,
owner and digest checks. No T5 capability is enabled or simulated.

Recovery only finishes bookkeeping after observed native success. Lost receipts after restart keep the
Publishing reservation and name the file in the tray. Persistence failures during hand-back keep its
obligation retryable; actual identity/content/copy failures keep the baseline terminal behavior.

The current commit-based Windows matrix harness is carried back so no freeze/pin artifacts are required.
It checks all discovered cases exactly once across the normal-user/SYSTEM legs, all four profiles at 0/0,
the admission tests and the new recovery tests. T5-only mandatory test names are replaced by the recovery
names because those components do not exist in this source; the main-branch matrix is unchanged.

Runtime remains pending: short Verifier run, 10,000 cycles with a six-hour-or-longer deadline, raw-volume
regressions and separate verified VM restoration. No failed result is converted to a pass.
