# Independent T4 allocation-reply recovery review

2026-10-16; model `gpt-6.1-sol`, reasoning effort `xhigh`, independent read-only agent `allocfault_review`.
Reviewed the working diff over `2a2a2b8973bcb30dadbea7a0ec4b669448bbed78`, the T4 design and new fault controls. No VM actions.

Initial disposition: **REVISE**.

1. Same-owner retry returned STATUS_DELETE_PENDING in StageAttachResumeOrRun before reaching the new retryable StageCreate
   branch. Corrected both routes with the same AllocationReceiptPending/no-op15 condition; no early reservation release.
2. A new test incorrectly expected StageDeleted after kind-5 ACK. Corrected to its separate DiscardAcknowledgedAtUtc/confirmed
   absence contract, preserving StageDeleted as the publication-disposal receipt.

Re-review disposition: **ACCEPT WITH CONDITIONS**. Both findings resolved; no remaining security, lifetime, lock-order or
retirement blocker found. Collection excludes live attachment and op15 ambiguity, requires local drain and pins RpcReferences.
Abort/discard run at PASSIVE outside namespace locks. Abort(None/Prepared) is journal-gate serialized and durable; historical
Prepare replay cannot revive the terminal record. Only exact cleanup ACK releases the reservation; reconnect rejects stale ACKs
and keeps exact requests for replay.

The reviewer independently ran the two extracted-control tests: GCC/Clang production controls with UBSan PASS. Its final evidence
note requested explicit successful Abort with ownerIsLive:false (the earlier helper used true). The primary agent subsequently
made initial Abort, restart replay and terminal replay explicitly use ownerIsLive:false and commitPolicyAllowed:false; all 33
selected agent cases then passed in both Debug and Release. Production code was unchanged after re-review.

Conditions: required matched Windows WDK/PREfast/ApiValidator/import builds and feature user+SYSTEM matrix; protected fault,
ordinary/runtime-/boot-Verifier, unchanged T4 regression gates and restoration. Source acceptance and local diagnostics do not
qualify the protected pair.
