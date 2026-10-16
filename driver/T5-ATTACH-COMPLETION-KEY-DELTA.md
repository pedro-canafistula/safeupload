# T5 attach completion: focused re-review delta

Base: `wt/mvp-pair`, `9e392df3bd8c7510409f65e2595f4a26234791fd` (owner reports WDK `mvp-k3` PASS).
Scope: the stale callback-data address described in [RCA, “Alternating copies”](/home/victor/Work/safeupload-staging/driver/evidence/2026-10-16/demo1/copy-rca-sol61.md).
One focused independent Sol 6.1 xhigh re-review is requested before boot; no review or runtime attribution is claimed here.

## Lifetime change

Add resident `StageAttachFinishCallback` immediately before `StageAttachComplete` in
[StageStream.c](SafeUpload.Minifilter/StageStream.c). Replace only its four completion calls:
native success with post-callback record, ordinary native read fallback without post-callback,
native failure, and staged completion. Preserve each result/context and prior IoStatus writes.

State order: registered cancellation is cleared (and an already-entered callback joined),
then all callback-data reads/status writes finish. The helper asserts cancellation is no
longer registered, takes `StageAttachLock`, transfers `Transaction->CallbackData` into a local
and sets the lookup key NULL, releases the lock, asserts the local is non-NULL, then calls
`FltCompletePendedPreOperation` once. A new CREATE reusing that address cannot match the old
transaction. The lock serializes the key clear with duplicate/cancellation lookup.

The attach worker calls completion at PASSIVE_LEVEL; the short spin region is resident,
O(1) and runs at DISPATCH_LEVEL. No other lock, allocation, I/O, wait, object release or
Filter Manager completion occurs inside it. No callback-data access follows completion.

Keep `StageAttachLookup`, LookupLinked, active count, instance identity, stream/related-object
pins, references, Completed event, final lookup removal and duplicate CREATE check unchanged.
A transaction with a NULL callback-data key still blocks instance teardown/capacity until
`StageAttachDrainTransaction` finishes stream cleanup and related-object release, removes
the lookup, drops the worker reference and releases active accounting in the existing order.
Cancellation before completion still finds the original transaction; after address reuse it
finds only the new transaction. Mandatory/instance teardown keeps its existing arbitration
and drain. No admission, inspection, publication or failure policy changes.

## Controls and verification

The new [attach-completion-key-selfcheck.py](scripts/t5/attach-completion-key-selfcheck.py)
compiles and executes production helper/completion/lookup bodies under deterministic
host C shims. Cover reentrant address reuse at all four completion sites, still-live duplicate
rejection, cancellation before/after the key transfer, cancellation completion join, and
teardown ownership surviving until final removal. Negative mutations must catch clear-after-
completion, missing lock, wrong result/context, early lookup/accounting release and lost
cancellation/teardown barriers. Update only existing source controls whose completion anchor
moves to the helper, retaining their assertions. Run all T5 Python checks and T4 verdict check.

Agent is untouched; no agent compile/matrix rerun is needed for this local change. Full WDK,
PREfast/ApiValidator and protected runtime qualification remain separate gates. Local results:

- GCC and Clang C11 with `-Wall -Wextra -Werror`: PASS. Full production helper,
  `StageAttachComplete`, cancellation lookup, instance lookup and final-drain bodies
  execute in 30 cases per compiler. All four hand-back sites, reused-address
  cancellation routing, pending cancellation join and retained teardown ownership
  are covered. All 14 runtime mutants compile and fail execution; five source
  mutants are rejected. Source comparison verifies the existing duplicate,
  cancellation, instance teardown, lookup removal, reference and drain functions
  are identical to HEAD.
- Python sweep: **13/14 scripts PASS** (12 T5 scripts, T4 verdict and matrix-runner
  self-check). `manifest-retry-selfcheck.py` has three pre-existing failures on
  unchanged `9e392df3`: its source/mutation patterns still require `20U <<
  persistenceAttempt`, while the owner's PREfast fix uses `(LONGLONG)20 <<
  persistenceAttempt`. Baseline replay reproduces all three; the retry function
  is unchanged by this delta. That separate control is left untouched.
- `git diff --check` and note links: PASS. Agent untouched; no agent build.
  [Local receipts and failed attempts](evidence/2026-10-16/attach-completion-key-local-1/result.md).

Changed files: StageStream.c, this note, the new control above, and only the two
completion-anchor substitutions in [attachment-replay-selfcheck.py](scripts/t5/attachment-replay-selfcheck.py)
and [teardown-participation-selfcheck.py](scripts/t5/teardown-participation-selfcheck.py).
Leave source uncommitted; no builder or VM action, and no independent review claimed.
