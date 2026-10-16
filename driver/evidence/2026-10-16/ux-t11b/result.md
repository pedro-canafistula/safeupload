# T11b: allocation-before-reconcile and exact cleanup retirement

Base `d89f9f7c4a6713cac936c02f8976610d8e270c7b`, branch `ux/t11`.
Product-only correction of the nine `st-m1-diag` allocator failures. Tests remain
byte-identical to that base. No kernel or harness change, VM action or remote run.

The missing-epoch guard confused a valid first allocation (already persisted,
attachment handshake next) with loss of an established epoch record. Before
publishing the first ordinary driver-bound manifest, `CreateAsync` now persists
that allocation's epoch under the same journal gate. It does so only when epoch
metadata is absent **and no retained driver receipt exists**. A pre-existing
record is never replaced by allocation; attachment capability/tuple/owner gates
still decide whether a caller can attach. The existing missing-epoch guards on
both reconciliation paths remain. Failure before manifest publication can leave
an accepted but empty epoch, which still requires its exact ordinary drain before
a different epoch is accepted; no positive manifest or permission is inferred.

The same regression also over-pinned terminal hot legacy cleanup records. An
exact acknowledged historical EmptyHeld cleanup (or its exact retired direct
child with matching version/driver/owner) can satisfy compatibility work in the
matching accepted live epoch; compaction still requires age, absence, no rename/cleanup/discard
obligation, and maximum-generation/reference closure. Missing epoch evidence, archived replay receipts and modern discard ACKs remain
pinned; a lost modern ACK is not driver-consumed retirement proof. Pending parent cleanup retains its exact
child, and a newer ordinary generation is required before obsolete legacy
parents/children can disappear. This preserves existing legacy compatibility
without emitting new EmptyHeld state or weakening protected byte authority.

Verification and delivery receipts follow below after execution. The supplied
Windows TRX and all local attempts are retained in `.scratch/st-m1-diag/` and
`.scratch/t11b/verification/`. Windows matrix remains a separate gate.

## Verification and remaining gate

- Final feature Debug/Release App + Service/Tests compile diagnostics: **0 warnings,
  0 errors**. The compiled service source equals this final working source in both.
- Existing focused actual xUnit methods: **88 pass + the same 5 Linux Windows-
  comparator failures** in each configuration, including all previous T11
  retention/missing-epoch/archive/closure controls. No failures are converted to
  skips or a Windows PASS.
- **13/13 journal-only diagnostics PASS** in Debug and Release. They use real
  portable stage identities and the unchanged allocator-test attachment and legacy
  fixture helpers, exercising allocation-before-reconcile; both legacy child
  cleanup kinds; SID/creation/driver mismatches; pending-parent restart, exact
  child ACK then max-generation compaction; released held-stage/disposal and
  replacement refusal; modern ACK retention; and wrong legacy generation,
  reference and parent-reservation retention. This does not exercise the native
  allocator constructor or Windows security/filesystem behavior. Released fixture
  bytes are written before portable identity capture because the developer-host
  fallback's creation timestamp can change on write.
- Attempting the unchanged nine allocator methods on Linux fails at the existing
  NTFS/ReFS constructor before their bodies. These are retained platform failures,
  not nine passing Windows tests. The supplied Windows failures and original TRX
  remain preserved.
- Matrix runner self-check: **21/21 PASS**. No source tests were added, edited,
  renamed, removed or skipped; the complete test tree is unchanged from d89f9f7c.
- Independent read-only Sol 6.1 xhigh worker advisory review: **ACCEPT WITH
  CONDITIONS** after narrowing the exception to the existing exact legacy child
  validator. It confirmed missing-epoch, archived and modern replay pins remain;
  it ran no build/test/VM and did not establish Windows qualification.

[Structured receipts and hashes](local-checks.json). Raw local attempts, including
intermediate scratch fixture failures, are retained under `.scratch/t11b/`.

Rerun all nine reported methods on Windows, then the unchanged four-leg feature
agent matrix on the integrated stable source. A failed first epoch write cannot
publish a positive manifest; a subsequent manifest-write failure can leave a
conservative empty epoch requiring exact drain. Modern discard ACK delivery is
not inferred from persistence. This fix changes no activation/capability gate,
protected public mutation, kernel code or imports.

Delivery: `.scratch/ux-t11b.bundle`, ref `refs/heads/ux/t11`, prerequisite exactly
`d89f9f7c4a6713cac936c02f8976610d8e270c7b`; final commit/bundle hash receipt is
`.scratch/t11b/delivery.txt`. Original checkout Git metadata remains read-only.
