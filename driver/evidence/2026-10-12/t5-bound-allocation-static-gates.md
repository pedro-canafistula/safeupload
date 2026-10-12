# T5 bound allocation and filename resolver gates

Driver source: `827b3f415f439e3c2c052d87275615ee7907c6cb`. Agent/matrix source:
`744fd08e2e01540e08dfd44d4c7b7872f4cd01f7`. **Static gates PASS; live allocation/publication and protected runtime remain open.**
The [Luna security-design review](../2026-10-11/t5-bound-allocation-publication-design-review-luna6.md) precedes implementation.
No revised pair was installed or booted. The bound-head capability is reserved, not advertised.

| WDK profile | Warnings / errors | PREfast / ApiValidator |
| --- | ---: | --- |
| Normal Debug | 0 / 0 | enabled / enabled |
| Normal Release | 0 / 0 | enabled / enabled |
| Feature Debug | 0 / 0 | enabled / enabled |
| Feature Release | 0 / 0 | enabled / enabled |

`t5-bound-allocation1` exact-source build exits 0; inspector normal/feature Release and writer fixture also pass at 0/0.
The signed feature Debug artifact SHA-256 is `DC284C2780AB2EBEB6C3749360DBA8BE43A7ECA42AAC17D6E87986B2FB406C7A`;
signature validation passes. Driver sources are unchanged from `827b3f41` through the agent source above.

| Agent profile | Passed / discovered / unique executions | V23 cases | New head cases |
| --- | ---: | ---: | ---: |
| Normal Debug | 863 / 863 / 863 | compiled out | 5 / 5 |
| Normal Release | 863 / 863 / 863 | compiled out | 5 / 5 |
| Feature Debug | 1101 / 1101 / 1101 | 69 / 69 | 5 / 5 |
| Feature Release | 1101 / 1101 / 1101 | 69 / 69 | 5 / 5 |

Agent `t5-bound-allocation2` exits 0 with `AgentMatrixGate=True` and independent discovery/execution gate PASS.
Every user/SYSTEM TRX result was independently recounted: all Passed, unique execution IDs, complete discovered totals.
Service/tray/test/discovery builds, test legs and both Release packages pass at 0 warnings / 0 errors.

V23 strictly checks the 124-byte packed carrier, full target/root/parent IDs, volume GUID, disposition/absence/reference rules,
exact UTF-16 leaf boundary and zero tails. Normal builds omit the payload/parser and reject its marker without text fallback.
The destination resolver preserves exact leaves, uses the Windows ordinal filename comparator consistently for queue/head/observation,
reuses legacy folded heads and refuses equivalent duplicate heads. Existing concurrent-alias generation and publication assertions remain.
The old folded-storage-hash unit assumption is replaced by exact-address checks and actual durable-head/reopen/ordering checks.

The first matrix passed all test legs but failed its final ZIP with disk full; it remains FAILED. The harness now reclaims only
completed project bin/obj after source verification and retained packages. PowerShell 5.1 parsing, eight host self-checks, native-job
cleanup and source/evidence-retention controls pass; the complete rerun above passes without changing a product or inventory assertion.

Raw output remains local under `/tmp/claude-1000/exact-t5-bound-allocation1/`, `output/exact-agent-matrix/t5-bound-allocation2/`,
matching `exact-t5-bound-allocation1-*` / `exact-agent-matrix-t5-bound-allocation2-*` prefixes in `evidence/2026-10-11/`, and host logs.
The failed first matrix and harness controls remain under the `bound-allocation1` and `bound-profile-cleanup` prefixes.
These are builder gates; they do not prove protected bytes, Verifier, restoration or automatic hold release.
Identity-bound manifests/seeding, anchored permits and every physical/recovery commit, asynchronous dispatch, native acknowledgements
and teardown still require integration before the single kernel lifetime review and protected application/fault rows.
