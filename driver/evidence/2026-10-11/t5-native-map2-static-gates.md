# T5 native lifetime record component gates

Source: `e9458807d61ef42d012478f9a5311f2c5c017a6c`. **Static gates PASS; CREATE admission, authenticated replay and protected recovery remain unqualified.**

| WDK profile | Warnings / errors | PREfast / ApiValidator |
| --- | ---: | --- |
| Normal Debug | 0 / 0 | enabled / enabled |
| Normal Release | 0 / 0 | enabled / enabled |
| Feature Debug | 0 / 0 | enabled / enabled |
| Feature Release | 0 / 0 | enabled / enabled |

The inspector's normal/feature Release builds and native writer fixture also pass at 0/0.
The exact-source build runner records `ExactSourceBuildSummaryGate=PASS`. The signed feature Debug artifact's SHA-256 is
`ACEF90B376BF87A616D7AEAF471ABB71CE939CADC51A92D8007B3D84466E63FB`; signature verification passes.
Normal builds omit the native-record compilation unit.

| Agent profile | Passed / discovered / unique executions | New cancellation cases | Guidance cases |
| --- | ---: | ---: | ---: |
| Normal Debug | 821 / 821 / 821 | 4 / 4 | 18 / 18 |
| Normal Release | 821 / 821 / 821 | 4 / 4 | 18 / 18 |
| Feature Debug | 885 / 885 / 885 | 4 / 4 | 18 / 18 |
| Feature Release | 885 / 885 / 885 | 4 / 4 | 18 / 18 |

Agent service/tray/test/discovery builds and both Release packages pass at 0 warnings / 0 errors. The runner exits 0 with
`AgentMatrixGate=True`; independent discovery/execution checks pass with no failures or skips. All four new cancellation cases and
all 18 guidance cases were checked individually in each profile's TRX. The cancellation cases reopen a real durable journal, require
the exact authenticated canceled-before-handle witness, release the exceptional publication hold automatically, and preserve the
scheduled generation floor without fabricating a negative CREATE result or physical deletion ACK.

Earlier attempt `t5-native-map1` failed both feature builds with PREfast C28112 for a mixed direct/interlocked counter read.
The retry uses interlocked accesses throughout; no suppression or assertion change was introduced. Raw output remains local under
`exact-t5-native-map1-*`, `exact-t5-native-map2-*`, `exact-agent-matrix-t5-native-map2-*`, and the corresponding host logs.

The bounded original-object record map and cancellation-safe callback ownership are source components. No CREATE producer fills
the map yet, no authenticated transport exports it, and live reconciliation/notification emission remains pending. Integrated kernel
lifetime/lock-order review and protected fault rows under Verifier are still required before runtime qualification. No VM install/run occurred.
