# T5 authenticated native replay static gates

Source: `aa1a2a46e20b2088b2381fe6bdf8fc48734e43e6`. **Static gates PASS; live admission/recovery and runtime remain unqualified.**

| WDK profile | Warnings / errors | PREfast / ApiValidator |
| --- | ---: | --- |
| Normal Debug | 0 / 0 | enabled / enabled |
| Normal Release | 0 / 0 | enabled / enabled |
| Feature Debug | 0 / 0 | enabled / enabled |
| Feature Release | 0 / 0 | enabled / enabled |

Inspector normal/feature Release and native writer fixture also pass at 0/0. Exact-source build `t5-native-replay3` exits 0;
the feature Debug signed artifact SHA-256 is `DDFD06FEFCB3C4D1C1BEBD42D2838C1044C9B7182D3D13FAAD3EDBB284E07DD3`, with valid signature.
Normal builds omit the native replay/record C units.

| Agent profile | Passed / discovered / unique executions | Replay cases |
| --- | ---: | ---: |
| Normal Debug | 821 / 821 / 821 | compiled out |
| Normal Release | 821 / 821 / 821 | compiled out |
| Feature Debug | 936 / 936 / 936 | 51 / 51 |
| Feature Release | 936 / 936 / 936 | 51 / 51 |

Agent `t5-native-replay2` exits 0 with independent discovery/execution gate PASS, no failure or skip. Both user/SYSTEM TRX legs
were independently counted; all 51 replay cases pass in each feature profile. Service/tray/test/discovery builds and both Release
packages pass at 0 warnings/errors. Tests reject malformed/stale/partial replay, duplicate identities and changed final revision,
exercise the full 1024-record bound and preserve cancellation/cleanup facts. No existing assertion was changed.

The first agent attempt had one unchanged inspection deadline assertion fail at 8155 ms against its 7500 ms maximum; the complete
unchanged retry passed after WDK jobs finished. Contention was not proven to be the cause. Earlier WDK attempts exposed C identity
type errors, then required local SEH/PAGE annotations; both were corrected without weakening PREfast or adding a failed-check suppression.

Raw output remains local: `/tmp/claude-1000/exact-t5-native-replay3/`, `exact-t5-native-replay1-*` through `exact-t5-native-replay3-*`,
`output/exact-agent-matrix/t5-native-replay1/` and `t5-native-replay2/`, matching `exact-agent-matrix-*` evidence and host logs.

The read-only transport is implemented and compiled. No native CREATE producer fills the map yet, destination-head discovery
(`e97585cb`) is newer than this agent gate, and startup recovery, driver-anchor export and notification emission remain open.
No revised driver/service pair was installed or booted. Verifier and protected fault rows remain required.
