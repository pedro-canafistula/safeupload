# T5 owner-approved Restart guidance gates

Source: `6ee1112ee4c62c8334adedcdf2d1474c334cf2a0`. **Agent component gate PASS; protected recovery remains unqualified.**

| Profile | Passed / discovered | Guidance cases | Service/tray/tests and Release packaging |
| --- | ---: | ---: | --- |
| Normal Debug | 817 / 817 | 18 / 18 | 0 warnings / 0 errors |
| Normal Release | 817 / 817 | 18 / 18 | 0 warnings / 0 errors |
| Feature Debug | 881 / 881 | 18 / 18 | 0 warnings / 0 errors |
| Feature Release | 881 / 881 | 18 / 18 | 0 warnings / 0 errors |

The matrix runner exited 0, `AgentMatrixGate=True`; independent discovery/execution checks confirm every discovered case ran
exactly once, with no failure or skip. All 18 guidance results were also checked individually in each profile's TRX.
The appended RestartWindows advice crosses the existing notification pipe without adding a transfer state or unlock action.
Its file-named tray message distinguishes Windows Restart from shutdown/power-on. It applies only to the owner-approved fixed-NTFS
forced-teardown exception; T21 requires remount reconciliation instead. Live recovery emission remains pending.

Attempt `t5-native-notice3` passed the same four test totals and all service/tray/test builds at 0/0, but its overall gate failed:
the isolated builder ran out of disk during feature Release bundling. Raw output was retained. Only reproducible `bin`/`obj`
directories from ten earlier isolated agent builds were cleared, after matching their retained source archive hashes; archives,
packages and evidence were preserved. Cleanup freed 2,854,539,264 bytes. The unchanged-source complete retry above passed.

Raw output remains local under `exact-agent-matrix-t5-native-notice3-*`, `exact-agent-matrix-t5-native-notice4-*`, their
`*-agent-matrix-host.txt` files and `t5-builder-generated-output-cleanup.txt`. This readout excludes machine/account metadata.
The normal admission capability remains compiled out and the feature capability remains enabled. No VM install/run occurred.
