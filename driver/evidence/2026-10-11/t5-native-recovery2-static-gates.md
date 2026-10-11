# T5 native recovery component gates

Source: `960ba2d701137a94f43b5915a0902bbfb2de0df7`.
Result: **component/static gates PASS; protected runtime NOT QUALIFIED**.
This curated readout omits machine/account metadata. Raw output remains local under this evidence directory.

| Driver profile | Warnings | Errors | PREfast | ApiValidator |
| --- | ---: | ---: | --- | --- |
| Normal Debug | 0 | 0 | PASS | PASS |
| Normal Release | 0 | 0 | PASS | PASS |
| Feature Debug | 0 | 0 | PASS | PASS |
| Feature Release | 0 | 0 | PASS | PASS |

| Agent profile | Passed / discovered | New native-recovery cases | Service/tray/test builds |
| --- | ---: | ---: | --- |
| Normal Debug | 785 / 785 | 24 / 24 | 0 warnings / 0 errors |
| Normal Release | 785 / 785 | 24 / 24 | 0 warnings / 0 errors |
| Feature Debug | 849 / 849 | 24 / 24 | 0 warnings / 0 errors |
| Feature Release | 849 / 849 | 24 / 24 | 0 warnings / 0 errors |

Both build runners exited 0. The matrix's independent discovery/result check passed: every discovered case ran exactly once,
with no failed or skipped case, including the user and SYSTEM legs. The 24 native-recovery cases were also checked individually
against all four raw TRX files. Admission evidence is absent in normal builds and present in feature builds.

The journal keeps the hold for live original handles, resumed original drivers, same-boot reload without cleanup, partial or
unreconciled replay, stale/disconnected/reconstructed tokens, wrong anchors and unexplained replacement. Exact replayed cleanup or
qualified boot evidence releases only the exceptional hold, preserving the on-close intent and generation floor.

Local raw output: `exact-t5-native-recovery2-summary.txt`, the four `exact-t5-native-recovery2-*-wdk.txt` files,
`exact-agent-matrix-t5-native-recovery2-summary.txt`, `exact-agent-matrix-t5-native-recovery2-root-readout.json`, and the four
`exact-agent-matrix-t5-native-recovery2-*-results-agent-tests.trx` files. The runner retains the remaining build/discovery/user/SYSTEM
logs locally too. They are not uploaded by this commit.

Still required: authenticated live driver record/anchor export, close/startup recovery dispatch and named-file diagnostics;
mandatory local lifetime drain and its pre-boot kernel review; protected fault injection, independent destination-byte observation,
runtime Verifier and separate VM restoration. No revised pair has booted.
