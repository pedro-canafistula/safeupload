# T5 volume provenance and unsupported-device component gates

Driver source: `1d3f47cc3e16cded56e9812b21ba2acc09c4b1d1`. Agent source:
`e088cde473ffaf56d86376807b692bf17112c1ae`. **Static gates PASS; live native recovery and runtime remain unqualified.**

| WDK profile | Warnings / errors | PREfast / ApiValidator |
| --- | ---: | --- |
| Normal Debug | 0 / 0 | enabled / enabled |
| Normal Release | 0 / 0 | enabled / enabled |
| Feature Debug | 0 / 0 | enabled / enabled |
| Feature Release | 0 / 0 | enabled / enabled |

`t5-native-volume1` exact-source build exits 0 with summary gate PASS. Inspector normal/feature Release and native writer fixture
also pass at 0/0. The signed feature Debug artifact SHA-256 is `60B606B7A1B5DB42C15772E1771C09586E1579FF0583A5926C0CECF9729F15FE`;
signature validation passes. Normal builds omit the new staging metadata and portability checks. Driver sources are unchanged
between `1d3f47cc` and `e088cde4`.

| Agent profile | Passed / discovered / unique executions | Native directory controls | Recovery guidance | Replay v22 | Native startup |
| --- | ---: | ---: | ---: | ---: | ---: |
| Normal Debug | 857 / 857 / 857 | 16 / 16 | 22 / 22 | compiled out | compiled out |
| Normal Release | 857 / 857 / 857 | 16 / 16 | 22 / 22 | compiled out | compiled out |
| Feature Debug | 982 / 982 / 982 | 16 / 16 | 22 / 22 | 53 / 53 | 8 / 8 |
| Feature Release | 982 / 982 / 982 | 16 / 16 | 22 / 22 | 53 / 53 | 8 / 8 |

Agent runner exits 0 with `AgentMatrixGate=True` and independent discovery/execution gate PASS. User/SYSTEM TRX legs were
independently counted: every result is Passed, with no duplicate or skipped execution. All service/tray/test/discovery builds and both
Release packages pass at 0 warnings / 0 errors. All three new durable clone/missing-volume/legacy-hold cases pass in each profile.

The new native NTFS controls reopen a recorded parent by ID after directory rename and saved-locator replacement, observe the
original pending child and then exact absence after last reader close, and preserve the replacement's bytes. A deleted parent cannot
be substituted by a new directory at its old pathname. These are unprotected Windows builder controls, not protected-driver evidence.

Durable-head tests separate identical filesystem IDs under different Mount Manager GUIDs, refuse a mismatched/missing original GUID,
and reopen a legacy admitted native intent without inventing its GUID or releasing its publication hold. Legacy guidance names the file
and permits diagnostics advice only; it does not promise a restart will reconstruct missing volume provenance. Replay v22 rejects the
older identity-incomplete version and zero GUID. A nonempty durable-intent replay regression proves full root/parent/public ID halves
match the journal without being transposed. Existing assertions remain intact.

The [Luna security-design review](t5-native-observation-transport-review-luna6.md) requires the GUID and portability corrections before
native admission. The feature driver captures complete `FileFsDeviceInformation`, blocks portable/removable/remote or unknown devices
from M2 admission/coverage, and records the captured GUID in native bindings. Actual fixed-reporting USB refusal still needs runtime
evidence; this is a scope guard, not T21 qualification.

Raw output remains local under `/tmp/claude-1000/exact-t5-native-volume1/`, `output/exact-agent-matrix/t5-native-volume1/`,
matching `exact-t5-native-volume1-*` / `exact-agent-matrix-t5-native-volume1-*` prefixes and host logs. No revised pair was installed
or booted. The driver-side observation RPC, live admission/physical commit dispatch, automatic hold release and teardown integration
remain open. The single integrated kernel review, protected Verifier/fault rows and separate restoration remain required.
