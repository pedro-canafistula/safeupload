# T5 anchored name observer component gates

Agent source: `3df7aa97a137c67cec484936e1db251aed472c3f`.
Result: **component gates PASS; protected runtime NOT QUALIFIED**.
Raw logs remain local; this curated readout omits machine/account metadata.

| Agent profile | Passed / discovered | Observer cases | Service/tray/test builds |
| --- | ---: | ---: | --- |
| Normal Debug | 799 / 799 | 14 / 14 | 0 warnings / 0 errors |
| Normal Release | 799 / 799 | 14 / 14 | 0 warnings / 0 errors |
| Feature Debug | 863 / 863 | 14 / 14 | 0 warnings / 0 errors |
| Feature Release | 863 / 863 | 14 / 14 | 0 warnings / 0 errors |

The matrix runner exited 0 and independently matched discovery to execution: every discovered case ran exactly once, without
failure or skip. All 14 observer results were also checked individually in each profile's raw TRX. Normal builds omit admission
evidence; feature builds include it. These matrices still include all 24 native-recovery proof cases.

Actual unprotected Windows NTFS controls proved:

- A native delete-on-close creator closed while another reader remained open. Child metadata reopening returned Win32 5;
  anchored enumeration still found the original full file identity, then found absence after the last reader closed.
- A child held with ShareAccess=0 could not be reopened for reading (Win32 32), while the observer found its exact identity.
  Wrong directory/root identities and parent case mode were refused; canceled observation did not produce a receipt.
- A directory spanning multiple query pages was fully enumerated. Repeated observations restarted the same anchor's cursor,
  found the target consistently and proved a missing leaf only after complete enumeration.

Hostile decoder cases reject short/overlapping/unaligned entries, invalid lengths/UTF-16, duplicate canonical names, directories,
reparse points and zero file IDs. Identity tests retain all 128 bits and distinguish case-sensitive matching.

Driver source is unchanged from `960ba2d7`; its four WDK/PREfast/ApiValidator builds passed at 0/0
([readout](t5-native-recovery2-static-gates.md)). The authenticated driver-anchor exporter, live close/startup dispatch, notification,
local kernel drain and protected fault-injection/Verifier/byte-observer/restoration gates remain pending. No revised pair has booted.

Local raw output uses the `exact-agent-matrix-t5-native-observer1` prefix, including the summary, execution check, build/discovery
logs and four profiles' main/user/SYSTEM TRX files. Those raw files are not uploaded by this commit.
