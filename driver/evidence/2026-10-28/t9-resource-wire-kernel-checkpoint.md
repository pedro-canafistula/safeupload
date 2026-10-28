# T9 passive wire kernel gate — 2026-10-28

**Static/build/import/signature gate PASS; no kernel boot or pair qualification.**
Source `c5e5c83cb17d13be0b82110de458a3434ba2ddb0`, builder2, exact source archive
SHA-256 `C2A4EF0C9FA23142DBB2D2B10166CBDAFCED073D99A125E17E3897CAAE17E901`.
The change adds passive C layouts/assertions; it supplies no active resource
handler, growth consumer, readiness or cutover.

**m2t9wirek1028a2**: both feature WDK Debug/Release builds, PREfast and ApiValidator
have zero warnings/errors. Import availability passes over both: 248 Debug and
247 Release imports. Feature Inspector/writer fixture builds also pass at zero
warnings/errors. Test signing is valid with the existing approved recovery signer
`A6D6CE1AA28835D509160A80ADB7894869AADF38` in LocalMachine (owner option B,
2026-10-15), unchanged unsigned artifact and independently verified signature.
[Structured result](t9-wire-kernel-m2t9wirek1028a2/result.json).

Artifact SHA-256:

- Debug unsigned: `8CFB5B83A854C515A79827D99034F7BDD554084C01CCE52A88200C0CCC363DE6`
- Release unsigned: `C30602E90CF8B206176D7E801ACA89CDAB09CAA83273EA8256558D8A206EC67E`
- Debug signed delivery copy: `07C8778F65144FCF83764182B424039230D58065879D7051FD851ED69E1009A1`

The first attempt **m2t9wirek1028a1** passed build/static/import checks but failed
signing because the shell wrapper default requested the absent old `220DD…`
certificate from CurrentUser. [Failed receipt](t9-wire-kernel-m2t9wirek1028a1/result.json)
and original raw logs remain unchanged. Read-only certificate inventory and the
2026-10-15 owner record / 2026-10-22 successful build identified the already-approved
LocalMachine signer. No certificate, account, image or host configuration changed.

The wrapper now defaults to those existing approved settings and retains explicit
overrides. Bash parsing and the existing runner's two self-checks pass, including
required-row/import/signature guard mutations. The
[default-selection control](t9-wire-kernel-m2t9wirek1028a2/default-selection-control.json)
executes the actual selector assignments and proves omitted defaults match the
verified A2 run and explicit overrides still work. The native PowerShell build
script is unchanged; A2 is its real Windows PowerShell 5.1 execution with those
same effective settings. No redundant third WDK build or product VM row.
