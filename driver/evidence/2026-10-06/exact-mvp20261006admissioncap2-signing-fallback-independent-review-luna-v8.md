# Independent V8 signing fallback review

Date: 2026-10-06. Review scope is read-only review of the frozen V8 signing
candidate and its parser/memory-fixture evidence. It does not include key,
store, ACL, trust, VM, build, or artifact-signing operations.

## Frozen pins and review result

The V8 manifest
`exact-mvp20261006admissioncap2-signing-key-recovery-sha256-v8.txt` is pinned
at SHA-256
`308b16cfe401f63a7fc338ea7cf81990c0ca5c71ebfbc43cbe3772b0a14621d6`; all 39
entries pass `sha256sum -c`. Reviewed principal pins are:

| File | SHA-256 |
|---|---|
| V8 plan | `4b12e0676921ddb59a9a49595e7ebdf8ed01a2976c4400699bbf53cc239928aa` |
| `signing-guard-helpers-v8.ps1` | `9585e1acd512f9532de032c6ce2df251fa774acc83d27cfc6afceb437ce64c42` |
| V8 key creator | `c314030c50ac5a1565833af633e64e19ad9494644d0e7afdd802490b7f84b57b` |
| V8 cold challenge | `cfa6dff0ba96f3bbc346bb1dc03eec6a47153c2cd4011b913deae0c3634896a3` |
| V8 memory fixture | `3545155af5f2adf1f20d702280960180b6252fe90a21068855b4dbdcc3e5a2bc` |
| V8 builder-root trust | `4c8a541e40d5ccb7b283a19a39bd2857051fd5fd5070c3d4aa62628408a7ee98` |
| V8 debuggee trust | `a803b84319c8686b5496556f53f8cd700f964c769e7c40d32ec65035eea8f5f0` |
| V8 rollback | `87d68295f42e740b26963e2fba4cb049a74b5b8ef044db6c22d43bb9131cee28` |

**Creation-only static gate: PASS.** The V8 design handles the observed
provider default without rewriting or widening it. The retained V7 failure
record shows identical before/failure snapshots: BA owner (`S-1-5-32-544`),
captured machine group (`S-1-5-21-316478115-1595729549-2803163825-513`),
protected and canonical DACL, and exactly three explicit noninheritable
FullControl (`2032127`) Allow ACEs ordered Creator Owner (`S-1-3-0`), SYSTEM
(`S-1-5-18`), Administrators (`S-1-5-32-544`). V8 requires that exact
principal sequence and mask, BA owner, protected/canonical descriptor, and
typed owner/group, SDDL, display-name, and ordered-row parity thereafter. The
group is captured and must remain identical; it has no separate initial SID
allowlist. V8 does not map Creator Owner to the owner, vika, SYSTEM, or
Administrators.

This interpretation is supported by Microsoft's [well-known SID
documentation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab),
which describes CREATOR_OWNER as a placeholder in an inheritable ACE and says
the SID is replaced when inherited; [ACE inheritance
rules](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-inheritance-rules),
which state that no inheritance flags have no effect on child objects; and
[AccessCheck documentation](https://learn.microsoft.com/en-us/windows/win32/secauthz/checking-access-to-private-objects),
which says access checking matches ACE trustees against the requester's token
trustees. Applying those semantics to the captured, explicit ACE is an
inference; V8 preserves the literal `S-1-3-0` row. Its separate same-invocation
challenge verifies that the pinned elevated vika token can use the actual
machine key. The V8 allowlist does not accept other principals, reordered or
duplicate rows, inherited/inheritable ACEs, another mask spelling, or an
unprotected/noncanonical descriptor.

The creator checks the exact builder name, UUID, and vika SID in its own
invocation and requires enabled Administrators membership. It checks the
original signer and PFX/CER hashes, `testsigning=No`, all six store inventories,
absence of the V8 subject and outputs, and existing package/evidence
directories. It creates a unique-subject RSA-3072 key in Microsoft Software
KSP with a nonexportable policy, code-signing-only EKU, DigitalSignature-only
key usage, CA=false, and 90-day validity. It preserves the KSP's default DACL,
checks it before and after an in-memory random sign/verify challenge, and only
then exports a public CER and metadata. Static inspection found no `Set-Acl`
or private-key export. A failure may leave a post-mint key; the failure record
forbids reuse and records inventories/ACL, while no trust/build/sign step is
attempted.

## Parser and memory fixture evidence

The root readout
`signing-guard-ps51-20261006v8a-root-readout.json` has SHA-256
`c5df399c99915957dff1d9ace29c90eb591de0e07b589e571d5b4e613052ff38`;
stdout is `af14708fa1be3a443968becf4ffd2c6257ab1f0284e6d2787ec42f418540f774`;
stderr is
`a3639af5e23464fc391dae127fd5493f02c8178068a35866d9c7fdd35dcd623f`.
All seven PS 5.1 parser checks report zero errors, the fixture emits
`V8_MEMORY_ONLY_FIXTURE_PASS`, self-check exit is 0, and the validation temp
was removed. Raw stderr is nonempty (392 bytes), containing only one CLIXML
progress record, “Preparing modules for first use”; there is no Error stream.
The readout and fixture report only the pinned helper as an external disk
input, with no certificate-store read, key access, filesystem ACL access,
trust change, or target mutation. This bounded progress is accepted as benign.

## Remaining lifecycle gates

This review and fixture pass clear only the creation-stage source and memory
fixture. The root's fresh recovery3 baseline and same-invocation identity/token
conditions were creator execution preconditions. The V8 key has since been
created and independently reviewed; its exact metadata and CER hashes, current
certificate inventory, and unmodified ACL are recorded below before a
separately checkpointed cold-boot challenge. At this initial-review point,
builder trust was planned for CurrentUser Root and remained untested. The later
V8 CurrentUser Root attempt failed; the separately reviewed V10 LocalMachine
Root route subsequently passed with only the expected merged CurrentUser Root
visibility. See the final V10 result below. No debuggee trust, TrustedPublisher
addition, artifact signing, rollback, or deployment is established by that
result. Artifact signing still requires separate review of the frozen proof
source and execution caller.

V7's failed thumbprint `CFC1B836F758E01358FACE11BE9B00AADF6A8468` is not to be
reused. It remains on the retained failed branch; V8 uses a new subject and a
fresh recovery3 builder baseline.

## Post-mint review and cold-challenge gate

The frozen V8 manifest still passes all 39 entries at the reviewed manifest
SHA above. The actual V8 creator output records `CreatedAndProbed` at
`2026-10-06T13:55:37.8120613Z`, thumbprint
`A6D6CE1AA28835D509160A80ADB7894869AADF38`, public CER SHA-256
`47E7069980A60CBCF4DFF61F0F2D3F02EDCF97C2976708790B49D03A09243B2A`, and
creation-metadata SHA-256
`51701037af41fcc19101e26dd2d632934d20b94190d42782474f68f05abdfc1e`. It
records the exact three-row captured DACL as unchanged, `NoAclWrite=true`,
nonexportable Microsoft Software KSP RSA-3072, `testsigning=No` before and
after, successful in-memory challenge verification, and no persistent trust
change or signature export. Creator stdout SHA-256 is
`7d4c28665f9122d551a77e0480f1becfa8ebc262051bcc662b4b3eb9f4e9e8d4`; stderr
is empty.

The independent current-builder inventory read confirms the pinned computer,
UUID, and vika SID, V8 thumb only in `LocalMachine\My`, all other five store
inventories unchanged from mint, original signer and PFX/CER hashes retained,
`testsigning=No`, no build actors, and `StateMutated=false`. Its stdout SHA-256
is `5b50213445743fb7b61b88cf70a4b3910563cecea546ff3251bca8c7cc7e3413` and
stderr is empty. Separate read-only certificate and key checks confirm the
machine certificate and public CER have the exact same V8 thumbprint, the
machine certificate has a private-key association, and current metadata/CER
hashes and key SDDL match the captured values. Their stdout SHA-256 values are
`4bef519534ca13e145af91e602fe5a221546077c4f28c643554eb8880af9c968` and
`8a1332231112118442ab813f4cf740dd50d6caf7d9dbb981703a6a8e2ab784ee`; both
stderr files are empty. The independent checks are read-only.

Static review of the pinned cold-challenge source is PASS for its stated
scope. It binds the same builder identity and enabled-admin token, testsigning
state, old signer/files, expected creation metadata and CER hashes, exact V8
thumbprint, captured ACL snapshots, KSP provider, RSA size, nonexportability,
machine-key flag and CNG unique name. It requires exact six-store parity with
mint, signs and verifies a new random challenge only in memory, repeats ACL
and store checks, and clears challenge/signature buffers. It emits no signature
bytes and performs no trust, build, or artifact signing. The source hash is
`cfa6dff0ba96f3bbc346bb1dc03eec6a47153c2cd4011b913deae0c3634896a3`.

The cold-challenge script's checkpoint and root-approval parameters are
caller-supplied switches; it does not itself consume a host checkpoint
readout or require a cold-proof file. Therefore execution must remain gated on
root's independent verification of the key-bearing child checkpoint and cold
boot, then a separately reviewed actual `V8_COLD_KEY_CHALLENGE_PASS` record
bound to the same thumbprint, CER hash, and metadata hash. The builder trust
script's source hash is
`4c8a541e40d5ccb7b283a19a39bd2857051fd5fd5070c3d4aa62628408a7ee98`. Static
scope is PASS for adding only this public CER to `CurrentUser\Root`; it
checks the current key-file ACL against the captured snapshots and enforces
the exact thumb's six-store delta, leaving `TrustedPublisher` and machine
trust unchanged. Its switches also do not consume the actual cold-proof
record, so root must withhold its invocation until that record has been
reviewed. ## Final frozen checkpoint packet review

The author froze the key-bearing checkpoint packet with
`execution-pins.json` SHA-256
`6aca834b6bcbbd14c5c4c7df17f45c7e7b327ad8872fb956057511f45da8a143`.
Its eight packet-file pins pass `sha256sum -c`, and all 19 external input
pins in `inputs.json` match the current V8 evidence. The corrected helper
compares the CER input pin case-insensitively to the pinned mint CER hash and
checks the exact V8 thumb, metadata, creator/helper/challenge hashes and
public CER bytes before any libvirt command. The earlier candidate's
case-sensitive CER comparison is withdrawn; no checkpoint command was
executed from that candidate. The frozen packet's CER pin is the actual
verified value
`47e7069980a60cbcf4dff61f0f2d3f02edcf97c2976708790b49d03a09243b2a`.

The packet uses the healthy Recovery3 disk as both initial disk and read-only
qcow2 parent, and one new child for the cold boot. It preserves the V7
UUID/XML, shutdown, file-mode/ownership, parent-stat, QMP backing-node,
pre-start definition-restoration, and two guest-baseline controls. The
checkpoint scope is system disk and signing state; no firmware, TPM, or RAM
snapshot and no full-VM rollback claim are made. The host readout checks NVRAM
metadata before and after start but does not claim NVRAM content integrity.
The corrected source/input pins and static checkpoint-safety review are
PASS. Root independently confirmed the exact hashes and all three XML
schemas; an intercepted early-guard check passed all metadata/CER/source
checks and reached the first `virsh domuuid` call without invoking libvirt.
This review approves only the checkpoint phase at these frozen pins.

The cold challenge remains gated on host QMP/parent/child evidence and two
strict guest baseline reads. The actual `V8_COLD_KEY_CHALLENGE_PASS` output
is absent; cold challenge and all trust operations remain pending.

## Cold-challenge execution gate

Independent review of the actual Recovery3-to-V8 host and guest evidence is
PASS for the pinned cold challenge only. The host readout SHA-256 is
`353e74a63e0a3473fe9821b23b4864716cfe0ea0dcd11f00d4a934ef01ca670f`; it
records the V8 child, Recovery3 parent, parent identity/size/mtime/mode
unchanged, and the cold boot. Independent QMP and live-domain evidence hashes
are `1c6b351ad95258e79dc46b2ed01298e2a4a6b5fcb5b63ea0ecef326885a1c421`
(`post-qmp.json`), `d5ffd4e7a3e9eea1e5b4329ab89c7e37e285156c0337dea56d2725ecc96dd219`
(`verified-named-block-nodes.json`), and
`b6347365af731c97821e1fea1c4c125f1b9a77b21bbdd90b601683270916fa3e`
(`post-live.xml`). QMP shows one V8 child with Recovery3 as its immediate
backing image and one matching Recovery3 qcow2 node marked read-only; the live
VDA points at the V8 child.

The guest-baseline root readout SHA-256 is
`1d80af7fc2658a7c54b968ca2c3c16c7e1848035229eda8c79982e53b93e6eb5`. Its ten
referenced evidence pins all verify locally. The pre-shutdown and two
post-start remote commands report exit 0. Each read has the exact builder
computer/UUID, vika SID and enabled Administrators membership; all six stores
match mint evidence, the replacement thumb is only in LocalMachine My, the
original files and signer remain, testsigning is No, no build actors are
present, and trust/private-key state is unchanged. The two post-start reads
agree on the boot time and all key/store state. All three stderr streams are
392 bytes of the same CLIXML progress-only “Preparing modules for first use”
record, with no error stream.

The guest wall clock moved backward after boot as NTP settled: the pre-shutdown
baseline records BootTimeUtc `17:53:46Z`, while both post-start reads record
`14:04:13Z`. This does not undermine the host-proven cold start or the stable
two post-start reads, but the guest timestamps are not monotonic proof by
themselves. Shared NVRAM metadata changed mtime across boot; its content hash
is unavailable. This is disclosed and remains outside this disk/key
checkpoint's scope; no firmware/TPM/RAM snapshot or full-VM rollback claim is
made.

Static review of the exact pinned V8 cold-challenge source and helper remains
PASS. Given the actual host readout and two verified post-start baselines, the
cold challenge is approved once using only the exact pinned identity, thumb,
CER, and metadata arguments. The challenge itself is not yet recorded. Trust
imports, artifact signing, rollback, and deployment remain gated on a separate
review of its actual `V8_COLD_KEY_CHALLENGE_PASS` output.

## Actual cold challenge and builder-root trust gate

The actual pinned V8 cold challenge completed successfully. Its root readout
SHA-256 is `18037dfca24375f2434e13d09dd6dae5ffd8b07f8cfa523660b87b1d06b549ef`;
raw stdout SHA-256 is
`337fa6c7c1bdfe6c70bc2175af6a1954e488cdb97baf6051d606626cc73f0371`, stderr
is empty, and remote exit code is 0. The public receipt SHA-256 is
`46bc0bdeed04d164aafd9efb59fda3c2ab4dab5bcb31e52903931c766d60bd98`. The
receipt and raw challenge output identify the same V8 thumbprint, public CER
hash, creation-metadata hash, key provider/size/export policy and machine-key
state. They report enabled Administrators membership, literal CO/SY/BA rows,
unchanged key ACL and six certificate stores, no private export, no trust or
artifact signing, and no persisted challenge signature. The root readout's
five evidence pins verify against the raw output, empty stderr, public receipt,
host checkpoint, and guest-baseline readout.

I independently reviewed the builder-root trust source and the final root
caller. The caller SHA-256 is
`74abeed6ef27094d512e5b9ddbf392853e6609710c29eb1934a32d20e098dcf9`; it
hash-checks the actual challenge stdout and receipt, host and guest baseline,
checks the cold proof's V8 identity values and prior challenge exit code, then
hash-checks and parses the pinned trust/helper sources before the trust script
runs. The trust source SHA-256 is
`4c8a541e40d5ccb7b283a19a39bd2857051fd5fd5070c3d4aa62628408a7ee98`; its only
trust mutation is importing the exact public CER into vika's `CurrentUser\Root`.
It requires the exact new thumb only in `LocalMachine\My` beforehand, checks
all six store inventories and the current key ACL against the mint snapshots,
requires testsigning remain No, and verifies the exact CurrentUser Root-only
store delta. On post-import verification failure, its catch removes only that
exact thumb from CurrentUser Root. This review approves one builder
CurrentUser Root import with those pins. No debuggee trust, TrustedPublisher,
LocalMachine trust, artifact signing, rollback, or deployment is approved.
At the time of that review, the builder-root trust operation had not run. The
following actual attempt supersedes its conditional V8 trust approval.

## Correction: V8 trust failed; V9 process-capture fixture passed

The actual V8 builder-root trust script ran and exited 1. Its catch reported a
generic failure after removing the exact V8 thumb from CurrentUser Root, so the
original underlying error was not retained. The independent post-failure root
readout, SHA-256
`e48aff481fb9a181b2a1dd88c62766bc07162607bb963f60696472f66b63ba37`, records
all six certificate stores exactly at the V8 mint baseline and the machine-key
SDDL unchanged. No artifact signing was attempted. The failed V8 child remains
retained; it must not be reused for another trust test. This evidence does not
establish why the V8 import failed.

The V9 candidate is a separately versioned root-only trust script with current
source pins:

- `exact-mvp20261006admissioncap2-replacement-trust-builder-root-v9.ps1`:
  `dd25f7ae5ac38db00f37da30e951f029ca1bef1e95f436e6f6c26d8b10cccc7a`
- `signing-process-capture-v9.ps1`:
  `6cac6f59c640c6fb045f61b87be1bb4deeeea451c80cd067ae022180a0a01a9f`
- `signing-process-capture-v9-fixture.ps1`:
  `3e1fad6693fc296a4163395e9a3ab557e5226feabc666876143b80220dfd097e`

The candidate keeps the CurrentUser Root-only certificate delta, the exact
six-store checks, current key-ACL parity, and exact-thumb rollback. It calls
the documented `certutil -user -addstore Root` interface and uses a pinned
ProcessStartInfo helper that redirects and drains stdout and stderr separately
before reading the child exit code. The failure path captures original error
details, both process streams, six-store inventories and key ACL before
failure and after rollback, then rethrows the original PowerShell ErrorRecord.
The diagnostic fixture exercises child-process success, stderr with exit 7,
and launch failure without certificate-store, key, or ACL operations.
The launch-failure path is randomized and checked absent before the process
start so the diagnostic cannot invoke a pre-planted executable from `%TEMP%`.

An independent static review of these exact V9/helper/fixture pins passed. The
actual Windows PowerShell 5.1.19041.6456 run then parsed all four production
and fixture sources with zero errors and passed the three process-capture
cases. The root readout SHA-256 is
`bdc9c9491dfdbdae6366061455aad23b3211b4d329dba8019ea61398a4330ccd`; it pins
the exact three current source hashes and the V8 guard-helper hash. Remote
exit was 0, stdout SHA-256 was
`9292776dbdfafc1a99b92b93ab498e2b67df9291fa8bdf24309abcdd16903408`, stderr
was empty, and validation temporary files were absent afterward. The raw
fixture reports success exit 0, captured stderr with exit 7, and preserved
GUID-path launch failure. It records no certificate-store, key, or ACL
operations. This validates process diagnostics only; it does not explain the
V8 failure or prove that V9 trust will succeed.

At this earlier review point, no V9 trust operation or artifact signing was
approved. The one later V9 attempt is recorded below. The Microsoft command
documentation supports `certutil -addstore` with the `-user` scope, but does
not establish why V8 failed or guarantee that a particular host will complete
the import noninteractively.

## Retry1 checkpoint and repeat cold-challenge gate

I independently reviewed the fresh retry1 child before its repeat in-memory
cold challenge. The host readout SHA-256 is
`957fa3066ad673b8dcfde47de0536cf5e0ed067c97308616fb4365f2c581ffa3`; the
guest-baseline root readout SHA-256 is
`4d89fb0291da3115a2102f7528c430c9a1682faab15cee862b4b99ed0b48b487`. All ten
guest evidence pins verify locally, including pre-shutdown and two post-start
guest reads with exit 0. The host post-QMP, named-node, and live XML hashes are
`0e35ef41891449593e009d3fe3f9d9f26ca892d6ad3db791fb332d4e6b3b2ab3`,
`4c9e812a4490bb8fe1306d1abc49d2678448d8849a2e5ba38bf60e06f33c6507`, and
`3ef16ebb9ec40c6d47a847c1034c708e066ed7db5275e8deb0dc1ee4b2cbeeb6`.

The retry1 VDA points to the fresh child, which has Recovery3 as its immediate
QMP backing image; the failed V8 trust child is retained and absent from the
new child chain. QMP identifies exactly one Recovery3 qcow2 node and marks it
read-only. The Recovery3 parent stat is unchanged, and the failed child stat
is retained. Both post-start guest reads agree on the V8 thumb, CER and mint
metadata, all six stores exactly match mint evidence, the thumb remains only
in LocalMachine My, the original signer remains, testsigning is No, there are
no build actors, and trust/key state has not changed. The second actual guest
read exited 0; its stderr is the known CLIXML module-initialization progress
record only, with no error stream. The guest BootTimeUtc moved backward from
`18:04:15Z` pre-shutdown to `14:18:05Z` after boot as the guest clock settled.
The host QMP evidence and matching two post-start reads establish the cold
start and stable state; guest timestamps alone are not monotonic proof.
Shared NVRAM mtime changed across boot and its content hash is unavailable.
This checkpoint covers system disk and signing state, with no firmware, TPM,
RAM snapshot, or full-VM rollback claim.

The unchanged challenge source/helper pins are
`cfa6dff0ba96f3bbc346bb1dc03eec6a47153c2cd4011b913deae0c3634896a3` and
`9585e1acd512f9532de032c6ce2df251fa774acc83d27cfc6afceb437ce64c42`. Given
this fresh host and guest baseline, I approve exactly one repeat
`V8_COLD_KEY_CHALLENGE` run on the retry1 child with V8 thumb
`A6D6CE1AA28835D509160A80ADB7894869AADF38`, CER SHA-256
`47E7069980A60CBCF4DFF61F0F2D3F02EDCF97C2976708790B49D03A09243B2A`, and
creation-metadata SHA-256
`51701037AF41FCC19101E26DD2D632934D20B94190D42782474F68F05ABDFC1E`. This
approval covers only its random in-memory proof. The actual receipt must be
reviewed against these pins before the V9 CurrentUser Root trust attempt; no
artifact signing is approved.

The separate source-and-fixture evidence manifest has SHA-256
`3777867bc09f78547ec32c969cbf0abe6ea252640097958504fd56cdc4c59022`; all
twelve entries pass `sha256sum -c`. It pins the exact V9 trust/helper/fixture,
the actual PS 5.1 fixture readout and raw output, V8 mint metadata/CER, and the
retry1 execution, host, and guest-baseline manifests. This confirms source and
baseline identity only; final V9 trust remains gated on review of the actual
retry1 cold-challenge receipt and root's new execution caller.

## Retry1 cold proof and V9 trust caller review

The repeat cold challenge on retry1 passed. The root readout SHA-256 is
`b1ad2b0cb99d549fbff6c83342ced02c02b50dad28e27ff0df11e3191f169928`; all six
evidence pins verify locally. It records remote exit 0, empty stderr, and
`V8_RETRY1_COLD_KEY_CHALLENGE_VERIFIED` for the exact V8 thumb, CER and
creation-metadata hashes already pinned above. The public receipt SHA-256 is
`de8a14bbbec61f4f46fc1d9aaa9bf3d911543c3aaa641d74338d5d836fe7ad51`, raw
stdout SHA-256 is
`2460e40ad6690cef71c247abad244583e2f1ac7044ed05bf151c2f17585ca15c`, and the
Windows PowerShell runner record pins the reviewed cold script/helper and
exit 0. The receipt reports RSA-3072 through the Microsoft Software KSP,
nonexportable machine key, enabled Administrators membership, literal CO/SY/BA
key ACL unchanged, all six stores unchanged, testsigning No, and no trust,
artifact signing, private-key export, or persisted challenge signature.

I independently reviewed the root's V9 trust caller at SHA-256
`2773ec39daa67c374440c959acbeac09a248f0876ad7175dd4cc4b96dc0dfb71`. It
checks the frozen 12-entry V9 source-and-fixture manifest, exact cold stdout
and receipt hashes plus the retry1 host and guest readout hashes, checks the
proof's exact identity/certificate/store/ACL values, verifies V9/helper source
hashes, and parses the three uploaded production scripts on Windows PowerShell
5.1 before invoking only the V9 CurrentUser Root trust script with the pinned
thumb/CER/metadata. Root reports the local guard-only interception reached no
VM command. This review approved one V9 CurrentUser Root attempt on the
retry1 child; that attempt ran and failed. The approval is exhausted and does
not authorize a retry or artifact signing. The actual failure and the separate
V10 candidate review are recorded below.

The READY4 artifact-proof source also passed independent static review. Its
script SHA-256 is
`bb0a4312f771e41652322ae27092506896a4f13f19e8c987a506c19bb2296f42`; its
18-entry source manifest SHA-256 is
`150f70853428730ecf5100205cf8b8af4f89905bddd50807e447220f478a2a1a`, and all
entries verify. The source checks cold and V9 trust receipts, exact signer
identity and key ACL/store state, the unsigned READY4 artifact hash, and the
exact V8 SignTool thumb. It signs only a fresh private copy, checks the
original unsigned bytes remain unchanged, validates the signed copy's
Authenticode status and signer, and publishes a separate proof package. Its
SignTool path matches the pinned `Build-ExactSource.ps1` source. I have not
executed the proof script; actual trust receipt review remains the gate before
any artifact-signing action.

## Actual V9 failure and narrow V10 machine-root candidate

The actual V9 trust run failed before adding trust. Its raw stdout SHA-256 is
`6ec7afcc5436bccb6779b902b995496e9562fd420ecf34f5df6d9414d08edc5a`, raw
stderr SHA-256 is
`ad803ac2a7f1654b9e38f6ca26015f95170cd6e18ea394c8b98e02301f2cc232`, and
the pinned independent post-failure readout SHA-256 is
`57600cdd67ae9fd5818596a36632934fd9c30b36158c43b4c5b519e772777179`.
`certutil -user -addstore Root` returned `-2147024846` / `0x80070032`
(`ERROR_NOT_SUPPORTED`) after reporting `Signature matches Public Key`;
native stderr was empty. The failure readout confirms all six store
inventories equal mint baseline, the V8 key SDDL equals the before state,
testsigning remains No, and no artifact signing occurred. The response did
not attempt rollback because no store delta appeared. This identifies the
failure code and its no-side-effect result, not the API's underlying reason.

I independently inspected the exact V8 public CER, SHA-256
`47e7069980a60cbcf4dff61f0f2d3f02edcf97c2976708790b49d03a09243b2a`. It is
self-issued (`Subject` equals `Issuer`), but its critical Basic Constraints
is `CA:FALSE`; its critical Key Usage is Digital Signature only and its EKU
is Code Signing. This profile differs from the MakeCert self-signed *root*
certificate in Microsoft's test-signing example. Microsoft documents
LocalMachine Root as the location for a test CA root, and documents that
CurrentUser stores other than Personal inherit the LocalMachine stores. Its
docs do not establish why Windows rejected this exact CA:FALSE certificate in
CurrentUser Root. The later V10 run accepted the same certificate in
LocalMachine Root, so CA:FALSE alone is not an adequate explanation for the V9
failure. A CurrentUser-scope or import-method difference remains possible but
unproven. Do not repeat the CurrentUser Root attempt.

I authored a distinct V10 candidate at
`exact-mvp20261006admissioncap2-machine-root-trust-builder-root-v10-candidate.ps1`,
SHA-256
`235f1c14cfcbd402c4fb7f464a7c2af2c54bcc67ac78ecb57f0b815903ca749a`.
V9 is unchanged. The candidate preserves the exact V8 certificate, identity,
metadata, key ACL, admin-token, six-store, and testsigning guards; it uses
`certutil -addstore Root` without `-user` or `-f`, so the only mutation target
is LocalMachine Root and it will not replace a baseline certificate. It
requires the V8 thumb absent from both LocalMachine Root and its CurrentUser
Root projection, expects one exact LMRoot addition plus the documented
CurrentUser Root inherited visibility, and requires every other store to
remain byte-for-byte equivalent by thumbprint inventory. On failure it
removes only that thumb from LocalMachine Root, only if the preflight saw it
absent and the add attempt subsequently made it visible; it never removes
CurrentUser Root entries, edits TrustedPublisher/My, or changes the key ACL.
The failure path captures native output/exit status, before/failure/after
store inventories, key ACL and testsigning. The immediately preceding source
hash `f1a617b10a92f8b7f1babf9e38750d6b590ff131330bb6bf942c50c9bd0ba299`
passed a Windows PowerShell 5.1 parse with zero errors; its readout SHA-256 is
`df289d69689998ba83ec6216877981b6287fa6da00d099938f8caf27f576e316`. The
current frozen source differs only in its header comment and passed the exact
Windows PowerShell 5.1 parse again: parse-b stdout SHA-256
`a4b6891a282a4c7c8ded28acf9e173323a81e409f789f299c9c6f1ac068342f2`, stderr
SHA-256 `a3639af5e23464fc391dae127fd5493f02c8178068a35866d9c7fdd35dcd623f`.
The structured stdout names current source hash
`235f1c14cfcbd402c4fb7f464a7c2af2c54bcc67ac78ecb57f0b815903ca749a`, PS
5.1.19041.6456, zero errors, source not executed, trust unchanged, and no
artifact signing. Parse results are not execution approval. If the documented
machine-root attempt is rejected or the exact expected delta does not hold,
stop rather than trying another store on this cert. A clean next design would
use a distinct nonexportable RSA-3072/SHA-256 machine CA key and a self-signed
CA certificate in LocalMachine My, with critical Basic Constraints CA:TRUE
pathLen 0 and critical Key Usage KeyCertSign+CRLSign, then add only that
public CA certificate to LocalMachine Root. Issue a separate nonexportable
RSA-3072/SHA-256 leaf into LocalMachine My using the CA as `-Signer`, with
critical CA:FALSE, DigitalSignature, and Code Signing EKU only. Keep both
private keys in machine CNG stores and export neither. The new CA/leaf
identities invalidate V8 cold receipts, signer pins, and the artifact-proof
manifest; this requires a fresh lifecycle epoch, cold proof, and complete
store/ACL review. Add the exact leaf to LocalMachine TrustedPublisher only if
later PnP installation requires it; that is a separate trust delta. The
Microsoft `New-SelfSignedCertificate` documentation supports custom
extensions, nonexportable keys, and `-Signer`; its CA example documents the
CA=true/pathLen/key-signing shape. This remains a proposed design, not an
executed or frozen source.

The retry2 recovery child is independently pinned for the V10 gate. Its
host readout SHA-256 is
`328f49eea19d1b222ceadbdc8008bb7b9eb4d86d39f37ded118d5001929a071d`, and its
guest-baseline root readout SHA-256 is
`fc894f1490442dd359b0fee24047530676320f3273d763777ada91072113756f`. I
verified all nine execution-manifest entries and all ten guest-baseline pins;
pre-shutdown and both post-start actual remote reads exited 0. QMP shows the
retry2 child backed directly by Recovery3, with Recovery3 read-only and the
failed retry1 child excluded from the chain. The root readout records
Recovery3 parent stat unchanged, failed retry1 retained, all six stores at
mint baseline, V8 signer only in LocalMachine My, testsigning No, no build
actors, and no trust. NVRAM metadata changes across boot and its content hash
is unavailable; this is not a full-VM checkpoint claim.

The fresh retry2 cold challenge then passed for the exact V8 thumb, CER, and
metadata. Root readout SHA-256 is
`f940d145b5e8126c0666cf06413969cb548fb67c8620f7ff7b0510615e1ba61c`, raw
stdout SHA-256 is
`c63d038082d4b390e8528c2cef7fe1934b47f62b513a15832bad5c9e4c113088`, public
receipt SHA-256 is
`3ec14f6af6883fae2fa51e4945da12a8390d12e599e384231c1c061bdc4ba93e`, and raw
stderr is empty. I checked all six nested cold evidence pins and the root-run
record; the public receipt verifies the exact A6D6CE1AA28835D509160A80ADB7894869AADF38
certificate, unchanged literal CO/SY/BA key ACL, no store changes, no
trust/import, no private-key export, and no artifact signing.

The V10 source-and-evidence manifest SHA-256 is
`3838699bcce00b01f159eaa1f6a724d8a25b3f6a0281aae3318faaad06af6126`, and
all thirteen entries verify. I reviewed the final caller SHA-256
`c9c60ff38bcd6f995cc4b3c203d60019bfeeb48abfc0e34b71a2b1e512f53f72`; its
evidence field now records `TrustModified` as unknown and separately marks
independent post-readback pending, while `BuilderLocalMachineRootTrustAttempted`
is true. It binds the manifest, current cold stdout/receipt and retry2 host/
guest readouts, source pins, identity, and exact V8 expected certificate
values; it uploads three pinned files, checks their hashes and parses all
three on Windows PowerShell 5.1 before invoking only the V10 candidate. The
remote cleanup refuses to delete an unexpected or changed temp file. I did
not run the caller; root reports that no V10 trust operation had occurred.

Bridge independently reviewed candidate hash
`235f1c14cfcbd402c4fb7f464a7c2af2c54bcc67ac78ecb57f0b815903ca749a` and
reported static PASS. I approve exactly one LM\Root diagnostic attempt using
this source/caller/manifest set on the current retry2 builder. This approval
allows only the precise thumbprint absent-at-baseline LocalMachine Root delta
and its CurrentUser Root inherited view, with no TrustedPublisher/My or ACL
change. Afterward, review actual native output and exit status, rollback
status, six-store inventories and key SDDL before any further trust action.
This does not authorize artifact signing or another store retry. No V10 trust
execution had occurred at the time of this review.

Primary Microsoft references: [certutil store-scope options](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil),
[Local Machine and Current User Certificate Stores](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/local-machine-and-current-user-certificate-stores),
[Installing Test Certificates](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/installing-test-certificates),
[MakeCert Test Certificate](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/makecert-test-certificate),
[Trusted Root store semantics](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/trusted-root-certification-authorities-certificate-store),
[New-SelfSignedCertificate](https://learn.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate?view=windowsserver2025-ps),
and Microsoft's [CA certificate example](https://learn.microsoft.com/en-us/azure/vpn-gateway/site-to-site-certificate-authentication-gateway).

## Actual V10 LocalMachine Root result

The single approved V10 trust run succeeded. The frozen candidate hash is
`235f1c14cfcbd402c4fb7f464a7c2af2c54bcc67ac78ecb57f0b815903ca749a`; the
13-entry source-and-evidence manifest hash is
`3838699bcce00b01f159eaa1f6a724d8a25b3f6a0281aae3318faaad06af6126`, and all
entries pass. The exact candidate passed the Windows PowerShell 5.1.19041.6456
parse with zero errors and was not executed by the parse fixture. Parse-b
stdout SHA-256 is
`a4b6891a282a4c7c8ded28acf9e173323a81e409f789f299c9c6f1ac068342f2`; stderr
SHA-256 is `a3639af5e23464fc391dae127fd5493f02c8178068a35866d9c7fdd35dcd623f`,
which contains only the retained module-initialization CLIXML progress record.

The actual trust runner exited 0. Raw stdout SHA-256 is
`960b8e1790b582774788d423253937b9c8a2a036192251bc039200523d6cfbeb`, and raw
stderr is empty (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
The receipt records native `certutil -addstore Root` exit 0, the exact V8
thumbprint, CER and creation-metadata hashes, one LocalMachine Root addition,
and the expected CurrentUser Root merged-store view. I recomputed the
inventories against the V8 post-mint store baseline as sets, since certificate
enumeration order can differ. Only LocalMachine Root and merged CurrentUser
Root gained `A6D6CE1AA28835D509160A80ADB7894869AADF38`; all other stores are
unchanged. The key SDDL, owner, group and ordered literal CO/SY/BA ACE rows
match V8 mint evidence exactly. Testsigning remains No; the original files and
certificate remain; TrustedPublisher and LocalMachine My are unchanged; no
ACL write occurred; and no private key was exported or artifact signed.

The independent post-trust read exited 0 and records
`V10_BUILDER_TRUST_INDEPENDENT_BASELINE_PASS`. Its stdout JSON SHA-256 is
`f14f599ed0d8d824a7fc44700fe56f88ad6345b0d8af23c177deee4ec1327ccb` and stderr
is the retained module-initialization progress only. The public receipt
SHA-256 is `ac22de20b6845a524de4fbb157514171eef02ef5678384c5c36225aea8306daa`;
the root readout SHA-256 is
`546e4af933179b58781f4c928c74740077083e40012306247653b51fc4116901`; and the
root-run record SHA-256 is
`c1de9dcccadd01b19d408f04d74305d7dabc288cde5632eb3ea8be2e5f4f4edd`. The
root readout pins the raw output, empty stderr, independent read, public
receipt, root-run record and frozen source/evidence manifest. I verified those
hashes and the inventory, ACL and testsigning assertions independently. V10
builder trust is verified within this exact LocalMachine Root scope. The V9
`ERROR_NOT_SUPPORTED` cause remains unknown; the V10 success does not identify
which V9 behavior caused it.

This result clears only the builder's V10 root-trust step. The READY4 artifact
proof still requires its final frozen source and execution-caller pins and a
separate review before artifact signing. This review does not authorize
signing, another trust mutation, or deployment.

## V10 READY4 fresh-copy proof review

The frozen proof source
`exact-mvp20261006ready4-artifact-sign-proof-v10.ps1` has SHA-256
`de29f2e9770e8c478770af33b04f194b0d810185bafac64b6c91652a5e0a7d8d`; its
source manifest SHA-256 is
`1221ec75b5dbca229a86315cfef4725e85c18eb50e8288e9f139aae0f9b48916`, and all
30 checksum rows pass. The source is a narrow V8-to-V10 trust-gate derivative:
it binds the exact cold and trust receipt hashes, the LocalMachine Root trust
receipt fields, all six inventories and the captured key ACL; verifies the
pinned unsigned READY4 input is still NotSigned; checks the current builder
identity and enabled-admin token; and uses SignTool with the exact A6D6… thumb
in LocalMachine My to sign only a fresh private copy. It checks that the
original remains unchanged, the signed copy has Valid Authenticode status and
the exact signer, the stores and key ACL remain unchanged, and then publishes
a separate proof package. It does not install or deploy the driver, export the
private key, edit the key ACL, or make another trust change. Static source
review is PASS for that scope.

The exact Windows PowerShell 5.1.19041.6456 parse reports zero errors for this
source hash and explicitly records source not executed, trust unchanged and no
artifact signing. Parse stdout SHA-256 is
`d64fa3f39eb40cac3a858f2e2ebb4a702d60ed4184ed9469540f6abb21f5c97d`; stderr
SHA-256 is `a3639af5e23464fc391dae127fd5493f02c8178068a35866d9c7fdd35dcd623f`,
only the accepted module-initialization CLIXML progress. Parsing did not change
builder state.

I reviewed the final root caller
`/tmp/safeupload-artifact-sign-proof-v10-20261006a.py` at SHA-256
`c561de7790c092f5e0ae7abc16e1d3e272e0d0f95ba88c895f3533db417b0b06`. It
checks the frozen root trust-readout hash and verdict, the fixed proof-manifest
hash and all 30 input rows, plus the exact cold receipt, V10 trust receipt,
unsigned artifact, and production source hashes before upload. Its remote
PowerShell checks the seven uploaded inputs and parses the four scripts before
invoking only the gated proof source. It uses fresh separate private/public
output roots and fetches only the five expected package files, then verifies
the generated checksums and proof summary. I caught a defect in a provisional
caller: it attempted to split manifest comment and blank lines as checksum
rows. That version was not used; the frozen final caller skips those rows,
asserts exactly 30 checksum rows, and separates `ArtifactSigningWorkflowAttempted`
from `ArtifactSignAttempted`, leaving the latter unknown until a successful
proof reports SignTool exit and Authenticode status. Root reports its local
guard-only interception reached the first SSH boundary without calling the VM.

After independently reviewing the successful V10 trust result, cold C receipt,
exact parse and final caller/source pins, I approve exactly one invocation to
sign a fresh copy of the pinned unsigned READY4 artifact. This approval covers
no driver install/deployment, additional trust mutation, key ACL change, or
private-key export. If the attempt fails or the public proof checks do not
pass, retain the raw evidence and do not retry without a new review. No artifact
signing had occurred at this review point.

## Actual V10 signed-copy result

Root executed the separately approved one-copy proof workflow. The raw proof
runner stdout SHA-256 is
`33b388baaebe500642f56fdebc9c191d2708645cdf83d4ad889e95e8cbde0b5e`, and its
stderr is the retained module-initialization progress only. It reports all
four Windows PowerShell 5.1 parser checks at zero errors, `ArtifactProofExit=0`,
SignTool exit 0, Authenticode `Valid`, and signer
`A6D6CE1AA28835D509160A80ADB7894869AADF38`. The published signed-copy hash is
`30AE04A0033FE80577F608D1FE8E10A06CF2FAA2CA034F88D1B848C3630CB14D`; the
pinned unsigned READY4 input remains
`8C19FE05135E10AABACABC433F0DC5CB68A53CCBD7A3CC82052D0D9804586FC9`.

The fetched five-file proof package passes its generated `sha256sum` manifest.
The proof JSON SHA-256 is
`f007f1bb9522ec38c7ea043b62546409aaa9ab6731fd331724a2ab396d7e710a`, the
package checksum-manifest SHA-256 is
`8e51d83991a97fe274ba30b1fe1138984a6a6e3b6cd1fa452a704c3aa35fb028`, and the
signed `.sys` SHA-256 is `30ae04a0033fe80577f608d1fe8e10a06cf2faa2ca034f88d1b848c3630cb14d`.
I checked that the proof JSON pins the exact cold C and V10 trust receipts,
records the selected LocalMachine My certificate and same-process enabled
Administrators check, and reports no private-key export, key ACL change, or
additional trust change.

The root readout SHA-256 is
`155ce22a721fb17b2200bc788c60d63fb06fcda5786720550cda1fc75f7820e5`. Its
all evidence pins verify locally. The post-sign independent output SHA-256 is
`abbd29d85a527798722bf7c48432fff6165825651bf5510a32dc9e34b26a0282` (two JSON
records); the independent read exited 0 and reports the signed file's exact
hash, Valid Authenticode status and A6D6… signer, while the original remains
`NotSigned` with its exact 8C19… hash. Its current six-store inventories match
the reviewed V10 trust receipt; the key SDDL/ACE state matches mint; testsigning
is No; no build actors or driver install/load occurred; and the read itself
attempted no signing. Root-run SHA-256 is
`7652a3b1a0b2158b48e8a5e66b024f816864bc204a0fba92ea0cea4de0cd1d94`, recording
workflow and SignTool attempts separately, SignTool exit 0, and Authenticode
Valid. I independently recomputed the package, public-proof, root-readout and
post-sign inventory/ACL checks. The one-copy review is complete; no further
signing attempt is authorized by this note.
