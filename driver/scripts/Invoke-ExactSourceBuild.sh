#!/usr/bin/env bash
# Build hash-pinned source on the isolated builder and fetch artifacts for verification.
# Usage: driver/scripts/Invoke-ExactSourceBuild.sh <label> [commit-ish=HEAD|--worktree] [--prepare-only]
# The default archives committed sources (a git archive, so the
# result never depends on the builder mirror's dirty state), writes a host-side per-file SHA-256 manifest, and
# has Build-ExactSource.ps1 verify every extracted file, build, sign and summarize in a fresh child directory.
# Evidence: driver/evidence/<today>/exact-<label>-*.txt. Artifacts: /tmp/claude-1000/exact-<label>/.
# The process exit code is NOT the verdict: read the summary lines (exit=, errors=, warnings=, artifact hashes).
# --worktree captures current tracked project bytes and freezes build tools without committing.
# --prepare-only stops before any network operation; use a fresh label for the later build.
# SAFEUPLOAD_SIGNING_THUMBPRINT and SAFEUPLOAD_SIGNING_STORE_LOCATION select
# an independently verified signer; defaults preserve the original test signer.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
label="${1:?label}"; commit="${2:-HEAD}"; mode="${3:-}"
[[ "$label" =~ ^[A-Za-z0-9._-]{3,60}$ ]] || { echo 'Invalid build label'; exit 2; }
[[ "$mode" == '' || "$mode" == '--prepare-only' ]] || { echo 'Invalid mode'; exit 2; }
host=192.168.122.210
thumb="${SAFEUPLOAD_SIGNING_THUMBPRINT:-220DD82C37FCF36048D59E4F10113185D81D5DC7}"
store="${SAFEUPLOAD_SIGNING_STORE_LOCATION:-CurrentUser}"
owner_fsp="${SAFEUPLOAD_OWNER_WINFSP_PROTOTYPE:-false}"
reviewed_inputs="${SAFEUPLOAD_REVIEWED_INPUTS_JSON:-}"
reviewed_sha="${SAFEUPLOAD_REVIEWED_INPUTS_SHA256:-}"
snapshot_args=()
if [[ -n "$reviewed_inputs" || -n "$reviewed_sha" ]]; then
    [[ "$commit" == '--worktree' && -n "$reviewed_inputs" && "$reviewed_sha" =~ ^[0-9A-Fa-f]{64}$ ]] || { echo 'Reviewed inputs require worktree mode, a document, and its SHA-256'; exit 2; }
    snapshot_args=(--reviewed-inputs-json "$reviewed_inputs" --reviewed-inputs-sha256 "$reviewed_sha")
fi
[[ "$owner_fsp" == 'true' || "$owner_fsp" == 'false' ]] || { echo 'Invalid owner prototype profile'; exit 2; }
[[ "$thumb" =~ ^[0-9A-Fa-f]{40}$ ]] || { echo 'Invalid signing thumbprint'; exit 2; }
[[ "$store" == 'CurrentUser' || "$store" == 'LocalMachine' ]] || { echo 'Invalid signing store'; exit 2; }
thumb="${thumb^^}"
day="$(date +%F)"; ev="driver/evidence/$day"; mkdir -p "$ev"
work="/tmp/claude-1000/exact-$label"
[[ ! -e "$work" ]] || { echo 'Existing build directory; use a fresh label'; exit 2; }
scp_opts=(-F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR -o StrictHostKeyChecking=yes)
build_script=driver/scripts/Build-ExactSource.ps1
remote_helper=driver/scripts/remote_ps.py
if [[ "$commit" == '--worktree' ]]; then
    snapshot_json="$(python3 driver/scripts/Prepare-ExactWorktreeSource.py --output "$work" "${snapshot_args[@]}")" || exit 2
    printf '%s\n' "$snapshot_json"
    build_script="$work/tools/Build-ExactSource.ps1"
    remote_helper="$work/tools/remote_ps.py"
    verify_snapshot() {
        python3 "$work/tools/Prepare-ExactWorktreeSource.py" --output "$work" --verify --provenance-json "$snapshot_json"
    }
    pins="$(verify_snapshot)" || exit 2
    read -r zip_sha man_sha <<< "$pins"
    build_sha="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["BuildToolsSHA256"]["driver/scripts/Build-ExactSource.ps1"])' "$snapshot_json")" || exit 2
    cp "$work/source-provenance.json" "$ev/exact-$label-source-provenance.json" || exit 2
else
mkdir -p "$work" || exit 2
full="$(git rev-parse --verify "$commit^{commit}")" || exit 2
paths=(driver/SafeUpload.Minifilter driver/SafeUpload.Inspector)
if git cat-file -e "$full:driver/SafeUpload.WriterFixture/WriterFixture.cs" 2>/dev/null; then paths+=(driver/SafeUpload.WriterFixture); fi

git archive --format=zip -o "$work/src.zip" "$full" "${paths[@]}" || exit 2
: > "$work/src.manifest"
while IFS= read -r f; do
    printf '%s  %s\n' "$(git show "$full:$f" | sha256sum | cut -d' ' -f1)" "$f" >> "$work/src.manifest"
done < <(git ls-tree -r --name-only "$full" -- "${paths[@]}")
echo "commit=$full files=$(wc -l < "$work/src.manifest")"
zip_sha="$(sha256sum "$work/src.zip" | cut -d' ' -f1)"; man_sha="$(sha256sum "$work/src.manifest" | cut -d' ' -f1)"
build_sha="$(sha256sum "$build_script" | cut -d' ' -f1)"
fi
echo "zip=$zip_sha manifest=$man_sha"
cp "$work/src.manifest" "$ev/exact-$label-source-manifest.txt" || exit 2
if [[ "$mode" == '--prepare-only' ]]; then
    echo "PREPARED_ONLY=$work; no upload or build performed"
    exit 0
fi

# Revalidate the recorded local builder immediately before private source delivery.
# Strict SSH host-key checks protect this read-only preflight as well as SCP.
python3 "$remote_helper" "$host" <<'PS' 2>&1 | tee "$ev/exact-$label-builder-preflight.txt"
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or
   (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69' -or
   -not @(Get-NetAdapter | Where-Object {$_.MacAddress -eq '52-54-00-63-87-7A'}).Count){throw 'Wrong builder; source delivery refused.'}
Write-Output ('BUILDER_PREFLIGHT_MATCH UTC='+[DateTime]::UtcNow.ToString('o'))
PS
preflight_status=("${PIPESTATUS[@]}")
[[ "${preflight_status[0]}" == 0 && "${preflight_status[1]}" == 0 ]] || exit 3
# Reject every upload destination before SCP; a retained remote label cannot
# be overwritten even if its host-side work directory was moved elsewhere.
python3 "$remote_helper" "$host" <<PS > "$ev/exact-$label-destination-preflight.stdout.txt" 2> "$ev/exact-$label-destination-preflight.stderr.txt"
\$ErrorActionPreference='Stop'
foreach(\$leaf in @('exact-$label', 'exact-$label.zip', 'exact-$label.manifest', 'Build-ExactSource-$label.ps1')) {
    if(Test-Path -LiteralPath (Join-Path 'C:\Users\vika\Documents' \$leaf)){throw 'Remote build destination already exists.'}
}
Write-Output ('FRESH_BUILD_DESTINATIONS=True UTC='+[DateTime]::UtcNow.ToString('o'))
PS
[[ "$?" == 0 ]] || exit 3
if [[ "$commit" == '--worktree' ]]; then
    # Retain the original pins; a later change must fail, never become a new pin.
    [[ "$(verify_snapshot)" == "$pins" ]] || exit 3
fi

d='vika@'"$host"':C:/Users/vika/Documents'
scp "${scp_opts[@]}" "$work/src.zip" "$d/exact-$label.zip" || exit 3
scp "${scp_opts[@]}" "$work/src.manifest" "$d/exact-$label.manifest" || exit 3
scp "${scp_opts[@]}" "$build_script" "$d/Build-ExactSource-$label.ps1" || exit 3

log="$ev/exact-$label-build.txt"
python3 "$remote_helper" "$host" <<PS > >(tee "$log") 2> >(tee "$ev/exact-$label-build.stderr.txt" >&2)
\$ErrorActionPreference='Stop'
if((Get-FileHash -LiteralPath 'C:\Users\vika\Documents\Build-ExactSource-$label.ps1' -Algorithm SHA256).Hash -ne '$build_sha'){throw 'Uploaded build-tool hash mismatch.'}
& 'C:\Users\vika\Documents\Build-ExactSource-$label.ps1' -Label '$label' -ArchiveSha256 '$zip_sha' -ManifestSha256 '$man_sha' -CertificateThumbprint '$thumb' -CertificateStoreLocation '$store' -OwnerWinFspPrototype '$owner_fsp'
PS
build_exit=$?

for f in summary.txt owned-feature-wdk.txt normal-wdk.txt owned-feature-release-wdk.txt normal-release-wdk.txt sign.txt \
         SafeUpload-stage-prototype.sys owned-feature.sys normal.sys owned-feature-release.sys normal-release.sys \
         inspector-feature-release.exe inspector-normal-release.exe inspector-feature-release.txt inspector-normal-release.txt \
         writer-fixture.exe writer-fixture.txt signature-verification.json; do
    scp "${scp_opts[@]}" "$d/exact-$label/out/$f" "$work/$f" 2>/dev/null || echo "not fetched: $f"
done
cp "$work/summary.txt" "$ev/exact-$label-summary.txt" 2>/dev/null
for f in owned-feature-wdk normal-wdk owned-feature-release-wdk normal-release-wdk; do cp "$work/$f.txt" "$ev/exact-$label-$f.txt" 2>/dev/null; done
for f in inspector-feature-release inspector-normal-release writer-fixture sign; do cp "$work/$f.txt" "$ev/exact-$label-$f.txt" 2>/dev/null; done
cp "$work/signature-verification.json" "$ev/exact-$label-signature-verification.json" 2>/dev/null
echo "== fetched artifact hashes (compare with summary.txt)"
( cd "$work" && sha256sum SafeUpload-stage-prototype.sys owned-feature.sys normal.sys owned-feature-release.sys normal-release.sys \
    inspector-feature-release.exe inspector-normal-release.exe writer-fixture.exe 2>/dev/null ) | tee "$ev/exact-$label-artifact-hashes.txt"

if [[ "$build_exit" != 0 || ! -s "$work/summary.txt" ]]; then
    echo 'Exact build incomplete; retained raw stdout/stderr and artifacts are diagnostic only.'
    exit 4
fi
python3 - "$work/summary.txt" "$thumb" "$store" "$owner_fsp" <<'PYGATE'
from pathlib import Path
import sys
lines = Path(sys.argv[1]).read_text(encoding='utf-8-sig').splitlines()
for name in ('driver:normal', 'driver:owned-feature', 'driver:normal-release',
             'driver:owned-feature-release', 'inspector-normal-release',
             'inspector-feature-release', 'writer-fixture'):
    rows = [line for line in lines if line.startswith(name + ' :')]
    if len(rows) != 1 or not all(token in rows[0].split() for token in
            ('exit=0', 'succeeded=True', 'warnings=0', 'errors=0')):
        raise SystemExit('Build gate failed: ' + name)
    if name.startswith('driver:') and not all(token in rows[0].split() for token in
            ('apivalidator=True', 'prefast=True')):
        raise SystemExit('Analysis gate missing: ' + name)
    if name.startswith('driver:') or name.startswith('inspector-'):
        expected_owner = sys.argv[4] if name.startswith('driver:owned-feature') or name == 'inspector-feature-release' else 'false'
        if 'owner_fsp=' + expected_owner not in rows[0].split():
            raise SystemExit('Owner prototype profile mismatch: ' + name)
rows = [line for line in lines if line.startswith('sign :')]
if len(rows) != 1 or not all(token in rows[0].split() for token in
        ('exit=0', 'signature_valid=True', 'unsigned_unchanged=True',
         'signer=' + sys.argv[2], 'store=' + sys.argv[3])) or 'signed_sha256=NONE' in rows[0].split():
    raise SystemExit('Signing gate failed; copied output is not a verified signed artifact.')
print('ExactSourceBuildSummaryGate=PASS')
PYGATE
