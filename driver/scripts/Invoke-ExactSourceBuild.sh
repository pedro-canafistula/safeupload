#!/usr/bin/env bash
# Build committed source on the isolated builder and fetch artifacts for verification.
# Usage: driver/scripts/Invoke-ExactSourceBuild.sh <label> [commit-ish=HEAD|--worktree] [--prepare-only]
# The default archives committed sources (a git archive, so the
# result never depends on the builder mirror's dirty state). The commit is the source pin;
# an archive hash checks delivery. Build-ExactSource.ps1 builds, signs and summarizes in a fresh child directory.
# Evidence: driver/evidence/<today>/exact-<label>-*.txt. Artifacts: /tmp/claude-1000/exact-<label>/.
# The process exit code is NOT the verdict: read the summary lines (exit=, errors=, warnings=, artifact hashes).
# Every driver must also import only routines Windows 10 19045 exports (exact-<label>-imports.txt; exit 5 otherwise).
# --worktree captures current tracked project bytes and freezes build tools without committing.
# --prepare-only stops before any network operation; use a fresh label for the later build.
# SAFEUPLOAD_SIGNING_THUMBPRINT and SAFEUPLOAD_SIGNING_STORE_LOCATION select
# an independently verified signer; defaults preserve the original test signer.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
label="${1:?label}"; commit="${2:-HEAD}"; mode="${3:-}"
[[ "$label" =~ ^[A-Za-z0-9._-]{3,60}$ ]] || { echo 'Invalid build label'; exit 2; }
[[ "$mode" == '' || "$mode" == '--prepare-only' ]] || { echo 'Invalid mode'; exit 2; }
selection="$(python3 driver/scripts/approved_builders.py --role kernel-sign --label "$label" --format fields)" || exit 2
read -r builder_name host builder_computer builder_user parity_check <<< "$selection"
remote_args=("$host" --role kernel-sign --label "$label")
# Existing approved recovery signer on both lab builders (owner option B,
# 2026-10-15). Explicit overrides still support other independently checked signers.
thumb="${SAFEUPLOAD_SIGNING_THUMBPRINT:-A6D6CE1AA28835D509160A80ADB7894869AADF38}"
store="${SAFEUPLOAD_SIGNING_STORE_LOCATION:-LocalMachine}"
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
support_dir=driver/scripts
if [[ "$commit" == '--worktree' ]]; then
    snapshot_json="$(python3 driver/scripts/Prepare-ExactWorktreeSource.py --output "$work" "${snapshot_args[@]}")" || exit 2
    printf '%s\n' "$snapshot_json"
    build_script="$work/tools/Build-ExactSource.ps1"
    remote_helper="$work/tools/remote_ps.py"
    support_dir="$work/tools"
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
echo "SOURCE_COMMIT=$full"
zip_sha="$(sha256sum "$work/src.zip" | cut -d' ' -f1)"
build_sha="$(sha256sum "$build_script" | cut -d' ' -f1)"
fi
python3 driver/scripts/approved_builders.py --role kernel-sign --label "$label" --format receipt > "$ev/exact-$label-builder.txt" || exit 2
echo "archive=$zip_sha"
if [[ "$commit" == '--worktree' ]]; then
    cp "$work/src.manifest" "$ev/exact-$label-source-manifest.txt" || exit 2
fi
if [[ "$mode" == '--prepare-only' ]]; then
    echo "PREPARED_ONLY=$work; no upload or build performed"
    exit 0
fi

# Revalidate the recorded local builder immediately before private source delivery.
# Strict SSH host-key checks protect this read-only preflight as well as SCP.
python3 "$remote_helper" "${remote_args[@]}" <<<'Write-Output "BUILDER_PREFLIGHT_MATCH"' 2>&1 | tee "$ev/exact-$label-builder-preflight.txt"
preflight_status=("${PIPESTATUS[@]}")
[[ "${preflight_status[0]}" == 0 && "${preflight_status[1]}" == 0 ]] || exit 3
# Reject every upload destination before SCP; a retained remote label cannot
# be overwritten even if its host-side work directory was moved elsewhere.
python3 "$remote_helper" "${remote_args[@]}" <<PS > "$ev/exact-$label-destination-preflight.stdout.txt" 2> "$ev/exact-$label-destination-preflight.stderr.txt"
\$ErrorActionPreference='Stop'
foreach(\$leaf in @('exact-$label', 'exact-$label.zip', 'exact-$label.manifest', 'Build-ExactSource-$label.ps1', 'exact-$label-tools')) {
    if(Test-Path -LiteralPath (Join-Path 'C:\Users\vika\Documents' \$leaf)){throw 'Remote build destination already exists.'}
}
Write-Output ('FRESH_BUILD_DESTINATIONS=True UTC='+[DateTime]::UtcNow.ToString('o'))
PS
[[ "$?" == 0 ]] || exit 3
if [[ "$commit" == '--worktree' ]]; then
    # Retain the original pins; a later change must fail, never become a new pin.
    [[ "$(verify_snapshot)" == "$pins" ]] || exit 3
fi

d="$builder_user@$host:C:/Users/$builder_user/Documents"
scp "${scp_opts[@]}" "$work/src.zip" "$d/exact-$label.zip" || exit 3
if [[ "$commit" == '--worktree' ]]; then
    scp "${scp_opts[@]}" "$work/src.manifest" "$d/exact-$label.manifest" || exit 3
    source_arg="-ManifestSha256 '$man_sha'"
else
    source_arg="-SourceCommit '$full'"
fi
scp "${scp_opts[@]}" "$build_script" "$d/Build-ExactSource-$label.ps1" || exit 3
python3 "$remote_helper" "${remote_args[@]}" <<<"[void](New-Item -ItemType Directory -Path 'C:/Users/$builder_user/Documents/exact-$label-tools')" || exit 3
for helper in ApprovedBuilders.ps1 approved-builders.json; do
    scp "${scp_opts[@]}" "$support_dir/$helper" "$d/exact-$label-tools/$helper" || exit 3
done
support_sha="$(sha256sum "$support_dir/ApprovedBuilders.ps1" | cut -d' ' -f1)"
config_sha="$(sha256sum "$support_dir/approved-builders.json" | cut -d' ' -f1)"

log="$ev/exact-$label-build.txt"
python3 "$remote_helper" "${remote_args[@]}" <<PS > >(tee "$log") 2> >(tee "$ev/exact-$label-build.stderr.txt" >&2)
\$ErrorActionPreference='Stop'
if((Get-FileHash -LiteralPath 'C:/Users/$builder_user/Documents/exact-$label-tools/ApprovedBuilders.ps1' -Algorithm SHA256).Hash -ne '$support_sha' -or (Get-FileHash -LiteralPath 'C:/Users/$builder_user/Documents/exact-$label-tools/approved-builders.json' -Algorithm SHA256).Hash -ne '$config_sha'){throw 'Uploaded builder support hash mismatch.'}
if((Get-FileHash -LiteralPath 'C:\Users\vika\Documents\Build-ExactSource-$label.ps1' -Algorithm SHA256).Hash -ne '$build_sha'){throw 'Uploaded build-tool hash mismatch.'}
& 'C:\Users\vika\Documents\Build-ExactSource-$label.ps1' -Label '$label' -ArchiveSha256 '$zip_sha' $source_arg -CertificateThumbprint '$thumb' -CertificateStoreLocation '$store' -OwnerWinFspPrototype '$owner_fsp' -BuilderName '$builder_name' -BuilderSupportPath 'C:/Users/$builder_user/Documents/exact-$label-tools/ApprovedBuilders.ps1' -BuilderConfigPath 'C:/Users/$builder_user/Documents/exact-$label-tools/approved-builders.json'
PS
build_exit=$?

for f in summary.txt owned-feature-wdk.txt owned-feature-release-wdk.txt sign.txt \
         SafeUpload-stage-prototype.sys owned-feature.sys owned-feature-release.sys \
         inspector-feature-release.exe inspector-feature-release.txt \
         writer-fixture.exe writer-fixture.txt signature-verification.json; do
    scp "${scp_opts[@]}" "$d/exact-$label/out/$f" "$work/$f" 2>/dev/null || echo "not fetched: $f"
done
cp "$work/summary.txt" "$ev/exact-$label-summary.txt" 2>/dev/null
for f in owned-feature-wdk owned-feature-release-wdk; do cp "$work/$f.txt" "$ev/exact-$label-$f.txt" 2>/dev/null; done
for f in inspector-feature-release writer-fixture sign; do cp "$work/$f.txt" "$ev/exact-$label-$f.txt" 2>/dev/null; done
cp "$work/signature-verification.json" "$ev/exact-$label-signature-verification.json" 2>/dev/null
echo "== fetched artifact hashes (compare with summary.txt)"
( cd "$work" && sha256sum SafeUpload-stage-prototype.sys owned-feature.sys owned-feature-release.sys \
    inspector-feature-release.exe writer-fixture.exe 2>/dev/null ) | tee "$ev/exact-$label-artifact-hashes.txt"

if [[ "$build_exit" != 0 || ! -s "$work/summary.txt" ]]; then
    echo 'Exact build incomplete; retained raw stdout/stderr and artifacts are diagnostic only.'
    exit 4
fi
# Target availability: ApiValidator does not prove that each import exists on Windows 10 19045, and a boot-start driver
# with a missing import cannot boot (m2t5rv1). Every driver artifact imports only exports of the qualified family.
if ! python3 driver/scripts/Test-DriverImports.py "$work/SafeUpload-stage-prototype.sys" "$work/owned-feature.sys" \
    "$work/owned-feature-release.sys" | tee "$ev/exact-$label-imports.txt"; then
    echo 'Import availability gate failed'; exit 5
fi
grep -qx 'DriverImportAvailability=PASS' "$ev/exact-$label-imports.txt" || { echo 'Import availability gate failed'; exit 5; }
python3 - "$work/summary.txt" "$thumb" "$store" "$owner_fsp" "$builder_name" "$host" "$builder_computer" "$ev/exact-$label-imports.txt" <<'PYGATE'
from pathlib import Path
import sys
lines = Path(sys.argv[1]).read_text(encoding='utf-8-sig').splitlines()
for key, value in zip(('Builder', 'BuilderHost', 'BuilderComputerName'), sys.argv[5:8]):
    if lines.count(key + '=' + value) != 1:
        raise SystemExit('Builder receipt mismatch: ' + key)
if lines.count('KernelBuildProfiles=owned-feature,owned-feature-release') != 1:
    raise SystemExit('Kernel profile set missing or ambiguous')
for name in ('driver:owned-feature', 'driver:owned-feature-release',
             'inspector-feature-release', 'writer-fixture'):
    rows = [line for line in lines if line.startswith(name + ' :')]
    if len(rows) != 1 or not all(token in rows[0].split() for token in
            ('exit=0', 'succeeded=True', 'warnings=0', 'errors=0')):
        raise SystemExit('Build gate failed: ' + name)
    if name.startswith('driver:') and not all(token in rows[0].split() for token in
            ('apivalidator=True', 'prefast=True', 'feature=true',
             'configuration=' + ('Release' if name.endswith('-release') else 'Debug'))):
        raise SystemExit('Analysis gate missing: ' + name)
    if name.startswith('driver:') or name.startswith('inspector-'):
        expected_owner = sys.argv[4]
        if 'owner_fsp=' + expected_owner not in rows[0].split():
            raise SystemExit('Owner prototype profile mismatch: ' + name)
rows = [line for line in lines if line.startswith('sign :')]
if len(rows) != 1 or not all(token in rows[0].split() for token in
        ('exit=0', 'signature_valid=True', 'unsigned_unchanged=True',
         'signer=' + sys.argv[2], 'store=' + sys.argv[3])) or 'signed_sha256=NONE' in rows[0].split():
    raise SystemExit('Signing gate failed; copied output is not a verified signed artifact.')
imports = Path(sys.argv[8]).read_text(encoding='utf-8-sig').splitlines()
if imports.count('DriverImportAvailability=PASS') != 1 or any(
        line.startswith('DriverImportAvailability=') and line != 'DriverImportAvailability=PASS'
        for line in imports):
    raise SystemExit('Import availability gate missing or failed')
for artifact in ('SafeUpload-stage-prototype.sys', 'owned-feature.sys', 'owned-feature-release.sys'):
    rows = [line for line in imports if line.startswith('DriverImports ' + artifact + ' ')]
    if len(rows) != 1 or rows[0].split()[2] != 'PASS':
        raise SystemExit('Import result missing or failed: ' + artifact)
print('ExactSourceBuildSummaryGate=PASS')
PYGATE
