#!/usr/bin/env bash
# Build one exact commit on the isolated builder and fetch hash-verified artifacts.
# Usage: driver/scripts/Invoke-ExactSourceBuild.sh <label> [commit-ish=HEAD]
# Archives only driver/SafeUpload.Minifilter and driver/SafeUpload.Inspector of that commit (a git archive, so the
# result never depends on the builder mirror's dirty state), writes a host-side per-file SHA-256 manifest, and
# has Build-ExactSource.ps1 verify every extracted file, build, sign and summarize in a fresh child directory.
# Evidence: driver/evidence/<today>/exact-<label>-*.txt. Artifacts: /tmp/claude-1000/exact-<label>/.
# The process exit code is NOT the verdict: read the summary lines (exit=, errors=, warnings=, artifact hashes).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
label="${1:?label}"; commit="${2:-HEAD}"
host=192.168.122.210; thumb=220DD82C37FCF36048D59E4F10113185D81D5DC7
day="$(date +%F)"; ev="driver/evidence/$day"; mkdir -p "$ev"
work="/tmp/claude-1000/exact-$label"; mkdir -p "$work"
scp_opts=(-F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new)
full="$(git rev-parse --verify "$commit^{commit}")" || exit 2
paths=(driver/SafeUpload.Minifilter driver/SafeUpload.Inspector)
if git cat-file -e "$full:driver/SafeUpload.WriterFixture/WriterFixture.cs" 2>/dev/null; then paths+=(driver/SafeUpload.WriterFixture); fi

git archive --format=zip -o "$work/src.zip" "$full" "${paths[@]}" || exit 2
: > "$work/src.manifest"
while IFS= read -r f; do
    printf '%s  %s\n' "$(git show "$full:$f" | sha256sum | cut -d' ' -f1)" "$f" >> "$work/src.manifest"
done < <(git ls-tree -r --name-only "$full" -- "${paths[@]}")
zip_sha="$(sha256sum "$work/src.zip" | cut -d' ' -f1)"; man_sha="$(sha256sum "$work/src.manifest" | cut -d' ' -f1)"
echo "commit=$full files=$(wc -l < "$work/src.manifest") zip=$zip_sha manifest=$man_sha"

d='vika@'"$host"':C:/Users/vika/Documents'
scp "${scp_opts[@]}" "$work/src.zip" "$d/exact-$label.zip" || exit 3
scp "${scp_opts[@]}" "$work/src.manifest" "$d/exact-$label.manifest" || exit 3
scp "${scp_opts[@]}" driver/scripts/Build-ExactSource.ps1 "$d/Build-ExactSource-$label.ps1" || exit 3

log="$ev/exact-$label-build.txt"
python3 driver/scripts/remote_ps.py "$host" <<PS 2>&1 | perl -pe 's/<Objs.*?<\/Objs>//g' | tr -d '\r' | grep -v -e '^$' -e CLIXML | tee "$log"
& 'C:\Users\vika\Documents\Build-ExactSource-$label.ps1' -Label '$label' -ArchiveSha256 '$zip_sha' -ManifestSha256 '$man_sha' -CertificateThumbprint '$thumb'
PS

for f in summary.txt owned-feature-wdk.txt normal-wdk.txt owned-feature-release-wdk.txt normal-release-wdk.txt sign.txt \
         SafeUpload-stage-prototype.sys owned-feature.sys inspector-feature-release.exe inspector-normal-release.exe writer-fixture.exe writer-fixture.txt; do
    scp "${scp_opts[@]}" "$d/exact-$label/out/$f" "$work/$f" 2>/dev/null || echo "not fetched: $f"
done
cp "$work/summary.txt" "$ev/exact-$label-summary.txt" 2>/dev/null
for f in owned-feature-wdk normal-wdk owned-feature-release-wdk normal-release-wdk; do cp "$work/$f.txt" "$ev/exact-$label-$f.txt" 2>/dev/null; done
echo "== fetched artifact hashes (compare with summary.txt)"
( cd "$work" && sha256sum SafeUpload-stage-prototype.sys owned-feature.sys inspector-feature-release.exe inspector-normal-release.exe 2>/dev/null ) | tee "$ev/exact-$label-artifact-hashes.txt"
