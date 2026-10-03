#!/usr/bin/env bash
# Usage: Invoke-ExactAgentBuild.sh <label> [commit=HEAD]. Read summary/TRX for the verdict.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
label="${1:?label}"; commit="${2:-HEAD}"
[[ "$label" =~ ^[A-Za-z0-9._-]{3,60}$ ]] || exit 2
full="$(git rev-parse --verify "$commit^{commit}")" || exit 2
work="/tmp/claude-1000/exact-agent-$label"
[[ ! -e "$work" ]] || { echo 'Existing agent evidence directory'; exit 2; }
mkdir -p "$work"
ev="driver/evidence/$(date +%F)"; mkdir -p "$ev"
git archive --format=zip -o "$work/src.zip" "$full" agente || exit 2
while IFS= read -r f; do
    printf '%s  %s\n' "$(git show "$full:$f" | sha256sum | cut -d' ' -f1)" "$f"
done < <(git ls-tree -r --name-only "$full" -- agente) > "$work/src.manifest"
zip_sha="$(sha256sum "$work/src.zip" | cut -d' ' -f1)"
man_sha="$(sha256sum "$work/src.manifest" | cut -d' ' -f1)"
opts=(-F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new)
d='vika@192.168.122.210:C:/Users/vika/Documents'
scp "${opts[@]}" "$work/src.zip" "$d/exact-agent-$label.zip" || exit 3
scp "${opts[@]}" "$work/src.manifest" "$d/exact-agent-$label.manifest" || exit 3
scp "${opts[@]}" driver/scripts/Build-ExactAgent.ps1 "$d/Build-ExactAgent-$label.ps1" || exit 3
printf 'SourceCommit=%s\nArchiveSHA256=%s\nManifestSHA256=%s\n' "$full" "$zip_sha" "$man_sha" > "$ev/exact-agent-$label-provenance.txt"
sha256sum driver/scripts/Build-ExactAgent.ps1 driver/scripts/Invoke-ExactAgentBuild.sh >> "$ev/exact-agent-$label-provenance.txt"
cp "$work/src.manifest" "$ev/exact-agent-$label-source-manifest.txt"
python3 driver/scripts/remote_ps.py 192.168.122.210 <<PS > "$ev/exact-agent-$label-build.txt" 2>&1
& 'C:\Users\vika\Documents\Build-ExactAgent-$label.ps1' -Label '$label' -ArchiveSha256 '$zip_sha' -ManifestSha256 '$man_sha'
PS
for f in summary.txt tests.txt agent-tests.trx publish.txt package-manifest.txt dotnet-info.txt stage-service-publish.zip; do
    scp "${opts[@]}" "$d/exact-agent-$label/out/$f" "$work/$f" 2>/dev/null || echo "not fetched: $f"
    if [[ -f "$work/$f" ]]; then
        case "$f" in *.zip) ;; *) cp "$work/$f" "$ev/exact-agent-$label-$f" ;; esac
    fi
done
cat "$work/summary.txt"
