#!/usr/bin/env bash
# Local, offline compile of the agent for normal/feature x Debug/Release (workflow rule 1, 2026-10-14). DIAGNOSTIC ONLY: it catches
# compile errors before a builder run; the Windows agent matrix (Invoke-ExactAgentMatrixBuild.py) remains the gate (tests, discovery,
# packages). Mirrors Build-ExactAgentMatrix.ps1 per profile: a fresh copy of agente/, then
#   dotnet build <Service|App|Tests>.csproj -c <Debug|Release> -warnaserror -p:SafeUploadAdmissionEvidence=<false|true>
# plus -p:EnableWindowsTargeting=true (needed on Linux for net10.0-windows/WPF/WinForms).
# Requirements: the user-local SDK matching the builder's dotnet-info (10.0.400, runtime 10.0.11) in ~/Work/safeupload-tools/dotnet
# and the warmed NuGet cache in ~/Work/safeupload-tools/nuget-cache. Restore is offline: the cache is a read-only fallback folder
# and the only restore source is an empty local directory. All writes go under ${TMPDIR:-/tmp} (works in the Codex
# workspace-write sandbox, which has no network and blocks MSBuild worker nodes and the compiler server: hence -m:1,
# --disable-build-servers and UseSharedCompilation=false).
# Usage: Invoke-LocalAgentCompile.sh [--root <checkout>] [profile ...]   profiles: normal-debug normal-release feature-debug feature-release
set -uo pipefail
TOOLS=${SAFEUPLOAD_TOOLS:-/home/victor/Work/safeupload-tools}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
profiles=()
while [ $# -gt 0 ]; do
    case "$1" in
        --root) root=$(cd "$2" && pwd); shift 2 ;;
        normal-debug|normal-release|feature-debug|feature-release) profiles+=("$1"); shift ;;
        *) echo "unknown argument: $1"; exit 2 ;;
    esac
done
[ ${#profiles[@]} -gt 0 ] || profiles=(normal-debug normal-release feature-debug feature-release)
dotnet_dir="$TOOLS/dotnet"; cache="$TOOLS/nuget-cache"
[ -x "$dotnet_dir/dotnet" ] || { echo "LocalAgentCompile=ERROR missing SDK at $dotnet_dir"; exit 2; }
[ -d "$cache" ] || { echo "LocalAgentCompile=ERROR missing NuGet cache at $cache"; exit 2; }
[ -d "$root/agente" ] || { echo "LocalAgentCompile=ERROR no agente/ under $root"; exit 2; }
work=$(mktemp -d "${TMPDIR:-/tmp}/safeupload-agent-compile.XXXXXX")
export DOTNET_ROOT="$dotnet_dir" PATH="$dotnet_dir:$PATH" DOTNET_CLI_HOME="$work/dotnet-home" DOTNET_NOLOGO=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_GENERATE_ASPNET_CERTIFICATE=false \
    NUGET_PACKAGES="$work/nuget-packages" NUGET_HTTP_CACHE_PATH="$work/nuget-http" MSBUILDDISABLENODEREUSE=1
mkdir -p "$DOTNET_CLI_HOME" "$NUGET_PACKAGES" "$work/empty-feed"
echo "LocalAgentCompile root=$root sdk=$("$dotnet_dir/dotnet" --version) work=$work (diagnostic only; the matrix is the gate)"
failed=0
for profile in "${profiles[@]}"; do
    case "$profile" in
        normal-debug) configuration=Debug; feature=false ;;
        normal-release) configuration=Release; feature=false ;;
        feature-debug) configuration=Debug; feature=true ;;
        feature-release) configuration=Release; feature=true ;;
    esac
    src="$work/$profile"; mkdir -p "$src"
    tar -C "$root" --exclude='*/bin' --exclude='*/obj' -cf - agente | tar -C "$src" -xf -
    for project in Service App Tests; do
        log="$work/$profile-$project.log"
        dotnet build "$src/agente/SafeUpload.Agent.$project/SafeUpload.Agent.$project.csproj" -c "$configuration" -warnaserror \
            -p:SafeUploadAdmissionEvidence="$feature" -p:EnableWindowsTargeting=true \
            -p:RestoreSources="$work/empty-feed" -p:RestoreFallbackFolders="$cache" -nologo \
            -m:1 --disable-build-servers -p:UseSharedCompilation=false > "$log" 2>&1
        rc=$?
        if [ $rc -eq 0 ]; then
            echo "LocalCompile $profile $project PASS"
        else
            failed=1
            echo "LocalCompile $profile $project FAIL (exit $rc, log $log)"
            if grep -qE '(error|warning) [A-Z]+[0-9]+' "$log"; then
                grep -E '(error|warning) [A-Z]+[0-9]+' "$log" | sed -E "s#$src/##" | sort -u | head -20 | sed 's/^/    /'
            else
                tail -8 "$log" | sed 's/^/    | /'   # not a compiler diagnostic: show the environment failure
            fi
        fi
    done
done
if [ $failed -eq 0 ]; then echo 'LocalAgentCompile=PASS'; rm -rf "$work"; else echo "LocalAgentCompile=FAIL (logs kept in $work)"; fi
exit $failed
