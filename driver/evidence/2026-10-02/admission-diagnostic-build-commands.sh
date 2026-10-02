#!/usr/bin/env bash
# Run in Git Bash on the WDK builder, from this checkout. This script is
# evidence-only: it builds and records output but does not install or deploy.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
evidence_dir="$repo_root/driver/evidence/2026-10-02"
project_win="$(cygpath -w "$repo_root/driver/SafeUpload.Minifilter/SafeUpload.Minifilter.vcxproj")"
rules_win="$(cygpath -w '/c/Program Files (x86)/Windows Kits/10/CodeAnalysis/DriverRecommendedRules.ruleset')"
agent_project_win="$(cygpath -w "$repo_root/agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj")"
service_project_win="$(cygpath -w "$repo_root/agente/SafeUpload.Agent.Service/SafeUpload.Agent.Service.csproj")"
results_win="$(cygpath -w "$evidence_dir/admission-diagnostic-agent-results")"
publish_win="$(cygpath -w "$evidence_dir/admission-diagnostic-service-publish")"
msbuild='/c/Program Files/Microsoft Visual Studio/18/Community/MSBuild/Current/Bin/amd64/MSBuild.exe'

mkdir -p "$evidence_dir" "$evidence_dir/admission-diagnostic-agent-results"

build_driver() {
    local configuration="$1"
    local feature="$2"
    local label="$3"
    local log="$evidence_dir/admission-diagnostic-$label.txt"

    MSYS_NO_PATHCONV=1 "$msbuild" "$project_win" /t:Rebuild \
        "/p:Configuration=$configuration" /p:Platform=x64 /warnaserror \
        "/p:SafeUploadStagingPrototype=$feature" /p:RunCodeAnalysis=true \
        /p:EnablePREfast=true "/p:CodeAnalysisRuleSet=$rules_win" 2>&1 | tee "$log"
}

# Match Build-StagedOwnedStreams.ps1: native x64 MSBuild, Warnings-as-errors,
# PREfast, DriverRecommendedRules, and Universal API validation.
build_driver Debug false normal-debug
build_driver Debug true feature-debug
build_driver Release false normal-release
build_driver Release true feature-release

dotnet test "$agent_project_win" --nologo \
    --logger 'trx;LogFileName=admission-diagnostic-agent-tests.trx' \
    --results-directory "$results_win" 2>&1 | \
    tee "$evidence_dir/admission-diagnostic-agent-tests.txt"

dotnet publish "$service_project_win" -c Release -r win-x64 \
    --self-contained true -o "$publish_win" --nologo 2>&1 | \
    tee "$evidence_dir/admission-diagnostic-service-release.txt"
