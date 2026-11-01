#!/usr/bin/env bash
# Usage: lab/terraform.sh init|plan|apply|output|destroy|test ...
# Uses the lab module and a local mkisofs wrapper; changes no host configuration.
set -euo pipefail
lab=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
umask 077
export PATH="$lab/bin:$PATH"
command -v xorriso >/dev/null || { echo 'missing tool: xorriso' >&2; exit 2; }
cd "$lab/terraform"
exec terraform "$@"
