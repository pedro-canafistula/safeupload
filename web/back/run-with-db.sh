#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
database_env="$project_dir/../../db/.env"

if [[ ! -f "$database_env" ]]; then
    echo "ERRO: crie db/.env a partir de db/.env.example antes de iniciar o backend." >&2
    exit 1
fi

set -a
# shellcheck source=/dev/null
source "$database_env"
set +a

export SAFEUPLOAD_DB_PASSWORD
export SAFEUPLOAD_DB_URL="jdbc:mysql://127.0.0.1:${SAFEUPLOAD_DB_PORT:-3306}/safeupload?serverTimezone=America/Sao_Paulo&allowPublicKeyRetrieval=true&useSSL=false"

exec mvn spring-boot:run
