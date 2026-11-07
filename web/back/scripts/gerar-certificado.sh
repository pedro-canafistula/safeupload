#!/usr/bin/env bash
# Certificado autoassinado para o backend falar HTTPS com os agentes no laboratório.
# Uso: web/back/scripts/gerar-certificado.sh <ip-ou-nome-do-servidor> [senha]
# Gera safeupload.p12 no diretório atual e imprime o SHA-256 que vai em
#   SafeUpload.Agent.Service.exe cadastrar https://<servidor>:8443/agent/ <token> --certificado <sha256>
# Depois suba o backend com:
#   --server.port=8443 --server.ssl.key-store=safeupload.p12 --server.ssl.key-store-password=<senha>
set -euo pipefail
name="${1:?informe o IP ou nome do servidor}"
password="${2:-safeupload}"
if [[ "$name" =~ ^[0-9.]+$ ]]; then san="ip:$name"; else san="dns:$name"; fi
rm -f safeupload.p12
keytool -genkeypair -alias safeupload -keyalg EC -groupname secp256r1 -validity 825 \
  -dname "CN=$name, O=SafeUpload" -ext "san=$san" \
  -storetype PKCS12 -keystore safeupload.p12 -storepass "$password" -keypass "$password" >/dev/null
fingerprint=$(keytool -list -v -alias safeupload -keystore safeupload.p12 -storepass "$password" \
  | sed -n 's/^\s*SHA256: //p' | tr -d ':' | tr 'A-F' 'a-f')
echo "safeupload.p12 criado para $name"
echo "SHA-256 do certificado: $fingerprint"
