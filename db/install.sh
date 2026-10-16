#!/bin/bash

set -e

echo "##################################################"
echo "## INSTALAR INSTÂNCIA MYSQL EM CONTAINER DOCKER ##"
echo "##################################################"

sleep 1

echo
read -rsp "Digite a senha do root: " MYSQL_SENHA_ROOT
echo 

MYSQL_SENHA_ROOT=$(printf '%s' "$MYSQL_SENHA_ROOT" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

while [[ -z "$MYSQL_SENHA_ROOT" ]]; do
    read -rsp "A senha não pode ser vazia. Digite novamente: " MYSQL_SENHA_ROOT
    echo 

    MYSQL_SENHA_ROOT=$(printf '%s' "$MYSQL_SENHA_ROOT" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
done

read -rsp "Confirme a senha: " MYSQL_SENHA_ROOT_CONF
echo 

MYSQL_SENHA_ROOT_CONF=$(printf '%s' "$MYSQL_SENHA_ROOT_CONF" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

if [[ "$MYSQL_SENHA_ROOT" != "$MYSQL_SENHA_ROOT_CONF" ]]; then
    echo "ERRO: As senhas não coincidem."
    exit 1
fi

echo
read -rsp "Digite a senha do usuário da aplicação (safeupload): " MYSQL_SENHA_APP
echo

MYSQL_SENHA_APP=$(printf '%s' "$MYSQL_SENHA_APP" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

while [[ -z "$MYSQL_SENHA_APP" ]]; do
    read -rsp "A senha não pode ser vazia. Digite novamente: " MYSQL_SENHA_APP
    echo

    MYSQL_SENHA_APP=$(printf '%s' "$MYSQL_SENHA_APP" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
done

read -rsp "Confirme a senha do usuário da aplicação: " MYSQL_SENHA_APP_CONF
echo

MYSQL_SENHA_APP_CONF=$(printf '%s' "$MYSQL_SENHA_APP_CONF" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

if [[ "$MYSQL_SENHA_APP" != "$MYSQL_SENHA_APP_CONF" ]]; then
    echo "ERRO: As senhas do usuário da aplicação não coincidem."
    exit 1
fi

printf '%s' "$MYSQL_SENHA_ROOT" > secrets/MYSQL_SENHA_ROOT.txt
printf '%s' "$MYSQL_SENHA_APP" > secrets/MYSQL_SENHA_APP.txt

echo "Executando Docker a partir do docker-compose..."

docker compose up -d

echo "Aguardando o MySQL consumir a senha de inicialização..."

# O secret do Compose é montado a partir deste arquivo. Não o limpe logo após
# `up -d`: o container pode ainda não ter iniciado e leria uma senha vazia.
for i in {1..90}; do
    if docker compose logs mysql 2>&1 | grep -q "Banco e usuário da aplicação configurados com sucesso"; then
        : > secrets/MYSQL_SENHA_ROOT.txt
        : > secrets/MYSQL_SENHA_APP.txt
        echo "Senha temporária removida do arquivo de secret."
        echo "Instalação finalizada com sucesso."
        exit 0
    fi

    if ! docker compose ps --status running --services 2>/dev/null | grep -qx "mysql"; then
        echo "ERRO: O container MySQL parou durante a inicialização."
        echo "A senha temporária foi mantida para permitir diagnóstico."
        echo "Consulte: docker compose logs mysql"
        exit 1
    fi

    sleep 1
done

echo "ERRO: O MySQL não confirmou a inicialização em 90 segundos."
echo "A senha temporária foi mantida para permitir diagnóstico."
echo "Consulte: docker compose logs mysql"
exit 1
