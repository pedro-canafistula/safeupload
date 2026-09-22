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

printf '%s' "$MYSQL_SENHA_ROOT" > secrets/MYSQL_SENHA_ROOT.txt

echo "Executando Docker a partir do docker-compose..."

docker compose up -d

: > secrets/MYSQL_SENHA_ROOT.txt

echo "Instalação finalizada com sucesso."