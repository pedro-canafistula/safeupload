#!/bin/bash
set -e

MYSQL_CONFIG="${MYSQL_CONFIG}"
MYSQL_SENHA_ROOT="$(head -n 1 /run/secrets/mysql_senha_root)"
SQLDIR="/app/initdb"

DATADIR="$(
    mysqld --defaults-file="$MYSQL_CONFIG" --verbose --help 2>/dev/null |
    awk '$1 == "datadir" {
    for (i = 2; i <= NF; i++) {
        if ($i != "=") {
            gsub(/^=/, "", $i)
            print $i
            exit
        }
    }
}'
)"

SOCKET="$(
    mysqld --defaults-file="$MYSQL_CONFIG" --verbose --help 2>/dev/null |
    awk '$1 == "socket" {
    for (i = 2; i <= NF; i++) {
        if ($i != "=") {
            gsub(/^=/, "", $i)
            print $i
            exit
        }
    }
}'
)"

if [[ ! -f /run/secrets/mysql_senha_root ]]; then
    echo "ERRO: Secret de senha do root não encontrado."
    exit 1
fi

mkdir -p /var/run/mysqld
chown -R mysql:mysql /var/run/mysqld
chown -R mysql:mysql "$DATADIR"

if [[ ! -d "$DATADIR/mysql" ]]; then
    mysqld --defaults-file="$MYSQL_CONFIG" --initialize-insecure --user=mysql 
    PRIMEIRA_INICIALIZACAO=true
else
    PRIMEIRA_INICIALIZACAO=false
fi

if [[ -z "$MYSQL_SENHA_ROOT" && "$PRIMEIRA_INICIALIZACAO" = true ]]; then
    echo "ERRO: É necessário definir MYSQL_SENHA_ROOT para inicializar o container."
    exit 1
fi

mysqld --defaults-file="$MYSQL_CONFIG" --user=mysql --skip-networking --socket="$SOCKET" &

MYSQL_PID=$!

for i in {1..60}; do
    if mysqladmin --protocol=socket --socket="$SOCKET" -u root ping --silent 2>/dev/null; then
        break
    fi
    sleep 1
done

if ! mysqladmin --protocol=socket --socket="$SOCKET" -u root ping --silent 2>/dev/null; then
    kill "$MYSQL_PID" 2>/dev/null || true
    echo "Falha ao conectar na instância temporária."
    exit 1
fi

if [[ "$PRIMEIRA_INICIALIZACAO" == true ]]; then
    mysql --protocol=socket --socket="$SOCKET" -u root <<SQL
ALTER USER 'root'@'localhost'
IDENTIFIED BY '${MYSQL_SENHA_ROOT}';
SQL
fi

cd "$SQLDIR"
if compgen -G "$SQLDIR/*.sql" > /dev/null && [[ "$PRIMEIRA_INICIALIZACAO" == true ]]; then
    for arquivo in "$SQLDIR"/*.sql; do
        mysql --protocol=socket --socket="$SOCKET" -u root -p"$MYSQL_SENHA_ROOT" < "$arquivo"
    done
fi

mysqladmin --protocol=socket --socket="$SOCKET" -u root -p"$MYSQL_SENHA_ROOT" shutdown
wait "$MYSQL_PID" || true

exec mysqld --defaults-file="$MYSQL_CONFIG" --user=mysql --console