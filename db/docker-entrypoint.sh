#!/bin/bash
set -e

MYSQL_CONFIG="${MYSQL_CONFIG}"
echo "$(date '+%d-%m-%Y %H:%M:%S') my.cnf: $MYSQL_CONFIG"

SQLDIR="/app/initdb"

DATADIR=$(sed -nE \
    's/^[[:space:]]*datadir[[:space:]]*=[[:space:]]*([^[:space:]#;]+).*$/\1/p' \
    $MYSQL_CONFIG)

echo "$(date '+%d-%m-%Y %H:%M:%S') Datadir: $DATADIR"

INDICADOR="${DATADIR%/}/.indicador"

SOCKET=$(grep -E '^[[:space:]]*socket[[:space:]]*=' $MYSQL_CONFIG |
         sed -E 's/^[[:space:]]*socket[[:space:]]*=[[:space:]]*([^[:space:]#;]+).*$/\1/')

echo "$(date '+%d-%m-%Y %H:%M:%S') Socket: $SOCKET"

if [[ ! -f /run/secrets/mysql_senha_root ]]; then
    echo "ERRO: Secret de senha do root não encontrado."
    exit 1
fi

MYSQL_SENHA_ROOT="$(head -n 1 /run/secrets/mysql_senha_root)"
MYSQL_SENHA_ROOT=$(printf '%s' "$MYSQL_SENHA_ROOT" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

mkdir -p /var/run/mysqld
chown -R mysql:mysql /var/run/mysqld
chown -R mysql:mysql "$DATADIR"

if [[ ! -f "$INDICADOR" ]]; then
    rm -rf "${DATADIR%/}"/*
    mysqld --defaults-file="$MYSQL_CONFIG" --initialize-insecure --user=mysql
    cat > "$INDICADOR" << EOF
## A instância do banco de dados será reiniciada caso este arquivo seja apagado.
## Os dados serão perdidos ao reiniciar o container.
EOF
    PRIMEIRA_INICIALIZACAO=true
    echo "$(date '+%d-%m-%Y %H:%M:%S') Primeira Inicialização = TRUE"
    echo "$(date '+%d-%m-%Y %H:%M:%S') Arquivo indicador criado."
else
    PRIMEIRA_INICIALIZACAO=false
    echo "$(date '+%d-%m-%Y %H:%M:%S') Primeira Inicialização = FALSE"
fi

if [[ -z "$MYSQL_SENHA_ROOT" && "$PRIMEIRA_INICIALIZACAO" = true ]]; then
    echo "$(date '+%d-%m-%Y %H:%M:%S') ERRO: É necessário definir MYSQL_SENHA_ROOT para inicializar o container."
    exit 1
fi

if [[ "$PRIMEIRA_INICIALIZACAO" = true ]]; then
    mysqld --defaults-file="$MYSQL_CONFIG" --user=mysql --skip-networking --socket="$SOCKET" &

    MYSQL_PID=$!
    echo "$(date '+%d-%m-%Y %H:%M:%S') Socket temporária iniciada."
    echo "$(date '+%d-%m-%Y %H:%M:%S') PID: $MYSQL_PID"

    for i in {1..60}; do
        if mysqladmin --protocol=socket --socket="$SOCKET" -u root ping --silent 2>/dev/null; then
            break
        fi
        sleep 1
    done

    if ! mysqladmin --protocol=socket --socket="$SOCKET" -u root ping --silent 2>/dev/null; then
        kill "$MYSQL_PID" 2>/dev/null || true
        echo "$(date '+%d-%m-%Y %H:%M:%S') ERRO: Falha ao conectar na instância temporária."
        exit 1
    else
        echo "$(date '+%d-%m-%Y %H:%M:%S') Conexão temporária realizada com êxito."
    fi
        mysql --protocol=socket --socket="$SOCKET" -u root <<SQL
ALTER USER 'root'@'localhost'
IDENTIFIED BY '${MYSQL_SENHA_ROOT}';
SQL

    if [[ $? -ne 0 ]];then
        echo "$(date '+%d-%m-%Y %H:%M:%S') ERRO: Falha ao definir senha do usuário ROOT."
        exit 1
    else
        echo "$(date '+%d-%m-%Y %H:%M:%S') Senha do ROOT definida com sucesso para a instância do banco de dados."
    fi

    cd "$SQLDIR"
    if compgen -G "$SQLDIR/*.sql" > /dev/null && [[ "$PRIMEIRA_INICIALIZACAO" == true ]]; then
        for arquivo in "$SQLDIR"/*.sql; do
            echo "$(date '+%d-%m-%Y %H:%M:%S') Executando ${arquivo##*/}..."
            MYSQL_PWD="$MYSQL_SENHA_ROOT" mysql --protocol=socket --socket="$SOCKET" -u root < "$arquivo"
            echo "$(date '+%d-%m-%Y %H:%M:%S') ${arquivo##*/} executado com sucesso no banco de dados."
        done
    fi

    echo "$(date '+%d-%m-%Y %H:%M:%S') Finalizando instância temporária..."
    MYSQL_PWD="$MYSQL_SENHA_ROOT" mysqladmin --protocol=socket --socket="$SOCKET" -u root shutdown
    wait "$MYSQL_PID" || true
    echo "$(date '+%d-%m-%Y %H:%M:%S') Instância temporária finalizada."
fi

echo "$(date '+%d-%m-%Y %H:%M:%S') Iniciando instância MySQL..."
echo "$(date '+%d-%m-%Y %H:%M:%S') A instância MySQL está aceitando conexões TCP/IP."

exec mysqld --defaults-file="$MYSQL_CONFIG" --user=mysql --console