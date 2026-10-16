# SafeUpload — execução local completa

Este guia reproduz do zero a execução da aplicação web com **MySQL no Docker**, **backend Spring Boot** e **frontend Angular**.

Após concluir os passos, os serviços estarão em:

| Serviço | Endereço |
| --- | --- |
| Frontend Angular | <http://localhost:4200> |
| Backend Spring Boot | <http://127.0.0.1:8080> |
| MySQL | `127.0.0.1:3306` |

Os comandos abaixo usam Bash no Linux, macOS ou WSL. Execute-os a partir da raiz do repositório, exceto quando indicado.

## 1. Pré-requisitos

Confirme as versões instaladas:

```bash
docker compose version
java --version
mvn --version
node --version
npm --version
```

São necessários Docker com Compose v2, Java 21, Maven 3.9+, Node.js 22.12+ (ou 24+) e npm. As portas `3306`, `8080` e `4200` precisam estar disponíveis.

## 2. Como os componentes se conectam

```text
Navegador (localhost:4200)
  └── /api/* ──> proxy Angular ──> Spring Boot (127.0.0.1:8080)
                                      └── JDBC ──> MySQL Docker (127.0.0.1:3306/safeupload)
```

O backend usa o schema MySQL `safeupload` e o usuário MySQL `safeupload`. A URL e o usuário estão definidos em `back/src/main/resources/application.properties`; a senha é recebida pela variável de ambiente `SAFEUPLOAD_DB_PASSWORD`.

## 3. Instalar e iniciar o banco (uma única vez por máquina)

O script `db/install.sh` prepara tudo que a aplicação precisa no primeiro uso:

1. solicita a senha administrativa do MySQL (`root`);
2. solicita a senha do usuário da aplicação (`safeupload`);
3. cria o container `safeupload-db`;
4. cria o schema `safeupload`;
5. cria `safeupload@'%'` e concede permissão no schema;
6. executa os scripts adicionais em `db/initdb`.

Execute:

```bash
cd db
chmod +x install.sh
./install.sh
```

Use senhas fortes e guarde a senha de aplicação. Para um teste local simples, você pode digitar `1234` nas quatro solicitações, usando a mesma senha para `root` e `safeupload`.

**Espere o script terminar com as mensagens abaixo antes de continuar:**

```text
Senha temporária removida do arquivo de secret.
Instalação finalizada com sucesso.
```

O script aguarda o MySQL concluir a criação do banco e do usuário; não interrompa essa etapa. Confirme o estado do serviço:

```bash
docker compose ps
docker compose exec mysql mysql -u root -p -e 'SELECT 1;'
```

Ao segundo comando, digite a senha de `root`. O resultado esperado contém o valor `1`.

> O container MySQL e o schema `safeupload` são coisas distintas. O container fornece o servidor; o schema é o banco lógico que o Spring acessa. O script de instalação cria ambos automaticamente.

### Próximos inícios do banco

Depois da instalação inicial, não execute `install.sh` novamente. Para iniciar o banco preservando os dados:

```bash
cd db
docker compose up -d
```

Para pará-lo sem apagar dados:

```bash
cd db
docker compose down
```

## 4. Iniciar o backend

Abra outro terminal na raiz do repositório. Substitua `SENHA_DA_APLICACAO` pela senha informada para o usuário `safeupload` na instalação — se você usou o exemplo simples, ela é `1234`.

```bash
cd web/back
export SAFEUPLOAD_DB_PASSWORD='SENHA_DA_APLICACAO'
mvn spring-boot:run
```

O backend configura as tabelas JPA automaticamente em uma instalação vazia e deve concluir com:

```text
Tomcat started on port 8080
Started SafeuploadApplication
```

Mantenha esse terminal em execução. Não use a senha de `root` aqui, salvo se você deliberadamente tiver escolhido a mesma senha para os dois usuários.

## 5. Iniciar o frontend

Abra um terceiro terminal e execute:

```bash
cd web/front
npm ci
npm start
```

Abra <http://localhost:4200>. Crie um usuário pela tela de cadastro e faça login. O Angular encaminha chamadas iniciadas por `/api` ao backend pela configuração em `front/proxy.conf.json`.

## 6. Verificações rápidas

Com todos os serviços ativos:

```bash
# Banco e container
cd db && docker compose ps

# Backend: 401 antes do login é esperado e confirma que a API respondeu
curl -i http://127.0.0.1:8080/api/auth/sessao

# Frontend
curl -I http://localhost:4200
```

## 7. Recomeçar completamente do zero

> **Atenção:** este procedimento apaga o volume Docker, todos os schemas, tabelas e dados locais do MySQL.

```bash
cd db
docker compose down -v
./install.sh
```

Após o script concluir, repita apenas as seções **4** e **5**. Não é necessário criar manualmente databases, usuários, permissões ou tabelas.

## 8. Solução de problemas

### `Connection refused`

O backend não encontrou um MySQL aceitando conexões em `127.0.0.1:3306`. Inicie o banco e veja os logs:

```bash
cd db
docker compose up -d
docker compose ps
docker compose logs --tail=100 mysql
```

### `Host '172.21.0.1' is not allowed to connect`

A instalação foi criada com uma versão antiga do script, que não criou a conta `safeupload@'%'`. Para corrigir **sem apagar dados**, entre com `root` e recrie a conta:

```bash
cd db
docker compose exec mysql mysql -u root -p
```

No prompt `mysql>`, substitua `SENHA_DA_APLICACAO` pela senha desejada e execute:

```sql
CREATE USER IF NOT EXISTS 'safeupload'@'%'
  IDENTIFIED BY 'SENHA_DA_APLICACAO';
ALTER USER 'safeupload'@'%'
  IDENTIFIED BY 'SENHA_DA_APLICACAO';
GRANT ALL PRIVILEGES ON safeupload.* TO 'safeupload'@'%';
FLUSH PRIVILEGES;
EXIT;
```

Depois, use a mesma senha em `SAFEUPLOAD_DB_PASSWORD` ao iniciar o backend.

### `Unknown database 'safeupload'`

A instalação foi criada sem o schema que o backend usa. Para corrigir **sem apagar dados**, entre no MySQL como `root` e execute:

```sql
CREATE DATABASE IF NOT EXISTS safeupload
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_0900_ai_ci;
GRANT ALL PRIVILEGES ON safeupload.* TO 'safeupload'@'%';
FLUSH PRIVILEGES;
EXIT;
```

Reinicie o backend. As tabelas serão criadas automaticamente por Hibernate na primeira execução.

### `Access denied for user 'safeupload'`

O servidor e o schema foram encontrados, mas a senha exportada não corresponde à da conta MySQL. Exporte a senha da aplicação correta antes de executar Maven:

```bash
export SAFEUPLOAD_DB_PASSWORD='SENHA_DA_APLICACAO'
```

Não confunda essa senha com a de `root`.

### O container encerra mostrando `É necessário definir as senhas`

O volume foi inicializado parcialmente. Em ambiente local, execute a seção **7** para apagar o volume e instalar novamente. Não execute `docker compose up` com os arquivos de senha vazios na primeira inicialização.

### Porta ocupada

- MySQL: libere `3306` ou altere o mapeamento no `db/docker-compose.yml` e a variável `SAFEUPLOAD_DB_URL`.
- Backend: execute `mvn -Dspring-boot.run.arguments='--server.port=8081' spring-boot:run` e atualize `front/proxy.conf.json`.
- Frontend: execute `npm start -- --port 4201`.

## 9. Testes e encerramento

Testes do backend:

```bash
mvn -f web/back/pom.xml clean test
```

Build do frontend:

```bash
cd web/front
npm run build
```

Para encerrar a execução local, pressione `Ctrl+C` nos terminais do Angular e Spring Boot. Em seguida, para parar o MySQL preservando os dados:

```bash
cd db
docker compose down
```
