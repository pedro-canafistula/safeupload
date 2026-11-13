# Executar a console SafeUpload localmente

Este guia inicia o banco MySQL, o backend Spring Boot, o frontend Angular e a coleta/visualização de logs com Grafana, Loki e Alloy. Execute os comandos a partir da raiz do repositório, exceto quando indicado. Mantenha cada serviço em um terminal separado.

## Requisitos

- Docker com o plugin Docker Compose;
- Java 21 e Maven;
- Node.js e npm compatíveis com Angular 20.

## 1. Iniciar o banco MySQL

O backend usa os schemas `acesso` e `app` no MySQL local, porta `3306`. Em um terminal, na raiz do repositório:

```bash
cd db
bash install.sh
```

O script pede e confirma uma senha para o usuário `root`, cria o secret local necessário e inicia o serviço Docker. Na primeira inicialização, também cria os schemas e o usuário `ms_safeupload`, cuja senha de aplicação está configurada como `admin123` no backend. O arquivo com a senha root fica em `db/secrets/` e não deve ser versionado.

Confira o estado do serviço:

```bash
docker compose ps
```

Se o backend apresentar `Communications link failure` ou `Connection refused`, confira se o contêiner do banco está rodando e se a porta `3306` está disponível. A definição do banco está em [`db/docker-compose.yml`](../db/docker-compose.yml) e as credenciais/URLs do backend em [`back/src/main/resources/application.properties`](back/src/main/resources/application.properties).

## 2. Preparar e iniciar os logs no Grafana

Abra outro terminal na raiz do repositório. A pasta `logs` deve ficar na raiz: o backend grava nela e o Alloy lê esses arquivos.

```bash
mkdir -p logs
cd grafana-lab
umask 077
if [ ! -f .env ]; then
  printf 'GRAFANA_ADMIN_PASSWORD=%s\n' "$(openssl rand -base64 32 | tr -d '\n')" > .env
fi
docker compose up -d
docker compose ps
```

Guarde a senha gerada em `grafana-lab/.env`; não a envie ao Git. Se o arquivo já existir, o comando preserva a senha atual. O Grafana fica em <http://127.0.0.1:3000>, usuário `admin`. A fonte de dados Loki é provisionada como `SafeUpload Loki`.

Se o Loki não iniciar com erro de montagem, confira `docker compose ps`, `docker compose config` e `ls -l loki-config/config.yaml` dentro de `grafana-lab`. O Loki monta a pasta `loki-config` inteira, em vez de montar o arquivo diretamente. Se o arquivo existir e o caminho resolvido estiver correto, reinicie o Docker Desktop/WSL e tente novamente.

Após iniciar o backend, consulte no Grafana **Explore**, selecione `SafeUpload Loki` e execute:

```logql
{job="safeupload"}
```

Os serviços e suas configurações estão em [`grafana-lab/docker-compose.yaml`](../grafana-lab/docker-compose.yaml); o guia de consultas e encerramento também está em [`grafana-lab/README.md`](../grafana-lab/README.md).

## 3. Iniciar o backend

Em outro terminal, volte à raiz do repositório. Iniciar o backend a partir dela garante que a pasta de logs corresponda ao volume lido pelo Alloy.

```bash
mkdir -p logs
SAFEUPLOAD_LOG_DIR="$(pwd)/logs" mvn -f web/back/pom.xml spring-boot:run
```

O backend fica em <http://127.0.0.1:8080>. Os logs são escritos no console e em `logs/safeupload.log`. O endereço, schemas e credenciais do banco estão em [`back/src/main/resources/application.properties`](back/src/main/resources/application.properties); o caminho do arquivo de log é configurado em [`back/src/main/resources/logback-spring.xml`](back/src/main/resources/logback-spring.xml).

## 4. Iniciar o frontend

Em outro terminal:

```bash
cd web/front
npm ci
npm start
```

`npm ci` é necessário na primeira execução ou após mudanças nas dependências. Abra <http://localhost:4200>. O servidor de desenvolvimento usa [`front/proxy.conf.json`](front/proxy.conf.json) para encaminhar chamadas `/api` ao backend em `127.0.0.1:8080`.

## Encerrar

Para parar os containers do Grafana/Loki/Alloy, execute `docker compose down` dentro de `grafana-lab`. Para parar o MySQL, execute `docker compose down` dentro de `db`. Esses comandos preservam os volumes de dados. Não use `docker compose down -v` a menos que queira apagar os dados persistidos do respectivo serviço.

Finalize o backend e o frontend com `Ctrl+C` nos terminais em que estão rodando.
