# Grafana local do SafeUpload

Este ambiente local usa Grafana para visualizar os logs do backend, Loki para armazená-los e Alloy para ler os arquivos de log. Os serviços ficam em Docker Compose; o backend continua sendo iniciado pelo Maven no host.

## Requisitos

- Docker Engine e Docker Compose plugin;
- backend iniciado na raiz do repositório para que `./logs` seja a pasta de saída;
- porta local `3000` disponível.

## Primeira execução

No terminal, a partir da raiz do repositório:

```bash
mkdir -p logs
cd grafana-lab
umask 077
printf 'GRAFANA_ADMIN_PASSWORD=%s\n' "$(openssl rand -base64 32 | tr -d '\n')" > .env
docker compose up -d
```

O arquivo `.env` contém a senha administrativa e não deve ser enviado ao git. O `.gitignore` da raiz ignora arquivos `.env`. Para recuperar a senha localmente:

```bash
sed -n 's/^GRAFANA_ADMIN_PASSWORD=//p' .env
```

Abra <http://127.0.0.1:3000>, entre com usuário `admin` e a senha guardada em `.env`. A fonte `SafeUpload Loki` é provisionada automaticamente. Em **Explore**, use o seletor de fonte `SafeUpload Loki` e a consulta inicial:

Se o volume `grafana-data` já tiver sido inicializado anteriormente, alterar `.env` não troca a senha que já está gravada no Grafana. Troque-a pela interface ou, somente se puder apagar os dados locais, recrie o volume com `docker compose down -v` antes de subir novamente.

```logql
{job="safeupload"}
```

Exemplos de filtros:

```logql
{job="safeupload"} |= "event=http.request.complete"
{job="safeupload"} |= "event=http.request.rejected"
{job="safeupload"} |= "event=api.request.rejected"
{job="safeupload"} |= "event=api.database.failure"
{job="safeupload"} |= "event=agent.auth.rejected"
{job="safeupload"} |= "event=http.request.rejected" |= "route=/politicas"
{job="safeupload"} |= "requestId=COLE_O_ID_AQUI"
```

Os eventos `http.request.rejected` mostram requisições `4xx` com rota e status; `api.request.rejected` mostra a categoria segura do erro; `api.database.failure` aponta falhas de acesso ao banco, sem incluir mensagem SQL ou valores. Para falhas ao salvar política, filtre por `route=/politicas` (criação) ou `route=/politicas/{id}` (edição), e pelo status. O backend inclui o ID de correlação na resposta HTTP no cabeçalho `X-Request-ID`; use o valor `requestId` encontrado na linha para pesquisar as demais linhas da mesma requisição.

## Iniciar o backend e verificar coleta

Em outro terminal, também a partir da raiz do repositório:

```bash
SAFEUPLOAD_LOG_DIR="$(pwd)/logs" mvn -f web/back/pom.xml spring-boot:run
```

O backend grava em `logs/safeupload.log` e no console. O Alloy lê os arquivos `logs/*.log`; o arquivo de log fica ignorado pelo git. Faça uma requisição ao backend e consulte a fonte Loki no Grafana. Confira o estado dos serviços com:

```bash
cd grafana-lab
docker compose ps
docker compose logs --tail=100 alloy loki grafana
```

## Encerrar e limpar

Para parar sem apagar os dados persistidos:

```bash
docker compose down
```

Para apagar também os volumes do Grafana/Loki (dashboards locais e logs coletados):

```bash
docker compose down -v
```

Logs ativos e rotacionados ficam limitados pelo Logback a 7 dias/200 MB; a retenção do Loki também está configurada para 7 dias. A aplicação e o Grafana estão destinados a desenvolvimento local: não publique as portas nem use essa configuração como ambiente de produção.
