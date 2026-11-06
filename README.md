# SafeUpload

Protótipo acadêmico de prevenção de vazamento acidental de dados (DLP).

O Centro de Administração usa **Java 21 / Spring Boot + Angular e MySQL**. O agente Windows usa **C#/.NET 10**; a proteção preventiva de arquivos combina unidades WinFsp, inspeção em stage e um driver gate em **C**.

## Fluxo funcional

```text
Agente C# → POST /agent/heartbeat (cadastro por token ou autenticação Ed25519) → Spring Boot → MySQL
Agente C# ← GET /agent/api/policy?ip=... ← política publicada para o host
Agente C# → POST /agent/events → recibo de auditoria → MySQL
Angular → /api/... → proxy remove /api → Spring Boot
```

- Cadastro, login, restauração de sessão e logout.
- Inventário real: heartbeat, online/offline após 90 segundos, filtros e inspeções dos últimos sete dias.
- Auditoria real: resultados, categorias, motivos de não inspeção e filtro por endpoint.
- Painel real: indicadores, sete dias em UTC, categorias bloqueadas, política ativa e seis eventos recentes.
- Cadastro de hosts em `app.hosts`; auditoria em `app.agent_audit_ingest`; cadastro administrativo no schema `acesso`. Reenvios idênticos não duplicam eventos.
- Publicação básica de categorias/ação para um host identificado por IP; o agente consulta e aplica a revisão da política.
- Identidade persistida no Windows, heartbeat assinado e cadastro explícito; o serviço não faz cadastro automático ao iniciar.
- Relatórios indica explicitamente que a exportação ainda não está disponível.

## Executar localmente

Requisitos: **Java 21**, **Maven 3.9+**, **Node 22.12+ da linha 22 ou Node 24**, npm e **MySQL 8.4** preparado para o projeto.

Antes de iniciar o backend, prepare um banco de desenvolvimento exclusivo com os DDLs, nesta ordem: [01_schema_acesso.sql](db/initdb/01_schema_acesso.sql), [02_schema_app.sql](db/initdb/02_schema_app.sql), [03_jobs.sql](db/initdb/03_jobs.sql) e [05_agent_audit_ingest.sql](db/initdb/05_agent_audit_ingest.sql). Configure um usuário com acesso aos dois schemas.

Confira `app.datasource.*` e `acesso.datasource.*` em [application.properties](web/back/src/main/resources/application.properties). O padrão aponta para MySQL local na porta 3306 e usa `ddl-auto=validate`: iniciar o Java não cria as tabelas. Uma propriedade genérica `spring.datasource.url` não substitui essas duas conexões. O ambiente Docker existente está em [db/docker-compose.yml](db/docker-compose.yml), com inicialização e credenciais de desenvolvimento em [db/docker-entrypoint.sh](db/docker-entrypoint.sh).

Na raiz do repositório, em um terminal:

```powershell
mvn -f web/back/pom.xml clean spring-boot:run
```

Em outro terminal:

```powershell
cd web/front
npm ci
npm start
```

Abra **http://localhost:4200** e siga o cadastro/login do ambiente. O [proxy de desenvolvimento](web/front/proxy.conf.json) encaminha `/api/...` para `127.0.0.1:8080`, removendo `/api`: por exemplo, `/api/painel` chega ao backend como `/painel`. Mantenha o mesmo endereço do navegador durante a sessão.

O backend escuta somente em loopback por padrão. Usuários, hosts, políticas e auditoria persistem no MySQL. Reiniciar o backend não limpa esses dados; os testes devem usar um banco separado do ambiente normal.

No agente, a URL de comunicação termina em `/agent/`. O contrato atual exige `HeartbeatProtocol=AgentApiEd25519`, provisionamento explícito e `PolicyProtocol=ConsoleByIp`, com IP correspondente ao cadastro/publicação. Preencher uma URL no instalador não provisiona identidade nem seleciona esses protocolos. `Legacy` e `AgentApi` sem assinatura ficam restritos aos ensaios históricos identificados; não há troca automática de protocolo após erro.

Consulte [cadastro e identidade Ed25519](agente/docs/AUTENTICACAO-ED25519-AGENTE5.md#contrato-implementado), [configuração da composição](agente/docs/COMPOSICAO-FINAL-20261105.md#configuração-e-provisionamento), [agente e interface Windows](agente/README.md) e [driver](driver/README.md). Os documentos preservam os SHAs e limites de seus ensaios. A composição consolidada entrou pelo [PR #100](https://github.com/pedro-canafistula/safeupload/pull/100).

O [instalador 0.1.18 e seu procedimento de manutenção](agente/installer/README.md), entregues no [PR #102](https://github.com/pedro-canafistula/safeupload/pull/102), incluem atualização/reversão manual da aplicação e remoção, preservando dados do endpoint. O modo `Drive` usa WinFsp/gate correspondentes; `FileSystemWatcher` observa após a gravação e não comprova bloqueio preventivo no kernel.

## Testes

Backend (as configurações de teste são próprias da suíte; o runtime descrito acima usa MySQL):

```powershell
mvn -f web/back/pom.xml clean test
```

Frontend:

```powershell
cd web/front
npm ci
npm run build
npx playwright install chromium
```

Para executar `npm test`, use **um backend exclusivo de testes**, com MySQL e os schemas originais vazios, na porta 8080. O exemplo abaixo pressupõe uma instância MySQL de laboratório na porta 13306, DDLs já aplicados e credenciais configuradas nas duas propriedades de datasource. Pare o backend normal antes. Na raiz do repositório:

```powershell
mvn -f web/back/pom.xml clean package
java -Duser.timezone=America/Sao_Paulo -jar web/back/target/backend-0.1.0.jar `
  "--app.datasource.url=jdbc:mysql://127.0.0.1:13306/app?serverTimezone=America/Sao_Paulo&allowPublicKeyRetrieval=true&useSSL=false" `
  "--acesso.datasource.url=jdbc:mysql://127.0.0.1:13306/acesso?serverTimezone=America/Sao_Paulo&allowPublicKeyRetrieval=true&useSSL=false"
```

Em outro terminal, dentro de `web/front`, execute `npm test`. O Playwright inicia e encerra seu próprio Angular na porta 4200. A suíte cadastra dados sintéticos; prepare novamente apenas o banco descartável antes de repetir. Reiniciar o Java não esvazia o MySQL. Os parâmetros sem TLS acima são exclusivos do laboratório em loopback; não são configuração de produção.

O workflow [functional-web.yml](.github/workflows/functional-web.yml) contém a receita validada de preparação do MySQL, DDLs, fuso, parâmetros das conexões, testes Java e testes de navegador em PRs para `main`.

### Contrato com o agente C# (Windows)

Com SDK .NET 10, execute a suíte existente:

```powershell
dotnet test agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj
dotnet test agente/SafeUpload.Agent.App.Tests/SafeUpload.Agent.App.Tests.csproj
dotnet build agente/SafeUpload.Agent.ContractSmoke/SafeUpload.Agent.ContractSmoke.csproj -c Release
```

Depois de empacotar o backend e compilar ContractSmoke, o roteiro atual usa PowerShell 7 e uma distribuição portátil MySQL 8.4:

```powershell
./agente/scripts/Test-FunctionalAudit.ps1 -MySqlBasePath C:\Ferramentas\mysql
```

O roteiro cria diretório/banco exclusivos em loopback e controla seus próprios processos; não instala serviço ou driver. [Test-Ed25519Backend.ps1](agente/scripts/Test-Ed25519Backend.ps1) exercita cadastro, assinatura e recuperação com parâmetros explícitos. Consulte [o workflow desse contrato](.github/workflows/agent-host-identity-backend.yml) para a compilação e os argumentos usados na CI. Fixtures legados exigem opção específica e não representam o contrato vigente.

## Limites desta entrega

- A assinatura do heartbeat não autentica automaticamente política e auditoria. Replay, revogação/rotação e o ciclo completo do dispositivo continuam em fechamento conjunto. O protótipo não está qualificado para exposição pública.
- `/painel`, `/auditoria`, `/endpoints`, `/admin/**`, `/auth/normalregister/**` e a publicação em `/politicas` exigem sessão ADMIN ou ROOT: sem sessão, 401; perfil sem permissão, 403. O primeiro cadastro mantém o fluxo público `/auth/firstregister`, com a restrição existente de ainda não haver usuários. A autenticação de dispositivo permanece separada da sessão administrativa.
- O publicador por IP não é uma gestão completa de políticas, escopos e canais. Configurações e exportação de relatórios ainda têm funções pendentes.
- Justificativas dependem da autorização da política e do canal; fila e recibo de auditoria não representam liberação automática.
- Retenção, orçamento de disco e operação prolongada continuam pendentes; diagnóstico da fila não implementa limpeza automática.
- O runtime usa MySQL e valida o schema existente. Migrations e operação de produção ainda precisam de fechamento próprio.
- Clipboard e Web/TLS têm cobertura e configuração próprias; sua presença no código não comprova aceite integrado de todos os canais.
- O pacote é de desenvolvimento, sem assinatura da equipe. Windows 11, condições de execução do driver e qualificação de distribuição continuam com seus aceites próprios.
- Atualização das telas é manual, pelo botão Atualizar.
- Os arquivos em `tests/`, `requirements.txt` e documentos antigos de frontend registram a versão FastAPI/Jinja. Não são a suíte de execução desta arquitetura. Os critérios portados estão em `web/back/src/test` e `web/front/e2e`.
- O histórico já rastreia dependências e artefatos gerados (`node_modules`, `target`, alguns arquivos de build). Esta entrega não faz sua remoção em massa; alterações locais nesses arquivos não devem ser incluídas em commits de código.

Veja [o registro histórico da migração com H2](docs/migracao-funcional.md) e o acompanhamento atual: [macro #43](https://github.com/pedro-canafistula/safeupload/issues/43), [distribuição #45](https://github.com/pedro-canafistula/safeupload/issues/45), [integração dos canais #46](https://github.com/pedro-canafistula/safeupload/issues/46), [autenticação #47](https://github.com/pedro-canafistula/safeupload/issues/47) e [retenção/operação #48](https://github.com/pedro-canafistula/safeupload/issues/48).

## Equipe

**Grupo Prevenção de vazamento de dados — UCB, 2026**

- Victor Nogueira da Nova Bonato
- Pedro Campos Canafístula
- Luiz Henrique Alves Rodrigues
- Lucas Ferreira Coelho
