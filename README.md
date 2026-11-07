# SafeUpload

Protótipo acadêmico de prevenção de vazamento acidental de dados (DLP). Um agente Windows inspeciona o que o usuário
grava em pastas protegidas, pendrives e compartilhamentos e bloqueia versões com dados sensíveis (CPF, CNPJ, cartão,
senhas, segredos e outras categorias); um console web define as políticas e recebe a auditoria.

## Componentes

| Pasta | O que é |
|---|---|
| `web/back` | Console: API Spring Boot (Java 21) com MySQL 8.4 |
| `web/front` | Console: interface Angular |
| `agente/` | Agente Windows em .NET 10: serviço, unidade SafeUpload (WinFsp), bandeja WPF, clipboard e inspeção TLS ([README](agente/README.md)) |
| `driver/` | Minifiltro gate em C que recusa gravações diretas nos lugares protegidos ([README](driver/README.md)) |
| `smoke/` | Teste ponta a ponta do agente com o driver numa VM descartável |
| `lab/` | Receitas Packer/Ansible/Terraform da VM de teste Windows 10 ([README](lab/README.md)) |
| `db/` | DDLs (`db/initdb`) e o MySQL em Docker |
| `docs/` | [Contrato console ↔ agente](docs/console-agente.md) e desenhos do [clipboard](docs/clipboard/README.md) e da [inspeção TLS](docs/rede/ARQUITETURA-INSPECAO-TLS.md) |

## Executar o console localmente

Requisitos: Java 21, Maven 3.9+, Node 22.12+ (ou 24) com npm, e MySQL 8.4.

**Banco.** O caminho mais simples é o Docker. A senha de root não fica no git: crie-a localmente (a pasta
`db/secrets` ignora tudo menos o próprio `.gitignore`) e suba o container:

```bash
openssl rand -base64 24 > db/secrets/MYSQL_SENHA_ROOT.txt
cd db && docker compose up -d
```

Na primeira inicialização o container aplica os DDLs de `db/initdb` em ordem numérica e cria o usuário da
aplicação. Num MySQL próprio, aplique os mesmos DDLs em ordem numérica e crie um usuário com acesso aos schemas
`acesso` e `app`.
As conexões ficam em `app.datasource.*` e `acesso.datasource.*` de
[application.properties](web/back/src/main/resources/application.properties) (padrão: MySQL local na 3306). O
backend usa `ddl-auto=validate`: ele não cria tabelas.

**Backend**, na raiz do repositório:

```bash
mvn -f web/back/pom.xml spring-boot:run
```

**Frontend**, em outro terminal:

```bash
cd web/front
npm ci
npm start
```

Abra http://localhost:4200 e faça o primeiro cadastro. O [proxy de desenvolvimento](web/front/proxy.conf.json)
encaminha `/api/...` para `127.0.0.1:8080` sem o prefixo `/api` (`/api/painel` chega como `/painel`). O backend
escuta só em loopback; para receber agentes de outra máquina, suba-o com `SAFEUPLOAD_BIND_ADDRESS=0.0.0.0` e HTTPS.

## Conectar um agente

No console, gere um token em **Configurações → Tokens de cadastro**. Na máquina, como administrador:

```powershell
SafeUpload.Agent.Service.exe cadastrar https://servidor:8443/agent/ <token> --certificado <sha256>
```

Identidade, assinatura das requisições, política e eventos estão em [docs/console-agente.md](docs/console-agente.md),
incluindo como gerar o certificado HTTPS do laboratório. Instalação do agente: [agente/README.md](agente/README.md).

## Testes

```bash
# Backend: testes de unidade e de segurança
mvn -f web/back/pom.xml test
# Fluxo completo console ↔ agente: só com um MySQL descartável, porque o teste APAGA os bancos app e acesso
SAFEUPLOAD_TEST_MYSQL_URL=jdbc:mysql://127.0.0.1:13306 mvn -f web/back/pom.xml test   # opcional: SAFEUPLOAD_TEST_MYSQL_USER/PASSWORD

# Frontend: build e testes Playwright
cd web/front
npm ci
npm run build
npx playwright install chromium
npm test
```

O `npm test` precisa de um backend de testes na porta 8080 apontando para um MySQL descartável com os schemas vazios
(o Playwright sobe o próprio Angular na 4200 e cadastra dados sintéticos; recrie o banco antes de repetir). A receita
completa, com MySQL, DDLs e parâmetros, está no workflow [functional-web.yml](.github/workflows/functional-web.yml).

```bash
# Agente (no Linux só compila; os testes rodam no Windows)
dotnet build agente/SafeUpload.Agent.sln -p:EnableWindowsTargeting=true
dotnet test agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj
```

O teste ponta a ponta com driver e Office é `smoke/run.sh` (ver [driver/README.md](driver/README.md)).

## Limites

- Protótipo acadêmico: não exponha o console à internet.
- O driver é assinado com certificado de teste; a máquina precisa de test signing ligado.
- Só Windows 10 x64 é suportado.
- Não há migrations: quando o schema muda, recrie o banco de desenvolvimento (no Docker, `docker compose down -v` e
  suba de novo).
- A exportação de relatórios é só CSV da auditoria (últimos 7 dias).
- Clipboard e inspeção TLS existem no agente, mas vêm desligados por padrão.

## Equipe

**Grupo Prevenção de vazamento de dados — UCB, 2026**

- Victor Nogueira da Nova Bonato
- Pedro Campos Canafístula
- Luiz Henrique Alves Rodrigues
- Lucas Ferreira Coelho
