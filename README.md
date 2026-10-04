# SafeUpload

Protótipo acadêmico de prevenção de vazamento acidental de dados (DLP).

O Centro de Administração usa **Java 21 / Spring Boot + Angular**. O agente Windows continua em **C#/.NET 10**, com driver minifilter em **C** opcional.

## Fluxo funcional

```text
Agente C# → POST /agent/heartbeat e /agent/events → Spring Boot → H2
Agente C# ← GET /agent/policy
Angular → /api/painel, /api/auditoria, /api/endpoints → Spring Boot → H2
```

- Cadastro, login, restauração de sessão e logout.
- Inventário real: heartbeat, online/offline após 90 segundos, filtros e inspeções dos últimos sete dias.
- Auditoria real: resultados, categorias, motivos de não inspeção e filtro por endpoint.
- Painel real: indicadores, sete dias em UTC, categorias bloqueadas, política ativa e seis eventos recentes.
- Endpoints, eventos e overrides persistem no banco H2. Reenvios idênticos não duplicam eventos.
- Relatórios indica explicitamente que a exportação ainda não está disponível.

## Executar localmente

Requisitos: **Java 21**, **Maven 3.9+**, **Node 22.12+ da linha 22 ou Node 24**, npm.

Na raiz do repositório, em um terminal:

```powershell
mvn -f web/back/pom.xml spring-boot:run
```

Em outro terminal:

```powershell
cd web/front
npm ci
npm start
```

Abra **http://localhost:4200**, crie uma conta de teste e faça login. O Angular usa URLs relativas `/api`; o proxy de desenvolvimento encaminha para `127.0.0.1:8080`. Também é possível usar `http://127.0.0.1:4200`, mantendo o mesmo endereço durante a sessão.

O backend escuta somente em loopback por padrão. O banco é `./data/safeupload`, relativo ao diretório de execução do backend; ao usar o Maven acima, fica em `web/back/data`. Não apague esse diretório para reiniciar. Usuários e registros de acesso também persistem. Não é necessário iniciar o MySQL de `db/` para este fluxo.

No agente, `CentroAdministracao:BaseUrl` está configurada como `http://127.0.0.1:8080/agent/`. A barra final e o prefixo `/agent/` fazem parte da integração. Consulte [agente/README.md](agente/README.md) para execução do serviço, inspeção e interface WPF; [driver/ARQUITETURA.md](driver/ARQUITETURA.md) para o driver.

## Testes

Backend (inclui teste de fechamento/reabertura da aplicação com H2 em arquivo temporário):

```powershell
mvn -f web/back/pom.xml test
```

Frontend:

```powershell
cd web/front
npm ci
npm run build
npx playwright install chromium
```

Para executar `npm test`, use **um backend exclusivo de testes**, com banco vazio, na porta 8080. Pare o backend normal antes. Na raiz do repositório:

```powershell
mvn -f web/back/pom.xml package
java -jar web/back/target/backend-0.1.0.jar "--spring.datasource.url=jdbc:h2:mem:e2e" "--spring.jpa.hibernate.ddl-auto=create-drop"
```

Em outro terminal, dentro de `web/front`, execute `npm test`. O Playwright inicia e encerra seu próprio Angular na porta 4200. A suíte usa cadastro e dados sintéticos reais, testa atualização de sessão, reenvio, filtros, erro HTTP e escape de HTML. Reinicie o backend de testes antes de repetir a suíte para começar com banco vazio. Os testes não devem apontar para o banco de uso normal.

O workflow [functional-web.yml](.github/workflows/functional-web.yml) executa os testes Java, build Angular e testes de navegador em PRs para `main`.

## Limites desta entrega

- A API do agente mantém o contrato anterior **sem autenticação de dispositivo**. Use localmente; não exponha esse protótipo diretamente à internet. A variável `SAFEUPLOAD_BIND_ADDRESS` permite mudar o bind quando houver infraestrutura de autenticação/rede apropriada.
- As consultas administrativas exigem sessão de um usuário ativo; autorização granular por papel ainda não foi implementada.
- A política é global, fixa e compatível com o contrato anterior. Edição/versionamento de políticas, gestão administrativa de usuários, exceções e exportação de relatórios são próximas entregas.
- O agente ainda envia overrides vazios. O backend aceita e persiste o contrato, mas não implementa um fluxo novo de justificativa.
- Consultas carregam os eventos persistidos em memória para agregação. Paginação, retenção e agregações no banco devem anteceder uso em escala.
- H2 e atualização automática de schema atendem ao protótipo. MySQL e migrations de produção não fazem parte desta migração.
- Atualização das telas é manual, pelo botão Atualizar.
- Os arquivos em `tests/`, `requirements.txt` e documentos antigos de frontend registram a versão FastAPI/Jinja. Não são a suíte de execução desta arquitetura. Os critérios portados estão em `web/back/src/test` e `web/front/e2e`.
- O histórico já rastreia dependências e artefatos gerados (`node_modules`, `target`, alguns arquivos de build). Esta entrega não faz sua remoção em massa; alterações locais nesses arquivos não devem ser incluídas em commits de código.

Veja [o contrato e as decisões da migração](docs/migracao-funcional.md).

## Equipe

**Grupo Prevenção de vazamento de dados — UCB, 2026**

- Victor Nogueira da Nova Bonato
- Pedro Campos Canafístula
- Luiz Henrique Alves Rodrigues
- Lucas Ferreira Coelho
