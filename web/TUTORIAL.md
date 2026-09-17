# SafeUpload — Tutorial: Angular + Java (Spring Boot)

## Estrutura

```
aplicacao-web/
├── back/     → Spring Boot (Java) — API REST + banco H2
└── front/    → Angular — telas de login, cadastro e dashboard
```

O backend fala JSON puro em `http://localhost:8080/api/...`.
O frontend roda em `http://localhost:4200` e chama essa API.

---

## Pré-requisitos

- **Java 21+** — confirme com `java -version`
- **Maven** — confirme com `mvn -version` (ou use o `mvnw` se preferir não instalar)
- **Node.js 18+ e npm** — confirme com `node -v` e `npm -v`
- **Angular CLI** — instale global: `npm install -g @angular/cli@18`

---

## Passo 1 — Rodar o backend

```powershell
cd aplicacao-web\back
mvn spring-boot:run
```

Se der certo, você vê no final do log algo como:
```
Tomcat started on port 8080
Started SafeuploadApplication
```

O banco H2 é criado automaticamente na primeira execução, em `back/data/safeupload.mv.db`.

**Testar rapidamente sem o Angular ainda**, via PowerShell:
```powershell
Invoke-RestMethod -Uri http://localhost:8080/api/auth/cadastro -Method Post -ContentType "application/json" -Body '{
  "nomeCompleto": "Maria da Silva",
  "username": "maria.silva",
  "email": "maria@exemplo.com",
  "cpf": "52998224725",
  "senha": "12345678",
  "confirmarSenha": "12345678"
}'
```
Se voltar um JSON com `idUsuario`, `email`, `role`, o cadastro funcionou.

**Ver o banco visualmente:** com o backend rodando, abra `http://localhost:8080/h2-console` no navegador.
Preencha:
- JDBC URL: `jdbc:h2:file:./data/safeupload`
- User Name: `sa`
- Password: (vazio)

Clique em "Connect" e rode `SELECT * FROM USUARIOS;`.

---

## Passo 2 — Instalar as dependências do Angular

```powershell
cd aplicacao-web\front
npm install
```

Isso lê o `package.json` que já está na pasta e baixa o Angular e tudo que ele precisa.

## Passo 3 — Rodar o frontend

Em outro terminal (deixe o backend rodando no primeiro):

```powershell
cd aplicacao-web\front
ng serve
```

Abra `http://localhost:4200` no navegador. Você deve ver a tela de login.

---

## Testando o fluxo completo

1. Acesse `http://localhost:4200/cadastro`, preencha o formulário e envie.
2. Você será redirecionado para `/login` com a mensagem de cadastro confirmado.
3. Faça login com o e-mail/senha cadastrados.
4. Você deve cair em `/dashboard`.
5. Clique em "Sair" — deve voltar para `/login`.

---

## Erros comuns

**`Failed to load resource... CORS` no console do navegador**
O backend não está rodando, ou você acessou o Angular por outra porta/host que não `localhost:4200`. Confirme a porta no terminal do `ng serve` e ajuste `CorsConfig.java` se for diferente.

**`401 Unauthorized` ao acessar `/dashboard` mesmo logado**
O cookie de sessão não está sendo enviado. Confirme que todo `HttpClient` no Angular usa `{ withCredentials: true }` (já está assim nos serviços que criei) — sem isso, o navegador não manda o cookie `JSESSIONID` de volta pro backend.

**`mvn: comando não encontrado`**
Instale o Maven, ou baixe o wrapper (`mvnw`) executando `mvn -N wrapper:wrapper` numa máquina que já tenha Maven, ou instale via `choco install maven` no Windows.

**Porta 8080 ou 4200 já em uso**
Backend: mude `server.port` em `application.properties`.
Frontend: `ng serve --port 4300` (e ajuste `environment.ts` e `CorsConfig.java` de acordo).

---

## O que ainda falta migrar

Login, cadastro e logout estão 100% funcionais e batendo no banco real (H2).
As demais telas do painel administrativo — **Painel**, **Auditoria**, **Endpoints**, **Relatórios**, **Categorias**, **Lista de exceções**, **Usuários** — ainda existem só como protótipo visual (dados fictícios) no projeto Python original. Migrar cada uma segue o mesmo padrão que fizemos aqui:

1. Criar a entidade JPA (se guardar dado novo no banco)
2. Criar o repositório Spring Data
3. Criar o método de serviço com a regra de negócio
4. Expor no controller REST
5. Criar o componente Angular que consome esse endpoint

Se quiser, posso migrar o **Painel (dashboard com indicadores)** a seguir, já que é o próximo passo natural depois do login.
