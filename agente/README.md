# SafeUpload — Agente Desktop

Veja [Integrações do agente na M2](docs/INTEGRACAO-M2.md) para escopo da entrega,
fluxo Git, validação e dependências com backend, painel e driver.

Componente instalado no endpoint do usuário: intercepta operações de
arquivo, decide localmente (CPF, CNPJ, cartão, senha, segredos), e — quando
configurado — sincroniza política e auditoria com o Centro de
Administração web.

---

## Visão geral

O instalador encaminha os mesmos argumentos de configuração ao seed da política
de boot e ao serviço. Com os argumentos padrão, `AdminBaseUrl` vazio seleciona
explicitamente a política local; uma URL informada seleciona a origem remota em
ambas as fases. `ServiceArguments` personalizados substituem o conjunto padrão
inteiro e são usados nas duas fases; se omitirem a origem, ambas herdam sua
configuração. O seed continua exigindo SYSTEM e não inicia o host ou interceptores.
A configuração compartilhada não congela a revisão remota entre as fases.
A instalação e o autostart da bandeja da M2 permanecem no mesmo fluxo.

O agente é composto por **4 projetos .NET** mais um **driver de kernel
opcional**:

| Projeto | O que é |
|---|---|
| `SafeUpload.Agent.Core` | Domínio: validadores (CPF/CNPJ/Luhn/senha/segredos), motor de decisão (`InspectionService`), extratores de texto/CSV, Word, Excel, PowerPoint, PDF e ZIP, política e auditoria |
| `SafeUpload.Agent.Service` | Serviço Windows que roda 24/7, intercepta operações de arquivo e chama o Core para decidir |
| `SafeUpload.Agent.App` | Interface WPF (bandeja do sistema, tela de status/histórico, aviso de bloqueio) — só exibe, não decide nada |
| `SafeUpload.Agent.Tests` | Testes automatizados (xUnit, sem framework de mock) |
| `SafeUpload.Agent.Minifilter` | Biblioteca de protocolo que conecta o Service ao driver de kernel |
| `SafeUpload.Agent.Network` | Inspeção TLS do tráfego web: CA local e certificados por host (Fase 1), proxy TLS e parser HTTP/1.1 (Fase 2), desvio dos navegadores (Fase 3); exceções e inspeção nas próximas fases ([arquitetura](../docs/rede/ARQUITETURA-INSPECAO-TLS.md), [plano](../docs/rede/PLANO-INSPECAO-TLS.md)) |

As extensões padrão, tanto na política criada pelo agente quanto na política
servida pelo backend, são `.txt`, `.csv`, `.docx`, `.xlsx`, `.pdf`, `.pptx`,
`.pptm`, `.potx`, `.ppsx`, `.zip` e `.7z`. Políticas explícitas existentes não
são migradas automaticamente. ZIP inspeciona cada membro sob orçamento cumulativo;
7z permanece recusado com `archive_7z_unavailable`. Veja o escopo e as recusas
em [INSPECTION-COVERAGE.md](docs/INSPECTION-COVERAGE.md).

Também existe `SafeUploadAgent/` — um protótipo visual WPF anterior (sem
lógica) — e `driver/` na raiz do repositório, o driver de kernel
(minifiltro) opcional, com documentação própria em
[`../driver/ARQUITETURA.md`](../driver/ARQUITETURA.md) e
[`../driver/DEPLOY.md`](../driver/DEPLOY.md).

### Duas formas de interceptar

O Service escolhe, por configuração (`Interception:Mode` em
`appsettings.json`), entre:

- **`FileSystemWatcher`** (padrão) — reage *depois* que o arquivo chega ao
  destino. Roda em qualquer máquina, sem instalar nada além do serviço.
- **`Minifilter`** — intercepta *antes*, no kernel, via o driver em
  `driver/`. Exige o driver compilado, assinado e carregado.

O padrão é sempre o modo mais simples: uma máquina sem o driver deve ficar
protegida de forma imperfeita, não sem proteção nenhuma.

---

## Como rodar

### Pré-requisitos

- Windows
- .NET 10 SDK (`winget install Microsoft.DotNet.SDK.10`)

### Rodar o serviço em modo console (para depurar)

```powershell
cd SafeUpload.Agent.Service
dotnet run
```

### Rodar a interface

```powershell
cd SafeUpload.Agent.App
dotnet run
```

Abre minimizada na bandeja do sistema — dê duplo clique no ícone para ver o
painel.

### CA da inspeção TLS

A inspeção TLS usa uma CA gerada na própria máquina. Num terminal de
administrador:

```powershell
cd SafeUpload.Agent.Service
dotnet run -- ca install   # cria a CA (chave não exportável) e a põe em LocalMachine\Root
dotnet run -- ca status    # mostra a CA e se está confiável
dotnet run -- ca remove    # remove CA, confiança e chave (desinstalação)
```

`ca install` também liga a política `ImportEnterpriseRoots` do Firefox, que
por padrão ignora as raízes do Windows.

### Proxy de inspeção TLS

Desligado por padrão. Em `SafeUpload.Agent.Service/appsettings.json`:

```json
"InspecaoTls": { "Habilitada": true, "Porta": 8877 }
```

Com isso o serviço cria a CA (se ainda não existir), sobe o proxy em
`127.0.0.1:8877` e desvia os navegadores para ele: políticas de proxy do
Chrome, Edge e Firefox, mais filtros WFP que impedem os navegadores de sair
direto pelas portas 80 e 443. Os outros programas não são afetados. Ao parar,
o serviço desfaz tudo. Com `"DesviarNavegadores": false` o desvio não é feito,
e o navegador precisa ser apontado à mão (`msedge --proxy-server=http://127.0.0.1:8877`).

Se o serviço morrer sem parar direito, os filtros somem sozinhos, mas as
políticas continuam apontando para o proxy fora do ar. Para devolver a
internet aos navegadores, num terminal de administrador:

```powershell
SafeUpload.Agent.Service.exe desvio status
SafeUpload.Agent.Service.exe desvio remove
``` Nesta fase o proxy só registra no log os
envios que veria (site, tamanho, tipo e processo) e libera tudo; o bloqueio
de verdade vem com a Fase 5.

### Rodar os testes

```powershell
cd agente
dotnet test SafeUpload.Agent.sln
```

O teste que instala uma CA em `LocalMachine\Root` só roda com
`SAFEUPLOAD_MACHINE_TESTS=1`, como administrador, numa máquina de teste.

---

### Instalar como serviço com o minifiltro (protótipo de escrita em estágio)

Somente em VM de teste, com o INF do minifiltro já instalado, em PowerShell **elevado**:

```powershell
dotnet publish agente\SafeUpload.Agent.Service -c Release -r win-x64 --self-contained false
.\agente\scripts\Install-SafeUploadAgent.ps1 -ServiceExecutablePath "<caminho>\SafeUpload.Agent.Service.exe"
sc.exe qsidtype SafeUploadAgent
```

O script registra o serviço como LocalSystem, no modo de minifiltro com escrita em estágio (`--Interception:Mode=Minifilter
--Interception:StagingPrototype=true`, alterável com `-ServiceArguments`; sem eles toda gravação de usuário comum numa pasta
protegida é recusada) e configura `SERVICE_SID_TYPE_UNRESTRICTED` para que o token contenha
`NT SERVICE\SafeUploadAgent`, exigido pelo driver para substituir política e conceder autorizações. Ele não inicia o serviço.
Instale primeiro o INF do minifiltro e execute o script antes de reiniciar. Ele semeia e verifica `BootPolicy` como SYSTEM,
mantém o driver em início sob demanda até a semeadura terminar e então o deixa em boot-start. Se a semeadura falhar, a
instalação para e o driver fica em início sob demanda. O filtro não é iniciado pelo instalador; a proteção ativa depois do reboot.

Antes de ler `policy.json`, o agente exige ACL protegida e explícita, sem ACEs herdadas, com controle total somente para
SYSTEM e Administradores em `%ProgramData%\SafeUpload` e no arquivo. Se a ACL existente não corresponder, ele recusa o
arquivo e mantém a última política aplicada em memória; sem uma política válida anterior, não carrega uma política mais fraca.
A fila local de auditoria (`queue.jsonl`) ainda não é protegida por ACL.

**Limitações do instalador encontradas no teste manual de 08/10/2026** (ver
[`../driver/evidence/2026-10-08/manual-test-win10-debug/README.md`](../driver/evidence/2026-10-08/manual-test-win10-debug/README.md)):

Registro histórico: os argumentos staged e o reconhecimento da saída SID foram
corrigidos no script atual. O encaminhamento de configuração ao seed também foi
validado localmente; a execução instalada no alvo homologado continua pendente.
o script registra o serviço só com o caminho do executável, mas o protótipo de escrita em estágio precisa de
`--Interception:Mode=Minifilter --Interception:StagingPrototype=true` na linha de comando do serviço (é assim que a bateria de
testes o inicia). Sem esses argumentos o agente fica fora do modo em estágio (`admissionCoverage` `NotAvailable`) e o driver recusa
toda gravação de usuário comum na pasta protegida. A última verificação do script também falha com a saída
`SERVICE_SID_TYPE:  UNRESTRICTED` do Windows 10 19045, depois de já ter configurado tudo.

## Integração com o Centro de Administração (HU-10)

Com `CentroAdministracao:BaseUrl` vazio, o agente é **autônomo**: lê a política de
`%ProgramData%\SafeUpload\policy.json` e só acumula auditoria em
`queue.jsonl`, localmente. Configurando uma URL em
`SafeUpload.Agent.Service/appsettings.json`:

```json
"CentroAdministracao": {
  "BaseUrl": "http://127.0.0.1:8000/agent/",
  "DispatchIntervalSeconds": 30,
  "TimeoutSeconds": 5
}
```

o agente passa a:

- **Buscar a política do painel** (`GET /agent/policy`) em vez do arquivo
  local — mesmo formato JSON nos dois casos, então trocar a fonte não muda
  o contrato do documento. O provedor mantém cache persistido protegido para
  consumidores legados. Decisões staged, seed e carga inicial do driver exigem
  a política atual pela leitura estrita; falha de consulta não autoriza por cache.
- **Mandar heartbeat periódico** (`POST /agent/heartbeat`) — aparece em
  `/admin/endpoints` no painel.
- **Entregar os eventos de auditoria pendentes** (`POST /agent/events`) — a
  fila local continua sendo a fonte da verdade; o envio é só uma etapa a
  mais. Justificativas também são enviadas; o lote só é marcado como entregue
  após confirmação compatível do servidor. Falha no heartbeat não impede essa
  tentativa. A gravação da justificativa precede a publicação ou concessão.

Sem `BaseUrl` configurado, nada disso roda — é o padrão de segurança do
projeto (ver `Interception:Mode` acima, mesma filosofia).

**Diagnóstico local de políticas:** com logs de nível Information habilitados,
procure `PolicyIntegration`. `SnapshotVersion`/`SnapshotSource` identificam a
política disponível para consumidores legados (remote, memory, disk ou default).
`StrictVersion`/`StrictFingerprint` registram a última leitura estrita bem-sucedida;
`StrictReadError` informa o tipo da falha posterior, sem copiar URL ou mensagem da
exceção. `LastAcceptedVersion`/`LastAcceptedFingerprint` são o histórico da política
cujo escopo foi aceito após as operações de porta e BootPolicy retornarem.
`DriverScopeRecorded` perde validade na falha de aplicação ou saída da conexão;
`ApplyError` registra o tipo da falha de aplicação. Nenhum desses dados comprova
readiness/proteção ativa. Uma nova política recebida não altera esse histórico de
aceite. Compare fingerprints apenas de consumos equivalentes: defaults omitidos
podem diferir entre snapshot legado e leitura estrita. Hash ausente é diagnóstico
indisponível, nunca equivalência. Estado é somente em memória, separado de
heartbeat, notificações da bandeja e protocolo do driver; observações idênticas
não repetem o log. Não há atualização dinâmica do driver neste incremento.

**Limitações conhecidas desta integração:** sem autenticação entre agente e
servidor; identidade padrão do endpoint é o hostname (`Environment.MachineName`,
não um id estável). As justificativas do serviço preservam o SID obtido da conexão;
a obtenção dessa identidade no pipe real ainda depende do ensaio instalado.
Heartbeat/refresh não comprovam aplicação dinâmica no kernel. Recibo HTTP não
substitui a validação de durabilidade no banco utilizado.

O campo `failOpen` é preservado no documento e no vínculo de conteúdo, mas não
alterna sozinho os modos do motor: staged bloqueia inspeção incompleta; legado
mantém `AllowedWithoutInspection` nas falhas previstas. Não alterar somente esse
campo para anunciar mudança do comportamento legado.

---

## Estrutura

`SafeUpload.Agent.ContractSmoke --policy-publication-contract <pasta-temporaria> <URL-raiz> <endpoint-sintetico> <revisao> <categorias-CSV>`
confere as revisões 1 a 3 de um Java local. Use um endpoint exclusivo com prefixo
`M2-POLICY-ANGULAR-` e preserve a mesma pasta/cache entre as revisões. A ferramenta
lê a política, executa inspeção staged em amostra sintética e envia heartbeat;
ela não publica a política administrativa nem transfere bytes pelo driver.
Exige USB/rede desligados e clipboard Off. Para repetir, use pasta e banco novos;
os recibos anteriores não são sobrescritos. O teste `PolicyFailureModeContractTests`
confere que tamanho excessivo, formato sem extrator e erro de parse bloqueiam no
staged; o modo legado mantém seu resultado atual, independentemente de `failOpen`.

```
agente/
├── SafeUpload.Agent.Core/         # Domínio + validadores + motor de inspeção
├── SafeUpload.Agent.Service/      # Serviço Windows (o "cérebro" rodando)
├── SafeUpload.Agent.App/          # Interface WPF (bandeja + painel)
├── SafeUpload.Agent.Tests/        # Testes automatizados
├── SafeUpload.Agent.Minifilter/   # Protocolo de comunicação com o driver
├── SafeUpload.Agent.Network/      # Inspeção TLS: CA local, certificados e proxy
├── SafeUpload.Fixtures/           # Gerador de arquivos de teste (.docx/.xlsx/.pdf)
├── SafeUpload.Minifilter.Probe/   # Ferramenta de teste do driver (sem lógica real)
├── SafeUploadAgent/                # Protótipo visual WPF anterior (sem lógica)
└── SafeUpload.Agent.sln
```
