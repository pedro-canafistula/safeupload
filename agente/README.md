# SafeUpload — Agente Desktop

Veja [Integrações do agente na M2](docs/INTEGRACAO-M2.md) para escopo da entrega,
fluxo Git, validação e dependências com backend, painel e driver.

Componente instalado no endpoint do usuário: intercepta operações de
arquivo, decide localmente (CPF, CNPJ, cartão, senha, segredos), e — quando
configurado — sincroniza política e auditoria com o Centro de
Administração web.

---

## Visão geral

O instalador (`scripts/Install-SafeUploadAgent.ps1`) instala o WinFsp, o driver gate, o serviço e a bandeja.
Com `AdminBaseUrl` vazio o agente usa a política local; com uma URL, a política vem do Centro de Administração.

O agente é composto pelos projetos .NET abaixo mais um **driver de kernel pequeno** (`driver/`):

| Projeto | O que é |
|---|---|
| `SafeUpload.Agent.Core` | Domínio: validadores (CPF/CNPJ/Luhn/senha/segredos), motor de decisão (`InspectionService`), extratores de texto/CSV, Word, Excel, PowerPoint, PDF e ZIP, política e auditoria |
| `SafeUpload.Agent.Service` | Serviço Windows que roda 24/7, intercepta operações de arquivo e chama o Core para decidir |
| `SafeUpload.Agent.App` | Interface WPF (bandeja do sistema, tela de status/histórico, aviso de bloqueio) — só exibe, não decide nada |
| `SafeUpload.Agent.Tests` | Testes automatizados (xUnit, sem framework de mock) |
| `SafeUpload.Agent.Drive` | Unidade SafeUpload (WinFsp): o que o usuário grava fica privado até ser inspecionado; só versões aprovadas chegam à pasta protegida |
| `SafeUpload.Agent.Network` | Inspeção TLS do tráfego web: CA local e certificados por host (Fase 1), proxy TLS e parser HTTP/1.1 (Fase 2), desvio dos navegadores (Fase 3); exceções e inspeção nas próximas fases ([arquitetura](../docs/rede/ARQUITETURA-INSPECAO-TLS.md), [plano](../docs/rede/PLANO-INSPECAO-TLS.md)) |

As extensões padrão, tanto na política criada pelo agente quanto na política
servida pelo backend, são `.txt`, `.csv`, `.docx`, `.xlsx`, `.pdf`, `.pptx`,
`.pptm`, `.potx`, `.ppsx`, `.zip` e `.7z`. Políticas explícitas existentes não
são migradas automaticamente. ZIP inspeciona cada membro sob orçamento cumulativo;
7z permanece recusado com `archive_7z_unavailable`. Veja o escopo e as recusas
em [INSPECTION-COVERAGE.md](docs/INSPECTION-COVERAGE.md).

Também existe `SafeUploadAgent/` — um protótipo visual WPF anterior (sem
lógica) — e `driver/` na raiz do repositório, o driver gate (minifiltro), com documentação própria em
[`../driver/README.md`](../driver/README.md).

### Como o agente protege

O Service escolhe por configuração (`Interception:Mode` em `appsettings.json`):

- **`Drive`** (padrão) — cada pasta protegida da política aparece como uma unidade SafeUpload (S:, T:, ...),
  e cada pendrive conectado também, quando a política protege mídia removível. O usuário salva na unidade; ao
  fechar o arquivo, o agente inspeciona uma cópia e só então a copia para a pasta real. Versões bloqueadas não
  chegam lá (a pasta mantém a versão anterior) e a bandeja mostra o aviso com a opção de justificativa. A pasta
  real fica somente leitura para usuários, e o driver gate recusa gravações diretas de qualquer outro processo.
  Exige o WinFsp instalado.
- **`FileSystemWatcher`** — o mock antigo: reage *depois* que o arquivo chega ao destino e o apaga.

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

### Instalar como serviço

Numa máquina de teste com test signing ligado, em PowerShell **elevado**:

```powershell
dotnet publish agente\SafeUpload.Agent.Service -c Release -r win-x64 --self-contained true -o pkg
dotnet publish agente\SafeUpload.Agent.App -c Release -r win-x64 --self-contained true -o pkg\App
.\agente\scripts\Install-SafeUploadAgent.ps1 -PackagePath pkg -DriverPath <pasta com SafeUpload.sys e .inf> -WinFspMsi winfsp-2.1.25156.msi
```

O driver vem de `driver/scripts/build-driver.sh`. Para remover: `.\agente\scripts\Uninstall-SafeUploadAgent.ps1`.
O teste ponta a ponta numa VM descartável é `smoke/run.sh` (ver `driver/README.md`).

Antes de ler `policy.json`, o agente exige ACL protegida e explícita, sem ACEs herdadas, com controle total somente para
SYSTEM e Administradores em `%ProgramData%\SafeUpload` e no arquivo (`scripts/Protect-SafeUploadPolicy.ps1` aplica essa
ACL). Se a ACL existente não corresponder, ele recusa o arquivo e mantém a última política aplicada em memória.

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
  o contrato do documento. O provedor mantém cache persistido protegido.
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
cujas pastas protegidas as unidades SafeUpload aplicaram.
`DriverScopeRecorded` perde validade na falha de aplicação;
`ApplyError` registra o tipo da falha de aplicação. Nenhum desses dados comprova
readiness/proteção ativa. Uma nova política recebida não altera esse histórico de
aceite. Compare fingerprints apenas de consumos equivalentes: defaults omitidos
podem diferir entre snapshot legado e leitura estrita. Hash ausente é diagnóstico
indisponível, nunca equivalência. Estado é somente em memória, separado do
heartbeat e protocolo do driver; observações idênticas não repetem o log.
A bandeja recebe um resumo opcional pela mensagem de status local existente,
sem hashes ou exceções internas. A seção Sincronização da política mostra a
política disponível, a última consulta bem-sucedida e o último aceite de escopo.
Um publicador separado verifica mudanças a cada dois segundos, preservando a
gravação durável de notificações antes da entrega. Versões antigas continuam
sem o campo opcional; a tela exibe diagnóstico indisponível. Perder a conexão
com o serviço limpa o resumo exibido. Nada disso altera os campos de proteção
ou introduz atualização dinâmica do driver.

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
├── SafeUpload.Agent.Drive/        # Unidade SafeUpload (WinFsp): stage, inspeção e publicação
├── SafeUpload.Agent.Network/      # Inspeção TLS: CA local, certificados e proxy
├── SafeUpload.Fixtures/           # Gerador de arquivos de teste (.docx/.xlsx/.pdf)
├── SafeUploadAgent/                # Protótipo visual WPF anterior (sem lógica)
└── SafeUpload.Agent.sln
```
