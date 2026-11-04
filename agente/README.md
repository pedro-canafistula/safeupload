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

O motor confere o limite configurado no arquivo aberto antes de reservar a captura legada para qualquer formato.
No staging, caminho e read lease exigem entrada somente leitura com o tamanho medido; divergências são retidas
antes do parser. Tamanho real acima do limite mantém `file_too_large`, inclusive quando a descoberta indicava zero.
O modo clássico preserva `AllowedWithoutInspection` nas falhas; staging preserva `Blocked`.

O cancelamento é reconferido após política, worker e auditoria. Uma decisão nova só entra no cache depois da tentativa
de auditoria e da conferência de cancelamento. Evento já gravado e cache válido de uma chamada anterior são mantidos;
falha comum de auditoria continua preservando o veredito.

Os leitores de política local e do formato remoto legado recusam campos repetidos, inclusive variações de caixa e
nomes escapados, em vez de substituir um valor anterior. JSON ambíguo não sobrescreve a última política remota válida.
Comentários e vírgulas finais continuam aceitos no arquivo local. O formato da console mantém sua validação existente.
Os caches de política (`CachedPolicyStore`) e vereditos medem validade por tempo decorrido, independentemente de
ajustes na hora do sistema. Uma carga cancelada não instala um novo snapshot; consultas atuais delegam ao provedor
interno sem usar ou substituir esse cache. No modo remoto, as inspeções continuam usando o snapshot atualizado em fundo.

O envio da auditoria lê o recibo em fluxo, com limite de 16 KiB e profundidade JSON de 16.
O prazo de `HttpClient.Timeout` cobre envio e leitura completa; cancelamento ou recibo inválido mantém o lote pendente.
Ambas as contagens `acceptedEvents` e `acceptedOverrides` devem existir uma única vez e corresponder ao lote,
inclusive quando zero. A confirmação em disco conserva o token de cancelamento do serviço e independe do prazo HTTP.

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

Nas unidades SafeUpload, aprovação da inspeção e publicação são etapas distintas. O evento de sucesso só é emitido
depois de copiar o snapshot e substituir o arquivo no destino. Falha de cópia/substituição gera um evento bloqueado
com `publication_failed` por versão aprovada; o snapshot fica disponível para nova tentativa. A recuperação gera
outro evento, sem reescrever o bloqueio ou a justificativa originais. A publicação usa o nome/destino finais do arquivo.

A resposta de justificativa confirma o agendamento, não a cópia concluída. O resultado aparece no histórico.
Esses eventos não confirmam flush físico, entrega ao servidor ou persistência após queda de energia.

Na parada ordenada, cada unidade cancela e aguarda seu worker antes de desmontar. O serviço aguarda então os relatos
de decisão/publicação já enfileirados. Cancelamento de inspeção não vira um novo bloqueio. Se o prazo de parada
terminar, a espera falha e não comprova a conclusão desses relatos; um provedor que ignora cancelamento pode atrasá-la.
Antes de substituir o destino por um snapshot aprovado, a unidade grava uma intenção no registro privado
`publication-audit`. Ele guarda ID/horário/metadados imutáveis do evento e o hash da cópia preparada,
sem copiar bytes do arquivo ou diagnósticos brutos; trechos já mascarados seguem o contrato da auditoria. Após a substituição, grava o resultado e tenta
entregá-lo à fila. Falha na fila mantém o registro para tentar novamente; falha em persistir a intenção impede a cópia final.

Na retomada, uma intenção sem resultado durável registra `publication_outcome_unknown`: o histórico mostra
"Não confirmado", sem afirmar que a cópia foi impedida, mesmo quando o destino contém os mesmos bytes.
A recuperação nunca conclui uma cópia antiga nem infere sucesso pela identidade/hash encontrados depois.
Resultados já gravados não são alterados por mudanças posteriores no destino.

A primeira entrega usa um ID novo; repetições conferem a fila, inclusive eventos já despachados, sem alterar seus bytes
ou estado de entrega. Um mesmo ID com metadados diferentes mantém a pendência para investigação. O registro usa ordem
persistida por unidade e admite até 1 MiB por entrada, 16 MiB pendentes e 4096 entradas. Isso cobre retomada do processo
para publicações de snapshots; não é uma transação de armazenamento, garantia de queda de energia ou journal de todas
as operações do filesystem. Auditoria de bloqueios e fluxos legados conserva seus contratos próprios.

O catálogo privado `stage-map.json` registra os arquivos retidos, nomes relativos, localização anterior publicada e
autor capturado pelo serviço. A gravação usa temporário no mesmo diretório, flush e substituição antes de aceitar
bytes novos ou alterar nomes/exclusões privadas. O catálogo admite até 1 MiB e 4096 entradas, é associado ao caminho
e à identidade de volume/diretório informada pelo Windows e só pode ter um filesystem ativo por área privada.
Catálogo inválido, stage ausente, destino trocado ou redirecionamentos/links incompatíveis impedem a recuperação,
preservando os arquivos. Arquivos antigos sem catálogo permanecem privados, sem tentativa de adivinhar seus nomes.

Após reinício, versões registradas voltam à unidade e são reinspecionadas com a política atual. Não se restauram
aprovações ou justificativas; a sessão/processo anterior não concede uma nova liberação. SID e nome capturados são
mantidos apenas para atribuição de auditoria. Uma publicação concluída retira do catálogo somente a versão atual;
uma edição mais nova permanece retida. Renomeações registram a intenção antes de mover o backing: após interrupção,
o nome novo pode ser recuperado mesmo que essa movimentação não tenha terminado. Isso não é um journal completo
do filesystem, não reproduz exclusões de backing após queda e não qualifica queda de energia ou USB/SMB sem ensaio real.

A autorização também carrega a impressão do conteúdo da política usada na inspeção. As unidades conferem essa
impressão antes da cópia e novamente antes da substituição do destino; mudança de regras, inclusive sob o mesmo
número de versão, revoga a aprovação e agenda nova inspeção do stage. Justificativas exigem o mesmo vínculo antes
e depois de gravar a solicitação na auditoria. Falha de leitura da política mantém a cópia aprovada retida para tentar
novamente. Na configuração remota essas leituras usam o snapshot validado do serviço de fundo, inclusive offline,
sem HTTP por arquivo. São reconferências pontuais, não uma transação atômica entre atualização de política e renomeação.

O estado das unidades distingue conexão com o serviço de proteção confirmada. Só anuncia proteção completa quando
o gate aceita o escopo e todas as unidades esperadas aparecem disponíveis no Windows. Nas consultas seguintes ao
mesmo escopo, usa o comando de contadores existente para verificar a conexão; falha ou resposta incompleta exige
reconexão e reenvio da política. Ausência de destinos, montagem incompleta, escopo recusado, política indisponível e
parada do serviço deixam a proteção inativa na notificação. O indicador verde acompanha esse estado, inclusive em
modo auditoria; conexão com o serviço por si só não o ativa. O detalhe DriveProtection é opcional no contrato do pipe.

É uma observação da sincronização periódica de 30 segundos, não uma prova contínua de todos os volumes/canais.
O recebimento do escopo pelo gate e a presença das letras não qualificam Office/USB/SMB sem o ensaio real. Se o
registro durável de uma notificação falhar, sua entrega continua suprimida; a sincronização tenta registrar novamente,
e a interface pode conservar a última observação até receber outra ou detectar a desconexão.

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
ACL). Se a ACL existente não corresponder, ele recusa o arquivo e mantém a última política aplicada em memória; sem uma
política válida anterior, não carrega uma política mais fraca.
A fila local (`queue.jsonl`) do serviço exige proprietário confiável e acesso somente a SYSTEM e Administradores,
com verificação da pasta e do arquivo aberto antes de ler, anexar ou confirmar eventos. Arquivos novos e temporários
de confirmação são criados com ACL protegida. Filas antigas que herdam apenas essas permissões da pasta protegida
continuam aceitas; permissões indevidas, links e múltiplos nomes físicos são recusados sem reparar ou apagar a fila.
Uma recusa aparece como falha de acesso na saúde da fila, sem confirmar entrega. Isso não autentica dados alterados
antes da validação, não recupera automaticamente cópias temporárias e não garante persistência contra perda de energia.
O construtor de caminho explícito continua destinado a ferramentas/testes isolados, fora da composição do serviço.
Os ensaios locais usam somente pastas temporárias próprias; o aceite instalado como SYSTEM é uma etapa separada.

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

- **Buscar a política do painel** a cada 30 s, com cache persistido protegido (ver abaixo).
- **Mandar heartbeat periódico** (`POST /agent/heartbeat`) — aparece em
  `/admin/endpoints` no painel.
- **Entregar os eventos de auditoria pendentes** (`POST /agent/events`) — a
  fila local continua sendo a fonte da verdade; o envio é só uma etapa a
  mais. Justificativas também são enviadas; o lote só é marcado como entregue
  após confirmação compatível do servidor. Falha no heartbeat não impede essa
  tentativa. A gravação da justificativa precede a publicação ou concessão.

Sem `BaseUrl` configurado, nada disso roda — é o padrão de segurança do
projeto (ver `Interception:Mode` acima, mesma filosofia).

### Política publicada pela console web

Com `"PolicyProtocol": "ConsoleByIp"`, `"PolicyHostIp"` (o IP cadastrado do host) e `"RegisteredHostId"` em
`CentroAdministracao`, o agente lê `GET /agent/api/policy?ip=<PolicyHostIp>`, a política que o administrador publica na
tela Políticas. Sem `PolicyProtocol`, continua o formato antigo (`GET /agent/policy`).

| Da console | No agente |
|---|---|
| `regras`: cpf, cnpj, cartao_credito, credenciais, rg, dados_bancarios, dados_saude, documentos_confidenciais, dados_pessoais | categorias ativas (`credenciais` = senha + segredo) |
| `acao`: bloquear / alertar | bloqueia / libera e registra o alerta (`AuditOnly`; evento `Approved` com as categorias). Arquivo que não pôde ser inspecionado continua bloqueado nos dois casos |
| `idPolitica` | versão da política |

A console ainda não publica pastas protegidas, pendrives, compartilhamentos, extensões, limites nem a permissão de
justificar: esses valores continuam vindo do `policy.json` local. Um documento de outro host, com regra desconhecida ou
mais antigo que o atual é recusado e a última política válida continua (memória e
`%ProgramData%\SafeUpload\console-policy-cache.json`). As unidades SafeUpload e o gate seguem a política nova no
próximo ciclo de 30 s.

As regras sem dígito verificador próprio precisam de rótulo ou de formato validável
(`SafeUpload.Agent.Core/Domain/Validators/ContextDetectors.cs`): RG rotulado ou de SP com DV; agência + conta
rotuladas ou IBAN; CID rotulado, Cartão Nacional de Saúde ou campo de formulário médico ("Diagnóstico: ..."); marcação
CONFIDENCIAL/SIGILOSO/USO INTERNO; e-mail, telefone ou data de nascimento rotulada.

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
