# SafeUpload — agente Windows

Serviço Windows e aplicativo de bandeja que impedem que arquivos com dados sensíveis cheguem a pastas protegidas,
pendrives e compartilhamentos. Alvo: Windows 10 x64 (22H2). O driver gate fica em [`../driver`](../driver/README.md);
a conversa com o console está em [`../docs/console-agente.md`](../docs/console-agente.md).

## Projetos (`SafeUpload.Agent.sln`)

| Projeto | O que faz |
|---|---|
| `SafeUpload.Agent.Core` | Inspeção: validadores (CPF e CNPJ com dígito verificador, cartão por Luhn, senhas, segredos, e detectores por rótulo para RG, dados bancários, saúde, documentos confidenciais e dados pessoais), extratores (texto/CSV, Word, Excel, PowerPoint, PDF, ZIP), motor de decisão (`InspectionService`), política e fila de auditoria. Não depende de Windows. |
| `SafeUpload.Agent.Service` | Serviço `SafeUploadAgent` (LocalSystem): carrega a política, monta as unidades SafeUpload, fala com o gate, atende a bandeja e o clipboard por pipes, sobe a inspeção TLS e conversa com o console. O mesmo executável tem os comandos `cadastrar`, `ca` e `desvio`. |
| `SafeUpload.Agent.Drive` | Sistema de arquivos WinFsp da unidade SafeUpload: stage privado, snapshot, inspeção e publicação no destino real. |
| `SafeUpload.Agent.App` | Bandeja WPF: estado da proteção, histórico, aviso de bloqueio com justificativa, monitor e proxy OLE do clipboard. |
| `SafeUpload.Agent.Network` | Inspeção TLS do tráfego web: CA local, proxy HTTP/1.1 e desvio dos navegadores. |
| `SafeUpload.Agent.Tests` | Testes xUnit do Core, do serviço, da unidade e da rede. `SafeUpload.Agent.App.Tests` (fora da solução) testa a bandeja. |
| `SafeUpload.Fixtures` | Gerador de arquivos de teste (.docx, .xlsx, .pdf). |

`installer/` tem o instalador ([README](installer/README.md)); `scripts/` tem a instalação manual, usada pelo
instalador e pelo `smoke/`.

## Como protege

1. **Unidade SafeUpload** (`Interception:Mode = Drive`, padrão; exige WinFsp). Cada pasta de `destinationPaths`
   (local `C:\...` ou compartilhamento `\\servidor\...`) e, com `removableDrives`, cada pendrive aparece como uma
   unidade (S:, T:, ...; letras em `Drive:Letters`). O que o usuário grava vai para um stage privado. Quando um
   arquivo alterado é fechado, o serviço inspeciona um snapshot: versão limpa é copiada para a pasta real; versão com
   dado sensível nunca chega lá (a pasta mantém a versão anterior) e a bandeja mostra o aviso.
2. **Gate** (`driver/`): recusa gravações diretas nesses lugares para todo processo que não seja o agente. Leituras
   nunca são recusadas. Com o agente parado, os lugares protegidos ficam fechados até ele voltar.

Regras:

- **Falha fecha.** Inspeção que falha, estoura `inspectionTimeoutSeconds`, arquivo acima de `maxFileSizeMb` ou
  formato sem leitor: a versão é bloqueada.
- **Categorias em alerta** (`alertCategories`) liberam a versão e registram o achado.
- **Justificativa** (com `overrideAllowed`): no aviso de bloqueio, o usuário tem 10 minutos para justificar. A
  justificativa vale para aquela versão exata, do mesmo usuário e sessão, sob a mesma política. Nova edição,
  renomeação ou mudança de política exigem nova inspeção.
- **Reinício:** versões retidas no stage voltam à unidade e são inspecionadas de novo com a política atual;
  aprovações e justificativas anteriores não são restauradas.

`Interception:Mode = FileSystemWatcher` é um modo de teste sem WinFsp nem gate: reage depois que o arquivo chegou ao
destino e o move para `C:\SafeUpload\_bloqueados`. Não é proteção preventiva.

### O que a inspeção lê

Texto e CSV; Word, Excel e PowerPoint (`.docx`, `.xlsx`, `.pptx`, `.pptm`, `.potx`, `.ppsx`), incluindo
cabeçalhos, comentários, propriedades, gráficos e slides ocultos; PDF (texto das páginas, anotações, formulários,
metadados); ZIP, membro a membro, até três níveis, com o mesmo limite de tamanho para a soma descompactada. O que não
tem leitor é recusado, e recusa bloqueia: imagens (sem OCR), objetos OLE embutidos, macros, `.ppt` binário, ZIP
criptografado, `.7z` (`archive_7z_unavailable`), PDF com anexos, JavaScript ou XFA. Cartão é qualquer número de 16
dígitos válido por Luhn, exceto `0000000000000000`. As categorias sem dígito verificador próprio exigem rótulo ou
formato validável (`Core/Domain/Validators/ContextDetectors.cs`).

### Outros canais

- **Clipboard** (desligado por padrão): bloqueia a colagem de texto sensível em navegadores e mensageiros. A
  auditoria inclui os nomes das regras personalizadas que dispararam. Desenho em
  [`docs/clipboard`](../docs/clipboard/README.md).
- **Web/TLS** (desligado por padrão, `InspecaoTls:Habilitada`): proxy local que inspeciona uploads dos navegadores.
  Diferente da unidade, libera quando a inspeção falha. Desenho e operação em
  [`docs/rede`](../docs/rede/ARQUITETURA-INSPECAO-TLS.md). Comandos (administrador):
  `SafeUpload.Agent.Service.exe ca install|status|remove` e `desvio status|remove` (devolve a internet aos
  navegadores se o serviço morrer com o desvio ligado).

### Privacidade da auditoria

O conteúdo dos arquivos e o texto copiado nunca entram em evento ou log; achados saem mascarados. O evento guarda só
o nome do arquivo (sem diretórios) e, na web, só a origem do site. Campos livres (nome, processo, destino,
justificativa) que contêm um valor reconhecido pelos validadores são omitidos inteiros. A bandeja só troca dados com
o processo do serviço `SafeUploadAgent` registrado no Windows.

## Política local (`policy.json`)

`%ProgramData%\SafeUpload\policy.json` usa o mesmo formato do documento de política do console
([Documento de política](../docs/console-agente.md#documento-de-política)), com o bloco opcional `clipboard`
descrito em [`docs/clipboard`](../docs/clipboard/README.md#política-bloco-clipboard). Exemplo mínimo:

```json
{
  "version": 1,
  "activeCategories": ["Cpf", "Cnpj", "PaymentCard", "Password", "Secret"],
  "monitoredScopes": {
    "extensions": [".txt", ".csv", ".docx", ".xlsx", ".pdf", ".pptx", ".zip"],
    "destinationPaths": ["C:\\SafeUpload\\Escopo Monitorado"],
    "removableDrives": true,
    "networkPaths": true
  },
  "overrideAllowed": true
}
```

- Sem o arquivo, o serviço grava um padrão parecido com esse (com justificativa desligada e clipboard `Off`).
- Comentários e vírgulas finais são aceitos; chave repetida invalida o arquivo.
- A pasta e o arquivo precisam de ACL explícita, sem herança, com controle total só para SYSTEM e Administradores
  (`scripts/Protect-SafeUploadPolicy.ps1` aplica). Arquivo inválido ou com ACL diferente é recusado e a última
  política válida continua valendo.
- Mudanças valem nas inspeções seguintes; unidades e gate seguem as pastas novas em até 30 s.

Com o agente cadastrado, a política do console tem precedência; o `policy.json` vale quando o console responde que
o host não tem política (`404`). Sem console alcançável, vale a última política em cache do cadastro atual.
Após trocar o cadastro ou atualizar de um cache antigo sem vínculo, vale a política local até obter a política
do console para o cadastro atual.

O documento remoto tem limite de 64 KiB. O cache local tem um limite separado para comportar o envelope de
identidade e a representação JSON usada no disco.

## Cadastro no console

Como administrador, com um token gerado no console (Configurações → Tokens de cadastro):

```powershell
& "$env:ProgramFiles\SafeUpload\Agent\service\SafeUpload.Agent.Service.exe" cadastrar https://servidor:8443/agent/ <token> --certificado <sha256>
```

O comando reinicia o serviço, que lê a identidade ao iniciar. Para trocar de servidor, rode de novo com
`--substituir` e um token novo. A troca só grava a nova identidade após receber o ID do host. Assinatura, rotas, heartbeat e
envio de eventos: [`docs/console-agente.md`](../docs/console-agente.md).

Para renovar o certificado do mesmo console, execute `SafeUpload.Agent.Service.exe atualizar-certificado <sha256>`
como administrador. O console precisa oferecer a rota assinada de verificação de identidade. A renovação preserva
o cadastro e a atribuição da fila.

## Onde ficam os dados

| Caminho | Conteúdo |
|---|---|
| `%ProgramFiles%\SafeUpload\Agent\` | Binários: `service\`, `ui\`, `setup\` (instalador) |
| `%ProgramData%\SafeUpload\policy.json` | Política local |
| `%ProgramData%\SafeUpload\queue.jsonl` | Histórico e fila de auditoria. O agente envia os pendentes do cadastro atual e preserva os demais localmente |
| `%ProgramData%\SafeUpload\console-policy-cache.json` | Última política válida recebida do console |
| `%ProgramData%\SafeUpload\authentication\ed25519-identity.dat` | Identidade do cadastro (chave, URL, `id_host`, certificado), protegida com DPAPI de máquina |
| `%ProgramData%\SafeUpload\drive\` | Uma pasta por destino: stage, snapshots, catálogo `stage-map.json` e registro de publicação |
| `%ProgramData%\SafeUpload\notifications\` | Registro das notificações emitidas para a bandeja |
| `C:\SafeUpload\` | Pasta protegida padrão (`Escopo Monitorado`) e quarentena do modo `FileSystemWatcher` |

`%ProgramData%\SafeUpload` só é acessível a SYSTEM e Administradores. Logs do serviço: Visualizador de Eventos →
Aplicativo. A desinstalação não apaga esses dados.

## Configuração do serviço

`service\appsettings.json` (substituído a cada atualização): `Interception:Mode` (`Drive` ou `FileSystemWatcher`),
`Drive:Letters`, e o bloco `InspecaoTls` (`Habilitada`, `Porta`, `DesviarNavegadores`, `Excecoes`).

## Build e testes

```bash
# Linux, com o SDK local (WPF precisa de EnableWindowsTargeting)
dotnet build agente/SafeUpload.Agent.sln -p:EnableWindowsTargeting=true
# Testes: rodam no Windows. No Linux cerca de um em oito falha por usar APIs do Windows (pipes, ACLs, certificados).
dotnet test agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj
dotnet test agente/SafeUpload.Agent.App.Tests/SafeUpload.Agent.App.Tests.csproj
```

Os testes que mexem na máquina (CA em `LocalMachine\Root`, filtros WFP) só rodam com `SAFEUPLOAD_MACHINE_TESTS=1`,
como administrador, numa VM de teste. O teste ponta a ponta com o driver é `smoke/run.sh` (ver
[`driver/README.md`](../driver/README.md)).

Para depurar, `dotnet run --project agente/SafeUpload.Agent.Service` roda o serviço em console (administrador; o
modo `Drive` precisa do WinFsp e do gate carregados). A bandeja só se conecta ao serviço registrado no Windows, não a
um processo de console.

## Instalar

Na VM de teste (test signing ligado), use o instalador: [installer/README.md](installer/README.md). Sem
instalador, a partir de um pacote publicado:

```powershell
dotnet publish agente\SafeUpload.Agent.Service -c Release -r win-x64 --self-contained true -o pkg
dotnet publish agente\SafeUpload.Agent.App -c Release -r win-x64 --self-contained true -o pkg\App
.\agente\scripts\Install-SafeUploadAgent.ps1 -PackagePath pkg -DriverPath <pasta com SafeUpload.sys e .inf> -WinFspMsi winfsp-2.1.25156.msi
```

O script instala nas mesmas pastas do instalador (`Agent\service\` e `Agent\ui\`): a bandeja só aceita como par o
serviço em `..\service\`. O driver vem de `driver/scripts/build-driver.sh`. Para remover:
`.\agente\scripts\Uninstall-SafeUploadAgent.ps1`.
