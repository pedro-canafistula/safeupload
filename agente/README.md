# SafeUpload — agente desktop (mock)

Mock do agente de endpoint do SafeUpload: um protótipo acadêmico de prevenção de vazamento de
dados (DLP) da UCB.

Na arquitetura aprovada, o agente real seriam **três artefatos** rodando na máquina do usuário —
um minifiltro em modo kernel, um serviço Windows em .NET e uma interface de notificação. Aqui são
**dois processos**, sem driver:

| Processo | O que é | Roda como |
|---|---|---|
| `SafeUpload.Agent.Service` | O agente. Vigia as pastas, inspeciona, decide e audita. | Serviço do Windows, LocalSystem |
| `SafeUpload.Agent.App` | O painel. Mostra estado e histórico. | Aplicativo de bandeja, usuário comum |

**O serviço decide, o aplicativo apenas mostra.** Nada que o usuário clique no painel altera um
veredito — o canal entre eles é de mão única, e a ausência do caminho de volta é a garantia, não a
disciplina de quem escreveu o código. Fechar o painel não desliga a proteção; encerrá-lo pela
bandeja também não.

O que **não** é mock: as regras de negócio, os validadores, a extração de texto, o mascaramento e
o motor de inspeção são código real, coberto por testes. O que é mock é o **gatilho**: em vez de
interceptar a operação de arquivo no kernel, um `FileSystemWatcher` reage a arquivos que aparecem
numa pasta vigiada.

**Nenhum arquivo sai da máquina.** O conteúdo é lido para memória, varrido e descartado no mesmo
escopo. Para o servidor central iriam apenas metadados e trechos já mascarados — e nesta entrega
nem isso, porque o envio ainda não foi implementado.

---

## Como rodar

Requisitos: Windows 10 ou 11 e .NET SDK 10.0.400.

Antes da primeira execução, uma vez, em PowerShell **elevado** — criar pasta na raiz de `C:` exige
administrador:

```powershell
New-Item -ItemType Directory -Force "C:\SafeUpload\Escopo Monitorado"
New-Item -ItemType Directory -Force "C:\SafeUpload\_bloqueados"
icacls "C:\SafeUpload" /grant "Users:(OI)(CI)M"
```

### Durante o desenvolvimento

Rode o serviço **como aplicação de console**. O mesmo executável serve aos dois modos, e depurar um
serviço de verdade exigiria anexar o depurador a um processo iniciado pelo gerenciador de serviços:

```
cd agente
dotnet build SafeUpload.Agent.sln
dotnet run --project SafeUpload.Agent.Service
```

Em outro terminal, o painel:

```
dotnet run --project SafeUpload.Agent.App
```

O painel **não abre janela ao iniciar**. Ele vive no ícone de bandeja, com a dica
"SafeUpload — proteção ativa". No Windows 10 o ícone costuma cair no menu de ícones ocultos, atrás
da seta `^` ao lado do relógio.

- **Clique** no ícone abre o painel.
- **Botão direito** abre o menu: *Abrir painel* · *Sair*.
- **Fechar o painel não encerra nada** — a janela apenas se oculta. E *Sair* encerra só o painel: a
  proteção é do serviço e continua.

### Instalando o serviço

Em PowerShell **elevado**:

```powershell
dotnet publish agente\SafeUpload.Agent.Service -c Release -r win-x64 --self-contained false
sc.exe create SafeUploadAgent binPath= "<caminho>\SafeUpload.Agent.Service.exe" start= auto
sc.exe start SafeUploadAgent
```

Para remover:

```powershell
sc.exe stop SafeUploadAgent
sc.exe delete SafeUploadAgent
```

Estado e diagnóstico do serviço:

```powershell
sc.exe query SafeUploadAgent
Get-EventLog -LogName Application -Source SafeUploadAgent -Newest 20
```

### Testes

```
cd agente
dotnet test SafeUpload.Agent.sln
```

---

## Vendo o agente funcionar

1. Abra o painel pelo ícone de bandeja e deixe-o na aba **Status**.
2. Copie, pelo Explorer, um arquivo `.txt` contendo `CPF: 529.982.247-25` para
   `C:\SafeUpload\Escopo Monitorado`.

O que deve acontecer:

- o arquivo **some** da pasta monitorada e reaparece em `C:\SafeUpload\_bloqueados`,
  com data e hora no nome;
- a notificação **"Envio bloqueado pelo SafeUpload"** aparece no canto inferior direito, listando
  a categoria encontrada e o trecho mascarado (`•••••••••25`), com um único botão, *Entendi*;
- uma linha nova surge em **Monitoramento de Atividade**, sem precisar reabrir a janela.

Um arquivo sem dado sensível permanece onde foi colocado e aparece como `PERMITIDO`.

**Feche o painel e repita.** O arquivo continua sendo bloqueado — este é o ponto de haver dois
processos: a proteção não depende da interface estar aberta. Ao reabrir o painel, o bloqueio que
aconteceu enquanto ele estava fechado aparece assim mesmo, porque o serviço guarda os eventos dos
últimos 60 segundos para quem conectar.

**Pare o serviço com o painel aberto.** O cartão "Status de Segurança" passa a mostrar
**"Serviço indisponível"** em vez de "Protegido". Mentir sobre proteção ativa é pior do que admitir
a falha: quem vê "Protegido" com o serviço fora do ar copia o arquivo confiante.

**Copie dez arquivos de uma vez.** Aparece **uma** notificação dizendo "10 arquivos bloqueados", e
não dez janelas empilhadas no mesmo canto.

---

## Onde fica o estado

| Caminho | O que é |
|---|---|
| `%ProgramData%\SafeUpload\policy.json` | A política vigente. Criada com valores padrão na primeira execução. |
| `%ProgramData%\SafeUpload\queue.jsonl` | A trilha de auditoria: uma linha JSON por evento. |
| `C:\SafeUpload\Escopo Monitorado` | Pasta vigiada (vem da política). |
| `C:\SafeUpload\_bloqueados` | Para onde vão os arquivos barrados. |

Nada fica no perfil do usuário, e isso é obrigatório e não preferência: quem vigia é um serviço
rodando como **LocalSystem**, e nesse contexto `%USERPROFILE%` aponta para o perfil da conta de
sistema. Uma pasta monitorada sob o perfil seria uma pasta que ninguém enxerga, e o serviço nunca
interceptaria nada.

`%ProgramData%` segue o produto real pelo mesmo motivo de sempre: política e trilha pertencem à
máquina e ao administrador, não a quem está logado. **No mock as pastas são apenas graváveis** —
não há ACL restritiva protegendo-as de quem usa a máquina.

### `policy.json`

```json
{
  "version": 1,
  "activeCategories": ["Cpf", "Cnpj", "PaymentCard", "Password"],
  "monitoredScopes": {
    "extensions": [".txt", ".csv", ".docx", ".xlsx"],
    "destinationPaths": ["C:\\SafeUpload\\Escopo Monitorado"],
    "removableDrives": true,
    "networkPaths": true
  },
  "maxFileSizeMb": 20,
  "inspectionTimeoutSeconds": 5,
  "failOpen": true,
  "excludedProcesses": ["System", "SafeUpload.Agent.App"]
}
```

Editar o arquivo muda o comportamento sem recompilar. Uma política **sem nenhuma categoria ativa é
recusada** no carregamento (RN-009): zero categorias não é "tudo desligado", é uma configuração que
aprovaria todo arquivo e ainda produziria uma auditoria falsamente limpa.

### `queue.jsonl`

Uma linha JSON por evento, formato *append-only*, UTF-8 sem BOM. Cada linha traz os campos da
HU-04, entre eles `verdict`, `categories`, `maskedSnippets`, `elapsedMs` e `dispatched`.

`dispatched` nasce `false` e assim permanece nesta entrega: o despachante para o Centro de
Administração ainda não existe.

---

## Como o agente decide

`InspectionService` executa as etapas nesta ordem, das mais baratas para as mais caras, de modo que
o caminho comum termine sem nunca abrir o conteúdo:

1. processo excluído → fora de escopo (RN-014)
2. destino ou extensão fora do escopo da política → fora de escopo (RN-011)
3. acerto de cache (chave: caminho + tamanho + data de modificação + processo; validade de 60 s)
4. acima de 20 MB → `AllowedWithoutInspection("file_too_large")` (RN-013)
5. formato sem extrator → `AllowedWithoutInspection("unsupported_format")` (RN-013)
6. extração e varredura com prazo de 5 s (RN-012)
7. qualquer achado válido → `Blocked` (RN-005)
8. grava no cache e audita

**Fail-open**: nenhuma falha vira bloqueio. Timeout, arquivo corrompido, formato mentiroso na
extensão — todos terminam em operação permitida, com o motivo registrado. Um DLP que bloqueia
quando quebra impede o usuário de trabalhar e é desligado na primeira semana.

**Mascaramento** (RN-007): o mascaramento acontece no domínio, no momento da varredura, e não na
interface. Números preservam só os dois últimos dígitos; senhas não preservam caractere nenhum.
Não existe caminho no código pelo qual o valor original chegue à tela ou ao disco.

### Regras de detecção

| Regra | Categoria | Critério |
|---|---|---|
| RN-001 | CPF | 11 dígitos, dígitos verificadores módulo 11, sequências repetidas recusadas |
| RN-002 | CNPJ | 14 dígitos, dígitos verificadores módulo 11 |
| RN-003 | Cartão | exatamente 16 dígitos e algoritmo de Luhn |
| RN-004 | Senha | par chave-valor `(senha\|password\|passwd\|pwd)\s*[:=]\s*\S{4,}` |

A varredura vai do padrão **mais longo para o mais curto** (cartão 16, CNPJ 14, CPF 11) e mantém os
intervalos já consumidos. Sem isso, como toda sequência de 14 dígitos contém quatro de 11, cada
CNPJ legítimo viraria vários achados de CPF e o bloqueio apontaria a categoria errada.

---

## Limitações declaradas

Estas não são pendências de implementação: são consequências de o mock rodar em modo usuário. Estão
listadas para que ninguém confunda a demonstração com o produto.

**Sem interceptação em modo kernel.** Não há minifiltro nem Filter Manager. O gatilho é um
`FileSystemWatcher`, que só avisa depois que o arquivo já chegou ao destino.

**A negação não é síncrona nem pré-operação.** Esta é a limitação central. O agente real veria a
operação *antes* de ela acontecer e poderia negá-la; aqui o arquivo **existe no destino por alguns
instantes** e o bloqueio é uma remoção posterior. Durante essa janela, o dado já está lá. Nenhum
ajuste em modo usuário resolve isso.

**O arquivo bloqueado é movido, não apagado.** Ele vai para `_bloqueados` e continua recuperável
pelo usuário. O agente tira o arquivo do destino monitorado, que é o que a política exige, mas não
tem mandato para destruir arquivo de ninguém.

**O processo de origem é desconhecido.** Sem interceptação em modo kernel não há como saber qual
processo copiou o arquivo. A trilha registra `desconhecido` em vez de um nome plausível: uma
suposição registrada como observação contaminaria a auditoria.

**Sem assinatura de código.** O executável não é assinado e não há proteção contra adulteração do
próprio agente. Os requisitos **RNF-10, RNF-12 e RNF-14 não são exercitados** por esta entrega.

**A notificação pode ir para a sessão errada.** O canal roteia por sessão do Windows, mas a origem
de uma operação vista pelo `FileSystemWatcher` não é determinável: ele informa o caminho do arquivo
e nada mais, então o PID chega como zero e a entrega **sempre cai em difusão**. Numa máquina com
duas sessões abertas, as duas veriam a mesma notificação. O código do roteamento existe e está
correto; só falta quem informe o processo de origem, que seria o minifiltro.

**Sem comunicação com o servidor central.** Nada é enviado ao Centro de Administração. A **HU-10
continua pendente**, mas o ponto de troca está preparado: `IPolicyStore` e `IAuditSink` são as duas
interfaces a implementar (`HttpPolicyStore` e um despachante que leia `ReadPendingAsync`, faça o
`POST` e chame `MarkDispatchedAsync`). Nada além da composição em `App.xaml.cs` precisa mudar.

**Sem OCR.** Texto dentro de imagens não é lido. Um CPF numa captura de tela colada num `.docx`
passa sem ser detectado.

**Sem PDF.** Fora do escopo desta entrega. Acrescentar é escrever um `ITextExtractor` e registrá-lo
no `ExtractorRegistry`.

**Detecção de senha é heurística por construção.** Diferente de CPF, CNPJ e cartão, uma senha não
tem forma verificável — não há dígito verificador que diga "isto é uma senha". A RN-004 é uma regra
sintática e **produz falsos positivos**: frases como `senha: siga o padrão corporativo` disparam a
detecção e, como qualquer achado leva a bloqueio, o custo recai sobre o usuário. Exigir entropia
mínima reduziria o ruído mas deixaria passar senhas fracas, que são justamente as que mais aparecem
em planilhas compartilhadas. O projeto escolheu errar para o lado do bloqueio.

**O estado local não é protegido.** Qualquer usuário da máquina pode editar `policy.json` ou apagar
`queue.jsonl`. No produto real, ACLs e o serviço em SYSTEM impediriam isso.

---

## Estrutura

```
agente/
  SafeUpload.Agent.sln
  SafeUpload.Agent.Core/     net10.0          regras, extração, orquestração, contratos
    Domain/                  validadores, varredura, mascaramento, política
    Application/             motor de inspeção, cache, interfaces de troca
    Infrastructure/          extratores, política local, fila de auditoria
    Contracts/               mensagens trocadas entre os dois processos
  SafeUpload.Agent.Service/  net10.0-windows  o agente: vigia, inspeciona e decide
    Interception/            FileSystemWatcher sobre as pastas monitoradas
    Notifications/           hub, servidor do pipe, sessão do cliente
  SafeUpload.Agent.App/      net10.0-windows  o painel: WPF + WinForms (bandeja)
    Notifications/           cliente do pipe
  SafeUpload.Agent.Tests/    net10.0-windows  xunit
```

A dependência é unidirecional: `App → Application → Domain ← Infrastructure`. Nada em `Domain`
conhece arquivo, JSON, HTTP ou WPF — é o que permite testar as regras sem tocar em disco.

Dependências externas: `DocumentFormat.OpenXml` no Core,
`Microsoft.Extensions.Hosting.WindowsServices` no serviço, `xunit` nos testes, **nenhum pacote no
projeto WPF**.

O projeto WPF **não referencia** `InspectionService`, `ContentScanner` nem os extratores. Se algum
deles reaparecer ali, alguma decisão voltou para o lado errado.

### Os dois processos

`SafeUpload.Agent.Service` é o agente: vigia, inspeciona, decide, move para a quarentena e audita.
`SafeUpload.Agent.App` é o painel: conecta ao serviço, mostra o estado e o histórico, e exibe a
notificação de bloqueio.

Entre eles, um named pipe chamado `SafeUpload.Agent`, em **NDJSON** — uma mensagem JSON por linha.
Duas mensagens, ambas do serviço para o aplicativo:

- `status` — versão da política, quantidade de categorias ativas e se a proteção está de fato
  vigiando;
- `event` — o evento de auditoria já gravado, mais os achados com a categoria de cada trecho.

**Não existe mensagem no sentido inverso.** É o que torna a regra "o serviço decide, o aplicativo
mostra" uma propriedade do código e não uma disciplina de quem o escreve: sem caminho de volta, não
há o que o painel possa pedir nem o que o serviço precise validar.

O pipe é criado com uma ACL explícita concedendo leitura e escrita ao grupo `Users`. Sem ela, o
descritor de segurança padrão de um pipe criado por LocalSystem não deixa o aplicativo de um
usuário comum conectar, e o erro é apenas "acesso negado", sem pista do motivo.

### Depurando

Rode o serviço em console (`dotnet run --project SafeUpload.Agent.Service`): o mesmo executável
serve aos dois modos, e é a única forma de ter um depurador normal. O log em console mostra cada
conexão, cada veredito e cada falha.

Se o painel mostrar **"Serviço indisponível"** com o serviço rodando, o problema está no pipe.
Confira se ele existe:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String "SafeUpload"
```
