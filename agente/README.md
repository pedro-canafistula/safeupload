# SafeUpload — Agente Desktop

Componente instalado no endpoint do usuário: intercepta operações de
arquivo, decide localmente (CPF, CNPJ, cartão, senha, segredos), e — quando
configurado — sincroniza política e auditoria com o Centro de
Administração web.

---

## Visão geral

O agente é composto por **4 projetos .NET** mais um **driver de kernel
opcional**:

| Projeto | O que é |
|---|---|
| `SafeUpload.Agent.Core` | Domínio: validadores (CPF/CNPJ/Luhn/senha/segredos), motor de decisão (`InspectionService`), extratores de texto (.txt/.docx/.xlsx/.pdf), política e auditoria |
| `SafeUpload.Agent.Service` | Serviço Windows que roda 24/7, intercepta operações de arquivo e chama o Core para decidir |
| `SafeUpload.Agent.App` | Interface WPF (bandeja do sistema, tela de status/histórico, aviso de bloqueio) — só exibe, não decide nada |
| `SafeUpload.Agent.Tests` | Testes automatizados (xUnit, sem framework de mock) |
| `SafeUpload.Agent.Minifilter` | Biblioteca de protocolo que conecta o Service ao driver de kernel |

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

### Rodar os testes

```powershell
cd agente
dotnet test SafeUpload.Agent.sln
```

---

## Integração com o Centro de Administração (HU-10)

Por padrão, o agente é **autônomo**: lê a política de
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
  nada no motor de inspeção. Se o painel estiver fora do ar, cai
  automaticamente na política padrão embutida (fail-open, RN-013) — nunca
  fica sem proteção por causa de uma falha de rede.
- **Mandar heartbeat periódico** (`POST /agent/heartbeat`) — aparece em
  `/admin/endpoints` no painel.
- **Entregar os eventos de auditoria pendentes** (`POST /agent/events`) — a
  fila local continua sendo a fonte da verdade; o envio é só uma etapa a
  mais, nunca bloqueia a decisão.

Sem `BaseUrl` configurado, nada disso roda — é o padrão de segurança do
projeto (ver `Interception:Mode` acima, mesma filosofia).

**Limitações conhecidas desta integração**, deliberadas: sem cache de
política em disco (cada consulta é uma chamada de rede), sem autenticação
entre agente e servidor, sem despacho de justificativas/overrides (só
eventos de bloqueio/aprovação), identidade do endpoint é o hostname
(`Environment.MachineName`, não um id estável).

---

## Estrutura

```
agente/
├── SafeUpload.Agent.Core/         # Domínio + validadores + motor de inspeção
├── SafeUpload.Agent.Service/      # Serviço Windows (o "cérebro" rodando)
├── SafeUpload.Agent.App/          # Interface WPF (bandeja + painel)
├── SafeUpload.Agent.Tests/        # Testes automatizados
├── SafeUpload.Agent.Minifilter/   # Protocolo de comunicação com o driver
├── SafeUpload.Fixtures/           # Gerador de arquivos de teste (.docx/.xlsx/.pdf)
├── SafeUpload.Minifilter.Probe/   # Ferramenta de teste do driver (sem lógica real)
├── SafeUploadAgent/                # Protótipo visual WPF anterior (sem lógica)
└── SafeUpload.Agent.sln
```
