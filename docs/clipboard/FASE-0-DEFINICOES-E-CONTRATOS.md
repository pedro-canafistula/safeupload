# Clipboard — Fase 0: definições e contratos

Estado: **concluída**, na `main` (PR #16).

## Objetivo

Determinar o que suja o clipboard e quais destinos contam como saída, e criar
a base no `Core`, sem nada de Windows, para que as regras possam ser testadas
sozinhas.

## Desenho

O Ctrl+C não bloqueia nada: só classifica o texto e marca o clipboard como
**sujo** quando há achado. O bloqueio acontece no Ctrl+V, e só quando o destino
é um processo de **saída** (navegador, mensageiro, e-mail). Colar entre
aplicativos locais continua livre, o que evita o falso positivo de quem só move
dados de uma planilha para outra.

Quem decide é o **serviço**; o App só observa e pergunta. É a mesma divisão do
resto do agente.

## Decisões

| Pergunta | Decisão | Onde está no código |
|---|---|---|
| Suja só pelo conteúdo ou também por processo contaminado no driver? | **Só pelo conteúdo.** Usar a contaminação de processo do driver fica como evolução, em aberto com o Victor. | `ClipboardRules.Classify` |
| Texto grande demais para varrer suja ou fica limpo? | **Suja** (`oversizedTextIsDirty = true` por padrão). Segue a regra do driver para origem: o que não foi olhado marca. O contrário abriria o furo de copiar um texto grande com o CPF no fim. Configurável na política. | `ClipboardPolicy.OversizedTextIsDirty`, `ClipboardCopyReason.TextTooLarge` |
| A lista de saída é de bloqueio ou de permissão? | **De bloqueio.** O que está em `egressDestinations` é saída; o que não está é aplicativo local. | `ClipboardPolicy.IsEgressDestination` |

Regras que decorrem dessas decisões:

- **Destino desconhecido não é saída.** Sem saber para onde vai, bloquear seria
  resolver incerteza negando, o que a RN-013 proíbe.
- **Mesmo processo de origem e destino cola livre** (Excel → Excel).
- **`excludedSources`** nunca suja o clipboard (gerenciadores de senha, que
  escrevem e limpam o clipboard o tempo todo). Processos excluídos pela
  política geral (RN-014) também não sujam.
- **Categorias vêm de `Policy.ActiveCategories`**, não de uma lista própria. Um
  CPF é o mesmo achado copiado ou salvo.
- **Texto acima do teto** não é varrido; o resultado segue `oversizedTextIsDirty`.

## O que foi implementado

| Arquivo | Papel |
|---|---|
| `Core/Domain/ClipboardPolicy.cs` | O bloco `clipboard` da política: modo, destinos de saída, fontes excluídas, teto de texto. Valida no carregamento. |
| `Core/Domain/ClipboardRules.cs` | As duas decisões: `Classify` (no Ctrl+C) e `DecidePaste` (no Ctrl+V). Sem nada de Windows. |
| `Core/Contracts/ClipboardProtocol.cs` | O contrato do pipe: mensagens, tetos, prazos e serialização. |
| `Core/Domain/AuditEvent.cs` | Campo `Channel` (`File` ou `Clipboard`). |
| `Core/Domain/Policy.cs` | Expõe `EffectiveClipboard` e valida o bloco junto com o resto da política. |
| `Core/Infrastructure/PolicyDocument.cs` | Lê o bloco `clipboard` do JSON. Serve ao arquivo local e à política que vem do painel. |

## Contratos

### Política: bloco `clipboard`

| Chave | Padrão | Observação |
|---|---|---|
| `mode` | `Off` | `Off`, `Audit` ou `Block`. Valor desconhecido falha alto (`InvalidPolicyException`), não é ignorado. |
| `egressDestinations` | navegadores, mensageiros, e-mail | Nomes de processo, com ou sem `.exe`, sem caixa. Os nomes são exemplos: confira na máquina. |
| `excludedSources` | KeePass, KeePassXC, 1Password, Bitwarden | |
| `maxTextLength` | 100 000 | Caracteres que o serviço aceita varrer. |
| `oversizedTextIsDirty` | `true` | |

- Política **sem o bloco carrega como `Off`**, então um arquivo antigo continua
  carregando igual.
- `Block` sem nenhum `egressDestinations` é recusado no carregamento (RN-009):
  seria uma política que promete bloquear e nunca bloqueia.
- O mapeamento vive em `PolicyDocument`, então vale para o arquivo local
  (`LocalPolicyStore`) e para a política do painel (`HttpPolicyStore`).

### Pipe: `\\.\pipe\SafeUpload.Agent.Clipboard`

NDJSON, um pipe próprio, para que ACLs e limites possam divergir dos outros
canais.

| Mensagem | Leva | Devolve |
|---|---|---|
| `classify` | texto, tamanho real, processo de origem | `copyId`, `dirty`, `categories`, `findings` (mascarados) |
| `paste` | `copyId`, processo de destino | `verdict` (`Allow`, `AuditOnly`, `Block`), `eventId` |

- O texto **não viaja de novo** no `paste`: quem guarda o estado da cópia é o serviço.
- Tetos: `MaxTextChars` 200 000; `MaxLineLength` = `MaxTextChars × 6 + 4096`
  (um escape JSON vira até 6 caracteres); nome de processo 260; `copyId` 64.
- Prazos: `paste` **500 ms** (o aplicativo do usuário fica parado esperando);
  `classify` **2 s** (ninguém espera na cópia).
- **A falha sempre libera (RN-013):** linha malformada, pedido desconhecido ou
  serviço que não responde a tempo → o App cola normalmente.
- Nenhum campo carrega o texto copiado (RN-006); achados sempre mascarados (RN-007).

### Auditoria: `AuditEvent.Channel`

`AuditChannel { File, Clipboard }`, padrão `File`, então eventos e linhas de fila
antigos continuam significando o que sempre significaram. Num evento de
clipboard: `FileName` e `Extension` vazios, `SizeBytes` é o tamanho do texto,
`ProcessName` é quem copiou, `DestinationPath` é o processo onde se tentou colar.

## Verificação

Testes xUnit, 243 passando no agente (os já existentes e os novos):

- `ClipboardPolicyTests`: padrões, validação, comparação de nomes de processo.
- `ClipboardRulesTests`: a tabela de quando suja e quando passa.
- `ClipboardProtocolTests`: serialização, tetos, entrada malformada.
- Política sem o bloco carrega como `Off`.

## Pontos em aberto

| Ponto | Com quem |
|---|---|
| Usar a contaminação de processo do driver como fonte de "sujo" (exige mensagem nova no protocolo do kernel) | Victor |
| O backend Spring reconhece a chave `clipboard` da política? Se não reconhecer, o canal fica desligado, sem erro | Time do backend |
| Coluna de canal e `fk_id_objeto` nulo na tabela `eventos`, porque uma colagem não tem arquivo | Time do banco e do painel |
