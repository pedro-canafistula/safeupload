# Clipboard

Como o agente trata dados sensíveis copiados e colados. O código fica em `SafeUpload.Agent.Core` (regras e
protocolo), `SafeUpload.Agent.Service/Clipboard` (decisão e auditoria) e `SafeUpload.Agent.App/ClipboardWatch`
(monitor e proxy OLE).

## Ideia

O Ctrl+C não bloqueia nada: o serviço só classifica o texto e marca a cópia como **suja** quando acha algo. O
bloqueio acontece no Ctrl+V, e só quando o destino é um processo de **saída** (navegador, mensageiro, e-mail).
Colar entre aplicativos locais (Excel → Word) continua livre. Quem decide é o serviço; o App observa e pergunta.

| Situação | `Block` | `Audit` | `Off` (padrão) |
|---|---|---|---|
| Colar CPF num navegador, Teams, WhatsApp | Aviso no lugar do texto, balão na bandeja, evento | Cola normal, evento | Nada |
| Colar CPF no Word, Excel, Bloco de Notas | Cola normal | Cola normal | Nada |
| Colar texto comum | Cola normal | Cola normal | Nada |

O aviso colado é `[SafeUpload] conteúdo bloqueado — a cópia contém dado sensível.`

## Regras

- A cópia é suja só pelo conteúdo, com as mesmas categorias ativas da política de arquivos.
- Texto acima de `maxTextLength` não é varrido e conta como sujo (`oversizedTextIsDirty`, padrão `true`).
- `egressDestinations` é a lista de saída; o que não está nela é aplicativo local. Destino desconhecido não é saída.
- Mesmo processo de origem e destino cola livre. `excludedSources` (gerenciadores de senha) e os processos
  excluídos da política nunca sujam o clipboard.
- `Block` sem nenhum destino de saída é recusado ao carregar a política.
- Falha do canal libera: serviço fora do ar, resposta atrasada ou mensagem inválida fazem o App colar normalmente.

## Política: bloco `clipboard`

| Chave | Padrão |
|---|---|
| `mode` | `Off` (`Off`, `Audit` ou `Block`; valor desconhecido invalida a política) |
| `egressDestinations` | navegadores, mensageiros e e-mail (nomes de processo, com ou sem `.exe`) |
| `excludedSources` | KeePass, KeePassXC, 1Password, Bitwarden |
| `maxTextLength` | 100 000 caracteres |
| `oversizedTextIsDirty` | `true` |

Política sem o bloco vale como `Off`. No console, o campo `clipboard` (`desligado`, `alertar`, `bloquear`) vira
`mode` (ver [console-agente.md](../console-agente.md)).

## Pipe `\\.\pipe\SafeUpload.Agent.Clipboard`

NDJSON, separado dos outros pipes.

| Mensagem | Leva | Devolve | Prazo |
|---|---|---|---|
| `classify` | texto, tamanho real, processo de origem | `copyId`, `dirty`, categorias, achados mascarados | 2 s |
| `paste` | `copyId`, processo de destino, `attempt` no Ctrl+V real | `verdict` (`Allow`, `AuditOnly`, `Block`), `eventId` | 500 ms |
| `state` | — | se o canal está ligado | — |

O texto não viaja de novo no `paste`: o serviço guarda o estado da cópia (origem, categorias, tamanho e versão da
política), nunca o texto. Teto de 200 000 caracteres por mensagem.

## Proxy OLE no App (`ClipboardPasteGuard`)

1. **Cópia suja com o canal ligado:** o App pega o `IDataObject` de quem copiou (`OleGetClipboard`), embrulha num
   proxy próprio e o instala como dono do clipboard (`OleSetClipboard`). Cópia limpa ou canal desligado: o conteúdo
   do usuário fica intacto.
2. **Ctrl+V:** o Windows chama o proxy a cada leitura. `ClipboardPasteGuardRules.DecideRead` decide: leitura do
   próprio agente recebe o original; o histórico do Windows (Win+V) é negado; qualquer outra leitura é uma colagem e
   o proxy pergunta o veredito ao serviço. `ClipboardPasteMemo` guarda a decisão por 1 s, para as várias leituras de
   um mesmo Ctrl+V virarem uma pergunta e um evento.
3. **Block:** entrega o aviso e nega os outros formatos. **Audit ou destino local:** entrega o original.
4. Depois de cada leitura de fora o proxy se reinstala, para a decisão não grudar na colagem seguinte.

Detalhes: o proxy vive numa thread STA própria; devolve HRESULT (`[PreserveSig]`) em vez de lançar exceção; guarda
texto e HTML só em memória enquanto está instalado (reserva para quem lê por Win32); o monitor ignora mudanças
feitas pelo próprio agente. Numa saída limpa o App devolve o `IDataObject` original; numa queda a cópia suja se perde,
sem vazar.

## Auditoria

| Fato | `verdict` | `notInspectedReason` |
|---|---|---|
| Colagem bloqueada | `Blocked` | — |
| Colagem que o `Audit` deixou passar | `AllowedWithoutInspection` | `clipboard_paste_audit_only` |
| Foco num destino de saída com cópia suja (App sem proxy) | `AllowedWithoutInspection` | `clipboard_focus_observed` |

Evento com `channel: "Clipboard"`: `fileName` e `extension` vazios, `sizeBytes` é o tamanho do texto,
`processName` é quem copiou e `destinationPath` é o processo onde se colou. O texto copiado nunca entra no evento
nem no log.

## Limites

- Só o App segura a proteção: fechado o App, as cópias seguintes ficam sem proteção.
- A cópia suja não aparece no histórico do Win+V (é o que impede colar de lá).
- Uma segunda colagem até 250 ms depois da primeira recebe o que foi entregue antes.
- Um programa sem janela que leia o clipboard é julgado pela janela em primeiro plano.
- O proxy OLE não tem teste de unidade; é validado à mão com os aplicativos reais.
