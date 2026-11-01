# Clipboard — Fase 3: bloqueio na colagem por destino

A Fase 1 marcava a cópia suja e media; a Fase 2 provou a técnica fora do produto. A Fase 3 leva a
técnica para o agente e **liga os modos Audit e Block**: no Ctrl+V de um clipboard sujo, o agente
decide pelo destino. Testes da técnica e roteiro manual: [FASE-3-TESTES.md](FASE-3-TESTES.md).

## O que o usuário vê

| Situação | Modo Block | Modo Audit | Modo Off (padrão) |
|---|---|---|---|
| Colar CPF num navegador, Teams, WhatsApp | **Aviso** no lugar do texto, balão na bandeja, evento | Cola normal, evento | Nada |
| Colar CPF no Word, Excel, Bloco de Notas | Cola normal | Cola normal | Nada |
| Colar texto comum em qualquer lugar | Cola normal | Cola normal | Nada |

O aviso é `[SafeUpload] conteúdo bloqueado — a cópia contém dado sensível.` (`ClipboardPasteGuard.WarningText`).

## As duas metades

A Fase 3 foi feita em dois commits, pela mesma razão que separou medir de bloquear: o que dá para
testar por unidade de um lado, o código de Windows do outro.

- **3a — protocolo, serviço, auditoria e regras** (Core e serviço). Funções puras e testadas.
- **3b — o proxy no App** (`ClipboardPasteGuard`). Código COM, validado à mão.

## 3a — o contrato e a decisão

### O Ctrl+V de verdade, separado da sonda de foco

Na Fase 1, o pedido `paste` do protocolo era uma **sonda de foco**: "o usuário foi para este
processo com o clipboard sujo", contada e sem efeito. Na Fase 3, o App faz um `paste` de verdade no
Ctrl+V. Para não misturar as duas coisas, o pedido ganhou o campo opcional `attempt`
(`ClipboardRequest.PasteAttempt`):

- com `attempt`, é um Ctrl+V de verdade: usa a mesma decisão, mas é contado à parte e o veredito
  volta para o App aplicar;
- sem `attempt`, continua sendo a sonda de foco.

É compatível nos dois sentidos: um App antigo não envia o campo, e um serviço antigo o ignora e
trata tudo como sonda, que libera (RN-013).

### A decisão e a auditoria

A decisão é a mesma da Fase 1 (`ClipboardRules.DecidePaste`): destino fora da lista de saída →
`Allow`; na lista → `Block` ou `AuditOnly`, conforme o modo. O que mudou é o registro:

| Fato | `Verdict` do evento | `NotInspectedReason` |
|---|---|---|
| Colagem bloqueada (Block) | `Blocked` | nulo, como um arquivo bloqueado |
| Colagem que o Audit deixou passar | `AllowedWithoutInspection` | `clipboard_paste_audit_only` |
| Sonda de foco (Fase 1, inalterada) | `AllowedWithoutInspection` | `clipboard_focus_observed` |

O texto copiado nunca entra no evento nem no log (RN-006). A ponte é `ClipboardAudit.WriteAsync`, no
serviço; o Core só devolve a observação.

**Nota de contrato.** A colagem em Audit usa `AllowedWithoutInspection` porque o enum `Verdict` não
tem "liberado com registro". O painel a conta como "liberado sem inspeção", como já faz com a sonda
de foco. Um veredito novo mexeria no contrato com o backend — decisão a confirmar com o painel.

### As regras do proxy, no Core

O proxy (3b) precisa decidir cada leitura do clipboard, e essas regras são puras e testadas em
`ClipboardPasteGuardRules.DecideRead`, uma por comportamento medido na Fase 2:

| Quem lê | Decisão | Reinstala? |
|---|---|---|
| O próprio agente (o OLE lê descritores ao instalar) | Entrega o original | Não (senão vira laço) |
| O serviço de histórico do Windows (`svchost`, Win+V) | **Nega** | Não |
| Qualquer outro | É uma colagem: destino = quem lê ou, se ninguém, a janela em primeiro plano | Sim |

`ClipboardPasteMemo` guarda a decisão de uma colagem por 1 s, para as várias leituras de um mesmo
Ctrl+V (texto, HTML, imagem, descritores) renderem uma pergunta ao serviço e um evento só.

## 3b — o proxy no App (`ClipboardPasteGuard`)

### Fluxo

1. **Cópia suja, canal ligado.** Ao classificar a cópia (`ClipboardMonitor`), se ela é suja e o
   canal está ligado, o agente toma a posse: `OleGetClipboard` pega o `IDataObject` do aplicativo
   que copiou, e um proxy próprio o embrulha e vira o dono (`OleSetClipboard`). Uma cópia limpa, ou
   o canal desligado, larga a posse e o conteúdo do usuário fica intacto.
2. **Ctrl+V.** O aplicativo de destino pede os dados ao clipboard, e o Windows chama o proxy. A cada
   leitura, as regras do Core decidem. Numa colagem, o proxy pergunta ao serviço (pelo pipe) qual é
   o veredito do destino.
3. **Block.** O proxy entrega o aviso em vez do texto e nega os outros formatos; o App mostra o
   balão. **Audit ou app local:** entrega o original (ou a cópia guardada, para quem lê por Win32).
4. **Reinstala.** Depois de cada leitura de fora, o proxy se reinstala, para o Windows não guardar a
   entrega e a decisão não "grudar" na colagem seguinte.

### Decisões de implementação

- **Thread STA própria.** O OLE entrega as leituras na thread que chamou `OleSetClipboard` e exige
  que ela bombeie mensagens. Para não travar a interface do WPF durante uma colagem, o proxy vive
  numa STA dedicada, com seu próprio laço de mensagens (uma janela oculta).
- **`[PreserveSig]` e HRESULT.** O proxy devolve código de erro em vez de lançar exceção: negar por
  exceção num objeto gerenciado derrubou o processo na Fase 2.
- **Cópia guardada em memória (RN-006).** Na instalação, o proxy guarda os formatos de texto e HTML,
  para servir de reserva a quem lê por Win32 (cujo repasse ao original falha com `0x800401D0`). Fica
  **só em memória**, enquanto o proxy está instalado, e some na cópia seguinte. Nunca em disco nem
  log.
- **O monitor ignora a si mesmo.** Instalar e reinstalar o proxy muda o clipboard e dispara o aviso
  de mudança. O monitor checa se o dono é o próprio agente (`ClipboardPasteGuard.OwnsClipboard`) e
  ignora, senão reclassificaria o próprio aviso em laço.
- **A pergunta é a auditoria.** Perguntar ao serviço no Ctrl+V é o que registra o evento, uma vez
  por colagem graças à memória. Com o proxy instalado, a sonda de foco da Fase 1 é desligada, para
  não duplicar.

### Devolução ao fechar

Numa saída limpa do agente, o proxy devolve o `IDataObject` original ao clipboard
(`ClipboardPasteGuard.HandBack`), para o usuário não perder o que copiou. Numa queda, não há como, e
a cópia suja se perde **sem vazar** (é falha segura). Isso é a decisão 18 da Fase 2 em vigor.

## Limites conhecidos

- **Só o App segura a proteção.** O App roda na sessão do usuário e pode ser fechado sem
  administrador. Com ele fora, as cópias seguintes ficam sem proteção. Mitigação proposta: o serviço
  vigiar e reabrir o App (vale para todos os canais que dependem dele). Fora desta fase.
- **A cópia suja não aparece no histórico do Win+V.** É o que impede o contorno (copiar, abrir o
  Win+V e colar de lá); o efeito colateral é a cópia suja não ficar no histórico.
- **Corrida de 250 ms.** Uma segunda colagem nesse intervalo após a primeira recebe o que foi
  renderizado antes.
- **Leitor em segundo plano.** Um programa sem janela que leia o clipboard não é identificado pelo
  primeiro plano e recebe o original quando a janela da frente não é saída.
- **Plataforma.** Validado no Windows 11 build 26300. O alvo do driver é o Windows 10 22H2, onde os
  testes principais ainda não rodaram.
- **O proxy OLE não tem teste de unidade.** A validação dele é manual ([FASE-3-TESTES.md](FASE-3-TESTES.md)).

## Pendências

| Ponto | Com quem |
|---|---|
| O serviço vigiar e reabrir o App fechado | Equipe |
| Veredito próprio para colagem em Audit, ou manter `AllowedWithoutInspection` | Painel |
| Conferir os nomes de processo de Telegram, Slack, Discord e Outlook novo | Clipboard |
| O backend voltar a publicar o bloco `clipboard` (removido em 19/10/2026) | Backend |
| Repetir os testes manuais no Windows 10 22H2 | Equipe |
