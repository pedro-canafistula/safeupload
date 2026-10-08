# Clipboard — Fase 1: marcar sujo e medir

Estado: **implementada e testada**, na branch `feat/clipboard-fase1`. O teste
manual com Excel, Word, Chrome, Edge e Bloco de Notas foi feito em 7/10/2026 e
passou (ver [Resultado do teste manual](#resultado-do-teste-manual)).

Parte das decisões e dos contratos da [Fase 0](FASE-0-DEFINICOES-E-CONTRATOS.md).

## Objetivo

O App ouve o Ctrl+C (`AddClipboardFormatListener`) e envia o texto ao serviço,
que classifica e devolve sujo ou limpo. **Nada muda para o usuário**: o serviço
não grava auditoria, não notifica e não bloqueia.

Medir:

- quantas cópias ficam sujas;
- quantas vezes o foco vai para um destino de saída com o clipboard sujo.

## O que foi implementado

**Serviço** (`agente/SafeUpload.Agent.Service/Clipboard/`)

| Arquivo | Papel |
|---|---|
| `ClipboardService` | Atende `classify` e `paste`: lê a política, pede a decisão a `ClipboardRules`, guarda o estado da cópia e conta. Não conhece o pipe, então é testável sem abrir um. |
| `ClipboardCopyStore` | Guarda a **última cópia de cada sessão do Windows**: identificador, se está suja e quem copiou. **Não guarda o texto.** Uma cópia nova substitui a anterior. |
| `ClipboardMetrics` | Os dois contadores da fase. |
| `ClipboardPipeServer` | O pipe `SafeUpload.Agent.Clipboard`. Uma conexão, um pedido, uma resposta; a ACL segue a dos outros canais. |

**App** (`agente/SafeUpload.Agent.App/ClipboardWatch/`)

| Arquivo | Papel |
|---|---|
| `ClipboardMonitor` | Janela só de mensagens que escuta `WM_CLIPBOARDUPDATE`, mais um gancho de foco (`SetWinEventHook`, `EVENT_SYSTEM_FOREGROUND`). Roda na thread da interface. |
| `ClipboardPipeClient` | Pergunta ao serviço. Uma conexão por pergunta; **qualquer falha vira `null`**, que o monitor trata como "limpo". |

**Contrato** (`Core/Contracts/ClipboardProtocol.cs`): `ReadLineAsync`, uma
leitura de linha com teto de tamanho, usada pelos dois lados. O `ReadLineAsync`
padrão não tem teto, e um processo do usuário que nunca mandasse a quebra faria
o serviço acumular memória.

**Registro:** `Program.cs` do serviço (3 singletons e 1 hosted service) e
`App.xaml.cs` (inicia e encerra o monitor). O resto fica em arquivos próprios,
para não colidir com os outros trabalhos no serviço.

## Como funciona

```
Ctrl+C
  └─ App: WM_CLIPBOARDUPDATE → espera 120 ms (agrupa a rajada) → lê o texto
       └─ pipe "classify" ─► Serviço: ClipboardRules.Classify → guarda a cópia
            ◄─ copyId, dirty, categories, findings mascarados
       └─ App guarda (copyId, dirty)

Troca de foco, com o clipboard sujo
  └─ App: processo da janela em primeiro plano (ignora o próprio App)
       └─ pipe "paste" (sonda) ─► Serviço: ClipboardRules.DecidePaste → conta
            ◄─ verdict (o App da Fase 1 o ignora)
```

Os dois contadores:

| Contador | Quando conta |
|---|---|
| Cópias / cópias sujas | A cada cópia classificada com o canal ligado. |
| Foco em destino de saída com o clipboard sujo | Quando o foco vai para um processo que `DecidePaste` considera saída (`AuditOnly` ou `Block`). Estima quantos bloqueios o modo Block faria. |

O serviço registra uma linha de log por cópia suja e uma por foco em saída, com
os totais acumulados. As linhas têm categorias, nomes de processo e contagens;
**nunca o texto nem o trecho achado**.

## Decisões

| Decisão | Por quê |
|---|---|
| **`paste` serve como sonda de foco.** O App o envia quando o foco muda, e o serviço só conta. | A fase precisa medir "foco em destino de saída com o clipboard sujo" sem criar uma mensagem nova no protocolo. |
| **Uma conexão por pergunta.** | O App pergunta em cadência humana, então o custo é baixo, e não há estado de conexão a reconectar nem a travar. |
| **O serviço não guarda o texto**, só o identificador e o estado. | O clipboard sujo é um dado sensível. Uma segunda cópia no serviço (LocalSystem) seria mais um lugar de vazamento (RN-006). |
| **Agrupar a rajada de avisos em 120 ms.** | Uma única cópia dispara mais de um `WM_CLIPBOARDUPDATE` (o WPF e muitos apps limpam e escrevem em seguida). Sem agrupar, uma cópia virava duas no contador. Achado no teste com o clipboard real. |
| **Uma sonda por (cópia, destino).** | Alt+Tab para a mesma janela, ou o Windows reanunciando o foco, não são duas trocas. |
| **O próprio App é ignorado como destino.** | É o visor do agente, e a política o exclui (RN-014). |
| **Sem auditoria.** | O serviço não grava evento, não notifica e não bloqueia. Os contadores vivem na memória. |
| **Cópia que não é texto limpa o estado.** | Imagem ou arquivos também substituem um clipboard sujo anterior. |
| **Clipboard que não abre = estado desconhecido, tratado como limpo.** | Não se afirma "sujo" sem ter lido (RN-013). O App tenta 5 vezes, a cada 40 ms. |
| **Cada sessão do Windows enxerga só a própria cópia.** | O clipboard é por sessão. |

## Verificação

- **269 testes passam** (243 anteriores e 26 novos), compilação sem avisos:
  - `ClipboardServiceTests`: classificação, texto grande, fonte excluída, canal
    desligado, política que falha, contadores, sessões, e que o texto não
    aparece em nenhum log.
  - `ClipboardPipeTests`: pipe real com classify e sonda de foco, 20 conexões
    seguidas, linha malformada, linha acima do teto, tipo desconhecido e a
    leitura de linha com teto.
- **Teste com o clipboard real do Windows**, num harness descartável (o monitor
  e o serviço no mesmo processo): CPF suja; foco em destino de saída conta 1;
  repetir a mesma troca não conta de novo; texto limpo volta a limpo; serviço
  parado não derruba o App. O harness não está no repositório; o que ele provou
  fica registrado aqui.

| Critério de entrega | Situação |
|---|---|
| Copiar um CPF marca sujo | ✅ Teste e harness |
| Copiar texto limpo volta a limpo | ✅ Teste e harness |
| O texto copiado não aparece em log, fila ou pipe de notificação | ✅ Teste (`Texto_copiado_nao_aparece_em_nenhum_log`); a resposta também não o leva |
| Os contadores estimam os bloqueios do modo Block | ✅ Contam; aparecem no log do serviço |
| Teste com Excel, Word e Chrome de verdade | ✅ Teste manual de 7/10/2026 ([resultado](#resultado-do-teste-manual)) |

## Como testar manualmente (Excel e Chrome)

1. Em `%ProgramData%\SafeUpload\policy.json`, ponha `"mode": "Audit"` no bloco `clipboard`.
2. Suba o serviço em modo console, lendo o arquivo local:
   ```
   dotnet run --project agente/SafeUpload.Agent.Service -- --CentroAdministracao:BaseUrl=
   ```
   **O `--CentroAdministracao:BaseUrl=` é necessário.** O `appsettings.json`
   aponta para o painel (`http://127.0.0.1:8080/agent/`), e com isso a política
   viria de lá, e não do arquivo. O serviço relê a política a cada pedido, então
   não precisa reiniciar para trocar o modo.
3. Suba o App: `dotnet run --project agente/SafeUpload.Agent.App`.
4. Cenários:

| Cenário | Esperado no log do serviço |
|---|---|
| Excel: copiar uma célula com `529.982.247-25` e ir para o Chrome | `Clipboard sujo: ... [Cpf], origem EXCEL`, depois `Foco em destino de saida ... chrome ... AuditOnly` |
| O mesmo, indo para o Word | Só "Clipboard sujo"; nenhuma linha de foco |
| Copiar `reunião às 14h` e ir para o Chrome | Nenhuma linha |
| Copiar o CPF, depois um texto limpo, e ir para o Chrome | Só a linha "sujo" da primeira cópia |
| Bloco de Notas → Chrome com CPF | As duas linhas, origem `Notepad` |

Não salve arquivo com CPF em `C:\SafeUpload\Escopo Monitorado` durante o teste:
o serviço também vigia essa pasta e apaga o que bloqueia.

### Resultado do teste manual

Feito em 7/10/2026, no PC de desenvolvimento, com o serviço em modo console
(`--CentroAdministracao:BaseUrl=`), o App na bandeja, `mode: Audit` e Excel, Word,
Chrome e Edge instalados. O log do serviço terminou com **0 avisos e 0 erros**, e o
App não imprimiu nada.

**Passos isolados**, uma ação por vez, comparando o log antes e depois:

| Passo | Esperado | Obtido |
|---|---|---|
| 1. Um Ctrl+C no Excel numa célula com `529.982.247-25` | 1 linha "sujo" | ✅ `Copias 9, sujas 8` (+1 em cada) |
| 2. Um Ctrl+C no Excel com `reunião às 14h` | Nenhuma linha | ✅ Nenhuma linha |
| 3. CPF copiado de novo; foco no Word; foco no Chrome | "sujo" e foco **só** no Chrome | ✅ `Copias 11, sujas 9` e uma linha de foco para `chrome`; nenhuma para o Word |

O `Copias 11, sujas 9` do passo 3 fecha a conta: de 9 para 11, uma cópia limpa
(passo 2, sem log) e uma suja. Isso prova que a cópia limpa **foi** classificada.

**Totais do teste inteiro:**

| Medida | Valor |
|---|---|
| Cópias classificadas | 11 (9 sujas, 2 limpas) |
| Sujas por origem | 8 `EXCEL`, 1 `Notepad` |
| Focos em destino de saída com o clipboard sujo | 8: 6 `chrome` e 2 `msedge`, todos `AuditOnly` |
| Trocas de foco com o clipboard sujo | 64 |

**Conclusões**

- O Excel é detectado de forma confiável: 8 cópias com CPF, todas marcadas, com
  origem `EXCEL`. O risco da renderização atrasada do Office (o texto só é gerado
  quando alguém o pede, e o App o perderia) não se concretizou.
- **Um Ctrl+C gera uma classificação**, e não duas. Isso confirma, com o Excel
  real, que agrupar a rajada em 120 ms basta.
- O Word não conta como saída; o Chrome e o Edge contam; o Bloco de Notas
  funciona como origem. O Excel → Word não gerou linha de foco.
- Texto limpo não gera log, mas é contado (`Copias` avança).

**Não testado:** copiar com a célula do Excel em modo de edição (cursor dentro da
célula, ou texto selecionado na barra de fórmulas).

## Limites conhecidos

- **Os contadores aparecem só no log do serviço e zeram ao reiniciar.** Não há
  painel nem persistência. Servem para estimar volume, não para auditoria.
- **Com `mode: Off` o App ainda envia o texto ao serviço**, que o descarta e
  responde "limpo". O texto só trafega no pipe local, mas o contrato não tem como
  o serviço dizer "canal desligado, não envie".
- **O gancho de foco conta qualquer processo com janela**, inclusive de apps da
  loja (`ApplicationFrameHost`), do terminal e deste chat. Por isso o total de
  "trocas de foco com o clipboard sujo" é ruidoso (64 no teste manual, contra 8
  em destino de saída). **A medida que importa é a de foco em destino de saída**;
  o total serve só como denominador aproximado.
- **Só texto.** Imagem, arquivos e HTML formatado não são varridos; uma cópia
  assim apenas limpa o estado.
- Um texto de centenas de MB é carregado inteiro por `Clipboard.GetText` antes
  de ser cortado no teto do protocolo.

## Pontos em aberto

| Ponto | Com quem |
|---|---|
| A criação do pipe em `ClipboardPipeServer.ExecuteAsync` fica fora do tratamento de erro: se falhar (por exemplo, acesso negado), a exceção derruba o serviço inteiro, inclusive a proteção de arquivos. Os outros dois canais têm o mesmo padrão. A corrigir antes do merge | Equipe do agente |
| O serviço poder dizer "canal desligado" para o App não enviar o texto | Equipe do agente |
| Mostrar os contadores no painel do agente, em vez de só no log | A definir |
