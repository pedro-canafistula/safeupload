# Clipboard — Fase 2: testes

Complementa [FASE-2-ARQUITETURA.md](FASE-2-ARQUITETURA.md). Este documento explica **como a prova de
conceito da colagem foi testada**, o que cada rodada provou, os defeitos que os testes acharam e o
que ficou sem prova.

## Resumo

| | |
|---|---|
| Técnica escolhida | **Proxy OLE** (`IDataObject` próprio com `[PreserveSig]`) que decide na hora da colagem |
| Aplicativos com resultado | Excel, Word, PowerShell, Edge, Chrome, Teams e WhatsApp |
| Onde rodou | Windows 11 build 26300, Office local. **Não** rodou no alvo (Windows 10 22H2) |
| Código do experimento | Programa descartável, **fora do repositório**. Nada do proxy entrou no produto nesta fase |
| Mudança no produto | `WhatsApp.Root` na lista padrão de saída, com teste (seção "No repositório") |
| Suíte do agente | 698 testes: **687 passando**, 4 ignorados e 7 falhas, **as mesmas 7 da `main`** nesta máquina (precisam de privilégio de symlink e de backup). Clipboard: **132 de 132** |

Como rodar a suíte:

```
dotnet test agente/SafeUpload.Agent.Tests
dotnet test agente/SafeUpload.Agent.Tests --filter "FullyQualifiedName~Clipboard"
```

## Como os testes foram feitos

A Fase 2 é uma prova de conceito: a pergunta era **se** dá para bloquear a colagem só no destino de
saída sem estragar o resto, e não como fica no App. Por isso os testes são **experimentos** num
programa C# descartável, e não testes xUnit.

**Cuidados em todas as rodadas**

- **Dados sintéticos.** CPF de teste `529.982.247-25` ou o texto `TESTE-ORIGINAL-123`. O programa
  registra só metadados (formato, quem leu, decisão), nunca o conteúdo.
- **O clipboard do usuário foi gravado em disco antes** de cada rodada e conferido depois. Uma queda
  no começo da fase apagou um texto do usuário; desde então isso é obrigatório.
- Nos apps de mensagem, só a **conversa consigo mesmo**, colando **sem apertar Enter**.

**Como se confere o resultado.** Cada método nasceu de um erro de conferência anterior:

| O que se mede | Como | Por que assim |
|---|---|---|
| Excel → Excel | Copia `A1:B5` (valores, fórmulas, cor, formato, negrito e o CPF em `A5`), cola em `D1` e lê as células por COM | **FIEL** = fórmula, cor, formato e negrito chegaram; **DEGRADADO** = só valores |
| PowerShell e Word | `Get-Clipboard -Raw` num processo novo; `Selection.Paste()` no Word por COM e leitura do documento | Leitores reais, pelo caminho OLE |
| Navegador | Página local cujo script escreve **no título da janela** o que recebeu (`ORIGINAL`, `AVISO`, vazia); o programa lê o título | A primeira versão relia a página pelo clipboard e **enganou**: a leitura registrada era a do próprio programa |
| Teams, WhatsApp e Chrome | **Manual**: o programa sobe o proxy, a pessoa cola e diz o que apareceu; o **rastro do proxy** confirma quem leu e o que recebeu | A automação do Teams por UI Automation travou e o `Ctrl+V` simulado não chegava ao Chrome |
| Leitor Win32 puro | Script com `OpenClipboard` e `GetClipboardData` | Reproduz sem o Teams o caminho que ele usa |

O **rastro** registra, em cada pedido ao proxy: formato, meio (`TYMED`), quem leu
(`GetOpenClipboardWindow`), o processo em primeiro plano e a decisão.

## Matriz técnica × aplicativo

| Técnica | Excel → Excel | Saída bloqueada | Liberado | Veredito |
|---|---|---|---|---|
| T1: segurar o clipboard (cópia Win32 + renderização atrasada) | **Degradado** | não medido | não medido | Descartada |
| T2: trocar pelo foco e restaurar por Win32 | **Degradado** | não medido | não medido | Descartada |
| T2 com restauração por OLE | FIEL | — | — | Viável, mas troca o conteúdo para todos |
| **Proxy OLE** (versão final) | **FIEL** | **Aviso** em PowerShell, Word, Edge, Chrome, Teams e WhatsApp | **Original** nos mesmos | **Escolhida** |

## Rodadas, na ordem

### 1. Excel → Excel (12/10/2026)

| ID | O que foi feito | Resultado |
|---|---|---|
| B0 | Linha de base, sem agente | FIEL (o Excel publica 30 formatos) |
| R1 | T1: cópia de 26 formatos (136 KB, 123 ms) e renderização atrasada | **Degradado**: ao perder a posse, o Excel zera o `CutCopyMode` |
| R2 | T2: aviso e depois restaura por Win32 | **Degradado** |
| R3 | Proxy que só repassa ao original | **FIEL**: o original continua servindo depois de perder a posse |
| R4 | Controle: dono só com texto | Degradado (esperado) |
| R5a, R5c | T2 restaurando por OLE, depois de 300 ms e de 5 s | FIEL |

### 2. Proxy que bloqueia (12/10/2026)

| ID | O que foi feito | Resultado |
|---|---|---|
| P1, P2 | Proxy com a interface gerenciada padrão, negando por **exceção** | **Instável**: o Word recebeu o original, o Excel passou a falhar ao colar e uma rodada caiu com violação de acesso |
| Q1, Q2 | Mesma ideia com interface própria `[PreserveSig]`, negando por `HRESULT` | **Estável**: Excel FIEL em qualquer ordem; PowerShell e Word com aviso, também na segunda leitura |

### 3. Navegador e decisão pelo primeiro plano (12/10/2026)

| ID | Edge | Resultado |
|---|---|---|
| Controle | Sem proxy | `ORIGINAL` (o método enxerga a colagem) |
| E1, E3 | Saída (texto e HTML) | **Aviso** |
| E2, E4 | Liberado, proxy só repassando | **Colagem vazia**: o original devolve `0x800401D0` |

Quem lê aparece como **ninguém** para o Edge: só o primeiro plano identifica o destino.

### 4. Morte do processo dono do proxy (12/10/2026)

Proxy num processo filho, morto à força antes (D2) e depois (D1) de colagens. Nos dois: o clipboard
fica **sem dono e sem texto**; PowerShell lê nada, o Word falha ao colar, o Excel continua FIEL pela
cópia interna. **Não vaza, mas perde o conteúdo.** A equipe aceitou a perda (decisão 18).

### 5. Cópia guardada e decisão que gruda (12/10/2026)

| ID | O que foi feito | Resultado |
|---|---|---|
| F1 | Proxy repassando, leitores pelo OLE | PowerShell e Word com o original; Excel FIEL |
| G1 | Proxy com **cópia guardada** de texto, HTML e RTF | Edge liberado volta a colar |
| H1 | Edge liberado → Edge saída | **Vazou**: a segunda colagem nem passou pelo proxy |
| H2 | Edge saída → Edge liberado | **Aviso nas duas**: colagem legítima perdida |

### 6. Reinstalar depois de cada colagem (12/10/2026)

| ID | Ordem (Edge) | 1ª | 2ª | 3ª |
|---|---|---|---|---|
| I1 | liberado → saída → liberado | original | aviso | original |
| I2 | saída → liberado → saída | aviso | original | aviso |

Custo medido: 2 a 3 ms e **um** aviso de mudança por colagem; parado, nada. A primeira versão entrou
em **laço** (41 reinstalações em 6 s) porque as leituras do próprio OLE também reinstalavam.

### 7. Teams (13 e 19/10/2026)

| Data | Situação | Resultado |
|---|---|---|
| 13/10 | Automação por UI Automation | Sem resultado: o Teams parou de responder à acessibilidade |
| 13/10 | Manual | A decisão saiu certa, mas **nada apareceu** na caixa |
| 19/10 | Manual, com a lista de formatos corrigida | **Vazou**: o histórico do Windows pegou o original antes |
| 19/10 | Manual, com o histórico negado | ✅ Ver tabela abaixo |

| Passo (19/10) | Teams | Resultado |
|---|---|---|
| 1 | Saída | **Aviso** (duas colagens) |
| 2 | Liberado (proxy novo) | **Original** |
| 3a e 3b | Liberado e depois saída, **mesmo proxy** | **Original**, depois **aviso** |

### 8. Chrome e WhatsApp (19/10/2026, manual)

Mesmo método, saída → liberado → saída no mesmo proxy. Chrome numa página local
`data:text/html,<textarea>`; WhatsApp na conversa consigo mesmo.

| App | Saída | Liberado | Saída de novo |
|---|---|---|---|
| Chrome | **Aviso** | **Original** | **Aviso** |
| WhatsApp (`WhatsApp.Root`) | **Aviso** | **Original** | **Aviso** |

### 9. Regressão depois das correções de 19/10

Q1, I1, I2 e F1 repetidos com a versão final do proxy: **todos certos**. Uma rodada do I2 ficou sem
resultado porque o `Ctrl+V` simulado não chegou ao Edge (o rastro não tem leitura nenhuma); a
repetição passou.

## Defeitos que os testes acharam

| # | Defeito | Como apareceu | Correção |
|---|---|---|---|
| 1 | Negar por exceção num `IDataObject` gerenciado | P1/P2: vazamento, Excel quebrado, queda | Interface própria com `[PreserveSig]` e `HRESULT` |
| 2 | "Decide por quem lê" não funciona | Edge e Teams: quem lê aparece como ninguém | Decidir pelo **primeiro plano** |
| 3 | Repasse ao Excel falha para leitores Win32 | E2/E4: colagem vazia, `0x800401D0` | **Cópia guardada** dos formatos de texto |
| 4 | A primeira entrega fica guardada no sistema | H1 vazou, H2 perdeu a colagem | **Reinstalar** o proxy depois de cada leitura de fora |
| 5 | Laço com as leituras do próprio OLE | 41 reinstalações em 6 s | Só leitura de **fora** reinstala |
| 6 | Laço com o histórico do Windows | 40 reinstalações a cada ~0,5 s (Teams, 13/10) | Leitura do `svchost` não reinstala |
| 7 | Aviso entregue no meio errado | Teams não colou nada | Entregar no meio pedido |
| 8 | Texto anunciado como fluxo e como memória | Leitor Win32 recebia `NULL` | Lista de formatos **própria**, com `TYMED_HGLOBAL` |
| 9 | Histórico do Windows recebia o original | Teams colou o original sem consultar o proxy | **Negar** a leitura do `svchost` para conteúdo sujo |
| 10 | `WhatsApp.Root` fora da lista de saída | Nome do processo no teste do WhatsApp | **Corrigido no produto** (abaixo) |

Os defeitos 1 a 9 são do proxy experimental e viram **regras obrigatórias** para a Fase 3. O 10 é do
produto atual e afeta já a Fase 1.

## No repositório

| Arquivo | O que mudou | Teste |
|---|---|---|
| `Core/Infrastructure/PolicyDocument.cs` | `WhatsApp.Root` na lista padrão de `egressDestinations`; o comentário registra os nomes conferidos | — |
| `Tests/ClipboardPolicyTests.cs` | Novo `Politica_padrao_trata_os_apps_conferidos_como_saida`, com `WhatsApp.Root`, `WhatsApp.Root.exe`, `ms-teams` e `msedge` | 4 casos, passando |

## Limites: o que estes testes não provam

- **Nada rodou no Windows 10 22H2**, que é a plataforma do driver.
- **O proxy não está no App.** Integração com o pipe, o serviço, a auditoria e a notificação é da
  Fase 3.
- **Leitor em segundo plano** (script sem janela) não é identificado pelo primeiro plano; recebe o
  original quando a janela da frente não é saída.
- **Corrida de 250 ms:** uma segunda colagem logo depois da primeira recebe o que foi entregue antes.
- **App fechado pelo usuário:** com o proxy fora, não há proteção.
- **Win+V:** com o histórico negado, a cópia suja não aparece no histórico. Não foi testada a API de
  histórico (E7).
- **Não medidos:** Firefox, Telegram, Slack, Discord e Outlook novo (nomes de processo não
  conferidos), apps abertos como administrador (E9), prazo do `WM_RENDERFORMAT` com o agente lento.
- Teams, Chrome e WhatsApp foram testados **à mão**, com três colagens cada; é uma amostra pequena.

## Pendente

| Ponto | Com quem |
|---|---|
| O agente guardar o texto sujo na memória enquanto o proxy está ativo (RN-006) | Equipe |
| Aceitar que a cópia suja não apareça no Win+V | Equipe |
| O serviço vigiar e reabrir o App fechado | Equipe |
| Conferir os nomes de processo de Telegram, Slack, Discord e Outlook novo | Clipboard |
| O backend voltar a publicar o bloco `clipboard` (removido em 19/10/2026) | Backend |
| Repetir os testes principais no Windows 10 22H2 | Equipe |
