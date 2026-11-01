# Clipboard — Fase 2: prova de conceito da colagem (arquitetura)

Estado: **desenho feito, nada implementado nem medido.** Este documento registra a
arquitetura proposta para a prova de conceito. Nenhum experimento foi rodado e
nenhuma das hipóteses abaixo foi confirmada.

Parte do contrato e das decisões da [Fase 0](FASE-0-DEFINICOES-E-CONTRATOS.md) e do que se
mediu na [Fase 1](FASE-1-MARCAR-SUJO-E-MEDIR.md).

## Como ler este documento

O desenho foi produzido por um agente arquiteto (modelo `opus`; a versão exata não foi
confirmada), lendo o código e os documentos das Fases 0 e 1. **Quase todas as afirmações
sobre Win32, OLE, Excel e o histórico do Windows vêm do conhecimento do modelo e não foram
conferidas.** A única verificação na documentação da Microsoft foi a página *Clipboard
Formats*, na parte dos formatos de histórico e de nuvem.

Cada afirmação técnica vem marcada:

| Marca | Significa |
|---|---|
| **[CONHECIDO]** | Comportamento estabelecido do Windows, no qual o arquiteto tem confiança alta. **Não quer dizer que foi verificado nesta sessão**: vem do conhecimento do modelo |
| **[CONFERIDO]** | Verificado na documentação da Microsoft. É a única marca que quer dizer "verificado" |
| **[INFERIDO]** | Dedução razoável, ainda sem confirmação |
| **[A MEDIR]** | Não se sabe; só um experimento responde |

Marcas combinadas, como **[CONHECIDO/INFERIDO]**, indicam que parte da afirmação é
conhecida e parte é dedução. Uma marca seguida de um motivo, como
**[INFERIDO, alta confiança]**, qualifica a afirmação.

## Objetivo

Testar as duas formas de saber onde o usuário está colando e escolher uma, **num protótipo
fora do App**.

- **Técnica 1, segurar o clipboard (delayed rendering):** o App vira dono do clipboard sujo
  e só entrega o texto no `WM_RENDERFORMAT`, conferindo a janela em primeiro plano.
- **Técnica 2, trocar pelo foco:** com o clipboard sujo, ao focar um destino de saída o App
  troca o conteúdo por um aviso e restaura ao voltar.

Testar com Excel, Word, Bloco de Notas, Chrome e Teams. Critérios obrigatórios:

- Excel → Excel mantém fórmulas e formatação.
- Colar no Word e logo depois no Chrome: as duas colagens são vistas (rearmar após cada entrega).
- Win+V não guarda texto sujo.

**Entrega:** tabela técnica × aplicativo com o resultado de cada teste, a técnica escolhida
registrada e o que não dá para controlar.

## Restrições que já valem

- O Ctrl+C não bloqueia nada; o clipboard só é marcado "sujo" (por conteúdo). O bloqueio é
  no Ctrl+V, só para destino de **saída**. Destino desconhecido libera. Mesmo processo de
  origem e destino libera.
- **RN-013:** a falha sempre libera.
- **RN-006:** o texto copiado nunca é guardado, logado nem devolvido.
- **Quem decide é o serviço; o App só observa e aplica.** Hoje o App **não escreve** no
  clipboard de propósito. As duas técnicas quebram essa garantia (ver
  [Modelo de confiança](#modelo-de-confiança-e-contrato)).
- O pedido `paste` do protocolo (`copyId` + processo de destino → `Allow`/`AuditOnly`/`Block`,
  prazo de 500 ms) já existe e, na Fase 1, serve de sonda de foco.

## Alerta de ambiente

O PC de desenvolvimento onde a Fase 1 foi testada roda **Windows 11 (build 26300,
Insider)**. O alvo do agente é o **Windows 10 22H2** (o PR #24 do driver diz que o MVP foi
qualificado **só** no build 19045.2965 x64; para o agente como um todo, o alvo
continua sendo uma decisão a confirmar). O Bloco de Notas, o
Win+V e o serviço de histórico mudam entre as duas versões. **A matriz precisa rodar no
Windows 10 22H2, numa VM.** Resultados no Windows 11 são só um primeiro sinal.

## Comparação das técnicas

### Como cada uma funciona

**Técnica 1: segurar o clipboard**

Há duas formas de ficar com o clipboard:

- **Win32:** `OpenClipboard(hwnd)` → `EmptyClipboard()` → `SetClipboardData(fmt, NULL)` para
  cada formato → `CloseClipboard()`. O `hwnd` passa a ser o dono **[CONHECIDO]**.
- **OLE:** `OleSetClipboard(IDataObject)`. O OLE cria uma janela oculta
  (`CLIPBRDWNDCLASS`) na thread STA de quem chamou e anuncia os formatos de forma atrasada.
  Quando alguém pede um formato, o OLE chama o `IDataObject::GetData` **[CONHECIDO/INFERIDO]**.

O que acontece depois:

- Quando um processo chama `GetClipboardData(fmt)`, o sistema manda `WM_RENDERFORMAT(fmt)` ao
  dono **de forma síncrona**, e quem pediu fica parado **[CONHECIDO]**. O dono responde com
  `SetClipboardData(fmt, h)`, sem abrir o clipboard **[CONHECIDO]**.
- `IsClipboardFormatAvailable`, `EnumClipboardFormats` e `CountClipboardFormats` **não**
  pedem renderização **[CONHECIDO]**.
- Se alguém chama `EmptyClipboard`, o dono perde a posse e recebe `WM_DESTROYCLIPBOARD` **[CONHECIDO]**.
- Quando a janela dona vai ser destruída ainda com formatos pendentes, chega
  `WM_RENDERALLFORMATS` **[CONHECIDO]**. Se o processo é **morto à força**, nada chega: os formatos
  continuam anunciados, mas `GetClipboardData` devolve `NULL` **[CONHECIDO/INFERIDO]**.
- Depois de renderizado, o dado **fica no clipboard**. A próxima colagem não gera
  `WM_RENDERFORMAT` **[CONHECIDO]**. Por isso o **rearme** (tomar a posse e anunciar tudo de novo) é
  obrigatório depois de cada entrega.
- Não se sabe se existe prazo para o dono responder ao `WM_RENDERFORMAT` **[A MEDIR]**.

**Técnica 2: trocar pelo foco**

1. `SetWinEventHook(EVENT_SYSTEM_FOREGROUND)` avisa da troca de janela. Isso já foi provado
   na Fase 1.
2. Com o destino na lista de saída, o App guarda **todos os formatos** do clipboard e escreve
   um aviso em `CF_UNICODETEXT`.
3. Quando o foco sai da saída, o App restaura o que guardou.

Não há como manter uma referência "viva" ao dado de origem depois que outro processo chama
`EmptyClipboard`. É quase certo que o `IDataObject` devolvido por `OleGetClipboard` lê do
clipboard Win32 atual **[INFERIDO]**, então a restauração exige uma **cópia completa** guardada antes.

### O que cada uma sabe sobre o destino

| | T1 (segurar) | T2 (trocar pelo foco) |
|---|---|---|
| Momento da decisão | **Na colagem.** Qualquer via que leia o clipboard passa por `WM_RENDERFORMAT` | **Na troca de foco.** Não sabe se houve colagem |
| Quem lê o clipboard | Durante o `WM_RENDERFORMAT`, `GetOpenClipboardWindow()` aponta a janela de quem abriu o clipboard. Pode vir `NULL` quando o leitor usou `OpenClipboard(NULL)` **[A MEDIR]**. No caminho OLE, talvez dê para achar o PID de quem chamou **[A MEDIR]** | Não sabe. Supõe que é a janela em primeiro plano |
| Leitor em segundo plano (gerenciador de clipboard, histórico do Windows, script) | Percebe, se o leitor for identificável | **Não percebe:** com o Word em foco, o leitor recebe o dado real |
| Apps com WebView2 (Teams novo `ms-teams`, Outlook novo `olk`) | O leitor provável é `msedgewebview2`, que não está na lista de saída e libera **[INFERIDO/A MEDIR]**. A decisão tem de usar o processo em primeiro plano, não só quem lê | Vê `ms-teams`, que está na lista |
| Apps da loja (`ApplicationFrameHost`) | Quem lê pode ser o processo real **[A MEDIR]** | Vê `ApplicationFrameHost`, destino desconhecido, libera |

### Formatos e fidelidade

O Excel põe no clipboard, entre outros, `Biff12`, `Biff8`, `XML Spreadsheet`,
`HTML Format`, `Rich Text Format`, `CF_UNICODETEXT`, `Csv`, `DataObject`,
`Ole Private Data`, `Embed Source`, `Object Descriptor`, `Link Source`, `Link`,
`Hyperlink`, `CF_BITMAP`/`CF_DIB` e `CF_ENHMETAFILE`. O Word põe RTF, HTML,
`Embed Source`/`Link Source` e EMF. **Essa lista é [INFERIDO]**: o protótipo deve registrar a lista
real com `EnumClipboardFormats` e `GetClipboardFormatName`.

- **Precisam de cópia completa:** a T2 sempre; a T1 sempre que não puder repassar os pedidos
  ao objeto original.
  - **Custo:** ler todos os formatos obriga o Excel a renderizar tudo, inclusive bitmap e EMF
    de uma faixa grande. Pode levar segundos e usar muitos MB **[A MEDIR]**.
  - **Perda:** formatos OLE que não são `HGLOBAL` (`Embed Source` e `Link Source` via
    `IStorage`) não sobrevivem a `GetClipboardData` com fidelidade **[INFERIDO]**.
- **Excel → Excel (a ameaça principal):**
  - O Excel cola fórmulas e formato "por dentro" quando **ainda é o dono** do clipboard. Ao
    perder a posse ele sai do modo de cópia (as "formigas marchando" somem) **[INFERIDO, alta
    confiança]**.
  - Colar dados "de fora", mesmo vindos de outro Excel, tende a perder as fórmulas **[INFERIDO,
    relatos conhecidos de colagem entre instâncias]**.
  - **Consequência:** uma T1 que toma a posse logo após a cópia provavelmente reprova o
    critério Excel → Excel **[A MEDIR, experimento E1]**. A T2 só toma a posse ao focar uma saída,
    então o Excel → Excel direto passa. Depois de passar por uma saída, provavelmente degrada
    (o mesmo vale para o híbrido).
  - Sinal objetivo: `Application.CutCopyMode` via COM.
- **O bloqueio precisa cobrir todos os formatos:**
  - O Chrome cola `HTML Format` antes do texto **[INFERIDO]**. Bloquear só `CF_UNICODETEXT` deixa o
    CPF vazar pelo HTML.
  - Ao bloquear: aviso nos formatos de texto (`CF_UNICODETEXT`; `CF_TEXT` e `CF_OEMTEXT` o
    sistema sintetiza **[CONHECIDO]**) e **nenhum dado** nos demais (HTML, RTF, BIFF, imagem).
  - Como cada app reage a um formato anunciado que volta `NULL` **[A MEDIR]**.

### Win+V e o clipboard na nuvem

O que a documentação da Microsoft diz **[CONFERIDO]**:

- Colocar **qualquer dado** no formato `ExcludeClipboardContentFromMonitorProcessing` exclui
  o item **inteiro** do histórico e da sincronização.
- `CanIncludeInClipboardHistory` e `CanUploadToCloudClipboard` recebem um DWORD 0 ou 1 e
  controlam cada um só a sua parte.
- **Esses formatos só valem para quem escreve.**

O problema:

- O serviço de histórico ouve a mesma atualização do clipboard que o App. Quando o App reage,
  o item original do Excel provavelmente **já entrou no histórico [INFERIDO/A MEDIR]**.
- **Nenhuma das duas técnicas, sozinha, cumpre "Win+V não guarda texto sujo".** Elas só
  conseguem marcar as **próprias** escritas: o rearme da T1, e o aviso e a restauração da T2.
- Sem esses formatos, a restauração da T2 **põe o texto sujo de volta** no histórico.

Precisa de um mecanismo à parte. Opções:

| Opção | Observação |
|---|---|
| **(a)** WinRT `Clipboard.GetHistoryItemsAsync()` + `DeleteItemFromHistory(item)`, logo após a classificação | Não se sabe se funciona num app desktop sem pacote, nem se exige estar em primeiro plano **[A MEDIR, experimento E7]** |
| **(b)** Política de grupo `AllowClipboardHistory=0` e `AllowCrossDeviceClipboard=0` (`HKLM\Software\Policies\Microsoft\Windows\System`) | Decisão administrativa |
| **(c)** Aceitar como limite | |

A T1 tem um bônus: anunciar o formato de exclusão junto com os formatos atrasados faz o
histórico **não pedir** a renderização **[INFERIDO/A MEDIR]**.

### Falhas, latência e efeitos colaterais

| Aspecto | T1 (segurar) | T2 (trocar pelo foco) |
|---|---|---|
| Latência na colagem | Quem cola espera o `WM_RENDERFORMAT`. Com veredito em cache, alguns ms; sem cache, até o prazo do pipe **[A MEDIR]** | Nenhuma na colagem. O custo fica na troca de foco: guardar tudo e escrever |
| Corrida | Nenhuma na decisão. Há uma brecha entre a renderização e o rearme: o dado fica real até o App reabrir o clipboard **[A MEDIR]** | **Estrutural.** Alt+Tab seguido de Ctrl+V rápido cola antes da troca. O evento de foco chega de forma assíncrona **[A MEDIR]** |
| App fecha normalmente | `WM_RENDERALLFORMATS`: renderiza o dado real, a falha libera | Precisa restaurar antes de sair |
| **App morto à força** | Formatos anunciados sem dado: a colagem vem vazia ou dá erro **[A MEDIR]**. A cópia se perde | **O aviso fica no clipboard e vale para todos os apps**, inclusive os locais, até a próxima cópia. Viola a RN-013 por persistência |
| Tempestade de avisos | Cada rearme dispara `WM_CLIPBOARDUPDATE` em todos os ouvintes | Cada troca de foco reescreve o clipboard, e cada reescrita dispara o aviso |
| Laço com o monitor da Fase 1 | O App reclassificaria a própria escrita. Precisa ignorar quando `GetClipboardOwner` é do próprio processo, usar um formato-marca próprio ou anotar `GetClipboardSequenceNumber` | O mesmo |
| Outros donos | O Excel perde a posse e sai do modo de cópia | O mesmo, mas só depois de focar uma saída |

## Quem consegue contornar

**Coberto pela T1, não pela T2** (falha de desenho da T2):

- Menu "Colar" do clique direito, Ctrl+Shift+V do Chrome, colar especial, `WM_PASTE` ou o
  padrão "Colar" da UI Automation: todas as vias acabam em `GetClipboardData` ou
  `OleGetClipboard`. A T1 vê; a T2 só vê se o foco estiver na saída.
- App que lê o clipboard sozinho em segundo plano (Ditto, sincronizadores, `Get-Clipboard`):
  a T1 vê, se conseguir identificar quem lê; a T2 libera.

**Não coberto por nenhuma das duas** (limite honesto):

- **Arrastar e soltar:** é `DoDragDrop`, não passa pelo clipboard.
- Digitar de novo, tirar print, OCR, ditado.
- **Matar o App:** ele é um processo do usuário. O efeito é sempre liberar, por desenho (RN-013).
- **Renomear `chrome.exe`:** a lista de saída é por nome.
- **Área de trabalho remota, VM e similares** (`mstsc`, `rdpclip`, VMware Tools, sessão
  avançada do Hyper-V): o clipboard sai da máquina por eles. Hoje não estão na lista de
  saída **[INFERIDO]**.
- **O histórico e a nuvem**, com o item original capturado antes do App reagir.
- **Colar a partir do Win+V:** o histórico escreve o item no clipboard e manda Ctrl+V. Isso
  vira uma cópia nova, que deve ser reclassificada; depende da corrida **[A MEDIR]**.
- **Apps elevados:** não se sabe como a UIPI interage com o `WM_RENDERFORMAT` de um leitor
  elevado, nem com a leitura de um dono elevado **[A MEDIR, experimento E9]**.

**Falhas de desenho que dá para corrigir:**

- Bloquear só o texto e deixar o HTML ou o RTF passar: cobrir todos os formatos.
- Destino WebView2 avaliado pelo processo que lê (`msedgewebview2`): decidir pelo processo em
  primeiro plano e usar quem lê só como registro.
- Teams clássico (`Teams`) e a variação de nome do WhatsApp novo não estão em
  `egressDestinations` **[A MEDIR]**.

## Arquitetura do protótipo

**Onde fica.** Um projeto novo, `agente/SafeUpload.Clipboard.Probe`, seguindo o precedente de
`SafeUpload.Minifilter.Probe`.

- Console `net10.0-windows`, com o próprio laço de mensagens Win32 numa thread STA. **Sem
  WPF**, para não carregar o `System.Windows.Clipboard` nem o comportamento de escrita do WPF.
- Referencia **só o `Core`**: `ClipboardRules`, `ClipboardPolicy`, `ClipboardProtocol`,
  `ContentScanner`.
- Não entra no instalador. Se entra no `.sln` é uma decisão em aberto.

**Dois papéis no mesmo executável, em processos separados:**

1. **`probe agent --technique none|hold|swap|hybrid`**: janela só de mensagens,
   `AddClipboardFormatListener`, gancho de foco. Aplica uma técnica. `none` é a **linha de
   base**, para separar o comportamento normal do app do efeito da técnica. Ignora as próprias
   escritas com um formato-marca registrado, `SafeUpload.Probe.Owned`.
2. **`probe run --matrix <arquivo> --app excel|word|notepad|chrome|teams`**: conduz os
   cenários e coleta o resultado. Processo separado para que a janela dele nunca seja o
   primeiro plano nem o dono do clipboard na hora de colar.

**Decisor, sem depender da política real.** Uma interface
`IPasteDecider.Decide(copyId, destinoEmPrimeiroPlano, processoQueLê, prazo)` com três
implementações:

- `RulesDecider`: chama `ClipboardRules.Classify` e `DecidePaste` com um `ClipboardPolicy`
  fixo do protótipo (`Block`; `chrome`, `msedge`, `ms-teams`, `Teams`, `WhatsApp`).
- `PipeDecider`: opcional; usa um `ClipboardPipeClient` ligado ao serviço real, só para medir
  a latência ponta a ponta.
- `FaultyDecider`: atraso configurável, `null`, exceção, para provar a RN-013.

**Veredito em cache.** O veredito é buscado na troca de foco (a sonda da Fase 1 vira busca
antecipada) e guardado por `(copyId, destino)`. No `WM_RENDERFORMAT`, com o veredito em cache,
responde na hora. Sem cache, espera com teto curto (proposta inicial: 150 ms, a medir) e,
vencido o prazo, libera.

**Variante híbrida (`hybrid`).** Uma terceira coluna, proposta porque ataca o ponto que
provavelmente derruba a T1 pura (Excel → Excel):

- guarda a cópia completa logo que a classificação volta "sujo", com o Excel ainda dono;
- **toma a posse** com renderização atrasada só quando o foco vai para um processo diferente
  da origem;
- decide no `WM_RENDERFORMAT` e rearma depois de cada entrega.

**O que se registra.** Um JSONL em `%LOCALAPPDATA%\SafeUpload\clipprobe\<runId>.jsonl`, com
tempos de alta resolução (`Stopwatch`): técnica, cenário, sequência do clipboard; processo e
PID do dono, do primeiro plano e de quem lê; formato (id e nome), veredito, latência da
decisão, da renderização e do rearme, tamanho em bytes por formato; no lado do condutor,
**SHA-256 com sal por execução** do que chegou no destino, comparado com o hash do esperado
(original ou aviso).

**Nunca se registra:** o texto, um trecho dele ou o conteúdo de qualquer formato. Os dados de
teste são sintéticos (CPF de teste `529.982.247-25` + um nonce por execução), mas a disciplina
é a mesma do produto.

**Como medir sem "olhei e parece ok".** O caminho do usuário é sempre foco real + `SendInput`;
COM e DevTools servem só para preparar e conferir:

| App | Preparar e conferir |
|---|---|
| Excel | COM. `Range.Select` e Ctrl+C via `SendInput`. Conferir `HasFormula`, `FormulaR1C1` igual à origem, `Interior.Color`, `NumberFormat`, `Font.Bold`, `Application.CutCopyMode` |
| Word | COM. Conferir `Range.Text` (hash), `Font.Bold`, `Tables.Count` |
| Bloco de Notas | UI Automation (`TextPattern`/`ValuePattern`), hash do conteúdo |
| Chrome | Perfil próprio (`--user-data-dir`, `--remote-debugging-port`) e uma página local com `textarea` + `contenteditable` cujo evento `paste` registra `clipboardData.types`. O condutor lê o DOM pelo DevTools Protocol e faz o hash |
| Teams | Pessoa (veja a matriz). Talvez automatizável por `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port` **[A MEDIR]** |
| Win+V | `GetHistoryItemsAsync` e procurar o hash do valor de teste **[A MEDIR]**. Se não der, uma pessoa abre o Win+V |

## Matriz de testes

As colunas de técnica são `none` (base), `hold` (T1), `swap` (T2) e `hybrid`. Cada cenário
roda nas quatro. **Auto:** A = automatizável; P = exige uma pessoa; A/P = automatizável com
uma checagem manual.

| ID | Apps | Ação | Esperado (aprovado) | Auto |
|---|---|---|---|---|
| **C1 Excel → Excel (obrigatório)** | Excel | A1:B3 com fórmula relativa, cor, formato de número e CPF. Ctrl+C, seleciona D1, Ctrl+V | `FormulaR1C1` de D1:E3 igual à origem; cor e formato iguais; resultado igual ao da coluna `none` | A |
| C1b | Excel | O mesmo, com uma passada de foco pelo Chrome (sem colar) antes de colar | Registrar. Degradação aceitável só se a equipe decidir | A |
| C1c | Excel | Para outra pasta de trabalho, na mesma instância | Igual ao C1 | A |
| C2 | Excel → Bloco de Notas | Ctrl+V | Hash igual ao original (destino local libera) | A |
| C3 | Excel → Chrome | Ctrl+V na `textarea` e no `contenteditable` | Hash igual ao aviso; **nenhum** tipo traz o valor de teste (HTML incluído) | A |
| **C4 Word → Word → Chrome → Word (obrigatório, rearme)** | Word, Chrome | Copiar parágrafo com CPF; colar no Word; em menos de 1 s colar no Chrome; voltar e colar no Word | 3 de 3 corretos (original, aviso, original) e **um evento de decisão por colagem** no registro | A |
| C5 | Bloco de Notas → Chrome / Word | Ctrl+V | Chrome recebe o aviso; Word recebe o original | A |
| C6 | Bloco de Notas → Teams; Teams → Teams | Colar no rascunho de um chat consigo mesmo, **sem enviar** | Aviso no Teams; original de Teams para Teams | P |
| **C7 Win+V (obrigatório)** | Excel e Bloco de Notas como origem | Copiar com CPF e inspecionar o histórico. Colar no Chrome pelo Win+V | Histórico sem o hash do valor de teste; a colagem pelo Win+V entrega o aviso | A/P |
| C8 RN-013 | Excel → Chrome / Bloco de Notas | `FaultyDecider` com atraso igual ao prazo + 100 ms, `null` e exceção | Cola o original dentro do prazo + margem; destino local nunca recebe o aviso | A |
| C8b morte | Qualquer | `taskkill /F` no agente com o clipboard tomado (T1) ou trocado (T2); colar no Excel, no Bloco de Notas e no Chrome | Registrar o que cada app recebe: vazio, erro ou aviso | A |
| C9 corrida | Excel → Chrome | Alt+Tab e Ctrl+V com atrasos de {0, 50, 100, 200, 400} ms, 20 repetições cada | Vazamentos (hash do original no Chrome) por atraso | A |
| C10 vias | Chrome, Word, Excel | Menu "Colar", Ctrl+Shift+V, colar especial (Ctrl+Alt+V), `WM_PASTE` enviado de fora, leitor em segundo plano com o Word em foco, arrastar do Word para o Chrome | Por via: coberta ou não coberta. Arrastar é um limite esperado | A (arrastar: P) |
| C11 elevado | Bloco de Notas elevado | Colar dentro dele e copiar dele | Registrar | A/P |
| C12 volume | Excel, 10 mil × 20 células | Copiar e colar | Tempo e memória da cópia completa e da tomada de posse | A |
| C13 limpo | Todos | Copiar texto sem achado | **Nenhuma** escrita do agente: dono e sequência inalterados | A |

**Expectativa provisória por técnica e app** (hipótese para os testes confirmarem ou derrubarem):

| | Excel (C1) | Word (C4) | Bloco de Notas | Chrome | Teams |
|---|---|---|---|---|---|
| hold | provável reprovação **[INFERIDO]** | aprovação, se o rearme funcionar | aprovação | aprovação; atenção ao HTML | depende de ver `ms-teams` ou `msedgewebview2` |
| swap | aprovação (sem passar por saída) | aprovação | aprovação | corrida (C9) | aprovação pelo foco |
| hybrid | aprovação | aprovação | aprovação | corrida menor que a da T2 **[A MEDIR]** | igual à T1 |

## Critério de escolha

**Eliminatórios** (reprovar um descarta a técnica):

1. C1 aprovado no Windows 10 22H2.
2. C4: 3 de 3, com uma decisão por colagem.
3. C8: nenhuma colagem local bloqueada e nenhum travamento além do prazo + 100 ms.
4. C9: zero vazamento com atraso ≥ 150 ms. O limiar é uma proposta para a equipe validar.
5. C13: zero escrita com o clipboard limpo.

**Pesos entre as aprovadas:**

| Critério | Peso | Cenários |
|---|---|---|
| Vias cobertas | 25% | C10 |
| Latência somada à colagem local (p95) | 20% | |
| Fidelidade de formatos em destino local | 20% | C1b, C2, C4 |
| Comportamento na morte do App | 15% | C8b |
| Interferência com o histórico e gerenciadores | 10% | |
| Complexidade e risco de COM/OLE | 10% | |

O **Win+V** não pesa na escolha da técnica: nenhuma das duas o resolve sozinha. Ele é julgado
à parte, no mecanismo complementar.

**Recomendação provisória: o híbrido** (cópia completa ao sujar, posse na saída do foco da
origem, decisão na colagem, rearme). Se a equipe exigir uma das duas originais, **T1 em vez
de T2**: decide no momento real da colagem, cobre todas as vias que passam pelo clipboard,
enxerga quem lê e, se morrer, deixa o clipboard vazio em vez de deixar o aviso valendo nos
apps locais.

**Confiança: média-baixa, cerca de 55%.** O que derrubaria a recomendação:

- **(a)** O Chrome ou o Teams lerem o clipboard ao receber foco. A decisão viraria igual à da
  T2, embora ainda correta.
- **(b)** O intervalo entre renderizar e rearmar vazar em C4 ou C9.
- **(c)** O caminho OLE (Excel e Word colando de nós) não passar pela renderização como
  esperado, ou perder formatos essenciais na cópia completa.
- **(d)** A cópia completa do Excel ser lenta demais (C12).
- **(e)** A corrida do híbrido em C9 ser igual à da T2. Nesse caso sobra a troca entre T1 pura
  (sem corrida, sem Excel → Excel) e T2, e a equipe teria de rever o critério 1 ou o 4.

## Modelo de confiança e contrato

**Modelo de confiança:**

- **O App deixa de ser um visor e passa a aplicar as decisões.** O serviço continua decidindo,
  mas a aplicação vive num processo do usuário, que ele pode matar, e o serviço (sessão 0) não
  consegue tocar o clipboard da sessão para compensar.
- Um defeito no App deixa de ser "não mediu" e vira "estragou o clipboard do usuário". Precisa
  constar como risco aceito.
- O comentário da classe `ClipboardMonitor` ("este código não tem como alterar o clipboard")
  deixa de ser verdade quando a técnica for para o App.

**RN-006:**

- A cópia completa mantém o dado sensível **na memória do App** enquanto a cópia estiver suja.
  Não é armazenamento nem log, mas é uma segunda cópia em modo usuário e entra num despejo de
  memória do WER se o App cair.
- A equipe precisa decidir se isso é aceitável, se o WER deve ser limitado ou desligado para o
  App, e se a memória deve ser zerada ao trocar de cópia (melhor esforço).
- O dado **nunca** vai ao serviço; o pedido `paste` continua só com o `copyId`.

**RN-013:**

- Com veredito em cache, a decisão no `WM_RENDERFORMAT` é local e a falha libera.
- **Pior caso:** morte do App. Na T1 a colagem vem vazia (perda de dado, não bloqueio). Na T2
  o aviso persiste nos apps locais (violação).

**Contrato** (só o impacto):

- **O `paste` atual cabe na busca antecipada**, a sonda da Fase 1. Para servir também à decisão
  na colagem, precisa de um campo que distinga sonda de decisão real (por exemplo,
  `"stage": "focus" | "render"`, opcional e compatível com o que existe). Sem isso, a conta da
  Fase 1 conta em dobro.
- **Os 500 ms são muito para bloquear quem está colando** dentro do `WM_RENDERFORMAT`.
  Proposta: o cache vem da sonda e, sem cache, o teto é bem menor, a medir. O protocolo não
  muda; muda o uso.
- **No modo Audit a T1 e o híbrido têm efeito colateral:** tomam a posse e o Excel perde o
  modo de cópia. Hoje a resposta do `classify` não diz o modo, só `dirty`; no modo `Off` sai
  `dirty=false`, então nada acontece. Se Audit não puder ter efeito colateral, a resposta do
  `classify` precisa de um campo do tipo `intercept: bool`.

## Riscos, do mais grave ao menos

1. **Excel → Excel com a tomada de posse.** Se até o híbrido degrada sem passar por uma saída
   (E1, C1/C1b), o critério 1 cai.
2. **Win+V:** nenhuma técnica resolve; a API de histórico pode não funcionar sem pacote (E7).
   Se não funcionar, sobra política de grupo ou aceitar o limite.
3. **Morte do App com o clipboard tomado ou trocado:** perda de dado, ou aviso persistente (C8b).
   Medido com o proxy (D1, D2): perde o conteúdo e não vaza; a perda foi aceita (decisão 18). O
   risco que sobra é o **App fechado pelo usuário**, que deixa as cópias seguintes sem proteção.
4. **Ambiente de teste Windows 11 contra o alvo Windows 10 22H2.**
5. **Corrida da T2 e do híbrido** (C9), e intervalo do rearme na T1 (C4).
6. **Quem lê em WebView2 e em apps da loja:** decisão por primeiro plano contra decisão por
   quem lê.
7. **Vazamento de HTML, RTF e imagem** quando só o texto é bloqueado.
8. **Custo da cópia completa do Excel** (C12) e formatos OLE perdidos.
9. **Prazo do `WM_RENDERFORMAT`** e app travado enquanto espera **[A MEDIR: dormir 5 s dentro do
   `WM_RENDERFORMAT` e observar]**.
10. **UIPI com apps elevados** (E9). Saídas por RDP ou VM fora da lista. Teams clássico e
    WhatsApp novo com nomes não confirmados.
11. **Interação com o Ditto ou outros gerenciadores de clipboard** que reagem ao rearme.

## Experimentos que destravam o resto

Em um ou dois dias, antes de construir o protótipo completo:

| ID | Pergunta |
|---|---|
| **E1** | `CutCopyMode` e fórmulas do Excel depois de um terceiro tomar o clipboard com `OleSetClipboard` — **medido** (seção seguinte) |
| **E2** | `GetOpenClipboardWindow` dentro do `WM_RENDERFORMAT`, com Chrome, Word, Bloco de Notas e Teams — **medido em parte** (Chrome, Word, PowerShell; Teams não) |
| **E3** | O `IDataObject` do Excel continua servindo depois de perder a posse? Decide entre repassar e copiar tudo — **medido: sim** |
| **E7** | `GetHistoryItemsAsync` e `DeleteItemFromHistory` num app sem pacote |
| **E9** | UIPI com apps elevados |

## Resultados medidos (12/10/2026)

Programa de experimento descartável (fora do repositório), em C#, nesta máquina: **Windows 11
build 26300**, Excel, Word e Chrome locais. Vale como primeiro sinal; o alvo é Windows 10 22H2
(seção 8 do alinhamento). Dados sintéticos (CPF de teste 529.982.247-25); o programa registra só
metadados, nunca o conteúdo, e o clipboard do usuário foi gravado em disco antes de cada rodada
e conferido depois.

**Como se mede a fidelidade Excel → Excel:** copia-se `A1:B5` (valores, fórmulas, cor, formato
numérico, negrito e o CPF em `A5`) e cola-se em `D1`. **FIEL** quer dizer que a fórmula, a cor,
o formato e o negrito chegaram; **DEGRADADO**, que chegou só o valor.

### Excel → Excel (E1 e E3)

| ID | O que foi feito | Resultado |
|---|---|---|
| B0 | Linha de base, sem agente | FIEL. O Excel publica **30 formatos** |
| R1 | Técnica 1: cópia completa por Win32 (26 de 30 formatos, 136 KB, 123 ms) e renderização atrasada | **DEGRADADO.** Ao perder a posse, o Excel zera o `CutCopyMode` e cola só valores |
| R2 | Técnica 2: aviso no lugar e depois restaura a cópia completa | **DEGRADADO**, pelo mesmo motivo |
| R4 | Controle: dono com só o texto | DEGRADADO, como esperado |
| R3 | **Proxy OLE** que repassa ao `IDataObject` original do Excel | **FIEL.** O `CutCopyMode` continua 1 e o original segue servindo (E3: sim) |
| R5a, R5c | Técnica 2 com restauração por OLE: guarda o `IDataObject` original, põe o aviso por Win32 e devolve com `OleSetClipboard`, depois de 300 ms e de 5 s | **FIEL** nos dois |

**Conclusão:** qualquer técnica que copia os formatos por Win32 degrada o Excel. Só as que
mantêm o `IDataObject` original (proxy OLE, ou restauração por OLE) preservam a cópia.

### Proxy OLE que bloqueia (P e Q)

| ID | O que foi feito | Resultado |
|---|---|---|
| P1, P2 | Proxy com a interface gerenciada padrão, negando por exceção | **Instável:** o Word recebeu o original com tabela (vazou), o Excel passou a falhar ao colar e uma rodada caiu com violação de acesso |
| Q1, Q2 | Mesmo proxy, com interface própria `[PreserveSig]` devolvendo `HRESULT` | **Estável.** Excel → Excel FIEL antes e depois das saídas, em qualquer ordem; PowerShell e Word recebem só o aviso, também na segunda leitura |

A decisão **não gruda** no primeiro leitor: cada leitura passa pelo proxy (Q2 lê a saída
antes do Excel, e o Excel continua FIEL). O Word pede cerca de 30 formatos (HTML, RTF, OLE,
imagens); o proxy entrega o aviso em texto e nega os outros, sem quebrar o Word.

Q1 e Q2 usaram um interruptor que força o bloqueio, então mediram **o efeito** do bloqueio, e
não **como decidir** quem está lendo. Isso foi medido em seguida.

### Navegador real e decisão pelo primeiro plano (Edge)

Edge com perfil temporário, colagem com `Ctrl+V` e foco real, em `textarea` (texto) e em
`contenteditable` (HTML). **Como se confere:** a própria página escreve no título da janela o que
recebeu (`ORIGINAL`, `AVISO` ou vazia), e o programa lê o título. Nada é relido pelo clipboard.

| ID | Situação | Resultado |
|---|---|---|
| Controle | Sem proxy | `ORIGINAL`: o método enxerga a colagem |
| E1 (`textarea`) | Edge na lista de saída | **Aviso** ✅ |
| E3 (`contenteditable`) | Edge na lista de saída | **Aviso** ✅ (o HTML foi negado) |
| E2 (`textarea`) | Edge **liberado**, o proxy repassa ao Excel | **Colagem vazia** ❌ |
| E4 (`contenteditable`) | Edge **liberado**, o proxy repassa ao Excel | **Nada colado** ❌ |

- **Quem lê:** durante o `GetData`, `GetOpenClipboardWindow()` devolveu **`NULL`** para o Edge.
  A decisão só funciona pelo primeiro plano (`msedge`), e por isso a regra é "**se quem lê é
  ninguém ou o próprio agente, decide pelo primeiro plano**".
- **Achado grave: o repasse quebra a colagem liberada no Edge.** Ao repassar ao `IDataObject` do
  Excel, todo pedido volta `0x800401D0` (`CLIPBRD_E_CANT_OPEN`). Hipótese: o Edge lê por Win32 e
  segura o clipboard aberto; o OLE renderiza pelo nosso proxy, e o Excel tenta abrir o clipboard
  para responder e não consegue.
- **O repasse funciona para quem lê pelo OLE** (F1, com a lista de saída vazia): o PowerShell e o
  Word receberam o original, com tabela no Word, e o Excel → Excel ficou FIEL.
- **Consequência:** do jeito que está, o proxy deixaria o usuário **sem colar em apps liberados que
  leem por Win32** (provavelmente a maioria, com o Bloco de Notas e os navegadores). Antes de
  seguir, é preciso testar um repasse que não dependa do Excel na hora: guardar os formatos de
  texto e HTML quando o proxy é instalado e entregar essa cópia, mantendo o original só para o
  próprio Excel.
- **Leitor em segundo plano não é identificado.** No D1 abaixo, o PowerShell sem janela leu com
  quem lê = ninguém e primeiro plano = outro app, e **recebeu o original**. É o limite já previsto
  para a decisão por primeiro plano (seção "Quem consegue contornar").

### Proxy com cópia guardada (G e H)

Na instalação, o proxy guarda `CF_UNICODETEXT`, `CF_TEXT`, `HTML Format` e `Rich Text Format`
(98 B, 49 B, 2,5 KB e 4,4 KB nesta cópia). Ao liberar, ele repassa ao original e, **se o original
falhar**, entrega a cópia guardada.

- **Resolve a colagem liberada no Edge:** o texto e o HTML chegaram (o original falhou com
  `0x800401D0` e a cópia foi entregue). O PowerShell, o Word e o Excel → Excel continuaram certos.
- **Custo:** o texto copiado fica na memória do agente enquanto o proxy estiver instalado. É a
  decisão 2 (RN-006).

**A primeira decisão gruda para quem lê por Win32** (H1 e H2, nos dois sentidos):

| Ordem | 1º leitor | 2º leitor |
|---|---|---|
| H1 | Edge liberado: original | Edge **como saída**: **original** (vazou) |
| H2 | Edge como saída: aviso | Edge **liberado**: **aviso** (colagem perdida) |

O segundo `Ctrl+V` nem chega ao proxy. Pelo rastro, o pedido de `CF_UNICODETEXT` não se repete:
o OLE, ao renderizar o formato para o primeiro leitor Win32, põe o dado no clipboard do sistema, e
o Windows o entrega pronto daí em diante. **Quem lê pelo OLE** (PowerShell, Word) passa pelo proxy
toda vez, e por isso Q1 e Q2 não mostraram o efeito.

- **Consequência:** sem tratar isso, **colar primeiro num app liberado e depois numa saída vaza**.
  É um contorno trivial e acontece até sem intenção.
- **Correção a testar:** depois de cada renderização, **reinstalar o proxy** (`OleSetClipboard` de
  novo), o que esvazia o que o sistema guardou e força a próxima colagem a passar pela decisão.
  Efeitos a medir: cada reinstalação avisa todos os ouvintes de clipboard (o próprio monitor do App,
  o histórico Win+V, gerenciadores como o Ditto) e conta como uma "cópia nova", e pode haver corrida
  com uma segunda colagem muito rápida.

### Reinstalar o proxy depois de cada colagem (I)

Depois de cada leitura **de fora** do processo, o proxy agenda um `OleSetClipboard` dele mesmo,
250 ms depois da última leitura, para juntar os vários formatos de uma mesma colagem numa
reinstalação só. Três colagens no Edge alternando saída e liberado, nos dois sentidos, e depois
PowerShell, Word e Excel → Excel.

| Ordem | 1ª | 2ª | 3ª | PowerShell, Word, Excel → Excel |
|---|---|---|---|---|
| I1: liberado → saída → liberado | original | **aviso** | **original** | corretos; Excel FIEL, `CutCopyMode` 1 |
| I2: saída → liberado → saída | aviso | **original** | **aviso** | corretos; Excel FIEL, `CutCopyMode` 1 |

- **Resolve a decisão que grudava:** cada colagem passa pela decisão.
- **Cuidado com laço:** a cada `OleSetClipboard`, o próprio OLE lê `Object Descriptor` e `Link
  Source Descriptor` pelo proxy. Na primeira versão, essas leituras também agendavam reinstalação, e
  o proxy entrou em laço (41 reinstalações em 6 s, até a trava do teste). Só leituras de fora podem
  agendar.
- **Custo medido:** cada reinstalação leva **2 a 3 ms**, gera **1 aviso de mudança**
  (`WM_CLIPBOARDUPDATE`) para todos os ouvintes e sobe o número de sequência do clipboard em cerca
  de 30. Parado, sem colar, não gera nada.
- **Janela de corrida:** uma segunda colagem nos 250 ms seguintes à primeira ainda recebe o que foi
  renderizado para a primeira.
- **Detalhe a corrigir:** as leituras internas do OLE foram **negadas** quando o primeiro plano era
  uma saída. Não houve efeito visível, mas o proxy deve sempre repassar as leituras do próprio
  processo.

**Não medido ainda:** se cada reinstalação cria uma **entrada nova no histórico do Win+V** (E7); como
o **monitor do próprio App** reage a esse aviso de mudança (ele trataria como uma cópia nova e
classificaria de novo, então precisa ignorar quando o dono do clipboard é o agente); e o
comportamento de gerenciadores como o Ditto.

### Teams: resultado (19/10/2026)

Teste manual: o programa instala o proxy (cópia guardada, reinstalação, lista de formatos própria
com `TYMED_HGLOBAL` e histórico negado) com o texto `TESTE-ORIGINAL-123`, e o usuário cola com
`Ctrl+V` no chat consigo mesmo, sem enviar. Conferido pelo que apareceu na caixa e pelo rastro.

| Passo | Teams | Resultado |
|---|---|---|
| 1 | Saída | **Aviso** (duas colagens, as duas bloqueadas) ✅ |
| 2 | Liberado (proxy novo) | **Original** ✅ |
| 3a | Liberado | **Original** ✅ |
| 3b | Saída, **no mesmo proxy, sem reiniciar** | **Aviso** ✅ (a decisão não grudou) |

- Em todas as colagens, quem lê aparece como ninguém e o primeiro plano é `ms-teams`: **a decisão
  pelo primeiro plano funciona no Teams**, que é um app WebView2.
- **Um vazamento achado e corrigido no caminho:** com o texto anunciado como `HGLOBAL`, o serviço
  de histórico do Windows (`svchost`) lia o clipboard logo na instalação do proxy, com o primeiro
  plano fora de uma saída, e recebia o original. O Windows guardava essa entrega, e o Teams colava o
  original **sem consultar o proxy**. **Correção:** para conteúdo sujo, o proxy **nega toda leitura
  do `svchost`**. Isso também impede que o histórico Win+V guarde o dado sensível (requisito do
  plano). Efeito colateral: a cópia suja não aparece no Win+V.
- **Regra que vale para o produto:** qualquer leitor que receba o conteúdo sem passar pela decisão
  faz o sistema guardar a entrega. Então o proxy só pode entregar o original a quem decidiu liberar,
  e precisa reinstalar depois.

### Teams: tentativas anteriores (13/10/2026)

A automação (colar e ler a caixa por UI Automation) não funcionou: depois de uma leitura de texto pela
acessibilidade, o Teams deixa de responder a ela quando a janela volta para a frente (190 s até
expirar). O teste passou a ser **manual**: o programa instala o proxy com um texto inofensivo
(`TESTE-ORIGINAL-123`) e o usuário cola com `Ctrl+V` no chat consigo mesmo. Nada foi enviado.

O que o rastro mostrou:

- **O Teams pede `CF_UNICODETEXT` só como fluxo (`TYMED_ISTREAM`)**, nunca como `HGLOBAL`. Quem lê
  aparece como ninguém, e o primeiro plano é `ms-teams`: a **decisão saiu certa** ("bloquear").
- Na primeira tentativa, o proxy respondeu com `HGLOBAL` e o Teams não colou nada. Corrigido para
  entregar no meio pedido (fluxo sobre `HGLOBAL`), **o Teams ainda não mostrou nada**. A causa não foi
  achada; suspeitas: a posição do fluxo, o formato que o Teams espera junto do texto, ou o Teams
  ler por outro caminho depois de recusar a resposta.
- **Causa achada em 19/10/2026, reproduzida sem o Teams** (um leitor Win32 com `OpenClipboard` e
  `GetClipboardData`, com o bloqueio forçado): quando a cópia vem de um programa comum (não OLE), o
  `IDataObject` original anuncia o texto como `TYMED_HGLOBAL` **e** `TYMED_ISTREAM`. Para atender um
  leitor Win32, o OLE pediu o fluxo, e a conversão de volta não entregou nada: o leitor recebeu
  `NULL`. A memória apagada ao liberar o fluxo **não** era a causa (igual nos dois modos).
  **Correção:** o proxy anuncia a própria lista de formatos (`EnumFormatEtc`), com `TYMED_HGLOBAL`
  para os formatos que ele guarda. Com isso, o leitor Win32 recebeu o aviso nas duas leituras. Falta
  repetir no Teams.
- **O serviço de clipboard do Windows** (`svchost`, que alimenta o histórico Win+V) lê o clipboard,
  também como fluxo, **depois de cada mudança**. Com a reinstalação ligada, isso virou um **laço**
  (40 reinstalações a cada ~0,5 s, até a trava do teste). Corrigido: leitura do `svchost` não agenda
  reinstalação. Mas o serviço **recebeu o texto liberado**, ou seja, **o histórico do Win+V guarda o
  conteúdo**. Para conteúdo sujo, o proxy precisa negar essa leitura (ligado à decisão 5 e ao E7).

### Chrome: resultado (manual)

Mesmo método do Teams: página local `data:text/html,<textarea>` (nada sai da máquina), proxy com o
texto `TESTE-ORIGINAL-123`, colagem com `Ctrl+V` pelo usuário e o modo trocado **sem reiniciar o
proxy**.

| Passo | Chrome | Resultado |
|---|---|---|
| 1 | Saída | **Aviso** ✅ |
| 2 | Liberado | **Original** ✅ (entregue pela cópia guardada; o original devolveu `0x800401D0`) |
| 3 | Saída de novo | **Aviso** ✅ (a decisão não grudou) |

Em todas, quem lê aparece como ninguém e o primeiro plano é `chrome`; depois de cada colagem o
proxy reinstalou e o histórico do Windows foi negado.

### WhatsApp: resultado (manual)

Mesmo método, na conversa consigo mesmo, sem enviar.

| Passo | WhatsApp | Resultado |
|---|---|---|
| 1 | Saída | **Aviso** ✅ |
| 2 | Liberado | **Original** ✅ (cópia guardada) |
| 3 | Saída de novo | **Aviso** ✅ |

- **O processo do WhatsApp para Windows se chama `WhatsApp.Root`**, e é esse o nome em primeiro
  plano.
- **Falha achada no produto:** a lista padrão de `egressDestinations` (`PolicyDocument.cs`) tem
  `"WhatsApp"`, e a comparação (`ClipboardPolicy.IsEgressDestination`) é exata, sem diferenciar
  maiúsculas e só tirando o `.exe`. Então **`WhatsApp.Root` não é tratado como saída**. Já na Fase 1,
  ir com o clipboard sujo para o WhatsApp não gera o registro de foco; na Fase 3, a colagem passaria.
  **Corrigido neste PR:** `WhatsApp.Root` entrou na lista padrão do agente (`PolicyDocument.cs`),
  com teste (`Politica_padrao_trata_os_apps_conferidos_como_saida`). O backend não foi alterado: em
  19/10/2026 ele deixou de ter o bloco `clipboard` (commits `3ca1be4f` e `f2112c6f` direto na
  `main`). Ainda falta conferir os nomes reais de Telegram, Slack, Discord e do Outlook novo.

**Chrome: tentativas automáticas anteriores, sem resultado.** Na rodada com a conferência pelo título, nem o controle sem proxy
colou: o `Ctrl+V` automático não chegou à página. Uma rodada anterior, que relia a página pelo
clipboard, parecia mostrar o aviso no Chrome, mas o rastro mostra que a leitura registrada era a
**do próprio programa de teste**. Aquele resultado foi descartado.

### Morte do processo dono do proxy (D)

O proxy foi instalado num **processo filho**, morto com `Kill` (equivale a `taskkill /F`), uma
vez depois de leituras (D1) e outra antes de qualquer leitura (D2). O resultado foi igual nos dois.

| Depois da morte | Resultado |
|---|---|
| Clipboard | Fica **sem dono**, com 5 de 30 formatos e **sem texto** |
| PowerShell (`Get-Clipboard`) | **Nada** (nulo) |
| Word (`Selection.Paste`) | **Falha** ao colar |
| Excel → Excel | **FIEL**: o Excel continua com `CutCopyMode` 1 e cola pela cópia interna dele |

- **Não vaza**, mas o usuário **perde o conteúdo** para todo app que não seja o próprio Excel até
  copiar de novo. É o cenário C8b medido, e confirma o risco 3: a morte do App com o proxy
  instalado causa perda de dado, mesmo sem ter havido colagem.
- O `OleFlushClipboard` numa parada **normal** evitaria isso, mas não protege contra uma morte
  forçada ou uma queda.

### O que muda no desenho

1. **O proxy OLE `[PreserveSig]` continua candidato**, por ser o único que manteve o Excel FIEL
   e bloqueou as saídas de forma estável, mas **ainda não está aprovado**: o repasse puro quebra
   a colagem liberada em quem lê por Win32 (Edge). As técnicas 1 e 2 por Win32 ficam descartadas
   para cópias do Excel.
2. **A decisão é pelo primeiro plano**, e quem lê serve só como registro e para os casos em que
   aponta um processo de fora. A tabela "O que cada uma sabe sobre o destino" precisa disso.
3. **A cópia guardada como reserva resolve a colagem liberada** (G1, H), ao custo de manter o texto
   na memória do agente (decisão 2).
4. **A primeira decisão gruda para leitores Win32** (H), e **reinstalar o proxy depois de cada
   colagem resolve** (I), com 1 aviso de mudança por colagem e uma janela de corrida de 250 ms.
   **Próximo teste:** o efeito da reinstalação no histórico do Win+V e no monitor do próprio App.
5. **A recuperação depois da morte** continua aberta (decisão 18).

### Ainda não medido

- Firefox (não instalado). Teams, Chrome e WhatsApp foram medidos à mão.
- ~~Regressão depois das mudanças de 19/10~~ **Feita em 19/10/2026**, com a lista de formatos
  própria e o histórico negado: Q1 (Excel FIEL; PowerShell e Word com aviso, duas vezes), I1 e I2
  (Edge alternando saída e liberado, três colagens em cada ordem, todas certas; PowerShell, Word e
  Excel → Excel certos) e F1 (repasse para PowerShell, Word e Excel). Uma rodada do I2 ficou sem
  resultado porque o `Ctrl+V` automático não chegou ao Edge (nenhuma leitura no rastro), e a
  repetição passou.
- O Bloco de Notas e outros apps locais liberados, com o proxy repassando (o teste automático não
  colou nem sem proxy; inconclusivo).
- Win+V e o histórico (E7); UIPI com apps elevados (E9).
- O prazo do `WM_RENDERFORMAT` com o agente lento, e o proxy com cópias que não são do Excel.
- Qualquer coisa no Windows 10 22H2.

## Alinhamento com o que entrou na `main` (PRs #20 a #31)

Estudo feito em 12/10/2026 sobre os 31 PRs fechados do repositório. **Limites:** foram lidas
as descrições de todos os PRs relevantes, as páginas dos PRs #19 a #31 no GitHub (conversa,
commits e verificações) e conferidos no código da `main` os pontos marcados como *conferido*; **o código do proxy TLS e o dos PRs de painel não foram lidos**.
O que está aqui é sobre como o clipboard se encaixa no resto, não sobre a técnica de
colagem da Fase 2, que não depende disto.

### 1. Quem cobre o quê

O desvio do tráfego da inspeção TLS é **só dos navegadores** (Chrome, Edge e Firefox, por
políticas corporativas e filtros WFP; PR #23). Programas como Teams e Outlook ficaram de
fora de propósito, porque parte deles recusa interceptação (pinning).

| Destino da colagem | Inspeção TLS (canal `Web`) | Clipboard |
|---|---|---|
| Navegador (Chrome, Edge, Firefox) | Vê o texto **quando é enviado**, depois de colado na página | Pode agir **antes** de a colagem acontecer |
| Teams, WhatsApp, Telegram, Slack, Discord, Outlook, Thunderbird | **Não vê** | **Único controle de colagem** |
| App local (Word, Excel, Bloco de Notas) | Não se aplica | Libera (não é saída) |

*Fonte: PR #23 e `ARQUITETURA-INSPECAO-TLS.md`, seção 4.4. A lista padrão de
`egressDestinations` do clipboard inclui os navegadores (`PolicyDocument.cs`; conferido).*

**A qualificação do TLS foi feita só com o Edge.** O PR #31 lista como não testados o Chrome e
o Firefox ("a VM só tem o Edge"), o upload com login no Drive e no Gmail, o uso prolongado e um
aplicativo com pinning de verdade. Para Chrome e Firefox, a coluna "Inspeção TLS" acima descreve
o desenho, e não algo qualificado.

### 2. Nos navegadores os dois canais se sobrepõem

- **O que cada um enxerga de diferente:** a régua de texto digitado do TLS **deixa passar CPF
  só com os números**, sem a palavra "cpf" por perto (custo aceito no PR #31). O clipboard usa o
  scanner de documentos (`ClipboardRules.cs:106`, conferido), que pega esse caso.
- **Com `clipboard.mode = Block`:** o aviso entra no lugar do texto, então o TLS só vê o
  aviso. Não há evento duplicado.
- **Com `Audit`:** a colagem passa, e o TLS pode barrar o envio depois. O mesmo dado gera um
  evento `Clipboard` e um evento `Web`, de canais com modos independentes (`clipboard.mode`
  contra `auditOnly` da política geral).
- A deduplicação que o Pedro fez (60 s, chave achado + programa + site; PR #29) vale **só dentro
  do canal `Web`**. Entre canais não existe nada.

### 3. A régua de texto

Na qualificação (PR #31), o scanner de documentos barrou telemetria de Edge, GitHub,
YouTube e Dropbox, e o Pedro criou o `TypedTextScanner`, uma régua conservadora para texto
que uma pessoa escreve. O clipboard continua no scanner agressivo.

- Copiar texto **não é telemetria**, mas uma **coluna de identificadores numa planilha** pode
  sujar o clipboard por acaso (qualquer 11 dígitos com dígito verificador de CPF, qualquer
  16 que passe no Luhn).
- **A taxa de falso positivo do clipboard em uso real nunca foi medida.** A Fase 1 só contou
  cópias sujas num teste dirigido: 11 cópias, das quais 9 sujas.

### 4. Exceções por LGPD

O PR #27 criou listas de exceção que passam por túnel, **sem inspeção**: bancos (26 domínios),
saúde (11) e governo (`gov.br`, `jus.br`, `leg.br`, `mp.br`, `def.br`, `mil.br`). O PR descreve
isso como "a troca prevista no plano (privacidade e LGPD contra cobertura)".

O clipboard **não tem equivalente**: só `excludedSources` (gerenciadores de senha). Um texto
copiado de um app de banco e colado num navegador seria varrido.

### 5. Contrato do evento e o painel

O enum `AuditChannel` tem hoje `File`, `Clipboard` e `Web`. O PR #28 avisa que o painel **não
conhece o canal `Web`** e que isso "precisa de alinhamento com o time do painel".

- **Conferido em 12/10/2026:** não existe nenhum campo de canal em `web/back`. O backend guarda
  cada evento num `ReceivedEvent` genérico (`eventKey`, `kind`, `occurredAtUtc`, `payload`), e o
  banco só tem `fk_id_objeto` (arquivo). Um evento `Clipboard` (ou `Web` só de texto) não tem
  arquivo nem objeto.
- No aplicativo, o `AuditSubject.Describe` devolve o `FileName` para qualquer canal que não
  seja `Web`. O evento `Clipboard` tem `FileName` vazio pelo contrato da Fase 0, então a janela
  de bloqueio, a atividade e o histórico mostrariam um assunto **em branco**. Precisa de um caso
  para `Clipboard` (por exemplo, "texto colado em chrome").
- A janela de bloqueio fala em "arquivo" e em "quarentena". O próprio Pedro lista isso como
  limitação (L26), então é uma pendência **compartilhada**.

### 6. O que dá para reaproveitar do aviso e da auditoria

O fluxo do Pedro (PR #29) é `NotificationHub.Publish(evento, sessão, SID)`, com aviso **só para o
dono** e a regra "dono desconhecido: bloqueia, registra e não avisa ninguém". Foi testado na
tela (PR #31).

- O clipboard já conhece a **sessão** (pelo pipe), mas **ainda não resolve o SID** do usuário.
- **Sem justificativa** na v1 do canal web (`OverrideAllowed` sempre falso). É um precedente
  direto para a nossa pendência "justificativa para colagem bloqueada".

### 7. A política local agora é protegida por ACL

Desde o PR #24, o serviço só lê um `policy.json` com a ACL protegida (dono SYSTEM, controle total
só para SYSTEM e Administradores, sem entrada para usuário comum) e **recusa** um arquivo
diferente (`LocalPolicyStore` e `ProtectedPolicyAcl`; conferido). Consequências:

- Mudar `clipboard.mode` passou a exigir **administrador** e o script `Protect-SafeUploadPolicy.ps1`.
  O roteiro de teste manual da Fase 1 foi corrigido por isso.
- O protótipo desta fase **não usa a política real** (usa um `ClipboardPolicy` fixo), então
  não é afetado.

### 8. Decisões do dono no driver

O plano pós-MVP do Victor (`driver/POST-MVP-PLAN.md`; conferido) registra decisões que valem
para o clipboard também:

- **Sem contaminação de processo** (*no process taint*, em vigor) e **leituras nunca recusadas**
  (T7, 08/10/2026). A fonte "processo contaminado" para sujar o clipboard **não vai existir**; a
  detecção continua só por conteúdo. A pendência foi encerrada na Fase 0.
- **A plataforma é o Windows 10 22H2 build 19045.2965 "por enquanto".** Outros builds, inclusive o
  Windows 11, foram adiados (T20). O próprio plano registra que **o suporte do Windows 10 terminou
  em 14/10/2025**. Os experimentos desta fase rodaram no Windows 11, então valem só como primeiro
  sinal para o alvo.

### 9. O que acontece quando um componente do agente morre

O canal web tem uma falha conhecida desse tipo: **serviço morto sem parar deixa as políticas dos
navegadores apontando para o proxy fora do ar, e o navegador fica sem internet** até o serviço
voltar ou alguém rodar `desvio remove` (limitação L5; PR #23, confirmada na qualificação do PR #31).

É a mesma classe de risco da **morte do App** nesta fase (cenário C8b): na Técnica 2 o aviso
fica valendo para todos os aplicativos, e na Técnica 1 os formatos ficam anunciados sem dado. Os
dois canais juntos poderiam deixar o usuário sem colar e sem navegar por causa de um único
processo morto. Isso pesa a favor de tratar a recuperação depois da morte do App como **critério
eliminatório**, e não só com 15% do peso (decisão 18).

### 10. Ambiente de desenvolvimento

Dois arquivos de `driver/recovery-dispositioned/` têm caminho de **261 caracteres** (PR #24).
Num Windows sem `core.longpaths`, `git clone` e `git pull` falham. O PR #25 resolveu só o CI, e
deixou a decisão de encurtar ou tirar esses arquivos do Git com o Victor. Quem usa Windows precisa
rodar uma vez `git config --global core.longpaths true` (feito nesta máquina em 12/10/2026).

## Decisões em aberto

Nenhuma foi tomada. Precisam ser decididas antes de codar o protótipo.

| # | Decisão |
|---|---|
| 1 | O App **pode escrever no clipboard** (mudança do modelo de confiança)? Com que garantias: formato-marca, formato de exclusão do histórico em toda escrita, nunca escrever com o clipboard limpo? |
| 2 | Pode manter a **cópia completa na memória do App** (RN-006)? Limita ou desliga o WER do App? |
| 3 | **Excel → Excel depois de passar por uma saída** pode degradar? |
| 4 | Qual o **limiar de corrida** aceitável em C9 (proposta: 150 ms)? |
| 5 | **Win+V:** tentar a API de histórico, exigir política de grupo ou aceitar como limite? |
| 6 | Incluir a coluna **`hybrid`** na prova de conceito, além das duas técnicas originais? |
| 7 | No modo **Audit**, interceptar (com efeito colateral) ou só medir pelo foco, como na Fase 1? |
| 8 | **Ambiente:** VM com Windows 10 22H2, Office e Teams com conta de teste. Quem faz os cenários manuais (Teams, Win+V, arrastar)? |
| 9 | O **projeto do protótipo** fica no repositório e no `.sln`, ou só no repositório? |
| 10 | **Lista de saída para os testes:** incluir `Teams`, `mstsc` e o nome real do WhatsApp? |
| 11 | Os **navegadores continuam em `egressDestinations`** do clipboard, já que o TLS os cobre? Proposta provisória: manter, porque o clipboard pega CPF só com dígitos e age antes do envio. Exige coordenar com o Pedro |
| 12 | Como **evitar ou tolerar eventos duplicados** `Clipboard` + `Web` para o mesmo dado, em modo Audit? |
| 13 | Qual **régua de texto** o clipboard usa: `ContentScanner` (atual), `TypedTextScanner` ou uma terceira? Medir a taxa de falso positivo em uso real **antes** do modo Block |
| 14 | O clipboard precisa de **exceções por origem** equivalentes às de LGPD do TLS (apps de banco, saúde, governo)? |
| 15 | **Contrato do evento `Clipboard` para o painel:** campo de canal, `fk_id_objeto` nulo e exibição. Dono: time do painel, com o Pedro (o `Web` tem o mesmo problema) |
| 16 | **Texto próprio do aviso** para o canal clipboard e um caso `Clipboard` no `AuditSubject`. A limitação L26 do Pedro é a mesma pendência |
| 17 | **Justificativa** para colagem bloqueada: seguir o precedente do canal web (v1 sem justificativa)? |
| 18 | ~~A **recuperação depois da morte do App** (cenário C8b) vira **critério eliminatório**?~~ **Encaminhada em 12/10/2026 (posição da equipe do driver, no grupo):** perder o clipboard numa queda é aceitável, porque não vaza; a prioridade é o agente não cair. **Fica aberto:** o App roda como o usuário e pode ser fechado sem administrador, e com ele fechado as cópias seguintes ficam sem proteção. Proposta: o serviço vigia o App da sessão, registra um evento e o reabre (vale para todos os canais que dependem do App) |
| 19 | **Plataforma do clipboard:** seguir o driver (Windows 10 22H2 build 19045.2965, fora de suporte desde 14/10/2025) ou qualificar também no Windows 11, onde os experimentos rodaram? |
