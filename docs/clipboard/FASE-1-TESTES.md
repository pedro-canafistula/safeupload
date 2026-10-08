# Clipboard — Fase 1: testes

Complementa [FASE-1-MARCAR-SUJO-E-MEDIR.md](FASE-1-MARCAR-SUJO-E-MEDIR.md).
Este documento explica **como a Fase 1 foi testada**, o que cada teste prova e
o que ficou sem prova.

## Resumo

| | |
|---|---|
| Suíte do agente | **270 testes passando**, 0 falhas, compilação sem avisos |
| Já existiam | 243 (incluem os da Fase 0: política, regras e protocolo do clipboard) |
| Novos na Fase 1 | **27**: 16 em `ClipboardServiceTests` e 11 em `ClipboardPipeTests` |
| Prova no Windows real | Harness descartável (fora do repositório) |
| Teste manual com Excel, Word, Chrome e Edge | ✅ **Passou** em 7/10/2026 (seção abaixo) |

Como rodar:

```
dotnet test agente/SafeUpload.Agent.Tests
dotnet test agente/SafeUpload.Agent.Tests --filter "FullyQualifiedName~Clipboard"
```

"Sem avisos de compilação" quer dizer que `dotnet build` não emitiu nenhum
warning. Isso mostra código bem formado, não código correto; quem mostra isso
são os testes abaixo.

## Camadas de teste

Cada camada pega um tipo de erro diferente.

| Camada | Usa | Pega |
|---|---|---|
| **Regras puras** (`ClipboardRules`, Fase 0) | Funções sem Windows | A lógica de "suja ou não" e "passa ou bloqueia" |
| **Serviço** (`ClipboardServiceTests`) | Uma loja de política de mentira e um logger que grava o que foi dito | Estado da cópia, contadores, falha que libera, texto vazando em log |
| **Pipe real** (`ClipboardPipeTests`) | Um named pipe do Windows de verdade, com nome único por teste | O protocolo no fio, linha malformada, linha gigante |
| **Windows real** (harness) | Clipboard e gancho de foco reais | O App funcionando de verdade |
| **Apps reais** (teste manual) | Excel, Word, Chrome, Edge e Bloco de Notas, com o serviço e o App rodando | O comportamento de aplicativos de verdade, como a renderização atrasada do Office |

Os testes do serviço não abrem pipe, porque `ClipboardService` não conhece o
pipe de propósito. Os do pipe sobem o `ClipboardPipeServer` com um nome único
(`SafeUpload.Test.Clipboard.<guid>`), então não colidem com um serviço de
verdade rodando na máquina nem entre si.

## Anatomia de um teste

`Copiar_um_cpf_marca_sujo`:

1. **Monta:** uma política em `Audit` com `chrome` e `WhatsApp` como saída, e um
   serviço cuja loja de política devolve sempre essa política.
2. **Age:** manda um pedido de classificação com o texto
   `"Cliente: 529.982.247-25"` e origem `notepad`.
3. **Confere:** `Dirty = true`, a categoria `Cpf` e um `CopyId` preenchido.

O CPF `529.982.247-25` tem **dígitos verificadores válidos**. O scanner só
marca como achado o que passa na conta do CPF; um número qualquer, como
`111.111.111-11`, não suja o clipboard.

## Os 27 testes novos

### `ClipboardServiceTests` (16)

**Classificação (Ctrl+C)**

| Teste | O que prova |
|---|---|
| `Copiar_um_cpf_marca_sujo` | CPF válido suja, com categoria `Cpf` e `CopyId` |
| `Copiar_texto_limpo_depois_de_um_sujo_volta_a_limpo` | Uma cópia nova substitui a anterior; o id da suja deixa de valer |
| `Resposta_traz_achado_mascarado_e_nunca_o_texto` | A resposta serializada não contém o CPF, nem sem pontuação, nem o texto ao redor |
| `Texto_copiado_nao_aparece_em_nenhum_log` | Nenhuma linha de log contém o CPF, o CPF sem pontuação, o nome "Joaquim" nem o texto limpo |
| `Texto_acima_do_teto_suja_por_padrao_e_nao_com_a_opcao_desligada` | `oversizedTextIsDirty` true suja, false não |
| `Texto_cortado_pelo_aplicativo_e_tratado_pelo_tamanho_real` | O App manda só o começo, mas o serviço usa o tamanho real (500 mil) e suja |
| `Fonte_excluida_nunca_suja` | Cópia de `KeePass.exe` com CPF não suja |
| `Canal_desligado_responde_limpo_e_nao_mede` | `mode: Off` responde limpo e os contadores ficam zerados |
| `Politica_que_nao_carrega_libera` | Política inválida: cópia limpa e foco `Allow` (RN-013) |

**Medição e foco**

| Teste | O que prova |
|---|---|
| `Conta_copias_e_copias_sujas` | 4 cópias, 2 sujas, contadas certo |
| `Conta_o_foco_em_destino_de_saida_com_o_clipboard_sujo` | `explorer` dá `Allow`, `chrome.exe` dá `AuditOnly`; 2 trocas, 1 em saída |
| `Foco_no_mesmo_processo_de_origem_nao_conta_como_saida` | Copiou no `chrome` e foi para o `chrome`: não conta |
| `Foco_com_o_clipboard_limpo_nao_entra_na_conta` | Clipboard limpo: a troca de foco nem é contada |
| `Cada_sessao_so_enxerga_a_propria_copia` | Uma sessão do Windows não responde pela cópia de outra |
| `Identificador_desconhecido_libera` | `copyId` que o serviço não conhece: `Allow` |
| `Modo_block_tambem_so_mede_na_fase_um_e_o_veredito_e_de_bloqueio` | Em `Block` o serviço devolve `Block` e a conta é a mesma |

### `ClipboardPipeTests` (11)

| Teste | O que prova |
|---|---|
| `Classifica_e_depois_responde_a_sonda_de_foco_pelo_pipe` | Classify e depois a sonda, pelo pipe real, ponta a ponta |
| `Atende_varias_conexoes_seguidas` | 20 conexões em sequência, sem vazar nem travar o pipe |
| `Linha_malformada_fecha_sem_responder_e_o_servidor_segue_de_pe` | Lixo fecha sem resposta, e a pergunta válida seguinte funciona |
| `Linha_acima_do_teto_e_descartada_sem_resposta` | Linha maior que `MaxLineLength` é descartada e não conta como cópia |
| `Pedido_de_tipo_desconhecido_fecha_sem_responder` | `{"type":"formatar-disco"}` não é atendido |
| `Falha_ao_criar_o_pipe_nao_derruba_o_servidor_e_ele_se_recupera` | Com o nome do pipe ocupado, a criação falha várias vezes; o servidor segue rodando, registra erro e, liberado o nome, volta a atender sozinho |
| `Leitura_de_linha_para_na_quebra_e_tira_o_retorno_de_carro` | `ReadLineAsync` para na quebra e remove o `\r` |
| `Leitura_de_linha_sem_quebra_vale_o_que_chegou` | Fim do fluxo sem quebra devolve o que chegou |
| `Leitura_de_linha_vazia_devolve_nulo` | Fluxo vazio devolve `null` |
| `Leitura_de_linha_acima_do_teto_devolve_nulo_mesmo_com_a_quebra_no_fim` | Estourar o teto devolve `null`, mesmo com a quebra no fim |
| `Leitura_de_linha_no_teto_exato_passa` | Exatamente no teto é aceito |

## O que acontece por baixo dos panos

Rastreio com o serviço real num pipe, mandando linhas cruas. Política: `Audit`,
saída `[chrome, WhatsApp]`, fonte excluída `[KeePass]`, teto de texto 1000.

**1. Ctrl+C com um CPF**
```
APP → SERVIÇO: {"type":"classify","text":"Cliente: Joao Silva, CPF 529.982.247-25","textLength":39,"sourceProcess":"notepad"}
SERVIÇO → APP: {"type":"classify","copyId":"998720db…","dirty":true,"categories":["Cpf"],"findings":["•••••••••25"],"verdict":"Allow"}
LOG:           Clipboard sujo: motivo Sensitive, categorias [Cpf], origem notepad. Copias 1, sujas 1.
```
O texto original **entra** no serviço, é varrido e **não volta**: a resposta só
tem o `copyId` e o achado mascarado (os 2 últimos dígitos). O log também não tem
o CPF.

**2. O foco vai para o Chrome, com o clipboard sujo**
```
APP → SERVIÇO: {"type":"paste","copyId":"4c546908…","destinationProcess":"chrome"}
SERVIÇO → APP: {"type":"paste","copyId":"4c546908…","dirty":false,"verdict":"AuditOnly"}
LOG:           Foco em destino de saida com o clipboard sujo: chrome (origem notepad, veredito AuditOnly). Total 1 de 1.
```
O `paste` não leva texto: leva só o `copyId`. O serviço procura a cópia, aplica
`DecidePaste` e conta. O `dirty:false` dessa resposta é o valor padrão do campo,
que não é usado nesse tipo de pedido; não quer dizer que o clipboard esteja
limpo.

**3. Foco no Word** → `Allow`, sem log. O Word não está na lista de saída.

**4. Ctrl+C de texto limpo** → `dirty:false`, e a cópia suja é substituída.

**5. Foco no Chrome com o id da cópia suja antiga** → `Allow`. O id já não vale.

**6. Cópia do KeePass com CPF** → `dirty:false`. Fonte excluída nunca suja.

**7. Texto de 5000 caracteres com teto de 1000** → `dirty:true`, `findings:[]`,
motivo `TextTooLarge`. Não foi varrido, e o que não foi olhado marca.

**8 e 9. Lixo que não é JSON, e `{"type":"formatar-disco"}`** → o servidor fecha
sem responder. O App trata a falta de resposta como "libera".

Contadores ao fim desse roteiro: `Copies=5, DirtyCopies=3,
FocusChangesWhileDirty=2, FocusOnEgressWhileDirty=1`.

## Prova no Windows real (harness)

Um programa de console descartável, **fora do repositório**, que sobe o
`ClipboardPipeServer` e o `ClipboardMonitor` no mesmo processo, no pipe real, e
usa o clipboard e o gancho de foco de verdade. Guarda o texto que o usuário tinha
copiado e o restaura no fim.

| Passo | Resultado |
|---|---|
| Copiar `"Cliente: 529.982.247-25"` | ✅ 1 cópia, 1 suja |
| Foco para um destino de saída (a barra de tarefas, `explorer`, na lista de saída do teste) | ✅ conta 1 |
| Repetir a mesma troca de foco | ✅ não conta de novo |
| Copiar um texto limpo e repetir o foco | ✅ cópias 2, sujas 1, foco continua 1 |
| Parar o serviço e copiar | ✅ o App segue de pé |

O gancho de foco também entregou um **evento real** durante o teste, sem
nenhuma chamada minha, o que mostra que ele funciona fora do harness.

### Achados durante a fase

| Achado | Como apareceu | Resolução |
|---|---|---|
| **Uma cópia contava duas vezes** (`Copies = 2` com um só `SetText`) | Harness com o clipboard real. O WPF e muitos apps disparam `WM_CLIPBOARDUPDATE` mais de uma vez por cópia | O monitor agrupa a rajada: espera 120 ms e trata só o último aviso. Depois: 1 cópia por Ctrl+C |
| **Aviso falso `Falha ao atender o canal de clipboard` após quase toda resposta boa** | Rastreio com um logger que mostra tudo. Os testes usam logger nulo e não viam | O `StreamWriter` era descartado no fim do método, depois de o cliente fechar, e o último `Flush` lançava `IOException: Pipe is broken`. A escrita agora tem escopo próprio e termina antes da espera. Medido: **5 avisos sem a correção, 0 com ela** |
| **Criação do pipe fora do tratamento de erro** | Revisão do código, ao fechar a fase. Nenhum teste nem o teste manual teria mostrado isso, porque só acontece se a criação falhar | Uma exceção não tratada num `BackgroundService` derruba o host inteiro, e com ele a proteção de arquivos. A criação agora fica num `try/catch`, com espera e recuo (1 s, dobrando até 30 s) e erro no log. A falha ao aceitar conexão também espera, para não virar um laço apertado |

Para a criação do pipe há teste automatizado, e ele **falha sem a correção**
(3 de 3 execuções, com a exceção escapando como antes) e passa com ela. Além
disso, com o nome real `SafeUpload.Agent.Clipboard` ocupado por outro pipe, o
serviço de verdade continuou vivo, registrou `Nao foi possivel criar o pipe do
canal de clipboard. Nova tentativa em 00:00:01` (depois `00:00:02`) e, liberado
o nome, o pipe voltou sozinho.

## Teste manual com aplicativos reais (7/10/2026)

O harness copiava texto pelo próprio processo. Este teste usa **os aplicativos de
verdade**, para ver o que o harness não consegue: a renderização atrasada do
Office, o nome real do processo de origem e as trocas de foco feitas por uma
pessoa.

### Como foi montado

| Peça | Como |
|---|---|
| Política | `%ProgramData%\SafeUpload\policy.json` com `"mode": "Audit"`; saída: navegadores (Chrome, Edge...), mensageiros e e-mail. O Word **não** está na lista |
| Serviço | Em modo console, `dotnet run --project agente/SafeUpload.Agent.Service -- --CentroAdministracao:BaseUrl=`. O argumento faz o serviço ler o arquivo local em vez da política do painel |
| App | `dotnet run --project agente/SafeUpload.Agent.App`, na bandeja |
| Aplicativos | Excel e Word (Office 16), Chrome, Edge e Bloco de Notas |
| Como se observou | O log do serviço, lido a cada passo; nada foi inferido de fora dele |

O serviço e o App ficaram conectados (`Aplicativo conectado ao canal de
notificacao (sessao 1)`), e o pipe `SafeUpload.Agent.Clipboard` apareceu em
`\\.\pipe\`.

### O que passou entre o App e o serviço

O que cada ação do usuário provoca, de ponta a ponta:

```
Ctrl+C no Excel, numa célula com 529.982.247-25
  └─ Excel dispara WM_CLIPBOARDUPDATE → o App espera 120 ms → lê o texto
       └─ pipe "classify": texto, tamanho real, origem "EXCEL"
            └─ serviço: varre, acha um CPF válido, guarda (copyId, sujo)
  LOG: Clipboard sujo: motivo Sensitive, categorias [Cpf], origem EXCEL. Copias 9, sujas 8.

Clique no Word (não é saída)
  └─ o gancho de foco avisa o App → o clipboard está sujo → pipe "paste" (sonda)
       └─ serviço: DecidePaste → Allow → conta a troca de foco, e só isso
  LOG: (nenhuma linha: só os focos em saída são logados)

Clique no Chrome (saída)
  └─ pipe "paste" (sonda) → serviço: DecidePaste → AuditOnly
  LOG: Foco em destino de saida com o clipboard sujo: chrome (origem EXCEL, veredito AuditOnly). Total 8 de 64 trocas de foco.
```

Em nenhum momento o CPF aparece no log, nem a resposta do serviço o devolve.

### Passos isolados

Para tirar a dúvida sobre cópias contadas em dobro, três ações, uma por vez,
comparando o log antes e depois de cada uma:

**Passo 1. Um único Ctrl+C no Excel numa célula com CPF** → esperado: 1 linha.
```
antes:  ... Copias 8, sujas 7.
depois: Clipboard sujo: motivo Sensitive, categorias [Cpf], origem EXCEL. Copias 9, sujas 8.
```
Uma linha, e os dois contadores subiram em 1. **O Excel não dispara
classificação dupla.**

**Passo 2. Um único Ctrl+C no Excel com `reunião às 14h`** → esperado: nenhuma linha.
```
antes:  (log com 43 linhas)
depois: (log com 43 linhas)
```
Nenhuma linha nova, como o esperado: texto limpo não gera log. Mas isso, sozinho,
não prova que a cópia foi contada. A prova veio no passo seguinte.

**Passo 3. CPF copiado de novo; foco no Word; foco no Chrome.**
```
Clipboard sujo: motivo Sensitive, categorias [Cpf], origem EXCEL. Copias 11, sujas 9.
Foco em destino de saida com o clipboard sujo: chrome (origem EXCEL, veredito AuditOnly). Total 8 de 64 trocas de foco.
```
- `Copias` foi de **9 para 11** e `sujas` de 8 para 9: houve uma cópia limpa (a do
  passo 2, que não gerou log) e uma suja. **Isso prova que a cópia limpa foi
  classificada.**
- Houve uma linha de foco só para o **Chrome**. O Word recebeu foco e não gerou
  linha, porque não está na lista de saída.

### O primeiro roteiro, em conjunto

Antes dos passos isolados, os cinco cenários (Excel → Chrome, Excel → Word, texto
limpo, volta a limpo, Bloco de Notas → Chrome) foram feitos em sequência. O log:

```
Clipboard sujo: ... origem EXCEL. Copias 1, sujas 1.
Clipboard sujo: ... origem EXCEL. Copias 3, sujas 2.            ← Copias 2 foi uma cópia limpa, sem log
Foco em destino de saida ...: msedge (origem EXCEL, AuditOnly). Total 1 de 1 trocas de foco.
Foco em destino de saida ...: msedge (origem EXCEL, AuditOnly). Total 2 de 3 trocas de foco.
Clipboard sujo: ... origem EXCEL. Copias 4, sujas 3.
Foco em destino de saida ...: chrome (origem EXCEL, AuditOnly). Total 3 de 6 trocas de foco.
Foco em destino de saida ...: chrome (origem EXCEL, AuditOnly). Total 4 de 10 trocas de foco.
Clipboard sujo: ... origem EXCEL. Copias 5, sujas 4.
Clipboard sujo: ... origem EXCEL. Copias 6, sujas 5.
Foco em destino de saida ...: chrome (origem EXCEL, AuditOnly). Total 5 de 17 trocas de foco.
Clipboard sujo: ... origem EXCEL. Copias 7, sujas 6.
Foco em destino de saida ...: chrome (origem EXCEL, AuditOnly). Total 6 de 21 trocas de foco.
Clipboard sujo: ... origem Notepad. Copias 8, sujas 7.
Foco em destino de saida ...: chrome (origem Notepad, AuditOnly). Total 7 de 25 trocas de foco.
```

O log não tem hora, então não dá para ligar cada linha a um cenário. Foi por isso
que se fizeram os passos isolados, que respondem às três perguntas que esta
sequência deixava abertas:

| Dúvida | O que respondeu |
|---|---|
| Um Ctrl+C no Excel conta como uma ou duas cópias? | Passo 1: uma |
| Uma cópia limpa é classificada, já que não gera log? | Passo 3: sim, `Copias` avançou em 2 |
| O Word recebe foco sem contar como saída? | Passo 3: sim |

### Totais do teste inteiro

| Medida | Valor |
|---|---|
| Cópias classificadas | 11 (9 sujas, 2 limpas) |
| Sujas por origem | 8 `EXCEL`, 1 `Notepad` |
| Focos em destino de saída com o clipboard sujo | 8: 6 `chrome` e 2 `msedge`, todos `AuditOnly` |
| Trocas de foco com o clipboard sujo | 64 |
| Avisos ou erros no log do serviço | **0** |
| Saída do App | Nenhuma (nenhuma exceção) |

### O que este teste provou

- **O Excel é detectado de forma confiável**: 8 cópias com CPF, todas marcadas,
  todas com origem `EXCEL`. O risco que preocupava antes do teste, o Office usar
  renderização atrasada e o App perder o CPF, não se concretizou.
- **Um Ctrl+C gera uma classificação**, e não duas, também no Excel real. O
  agrupamento de 120 ms basta.
- **O Word não conta como saída.** O Chrome e o Edge contam. O Bloco de Notas
  funciona como origem.
- **O nome do processo de origem** vem certo: `EXCEL` e `Notepad`.
- **Texto limpo** é classificado e contado, e não gera log.
- O serviço e o App rodaram o teste inteiro sem erro.

### O que ele não provou

- **Cópia com a célula do Excel em modo de edição** (cursor dentro da célula, ou
  texto selecionado na barra de fórmulas) não foi testada.
- **Word como origem** não foi testado. O Word só foi usado como destino.
- **Teams, WhatsApp e outros mensageiros** não foram testados.
- **A contagem de "trocas de foco" é ruidosa** (64 contra 8 em saída). O gancho
  conta toda troca de janela com o clipboard sujo, inclusive para o terminal e
  para a conversa de desenvolvimento. A medida que importa é a de foco em
  destino de saída.
- O teste usa o texto `529.982.247-25`, um CPF de teste. Outras categorias
  (cartão, senha, segredo) foram cobertas só pelos testes automatizados.

## Limites: o que a suíte não prova

- **O App não tem teste xUnit.** `ClipboardMonitor` e `ClipboardPipeClient` falam
  com o Windows (janela de mensagens, gancho de foco, clipboard), e a única prova
  é o harness, que **não está no repositório**. Este documento registra o que ele
  provou, mas a equipe não consegue repeti-lo sem o código.
- **O teste com aplicativos reais é manual**, não automatizado, e foi feito uma
  vez, com o Office 16 e os navegadores desta máquina. Não há como a equipe
  repeti-lo sem uma pessoa na frente do PC. O roteiro está em
  [FASE-1-MARCAR-SUJO-E-MEDIR.md](FASE-1-MARCAR-SUJO-E-MEDIR.md).
- **O conserto do aviso falso não tem teste automatizado.** Foi tentado um teste
  de regressão, mas ele passava com e sem a correção, ou seja, não detectava o
  problema. Foi removido para não dar falsa segurança. A validação é o rastreio
  (5 → 0).
- Os 243 testes que já existiam foram executados, mas não reexaminados um a um.
- O rastreio acima também é um programa descartável e não está no repositório.

## Pendente

| Item | Observação |
|---|---|
| Cópia com a célula do Excel em modo de edição, Word como origem, Teams e WhatsApp | Cenários não cobertos pelo teste manual de 7/10/2026 |
| Levar o harness e o rastreio para o repositório | Fecharia o maior buraco de cobertura (o App) e permitiria à equipe repetir a prova |
