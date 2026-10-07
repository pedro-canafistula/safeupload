# Clipboard — Fase 1: testes

Complementa [FASE-1-MARCAR-SUJO-E-MEDIR.md](FASE-1-MARCAR-SUJO-E-MEDIR.md).
Este documento explica **como a Fase 1 foi testada**, o que cada teste prova e
o que ficou sem prova.

## Resumo

| | |
|---|---|
| Suíte do agente | **269 testes passando**, 0 falhas, compilação sem avisos |
| Já existiam | 243 (incluem os da Fase 0: política, regras e protocolo do clipboard) |
| Novos na Fase 1 | **26**: 16 em `ClipboardServiceTests` e 10 em `ClipboardPipeTests` |
| Prova no Windows real | Harness descartável (fora do repositório) |
| Teste manual com Excel e Chrome | ⏳ **Pendente** |

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

## Os 26 testes novos

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

### `ClipboardPipeTests` (10)

| Teste | O que prova |
|---|---|
| `Classifica_e_depois_responde_a_sonda_de_foco_pelo_pipe` | Classify e depois a sonda, pelo pipe real, ponta a ponta |
| `Atende_varias_conexoes_seguidas` | 20 conexões em sequência, sem vazar nem travar o pipe |
| `Linha_malformada_fecha_sem_responder_e_o_servidor_segue_de_pe` | Lixo fecha sem resposta, e a pergunta válida seguinte funciona |
| `Linha_acima_do_teto_e_descartada_sem_resposta` | Linha maior que `MaxLineLength` é descartada e não conta como cópia |
| `Pedido_de_tipo_desconhecido_fecha_sem_responder` | `{"type":"formatar-disco"}` não é atendido |
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

### Achados dos testes de integração

| Achado | Como apareceu | Resolução |
|---|---|---|
| **Uma cópia contava duas vezes** (`Copies = 2` com um só `SetText`) | Harness com o clipboard real. O WPF e muitos apps disparam `WM_CLIPBOARDUPDATE` mais de uma vez por cópia | O monitor agrupa a rajada: espera 120 ms e trata só o último aviso. Depois: 1 cópia por Ctrl+C |
| **Aviso falso `Falha ao atender o canal de clipboard` após quase toda resposta boa** | Rastreio com um logger que mostra tudo. Os testes usam logger nulo e não viam | O `StreamWriter` era descartado no fim do método, depois de o cliente fechar, e o último `Flush` lançava `IOException: Pipe is broken`. A escrita agora tem escopo próprio e termina antes da espera. Medido: **5 avisos sem a correção, 0 com ela** |

## Limites: o que a suíte não prova

- **O App não tem teste xUnit.** `ClipboardMonitor` e `ClipboardPipeClient` falam
  com o Windows (janela de mensagens, gancho de foco, clipboard), e a única prova
  é o harness, que **não está no repositório**. Este documento registra o que ele
  provou, mas a equipe não consegue repeti-lo sem o código.
- **Excel e Chrome reais não foram testados.** O harness copiava texto pelo
  próprio processo, e o destino era a barra de tarefas. O roteiro manual está em
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
| Teste manual com Excel e Chrome | Exige alguém na frente do PC; roteiro no documento da fase |
| Levar o harness e o rastreio para o repositório | Fecharia o maior buraco de cobertura (o App) e permitiria à equipe repetir a prova |
