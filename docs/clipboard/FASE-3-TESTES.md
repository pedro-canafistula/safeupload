# Clipboard — Fase 3: testes

Complementa [FASE-3-BLOQUEIO-NA-COLAGEM.md](FASE-3-BLOQUEIO-NA-COLAGEM.md). Explica como a Fase 3 foi
testada: o que é automático (3a) e o que é manual (3b), e por quê.

## Resumo

| | |
|---|---|
| Automático (3a) | **25 testes novos**; clipboard **153 de 153** |
| Suíte do agente | 719 testes, **708 passando**, 4 ignorados e 7 falhas, **as mesmas 7 da `main`** nesta máquina (precisam de privilégio de symlink e de backup) |
| Manual (3b) | ✅ **Passou** em modo Block, com o serviço e o App reais (20/10/2026) |
| Onde rodou | Windows 11 build 26300. **Não** no alvo (Windows 10 22H2) |

```
dotnet test agente/SafeUpload.Agent.Tests
dotnet test agente/SafeUpload.Agent.Tests --filter "FullyQualifiedName~Clipboard"
```

## Por que parte é manual

O proxy OLE (`ClipboardPasteGuard`) é código COM que só funciona com o clipboard, o OLE e os
aplicativos reais: não há como cobri-lo por teste de unidade. O que **dá** para testar sem Windows —
o protocolo, a decisão, a auditoria e as regras do proxy — está em testes automáticos (3a). O proxy
em si (3b) é validado à mão, pelo roteiro abaixo, e o rastro de cada comportamento está medido na
Fase 2 ([FASE-2-TESTES.md](FASE-2-TESTES.md)).

## Testes automáticos (3a)

| Arquivo | O que prova |
|---|---|
| `ClipboardPasteGuardRulesTests` | As regras do proxy: colagem decide pelo destino e reinstala; leitura do próprio agente entrega o original sem reinstalar; histórico do Windows é negado; destino desconhecido não é saída. E a memória: reusa a decisão da mesma colagem, pergunta de novo para outra cópia, outro destino ou depois da janela de 1 s |
| `ClipboardInspectionServiceTests` | Colagem em saída no Block é bloqueada e auditada como `Blocked`; em Audit passa e é auditada como registro; em app local ou destino desconhecido passa sem evento; cópia limpa ou desconhecida passa; a colagem é contada à parte das trocas de foco; sem política, libera |
| `ClipboardStateProtocolTests` | O campo `attempt` vai e volta; a sonda de foco não o leva e não conta como colagem; um pedido antigo sem o campo continua sendo sonda |
| `ClipboardPipeTests` | A colagem de verdade pelo **pipe real** é contada e auditada à parte do foco |

Cada teste de bloqueio confere também que **o texto e o CPF não aparecem** no evento serializado nem
no log (RN-006).

## Teste manual (3b), 20/10/2026

### Como foi montado

- Política local em `%ProgramData%\SafeUpload\policy.json` com `clipboard.mode = Block` e `chrome`
  na lista de saída, protegida por ACL (`Protect-SafeUploadPolicy.ps1`).
- Serviço em console, elevado, lendo o arquivo local
  (`dotnet run --project agente/SafeUpload.Agent.Service -- --CentroAdministracao:BaseUrl=`).
- App na bandeja (`dotnet run --project agente/SafeUpload.Agent.App`).
- CPF de teste sintético `529.982.247-25`. Página local no Chrome (`data:text/html,<textarea>`),
  nada sai da máquina.

### Casos e resultados

| # | Ação | Esperado | Obtido |
|---|---|---|---|
| PT-01 | Copiar o CPF no Bloco de Notas; colar no Chrome | Aviso no lugar do texto + balão | ✅ Apareceu o aviso e o balão |
| PT-02 | Log do serviço após o PT-01 | Linha de colagem com veredito Block | ✅ `Colagem em destino de saida ... chrome (origem Notepad, veredito Block). Bloqueadas 1 de 1 colagens.` |
| PT-03 | Copiar o CPF; colar no Word | O CPF original (app local não é saída) | ✅ Veio o original, sem balão nem linha de colagem |
| PT-04 | Copiar "reunião às 14h"; colar no Chrome | O texto limpo | ✅ Colou normal |
| PT-07 | Copiar o CPF; fechar o App pela bandeja; colar no Chrome | O CPF original (devolução ao sair) | ✅ Veio o original |

### O que o teste provou

- **Bloqueia o que deve:** CPF para o navegador vira o aviso, com evento `Blocked` na auditoria.
- **Não bloqueia demais:** app local e texto comum passam sem atrito, e o log não registra colagem
  nesses casos.
- **A decisão pelo primeiro plano funciona** com o serviço e o App reais, não só no experimento.
- **Não perde dado:** fechar o App devolve a cópia ao clipboard.
- **Privacidade:** o log do serviço mostra só `[Cpf]`, nunca o número.

### O que não foi coberto

- **Diagnóstico de montagem.** Na primeira tentativa "nenhum caso funcionou": o serviço tinha subido
  sem a política local (buscando o painel, que está fora do ar), então liberava tudo (RN-013). Com o
  argumento `--CentroAdministracao:BaseUrl=`, passou. Fica o registro de que o sintoma de "não
  bloqueia nada" é, quase sempre, a política não ter carregado.
- **Modo Audit** no App real não foi exercido à mão (o mecanismo é o mesmo do Block, menos a troca
  pelo aviso; a decisão em Audit está nos testes automáticos).
- **PT-05 e PT-06** (duas colagens seguidas; busca do CPF no log) não foram repetidos à mão nesta
  rodada; a não-aderência da decisão está medida na Fase 2 (casos H e I) e a ausência de texto no
  evento, nos testes automáticos.
- Teams e WhatsApp pelo App real: a técnica foi validada neles na Fase 2, com o mesmo proxy; aqui o
  destino de saída testado à mão foi o Chrome.

## Limites: o que a suíte não prova

- Nada rodou no **Windows 10 22H2** (plataforma do driver).
- O **proxy OLE** não tem teste de unidade; a validação é a manual acima.
- **App fechado**, **corrida de 250 ms** e **leitor em segundo plano**: limites de desenho, descritos
  em [FASE-3-BLOQUEIO-NA-COLAGEM.md](FASE-3-BLOQUEIO-NA-COLAGEM.md).

## Pendente

| Ponto | Com quem |
|---|---|
| Repetir o roteiro manual no Windows 10 22H2 | Equipe |
| Exercer o modo Audit no App real | Clipboard |
| Veredito próprio para colagem em Audit | Painel |
