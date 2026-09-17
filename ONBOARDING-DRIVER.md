# O driver do Victor — guia de retomada

> Documento gerado em 2026-09-09 a partir de uma investigação completa do branch
> `origin/develop-victor-minifiltro-driver` (78 commits, 3–9/09/2026), cruzando
> `driver/ARQUITETURA.md`, `driver/DEPLOY.md`, o código-fonte C do driver e a
> integração C#. Objetivo: você conseguir continuar o trabalho do Victor sem
> precisar reconstruir esse contexto do zero.
>
> **Este arquivo não está no branch do driver — está solto no repo, só pra
> leitura.** O código de verdade só existe em
> `origin/develop-victor-minifiltro-driver` (`git checkout` nesse branch pra
> trabalhar nele).

---

## 0. Por que este documento existe

Durante uma revisão do repositório, foi descoberto que o merge do PR #4
(`481ae9a`, "Adiciona tela básica para agente desktop") **apagou** por engano os
projetos `SafeUpload.Agent.App/Core/Service/Tests` (autor: Victor Bonato) da
branch `main`, substituindo-os por um mockup visual sem lógica (`SafeUploadAgent`,
de Luís/`lzhar`). Nada foi perdido de verdade — está no histórico git — mas
sumiu da `main`, e isso já causou retrabalho (uma tela de histórico foi
reconstruída do zero por outro colega, duplicando algo que já existia pronto).

Paralelamente, descobriu-se que o Victor, pra evitar que isso acontecesse de
novo, passou a trabalhar isolado num branch próprio
(`develop-victor-minifiltro-driver`), onde evoluiu o projeto de um simples
serviço com `FileSystemWatcher` para um **driver de kernel Windows de verdade**
(minifiltro). Esse branch ainda não foi mesclado com ninguém — a decisão de
restaurar o código antigo e integrar o driver é do time.

---

## 1. O que é um minifiltro driver (do zero)

Toda operação de arquivo no Windows passa por uma estrutura chamada **IRP**
(*I/O Request Packet*): "abra este arquivo", "leia estes bytes", "renomeie",
etc. O **Filter Manager** (`FltMgr.sys`) permite que drivers de kernel se
registrem numa pilha e sejam chamados a cada IRP que passa por ali — de
qualquer processo da máquina, não só de pastas que você escolheu observar.
Cada driver ocupa uma **altitude** (posição numérica) nessa pilha, que ordena
vários filtros concorrentes (antivírus, sync de nuvem, DLP) observando a mesma
operação.

Para cada tipo de IRP, um minifiltro registra um callback de:
- **pré-operação** — roda *antes* da operação acontecer. É aqui que dá pra
  **negar de verdade**, garantindo zero bytes gravados.
- **pós-operação** — roda *depois*, quando o resultado já existe. Útil para
  reagir a algo que só existe depois do create (como o contexto de fluxo,
  ver §5), mas negar aqui é mais caro (a operação já começou; usa-se
  `FltCancelFileOpen` pra desfazer).

No `IRP_MJ_CREATE` (abrir/criar arquivo) é onde a decisão de bloqueio
acontece. Outros tipos relevantes usados neste projeto:
`IRP_MJ_SET_INFORMATION` (rename, hard link, delete),
`IRP_MJ_CLEANUP` (fechamento de handle).

### Por que isso substitui o `FileSystemWatcher`

| | `FileSystemWatcher` (modo usuário, o que já existia) | Minifiltro (o que o Victor construiu) |
|---|---|---|
| Quando avisa | **Depois** que o arquivo já existe no destino | **Antes**, no pré-create |
| Pode impedir a operação | Não — só reage apagando/movendo depois | Sim — nega, nada chega a ser criado |
| Sabe o processo de origem | Não (PID sempre chega como zero) | Sim, confiável |
| Custo de um bug | Trava o aplicativo | Pode causar **tela azul** (derruba a máquina) |

O `README.md` do agente documenta essa limitação como "de natureza, não de
implementação":

> "A negação não é síncrona nem pré-operação. Esta é a limitação central. [...]
> aqui o arquivo existe no destino por alguns instantes e o bloqueio é uma
> remoção posterior. Durante essa janela, o dado já está lá. Nenhum ajuste em
> modo usuário resolve isso."

**Os dois modos nunca sobem juntos** — é uma escolha de configuração
(`appsettings.json`, `Interception:Mode`), com o `FileSystemWatcher` como
*fallback* de segurança padrão: "uma máquina sem o driver deve ficar protegida
de forma imperfeita em vez de ficar sem proteção nenhuma."

---

## 2. Os 7 projetos e como se encaixam

```
driver/SafeUpload.Minifilter/         ← o driver de kernel em C (vira SafeUpload.sys)
driver/SafeUpload.Inspector/          ← sonda de teste burra em C (legado)
agente/SafeUpload.Agent.Minifilter/   ← protocolo/porta em C# (Protocol, FilterPort, PolicyBuilder)
agente/SafeUpload.Agent.Service/      ← o serviço Windows real, com MinifilterInterceptor
agente/SafeUpload.Agent.Core/         ← o domínio que já existia (validadores, InspectionService)
agente/SafeUpload.Fixtures/           ← gerador de arquivos de teste realistas (.docx/.xlsx/.pdf)
agente/SafeUpload.Minifilter.Probe/   ← sonda de teste em C# (sucessora do Inspector)
```

> ⚠️ **Cuidado ao ler `driver/DEPLOY.md`**: ele descreve uma pasta `service/`
> que **não existe mais**. O Victor criou essa pasta primeiro, duplicando por
> engano o que `agente/` já tinha, e depois consolidou tudo — confissão dele
> mesmo no commit `64d36ea`: *"escrevi um `Decide()` com `BLOQUEAR_TESTE`
> competindo com um motor de inspeção de verdade [...] não li o README nem
> listei o repositório."* Onde ler `service/SafeUpload.Agent/...`, mentalmente
> troque por `agente/SafeUpload.Agent.Minifilter/` e
> `agente/SafeUpload.Agent.Service/`.

### Fluxo ponta a ponta (exemplo real do `ARQUITETURA.md`)

```
1. Word abre C:\docs\clientes.xlsx pra leitura
   → pré-CREATE do driver: portas baratas (extensão monitorada? origem sensível?)
   → sem veredito em cache → pós-CREATE manda 1 mensagem ao serviço C#
   → serviço extrai texto (OpenXml), varre com CpfValidator etc., responde "sensível"
   → driver PERMITE a leitura (negar aqui impediria trabalho legítimo)
     mas grava o veredito no contexto do arquivo E marca o processo do Word
     como "contaminado"

2. Usuário faz "Salvar como" num pendrive (E:\)
   → pré-CREATE: processo contaminado + destino removível
   → RECUSA só consultando uma tabela hash — SEM ida ao modo usuário,
     zero bytes gravados no pendrive
```

Quem fala com quem:
- O **driver** decide sozinho nos casos baratos; só sobe ao modo usuário
  quando não tem veredito em cache.
- A **porta de comunicação** (`\SafeUploadPort`) aceita **uma única conexão
  simultânea** — por isso é o **serviço Windows** (LocalSystem) quem a segura;
  o app WPF nunca fala com o driver diretamente, só com o serviço.
- O **`MinifilterInterceptor`** (dentro do serviço) reaproveita 100% do motor
  de inspeção, validadores e extratores que já existiam — não foi reescrito.

---

## 3. O protocolo kernel↔user-mode

Definido uma vez em C (`driver/SafeUpload.Minifilter/Protocol.h`) e espelhado
à mão em C# (`agente/SafeUpload.Agent.Minifilter/Protocol.cs`). Layout fixo
(`#pragma pack(push, 8)`, sem ponteiros, campos de largura explícita). O lado C
fecha com `C_ASSERT` travando `sizeof`/offset de cada struct — se alguém mudar
o layout num lado e esquecer o outro, **a build do driver quebra**, não o
runtime.

Do lado C#, `Contract.Verify()` roda **antes** de conectar na porta — se os
tamanhos não baterem, o serviço nem tenta subir o gatilho de kernel.

Mensagens principais:
- `SAFEUPLOAD_REQUEST` (kernel→user, 1192 bytes): PID, caminho, flags de
  escopo origem/destino.
- `SAFEUPLOAD_RESPONSE` (user→kernel, 24 bytes): veredito Allow/Deny.
- `SAFEUPLOAD_POLICY_MESSAGE` (~19 KB): política inteira (extensões,
  prefixos de destino/origem, processos excluídos, timeout).
- `SAFEUPLOAD_OVERRIDE_MESSAGE`: concessão de exceção com justificativa.
- `SAFEUPLOAD_COUNTERS`: telemetria cumulativa (creates vistos, hits de
  cache, negações por estágio).

**Regra de ouro, repetida em pelo menos 5 lugares independentes do código**:
qualquer falha no protocolo (timeout, versão desconhecida, porta fechada,
exceção) = **ALLOW**. Nunca há um caminho que resolva incerteza bloqueando.

> ⚠️ **Verifique antes de escrever código novo**: a versão do protocolo mudou
> várias vezes ao longo dos commits (2→3→6→7→8→10). Confira o valor atual
> direto em `Protocol.h`, não confie no que os documentos dizem.

---

## 4. As decisões de design mais importantes

### Cache de veredito por "contexto de fluxo" — a virada estrutural da v2

O coração de tudo. Objetivo: **uma ida ao modo usuário por versão de arquivo**,
não por operação. O contexto de fluxo (`FLT_STREAM_CONTEXT`) só existe
**depois** do create — por isso a consulta ao cache migrou do pré-create pro
pós-create, e negar passou a ser `FltCancelFileOpen` (desfaz uma operação que
já começou tecnicamente). O contexto guarda: veredito, um "carimbo" (tamanho +
data de modificação, pra saber se o arquivo mudou por fora) e um flag de
"sujo" (invalidado se um handle aberto pra escrita fecha).

### Três níveis de contexto

- **Instância** (por volume): "isso é removível/rede/local?" — calculado 1x
  quando o volume monta.
- **Fluxo** (por arquivo): o veredito — sobrevive ao fechamento, serve
  qualquer processo que reabra o mesmo arquivo depois.
- **Handle**: "este handle específico escreve num destino monitorado" —
  fecha o furo de abrir antes de se contaminar e escrever depois.

### Contaminação de processo (taint) — a regra central do bloqueio

Tabela hash por PID. A cadeia tem **dois elos em lugares diferentes de
propósito**:

- **Pós-create, escopo origem**: achou conteúdo sensível → **não nega** (você
  tem direito de abrir seu próprio arquivo) → **marca o processo**.
- **Pré-create, escopo destino**: processo marcado abre destino monitorado
  pra escrita → **nega ali**, sem consultar modo usuário, sem criar nada.

TTL de 5 minutos (senão o Explorer ficaria banido de USB até reiniciar a
máquina), limpeza automática na saída do processo (senão um PID reciclado
herdaria marca alheia). **Custo aceito e documentado**: exfiltração indireta
via IPC entre dois processos **não é coberta** — decisão consciente, não
brecha esquecida.

### Override/justificativa (mecanismo pronto, UI pendente)

1. Bloqueio original vira uma entrada em `PendingOverrides` (3 min de
   validade).
2. App manda `JustificationRequest` por named pipe dedicado.
3. Serviço valida (política permite? prazo válido? mesma sessão que recebeu
   o aviso?) e **audita antes de conceder** — "concedendo primeiro, uma falha
   aqui deixaria a exceção de pé sem registro nenhum de quem a pediu."
4. A concessão entra numa fila (`OverrideGrantQueue`) porque a porta do
   driver só tem 1 cliente, e quem a segura é a thread do
   `MinifilterInterceptor` — outra thread não pode falar com o driver direto.
5. O loop principal drena a fila e manda `GRANT_OVERRIDE` pro driver.
6. Driver grava numa tabela de 16 slots: **processo + caminho exato de
   destino** (não prefixo), 10–120s, um uso só.
7. Próxima tentativa: driver consome a entrada e libera — nunca vira
   "período de liberdade geral".

**A UI pra digitar a justificativa não existe ainda** — é o item mais visível
que falta.

### Hard link e rename — a descoberta contraintuitiva

Um gancho foi escrito pra pegar renomeação/hard-link pra dentro de pasta
monitorada. Medição real mostrou que **nenhum dos dois casos chega nesse
gancho** — o Win32/NTFS já emite uma abertura interna do nome de destino
*antes*, que o pré-create já recusa. O primeiro instrumento de medição (um
bitmap global) enganou o Victor a achar que chegava; contadores dedicados
provaram zero. Lição dele, literal:

> "Um agregado global não responde uma pergunta sobre uma operação específica,
> por mais que pareça responder."

O gancho **ficou** mesmo assim, como cinto de segurança — a recusa mais cedo
depende de comportamento observado do Windows, não de contrato documentado.

### Por que `IRP_MJ_READ` foi removido

Duas fases: primeiro por performance (o create já pedindo `FILE_READ_DATA` já
é "declaração de intenção de ler"). Depois virou urgente — um bug de
use-after-free (lendo `FileObject->FileName` fora da janela em que é válido)
causou um **crash real na VM de teste**, inicialmente culpado erroneamente no
`condrv.sys`. Removendo o gancho, o bug some, mas isso trouxe um reflexo: sem
aquela porta de extensão, toda leitura de todo processo passou a subir ao
modo usuário, criando um loop de realimentação (o próprio log do inspetor
sendo lido provocava nova inspeção). Se um dia voltar: só com
`SKIP_CACHED_IO` e apoiado em contexto de handle, nunca como estava.

### Timeout vindo da política, não de constante fixa

Movido de uma constante de compilação (500ms) pra dentro da mensagem de
política, porque RN-012 dá ao motor de inspeção até 5s. Medição real de custo
de extração:

| Tamanho do documento | Tempo |
|---|---|
| 400 parágrafos / 2,6 KB | 34 ms |
| 10000 / 33 KB | 259 ms |
| 40000 / 126 KB | 640 ms |
| `.xlsx` de 229 KB | 971 ms |

> "500 ms quebrava a partir de uns 50 KB, tamanho de documento comum."

### `AllowedWithoutInspection` — a assimetria origem/destino

Três caminhos fazem um arquivo passar sem ser lido: `file_too_large` (>20MB),
`unsupported_format`, `inspection_timeout`. Originalmente os três liberavam
**sem marcar o processo** — um furo trivial (bastava inflar o arquivo até
passar do limite). Corrigido usando a mesma assimetria do taint:

```
origem  + não inspecionado  →  DENY  →  marca o processo, leitura permitida
destino + não inspecionado  →  ALLOW →  inalterado (negar ali impede trabalho)
```

---

## 5. Segurança e assinatura (resumo prático)

O driver usa um **certificado de teste autoassinado** (não é assinatura real
da Microsoft), guardado no repositório de certificados do Windows (não como
`.pfx` solto). Só funciona em VM com Secure Boot desligado e test signing
ligado.

Ordem de assinatura importa: assinar o `.sys` **primeiro** → gerar o
catálogo (`Inf2Cat`, que depende do hash do `.sys` já assinado) → assinar o
catálogo. O `.cer` (público) vai pra VM alvo; o `.pfx` (privado) **nunca sai**
da máquina de desenvolvimento.

**Altitude do driver é provisória (321410)** — está na faixa certa
(FSFilter Anti-Virus) mas não é alocada oficialmente pela Microsoft. Risco
real de colisão com qualquer antivírus de verdade. **Não instalar fora de VM
descartável.**

---

## 6. Como testar (o pipeline do Victor)

Duas VMs: uma "de desenvolvimento" (compila, assina) e uma "VM alvo
descartável" (instala, testa — **nunca** a máquina real; tirar snapshot
antes).

- **`Publish-SafeUpload.ps1`** (roda na VM de dev): compila, assina `.sys`,
  gera e assina o catálogo, publica o serviço real (self-contained +
  single-file) e a sonda de teste (Native AOT), gera fixtures de teste
  reais, serve tudo via `serve.py`.
- **`Invoke-SafeUploadTest.ps1`** (roda na VM alvo, elevado): confere
  pré-requisitos, baixa o pacote, confere hash, carrega o filtro, roda a
  bateria completa (permitido/bloqueado/cache/taint/rename/RN-013/
  justificativa/auditoria), confere vazamento via Driver Verifier.
- **`serve.py`**: ponte HTTP simples entre as duas VMs, recebe os
  resultados de volta.

Ferramentas de teste dedicadas:
- **`SafeUpload.Fixtures`**: gera `.docx`/`.xlsx`/`.pdf` de teste reais
  (não `.txt`, que "não mede nada que importe"), com CPF sintético válido
  sempre no fim do documento.
- **`SafeUpload.Minifilter.Probe`**: sonda deliberadamente burra (decide
  por string, nunca roda a inspeção real) — "senão toda falha fica ambígua
  entre driver e agente".

---

## 7. Qualidade do código C — é sério, não é protótipo

- Cada função documenta seu IRQL; `PAGED_CODE()` consistente nas rotinas
  paginadas.
- Pool tagueado (`SAFEUPLOAD_POOL_TAG`), liberado simetricamente em todo
  path de erro.
- `try/except` com `ProbeForRead`/`ProbeForWrite` corretos antes de tocar
  ponteiro de modo usuário; copia pro kernel antes de validar (evita
  TOCTOU).
- Locks: `EX_PUSH_LOCK` pra política (leitura dominante), `EX_RUNDOWN_REF`
  pra proteger o canal de comunicação durante unload.
- `/W4 /WX` (warnings viram erro).
- CodeQL: suíte `mustfix` limpa (0 achados); os 2 achados de
  `recommended` são falsos positivos confirmados e documentados.
- Fail-open é aplicado de forma consistente em **todo** ponto de falha.

---

## 8. Dívida técnica conhecida — leia com atenção

| Severidade | Problema | Detalhe |
|---|---|---|
| 🔴 Crítico | **Vazamento de memória no unload — NÃO RESOLVIDO** | Bugcheck `0xC4`/`0x62`. O próprio Victor: *"registrado para não se perder, porque não foi resolvido — apenas deixou de reproduzir."* Três mudanças aconteceram juntas e nenhuma foi isolada como causa. **Pode voltar se o tráfego aumentar.** Se voltar: ligar `CrashDumpEnabled=2` ANTES de reproduzir, usar `!verifier 0x80 SafeUpload.sys` (não `Arg2`/`Arg3` do bugcheck). |
| 🟡 Médio | **Build de Release quebrado** | Desde `Override.c`, só o binário **Debug** passa no `ApiValidator`. É o Debug que a bateria testa hoje. |
| 🟡 Médio | **Altitude provisória (321410)** | Não alocada oficialmente pela Microsoft — risco de colisão com antivírus real. |
| 🟡 Médio | **Cliente de porta é single-thread** | `FilterGetMessage` bloqueia a thread chamadora — toda abertura monitorada da máquina faz fila atrás do veredito mais lento. |
| ⚪ Nota | **"Executável nativo único" não é bem assim** | O commit que fala isso se refere ao projeto `service/` antigo, descartado. O `SafeUpload.Agent.Service` real publica self-contained + single-file, **não** AOT (usa DI + OpenXml/PdfPig, que "o AOT poda mal"). Só a sonda `Minifilter.Probe` é AOT de verdade. Confirmar com o Victor se isso era esperado. |

---

## 9. O que falta (roteiro do próprio Victor, já priorizado)

**✅ Feito:** contadores, política empurrada pela porta, contaminação de
processo, cache por contexto de fluxo, prazo vindo da política, modo
auditoria, extrator de PDF (via PdfPig), detector de segredos (chaves
AWS/GitHub/Google/Slack/JWT via regex — sem entropia, de propósito, pra não
incomodar em máquina de desenvolvedor).

**⏳ Pendente, em ordem:**
1. UI de justificativa (mecanismo em kernel já pronto e testado)
2. Classificação de arquivo persistida entre reboots
3. Cobertura de área de transferência (clipboard)
4. Hash de documento exato (EDM/IDM)
5. Impressão e upload por navegador ("cada um é um projeto próprio")
6. Pool de threads na porta de comunicação
7. Altitude definitiva junto à Microsoft ("não é trabalho, é fila")

---

## 10. Detector de segredos e extrator de PDF — o que foi adicionado neste branch

**`SecretDetector`** — detecta por regex fixa (sem entropia, decisão
deliberada: entropia pegaria hash/UUID/base64 de qualquer arquivo e tornaria
o agente insuportável numa máquina de dev):

| Tipo | Padrão |
|---|---|
| Chave privada | cabeçalho PEM `-----BEGIN ... PRIVATE KEY-----` |
| Chave AWS | `AKIA`/`ASIA`/etc. + 16 caracteres |
| Token GitHub | `gh[pousr]_...` |
| Chave Google | `AIza...` |
| Token Slack | `xox[baprs]-...` |
| JWT | 3 segmentos base64url separados por ponto |

**`PdfExtractor`** — usa a biblioteca **PdfPig**, extrai por ordem de
*desenho* do texto (não posição geométrica — evita colar números de colunas
vizinhas). **Não faz OCR** — PDF escaneado (imagem) não gera achados, e isso
é declarado explicitamente no código, não escondido.

---

## Fontes

- `driver/ARQUITETURA.md` (1095 linhas) e `driver/DEPLOY.md` (1148 linhas),
  ambos escritos pelo Victor, no branch `develop-victor-minifiltro-driver`.
- Código-fonte completo de `driver/SafeUpload.Minifilter/*.c/.h`,
  `driver/SafeUpload.Inspector/main.c`.
- Integração C#: `agente/SafeUpload.Agent.Minifilter/*`,
  `agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs`,
  `agente/SafeUpload.Agent.Core/Domain/Validators/SecretDetector.cs`,
  `agente/SafeUpload.Agent.Core/Infrastructure/Extraction/PdfExtractor.cs`.
- Corpo integral de ~40 mensagens de commit (`docs(driver):`, `feat(driver):`,
  `fix(driver):`) entre `fc8ed6f` e `4020dea`.
