# Planejamento — driver SafeUpload

> Arquivo de trabalho local, não commitado ainda. Criado em 2026-09-17 pra
> registrar as decisões da sessão de hoje (apresentação amanhã) antes de
> começar a implementar, e servir de backlog organizado pras próximas.

---

## O backlog completo (ClickUp), organizado por dependência real

A lista original tinha 16 itens soltos. Investigando o código, eles se
agrupam assim (não é a ordem em que vieram no ClickUp):

### Grupo A — mesmo bug raiz, confirmado no código, **fazendo hoje**
1. Armazenar no cache somente vereditos recebidos com sucesso
3. Contabilizar corretamente timeouts e respostas inválidas em `AllowedWithoutInspection`

**Causa raiz (confirmada em `driver/SafeUpload.Minifilter/`):**
- `Communication.c:394-408` (`SafeUploadRequestVerdict`) — `FltSendMessage` pode
  devolver `STATUS_TIMEOUT`, que é status classe-sucesso
  (`NT_SUCCESS(STATUS_TIMEOUT) == TRUE`).
- `Filter.c:902-907` (`SafeUploadEvaluate`) — `if (!NT_SUCCESS(status))` não
  pega timeout por causa disso. Só incrementa `AllowedWithoutInspection` em
  falhas "duras" (porta fechada, sem memória).
- `Filter.c:1425` — `(VOID) SafeUploadEvaluate(...)`: o status é **descartado**
  pelo chamador.
- `Filter.c:1433-1434` — o cache é gravado só olhando `scopeFlags != 0`,
  nunca se a resposta veio de uma inspeção real:
  ```c
  streamContext->Verdict = verdict;
  streamContext->VerdictValid = (BOOLEAN) (scopeFlags != 0);
  ```

**O que isso causa:** um timeout vira `ALLOW`, esse `ALLOW` fica **cacheado**
como se fosse veredito de verdade. Um arquivo sensível que não pôde ser
inspecionado passa livre em **todas** as aberturas seguintes, até o conteúdo
mudar — não só na hora do timeout.

**A correção (não muda política, só correção de estado):**
Threadear um booleano "resposta obtida com sucesso" (nem toda `ALLOW` é
igual — precisa distinguir "verifiquei e é seguro" de "não consegui
verificar") desde `SafeUploadRequestVerdict` → `SafeUploadEvaluate` → o ponto
que grava o cache e conta o contador. Ideia:
- `SafeUploadRequestVerdict` já sabe internamente se voltou `STATUS_SUCCESS`
  de verdade vs. timeout/erro — só precisa **expor** isso, não só devolver o
  veredito.
- `SafeUploadEvaluate` propaga esse booleano pro chamador em vez de descartar.
- `Filter.c:1433-1434`: só marca `VerdictValid = TRUE` quando a resposta foi
  bem-sucedida **e** está em escopo.
- `Filter.c:902-907`: contar `AllowedWithoutInspection` sempre que a resposta
  não foi bem-sucedida (troca a checagem de `NT_SUCCESS` por essa flag
  explícita, não mais por status code).

**Teste esperado:** forçar timeout (inspetor não responde), confirmar (a)
`AllowedWithoutInspection` sobe no contador, (b) o arquivo **não** fica em
cache — reabrir o mesmo arquivo deve tentar de novo, não servir do cache.

---

### Discussão de política (RN-013) — decisão: **manter fail-open**

Levantamos se fail-open é a escolha certa. Conclusão da conversa:

- RN-013 é regra de negócio formal, implementada em dobro (driver C **e**
  `InspectionService` C#), testada explicitamente (`InspectionServiceTests`).
- Motivo documentado no próprio código
  (`Communication.c:271-273`, `SafeUploadPortDisconnect`): *"an inspector
  that crashed must not take the file system down with it"* — o driver fica
  na frente de toda operação de arquivo em escopo da máquina inteira; fail-closed
  aqui significa risco de travar operações de arquivo do SO inteiro se o
  serviço cair, não só falhar um app.
- Bate com o padrão de mercado que o Victor já tinha levantado (Forcepoint/
  Symantec/Purview também são fail-open no nível de kernel).
- **Decisão: manter fail-open.** Mudar isso é decisão de time/requisito
  oficial, não algo pra fazer sob pressão de prazo.
- **Vira observação de análise crítica pra apresentação**, não código.

---

### Achado extra da conversa: fail-open é silencioso em produção — **não é hoje, mas não esquecer**

Confirmado no código: `GetCounters()` só é chamado por
`SafeUpload.Minifilter.Probe/Program.cs` (ferramenta manual de teste). Nada
em `MinifilterInterceptor.cs` ou no app WPF lê o contador do kernel em
produção. Ou seja: mesmo depois de corrigir a contagem (item 3), **ninguém
observa esse contador de verdade** — ele fica correto, mas inerte.

**Não faz parte do Grupo A.** É trabalho novo de encanamento (puxar o
contador periodicamente do serviço, decidir onde ele aparece — log? alerta?
painel?). Fica registrado aqui como candidato a próximo item do backlog,
próximo do item 11 (medir taxa de acerto do cache), porque é a mesma ideia:
telemetria do kernel → visibilidade humana.

---

### Grupo B — item 2, não implementado, maior que parece
2. Invalidar o cache quando a política ou as regras de detecção mudarem

Não existe **nenhum** conceito de versão/geração de política no driver hoje
(confirmado — busquei `PolicyVersion`/`Generation` em todo `driver/` e não
achei nada). Diferente do `VerdictCache` em C#, que já tem isso. Exige:
contador global de geração (incrementa a cada `SET_POLICY` em `Policy.c`),
gravar no contexto de cada arquivo, comparar na consulta do cache
(`Filter.c` ~linha 1408-1411). Mexe na struct do contexto — candidato a
segunda entrega hoje, **se sobrar tempo** depois do Grupo A.

---

### Grupo C — dependência documentada pelo próprio Victor, não fazer sob pressão
6. Substituir o consumidor síncrono da porta por um pool limitado de workers
8. Implementar marcação provisória enquanto uma inspeção continua em segundo plano
9. Limpar marcações provisórias quando o serviço desconectar

8 e 9 **exigem** 6 como pré-requisito (documentado no próprio
`ARQUITETURA.md` do Victor). Featureset grande — protocolo novo, estado por
PID, limpeza na desconexão. Não entra no plano de hoje.

---

### Demais itens (sem investigação de código ainda, avaliação inicial)

| # | Item | Avaliação |
|---|---|---|
| 4 | Persistir classificações por volume+FileID+sequência | Feature nova, território novo (USN journal). Par com o 5. |
| 5 | Invalidar classificações persistidas na mudança de política/classificador | Depende do 4 existir primeiro. |
| 7 | Responder ao kernel antes de notificações/auditorias não essenciais | Otimização de latência — não verificada ainda se já está assim ou não. |
| 10 | Medir latência/timeout com DOCX/XLSX grandes | Depende da infra de VM (`Publish`/`Invoke` scripts) rodando. |
| 11 | Medir taxa de acerto do cache em uso cotidiano | Mesma dependência de infra + a lacuna de observabilidade acima. |
| 12 | Medir falsos positivos por marcação de processo | Idem — precisa de uso real/VM. |
| 13 | Inspeção do conteúdo completo no egresso | Mudança de arquitetura maior (hoje é taint, não conteúdo, no destino). |
| 14 | Classificação de documentos por hash SHA-256 | Feature nova e isolada (EDM/IDM), razoável, não urgente. |
| 15 | Corrigir falha do ApiValidator no build Release | Já resistiu à investigação do próprio Victor ("nunca totalmente explicado"). Risco alto pra hoje. |
| 16 | Rodar CodeQL/validações no build Release | Depende do 15. |

---

## Plano de execução de hoje

1. ✅ Entender o Grupo A a fundo (feito nesta conversa)
2. ✅ Implementar a correção do Grupo A (itens 1+3) — código feito, ver abaixo
3. ⏳ **Compilar e validar na VM — ainda não feito.** Esta máquina não tem
   WDK/Visual Studio, não foi possível compilar nem testar aqui.
4. Se sobrar tempo: avaliar o Grupo B (item 2)
5. Preparar a observação sobre fail-open silencioso + a decisão de manter
   RN-013 como material de apresentação (não é código)

---

## Grupo A — o que foi implementado (2026-09-17)

**Ideia central**: `SafeUploadRequestVerdict` já sabia distinguir internamente
"consegui uma resposta de verdade" de "caiu em fail-open", mas essa
informação nunca saía da função — só o veredito (`ALLOW`/`DENY`) saía, e o
`NTSTATUS` de retorno era ambíguo (`STATUS_TIMEOUT` é status classe-sucesso).
A correção foi expor essa distinção explicitamente como um parâmetro
`Answered` (booleano), e propagar até o ponto que grava o cache e conta o
contador.

**Arquivos alterados:**

| Arquivo | O que mudou |
|---|---|
| `Filter.h` | Assinatura de `SafeUploadRequestVerdict` ganhou `_Out_ PBOOLEAN Answered`. |
| `Communication.c` | `SafeUploadRequestVerdict`: `*Answered = FALSE` por padrão; vira `TRUE` só depois que uma resposta válida (tamanho certo, versão certa, `RequestId` batendo) é confirmada — logo antes de decidir ALLOW/DENY. |
| `Filter.c` — `SafeUploadEvaluate` | Assinatura mudou de `NTSTATUS` pra `BOOLEAN` (o único bit que o chamador realmente usava). Retorna `TRUE` quando: fora de escopo, processo excluído (RN-014), ou resposta real do modo usuário. Retorna `FALSE` (e conta `AllowedWithoutInspection`) quando: falha de alocação, falha ao resolver o nome, ou `Answered=FALSE` vindo de `SafeUploadRequestVerdict` (porta fechada, timeout, resposta malformada). |
| `Filter.c` — `SafeUploadPostCreate` | O `(VOID) SafeUploadEvaluate(...)` que descartava o resultado virou `inspected = SafeUploadEvaluate(...)`. O cache agora só marca `VerdictValid = TRUE` quando `scopeFlags != 0 **e** inspected` — antes era só `scopeFlags != 0`. |

**O que isso resolve:**
- Item 1: um veredito só entra no cache quando foi de fato checado — nunca
  mais uma falha vira aprovação permanente.
- Item 3: `AllowedWithoutInspection` agora conta com base no sinal explícito
  `Answered`, não em `NT_SUCCESS(status)` — cobre `STATUS_TIMEOUT`
  corretamente, que antes escapava da contagem por ser status classe-sucesso.

**Pendente, precisa da sua VM:**
1. Compilar (`MSBuild driver\SafeUpload.Driver.sln`, ou `Publish-SafeUpload.ps1`).
2. Validar manualmente (roteiro abaixo) — não criei um teste automatizado
   novo no `Invoke-SafeUploadTest.ps1` porque não consigo rodar o script pra
   garantir que funciona; o `Caso 11` existente testa que fail-open funciona,
   mas não testa especificamente que o resultado não fica preso em cache.

### Roteiro de validação manual (na VM alvo)

1. Com o driver carregado e a sonda (`Probe`) conectada, abra um arquivo em
   escopo qualquer — confirme que abre normal.
2. Pare a sonda/inspetor (`Stop-Inspector`, ou feche o processo).
3. Abra esse **mesmo arquivo** de novo — deve abrir (fail-open). Rode
   `SafeUpload.Minifilter.Probe --counters` (com outra instância, ou antes de
   parar — ajuste conforme o fluxo do script) e confirme que
   `AllowedWithoutInspection` subiu.
4. Suba a sonda de novo, agora configurada (ou troque temporariamente por uma
   política/regra) pra **negar** esse mesmo arquivo.
5. Abra o arquivo pela terceira vez, **sem alterar o conteúdo/tamanho/data**.
   - **Se a correção estiver certa**: o arquivo agora é negado — prova que o
     `ALLOW` do passo 3 não ficou em cache.
   - **Se ainda tiver o bug**: o arquivo continua abrindo normalmente, porque
     o `ALLOW` do fail-open ficou cacheado e a nova consulta nunca acontece.

---

## Notas pra não esquecer

- Estamos no branch `develop-victor-minifiltro-driver` (checkout feito em
  2026-09-17). Nada foi mesclado com `main` ainda.
- `origin/develop-victor-minifiltro-driver` não teve nenhum commit novo desde
  a última investigação (`4020dea` continua sendo o topo, confirmado hoje).
- Existe um `ONBOARDING-DRIVER.md` na raiz do repo (branch `main`, não neste
  branch) com o mapeamento completo da arquitetura do driver, caso precise
  relembrar o quadro geral.
