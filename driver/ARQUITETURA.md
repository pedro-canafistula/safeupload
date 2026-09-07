# Arquitetura do minifiltro SafeUpload — v2

Documento de desenho. Descreve como o minifiltro deve evoluir da v1
(interceptar tudo, perguntar sempre) para uma versão que sustenta uso real.

## Escopo desta versão

**Dentro:**

- Cópia de arquivo para mídia removível, compartilhamento de rede e pasta de
  sincronização de nuvem.
- Leitura de arquivo de origem sensível.
- Bloqueio **antes** de qualquer byte chegar ao destino.

**Fora, e explicitamente não coberto:**

- Copiar e colar texto. Nenhuma operação de arquivo acontece quando o usuário
  seleciona texto em um documento e cola em um formulário — não há nada para
  um filtro de sistema de arquivos interceptar. Exige um ouvinte de área de
  transferência na sessão do usuário.
- Digitação direta de dado sensível em formulário web.
- Upload HTTP em si. O filtro pode negar a *leitura* do arquivo pelo
  navegador; não vê o POST.

Isso precisa estar escrito porque é a diferença entre "o SafeUpload previne
vazamento" e "o SafeUpload previne vazamento por arquivo". Só a segunda
afirmação é verdadeira com este componente sozinho.

---

## O princípio

Um minifiltro vê toda operação de arquivo da máquina. Em um Windows ocioso
isso já são milhares de `IRP_MJ_CREATE` por segundo. Qualquer desenho que
faça trabalho apreciável por operação é inviável, e qualquer desenho que
converse com o modo usuário por operação é catastrófico — foi o que a v1
fez, e por isso a VM ficou perceptivelmente lenta.

Os três alvos que guiam todo o resto:

| Alvo | Valor |
|---|---|
| Operações resolvidas inteiramente em kernel | **> 99%** |
| Idas ao modo usuário | **1 por versão de arquivo**, não por operação nem por handle |
| Idas ao modo usuário no caminho de **bloqueio** | **zero** |

O terceiro é o mais importante e o menos óbvio: quando o driver decide negar
uma cópia para o pendrive, ele já sabe a resposta. A inspeção cara aconteceu
antes, em outro momento, e o resultado estava guardado.

---

## Como se bloqueia antes da escrita

Existe um impedimento fundamental que descarta a abordagem ingênua: **não se
inspeciona conteúdo parcial**. Um `.docx` é um ZIP cujo índice central fica
no fim do arquivo; com 40% dele gravado não há extração possível. E um CPF
pode cair exatamente na fronteira entre dois blocos de escrita. Inspecionar
o fluxo de escrita para o destino não funciona.

A saída é decidir na **origem** e propagar por **contaminação de processo**:

```
1. Word abre C:\docs\clientes.xlsx pedindo leitura
   -> pré-CREATE: extensão monitorada, sem veredito em cache
   -> uma ida ao modo usuário: extrai, varre, acha CPF
   -> guarda o veredito no contexto de fluxo do arquivo
   -> marca o PID do Word como contaminado

2. Usuário faz "Salvar como" em E:\ (pendrive)
   -> pré-CREATE: abertura para escrita, volume removível, PID contaminado
   -> STATUS_ACCESS_DENIED, sem ida ao modo usuário, zero byte gravado
```

A inspeção cara acontece na abertura do documento, onde 1–2 s de latência
passam despercebidos, e acontece **uma vez por versão do arquivo**. O
bloqueio é uma comparação de inteiro em uma tabela hash.

### Custos honestos da contaminação

Nenhum produto de DLP resolve isto perfeitamente. Os três problemas e as
mitigações que os produtos de mercado adotam:

| Problema | Mitigação |
|---|---|
| Falso positivo: processo leu algo sensível e depois grava coisa não relacionada | TTL na contaminação (padrão: 5 min) e limpeza na saída do processo |
| Processos longevos (`explorer.exe`, navegador) acumulam contaminação para sempre | TTL + contaminação por handle quando determinável |
| Caminho indireto: A lê, manda por IPC para B, B grava | Não coberto. Aceito. |

O TTL é a peça que torna o mecanismo utilizável: uma contaminação que não
expira transforma o `explorer.exe` em um processo permanentemente proibido
de escrever em pendrive.

---

## Camadas de decisão

Ordenadas por custo. Cada camada só é alcançada quando a anterior não
resolveu. As camadas L1 e L2 **não alocam memória**.

### L0 — Registro: interceptar o mínimo

```c
IRP_MJ_CREATE    pré + pós    0
IRP_MJ_WRITE     pré          FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO
IRP_MJ_CLEANUP   pré          0
```

Mudanças em relação à v1:

- **`IRP_MJ_READ` sai.** Era o maior custo da v1: uma ida ao modo usuário por
  leitura. A decisão de origem passa para o `CREATE`, que acontece uma vez
  por abertura em vez de uma vez por bloco lido. Um `CREATE` que pede
  `FILE_READ_DATA` já é a declaração de intenção de ler, e cobre dois casos
  que o `READ` não cobre: arquivo mapeado em memória, cujas leituras chegam
  como paging I/O e nunca aparecem, e handle longevo aberto muito antes da
  leitura.

  **Sob que evidência ele voltaria.** Contaminar na abertura é mais agressivo
  do que contaminar na leitura efetiva: um processo que abre pedindo leitura
  e não lê fica contaminado à toa. Se os contadores mostrarem falso positivo
  demais por esse motivo, o gancho volta — mas não como estava. Volta com
  `FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO` e apoiado no contexto de
  *handle*: dispara na primeira leitura real de cada handle e, nas seguintes,
  é um teste de sinalizador. É por isso que os contadores vêm antes da
  contaminação na ordem de implementação — a escolha é empírica, e sem medir
  vira palpite.
- **`IRP_MJ_WRITE` entra**, mas apenas como porta barata. Ele não inspeciona
  nada: apenas testa um sinalizador no contexto do handle. Existe para fechar
  um furo específico — um processo que abre o arquivo de destino *antes* de
  se contaminar e escreve depois. Sem ele, o `CREATE` já teria sido
  permitido.
- **`IRP_MJ_CLEANUP` entra** para invalidar o cache: se o handle foi aberto
  para escrita, o conteúdo pode ter mudado e o veredito guardado no contexto
  de fluxo deixa de valer.

### L1 — Portas baratas no pré-CREATE

Na ordem, e a ordem importa — a mais seletiva vem primeiro:

1. **Paging I/O, abertura de diretório, abertura de volume.** Já na v1.
2. **`DesiredAccess`.** A operação precisa pedir `FILE_READ_DATA`,
   `FILE_WRITE_DATA` ou `FILE_APPEND_DATA`. **Esta é a porta mais eficaz de
   todas**: a maioria esmagadora dos creates de um Windows em uso pede apenas
   atributos ou metadados e morre aqui, em duas comparações de bits.
3. **Processo excluído.** Serviço, aplicativo, e a lista da política. Consulta
   em tabela hash por PID.
4. **Volume monitorado.** Lido do contexto de instância, calculado uma única
   vez no `InstanceSetup`.
5. **Extensão monitorada.** Comparação sobre `UNICODE_STRING`, sem alocar.
6. **Prefixo de caminho monitorado**, quando o volume não é removível nem de
   rede (caso das pastas de nuvem).

### L2 — Bloqueio, sem ida ao modo usuário

```
abertura para escrita
  E destino monitorado (L1.4 ou L1.6)
  E processo contaminado e dentro do TTL
=> FLT_PREOP_COMPLETE com STATUS_ACCESS_DENIED
```

É o caminho de bloqueio inteiro: três testes e uma consulta hash. Nenhuma
alocação, nenhuma mensagem, nenhuma espera.

### L3 — Cache por arquivo

Abertura para leitura de arquivo com extensão monitorada. Consulta o
`FLT_STREAM_CONTEXT`:

- Veredito presente, carimbo (tamanho + `LastWriteTime`) casando e sem
  sinalizador de sujo → usa o veredito guardado. Se for sensível, contamina o
  processo. **Sem ida ao modo usuário.**
- Ausente ou inválido → L4.

O contexto de fluxo é por *arquivo*, não por handle: sobrevive ao fechamento
e serve todos os processos que abrirem o mesmo arquivo. É o que faz a segunda
abertura de um documento custar praticamente nada.

### L4 — Ida ao modo usuário

Só no miss da L3. Timeout configurável, padrão **2000 ms** — bem mais
generoso que os 500 ms da v1, porque agora é raro e acontece na abertura de
um documento, não em um laço de leitura.

A RN-013 continua valendo sem alteração: timeout, porta fechada, resposta
malformada ou falta de recurso resultam em permitir.

---

## Estruturas

### Contextos do FltMgr

| Contexto | Conteúdo | Vida |
|---|---|---|
| `FLT_INSTANCE_CONTEXT` | Tipo do volume: removível, rede, local. `FltGetVolumeProperties` no `InstanceSetup`, testando `FILE_REMOVABLE_MEDIA` | Enquanto a instância existir |
| `FLT_STREAM_CONTEXT` | Veredito da última inspeção, carimbo de validade, sinalizador de sujo | Por arquivo, enquanto o fluxo existir |
| `FLT_STREAMHANDLE_CONTEXT` | "Este handle escreve em destino monitorado" | Por handle |

A v1 registra `NULL` em context registration. Isto é a mudança estrutural
mais relevante do desenho.

### Tabela de contaminação

Hash por PID, protegida por `EX_PUSH_LOCK` (leitura dominante). Cada entrada
guarda as categorias encontradas e o instante da contaminação, para o TTL.

Limpeza na saída do processo via `PsSetCreateProcessNotifyRoutineEx` — sem
isso a tabela cresce indefinidamente e um PID reciclado herda contaminação
alheia, que é um falso positivo particularmente difícil de diagnosticar.

### Política em kernel

Instantâneo imutável contendo prefixos de caminho **já em forma NT**,
extensões monitoradas e imagens excluídas. Ponteiro trocado atomicamente na
atualização, leitores protegidos por rundown.

Empurrado pelo serviço por uma mensagem de controle na mesma porta, no
momento da conexão e a cada mudança de política. Duas consequências boas:

- O kernel nunca lê o registro nem converte caminho no caminho quente.
- A conversão DOS → NT acontece **uma vez**, no modo usuário, onde é fácil —
  em vez de o kernel entregar caminhos NT e o serviço converter a cada
  operação.

### Alocação

`ExInitializeLookasideListEx` não paginada para os blocos de troca, em vez de
`ExAllocatePool2` por operação. A medição da v1 sob Driver Verifier mostrou
pico de 33 alocações simultâneas de 1216 bytes; com a L4 sendo rara, uma
lookaside elimina a alocação do caminho quente por completo.

---

## O que sobra do protocolo

`Protocol.h` ganha:

- `SAFEUPLOAD_OPERATION_*` passa a distinguir origem e destino.
- `DestinationKind` na requisição — o kernel já sabe classificar, o serviço
  não precisa redescobrir.
- Mensagem de controle no sentido usuário → kernel para empurrar a política.
- Resposta ganha as categorias encontradas, para alimentar a contaminação.

`SAFEUPLOAD_PROTOCOL_VERSION` sobe para 2. O mecanismo de versão já existe
desde a v1 exatamente para isto: um par kernel/usuário incompatível é
detectado, não mal interpretado.

---

## Estado: a cadeia de bloqueio está implementada e verificada

Os dois elos existem e foram exercitados ponta a ponta na VM alvo:

| Elo | Onde | Custo | Verificado por |
|---|---|---|---|
| Origem sensível marca o processo | pós-create | uma ida ao modo usuário, cacheada | leitura sensível é permitida e marca |
| Processo marcado não escreve no destino | pré-create | consulta em tabela hash | escrita negada, e **nenhum arquivo criado** |

A segunda linha é a que importa: a recusa acontece antes de o create existir,
então não sobra arquivo vazio nem truncado no destino. Isso é verificado
explicitamente, e não deduzido do fato de a escrita ter falhado — uma recusa
de pós-create também faria a escrita falhar, deixando rastro.

Verificado também que a marcação não vira proibição geral: o mesmo processo
marcado continua escrevendo fora dos destinos monitorados.

Medições da mesma execução, com o inspetor conectado durante todo o teste:

- 18 linhas no log do inspetor para a bateria inteira
- quatro aberturas do mesmo arquivo produzem **uma** consulta
- uma escrita entre elas produz outra, e só uma
- arquivo fora de escopo nunca chega ao modo usuário
- nenhuma alocação de pool pendente depois do unload

---

## Descartado: lookaside no lugar do pool por operação

Estava na ordem de implementação e foi implementado, medido contra o build e
depois **abandonado**. Registrado porque a próxima pessoa que ler a lista vai
querer saber por que o item sumiu.

**Por que estava na lista.** Quando o desenho foi escrito, cada operação em
escopo alocava um bloco de troca e o liberava em seguida — a forma exata para
a qual uma lista de lookaside existe.

**Por que deixou de valer.** O cache por contexto de fluxo esvaziou esse
caminho. A alocação passou a acontecer uma vez por *versão de arquivo*, não
por operação: um documento aberto vinte vezes aloca uma vez. Otimizar a
frequência de alocação depois disso é otimizar um caminho que já é raro.

**O que decidiu.** Com o lookaside, o build de Release passou a falhar no
`ApiValidator`: `aitstatic` retorna 193 (`ERROR_BAD_EXE_FORMAT`) e o resumo
diz "was not checked" — a ferramenta não reprova uma API, ela falha em
analisar o binário. Verificado que:

- as quatro APIs (`ExInitializeLookasideListEx`, `ExAllocateFromLookasideListEx`,
  `ExFreeToLookasideListEx`, `ExDeleteLookasideListEx`) **estão** em
  `UniversalDDIs.xml`;
- o binário de Debug passa como Universal;
- só o de Release falha, e só com esse código presente.

Não foi explicado. Trocar um ganho marginal por uma verificação de build
quebrada que ninguém entende é mau negócio, e desligar o `ApiValidator` para
contornar seria pior: ele é a verificação que garante que o driver só usa API
permitida em Universal.

**Se voltar a valer.** Se os contadores mostrarem `UserModeRoundTrips` alto
em relação a `CreatesSeen` sob carga real — ou seja, o cache não segurando —,
a alocação volta a ser frequente e a questão se reabre. Aí vale investigar o
`aitstatic`, e não antes.

---

## Pendência conhecida: vazamento de uma alocação no unload

Registrado para não se perder, porque não foi resolvido — apenas deixou de
reproduzir.

**O que foi observado.** Bugcheck `0xC4` subcódigo `0x62` ("a driver has
forgotten to free its pool allocations prior to unloading"), com
`IMAGE_NAME: SafeUpload.sys` e **uma** alocação não liberada. Aconteceu ao
descarregar o filtro logo depois de matar o inspetor, com o driver ainda
registrando `IRP_MJ_READ` e cerca de 33 mensagens em voo.

**O que não foi determinado.** Qual alocação. A pilha de alocação que o
Driver Verifier guarda exige memória de pool, e a VM estava configurada para
minidump, que não a carrega. Quando houve depurador disponível, o defeito já
não reproduzia.

**O que foi tentado.** Reprodução com carga concorrente e a porta fechada no
meio das mensagens em voo, via `Invoke-SafeUploadTest.ps1
-ReproduceUnloadLeak`, com picos medidos de 8 e de 34 alocações simultâneas —
acima das 33 do caso original. Nenhuma reproduziu.

**Por que isso não é o mesmo que corrigido.** Entre o travamento e as
tentativas mudaram três coisas ao mesmo tempo: o gancho de `IRP_MJ_READ`
saiu, o `InstanceSetup` passou a sempre anexar, e um acesso indevido a
`FILE_OBJECT.FileName` foi corrigido. Não dá para atribuir o desaparecimento
a nenhuma delas. Se o vazamento depender de volume de tráfego, ele volta
quando a v2 aumentar a carga.

**O que fazer se voltar.** Configurar `CrashDumpEnabled = 2` (dump de
kernel) *antes*, ou manter um depurador anexado, e então
`!verifier 0x80 SafeUpload.sys` entrega a pilha de alocação. Atenção aos
parâmetros do `0xC4`: `Arg2` é o nome do driver e `Arg3` é uma estrutura
interna do Verifier — **nenhum dos dois é o endereço do bloco vazado**.

**Descartado.** Um `0x3B` observado na mesma sessão *não* era deste driver:
a pilha era inteiramente `condrv!CdCompleteIo` em `conhost.exe`, sem nenhum
quadro nosso e com o módulo sequer carregado. Não reinvestigar.

---

## Como medir se funcionou

Contadores expostos por ETW, consultáveis sem depurador:

| Contador | Alvo |
|---|---|
| Creates vistos | — |
| Creates que passaram da L1 | < 1% do total |
| Idas ao modo usuário | < 1% dos creates que passaram da L1 |
| Acertos de cache de fluxo | > 95% |
| Bloqueios | — |
| Timeouts (permitidos sem inspeção) | próximo de zero |

Sem esses números não há como afirmar que o desenho está funcionando; a
percepção de lentidão é tarde demais como sinal.

---

## Ordem de implementação sugerida

1. ~~Contextos de instância e de fluxo + classificação de volume.~~ **feito**
2. ~~Portas da L1, com destaque para o teste de `DesiredAccess`.~~ **feito**
3. ~~Política empurrada pela porta e a conversão DOS → NT no serviço.~~
   **feito**, com escopo de origem além do de destino.
4. ~~Trocar o gancho de `READ` por `CREATE`/`CLEANUP`~~ **feito**, junto com o
   cache por contexto de fluxo.
5. ~~Tabela de contaminação com TTL e notificação de saída de processo.~~
   **feito**, e é o que trouxe a negação sem byte gravado.
6. ~~Contadores.~~ **feito**, lidos pela porta em vez de por ETW - ver o commit
   que os introduziu para o porque. ETW segue sendo a resposta para producao.
   Adiantados na ordem original: a escolha entre
   marcar na abertura ou na primeira leitura efetiva é empírica, e o custo de
   não ter observabilidade já se pagou caro uma vez.
7. ~~Lookaside no lugar do `ExAllocatePool2` por operação.~~ **descartado**, ver a seção acima.
8. ~~`IRP_MJ_SET_INFORMATION`~~ **feito**: renomear e criar link para dentro de
   um destino monitorado sao recusados; apagar continua fora de escopo,
   de proposito.
9. **Static Driver Verifier** antes de considerar pronto.

Os passos 1 a 3 valem mesmo que a contaminação seja descartada mais tarde por
excesso de falso positivo; são redução de custo pura. O passo 4 é o único que
carrega risco de produto, e é onde vale medir antes de decidir.
