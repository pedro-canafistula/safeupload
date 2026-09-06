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

1. **Contextos de instância e de fluxo** + classificação de volume. Base de
   tudo, e já reduz custo sozinha.
2. **Portas da L1**, com destaque para o teste de `DesiredAccess`. É a maior
   redução de custo por linha escrita.
3. **Política empurrada pela porta** e a conversão DOS → NT no serviço.
4. **Tabela de contaminação** com TTL e notificação de saída de processo.
5. **Trocar o gancho de `READ` por `CREATE`/`CLEANUP`** e ligar a decisão de
   destino.
6. **Lookaside** e contadores por ETW.
7. **Static Driver Verifier** antes de considerar pronto.

Os passos 1 a 3 valem mesmo que a contaminação seja descartada mais tarde por
excesso de falso positivo; são redução de custo pura. O passo 4 é o único que
carrega risco de produto, e é onde vale medir antes de decidir.
