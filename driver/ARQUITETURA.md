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

## Como o mercado resolve isto, e onde divergimos

Escrito depois de comparar com Microsoft Purview, Forcepoint, Symantec DLP e
Strac. A comparação é contra documentação pública desses produtos, não contra
o código deles — o que dá para afirmar é o modelo, não a implementação.

### O que os quatro fazem igual

**1. A política é escrita em cima de canais de saída, não de leituras.**

Purview enumera atividades de egresso — copiar para mídia removível, imprimir,
salvar em compartilhamento de rede, subir para nuvem. Strac enumera "cada
saída da máquina": abertura e download de arquivo, escrita em USB, impressão,
captura de tela, AirDrop, área de transferência, upload pelo navegador, texto
digitado num prompt de IA generativa. A pergunta cara — "este conteúdo é
sensível?" — é feita **sobre o arquivo que está saindo**, no momento em que
ele sai.

**2. Cada atividade tem modo próprio, e bloquear é o último deles.**

Purview: Off, Allow, Audit only, Block with override, Block — por atividade.
Strac: Block, Warn ou Audit, por saída, em Mac e Windows. A recomendação de
implantação é explícita: subir em modo auditoria primeiro, para conhecer o que
é atividade legítima, e só depois passar a bloquear.

**3. Bloqueio com justificativa é a norma, não a exceção.**

"Block with override" bloqueia mas deixa o usuário prosseguir informando uma
justificativa de negócio, que fica auditada. Transforma proibição em
responsabilização, e é o que impede o DLP de ser desinstalado na primeira
semana por atrapalhar trabalho legítimo.

**4. Detecção por impressão digital, além de padrão.**

Symantec e Forcepoint têm duas famílias que nós não temos:

- **EDM** (Exact Data Matching): índice de uma fonte estruturada — a tabela de
  clientes, por exemplo — para reconhecer *aquele* registro, e não qualquer
  coisa com formato de CPF.
- **IDM** (Indexed Document Matching): índice de documentos, capaz de
  reconhecer o documento inteiro, um trecho dele, ou conteúdo apenas
  semelhante.

O índice é construído no servidor e **baixado para o agente**, que passa a
casar localmente e continua funcionando sem rede. É o padrão de duas camadas:
o caro acontece fora da máquina, o rápido acontece nela.

**5. Um classificador, muitos canais.**

Em Strac, um tipo de dado definido uma vez vale igual saindo por USB ou por
API de SaaS. Nós já temos essa forma — o `InspectionService` não sabe por onde
a operação chegou —, e vale preservá-la de propósito.

### Onde divergimos, e o que isso significa

Nosso modelo é diferente e é bom saber disso de propósito, em vez de
descobrir depois.

| | Purview / Forcepoint / Symantec / Strac | SafeUpload |
|---|---|---|
| Onde inspeciona | o arquivo que está saindo | o arquivo que está sendo **lido** |
| O que decide | conteúdo do que sai | processo marcado por ter lido origem sensível |
| Custo por operação | egresso é raro | **toda abertura em escopo paga** |
| Falso positivo | conteúdo limpo passa | processo marcado não escreve por 300 s |

**O que o nosso modelo pega e o deles não.** Ler um contrato com CPF,
retrabalhar o conteúdo e salvar um arquivo derivado que não contém o número
literal. Inspeção de conteúdo no egresso libera — o arquivo novo não casa
padrão nenhum. Contaminação de processo bloqueia. Isso não é detalhe: é uma
categoria de produto à parte, rastreio de linhagem de dados, e o próprio
material de mercado a trata como concorrência distinta do DLP clássico.

**O que o modelo deles pega e o nosso não.** Copiar um arquivo sensível que o
processo nunca leu por este caminho, colar conteúdo pela área de transferência,
imprimir, subir pelo navegador, digitar num prompt de IA. Nada disso passa
por `IRP_MJ_CREATE` num destino vigiado.

**A conclusão honesta:** chegamos ao modelo de linhagem sem escolher. Ele tem
mérito real, mas foi consequência do desenho de contaminação, não decisão de
produto. E ele carrega o custo que os outros evitaram: inspecionar na abertura
põe o trabalho caro no caminho quente, que é exatamente a origem do problema
de prazo documentado acima.

### O que trazer, em ordem de valor por esforço

**1. Modos por atividade: auditar, avisar, bloquear.** É o que os quatro têm e
nós não — hoje só existe bloquear, desde o primeiro minuto. Modo auditoria
roda tudo, nega nada e registra: além de ser como se implanta DLP sem ser
desinstalado, é a única forma de medir nossa taxa de falso positivo, que é
justamente a pergunta em aberto sobre a contaminação. É barato: o veredito já
passa por um ponto único no `MinifilterInterceptor`.

**2. Bloqueio com justificativa.** O painel WPF e a trilha de auditoria já
existem; falta o caminho de volta do usuário para o serviço, que hoje é de mão
única de propósito. Vale rever essa decisão à luz do que o mercado faz — mão
única protege contra o usuário desligar a proteção, mas justificativa auditada
não é desligar, é registrar.

**3. Classificação persistida por identidade de arquivo.** Hoje o veredito vive
no contexto de fluxo e morre no unload. Persistir por volume + id de arquivo +
número de sequência de mudança faz um arquivo grande ser varrido uma vez na
vida, e não uma vez por sessão — o que resolve o problema de prazo por outro
caminho, sem marca provisória nenhuma.

**4. Inspecionar também no egresso, sem abandonar a contaminação.** Os dois
juntos cobrem coisas diferentes: conteúdo no egresso pega a cópia literal que
a contaminação perde; a contaminação pega a transformação que o conteúdo
perde. Manter os dois é escolha defensável — manter só a contaminação por
inércia não é.

**5. EDM e IDM.** É o degrau mais alto e o mais caro: exige índice construído
fora da máquina e distribuído ao agente. Fica registrado como direção, não
como próximo passo.

### O que não copiar

Esses produtos guardam cópia ou hash do arquivo que gerou o alerta, para
investigação. Nós guardamos apenas achados mascarados, e isso foi decisão
consciente de privacidade — está no `README` do agente: nenhum arquivo sai da
máquina, o conteúdo é lido para memória e descartado no mesmo escopo.
Divergir aqui é intencional e deve continuar.

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

Depois subiu para **3**, quando `SAFEUPLOAD_COUNTERS` ganhou `DeniedRename`
e passou de 96 para 104 bytes. Vale registrar por que uma mudança só de
contador move a versão: o inspetor lê a estrutura inteira de uma vez, então
um campo novo no meio desloca tudo o que vem depois. Um inspetor antigo
contra um driver novo não leria um número errado por pouco — leria os campos
seguintes trocados entre si, e números trocados são pior que números
ausentes, porque parecem plausíveis.

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

Esta seção cobre os dois elos da cadeia, e só eles. O gancho de rename e
hard link é outra coisa, e o que ficou verificado dele está na seção
seguinte — que é menos do que a leitura otimista sugeriria.

---

## A cadeia com o agente de verdade

Tudo acima foi medido contra a **sonda**, cuja decisão é uma comparação de
string no caminho. Isso mede o driver, e é o que se quer para medir o driver
— mas não prova que a coisa funciona, porque o que decide no produto é o
`InspectionService` com as regras RN-001 a RN-004.

Agora foi medido com o agente real, e passa. O caso é este:

1. Um `.txt` de nome inocente — `relatorio-com-cpf.txt` — contendo um CPF
   sintético válido, numa pasta de origem vigiada.
2. Ler o arquivo. O driver classifica como `SCOPE_SOURCE` e pergunta.
3. O serviço extrai o texto, o `CpfValidator` confere os dígitos módulo 11 e
   responde bloqueio.
4. O driver **permite a leitura** e marca o processo.
5. O mesmo processo escreve no destino vigiado, e é negado no pré-CREATE, com
   zero bytes gravados.

O controle roda antes, num processo separado: um arquivo sem nada sensível,
lido do mesmo lugar, e a escrita seguinte passa. Os dois têm de rodar em
processos **novos**, porque a marca é por PID e o PowerShell da bateria já
foi marcado na fase da sonda.

### Duas coisas que só apareceram aqui

**A política do agente não tinha origem.** `MonitoredScopes` só modelava
destinos, porque no mock a inspeção começa quando um arquivo *chega* à pasta
vigiada e origem e destino são a mesma coisa. Sem `SourcePaths` o driver
nunca classifica nada como `SCOPE_SOURCE`, e o primeiro elo da cadeia não
existe.

**O motor descartava a pergunta.** Corrigido o item acima, a bateria ainda
falhou: `InspectionService` decidia escopo por `IsMonitoredDestination`, que
testa o caminho de destino. Uma leitura de origem não tem destino, então
caía como fora de escopo e o arquivo nunca era aberto. O driver tinha feito
a parte dele — mandou `SCOPE_SOURCE` — e o motor jogava fora a pergunta,
porque a única que sabia responder era sobre destino.

`DestinationKind.SensitiveSource` e `Policy.IsInScope` fecham isso. Vale
registrar que os 156 testes do agente passavam durante todo esse tempo:
nenhum perguntava se uma leitura de origem entra em escopo.

### O prazo, ainda aberto — e a evidência que ele não é o problema de hoje

O driver espera 500 ms e a RN-012 dá 5 s ao motor. A previsão era que
extração real estouraria o orçamento e tudo passaria sem inspeção. **Não é o
que acontece**: nesta execução `AllowedWithoutInspection` ficou em zero e
nenhuma inspeção estourou o prazo de 400 ms do interceptador.

Isso não fecha a questão, delimita. Um `.txt` pequeno cabe folgado; um
`.docx` ou `.xlsx` grande, passando pelo Open XML, é outra história e ainda
não foi medido. O interceptador conta e registra cada estouro, então quando
começar a acontecer vai aparecer em vez de sumir.

---

## O que fazer quando não se consegue inspecionar

A RN-013 diz que falha de inspeção vale permitir, e a razão é boa: um DLP que
bloqueia quando quebra impede o usuário de trabalhar e é desligado na primeira
semana. Só que "permitir" estava sendo aplicado a mais do que devia.

Há **três** caminhos que produzem `AllowedWithoutInspection`, e nos três o
conteúdo do arquivo nunca foi olhado:

| Motivo | Quando | Deliberado? |
|---|---|---|
| `file_too_large` | acima de `maxFileSizeMb` (20 MB) | sim, por política |
| `unsupported_format` | extensão monitorada sem extrator | sim, por configuração |
| `inspection_timeout` | extração e varredura não couberam no prazo | não |

Até aqui os três liberavam **e não marcavam o processo**. A consequência: um
arquivo grande demais para ser inspecionado saía livre para qualquer destino
vigiado, e a política documentava o limite que abria essa porta. É trivial de
explorar — basta encher o arquivo até passar do corte.

### A assimetria que resolve

O que salva o caso é que **negar não significa a mesma coisa nos dois lados
do escopo**:

- Numa requisição de **destino**, negar impede a operação. É o bloqueio de
  verdade, com zero bytes gravados.
- Numa requisição de **origem**, negar não impede nada: o driver permite a
  leitura e apenas **marca o processo**. O usuário abre seu documento
  normalmente.

Então "não consegui inspecionar" pode virar negação do lado da origem sem
custo nenhum para quem abre o arquivo. É o que passou a acontecer:

```
origem  + não inspecionado  →  DENY  →  marca o processo, leitura permitida
destino + não inspecionado  →  ALLOW →  inalterado, negar ali impede trabalho
```

O mesmo vale para o estouro de prazo e para erro durante a inspeção. A regra é
uma só: **na origem, o que não foi olhado marca; no destino, o que não foi
olhado passa.**

### O custo, dito por inteiro

Falso positivo. Um arquivo legítimo de 25 MB marca o processo, e ele fica sem
escrever em destino vigiado pelo TTL da tabela — 300 segundos. Ninguém é
impedido de abrir, editar ou salvar fora dos destinos monitorados; o que fica
suspenso é a cópia para nuvem, pen drive ou rede.

Isso é aceitável enquanto for raro, e os contadores dizem se é:
`AllowedWithoutInspection` contra `TaintsRecorded`. Se o número subir em uso
real, o custo deixa de ser aceitável e a resposta já está desenhada — ver
abaixo.

### O que foi deliberadamente NÃO construído

A ideia melhor é marca **provisória**: em vez de marcar pelo TTL inteiro,
marcar enquanto a inspeção continua em segundo plano e desmarcar quando ela
terminar limpa. A janela de falso positivo cai de 300 segundos para o tempo
real da inspeção.

Ela exige, e é por isso que não foi feita agora:

1. **Pool de threads no interceptador.** O laço é síncrono; inspecionar em
   segundo plano exige separar a resposta ao kernel do trabalho pesado.
2. **Estado provisório na tabela**, com contador de inspeções pendentes por
   PID — um processo pode abrir vários arquivos grandes de uma vez.
3. **Comando novo no protocolo** para o serviço resolver cada pendência.
4. **Limpeza na desconexão da porta.** Se o serviço morrer no meio, ninguém
   resolve, e o processo ficaria travado pelo TTL sem nada explicando. Sem
   inspetor não pode haver bloqueio — que é o que a RN-013 já diz e o Caso 11
   já testa.

Quatro peças, cada uma um lugar onde uma falha silenciosa pode se esconder,
para encurtar uma janela cuja frequência ninguém mediu. A versão de uma linha
fecha os três buracos hoje; a maquinaria se justifica quando o contador
mostrar que o falso positivo incomoda, e não antes.

### Como é testado

O caso força o caminho pelo **formato sem extrator**: um `.bin` que está na
lista de extensões monitoradas, então o driver manda a requisição, e que o
motor não tem como abrir. O arquivo não tem nada sensível — o que precisa
marcar o processo é a ausência de inspeção, não o conteúdo.

A primeira versão forçava por `maxFileSizeMb = 0` e não funcionava: a política
se recusa a carregar com limite zero (`EnsureValid`), e o serviço nem subia.
Formato sem extrator é melhor de qualquer forma — não exige reiniciar o
serviço, não depende de arquivo gigante e é o caso mais realista dos três: um
`.pdf` ou um `.zip` numa pasta de origem é exatamente isso.

Prazo curto seria a pior das três opções: depende de quanto a máquina está
carregada, e um teste que reprova conforme a carga não é teste, é incômodo.

### O buraco que nada disso fecha

O driver vigia quatro extensões. Um `.pdf`, um `.zip` ou um print de tela não
chegam ao modo usuário, não marcam e copiam livremente. Isso é decisão de
escopo, não defeito — mas é maior que os três caminhos acima somados, e
nenhuma dessas mudanças o toca. Vale lembrar antes de alguém ler esta seção e
concluir que a cadeia está fechada.

---

## Quem realmente fecha o desvio por rename

O gancho de `IRP_MJ_SET_INFORMATION` foi escrito para fechar duas portas:
renomear um arquivo pronto para dentro do destino monitorado, e criar um
hard link que torne o conteúdo alcançável lá dentro. Medindo, descobriu-se
que ele fecha **uma** delas — e não a que motivou escrevê-lo.

O que os contadores mostraram, com dois renames diretos emitidos por
`SetFileInformationByHandle(FileRenameInfo)` no mesmo processo marcado:

| Rename | Destino | Chegou ao callback | Resultado |
|---|---|---|---|
| `rename-direto.txt` | monitorado | **não** | `ACCESS_DENIED` |
| `rename-controle.txt` | fora de escopo | sim | permitido |

O de controle chegou, passou pela porta de classe, passou pela checagem de
marca, não casou o destino e foi liberado — exatamente o desenhado. O outro
foi recusado **antes** de chegar: o sistema de arquivos emite uma abertura
interna ao processar o rename, e a porta do pré-CREATE a pega primeiro.

Duas consequências, e nenhuma é "está tudo bem":

1. O desvio por rename **está fechado**, mas por um caminho que ninguém
   projetou para isso. Fecha por efeito colateral, e efeito colateral não
   tem teste que o defenda de uma mudança futura no pré-CREATE.

2. O ramo de recusa do gancho — resolver o destino, casar o prefixo, negar —
   **nunca é alcançado por um rename**. `DeniedRename` fica em zero por mais
   renames que sejam bloqueados, e isso não é defeito do contador.

O hard link parecia ser a operação que alcançaria esse ramo: não cria
arquivo, não move nada, e portanto não ofereceria nada para a porta do
CREATE pegar. **Não é o que acontece.** Um bitmap das classes que chegam ao
callback resolveu a questão:

```
ClassesSeen: 0000000000000001 0000000000180410
  4 FileBasicInformation   10 FileRenameInformation
 19 FileEndOfFileInformation   20 FileAllocationInformation
 64 FileDispositionInformationEx
```

As classes **11** (`FileLinkInformation`) e **72** (`FileLinkInformationEx`)
não aparecem. O `CreateHardLinkW` abre o novo nome com acesso de escrita
antes de emitir o link, e o pré-CREATE o recusa ali — `DeniedPreCreate`
sobe, e a operação de link nunca é emitida.

**O bitmap sozinho não bastava para afirmar isso**, e vale registrar por
quê, porque a armadilha é sutil. Ele é global e cumulativo: registra toda
classe que passou pelo callback desde o load, de qualquer processo da
máquina. Numa execução posterior a classe 11 apareceu, e a leitura
automática anunciou que o hard link chegava ao gancho — conclusão que
`RenamesFromTainted = 1` contradizia, já que o rename de controle sozinho
explicava aquele único acerto.

Quem resolveu foram `LinksSeen` e `LinksFromTainted`, contadores dedicados
ao caminho do link. Ambos em **zero**, com o caso do hard link recusado na
mesma execução: o link não chega, e o 11 daquela vez era tráfego de outro
processo. A lição vale além deste caso — um agregado global não responde
uma pergunta sobre uma operação específica, por mais que pareça responder.

O mesmo vale para o rename: mesmo emitido direto por
`SetFileInformationByHandle`, sem `MoveFileEx` no meio, o destino
monitorado é recusado numa abertura interna antes de o rename chegar.

### O que isso torna verdadeiro

`DeniedRename` **não pode subir** neste sistema. Não é contador quebrado
nem gancho defeituoso: as duas portas que ele existe para fechar já estão
fechadas mais cedo, por construção. Uma bateria que exigisse
`DeniedRename > 0` estaria exigindo o impossível — e exigiu, por três
execuções, até o bitmap mostrar por quê.

O que fica verificado do gancho: ele **é alcançado** (renames fora de
escopo chegam), respeita a marca, e **libera corretamente** o que não é
destino monitorado. Esse é o ramo perigoso se estivesse errado, e está
certo. O ramo de recusa nunca executou.

### Por que ele fica

O critério anunciado antes de medir era: se o hard link também for pego
pelo CREATE, o gancho é código morto e deve sair. Revendo com o dado na
mão, **fica** — e a razão é específica, não conservadorismo.

A recusa mais cedo depende de o Win32 e o NTFS emitirem uma abertura do
nome de destino antes da operação. Isso é comportamento observado, não
contrato documentado: nada obriga uma versão futura, ou um chamador que
monte o IRP por conta própria, a fazer a mesma coisa. Remover o gancho faria
a defesa inteira repousar sobre esse acidente. Um backstop que nunca
disparou custa uma comparação de classe por `IRP_MJ_SET_INFORMATION`, e é
barato pelo que segura.

O que **não** é aceitável é deixá-lo passar por verificado. Ele está aqui
como rede, sem uma única recusa observada, e este parágrafo existe para que
ninguém leia a linha verde da bateria como prova do contrário.

---

## Análise estática: CodeQL, porque o SDV não existe mais

O SDV foi removido do WDK (ver a ordem de implementação). O substituto é
CodeQL com o pacote `Windows-Driver-Developer-Supplemental-Tools` da
Microsoft — o mesmo que alimenta o `dvl.exe` e o Static Tools Logo Test.

### Como reproduzir

```
codeql database create <db> --language=cpp --command="msbuild SafeUpload.Minifilter.vcxproj /t:Rebuild /p:Configuration=Release /p:Platform=x64"
codeql database analyze <db> <tools>/src/windows-driver-suites/mustfix.qls      --additional-packs <tools>/src --format=sarifv2.1.0 --output mustfix.sarif
codeql database analyze <db> <tools>/src/windows-driver-suites/recommended.qls  --additional-packs <tools>/src --format=sarifv2.1.0 --output recommended.sarif
```

Duas armadilhas que custaram tempo: os `.qls` de `suites/` na raiz do
repositório referenciam caminhos relativos de dentro do pacote e falham com
*"is not in a pack"* — as suítes utilizáveis são as de
`src/windows-driver-suites/`, com `--additional-packs` apontando para `src`.
E a primeira execução da `recommended` gasta mais de meia hora só
**compilando** as consultas, antes de avaliar qualquer coisa; execuções
seguintes reaproveitam o cache.

### Resultado

| Suíte | Consultas | Achados |
|---|---:|---:|
| `mustfix` | 31 | **0** |
| `recommended` | 106 | 2 |

A `mustfix` é a que importa para certificação, e está limpa. Ela inclui
`cpp/unsafe-dacl-security-descriptor`, que é a consulta que olharia o
descritor de segurança da porta de comunicação.

### Os dois achados da `recommended`, e por que não são defeitos

Ambos são `cpp/paddingbyteinformationdisclosure`:

```
Policy.c:233  _SAFEUPLOAD_POLICY       includes uninitialized padding bytes
Taint.c:330   _SAFEUPLOAD_TAINT_ENTRY  includes uninitialized padding bytes
```

São **falsos positivos**, por dois motivos independentes.

O primeiro está na própria consulta. O modelo de alocação casa por prefixo
de nome e nunca lê o argumento de flags:

```ql
this.getTarget().getName().matches("ExAllocatePool%")
```

Isso trata `ExAllocatePool2` como `ExAllocatePoolWithTag`, e as duas têm
semânticas opostas: a segunda não zera, a primeira zera **por padrão**. O
`wdm.h` demonstra ao definir o opt-out — `POOL_FLAG_UNINITIALIZED`, *"Don't
zero-initialize allocation"*. As duas chamadas passam `POOL_FLAG_NON_PAGED`
e não esse flag, então a memória sai zerada, padding incluído.

O segundo é de escopo: nenhuma das duas estruturas cruza para o modo
usuário. `SAFEUPLOAD_POLICY` é o instantâneo em kernel e
`SAFEUPLOAD_TAINT_ENTRY` é entrada da tabela hash. Não há para quem
divulgar.

Nenhum dos dois pede mudança no código. Acrescentar um `RtlZeroMemory`
redundante para silenciar a ferramenta seria pior: sugeriria ao próximo
leitor que o `ExAllocatePool2` não zera.

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

### Primeira leitura, e o que ela pegou

A primeira leitura real, numa bateria de testes na VM alvo:

| Contador | Valor |
|---|---|
| Creates vistos | 287 |
| Passaram da L1 | 14 (4,88%) |
| Avaliações de escopo | 8 |
| Idas ao modo usuário | 5 |
| Acertos de cache | 4 (33%) |
| Negados no pós-create | 1 |
| **Negados no pré-create** | **0** |
| Permitidos sem inspeção | 0 |
| Marcas registradas / consultas / acertos | 1 / 5 / 4 |

Os dois últimos números do meio não podiam coexistir: a marca foi encontrada
quatro vezes e nada foi negado no pré-create, num teste em que a escrita
marcada comprovadamente foi recusada. A contradição não estava no driver —
a recusa por marca **não incrementava contador nenhum**, e o único
`SafeUploadCount( DeniedPreCreate )` estava no caminho do rename.

Duas correções saíram disso: o incremento que faltava, e `DeniedRename`
separado de `DeniedPreCreate` — os dois respondem perguntas diferentes
(o arquivo sendo escrito e o arquivo sendo movido para o lugar), e somá-los
esconde qual elo da cadeia está segurando.

O script de teste agora confere os contadores contra os casos que passaram.
Essa é a lição que vale mais que os números: um caso de bloqueio fica verde
quando a operação falha por qualquer motivo, e os contadores são a única
testemunha independente de *por que* ele passou.

Sobre os alvos naquela amostra: 4,88% está acima do `< 1%`, e 33% muito
abaixo do `> 95%`. Nenhum dos dois era conclusivo com 287 creates de uma
bateria que só mexe em arquivos monitorados — a amostra é feita de exatamente
o caso que as portas deixam passar.

### Leitura com a cadeia completa

Com o serviço real, os arquivos do Office e uma amostra dez vezes maior:

| Contador | Valor |
|---|---|
| Creates vistos | 8600 |
| Passaram da L1 | 39 (**0,45%**) |
| Idas ao modo usuário | 17 |
| Acertos de cache | 4 (19%) |
| Negados no pré-create | 7 |
| Permitidos sem inspeção | **0** |
| Marcas registradas | 4 |

**O alvo de `< 1%` foi atingido**, com folga e com a maior amostra até agora.
As portas baratas filtram o que o desenho dizia que filtrariam.

**`AllowedWithoutInspection` em zero é o que valida o prazo vindo da
política.** Um `.docx` de 123 KB e um `.xlsx` de 223 KB foram extraídos e
varridos dentro do prazo — os mesmos que custam 805 ms e 654 ms medidos, e
que teriam passado sem inspeção sob os 500 ms fixos de antes.

**Os 19% de acerto de cache continuam sem significado**, e vale ser claro
sobre por quê em vez de repetir que a amostra é pequena. Uma bateria toca
cada arquivo uma ou duas vezes e escreve entre as leituras, justamente para
testar a invalidação. É o pior caso possível para um cache. Esse número só
diz alguma coisa contra uma máquina em uso normal, e continua sem medição.


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
9. ~~**Static Driver Verifier** antes de considerar pronto.~~ **impossível**:
   o SDV foi **removido** do WDK. O alvo `sdv` do WDK 10.0.28000 responde
   "Static Driver Verifier (SDV) is no longer included in the Windows Driver
   Kit and is no longer compatible with VS2022 and later", e não existe
   `sdv.exe` nem `staticdv.exe` no kit. Não é falha de configuração; a
   ferramenta não está lá. Substituído por **CodeQL** com o pacote de
   consultas de driver da Microsoft, que é o que o Static Tools Logo Test
   exige hoje e o que alimenta o `dvl.exe` — este sim ainda presente, em
   `Tools\dvl\`. Ver a seção seguinte.

Os passos 1 a 3 valem mesmo que a contaminação seja descartada mais tarde por
excesso de falso positivo; são redução de custo pura. O passo 4 é o único que
carrega risco de produto, e é onde vale medir antes de decidir.

### Trazido do mercado

Continuação da mesma lista, agora com o que a comparação com Purview,
Forcepoint, Symantec e Strac mostrou faltar. Cada item traz o exemplo que o
justifica, porque sem ele a prioridade vira gosto.

10. ~~**Modo auditoria.**~~ **feito**. Empresa de 200 pessoas: o financeiro
    copia planilhas para uma pasta de rede cinquenta vezes por dia, e isso é
    trabalho normal. Com bloqueio direto, o dia 1 é uma enxurrada no suporte e
    o agente é desinstalado na sexta. Precisou existir nos dois lados — a
    recusa por contaminação acontece no kernel, sem perguntar a ninguém.

11. ~~**Extrator de `.pdf`.**~~ **feito**. O contrato com CPF é exportado para
    PDF e copiado para o pen drive; sem extrator, a porta barata do driver
    rejeitava a extensão antes de qualquer coisa e a versão final passava em
    silêncio enquanto o rascunho `.docx` era inspecionado.

12. **Detector de segredos e mais identificadores.** Desenvolvedor copia a
    pasta do projeto para o Dropbox. Dentro, um `appsettings.json` com chave
    da AWS e string de conexão. Hoje `.json` não é monitorado e não há
    detector de segredo: nada dispara. Somar chave PIX, RG e CNH cobre o resto
    do uso brasileiro.

13. **Bloqueio com justificativa.** Advogada precisa mandar o contrato com CPF
    à parte contrária pela pasta de rede. Hoje: bloqueio seco, liga para o
    suporte, espera. Com justificativa, digita o motivo, segue, e o evento
    fica auditado. O painel e a trilha já existem; falta o canal de volta do
    usuário para o serviço, hoje de mão única de propósito — decisão que
    precisa ser revista, não contornada.

14. **Classificação persistida por identidade de arquivo.** Planilha de 15 MB
    aberta toda manhã: hoje o veredito vive no contexto de fluxo e morre no
    reboot, então varre de novo a cada sessão. Persistida por volume, id de
    arquivo e número de sequência de mudança, varre uma vez na vida. Resolve o
    problema de prazo por outro caminho, sem marca provisória.

15. **Área de transferência.** Usuário abre o contrato (permitido, processo
    marcado), seleciona o CPF, Ctrl+C e cola numa aba de IA generativa. Hoje
    nada acontece: nenhuma operação de arquivo ocorreu, e a marca não ajuda
    porque nada foi escrito. É o canal de saída mais barato de acrescentar —
    modo usuário puro, com o classificador já pronto.

16. **Impressão digital de documento, começando por hash exato.** "Folha de
    pagamento.xlsx": sem CPF, só nomes e salários. Detector nenhum dispara e o
    arquivo é confidencial. Com lista de SHA-256 na política ele é reconhecido
    pelo que é, mesmo renomeado. Hash exato é a maior parte do valor do IDM
    por uma fração do custo; casamento parcial e por similaridade é que exige
    índice construído fora da máquina.

17. **Impressão e upload por navegador.** Cada um é um projeto próprio.

18. **Pool de threads sobre a porta.** `FilterGetMessage` bloqueia a thread
    que o chama, então hoje toda abertura monitorada da máquina enfileira
    atrás do veredito mais lento. É também pré-requisito da marca provisória
    descrita acima.

19. **Altitude definitiva junto à Microsoft.** Não é trabalho, é fila: 321410
    está na faixa certa mas não foi alocada para este produto, e dois filtros
    na mesma altitude não coexistem. Bloqueia qualquer instalação fora de VM
    descartável, e o pedido não depende de nós.

### O que deliberadamente não entra

**Trocar contaminação por inspeção no egresso.** Os dois cobrem coisas
diferentes e devem coexistir: conteúdo no egresso pega a cópia literal que a
contaminação perde; a contaminação pega a transformação que o conteúdo perde.
E a negação no pré-create garante zero bytes no destino, que inspeção no write
não consegue dar.

**Guardar cópia ou hash do arquivo que gerou alerta.** O mercado faz, para
investigação. Nós guardamos só achados mascarados, por decisão de privacidade
registrada no README do agente.

---

## Fontes da comparação de mercado

Documentação pública consultada ao escrever a seção "Como o mercado resolve
isto". Nenhuma delas descreve implementação interna; o que dá para extrair é o
modelo de produto.

- [Purview — bloquear com permissão de substituição](https://learn.microsoft.com/en-us/purview/endpoint-dlp-create-policy-unauthorized-data-sharing)
- [Purview — referência de política de DLP](https://learn.microsoft.com/en-us/purview/dlp-policy-reference)
- [Purview — configurações de DLP de endpoint](https://learn.microsoft.com/en-us/purview/dlp-configure-endpoint-settings)
- [Symantec — Exact Match Data Identifier, perfil e índice](https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/16-1/about-data-loss-prevention-policy-authoring/introducing-exact-match-data-identifiers-emdi/about-the-exact-match-data-identifier-profile-and-index.html)
- [Symantec — implantação e log do índice IDM](https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/16-0/about-data-loss-prevention-policies-v27576413-d327e9/introducing-indexed-document-matching-idm-v27388119-d327e27601/about-index-deployment-and-logging-v83990894-d327e28083.html)
- [Forcepoint — configuração de DLP](https://help.forcepoint.com/fpone/deploy/rhtml/guid-5d451096-ddf6-4849-96dc-07bb4bd84891.html)
- [Strac — Endpoint DLP](https://www.strac.io/endpoint-dlp)
- [Strac — o que é um agente de DLP de endpoint](https://www.strac.io/blog/what-is-dlp-endpoint-agent)
