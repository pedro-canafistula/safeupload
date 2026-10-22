# Fila local: integridade e custo de operação — 22/10/2026

**Resultado desta etapa: integridade aprovada nos cenários exercitados; operação
prolongada ainda aberta em #48.** Foram acrescentados diagnóstico e testes,
sem mudar a implementação da fila, a inspeção ou a retenção de dados.

Fonte do diagnóstico/testes: `6eed4f98ae354793080eb0e6c5e6df13e899ee31`.
O código de produção permanece igual ao anterior. O instalador homologado no
Windows 10 continua sendo o candidato da fonte `0e9e05d1`; um novo artifact de CI
com outro commit não herda automaticamente aquela homologação de cliente.

## O que foi executado

- Diagnóstico `agente/tools/QueueProbe`, referenciando o `LocalQueueAuditSink`
  real. Gerou arquivos próprios em uma nova subpasta do laboratório; não abriu
  `%ProgramData%\SafeUpload`, não instalou serviço e não modificou a VM.
- Gravação de 1 mil, 10 mil e 50 mil eventos sintéticos. Em cada tamanho:
  cinco buscas de 100 pendentes, cinco leituras de 500 recentes e três
  confirmações de 100. Reabertura validou todos os IDs e 300 confirmações.
- Concorrência por **120,426 s**, iniciando com 10 mil pendentes: produtor com
  pausa de 250 ms entre gravações; consumidor com pausa de 100 ms entre ciclos,
  além do tempo de I/O. Uma única instância da fila, como no serviço.
- **397 ciclos, 403 eventos novos, 10.403 registros conferidos**, todos
  confirmados e nenhum pendente no final. Após reabertura, conjuntos de IDs e
  confirmações coincidiram exatamente; nenhuma perda/duplicação detectada.
- Teste HTTP em loopback com **1.201 eventos e 13 justificativas**. Uma resposta
  foi perdida depois de o servidor sintético aceitar o primeiro lote; outro
  envio recebeu 503. A fila/despachante foram reabertos entre tentativas.
  Foram 15 tentativas e 100 eventos recebidos novamente, com IDs e payloads
  originais. A deduplicação foi modelada no servidor de teste, não implementada
  nem comprovada na API da equipe. As filas ficaram vazias de pendentes,
  mantendo a trilha completa no disco.
- Falhas reais de compartilhamento de arquivos: append recusado e substituição
  do destino recusada. Os erros chegaram ao chamador da fila; hashes anteriores
  foram preservados e houve recuperação depois de liberar o arquivo. A falha de
  substituição limpou o temporário; linhas desconhecidas/truncadas permaneceram.

Reabrir objetos não equivale a encerrar um processo abruptamente. O teste não
simulou corte de energia, indisponibilidade prolongada de dias ou disco cheio.

## Medições

Windows 11 Pro, build 26300, .NET 10.0.13, Release, Ryzen 7 5700X, 16 processadores
lógicos e aproximadamente 24 GiB de RAM. Este é o computador de desenvolvimento,
com outras aplicações e testes durante parte da coleta, não um benchmark isolado.
Isso **não homologa o instalador ou serviço no Windows 11**.

Cache do SO aquecido e poucas repetições: valores abaixo são medianas da rodada,
não limites de latência ou capacidade garantida.

| Eventos no arquivo | Tamanho antes das confirmações | Buscar 100 pendentes | Ler 500 recentes | Confirmar 100 |
| --- | --- | --- | --- | --- |
| 1.000 | 0,49 MiB | 23,40 ms | 22,06 ms | 16,08 ms |
| 10.000 | 4,92 MiB | 80,75 ms | 97,83 ms | 66,36 ms |
| 50.000 | 24,64 MiB | 345,43 ms | 356,33 ms | 270,92 ms |

Com 50 mil eventos, a busca alocou em média **131,04 MiB** e a confirmação
**157,90 MiB** por operação. São deltas cumulativos de alocação do processo,
não memória viva nem vazamento demonstrado. Pico de working set do diagnóstico
completo: aproximadamente **177,11 MiB**.

O arquivo da fase concorrente terminou com 5.408.853 bytes. A soma dos tamanhos
de destino das regravações foi **2.103.498.320 bytes (~1,96 GiB)**. É uma estimativa
de bytes de arquivo reescritos, não medição de escrita física no SSD. O consumidor
foi acelerado; não representa a frequência configurada no serviço de produção.

As amostras confirmam o mecanismo visto na fonte: `ReadPendingAsync` e
`ReadRecentAsync` materializam o arquivo inteiro antes de recortar; cada
confirmação regrava toda a fila, inclusive eventos já confirmados. Portanto,
drenar 50 mil eventos em lotes de 100 exigiria cerca de 500 regravações de
aproximadamente 25,8 MB se o arquivo não mudasse. Essa extrapolação não foi
executada; o ensaio de escala confirmou apenas 300 eventos por tamanho.

## Persistência e limitações encontradas

1. **P1 — Sinalizar falha ao auditar.** `InspectionService.cs`, linhas 331–339,
   captura a falha de `WriteAsync` e conserva o veredito, mas não registra nem
   expõe a perda do evento. O teste existente `Falha_ao_auditar_nao_altera_o_veredito`
   confirma a preservação da decisão. Os novos testes comprovam que o erro sai
   do sink; não comprovam alerta ao operador. Próxima mudança deve tornar a
   degradação observável por canal independente da própria fila, com metadados
   mínimos e sem conteúdo sensível, preservando a regra atual de decisão.
2. Linhas malformadas são ignoradas na leitura e preservadas na regravação,
   sem contador/diagnóstico de corrupção. Preservar linhas não significa que
   seu conteúdo possa ser recuperado ou despachado.
3. O temporário e a substituição protegem o arquivo anterior nas falhas de I/O
   exercitadas, mas `FlushAsync` não demonstra persistência física após energia
   perdida. Encerramento abrupto durante gravação/substituição ainda precisa de
   ensaio próprio. Não confundir a linha truncada sintética com essa prova.
4. Sem retenção/compactação: confirmar entrega não reduz o arquivo. Não há
   orçamento de disco ou limite operacional validado para dias de uso.
5. Disco cheio real e acesso negado por ACL não foram simulados nesta rodada;
   bloqueio de compartilhamento é outro tipo de falha. Não reduzir espaço no
   disco do usuário para testá-los: usar volume descartável no clone.

## Decisão de retenção nesta entrega

**Manter a política atual, sem apagar registros automaticamente.** Não foi
introduzida expiração, limite que descarte pendentes ou mudança de formato.
Esta é uma decisão provisória para preservar dados, não aceite de crescimento
ilimitado em produção.

A evolução proposta deve separar armazenamento de pendentes e histórico,
considerar segmentos/checkpoints de confirmação e limitar a memória usada na
consulta do histórico. Antes de alterar o formato, testar migração, interrupção,
compatibilidade e recuperação. Para excluir confirmados, alinhar prazo de
retenção e orçamento de disco com a equipe, e confirmar recibo durável e
idempotência por identidade do endpoint + EventId no servidor. Esses pontos são
dependências de contrato; não foram implementados no Java/banco/painel.

## Validação e evidências

Local: **3/3** novos testes em Debug e **54/54** na regressão relacionada em
Release, sem skips nesses recortes. A primeira execução Release teve 2/3:
a substituição bloqueada gerou `UnauthorizedAccessException`, enquanto o teste
esperava `IOException`. A versão final exige uma recusa de filesystem e mantém
as asserções de integridade, recuperação e limpeza; nenhum erro do produto foi
ocultado ou alteração de comportamento feita para passar o teste.

O CI [39862472507](https://github.com/pedro-canafistula/safeupload/actions/runs/39862472507)
compila o diagnóstico nas duas configurações e executa a suíte inteira sem filtro.
Os três jobs concluíram com sucesso: **752 aprovados, zero falhas e quatro skips
em 756**, tanto Debug quanto Release; PS7/PS5.1 **39/39** cada, ambiente **4/4**,
validação estática e smoke do instalador aprovados no runner descartável.
Recibo e etapas em `evidencias/fila-20261022/ci.json`.
Os quatro skips anteriores devem continuar explícitos; o Functional web e a
API real permanecem sem homologação ponta a ponta.

[Dados brutos e hashes](evidencias/fila-20261022/resumo.json),
[amostras do diagnóstico](evidencias/fila-20261022/medicao.json),
[TRX Debug](evidencias/fila-20261022/fila-debug.trx) e
[TRX da regressão Release](evidencias/fila-20261022/fila-regressao-release.trx).
As filas grandes ficaram no laboratório local, fora do Git. Os TRX foram
inspecionados: URLs `example.test` e credenciais nelas são fixtures sintéticas,
não acessos reais; não há tokens/chaves de acesso nas evidências.

O PR #49 permanece em rascunho, sem merge. A atividade #48 fica aberta até
fechar observabilidade, ensaios de interrupção/disco cheio e política de retenção.
