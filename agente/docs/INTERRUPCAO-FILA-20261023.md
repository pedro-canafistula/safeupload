# Interrupção de processos da fila — ensaio de 23/10/2026

Fonte `50d887b12453edc07c9b955c55da012553fbe308`, ferramenta
[`QueueCrashProbe`](../tools/QueueCrashProbe/README.md). Alterações restritas à
ferramenta de diagnóstico e execução no workflow do agente; nenhum código de
produção, serviço instalado, dados da VM, Java, Angular, banco ou driver mudou.

O ensaio cria e termina seus próprios processos filhos. Cada cenário usa cópia
nova de uma semente de 4.096 eventos e 16 justificativas sintéticos, fila de
18.893.156 bytes. O padding por evento e payload de append de 8 MiB são estímulos
artificiais de I/O, não perfil real de uso ou recomendação de tamanho de auditoria.
Não houve suspensão de processos externos nem hooks/atrasos no Core de produção.

## Cobertura efetivamente observada

No [CI 39967578641](https://github.com/pedro-canafistula/safeupload/actions/runs/39967578641),
Debug e Release executaram três repetições de quatro cenários: **24 processos
interrompidos**, com invariantes aprovados. Rodada local final Debug: quatro
cenários aprovados. Rodadas exploratórias Release também passaram; os recibos
publicados representam a versão final do protocolo de observação.

| Cenário no CI | Repetições nas duas configurações | Resultado observado após encerrar |
| --- | --- | --- |
| Append de evento | 6 | Chamada já concluída e recibo recebido; 4.097 eventos íntegros e 16 justificativas |
| Append de justificativa | 6 | Chamada já concluída e recibo recebido; 4.096 eventos e 17 justificativas íntegras |
| Confirmar 100 eventos | 6 | Task pendente na fronteira informada, temporário incompleto; fila publicada original, nenhum evento confirmado |
| Confirmar 16 justificativas | 6 | Task pendente na fronteira informada, temporário incompleto; fila publicada original, todas as justificativas pendentes |

Nas doze confirmações interrompidas, o hash da fila reaberta foi idêntico ao da
semente e os 4.096 IDs/fingerprints de metadados anteriores permaneceram íntegros.
Cada uma deixou **um temporário órfão**, com 163.840 a 671.744 bytes, menor que a
fila original. Esses tamanhos, registrados após a saída do processo, demonstram
reescrita interrompida antes de substituir a fila publicada. Não se inferiu a
instrução exata executando no instante do pedido de Kill.

**Não foi atingida uma cauda parcial por interrupção de append.** Mesmo após
refinar a observação com o estado da Task do Core, os appends concluíram antes
do encerramento no host e no CI. O recibo distingue esse resultado, sem registrar
como teste de append em curso. A sobrevivência de appends concluídos foi provada
para encerramento de processo com Windows funcionando. O teste sintético de linha
truncada anterior permanece uma prova diferente.

## Reabertura e repetição

Cada repetição reabriu a fila com instância nova do Core, conferiu unicidade/IDs,
metadados anteriores, justificativas e estado de confirmação. O oráculo aceita
lote inteiro ou nenhum, nunca confirmação parcial ou de eventos não selecionados.
Para operações que informaram conclusão, exige o registro/confirmação correspondente.

Depois foram escritos novo evento e nova justificativa, conferidos após outra
reabertura. A repetição da confirmação dos mesmos 100 IDs e 16 justificativas
passou, sem perder/duplicar histórico nem ocultar linhas inválidas. Nenhuma linha
inválida foi observada nesta reprodução. A ferramenta falha se surgir mais de uma
linha inválida após append ou qualquer corrupção da fila publicada após confirmação.

## Lacuna confirmada: temporários órfãos

O Core usa a fila publicada e consegue continuar operando, mas não promove nem
remove o temporário deixado pelo processo interrompido. O ensaio mantém esses
órfãos e verifica que a operação normal seguinte não os apaga inadvertidamente.
Eles podem consumir espaço após interrupções repetidas. Isso é uma pendência de
operação, não evidência de evento perdido ou de confirmação aplicada.

Próxima regra a desenvolver: inventariar/diagnosticar órfãos com acesso
administrativo e orçamento de disco, sem expor conteúdo. Recuperação/remoção exige
regra explícita; não promover um arquivo que pode estar incompleto, nem marcar
evento como entregue sem recibo. Nenhuma limpeza automática foi acrescentada.

## Segurança, evidências e limites

Guardas locais recusaram ProgramData/SafeUpload e ancestral junction antes de criar
um laboratório/filho de destino. O worker exige marcador e manifesto de operação;
o pai guarda o objeto do processo criado e o encerra em finally se a asserção falhar.
Não há busca/encerramento por nome de executável ou alteração de autenticação/UAC.

Recibos JSON brutos e hashes em
[`evidencias/interrupcao-fila-20261023`](evidencias/interrupcao-fila-20261023/).
ZIPs de Debug/Release baixados e digest SHA-256 comparado ao GitHub. Filas grandes
e temporários permanecem no laboratório local/runner; não foram enviados ao Git.
O runner publica somente o recibo e o log curto de cada configuração.

Pico do processo controlador: 1.113.333.760 bytes no Debug e 996.966.400 no Release,
durante aproximadamente 38,4 s/26,9 s. É consumo da ferramenta com leituras completas,
payloads artificiais grandes e múltiplas verificações; não é medição do serviço,
vazamento demonstrado ou orçamento aceitável de produção. A ferramenta exige 2 GiB
livres e não faz limpeza automática dos dados sintéticos.

Kill de processo não testa energia perdida, persistência física, disco cheio,
danos de filesystem/kernel ou API real. Permanecem pendentes a janela de append
interrompido antes de concluir, teste de volume descartável cheio, operação por dias,
durabilidade, memória limitada/segmentação e retenção. #48 permanece aberta.
Não houve instalação/homologação adicional na VM Windows 10. O pacote 0.1.8 do
diagnóstico anterior tem sua própria fonte/hash; eventual reconstrução pelo CI
deste commit não herda automaticamente aquela identidade ou aceite da VM.

CI **aprovado nos três jobs**. Suíte C# completa: **780 aprovados, zero falhas e
quatro skips em 784**, tanto Debug quanto Release. Contratos PowerShell 7 e 5.1
**39/39** cada; ambiente **4/4**. O smoke instalado passou no runner descartável;
não houve instalação no host/VM por este ensaio. A alteração de fonte continua
limitada à ferramenta e ao CI, sem mudança da implementação da fila.

O [Functional web 39967588809](https://github.com/pedro-canafistula/safeupload/actions/runs/39967588809)
permanece reprovado: migration sem EmpresaRepository; agent-contract aguardou
backend que não iniciou; installed-service encerrou porque backend terminou antes
de iniciar. Sem correção fora do escopo ou afirmação de integração ponta a ponta.
PR #49 e PR #42 continuam em rascunho e sem merge.
