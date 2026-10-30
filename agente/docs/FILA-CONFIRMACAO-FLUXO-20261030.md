# Fila — confirmação linha a linha — 30/10/2026

Recorte seletivo da confirmação preservada no #49/9680383e, adaptado à main 5d137c06. Remove a montagem do texto completo da fila em memória: a cópia de confirmação é escrita linha a linha em um temporário exclusivo na mesma pasta. Continua percorrendo e reescrevendo o arquivo inteiro em disco; não é compactação, retenção ou confirmação incremental por índice.

## Seleção e publicação

Eventos continuam selecionados pelo ID recebido. Justificativas continuam selecionadas pelo registro completo enviado, incluindo conteúdo, horário e identidade; outra justificativa do mesmo evento permanece pendente. Duplicatas selecionadas são confirmadas como antes. Linhas desconhecidas/inválidas, metadados futuros e registros não selecionados permanecem na cópia. Não se faz limpeza ou reparo de registros.

O temporário usa CreateNew e nome exclusivo. O original só é substituído depois de copiar, concluir o flush, fechar os streams e conferir cancelamento. Uma exceção durante a cópia ou antes da substituição preserva o original e libera o lock local. A limpeza em finally alcança somente o temporário criado por essa operação, sem procurar ou excluir outros arquivos.

O contrato de codificação permanece: confirmação normaliza os terminadores para os do ambiente, grava UTF-8 sem BOM e acrescenta terminador à última linha. Por isso confirmação não promete identidade de bytes com o arquivo de entrada; as leituras continuam sem reescrever dados. Em falha antes da substituição, os bytes do original são preservados.

## Limites

Memória retida deixa de depender do texto completo da fila, mas continua proporcional aos IDs/registros do lote, maior linha, buffers e objetos temporários do JSON. Não há limite absoluto de bytes. O temporário ainda exige espaço para outra cópia da fila. Mantido o lock por instância; não foi introduzida coordenação entre múltiplos escritores de processos diferentes.

Não há novo aceite de queda de energia, flush físico do disco, interrupção abrupta do processo ou recuperação automática de temporários órfãos. finally não executa se o processo for encerrado abruptamente. Não se alteraram recibos, dispatcher, rede, política, backend, driver ou instalador.

## Verificação

83 testes locais Release aprovados, zero falhas/ignorados, incluindo dez casos de confirmação em fluxo e os controles existentes de leitura limitada, persistência, codificação, justificativas, projeção HTTP e recibos.

Os casos preservados verificam cancelamento prévio, linhas mistas/BOM/terminadores variados, metadados, duplicatas, idempotência, justificativas distintas do mesmo evento e linha maior que o buffer. Novos casos verificam lote vazio/fila ausente, falha de escrita e cancelamento depois de uma escrita nativa real no temporário, bloqueio real da substituição no Windows, preservação de outro temporário e retomada na mesma instância. Uma fábrica interna de FileStream permite interromper a primeira escrita de forma determinística; os construtores públicos mantêm o caminho nativo sem injeção.

O workflow de recibos executa e exige o grupo QueueStreamingConfirmationTests. Conferir os checks no HEAD da entrega antes de integrar. Este recorte não encerra a frente #48 nem a macro #43.
