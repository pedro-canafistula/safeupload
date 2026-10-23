# Consultas limitadas da fila — 23/10/2026

Fonte `42e34afd73b9e7fe8d183a032a3bcf9abc13f282`, candidato **0.1.11**, atividade #51, parte da macro #43 e confiabilidade #48. PR #49 em rascunho, sem merge. Mudança apenas no leitor do Core, testes C# e versão do candidato no CI do agente.

## Comportamento

Antes, ReadPendingAsync e ReadRecentAsync materializavam todos os eventos para depois recortar. Agora um lote positivo de pendentes encerra a varredura ao encontrar N eventos elegíveis, na ordem do arquivo. Histórico com limite positivo percorre o arquivo, mantendo em uma fila circular apenas os últimos N eventos; devolve em ordem inversa de append. A capacidade cresce conforme os eventos encontrados, sem pré-alocar pelo valor recebido. Limites zero/negativos continuam retornando a coleção completa.

Não há ordenação por timestamp ou deduplicação nova. Parser, compatibilidade com BOM, eventos confirmados no histórico, justificativas/tipos futuros ignorados, JSON inválido ignorado e bytes preservados mantêm o comportamento anterior. Escrita, confirmação, formato, HTTP, pipe, ACL, retenção e diagnósticos não mudaram. Mesmo lock e compartilhamento de arquivo; I/O/cancelamento continuam propagados com liberação do lock. O lote limitado de pendentes não examina a cauda após completá-lo e não substitui audit-integrity.

## Comparação local

Mesmo QueueProbe existente, Release/.NET 10.0.13, Windows build 26300, x64, 16 processadores lógicos. Rodadas consecutivas com cache aquecido, cinco leituras e três confirmações por tamanho; computador com outras aplicações e testes, sem isolamento de benchmark. Antes: fonte 43d13c55; depois: fonte acima. Filas próprias com eventos sintéticos e IDs aleatórios em diretórios novos, sem dados de produção/VM. Tamanhos antes da confirmação: 514.890, 5.158.890 e 25.838.890 bytes.

Medianas: ms e MiB de **alocação cumulativa por operação**, não memória viva.

| Eventos | Consulta | Antes ms | Depois ms | Antes MiB alocados | Depois MiB alocados |
| --- | --- | --- | --- | --- | --- |
| 1.000 | pending-100 | 20.65 | 3.02 | 2.61 | 0.27 |
| 1.000 | recent-500 | 19.58 | 23.32 | 2.59 | 2.59 |
| 10.000 | pending-100 | 126.12 | 0.87 | 26.30 | 0.27 |
| 10.000 | recent-500 | 119.12 | 58.23 | 26.06 | 25.82 |
| 50.000 | pending-100 | 274.52 | 0.64 | 131.05 | 0.27 |
| 50.000 | recent-500 | 272.85 | 189.58 | 130.04 | 129.05 |

A medição de pending-100 tem pendentes no início, antes de confirmar eventos: não é garantia para fila com prefixo longo já confirmado ou sem pendentes, que ainda exige percorrer muitos/todos os registros. Histórico ainda desserializa o arquivo inteiro: reduziu referências retidas pelo leitor para O(N), mas não eliminou custo de parsing/alocação total. Linha individual grande continua podendo consumir memória elevada; maxEvents não é limite de bytes/latência. Consultas sem limite continuam sem orçamento de memória.

Não houve redução comprovada no pico de memória do processo completo do probe: ~176,41 MiB antes e ~180,48 MiB depois, incluindo geração, consultas ilimitadas e confirmações. Confirmação continua regravando a fila inteira (~158 MiB alocados por operação com 50 mil registros); diferenças de tempo dessa operação não são atribuídas à mudança, porque seu código não mudou.

Reabertura dos três tamanhos conferiu IDs únicos, contagem original e 300 confirmados em cada rodada. Ensaio concorrente curto de ~10 s: 10.039 eventos em ambas; antes 4.000 confirmados/6.039 pendentes, depois 5.200/4.839, conjuntos conferidos após reabertura. Como o consumidor avançou mais, bytes estimados de destinos reescritos cresceram de ~197,48 MiB para ~256,83 MiB; não confundir com escrita física medida ou ganho de durabilidade. Este ensaio curto não representa dias de operação.

## Testes

Quinze casos novos: limites 1/2/7/0/-1/int.MaxValue, com/sem BOM e terminadores mistos; duplicatas, timestamps invertidos, conteúdo inválido/futuro/override, cauda truncada, hashes e reabertura; 1.027 eventos com janela 500; arquivo ausente/sem eventos; cancelamento e acesso ocupado liberando lock. Novos casos Debug 15/15. Contratos PS7/PS5.1 41/41 cada; ambiente 4/4.

Suíte completa no host em Debug/Release: **794 aprovados, sete falhas, quatro skips em 805** cada. Cinco falhas ocorreram ao criar links simbólicos sem privilégio e duas ao atribuir SID/proprietário no diretório de devolução; as duas últimas incluem o teste que esperava cancelamento e recebeu IOException durante a preparação do diretório. TRX/logs completos preservados, sem ocultar/filtrar esses resultados nem mudar permissões do host. A primeira invocação PS5.1 foi impedida pela política padrão; nova execução usou RemoteSigned somente no processo, sem mudança permanente, e passou.

## CI e aceite do pacote

[CI 40003228220](https://github.com/pedro-canafistula/safeupload/actions/runs/40003228220) **aprovado nos três jobs**, fonte limpa acima. C# **801 aprovados, zero falhas, quatro skips em 805**, Debug e Release, suíte completa sem filtro; os sete casos com falha no host passaram no runner. PS7/PS5.1 41/41 cada; ambiente 4/4. Diagnósticos e ensaio de interrupção existentes passaram.

Validação estática do pacote: 724 arquivos + manifesto conferidos no runner, self-contained, não assinado. Smoke instalado LocalSystem: inspeção de arquivo, falha/retomada audit-health, integridade/temporários, reinício preservando evento/política e remoção com UI real PID 2884 aberta (runningBefore=true/exitedAfter=true), preservando dados, aprovados. Validação estática e teste instalado são recibos distintos.

EXE **0.1.11**, 84.060.450 bytes, SHA-256 **`66BA476103B5F9F32FAB0126F979CE60B1F85A04172EDA5BAA6C4494F951C671`**. Manifesto SHA-256 `1D9C2D15EA3E26A60480CEB0D853AF5320D19B7CD143056DCEC57C1B90D71990`. ZIP artifact 12523635668: 83.609.056 bytes, digest `6926A29FE3549578F901F08651CD6869B5C9F8CE70BC09018C5B9544155EE547`, baixado e conferido; EXE também conferido localmente.

[Functional web 40003237451](https://github.com/pedro-canafistula/safeupload/actions/runs/40003237451) reprovado nos três jobs: migration sem EmpresaRepository; agent-contract com backend não iniciado; installed-service com backend encerrado antes de iniciar. Logs conferidos; C# do agent-contract passou com 801/805 e quatro skips. Sem edição de backend, nem afirmação de ponta a ponta/PR inteiramente verde.

Atualização posterior: o mesmo EXE 0.1.11 recebeu [homologação própria no clone Windows 10](HOMOLOGACAO-WIN10-0111-20261023.md): instalação/724 arquivos, inspeções, 17 eventos, reconexão, boot e remoção com UI aberta aprovados, dados preservados. O ciclo da VM usa 17 eventos; não repete a medição de escala acima. Nenhum instalador foi executado no host; o aceite do pacote 0.1.10 permanece documentado separadamente.

## Pendências

#48 continua aberta para crescimento do arquivo, retenção/compactação, confirmação custosa, append efetivamente interrompido, energia/volume cheio, tratamento de temporários e dias de carga. API/autenticação/idempotência dependem da equipe (#44/#47), par exato do driver de #46. Sem Java, Angular, banco ou driver editados. Não equivale a integração ponta a ponta.

[Evidências, TRX e hashes](evidencias/leitura-fila-20261023/resumo.json); filas sintéticas grandes ficaram fora do Git.
