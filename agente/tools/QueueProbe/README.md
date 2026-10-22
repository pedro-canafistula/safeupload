# Diagnóstico limitado da fila local

Usa o `LocalQueueAuditSink` real, com dados sintéticos em uma nova subpasta de
saída. Não instala serviço, não acessa API e não abre a fila instalada. Não apaga
os arquivos gerados. Não altera retenção ou compactação.

Requer SDK .NET 10 e pelo menos 2 GiB livres. Executar em Release:

```powershell
dotnet run --project agente/tools/QueueProbe/QueueProbe.csproj -c Release -- C:\Laboratorio\Fila 120
```

O argumento final é a duração de concorrência em segundos (10–600; padrão 120).
Antes dela, mede gravação de 1 mil, 10 mil e 50 mil eventos, cinco buscas de 100
pendentes/cinco leituras de 500 recentes e três confirmações de 100 por tamanho.
A fase concorrente começa com 10 mil pendentes; um produtor grava a cada 250 ms
enquanto o consumidor confirma lotes e consulta o histórico. Uma única instância
da fila coordena os acessos, como no serviço. Depois reabre os dados e compara
identificadores e confirmações. `result.json` contém amostras, hashes e ambiente;
`failure.json` registra a falha se houver. Não há limite artificial de latência
que transforme desempenho variável do laboratório em regressão funcional.

É um ensaio acelerado, com cache do sistema aquecido. Não representa dias de
operação, concorrência entre serviços, queda de energia ou disco cheio. O contador
de bytes de regravação usa o tamanho do destino, não instrumentação física do disco.
Alocação é a diferença acumulada do processo, não memória viva nem pico por operação.
Os testes `QueueLongevityTests` complementam o diagnóstico com HTTP em loopback,
resposta perdida, 503, reabertura e falhas reais de compartilhamento de arquivos.
