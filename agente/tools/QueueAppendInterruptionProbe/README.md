# Append interrompido com I/O controlado

Somente fixtures sintéticas em diretório novo. Nunca instala agente/driver, usa
API, abre dados instalados ou encerra processos encontrados por nome.

```powershell
dotnet build agente/tools/QueueAppendInterruptionProbe/QueueAppendInterruptionProbe.csproj -c Release
dotnet agente/tools/QueueAppendInterruptionProbe/bin/Release/net10.0/QueueAppendInterruptionProbe.dll C:\Laboratorio\append 3
```

O diretório pai pode existir; cada execução cria subdiretório com GUID. Recusa
ProgramData/SafeUpload e ancestrais reparse, exige 512 MiB livres e mantém filas
sintéticas/recibos para inspeção. Repetições: 1..3; dois tipos de append, três
cortes (1/4.096/65.536 bytes), total de 6..18 filhos próprios.

O construtor interno do Core aceita uma fábrica de FileStream apenas para
injeção de falhas. Construtores públicos continuam usando o FileStream nativo.
O stream do ensaio grava/flush um prefixo real da linha, informa seu tamanho e
hash e bloqueia a conclusão de WriteAsync. O pai exige Task pendente, lê bytes
com compartilhamento compatível, confere tamanho/hash/prefixo da semente e só
então encerra o filho. Não usa atraso cego, reflexão, alteração de binário ou
truncamento manual da fila. Falha se a operação concluir ou não houver prova
dos bytes parciais. O prazo de observação é 30 s, não um SLA do serviço.

Instância nova com construtor público verifica 32 eventos/quatro justificativas
anteriores por IDs/metadados, uma linha inválida e nenhuma promoção do registro
interrompido. Consultas preservam bytes; append de recuperação preserva toda a
cauda original e insere terminador antes do novo evento. Nova reabertura encontra
o evento/justificativa de recuperação. Confirmação e sua repetição preservam
pendentes anteriores e contagem de inválidos, com hash idempotente.

`result.json` registra hashes dos assemblies, tamanho/hash da cauda, PID/exit
do filho e invariantes. Em falha, mantém `failure.json` e diretórios. Apenas
JSON/logs devem ser anexados ao Git; não publicar filas sintéticas grandes.

Este é um ensaio determinístico de interrupção de processo durante uma operação
lógica de append parcialmente escrita, com I/O instrumentado. **Não demonstra
interrupção de uma chamada nativa não instrumentada nem queda de energia ou
persistência física.** FlushAsync não constitui garantia de durabilidade no disco.
A cauda inválida continua diagnosticável; não foi reparada, promovida ou apagada.
