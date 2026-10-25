# Append interrompido com prefixo real — 25/10/2026

Continuidade de #48 no PR #49, a partir de `2ec2f173`. O ensaio antigo de #48
terminava o append antes de Kill; esta entrega exercita deterministicamente uma
operação lógica ainda pendente com bytes parciais já presentes no arquivo.

## Método e alteração delimitada do Core

O append normal envia a linha serializada inteira em uma chamada WriteAsync.
Observação de Task/crescimento não impede que ela conclua antes de Kill. Para
eliminar essa corrida, foi acrescentado construtor **interno** de
LocalQueueAuditSink que recebe fábrica de FileStream, acessível à nova ferramenta
por InternalsVisibleTo. Os dois construtores públicos continuam criando o mesmo
FileStream nativo, com os mesmos argumentos. Serialização, separação da cauda,
flush, lock, formato, recibo, retenção e configuração do serviço permanecem iguais.
Existe uma nova fronteira de injeção de falha no Core; a alteração não é apenas
documentação/testes. Não há seleção desta fábrica por CLI/configuração pública.

[QueueAppendInterruptionProbe](../tools/QueueAppendInterruptionProbe/README.md)
cria filho próprio e stream que grava/flush um prefixo **real** da linha do Core,
emite contagem/hash e mantém WriteAsync pendente. O pai exige relatório de Task
pendente e lê o arquivo com compartilhamento compatível: tamanho exato, prefixo
anterior idêntico e hash da cauda igual aos bytes enviados. Só então encerra o
Process criado. Depois da saída, os bytes devem ser idênticos aos observados.
Não há truncamento manual da fila, suspensão de processos externos, driver ou VM.

Cortes: **1, 4.096 e 65.536 bytes**, tanto evento quanto justificativa, sobre
payload sintético de 128 KiB. Três repetições de cada combinação. O teste falha
se a operação concluir, não houver bytes parciais ou as invariantes divergirem;
não considera esse caso simplesmente ignorado. Cada filho usa prazo de 30 s
para observação/verificações; não é SLA do serviço.

É **injeção de I/O controlada**, não demonstra interrupção no meio de uma chamada
nativa não instrumentada do Windows. A operação está bloqueada após escrita de
prefixo, antes de entregar o restante; não se afirma atividade física de disco
no exato instante de Kill. FlushAsync não prova persistência física/energia.

## Invariantes de recuperação

Cada cenário semeia 32 eventos pendentes e quatro justificativas com IDs/horários
e metadados conhecidos. Após Kill:

- Prefixo anterior idêntico por bytes, uma linha inválida, nenhum tipo desconhecido.
- Todos os eventos/justificativas anteriores preservados uma única vez, com metadados.
- Registro incompleto não aparece como evento/justificativa recuperados ou entregues.
- Consultas/diagnóstico não alteram o arquivo.

Uma instância nova, pelo **construtor público sem injeção**, acrescenta evento e
justificativa de recuperação. A cauda original permanece byte a byte e recebe
terminador antes do novo registro. Outra reabertura encontra 33 eventos/cinco
justificativas e a mesma linha inválida. Confirmação somente do novo registro e
sua repetição preservam 32/quatro pendentes anteriores, inválidos e hash idempotente.
Confirmação pode normalizar terminadores conforme contrato existente; preservação
byte a byte da cauda é exigida até o append de recuperação, não após reescrita.

Dois novos casos xUnit, evento/justificativa, injetam IOException depois de 13
bytes reais e exigem propagação da falha, descarte do stream, liberação do lock
e novo append na **mesma instância** dentro do prazo. O evento incompleto não é
promovido, e a linha inválida continua visível após reabertura.

## Resultados e reprodução

Local Release: **18/18 cenários de processo aprovados**. Local Debug: **18/18**.
Regressão focada em **Debug e Release: 80 aprovados, zero falhas/ignorados por configuração**, incluindo dois
casos novos e regressões de auditoria, justificativas, histórico, integridade,
leitura limitada, confirmação em fluxo, retenção simulada e backlog. Resultado
CI será registrado após conclusão; não declarar suíte completa aprovada
a partir deste recorte.

Primeiras tentativas: projeto novo exigiu restore de assets (dependências já no
cache); a leitura ao vivo inicial usava ReadAllBytesAsync com compartilhamento
incompatível com o escritor, falhou antes da comparação e foi corrigida para
leitura com FileShare.ReadWrite. O filho foi encerrado no finally e o failure.json
foi preservado. O runner local dentro do sandbox não produziu resultado e foi
interrompido; fora da restrição, o mesmo recorte Release concluiu em dois segundos.
Sem resultado bruto não foi declarado sucesso. Compilação explícita sem servidor
compartilhado antecedeu a execução do TRX final.

Reprodução e guardas estão no README da ferramenta. O workflow existente do
agente executa três repetições em Debug/Release e publica somente JSON/logs,
incluindo falhas. Essa regressão é justificada pela nova fronteira no Core;
nenhuma homologação interativa foi repetida. Eventual instalador gerado pelo CI
tem nova identidade e **não substitui o 0.1.14 homologado na VM**.

## Limites e continuidade

O ensaio comprova isolamento de cauda parcial e retomada em interrupção
controlada de append. Não repara/promove/apaga a cauda, não recupera o evento
que não terminou de ser gravado e não promete entrega desse registro. Não há
mudança de formato, compactação, descarte ou política de retenção.

#48 permanece aberta para interrupção de escrita nativa sem instrumentação,
energia/durabilidade física, operação por dias e regras de retenção/órfãos.
Integrações API #44/#47 e par M2 #46 mantêm aceites próprios. Nenhum Java,
Angular, banco ou driver foi alterado; nenhum componente instalado, VM ligada
ou dado preservado do clone acessado. PR #42 preservado; sem merge.
