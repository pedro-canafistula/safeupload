# Demonstração de confiabilidade do agente (45–60 segundos)

Execute na raiz deste repositório, em PowerShell:

```powershell
& .\agente\scripts\Show-ReliabilityDemo.ps1 -Video
```

Pré-requisitos: .NET 10, Java 21 e backend compilado com
`mvn -B -f web/back/pom.xml package -DskipTests`.
O script compila a ferramenta C#, inicia o backend em 127.0.0.1:18081 com H2
em memória, para esse processo, inicia outro e encerra tudo ao terminar.
Use `-Port` se a porta estiver ocupada. A primeira compilação pode aumentar
o tempo; para gravar, execute uma vez antes e use `-Video -SkipBuild`.
Os logs, a política e a fila ficam em uma pasta nova `%TEMP%\safeupload-demo-*`.

Roteiro de narração:

| Tempo aproximado | Mostrar | Narração |
| --- | --- | --- |
| 0–12 s | ONLINE; política recebida; evento e justificativa registrados | “O agente recebe a política do servidor Java e guarda uma cópia válida em disco.” |
| 12–30 s | Backend encerrado; falha real de conexão; REINÍCIO OFFLINE | “Com o servidor fora do ar, um novo processo recupera a última política válida. A origem é conferida como disco, mesmo quando a versão coincide com o padrão.” |
| 30–43 s | PRESERVADO; evento e justificativa pendentes | “A falha de envio mantém o evento e a justificativa na fila local.” |
| 43–60 s | RECONECTADO; zero pendências; trilha preservada | “Quando a conexão volta, o servidor confirma os dois registros. As pendências zeram e a trilha local continua disponível.” |

A demonstração usa componentes reais do agente e o backend Java, mas não
instala serviço, driver, certificados ou regras de rede. Não é uma demonstração
de interceptação de arquivos pelo driver: o evento de bloqueio é sintético.
Cada etapa inicia um processo C# novo. A pasta temporária usa o construtor
interno de teste sem ACL de máquina; o serviço usa o construtor público, que
mantém a validação de ACL protegida.

O backend aceita e persiste justificativas. A consulta administrativa também
as retorna, vinculadas aos eventos selecionados; em Auditoria, “Ver detalhes”
mostra a justificativa, a identidade e a data. O acesso exige administrador.
O registro comprova uma solicitação de exceção, não a conclusão da transferência.

Comportamento implementado:

- Política remota válida tem prioridade; uma resposta inválida não substitui o cache.
- Em falha de rede: última política em memória, depois cache validado em disco,
  depois o padrão existente apenas se nenhuma política anterior for recuperável.
- Cancelamento solicitado pelo chamador continua sendo cancelamento.
- Uma falha de disco mantém a política válida em memória e gera diagnóstico;
  não garante recuperação dessa versão depois de reiniciar.
- O serviço inicializa pelo cache protegido em disco ou pelo padrão existente,
  sem aguardar HTTP. Atualiza a política em segundo plano a cada 30 segundos.
  Inspeções usam o último snapshot validado imediatamente durante uma atualização.
- A identidade de uma justificativa recebida pelo pipe vem do SID verificado
  da conexão, sem substituí-la pela conta que executa o serviço.
- Eventos e justificativas só são confirmados localmente após as contagens
  `acceptedEvents` e `acceptedOverrides` coincidirem com o lote enviado.
- Reenvios usam a idempotência já existente no backend por identificador do evento.
  Falhas do heartbeat não impedem uma tentativa independente de enviar auditoria.
- Confirmações preservam linhas desconhecidas e campos adicionais; uma última
  linha truncada é separada da próxima gravação para não consumir o novo evento.

Limites: a trava da fila é por instância no processo; o serviço deve continuar
como único escritor. A fila não ganha criptografia, rotação ou trava entre
processos nesta entrega. Os testes de instalação/ACL privilegiada exigem VM
apropriada; a demonstração não os substitui.
