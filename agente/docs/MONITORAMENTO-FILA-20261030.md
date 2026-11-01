# Monitoramento das operações da fila — 30/10/2026

Recorte seletivo do AuditQueueHealth/MonitoredAuditSink preservado no #49/9680383e, adaptado à main ba8dc755. Observa operações reais do serviço, sem trocar o armazenamento local nem alterar decisões, recibos, confirmação ou política de erro dos chamadores.

## Consulta administrativa

Com o serviço atualizado rodando, executar em PowerShell como administrador:

```powershell
$estado = .\agente\scripts\Get-SafeUploadDiagnostics.ps1 -Query audit-health
$estado
$estado.operations | Format-Table operation, degraded, failures, successes, failureKind, lastFailureUtc, lastSuccessUtc
```

A consulta usa o canal administrativo existente, sem acessar a fila, driver ou rede. É independente de audit-integrity, que faz o inventário somente leitura do arquivo. Não foi acrescentada tela, alerta externo ou tarefa agendada.

## Significado do estado

Sete operações observadas: gravar evento, gravar justificativa, ler histórico, ler pendentes, ler justificativas pendentes, confirmar eventos e confirmar justificativas. Cada uma mantém contagens de falhas/sucessos, última falha/sucesso em UTC, categoria da última falha e HRESULT. Uma operação fica degradada após falhar e só sai desse estado ao concluir uma tentativa da própria operação. Uma leitura bem-sucedida não limpa uma falha de gravação.

FailedWriteAttempts soma tentativas falhas de gravação de eventos/justificativas. Não mede eventos únicos perdidos. Sucesso significa retorno normal da chamada, inclusive uma leitura vazia ou confirmação sem itens; não é quantidade de registros entregues. Cancelamento solicitado pelo chamador continua propagado e não vira falha de armazenamento; cancelamento inesperado é contado.

Os contadores ficam em memória e recomeçam com uma nova instância do serviço. SinceUtc identifica o período de observação. Zero falhas antes de qualquer tentativa significa ausência de falha observada, sem atestar que uma operação foi testada. A categoria da última falha permanece como histórico depois da retomada. Uma chamada posterior que voltou a funcionar não recupera gravações anteriores que falharam nem prova persistência no servidor ou proteção do driver.

## Logs, privacidade e integração

Emitido um log 3101 ao entrar em falha e um 3102 ao retomar a mesma operação. Falhas repetidas são contadas sem repetir o log de transição. Mensagens contêm apenas operação, categoria padronizada e HRESULT; o monitor não anexa exceção, mensagem bruta, IDs, caminhos, usuários ou conteúdo. Falha do provedor de logs não substitui a exceção da fila e não faz uma operação concluída falhar.

Categorias: access_denied, disk_full para os HRESULTs conhecidos, io_error, unexpected_cancellation e unexpected_error. Não houve teste com volume real cheio neste recorte; esse ramo é exercitado por exceção sintética com HRESULT. Erros continuam sendo propagados para os chamadores existentes.

O serviço registra uma única LocalQueueAuditSink, um monitor e um decorador MonitoredAuditSink. IAuditSink aponta para o decorador, que preserva IOverrideQueue. O inventário audit-integrity continua usando a mesma fila concreta, com a coordenação e leitura capturada do #69. A consulta audit-health não altera os contadores; o inventário explícito não é uma das sete operações monitoradas.

## Validação e limites

157 testes locais Release aprovados, zero falhas/ignorados, incluindo 17 casos do monitor e regressões de integridade, concorrência, confirmação, leitura limitada, comunicação e recibos. Verificados erro real de arquivo ocupado durante inspeção, veredito preservado, propagação da exceção original, retomada, falhas repetidas sem excesso de logs, log com falha, cancelamentos, justificativas/identidade, composição real do serviço, recibos completo/incompleto no dispatcher, contagens concorrentes exatas, novo monitor sem histórico e consulta real no canal sem estado saudável fictício.

Sintaxe da ferramenta conferida em PowerShell 7 e Windows PowerShell 5.1; ensaio em PowerShell 7. O aceite restrito ao runner Windows descartável foi ampliado para consultar audit-health no serviço LocalSystem, observar leituras reais do dispatcher no primeiro início e após reinício offline e conferir novo período de observação. Conferir o resultado remoto no HEAD da entrega; não houve instalação local.

Sem alteração em Core, dispatcher/recibos, backend/banco, painel, política, driver ou instalador. Não qualifica recuperação de eventos cuja gravação falhou, retenção, queda de energia, disco cheio real ou alerta central. Frente #48 e macro #43 conservam as pendências restantes.
