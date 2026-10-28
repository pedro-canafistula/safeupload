# Diagnóstico da comunicação na composição atual

Entrega de 28/10/2026, somente no agente C#/.NET e em sua ferramenta administrativa. Base local: composição de heartbeat e recibos `5c2e4f01d03f410907d629ac81e83e1596bbcd6a`. Não altera Java, Angular, bancos, driver, instalador ou CI.

## Resultado

O agente mantém um snapshot da comunicação com três operações: política, heartbeat e auditoria. Há contagens de tentativas, sucessos, falhas, cancelamentos e operações em andamento, horários UTC e o último status HTTP conhecido. O diagnóstico do heartbeat foi adaptado ao cliente atual, que envia id_host para /agent/heartbeat, sem contar a mesma tentativa no cliente e no dispatcher.

A consulta não faz requisições HTTP nem lê fila/driver. O snapshot contém somente metadados fechados: não inclui URL, identidade da máquina/usuário, id_host, token, corpo de resposta, caminho de arquivo, conteúdo do evento ou texto de exceção. Os registros de integração também foram adaptados para categorias sanitizadas, e os clientes HTTP de administração não usam os loggers automáticos que incluem URI.

Os contadores vivem em memória, em três posições fixas; reiniciar o serviço reinicia a observação. Não há histórico crescente nem persistência nova.

## Uso

Com o serviço desta fonte em execução, em PowerShell administrativo, na pasta agente da árvore de desenvolvimento:

```powershell
.\scripts\Get-SafeUploadDiagnostics.ps1 -Query communication-health | ConvertTo-Json -Depth 10
```

A consulta usa o pipe administrativo existente, sem alterar sua DACL. Ele é iniciado tanto em Minifilter quanto em FileSystemWatcher, para que comunicação possa ser consultada sem um driver carregado. As consultas específicas do driver continuam dependendo de sua conexão. Nenhum serviço instalado foi iniciado, reiniciado ou substituído nesta entrega.

O script continua exigindo administrador e PowerShell 5.1. Esta entrega não modifica o instalador nem inclui o script automaticamente no pacote instalado; não presumir disponibilidade em instalações anteriores.

## Interpretação

| Campo ou estado | Significado |
| --- | --- |
| not_configured | Serviço sem URL central configurada |
| not_attempted | Operação ainda não tentada neste processo |
| in_progress | Uma ou mais tentativas em andamento |
| Success / Failure / Cancelled | Resultado da tentativa concluída de sequência mais recente |
| HttpRejected | Resposta HTTP recusada |
| TransportError | Falha de transporte durante a comunicação observada |
| Timeout | Orçamento de tempo excedido sem cancelamento solicitado pelo chamador |
| InvalidResponse | Recibo ou documento inválido, ambíguo ou acima do limite do cliente |
| LastPolicySource | Remote, Memory, Disk ou Default, conforme a política utilizada |
| LastRemoteCachePersisted | Indica persistência do cache de uma política remota válida; não indica aplicação no driver |

Um sucesso novo mantém o último horário/categoria de falha para diagnóstico de recuperação. Tentativas antigas concluídas depois não substituem o resultado da tentativa concluída mais nova. Status desconhecido fica nulo. No heartbeat atual, recibo inválido é classificado depois de HTTP 200; timeout/transporte podem não ter status disponível.

Falha no monitor não impede o heartbeat, a política ou a confirmação da auditoria. Fila vazia não inventa uma tentativa de envio. Configuração/ID de host inválido não gera tentativa HTTP. O cadastro explícito não faz parte dessas três operações monitoradas.

Um recibo de auditoria válido é sucesso da comunicação; uma falha posterior ao confirmar a fila local continua sendo erro local, com pendentes preservados. Consultar/verificar a fila separadamente. Nenhum campo do snapshot comprova persistência no banco, proteção ativa, autenticação de dispositivo ou política aplicada no kernel; os indicadores de qualificação permanecem falsos.

## Origem e escopo do reaproveitamento

Recortes reaproveitados do PR #49, sem importar a consolidação inteira:

- `51f15f9565f87d127ed602cb89b0c00a864ad3a7`: observador, snapshot, observação de política e testes de comunicação.
- `c3ba5a0aa5e928127c5285e773e8987f2686b187`: registros sanitizados, supressão de logs HTTP e testes relacionados.

Dispatcher, registro no host, pipe e script foram adaptados à base atual. Cliente AgentApi/configuração receberam observador opcional. Payload, identificação, validação do recibo, fila, timeout e periodicidade das operações existentes foram preservados. Não transplanta os diagnósticos de fila/M2, projeção de payload, versão de instalador ou outros componentes do #49.

## Evidência

- Windows/.NET 10: **170 testes aprovados, zero falhas/skips**, cobrindo cliente atual, diagnóstico, logs, recibos, cache/refresh e consultas de diagnóstico.
- Os testes adicionais do cliente atual distinguem HTTP, recibo inválido/duplicado/grande, timeout, transporte e cancelamento; verificam ausência de dados sensíveis, observador defeituoso, ID inválido sem tentativa, recuperação e contagem única no dispatcher.
- Os testes de pipe exercitam consulta em processo, sem driver, e verificam que a leitura não muda os contadores. Não representam serviço instalado nem qualificação de acesso entre contas reais.
- Build Release do ApiSmoke sem erros/avisos; ensaio HTTP local do utilitário preserva os 13 cenários existentes. A saída e o TRX acompanham o pacote local.
- Sem backend/bancos reais, painel, serviço instalado, driver carregado ou alteração de política central. Não foi criada nova fixture Java nem alterado o ambiente dos colegas.

## Próximo aceite

Usar a mesma fonte candidata no teste com Thiago: acompanhar heartbeat e auditoria pelo snapshot, conferir o banco em transação nova e comparar com a fila local. O GET de política ainda depende do backend; o diagnóstico permite identificar essa falha e a origem do fallback, sem declarar sincronização concluída. Publicação/revisão e checks da composição permanecem necessários antes de merge na main.
