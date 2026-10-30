# Configuração e versão do agente — 29/10/2026

Atualização posterior: Lucas escolheu id_host para esta integração. Ver [identidade persistente por servidor](IDENTIDADE-HOST-20261029.md); em AgentApi, após provisionamento, RegisteredHostId pode ser recuperado do armazenamento protegido. As evidências de 181 testes abaixo pertencem ao incremento anterior, 0fa5bda0.

Incremento sobre a composição f2591c02 do PR #64. Corrige a versão fixa do heartbeat por endpointId e valida a configuração do serviço antes de criar os clientes de comunicação. Não altera contratos Java, políticas, cadastro, fila, driver ou painel.

## Modos preservados

| Configuração | Comportamento |
| --- | --- |
| BaseUrl vazia e sem identidade cadastrada configurada | Operação local, sem criar clientes de rede; os prazos de rede não são exigidos |
| URL configurada e HeartbeatProtocol ausente ou Legacy | Contrato existente por endpointId, hostname, os, agentVersion e policyVersion |
| HeartbeatProtocol=AgentApi e RegisteredHostId positivo | Contrato atual da main Java: somente id_host no heartbeat; exige cadastro anterior |

Não há detecção ou fallback automático entre contratos nem cadastro automático. RegisteredUserId permanece recusado. O corpo e a resposta do backend atual são diferentes dos propostos no PDF do MVP de Pedro, de 27/10. A equipe ainda precisa confirmar o contrato da entrega. A seleção padrão não foi trocada por causa do documento.

## Validação da configuração

- BaseUrl exige endereço absoluto HTTP ou HTTPS, terminado em /agent/. Um prefixo de contexto é permitido, como /safeupload/agent/.
- A barra final omitida é acrescentada. Espaços externos são removidos.
- Credenciais embutidas, query, fragmento, esquema inadequado ou caminho diferente são recusados com mensagem fixa, sem reproduzir a URL ou a exceção do parser.
- TimeoutSeconds e DispatchIntervalSeconds ausentes/vazios conservam os padrões 5 e 30 segundos. Um valor informado inválido não vira padrão silenciosamente: é recusado.
- Prazos devem ser inteiros positivos, dentro dos limites do HttpClient e Task.Delay. Os maiores valores inteiros aceitos são 2.147.483 segundos para timeout e 4.294.967 para intervalo; são limites técnicos, não recomendações operacionais.
- AgentApi exige URL e RegisteredHostId de cadastro confirmado. Não se converte id_usuario_so, SID ou endpointId nesse identificador.

Isso torna o erro visível na configuração, antes de iniciar as tarefas de comunicação. Não muda redirecionamentos, recibos ou transporte dos modos existentes. Os 30 segundos configurados são uma espera entre ciclos, não SLA de aplicação de política.

## Versão informada

O heartbeat por endpointId lê AssemblyInformationalVersion do assembly do serviço, preservando o sufixo de revisão que o SDK inclui. Não usa a versão do test runner ou do utilitário que o hospeda. Se esse metadado estiver ausente, usa AssemblyVersion e, em último caso, unknown.

O valor deixa de ser a constante 1.0.0. Um build padrão pode continuar tendo versão-base 1.0.0, acrescida da revisão do Git; isso não cria uma nova versão comercial ou numeração do instalador. Para pacotes com versão própria, informar Version no build/publish e preservar a identificação da fonte. A política de releases do instalador fica no recorte de empacotamento.

O modo AgentApi não recebe campos extras de versão: continua enviando somente id_host, como o backend espera. Corrigir a versão no outro modo não resolve a ausência dos campos de inventário no contrato Java atual.

## Validação deste incremento

181 testes selecionados de cliente, dispatcher, cache, diagnóstico, logs, tradução C# e configuração aprovados, zero falhas/skips. Incluem o corpo de cinco campos do heartbeat por endpointId, a versão do assembly do serviço, versão da política, URLs inválidas sanitizadas, prazos e modos explícitos.

Foi feita também compilação de teste com Version=0.0.0-configcheck, exercitando os dois casos do heartbeat por endpointId para comprovar que o campo acompanha os metadados de build, em vez de permanecer fixo. Essa versão é exclusiva da verificação; não foi instalada ou lançada.

O workflow exclusivo do agente inclui o novo grupo de configuração e recusa grupos vazios/ignorados. O CI do novo HEAD deve ser conferido no PR; resultados de commits anteriores não o substituem.

Não há aceite novo de serviço SYSTEM, UI em sessão real, driver, backend, autenticação de dispositivo ou política central. Esses testes não foram repetidos por este ajuste de configuração. O teste isolado de reset de política v3 para v1 foi registrado na análise do PDF e não exigiu alteração de produto.
