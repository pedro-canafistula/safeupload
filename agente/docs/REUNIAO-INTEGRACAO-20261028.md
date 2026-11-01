# Preparação do teste com Thiago

> Atualização após ensaio real: heartbeat, auditoria, offline e resposta perdida foram testados contra Java/MySQL reais. Consulte RESULTADO-JAVA-MYSQL-20261028.md e ROTEIRO-LUCAS-THIAGO-20261028.md para os resultados e o roteiro atual. Este guia inicial permanece como referência dos comandos do kit.

Data: 28/10/2026. O agente está preparado para testar heartbeat, fila, envio e reenvio de auditoria. A integração completa ainda não está aceita. Na main Java d6605e4d, reconferida nesta preparação, a consulta de políticas continua comentada; credencial de dispositivo, provisão automática e consultas administrativas também conservam suas pendências. HTTP 200 não comprova persistência ou painel integrado.

## O que Lucas leva

- Kit portátil desta reunião com SafeUpload.Agent.IntegrationSmoke.exe e dependências. Não exige SDK/runtime .NET instalado, serviço Windows, privilégios administrativos ou driver.
- O utilitário usa AgentApiClient, LocalQueueAuditSink, HttpAgentDispatcher e CommunicationHealth reais da fonte candidata. Não inicia o host do serviço, intercepta arquivos, cadastra máquinas, consulta/aplica políticas ou altera a fila instalada.
- Pasta exclusiva com um evento sintético Blocked, de metadados fixos e IDs/horário preservados. Esse veredito é preparado pelo ensaio e não comprova inspeção real de arquivo.
- Diagnóstico das tentativas e resultados separado por heartbeat e auditoria, sem URL, token ou texto bruto de erro. Saída JSON local com eventId/endpointId sintéticos para Thiago localizar o evento.
- Fonte e evidências da composição atual. A main e o PR #64 sozinhos ainda não contêm os incrementos locais de auditoria/diagnóstico/kit desta reunião. Thiago usa seu Java; Lucas usa o executável deste pacote.

Extrair o ZIP inteiro antes de executar. Manter a pasta utilitario e suas dependências juntas. O apphost SafeUpload.Agent.Service.exe foi removido do kit: não é um pacote de instalação.

## O que confirmar com Thiago antes de começar

1. SHA do backend realmente iniciado e URL de teste acessível a partir da máquina de Lucas. Se o backend estiver em outra máquina, localhost aponta para a máquina de Lucas. A configuração Java padrão usa bind 127.0.0.1; Thiago deve configurar o acesso de teste quando necessário.
2. Os dois bancos MySQL, app e acesso, precisam estar disponíveis e compatíveis com o código. Conferir a migração das tabelas existentes: CREATE TABLE IF NOT EXISTS não move colunas antigas. No contrato atual, ativo/visto_por_ultimo pertencem a hosts.
3. id_host de um cadastro exclusivo de teste, conferido no banco. Não usar id_usuario_so, SID ou hostname no lugar dele. O utilitário não faz cadastro. Escolher também um host de controle.
4. Rotas POST /agent/heartbeat e POST /agent/events ativas, tabela agent_audit_ingest criada e acesso do Thiago para consultas em nova transação.
5. Se houve alteração posterior ao Java de referência, trazer as rotas/JSON efetivos antes de alterar nossa configuração. Não improvisar autenticação ou traduzir política administrativa em política efetiva por suposição.

Não precisam de senha ou token no chat. A configuração Java conferida usa permitAll; passar no ensaio atual não fecha o requisito de autenticação por dispositivo. Usar ambiente de teste controlado.

## Sequência prática

Abrir PowerShell na pasta extraída do kit. Os comandos abaixo criam uma pasta nova no TEMP e mantêm os dados de teste entre processos. Guardar o valor de $ensaio para retomar após fechar o terminal. Não substituir pelo diretório de uma instalação real.

### Preparar antes da reunião sem backend

```powershell
$exe = Join-Path (Get-Location) 'utilitario\SafeUpload.Agent.IntegrationSmoke.exe'
$ensaio = Join-Path $env:TEMP ('SafeUpload-Reuniao-' + [guid]::NewGuid().ToString('N'))
& $exe prepare $ensaio
$LASTEXITCODE
$ensaio
& $exe status $ensaio
```

Esperado: saída 0, pendingAfter=1 e result=local_only. Anotar eventId, endpointId e occurredAtUtc. Não há tráfego HTTP nesses comandos. Uma segunda preparação na mesma pasta é recusada; não apaga ou substitui o ensaio.

### Confirmar heartbeat e entrega de auditoria

Thiago consulta antes, substituindo o ID:

```sql
SELECT id_host, hostname, visto_por_ultimo, ativo
FROM hosts WHERE id_host IN (<HOST_DE_TESTE>, <HOST_DE_CONTROLE>);
```

Lucas informa os dados conferidos e executa:

```powershell
$url = Read-Host 'URL de teste terminada em /agent/'
$hostId = Read-Host 'id_host de teste conferido com Thiago'
& $exe send $ensaio --base-url $url --registered-host-id $hostId
$LASTEXITCODE
& $exe status $ensaio
```

Esperado: saída 0, result=receipt_confirmed e pendingAfter=0; Heartbeat e Audit em Success. Thiago repete a consulta em transação nova: host certo com horário avançado/ativo=1, controle inalterado e nenhum novo cadastro. O envio de auditoria é independente: heartbeat pode falhar e a auditoria ser confirmada; nesse caso a saída geral é 1 e os dois resultados devem ser avaliados separadamente.

Thiago consulta o eventId mostrado, sem convertê-lo para id_host:

```sql
SELECT record_key, kind, event_id, endpoint_id, occurred_at_utc, received_at_utc, payload
FROM agent_audit_ingest
WHERE event_id = '<EVENT_ID_MOSTRADO_PELO_UTILITARIO>';
```

Comparar identidade sintética e horário original. Só confirmar persistência central depois da consulta. A saída do utilitário mantém centralPersistenceVerified=false por não ter acesso ao banco.

### Conferir repetição sem duplicação central

Após confirmar a primeira entrega, enviar explicitamente uma cópia do mesmo evento pela fila de replay separada:

```powershell
& $exe replay $ensaio --base-url $url --registered-host-id $hostId
$LASTEXITCODE
```

Esperado: mesmo eventId, endpointId, horário e metadados; recibo válido e uma única linha audit central. Não mudar o JSON ou gerar outro ID entre essas tentativas. O replay não limpa nem modifica a primeira fila e é um ensaio de duplicação explícita; não simula sozinho uma resposta perdida real. Repetir replay após sua fila já confirmada não gera outro evento automaticamente.

### Conferir desconexão e retomada em outro processo

Preparar uma segunda pasta nova com prepare. Com o backend/rota de teste temporariamente indisponível, executar send e depois status. Esperado: saída 1 e pendingAfter=1. Reabrir PowerShell, recuperar o caminho da mesma pasta e os parâmetros, restabelecer a conexão e repetir send. Esperado: mesmo ID/horário e pendingAfter=0, confirmado também no banco. Não executar prepare de novo nessa pasta.

Resposta perdida após persistência exige uma interrupção controlada na resposta em ambiente de teste, alinhada com Thiago. A fila deve permanecer pendente até obter recibo válido; o reenvio não deve duplicar o registro central. Esse cenário passou no fixture HTTP local do kit, mas o aceite com Java real permanece pendente.

## Como interpretar a saída

| Saída | Ação |
| --- | --- |
| 0 + receipt_confirmed | Recibo e confirmação local aprovados; conferir banco separadamente |
| 0 + local_only | Preparação/status local, sem tentativa de integração |
| already_confirmed | Fila já confirmada; não foi criado novo envio de auditoria nesse comando |
| 1 | Comunicação ou operação não concluída; consultar Heartbeat/Audit e preservar a pasta |
| 2 | Argumentos, URL, ID ou pasta inadequados; corrigir antes de tentar novamente |

O utilitário faz um ciclo por chamada. Não testa a periodicidade de 30 segundos, o serviço instalado, o painel, inspeção de arquivo, autenticação de dispositivo ou aplicação de política no driver. Há lock exclusivo da pasta durante cada comando; não executar duas instâncias sobre a mesma pasta. Não há limpeza automática dos arquivos de teste.

## O que impede chamar tudo de ponta a ponta

| Fluxo restante | Condição para testar |
| --- | --- |
| Política painel → API → agente | Thiago/Luiz entregar rota ativa, documento efetivo versionado e consulta/publicação compatíveis. Hoje o C# consulta GET /agent/policy?endpointId=... e o Java não publica essa rota |
| Auditoria no painel | API administrativa e tela consultarem o mesmo evento persistido; ingestão não demonstra visualização |
| Proteção real e notificação | Serviço/UI candidatos em ambiente controlado e par do driver identificado, com arquivo sintético e escopo acordado |
| Cadastro/identidade/autenticação | Repetição segura, recuperação dos IDs e credencial do dispositivo definidos; não cadastrar repetidamente para contornar falhas |
| Distribuição | Pacote de serviço/instalador da composição, revisão, checks e homologação próprios; este kit é um utilitário de ensaio |

## Registro do encontro

Preencher: data/hora/fuso, SHA do kit e do Java, ambiente/schema, URL sem credenciais, id_host/controle, eventId/endpointId, consultas antes/depois, códigos de saída, pendentes antes/depois, comportamento no reenvio e responsável por cada pendência. Não enviar conteúdo de arquivo, credenciais ou dump integral de banco.

Aceitar cada fluxo separadamente como aprovado, reprovado ou bloqueado. Se a política ainda não estiver disponível, registrar esse bloqueio e concluir heartbeat/auditoria; não marcar sincronização completa apenas porque a rede respondeu.
