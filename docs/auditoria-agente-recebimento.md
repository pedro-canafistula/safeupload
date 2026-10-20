# Recebimento de auditoria do agente Windows

## Escopo e divisão de trabalho

A integração anterior usava `POST /agent/events`, ausente da main de referência
`8ed90220`. O agente da branch `feat/agente-instalador` continua enviando para
essa rota. A recuperação local `fix/ci-integracao-isolada-20261020` abrangia
também políticas, autenticação e consultas administrativas; ela não foi
incorporada nesta entrega.

O alinhamento de 20/10 atribuiu ao lado Windows o instalador e o envio de
metadados de auditoria, enquanto Thiago continua a API web e os outros endpoints.
Esta mudança acrescenta exclusivamente o recebimento durável desses metadados.
Não substitui `AgentController`, cadastro/sincronização, heartbeat, publicação de
políticas, autenticação, bancos existentes nem o painel. Nenhuma conversa privada
foi adicionada ao repositório.

## Rota e persistência

`POST /agent/events`, implementado em `com.safeupload.audit`, aceita o envelope
emitido por `AgentAuditPayload` do serviço C#. Campos opcionais do envelope:
`schemaVersion` (1), `hostname` e `agentVersion`. Envelopes antigos sem esses
campos continuam aceitos. `events` e `overrides` admitem até 100 itens cada;
listas ausentes equivalem a listas vazias. A validação usa os enums do agente:
`Approved`, `Blocked`, `AllowedWithoutInspection`, `Retained`; canais `File`,
`Clipboard`, `Web` (ausência assume `File`).

Aplicar **antes de publicar o backend**, no banco `app` existente:

```sh
mysql --host=HOST --user=USUARIO --password app < db/initdb/05_agent_audit_ingest.sql
```

O script cria somente `agent_audit_ingest`, com chave única e índices próprios.
Não depende da migração `04` da recuperação ampla. Volumes existentes não
reexecutam os scripts initdb automaticamente. O usuário `appDataSource` precisa
de SELECT e INSERT nessa tabela. Usar conexão/sessão MySQL em UTC para as colunas
TIMESTAMP; configurar `connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true`
na URL JDBC conforme o ambiente. Não apagar ou recriar volumes para migrar.

Cada lote é validado e gravado em uma transação. Só depois do commit retorna:

```json
{"acceptedEvents":1,"acceptedOverrides":0}
```

As contagens incluem registros já persistidos iguais e repetidos no mesmo lote.
Evento é identificado por `eventId`; conteúdo conhecido diferente para o mesmo
ID retorna 409 e desfaz o lote. Justificativas usam a tupla completa do agente
(`eventId`, `justification`, `occurredAtUtc`, `userName`, `endpointId`), permitindo
mais de uma justificativa por evento. Uma disputa concorrente de inserção pode
retornar erro não-2xx; o agente mantém o lote e um reenvio confirma o já gravado.
Falha no banco, inclusive tabela não migrada, nunca confirma entrega.

São preservados metadados conhecidos, ID, horário original normalizado para UTC,
host, usuário, decisão, categorias, canal e política. `payload` é JSON de campos
explicitamente tipados. Conteúdo do arquivo, campos desconhecidos,
`maskedSnippets` e `dispatched` não são armazenados. Host e versão do envelope
são informativos, não uma identidade autenticada. Esta rota acompanha a política
de segurança atual do backend; cadastro/autenticação de máquinas continua a
depender do contrato do web. O bind padrão do backend continua loopback.

## Como Thiago pode testar quando for integrar

1. Atualizar para o commit desta entrega na main e aplicar a migração no MySQL.
2. Iniciar o backend com as duas fontes de dados usuais. Esta entrega não troca
   suas configurações de inicialização.
3. Rodar o teste abaixo com uma URL local/de teste. O agente usa
   `CentroAdministracao:BaseUrl=http://127.0.0.1:8080/agent/` no desenvolvimento;
   `events` é acrescentado pelo despachante. Em outro host usar HTTPS e a URL
   do servidor web, não a porta do proxy local do agente.
4. Conferir a linha em `app.agent_audit_ingest`; repetir a requisição com o mesmo
   ID deve confirmar de novo sem criar outra linha.
5. Instalar o candidato Windows em VM, gerar bloqueio sintético, interromper a
   conexão e religar. Confirmar o mesmo ID/horário depois do reenvio. Essa etapa
   de instalação e teste ponta a ponta não foi executada nesta entrega.

```powershell
$base = 'http://127.0.0.1:8080'
$auditEvent = @{
  eventId = [guid]::NewGuid().ToString()
  occurredAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
  endpointId = 'PC-SINTETICO'; userName = 'usuario-teste'
  fileName = 'exemplo.txt'; extension = '.txt'; sizeBytes = 42
  verdict = 'Blocked'; categories = @('Cpf'); maskedSnippets = @()
  processName = 'explorer.exe'; processId = 123
  destinationPath = 'E:\Destino'; policyVersion = 7; elapsedMs = 15
  dispatched = $false; channel = 'File'
}
$batch = @{
  schemaVersion = 1; hostname = 'PC-SINTETICO'; agentVersion = 'teste-manual'
  events = @($auditEvent); overrides = @()
} | ConvertTo-Json -Depth 8
1..2 | ForEach-Object {
  $ack = Invoke-RestMethod -Method Post -Uri "$base/agent/events" `
    -ContentType 'application/json; charset=utf-8' `
    -Body ([Text.Encoding]::UTF8.GetBytes($batch))
  if ($ack.acceptedEvents -ne 1 -or $ack.acceptedOverrides -ne 0) {
    throw 'A API não confirmou o lote inteiro.'
  }
  $ack
}
# Guardar eventId para conferir no banco de teste.
$auditEvent.eventId
```

Consulta para conferir (substituir o UUID sintético):

```sql
SELECT record_key, event_id, endpoint_id, occurred_at_utc, received_at_utc,
       sender_hostname, agent_version, payload
FROM app.agent_audit_ingest WHERE event_id = 'UUID-DO-TESTE';
```

## Limites e próximos passos

- A rota de auditoria pode funcionar mesmo se o heartbeat antigo falhar: o
  despachante tenta auditoria independentemente. Essa mudança não restaura
  `/agent/heartbeat` ou `/agent/policy` nem comprova a comunicação completa.
- A tabela de entrada permite ao backend consumir os registros posteriormente;
  ainda não alimenta as tabelas/telas de auditoria do Thiago automaticamente.
  O próximo passo conjunto é mapear esses metadados ao modelo oficial dele.
- Não foi adicionado GET público para consultar auditoria. Leitura administrativa
  e associação com `id_host`/`id_usuario_so` seguem no escopo do web.
- Testes locais usam HTTP Spring em processo e SQL real H2, com o serviço do
  controller existente simulado. Eles não iniciam os dois bancos do backend nem
  o serviço Windows. O workflow `Agent events intake` executa o mesmo contrato
  sobre MySQL 8.4 real e o DDL original, sem simular a persistência.
- Não declarar deploy concluído, teste de VM ou painel funcionando a partir
  apenas da presença da rota ou do sucesso dos testes de contrato.
