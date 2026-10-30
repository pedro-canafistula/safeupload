# Roteiro de Lucas para o teste com Thiago

Você chega à reunião com uma conclusão concreta: heartbeat e auditoria já funcionaram com Java/MySQL reais no ensaio local. A reunião serve para reproduzir esse resultado no ambiente do Thiago, alinhar os contratos que faltam e registrar o que a equipe aceita. Não precisa começar supondo que todo o agente ou todo o backend esteja quebrado.

## O que estamos fazendo e por quê

O agente toma decisões no Windows e precisa conversar com a administração central. O heartbeat informa que o host está se comunicando. A auditoria entrega os metadados das decisões para rastreabilidade. A fila permite guardar eventos sem rede, e a deduplicação evita que o mesmo evento vire duas ocorrências quando houver reenvio.

A política central deve fazer o caminho inverso: regras criadas na administração chegam ao agente para orientar a inspeção. Essa parte ainda depende de uma API consultável e de um documento efetivo acordado. Ter heartbeat online não comprova política aplicada ou proteção pelo driver.

No ensaio local, usamos componentes reais do agente e a aplicação Java sem modificar sua fonte, com bancos de teste novos. Passaram o envio, a persistência, o replay, a desconexão e a perda de resposta depois do commit. Falharam a disponibilidade de política, o tratamento de host inexistente e a repetição segura de cadastro. Os detalhes e evidências estão em RESULTADO-TESTE-REAL.md.

## Como abrir a reunião

Você pode explicar assim:

“Eu já rodei o agente contra o Java atual com MySQL. O heartbeat atualizou o host correto, a auditoria foi gravada e o reenvio não duplicou o evento, inclusive quando a resposta se perdeu depois da gravação. Quero repetir isso no teu ambiente e depois fechar as pendências de política, cadastro e respostas de erro. Não alterei teu Java.”

## O que deixar aberto no seu computador

- Este roteiro e RESULTADO-TESTE-REAL.md.
- A pasta extraída do kit atualizado, com utilitario/SafeUpload.Agent.IntegrationSmoke.exe e suas dependências.
- PowerShell aberto na pasta do kit e REGISTRO-DO-TESTE.md para anotar o resultado.
- O local onde serão guardadas as saídas JSON e o caminho da pasta exclusiva do ensaio.

O utilitário não instala serviço/driver nem exige SDK .NET. Use o kit fornecido; baixar apenas a main ou o PR #64 não traz todos os incrementos locais. Não usar uma pasta de instalação ou uma fila real como pasta de ensaio.

## O que pedir ao Thiago antes de executar

1. “Qual commit do Java está rodando? O meu teste foi sobre d6605e4d.” Se houver versão nova, registrar o SHA e confirmar rotas/DTOs antes de comparar resultados.
2. “Qual URL da API eu consigo acessar daqui?” Se estiver em outro computador, localhost não serve. Ele confirma bind, porta e acesso de rede do ambiente de teste.
3. “Qual id_host exclusivo de teste vamos usar e qual host vai ser nosso controle?” Conferir no banco. Não usar id_usuario_so, SID ou hostname no lugar do ID.
4. “Os bancos app/acesso e a tabela agent_audit_ingest estão atualizados?” O teste local criou bancos novos; a migração do banco dele ainda precisa ser conferida.
5. “Você consegue consultar hosts e agent_audit_ingest em uma transação nova enquanto eu executo?” Essa consulta é a confirmação central. Não basta olhar somente o 200 da API.
6. “Vamos conferir o fuso do Java, JDBC e MySQL?” O Clock da aplicação usa America/Sao_Paulo. Antes de aceitar a classificação offline por tempo, alinhar NOW(), UTC_TIMESTAMP() e o job de inatividade. Não foi testado esperar 11 minutos.

Não precisa pedir senha/token pelo chat. Os dados desta reprodução são sintéticos e o ambiente deve ser de teste.

## Sequência do seu teste

### 1 Preparar um evento sem rede

Na pasta extraída do kit:

```powershell
$exe = Join-Path (Get-Location) 'utilitario\SafeUpload.Agent.IntegrationSmoke.exe'
$ensaio = Join-Path $env:TEMP ('SafeUpload-Reuniao-' + [guid]::NewGuid().ToString('N'))
& $exe prepare $ensaio
$LASTEXITCODE
$ensaio
& $exe status $ensaio
```

Esperar saída 0 e pendingAfter=1. Anotar eventId, endpointId, occurredAtUtc e o caminho $ensaio. Não foi feito envio nessa etapa. O evento Blocked é sintético: não houve análise de um arquivo real.

Por que fazemos isso: fixa o evento que será acompanhado do armazenamento local até o banco, sem confundir um novo evento com um reenvio.

### 2 Confirmar heartbeat e auditoria

Thiago consulta os dois hosts antes:

```sql
SELECT id_host, hostname, visto_por_ultimo, ativo
FROM hosts WHERE id_host IN (<HOST_DE_TESTE>, <HOST_DE_CONTROLE>);
```

Você executa com os valores que ele acabou de conferir:

```powershell
$url = Read-Host 'URL de teste terminada em /agent/'
$hostId = Read-Host 'id_host de teste conferido com Thiago'
& $exe send $ensaio --base-url $url --registered-host-id $hostId
$LASTEXITCODE
& $exe status $ensaio
```

Esperar saída 0, result=receipt_confirmed, pendingAfter=0 e Heartbeat/Audit em Success. Thiago repete a consulta dos hosts: horário do alvo avançou, ativo=1, controle inalterado e nenhum cadastro novo. Ele também consulta o eventId mostrado:

```sql
SELECT record_key, kind, event_id, endpoint_id, occurred_at_utc, received_at_utc, payload
FROM agent_audit_ingest
WHERE event_id = '<EVENT_ID_DO_ENSAIO>';
```

Esperar uma linha audit com o endpointId e os metadados do mesmo evento. Não copiar o id_host=2 do nosso ensaio local para o ambiente dele.

Por que fazemos isso: demonstra comunicação e persistência reais. A saída centralPersistenceVerified=false do utilitário é intencional: ele não tem acesso ao banco. O aceite central é registrado por vocês após a consulta.

### 3 Reenviar explicitamente o mesmo evento

```powershell
& $exe replay $ensaio --base-url $url --registered-host-id $hostId
$LASTEXITCODE
```

Esperar saída 0 e o mesmo eventId/horário. Thiago repete a consulta: continua uma linha, sem duplicação. O utilitário usa outra fila de teste para esse replay e preserva a primeira.

Por que fazemos isso: uma resposta pode se perder mesmo quando o servidor gravou. O agente precisa poder repetir o evento sem inflar a auditoria.

### 4 Desconectar e retomar em outro processo

Criar uma segunda pasta nova com prepare, guardar seu caminho e eventId. Combinar uma indisponibilidade temporária apenas do ambiente de teste. Executar send: esperar saída 1 e pendingAfter=1. Fechar/reabrir o processo ou terminal, recuperar o caminho da mesma pasta e os parâmetros e repetir send após restabelecer o backend. Esperar saída 0, mesmo ID/horário, fila confirmada e uma linha no banco.

Não executar prepare de novo na mesma pasta. Não apagar ou editar a fila. Uma falha de heartbeat não impede automaticamente a auditoria: olhar os resultados das duas operações, pois a saída geral 1 pode coexistir com auditoria entregue.

Por que fazemos isso: confirma que reiniciar o processo ou perder rede não faz a auditoria desaparecer. Esse teste ainda não qualifica o serviço Windows instalado ou uma reinicialização do sistema operacional.

### 5 Resposta perdida depois de gravar

Esse cenário já passou no ensaio local com um proxy que recebeu a resposta 200 do Java depois da transação e encerrou a conexão com o agente. O banco ficou com uma linha, a fila continuou pendente e a repetição confirmou o mesmo registro sem duplicar.

Se forem repetir na reunião, combinar interrupção controlada da resposta no ambiente de teste. Sem esse controle, não afirmar que desligar a rede em um instante qualquer reproduziu perda posterior ao commit. Podem registrar a evidência local e priorizar os testes anteriores.

## Conversas que precisam terminar em decisão

| Tema | O que você já sabe | Pergunta objetiva ao Thiago |
| --- | --- | --- |
| Política | As duas rotas consultadas retornaram 404 | Qual rota/JSON/versionamento por destino será entregue para o C# consumir? Como representar ausência de política e qual prazo de retorno? |
| Host inexistente | O heartbeat retornou 500 com ID inexistente | Podemos retornar 404 ou outro erro de cliente definido no contrato, sem tratar isso como falha interna? |
| Cadastro repetido | Repetir o mesmo cadastro criou outro host | Qual identidade/chave de idempotência usaremos? Até fechar isso, mantenho o cadastro explícito e sem repetição automática |
| Suíte Java | Sete erros por EmpresaRepository ausente na fixture | Você consegue ajustar a fixture e revisar o caminho do schema, preservando a cobertura de auditoria? |
| Painel | /api/endpoints, /api/auditoria e /api/painel retornaram 404 no teste | Quais consultas administrativas estão disponíveis agora e quais o Luiz vai consumir para mostrar este mesmo evento? |
| Autenticação | As chamadas de teste funcionam sem credencial de dispositivo | Qual contrato de registro, credencial e renovação será adotado? O login administrativo não resolve sozinho a identidade do agente |

Não tratar o JSON administrativo de regras como se fosse automaticamente o documento de política do agente. Acordar categorias, ações, escopos, versão, destino e tratamento de falha antes de adaptar o cliente.

## Como encerrar a reunião

Registrar separadamente: heartbeat, persistência, deduplicação, offline, política, painel e serviço/driver. Para cada item, marcar aprovado, reprovado ou bloqueado, com evidência, responsável e próximo passo. Não fazer merge só porque estes testes passaram: os checks e a revisão ainda precisam de encaminhamento.

O resultado útil hoje é sair com os fluxos de comunicação confirmados no ambiente da equipe e contratos/prazos objetivos para as lacunas. O fluxo completo de proteção só fecha com política publicada/aplicada, inspeção real, aviso ao usuário e evento consultável no painel na composição identificada.
