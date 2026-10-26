# Ponte do agente com o backend atual

Preparação de 26/10/2026 sobre main `efe93cf75aa668f2870c0951b48b3ef2c6332226`. Escopo: somente C# do agente, utilitário de ensaio e testes. Sem alteração Java, Angular, banco, driver, workflow ou configuração padrão de produção. A nova ponte ainda não foi publicada nem homologada contra backend real.

## O que foi implementado

O cliente `AgentApiClient` acompanha `AgentController` e `AgentContracts` da main: cadastro explícito por `POST /agent/api/synchronize` e heartbeat de cadastro existente por `POST /agent/api/heartbeat`. Os DTOs preservam nomes como `usuarioSo`, `id_usuario_so` e `sistema_operacional`. O cadastro devolve `id_host` e `id_usuario_so`; nenhum desses números é SID, endpointId ou versão de política.

O heartbeat do serviço pode selecionar esse cliente por configuração. A seleção fica em `IAgentHeartbeat`; sem opt-in, o dispatcher mantém seu contrato anterior. O modo novo usa um HttpClient separado, com redirecionamentos desativados e sem logs HTTP automáticos. Falha no heartbeat continua permitindo a tentativa de entrega da auditoria. A consulta de política não é necessária para enviar o heartbeat novo.

O cliente valida status HTTP e recibo JSON, exige IDs positivos e campos essenciais únicos, limita recibos a 16 KiB e aplica timeout também à leitura do corpo após os cabeçalhos. Falhas não guardam corpo, URL, SID ou mensagem bruta do servidor na exceção. Campos futuros adicionais são aceitos. Não há fallback de protocolo nem retentativa interna.

`SynchronizeAsync` não é chamado pelo serviço ou pelo utilitário. A implementação Java atual cria registros; reenvio após resposta perdida pode duplicar cadastros. O provisionamento, a persistência/vinculação dos IDs e a identidade de máquina autenticada precisam ser acordados com o backend antes de automatizá-lo. Não deduzir o usuário real a partir de SYSTEM.

## Ativação controlada do heartbeat

Exemplo exclusivamente para ambiente de teste; **23 é ID sintético**. Substitua pelo `id_usuario_so` de um cadastro existente, conferido no backend do ambiente correto. Não use matrícula, SID, nome da máquina ou id_host.

```json
{
  "CentroAdministracao": {
    "BaseUrl": "http://127.0.0.1:8080/agent/",
    "HeartbeatProtocol": "AgentApi",
    "RegisteredUserId": 23,
    "DispatchIntervalSeconds": 30,
    "TimeoutSeconds": 5
  }
}
```

Somente o protocolo de heartbeat muda. Política continua pelo cliente/cache existentes; auditoria continua em `/agent/events`. A base deve terminar em `/agent/`, podendo ter um contexto anterior, e não pode conter credenciais, query ou fragmento. Configuração incompleta/desconhecida falha explicitamente. Nenhuma alteração foi feita no appsettings padrão. Para retornar ao comportamento anterior, remova os dois campos novos; não mantenha RegisteredUserId com Legacy.

Sem GET de política compatível no Java atual, a renovação remota ainda falha e o agente depende de política válida local/cache/padrão conforme a implementação existente. Essa falha não é resolvida por esta entrega. Heartbeat confirmado não demonstra política aplicada, identidade autenticada nem proteção no kernel.

## Ensaio sem instalar agente

Com .NET SDK 10 e um backend de teste disponível:

```powershell
dotnet run --project agente/SafeUpload.Agent.ApiSmoke -c Release -- --base-url http://127.0.0.1:8080/agent/ --registered-user-id 23
```

O utilitário faz um heartbeat no cadastro existente e encerra. Isso atualiza o horário de atividade desse cadastro, portanto escolha apenas um cadastro do ambiente de teste. Não cria cadastro, instala serviço, chama driver, publica política ou envia eventos. Exit 0: HTTP 200 e status OK; exit 1: falha de comunicação/recibo; exit 2: configuração inválida. Não inclua credenciais na URL.

Para repetir apenas o ensaio de transporte sintético, sem Java/banco:

```powershell
dotnet build agente/SafeUpload.Agent.ApiSmoke -c Release
python agente/scripts/Test-AgentApiSmoke.py
```

O script usa uma porta efêmera em localhost e confere caminho, corpo, quantidade de requisições e códigos de saída. Essa aprovação não é ensaio contra Java.

## Integrações com painel e driver

| Frente | Nossa parte disponível | Condição restante |
| --- | --- | --- |
| Backend heartbeat | Cliente, configuração opcional do serviço e utilitário de ensaio | Cadastro existente correto, autorização/identidade e teste com API/banco reais |
| Backend cadastro | DTOs e cliente de chamada explícita | Contrato de idempotência e ciclo de vida dos identificadores antes de automatizar |
| Políticas | Cache e refresh existentes preservados | GET/JSON/versionamento compatíveis com o agente; não abrir listener 8426 implicitamente |
| Frontend | Auditoria continua pela API central, com IDs e metadados do contrato existente | Angular consulta /api/endpoints, /api/painel e /api/auditoria; esses endpoints não aparecem nos controllers atuais da main. O consumo administrativo é responsabilidade do web |
| Driver | MinifilterPolicyFactory existente traduz escopos, flags e prazo; nove casos de contrato C# adicionados | Par real identificado e ensaio Windows; teste de mensagem em memória não confirma envio/aceite/aplicação no kernel |

O frontend não recebe dados diretamente desta ponte. O heartbeat novo não informa agentVersion/policyVersion nem restitui o modelo anterior de inventário. Não alterar Angular, criar endpoints administrativos ou misturar cadastros para simular essa integração.

No driver, os testes conferem auditoria, exceção manual, escopo removível/rede, contagens de escopo e orçamento padrão de 5 s com mensagem de 5.500 ms. Usam caminho NT sintético para evitar resolução de unidade Windows. Não modificam protocolo, C/C++, M2 nem atualização dinâmica de política.

## Validação realizada

Build Release do projeto de testes e dependências (incluindo serviço e minifiltro C#): **zero erros e zero avisos**. Build Release do ApiSmoke: **zero erros e zero avisos**. Executado em Linux com SDK 10.0.100, sem instalar serviço ou driver.

Seleção final xUnit: **86 aprovados e uma falha em 87, zero skips**:

| Grupo | Aprovados | Falhas |
| --- | --- | --- |
| AgentApiClientTests | 50 | 0 |
| DispatcherReliabilityTests | 10 | 0 |
| MinifilterPolicyBridgeTests | 9 | 0 |
| DurableHttpPolicyStoreTests | 10 | 1 |
| RefreshingPolicyStoreTests | 7 | 0 |

A única falha é `Construtor_de_producao_recusa_cache_sem_ACL_protegida_sem_reparar_ou_carregar`: lança PlatformNotSupportedException ao acessar ACL no Linux. O arquivo desse teste e a implementação de cache não foram alterados. O resultado original permanece no TRX; não foi removido/ignorado para produzir aprovação artificial. Suíte completa Windows não foi executada.

Ensaio HTTP local do ApiSmoke: **cinco cenários aprovados** — confirmação válida, HTTP 401, recibo inválido, redirecionamento recusado sem chamada seguinte e ID inválido sem tráfego. Não houve teste Java, MySQL, front, porta do minifiltro ou persistência de cadastro.

Reprodução dos testes:

```powershell
dotnet test agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj -c Release --filter "FullyQualifiedName~AgentApiClientTests|FullyQualifiedName~DispatcherReliabilityTests|FullyQualifiedName~MinifilterPolicyBridgeTests|FullyQualifiedName~DurableHttpPolicyStoreTests|FullyQualifiedName~RefreshingPolicyStoreTests" --logger "trx;LogFileName=bridge.trx"
```

O diff do PR #63 passa `git apply --check` sobre esta preparação, sem aplicação efetiva. Isso verifica compatibilidade textual, não teste da composição nem autorização de merge. A correção dos recibos do #63 continua pendente e não foi incorporada. Não importar o #49 inteiro para usar esta ponte; sua integração exige revisão própria.

## Próximos aceites

1. Disponibilizar cadastro de teste existente e backend/banco para executar ApiSmoke contra Java real; conferir atualização no registro certo.
2. Validar serviço Windows com a configuração opcional, confirmando falha de heartbeat sem interromper inspeção/auditoria.
3. Acordar consulta de política e identidade/provisionamento com os responsáveis; adaptar somente C# depois do contrato.
4. Preservar o bloqueio/revisão do #63 e revisar composição antes de qualquer integração na main.
5. Qualificar o par agente/driver e a visualização do backend no painel com seus responsáveis.

Nenhuma alteração foi publicada: a conexão GitHub informa push=false. A branch local e o patch são uma preparação revisável, sem PR novo, merge, comentário ou mensagem à equipe.
