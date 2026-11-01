# Integração agente–backend — 28/10/2026

Base Java conferida: `d6605e4db8043d56e25e0e05adc075f797aa77c9`, PR #65 do Thiago integrado em 28/10, 01:44 no horário de Brasília. Esta atualização altera somente agente C#, testes, utilitário e documentação. Não modifica Java, Angular, banco, driver ou CI.

## Resultado e alcance

O cliente usa `POST /agent/synchronize` e `POST /agent/heartbeat`. Heartbeat envia apenas `{"id_host": ID_HOST}`; cadastro ainda devolve dois identificadores distintos, `id_host` e `id_usuario_so`. O serviço passa a exigir `RegisteredHostId` no modo AgentApi. Uma configuração com `RegisteredUserId` é recusada explicitamente, inclusive quando contém também um host válido: não converter ou reaproveitar o número do usuário.

O cadastro permanece uma chamada explícita da biblioteca, sem execução automática pelo serviço ou utilitário: o backend ainda cria host/usuário novos a cada solicitação, sem chave de repetição segura. Não repetir cadastro após timeout sem conferir o banco. Persistência local e recuperação automática da identidade ainda não estão entregues.

Política e auditoria mantêm seus contratos existentes. O heartbeat novo independe da leitura de política, e sua falha não impede a tentativa de auditoria. Sem configuração AgentApi, continua o modo legado, que não é compatível com o heartbeat da main atual. Nenhum fallback automático troca um protocolo pelo outro.

## O que os commits do Thiago entregaram

| Alteração | Estado no código atual | Consequência |
| --- | --- | --- |
| Heartbeat por host | Ativo, `/agent/heartbeat`, campo `id_host` | C# adaptado nesta entrega |
| Atividade da máquina | `ativo` e `visto_por_ultimo` movidos de usuarios_so para hosts | Conferir persistência em hosts |
| Remoção do envio direto | AdminService não envia mais para porta 8426 | Agente não precisa abrir receptor |
| Consulta de política | `/agent/policies` comentado; PolicyResponse vazio | Ainda não consumível; não trocar apenas o nome da rota no C# |
| Cadastro/login | Correções em AuthService e tratamento de erro | Não fornece credencial individual ao agente |

Fontes: [PR #65](https://github.com/pedro-canafistula/safeupload/pull/65), [commit do Thiago](https://github.com/pedro-canafistula/safeupload/commit/26349f1e8ff4bca8c6e817c85cd985480fd8632b).

## Ensaio hoje à noite

1. Thiago inicia seu backend e confirma URL acessível pela máquina do agente. A configuração Java padrão vincula o servidor a `127.0.0.1`; outra máquina exige bind/rede de teste definidos por ele.
2. Thiago confere a atualização do banco existente. `CREATE TABLE IF NOT EXISTS` não migra tabelas antigas. Não apagar banco/volumes para contornar divergência; combinar migração com o responsável.
3. Escolher um host de teste já cadastrado e conferir seu `id_host`. Usar um cadastro de controle para detectar alteração indevida. Não confundir host com usuário, SID ou hostname.
4. Consultar antes e depois em transações novas:

```sql
SELECT id_host, hostname, visto_por_ultimo, ativo
FROM hosts WHERE id_host = <ID_HOST_DE_TESTE>;
```

5. Executar da pasta do utilitário portátil (substituindo os exemplos):

```powershell
.\SafeUpload.Agent.ApiSmoke.exe --base-url http://SERVIDOR:8080/agent/ --registered-host-id ID_HOST_DE_TESTE
$LASTEXITCODE
```

Alternativa pelo fonte, na raiz do repositório:

```powershell
dotnet run --project agente/SafeUpload.Agent.ApiSmoke -c Release -- --base-url http://SERVIDOR:8080/agent/ --registered-host-id ID_HOST_DE_TESTE
```

O utilitário faz uma chamada e encerra; não instala agente/driver, não cria host e não envia eventos. Exit 0 = HTTP 200 e recibo status OK; 1 = falha de comunicação/recibo; 2 = configuração inválida. Não repetir cadastro como solução para erro de heartbeat. Não incluir senhas/tokens na URL.

6. Aceitar heartbeat apenas se o host correto tiver `visto_por_ultimo` avançado e `ativo=1`, o controle não mudar e nenhum cadastro novo surgir. HTTP 200 sozinho não comprova persistência. Registrar URL sanitizada, SHAs C#/Java, IDs de teste, horários/fuso, saída e consulta antes/depois.
7. Só depois validar o serviço Windows com os campos abaixo incorporados à configuração de teste pelo procedimento de instalação já adotado. Não substituir o appsettings inteiro por este trecho. O exemplo usa host sintético 7; usar o ID conferido.

```json
{
  "CentroAdministracao": {
    "BaseUrl": "http://SERVIDOR:8080/agent/",
    "HeartbeatProtocol": "AgentApi",
    "RegisteredHostId": 7,
    "DispatchIntervalSeconds": 30,
    "TimeoutSeconds": 5
  }
}
```

Confirmar envio periódico sem depender de política disponível. O utilitário de chamada única não valida execução periódica do serviço. Nenhum serviço foi instalado/reiniciado nesta entrega.

## Próximos fluxos e pendências objetivas

| Fluxo | Disponível do nosso lado | Falta para aceite |
| --- | --- | --- |
| Heartbeat | Cliente, seleção no serviço, validação de recibo e utilitário atualizados | API/banco reais e serviço periódico |
| Cadastro | DTOs/cliente explícito com os dois IDs | Repetição segura, vínculo e recuperação local da identidade |
| Política | Refresh/cache/validação existentes | Backend entregar rota ativa e documento efetivo versionado; hoje C# consulta `GET /agent/policy?endpointId=...` e Java não publica essa rota |
| Auditoria | Fila e dispatcher para `/agent/events` | Composição/revisão do PR #63, conferência de persistência/deduplicação e resposta perdida no Java real |
| Painel | Eventos enviados pela API central | Consultas administrativas e exibição web; heartbeat não demonstra painel integrado |
| Autenticação | Transporte HTTP(S), recibos e erros sanitizados | Contrato de credencial por dispositivo; SecurityConfig atual usa permitAll e não comprova autenticação |

O backend possui ingestão de eventos em `AgentEventsController`/`AgentEventsStore`, com confirmação depois da transação e deduplicação pelo ID/conteúdo. Isso é evidência de implementação, não de execução neste ambiente. Para auditoria, usar eventos sintéticos de IDs conhecidos, confirmar `agent_audit_ingest`, reenviar os mesmos IDs após resposta perdida e verificar ausência de duplicação. A correção de recibos ambíguos do #63 continua fora desta composição; não declarar auditoria pronta para entrega definitiva.

Para política, combinar com Thiago o JSON, versão, destino, ausência de política e precedência. O modelo administrativo de regras não pode ser assumido equivalente ao PolicyDocument do agente. Até a API existir, a falha de refresh não é aceite de sincronização; conferir separadamente a política/cache efetivamente utilizada.

## Validação desta atualização

- Windows/.NET 10: build Release de testes e dependências, incluindo serviço e minifiltro C#, concluído.
- 64/64 testes de AgentApiClientTests e DispatcherReliabilityTests aprovados, zero skips/falhas. Cobrem host diferente do usuário, rejeição da chave antiga e auditoria independente de heartbeat/política.
- Publicação portátil Windows x64 self-contained: zero erros e avisos. Não exige instalação do SDK/runtime .NET para executar o utilitário.
- 13/13 cenários HTTP locais contra o executável publicado, incluindo rota/corpo exatos, timeout após cabeçalhos, recibos inválidos/ambíguos/grandes, redirecionamento recusado, opção antiga e configurações inválidas sem tráfego.
- Nenhum backend real, banco, serviço instalado, painel ou driver carregado foi testado. Ambiente real ainda não disponibilizado, conforme informado pelo usuário.

Progresso: implementação C# e validação local concluídas para o contrato de heartbeat; integração na main e aceite ponta a ponta pendentes. Não há base para percentual global ou promessa de fechar todos os fluxos hoje. O objetivo viável para a noite é confirmar heartbeat/persistência, avançar auditoria e fechar o contrato que falta para política.
