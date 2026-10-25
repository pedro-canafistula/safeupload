# Auditoria do agente → API web: proposta para alinhamento com Thiago

Implementado no agente C# nesta branch. A API Java e o painel Angular não foram alterados nesta rodada. Este documento descreve o formato emitido; não comprova aceite ou persistência pela API atual da main.

## Fluxo e responsabilidade

1. A inspeção decide e grava o evento na fila local `queue.jsonl`.
2. Com `CentroAdministracao:BaseUrl` configurada, o despachante tenta heartbeat e auditoria a cada intervalo configurado (padrão 30 segundos). A inspeção não espera a rede.
3. `POST /agent/events` envia até 100 eventos e até 100 justificativas por lote.
4. Somente HTTP 2xx **com ambas as contagens inteiras, presentes uma única vez e iguais às enviadas** confirma o lote. Falha HTTP, rede, JSON inválido, contagens ausentes, repetidas ou parciais deixam os registros pendentes para reenvio, inclusive após reiniciar o agente. A comparação dos nomes permanece sem distinção de caixa; nomes escapados no JSON são comparados após decodificação. Campos adicionais continuam ignorados e só as contagens do objeto principal confirmam o lote.
5. Falha no heartbeat não impede a tentativa de enviar auditoria.

Entrega é **pelo menos uma vez**: uma resposta perdida pode reenviar registros já persistidos. O backend deve deduplicar eventos por `eventId` e devolver a contagem de registros recebidos válidos, incluindo repetições já persistidas. Se contar somente inserções novas, um reenvio ficará pendente para sempre. Para justificativas, a identidade atual é a tupla completa (`eventId`, `justification`, `occurredAtUtc`, `userName`, `endpointId`); não deduplicar apenas pelo evento, que pode ter mais de uma justificativa. Preferir transação para persistir integralmente cada lote; em caso de recusa, não confirmar silenciosamente dados descartados.

O hostname no envelope identifica o computador remetente no momento do envio. `events[].endpointId` e `overrides[].endpointId` preservam a identidade registrada na origem. Hoje o agente usa o nome da máquina como endpointId; identidade persistente e credencial por instalação ainda dependem de desenho conjunto.

## Exemplo sintético de requisição

```json
{
  "schemaVersion": 1,
  "hostname": "PC-SINTETICO",
  "agentVersion": "0.1.1+commit",
  "events": [
    {
      "eventId": "8b4fef7b-d8d8-4bc0-9212-629fb2dd3765",
      "occurredAtUtc": "2026-10-20T16:15:00+00:00",
      "endpointId": "PC-SINTETICO",
      "userName": "usuario-sintetico",
      "fileName": "exemplo.txt",
      "extension": ".txt",
      "sizeBytes": 42,
      "verdict": "Blocked",
      "categories": ["Cpf"],
      "maskedSnippets": [],
      "processName": "explorer.exe",
      "processId": 123,
      "destinationPath": "E:\\Destino",
      "notInspectedReason": null,
      "policyVersion": 7,
      "elapsedMs": 15,
      "dispatched": false,
      "publishedSha256Hex": null,
      "channel": "File"
    }
  ],
  "overrides": []
}
```

Resposta para esse lote, depois de persistir:

```json
{"acceptedEvents": 1, "acceptedOverrides": 0}
```

Mesmo quando uma lista está vazia, sua contagem deve estar presente. O horário é o momento original da decisão em UTC, não o momento do envio. `Blocked` identifica bloqueio; o mesmo endpoint envia também outras decisões do enum existente. `policyVersion` informa a versão utilizada na decisão, que pode diferir da atual após operação offline. `publishedSha256Hex` é opcional e pode estar ausente em eventos antigos; não é prova de hash do arquivo bloqueado em todos os canais.

Os nomes/enums existentes foram preservados. `schemaVersion`, `hostname` e `agentVersion` são adições no envelope: Thiago precisa confirmar o aceite desses campos. Não mudar enums ou rotas de um lado sem atualizar o contrato e validar os dois lados.

## Conteúdo e proteção de dados

- O agente envia **metadados do arquivo bloqueado**, sem bytes, texto extraído ou anexo do arquivo. Não é um upload da quarentena.
- `maskedSnippets` vai sempre vazio para manter a chave do contrato anterior sem enviar os trechos locais. A fila local permanece intacta.
- `fileName` é reduzido ao nome, removendo caminhos de produtores antigos.
- No canal `Web`, `destinationPath` contém apenas a origem HTTP(S), por exemplo `https://exemplo.test:8443`. Caminho, usuário/senha, query e fragmento são removidos; destino inválido resulta em string vazia. Nos demais canais, o destino registrado é preservado.
- Justificativas são texto livre necessário ao fluxo de autorização e continuam sendo enviadas. Nomes, usuários, caminhos e justificativas podem conter dados pessoais: não representam anonimização. O backend deve controlar acesso, retenção e visualização.
- O instalador exige HTTPS remoto e permite HTTP apenas em loopback para desenvolvimento. Credencial de máquina, autorização da API, registro seguro e rotação ainda não estão implementados neste contrato. Não expor coleta anônima à internet.

## Heartbeat e dependências do web

`POST /agent/heartbeat` mantém `endpointId`, `hostname`, `os`, `agentVersion` e `policyVersion`. A versão agora vem do assembly do serviço publicado, igual à informada no lote; não é mais uma constante independente do instalador. A versão informativa pode incluir o hash Git depois de `+`.

Thiago: conferir rotas `/agent/heartbeat`, `/agent/policy` e `/agent/events`, aceite de campos/enums, persistência e deduplicação, autenticação e exposição na auditoria administrativa. O C# não passa a chamar `/agent/api/synchronize` automaticamente. Validar os endpoints efetivamente implementados na branch que será integrada.

## Critérios de aceite conjuntos

1. Em VM, instalar o candidato e apontar para a API de teste em HTTPS.
2. Gerar bloqueio com arquivo sintético e conferir `eventId`, nome, horário, host, usuário, decisão, canal e política no banco e no painel.
3. Desligar rede/API, gerar evento, reiniciar o serviço e restabelecer conexão: evento deve chegar com o mesmo ID/horário.
4. Simular resposta perdida, contagem parcial, autenticação recusada e evento repetido; não perder auditoria nem duplicar registros administrativos.
5. Confirmar ausência de conteúdo do arquivo e segredos de URL nas requisições e logs do servidor.

Os testes automatizados locais usam fila real em disco e transporte HTTP simulado, não MySQL, API Java ou serviço instalado. A fila ainda não tem política de retenção/compactação nem armazenamento local autenticado; esses pontos e o limite de leitura de filas grandes seguem no backlog.
