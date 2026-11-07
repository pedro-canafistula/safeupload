# Console ↔ agente

Como o Centro de Administração (Spring Boot + Angular + MySQL) e o agente Windows conversam. Este é o único
documento do contrato; se o código mudar, mude este arquivo junto.

## Identidade do agente

1. No console, **Configurações → Tokens de cadastro → Gerar**. O token tem 8 caracteres, vale 15 minutos, serve uma
   vez e pertence à empresa de quem o gerou.
2. Na máquina, como administrador: `SafeUpload.Agent.Service.exe cadastrar https://servidor:8443/agent/ <token>`
   (opcional: `--certificado <sha256>` para fixar o certificado do servidor). O agente cria um par Ed25519 e guarda,
   com DPAPI de máquina, a chave privada, a URL, o `id_host` e o certificado fixado em
   `%ProgramData%\SafeUpload\authentication\ed25519-identity.dat`. O servidor cria o host na empresa do token.
3. Ao iniciar, o serviço lê esse arquivo: com identidade, fala com o servidor; sem identidade, protege só com o
   `policy.json` local. Para trocar o cadastro, use `cadastrar` com `--substituir` e um token novo. A identidade
   anterior permanece válida se o novo cadastro for recusado ou se o agente não receber um ID válido.

`POST /agent/enroll` (sem assinatura): `{"token","chave_publica","host":{...}}` → `201 {"id_host": n}`.

O objeto `host` é `{"hostname","ip","mascara","sistema_operacional","versao_so","mac_address"}`. O agente detecta
esses dados sozinho. Eles são só informativos e o console os mostra na tela Endpoints.

## Assinatura

Toda rota `/agent/**`, menos `enroll`, exige quatro cabeçalhos:

| Cabeçalho | Valor |
|---|---|
| `X-SafeUpload-Host` | `id_host` |
| `X-SafeUpload-Time` | segundos Unix (UTC) |
| `X-SafeUpload-Nonce` | valor aleatório novo a cada requisição (16 a 64 caracteres `A-Za-z0-9+/=_-`) |
| `X-SafeUpload-Signature` | Base64 da assinatura Ed25519 (RFC 8032) da mensagem abaixo |

Mensagem assinada (UTF-8, separada por `\n`, sem `\n` no final):

```
SafeUpload-v1
<MÉTODO>                 ex.: POST
<rota após /agent/>      ex.: heartbeat   (com "?query" se houver)
<id_host>
<time>
<nonce>
<sha256 hex minúsculo do corpo; corpo vazio = sha256 de zero bytes>
```

O servidor recusa com **401** quando: o host não existe; a assinatura não confere; o horário difere mais de 5
minutos do relógio do servidor; ou o mesmo nonce já foi usado por esse host nos últimos 10 minutos (replay). Um host
revogado recebe **403**. Como o corpo entra na assinatura, ninguém altera um heartbeat ou um lote de eventos no
caminho.

Vetor de teste (o mesmo nos testes Java e C#): semente `000102…1f` (32 bytes 0x00..0x1f), nonce
`AAECAwQFBgcICQoLDA0ODw==`, mensagem `SafeUpload-v1\nPOST\nheartbeat\n7\n1700000000\n<nonce>\n<sha256 de {"x":1}>`. A assinatura esperada está em
`AgentSignatureTest` (Java) e em `SignedRequestTests` (C#).

## Rotas do agente

| Rota | Corpo | Resposta |
|---|---|---|
| `POST /agent/heartbeat` | `{"host":{...},"politica_aplicada": <versão ou null>,"versao_agente":"0.2.0"}` | `200 {"id_host": n}` |
| `GET /agent/policy` | — | `200` documento de política · `404` sem política atribuída |
| `POST /agent/events` | lote de auditoria (formato inalterado, `schemaVersion` 1) | `200 {"acceptedEvents","acceptedOverrides"}` |

A cada 30 s o agente envia heartbeat e lê a política. Com o servidor fora do ar, ele usa a última política válida
guardada em `console-policy-cache.json`, vinculada ao servidor, ao ID do host e à chave pública do cadastro.
Após trocar o cadastro, ou se o cache for de um formato anterior sem esse vínculo, vale o `policy.json` local
até a primeira leitura bem-sucedida da política. Com `404`, usa o `policy.json` local. Os eventos ficam numa fila em disco e
só saem dela depois do recibo. O servidor grava cada evento com o `id_host` autenticado: o `endpointId` do corpo é
apenas um rótulo.

A fila associa cada evento ao cadastro que o originou. Depois de um recadastro, só os eventos do novo cadastro e
as justificativas dos eventos dele são enviados. Registros do cadastro anterior e registros antigos sem vínculo
ficam no histórico local, inclusive após recuperação de publicação. O formato enviado à API continua o mesmo.

## Documento de política

É o mesmo formato do `policy.json` local, e o agente não traduz nada:

```json
{
  "version": 42,
  "activeCategories": ["Cpf", "Cnpj", "Rg"],
  "alertCategories": ["Rg"],
  "monitoredScopes": {
    "extensions": [".txt", ".docx"],
    "destinationPaths": ["C:\\Dados\\Financeiro", "\\\\srv\\publico"],
    "removableDrives": true,
    "networkPaths": true
  },
  "maxFileSizeMb": 100,
  "inspectionTimeoutSeconds": 900,
  "overrideAllowed": false,
  "failOpen": false,
  "excludedProcesses": ["System", "SafeUpload.Agent.App"],
  "clipboard": { "mode": "Off" }
}
```

- `version` é o número da versão publicada. Cada edição no console cria uma versão nova e invalida as decisões e
  justificativas da anterior.
- `activeCategories` reúne todas as categorias inspecionadas. As que também aparecem em `alertCategories` são
  liberadas com registro de auditoria (alerta). As demais bloqueiam. Uma falha de inspeção bloqueia sempre.
- `auditOnly: true` continua aceito no `policy.json` local e equivale a pôr todas as categorias em alerta.
- A ação por categoria vale para arquivos (unidades SafeUpload) e upload web. O clipboard tem modo próprio
  (`clipboard.mode`: `Off`, `Audit` ou `Block`) e as listas de destinos e origens padrão do agente.

## Políticas, grupos e padrão (console)

- Cada empresa tem as suas políticas e os seus grupos de máquinas, e só vê as próprias máquinas (ROOT incluído).
- Uma política pode ser a **padrão** da empresa, e só uma de cada vez. Um grupo aponta para uma política ou fica
  sem política.
- **Política de um host** = a política do seu grupo; se o host não tiver grupo, ou o grupo não tiver política, vale
  a padrão; se não houver padrão, a resposta é `404`.
- A tela Endpoints mostra a política **esperada** (calculada como acima) e a **aplicada** (relatada no heartbeat).
  Quando as duas diferem, a máquina ainda não buscou a versão nova ou está offline.

Rotas administrativas (sessão ADMIN/ROOT, sempre dentro da empresa do usuário):

| Rota | Uso |
|---|---|
| `GET /politicas` | lista: `id, nome, padrao, versao, atualizadaEm, atualizadaPor, grupos[], hosts` |
| `GET /politicas/{id}` | `id, nome, padrao, versao, configuracao, historico[{versao, criadaEm, criadaPor}]` |
| `POST /politicas` · `PUT /politicas/{id}` | `{nome, padrao, configuracao}` → `{id, versao}`; cada `PUT` cria uma versão |
| `DELETE /politicas/{id}` | `409` se algum grupo usa a política ou se ela é a padrão |
| `GET/POST /grupos` · `PUT/DELETE /grupos/{id}` | `{nome, politicaId}`; ao apagar um grupo, os hosts dele ficam sem grupo |
| `PUT /endpoints/{idHost}/grupo` | `{grupoId}` (ou `null`) |
| `POST /endpoints/{idHost}/revogar` | o host passa a receber 403; para voltar, é preciso cadastrar de novo |
| `GET /auditoria/exportar?host=` | CSV dos últimos 7 dias (todas as máquinas, ou uma com `host=<idHost>`) |
| `POST /admin/token` · `GET /admin/tokens` · `DELETE /admin/tokens/{id}` | tokens de cadastro |

`configuracao` é o formulário do console. O servidor o converte no documento acima:

```json
{
  "categorias": { "cpf": "bloquear", "cnpj": "alertar", "rg": "ignorar", "cartao_credito": "bloquear",
                  "dados_bancarios": "bloquear", "credenciais": "bloquear", "dados_saude": "alertar",
                  "dados_pessoais": "ignorar", "documentos_confidenciais": "bloquear" },
  "pastas": ["C:\\Dados\\Financeiro"],
  "pendrives": true,
  "rede": true,
  "extensoes": [".txt", ".csv", ".docx", ".xlsx", ".pdf"],
  "tamanhoMaximoMb": 100,
  "tempoLimiteSegundos": 900,
  "permitirJustificativa": false,
  "clipboard": "desligado"
}
```

Regras: as 9 categorias são obrigatórias (`bloquear`, `alertar` ou `ignorar`) e pelo menos uma não pode ser
`ignorar`; `credenciais` vira `Password` + `Secret` no agente. `pastas` aceita até 32 caminhos absolutos (`C:\...`
ou `\\servidor\compartilhamento`). `extensoes` aceita de 1 a 64 itens no formato `.abc`. `tamanhoMaximoMb` vai de 1
a 4096 e `tempoLimiteSegundos` de 5 a 3600. `clipboard` é `desligado`, `alertar` ou `bloquear`.

## Transporte

Fora do loopback o agente só fala HTTPS. Para o laboratório,
`web/back/scripts/gerar-certificado.sh <nome-ou-ip>` cria `safeupload.p12` e imprime o SHA-256 que vai em
`cadastrar --certificado`. O backend sobe com
`--server.ssl.key-store=safeupload.p12 --server.ssl.key-store-password=... --server.port=8443`. Com o certificado
fixado, o agente ignora a cadeia de confiança e compara só o SHA-256.
