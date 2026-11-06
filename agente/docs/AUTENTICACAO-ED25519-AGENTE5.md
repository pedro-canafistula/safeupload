# Autenticação Ed25519 — Agente 5

05/11/2026. Branch `feat/agente-auth-ed25519-20261105`, criada exatamente sobre
o PR #95 (`3c13b3e7b41bb7a66f276ca2a99eac2766dfde08`). Backend de referência:
main após #96, `4627bb1757976602aa53f19fea9f19079a4fe05b`. Guia dos Agentes,
Trilha e relatórios dos PRs #90–#95 conferidos. O aceite nativo do #95 permanece
evidência daquela composição; esta mudança precisa ser incorporada pelo Agente 4.

## Contrato implementado

As duas operações são `POST /agent/heartbeat`, com exatamente um entre `cadastro`
e `autenticacao`, além de `host`:

```json
{
  "cadastro": { "token": "TOKEN_SINTETICO", "chave_publica": "BASE64_SPKI_ED25519" },
  "host": { "ip": "10.95.0.51", "mascara": 24, "hostname": "PC-SYNTHETIC", "sistema_operacional": "Windows", "versao_so": "10.0", "mac_address": "001122334455" }
}
```

```json
{
  "autenticacao": { "id_host": 1, "assinatura": "BASE64_ASSINATURA_ED25519" },
  "host": { "ip": "10.95.0.51", "mascara": 24, "hostname": "PC-SYNTHETIC", "sistema_operacional": "Windows", "versao_so": "10.0", "mac_address": "001122334455" }
}
```

Os valores acima são exemplos, não credenciais. A chave pública é DER X.509
SubjectPublicKeyInfo (OID Ed25519), codificada em Base64, **não** os 32 bytes crus.
A assinatura Ed25519, sem prehash, cobre exclusivamente a representação decimal
invariante do `id_host` em UTF-8. Não assina JSON, hash, host ou desafio inventado.
Resposta aceita: HTTP 200, `resposta.status="OK"` e `id_host` positivo; heartbeat
exige o mesmo ID solicitado. Recibo inválido/ambíguo não confirma identidade.

`AgentApiClient` preserva o limite de leitura e o orçamento do corpo completo.
Clientes de produção do serviço/ferramenta não seguem redirects e não registram
corpos. As novas operações exigem HTTPS; HTTP é aceito apenas em loopback de teste.

## Criptografia e identidade no Windows

Não foi presumida uma API Ed25519 nativa: a referência do SDK/runtime instalado
10.0.402/10.0.13 não expõe um tipo público autônomo `System.Security.Cryptography.Ed25519`.
Não usamos ECDSA como substituto nem dependemos de suporte a essa curva no CNG.
Foi escolhida [BouncyCastle.Cryptography 2.7.0](https://www.nuget.org/packages/BouncyCastle.Cryptography/2.7.0),
implementação gerenciada compatível com .NET 10, e suas rotinas RFC 8032/SPKI.
O Java padrão do #96 verificou as assinaturas produzidas por ela no ensaio real.

`SignedHostIdentityStore` usa [DPAPI do Windows](https://learn.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection)
(`ProtectedData`, LocalMachine), **mais** diretório/arquivos com DACL protegida e
somente SYSTEM e Administrators com controle total. LocalMachine permite ao
administrador provisionar para o serviço LocalSystem; a confidencialidade frente
a usuários comuns depende também dessas ACLs. Administradores e SYSTEM são a
fronteira confiável, como no armazenamento protegido existente do agente.
Diretório existente com permissões divergentes é recusado, sem reparo silencioso.
Reparse points e ancestrais redirecionados são recusados antes de criar material.

O arquivo contém somente o envelope DPAPI, incluindo servidor, ID e semente
privada. Não há PEM, seed ou token em texto simples no disco. Buffers da semente e
do documento descriptografado são zerados após uso. O token não é persistido.
O vínculo é específico da base `/agent/`; erro de chave, arquivo, servidor ou ID
nunca gera substituição automática. A identidade legada não é convertida nem
sobrescrita. Falha ao ler a identidade assinada não provoca fallback para legado.

## Cadastro explícito e recuperação

O serviço **não cadastra** durante o startup ou no laço periódico. A ferramenta
ApiSmoke ganhou `--ed25519 register|heartbeat|recover`. Executar o provisionamento
como administrador elevado ou LocalSystem, com o pacote desta revisão:

```powershell
dotnet agente/SafeUpload.Agent.ApiSmoke/bin/Release/net10.0/SafeUpload.Agent.ApiSmoke.dll --ed25519 register https://servidor.exemplo/agent/ "$env:ProgramData\SafeUpload\authentication\ed25519-identity.dat" 10.95.0.51 24
```

`register` lê o token em entrada oculta ou stdin redirecionado, nunca como argumento.
Não colocar o token em comando literal, histórico, arquivo de configuração ou log.
A ferramenta imprime apenas operação, ID e SHA256 da chave **pública**.

Antes da única requisição de cadastro, a chave é persistida e marcada pendente.
Um lock de arquivo exclui operações concorrentes. Resposta perdida, timeout,
cancelamento ou erro HTTP mantém a mesma chave pendente; reiniciar a ferramenta
ou serviço não reenvia o token e não cria outro par. Mesmo token inválido exige
reconciliação administrativa, sem apagar o arquivo para tentar novamente.

Quando o backend já tiver criado o host e a equipe informar seu ID correto:

```powershell
dotnet agente/SafeUpload.Agent.ApiSmoke/bin/Release/net10.0/SafeUpload.Agent.ApiSmoke.dll --ed25519 recover https://servidor.exemplo/agent/ "$env:ProgramData\SafeUpload\authentication\ed25519-identity.dat" 10.95.0.51 24 ID_CONFERIDO
```

`recover` primeiro exige autenticação válida com a chave pendente para aquele ID.
Somente então confirma o vínculo. Não aceita modificar uma identidade já confirmada.

## Composição do serviço — Agente 4

Depois do provisionamento e da conferência do cadastro/IP exclusivos:

```json
{
  "CentroAdministracao": {
    "BaseUrl": "https://servidor.exemplo/agent/",
    "HeartbeatProtocol": "AgentApiEd25519",
    "HostIp": "10.95.0.51",
    "HostMask": 24,
    "PolicyProtocol": "ConsoleByIp",
    "PolicyHostIp": "10.95.0.51",
    "TimeoutSeconds": 5,
    "DispatchIntervalSeconds": 30
  }
}
```

`RegisteredHostId` é opcional nesse modo; se informado, deve corresponder exatamente
ao arquivo assinado. Não reutilizar um bootstrap antigo sem reconciliar o cadastro.
`HostIp` e `PolicyHostIp` devem ser iguais; campos do SO/hostname/MAC são coletados
localmente. O serviço lê a identidade protegida e injeta `IAgentHeartbeat` assinado
no ponto já existente. Não houve alteração em `HttpAgentDispatcher.cs`.

`AgentApi` e `Legacy` permanecem escolhas explícitas para composições antigas;
**não são compatíveis com o heartbeat do #96** e não são fallback do modo assinado.
A política continua em `GET /agent/api/policy?ip=...`; `idPolitica` continua a revisão.
A propriedade `politica` do recibo novo não substitui esse fluxo existente.
A auditoria continua em `POST /agent/events`, com o recibo integral atual. Não foi
adicionada uma assinatura inexistente a essas duas rotas: elas continuam aceitando
requisições sem autenticação de heartbeat na configuração atual do Java.

Para a integração final:

1. Incorporar este incremento à composição do #95 e publicar **todos** os artefatos
   e dependências do serviço/ApiSmoke; não copiar somente a DLL principal. Nenhuma
   mudança em instalador ou scripts dos outros Works foi feita nesta frente.
2. Em ambiente próprio autorizado do Agente 4, provisionar em pasta nova sob
   ProgramData, verificar owner e DACL exata de identidade e lock, iniciar como
   LocalSystem e verificar heartbeat no mesmo ID após reinício. Usuário comum deve
   ser impedido de ler/escrever o material. Esse aceite nativo de ACL ainda falta.
3. Usar `heartbeat` da ferramenta e depois o serviço com o mesmo arquivo/base/IP.
   Confirmar o fingerprint público e o ID; não solicitar novo token a cada startup.
4. Repetir os roteiros centrais já aprovados no #95: política, operação Drive,
   notificação, auditoria e offline. Os testes desta frente não transferem aceite
   visual, SYSTEM ou gate para a nova composição. WPF/driver/despachante não mudaram.

## Evidência dirigida e limites

**245 testes Windows Release aprovados**, zero falhas/ignorados, incluindo 14 novos
casos/variações de autenticação. Cobrem contrato, assinatura, DPAPI real, reinício,
timeout/resposta perdida, bloqueio de duplicatas locais, troca de chave/ID/servidor,
cifra corrompida, diretório inseguro recusado, HTTPS e configuração do serviço.
Recorte inclui clientes legados, políticas, identidade anterior e recibos/auditoria.
CA2022 preexistente em teste de fila; nenhuma advertência nova no produto.
Consulta NuGet de vulnerabilidades do Core, incluindo dependências transitivas,
não retornou pacotes vulneráveis nesta execução.
Service/Core, ApiSmoke e ContractSmoke compilaram; as duas ferramentas tiveram
compilação Release sem erros/avisos. Não foi modificada a WPF.

**Java atual + MySQL 8.4.13 reais e exclusivos: 23 verificações aprovadas.**
Token emitido por `/admin/token`, cadastro SPKI, heartbeat Ed25519 validado pelo
Java, assinatura inválida HTTP 401, contrato antigo recusado, token inválido,
consumido e expirado recusados (HTTP 500 atual). Expiração pelo evento MySQL
original, com `event_scheduler=ON`, sem alterar DDL. Uma política CPF consumida
pelo C# e dois eventos confirmados/persistidos uma vez. SQL independente: um host,
dois eventos distintos. Java encerrado realmente; outro processo restaurou
identidade/política e preservou fila/cache offline; Java reiniciado e terceiro
processo autenticou no mesmo host e enviou o mesmo evento pendente.

IDs sintéticos: host 1; revisão 1; eventos `1dd6800f-53ac-4416-8d62-d4b806422422`
e `f8b46adb-4a9b-473b-8f5d-c2e0d0ff36c9`. JAR inalterado SHA256
`82114467B340FD2117E0B76FD89DB8E39F321292FC3541A1F07EB28095FD2FC3`.
Todos os processos criados foram encerrados. Nenhuma VM foi acessada.
O processo local não estava elevado: DPAPI foi real, mas o ensaio usou o construtor
interno de arquivos isolados, sem qualificar a criação de ACL SYSTEM/Administrators.
O construtor de produção sempre verifica essas permissões e recusa o diretório
inseguro no teste. Não foi simulado sucesso criptográfico para anunciar integração.

Reprodução: compilar ContractSmoke e executar `agente/scripts/Test-Ed25519Backend.ps1`
com `-MySqlBasePath`, `-BackendReferencePath` (cópia original da main #96 incluindo
`web/back/target/backend-0.1.0.jar` e `db/initdb`), `-JavaPath` e diretório de saída
**novo**. Portas padrão exclusivas 13357/18095; não usar o ambiente de outro Work.
O script cria dados descartáveis, executa o DDL original e encerra só seus processos.
Tokens do ensaio não são impressos, persistidos pelo agente ou incluídos no relatório.

## Perguntas exatas para Thiago/equipe

- Como reconciliar `id_host` pela chave pública após resposta de cadastro perdida?
  Hoje não há consulta de recuperação contratada. `recover` exige o ID fornecido
  pelo administrador; não adivinhamos por IP/hostname nem reenviamos cadastro.
- Qual procedimento para token rejeitado antes de criar host e para migração dos
  hosts legados sem chave pública, preservando políticas/auditoria/IDs? Não existe
  endpoint contratado de rotação/revinculação, e não o inventamos no cliente.
- Token inválido/consumido/expirado deverá retornar qual status/código estável?
  Hoje houve HTTP 500. A expiração dependerá do evento MySQL ativo ou será validada
  transacionalmente no Java? O cliente não consegue comprovar expiração só pela data.
- O contrato manterá assinatura determinística só do ID, sem desafio/nonce/horário
  e sem cobrir `host`? Esse formato permite replay; o cliente o respeita exatamente.
- Como serão revogação/rotação e eventual autenticação de política/auditoria e da
  emissão administrativa de tokens? Heartbeat assinado não protege essas rotas.

Nenhuma mensagem foi enviada à equipe. Sem mudança em Java, Angular, driver,
esquema, WPF, despachante ou instaladores. Implementado e validado em componentes;
sem merge e sem aceite nativo da composição nova.
