# Integração central do agente

Em 04/11/2026, #64 e #81 estão integrados na main `7dcf139f`; #90 e #91 continuam draft.
Esta entrega usa branch isolada `feat/agente-integracao-central-20261104`, sobre o #91 (`07802232`),
para preservar a correção preventiva do Agente 1. Não representa aceite ou merge dessas dependências.
Guia dos agentes, Trilha, Arquitetura 3.1 e Requisitos 2.1 foram consultados. Os documentos de outubro
descrevem contratos históricos; a composição atual usa WinFsp e gate v1.

## Contratos conferidos no código atual

| Operação | Contrato |
| --- | --- |
| Cadastro explícito | `POST /agent/synchronize` → `id_host`, `id_usuario_so`. Cada chamada cria registros; o serviço não deve repetir cadastro automaticamente. |
| Heartbeat | `POST /agent/heartbeat`, corpo `{"id_host": 1}`. Atualiza `hosts.visto_por_ultimo`/`ativo` do host existente. Não usa `id_usuario_so`. |
| Publicação administrativa | Angular publica `POST /politicas`, com sessão administrativa, `destino.ip`, `acao` e `regras`. Java grava `politicas`, `regras` e vínculo `fk_id_host` no MySQL. |
| Consulta do agente | `GET /agent/api/policy?ip=10.90.0.21`; confere `destino.idHost` e `destino.ip`. `idPolitica` identifica a publicação; `versao="1.0"` identifica o formato. |
| Auditoria e consulta | `POST /agent/events`; `GET /auditoria`, `/endpoints`, `/painel` com sessão administrativa. A versão do inventário vem do último evento e não confirma aplicação no gate. |

Configuração explícita do serviço, com valores reais do ambiente:

```json
{
  "CentroAdministracao": {
    "BaseUrl": "http://127.0.0.1:18080/agent/",
    "HeartbeatProtocol": "AgentApi",
    "RegisteredHostId": 1,
    "PolicyProtocol": "ConsoleByIp",
    "PolicyHostIp": "10.90.0.21",
    "DispatchIntervalSeconds": 30,
    "TimeoutSeconds": 5
  },
  "Interception": { "Mode": "Drive" }
}
```

`RegisteredHostIdentityStore` persiste servidor + ID em `identity/host-registration.json` e recupera o ID
quando o parâmetro de bootstrap é omitido. Não é credencial. Provisionamento e autenticação individual
do dispositivo, renovação/revogação e HTTPS do ambiente publicado permanecem dependências do backend/equipe.
Nenhum contrato de autenticação novo foi criado.

| Regra central | Categoria do agente |
| --- | --- |
| cpf / cnpj / cartao_credito | Cpf / Cnpj / PaymentCard |
| credenciais | Password + Secret |
| rg / dados_bancarios / dados_saude | Rg / BankData / HealthData |
| documentos_confidenciais / dados_pessoais | ConfidentialDocument / PersonalData |

`bloquear` desativa `AuditOnly`; `alertar` ativa. O motor continua reportando o achado; no canal Drive,
somente inspeção concluída com achados pode ser liberada como `Approved` com categorias. Falha continua
bloqueada. Escopos, extensões, limites e justificativa vêm do `policy.json` local.
O refresh é periódico, com snapshot validado e cache `console-policy-cache.json`; não há HTTP por arquivo.
O intervalo de 30 s não é SLA de aplicação.

## Correção e validação desta entrega

A comparação de publicações centrais incluía `OverrideAllowed`, que pertence à política local. Revogar
justificativa localmente fazia a mesma publicação central ser rejeitada como adulterada; a carga tolerante
mantinha a permissão anterior. A comparação agora usa somente revisão, ação e categorias centrais.
A impressão da política efetiva continua incluindo a permissão local; os controles de publicação não mudaram.
Quatro regressões falharam antes da correção e passaram depois, incluindo reinício e leitura estrita.
Ação ou categorias alteradas sem nova revisão e rollback continuam recusados.

Validação Windows Release: **179 testes relacionados aprovados**, zero falhas/ignorados. Compilação do
ContractSmoke sem avisos/erros; CA2022 preexistente em teste de fila fora da correção. Parser Windows
PowerShell 5.1 do roteiro aprovado; execução nativa do roteiro ainda pendente.

O ensaio C# com Java sem alterações e MySQL 8.4.13 exclusivos aprovou **57 verificações**: identidade reaberta, avanço do heartbeat
sem duplicar cadastro, host de controle intacto, publicações reais, consultas e recibos. SQL independente:
2 hosts, 3 políticas vinculadas ao host 1 e 8 eventos centrais. Os eventos da inspeção de política deste
recorte ficam em fila separada de componente; não representam publicação pelo Drive.

| Publicação real | Snapshot e inspeção do mesmo CPF sintético |
| --- | --- |
| 1: CPF, Bloquear | v1, Cpf, classificação Blocked |
| 2: CPF, Alertar | v2, AuditOnly=true, achado Cpf preservado; liberação pelo canal nativo pendente |
| 3: CNPJ, Bloquear | v3, Cnpj, classificação Approved para o mesmo arquivo CPF |

A perda real do backend e a recuperação em novo processo foram aprovadas pelo modo
`--console-offline-probe <pasta-central-policy> <id-host> <ip> <revisao>` do ContractSmoke, após encerrar
o Java descartável: revisão 3 recuperada do disco, inspeção Approved sob CNPJ e bytes do cache preservados.
Este ensaio usa cache de componente sem qualificar ACL SYSTEM, serviço instalado ou gate.
O ensaio SYSTEM/ConsoleByIp anterior do #90 permanece evidência histórica da sua composição, sem transferir
aceite preventivo para esta entrega.

## Demonstração na VM e continuidade para o Agente 3

**Bloqueio atual:** falta o pacote `SafeUpload.sys` x64 Release do gate v1, porta `\SafeUploadGatePort`,
commit, SHA256 e certificado público de teste, sob responsabilidade de Victor/equipe do driver. A Trilha
registra WinFsp instalado na VM isolada, mas gate ausente. Não substituir por FileSystemWatcher para encerrar M3.

1. Compor #90 + #91 + esta branch na VM descartável, com o gate identificado. Executar primeiro
   [o ensaio preventivo mínimo](ENSAIO-PREVENTIVO-MINIMO.md). Preservar hashes e resultados.
2. Usar Java/MySQL reais e frontend da mesma composição. Provisionar um único cadastro com IP exclusivo,
   conferir o ID e heartbeat no banco antes/depois, mantendo um host de controle. IP duplicado ou mudança
   de endereço exige alinhamento do cadastro, sem escolher um host arbitrariamente.
3. Configurar ConsoleByIp e Drive; manter justificativa desativada, destino protegido e extensões `.txt`/`.docx`.
   Para este roteiro, passar `PolicyProtocol=ConsoleByIp` explicitamente na linha do serviço.
4. Pelo painel, publicar CPF/Bloquear, anotar `idPolitica`, aguardar snapshot/unidades e executar:

```powershell
.\agente\scripts\Test-CentralPolicyDrive.ps1 -Destination C:\DestinoProtegido -DriveRoot S:\ -PolicyVersion 1 -Action Bloquear -GatePath C:\Windows\System32\drivers\SafeUpload.sys -ResultPath C:\Teste\bloquear.json
```

5. Pelo painel, publicar CPF/Alertar; repetir com a revisão real nova, `-Action Alertar` e outro JSON.
   Comparar PID/horário do serviço, hash do gate e política local entre fases: a troca não deve exigir
   reinício nem reinstalação. O roteiro confere versão no evento, CPF, bytes publicados/retidos e falha
   de DOCX bloqueada mesmo em Alertar. Cache recebido, sozinho, não satisfaz esses checks.
6. Encerrar somente o backend de teste; repetir a última fase com `-Offline`. Reiniciar o serviço offline
   e repetir com outro JSON. Conferir identidade/cache preservados e eventos pendentes. Reconectar e conferir
   os mesmos IDs, versões e horários em `/auditoria` e no MySQL, sem duplicação. Obter esses registros com a
   equipe do backend/painel; o roteiro local não comprova persistência central ou operação pelo Angular.

Interromper no primeiro pré-requisito ausente ou divergência concreta. Java, Angular, autorização global e
esquema de banco não foram alterados. Necessidades dessas frentes devem ser propostas aos responsáveis antes
da implementação. Merge e aceite da equipe permanecem pendentes; a missão ainda não está concluída ponta a ponta.
