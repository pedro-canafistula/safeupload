# Candidata Windows C# — demonstração de 07/11/2026

## Situação vigente — 06/11/2026

O [PR #100](https://github.com/pedro-canafistula/safeupload/pull/100) foi integrado; os PRs de origem foram incorporados
e encerrados. A indicação de draft e as atribuições por agente no histórico abaixo descrevem a preparação original.
O cenário nativo central foi concluído com política Bloquear→Alertar, auditoria correlacionada e par WinFsp/gate
no laboratório declarado. A manutenção manual da aplicação foi entregue e validada no escopo de #102.

Use a seção [Configuração e provisionamento](#configuração-e-provisionamento) abaixo e o
[contrato vigente de integração](INTEGRACAO-CENTRAL.md#contrato-vigente--06112026).
As correções posteriores até #113 têm testes de componentes/integração automática; conferir o manifesto e a fonte
do pacote em uso. Não transferir o aceite nativo de #100/#102 para uma candidata posterior nem declarar clipboard/TLS,
Windows11, assinatura ou distribuição completos a partir do CI. O restante conjunto permanece nas #43/#45–#48.

## Histórico da composição inicial

Branch própria `integracao/agente-final-20261105`, [PR #100](https://github.com/pedro-canafistula/safeupload/pull/100), draft para main. Base #95 `3c13b3e7b41bb7a66f276ca2a99eac2766dfde08`. O SHA inicial fixado e publicado é `57fb6ed72cece5ac2e5cf4ca855b791c7b06af3b`; os incrementos posteriores devem avançar essa história, sem amend/rebase/force-push. O SHA e os hashes do pacote entregue para instalação ficam no manifesto e na descrição do PR. Não transferir aceite entre SHAs.

## Conteúdo preservado

| Origem conferida | SHA | Incorporação |
|---|---|---|
| Núcleo preventivo, política central, auditoria/offline e cadências #95 | `3c13b3e7b41bb7a66f276ca2a99eac2766dfde08` | Base; contém #90–#94. Não reaplicados `dd1fa503`, `aa8cda59` e `3c13b3e7`. |
| Main após #96 | `4627bb1757976602aa53f19fea9f19079a4fe05b` | Merge preservando o backend/banco originais. Nenhuma edição dessas áreas. |
| Recuperação e investigação do despachante #97 | `02754dd3f2d3e94e3cc23a825307979571b6fd2b` | Merge do incremento de testes/documentação; despachante de produção preservado. |
| Apresentação WPF #98 | `62ca149eb594123385948d92252b53a4de62fcd0` | Merge; resultados, deduplicação, estados e omissão na apresentação. |
| Cadastro/heartbeat Ed25519 #99 | `cdd68aa3647d1c15e348acb9cba081b718214fee` | Merge; identidade DPAPI, provisionamento explícito e sender assinado. |

Refs remotas reconciliadas antes da composição, sem diferenças para os SHAs autorizados. Os merges iniciais não tiveram conflitos; autores/commits originais permanecem no grafo. `web/`, `db/`, `driver/`, `smoke/` e `lab/` correspondem à main incorporada; checkouts dos outros trabalhos e `sources/` foram preservados. O Agente 2 é o único editor de ContractSmoke/scripts/workflows desta rodada e parte exatamente do SHA inicial. O Agente 1 é o único operador da VM candidata.

## Configuração e provisionamento

Consultar [o contrato completo](AUTENTICACAO-ED25519-AGENTE5.md). `AgentApiEd25519` é uma escolha explícita. O serviço não faz cadastro no startup e não tenta o protocolo antigo após erro. `AgentApi`/`Legacy` continuam exclusivamente para ensaios identificados de bases antigas; não comprovam compatibilidade com #96.

Após cadastro único, configurar o serviço com valores reais conferidos:

```json
{
  "CentroAdministracao": {
    "BaseUrl": "https://administracao.exemplo/agent/",
    "HeartbeatProtocol": "AgentApiEd25519",
    "HostIp": "10.95.0.51",
    "HostMask": 24,
    "PolicyProtocol": "ConsoleByIp",
    "PolicyHostIp": "10.95.0.51",
    "DispatchIntervalSeconds": 30,
    "TimeoutSeconds": 5
  },
  "Interception": { "Mode": "Drive" }
}
```

O endereço acima é exemplo. HostIp, máscara e PolicyHostIp devem corresponder ao cadastro e à rede da VM; `RegisteredHostId`, quando informado, precisa coincidir com a identidade. O serviço lê `%ProgramData%\SafeUpload\authentication\ed25519-identity.dat`. Não migrar silenciosamente uma identidade legada nem alterar o vínculo para conseguir iniciar.

Provisionar como administrador elevado ou SYSTEM pelo executável completo de ApiSmoke. O token é digitado em entrada oculta ou encaminhado por stdin; nunca consta em argumento, configuração ou log:

```powershell
& C:\SafeUploadCandidate\tools\ApiSmoke\SafeUpload.Agent.ApiSmoke.exe --ed25519 register https://administracao.exemplo/agent/ "$env:ProgramData\SafeUpload\authentication\ed25519-identity.dat" 10.95.0.51 24
```

A chave pendente é persistida antes da única tentativa de cadastro. Se a resposta se perder ou o token for recusado, preservar o arquivo: não apagar, trocar chave ou repetir cadastro. Recuperação só com ID administrativamente conferido e prova assinada aceita pelo Java:

```powershell
& C:\SafeUploadCandidate\tools\ApiSmoke\SafeUpload.Agent.ApiSmoke.exe --ed25519 recover https://administracao.exemplo/agent/ "$env:ProgramData\SafeUpload\authentication\ed25519-identity.dat" 10.95.0.51 24 ID_CONFERIDO
```

Conferir DACL protegida exata de diretório/identidade/lock: SYSTEM e Administrators, sem ACE adicional/herdada, owner autorizado; usuário comum não pode ler/escrever. DPAPI LocalMachine mais ACL constitui o armazenamento protegido; o aceite dos arquivos de teste sem ACL de produção não basta. Nenhum comando deste documento deve imprimir token ou material privado.

HTTPS é obrigatório fora de loopback. HTTP para 127.0.0.1/localhost serve somente ao laboratório dentro da própria máquina. O endereço NAT do host, como 10.0.2.2, não é loopback do guest. Usar Java local ao guest ou HTTPS com cadeia confiável e nome válido. Não desativar validação de certificado nem redirects como atalho.

Política permanece `GET /agent/api/policy?ip=...`, revisão `idPolitica`; auditoria permanece `POST /agent/events`, confirmação somente após recibo integral. O campo `politica` do heartbeat não substitui a consulta existente. Não inventar assinatura para rotas que o Java não a exige. Cadências de heartbeat e auditoria permanecem independentes e cada lote serial.

## Pacote e validação

Publicar todos os arquivos self-contained win-x64 de serviço, WPF e ApiSmoke. O layout de instalação deve manter `service/` e `app/` como irmãos: a validação do pipe na WPF exige `../service/SafeUpload.Agent.Service.exe` e o processo de serviço confiável. Incluir BouncyCastle.Cryptography e demais dependências em cada publicação; copiar só a DLL principal não constitui pacote. O gate v1 identificado é componente separado, sem recompilar/modificar C nesta frente.

No SHA inicial: builds Release Service/App/ApiSmoke/ContractSmoke/App.Tests aprovados. Seleção única Agent.Tests: 389 aprovados, zero falhas/ignorados; projeto App.Tests: 32 aprovados, zero falhas/ignorados, seis renderizações XAML inspecionadas. Não somar suítes históricas sobrepostas. CA2022 preexistente no teste de fila. Renderização em memória testa apresentação/bindings, sem serviço, bandeja ou balão real. Os ensaios atuais do contrato #96 e os legados devem ser identificados separadamente pelo incremento do Agente 2.

O PR é destinado à main e disparou CI real já no SHA inicial; relatório/descrição devem informar execuções e conclusões efetivas para cada revisão, incluindo falhas dos fixtures antigos. Build ou CI verde não é aceite nativo. Após incorporar o incremento do Agente 2, repetir somente os checks afetados, publicar SHA final e manifesto e entregar ao Agente 1.

No SHA inicial, o roteiro existente de Ed25519 também aprovou 23 verificações com Java da main #96 e MySQL 8.4.13 exclusivos: um host e dois eventos distintos, assinatura válida/inválida, token recusado/expirado, política, auditoria e processos C# separados durante perda real do Java/reconexão. JAR inalterado SHA256 `82114467B340FD2117E0B76FD89DB8E39F321292FC3541A1F07EB28095FD2FC3`. Os processos próprios foram encerrados. Esse ensaio usa DPAPI real com arquivos isolados; não qualifica a criação/uso de ACL de produção sob SYSTEM, serviço instalado, gate ou WPF visual.

O aceite dessa revisão exige instalação LocalSystem, ACL/DPAPI/usuário comum, provisionamento único, heartbeat no mesmo ID após reinício, política central, WinFsp/gate reais, limpo/CPF/escrita direta negada, Bloquear→Alertar sem reinstalar, arquivo inválido bloqueado, WPF visual autorizada sem repetição e ciclo offline/reconexão com IDs/horários/recibos preservados. Estados não confirmados sem ocorrência genuína ficam pendentes; não adulterar fila/stage para fabricar prova. O #95 é evidência histórica própria e não homologa esta candidata.

O incremento de ensaios do Agente 2 (`8842c7f24f807b507da4f4d011f24a8d8cd5637c`, filho exato do SHA inicial) adapta ContractSmoke, scripts e três workflows, sem editar produção. O ensaio funcional passa a usar a identidade assinada nos novos processos e o DDL original `03_jobs.sql`; SQL de fixture segue por stdin. Os fixtures sem assinatura/H2 exigem opção legada explícita e deixam de ser apresentados como testes do #96. CI inclui os casos novos de autenticação/recuperação e App.Tests; a expectativa Java inválida de rota antiga permanece visível, sem supressão. A retirada das chamadas de serviço sem assinatura reduz essa cobertura antiga do contrato corrente; não é um novo aceite SYSTEM, que permanece atribuído ao Agente 1.

Correção posterior à candidata `20bd3a2e`: [#101](https://github.com/pedro-canafistula/safeupload/pull/101), `fdc3c63f019122863d986ebc722948e7fc8c7069`, filho exato daquela revisão. Somente `Test-AgentIntegrationSmoke.py`: identificar requisições por ciclo/rota, com contagem exata, POST, payload/IDs/horários e recibos preservados, aceitando as duas ordens permitidas pelas cadências independentes. A hipótese foi reproduzida: roteiro antigo passa heartbeat-primeiro e falha eventos-primeiro; corrigido passa 15 casos em cada ordem controlada e 15 naturais; ApiSmoke 13 casos. Nenhuma mudança em produção ou aumento de timeout. O pacote 20bd permanece preservado com sua falha registrada. O sucessor exige novo SHA/pacote, novo ensaio HTTP e novo CI; não reutilizar o nome/hash do ZIP anterior nem declarar aceite nativo herdado.

Para o roteiro nativo central atualizado, o comando do serviço precisa declarar explicitamente `PolicyProtocol=ConsoleByIp` e `HeartbeatProtocol=AgentApiEd25519`. Depois da política publicada e do ID/base conferidos, executar como administrador de ensaio, distinto do serviço SYSTEM:

```powershell
.\agente\scripts\Test-CentralPolicyDrive.ps1 -Destination C:\SafeUpload\Destino -DriveRoot S:\ -PolicyVersion REVISAO_CONFERIDA -Action Bloquear -GatePath C:\Windows\System32\drivers\SafeUpload.sys -ResultPath C:\Evidencias\bloquear.json -RegisteredHostId ID_CONFERIDO -AgentBaseUri https://administracao.exemplo/agent/
```

Substituir os valores de contexto pelos conferidos. O script registra o hash opaco da identidade DPAPI, sem expor a chave; seu hash não substitui a prova de provisionamento/ACL/ID pelo serviço e ApiSmoke. Repetir com a nova revisão/ação Alertar e depois Offline, arquivos de resultado novos, preservando política, fila, identidade, stage e binários. `LegacyBackend` seleciona apenas a composição anterior ao #96 e não deve ser usado para aprovar esta candidata.

## Demonstração de até cinco minutos

Preparar instalação e cadastro antes de começar. Usar apenas o SHA/pacote aceito pelo Agente 1; caso o aceite não esteja concluído, anunciar explicitamente quais cenas são evidências anteriores ou testes de componente.

| Tempo | Cena e evidência |
|---|---|
| 0:00–0:30 | Mostrar SHA/manifesto, serviço e app da mesma revisão, identidade pública/ID sem segredos, cobertura local separada da comunicação central. |
| 0:30–1:25 | Limpo publicado intacto; CPF retido com janela correta; escrita direta recusada pelo gate com contador real. |
| 1:25–2:20 | Publicar CPF/Alertar no Angular; aguardar revisão nova; mesmo serviço/gate, CPF publicado com achado/alerta. DOCX inválido continua inconclusivo/bloqueado. |
| 2:20–3:15 | Abrir auditoria central e correlacionar EventId/revisão/hash/horário; mostrar heartbeat no mesmo cadastro e controle preservado. |
| 3:15–4:30 | Backend de teste fora do ar: política válida e proteção local continuam; eventos ficam pendentes. Reconexão confirma mesmos IDs sem duplicação. Reinício offline pode ser evidência gravada desta revisão se não couber ao vivo. |
| 4:30–5:00 | Reabrir WPF e conferir histórico/replay sem repetir alertas antigos. Explicar limites nativos ainda pendentes e dependências externas. |

## Próxima semana e dependências

- Thiago/backend: recuperação do ID após resposta perdida, reconciliação de token rejeitado e migração dos legados; códigos HTTP estáveis; expiração transacional versus scheduler; replay por assinatura só do ID, revogação/rotação e autenticação das demais rotas.
- Luiz/Thiago: explicação da auditoria web para Approved com achados e falha de inspeção. Nenhuma alteração Angular foi feita nesta frente.
- Agente 1/equipe Windows: fechar somente os itens nativos não comprovados nesta revisão, depois Office/USB/SMB e Windows 10/11 conforme escopo acordado. Não anunciar carga, queda de energia, interrupção abrupta ou distribuição/upgrade sem seus próprios aceites.
- Latência histórica: manter diagnóstico do #97 e colher durações monotônicas por etapa se houver nova reprodução; não aumentar timeouts, reduzir recibos ou criar filas paralelas como suposta correção.

Resumo para o professor: a candidata reúne proteção preventiva, política central, apresentação Windows e cadastro/heartbeat assinados no contrato atual, preservando cache e auditoria offline. Os testes locais e o CI demonstram recortes específicos; a prova instalada pertence ao SHA ensaiado na VM. O relatório evolutivo e a Trilha registram precisamente o que foi implementado, testado localmente, verificado em CI e observado no ambiente nativo.
## Correção posterior do registro de notificações

O CI do sucessor ecf5fe8e aprovou recibos/WPF/HTTP sintético e o contrato atual
C#/Ed25519/Java/MySQL, mas o instalador 42071008851 falhou esperando status.
O artefato confirmou o peer correto e a recusa de imagem incorreta; uma falha
de compartilhamento (NativeError 32) ao construir o registro criou um fallback
permanentemente indisponível. O Agente 2 reproduziu a ausência de recuperação
em pasta privada, sem identificar o detentor original do arquivo na CI.

A correção C# substitui esse fallback por admissão sob demanda, com intervalo
mínimo de um segundo entre tentativas. Cada tentativa usa o construtor original,
mantendo lease exclusivo, ACL, verificação de links e validação da timeline.
Um gravador já admitido nunca é substituído após falha de escrita: sua recuperação
estrita continua responsável por operações incertas. Sem append durável, não há
entrega, replay ou retenção de eventos. O hub guarda separadamente apenas o
último status ainda não emitido, repetindo a tentativa no próximo cliente ou na
amostra de comunicação de cinco segundos, mesmo sem mudança da comunicação.
Não reenvia notificações de transferência que foram suprimidas.

Sete casos novos verificam liberação real do lease, retomada do status mais
recente por amostra/cliente, falha persistente e limitação de tentativas, ACL
inválida sem reparo, hardlink sem alteração externa, escrita incerta sem trocar
o gravador e descarte do lease. A seleção afetada local passou 62 testes,
incluindo os 16 cenários de estado preventivo. A deduplicação do Drive exige
que não exista status pendente: voltar ao último estado emitido deve substituir
um estado intermediário cuja gravação falhou. O último status registrado
continua preservado internamente, mas não autoriza essa deduplicação nem
o envio ao novo cliente quando há uma observação mais recente pendente.
A primeira seleção ampliada registrou 88 aprovados e cinco falhas ao criar
links simbólicos por falta de privilégio no ambiente local (incluindo o caso
novo, posteriormente substituído por hardlink real); não houve skip nem
alteração das quatro verificações preexistentes. CI deve executar também os
casos de links simbólicos no runner Windows e repetir o instalador.
Essa correção exige outro SHA/pacote e novo aceite do Agente 1, sem transferir
resultados nativos das revisões anteriores. Fontes de autenticação, política,
fila e driver permanecem sem mudança; a falha de migration Java é externa.

No CI de 7a966ce0, instalador e contrato atual passaram; recibos executou
974 casos, com 973 aprovados e um teste de log ainda esperando emissão única.
O ajuste posterior é somente de teste: exige mensagem segura após a primeira
falha e exatamente duas mensagens seguras após a tentativa do novo cliente,
mantendo recusa de entrega e privacidade. Nenhuma produção mudou nesse ajuste.
