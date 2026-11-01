# Política central no agente — 01/11/2026

Entrega incremental sobre main `c6409002`, após #78 (unidades WinFsp + gate). Reaproveita a candidata local de 30–31/10, adaptada sem restaurar o driver/staging antigo. Somente C#, testes e workflow do agente; Java, Angular, banco, driver e regras internas dos canais não foram modificados.

## Ativação explícita

No arquivo de configuração protegido do serviço, com host e IP previamente cadastrados no backend:

```json
{
  "CentroAdministracao": {
    "BaseUrl": "https://servidor.example/agent/",
    "HeartbeatProtocol": "AgentApi",
    "RegisteredHostId": 23,
    "PolicyProtocol": "ConsoleByIp",
    "PolicyHostIp": "192.0.2.10"
  }
}
```

O exemplo usa endereço e identidade sintéticos: substituir pelos valores provisionados. O vínculo protegido existente permite omitir RegisteredHostId após provisionamento. O IP é explícito, sem descoberta ou cadastro automático. Sem ConsoleByIp permanece o consumidor legado. O arquivo local `%ProgramData%\SafeUpload\policy.json` mantém escopos, extensões, limites e canais: revisar antes de ativar. Sem cache central compatível, o modo clássico conserva o fallback operacional local existente.

O consumidor usa o endpoint existente `GET /agent/api/policy?ip=...`, confere `destino.idHost` e `destino.ip`, exige `versao="1.0"` e usa `idPolitica` positivo como revisão de publicação. Isso acompanha a consulta Java atual, ordenada por idPolitica decrescente; não pressupõe um endpoint novo de versionamento/ETag. CPF, CNPJ, cartão e credenciais são traduzidos; qualquer regra desconhecida ou lista vazia recusa o documento inteiro. Bloquear desativa AuditOnly; alertar ativa AuditOnly. Justificativa fica desabilitada neste contrato.

## Aplicação e continuidade

Cache central separado em `%ProgramData%\SafeUpload\console-policy-cache.json`, com vínculo a URL completa do servidor, id_host e IP. Arquivo protegido, gravação temporária e troca no mesmo diretório; inicialização pelo cache antes da rede. Revisão inferior, mudança das regras/ação com a mesma revisão, documento inválido ou host divergente preservam a última política válida. Publicação idêntica é idempotente. Alterações locais de escopos/limites são composição operacional, não nova revisão central, e mudam a impressão do conteúdo usada nas decisões.

O refresh permanece em fundo a cada 30 s para consumidores clássicos. A leitura `LoadCurrentAsync` consulta a origem e a política operacional atual, sem devolver cache/default em falha; o wrapper encaminha essa leitura. Isso preserva retenção quando uma decisão de publicação exige política atual. O cache de vereditos clássico também compara o conteúdo efetivo, evitando colisão entre revisão local e central com o mesmo número. Usa a impressão de conteúdo já existente na main; não altera o protocolo do gate. Corpo HTTP/cache limitado a 64 KiB, profundidade 16, timeout até o fim da resposta e cliente sem redirects.

## Estado reconciliado e dependências

- #42/#49 encerrados sem merge integral; #63 incorporado em #64. #64 foi integrado em 30/10, portanto `ba23cc0b` e a divergência antiga de heartbeat não descrevem mais a main. O cliente AgentApi atual envia `id_host` a `/agent/heartbeat`, com identidade persistente. Esta entrega preserva esse caminho.
- #66–#77 trouxeram auditoria, fila, histórico e proteção de comunicação posteriores a 27/10. Recibos completos e reenvio idempotente são preservados e incluídos na regressão leve; não foi criada outra fila ou outro ACK.
- #78 já integrado mudou o par de proteção para unidades SafeUpload/gate. A qualificação v18 anterior não se transfere ao par atual. Nenhum kernel/WinFsp ou infraestrutura foi alterado nesta entrega.
- A listagem GitHub consultada não contém uma branch remota identificada como política central. A candidata local foi reaproveitada; código ainda não publicado de Pedro precisa ser comparado antes de consolidar duas implementações.
- Thiago/equipe: confirmar `idPolitica` como revisão monotônica, significado de `versao`, seleção por IP quando muda a rede, autenticação de dispositivo e confirmação de política efetivamente aplicada no painel. Identidade persistente e IP não são credenciais; não foi inventado ACK de política no heartbeat.
- Publicação de escopos/canais, regras ainda não suportadas e autenticação exigem contrato da equipe. Política recebida/cacheada não comprova montagem das unidades nem aplicação do gate.

## Validação rápida

Executar `dotnet test agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj --filter "FullyQualifiedName~ConsolePolicyTests|FullyQualifiedName~PolicyContentBindingTests|FullyQualifiedName~RemotePolicyAuthorityTests|FullyQualifiedName~DurableHttpPolicyStoreTests|FullyQualifiedName~RefreshingPolicyStoreTests"`.

Validação local ampliada: 252 testes aprovados, zero falhas e zero ignorados, incluindo falha da origem operacional; build da interface sem erros/avisos. Há um aviso CA2022 preexistente no projeto de testes, fora dos arquivos modificados. O workflow de recibos inclui e exige os grupos de política. Conferir resultado final no PR.

Aceite conjunto pendente: publicar A/B pelo painel no host cadastrado, observar mudança de decisão, reiniciar offline e conferir o cache; testar documento inválido/regressivo sem perder A/B; reconectar e conferir os mesmos eventIds sem duplicação. Sem ensaio de VM, pacote instalado, backend/MySQL ou proteção real nesta rodada. PR em rascunho; não é autorização de merge ou aceite de produção.

## Continuação — recibos e reconexão

O POST de auditoria agora lê o recibo em fluxo, com limite de 16 KiB (incluindo campos futuros), profundidade JSON 16 e o mesmo prazo HTTP até terminar o corpo. Respostas rejeitadas não precisam carregar o corpo inteiro. Um recibo excessivo, truncado, profundo demais ou interrompido não confirma a fila; eventos e justificativas mantêm os bytes originais. Na reconexão, a fila reaberta reenvia o mesmo payload e só confirma após ambas as contagens completas. O prazo de rede não limita a gravação local da confirmação.

Sete casos novos cobrem tamanho anunciado/sem tamanho, limite exato com leitura fragmentada, JSON inválido/profundo, servidor silencioso e cancelamento. Recorte final: 94 testes aprovados, zero falhas/ignorados, incluindo recibos existentes, comunicação e política central. A primeira execução teve duas asserções excessivamente específicas quanto ao subtipo de exceção JSON; corrigidas sem mudar o comportamento do produto. Não substitui ensaio com backend real. O CI exige o novo grupo AuditReceiptBoundsTests.

Entrega publicada no [PR #79](https://github.com/pedro-canafistula/safeupload/pull/79), em rascunho. Checks remotos devem ser conferidos no HEAD atual; nenhuma aprovação de produção ou merge é presumida.


O provisionamento inicial agora só persiste a identidade depois de validar também PolicyProtocol e PolicyHostIp. Antes, uma inicialização recusada por política inválida podia deixar o ID gravado e impedir a correção do cadastro pelo operador. Quatro testes reproduziram o problema antes da correção e passaram depois; cada caso confere ausência de arquivo no erro e provisionamento do ID corrigido. Recorte de identidade/configuração/política/recibos: 140 aprovados, zero falhas/ignorados. Não altera o formato da identidade nem substitui vínculo existente.


O ensaio existente `ContractSmoke --current-api` foi ampliado para consumir as duas publicações do backend Java/MySQL descartável: A com CPF/alertar e B com CNPJ/bloquear. Usa o mesmo arquivo e uma fila isolada para conferir categorias/decisão/revisões, colisão com a versão local, persistência e repetição idempotente. Reabre o provedor com transporte explicitamente indisponível para conferir restauração do disco, fallback clássico e recusa de leitura atual. Não desliga o backend nem altera os totais de eventos/justificativas/políticas já verificados no banco. O modo alertar é conferido no snapshot; não se presume aplicação de AuditOnly por um canal instalado.

Compilação Release de ContractSmoke aprovada sem erros/avisos; sintaxe do roteiro PowerShell aprovada. A execução ampliada contra Java/MySQL fica para o job de contrato já existente no CI; ainda não foi executada localmente. O marcador de sucesso só é emitido depois de todas as verificações e mantém explícitos InstalledConsolePolicy=Pending, PolicyCacheAclQualified=False e DriverQualified=False. A restauração usa uma nova instância no mesmo processo, não um reinício SCM ou novo processo Windows.


Justificativas de versões retidas agora usam LoadCurrentAsync, sem aceitar o snapshot clássico como autoridade de liberação. O registro em memória recebe a impressão da política capturada no resultado da inspeção; revisão/conteúdo diferentes, justificativa desabilitada ou ausência dessa impressão impedem autorização. O serviço reconfere a política depois de auditar e antes de chamar o publicador existente. Sessão, SID, prazo e consumo único continuam exigidos. Nenhuma alteração no gate, formato do pipe ou mecanismo de publicação WinFsp. São leituras pontuais, não uma transação atômica entre servidor remoto e publicação.

Doze casos novos verificam mudanças de revisão/conteúdo/permissão, usuário/sessão, uso único, indisponibilidade da origem antes/depois da auditoria e falha de auditoria. Recorte local: 86 aprovados, zero falhas/ignorados. Grupo DriveJustificationPolicyTests exigido no workflow. Registro de justificativa anterior à publicação continua representando uma solicitação: se a conferência posterior falhar, a versão não é publicada, mas o registro fica preservado. Aceite de pipe/serviço/WinFsp em VM com essa mudança ainda pendente.


O CI agora inclui um cenário separado ConsoleByIp no serviço SYSTEM, reaproveitando o backend/MySQL e os controles de isolamento/limpeza do roteiro existente. Provisiona explicitamente a política operacional CPF com o script de ACL do produto; o serviço deve criar seu próprio cache central CNPJ. Confere dono SYSTEM/DACL exata do cache e diretório, vínculo, revisão e decisão de arquivo. Reinicia o serviço com backend parado e sem RegisteredHostId na linha de comando, exige a mesma política/cache/identidade e evento pendente. Na recuperação publica CPF, exige mudança de decisão, movimento intacto pelo watcher e persistência central de cada eventId uma única vez, seguida da confirmação local por recibo. A política operacional deve permanecer inalterada.

Build Release de ContractSmoke aprovado sem erros/avisos; PowerShell e YAML conferidos. O cenário novo ainda depende da execução remota deste commit: código preparado não é aceite concluído. Não foi executado localmente porque o roteiro só aceita runner Windows descartável. O cenário usa FileSystemWatcher (observação após gravação), não WinFsp/gate, e não qualifica bloqueio preventivo ou atualização do status remoto da UI. Os ensaios anteriores de identidade e contrato permanecem preservados.

Uma falha anterior do instalador foi localizada no primeiro teste de resposta válida fragmentada do diagnóstico em PS5.1: 1275 ms excederam o orçamento sintético de 1 s. Apenas esse caso de sucesso passa a ter 5 s para inicialização do runtime; casos negativos e prazo de produção permanecem intactos. Validação local final: 26/26 em PS7.6.5 e 26/26 em PS5.1.26100.9711.


Primeira execução do cenário SYSTEM (41352573361): recusada antes do início do serviço porque o helper em scripts/support resolveu o script de ACL relativo à pasta errada. Caminho corrigido para ../Protect-SafeUploadPolicy.ps1 e existência conferida; artefatos originais preservados. Essa falha não é aceite do serviço nem reprovação do consumidor C#.


Aceite remoto concluído no commit 8513d5a75be605058a660194f69182d05bb52c12: [cenário ConsoleByIp SYSTEM aprovado](https://github.com/pedro-canafistula/safeupload/actions/runs/41352846785/job/124986554617), com cache criado pelo serviço e ACLs exatas, novo processo offline sem ID inicial, preservação de identidade/política local/cache, mudança de regra após reconexão e auditoria deduplicada/confirmada. [Artefato](https://github.com/pedro-canafistula/safeupload/actions/runs/41352846785/artifacts/13102091864). Esse aceite é do FileSystemWatcher; não das unidades WinFsp/gate. Comunicação, recibos e instalador do mesmo commit também aprovados; conferir contrato geral e HEAD posterior separadamente.

Na preparação do par atual, o cliente C# do gate deixava de transmitir destinos não resolvidos, cortava a lista após 16 pastas e truncava caminhos. Agora a mensagem v1 é montada/validada integralmente antes de conectar/iniciar driver/enviar: excesso de pastas, destino não resolvido, caminho sem espaço para terminador, NUL interno ou UTF-16 inválido recusam a política inteira, sem transmitir uma versão parcial. Layout permanece 16400 bytes, com os mesmos comandos, versão, flags e 16 campos de 512 WCHAR. A chave de repetição deriva dos bytes transmitidos. Não altera kernel nem mecanismo WinFsp; rejeição não comprova aplicação de outra política ou montagem das unidades.

72 testes focados aprovados, zero falhas/ignorados, incluindo 14 casos do gate: layout/flags/terminadores, limites exatos, recusa integral e entrada real do cliente sem conexão em excesso de escopo. Testes não carregam driver nem montam unidade. A VM 192.168.122.52 indicada no repositório não respondeu à conexão TCP/22 a partir deste ambiente e WinFsp não está instalado aqui; o aceite real continua dependendo do laboratório preparado, sem instalação na máquina de trabalho.


A liberação automática de versões retidas em modo auditoria deixou de confiar apenas no snapshot periódico do DriveService. Agora exige inspeção concluída com achados (sem motivo de falha), vínculo de conteúdo da política da inspeção e consulta atual à origem, com AuditOnly ainda ativo e escopo/extensão/processo compatíveis. Falha na origem, política alterada, ausência do vínculo, erro de parsing/timeout/limite e recusa do publicador mantêm a versão retida. A chamada continua depois da auditoria existente, sem alterar seu contrato ou o publicador WinFsp. Leituras pontuais não são transação atômica com o publicador.

85 testes focados aprovados, zero falhas/ignorados, incluindo 13 casos novos. Os testes usam o motor real para gerar decisão de CPF e falha de PDF, e verificam a fronteira anterior à chamada de publicação sem montar unidade. Aceite real desse caminho em WinFsp/gate permanece pendente pelo acesso ao laboratório.


A janela de dez minutos das justificativas também passa a usar tempo decorrido (TimeProvider), sem depender do relógio civil. Ajustes de horário não encurtam/estendem a autorização e tentativas recusadas não renovam o prazo. Versão/conteúdo de política, SID/sessão e consumo único permanecem exigidos. Construtor público de produção preservado, com relógio controlado restrito à fronteira interna de testes. 67 testes focados aprovados, zero falhas/ignorados, incluindo cinco cenários novos de relógio/limite exato/tentativa recusada; sem alterar o horário do Windows.


Diagnóstico local de política disponível pelo comando `Get-SafeUploadDiagnostics.ps1 -Query policy-status`. Reutiliza o pipe administrativo, com snapshots em memória: última política entregue por LoadAsync, última consulta atual bem-sucedida e falha/cancelamento posterior, revisões remotas validadas/cache escrito/cache lido, além do recibo de transporte do escopo do gate. Conteúdo diferente na mesma versão tem impressão distinta. Não consulta rede/disco/driver, não altera política/autoridade, não inicia driver e não envia ACK central. Revisões salvas/lidas são observações desde este processo, não inventário atual do arquivo. Escopo aceito pelo transporte não prova unidades montadas, bloqueio ou publicação final. Consulta disponível também sem driver e em modo local. Nenhum destino, URL, host ou texto de exceção é exposto.

Validação: 101 testes focados aprovados (sete casos novos de PolicyDiagnosticsTests), 27/27 casos do cliente de suporte em PS7 e PS5.1, interface/dependências Release sem erros/avisos. CI passa a exigir o novo grupo. A composição mantém consumidores remotos sem cache periódico adicional; não altera regras de clipboard/TLS. [Fechamento do núcleo e limites](NUCLEO-AGENTE-20261101.md).


Correção do motor no fechamento: cancelamento durante leitura de política interrompe decisões rápidas e conferências de autoridade; também é reconferido depois do worker e da auditoria. O cache clássico recebe nova decisão somente depois da tentativa de auditoria e da checagem de cancelamento. Falha comum de auditoria continua sem mudar o veredito. Evento já durável é preservado, cache anterior legítimo não é apagado e nova tentativa após chamada cancelada não herda a decisão nova dessa chamada. Nenhuma alteração de contrato/driver/canais. Treze casos reproduzidos com falha antes da correção; grupo final com 14 casos, incluindo fila real. Recorte final: 181 aprovados, zero falhas/ignorados. Grupo InspectionCancellationTests exigido no CI; sem serviço/driver instalado nem ensaio pesado local.


Fechamento do motor: o caminho clássico agora limita o tamanho real do arquivo aberto antes de alocar o buffer de captura para qualquer formato; metadado SizeBytes antigo não contorna o limite. O staged valida tamanho real/medido e permissão de leitura tanto ao abrir por caminho quanto por read lease. Divergência retém antes do parser e fecha a entrada. Tamanho real acima do limite mantém file_too_large, inclusive ZIP e arquivo declarado vazio. Fail-open clássico versus retenção staged preservados, sem alterar driver/publicador/canais. Sete casos reproduziram falha antes da correção; grupo final com 18 casos. Recorte final: 241 aprovados, zero falhas/ignorados, incluindo regressões de ZIP/compartilhamento/auditoria/cache/cancelamento. Grupo InspectionInputSizeTests exigido no CI; sem ensaio pesado local. Todos os workflows do checkpoint anterior afe75044 foram aprovados; o novo HEAD deve ser avaliado separadamente.
