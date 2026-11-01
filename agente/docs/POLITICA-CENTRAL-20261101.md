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
