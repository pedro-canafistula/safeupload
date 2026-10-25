# Políticas no painel — proposta de regras de negócio

Data: 25/10/2026. Base inspecionada: `7327965b5538b590f9957b16ca89b7385dcd99f2`, PR #49, branch `tarefa/consolidar-base-agente-windows`. **Proposta para alinhamento, sem implementação de painel, API, banco ou driver.** Não aprova contrato de distribuição, habilita controles ou encerra #44/#47. PR #42 preservado; nenhum merge.

## 1. Entrega pretendida

Primeiro, desenhar um formulário que represente a política única já consumida pelo agente. Depois, mediante acordo de contrato e evolução do motor, oferecer múltiplas regras, exceções e composição. Uma interface rica que produza condições descartadas pelo agente não constitui proteção.

O formulário deve explicar: quais dados procurar, em quais operações, qual ação é solicitada, quais limitações se aplicam e como verificar o resultado por endpoint. Salvar um rascunho deve ser possível sem dispositivos conectados; publicar exige validação, autorização e um contrato de entrega acordado. A publicação central permanece dependência externa nesta entrega.

## 2. O que o código atual permite afirmar

| Assunto | Comportamento observado | Consequência para o desenho |
| --- | --- | --- |
| Modelo | `Policy` contém uma versão inteira, categorias, escopos, limites, exclusões, auditOnly, overrideAllowed e clipboard | Não há coleção de regras, prioridade ou exceção por regra nesse documento |
| Categorias | Cpf, Cnpj, PaymentCard, Password e Secret; versão e limites positivos; nenhuma categoria ativa é inválida | Oferecer nomes compreensíveis com identificadores estáveis; não oferecer OCR ou classificadores personalizados como disponíveis |
| Compatibilidade | `PolicyDocument` ignora categorias desconhecidas quando ainda restam conhecidas; sourcePaths é aceito e ignorado | O painel deve detectar incompatibilidade antes da futura publicação; isso é validação proposta, mais estrita que o leitor atual |
| Escopos | Extensões, pastas de destino, removível e rede; leituras SensitiveSource entram independentemente da pasta | Não apresentar sourcePaths como filtro efetivo; diferenciar extensão de classificador de conteúdo |
| Caminhos | Expansão de variáveis ocorre no processo que carrega a política; serviço é LocalSystem | `%USERPROFILE%` não representa automaticamente cada usuário conectado. Preferir caminhos de máquina; preview deve declarar contexto de resolução |
| Falhas | Fluxo clássico registra AllowedWithoutInspection para tamanho, formato, timeout e erro; staging exige aprovação para publicar | Não oferecer um botão universal de fail-closed nem converter falta de análise em Approved; failOpen=false não é garantia implementada |
| Auditoria | AuditOnly é consumido pelos canais/interceptores; EffectiveClipboard converte Block em Audit | Achado/veredito do motor não prova negação da operação; distinguir ação solicitada, ação efetiva e modo |
| Clipboard | Off/Audit/Block; ausência do bloco equivale a Off; Block exige destino de saída; categorias são compartilhadas | Cópia e colagem não são a mesma operação; não prometer bloqueio de Ctrl+C ou cobertura de toda aplicação |
| Justificativa | overrideAllowed é global na política, com controles de evento/sessão/prazo no fluxo correspondente | Não equivale a allowlist por valor (HU-08), exceção administrativa permanente ou permissão de qualquer canal |
| Offline | DurableHttpPolicyStore tenta remoto, mantém memória, recupera disco e usa padrão quando não há política recuperável; falha de cache pode deixar política remota apenas em memória | Mostrar origem e persistência separadas; uma versão observada em memória não comprova recuperação após reinício |
| Atualização | RefreshingPolicyStore publica snapshot; MinifilterInterceptor envia política ao conectar; Watcher mantém configuração própria de pastas | Snapshot atualizado não comprova troca atômica de todos os interceptores. Não prometer aplicação em 30 s nem SLA de 15 min |
| Transporte | Consulta C# `policy?endpointId=...`; divergência das rotas/DTOs Java documentada | Não abrir listener 8426 nem traduzir DTO administrativo por suposição; aguardar #44 |
| Capacidade | Watcher observa após gravação; minifiltro/staging dependem do par identificado e qualificação | “Bloqueio preventivo” exige canal e pacote comprovados. Online e instalado não significam protegido |

Fontes de código relativas a esta base: [Policy](../SafeUpload.Agent.Core/Domain/Policy.cs), [Category](../SafeUpload.Agent.Core/Domain/Category.cs), [PolicyDocument](../SafeUpload.Agent.Core/Infrastructure/PolicyDocument.cs), [ClipboardPolicy](../SafeUpload.Agent.Core/Domain/ClipboardPolicy.cs), [InspectionService](../SafeUpload.Agent.Core/Application/InspectionService.cs), [cache durável](../SafeUpload.Agent.Core/Infrastructure/DurableHttpPolicyStore.cs), [refresh](../SafeUpload.Agent.Service/Policy/RefreshingPolicyStore.cs), [minifiltro](../SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs), [Watcher](../SafeUpload.Agent.Service/Interception/FileSystemInterceptor.cs), [limites binários](../SafeUpload.Agent.Minifilter/Protocol.cs) e [conversão](../SafeUpload.Agent.Minifilter/PolicyBuilder.cs).

O protocolo atual limita 32 extensões, 16 prefixos de destino e 16 imagens excluídas, com slots de 16, 260 e 64 caracteres respectivamente, incluindo terminador. O prefixo deve caber **após conversão** para caminho NT; contar apenas o caminho exibido no painel não basta. Esses limites não são um novo contrato central. O timeout do kernel é limitado pelo builder a 100–10.000 ms, enquanto a fábrica soma 500 ms ao orçamento do motor: não aceitar qualquer inteiro positivo como orçamento operacional seguro sem definir limites comuns. Não alteramos esses comportamentos.

## 3. Referências profissionais e escolha explícita

As referências são comparativas; suas funcionalidades não passam a existir no SafeUpload por constarem aqui. Consultadas em 25/10/2026:

- Microsoft Purview Endpoint DLP combina as ações mais restritivas por atividade e usa prioridades para desempate de ações iguais; o modo de simulação altera a ação de execução. Isso sustenta separar intenção e efeito e avaliar conflitos por atividade. [Referência de políticas Microsoft](https://learn.microsoft.com/en-us/purview/dlp-policy-reference).
- Forcepoint modela regras, classificadores, recursos e exceções subordinadas; a exceção é avaliada quando a regra mãe corresponde. Isso fundamenta a proposta de exceções locais à regra. [Policies — Forcepoint](https://help.forcepoint.com/datasecurity/en-us/onlinehelp/guid-5de13f55-c40c-4f7d-b958-9d74d2baf515.html).
- Palo Alto Endpoint DLP usa ordem e primeira regra correspondente para o mesmo conjunto de usuários/periféricos; também orienta conferir recebimento e incidentes após distribuir. Logo, “prioridade DLP” não possui uma semântica universal que possa ficar implícita. [Endpoint DLP Policy Rule — Palo Alto](https://docs.paloaltonetworks.com/enterprise-dlp/administration/configure-enterprise-dlp/endpoint-dlp/create-an-endpoint-dlp-policy-rule).

Recomendação SafeUpload: no primeiro incremento, **uma política efetiva por endpoint**. No incremento de múltiplas regras, usar composição restritiva por operação conforme a seção 6, condicionada à aprovação e à capacidade do motor. Não copiar automaticamente regras de override dos produtos consultados.

## 4. Formulário inicial compatível

| Etapa | Informações de negócio | Validação e apresentação propostas |
| --- | --- | --- |
| Identificar | Nome, descrição, responsável, motivo da alteração | Metadados administrativos futuros, fora do PolicyDocument atual; não inventar campos enviados ao agente |
| Selecionar dados | Categorias suportadas | Ao menos uma; explicar limites da detecção textual, sem conteúdo real como exemplo |
| Definir escopo | Extensões, pastas de destino, removível/rede | Preview dos alvos; listas vazias devem ter significado explícito; rejeitar padrão/wildcard que o consumidor não interpreta |
| Definir comportamento | Auditoria global; justificativa autorizada; limites de análise; clipboard | Exibir efeito de auditOnly sobre clipboard; escolhas de segurança sem suporte ficam indisponíveis, com motivo |
| Revisar exclusões | Processos excluídos e fontes excluídas de clipboard | Diferenciar exclusão técnica de inspeção, exclusão de origem e justificativa temporária. Nome de processo não comprova identidade criptográfica do executável |
| Conferir impacto | Endpoints pretendidos, capacidades conhecidas, diferenças da revisão anterior | Identidade e grupos dependem do cadastro/autorização acordados; IP serve de informação, não de identidade/autorização |
| Salvar/revisar | Rascunho e validações | Salvar não altera agentes. Download de JSON deve ser identificado como exportação, sem selo “distribuída” |
| Publicar/acompanhar | Revisão imutável e situação por endpoint | Só implementar após contrato #44; exibir falha/incompatibilidade/estado desconhecido em vez de sucesso presumido |

Não criar controles de impressão, Bluetooth, RDP, domínio web, rótulos, grupos por usuário ou limiar por classificador como configuráveis no MVP compatível. Há outros canais no código, mas isso não prova suporte desses seletores no documento de política nem sua qualificação operacional. Modo staging/interceptor é configuração de execução e não deve ser convertido em campo da política atual por iniciativa do painel.

## 5. Revisão, publicação e aplicação — contrato conceitual proposto

1. **Rascunho:** editável, com proprietário e revisão de edição. Conflito de edição deve exigir comparação; não sobrescrever silenciosamente trabalho concorrente.
2. **Validada:** configuração coerente e compatível com o público selecionado. Mudar conteúdo, alvos ou capacidades invalida a revisão anterior da validação/aprovação.
3. **Aprovada para publicação:** ator com autorização confirma diferença, impacto e motivo. Recomenda-se separação de autor e aprovador para aumento de bloqueio ou exclusões amplas; modelo de papéis e exceções de emergência requer decisão da equipe.
4. **Publicada:** revisão imutável disponibilizada ao conjunto de alvos identificado. Reenvio idempotente não cria outra revisão; reuso do mesmo identificador com outro conteúdo é conflito. Auditoria administrativa deve registrar ator, UTC, alvo, revisão anterior/nova e motivo.
5. **Distribuição por endpoint:** pretendida → recebida → validada → aplicada, ou rejeitada/pendente/desconhecida. Uma resposta HTTP de entrega não prova os estágios seguintes. Recebimento deve estar vinculado a identidade autenticada e revisão/conteúdo esperado.
6. **Aplicada por capacidade:** serviço, persistência offline e interceptores relevantes precisam de resultados próprios. Sem confirmação de algum canal necessário, apresentar aplicação parcial/desconhecida; não consolidar “aplicada” apenas pela versão do snapshot.
7. **Observada:** evento sintético e diagnóstico podem demonstrar uma atividade no canal e versão declarados. Não equivalem a homologação de todos os destinos/formatos ou SLA global.

Estado de edição, modo de execução (auditoria/enforcement) e estado de distribuição são eixos diferentes. Uma revisão em auditoria também precisa ser distribuída/aplicada; um endpoint offline pode continuar usando uma revisão anterior. Totais do painel devem indicar denominador/alvos, horário de observação e revisão desejada versus observada.

Versão de política, versão de schema, versão de protocolo binário (18 na referência) e versão do pacote são identificadores distintos. Proposta: revisão imutável com hash do conteúdo canônico e especificação de canonicalização/versionamento acordada; não enviar um hash arbitrário e chamá-lo de assinatura. Credencial de dispositivo, autorização, integridade do transporte e eventual assinatura requerem contrato próprio.

Rollback deve publicar uma **nova revisão** com conteúdo de uma anterior e motivo, preservando histórico. A recomendação de rejeitar revisões antigas ou mesma revisão com conteúdo divergente requer protocolo e implementação futura: o leitor atual não deve ser descrito como proteção anti-replay. Sem API acordada, esta seção não define URLs, tabelas ou DTOs novos.

## 6. Múltiplas regras — semântica futura proposta

Uma regra teria ID estável, revisão, categorias/condições suportadas, atividade, escopo, ação, modo e exceções locais. No modelo inicial futuro, dimensões diferentes se combinam por AND; itens de uma mesma lista por OR. Não adicionar expressões arbitrárias/negações sem gramática e capacidade explícitas. Identidade ou atributo ausente produz “não foi possível avaliar”, nunca uma correspondência negativa limpa por conveniência.

Para cada operação, com os mesmos dados e a mesma revisão:

1. Selecionar regras aplicáveis àquela atividade e avaliar suas condições.
2. Aplicar exceções somente às respectivas regras mães correspondentes. Uma exceção não encerra a avaliação das demais regras. Exceção expirada deixa de valer; relógio/origem do tempo e comportamento offline precisam de contrato antes de disponibilizar validade temporal.
3. Calcular ação efetiva: regra em simulação contribui com auditoria e intenção de bloqueio; não contribui com negação efetiva. Canal desligado não deve ser chamado de auditoria.
4. Entre regras em enforcement que correspondam, prevalece Bloquear sem justificativa > Bloquear com justificativa > Auditar. A operação só admite justificativa se **todas as regras bloqueantes aplicáveis** a admitirem. Exceção administrativa não é concessão de override.
5. Prioridade numérica crescente e ID estável em ordem ordinal desempatam a explicação exibida entre ações iguais. Não interrompem a avaliação nem tornam uma ação permissiva superior ao bloqueio. Registrar todos os IDs correspondentes e a razão da decisão; campos adicionais dependem de evolução da auditoria.
6. Se só houver simulação, registrar “seria bloqueada” e a ação realmente executada. Se nenhuma regra corresponder após avaliação completa, registrar ausência de correspondência conforme o canal. Inspeção incompleta permanece categoria de resultado própria.

Essa ordem compara apenas essas três respostas da **mesma operação**. Quarentena posterior, retenção em staging, indisponibilidade, erro de análise e canal desabilitado não entram como posições nessa escala. A proposta não muda fail-open, staging nem controles de autorização já existentes.

Não compilar várias regras por união de categorias e destinos: “CPF em USB” + “Secret em rede” viraria “CPF ou Secret em USB ou rede”, ampliando o bloqueio. Também não usar união de exclusões, que pode remover proteção exigida por outra regra. Quando o contrato único não representa o resultado com equivalência demonstrada, recusar publicação da composição; não degradar silenciosamente. Inicialmente, atribuições sobrepostas devem ser resolvidas explicitamente para uma única política efetiva, com revisão do impacto.

## 7. Offline, capacidade e proteção da auditoria

- Manter a última política válida recuperável durante indisponibilidade. Falha de renovação de credencial, cache ou distribuição deve aparecer como degradação, sem desligar proteção por inferência. Primeiro uso com padrão local deve ser identificado como tal.
- Não introduzir expiração de política que desligue proteção offline. Política de idade máxima, revogação e comportamento sem cache é decisão pendente; ausência de contato não comprova recebimento de revogação.
- Exigir compatibilidade de agente, canal, esquema e par driver antes de prometer enforcement. Capacidade declarada precisa distinguir implementação, qualificação e estado observado; status antigo deve mostrar idade.
- Preservar IDs, instante original e versão usados na operação. Reenvio de auditoria não pode adotar a versão mais recente nem duplicar o total do painel. Persistência/consulta/autorização reais continuam em #47.
- Não enviar conteúdo integral nem valores detectados em preview, auditoria administrativa ou exemplos de política. Justificativas podem conter dados escritos pelo usuário e precisam de limites/acesso definidos.
- Política de inspeção não autoriza apagar fila, temporário ou quarentena. Retenção, confirmação e recuperação são decisões próprias de #48. “72 horas” no roteiro de carga é duração de ensaio, não TTL de eventos. Temporário completo não substitui automaticamente fila válida.

## 8. Decisões necessárias antes de implementação integrada

| ID | Decisão recomendada para discussão | Dependência / aceite |
| --- | --- | --- |
| D01 | Uma política efetiva por endpoint no primeiro incremento; sem união automática | Produto/painel + agente; revisar atribuições conflitantes |
| D02 | Composição restritiva por atividade, exceção local e desempate só de explicação no futuro | Produto/segurança + agente/driver; aprovar matriz C01–C10 antes de motor novo |
| D03 | Publicação imutável, idempotência, rollback como nova revisão e estados separados | Responsável pela API de políticas + agente; contrato consultável #44 |
| D04 | Autorização administrativa no servidor e identidade autenticada de dispositivo | Backend + painel; emissão/renovação/revogação e isolamento entre empresas, sem confiar em endpointId enviado sozinho |
| D05 | Prova de aplicação por componente e persistência offline; prazo medido após integração | Agente + API + driver; não converter refresh em SLA |
| D06 | Limites comuns, categorias desconhecidas, timeout e resolução de caminhos sob SYSTEM | Agente + responsável driver + painel; configuração incompatível bloqueia publicação aos alvos afetados |
| D07 | Autor/aprovador, exceções emergenciais e dados mínimos de auditoria | Produto/segurança + backend/painel; não presumir RBAC já implementado |
| D08 | Idade de política, relógio e comportamento de revogação/exceções offline | Produto/segurança + API/agente; nenhuma expiração automática introduzida aqui |

Sequência sugerida: aprovar D01/D06 e o formulário compatível; acordar D03–D05 com entrega #44; validar distribuição e auditoria reais #47; só então implementar regras múltiplas após D02/D07/D08. É possível revisar linguagem, campos, diferenças e estados agora, sem modificar componentes dos colegas.

## 9. Critérios de aceite e registro desta entrega

A [matriz de cenários](ACEITE-PAINEL-POLITICAS-20261025.md) distingue comportamento existente, proposta e dependência. Nenhum cenário conceitual foi contabilizado como teste executado. O [recibo da revisão](evidencias/desenho-politicas-20261025/revisao.json) identifica os blobs consultados e as referências externas, permitindo recuperar a mesma base com `git show 7327965b:<caminho>` (usar o SHA completo acima na reprodução formal).

Conferência desta entrega: somente documentos novos; links locais e referências de fonte conferidos, diff sem erros de whitespace. Nenhuma suíte de produto, homologação ou instalação repetida; nenhuma VM iniciada. Último resultado de agente continua o de [temporários SYSTEM](TEMPORARIOS-SYSTEM-20261025.md), e a falha funcional do backend ali registrada continua aberta. Alteração documental pode disparar Functional web pelo evento de PR; isso não é solicitação de novo ensaio nem transfere aceite para a integração. Não despachar workflows manualmente para este desenho.

Rastreabilidade: HU-07/RN-009 (categorias/política), HU-06 (autorização), HU-10/HU-12 (endpoint/offline), HU-03/HU-04 (justificativa/auditoria), HU-08 (allowlist futura), RN-011–014 (escopo/limites/exclusões). Requisitos revisados em 21/10 permanecem requisitos; consultar [divergência das rotas](VERIFICACAO-ROTAS-POLITICA-20261021.md), [inventário presencial](RETOMADA-EVIDENCIAS-20261025.md), [#44](https://github.com/pedro-canafistula/safeupload/issues/44) e [#47](https://github.com/pedro-canafistula/safeupload/issues/47). Não foi reconsultada a VM nem alterada a documentação sincronizada em sources/.
