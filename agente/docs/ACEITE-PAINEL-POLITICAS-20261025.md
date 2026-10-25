# Matriz de aceite — políticas no painel

Especificação proposta em 25/10/2026, vinculada ao [desenho](REGRAS-PAINEL-POLITICAS-20261025.md), base `7327965b5538b590f9957b16ca89b7385dcd99f2`. **Não é resultado de testes executados, homologação ou contrato aprovado.** Cada linha é um oráculo de aceite para implementação futura. Onde houver comportamento de código existente, isso não comprova sua integração central.

## Preparação reproduzível para implementação futura

Usar apenas uma empresa e endpoints fictícios E-A/E-B, identidades autenticadas de teste, conteúdo sintético e diretório descartável. Fixar horário T0, revisão, capacidades e contexto de execução em cada caso. Casos temporais exigem relógio injetável e regra de tempo aprovada; não adiantar relógio da máquina/VM para simular validade. O avaliador deve consumir achados sintéticos, sem CPFs/segredos reais.

Notação: R1/R2/R3 são regras conceituais, inexistentes no contrato único atual. B = bloquear sem justificativa; J = bloquear com justificativa; A = auditar; S = simulação. Prioridade menor vem primeiro no desempate de explicação. Não enviar essas estruturas ao agente atual. Repetir a decisão com regras de entrada permutadas deve preservar efeito e IDs/explicação, usando ordenação estável definida no desenho.

## Composição futura (dependente de D02)

| ID | Entrada sintética | Resultado esperado proposto |
| --- | --- | --- |
| C01 | Mesma operação corresponde a R1=A/prioridade 1 e R2=B/prioridade 2 | B; registrar R1/R2; prioridade não reduz bloqueio |
| C02 | R1=J e R2=B correspondem | B; não oferecer justificativa |
| C03 | Duas regras J correspondem, sem B | J, somente no canal que suporte concessão autorizada; controles de evento/sessão/prazo preservados |
| C04 | R1=B com exceção aplicável; R2=B sem exceção | R1 excetuada, R2 bloqueia; exceção não libera toda a operação |
| C05 | Somente R1=B em S corresponde | Ação de auditoria; informar intenção B e ausência de bloqueio efetivo |
| C06 | R1=B em S e R2=J em enforcement correspondem | J; a regra em simulação não se torna B efetivo |
| C07 | R1=B/prioridade 2 e R2=B/prioridade 1; permutar entrada | B em todas; explicação principal R2 e todas as correspondências registradas |
| C08 | Mesmo efeito/prioridade, IDs R1 e R2 | Desempate ordinal por ID; efeito idêntico; ordem de armazenamento não decide |
| C09 | R1=CPF em USB, R2=Secret em rede; operação CPF em rede, sem Secret | Nenhuma correspondência dessas duas regras; compilação por união deve ser recusada |
| C10 | Atributo necessário de identidade ausente ou inspeção incompleta | Estado de avaliação incompleta; não declarar “sem correspondência/Approved”. Tratamento do canal requer contrato |

## Formulário e publicação

| ID | Entrada / ação | Aceite e situação atual |
| --- | --- | --- |
| P01 | Desmarcar todas as categorias | Rejeitar como inválida; RN-009 já existe no domínio |
| P02 | Categoria conhecida + categoria não suportada no alvo | Bloquear publicação ao alvo ou exigir correção explícita. Proposta mais estrita: leitor atual ignora desconhecida se sobrar conhecida |
| P03 | auditOnly=true e clipboard.mode=Block com destino válido | Preview mostra clipboard em Audit; domínio já calcula isso; distribuição real pendente |
| P04 | Clipboard Block sem destino de saída | Inválido mesmo com auditoria global; validação já existe |
| P05 | Incluir sourcePaths, wildcard de processo ou timeout acima do orçamento comum | Não prometer seletor/limite sem suporte. sourcePaths é ignorado hoje; limites operacionais comuns dependem de D06 |
| P06 | Caminho com `%USERPROFILE%`, contexto SYSTEM | Preview declara perfil de sistema; exigir caminho/resolução acordada. Não representar perfil de usuário interativo automaticamente |
| P07 | Editores A/B partem da mesma revisão; A salva, B salva depois | Exibir conflito e diferença; sem perda silenciosa. Depende de API/autorização |
| P08 | Salvar/exportar JSON sem contrato de distribuição | Rascunho/exportado; nenhum endpoint marcado como recebeu/aplicou |
| P09 | Endpoint recebe revisão mas driver não confirma novo escopo | Recebida/validada no serviço, aplicação do canal parcial/desconhecida; sem selo de proteção completa |
| P10 | E-A aplica; E-B permanece offline na revisão anterior | Mostrar duas situações e revisões; não marcar publicação inteira como aplicada |
| P11 | Repetir solicitação de publicação idêntica; depois reutilizar ID com outro conteúdo | Uma publicação no primeiro caso, conflito no segundo; dependente de D03 e idempotência central |
| P12 | Restaurar configuração de revisão anterior | Nova revisão e motivo, histórico anterior preservado; não presumir anti-replay no leitor atual |
| P13 | Recurso compartilhado muda após validação/aprovação | Invalidar aceite do candidato afetado e mostrar diferença; não mudar revisão publicada por referência mutável |
| P14 | Mesmo endpoint recebe duas atribuições incompatíveis | Resolver explicitamente uma política efetiva; recusar união sem equivalência. D01, sem múltiplas políticas no contrato atual |

## Operação, autorização e auditoria

| ID | Situação | Aceite / dependência |
| --- | --- | --- |
| O01 | Offline/reinício após cache persistido | Última política válida recuperável; origem/versão observadas, sem depender de login do usuário final; integração real pendente |
| O02 | Remoto inválido, ou atualização de cache falha | Última válida conforme fluxo; diferenciar memória de persistência. Não declarar que nova revisão sobreviverá ao reinício sem prova |
| O03 | Primeiro uso sem política remota/cache recuperável | Identificar uso do padrão local, sem selo de política central aplicada |
| O04 | Heartbeat recente, interceptor indisponível | Mostrar conectividade e degradação independentes; online não comprova enforcement |
| O05 | Watcher move arquivo sensível à quarentena após escrita | Mostrar quarentena posterior, sem afirmar impedimento preventivo do upload; não repetir homologação Win10 para testar o desenho |
| O06 | Resposta de ingestão perdida, reenvio do mesmo evento | ID/UTC/versão originais, sem contagem duplicada; API/persistência/painel reais dependem de #47 |
| O07 | Usuário sem papel administrativo ou dispositivo de outra empresa envia ID de endpoint | API nega acesso/alteração; campos enviados pelo cliente não conferem autoridade. D04/D07, ainda não demonstrados |
| O08 | Override solicitado quando desativado, sessão errada ou prazo expirado | Recusar; nunca transformar em allowlist de valor. Evidência integrada precisa do canal identificado |
| O09 | Roteiro de 72 h termina com eventos pendentes e temporário completo | Preservar ambos; desenho de política não concede descarte/promoção/retention TTL. #48 continua aberta |
| O10 | Pipeline do backend falha antes do contrato | Registrar bloqueio da integração; não marcar casos P/O como aprovados por sucesso da suíte isolada do agente |

## Registro esperado quando os casos forem executados

Por caso: ID, data/UTC, revisão da especificação, commits e hashes dos componentes, ambiente/capacidades, entrada sintética, saída esperada/obtida, status (passou/falhou/não executado/bloqueado), logs sanitizados e hashes dos recibos. Em caso integrado, incluir identidade do dispositivo e prova de versão por componente, persistência após reinício quando pertinente e correspondência do evento no painel. Não guardar credenciais nem conteúdo detectado.

Até implementação/alinhamento, todos os **34 cenários desta matriz** são especificações não executadas nesta entrega: C01–C10 (10), P01–P14 (14), O01–O10 (10). A consulta ao código e a revisão documental não contam como aprovação desses cenários. As homologações anteriores continuam com seus aceites próprios, sem repetição.
